//! MeshLake-owned Windows Filtering Platform kill-switch filters.
//!
//! The filter set is persistent so an unexpected process exit does not reopen
//! physical-network egress. Each reconciliation first removes only filters in
//! MeshLake's dedicated sublayer, then installs a transactional replacement.

use super::super::kill_switch::{BootstrapTransport, KillSwitchPlan};
use anyhow::{anyhow, bail, Context, Result};
use std::{ffi::c_void, net::IpAddr, ptr};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::{
            IpHelper::ConvertInterfaceAliasToLuid,
            Ndis::NET_LUID_LH,
            WindowsFilteringPlatform::{
                FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
                FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0,
                FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0,
                FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
                FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
                FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
                FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SUBLAYER0,
                FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
                FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
                FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
                FWP_EMPTY, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT16, FWP_UINT32,
                FWP_UINT64, FWP_UINT8, FWP_VALUE0, FWP_VALUE0_0,
            },
        },
    },
};

const SUBLAYER_KEY: GUID = GUID::from_u128(0x4d455348_4c414b45_8d59_77e1cc0a0001);
const FILTER_KEY_BASE: u128 = 0x4d455348_4c414b45_8d59_77e1cc0a1000;
const WFP_ALREADY_EXISTS: u32 = 0x8032_0009;
const WFP_NO_MORE_ITEMS: u32 = 0x8032_0013;
const ERROR_NOT_SUPPORTED: u32 = 50;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
const PERMIT_WEIGHT: u8 = 0xf0;
const BLOCK_WEIGHT: u8 = 0x10;

/// Replaces the complete MeshLake WFP set atomically. This function never
/// edits firewall profiles or filters owned by other applications.
pub(super) enum ReconcileOutcome {
    Applied,
    Unavailable,
}

pub(super) fn reconcile_kill_switch(
    adapter_alias: &str,
    plan: &KillSwitchPlan,
) -> Result<ReconcileOutcome> {
    let Some(engine) = WfpEngine::open()? else {
        return Ok(ReconcileOutcome::Unavailable);
    };
    check_wfp(
        unsafe { FwpmTransactionBegin0(engine.handle, 0) },
        "begin transaction",
    )?;
    let result = (|| {
        ensure_sublayer(engine.handle)?;
        remove_owned_filters(engine.handle)?;
        if plan.enabled {
            let interface_luid = interface_luid(adapter_alias)?;
            let app_id = current_process_app_id()?;
            install_kill_switch_filters(engine.handle, interface_luid, &app_id, plan)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            check_wfp(
                unsafe { FwpmTransactionCommit0(engine.handle) },
                "commit transaction",
            )?;
            Ok(ReconcileOutcome::Applied)
        }
        Err(error) => {
            let _ = unsafe { FwpmTransactionAbort0(engine.handle) };
            Err(error)
        }
    }
}

struct WfpEngine {
    handle: HANDLE,
}

impl WfpEngine {
    fn open() -> Result<Option<Self>> {
        let mut handle = ptr::null_mut();
        let status =
            unsafe { FwpmEngineOpen0(ptr::null(), 0, ptr::null(), ptr::null(), &mut handle) };
        if wfp_engine_is_unavailable(status) {
            return Ok(None);
        }
        check_wfp(status, "open WFP engine")?;
        if handle.is_null() {
            bail!("WFP engine returned an invalid handle");
        }
        Ok(Some(Self { handle }))
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        let _ = unsafe { FwpmEngineClose0(self.handle) };
    }
}

fn ensure_sublayer(engine: HANDLE) -> Result<()> {
    let mut name = wide("MeshLake Kill Switch");
    let mut description = wide("MeshLake-owned persistent physical-egress leak guard.");
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: ptr::null_mut(),
        providerData: empty_blob(),
        // Keep the dedicated sublayer above ordinary policy while individual
        // permit/block filter weights determine MeshLake's own ordering.
        weight: u16::MAX,
    };
    let result = unsafe { FwpmSubLayerAdd0(engine, &sublayer, ptr::null_mut()) };
    if result == 0 || result == WFP_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(wfp_error("add MeshLake sublayer", result))
    }
}

fn remove_owned_filters(engine: HANDLE) -> Result<()> {
    for layer in [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ] {
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.layerKey = layer;
        let mut enumeration = ptr::null_mut();
        check_wfp(
            unsafe { FwpmFilterCreateEnumHandle0(engine, &template, &mut enumeration) },
            "create WFP filter enumeration",
        )?;
        let result: Result<()> = (|| {
            let mut owned_filter_ids = Vec::new();
            loop {
                let mut filters: *mut *mut FWPM_FILTER0 = ptr::null_mut();
                let mut count = 0;
                let status =
                    unsafe { FwpmFilterEnum0(engine, enumeration, 64, &mut filters, &mut count) };
                if status == WFP_NO_MORE_ITEMS || count == 0 {
                    if !filters.is_null() {
                        unsafe { FwpmFreeMemory0(&mut filters.cast::<c_void>()) };
                    }
                    break;
                }
                check_wfp(status, "enumerate WFP filters")?;
                owned_filter_ids.extend(unsafe {
                    std::slice::from_raw_parts(filters, count as usize)
                        .iter()
                        .filter_map(|filter| {
                            (!filter.is_null() && guid_eq((**filter).subLayerKey, SUBLAYER_KEY))
                                .then_some((**filter).filterId)
                        })
                });
                unsafe { FwpmFreeMemory0(&mut filters.cast::<c_void>()) };
            }
            for id in owned_filter_ids {
                check_wfp(
                    unsafe { FwpmFilterDeleteById0(engine, id) },
                    "remove MeshLake WFP filter",
                )?;
            }
            Ok(())
        })();
        let destroy = unsafe { FwpmFilterDestroyEnumHandle0(engine, enumeration) };
        result?;
        check_wfp(destroy, "destroy WFP filter enumeration")?;
    }
    Ok(())
}

fn install_kill_switch_filters(
    engine: HANDLE,
    interface_luid: u64,
    app_id: &[u8],
    plan: &KillSwitchPlan,
) -> Result<()> {
    let mut index = 1_u128;
    for layer in [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ] {
        let mut interface_luid = interface_luid;
        add_filter(
            engine,
            filter_key(index),
            "MeshLake allow virtual interface",
            layer,
            &mut [condition_uint64(
                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                &mut interface_luid,
            )],
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
        )?;
        index += 1;

        add_filter(
            engine,
            filter_key(index),
            "MeshLake allow loopback",
            layer,
            &mut [condition_uint32_flags(
                FWPM_CONDITION_FLAGS,
                FWP_CONDITION_FLAG_IS_LOOPBACK,
            )],
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
        )?;
        index += 1;

        for bootstrap in &plan.bootstrap_endpoints {
            if guid_eq(layer, FWPM_LAYER_ALE_AUTH_CONNECT_V4) != bootstrap.endpoint.is_ipv4() {
                continue;
            }
            let mut app_blob = FWP_BYTE_BLOB {
                size: app_id
                    .len()
                    .try_into()
                    .context("MeshLake app ID is too large")?,
                data: app_id.as_ptr() as *mut u8,
            };
            let mut port = bootstrap.endpoint.port();
            let mut protocol = match bootstrap.transport {
                BootstrapTransport::Tcp => PROTOCOL_TCP,
                BootstrapTransport::Udp => PROTOCOL_UDP,
            };
            let mut address_v6 = FWP_BYTE_ARRAY16 {
                byteArray16: [0; 16],
            };
            let mut conditions = vec![
                condition_blob(FWPM_CONDITION_ALE_APP_ID, &mut app_blob),
                condition_uint16(FWPM_CONDITION_IP_REMOTE_PORT, &mut port),
                condition_uint8(FWPM_CONDITION_IP_PROTOCOL, &mut protocol),
            ];
            match bootstrap.endpoint.ip() {
                IpAddr::V4(address) => conditions.push(condition_uint32(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    u32::from_be_bytes(address.octets()),
                )),
                IpAddr::V6(address) => {
                    address_v6.byteArray16 = address.octets();
                    conditions.push(condition_byte_array16(
                        FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        &mut address_v6,
                    ));
                }
            }
            add_filter(
                engine,
                filter_key(index),
                "MeshLake allow signed bootstrap endpoint",
                layer,
                &mut conditions,
                FWP_ACTION_PERMIT,
                PERMIT_WEIGHT,
            )?;
            index += 1;
        }

        add_filter(
            engine,
            filter_key(index),
            "MeshLake block physical egress",
            layer,
            &mut [],
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
        )?;
        index += 1;
    }
    Ok(())
}

fn add_filter(
    engine: HANDLE,
    key: GUID,
    display_name: &str,
    layer: GUID,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    action: u32,
    weight: u8,
) -> Result<()> {
    let mut name = wide(display_name);
    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.filterKey = key;
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr(),
        description: ptr::null_mut(),
    };
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.providerKey = ptr::null_mut();
    filter.providerData = empty_blob();
    filter.layerKey = layer;
    filter.subLayerKey = SUBLAYER_KEY;
    filter.weight = value_uint8(weight);
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = conditions.as_mut_ptr();
    filter.action = FWPM_ACTION0 {
        r#type: action,
        Anonymous: unsafe { std::mem::zeroed() },
    };
    filter.Anonymous = unsafe { std::mem::zeroed() };
    filter.reserved = ptr::null_mut();
    filter.filterId = 0;
    filter.effectiveWeight = value_empty();
    check_wfp(
        unsafe { FwpmFilterAdd0(engine, &filter, ptr::null_mut(), ptr::null_mut()) },
        "add MeshLake WFP filter",
    )
}

fn interface_luid(alias: &str) -> Result<u64> {
    let alias = wide(alias);
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
    if status != 0 {
        bail!("cannot resolve the MeshLake adapter interface LUID (Windows error {status})");
    }
    Ok(unsafe { luid.Value })
}

fn current_process_app_id() -> Result<Vec<u8>> {
    let executable =
        std::env::current_exe().context("cannot determine MeshLake executable path")?;
    let executable = wide(&executable.to_string_lossy());
    let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
    check_wfp(
        unsafe { FwpmGetAppIdFromFileName0(executable.as_ptr(), &mut blob) },
        "resolve MeshLake WFP application ID",
    )?;
    if blob.is_null() || unsafe { (*blob).data.is_null() } {
        if !blob.is_null() {
            unsafe { FwpmFreeMemory0(&mut blob.cast::<c_void>()) };
        }
        bail!("WFP returned an empty MeshLake application ID");
    }
    let app_id =
        unsafe { std::slice::from_raw_parts((*blob).data, (*blob).size as usize).to_vec() };
    unsafe { FwpmFreeMemory0(&mut blob.cast::<c_void>()) };
    if app_id.is_empty() {
        bail!("WFP returned an empty MeshLake application ID");
    }
    Ok(app_id)
}

fn condition_uint8(field: GUID, value: &mut u8) -> FWPM_FILTER_CONDITION0 {
    condition(
        field,
        FWP_MATCH_EQUAL,
        FWP_UINT8,
        FWP_CONDITION_VALUE0_0 { uint8: *value },
    )
}

fn condition_uint16(field: GUID, value: &mut u16) -> FWPM_FILTER_CONDITION0 {
    condition(
        field,
        FWP_MATCH_EQUAL,
        FWP_UINT16,
        FWP_CONDITION_VALUE0_0 { uint16: *value },
    )
}

fn condition_uint32(field: GUID, value: u32) -> FWPM_FILTER_CONDITION0 {
    condition(
        field,
        FWP_MATCH_EQUAL,
        FWP_UINT32,
        FWP_CONDITION_VALUE0_0 { uint32: value },
    )
}

fn condition_uint32_flags(field: GUID, value: u32) -> FWPM_FILTER_CONDITION0 {
    condition(
        field,
        FWP_MATCH_FLAGS_ALL_SET,
        FWP_UINT32,
        FWP_CONDITION_VALUE0_0 { uint32: value },
    )
}

fn condition_uint64(field: GUID, value: &mut u64) -> FWPM_FILTER_CONDITION0 {
    condition(
        field,
        FWP_MATCH_EQUAL,
        FWP_UINT64,
        FWP_CONDITION_VALUE0_0 { uint64: value },
    )
}

fn condition_blob(field: GUID, value: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    condition(
        field,
        FWP_MATCH_EQUAL,
        FWP_BYTE_BLOB_TYPE,
        FWP_CONDITION_VALUE0_0 { byteBlob: value },
    )
}

fn condition_byte_array16(field: GUID, value: &mut FWP_BYTE_ARRAY16) -> FWPM_FILTER_CONDITION0 {
    condition(
        field,
        FWP_MATCH_EQUAL,
        FWP_BYTE_ARRAY16_TYPE,
        FWP_CONDITION_VALUE0_0 { byteArray16: value },
    )
}

fn condition(
    field: GUID,
    match_type: i32,
    value_type: i32,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: value_type,
            Anonymous: value,
        },
    }
}

fn value_uint8(value: u8) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: value },
    }
}

fn value_empty() -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_EMPTY,
        Anonymous: unsafe { std::mem::zeroed() },
    }
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: ptr::null_mut(),
    }
}

fn filter_key(index: u128) -> GUID {
    GUID::from_u128(FILTER_KEY_BASE + index)
}

fn guid_eq(left: GUID, right: GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check_wfp(status: u32, operation: &str) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(wfp_error(operation, status))
    }
}

fn wfp_error(operation: &str, status: u32) -> anyhow::Error {
    anyhow!("cannot {operation} (WFP error 0x{status:08x})")
}

fn wfp_engine_is_unavailable(status: u32) -> bool {
    status == ERROR_NOT_SUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_keys_are_stable_and_distinct() {
        assert!(!guid_eq(filter_key(1), filter_key(2)));
        assert!(!guid_eq(filter_key(1), SUBLAYER_KEY));
    }

    #[test]
    fn protocol_selection_is_explicit() {
        assert_eq!(PROTOCOL_TCP, 6);
        assert_eq!(PROTOCOL_UDP, 17);
    }

    #[test]
    fn recognizes_a_windows_wfp_engine_that_is_not_supported() {
        assert!(wfp_engine_is_unavailable(ERROR_NOT_SUPPORTED));
        assert!(!wfp_engine_is_unavailable(0));
        assert!(!wfp_engine_is_unavailable(WFP_ALREADY_EXISTS));
    }
}
