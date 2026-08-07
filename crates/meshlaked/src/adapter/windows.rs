//! Windows Wintun adapter lifecycle.
//!
//! The driver is intentionally not linked at build time. A release package places the signed
//! `wintun.dll` next to `meshlaked.exe`; development can pass `--wintun-dll <path>`.

use super::policy::{apply_policy_transaction, finalize_policy_transaction, PolicyPlan};
use crate::exit_gateway::{ExitGatewayPlan, GatewayRoute};
use anyhow::{anyhow, bail, Context, Result};
use libloading::Library;
use meshlake_core::JoinedNetwork;
use std::{
    env,
    ffi::c_void,
    fs,
    path::{Path, PathBuf},
    process::Command,
    ptr,
    sync::{Arc, Mutex},
};

const RING_CAPACITY: u32 = 0x400000; // 4 MiB; required by Wintun to be a power of two.
const ADAPTER_NAME: &str = "MeshLake";
const TUNNEL_TYPE: &str = "MeshLake";
const BUNDLED_WINTUN: &[u8] = include_bytes!("../../../../third_party/wintun/wintun.dll");

type RawAdapterHandle = *mut c_void;
type RawSessionHandle = *mut c_void;
type CreateAdapter =
    unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> RawAdapterHandle;
type OpenAdapter = unsafe extern "system" fn(*const u16) -> RawAdapterHandle;
type CloseAdapter = unsafe extern "system" fn(RawAdapterHandle);
type StartSession = unsafe extern "system" fn(RawAdapterHandle, u32) -> RawSessionHandle;
type EndSession = unsafe extern "system" fn(RawSessionHandle);
type ReceivePacket = unsafe extern "system" fn(RawSessionHandle, *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(RawSessionHandle, *const u8);
type AllocateSendPacket = unsafe extern "system" fn(RawSessionHandle, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(RawSessionHandle, *const u8);

struct WintunApi {
    _library: Library,
    create_adapter: CreateAdapter,
    open_adapter: OpenAdapter,
    close_adapter: CloseAdapter,
    start_session: StartSession,
    end_session: EndSession,
    receive_packet: ReceivePacket,
    release_receive_packet: ReleaseReceivePacket,
    allocate_send_packet: AllocateSendPacket,
    send_packet: SendPacket,
}

impl WintunApi {
    unsafe fn load(path: &Path) -> Result<Self> {
        let library =
            Library::new(path).with_context(|| format!("cannot load {}", path.display()))?;
        Ok(Self {
            create_adapter: *library.get(b"WintunCreateAdapter\0")?,
            open_adapter: *library.get(b"WintunOpenAdapter\0")?,
            close_adapter: *library.get(b"WintunCloseAdapter\0")?,
            start_session: *library.get(b"WintunStartSession\0")?,
            end_session: *library.get(b"WintunEndSession\0")?,
            receive_packet: *library.get(b"WintunReceivePacket\0")?,
            release_receive_packet: *library.get(b"WintunReleaseReceivePacket\0")?,
            allocate_send_packet: *library.get(b"WintunAllocateSendPacket\0")?,
            send_packet: *library.get(b"WintunSendPacket\0")?,
            _library: library,
        })
    }

    fn create_or_open(self: &Arc<Self>) -> Result<AdapterSession> {
        let adapter_name = wide(ADAPTER_NAME);
        let tunnel_type = wide(TUNNEL_TYPE);
        // Creating first makes the common fresh-install path cheap. If it already exists,
        // Wintun returns null and opening the stable MeshLake adapter name succeeds.
        let mut adapter = unsafe {
            (self.create_adapter)(adapter_name.as_ptr(), tunnel_type.as_ptr(), ptr::null())
        };
        if adapter.is_null() {
            adapter = unsafe { (self.open_adapter)(adapter_name.as_ptr()) };
        }
        if adapter.is_null() {
            return Err(anyhow!(
                "Wintun could not create or open the MeshLake adapter: {}",
                std::io::Error::last_os_error()
            ));
        }
        let session = unsafe { (self.start_session)(adapter, RING_CAPACITY) };
        if session.is_null() {
            unsafe { (self.close_adapter)(adapter) };
            return Err(anyhow!(
                "Wintun could not start an adapter session: {}",
                std::io::Error::last_os_error()
            ));
        }
        // Store opaque Windows handles as integers. They never leave AdapterController's mutex,
        // and are cast back only at the FFI boundary. This makes the agent state Send + Sync.
        Ok(AdapterSession {
            api: Arc::clone(self),
            adapter: adapter as usize,
            session: session as usize,
        })
    }
}

struct AdapterSession {
    api: Arc<WintunApi>,
    adapter: usize,
    session: usize,
}
impl Drop for AdapterSession {
    fn drop(&mut self) {
        unsafe { (self.api.end_session)(self.session as RawSessionHandle) };
        unsafe { (self.api.close_adapter)(self.adapter as RawAdapterHandle) };
    }
}

impl AdapterSession {
    /// Reads one layer-3 packet when Wintun has data available. `Ok(None)` is normal when
    /// its receive ring is empty and lets the transport worker yield without busy looping.
    fn try_read_packet(&self) -> Result<Option<Vec<u8>>> {
        let mut size = 0_u32;
        let packet = unsafe {
            (self.api.receive_packet)(
                self.session as RawSessionHandle,
                std::ptr::addr_of_mut!(size),
            )
        };
        if packet.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(259) {
                return Ok(None); // ERROR_NO_MORE_ITEMS
            }
            return Err(anyhow!("Wintun receive failed: {error}"));
        }
        let bytes = unsafe { std::slice::from_raw_parts(packet, size as usize).to_vec() };
        unsafe { (self.api.release_receive_packet)(self.session as RawSessionHandle, packet) };
        Ok(Some(bytes))
    }

    fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() || packet.len() > u16::MAX as usize {
            bail!(
                "Wintun packet length must be between 1 and {} bytes",
                u16::MAX
            );
        }
        let destination = unsafe {
            (self.api.allocate_send_packet)(self.session as RawSessionHandle, packet.len() as u32)
        };
        if destination.is_null() {
            return Err(anyhow!(
                "Wintun send buffer allocation failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe { std::ptr::copy_nonoverlapping(packet.as_ptr(), destination, packet.len()) };
        unsafe { (self.api.send_packet)(self.session as RawSessionHandle, destination) };
        Ok(())
    }
}

/// Owns one process-local Wintun session. Creating the adapter requires Windows elevation;
/// stopping the session does not delete the adapter or alter routes.
pub struct AdapterController {
    dll_path: PathBuf,
    session: Mutex<Option<AdapterSession>>,
    applied_policy: Mutex<PolicyPlan>,
    applied_exit_gateways: Mutex<ExitGatewayPlan>,
}

impl AdapterController {
    pub fn new(dll_path: PathBuf) -> Self {
        Self {
            dll_path,
            session: Mutex::new(None),
            applied_policy: Mutex::new(PolicyPlan::default()),
            applied_exit_gateways: Mutex::new(ExitGatewayPlan::default()),
        }
    }
    pub fn status(&self) -> String {
        if self
            .session
            .lock()
            .expect("adapter lock poisoned")
            .is_some()
        {
            return "active".into();
        }
        if !self.dll_path.is_file() {
            return "driver-missing".into();
        }
        match unsafe { WintunApi::load(&self.dll_path) } {
            Ok(_) => "ready".into(),
            Err(_) => "driver-invalid".into(),
        }
    }
    pub fn activate(&self) -> Result<()> {
        let mut guard = self.session.lock().expect("adapter lock poisoned");
        if guard.is_some() {
            return Ok(());
        }
        if !self.dll_path.is_file() {
            return Err(anyhow!(
                "Wintun driver not found at {}",
                self.dll_path.display()
            ));
        }
        let api = Arc::new(unsafe { WintunApi::load(&self.dll_path)? });
        *guard = Some(api.create_or_open()?);
        Ok(())
    }
    pub fn deactivate(&self) {
        if let Err(error) = self.rollback_exit_gateways() {
            eprintln!(
                "MeshLake could not completely roll back Windows exit-gateway rules: {error:#}"
            );
        }
        if let Err(error) = self.rollback_policy() {
            eprintln!(
                "MeshLake could not completely roll back Windows route/DNS policy: {error:#}"
            );
        }
        self.session.lock().expect("adapter lock poisoned").take();
    }

    pub fn is_active(&self) -> bool {
        self.session
            .lock()
            .expect("adapter lock poisoned")
            .is_some()
    }

    pub fn try_read_packet(&self) -> Result<Option<Vec<u8>>> {
        let guard = self.session.lock().expect("adapter lock poisoned");
        let session = guard
            .as_ref()
            .ok_or_else(|| anyhow!("MeshLake adapter is not active"))?;
        session.try_read_packet()
    }

    pub fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let guard = self.session.lock().expect("adapter lock poisoned");
        let session = guard
            .as_ref()
            .ok_or_else(|| anyhow!("MeshLake adapter is not active"))?;
        session.write_packet(packet)
    }

    /// Assigns each controller-issued IPv4/IPv6 address to the MeshLake adapter.
    /// This intentionally installs only connected routes; it never changes a default route.
    pub fn configure_networks(&self, networks: &[JoinedNetwork]) -> Result<()> {
        if !self.is_active() {
            bail!("MeshLake adapter is not active");
        }
        for joined in networks {
            for address in &joined.assigned_addresses {
                match address {
                    std::net::IpAddr::V4(address) => {
                        let prefix = ipv4_prefix_len(&joined.network.ipv4_prefix)?;
                        run_netsh(&[
                            "interface",
                            "ipv4",
                            "add",
                            "address",
                            &format!("name={ADAPTER_NAME}"),
                            &format!("address={address}"),
                            &format!("mask={}", ipv4_mask(prefix)),
                            "store=active",
                        ])?;
                    }
                    std::net::IpAddr::V6(address) => {
                        let prefix = joined
                            .network
                            .ipv6_prefix
                            .as_deref()
                            .map(ipv6_prefix_len)
                            .transpose()?
                            .unwrap_or(128);
                        run_netsh(&[
                            "interface",
                            "ipv6",
                            "add",
                            "address",
                            &format!("interface={ADAPTER_NAME}"),
                            &format!("address={address}/{prefix}"),
                            "store=active",
                        ])?;
                    }
                }
            }
        }
        // A fresh Wintun interface is normally classified as an unidentified
        // (Public) network. Windows Firewall would then discard traffic after
        // it has been authenticated and injected by the agent. This rule is
        // restricted to the MeshLake virtual adapter, never a physical NIC.
        ensure_virtual_lan_firewall_rule()?;
        self.configure_policy(networks)?;
        Ok(())
    }

    pub fn remove_network(&self, joined: &JoinedNetwork) -> Result<()> {
        if !self.is_active() {
            return Ok(());
        }
        for address in &joined.assigned_addresses {
            match address {
                std::net::IpAddr::V4(address) => run_netsh(&[
                    "interface",
                    "ipv4",
                    "delete",
                    "address",
                    &format!("name={ADAPTER_NAME}"),
                    &format!("address={address}"),
                ])?,
                std::net::IpAddr::V6(address) => run_netsh(&[
                    "interface",
                    "ipv6",
                    "delete",
                    "address",
                    &format!("interface={ADAPTER_NAME}"),
                    &format!("address={address}"),
                ])?,
            }
        }
        Ok(())
    }

    pub fn configure_policy(&self, networks: &[JoinedNetwork]) -> Result<()> {
        let plan = PolicyPlan::from_networks(networks, now())?;
        if !self.is_active() {
            return Ok(());
        }
        self.reconcile_policy(plan)
    }

    /// Applies explicit local forwarding/NAT configuration. IPv4 uses a named
    /// NetNat object per virtual prefix; IPv6 enables forwarding but does not
    /// invent NAT66, so its return path remains an explicit network design.
    pub fn configure_exit_gateways(&self, desired: ExitGatewayPlan) -> Result<()> {
        if !self.is_active() {
            bail!("MeshLake adapter is not active");
        }
        let mut current = self
            .applied_exit_gateways
            .lock()
            .expect("exit gateway lock poisoned");
        if *current == desired {
            return Ok(());
        }
        let previous = current.clone();
        if let Err(primary) = run_policy_scripts(&windows_exit_gateway_scripts(
            &previous,
            GatewayOperation::Remove,
        ))
        .and_then(|_| {
            run_policy_scripts(&windows_exit_gateway_scripts(
                &desired,
                GatewayOperation::Apply,
            ))
        }) {
            let cleanup = run_policy_scripts(&windows_exit_gateway_scripts(
                &desired,
                GatewayOperation::Remove,
            ));
            let restore = run_policy_scripts(&windows_exit_gateway_scripts(
                &previous,
                GatewayOperation::Apply,
            ));
            if cleanup.is_err() || restore.is_err() {
                drop(current);
                self.session.lock().expect("adapter lock poisoned").take();
                bail!(
                    "Windows exit-gateway transaction failed: {primary:#}; rollback failed and the adapter was disabled fail closed"
                );
            }
            bail!("Windows exit-gateway transaction failed and the previous rules were restored: {primary:#}");
        }
        *current = desired;
        Ok(())
    }

    fn reconcile_policy(&self, desired: PolicyPlan) -> Result<()> {
        if desired.search_domains.len() > 1 {
            bail!(
                "Windows supports one connection-specific search domain on the MeshLake adapter; policy requested {}",
                desired.search_domains.len()
            );
        }
        let mut current = self
            .applied_policy
            .lock()
            .expect("applied policy lock poisoned");
        if *current == desired {
            return Ok(());
        }
        let previous = current.clone();
        let result = apply_policy_transaction(
            || {
                run_policy_scripts(&windows_policy_scripts(&previous, PolicyOperation::Remove))
                    .map_err(|error| error.to_string())
            },
            || {
                run_policy_scripts(&windows_policy_scripts(&desired, PolicyOperation::Apply))
                    .map_err(|error| error.to_string())
            },
            || {
                run_policy_scripts(&windows_policy_scripts(&desired, PolicyOperation::Remove))
                    .map_err(|error| error.to_string())
            },
            || {
                run_policy_scripts(&windows_policy_scripts(&previous, PolicyOperation::Apply))
                    .map_err(|error| error.to_string())
            },
        );
        if let Err(error) = finalize_policy_transaction(&mut current, desired, result) {
            if error.is_fail_closed() {
                drop(current);
                self.session.lock().expect("adapter lock poisoned").take();
                return Err(anyhow!(
                    "Windows policy transaction failed closed and disabled the adapter: {error}"
                ));
            }
            return Err(anyhow!(error));
        }
        Ok(())
    }

    fn rollback_policy(&self) -> Result<()> {
        let mut current = self
            .applied_policy
            .lock()
            .expect("applied policy lock poisoned");
        let result = run_policy_scripts(&windows_policy_scripts(&current, PolicyOperation::Remove));
        *current = PolicyPlan::default();
        result
    }

    fn rollback_exit_gateways(&self) -> Result<()> {
        let mut current = self
            .applied_exit_gateways
            .lock()
            .expect("exit gateway lock poisoned");
        let result = run_policy_scripts(&windows_exit_gateway_scripts(
            &current,
            GatewayOperation::Remove,
        ));
        *current = ExitGatewayPlan::default();
        result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyOperation {
    Apply,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayOperation {
    Apply,
    Remove,
}

fn windows_policy_scripts(plan: &PolicyPlan, operation: PolicyOperation) -> Vec<String> {
    let mut scripts = Vec::new();
    for route in plan.routes.iter().chain(&plan.exit_routes) {
        scripts.push(match operation {
            PolicyOperation::Apply => format!(
                "New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}' -InterfaceAlias '{}' -NextHop '{}' -RouteMetric 5 -ErrorAction Stop | Out-Null",
                route.prefix,
                ADAPTER_NAME,
                if route.prefix.contains(':') { "::" } else { "0.0.0.0" }
            ),
            PolicyOperation::Remove => format!(
                "Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}' -InterfaceAlias '{}' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction Stop",
                route.prefix, ADAPTER_NAME
            ),
        });
    }
    match operation {
        PolicyOperation::Apply => {
            if !plan.dns_servers.is_empty() {
                let servers = plan
                    .dns_servers
                    .iter()
                    .map(|server| format!("'{server}'"))
                    .collect::<Vec<_>>()
                    .join(",");
                scripts.push(format!(
                    "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({servers}) -ErrorAction Stop",
                    ADAPTER_NAME
                ));
            }
            if let Some(domain) = plan.search_domains.first() {
                scripts.push(format!(
                    "Set-DnsClient -InterfaceAlias '{}' -ConnectionSpecificSuffix '{}' -RegisterThisConnectionsAddress:$false -ErrorAction Stop",
                    ADAPTER_NAME, domain
                ));
            }
        }
        PolicyOperation::Remove => {
            if !plan.dns_servers.is_empty() {
                scripts.push(format!(
                    "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses -ErrorAction Stop",
                    ADAPTER_NAME
                ));
            }
            if !plan.search_domains.is_empty() {
                scripts.push(format!(
                    "Set-DnsClient -InterfaceAlias '{}' -ConnectionSpecificSuffix '' -ErrorAction Stop",
                    ADAPTER_NAME
                ));
            }
        }
    }
    scripts
}

fn windows_exit_gateway_scripts(
    plan: &ExitGatewayPlan,
    operation: GatewayOperation,
) -> Vec<String> {
    let mut scripts = Vec::new();
    for route in &plan.routes {
        let family = if route.ipv6 { "IPv6" } else { "IPv4" };
        let nat_name = windows_nat_name(route);
        match operation {
            GatewayOperation::Apply => {
                scripts.push(format!(
                    "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily {family} -Forwarding Enabled -ErrorAction Stop",
                    ADAPTER_NAME
                ));
                scripts.push(format!(
                    "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily {family} -Forwarding Enabled -ErrorAction Stop",
                    route.egress_interface
                ));
                if !route.ipv6 {
                    scripts.push(format!(
                        "New-NetNat -Name '{}' -InternalIPInterfaceAddressPrefix '{}' -ErrorAction Stop | Out-Null",
                        nat_name, route.prefix
                    ));
                }
            }
            GatewayOperation::Remove => {
                if !route.ipv6 {
                    scripts.push(format!(
                        "Get-NetNat -Name '{}' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction Stop",
                        nat_name
                    ));
                }
            }
        }
    }
    scripts
}

fn windows_nat_name(route: &GatewayRoute) -> String {
    format!(
        "MeshLake-{}-{}",
        route.network_id.0,
        if route.ipv6 { "v6" } else { "v4" }
    )
}

fn run_policy_scripts(scripts: &[String]) -> Result<()> {
    run_policy_scripts_with(scripts, |script| {
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|error| {
                format!("cannot start PowerShell to configure MeshLake policy: {error}")
            })?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "PowerShell policy command failed ({}): {}{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    })
}

fn run_policy_scripts_with(
    scripts: &[String],
    mut execute: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<()> {
    let mut failures = Vec::new();
    for script in scripts {
        if let Err(error) = execute(script) {
            failures.push(error);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("\n"))
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_secs()
}

fn ipv4_prefix_len(prefix: &str) -> Result<u8> {
    prefix
        .split_once('/')
        .and_then(|(_, length)| length.parse::<u8>().ok())
        .filter(|length| *length <= 32)
        .ok_or_else(|| anyhow!("invalid IPv4 prefix: {prefix}"))
}

fn ipv6_prefix_len(prefix: &str) -> Result<u8> {
    prefix
        .split_once('/')
        .and_then(|(_, length)| length.parse::<u8>().ok())
        .filter(|length| *length <= 128)
        .ok_or_else(|| anyhow!("invalid IPv6 prefix: {prefix}"))
}

fn ipv4_mask(prefix_len: u8) -> std::net::Ipv4Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    std::net::Ipv4Addr::from(mask)
}

fn run_netsh(arguments: &[&str]) -> Result<()> {
    let output = Command::new("netsh")
        .args(arguments)
        .output()
        .context("cannot start netsh; Windows is required")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "netsh failed ({})\n{}{}",
        output.status,
        stdout,
        stderr
    ))
}

fn ensure_virtual_lan_firewall_rule() -> Result<()> {
    const RULE_NAME: &str = "MeshLake.VirtualLan.Inbound";
    const SCRIPT: &str = concat!(
        "$ErrorActionPreference='Stop'; ",
        "Remove-NetFirewallRule -Name 'MeshLake.VirtualLan.Inbound' -ErrorAction SilentlyContinue; ",
        "New-NetFirewallRule -Name 'MeshLake.VirtualLan.Inbound' ",
        "-DisplayName 'MeshLake Virtual LAN' ",
        "-Description 'Allows authenticated MeshLake overlay traffic only on the MeshLake virtual adapter.' ",
        "-Direction Inbound -Action Allow -InterfaceAlias 'MeshLake' -Profile Any | Out-Null"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .output()
        .context("cannot start PowerShell to configure the MeshLake firewall rule")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "cannot create {RULE_NAME} firewall rule ({})\n{}{}",
        output.status,
        stdout,
        stderr
    ))
}

pub fn default_wintun_path() -> PathBuf {
    if let Some(path) = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|folder| folder.join("wintun.dll")))
    {
        if path.is_file() {
            return path;
        }
    }
    let fallback = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir())
        .join("MeshLake")
        .join("wintun.dll");
    if !fallback.is_file() {
        if let Some(folder) = fallback.parent() {
            let _ = fs::create_dir_all(folder);
        }
        // The DLL is the unchanged, signed AMD64 binary from the verified Wintun package.
        let _ = fs::write(&fallback, BUNDLED_WINTUN);
    }
    fallback
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_prefix_length_to_mask() {
        assert_eq!(ipv4_mask(24).to_string(), "255.255.255.0");
        assert_eq!(ipv4_mask(32).to_string(), "255.255.255.255");
        assert!(ipv4_prefix_len("not-a-prefix").is_err());
        assert_eq!(ipv6_prefix_len("fd42:4d4c::/64").unwrap(), 64);
        assert!(ipv6_prefix_len("fd42:4d4c::/129").is_err());
    }

    #[test]
    fn builds_pure_windows_route_and_dns_transactions() {
        let plan = PolicyPlan {
            routes: vec![super::super::policy::PlannedRoute {
                prefix: "10.20.0.0/16".into(),
                network_id: meshlake_core::NetworkId(uuid::Uuid::from_u128(1)),
                gateway_device_id: meshlake_core::DeviceId(uuid::Uuid::from_u128(2)),
            }],
            exit_routes: vec![],
            exit_kill_switch: false,
            dns_servers: vec!["10.20.0.53".parse().unwrap()],
            search_domains: vec!["corp.example".into()],
        };
        let apply = windows_policy_scripts(&plan, PolicyOperation::Apply).join("\n");
        assert!(apply.contains("New-NetRoute"));
        assert!(apply.contains("Set-DnsClientServerAddress"));
        assert!(apply.contains("ConnectionSpecificSuffix 'corp.example'"));
        let remove = windows_policy_scripts(&plan, PolicyOperation::Remove).join("\n");
        assert!(remove.contains("Remove-NetRoute"));
        assert!(remove.contains("ResetServerAddresses"));
    }

    #[test]
    fn builds_scoped_windows_nat_and_forwarding_transactions() {
        let plan = ExitGatewayPlan {
            routes: vec![GatewayRoute {
                network_id: meshlake_core::NetworkId(uuid::Uuid::from_u128(21)),
                prefix: "100.64.21.0/24".into(),
                egress_interface: "Ethernet".into(),
                ipv6: false,
            }],
        };
        let apply = windows_exit_gateway_scripts(&plan, GatewayOperation::Apply).join("\n");
        assert!(apply.contains("Set-NetIPInterface"));
        assert!(apply.contains("New-NetNat"));
        assert!(apply.contains("MeshLake-00000000-0000-0000-0000-000000000015-v4"));
        assert!(!apply.contains("Remove-NetNat"));
        let remove = windows_exit_gateway_scripts(&plan, GatewayOperation::Remove).join("\n");
        assert!(remove.contains("Get-NetNat"));
        assert!(remove.contains("Remove-NetNat"));
        assert!(!remove.contains("Set-NetIPInterface"));
    }

    #[test]
    fn windows_command_runner_continues_after_injected_failure() {
        let scripts = vec!["first".to_owned(), "second".to_owned()];
        let mut executed = Vec::new();
        let result = run_policy_scripts_with(&scripts, |script| {
            executed.push(script.to_owned());
            if script == "first" {
                Err("injected Windows command failure".into())
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(executed, scripts);
    }
}
