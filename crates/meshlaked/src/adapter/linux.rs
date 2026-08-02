//! Linux TUN adapter implementation used by the headless MeshLake agent.

use anyhow::{anyhow, bail, Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use meshlake_core::JoinedNetwork;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::IpAddr,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::PathBuf,
    process::Command,
    sync::Mutex,
};

const INTERFACE_NAME: &str = "meshlake0";
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct TunIfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlannedAddress {
    address: IpAddr,
    prefix_length: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressOperation {
    Replace,
    Delete,
}

impl AddressOperation {
    fn argument(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::Delete => "del",
        }
    }
}

pub struct AdapterController {
    session: Mutex<Option<File>>,
}

impl AdapterController {
    pub fn new(_: PathBuf) -> Self {
        Self {
            session: Mutex::new(None),
        }
    }

    pub fn status(&self) -> String {
        if self.is_active() {
            "active".into()
        } else if std::path::Path::new("/dev/net/tun").exists() {
            "ready".into()
        } else {
            "driver-missing".into()
        }
    }

    pub fn activate(&self) -> Result<()> {
        let mut guard = self.session.lock().expect("adapter lock poisoned");
        if guard.is_some() {
            return Ok(());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")
            .context("cannot open /dev/net/tun; load the tun module and run MeshLake as root")?;
        let mut request = TunIfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };
        for (destination, source) in request
            .name
            .iter_mut()
            .zip(INTERFACE_NAME.as_bytes().iter().copied())
        {
            *destination = source as libc::c_char;
        }
        let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut request) };
        if result < 0 {
            return Err(anyhow!(
                "cannot create Linux TUN interface {INTERFACE_NAME}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let command = interface_up_command();
        publish_session_after_interface_up(&mut guard, file, || run_ip(&command))
    }

    pub fn deactivate(&self) {
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
        let mut file = guard
            .as_ref()
            .ok_or_else(|| anyhow!("MeshLake adapter is not active"))?;
        let mut packet = vec![0_u8; u16::MAX as usize];
        match file.read(&mut packet) {
            Ok(0) => Ok(None),
            Ok(size) => {
                packet.truncate(size);
                Ok(Some(packet))
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error).context("cannot read Linux TUN packet"),
        }
    }

    pub fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() || packet.len() > u16::MAX as usize {
            bail!("invalid Linux TUN packet length");
        }
        let guard = self.session.lock().expect("adapter lock poisoned");
        let mut file = guard
            .as_ref()
            .ok_or_else(|| anyhow!("MeshLake adapter is not active"))?;
        file.write_all(packet)
            .context("cannot write packet to Linux TUN")
    }

    pub fn configure_networks(&self, networks: &[JoinedNetwork]) -> Result<()> {
        if !self.is_active() {
            bail!("MeshLake adapter is not active");
        }
        for command in address_commands(networks, AddressOperation::Replace)? {
            run_ip(&command)?;
        }
        Ok(())
    }

    pub fn remove_network(&self, joined: &JoinedNetwork) -> Result<()> {
        if !self.is_active() {
            return Ok(());
        }
        for command in address_commands(std::slice::from_ref(joined), AddressOperation::Delete)? {
            let _ = run_ip(&command);
        }
        Ok(())
    }
}

fn publish_session_after_interface_up<T>(
    slot: &mut Option<T>,
    session: T,
    bring_interface_up: impl FnOnce() -> Result<()>,
) -> Result<()> {
    bring_interface_up()?;
    *slot = Some(session);
    Ok(())
}

fn interface_up_command() -> Vec<String> {
    ["link", "set", "dev", INTERFACE_NAME, "up"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn address_commands(
    networks: &[JoinedNetwork],
    operation: AddressOperation,
) -> Result<Vec<Vec<String>>> {
    Ok(planned_addresses(networks)?
        .into_iter()
        .map(|planned| {
            vec![
                "address".to_owned(),
                operation.argument().to_owned(),
                format!("{}/{}", planned.address, planned.prefix_length),
                "dev".to_owned(),
                INTERFACE_NAME.to_owned(),
            ]
        })
        .collect())
}

fn planned_addresses(networks: &[JoinedNetwork]) -> Result<Vec<PlannedAddress>> {
    let mut addresses = BTreeMap::<IpAddr, u8>::new();
    for joined in networks {
        for address in &joined.assigned_addresses {
            let prefix_length = assigned_prefix_length(joined, *address)?;
            match addresses.insert(*address, prefix_length) {
                Some(existing) if existing != prefix_length => {
                    bail!(
                        "assigned address {address} has conflicting prefix lengths {existing} and {prefix_length}"
                    );
                }
                _ => {}
            }
        }
    }
    Ok(addresses
        .into_iter()
        .map(|(address, prefix_length)| PlannedAddress {
            address,
            prefix_length,
        })
        .collect())
}

fn assigned_prefix_length(joined: &JoinedNetwork, address: IpAddr) -> Result<u8> {
    match address {
        IpAddr::V4(address) => {
            let prefix = joined
                .network
                .ipv4_prefix
                .parse::<Ipv4Net>()
                .with_context(|| {
                    format!(
                        "invalid IPv4 prefix for network {}: {}",
                        joined.network.id.0, joined.network.ipv4_prefix
                    )
                })?;
            if !prefix.contains(&address) {
                bail!("assigned IPv4 address {address} is outside network prefix {prefix}");
            }
            Ok(prefix.prefix_len())
        }
        IpAddr::V6(address) => {
            let raw_prefix = joined.network.ipv6_prefix.as_deref().ok_or_else(|| {
                anyhow!(
                    "network {} assigns IPv6 address {address} without an IPv6 prefix",
                    joined.network.id.0
                )
            })?;
            let prefix = raw_prefix.parse::<Ipv6Net>().with_context(|| {
                format!(
                    "invalid IPv6 prefix for network {}: {raw_prefix}",
                    joined.network.id.0
                )
            })?;
            if !prefix.contains(&address) {
                bail!("assigned IPv6 address {address} is outside network prefix {prefix}");
            }
            Ok(prefix.prefix_len())
        }
    }
}

fn run_ip(arguments: &[String]) -> Result<()> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .context("cannot start iproute2 command 'ip'")?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "ip {} failed ({}): {}{}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Kept for a stable constructor interface shared with Windows. Linux ignores it.
pub fn default_wintun_path() -> PathBuf {
    PathBuf::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::{NetworkControlPlane, NetworkId, RelayPolicy, VirtualNetwork};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use uuid::Uuid;

    fn joined_network(
        id: u128,
        ipv4_prefix: &str,
        ipv6_prefix: Option<&str>,
        assigned_addresses: &[&str],
    ) -> JoinedNetwork {
        JoinedNetwork {
            network: VirtualNetwork {
                id: NetworkId(Uuid::from_u128(id)),
                name: format!("network-{id}"),
                ipv4_prefix: ipv4_prefix.to_owned(),
                ipv6_prefix: ipv6_prefix.map(str::to_owned),
                relay_policy: RelayPolicy::Preferred,
            },
            assigned_addresses: assigned_addresses
                .iter()
                .map(|address| address.parse().unwrap())
                .collect(),
            certificate: None,
            network_key: Vec::new(),
            control_plane: NetworkControlPlane::default(),
        }
    }

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn activation_failure_does_not_publish_the_session() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut slot = None;
        let result =
            publish_session_after_interface_up(&mut slot, DropProbe(Arc::clone(&dropped)), || {
                Err(anyhow!("simulated ip link failure"))
            });
        assert!(result.is_err());
        assert!(slot.is_none());
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn plans_deduplicated_dual_stack_addresses() {
        let network = joined_network(
            1,
            "100.64.0.0/24",
            Some("fd00::/64"),
            &["100.64.0.1", "fd00::1", "100.64.0.1", "fd00::1"],
        );
        assert_eq!(
            planned_addresses(&[network]).unwrap(),
            vec![
                PlannedAddress {
                    address: "100.64.0.1".parse().unwrap(),
                    prefix_length: 24,
                },
                PlannedAddress {
                    address: "fd00::1".parse().unwrap(),
                    prefix_length: 64,
                },
            ]
        );
    }

    #[test]
    fn builds_replace_and_delete_commands() {
        let network = joined_network(
            2,
            "100.64.2.0/24",
            Some("fd00:2::/64"),
            &["100.64.2.1", "fd00:2::1"],
        );
        assert_eq!(
            address_commands(std::slice::from_ref(&network), AddressOperation::Replace).unwrap(),
            vec![
                vec!["address", "replace", "100.64.2.1/24", "dev", "meshlake0"],
                vec!["address", "replace", "fd00:2::1/64", "dev", "meshlake0"],
            ]
        );
        assert_eq!(
            address_commands(&[network], AddressOperation::Delete).unwrap(),
            vec![
                vec!["address", "del", "100.64.2.1/24", "dev", "meshlake0"],
                vec!["address", "del", "fd00:2::1/64", "dev", "meshlake0"],
            ]
        );
    }

    #[test]
    fn rejects_invalid_mismatched_and_out_of_network_prefixes() {
        for network in [
            joined_network(3, "100.64.3.0/33", None, &["100.64.3.1"]),
            joined_network(4, "fd00:4::/64", None, &["100.64.4.1"]),
            joined_network(5, "100.64.5.0/24", Some("fd00:5::/129"), &["fd00:5::1"]),
            joined_network(6, "100.64.6.0/24", Some("100.64.6.0/24"), &["fd00:6::1"]),
            joined_network(7, "100.64.7.0/24", None, &["fd00:7::1"]),
            joined_network(8, "100.64.8.0/24", None, &["100.64.9.1"]),
            joined_network(9, "100.64.9.0/24", Some("fd00:9::/64"), &["fd00:10::1"]),
        ] {
            assert!(planned_addresses(&[network]).is_err());
        }
    }

    #[test]
    fn rejects_conflicting_prefixes_for_the_same_address() {
        let first = joined_network(10, "100.64.10.0/24", None, &["100.64.10.1"]);
        let second = joined_network(11, "100.64.10.0/25", None, &["100.64.10.1"]);
        assert!(planned_addresses(&[first, second]).is_err());
    }
}
