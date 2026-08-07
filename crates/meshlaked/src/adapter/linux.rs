//! Linux TUN adapter implementation used by the headless MeshLake agent.

use super::{
    kill_switch::{BootstrapTransport, KillSwitchPlan},
    policy::{apply_policy_transaction, finalize_policy_transaction, PolicyPlan},
};
use crate::exit_gateway::{ExitGatewayPlan, GatewayRoute};
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
    applied_policy: Mutex<PolicyPlan>,
    applied_exit_gateways: Mutex<ExitGatewayPlan>,
    applied_kill_switch: Mutex<KillSwitchPlan>,
}

impl AdapterController {
    pub fn new(_: PathBuf) -> Self {
        Self {
            session: Mutex::new(None),
            applied_policy: Mutex::new(PolicyPlan::default()),
            applied_exit_gateways: Mutex::new(ExitGatewayPlan::default()),
            applied_kill_switch: Mutex::new(KillSwitchPlan::default()),
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
        if let Err(error) = self.rollback_kill_switch() {
            eprintln!("MeshLake could not completely roll back Linux kill-switch rules: {error:#}");
        }
        if let Err(error) = self.rollback_exit_gateways() {
            eprintln!(
                "MeshLake could not completely roll back Linux exit-gateway rules: {error:#}"
            );
        }
        if let Err(error) = self.rollback_policy() {
            eprintln!("MeshLake could not completely roll back Linux route/DNS policy: {error:#}");
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
        self.configure_policy(networks)?;
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

    pub fn configure_policy(&self, networks: &[JoinedNetwork]) -> Result<()> {
        let plan = PolicyPlan::from_networks(networks, now())?;
        if !self.is_active() {
            return Ok(());
        }
        self.reconcile_policy(plan)
    }

    /// Applies explicit local forwarding/NAT rules. These rules are scoped to
    /// MeshLake source prefixes and carry an exact per-network comment, so
    /// teardown never flushes user-managed firewall state.
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
        if let Err(primary) = run_linux_policy_commands(&linux_exit_gateway_commands(
            &previous,
            GatewayOperation::Remove,
        ))
        .and_then(|_| {
            run_linux_policy_commands(&linux_exit_gateway_commands(
                &desired,
                GatewayOperation::Apply,
            ))
        }) {
            let cleanup = run_linux_policy_commands(&linux_exit_gateway_commands(
                &desired,
                GatewayOperation::Remove,
            ));
            let restore = run_linux_policy_commands(&linux_exit_gateway_commands(
                &previous,
                GatewayOperation::Apply,
            ));
            if cleanup.is_err() || restore.is_err() {
                drop(current);
                self.session.lock().expect("adapter lock poisoned").take();
                bail!(
                    "Linux exit-gateway transaction failed: {primary:#}; rollback failed and the adapter was disabled fail closed"
                );
            }
            bail!("Linux exit-gateway transaction failed and the previous rules were restored: {primary:#}");
        }
        *current = desired;
        Ok(())
    }

    /// Installs only MeshLake-owned OUTPUT rules. Exact controller/root/relay
    /// endpoints remain reachable, while all other non-local physical-network
    /// egress is rejected whenever an explicit exit kill switch is selected.
    pub fn configure_kill_switch(&self, desired: KillSwitchPlan) -> Result<()> {
        if !self.is_active() {
            bail!("MeshLake adapter is not active");
        }
        let mut current = self
            .applied_kill_switch
            .lock()
            .expect("kill-switch lock poisoned");
        if *current == desired {
            return Ok(());
        }
        let previous = current.clone();
        if let Err(primary) = run_linux_policy_commands(&linux_kill_switch_commands(
            &previous,
            KillSwitchOperation::Remove,
        ))
        .and_then(|_| {
            run_linux_policy_commands(&linux_kill_switch_commands(
                &desired,
                KillSwitchOperation::Apply,
            ))
        }) {
            let cleanup = run_linux_policy_commands(&linux_kill_switch_commands(
                &desired,
                KillSwitchOperation::Remove,
            ));
            let restore = run_linux_policy_commands(&linux_kill_switch_commands(
                &previous,
                KillSwitchOperation::Apply,
            ));
            if cleanup.is_err() || restore.is_err() {
                drop(current);
                self.session.lock().expect("adapter lock poisoned").take();
                bail!(
                    "Linux kill-switch transaction failed: {primary:#}; rollback failed and the adapter was disabled fail closed"
                );
            }
            bail!("Linux kill-switch transaction failed and the previous rules were restored: {primary:#}");
        }
        *current = desired;
        Ok(())
    }

    fn reconcile_policy(&self, desired: PolicyPlan) -> Result<()> {
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
                run_linux_policy_commands(&linux_policy_commands(
                    &previous,
                    PolicyOperation::Remove,
                ))
                .map_err(|error| error.to_string())
            },
            || {
                run_linux_policy_commands(&linux_policy_commands(&desired, PolicyOperation::Apply))
                    .map_err(|error| error.to_string())
            },
            || {
                run_linux_policy_commands(&linux_policy_commands(&desired, PolicyOperation::Remove))
                    .map_err(|error| error.to_string())
            },
            || {
                run_linux_policy_commands(&linux_policy_commands(&previous, PolicyOperation::Apply))
                    .map_err(|error| error.to_string())
            },
        );
        if let Err(error) = finalize_policy_transaction(&mut current, desired, result) {
            if error.is_fail_closed() {
                drop(current);
                self.session.lock().expect("adapter lock poisoned").take();
                return Err(anyhow!(
                    "Linux policy transaction failed closed and disabled the adapter: {error}"
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
        let result =
            run_linux_policy_commands(&linux_policy_commands(&current, PolicyOperation::Remove));
        *current = PolicyPlan::default();
        result
    }

    fn rollback_exit_gateways(&self) -> Result<()> {
        let mut current = self
            .applied_exit_gateways
            .lock()
            .expect("exit gateway lock poisoned");
        let result = run_linux_policy_commands(&linux_exit_gateway_commands(
            &current,
            GatewayOperation::Remove,
        ));
        *current = ExitGatewayPlan::default();
        result
    }

    fn rollback_kill_switch(&self) -> Result<()> {
        let mut current = self
            .applied_kill_switch
            .lock()
            .expect("kill-switch lock poisoned");
        let result = run_linux_policy_commands(&linux_kill_switch_commands(
            &current,
            KillSwitchOperation::Remove,
        ));
        *current = KillSwitchPlan::default();
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillSwitchOperation {
    Apply,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxPolicyCommand {
    program: &'static str,
    arguments: Vec<String>,
}

fn linux_policy_commands(plan: &PolicyPlan, operation: PolicyOperation) -> Vec<LinuxPolicyCommand> {
    let mut commands = plan
        .routes
        .iter()
        .chain(&plan.exit_routes)
        .map(|route| LinuxPolicyCommand {
            program: "ip",
            arguments: vec![
                "route".into(),
                match operation {
                    PolicyOperation::Apply => "replace",
                    PolicyOperation::Remove => "del",
                }
                .into(),
                route.prefix.clone(),
                "dev".into(),
                INTERFACE_NAME.into(),
            ],
        })
        .collect::<Vec<_>>();
    match operation {
        PolicyOperation::Apply if !plan.dns_servers.is_empty() => {
            commands.push(LinuxPolicyCommand {
                program: "resolvectl",
                arguments: std::iter::once("dns".into())
                    .chain(std::iter::once(INTERFACE_NAME.into()))
                    .chain(plan.dns_servers.iter().map(ToString::to_string))
                    .collect(),
            });
            let mut domains = plan.search_domains.clone();
            if !plan.exit_routes.is_empty() {
                // `~.` gives the MeshLake link ownership of all DNS domains
                // while the signed exit default route is active.
                domains.push("~.".into());
            }
            if !domains.is_empty() {
                commands.push(LinuxPolicyCommand {
                    program: "resolvectl",
                    arguments: std::iter::once("domain".into())
                        .chain(std::iter::once(INTERFACE_NAME.into()))
                        .chain(domains)
                        .collect(),
                });
            }
            commands.push(LinuxPolicyCommand {
                program: "resolvectl",
                arguments: vec![
                    "default-route".into(),
                    INTERFACE_NAME.into(),
                    if plan.exit_routes.is_empty() {
                        "no".into()
                    } else {
                        "yes".into()
                    },
                ],
            });
        }
        PolicyOperation::Remove if !plan.dns_servers.is_empty() => {
            commands.push(LinuxPolicyCommand {
                program: "resolvectl",
                arguments: vec!["revert".into(), INTERFACE_NAME.into()],
            });
        }
        _ => {}
    }
    commands
}

fn linux_exit_gateway_commands(
    plan: &ExitGatewayPlan,
    operation: GatewayOperation,
) -> Vec<LinuxPolicyCommand> {
    let mut commands = Vec::new();
    let mut enabled_ipv4_forwarding = false;
    let mut enabled_ipv6_forwarding = false;
    for route in &plan.routes {
        if matches!(operation, GatewayOperation::Apply) {
            let (sysctl_key, already_enabled) = if route.ipv6 {
                (
                    "net.ipv6.conf.all.forwarding=1",
                    &mut enabled_ipv6_forwarding,
                )
            } else {
                ("net.ipv4.ip_forward=1", &mut enabled_ipv4_forwarding)
            };
            if !*already_enabled {
                commands.push(LinuxPolicyCommand {
                    program: "sysctl",
                    arguments: vec!["-w".into(), sysctl_key.into()],
                });
                *already_enabled = true;
            }
        }
        let program = if route.ipv6 { "ip6tables" } else { "iptables" };
        let operation_argument = match operation {
            GatewayOperation::Apply => "-A",
            GatewayOperation::Remove => "-D",
        };
        let comment = gateway_comment(route);
        commands.push(LinuxPolicyCommand {
            program,
            arguments: vec![
                "-w".into(),
                "-t".into(),
                "nat".into(),
                operation_argument.into(),
                "POSTROUTING".into(),
                "-s".into(),
                route.prefix.clone(),
                "-o".into(),
                route.egress_interface.clone(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                comment.clone(),
                "-j".into(),
                "MASQUERADE".into(),
            ],
        });
        commands.push(LinuxPolicyCommand {
            program,
            arguments: vec![
                "-w".into(),
                operation_argument.into(),
                "FORWARD".into(),
                "-i".into(),
                INTERFACE_NAME.into(),
                "-o".into(),
                route.egress_interface.clone(),
                "-s".into(),
                route.prefix.clone(),
                "-m".into(),
                "conntrack".into(),
                "--ctstate".into(),
                "NEW,ESTABLISHED,RELATED".into(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                comment.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        });
        commands.push(LinuxPolicyCommand {
            program,
            arguments: vec![
                "-w".into(),
                operation_argument.into(),
                "FORWARD".into(),
                "-i".into(),
                route.egress_interface.clone(),
                "-o".into(),
                INTERFACE_NAME.into(),
                "-d".into(),
                route.prefix.clone(),
                "-m".into(),
                "conntrack".into(),
                "--ctstate".into(),
                "ESTABLISHED,RELATED".into(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                comment,
                "-j".into(),
                "ACCEPT".into(),
            ],
        });
    }
    commands
}

fn linux_kill_switch_commands(
    plan: &KillSwitchPlan,
    operation: KillSwitchOperation,
) -> Vec<LinuxPolicyCommand> {
    if !plan.enabled {
        return Vec::new();
    }
    let mut commands = Vec::new();
    for (program, ipv6) in [("iptables", false), ("ip6tables", true)] {
        let family = if ipv6 { "v6" } else { "v4" };
        let rule_operation = match operation {
            KillSwitchOperation::Apply => "-I",
            KillSwitchOperation::Remove => "-D",
        };
        commands.push(LinuxPolicyCommand {
            program,
            arguments: vec![
                "-w".into(),
                rule_operation.into(),
                "OUTPUT".into(),
                "-o".into(),
                INTERFACE_NAME.into(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                format!("meshlake:killswitch:{family}:overlay"),
                "-j".into(),
                "ACCEPT".into(),
            ],
        });
        for endpoint in plan
            .bootstrap_endpoints
            .iter()
            .filter(|endpoint| endpoint.endpoint.is_ipv6() == ipv6)
        {
            let transport = match endpoint.transport {
                BootstrapTransport::Tcp => "tcp",
                BootstrapTransport::Udp => "udp",
            };
            commands.push(LinuxPolicyCommand {
                program,
                arguments: vec![
                    "-w".into(),
                    rule_operation.into(),
                    "OUTPUT".into(),
                    "-d".into(),
                    endpoint.endpoint.ip().to_string(),
                    "-p".into(),
                    transport.into(),
                    "--dport".into(),
                    endpoint.endpoint.port().to_string(),
                    "-m".into(),
                    "comment".into(),
                    "--comment".into(),
                    format!("meshlake:killswitch:{family}:bootstrap"),
                    "-j".into(),
                    "ACCEPT".into(),
                ],
            });
        }
        commands.push(LinuxPolicyCommand {
            program,
            arguments: vec![
                "-w".into(),
                match operation {
                    KillSwitchOperation::Apply => "-A",
                    KillSwitchOperation::Remove => "-D",
                }
                .into(),
                "OUTPUT".into(),
                "!".into(),
                "-o".into(),
                INTERFACE_NAME.into(),
                "-m".into(),
                "addrtype".into(),
                "!".into(),
                "--dst-type".into(),
                "LOCAL".into(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                format!("meshlake:killswitch:{family}:block"),
                "-j".into(),
                "REJECT".into(),
            ],
        });
    }
    commands
}

fn gateway_comment(route: &GatewayRoute) -> String {
    format!(
        "meshlake:{}:{}",
        route.network_id.0,
        if route.ipv6 { "v6" } else { "v4" }
    )
}

fn run_linux_policy_commands(commands: &[LinuxPolicyCommand]) -> Result<()> {
    run_linux_policy_commands_with(commands, |command| {
        let output = Command::new(command.program)
            .args(&command.arguments)
            .output()
            .map_err(|error| format!("cannot start {}: {error}", command.program))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{} {} failed ({}): {}{}",
                command.program,
                command.arguments.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    })
}

fn run_linux_policy_commands_with(
    commands: &[LinuxPolicyCommand],
    mut execute: impl FnMut(&LinuxPolicyCommand) -> std::result::Result<(), String>,
) -> Result<()> {
    let mut failures = Vec::new();
    for command in commands {
        if let Err(error) = execute(command) {
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
    let mut addresses = BTreeMap::<IpAddr, (meshlake_core::NetworkId, u8)>::new();
    for joined in networks {
        for address in &joined.assigned_addresses {
            let prefix_length = assigned_prefix_length(joined, *address)?;
            match addresses.get(address) {
                Some((existing_network, _)) if *existing_network != joined.network.id => {
                    bail!(
                        "assigned address {address} belongs to both network {} and network {}; refusing cross-network address reuse",
                        existing_network.0,
                        joined.network.id.0
                    );
                }
                Some((_, existing_prefix)) if *existing_prefix != prefix_length => {
                    bail!(
                        "assigned address {address} has conflicting prefix lengths {existing_prefix} and {prefix_length}"
                    );
                }
                Some(_) => {}
                None => {
                    addresses.insert(*address, (joined.network.id, prefix_length));
                }
            }
        }
    }
    Ok(addresses
        .into_iter()
        .map(|(address, (_, prefix_length))| PlannedAddress {
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
        let second = joined_network(10, "100.64.10.0/25", None, &["100.64.10.1"]);
        assert!(planned_addresses(&[first, second]).is_err());
    }

    #[test]
    fn deduplicates_the_same_address_for_the_same_network_id() {
        let first = joined_network(
            11,
            "100.64.11.0/24",
            Some("fd00:11::/64"),
            &["100.64.11.1", "fd00:11::1"],
        );
        let duplicate = first.clone();
        assert_eq!(
            planned_addresses(&[first, duplicate]).unwrap(),
            vec![
                PlannedAddress {
                    address: "100.64.11.1".parse().unwrap(),
                    prefix_length: 24,
                },
                PlannedAddress {
                    address: "fd00:11::1".parse().unwrap(),
                    prefix_length: 64,
                },
            ]
        );
    }

    #[test]
    fn rejects_the_same_address_from_distinct_networks_with_the_same_prefix() {
        let first = joined_network(12, "100.64.12.0/24", None, &["100.64.12.1"]);
        let second = joined_network(13, "100.64.12.0/24", None, &["100.64.12.1"]);
        assert!(planned_addresses(&[first, second]).is_err());
    }

    #[test]
    fn builds_linux_route_and_resolved_commands_without_touching_resolv_conf() {
        let plan = PolicyPlan {
            routes: vec![super::super::policy::PlannedRoute {
                prefix: "2001:db8:10::/64".into(),
                network_id: NetworkId(Uuid::from_u128(1)),
                gateway_device_id: meshlake_core::DeviceId(Uuid::from_u128(2)),
            }],
            exit_routes: vec![],
            exit_kill_switch: false,
            dns_servers: vec!["2001:db8:10::53".parse().unwrap()],
            search_domains: vec!["corp.example".into()],
        };
        let commands = linux_policy_commands(&plan, PolicyOperation::Apply);
        assert_eq!(commands[0].program, "ip");
        assert_eq!(
            commands[0].arguments,
            vec!["route", "replace", "2001:db8:10::/64", "dev", "meshlake0"]
        );
        assert!(commands
            .iter()
            .any(|command| command.program == "resolvectl"
                && command
                    .arguments
                    .first()
                    .is_some_and(|argument| argument == "dns")));
        assert!(commands.iter().all(|command| !command
            .arguments
            .iter()
            .any(|argument| argument == "/etc/resolv.conf")));
    }

    #[test]
    fn builds_scoped_linux_nat_and_forwarding_rules_without_flushes() {
        let route = GatewayRoute {
            network_id: NetworkId(Uuid::from_u128(19)),
            prefix: "100.64.19.0/24".into(),
            egress_interface: "eth0".into(),
            ipv6: false,
        };
        let commands = linux_exit_gateway_commands(
            &ExitGatewayPlan {
                routes: vec![route],
            },
            GatewayOperation::Apply,
        );
        assert_eq!(commands[0].program, "sysctl");
        assert_eq!(commands[0].arguments, vec!["-w", "net.ipv4.ip_forward=1"]);
        assert!(commands.iter().any(|command| {
            command.program == "iptables"
                && command
                    .arguments
                    .windows(2)
                    .any(|part| part == ["-t", "nat"])
                && command
                    .arguments
                    .iter()
                    .any(|argument| argument == "MASQUERADE")
                && command
                    .arguments
                    .iter()
                    .any(|argument| argument == "meshlake:00000000-0000-0000-0000-000000000013:v4")
        }));
        assert!(commands.iter().all(|command| !command
            .arguments
            .iter()
            .any(|argument| argument == "-F" || argument == "--flush")));
        let remove = linux_exit_gateway_commands(
            &ExitGatewayPlan {
                routes: vec![GatewayRoute {
                    network_id: NetworkId(Uuid::from_u128(19)),
                    prefix: "100.64.19.0/24".into(),
                    egress_interface: "eth0".into(),
                    ipv6: false,
                }],
            },
            GatewayOperation::Remove,
        );
        assert!(remove.iter().all(|command| command.program != "sysctl"));
        assert!(remove
            .iter()
            .all(|command| command.arguments.iter().any(|argument| argument == "-D")));
    }

    #[test]
    fn builds_exact_linux_kill_switch_exceptions_without_global_flushes() {
        let plan = KillSwitchPlan::new(
            true,
            [
                super::super::kill_switch::BootstrapEndpoint {
                    endpoint: "198.51.100.20:443".parse().unwrap(),
                    transport: BootstrapTransport::Tcp,
                },
                super::super::kill_switch::BootstrapEndpoint {
                    endpoint: "[2001:db8::20]:3478".parse().unwrap(),
                    transport: BootstrapTransport::Udp,
                },
            ],
        )
        .unwrap();
        let apply = linux_kill_switch_commands(&plan, KillSwitchOperation::Apply);
        assert!(apply.iter().any(|command| {
            command.program == "iptables"
                && command
                    .arguments
                    .windows(2)
                    .any(|part| part == ["-d", "198.51.100.20"])
                && command.arguments.iter().any(|argument| argument == "443")
                && command.arguments.iter().any(|argument| argument == "tcp")
        }));
        assert!(apply.iter().any(|command| {
            command.program == "ip6tables"
                && command
                    .arguments
                    .windows(2)
                    .any(|part| part == ["-d", "2001:db8::20"])
                && command.arguments.iter().any(|argument| argument == "3478")
                && command.arguments.iter().any(|argument| argument == "udp")
        }));
        assert!(apply.iter().any(|command| {
            command
                .arguments
                .iter()
                .any(|argument| argument == "REJECT")
                && command
                    .arguments
                    .iter()
                    .any(|argument| argument == "meshlake:killswitch:v4:block")
        }));
        assert!(apply.iter().all(|command| !command
            .arguments
            .iter()
            .any(|argument| argument == "-F" || argument == "--flush")));
        let remove = linux_kill_switch_commands(&plan, KillSwitchOperation::Remove);
        assert!(remove
            .iter()
            .all(|command| command.arguments.iter().any(|argument| argument == "-D")));
    }

    #[test]
    fn linux_command_runner_continues_after_injected_failure() {
        let commands = vec![
            LinuxPolicyCommand {
                program: "ip",
                arguments: vec!["first".into()],
            },
            LinuxPolicyCommand {
                program: "resolvectl",
                arguments: vec!["second".into()],
            },
        ];
        let mut executed = Vec::new();
        let result = run_linux_policy_commands_with(&commands, |command| {
            executed.push(command.program);
            if command.program == "ip" {
                Err("injected Linux command failure".into())
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(executed, vec!["ip", "resolvectl"]);
    }
}
