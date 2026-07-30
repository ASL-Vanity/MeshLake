//! MeshLake authenticated rendezvous root.
//!
//! This service coordinates peer discovery and NAT candidates. It does not
//! receive virtual-network traffic keys and it is not a packet relay.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use meshlake_core::{
    DeviceId, MembershipCertificate, NetworkId, RootPeer, RootRegistration, RootResponse,
    SignedRootResponse,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

const MAX_DATAGRAM_SIZE: usize = 65_507;
const MAX_CERTIFICATES_PER_REGISTRATION: usize = 64;
const MAX_CANDIDATES_PER_PEER: usize = 16;
const MAX_ADDRESSES_PER_PEER: usize = 16;
const MAX_PEERS_PER_RESPONSE: usize = 64;
const REGISTRATION_NONCE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Parser)]
#[command(
    name = "meshlake-root",
    about = "MeshLake authenticated root discovery service"
)]
struct Cli {
    /// Load persistent server settings from a JSON file.
    #[arg(long)]
    config: Option<PathBuf>,
    /// UDP listener reachable by MeshLake clients.
    #[arg(long)]
    bind: Option<SocketAddr>,
    /// Persistent Ed25519 root identity. Generated on first start.
    #[arg(long)]
    identity_file: Option<PathBuf>,
    /// Trusted controller public key in Base64. Repeat for multiple controllers.
    #[arg(long = "controller-public-key-base64")]
    controller_public_keys_base64: Vec<String>,
    /// Remove peers that have not refreshed their registration within this time.
    #[arg(long)]
    peer_ttl_seconds: Option<u64>,
    /// Maximum accepted clock difference for a signed registration.
    #[arg(long)]
    maximum_clock_skew_seconds: Option<u64>,
    /// Save the resolved settings as JSON and exit.
    #[arg(long)]
    write_config: Option<PathBuf>,
    /// Print the root public key and exit.
    #[arg(long)]
    print_public_key: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the root discovery service (the default command).
    Run,
    /// Install, remove or inspect operating-system startup integration.
    Autostart {
        #[command(subcommand)]
        command: AutostartCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AutostartCommand {
    Install,
    Uninstall,
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RootConfig {
    bind: SocketAddr,
    identity_file: PathBuf,
    controller_public_keys_base64: Vec<String>,
    peer_ttl_seconds: u64,
    maximum_clock_skew_seconds: u64,
}

impl Default for RootConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:51819".parse().unwrap(),
            identity_file: default_identity_path(),
            controller_public_keys_base64: Vec::new(),
            peer_ttl_seconds: 90,
            maximum_clock_skew_seconds: 120,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedIdentity {
    schema_version: u32,
    secret_key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PeerRecord {
    candidates: Vec<SocketAddr>,
    assigned_addresses: Vec<IpAddr>,
    certificate: MembershipCertificate,
    last_seen: Instant,
}

type PeerKey = (NetworkId, DeviceId);

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = if let Some(path) = &cli.config {
        serde_json::from_slice::<RootConfig>(
            &fs::read(path).with_context(|| format!("cannot read {}", path.display()))?,
        )
        .with_context(|| format!("invalid root configuration {}", path.display()))?
    } else {
        RootConfig::default()
    };
    if let Some(bind) = cli.bind {
        config.bind = bind;
    }
    if let Some(identity_file) = cli.identity_file {
        config.identity_file = identity_file;
    }
    if !cli.controller_public_keys_base64.is_empty() {
        config.controller_public_keys_base64 = cli.controller_public_keys_base64;
    }
    if let Some(peer_ttl_seconds) = cli.peer_ttl_seconds {
        config.peer_ttl_seconds = peer_ttl_seconds;
    }
    if let Some(maximum_clock_skew_seconds) = cli.maximum_clock_skew_seconds {
        config.maximum_clock_skew_seconds = maximum_clock_skew_seconds;
    }
    if let Some(path) = cli.write_config {
        write_json(&path, &config)?;
        println!("MeshLake root configuration written to {}", path.display());
        return Ok(());
    }
    if let Some(Command::Autostart { command }) = cli.command {
        manage_autostart(command, cli.config.as_deref())?;
        return Ok(());
    }
    let identity_path = config.identity_file.clone();
    let signing_key = load_or_create_identity(&identity_path)?;
    let root_public_key = STANDARD.encode(signing_key.verifying_key().to_bytes());
    if cli.print_public_key {
        println!("{root_public_key}");
        return Ok(());
    }
    if config.controller_public_keys_base64.is_empty() {
        bail!("at least one --controller-public-key-base64 is required when serving requests");
    }
    let trusted_controller_keys = decode_controller_keys(&config.controller_public_keys_base64)?;
    let socket = UdpSocket::bind(config.bind)
        .await
        .with_context(|| format!("cannot bind MeshLake root UDP listener at {}", config.bind))?;
    println!("MeshLake root listening on udp://{}", config.bind);
    println!("Root public key (pin in Planet): {root_public_key}");
    println!("Identity file: {}", identity_path.display());

    let peer_ttl = Duration::from_secs(config.peer_ttl_seconds.clamp(30, 600));
    let maximum_clock_skew_seconds = config.maximum_clock_skew_seconds.clamp(30, 600);
    let mut peers = HashMap::<PeerKey, PeerRecord>::new();
    let mut seen_nonces = HashMap::<[u8; 16], Instant>::new();
    let mut buffer = vec![0_u8; MAX_DATAGRAM_SIZE];
    loop {
        let (size, remote) = socket.recv_from(&mut buffer).await?;
        let Ok(registration) = serde_json::from_slice::<RootRegistration>(&buffer[..size]) else {
            continue;
        };
        let nonce = registration.payload.nonce;
        let response = match process_registration(
            registration,
            remote,
            &trusted_controller_keys,
            maximum_clock_skew_seconds,
            peer_ttl,
            &mut peers,
            &mut seen_nonces,
        ) {
            Ok(response) => response,
            Err(error) => RootResponse::Error {
                message: error.to_string(),
            },
        };
        let signed = SignedRootResponse::sign(nonce, response, &signing_key)?;
        let encoded = serde_json::to_vec(&signed)?;
        if encoded.len() <= MAX_DATAGRAM_SIZE {
            socket.send_to(&encoded, remote).await?;
        }
    }
}

fn process_registration(
    registration: RootRegistration,
    observed_endpoint: SocketAddr,
    trusted_controller_keys: &[Vec<u8>],
    maximum_clock_skew_seconds: u64,
    peer_ttl: Duration,
    peers: &mut HashMap<PeerKey, PeerRecord>,
    seen_nonces: &mut HashMap<[u8; 16], Instant>,
) -> Result<RootResponse> {
    if registration.payload.certificates.len() > MAX_CERTIFICATES_PER_REGISTRATION {
        bail!("registration contains too many memberships");
    }
    registration
        .verify(trusted_controller_keys, now(), maximum_clock_skew_seconds)
        .context("registration authentication failed")?;
    seen_nonces.retain(|_, seen| seen.elapsed() <= REGISTRATION_NONCE_TTL);
    if seen_nonces
        .insert(registration.payload.nonce, Instant::now())
        .is_some()
    {
        bail!("registration nonce was already used");
    }
    peers.retain(|_, peer| peer.last_seen.elapsed() <= peer_ttl);

    let mut candidates = Vec::with_capacity(MAX_CANDIDATES_PER_PEER);
    candidates.push(observed_endpoint);
    candidates.extend(
        registration
            .payload
            .candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.port() != 0 && !candidate.ip().is_unspecified()),
    );
    candidates.sort_unstable();
    candidates.dedup();
    candidates.truncate(MAX_CANDIDATES_PER_PEER);

    let mut memberships = HashMap::<NetworkId, (Vec<IpAddr>, MembershipCertificate)>::new();
    for certificate in &registration.payload.certificates {
        if certificate.claims.assigned_addresses.len() > MAX_ADDRESSES_PER_PEER {
            bail!("membership contains too many virtual addresses");
        }
        if certificate
            .claims
            .assigned_addresses
            .iter()
            .any(|address| address.is_unspecified() || address.is_multicast())
        {
            bail!("membership contains an invalid virtual address");
        }
        let mut addresses = certificate
            .claims
            .assigned_addresses
            .iter()
            .copied()
            .filter(|address| !address.is_unspecified() && !address.is_multicast())
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        if memberships
            .insert(
                certificate.claims.network_id,
                (addresses, certificate.clone()),
            )
            .is_some()
        {
            bail!("registration contains duplicate memberships for one network");
        }
    }
    for (network_id, (addresses, _)) in &memberships {
        let conflict = peers.iter().any(|((peer_network, peer_device), peer)| {
            *peer_network == *network_id
                && *peer_device != registration.payload.device_id
                && peer
                    .assigned_addresses
                    .iter()
                    .any(|address| addresses.contains(address))
        });
        if conflict {
            bail!("registration conflicts with an existing virtual address");
        }
    }
    let mut discovered = peers
        .iter()
        .filter_map(|((network_id, device_id), peer)| {
            (memberships.contains_key(network_id) && *device_id != registration.payload.device_id)
                .then_some(RootPeer {
                    network_id: *network_id,
                    device_id: *device_id,
                    candidates: peer.candidates.clone(),
                    assigned_addresses: peer.certificate.claims.assigned_addresses.clone(),
                    certificate: Some(peer.certificate.clone()),
                })
        })
        .take(MAX_PEERS_PER_RESPONSE)
        .collect::<Vec<_>>();
    discovered.sort_by_key(|peer| (peer.network_id.0, peer.device_id.0));

    for (network_id, (assigned_addresses, certificate)) in memberships {
        peers.insert(
            (network_id, registration.payload.device_id),
            PeerRecord {
                candidates: candidates.clone(),
                assigned_addresses,
                certificate,
                last_seen: Instant::now(),
            },
        );
    }
    Ok(RootResponse::Registered {
        observed_endpoint,
        peers: discovered,
        refresh_after_seconds: (peer_ttl.as_secs() / 3).clamp(10, 60) as u32,
    })
}

fn decode_controller_keys(values: &[String]) -> Result<Vec<Vec<u8>>> {
    values
        .iter()
        .map(|encoded| {
            let key = STANDARD
                .decode(encoded.trim())
                .context("controller public key is not valid Base64")?;
            if key.len() != 32 {
                bail!("controller public key must contain exactly 32 bytes");
            }
            Ok(key)
        })
        .collect()
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("cannot replace {}", path.display()))?;
    }
    fs::rename(&temporary, path).with_context(|| format!("cannot install {}", path.display()))?;
    Ok(())
}

fn load_or_create_identity(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let identity: PersistedIdentity = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("cannot read {}", path.display()))?,
        )
        .with_context(|| format!("invalid root identity {}", path.display()))?;
        let bytes: [u8; 32] = identity
            .secret_key
            .as_slice()
            .try_into()
            .context("root identity secret key must contain exactly 32 bytes")?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
    let mut secret_key = [0_u8; 32];
    getrandom::fill(&mut secret_key)
        .map_err(|error| anyhow::anyhow!("cannot generate root identity: {error:?}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(&PersistedIdentity {
            schema_version: 1,
            secret_key: secret_key.to_vec(),
        })?,
    )
    .with_context(|| format!("cannot write {}", path.display()))?;
    restrict_identity_permissions(path)?;
    Ok(SigningKey::from_bytes(&secret_key))
}

#[cfg(unix)]
fn restrict_identity_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_identity_permissions(_: &Path) -> Result<()> {
    Ok(())
}

fn default_identity_path() -> PathBuf {
    if let Some(directory) = env::var_os("MESHLAKE_STATE_DIR") {
        return PathBuf::from(directory).join("root-identity.json");
    }
    if let Some(directory) = env::var_os("LOCALAPPDATA") {
        return PathBuf::from(directory)
            .join("MeshLake")
            .join("root-identity.json");
    }
    if let Some(directory) = env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(directory)
            .join("meshlake")
            .join("root-identity.json");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().expect("current directory unavailable"))
        .join(".local")
        .join("state")
        .join("meshlake")
        .join("root-identity.json")
}

#[cfg(windows)]
fn manage_autostart(command: AutostartCommand, config_path: Option<&Path>) -> Result<()> {
    const TASK_NAME: &str = "MeshLake Root";
    match command {
        AutostartCommand::Install => {
            let config_path = config_path.context(
                "autostart install requires --config pointing to a persistent root JSON file",
            )?;
            let config_path = fs::canonicalize(config_path)
                .with_context(|| format!("cannot resolve {}", config_path.display()))?;
            let executable =
                env::current_exe().context("cannot locate meshlake-root executable")?;
            let task_command = format!(
                "\"{}\" --config \"{}\" run",
                executable.display(),
                config_path.display()
            );
            let output = std::process::Command::new("schtasks.exe")
                .args([
                    "/Create", "/TN", TASK_NAME, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL",
                    "HIGHEST", "/TR",
                ])
                .arg(task_command)
                .args(["/F"])
                .output()
                .context("cannot start schtasks.exe")?;
            if !output.status.success() {
                bail!(
                    "cannot install MeshLake root startup task: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            println!("MeshLake root startup task installed for system boot.");
        }
        AutostartCommand::Uninstall => {
            let output = std::process::Command::new("schtasks.exe")
                .args(["/Delete", "/TN", TASK_NAME, "/F"])
                .output()
                .context("cannot start schtasks.exe")?;
            if !output.status.success() {
                bail!(
                    "cannot remove MeshLake root startup task: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            println!("MeshLake root startup task removed.");
        }
        AutostartCommand::Status => {
            let status = std::process::Command::new("schtasks.exe")
                .args(["/Query", "/TN", TASK_NAME])
                .status()
                .context("cannot start schtasks.exe")?;
            println!(
                "Autostart: {}",
                if status.success() {
                    "installed"
                } else {
                    "not installed"
                }
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn manage_autostart(command: AutostartCommand, config_path: Option<&Path>) -> Result<()> {
    const UNIT_PATH: &str = "/etc/systemd/system/meshlake-root.service";
    match command {
        AutostartCommand::Install => {
            let config_path = config_path.context(
                "autostart install requires --config pointing to a persistent root JSON file",
            )?;
            let config_path = fs::canonicalize(config_path)
                .with_context(|| format!("cannot resolve {}", config_path.display()))?;
            let executable =
                env::current_exe().context("cannot locate meshlake-root executable")?;
            let unit = format!(
                "[Unit]\nDescription=MeshLake root discovery service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=\"{}\" --config \"{}\" run\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nReadWritePaths={}\n\n[Install]\nWantedBy=multi-user.target\n",
                executable.display(),
                config_path.display(),
                config_path
                    .parent()
                    .context("root config path has no parent directory")?
                    .display()
            );
            fs::write(UNIT_PATH, unit)
                .context("cannot install systemd unit; run this command as root")?;
            run_systemctl(&["daemon-reload"])?;
            run_systemctl(&["enable", "--now", "meshlake-root.service"])?;
            println!("MeshLake root systemd service installed and started.");
        }
        AutostartCommand::Uninstall => {
            let _ = run_systemctl(&["disable", "--now", "meshlake-root.service"]);
            if Path::new(UNIT_PATH).exists() {
                fs::remove_file(UNIT_PATH)
                    .context("cannot remove systemd unit; run this command as root")?;
            }
            run_systemctl(&["daemon-reload"])?;
            println!("MeshLake root systemd service removed.");
        }
        AutostartCommand::Status => {
            let status = std::process::Command::new("systemctl")
                .args(["is-enabled", "meshlake-root.service"])
                .status()
                .context("cannot start systemctl")?;
            println!(
                "Autostart: {}",
                if status.success() {
                    "installed"
                } else {
                    "not installed"
                }
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn run_systemctl(arguments: &[&str]) -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(arguments)
        .output()
        .context("cannot start systemctl")?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "systemctl {} failed ({}): {}{}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use meshlake_core::{MembershipCertificate, MembershipClaims};
    use uuid::Uuid;

    fn test_certificate(
        controller: &SigningKey,
        node: &SigningKey,
        network: NetworkId,
        device: DeviceId,
        address: &str,
    ) -> MembershipCertificate {
        MembershipCertificate::sign(
            MembershipClaims {
                network_id: network,
                device_id: device,
                device_public_key: node.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec![address.parse().unwrap()],
                allowed_routes: vec![],
                issued_at_unix_seconds: now(),
                expires_at_unix_seconds: None,
            },
            controller,
        )
        .unwrap()
    }

    #[test]
    fn registration_returns_existing_peer_on_the_same_network() {
        let controller = SigningKey::from_bytes(&[1_u8; 32]);
        let network = NetworkId(Uuid::from_u128(9));
        let existing_device = DeviceId(Uuid::from_u128(1));
        let existing_node = SigningKey::from_bytes(&[10_u8; 32]);
        let existing_certificate = test_certificate(
            &controller,
            &existing_node,
            network,
            existing_device,
            "100.64.0.1",
        );
        let mut peers = HashMap::new();
        peers.insert(
            (network, existing_device),
            PeerRecord {
                candidates: vec!["198.51.100.1:40000".parse().unwrap()],
                assigned_addresses: vec!["100.64.0.1".parse().unwrap()],
                certificate: existing_certificate.clone(),
                last_seen: Instant::now(),
            },
        );
        let node = SigningKey::from_bytes(&[2_u8; 32]);
        let device = DeviceId(Uuid::from_u128(2));
        let certificate = MembershipCertificate::sign(
            MembershipClaims {
                network_id: network,
                device_id: device,
                device_public_key: node.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.0.2".parse().unwrap()],
                allowed_routes: vec!["100.64.0.0/24".into()],
                issued_at_unix_seconds: now(),
                expires_at_unix_seconds: None,
            },
            &controller,
        )
        .unwrap();
        let registration = RootRegistration::sign(
            device,
            vec![certificate],
            vec!["192.168.1.2:30000".parse().unwrap()],
            now(),
            [7_u8; 16],
            &node,
        )
        .unwrap();
        let mut seen_nonces = HashMap::new();
        let response = process_registration(
            registration,
            "203.0.113.2:41000".parse().unwrap(),
            &[controller.verifying_key().to_bytes().to_vec()],
            120,
            Duration::from_secs(90),
            &mut peers,
            &mut seen_nonces,
        )
        .unwrap();
        let RootResponse::Registered {
            observed_endpoint,
            peers,
            ..
        } = response
        else {
            panic!("expected successful registration");
        };
        assert_eq!(observed_endpoint, "203.0.113.2:41000".parse().unwrap());
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].device_id, existing_device);
        assert_eq!(
            peers[0].assigned_addresses,
            vec!["100.64.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(peers[0].certificate, Some(existing_certificate));
    }

    #[test]
    fn registration_rejects_a_conflicting_virtual_address() {
        let controller = SigningKey::from_bytes(&[3_u8; 32]);
        let network = NetworkId(Uuid::from_u128(19));
        let existing_device = DeviceId(Uuid::from_u128(20));
        let existing_node = SigningKey::from_bytes(&[11_u8; 32]);
        let mut peers = HashMap::from([(
            (network, existing_device),
            PeerRecord {
                candidates: vec!["198.51.100.20:40000".parse().unwrap()],
                assigned_addresses: vec!["100.64.19.2".parse().unwrap()],
                certificate: test_certificate(
                    &controller,
                    &existing_node,
                    network,
                    existing_device,
                    "100.64.19.2",
                ),
                last_seen: Instant::now(),
            },
        )]);
        let node = SigningKey::from_bytes(&[4_u8; 32]);
        let device = DeviceId(Uuid::from_u128(21));
        let certificate = MembershipCertificate::sign(
            MembershipClaims {
                network_id: network,
                device_id: device,
                device_public_key: node.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.19.2".parse().unwrap()],
                allowed_routes: vec!["100.64.19.0/24".into()],
                issued_at_unix_seconds: now(),
                expires_at_unix_seconds: None,
            },
            &controller,
        )
        .unwrap();
        let registration =
            RootRegistration::sign(device, vec![certificate], vec![], now(), [8_u8; 16], &node)
                .unwrap();
        let mut seen_nonces = HashMap::new();
        assert!(process_registration(
            registration,
            "203.0.113.21:41000".parse().unwrap(),
            &[controller.verifying_key().to_bytes().to_vec()],
            120,
            Duration::from_secs(90),
            &mut peers,
            &mut seen_nonces,
        )
        .is_err());
    }

    #[test]
    fn registration_nonce_cannot_be_replayed_from_another_endpoint() {
        let controller = SigningKey::from_bytes(&[5_u8; 32]);
        let node = SigningKey::from_bytes(&[6_u8; 32]);
        let network = NetworkId(Uuid::from_u128(29));
        let device = DeviceId(Uuid::from_u128(30));
        let certificate = MembershipCertificate::sign(
            MembershipClaims {
                network_id: network,
                device_id: device,
                device_public_key: node.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.29.2".parse().unwrap()],
                allowed_routes: vec!["100.64.29.0/24".into()],
                issued_at_unix_seconds: now(),
                expires_at_unix_seconds: None,
            },
            &controller,
        )
        .unwrap();
        let registration =
            RootRegistration::sign(device, vec![certificate], vec![], now(), [9_u8; 16], &node)
                .unwrap();
        let trusted_keys = [controller.verifying_key().to_bytes().to_vec()];
        let mut peers = HashMap::new();
        let mut seen_nonces = HashMap::new();

        process_registration(
            registration.clone(),
            "203.0.113.30:41000".parse().unwrap(),
            &trusted_keys,
            120,
            Duration::from_secs(90),
            &mut peers,
            &mut seen_nonces,
        )
        .unwrap();
        assert!(process_registration(
            registration,
            "203.0.113.31:42000".parse().unwrap(),
            &trusted_keys,
            120,
            Duration::from_secs(90),
            &mut peers,
            &mut seen_nonces,
        )
        .is_err());
        assert_eq!(
            peers.get(&(network, device)).unwrap().candidates[0],
            "203.0.113.30:41000".parse().unwrap()
        );
    }
}
