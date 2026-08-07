mod adapter;
mod data_plane;
mod exit_gateway;
mod port_mapping;
mod session_observability;
mod state_backup_command;
mod transport_health;
mod upnp;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
#[cfg(test)]
use data_plane::ip::network_for_ip_packet;
use data_plane::ip::{
    address_belongs_to_network, is_group_destination, local_device_is_gateway_for,
    outbound_route_for_ip_packet, packet_addresses, peer_is_gateway_for_source,
};
use ed25519_dalek::SigningKey;
use exit_gateway::{ExitGatewayConfig, ExitGatewayPlan};
use meshlake_core::{
    accept_pairwise_handshake, cleanup_stale_state_backup, decode_protected_state_with,
    parse_peer_identity, parse_session_routing_header, recover_protected_state_file,
    restrict_state_file_permissions, session_handshake_id, write_protected_state_file_with,
    AgentStatus, AuthorizationEpochHint, DeviceId, EnrollmentResponse, ExitNodeSelection,
    InitiatorHandshake, JoinedNetwork, MembershipCertificate, MembershipRefreshRequest,
    MembershipRefreshResponse, NetworkAuthorizationManifest, NetworkControlPlane, NetworkId,
    NetworkKey, NetworkPolicyManifest, PairwiseSessionKeys, PeerPathStatus, PlanetManifest,
    PlanetRelay, PlanetRoot, RelayPolicy, ReplayWindow, RootRegistration,
    RootRegistrationServiceKind, RootResponse, ServiceIdentityPolicy, SessionList, SessionPath,
    SessionQueueCounters, SessionSecurityCounters, SessionState, SignedRelayRegistrationAck,
    SignedRootResponse, StateFileLock, StateKeyProvider, StateProtection, TransportStatus,
    UpsertNetworkRequest, VirtualNetwork, AGENT_STATE_PROTECTION_PURPOSE, RELAY_CANDIDATE,
    RELAY_DATA, RELAY_MAGIC, RELAY_MAX_ASSIGNED_ADDRESSES, RELAY_PEER, RELAY_PEER_IDENTITY,
    RELAY_PUNCH, RELAY_PUNCH_ACK, RELAY_REGISTER_ACK, RELAY_REGISTER_ACK_SIGNED,
    RELAY_REGISTER_SIGNED, RELAY_SESSION_DATA, RELAY_SESSION_INIT, RELAY_SESSION_RESPONSE,
};
use reqwest::{Certificate, Client, Url};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    env, fs,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, Notify, RwLock},
};
use transport_health::{
    select_relay_endpoint, EndpointHealthTable, RegistrationSchedule, RegistrationServiceKind,
    RegistrationTarget,
};
use uuid::Uuid;

#[cfg(test)]
use meshlake_core::decode_protected_state;

use session_observability::{SessionObservability, SessionTelemetry};

const LOCAL_API: &str = "127.0.0.1:51821";
const AGENT_STATE_SCHEMA_VERSION: u32 = 4;
const PEER_DIRECTORY_TTL: Duration = Duration::from_secs(120);
const PAIRWISE_SESSION_TTL: Duration = Duration::from_secs(3_600);
const HANDSHAKE_TTL: Duration = Duration::from_secs(10);
const HANDSHAKE_RETRY: Duration = Duration::from_secs(1);
const HANDSHAKE_CLOCK_SKEW_SECONDS: u64 = 120;
const HANDSHAKE_REPLAY_TTL: Duration = Duration::from_secs(300);
const MAX_HANDSHAKE_REPLAY_ENTRIES: usize = 16_384;
const TRANSPORT_TRANSACTION_TTL: Duration = Duration::from_secs(30);
const AUTHORIZATION_REFRESH_INTERVAL: Duration = Duration::from_secs(20);
const PLANET_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const CERTIFICATE_REFRESH_MARGIN_SECONDS: u64 = 300;
const SESSION_QUEUE_CAPACITY: usize = 8;

#[derive(Parser)]
#[command(
    name = "meshlaked",
    about = "MeshLake background overlay-network agent"
)]
struct Cli {
    /// Path to local agent state. The default is %LOCALAPPDATA%\\MeshLake\\agent.json.
    #[arg(long)]
    state_file: Option<PathBuf>,
    /// Linux: encrypt state using exactly 32 raw bytes from this restricted external file.
    #[arg(
        long,
        value_name = "MASTER_KEY_FILE",
        conflicts_with = "state_key_systemd_credential"
    )]
    state_key_file: Option<PathBuf>,
    /// Linux: encrypt state using a named file from systemd's CREDENTIALS_DIRECTORY.
    #[arg(
        long,
        value_name = "CREDENTIAL_NAME",
        conflicts_with = "state_key_file"
    )]
    state_key_systemd_credential: Option<String>,
    /// Linux: allow one explicit startup to migrate legacy plaintext state into the configured encrypted envelope.
    #[arg(long)]
    allow_plaintext_state_migration: bool,
    /// Path to the signed Wintun DLL. Defaults to wintun.dll beside meshlaked.exe.
    #[arg(long)]
    wintun_dll: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Run,
    PrintStatePath,
    /// Export or restore password-protected agent state.
    State {
        #[command(subcommand)]
        command: state_backup_command::StateCommand,
    },
    Autostart {
        #[command(subcommand)]
        command: AutostartCommand,
    },
}

#[derive(Subcommand)]
enum AutostartCommand {
    /// Register meshlaked to start as SYSTEM during Windows boot or as a systemd service.
    Install,
    /// Remove the startup registration created by `autostart install`.
    Uninstall,
    /// Print whether the startup registration exists.
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    schema_version: u32,
    device_id: DeviceId,
    #[serde(default)]
    identity_secret_key: Vec<u8>,
    networks: Vec<JoinedNetwork>,
    #[serde(default)]
    relay_endpoint: Option<SocketAddr>,
    #[serde(default)]
    relay_endpoints: Vec<SocketAddr>,
    #[serde(default)]
    upnp_enabled: bool,
    /// STUN servers (`host:port`) used to discover server-reflexive UDP
    /// candidates. The encrypted relay remains the fallback when no direct
    /// path is possible.
    #[serde(default)]
    stun_servers: Vec<String>,
    #[serde(default)]
    root_servers: Vec<PlanetRoot>,
    #[serde(default)]
    authorizations: HashMap<NetworkId, meshlake_core::NetworkAuthorizationManifest>,
    #[serde(default)]
    planet: Option<PersistedPlanet>,
    #[serde(default)]
    exit_gateways: Vec<ExitGatewayConfig>,
}

/// Enrollment plus the controller public key supplied through a trusted, out-of-band channel.
#[derive(Debug, Clone, Deserialize)]
struct TrustedEnrollment {
    enrollment: EnrollmentResponse,
    controller_public_key: Vec<u8>,
    #[serde(default)]
    control_plane: Option<EnrollmentControlPlane>,
}

#[derive(Debug, Clone, Deserialize)]
struct EnrollmentControlPlane {
    controller_url: String,
    #[serde(default)]
    planet_manifest_url: Option<String>,
    #[serde(default)]
    controller_tls_ca_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RelayConfig {
    endpoint: SocketAddr,
    #[serde(default)]
    enable_upnp: bool,
    #[serde(default)]
    stun_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPlanet {
    manifest_url: String,
    controller_url: String,
    controller_public_key_base64: String,
    #[serde(default)]
    controller_tls_ca_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PlanetConfig {
    manifest_url: String,
    controller_public_key_base64: String,
    #[serde(default)]
    tls_ca_certificate_pem: Option<String>,
}

/// A local, explicit exit-node choice. Controller policy advertises the
/// candidates; it never supplies this request or enables an exit by itself.
#[derive(Debug, Deserialize)]
struct ExitSelectionConfig {
    #[serde(default)]
    ipv4_gateway: Option<DeviceId>,
    #[serde(default)]
    ipv6_gateway: Option<DeviceId>,
    #[serde(default)]
    kill_switch: bool,
}

#[derive(Debug, Deserialize)]
struct ExitGatewayRequest {
    egress_interface: String,
    #[serde(default)]
    enable_ipv4: bool,
    #[serde(default)]
    enable_ipv6: bool,
}

impl From<ExitSelectionConfig> for ExitNodeSelection {
    fn from(config: ExitSelectionConfig) -> Self {
        Self {
            ipv4_gateway: config.ipv4_gateway,
            ipv6_gateway: config.ipv6_gateway,
            kill_switch: config.kill_switch,
        }
    }
}

impl PersistedState {
    fn new() -> Self {
        let mut identity_secret_key = [0_u8; 32];
        getrandom::fill(&mut identity_secret_key)
            .expect("operating-system randomness is required for node identity");
        Self {
            schema_version: AGENT_STATE_SCHEMA_VERSION,
            device_id: DeviceId(Uuid::new_v4()),
            identity_secret_key: identity_secret_key.to_vec(),
            networks: Vec::new(),
            relay_endpoint: None,
            relay_endpoints: Vec::new(),
            upnp_enabled: true,
            stun_servers: Vec::new(),
            root_servers: Vec::new(),
            authorizations: HashMap::new(),
            planet: None,
            exit_gateways: Vec::new(),
        }
    }
}

struct Agent {
    path: PathBuf,
    state_protection: StateProtection,
    _state_lock: StateFileLock,
    state: RwLock<PersistedState>,
    adapter: adapter::AdapterController,
    /// Serializes adapter activation, shutdown, address changes, and state
    /// updates that drive them. When both locks are needed, acquire this before
    /// `state` to avoid lifecycle/state lock inversion.
    adapter_lifecycle: Mutex<()>,
    relay_running: AtomicBool,
    transport_supervisor_running: AtomicBool,
    authorization_supervisor_running: AtomicBool,
    transport_revision: AtomicU64,
    relay_confirmations_accepted: AtomicU64,
    relay_confirmations_rejected: AtomicU64,
    authorization_hint_refreshes: AtomicU64,
    registration_backoff_seconds: AtomicU64,
    shutting_down: AtomicBool,
    transport_health: RwLock<TransportHealth>,
    session_observability: SessionObservability,
    transport_reload: Notify,
    authorization_refresh: Notify,
    shutdown: Notify,
}

#[derive(Debug, Clone, Default)]
struct NetworkTransportConfiguration {
    relay_endpoints: Vec<SocketAddr>,
    relay_identities: HashMap<SocketAddr, ServiceIdentityPolicy>,
    planet_manifest_version: Option<u8>,
    planet_expires_at_unix_seconds: Option<u64>,
    root_servers: Vec<PlanetRoot>,
}

#[derive(Debug, Clone, Default)]
struct TransportConfiguration {
    networks: HashMap<NetworkId, NetworkTransportConfiguration>,
    relay_endpoints: Vec<SocketAddr>,
    root_servers: Vec<PlanetRoot>,
    stun_servers: Vec<String>,
    upnp_enabled: bool,
}

#[derive(Debug, Clone)]
struct AuthorizationRefreshTarget {
    network_id: NetworkId,
    controller_url: String,
    controller_tls_ca_pem: Option<String>,
    pinned_controller_public_key: Vec<u8>,
    certificate: MembershipCertificate,
    authorization_epoch: Option<u64>,
}

#[derive(Debug, Clone)]
struct PlanetRefreshTarget {
    network_id: NetworkId,
    manifest_url: String,
    controller_url: String,
    controller_tls_ca_pem: Option<String>,
    pinned_controller_public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct VerifiedPlanetUpdate {
    version: u8,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    semantic_digest: Vec<u8>,
    controller_url: String,
    roots: Vec<PlanetRoot>,
    relays: Vec<PlanetRelay>,
    stun_servers: Vec<String>,
}

#[derive(Debug, Clone)]
struct RegistrationMembership {
    certificate: MembershipCertificate,
    authorization: NetworkAuthorizationManifest,
}

#[derive(Debug)]
enum AuthorizationRefreshAction {
    Update {
        certificate: MembershipCertificate,
        network_key: Vec<u8>,
        authorization: NetworkAuthorizationManifest,
    },
    UpdateManifest(NetworkAuthorizationManifest),
    Revoke,
}

impl TransportConfiguration {
    fn is_empty(&self) -> bool {
        self.relay_endpoints.is_empty() && self.root_servers.is_empty()
    }

    fn relay_endpoints_for(&self, network_id: NetworkId) -> &[SocketAddr] {
        self.networks
            .get(&network_id)
            .map(|network| network.relay_endpoints.as_slice())
            .unwrap_or_default()
    }

    fn root_servers_for(&self, network_id: NetworkId) -> &[PlanetRoot] {
        self.networks
            .get(&network_id)
            .map(|network| network.root_servers.as_slice())
            .unwrap_or_default()
    }

    fn relay_identity_for(
        &self,
        network_id: NetworkId,
        endpoint: SocketAddr,
    ) -> Option<&ServiceIdentityPolicy> {
        self.networks
            .get(&network_id)?
            .relay_identities
            .get(&endpoint)
    }

    fn planet_manifest_version_for(&self, network_id: NetworkId) -> Option<u8> {
        self.networks.get(&network_id)?.planet_manifest_version
    }

    fn has_expired_planet(&self, now_unix_seconds: u64) -> bool {
        self.networks.values().any(|network| {
            network
                .planet_expires_at_unix_seconds
                .is_some_and(|expiry| now_unix_seconds > expiry)
        })
    }
}

#[derive(Default)]
struct TransportHealth {
    endpoints: EndpointHealthTable,
    peer_paths: Vec<PeerPathStatus>,
}

impl Agent {
    #[cfg(test)]
    fn open(path: PathBuf, wintun_dll: PathBuf) -> Result<Self> {
        Self::open_with_protection(path, wintun_dll, StateProtection::platform_default())
    }

    fn open_with_protection(
        path: PathBuf,
        wintun_dll: PathBuf,
        state_protection: StateProtection,
    ) -> Result<Self> {
        let state_lock = StateFileLock::acquire(&path)?;
        recover_protected_state_file(&path)?;
        if path.exists() {
            restrict_state_file_permissions(&path)?;
        }
        let (mut state, mut state_changed) = if path.exists() {
            let bytes =
                fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            let decoded = decode_protected_state_with(
                &bytes,
                AGENT_STATE_PROTECTION_PURPOSE,
                &state_protection,
            )
            .with_context(|| format!("invalid or unreadable state file {}", path.display()))?;
            (decoded.value, decoded.needs_protection_upgrade)
        } else {
            let state = PersistedState::new();
            write_state_with_protection(&path, &state, &state_protection)?;
            (state, false)
        };
        state_changed |= migrate_and_validate_agent_state(&mut state)?;
        if state_changed {
            write_state_with_protection(&path, &state, &state_protection)?;
        }
        cleanup_stale_state_backup(&path)?;
        let session_observability = SessionObservability::default();
        session_observability.reset(1);
        Ok(Self {
            path,
            state_protection,
            _state_lock: state_lock,
            state: RwLock::new(state),
            adapter: adapter::AdapterController::new(wintun_dll),
            adapter_lifecycle: Mutex::new(()),
            relay_running: AtomicBool::new(false),
            transport_supervisor_running: AtomicBool::new(false),
            authorization_supervisor_running: AtomicBool::new(false),
            transport_revision: AtomicU64::new(1),
            relay_confirmations_accepted: AtomicU64::new(0),
            relay_confirmations_rejected: AtomicU64::new(0),
            authorization_hint_refreshes: AtomicU64::new(0),
            registration_backoff_seconds: AtomicU64::new(0),
            shutting_down: AtomicBool::new(false),
            transport_health: RwLock::new(TransportHealth::default()),
            session_observability,
            transport_reload: Notify::new(),
            authorization_refresh: Notify::new(),
            shutdown: Notify::new(),
        })
    }

    async fn status(&self) -> AgentStatus {
        let state = self.state.read().await;
        let identity_public_key = identity_signing_key(&state)
            .map(|key| key.verifying_key().to_bytes().to_vec())
            .unwrap_or_default();
        let device_id = state.device_id;
        let networks = state.networks.clone();
        let transport_configuration = transport_configuration_from_state(&state);
        let relay_health_requirements = transport_configuration
            .networks
            .iter()
            .flat_map(|(network_id, configuration)| {
                configuration
                    .relay_endpoints
                    .iter()
                    .map(|endpoint| (*network_id, *endpoint))
            })
            .collect::<Vec<_>>();
        let root_health_requirements = transport_configuration
            .networks
            .iter()
            .flat_map(|(network_id, configuration)| {
                configuration.root_servers.iter().flat_map(|root| {
                    root.endpoints
                        .iter()
                        .map(|endpoint| (*network_id, *endpoint))
                })
            })
            .collect::<Vec<_>>();
        let mut configured_roots = transport_configuration
            .root_servers
            .iter()
            .flat_map(|root| root.endpoints.iter().copied())
            .collect::<Vec<_>>();
        configured_roots.sort_unstable();
        configured_roots.dedup();
        let mut configured_relays = transport_configuration.relay_endpoints;
        configured_relays.sort_unstable();
        configured_relays.dedup();
        drop(state);
        let health = self.transport_health.read().await;
        let peer_paths = health.peer_paths.clone();
        let health_time = Instant::now();
        let mut responsive_roots = health
            .endpoints
            .responsive_root_endpoints(&root_health_requirements, health_time);
        responsive_roots.sort_unstable();
        responsive_roots.dedup();
        let mut healthy_relays = health
            .endpoints
            .healthy_relay_endpoints(&relay_health_requirements, health_time);
        healthy_relays.sort_unstable();
        healthy_relays.dedup();
        AgentStatus {
            device_id,
            identity_public_key,
            adapter_state: self.adapter.status(),
            networks,
            transport: TransportStatus {
                worker_running: self.relay_running.load(Ordering::Acquire),
                configured_roots,
                responsive_roots,
                configured_relays,
                healthy_relays,
                relay_confirmations_accepted: self
                    .relay_confirmations_accepted
                    .load(Ordering::Relaxed),
                relay_confirmations_rejected: self
                    .relay_confirmations_rejected
                    .load(Ordering::Relaxed),
                authorization_hint_refreshes: self
                    .authorization_hint_refreshes
                    .load(Ordering::Relaxed),
                registration_backoff_seconds: self
                    .registration_backoff_seconds
                    .load(Ordering::Relaxed),
                peer_paths,
            },
        }
    }

    async fn mark_relay_acknowledged(&self, network_id: NetworkId, endpoint: SocketAddr) {
        self.transport_health
            .write()
            .await
            .endpoints
            .mark_relay_acknowledged(network_id, endpoint, Instant::now());
    }

    async fn mark_root_responsive(&self, network_id: NetworkId, endpoint: SocketAddr) {
        self.transport_health
            .write()
            .await
            .endpoints
            .mark_root_responsive(network_id, endpoint, Instant::now());
    }

    async fn update_peer_paths(&self, peers: &HashMap<PeerKey, PeerRoute>, now: Instant) {
        let mut paths = peers
            .iter()
            .filter_map(|((network_id, device_id), route)| {
                route.best_candidate(now).map(|candidate| PeerPathStatus {
                    network_id: *network_id,
                    device_id: *device_id,
                    endpoint: candidate.endpoint,
                    smoothed_rtt_ms: candidate
                        .smoothed_rtt
                        .map(|rtt| rtt.as_millis().min(u128::from(u64::MAX)) as u64),
                    consecutive_failures: candidate.consecutive_failures,
                })
            })
            .collect::<Vec<_>>();
        paths.sort_by_key(|path| (path.network_id.0, path.device_id.0));
        self.transport_health.write().await.peer_paths = paths;
    }

    async fn configure_relay(&self, config: RelayConfig) -> Result<(), ApiError> {
        let mut state = self.state.write().await;
        state.relay_endpoint = Some(config.endpoint);
        state.relay_endpoints = vec![config.endpoint];
        state.upnp_enabled = config.enable_upnp;
        state.stun_servers = config
            .stun_servers
            .into_iter()
            .map(|server| server.trim().to_owned())
            .filter(|server| !server.is_empty())
            .take(8)
            .collect();
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        drop(state);
        self.request_transport_reload();
        Ok(())
    }

    async fn configure_exit_selection(
        &self,
        network_id: NetworkId,
        selection: ExitNodeSelection,
    ) -> Result<(), ApiError> {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        let mut state = self.state.write().await;
        let index = state
            .networks
            .iter()
            .position(|joined| joined.network.id == network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        validate_exit_selection(&state.networks[index], &selection)?;
        let previous = state.networks[index]
            .control_plane
            .exit_node_selection
            .clone();
        if previous == selection {
            return Ok(());
        }
        state.networks[index].control_plane.exit_node_selection = selection;
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        let networks = state.networks.clone();
        drop(state);
        if let Err(error) = self.adapter.configure_policy(&networks) {
            let mut state = self.state.write().await;
            if let Some(joined) = state
                .networks
                .iter_mut()
                .find(|joined| joined.network.id == network_id)
            {
                joined.control_plane.exit_node_selection = previous;
            }
            write_state_with_protection(&self.path, &state, &self.state_protection)
                .map_err(ApiError::internal)?;
            let rollback_networks = state.networks.clone();
            drop(state);
            if let Err(rollback_error) = self.adapter.configure_policy(&rollback_networks) {
                self.adapter.deactivate();
                return Err(ApiError::internal(format!(
                    "exit selection was rejected by the platform: {error:#}; persisted selection was restored but policy rollback also failed: {rollback_error:#}; adapter was disabled fail closed"
                )));
            }
            return Err(ApiError::bad_request(format!(
                "exit selection was rejected by the platform and the previous policy was restored: {error:#}"
            )));
        }
        Ok(())
    }

    async fn configure_exit_gateway(
        &self,
        network_id: NetworkId,
        request: ExitGatewayRequest,
    ) -> Result<(), ApiError> {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        let mut state = self.state.write().await;
        let joined = state
            .networks
            .iter()
            .find(|joined| joined.network.id == network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        let config = ExitGatewayConfig {
            network_id,
            egress_interface: request.egress_interface,
            enable_ipv4: request.enable_ipv4,
            enable_ipv6: request.enable_ipv6,
        };
        validate_local_exit_gateway(joined, state.device_id, &config)?;
        let previous = state.exit_gateways.clone();
        state
            .exit_gateways
            .retain(|existing| existing.network_id != network_id);
        state.exit_gateways.push(config);
        let plan = ExitGatewayPlan::from_configs(&state.exit_gateways, &state.networks)
            .map_err(ApiError::bad_request)?;
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        drop(state);
        if let Err(error) = self.adapter.configure_exit_gateways(plan) {
            let mut state = self.state.write().await;
            state.exit_gateways = previous;
            let rollback_plan =
                ExitGatewayPlan::from_configs(&state.exit_gateways, &state.networks)
                    .map_err(ApiError::internal)?;
            write_state_with_protection(&self.path, &state, &self.state_protection)
                .map_err(ApiError::internal)?;
            drop(state);
            if let Err(rollback_error) = self.adapter.configure_exit_gateways(rollback_plan) {
                self.adapter.deactivate();
                return Err(ApiError::internal(format!(
                    "exit gateway configuration failed: {error:#}; rollback also failed: {rollback_error:#}; adapter was disabled fail closed"
                )));
            }
            return Err(ApiError::bad_request(format!(
                "exit gateway configuration failed and the previous gateway rules were restored: {error:#}"
            )));
        }
        Ok(())
    }

    async fn remove_exit_gateway(&self, network_id: NetworkId) -> Result<(), ApiError> {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        let mut state = self.state.write().await;
        let previous = state.exit_gateways.clone();
        state
            .exit_gateways
            .retain(|existing| existing.network_id != network_id);
        if state.exit_gateways == previous {
            return Ok(());
        }
        let plan = ExitGatewayPlan::from_configs(&state.exit_gateways, &state.networks)
            .map_err(ApiError::internal)?;
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        drop(state);
        if let Err(error) = self.adapter.configure_exit_gateways(plan) {
            let mut state = self.state.write().await;
            state.exit_gateways = previous;
            let rollback_plan =
                ExitGatewayPlan::from_configs(&state.exit_gateways, &state.networks)
                    .map_err(ApiError::internal)?;
            write_state_with_protection(&self.path, &state, &self.state_protection)
                .map_err(ApiError::internal)?;
            drop(state);
            if let Err(rollback_error) = self.adapter.configure_exit_gateways(rollback_plan) {
                self.adapter.deactivate();
                return Err(ApiError::internal(format!(
                    "exit gateway removal failed: {error:#}; rollback also failed: {rollback_error:#}; adapter was disabled fail closed"
                )));
            }
            return Err(ApiError::internal(format!(
                "exit gateway removal failed and the previous rules were restored: {error:#}"
            )));
        }
        Ok(())
    }

    async fn configure_planet(&self, config: PlanetConfig) -> Result<(), ApiError> {
        let manifest_url = normalize_http_url(&config.manifest_url, "Planet manifest URL")?;
        let tls_ca_requested = config
            .tls_ca_certificate_pem
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if tls_ca_requested && !manifest_url.starts_with("https://") {
            return Err(ApiError::bad_request(
                "a pinned TLS CA requires an https:// Planet manifest URL",
            ));
        }
        let tls_ca_pem = normalize_tls_ca_pem(config.tls_ca_certificate_pem.as_deref())?;
        let pinned_key = STANDARD
            .decode(config.controller_public_key_base64.trim())
            .map_err(ApiError::bad_request)?;
        if pinned_key.len() != 32 {
            return Err(ApiError::bad_request(
                "Planet controller public key must contain exactly 32 bytes",
            ));
        }
        let client = controller_http_client(tls_ca_pem.as_deref(), Duration::from_secs(8))
            .map_err(ApiError::internal)?;
        let manifest = fetch_planet_manifest(&client, &manifest_url)
            .await
            .map_err(ApiError::bad_request)?;
        let baseline = NetworkControlPlane::default();
        let global_update = validate_planet_update(&baseline, &manifest, &pinned_key, None, now())?;
        if tls_ca_pem.is_some() && !global_update.controller_url.starts_with("https://") {
            return Err(ApiError::bad_request(
                "a pinned TLS CA requires an https:// Planet controller URL",
            ));
        }
        let mut state = self.state.write().await;
        let mut candidate = state.clone();
        let mut network_updates = Vec::new();
        for (index, joined) in candidate.networks.iter().enumerate() {
            if joined.control_plane.pinned_controller_public_key != pinned_key {
                continue;
            }
            let update = validate_planet_update(
                &joined.control_plane,
                &manifest,
                &pinned_key,
                joined.control_plane.controller_url.as_deref(),
                now(),
            )?;
            network_updates.push((index, update));
        }
        candidate.relay_endpoints = global_update
            .relays
            .iter()
            .map(|relay| relay.endpoint)
            .collect();
        if candidate.relay_endpoints.is_empty() {
            candidate.relay_endpoints.push(manifest.relay_endpoint);
        }
        candidate.relay_endpoint = candidate.relay_endpoints.first().copied();
        candidate.root_servers = global_update.roots.clone();
        candidate.stun_servers = global_update.stun_servers.clone();
        candidate.planet = Some(PersistedPlanet {
            manifest_url: manifest_url.clone(),
            controller_url: global_update.controller_url.clone(),
            controller_public_key_base64: config.controller_public_key_base64.trim().to_owned(),
            controller_tls_ca_pem: tls_ca_pem.clone(),
        });
        for (index, update) in network_updates {
            apply_configured_planet_update(
                &mut candidate.networks[index].control_plane,
                manifest_url.clone(),
                tls_ca_pem.clone(),
                &update,
            );
        }
        persist_state_candidate(&mut state, candidate, |candidate| {
            write_state_with_protection(&self.path, candidate, &self.state_protection)
        })
        .map_err(ApiError::internal)?;
        drop(state);
        self.request_transport_reload();
        Ok(())
    }

    async fn transport_configuration(&self) -> TransportConfiguration {
        let state = self.state.read().await;
        transport_configuration_from_state(&state)
    }

    fn request_transport_reload(&self) {
        let revision = self.transport_revision.fetch_add(1, Ordering::AcqRel) + 1;
        self.session_observability.reset(revision);
        self.transport_reload.notify_one();
    }

    async fn consider_authorization_hint(&self, hint: &AuthorizationEpochHint) -> bool {
        let state = self.state.read().await;
        let Some(network) = state
            .networks
            .iter()
            .find(|network| network.network.id == hint.network_id)
        else {
            return false;
        };
        if hint
            .verify_from_controller(pinned_controller_key(network), now())
            .is_err()
        {
            return false;
        }
        let current_epoch = network
            .control_plane
            .authorization_manifest
            .as_ref()
            .map(|authorization| authorization.authorization_epoch)
            .unwrap_or_default();
        if hint.authorization_epoch <= current_epoch {
            return false;
        }
        drop(state);
        self.authorization_refresh.notify_one();
        true
    }

    fn sessions(&self) -> SessionList {
        self.session_observability.snapshot()
    }

    async fn relay_snapshot(&self) -> (DeviceId, Vec<JoinedNetwork>) {
        let state = self.state.read().await;
        (state.device_id, state.networks.clone())
    }

    async fn root_registration_material(
        &self,
    ) -> Result<(DeviceId, SigningKey, Vec<RegistrationMembership>)> {
        let state = self.state.read().await;
        let memberships = state
            .networks
            .iter()
            .filter_map(|network| {
                let certificate = network.certificate.clone()?;
                let authorization = verified_authorization_manifest(network, now())?.clone();
                authorization
                    .authorizes(&certificate)
                    .then_some(RegistrationMembership {
                        certificate,
                        authorization,
                    })
            })
            .collect();
        Ok((state.device_id, identity_signing_key(&state)?, memberships))
    }

    async fn authorization_refresh_material(
        &self,
    ) -> Result<(DeviceId, SigningKey, Vec<AuthorizationRefreshTarget>)> {
        let state = self.state.read().await;
        let targets = state
            .networks
            .iter()
            .filter_map(|network| {
                Some(AuthorizationRefreshTarget {
                    network_id: network.network.id,
                    controller_url: network.control_plane.controller_url.clone()?,
                    controller_tls_ca_pem: network.control_plane.controller_tls_ca_pem.clone(),
                    pinned_controller_public_key: (!network
                        .control_plane
                        .pinned_controller_public_key
                        .is_empty())
                    .then(|| network.control_plane.pinned_controller_public_key.clone())?,
                    certificate: network.certificate.clone()?,
                    authorization_epoch: network
                        .control_plane
                        .authorization_manifest
                        .as_ref()
                        .map(|authorization| authorization.authorization_epoch),
                })
            })
            .collect();
        Ok((state.device_id, identity_signing_key(&state)?, targets))
    }

    async fn planet_refresh_targets(&self) -> Vec<PlanetRefreshTarget> {
        let state = self.state.read().await;
        state
            .networks
            .iter()
            .filter_map(|network| {
                Some(PlanetRefreshTarget {
                    network_id: network.network.id,
                    manifest_url: network.control_plane.planet_manifest_url.clone()?,
                    controller_url: network.control_plane.controller_url.clone()?,
                    controller_tls_ca_pem: network.control_plane.controller_tls_ca_pem.clone(),
                    pinned_controller_public_key: (!network
                        .control_plane
                        .pinned_controller_public_key
                        .is_empty())
                    .then(|| network.control_plane.pinned_controller_public_key.clone())?,
                })
            })
            .collect()
    }

    async fn refresh_planets_once(&self, default_client: &reqwest::Client) -> Result<()> {
        for target in self.planet_refresh_targets().await {
            if let Err(error) = self.refresh_one_planet(default_client, &target).await {
                eprintln!(
                    "MeshLake could not refresh Planet for network {}: {error:#}",
                    target.network_id.0
                );
            }
        }
        Ok(())
    }

    async fn refresh_one_planet(
        &self,
        default_client: &reqwest::Client,
        target: &PlanetRefreshTarget,
    ) -> Result<()> {
        let pinned_client = target
            .controller_tls_ca_pem
            .as_deref()
            .map(|pem| controller_http_client(Some(pem), Duration::from_secs(8)))
            .transpose()?;
        let client = pinned_client.as_ref().unwrap_or(default_client);
        let manifest = fetch_planet_manifest(client, &target.manifest_url).await?;
        let mut state = self.state.write().await;
        let Some(index) = state
            .networks
            .iter()
            .position(|network| network.network.id == target.network_id)
        else {
            return Ok(());
        };
        let control_plane = &state.networks[index].control_plane;
        if control_plane.planet_manifest_url.as_deref() != Some(target.manifest_url.as_str())
            || control_plane.controller_url.as_deref() != Some(target.controller_url.as_str())
            || control_plane.controller_tls_ca_pem != target.controller_tls_ca_pem
            || control_plane.pinned_controller_public_key != target.pinned_controller_public_key
        {
            return Ok(());
        }
        let update = validate_planet_update(
            control_plane,
            &manifest,
            &target.pinned_controller_public_key,
            Some(&target.controller_url),
            now(),
        )
        .map_err(|error| anyhow::anyhow!(error.1))?;
        let mut candidate = state.clone();
        let changed = apply_planet_update(
            &mut candidate.networks[index].control_plane,
            Some(target.manifest_url.clone()),
            &update,
        );
        if changed {
            persist_state_candidate(&mut state, candidate, |candidate| {
                write_state_with_protection(&self.path, candidate, &self.state_protection)
            })?;
        }
        drop(state);
        if changed {
            self.request_transport_reload();
        }
        Ok(())
    }

    async fn apply_authorization_action(
        &self,
        target: &AuthorizationRefreshTarget,
        action: AuthorizationRefreshAction,
    ) -> Result<()> {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        let mut state = self.state.write().await;
        let Some(index) = state
            .networks
            .iter()
            .position(|network| network.network.id == target.network_id)
        else {
            return Ok(());
        };
        let current_certificate_id = state.networks[index]
            .certificate
            .as_ref()
            .map(|certificate| certificate.certificate_id);
        if current_certificate_id != Some(target.certificate.certificate_id) {
            return Ok(());
        }

        let reload_transport;
        let mut removed_network = None;
        let previous_exit_gateways = state.exit_gateways.clone();
        match action {
            AuthorizationRefreshAction::UpdateManifest(authorization) => {
                let previous = state.networks[index]
                    .control_plane
                    .authorization_manifest
                    .as_ref();
                reload_transport = previous.is_none_or(|previous| {
                    previous.authorization_epoch != authorization.authorization_epoch
                        || previous.network_key_epoch != authorization.network_key_epoch
                });
                state.networks[index].control_plane.authorization_manifest = Some(authorization);
            }
            AuthorizationRefreshAction::Update {
                certificate,
                network_key,
                authorization,
            } => {
                let joined = &mut state.networks[index];
                joined.assigned_addresses = certificate.claims.assigned_addresses.clone();
                joined.certificate = Some(certificate);
                joined.network_key = network_key;
                joined.control_plane.authorization_manifest = Some(authorization);
                reload_transport = true;
            }
            AuthorizationRefreshAction::Revoke => {
                removed_network = Some(state.networks.remove(index));
                reload_transport = true;
            }
        }
        if removed_network.is_none() {
            if let (Some(policy), Some(authorization)) = (
                state.networks[index].control_plane.policy_manifest.as_ref(),
                state.networks[index]
                    .control_plane
                    .authorization_manifest
                    .as_ref(),
            ) {
                let controller_key = &state.networks[index]
                    .control_plane
                    .pinned_controller_public_key;
                if policy
                    .verify_for_network(
                        state.networks[index].network.id,
                        controller_key,
                        authorization,
                        now(),
                        None,
                    )
                    .is_err()
                {
                    state.networks[index].control_plane.policy_manifest = None;
                }
            }
        }
        let exit_selection_cleared =
            removed_network.is_none() && clear_unusable_exit_selection(&mut state.networks[index]);
        let gateway_networks = state.networks.clone();
        let local_device = state.device_id;
        let exit_gateways_cleared =
            clear_unusable_exit_gateways(&mut state.exit_gateways, &gateway_networks, local_device);
        let exit_gateway_plan =
            ExitGatewayPlan::from_configs(&state.exit_gateways, &state.networks)?;
        write_state_with_protection(&self.path, &state, &self.state_protection)?;
        let networks = state.networks.clone();
        drop(state);

        if reload_transport {
            // Security state changes must invalidate the old peer/session worker
            // even if best-effort operating-system adapter cleanup fails.
            self.request_transport_reload();
        }
        if let Some(removed_network) = removed_network {
            if let Err(error) = self.adapter.remove_network(&removed_network) {
                self.adapter.deactivate();
                anyhow::bail!(
                    "controller revoked network {} but adapter address cleanup failed: {error:#}; adapter was disabled fail closed",
                    removed_network.network.id.0
                );
            }
            if let Err(error) = self.adapter.configure_policy(&networks) {
                self.adapter.deactivate();
                anyhow::bail!(
                    "controller revoked network {} but policy cleanup failed: {error:#}; adapter was disabled fail closed",
                    removed_network.network.id.0
                );
            }
            eprintln!(
                "MeshLake network {} was revoked by its controller and has been disabled",
                removed_network.network.id.0
            );
        } else if reload_transport && self.adapter.is_active() {
            if let Err(error) = self.adapter.configure_networks(&networks) {
                if exit_selection_cleared || exit_gateways_cleared {
                    self.adapter.deactivate();
                    anyhow::bail!(
                        "authorization update withdrew exit privileges but platform policy cleanup failed: {error:#}; adapter was disabled fail closed"
                    );
                }
                return Err(error);
            }
        }
        if let Err(error) = self.adapter.configure_exit_gateways(exit_gateway_plan) {
            if exit_gateways_cleared {
                self.adapter.deactivate();
                anyhow::bail!(
                    "authorization update withdrew a locally enabled exit gateway but gateway-rule cleanup failed: {error:#}; adapter was disabled fail closed"
                );
            }
            let mut state = self.state.write().await;
            state.exit_gateways = previous_exit_gateways;
            write_state_with_protection(&self.path, &state, &self.state_protection)?;
            return Err(anyhow::anyhow!(
                "could not apply local exit-gateway rules after authorization update: {error:#}; persisted local gateway configuration was restored"
            ));
        }
        Ok(())
    }

    async fn refresh_authorizations_once(&self, client: &reqwest::Client) -> Result<()> {
        self.expire_stale_policies().await?;
        let (device_id, identity, targets) = self.authorization_refresh_material().await?;
        for target in targets {
            let pinned_client = match target.controller_tls_ca_pem.as_deref() {
                Some(tls_ca_pem) => {
                    match controller_http_client(Some(tls_ca_pem), Duration::from_secs(8)) {
                        Ok(client) => Some(client),
                        Err(error) => {
                            eprintln!(
                                "MeshLake could not configure pinned TLS for network {}: {error:#}",
                                target.network_id.0
                            );
                            continue;
                        }
                    }
                }
                None => None,
            };
            let client = pinned_client.as_ref().unwrap_or(client);
            match fetch_authorization_action(client, device_id, &identity, &target).await {
                Ok(action) => {
                    if let Err(error) = self.apply_authorization_action(&target, action).await {
                        eprintln!(
                            "MeshLake could not apply authorization update for network {}: {error:#}",
                            target.network_id.0
                        );
                        continue;
                    }
                    if let Err(error) = self.refresh_policy(client, &target).await {
                        eprintln!(
                            "MeshLake could not refresh signed policy for network {}: {error:#}",
                            target.network_id.0
                        );
                    }
                }
                Err(error) => eprintln!(
                    "MeshLake could not refresh authorization for network {}: {error:#}",
                    target.network_id.0
                ),
            }
        }
        Ok(())
    }

    async fn refresh_policy(
        &self,
        default_client: &reqwest::Client,
        target: &AuthorizationRefreshTarget,
    ) -> Result<()> {
        let pinned_client = target
            .controller_tls_ca_pem
            .as_deref()
            .map(|pem| controller_http_client(Some(pem), Duration::from_secs(8)))
            .transpose()?;
        let client = pinned_client.as_ref().unwrap_or(default_client);
        let url = format!(
            "{}/v1/networks/{}/policy",
            target.controller_url.trim_end_matches('/'),
            target.network_id.0
        );
        let response = client
            .get(url)
            .send()
            .await
            .context("cannot fetch network policy")?
            .error_for_status()
            .context("controller rejected network policy request")?;
        let policy = response
            .json::<NetworkPolicyManifest>()
            .await
            .context("controller returned an invalid network policy")?;
        self.apply_policy_manifest(target.network_id, policy).await
    }

    async fn apply_policy_manifest(
        &self,
        network_id: NetworkId,
        policy: NetworkPolicyManifest,
    ) -> Result<()> {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        let mut state = self.state.write().await;
        let index = state
            .networks
            .iter()
            .position(|joined| joined.network.id == network_id)
            .context("network was removed while policy was being fetched")?;
        let joined = &state.networks[index];
        let authorization = joined
            .control_plane
            .authorization_manifest
            .as_ref()
            .context("network has no current authorization manifest")?;
        authorization
            .verify_from_controller(&joined.control_plane.pinned_controller_public_key, now())?;
        let previous = joined.control_plane.policy_manifest.clone();
        let previous_exit_selection = joined.control_plane.exit_node_selection.clone();
        let previous_exit_gateways = state.exit_gateways.clone();
        if let Some(previous) = &previous {
            if policy.policy_epoch < previous.policy_epoch
                || (policy.policy_epoch == previous.policy_epoch
                    && (!same_policy_semantics(&policy, previous)
                        || policy.issued_at_unix_seconds < previous.issued_at_unix_seconds))
            {
                anyhow::bail!("controller attempted a policy rollback or same-epoch mutation");
            }
        }
        policy.verify_for_network(
            network_id,
            &joined.control_plane.pinned_controller_public_key,
            authorization,
            now(),
            previous
                .as_ref()
                .filter(|previous| previous.policy_epoch != policy.policy_epoch)
                .map(|previous| previous.policy_epoch),
        )?;
        if previous.as_ref() == Some(&policy) {
            return Ok(());
        }
        state.networks[index].control_plane.policy_manifest = Some(policy);
        let exit_selection_cleared = clear_unusable_exit_selection(&mut state.networks[index]);
        let gateway_networks = state.networks.clone();
        let local_device = state.device_id;
        let exit_gateways_cleared =
            clear_unusable_exit_gateways(&mut state.exit_gateways, &gateway_networks, local_device);
        let exit_gateway_plan =
            ExitGatewayPlan::from_configs(&state.exit_gateways, &state.networks)?;
        write_state_with_protection(&self.path, &state, &self.state_protection)?;
        let networks = state.networks.clone();
        drop(state);
        if let Err(error) = self.adapter.configure_policy(&networks) {
            if exit_selection_cleared || exit_gateways_cleared {
                // A verified controller policy just withdrew a selected exit.
                // Never restore the old default route while trying to recover
                // from a platform failure; keep the new policy and disable the
                // adapter so traffic cannot continue through a revoked exit.
                self.adapter.deactivate();
                anyhow::bail!(
                    "policy withdrew a selected exit gateway but platform policy application failed: {error:#}; adapter was disabled fail closed"
                );
            }
            let mut state = self.state.write().await;
            if let Some(joined) = state
                .networks
                .iter_mut()
                .find(|joined| joined.network.id == network_id)
            {
                joined.control_plane.policy_manifest = previous;
                joined.control_plane.exit_node_selection = previous_exit_selection;
            }
            state.exit_gateways = previous_exit_gateways;
            write_state_with_protection(&self.path, &state, &self.state_protection)?;
            let rollback_networks = state.networks.clone();
            drop(state);
            if let Err(rollback_error) = self.adapter.configure_policy(&rollback_networks) {
                self.adapter.deactivate();
                anyhow::bail!(
                    "policy application failed: {error:#}; persisted policy was restored but adapter rollback also failed: {rollback_error:#}; adapter was disabled fail closed"
                );
            }
            anyhow::bail!(
                "policy application failed: {error:#}; persisted policy was restored{}",
                if self.adapter.is_active() {
                    " and the previous adapter policy is active"
                } else {
                    " and the adapter is disabled fail closed"
                }
            );
        }
        if let Err(error) = self.adapter.configure_exit_gateways(exit_gateway_plan) {
            if exit_gateways_cleared {
                self.adapter.deactivate();
                anyhow::bail!(
                    "policy withdrew a locally enabled exit gateway but gateway-rule cleanup failed: {error:#}; adapter was disabled fail closed"
                );
            }
            anyhow::bail!("could not apply local exit-gateway rules for the new policy: {error:#}");
        }
        self.request_transport_reload();
        Ok(())
    }

    async fn expire_stale_policies(&self) -> Result<()> {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        let mut state = self.state.write().await;
        let current_time = now();
        let mut changed = false;
        for joined in &mut state.networks {
            if joined
                .control_plane
                .policy_manifest
                .as_ref()
                .is_some_and(|policy| current_time > policy.expires_at_unix_seconds)
            {
                joined.control_plane.policy_manifest = None;
                changed = true;
            }
        }
        let gateway_networks = state.networks.clone();
        let local_device = state.device_id;
        let exit_gateways_cleared =
            clear_unusable_exit_gateways(&mut state.exit_gateways, &gateway_networks, local_device);
        changed |= exit_gateways_cleared;
        if !changed {
            return Ok(());
        }
        write_state_with_protection(&self.path, &state, &self.state_protection)?;
        let networks = state.networks.clone();
        let exit_gateway_plan = ExitGatewayPlan::from_configs(&state.exit_gateways, &networks)?;
        drop(state);
        self.adapter.configure_policy(&networks)?;
        if let Err(error) = self.adapter.configure_exit_gateways(exit_gateway_plan) {
            if exit_gateways_cleared {
                self.adapter.deactivate();
                anyhow::bail!(
                    "an exit policy expired but gateway-rule cleanup failed: {error:#}; adapter was disabled fail closed"
                );
            }
            return Err(error);
        }
        self.request_transport_reload();
        Ok(())
    }

    async fn start_authorization_supervisor(self: &Arc<Self>) -> Result<()> {
        if self
            .authorization_supervisor_running
            .swap(true, Ordering::AcqRel)
        {
            return Ok(());
        }
        let client = controller_http_client(None, Duration::from_secs(8))?;
        let agent = Arc::clone(self);
        tokio::spawn(async move {
            let mut next_planet_refresh = tokio::time::Instant::now();
            loop {
                if agent.shutting_down.load(Ordering::Acquire) {
                    break;
                }
                if let Err(error) = agent.refresh_authorizations_once(&client).await {
                    eprintln!("MeshLake authorization supervisor failed: {error:#}");
                }
                if tokio::time::Instant::now() >= next_planet_refresh {
                    if let Err(error) = agent.refresh_planets_once(&client).await {
                        eprintln!("MeshLake Planet refresh failed: {error:#}");
                    }
                    next_planet_refresh = tokio::time::Instant::now() + PLANET_REFRESH_INTERVAL;
                }
                tokio::select! {
                    _ = tokio::time::sleep(AUTHORIZATION_REFRESH_INTERVAL) => {}
                    _ = agent.authorization_refresh.notified() => {}
                    _ = agent.shutdown.notified() => break,
                }
            }
            agent
                .authorization_supervisor_running
                .store(false, Ordering::Release);
        });
        Ok(())
    }

    async fn start_relay_worker(self: &Arc<Self>) -> Result<()> {
        if self
            .transport_supervisor_running
            .swap(true, Ordering::AcqRel)
        {
            return Ok(());
        }
        let agent = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                if agent.shutting_down.load(Ordering::Acquire) {
                    break;
                }
                let revision = agent.transport_revision.load(Ordering::Acquire);
                agent.session_observability.reset(revision);
                let configuration = agent.transport_configuration().await;
                if configuration.is_empty() {
                    agent.relay_running.store(false, Ordering::Release);
                    tokio::select! {
                        _ = agent.transport_reload.notified() => continue,
                        _ = agent.shutdown.notified() => break,
                    }
                }
                agent.relay_running.store(true, Ordering::Release);
                let result = run_relay_worker(Arc::clone(&agent), configuration, revision).await;
                agent.relay_running.store(false, Ordering::Release);
                agent.session_observability.clear_if_revision(revision);
                *agent.transport_health.write().await = TransportHealth::default();
                if agent.shutting_down.load(Ordering::Acquire) {
                    break;
                }
                if agent.transport_revision.load(Ordering::Acquire) != revision {
                    continue;
                }
                if let Err(error) = result {
                    eprintln!(
                        "MeshLake transport worker failed and will retry in 3 seconds: {error:#}"
                    );
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                    _ = agent.transport_reload.notified() => {}
                    _ = agent.shutdown.notified() => break,
                }
            }
            agent.relay_running.store(false, Ordering::Release);
            let revision = agent.transport_revision.load(Ordering::Acquire);
            agent.session_observability.clear_if_revision(revision);
            agent
                .transport_supervisor_running
                .store(false, Ordering::Release);
            *agent.transport_health.write().await = TransportHealth::default();
        });
        Ok(())
    }

    async fn add_network(&self, request: UpsertNetworkRequest) -> Result<JoinedNetwork, ApiError> {
        request.validate().map_err(ApiError::bad_request)?;
        let mut state = self.state.write().await;
        let id = request.id.unwrap_or(NetworkId(Uuid::new_v4()));
        if state.networks.iter().any(|entry| entry.network.id == id) {
            return Err(ApiError::conflict(
                "this device already belongs to that network",
            ));
        }
        let joined = JoinedNetwork {
            network: VirtualNetwork {
                id,
                name: request.name,
                ipv4_prefix: request.ipv4_prefix,
                ipv6_prefix: request.ipv6_prefix,
                relay_policy: request.relay_policy,
            },
            assigned_addresses: Vec::new(),
            certificate: None,
            network_key: Vec::new(),
            control_plane: NetworkControlPlane::default(),
        };
        state.networks.push(joined.clone());
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        Ok(joined)
    }

    async fn remove_network(&self, id: NetworkId) -> Result<(), ApiError> {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        let mut state = self.state.write().await;
        let joined = state
            .networks
            .iter()
            .find(|entry| entry.network.id == id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("network is not enrolled on this device"))?;
        self.adapter
            .remove_network(&joined)
            .map_err(ApiError::internal)?;
        state.networks.retain(|entry| entry.network.id != id);
        state.authorizations.remove(&id);
        state
            .exit_gateways
            .retain(|gateway| gateway.network_id != id);
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        let networks = state.networks.clone();
        let exit_gateway_plan = ExitGatewayPlan::from_configs(&state.exit_gateways, &networks)
            .map_err(ApiError::internal)?;
        drop(state);
        self.adapter
            .configure_policy(&networks)
            .map_err(ApiError::internal)?;
        self.adapter
            .configure_exit_gateways(exit_gateway_plan)
            .map_err(ApiError::internal)?;
        self.request_transport_reload();
        Ok(())
    }

    async fn enroll_network(
        &self,
        trusted_enrollment: TrustedEnrollment,
    ) -> Result<JoinedNetwork, ApiError> {
        let TrustedEnrollment {
            enrollment,
            controller_public_key,
            control_plane,
        } = trusted_enrollment;
        enrollment
            .certificate
            .verify_from_controller(&controller_public_key, now())
            .map_err(ApiError::bad_request)?;
        enrollment
            .authorization
            .verify_from_controller(&controller_public_key, now())
            .map_err(ApiError::bad_request)?;
        if !enrollment.authorization.authorizes(&enrollment.certificate) {
            return Err(ApiError::bad_request(
                "membership certificate is not active in the controller authorization manifest",
            ));
        }
        NetworkKey::from_slice(&enrollment.network_key).map_err(ApiError::bad_request)?;
        if enrollment.certificate.claims.network_id != enrollment.network.id {
            return Err(ApiError::bad_request(
                "certificate network id does not match enrollment",
            ));
        }
        let existing_control_plane = {
            let state = self.state.read().await;
            if enrollment.certificate.claims.device_id != state.device_id {
                return Err(ApiError::bad_request(
                    "certificate belongs to another device",
                ));
            }
            let local_public_key = identity_signing_key(&state)
                .map_err(ApiError::internal)?
                .verifying_key()
                .to_bytes();
            if enrollment.certificate.claims.device_public_key != local_public_key {
                return Err(ApiError::bad_request(
                    "certificate belongs to a different node identity",
                ));
            }
            state
                .networks
                .iter()
                .find(|entry| entry.network.id == enrollment.network.id)
                .map(|entry| entry.control_plane.clone())
        };
        if let Some(existing) = existing_control_plane.as_ref() {
            let existing_controller_key = if !existing.pinned_controller_public_key.is_empty() {
                existing.pinned_controller_public_key.as_slice()
            } else {
                &[]
            };
            if !existing_controller_key.is_empty()
                && existing_controller_key != controller_public_key.as_slice()
            {
                return Err(ApiError::conflict(
                    "this network id is already pinned to a different controller",
                ));
            }
        }
        let persisted_control_plane = resolve_enrollment_control_plane(
            control_plane,
            &controller_public_key,
            enrollment.authorization.clone(),
            existing_control_plane.as_ref(),
        )
        .await?;
        let _lifecycle = self.adapter_lifecycle.lock().await;
        let mut state = self.state.write().await;
        let joined = JoinedNetwork {
            network: enrollment.network,
            assigned_addresses: enrollment.certificate.claims.assigned_addresses.clone(),
            certificate: Some(enrollment.certificate),
            network_key: enrollment.network_key,
            control_plane: persisted_control_plane,
        };
        let previous = if let Some(index) = state
            .networks
            .iter()
            .position(|entry| entry.network.id == joined.network.id)
        {
            let existing = &state.networks[index];
            let existing_controller_key = if !existing
                .control_plane
                .pinned_controller_public_key
                .is_empty()
            {
                existing
                    .control_plane
                    .pinned_controller_public_key
                    .as_slice()
            } else {
                existing
                    .certificate
                    .as_ref()
                    .map(|certificate| certificate.controller_public_key.as_slice())
                    .unwrap_or_default()
            };
            if !existing_controller_key.is_empty()
                && existing_controller_key != controller_public_key.as_slice()
            {
                return Err(ApiError::conflict(
                    "this network id is already pinned to a different controller",
                ));
            }
            validate_planet_acceptance_metadata(
                &existing.control_plane,
                joined.control_plane.planet_manifest_version,
                joined.control_plane.planet_last_issued_at_unix_seconds,
                &joined.control_plane.planet_semantic_digest,
            )?;
            Some(std::mem::replace(
                &mut state.networks[index],
                joined.clone(),
            ))
        } else {
            state.networks.push(joined.clone());
            None
        };
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        drop(state);
        if self.adapter.is_active() {
            if let Some(previous) = &previous {
                self.adapter
                    .remove_network(previous)
                    .map_err(ApiError::internal)?;
            }
            self.adapter
                .configure_networks(std::slice::from_ref(&joined))
                .map_err(ApiError::internal)?;
        }
        self.request_transport_reload();
        Ok(joined)
    }

    async fn activate_adapter(&self) -> Result<(), ApiError> {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        ensure_adapter_activation_allowed(self.shutting_down.load(Ordering::Acquire))?;
        let state = self.state.read().await;
        let networks = state.networks.clone();
        let exit_gateway_plan = ExitGatewayPlan::from_configs(&state.exit_gateways, &networks)
            .map_err(ApiError::bad_request)?;
        drop(state);
        let was_active = self.adapter.is_active();
        activate_adapter_transaction(
            was_active,
            || self.adapter.activate(),
            || {
                self.adapter.configure_networks(&networks)?;
                self.adapter.configure_exit_gateways(exit_gateway_plan)
            },
            || self.adapter.deactivate(),
        )
        .map_err(ApiError::internal)
    }

    async fn deactivate_adapter(&self) {
        let _lifecycle = self.adapter_lifecycle.lock().await;
        self.adapter.deactivate();
    }
}

fn same_policy_semantics(left: &NetworkPolicyManifest, right: &NetworkPolicyManifest) -> bool {
    left.network_id == right.network_id
        && left.policy_epoch == right.policy_epoch
        && left.dns == right.dns
        && left.routes.len() == right.routes.len()
        && left.routes.iter().zip(&right.routes).all(|(left, right)| {
            left.prefix == right.prefix
                && left.gateway_certificate.claims.device_id
                    == right.gateway_certificate.claims.device_id
        })
        && left.exit_nodes.len() == right.exit_nodes.len()
        && left
            .exit_nodes
            .iter()
            .zip(&right.exit_nodes)
            .all(|(left, right)| {
                left.gateway_certificate.claims.device_id
                    == right.gateway_certificate.claims.device_id
                    && left.supports_ipv4 == right.supports_ipv4
                    && left.supports_ipv6 == right.supports_ipv6
            })
}

fn validate_exit_selection(
    joined: &JoinedNetwork,
    selection: &ExitNodeSelection,
) -> Result<(), ApiError> {
    if selection.kill_switch && selection.ipv4_gateway.is_none() && selection.ipv6_gateway.is_none()
    {
        return Err(ApiError::bad_request(
            "an exit kill switch requires an IPv4 or IPv6 exit gateway selection",
        ));
    }
    if selection.is_empty() {
        return Ok(());
    }
    let policy = joined
        .control_plane
        .policy_manifest
        .as_ref()
        .ok_or_else(|| {
            ApiError::bad_request("fetch a signed network policy before selecting an exit")
        })?;
    let authorization = joined
        .control_plane
        .authorization_manifest
        .as_ref()
        .ok_or_else(|| {
            ApiError::bad_request("fetch current member authorization before selecting an exit")
        })?;
    policy
        .verify_for_network(
            joined.network.id,
            &joined.control_plane.pinned_controller_public_key,
            authorization,
            now(),
            None,
        )
        .map_err(|_| {
            ApiError::bad_request(
                "the signed exit policy is invalid, expired, or no longer authorized",
            )
        })?;
    for (gateway, probe) in [
        (
            selection.ipv4_gateway,
            "192.0.2.1"
                .parse()
                .expect("literal IPv4 exit-selection probe"),
        ),
        (
            selection.ipv6_gateway,
            "2001:db8::1"
                .parse()
                .expect("literal IPv6 exit-selection probe"),
        ),
    ] {
        let Some(gateway) = gateway else {
            continue;
        };
        if !policy.exit_node_supports(gateway, probe) {
            return Err(ApiError::bad_request(
                "the selected device is not an authorized exit gateway for this address family",
            ));
        }
    }
    Ok(())
}

fn validate_local_exit_gateway(
    joined: &JoinedNetwork,
    local_device: DeviceId,
    config: &ExitGatewayConfig,
) -> Result<(), ApiError> {
    if config.network_id != joined.network.id {
        return Err(ApiError::bad_request(
            "exit gateway configuration belongs to another network",
        ));
    }
    let plan =
        ExitGatewayPlan::from_configs(std::slice::from_ref(config), std::slice::from_ref(joined))
            .map_err(ApiError::bad_request)?;
    if plan.routes.is_empty() {
        return Err(ApiError::bad_request(
            "exit gateway configuration enables neither IPv4 nor IPv6",
        ));
    }
    let policy = joined
        .control_plane
        .policy_manifest
        .as_ref()
        .ok_or_else(|| {
            ApiError::bad_request("fetch a signed network policy before enabling an exit gateway")
        })?;
    let authorization = joined
        .control_plane
        .authorization_manifest
        .as_ref()
        .ok_or_else(|| {
            ApiError::bad_request(
                "fetch current member authorization before enabling an exit gateway",
            )
        })?;
    policy
        .verify_for_network(
            joined.network.id,
            &joined.control_plane.pinned_controller_public_key,
            authorization,
            now(),
            None,
        )
        .map_err(|_| {
            ApiError::bad_request(
                "the local exit-gateway policy is invalid, expired, or unauthorized",
            )
        })?;
    if config.enable_ipv4
        && !policy.exit_node_supports(
            local_device,
            "192.0.2.1"
                .parse()
                .expect("literal IPv4 exit-gateway probe"),
        )
    {
        return Err(ApiError::bad_request(
            "this device is not authorized as an IPv4 exit gateway for the network",
        ));
    }
    if config.enable_ipv6
        && !policy.exit_node_supports(
            local_device,
            "2001:db8::1"
                .parse()
                .expect("literal IPv6 exit-gateway probe"),
        )
    {
        return Err(ApiError::bad_request(
            "this device is not authorized as an IPv6 exit gateway for the network",
        ));
    }
    Ok(())
}

/// Removes only the local portions of an exit preference that a newly verified
/// policy no longer authorizes. Controller policy is authoritative for
/// candidates; retaining a revoked local choice would otherwise make a later
/// adapter retry restore an obsolete default route.
fn clear_unusable_exit_selection(joined: &mut JoinedNetwork) -> bool {
    let policy = joined.control_plane.policy_manifest.clone();
    let selection = &mut joined.control_plane.exit_node_selection;
    let Some(policy) = policy.as_ref() else {
        let changed = !selection.is_empty();
        *selection = ExitNodeSelection::default();
        return changed;
    };
    let mut changed = false;
    if selection.ipv4_gateway.is_some_and(|gateway| {
        !policy.exit_node_supports(
            gateway,
            "192.0.2.1".parse().expect("literal IPv4 exit probe"),
        )
    }) {
        selection.ipv4_gateway = None;
        changed = true;
    }
    if selection.ipv6_gateway.is_some_and(|gateway| {
        !policy.exit_node_supports(
            gateway,
            "2001:db8::1".parse().expect("literal IPv6 exit probe"),
        )
    }) {
        selection.ipv6_gateway = None;
        changed = true;
    }
    if selection.ipv4_gateway.is_none() && selection.ipv6_gateway.is_none() && selection.kill_switch
    {
        selection.kill_switch = false;
        changed = true;
    }
    changed
}

fn clear_unusable_exit_gateways(
    gateways: &mut Vec<ExitGatewayConfig>,
    networks: &[JoinedNetwork],
    local_device: DeviceId,
) -> bool {
    let original_len = gateways.len();
    gateways.retain(|gateway| {
        let Some(joined) = networks
            .iter()
            .find(|joined| joined.network.id == gateway.network_id)
        else {
            return false;
        };
        let Some(policy) = joined.control_plane.policy_manifest.as_ref() else {
            return false;
        };
        (!gateway.enable_ipv4
            || policy.exit_node_supports(
                local_device,
                "192.0.2.1"
                    .parse()
                    .expect("literal IPv4 exit-gateway probe"),
            ))
            && (!gateway.enable_ipv6
                || policy.exit_node_supports(
                    local_device,
                    "2001:db8::1"
                        .parse()
                        .expect("literal IPv6 exit-gateway probe"),
                ))
    });
    gateways.len() != original_len
}

fn activate_adapter_transaction<E>(
    was_active: bool,
    activate: impl FnOnce() -> std::result::Result<(), E>,
    configure: impl FnOnce() -> std::result::Result<(), E>,
    rollback: impl FnOnce(),
) -> std::result::Result<(), E> {
    activate()?;
    if let Err(error) = configure() {
        if !was_active {
            rollback();
        }
        return Err(error);
    }
    Ok(())
}

fn ensure_adapter_activation_allowed(shutting_down: bool) -> Result<(), ApiError> {
    if shutting_down {
        return Err(ApiError::conflict("MeshLake agent is shutting down"));
    }
    Ok(())
}

fn identity_signing_key(state: &PersistedState) -> Result<SigningKey> {
    let bytes: [u8; 32] = state
        .identity_secret_key
        .as_slice()
        .try_into()
        .context("node identity secret key is invalid")?;
    Ok(SigningKey::from_bytes(&bytes))
}

async fn resolve_enrollment_control_plane(
    configured: Option<EnrollmentControlPlane>,
    pinned_controller_public_key: &[u8],
    authorization_manifest: meshlake_core::NetworkAuthorizationManifest,
    current: Option<&NetworkControlPlane>,
) -> Result<NetworkControlPlane, ApiError> {
    let mut control_plane = current.cloned().unwrap_or_default();
    control_plane.pinned_controller_public_key = pinned_controller_public_key.to_vec();
    control_plane.authorization_manifest = Some(authorization_manifest);
    let Some(configured) = configured else {
        return Ok(control_plane);
    };
    let controller_url = normalize_http_url(&configured.controller_url, "controller URL")?;
    control_plane.controller_url = Some(controller_url.clone());
    let tls_ca_requested = configured
        .controller_tls_ca_pem
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if tls_ca_requested && !controller_url.starts_with("https://") {
        return Err(ApiError::bad_request(
            "a pinned controller TLS CA requires an https:// controller URL",
        ));
    }
    let manifest_url = configured
        .planet_manifest_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|url| normalize_http_url(url, "Planet manifest URL"))
        .transpose()?;
    if tls_ca_requested
        && manifest_url
            .as_deref()
            .is_some_and(|url| !url.starts_with("https://"))
    {
        return Err(ApiError::bad_request(
            "a pinned controller TLS CA requires an https:// Planet manifest URL",
        ));
    }
    let tls_ca_pem = normalize_tls_ca_pem(configured.controller_tls_ca_pem.as_deref())?;
    control_plane.controller_tls_ca_pem = tls_ca_pem.clone();
    let Some(manifest_url) = manifest_url else {
        return Ok(control_plane);
    };
    let client = controller_http_client(tls_ca_pem.as_deref(), Duration::from_secs(8))
        .map_err(ApiError::internal)?;
    let manifest = fetch_planet_manifest(&client, &manifest_url)
        .await
        .map_err(ApiError::bad_request)?;
    let update = validate_planet_update(
        current.unwrap_or(&control_plane),
        &manifest,
        pinned_controller_public_key,
        Some(&controller_url),
        now(),
    )?;
    if tls_ca_pem.is_some() && !update.controller_url.starts_with("https://") {
        return Err(ApiError::bad_request(
            "a pinned controller TLS CA requires an https:// Planet controller URL",
        ));
    }
    apply_planet_update(&mut control_plane, Some(manifest_url), &update);
    Ok(control_plane)
}

async fn fetch_planet_manifest(
    client: &reqwest::Client,
    manifest_url: &str,
) -> Result<PlanetManifest> {
    let response = client
        .get(manifest_url)
        .send()
        .await
        .with_context(|| format!("cannot fetch Planet manifest from {manifest_url}"))?;
    if !response.status().is_success() {
        anyhow::bail!("Planet manifest request returned {}", response.status());
    }
    response
        .json::<PlanetManifest>()
        .await
        .context("Planet server returned an invalid manifest")
}

fn validate_planet_update(
    current: &NetworkControlPlane,
    manifest: &PlanetManifest,
    pinned_controller_public_key: &[u8],
    expected_controller_url: Option<&str>,
    now_unix_seconds: u64,
) -> Result<VerifiedPlanetUpdate, ApiError> {
    manifest
        .verify_from_controller(pinned_controller_public_key, now_unix_seconds)
        .map_err(ApiError::bad_request)?;
    let controller_url = normalize_http_url(&manifest.controller_url, "Planet controller URL")?;
    if let Some(expected) = expected_controller_url {
        let expected = normalize_http_url(expected, "network controller URL")?;
        if controller_url != expected {
            return Err(ApiError::bad_request(
                "Planet controller URL does not match the enrolled controller URL",
            ));
        }
    }
    let semantic_digest = manifest
        .semantic_digest()
        .map_err(ApiError::bad_request)?
        .to_vec();
    validate_planet_acceptance_metadata(
        current,
        Some(manifest.version),
        Some(manifest.issued_at_unix_seconds),
        &semantic_digest,
    )?;

    let mut roots = manifest.roots.clone();
    roots.sort_by_key(|root| root.priority);
    let mut relays = manifest.relays.clone();
    relays.sort_by_key(|relay| relay.priority);
    if relays.is_empty() {
        relays.push(PlanetRelay {
            endpoint: manifest.relay_endpoint,
            priority: 0,
            identity: None,
        });
    }
    let mut stun_servers = manifest
        .stun_servers
        .iter()
        .map(|server| server.trim().to_owned())
        .filter(|server| !server.is_empty())
        .take(8)
        .collect::<Vec<_>>();
    stun_servers.sort();
    stun_servers.dedup();
    Ok(VerifiedPlanetUpdate {
        version: manifest.version,
        issued_at_unix_seconds: manifest.issued_at_unix_seconds,
        expires_at_unix_seconds: manifest.expires_at_unix_seconds,
        semantic_digest,
        controller_url,
        roots,
        relays,
        stun_servers,
    })
}

fn validate_planet_acceptance_metadata(
    current: &NetworkControlPlane,
    candidate_version: Option<u8>,
    candidate_issued_at: Option<u64>,
    candidate_semantic_digest: &[u8],
) -> Result<(), ApiError> {
    if !current.planet_semantic_digest.is_empty() && current.planet_semantic_digest.len() != 32 {
        return Err(ApiError::bad_request(
            "persisted Planet semantic digest has an invalid length",
        ));
    }
    let Some(previous_version) = current.planet_manifest_version else {
        return Ok(());
    };
    let Some(candidate_version) = candidate_version else {
        return Err(ApiError::bad_request(
            "Planet manifest version rollback was rejected",
        ));
    };
    if candidate_semantic_digest.len() != 32 {
        return Err(ApiError::bad_request(
            "candidate Planet semantic digest has an invalid length",
        ));
    }
    if candidate_version < previous_version {
        return Err(ApiError::bad_request(
            "Planet manifest version rollback was rejected",
        ));
    }
    if let Some(previous_issued_at) = current.planet_last_issued_at_unix_seconds {
        let Some(candidate_issued_at) = candidate_issued_at else {
            return Err(ApiError::bad_request(
                "Planet manifest issued_at rollback was rejected",
            ));
        };
        if candidate_issued_at < previous_issued_at {
            return Err(ApiError::bad_request(
                "Planet manifest issued_at rollback was rejected",
            ));
        }
        if candidate_version == previous_version
            && candidate_issued_at == previous_issued_at
            && !current.planet_semantic_digest.is_empty()
            && current.planet_semantic_digest != candidate_semantic_digest
        {
            return Err(ApiError::bad_request(
                "Planet manifest changed semantics without advancing issued_at",
            ));
        }
    }
    Ok(())
}

fn apply_planet_update(
    control_plane: &mut NetworkControlPlane,
    manifest_url: Option<String>,
    update: &VerifiedPlanetUpdate,
) -> bool {
    let changed = control_plane.planet_manifest_url != manifest_url
        || control_plane.planet_manifest_version != Some(update.version)
        || control_plane.planet_last_issued_at_unix_seconds != Some(update.issued_at_unix_seconds)
        || control_plane.planet_expires_at_unix_seconds != update.expires_at_unix_seconds
        || control_plane.planet_semantic_digest != update.semantic_digest
        || control_plane.controller_url.as_deref() != Some(update.controller_url.as_str())
        || control_plane.verified_roots != update.roots
        || control_plane.verified_relays != update.relays
        || control_plane.verified_stun_servers != update.stun_servers;
    control_plane.planet_manifest_url = manifest_url;
    control_plane.planet_manifest_version = Some(update.version);
    control_plane.planet_last_issued_at_unix_seconds = Some(update.issued_at_unix_seconds);
    control_plane.planet_expires_at_unix_seconds = update.expires_at_unix_seconds;
    control_plane.planet_semantic_digest = update.semantic_digest.clone();
    control_plane.controller_url = Some(update.controller_url.clone());
    control_plane.verified_roots = update.roots.clone();
    control_plane.verified_relays = update.relays.clone();
    control_plane.verified_stun_servers = update.stun_servers.clone();
    changed
}

fn apply_configured_planet_update(
    control_plane: &mut NetworkControlPlane,
    manifest_url: String,
    controller_tls_ca_pem: Option<String>,
    update: &VerifiedPlanetUpdate,
) -> bool {
    let ca_changed = control_plane.controller_tls_ca_pem != controller_tls_ca_pem;
    control_plane.controller_tls_ca_pem = controller_tls_ca_pem;
    let manifest_changed = apply_planet_update(control_plane, Some(manifest_url), update);
    ca_changed || manifest_changed
}

fn normalize_http_url(value: &str, description: &str) -> Result<String, ApiError> {
    let value = value.trim();
    let Some((raw_scheme, authority_and_path)) = value.split_once("://") else {
        return Err(ApiError::bad_request(format!(
            "{description} must start with https:// or http://"
        )));
    };
    let raw_authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if !matches!(raw_scheme.to_ascii_lowercase().as_str(), "https" | "http")
        || authority_and_path.is_empty()
        || authority_and_path.starts_with('/')
        || value.contains('\\')
        || raw_authority.contains('@')
    {
        return Err(ApiError::bad_request(format!(
            "{description} must include a valid HTTP authority"
        )));
    }
    let mut url = Url::parse(value)
        .map_err(|error| ApiError::bad_request(format!("{description} is invalid: {error}")))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(ApiError::bad_request(format!(
            "{description} must start with https:// or http://"
        )));
    }
    if url.host_str().is_none() {
        return Err(ApiError::bad_request(format!(
            "{description} must include a host"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ApiError::bad_request(format!(
            "{description} must not contain credentials"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ApiError::bad_request(format!(
            "{description} must not contain a query or fragment"
        )));
    }
    if url.path().ends_with('/') && url.path() != "/" {
        let path = url.path().trim_end_matches('/').to_owned();
        url.set_path(&path);
    }
    if url.path() == "/" {
        url.set_path("");
    }
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn normalize_tls_ca_pem(value: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 64 * 1024 {
        return Err(ApiError::bad_request(
            "controller TLS CA PEM exceeds the 64 KiB limit",
        ));
    }
    let certificates =
        Certificate::from_pem_bundle(value.as_bytes()).map_err(ApiError::bad_request)?;
    if certificates.is_empty() {
        return Err(ApiError::bad_request(
            "controller TLS CA PEM contains no certificates",
        ));
    }
    Ok(Some(format!("{}\n", value.trim_end())))
}

fn controller_http_client(tls_ca_pem: Option<&str>, timeout: Duration) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(tls_ca_pem) = tls_ca_pem {
        let certificates = Certificate::from_pem_bundle(tls_ca_pem.as_bytes())
            .context("controller TLS CA PEM bundle is invalid")?;
        if certificates.is_empty() {
            anyhow::bail!("controller TLS CA PEM bundle contains no certificates");
        }
        builder = builder.tls_built_in_root_certs(false);
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder
        .build()
        .context("cannot construct controller HTTPS client")
}

fn pinned_controller_key(network: &JoinedNetwork) -> &[u8] {
    if !network
        .control_plane
        .pinned_controller_public_key
        .is_empty()
    {
        &network.control_plane.pinned_controller_public_key
    } else {
        network
            .certificate
            .as_ref()
            .map(|certificate| certificate.controller_public_key.as_slice())
            .unwrap_or_default()
    }
}

fn verified_authorization_manifest(
    network: &JoinedNetwork,
    now_unix_seconds: u64,
) -> Option<&NetworkAuthorizationManifest> {
    let authorization = network.control_plane.authorization_manifest.as_ref()?;
    authorization
        .verify_from_controller(pinned_controller_key(network), now_unix_seconds)
        .ok()?;
    Some(authorization)
}

fn local_network_is_authorized(network: &JoinedNetwork, now_unix_seconds: u64) -> bool {
    let Some(certificate) = network.certificate.as_ref() else {
        return false;
    };
    verified_authorization_manifest(network, now_unix_seconds)
        .is_some_and(|authorization| authorization.authorizes(certificate))
}

fn peer_certificate_is_authorized(
    network: &JoinedNetwork,
    certificate: &MembershipCertificate,
    now_unix_seconds: u64,
) -> bool {
    verified_authorization_manifest(network, now_unix_seconds)
        .is_some_and(|authorization| authorization.authorizes(certificate))
}

async fn fetch_authorization_action(
    client: &reqwest::Client,
    device_id: DeviceId,
    identity: &SigningKey,
    target: &AuthorizationRefreshTarget,
) -> Result<AuthorizationRefreshAction> {
    let authorization_url = format!(
        "{}/v1/networks/{}/authorization",
        target.controller_url.trim_end_matches('/'),
        target.network_id.0
    );
    let response = client
        .get(&authorization_url)
        .send()
        .await
        .with_context(|| format!("cannot contact controller at {authorization_url}"))?;
    if !response.status().is_success() {
        anyhow::bail!(
            "controller authorization request returned {}",
            response.status()
        );
    }
    let authorization: NetworkAuthorizationManifest = response
        .json()
        .await
        .context("controller returned an invalid authorization manifest")?;
    authorization
        .verify_from_controller(&target.pinned_controller_public_key, now())
        .context("controller authorization signature is invalid")?;
    if authorization.network_id != target.network_id {
        anyhow::bail!("controller returned authorization for another network");
    }
    if target
        .authorization_epoch
        .is_some_and(|current| authorization.authorization_epoch < current)
    {
        anyhow::bail!("controller returned an older authorization epoch");
    }

    let active_member = authorization
        .active_members
        .iter()
        .find(|member| member.device_id == device_id);
    let Some(active_member) = active_member else {
        return Ok(AuthorizationRefreshAction::Revoke);
    };
    if active_member.device_public_key != identity.verifying_key().to_bytes()
        || active_member.certificate_id != target.certificate.certificate_id
    {
        return Ok(AuthorizationRefreshAction::Revoke);
    }
    let certificate_expires_soon = target
        .certificate
        .claims
        .expires_at_unix_seconds
        .is_some_and(|expiry| expiry <= now().saturating_add(CERTIFICATE_REFRESH_MARGIN_SECONDS));
    if authorization.authorizes(&target.certificate) && !certificate_expires_soon {
        return Ok(AuthorizationRefreshAction::UpdateManifest(authorization));
    }

    let refresh = MembershipRefreshRequest::sign(
        target.network_id,
        device_id,
        target.certificate.certificate_id,
        now(),
        new_root_nonce(),
        identity,
    )?;
    let refresh_url = format!(
        "{}/v1/membership/refresh",
        target.controller_url.trim_end_matches('/')
    );
    let response = client
        .post(&refresh_url)
        .json(&refresh)
        .send()
        .await
        .with_context(|| format!("cannot refresh membership at {refresh_url}"))?;
    if !response.status().is_success() {
        anyhow::bail!(
            "controller membership refresh returned {}",
            response.status()
        );
    }
    let response: MembershipRefreshResponse = response
        .json()
        .await
        .context("controller returned an invalid membership refresh response")?;
    response
        .authorization
        .verify_from_controller(&target.pinned_controller_public_key, now())
        .context("refreshed authorization signature is invalid")?;
    if response.authorization.network_id != target.network_id {
        anyhow::bail!("refreshed authorization belongs to another network");
    }
    if response.authorization.authorization_epoch < authorization.authorization_epoch {
        anyhow::bail!("membership refresh returned an older authorization epoch");
    }
    if response.revoked {
        let signed_revocation = !response.authorization.active_members.iter().any(|member| {
            member.device_id == device_id
                && member.certificate_id == target.certificate.certificate_id
                && member.device_public_key == identity.verifying_key().to_bytes()
        });
        if signed_revocation {
            return Ok(AuthorizationRefreshAction::Revoke);
        }
        anyhow::bail!("membership refresh revocation is not supported by the signed authorization");
    }
    let certificate = response
        .certificate
        .context("controller refresh response contains no certificate")?;
    certificate
        .verify_from_controller(&target.pinned_controller_public_key, now())
        .context("refreshed membership certificate is invalid")?;
    if certificate.claims.network_id != target.network_id
        || certificate.claims.device_id != device_id
        || certificate.claims.device_public_key != identity.verifying_key().to_bytes()
        || certificate.certificate_id != target.certificate.certificate_id
        || !response.authorization.authorizes(&certificate)
    {
        anyhow::bail!("controller refresh response does not authorize this device");
    }
    NetworkKey::from_slice(&response.network_key)
        .context("controller refresh response contains an invalid network key")?;
    Ok(AuthorizationRefreshAction::Update {
        certificate,
        network_key: response.network_key,
        authorization: response.authorization,
    })
}

fn migrate_legacy_network_control_planes(state: &mut PersistedState) -> bool {
    let legacy_controller_url = state.planet.as_ref().and_then(|planet| {
        normalize_http_url(&planet.controller_url, "legacy Planet controller URL").ok()
    });
    let legacy_manifest_url = state.planet.as_ref().and_then(|planet| {
        normalize_http_url(&planet.manifest_url, "legacy Planet manifest URL").ok()
    });
    let legacy_controller_key = state
        .planet
        .as_ref()
        .and_then(|planet| {
            STANDARD
                .decode(planet.controller_public_key_base64.trim())
                .ok()
        })
        .filter(|key| key.len() == 32);
    let legacy_tls_ca_pem = state
        .planet
        .as_ref()
        .and_then(|planet| planet.controller_tls_ca_pem.clone())
        .filter(|value| !value.trim().is_empty());
    let legacy_tls_urls_are_https = legacy_controller_url
        .as_deref()
        .is_some_and(|url| url.starts_with("https://"))
        && legacy_manifest_url
            .as_deref()
            .is_some_and(|url| url.starts_with("https://"));
    let legacy_relays = state
        .relay_endpoints
        .iter()
        .copied()
        .enumerate()
        .map(|(priority, endpoint)| PlanetRelay {
            endpoint,
            priority: priority.min(u16::MAX as usize) as u16,
            identity: None,
        })
        .collect::<Vec<_>>();
    let mut changed = false;
    for joined in &mut state.networks {
        let control_plane = &mut joined.control_plane;
        let configured_key = (!control_plane.pinned_controller_public_key.is_empty())
            .then_some(control_plane.pinned_controller_public_key.as_slice());
        let certificate_key = joined
            .certificate
            .as_ref()
            .map(|certificate| certificate.controller_public_key.as_slice());
        let normalized_network_controller_url = control_plane
            .controller_url
            .as_deref()
            .and_then(|url| normalize_http_url(url, "network controller URL").ok());
        let legacy_url_is_compatible = match control_plane.controller_url.as_deref() {
            None => true,
            Some(_) => {
                normalized_network_controller_url.as_deref() == legacy_controller_url.as_deref()
            }
        };
        let legacy_binding_is_safe = legacy_url_is_compatible
            && legacy_controller_url.is_some()
            && legacy_controller_key.as_ref().is_some_and(|legacy_key| {
                [configured_key, certificate_key]
                    .into_iter()
                    .flatten()
                    .all(|key| key.len() == 32 && key == legacy_key.as_slice())
            });
        if control_plane.controller_url.is_none() && legacy_binding_is_safe {
            if let Some(controller_url) = &legacy_controller_url {
                control_plane.controller_url = Some(controller_url.clone());
                changed = true;
            }
        }
        if control_plane.pinned_controller_public_key.is_empty() && legacy_binding_is_safe {
            let key = certificate_key
                .filter(|key| key.len() == 32)
                .map(ToOwned::to_owned)
                .or_else(|| legacy_controller_key.clone());
            if let Some(key) = key {
                control_plane.pinned_controller_public_key = key;
                changed = true;
            }
        }
        let uses_legacy_controller = legacy_binding_is_safe
            && control_plane
                .controller_url
                .as_deref()
                .and_then(|url| normalize_http_url(url, "network controller URL").ok())
                .zip(legacy_controller_url.as_deref())
                .is_some_and(|(network, legacy)| network == legacy)
            && legacy_controller_key.as_ref().is_some_and(|legacy_key| {
                control_plane.pinned_controller_public_key == *legacy_key
            });
        if uses_legacy_controller {
            if control_plane.controller_tls_ca_pem.is_none()
                && (legacy_tls_ca_pem.is_none() || legacy_tls_urls_are_https)
            {
                if let Some(tls_ca_pem) = &legacy_tls_ca_pem {
                    control_plane.controller_tls_ca_pem = Some(tls_ca_pem.clone());
                    changed = true;
                }
            }
            if control_plane.planet_manifest_url.is_none() {
                if let Some(manifest_url) = &legacy_manifest_url {
                    control_plane.planet_manifest_url = Some(manifest_url.clone());
                    changed = true;
                }
            }
            if control_plane.verified_roots.is_empty() && !state.root_servers.is_empty() {
                control_plane.verified_roots = state.root_servers.clone();
                changed = true;
            }
            if control_plane.verified_relays.is_empty() && !legacy_relays.is_empty() {
                control_plane.verified_relays = legacy_relays.clone();
                changed = true;
            }
            if control_plane.verified_stun_servers.is_empty() && !state.stun_servers.is_empty() {
                control_plane.verified_stun_servers = state.stun_servers.clone();
                changed = true;
            }
        }
        if control_plane.authorization_manifest.is_none() {
            if let Some(authorization) = state.authorizations.get(&joined.network.id).cloned() {
                control_plane.authorization_manifest = Some(authorization);
                changed = true;
            }
        }
        changed |= migrate_planet_acceptance_metadata(control_plane);
    }
    if !state.authorizations.is_empty()
        && state.networks.iter().all(|joined| {
            !state.authorizations.contains_key(&joined.network.id)
                || joined.control_plane.authorization_manifest.is_some()
        })
    {
        state.authorizations.clear();
        changed = true;
    }
    changed
}

fn migrate_planet_acceptance_metadata(control_plane: &mut NetworkControlPlane) -> bool {
    if control_plane.verified_relays.is_empty()
        || control_plane.controller_url.is_none()
        || control_plane.pinned_controller_public_key.len() != 32
    {
        return false;
    }
    let mut changed = false;
    let inferred_version = if control_plane
        .verified_relays
        .iter()
        .all(|relay| relay.identity.is_some())
        && control_plane
            .verified_roots
            .iter()
            .all(|root| root.identity.is_some())
    {
        3
    } else {
        2
    };
    if control_plane.planet_manifest_version.is_none() {
        control_plane.planet_manifest_version = Some(inferred_version);
        changed = true;
    }
    if control_plane.planet_last_issued_at_unix_seconds.is_none() {
        control_plane.planet_last_issued_at_unix_seconds = Some(0);
        changed = true;
    }
    if control_plane.planet_semantic_digest.is_empty() {
        let mut roots = control_plane.verified_roots.clone();
        roots.sort_by_key(|root| root.priority);
        let mut relays = control_plane.verified_relays.clone();
        relays.sort_by_key(|relay| relay.priority);
        let mut stun_servers = control_plane.verified_stun_servers.clone();
        stun_servers.sort();
        stun_servers.dedup();
        let manifest = PlanetManifest {
            version: control_plane
                .planet_manifest_version
                .unwrap_or(inferred_version),
            controller_url: control_plane.controller_url.clone().unwrap_or_default(),
            relay_endpoint: relays[0].endpoint,
            roots,
            relays,
            stun_servers,
            issued_at_unix_seconds: 0,
            expires_at_unix_seconds: None,
            controller_public_key: control_plane.pinned_controller_public_key.clone(),
            signature: Vec::new(),
        };
        if let Ok(digest) = manifest.semantic_digest() {
            control_plane.planet_semantic_digest = digest.to_vec();
            changed = true;
        }
    }
    changed
}

fn discard_invalid_persisted_policies(state: &mut PersistedState, current_time: u64) -> bool {
    let mut changed = false;
    for joined in &mut state.networks {
        let Some(policy) = joined.control_plane.policy_manifest.as_ref() else {
            continue;
        };
        let valid = joined
            .control_plane
            .authorization_manifest
            .as_ref()
            .is_some_and(|authorization| {
                authorization
                    .verify_from_controller(
                        &joined.control_plane.pinned_controller_public_key,
                        current_time,
                    )
                    .is_ok()
                    && policy
                        .verify_for_network(
                            joined.network.id,
                            &joined.control_plane.pinned_controller_public_key,
                            authorization,
                            current_time,
                            None,
                        )
                        .is_ok()
            });
        if !valid {
            joined.control_plane.policy_manifest = None;
            changed = true;
        }
    }
    changed
}

fn transport_configuration_from_state(state: &PersistedState) -> TransportConfiguration {
    let current_time = now();
    let mut legacy_relays = state.relay_endpoints.clone();
    if legacy_relays.is_empty() {
        legacy_relays.extend(state.relay_endpoint);
    }
    legacy_relays.dedup();

    let mut configuration = TransportConfiguration {
        upnp_enabled: state.upnp_enabled,
        stun_servers: state
            .stun_servers
            .iter()
            .map(|server| server.trim().to_owned())
            .filter(|server| !server.is_empty())
            .collect(),
        ..TransportConfiguration::default()
    };

    for joined in &state.networks {
        let planet_expired = joined
            .control_plane
            .planet_expires_at_unix_seconds
            .is_some_and(|expiry| current_time > expiry);
        let planet_was_accepted = joined.control_plane.planet_manifest_version.is_some();
        let mut relays = if planet_expired {
            Vec::new()
        } else {
            joined.control_plane.verified_relays.clone()
        };
        relays.sort_by_key(|relay| relay.priority);
        let relay_identities = relays
            .iter()
            .filter_map(|relay| Some((relay.endpoint, relay.identity.clone()?)))
            .collect::<HashMap<_, _>>();
        let mut relay_endpoints = relays
            .iter()
            .map(|relay| relay.endpoint)
            .collect::<Vec<_>>();
        if relay_endpoints.is_empty() && !planet_was_accepted {
            relay_endpoints = legacy_relays.clone();
        }
        relay_endpoints.dedup();

        let mut root_servers = if planet_expired {
            Vec::new()
        } else {
            joined.control_plane.verified_roots.clone()
        };
        root_servers.sort_by_key(|root| root.priority);
        if root_servers.is_empty() && !planet_was_accepted {
            root_servers = state.root_servers.clone();
            root_servers.sort_by_key(|root| root.priority);
        }

        for endpoint in &relay_endpoints {
            if !configuration.relay_endpoints.contains(endpoint) {
                configuration.relay_endpoints.push(*endpoint);
            }
        }
        for root in &root_servers {
            if !configuration.root_servers.contains(root) {
                configuration.root_servers.push(root.clone());
            }
        }
        for server in joined
            .control_plane
            .verified_stun_servers
            .iter()
            .filter(|_| !planet_expired)
        {
            let server = server.trim();
            if !server.is_empty()
                && !configuration
                    .stun_servers
                    .iter()
                    .any(|configured| configured == server)
            {
                configuration.stun_servers.push(server.to_owned());
            }
        }
        configuration.networks.insert(
            joined.network.id,
            NetworkTransportConfiguration {
                relay_endpoints,
                relay_identities,
                planet_manifest_version: joined.control_plane.planet_manifest_version,
                planet_expires_at_unix_seconds: (!planet_expired)
                    .then_some(joined.control_plane.planet_expires_at_unix_seconds)
                    .flatten(),
                root_servers,
            },
        );
    }

    if state.networks.is_empty() {
        configuration.relay_endpoints = legacy_relays;
        configuration.root_servers = state.root_servers.clone();
        configuration.root_servers.sort_by_key(|root| root.priority);
    }
    configuration.stun_servers.sort();
    configuration.stun_servers.dedup();
    configuration
}

fn write_state_with_protection(
    path: &FsPath,
    state: &PersistedState,
    protection: &StateProtection,
) -> Result<()> {
    write_protected_state_file_with(path, state, AGENT_STATE_PROTECTION_PURPOSE, protection)
        .map_err(Into::into)
}

#[cfg(test)]
fn write_state(path: &FsPath, state: &PersistedState) -> Result<()> {
    write_state_with_protection(path, state, &StateProtection::platform_default())
}

fn persist_state_candidate(
    live: &mut PersistedState,
    candidate: PersistedState,
    persist: impl FnOnce(&PersistedState) -> Result<()>,
) -> Result<()> {
    persist(&candidate)?;
    *live = candidate;
    Ok(())
}

fn migrate_and_validate_agent_state(state: &mut PersistedState) -> Result<bool> {
    if state.schema_version > AGENT_STATE_SCHEMA_VERSION {
        anyhow::bail!(
            "agent state schema {} is newer than supported schema {}",
            state.schema_version,
            AGENT_STATE_SCHEMA_VERSION
        );
    }
    let mut changed = false;
    if state.identity_secret_key.len() != 32 {
        if state.schema_version >= AGENT_STATE_SCHEMA_VERSION {
            anyhow::bail!(
                "agent state contains an invalid node identity key; refusing automatic identity rotation"
            );
        }
        let mut identity_secret_key = [0_u8; 32];
        getrandom::fill(&mut identity_secret_key)
            .map_err(|error| anyhow::anyhow!("cannot generate node identity: {error:?}"))?;
        state.identity_secret_key = identity_secret_key.to_vec();
        changed = true;
    }
    for network in &state.networks {
        if network.network_key.len() != 32 {
            anyhow::bail!(
                "agent network {} contains an invalid network key",
                network.network.id.0
            );
        }
    }
    if state.relay_endpoints.is_empty() {
        if let Some(endpoint) = state.relay_endpoint {
            state.relay_endpoints.push(endpoint);
            changed = true;
        }
    }
    if migrate_legacy_network_control_planes(state) {
        changed = true;
    }
    if discard_invalid_persisted_policies(state, now()) {
        changed = true;
    }
    for joined in &mut state.networks {
        if clear_unusable_exit_selection(joined) {
            changed = true;
        }
    }
    if clear_unusable_exit_gateways(&mut state.exit_gateways, &state.networks, state.device_id) {
        changed = true;
    }
    ExitGatewayPlan::from_configs(&state.exit_gateways, &state.networks).context(
        "agent state contains an invalid local exit-gateway configuration; refusing to restore platform forwarding",
    )?;
    if state.schema_version < AGENT_STATE_SCHEMA_VERSION {
        state.schema_version = AGENT_STATE_SCHEMA_VERSION;
        changed = true;
    }
    Ok(changed)
}

#[derive(Debug)]
struct ApiError(StatusCode, String);
impl ApiError {
    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self(StatusCode::BAD_REQUEST, error.to_string())
    }
    fn conflict(error: impl Into<String>) -> Self {
        Self(StatusCode::CONFLICT, error.into())
    }
    fn not_found(error: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, error.into())
    }
    fn internal(error: impl std::fmt::Display) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.0, self.1).into_response()
    }
}

async fn get_status(State(agent): State<Arc<Agent>>) -> Json<AgentStatus> {
    Json(agent.status().await)
}
async fn list_sessions(State(agent): State<Arc<Agent>>) -> Json<SessionList> {
    Json(agent.sessions())
}
async fn list_networks(State(agent): State<Arc<Agent>>) -> Json<Vec<JoinedNetwork>> {
    Json(agent.status().await.networks)
}
async fn create_network(
    State(agent): State<Arc<Agent>>,
    Json(request): Json<UpsertNetworkRequest>,
) -> Result<(StatusCode, Json<JoinedNetwork>), ApiError> {
    let joined = agent.add_network(request).await?;
    Ok((StatusCode::CREATED, Json(joined)))
}
async fn enroll_network(
    State(agent): State<Arc<Agent>>,
    Json(enrollment): Json<TrustedEnrollment>,
) -> Result<(StatusCode, Json<JoinedNetwork>), ApiError> {
    let joined = agent.enroll_network(enrollment).await?;
    Ok((StatusCode::CREATED, Json(joined)))
}
async fn configure_relay(
    State(agent): State<Arc<Agent>>,
    Json(config): Json<RelayConfig>,
) -> Result<StatusCode, ApiError> {
    agent.configure_relay(config).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn configure_planet(
    State(agent): State<Arc<Agent>>,
    Json(config): Json<PlanetConfig>,
) -> Result<StatusCode, ApiError> {
    agent.configure_planet(config).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn configure_exit_selection(
    State(agent): State<Arc<Agent>>,
    Path(id): Path<Uuid>,
    Json(config): Json<ExitSelectionConfig>,
) -> Result<StatusCode, ApiError> {
    agent
        .configure_exit_selection(NetworkId(id), config.into())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn configure_exit_gateway(
    State(agent): State<Arc<Agent>>,
    Path(id): Path<Uuid>,
    Json(config): Json<ExitGatewayRequest>,
) -> Result<StatusCode, ApiError> {
    agent.configure_exit_gateway(NetworkId(id), config).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn remove_exit_gateway(
    State(agent): State<Arc<Agent>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    agent.remove_exit_gateway(NetworkId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn leave_network(
    State(agent): State<Arc<Agent>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    agent.remove_network(NetworkId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn activate_adapter(State(agent): State<Arc<Agent>>) -> Result<StatusCode, ApiError> {
    agent.activate_adapter().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn deactivate_adapter(State(agent): State<Arc<Agent>>) -> StatusCode {
    agent.deactivate_adapter().await;
    StatusCode::NO_CONTENT
}
async fn shutdown_agent(State(agent): State<Arc<Agent>>) -> StatusCode {
    agent.shutting_down.store(true, Ordering::Release);
    agent.deactivate_adapter().await;
    agent.shutdown.notify_waiters();
    StatusCode::NO_CONTENT
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = cli.state_file.clone().unwrap_or_else(default_state_path);
    let wintun_dll = cli
        .wintun_dll
        .clone()
        .unwrap_or_else(adapter::default_wintun_path);
    let state_key_provider = cli
        .state_key_file
        .clone()
        .map(StateKeyProvider::RestrictedFile)
        .or_else(|| {
            cli.state_key_systemd_credential
                .clone()
                .map(StateKeyProvider::SystemdCredential)
        });
    let command = match cli.command {
        Some(Command::PrintStatePath) => {
            println!("{}", path.display());
            return Ok(());
        }
        Some(Command::Autostart { command }) => {
            if cli.allow_plaintext_state_migration {
                anyhow::bail!(
                    "--allow-plaintext-state-migration is a one-run authorization and cannot be installed in an autostart unit"
                );
            }
            return manage_autostart(command, &path, &wintun_dll, state_key_provider.as_ref());
        }
        command => command,
    };
    if cli.allow_plaintext_state_migration && state_key_provider.is_none() {
        anyhow::bail!(
            "--allow-plaintext-state-migration requires --state-key-file or --state-key-systemd-credential"
        );
    }
    let state_protection = match state_key_provider {
        Some(provider) => StateProtection::from_provider_with_plaintext_migration(
            &path,
            provider,
            cli.allow_plaintext_state_migration,
        )?,
        None => StateProtection::platform_default(),
    };
    eprintln!("State protection: {}", state_protection.level());
    match command {
        Some(Command::State { command }) => {
            return state_backup_command::run(command, &path, &state_protection)
        }
        Some(Command::Run) | None => {}
        Some(Command::PrintStatePath) | Some(Command::Autostart { .. }) => {
            unreachable!("handled before loading state protection")
        }
    }
    let agent = Arc::new(Agent::open_with_protection(
        path.clone(),
        wintun_dll.clone(),
        state_protection,
    )?);
    // A headless installation must become usable again after logon or a service
    // restart. Wintun sessions are process-local, so an adapter that was active
    // before shutdown has to be opened and configured again here.  Keep serving
    // the local API if this fails (for example when a non-elevated user starts
    // the daemon); the GUI can then show the actionable error and retry it.
    if !agent.status().await.networks.is_empty() {
        if let Err(error) = agent.activate_adapter().await {
            eprintln!(
                "MeshLake could not automatically activate the virtual adapter: {}",
                error.1
            );
        }
    }
    agent.start_authorization_supervisor().await?;
    agent.start_relay_worker().await?;
    let app = Router::new()
        .route("/v1/status", get(get_status))
        .route("/v1/sessions", get(list_sessions))
        .route("/v1/networks", get(list_networks).post(create_network))
        .route("/v1/networks/enroll", post(enroll_network))
        .route("/v1/networks/{id}", delete(leave_network))
        .route(
            "/v1/networks/{id}/exit-selection",
            post(configure_exit_selection),
        )
        .route(
            "/v1/networks/{id}/exit-gateway",
            post(configure_exit_gateway).delete(remove_exit_gateway),
        )
        .route("/v1/relay", post(configure_relay))
        .route("/v1/planet", post(configure_planet))
        .route(
            "/v1/adapter",
            post(activate_adapter).delete(deactivate_adapter),
        )
        .route("/v1/shutdown", post(shutdown_agent))
        .with_state(Arc::clone(&agent));
    let address: SocketAddr = LOCAL_API.parse().unwrap();
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .context("cannot bind local MeshLake API; is meshlaked already running?")?;
    println!("MeshLake agent listening on http://{LOCAL_API}");
    println!("State file: {}", path.display());
    #[cfg(windows)]
    println!("Wintun DLL: {}", wintun_dll.display());
    let shutdown_agent = Arc::clone(&agent);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = shutdown_agent.shutdown.notified() => {}
                signal = tokio::signal::ctrl_c() => {
                    if let Err(error) = signal {
                        eprintln!("MeshLake could not install the Ctrl+C handler: {error}");
                    }
                    shutdown_agent.shutting_down.store(true, Ordering::Release);
                    shutdown_agent.deactivate_adapter().await;
                    shutdown_agent.shutdown.notify_waiters();
                }
            }
        })
        .await?;
    Ok(())
}

#[cfg(windows)]
fn manage_autostart(
    command: AutostartCommand,
    state_path: &FsPath,
    wintun_dll: &FsPath,
    state_key_provider: Option<&StateKeyProvider>,
) -> Result<()> {
    const TASK_NAME: &str = "MeshLake Agent";
    match command {
        AutostartCommand::Install => {
            let state_protection = match state_key_provider {
                Some(provider) => StateProtection::from_provider(state_path, provider.clone())?,
                None => StateProtection::platform_default(),
            };
            let _state_lock = StateFileLock::acquire(state_path)?;
            recover_protected_state_file(state_path)?;
            if !state_path.exists() {
                write_state_with_protection(state_path, &PersistedState::new(), &state_protection)?;
            } else {
                restrict_state_file_permissions(state_path)?;
            }
            let state_path = fs::canonicalize(state_path)
                .with_context(|| format!("cannot resolve {}", state_path.display()))?;
            let wintun_dll = fs::canonicalize(wintun_dll)
                .with_context(|| format!("cannot resolve {}", wintun_dll.display()))?;
            let executable = env::current_exe().context("cannot locate meshlaked executable")?;
            let task_command = format!(
                "\"{}\" --state-file \"{}\" --wintun-dll \"{}\" run",
                executable.display(),
                state_path.display(),
                wintun_dll.display()
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
                anyhow::bail!(
                    "cannot create MeshLake autostart task: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            println!("MeshLake will start as SYSTEM during Windows boot.");
        }
        AutostartCommand::Uninstall => {
            let _ = std::process::Command::new("schtasks.exe")
                .args(["/End", "/TN", TASK_NAME])
                .output();
            let output = std::process::Command::new("schtasks.exe")
                .args(["/Delete", "/TN", TASK_NAME, "/F"])
                .output()
                .context("cannot start schtasks.exe")?;
            if !output.status.success() {
                anyhow::bail!(
                    "cannot remove MeshLake autostart task: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            println!("MeshLake autostart task removed.");
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
fn manage_autostart(
    command: AutostartCommand,
    state_path: &FsPath,
    _wintun_dll: &FsPath,
    state_key_provider: Option<&StateKeyProvider>,
) -> Result<()> {
    const UNIT_PATH: &str = "/etc/systemd/system/meshlaked.service";
    match command {
        AutostartCommand::Install => {
            let executable = env::current_exe().context("cannot locate meshlaked executable")?;
            let (credential_directive, provider_argument) = match state_key_provider {
                Some(StateKeyProvider::SystemdCredential(name)) => (
                    format!("LoadCredential={name}\n"),
                    format!(" --state-key-systemd-credential \"{name}\""),
                ),
                Some(StateKeyProvider::RestrictedFile(path)) => (
                    String::new(),
                    format!(" --state-key-file \"{}\"", path.display()),
                ),
                None => (String::new(), String::new()),
            };
            let unit = format!(
                "[Unit]\nDescription=MeshLake virtual LAN agent\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\n{credential_directive}ExecStart=\"{}\" --state-file \"{}\"{provider_argument} run\nRestart=on-failure\nRestartSec=3\nStateDirectory=meshlake\nNoNewPrivileges=false\n\n[Install]\nWantedBy=multi-user.target\n",
                executable.display(),
                state_path.display(),
            );
            fs::write(UNIT_PATH, unit)
                .context("cannot install systemd unit; run this command as root")?;
            run_systemctl(&["daemon-reload"])?;
            run_systemctl(&["enable", "--now", "meshlaked.service"])?;
            println!("MeshLake systemd service installed and started.");
        }
        AutostartCommand::Uninstall => {
            let _ = run_systemctl(&["disable", "--now", "meshlaked.service"]);
            if std::path::Path::new(UNIT_PATH).exists() {
                fs::remove_file(UNIT_PATH)
                    .context("cannot remove systemd unit; run this command as root")?;
            }
            run_systemctl(&["daemon-reload"])?;
            println!("MeshLake systemd service removed.");
        }
        AutostartCommand::Status => {
            let status = std::process::Command::new("systemctl")
                .args(["is-enabled", "meshlaked.service"])
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
    anyhow::bail!(
        "systemctl {} failed ({}): {}{}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn default_state_path() -> PathBuf {
    if let Some(directory) = env::var_os("MESHLAKE_STATE_DIR") {
        return PathBuf::from(directory).join("agent.json");
    }
    if let Some(directory) = env::var_os("LOCALAPPDATA") {
        return PathBuf::from(directory).join("MeshLake").join("agent.json");
    }
    if let Some(directory) = env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(directory).join("meshlake").join("agent.json");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().expect("current directory unavailable"))
        .join(".local")
        .join("state")
        .join("meshlake")
        .join("agent.json")
}

#[derive(Clone)]
struct PeerRoute {
    candidates: Vec<PeerCandidate>,
    assigned_addresses: Vec<std::net::IpAddr>,
    device_public_key: Vec<u8>,
    directory_last_seen: Option<Instant>,
}

#[derive(Clone)]
struct PeerCandidate {
    endpoint: SocketAddr,
    last_probe_sent: Option<Instant>,
    last_seen: Option<Instant>,
    smoothed_rtt: Option<Duration>,
    consecutive_failures: u8,
}

impl PeerRoute {
    fn new(candidate: SocketAddr) -> Self {
        Self {
            candidates: vec![PeerCandidate::new(candidate)],
            assigned_addresses: Vec::new(),
            device_public_key: Vec::new(),
            directory_last_seen: None,
        }
    }

    fn empty() -> Self {
        Self {
            candidates: Vec::new(),
            assigned_addresses: Vec::new(),
            device_public_key: Vec::new(),
            directory_last_seen: None,
        }
    }

    fn add_candidate(&mut self, candidate: SocketAddr) {
        if !self
            .candidates
            .iter()
            .any(|existing| existing.endpoint == candidate)
            && self.candidates.len() < 16
        {
            self.candidates.push(PeerCandidate::new(candidate));
        }
    }

    fn set_assigned_addresses(&mut self, assigned_addresses: Vec<std::net::IpAddr>) {
        self.set_assigned_addresses_at(assigned_addresses, Instant::now());
    }

    fn set_assigned_addresses_at(
        &mut self,
        assigned_addresses: Vec<std::net::IpAddr>,
        now: Instant,
    ) {
        self.assigned_addresses = assigned_addresses;
        self.directory_last_seen = Some(now);
    }

    fn expire_directory(&mut self, now: Instant) {
        if self
            .directory_last_seen
            .is_some_and(|seen| now.saturating_duration_since(seen) > PEER_DIRECTORY_TTL)
        {
            self.assigned_addresses.clear();
            self.device_public_key.clear();
            self.directory_last_seen = None;
        }
    }

    fn endpoints(&self) -> Vec<SocketAddr> {
        self.candidates
            .iter()
            .map(|candidate| candidate.endpoint)
            .collect()
    }

    fn mark_probe_sent(&mut self, endpoint: SocketAddr, now: Instant) {
        if let Some(candidate) = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.endpoint == endpoint)
        {
            candidate.last_probe_sent = Some(now);
        }
    }

    fn mark_success(&mut self, endpoint: SocketAddr, now: Instant) -> bool {
        let Some(candidate) = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.endpoint == endpoint)
        else {
            return false;
        };
        if let Some(sent) = candidate.last_probe_sent.take() {
            let sample = now.saturating_duration_since(sent);
            candidate.smoothed_rtt = Some(match candidate.smoothed_rtt {
                Some(previous) => weighted_rtt(previous, sample),
                None => sample,
            });
        }
        candidate.last_seen = Some(now);
        candidate.consecutive_failures = 0;
        true
    }

    fn expire_probes(&mut self, now: Instant) {
        for candidate in &mut self.candidates {
            let timed_out = candidate
                .last_probe_sent
                .is_some_and(|sent| now.saturating_duration_since(sent) > Duration::from_secs(3))
                && candidate
                    .last_seen
                    .zip(candidate.last_probe_sent)
                    .map_or(true, |(seen, sent)| seen < sent);
            if timed_out {
                candidate.last_probe_sent = None;
                candidate.consecutive_failures = candidate.consecutive_failures.saturating_add(1);
            }
        }
    }

    fn best_endpoint(&self, now: Instant) -> Option<SocketAddr> {
        self.best_candidate(now).map(|candidate| candidate.endpoint)
    }

    fn best_candidate(&self, now: Instant) -> Option<&PeerCandidate> {
        self.candidates
            .iter()
            .filter(|candidate| {
                candidate.last_seen.is_some_and(|seen| {
                    now.saturating_duration_since(seen) < Duration::from_secs(45)
                })
            })
            .min_by_key(|candidate| candidate.score())
    }
}

impl PeerCandidate {
    fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            last_probe_sent: None,
            last_seen: None,
            smoothed_rtt: None,
            consecutive_failures: 0,
        }
    }

    fn score(&self) -> u128 {
        self.smoothed_rtt
            .unwrap_or(Duration::from_millis(500))
            .as_micros()
            + u128::from(self.consecutive_failures) * 250_000
    }
}

fn weighted_rtt(previous: Duration, sample: Duration) -> Duration {
    let micros = (previous.as_micros() * 7 + sample.as_micros()) / 8;
    Duration::from_micros(micros.min(u64::MAX as u128) as u64)
}

fn update_peer_addresses(
    peers: &mut HashMap<PeerKey, PeerRoute>,
    key: PeerKey,
    assigned_addresses: &[std::net::IpAddr],
    self_id: DeviceId,
    networks: &[JoinedNetwork],
) -> bool {
    if key.1 == self_id || assigned_addresses.len() > RELAY_MAX_ASSIGNED_ADDRESSES {
        return false;
    }
    let Some(network) = networks.iter().find(|network| network.network.id == key.0) else {
        return false;
    };
    let mut addresses = assigned_addresses.to_vec();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !address_belongs_to_network(network, *address))
        || addresses
            .iter()
            .any(|address| network.assigned_addresses.contains(address))
        || peers.iter().any(|(peer_key, route)| {
            *peer_key != key
                && peer_key.0 == key.0
                && route
                    .assigned_addresses
                    .iter()
                    .any(|address| addresses.contains(address))
        })
    {
        return false;
    }
    peers
        .entry(key)
        .or_insert_with(PeerRoute::empty)
        .set_assigned_addresses(addresses);
    true
}

/// Installs a controller-authorized address and identity directory entry.
/// Returns whether the peer identity key changed and existing sessions must be
/// discarded. Signature and controller trust are verified by the caller.
fn update_peer_membership(
    peers: &mut HashMap<PeerKey, PeerRoute>,
    certificate: &MembershipCertificate,
    self_id: DeviceId,
    networks: &[JoinedNetwork],
) -> Option<bool> {
    if certificate.claims.device_public_key.len() != 32 {
        return None;
    }
    let key = (certificate.claims.network_id, certificate.claims.device_id);
    let previous_key = peers
        .get(&key)
        .map(|route| route.device_public_key.clone())
        .unwrap_or_default();
    if !update_peer_addresses(
        peers,
        key,
        &certificate.claims.assigned_addresses,
        self_id,
        networks,
    ) {
        return None;
    }
    let route = peers.get_mut(&key)?;
    route.device_public_key = certificate.claims.device_public_key.clone();
    Some(!previous_key.is_empty() && previous_key != route.device_public_key)
}

fn record_session_handshake(
    seen: &mut HashMap<(PeerKey, [u8; 16]), Instant>,
    peer: PeerKey,
    session_id: [u8; 16],
    current_time: Instant,
) -> bool {
    seen.retain(|_, recorded| {
        current_time.saturating_duration_since(*recorded) <= HANDSHAKE_REPLAY_TTL
    });
    let cache_key = (peer, session_id);
    if seen.contains_key(&cache_key) {
        return false;
    }
    if seen.len() >= MAX_HANDSHAKE_REPLAY_ENTRIES {
        if let Some(oldest) = seen
            .iter()
            .max_by_key(|(_, recorded)| current_time.saturating_duration_since(**recorded))
            .map(|(key, _)| *key)
        {
            seen.remove(&oldest);
        }
    }
    seen.insert(cache_key, current_time);
    true
}

type PeerKey = (NetworkId, DeviceId);

enum PeerSessionState {
    Pending {
        handshake: InitiatorHandshake,
        init_packet: Vec<u8>,
        peer_public_key: Vec<u8>,
        created_at: Instant,
        last_sent: Instant,
        queued_packets: VecDeque<Vec<u8>>,
        path: SessionPath,
        dropped_packets: u64,
        handshake_attempts: u64,
        handshake_retries: u64,
        rejected_packets_received: u64,
    },
    Established {
        keys: PairwiseSessionKeys,
        peer_public_key: Vec<u8>,
        next_sequence: u64,
        replay_window: ReplayWindow,
        established_at: Instant,
        cached_response: Option<Vec<u8>>,
        path: SessionPath,
        dropped_packets: u64,
        handshake_attempts: u64,
        handshake_retries: u64,
        encrypted_packets_sent: u64,
        authenticated_packets_received: u64,
        rejected_packets_received: u64,
    },
}

impl PeerSessionState {
    fn peer_public_key(&self) -> &[u8] {
        match self {
            Self::Pending {
                peer_public_key, ..
            }
            | Self::Established {
                peer_public_key, ..
            } => peer_public_key,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        match self {
            Self::Pending { created_at, .. } => {
                now.saturating_duration_since(*created_at) > HANDSHAKE_TTL
            }
            Self::Established { established_at, .. } => {
                now.saturating_duration_since(*established_at) > PAIRWISE_SESSION_TTL
            }
        }
    }

    fn set_path(&mut self, path: SessionPath) {
        match self {
            Self::Pending {
                path: current_path, ..
            }
            | Self::Established {
                path: current_path, ..
            } => *current_path = path,
        }
    }

    fn record_rejected_packet(&mut self) {
        match self {
            Self::Pending {
                rejected_packets_received,
                ..
            }
            | Self::Established {
                rejected_packets_received,
                ..
            } => {
                *rejected_packets_received = rejected_packets_received.saturating_add(1);
            }
        }
    }

    fn record_authenticated_packet(&mut self) {
        if let Self::Established {
            authenticated_packets_received,
            ..
        } = self
        {
            *authenticated_packets_received = authenticated_packets_received.saturating_add(1);
        }
    }

    fn record_encrypted_send_results(&mut self, results: impl IntoIterator<Item = bool>) {
        let Self::Established {
            encrypted_packets_sent,
            ..
        } = self
        else {
            return;
        };
        for sent in results {
            if sent {
                *encrypted_packets_sent = encrypted_packets_sent.saturating_add(1);
            }
        }
    }

    fn telemetry(&self) -> SessionTelemetry {
        match self {
            Self::Pending {
                created_at,
                queued_packets,
                path,
                dropped_packets,
                handshake_attempts,
                handshake_retries,
                rejected_packets_received,
                ..
            } => SessionTelemetry {
                state: SessionState::Pending,
                path: *path,
                started_at: *created_at,
                queue: SessionQueueCounters {
                    queued_packets: queued_packets.len() as u64,
                    queue_capacity: SESSION_QUEUE_CAPACITY as u64,
                    dropped_packets: *dropped_packets,
                },
                security: SessionSecurityCounters {
                    handshake_attempts: *handshake_attempts,
                    handshake_retries: *handshake_retries,
                    rejected_packets_received: *rejected_packets_received,
                    ..SessionSecurityCounters::default()
                },
            },
            Self::Established {
                established_at,
                path,
                dropped_packets,
                handshake_attempts,
                handshake_retries,
                encrypted_packets_sent,
                authenticated_packets_received,
                rejected_packets_received,
                ..
            } => SessionTelemetry {
                state: SessionState::Established,
                path: *path,
                started_at: *established_at,
                queue: SessionQueueCounters {
                    queued_packets: 0,
                    queue_capacity: SESSION_QUEUE_CAPACITY as u64,
                    dropped_packets: *dropped_packets,
                },
                security: SessionSecurityCounters {
                    handshake_attempts: *handshake_attempts,
                    handshake_retries: *handshake_retries,
                    encrypted_packets_sent: *encrypted_packets_sent,
                    authenticated_packets_received: *authenticated_packets_received,
                    rejected_packets_received: *rejected_packets_received,
                },
            },
        }
    }
}

fn publish_session(
    agent: &Agent,
    transport_revision: u64,
    key: PeerKey,
    session: &PeerSessionState,
) {
    agent
        .session_observability
        .publish(transport_revision, key.0, key.1, session.telemetry());
}

enum PreparedPeerPacket {
    Handshake(Vec<u8>),
    Data(Vec<u8>),
}

fn seal_queued_packets(
    keys: &PairwiseSessionKeys,
    network_id: NetworkId,
    local_device: DeviceId,
    peer_device: DeviceId,
    queued_packets: VecDeque<Vec<u8>>,
) -> Result<(u64, Vec<Vec<u8>>)> {
    let mut next_sequence = 0_u64;
    let mut encrypted = Vec::with_capacity(queued_packets.len());
    for queued in queued_packets {
        encrypted.push(keys.seal(
            network_id,
            local_device,
            peer_device,
            next_sequence,
            &queued,
        )?);
        next_sequence += 1;
    }
    Ok((next_sequence, encrypted))
}

fn prepare_outbound_peer_packet(
    sessions: &mut HashMap<PeerKey, PeerSessionState>,
    network: &JoinedNetwork,
    local_device: DeviceId,
    peer_device: DeviceId,
    peer_public_key: &[u8],
    identity: &SigningKey,
    plaintext: &[u8],
) -> Result<Option<PreparedPeerPacket>> {
    if peer_public_key.len() != 32 {
        trace_transport(format!(
            "cannot start a pairwise session with member {} because no authenticated identity key is available",
            peer_device.0
        ));
        return Ok(None);
    }
    let key = (network.network.id, peer_device);
    let current_time = Instant::now();
    let must_discard = sessions.get(&key).is_some_and(|session| {
        session.is_expired(current_time)
            || session.peer_public_key() != peer_public_key
            || matches!(
                session,
                PeerSessionState::Established {
                    next_sequence: u64::MAX,
                    ..
                }
            )
    });
    if must_discard {
        sessions.remove(&key);
    }

    if let Some(session) = sessions.get_mut(&key) {
        match session {
            PeerSessionState::Pending {
                init_packet,
                last_sent,
                queued_packets,
                dropped_packets,
                handshake_attempts,
                handshake_retries,
                ..
            } => {
                if queued_packets.len() < SESSION_QUEUE_CAPACITY {
                    queued_packets.push_back(plaintext.to_vec());
                } else {
                    *dropped_packets = dropped_packets.saturating_add(1);
                }
                if current_time.saturating_duration_since(*last_sent) >= HANDSHAKE_RETRY {
                    *last_sent = current_time;
                    *handshake_attempts = handshake_attempts.saturating_add(1);
                    *handshake_retries = handshake_retries.saturating_add(1);
                    return Ok(Some(PreparedPeerPacket::Handshake(init_packet.clone())));
                }
                return Ok(None);
            }
            PeerSessionState::Established {
                keys,
                next_sequence,
                ..
            } => {
                let sequence = *next_sequence;
                *next_sequence = next_sequence.saturating_add(1);
                return Ok(Some(PreparedPeerPacket::Data(keys.seal(
                    network.network.id,
                    local_device,
                    peer_device,
                    sequence,
                    plaintext,
                )?)));
            }
        }
    }

    let (handshake, init_packet) = InitiatorHandshake::start(
        network.network.id,
        local_device,
        peer_device,
        identity,
        now(),
    )?;
    sessions.insert(
        key,
        PeerSessionState::Pending {
            handshake,
            init_packet: init_packet.clone(),
            peer_public_key: peer_public_key.to_vec(),
            created_at: current_time,
            last_sent: current_time,
            queued_packets: VecDeque::from([plaintext.to_vec()]),
            path: SessionPath::Unknown,
            dropped_packets: 0,
            handshake_attempts: 1,
            handshake_retries: 0,
            rejected_packets_received: 0,
        },
    );
    Ok(Some(PreparedPeerPacket::Handshake(init_packet)))
}

async fn send_peer_routed_packet(
    sockets: &TransportSockets,
    relay_endpoints: &[SocketAddr],
    endpoint_health: &EndpointHealthTable,
    network: &JoinedNetwork,
    route: &PeerRoute,
    target_device: DeviceId,
    packet: &[u8],
    description: &str,
) -> Option<SessionPath> {
    if !matches!(network.network.relay_policy, RelayPolicy::Required) {
        if let Some(direct_endpoint) = route.best_endpoint(Instant::now()) {
            if sockets.send_to(packet, direct_endpoint).await {
                trace_transport(format!(
                    "sent {description} for member {} directly to {direct_endpoint}",
                    target_device.0
                ));
                return Some(SessionPath::Direct);
            }
        }
    }
    if matches!(network.network.relay_policy, RelayPolicy::Disabled) {
        return None;
    }
    let Some(relay_endpoint) = select_relay_endpoint(
        network.network.id,
        relay_endpoints,
        endpoint_health,
        Instant::now(),
        network.control_plane.planet_manifest_version == Some(3),
    ) else {
        return None;
    };
    if sockets.send_to(packet, relay_endpoint).await {
        trace_transport(format!(
            "sent {description} for member {} through relay {relay_endpoint}",
            target_device.0
        ));
        return Some(SessionPath::Relay);
    }
    None
}

#[derive(Clone, Copy)]
struct StunTransaction {
    server: SocketAddr,
    issued_at: Instant,
}

struct RootTransaction {
    network_id: NetworkId,
    endpoint: SocketAddr,
    public_key: Vec<u8>,
    identity: Option<ServiceIdentityPolicy>,
    issued_at: Instant,
}

#[allow(clippy::too_many_arguments)]
fn sign_registration_for_planet_service(
    planet_manifest_version: Option<u8>,
    service_kind: RootRegistrationServiceKind,
    service_identity: Option<&ServiceIdentityPolicy>,
    device_id: DeviceId,
    certificate: &MembershipCertificate,
    authorization: &NetworkAuthorizationManifest,
    advertised_candidates: &[SocketAddr],
    issued_at_unix_seconds: u64,
    nonce: [u8; 16],
    signing_key: &SigningKey,
) -> std::result::Result<Option<RootRegistration>, meshlake_core::RootProtocolError> {
    match planet_manifest_version {
        Some(3) => {
            let Some(identity) = service_identity else {
                return Ok(None);
            };
            RootRegistration::sign_authorized_for_service(
                device_id,
                vec![certificate.clone()],
                vec![authorization.clone()],
                advertised_candidates.to_vec(),
                issued_at_unix_seconds,
                nonce,
                service_kind,
                identity.service_id,
                signing_key,
            )
            .map(Some)
        }
        Some(1 | 2) | None => RootRegistration::sign_authorized(
            device_id,
            vec![certificate.clone()],
            vec![authorization.clone()],
            advertised_candidates.to_vec(),
            issued_at_unix_seconds,
            nonce,
            signing_key,
        )
        .map(Some),
        Some(_) => Ok(None),
    }
}

#[derive(Clone)]
struct RelayRegistrationTransaction {
    network_id: NetworkId,
    device_id: DeviceId,
    endpoint: SocketAddr,
    planet_manifest_version: Option<u8>,
    identity: Option<ServiceIdentityPolicy>,
    issued_at: Instant,
}

struct TransportSockets {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
}

impl TransportSockets {
    async fn bind() -> Result<Self> {
        // Keep both sockets unconnected: direct peer packets must arrive through
        // the exact NAT mapping that the corresponding relay or root observed.
        let ipv4 = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("cannot bind the IPv4 UDP transport socket")?;
        let ipv6 = match UdpSocket::bind("[::]:0").await {
            Ok(socket) => Some(socket),
            Err(error) => {
                eprintln!("MeshLake IPv6 UDP transport unavailable: {error}");
                None
            }
        };
        Ok(Self { ipv4, ipv6 })
    }

    fn supports(&self, endpoint: SocketAddr) -> bool {
        endpoint.is_ipv4() || self.ipv6.is_some()
    }

    async fn send_to(&self, packet: &[u8], endpoint: SocketAddr) -> bool {
        let socket = if endpoint.is_ipv4() {
            Some(&self.ipv4)
        } else {
            self.ipv6.as_ref()
        };
        let Some(socket) = socket else {
            trace_transport(format!(
                "skipped {endpoint} because the matching UDP address family is unavailable"
            ));
            return false;
        };
        match socket.send_to(packet, endpoint).await {
            Ok(_) => true,
            Err(error) => {
                trace_transport(format!("UDP send to {endpoint} failed: {error}"));
                false
            }
        }
    }
}

async fn receive_optional(
    socket: Option<&UdpSocket>,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => std::future::pending().await,
    }
}

async fn run_relay_worker(
    agent: Arc<Agent>,
    mut configuration: TransportConfiguration,
    configuration_revision: u64,
) -> Result<()> {
    let sockets = TransportSockets::bind().await?;
    let (_, identity, _) = agent.root_registration_material().await?;
    configuration
        .relay_endpoints
        .retain(|endpoint| sockets.supports(*endpoint));
    for network in configuration.networks.values_mut() {
        network
            .relay_endpoints
            .retain(|endpoint| sockets.supports(*endpoint));
    }
    let relay_endpoints = configuration.relay_endpoints.clone();
    let root_servers = configuration.root_servers.clone();
    trace_transport(format!(
        "IPv4 UDP transport bound at {} for {} relay endpoint(s)",
        sockets.ipv4.local_addr()?,
        relay_endpoints.len()
    ));
    if let Some(ipv6) = &sockets.ipv6 {
        trace_transport(format!(
            "IPv6 UDP transport bound at {}",
            ipv6.local_addr()?
        ));
    }
    let mut advertised_candidates = Vec::<SocketAddr>::new();
    let mut automatic_mapping_candidate = None;
    let ipv4_probe_endpoint = relay_endpoints
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| {
            root_servers
                .iter()
                .flat_map(|root| root.endpoints.iter().copied())
                .find(SocketAddr::is_ipv4)
        });
    let mut port_mapping = if configuration.upnp_enabled {
        if let Some(probe_endpoint) = ipv4_probe_endpoint {
            match port_mapping::Mapping::establish(
                probe_endpoint,
                sockets.ipv4.local_addr()?.port(),
            ) {
                Ok((mapping, external)) => {
                    eprintln!(
                        "MeshLake {} UDP mapping active at {external}",
                        mapping.protocol_name()
                    );
                    advertised_candidates.push(external);
                    automatic_mapping_candidate = Some(external);
                    Some(mapping)
                }
                Err(error) => {
                    eprintln!("MeshLake automatic port mapping unavailable: {error}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    let mut stun_servers = resolve_stun_servers(&configuration.stun_servers).await;
    stun_servers.retain(|server| sockets.supports(*server));
    if !stun_servers.is_empty() {
        trace_transport(format!(
            "using {} configured STUN server(s) for candidate gathering",
            stun_servers.len()
        ));
    }
    let mut peers = HashMap::<PeerKey, PeerRoute>::new();
    let mut sessions = HashMap::<PeerKey, PeerSessionState>::new();
    let mut seen_handshakes = HashMap::<(PeerKey, [u8; 16]), Instant>::new();
    let mut stun_transactions = HashMap::<[u8; 12], StunTransaction>::new();
    let mut root_transactions = HashMap::<[u8; 16], RootTransaction>::new();
    let mut relay_registration_transactions =
        HashMap::<[u8; 16], RelayRegistrationTransaction>::new();
    let mut registration_schedules = HashMap::<RegistrationTarget, RegistrationSchedule>::new();
    let mut endpoint_health = EndpointHealthTable::default();
    let mut incoming_ipv4 = vec![0_u8; u16::MAX as usize];
    let mut incoming_ipv6 = vec![0_u8; u16::MAX as usize];
    let mut tick = tokio::time::interval(Duration::from_millis(5));
    let mut next_registration_scan = tokio::time::Instant::now();
    let mut next_stun_refresh = tokio::time::Instant::now();
    let mut next_port_mapping_refresh = tokio::time::Instant::now() + Duration::from_secs(1_800);
    let mut next_peer_probe = tokio::time::Instant::now();
    let mut next_handshake_retry = tokio::time::Instant::now();
    let shutdown = agent.shutdown.notified();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            received = sockets.ipv4.recv_from(&mut incoming_ipv4) => {
                let (size, remote) = received?;
                receive_udp_packet(
                    &agent,
                    &sockets,
                    &configuration,
                    configuration_revision,
                    remote,
                    &incoming_ipv4[..size],
                    &mut peers,
                    &mut sessions,
                    &mut seen_handshakes,
                    &identity,
                    &mut stun_transactions,
                    &mut root_transactions,
                    &mut relay_registration_transactions,
                    &mut advertised_candidates,
                    &mut endpoint_health,
                    &mut registration_schedules,
                ).await?;
            }
            received = receive_optional(sockets.ipv6.as_ref(), &mut incoming_ipv6) => {
                let (size, remote) = received?;
                receive_udp_packet(
                    &agent,
                    &sockets,
                    &configuration,
                    configuration_revision,
                    remote,
                    &incoming_ipv6[..size],
                    &mut peers,
                    &mut sessions,
                    &mut seen_handshakes,
                    &identity,
                    &mut stun_transactions,
                    &mut root_transactions,
                    &mut relay_registration_transactions,
                    &mut advertised_candidates,
                    &mut endpoint_health,
                    &mut registration_schedules,
                ).await?;
            }
            _ = tick.tick() => {
                if agent.transport_revision.load(Ordering::Acquire)
                    != configuration_revision
                {
                    trace_transport("transport configuration changed; rebuilding UDP sockets");
                    break;
                }
                if configuration.has_expired_planet(now()) {
                    trace_transport(
                        "accepted Planet manifest expired; rebuilding transport fail closed",
                    );
                    break;
                }
                if tokio::time::Instant::now() >= next_port_mapping_refresh {
                    if let Some(mapping) = port_mapping.as_mut() {
                        match mapping.renew() {
                            Ok(external) => {
                                if let Some(previous) = automatic_mapping_candidate.replace(external) {
                                    advertised_candidates.retain(|candidate| *candidate != previous);
                                }
                                if !advertised_candidates.contains(&external)
                                    && advertised_candidates.len() < 16
                                {
                                    advertised_candidates.push(external);
                                }
                                trace_transport(format!(
                                    "renewed {} UDP mapping at {external}",
                                    mapping.protocol_name()
                                ));
                            }
                            Err(error) => eprintln!(
                                "MeshLake {} UDP mapping renewal failed: {error}",
                                mapping.protocol_name()
                            ),
                        }
                    }
                    next_port_mapping_refresh =
                        tokio::time::Instant::now() + Duration::from_secs(1_800);
                }
                let (device_id, networks) = agent.relay_snapshot().await;
                let authorization_time = now();
                peers.retain(|(network_id, _), _| {
                    networks.iter().any(|network| {
                        network.network.id == *network_id
                            && local_network_is_authorized(network, authorization_time)
                    })
                });
                let unauthorized_sessions = sessions
                    .keys()
                    .copied()
                    .filter(|(network_id, _)| {
                        !networks.iter().any(|network| {
                            network.network.id == *network_id
                                && local_network_is_authorized(network, authorization_time)
                        })
                    })
                    .collect::<Vec<_>>();
                for key in unauthorized_sessions {
                    sessions.remove(&key);
                    agent.session_observability.remove(
                        configuration_revision,
                        key.0,
                        key.1,
                    );
                }
                if tokio::time::Instant::now() >= next_handshake_retry {
                    let retry_time = Instant::now();
                    let retries = sessions
                        .iter_mut()
                        .filter_map(|(key, session)| match session {
                            PeerSessionState::Pending {
                                init_packet,
                                last_sent,
                                handshake_attempts,
                                handshake_retries,
                                ..
                            } if retry_time.saturating_duration_since(*last_sent)
                                >= HANDSHAKE_RETRY =>
                            {
                                *last_sent = retry_time;
                                *handshake_attempts = handshake_attempts.saturating_add(1);
                                *handshake_retries = handshake_retries.saturating_add(1);
                                Some((*key, init_packet.clone()))
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    for ((network_id, target_device), handshake) in retries {
                        let Some(network) = networks
                            .iter()
                            .find(|network| {
                                network.network.id == network_id
                                    && local_network_is_authorized(network, authorization_time)
                            })
                        else {
                            continue;
                        };
                        let Some(route) = peers.get(&(network_id, target_device)) else {
                            continue;
                        };
                        if let Some(path) = send_peer_routed_packet(
                            &sockets,
                            configuration.relay_endpoints_for(network_id),
                            &endpoint_health,
                            network,
                            route,
                            target_device,
                            &handshake,
                            "session handshake retry",
                        )
                        .await
                        {
                            if let Some(session) = sessions.get_mut(&(network_id, target_device)) {
                                session.set_path(path);
                            }
                        }
                        if let Some(session) = sessions.get(&(network_id, target_device)) {
                            publish_session(
                                &agent,
                                configuration_revision,
                                (network_id, target_device),
                                session,
                            );
                        }
                    }
                    next_handshake_retry =
                        tokio::time::Instant::now() + Duration::from_millis(250);
                }
                if tokio::time::Instant::now() >= next_peer_probe {
                    let mut probes = Vec::new();
                    let probe_time = Instant::now();
                    for ((network_id, _), route) in &mut peers {
                        route.expire_directory(probe_time);
                        route.expire_probes(probe_time);
                        for peer_endpoint in route.endpoints() {
                            route.mark_probe_sent(peer_endpoint, probe_time);
                            probes.push((
                                peer_endpoint,
                                punch_packet(*network_id, device_id, RELAY_PUNCH),
                            ));
                        }
                    }
                    let stale_sessions = sessions
                        .iter()
                        .filter_map(|(key, session)| {
                            let identity_valid = peers.get(key).is_some_and(|route| {
                                !route.device_public_key.is_empty()
                                    && route.device_public_key == session.peer_public_key()
                            });
                            (!identity_valid || session.is_expired(probe_time))
                                .then_some((*key, session.is_expired(probe_time)))
                        })
                        .collect::<Vec<_>>();
                    for (key, naturally_expired) in stale_sessions {
                        if naturally_expired {
                            agent.session_observability.expire(
                                configuration_revision,
                                key.0,
                                key.1,
                            );
                        } else {
                            agent.session_observability.remove(
                                configuration_revision,
                                key.0,
                                key.1,
                            );
                        }
                        sessions.remove(&key);
                    }
                    for (peer_endpoint, punch) in probes {
                        sockets.send_to(&punch, peer_endpoint).await;
                    }
                    agent.update_peer_paths(&peers, probe_time).await;
                    next_peer_probe =
                        tokio::time::Instant::now() + Duration::from_secs(5);
                }
                if tokio::time::Instant::now() >= next_registration_scan {
                    next_registration_scan = tokio::time::Instant::now() + Duration::from_millis(250);
                    let schedule_time = Instant::now();
                    let (root_device, identity, memberships) =
                        agent.root_registration_material().await?;
                    let mut active_targets = Vec::new();
                    for membership in &memberships {
                        let certificate = &membership.certificate;
                        for relay_endpoint in configuration
                            .relay_endpoints_for(certificate.claims.network_id)
                        {
                            let target = RegistrationTarget {
                                network_id: certificate.claims.network_id,
                                endpoint: *relay_endpoint,
                                kind: RegistrationServiceKind::Relay,
                            };
                            active_targets.push(target);
                            let schedule = registration_schedules
                                .entry(target)
                                .or_insert_with(|| RegistrationSchedule::new(root_device, target, schedule_time));
                            schedule.expire_if_timed_out(
                                schedule_time,
                                TRANSPORT_TRANSACTION_TTL,
                            );
                            if !schedule.is_due(schedule_time) {
                                continue;
                            }
                            let transaction_key =
                                (certificate.claims.network_id, *relay_endpoint);
                            relay_registration_transactions.retain(|_, transaction| {
                                (transaction.network_id, transaction.endpoint) != transaction_key
                            });
                            let nonce = new_root_nonce();
                            let manifest_version = configuration
                                .planet_manifest_version_for(certificate.claims.network_id);
                            let relay_identity = configuration
                                .relay_identity_for(
                                    certificate.claims.network_id,
                                    *relay_endpoint,
                                )
                                .cloned();
                            let Some(signed) = sign_registration_for_planet_service(
                                manifest_version,
                                RootRegistrationServiceKind::Relay,
                                relay_identity.as_ref(),
                                root_device,
                                certificate,
                                &membership.authorization,
                                &advertised_candidates,
                                now(),
                                nonce,
                                &identity,
                            )?
                            else {
                                trace_transport(match manifest_version {
                                    Some(3) => format!(
                                        "skipped V3 Relay registration without a pinned service identity for network {}",
                                        certificate.claims.network_id.0
                                    ),
                                    Some(version) => format!(
                                        "skipped Relay registration for unsupported Planet version {version}"
                                    ),
                                    None => unreachable!(
                                        "legacy registration always has sufficient service metadata"
                                    ),
                                });
                                continue;
                            };
                            let mut registration = Vec::from(RELAY_MAGIC);
                            registration.push(RELAY_REGISTER_SIGNED);
                            registration.extend_from_slice(&serde_json::to_vec(&signed)?);
                            if sockets.send_to(&registration, *relay_endpoint).await {
                                schedule.mark_sent(schedule_time);
                                relay_registration_transactions.insert(
                                    nonce,
                                    RelayRegistrationTransaction {
                                        network_id: certificate.claims.network_id,
                                        device_id: root_device,
                                        endpoint: *relay_endpoint,
                                        planet_manifest_version: manifest_version,
                                        identity: relay_identity,
                                        issued_at: Instant::now(),
                                    },
                                );
                            } else {
                                schedule.mark_send_failure(schedule_time);
                            }
                        }
                        trace_transport(format!(
                            "sent signed relay registration for network {}",
                            certificate.claims.network_id.0
                        ));
                        for root in
                            configuration.root_servers_for(certificate.claims.network_id)
                        {
                            for root_endpoint in root.endpoints.iter().copied() {
                                let target = RegistrationTarget {
                                    network_id: certificate.claims.network_id,
                                    endpoint: root_endpoint,
                                    kind: RegistrationServiceKind::Root,
                                };
                                active_targets.push(target);
                                let schedule = registration_schedules
                                    .entry(target)
                                    .or_insert_with(|| RegistrationSchedule::new(root_device, target, schedule_time));
                                schedule.expire_if_timed_out(
                                    schedule_time,
                                    TRANSPORT_TRANSACTION_TTL,
                                );
                                if !schedule.is_due(schedule_time) {
                                    continue;
                                }
                                root_transactions.retain(|_, transaction| {
                                    transaction.network_id != certificate.claims.network_id
                                        || transaction.endpoint != root_endpoint
                                });
                                let nonce = new_root_nonce();
                                let manifest_version = configuration
                                    .planet_manifest_version_for(certificate.claims.network_id);
                                let Some(registration) =
                                    sign_registration_for_planet_service(
                                        manifest_version,
                                        RootRegistrationServiceKind::Root,
                                        root.identity.as_ref(),
                                        root_device,
                                        certificate,
                                        &membership.authorization,
                                        &advertised_candidates,
                                        now(),
                                        nonce,
                                        &identity,
                                    )?
                                else {
                                    trace_transport(match manifest_version {
                                        Some(3) => format!(
                                            "skipped V3 Root registration without a pinned service identity for network {}",
                                            certificate.claims.network_id.0
                                        ),
                                        Some(version) => format!(
                                            "skipped Root registration for unsupported Planet version {version}"
                                        ),
                                        None => unreachable!(
                                            "legacy registration always has sufficient service metadata"
                                        ),
                                    });
                                    continue;
                                };
                                if sockets
                                    .send_to(&serde_json::to_vec(&registration)?, root_endpoint)
                                    .await
                                {
                                    schedule.mark_sent(schedule_time);
                                    root_transactions.insert(
                                        nonce,
                                        RootTransaction {
                                            network_id: certificate.claims.network_id,
                                            endpoint: root_endpoint,
                                            public_key: root.public_key.clone(),
                                            identity: root.identity.clone(),
                                            issued_at: Instant::now(),
                                        },
                                    );
                                } else {
                                    schedule.mark_send_failure(schedule_time);
                                }
                            }
                        }
                    }
                    registration_schedules.retain(|target, _| active_targets.contains(target));
                    if tokio::time::Instant::now() >= next_stun_refresh {
                        for server in &stun_servers {
                            let transaction_id = new_stun_transaction_id();
                            if sockets
                                .send_to(&stun_binding_request(transaction_id), *server)
                                .await
                            {
                                stun_transactions.insert(
                                    transaction_id,
                                    StunTransaction {
                                        server: *server,
                                        issued_at: Instant::now(),
                                    },
                                );
                            }
                        }
                        next_stun_refresh = tokio::time::Instant::now() + Duration::from_secs(20);
                    }
                    stun_transactions.retain(|_, transaction| {
                        transaction.issued_at.elapsed() < Duration::from_secs(30)
                    });
                    root_transactions.retain(|_, transaction| {
                        transaction.issued_at.elapsed() < TRANSPORT_TRANSACTION_TTL
                    });
                    relay_registration_transactions.retain(|_, transaction| {
                        transaction.issued_at.elapsed() < TRANSPORT_TRANSACTION_TTL
                    });
                    let maximum_backoff = registration_schedules
                        .values()
                        .map(RegistrationSchedule::last_delay)
                        .max()
                        .unwrap_or_default();
                    agent
                        .registration_backoff_seconds
                        .store(maximum_backoff.as_secs(), Ordering::Relaxed);
                }
                if !agent.adapter.is_active() {
                    continue;
                }
                for _ in 0..32 {
                    let Some(packet) = agent.adapter.try_read_packet()? else { break; };
                    let Some(outbound_route) = outbound_route_for_ip_packet(&networks, device_id, &packet)
                        .filter(|route| local_network_is_authorized(route.network, now()))
                    else { continue; };
                    let network = outbound_route.network;
                    let targets = peer_targets_for_packet(&peers, network, outbound_route.gateway, &packet);
                    if targets.is_empty() {
                        trace_transport(format!(
                            "dropped packet for network {} because no authorized peer owns the destination",
                            network.network.id.0
                        ));
                        continue;
                    }
                    for (target_device, route) in targets {
                        let Some(prepared) = prepare_outbound_peer_packet(
                            &mut sessions,
                            network,
                            device_id,
                            target_device,
                            &route.device_public_key,
                            &identity,
                            &packet,
                        )? else {
                            continue;
                        };
                        let is_encrypted_data = matches!(&prepared, PreparedPeerPacket::Data(_));
                        let (outbound, description) = match prepared {
                            PreparedPeerPacket::Handshake(packet) => (packet, "session handshake"),
                            PreparedPeerPacket::Data(packet) => (packet, "pairwise-encrypted packet"),
                        };
                        let selected_path = send_peer_routed_packet(
                            &sockets,
                            configuration.relay_endpoints_for(network.network.id),
                            &endpoint_health,
                            network,
                            &route,
                            target_device,
                            &outbound,
                            description,
                        )
                        .await;
                        let key = (network.network.id, target_device);
                        if let (Some(path), Some(session)) =
                            (selected_path, sessions.get_mut(&key))
                        {
                            session.set_path(path);
                            if is_encrypted_data {
                                session.record_encrypted_send_results([true]);
                            }
                        }
                        if let Some(session) = sessions.get(&key) {
                            publish_session(&agent, configuration_revision, key, session);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn receive_udp_packet(
    agent: &Agent,
    sockets: &TransportSockets,
    configuration: &TransportConfiguration,
    configuration_revision: u64,
    remote: SocketAddr,
    packet: &[u8],
    peers: &mut HashMap<PeerKey, PeerRoute>,
    sessions: &mut HashMap<PeerKey, PeerSessionState>,
    seen_handshakes: &mut HashMap<(PeerKey, [u8; 16]), Instant>,
    identity: &SigningKey,
    stun_transactions: &mut HashMap<[u8; 12], StunTransaction>,
    root_transactions: &mut HashMap<[u8; 16], RootTransaction>,
    relay_registration_transactions: &mut HashMap<[u8; 16], RelayRegistrationTransaction>,
    advertised_candidates: &mut Vec<SocketAddr>,
    endpoint_health: &mut EndpointHealthTable,
    registration_schedules: &mut HashMap<RegistrationTarget, RegistrationSchedule>,
) -> Result<()> {
    let relay_endpoints = configuration.relay_endpoints.as_slice();
    if let Some((transaction_id, candidate)) = parse_stun_binding_success(packet) {
        if let Some(transaction) = stun_transactions.remove(&transaction_id) {
            if transaction.server == remote
                && transaction.issued_at.elapsed() < Duration::from_secs(30)
            {
                if !advertised_candidates.contains(&candidate) && advertised_candidates.len() < 16 {
                    advertised_candidates.push(candidate);
                }
                let (device, networks) = agent.relay_snapshot().await;
                for network in &networks {
                    if network.certificate.is_some() {
                        let announcement =
                            candidate_announcement(network.network.id, device, candidate);
                        for relay_endpoint in configuration.relay_endpoints_for(network.network.id)
                        {
                            sockets.send_to(&announcement, *relay_endpoint).await;
                        }
                    }
                }
                trace_transport(format!(
                    "received STUN server-reflexive candidate {candidate}"
                ));
            }
        }
        return Ok(());
    }
    if handle_root_response(
        agent,
        sockets,
        remote,
        packet,
        peers,
        sessions,
        configuration_revision,
        configuration,
        root_transactions,
        registration_schedules,
    )
    .await?
    {
        return Ok(());
    }
    if packet.len() < 5 || packet[..4] != RELAY_MAGIC {
        return Ok(());
    }
    match packet[4] {
        RELAY_REGISTER_ACK_SIGNED if relay_endpoints.contains(&remote) => {
            let Ok(acknowledgement) =
                serde_json::from_slice::<SignedRelayRegistrationAck>(&packet[5..])
            else {
                agent
                    .relay_confirmations_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            let Some((network, authorization_hint)) = acknowledge_signed_relay_registration(
                relay_registration_transactions,
                endpoint_health,
                &acknowledgement,
                remote,
                Instant::now(),
                now(),
            ) else {
                agent
                    .relay_confirmations_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            agent
                .relay_confirmations_accepted
                .fetch_add(1, Ordering::Relaxed);
            if let Some(schedule) = registration_schedules.get_mut(&RegistrationTarget {
                network_id: network,
                endpoint: remote,
                kind: RegistrationServiceKind::Relay,
            }) {
                schedule.mark_success(Instant::now());
            }
            agent.mark_relay_acknowledged(network, remote).await;
            if let Some(hint) = authorization_hint.as_ref() {
                if agent.consider_authorization_hint(hint).await {
                    agent
                        .authorization_hint_refreshes
                        .fetch_add(1, Ordering::Relaxed);
                    trace_transport(format!(
                        "Relay authorization hint requested a signed manifest refresh for network {}",
                        network.0
                    ));
                }
            }
            trace_transport(format!(
                "verified signed Relay registration acknowledgement for network {}",
                network.0
            ));
        }
        RELAY_REGISTER_ACK if relay_endpoints.contains(&remote) => {
            let Some((network, device, nonce)) = parse_registration_ack(packet) else {
                return Ok(());
            };
            if !configuration.relay_endpoints_for(network).contains(&remote) {
                return Ok(());
            }
            let (self_id, networks) = agent.relay_snapshot().await;
            if device != self_id || !networks.iter().any(|entry| entry.network.id == network) {
                return Ok(());
            }
            let acknowledged = Instant::now();
            if !acknowledge_relay_registration(
                relay_registration_transactions,
                endpoint_health,
                network,
                device,
                nonce,
                remote,
                acknowledged,
            ) {
                agent
                    .relay_confirmations_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            agent
                .relay_confirmations_accepted
                .fetch_add(1, Ordering::Relaxed);
            if let Some(schedule) = registration_schedules.get_mut(&RegistrationTarget {
                network_id: network,
                endpoint: remote,
                kind: RegistrationServiceKind::Relay,
            }) {
                schedule.mark_success(acknowledged);
            }
            agent.mark_relay_acknowledged(network, remote).await;
            trace_transport(format!(
                "relay {remote} registration acknowledged for network {}",
                network.0
            ));
        }
        RELAY_PEER_IDENTITY if relay_endpoints.contains(&remote) => {
            let Some(certificate) = parse_peer_identity(packet) else {
                return Ok(());
            };
            let network = certificate.claims.network_id;
            let device = certificate.claims.device_id;
            let (self_id, networks) = agent.relay_snapshot().await;
            let Some(local_network) = networks.iter().find(|joined| joined.network.id == network)
            else {
                return Ok(());
            };
            if certificate
                .verify_from_controller(pinned_controller_key(local_network), now())
                .is_err()
                || certificate.claims.device_public_key.len() != 32
                || !local_network_is_authorized(local_network, now())
                || !peer_certificate_is_authorized(local_network, &certificate, now())
            {
                trace_transport(format!(
                    "rejected untrusted peer membership for member {} on network {}",
                    device.0, network.0
                ));
                return Ok(());
            }
            match update_peer_membership(peers, &certificate, self_id, &networks) {
                Some(true) => {
                    sessions.remove(&(network, device));
                    agent
                        .session_observability
                        .remove(configuration_revision, network, device);
                    trace_transport(format!(
                        "discarded the old pairwise session because member {} changed its identity key",
                        device.0
                    ));
                }
                Some(false) => {}
                None => {
                    trace_transport(format!(
                        "rejected peer address directory for member {} on network {}",
                        device.0, network.0
                    ));
                }
            }
        }
        RELAY_PEER if relay_endpoints.contains(&remote) => {
            let Some((network, device, peer_endpoint)) = parse_peer_announcement(packet) else {
                return Ok(());
            };
            let (self_id, networks) = agent.relay_snapshot().await;
            let Some(local_network) = networks.iter().find(|entry| entry.network.id == network)
            else {
                return Ok(());
            };
            if device == self_id || !local_network_is_authorized(local_network, now()) {
                return Ok(());
            }
            if !sockets.supports(peer_endpoint) {
                return Ok(());
            }
            let route = peers
                .entry((network, device))
                .and_modify(|route| route.add_candidate(peer_endpoint))
                .or_insert_with(|| PeerRoute::new(peer_endpoint));
            route.mark_probe_sent(peer_endpoint, Instant::now());
            trace_transport(format!("received peer candidate {peer_endpoint}"));
            let punch = punch_packet(network, self_id, RELAY_PUNCH);
            // Several quick probes improve the chance of overlapping NAT
            // mappings without delaying normal relay connectivity.
            for _ in 0..3 {
                sockets.send_to(&punch, peer_endpoint).await;
            }
        }
        RELAY_PUNCH | RELAY_PUNCH_ACK => {
            let kind = packet[4];
            let Some((network, device)) = parse_punch(packet, kind) else {
                return Ok(());
            };
            let (self_id, networks) = agent.relay_snapshot().await;
            let Some(local_network) = networks.iter().find(|entry| entry.network.id == network)
            else {
                return Ok(());
            };
            if device == self_id || !local_network_is_authorized(local_network, now()) {
                return Ok(());
            }
            let Some(route) = peers.get_mut(&(network, device)) else {
                return Ok(());
            };
            if !route
                .candidates
                .iter()
                .any(|candidate| candidate.endpoint == remote)
            {
                return Ok(());
            }
            route.mark_success(remote, Instant::now());
            if let Some(response_kind) = punch_response_kind(kind) {
                sockets
                    .send_to(&punch_packet(network, self_id, response_kind), remote)
                    .await;
            }
        }
        RELAY_SESSION_INIT => {
            receive_session_init(
                agent,
                sockets,
                relay_endpoints,
                remote,
                packet,
                peers,
                sessions,
                seen_handshakes,
                identity,
                configuration_revision,
            )
            .await?;
        }
        RELAY_SESSION_RESPONSE => {
            receive_session_response(
                agent,
                sockets,
                relay_endpoints,
                remote,
                packet,
                peers,
                sessions,
                configuration_revision,
            )
            .await?;
        }
        RELAY_SESSION_DATA => {
            receive_session_data(
                agent,
                relay_endpoints,
                remote,
                packet,
                peers,
                sessions,
                configuration_revision,
            )
            .await?;
        }
        RELAY_DATA => {
            trace_transport(
                "dropped a legacy network-key data frame; pairwise sessions are required",
            );
        }
        _ => {}
    }
    Ok(())
}

async fn handle_root_response(
    agent: &Agent,
    sockets: &TransportSockets,
    remote: SocketAddr,
    packet: &[u8],
    peers: &mut HashMap<PeerKey, PeerRoute>,
    sessions: &mut HashMap<PeerKey, PeerSessionState>,
    configuration_revision: u64,
    configuration: &TransportConfiguration,
    root_transactions: &mut HashMap<[u8; 16], RootTransaction>,
    registration_schedules: &mut HashMap<RegistrationTarget, RegistrationSchedule>,
) -> Result<bool> {
    let Ok(response) = serde_json::from_slice::<SignedRootResponse>(packet) else {
        return Ok(false);
    };
    let Some(transaction) = root_transactions.get(&response.request_nonce) else {
        return Ok(true);
    };
    if transaction.endpoint != remote
        || Instant::now().saturating_duration_since(transaction.issued_at)
            >= TRANSPORT_TRANSACTION_TTL
    {
        return Ok(true);
    }
    let Some(current_root) = configuration
        .root_servers_for(transaction.network_id)
        .iter()
        .find(|root| {
            root.public_key == transaction.public_key
                && root.endpoints.contains(&remote)
                && root.identity == transaction.identity
        })
    else {
        return Ok(true);
    };
    let identity_verified = current_root
        .identity
        .as_ref()
        .map(|identity| response.verify_identity(identity, now()))
        .unwrap_or_else(|| response.verify(&current_root.public_key));
    if identity_verified.is_err() {
        return Ok(true);
    }
    let transaction = root_transactions
        .remove(&response.request_nonce)
        .expect("verified Root transaction remains present");
    match response.response {
        RootResponse::Registered {
            observed_endpoint,
            peers: discovered,
            authorization_hints,
            ..
        } => {
            if let Some(schedule) = registration_schedules.get_mut(&RegistrationTarget {
                network_id: transaction.network_id,
                endpoint: remote,
                kind: RegistrationServiceKind::Root,
            }) {
                schedule.mark_success(Instant::now());
            }
            agent
                .mark_root_responsive(transaction.network_id, remote)
                .await;
            trace_transport(format!(
                "authenticated root {remote} observed this node at {observed_endpoint}"
            ));
            for hint in &authorization_hints {
                if hint.network_id == transaction.network_id {
                    agent.consider_authorization_hint(hint).await;
                }
            }
            let (self_id, networks) = agent.relay_snapshot().await;
            for peer in discovered {
                if peer.network_id != transaction.network_id
                    || peer.device_id == self_id
                    || !networks
                        .iter()
                        .any(|network| network.network.id == peer.network_id)
                {
                    continue;
                }
                let key = (peer.network_id, peer.device_id);
                let Some(certificate) = peer.certificate else {
                    trace_transport(format!(
                        "ignored legacy root directory entry for member {} because it has no membership certificate",
                        peer.device_id.0
                    ));
                    continue;
                };
                let Some(local_network) = networks
                    .iter()
                    .find(|joined| joined.network.id == peer.network_id)
                else {
                    continue;
                };
                if certificate.claims.network_id != peer.network_id
                    || certificate.claims.device_id != peer.device_id
                    || certificate.claims.assigned_addresses != peer.assigned_addresses
                    || certificate
                        .verify_from_controller(pinned_controller_key(local_network), now())
                        .is_err()
                    || !local_network_is_authorized(local_network, now())
                    || !peer_certificate_is_authorized(local_network, &certificate, now())
                {
                    trace_transport(format!(
                        "rejected unauthenticated root directory for member {} on network {}",
                        peer.device_id.0, peer.network_id.0
                    ));
                    continue;
                }
                match update_peer_membership(peers, &certificate, self_id, &networks) {
                    Some(true) => {
                        sessions.remove(&key);
                        agent
                            .session_observability
                            .remove(configuration_revision, key.0, key.1);
                        trace_transport(format!(
                            "discarded the old pairwise session because member {} changed its identity key",
                            peer.device_id.0
                        ));
                    }
                    Some(false) => {}
                    None => {
                        trace_transport(format!(
                            "rejected root address directory for member {} on network {}",
                            peer.device_id.0, peer.network_id.0
                        ));
                        continue;
                    }
                }
                for candidate in peer.candidates.into_iter().filter(|candidate| {
                    sockets.supports(*candidate)
                        && candidate.port() != 0
                        && !candidate.ip().is_unspecified()
                }) {
                    let route = peers
                        .entry(key)
                        .and_modify(|route| route.add_candidate(candidate))
                        .or_insert_with(|| PeerRoute::new(candidate));
                    route.mark_probe_sent(candidate, Instant::now());
                    let punch = punch_packet(peer.network_id, self_id, RELAY_PUNCH);
                    for _ in 0..3 {
                        sockets.send_to(&punch, candidate).await;
                    }
                }
            }
        }
        RootResponse::Error { message } => {
            trace_transport(format!("root {remote} rejected registration: {message}"));
        }
    }
    Ok(true)
}

async fn receive_session_init(
    agent: &Agent,
    sockets: &TransportSockets,
    relay_endpoints: &[SocketAddr],
    remote: SocketAddr,
    packet: &[u8],
    peers: &HashMap<PeerKey, PeerRoute>,
    sessions: &mut HashMap<PeerKey, PeerSessionState>,
    seen_handshakes: &mut HashMap<(PeerKey, [u8; 16]), Instant>,
    identity: &SigningKey,
    configuration_revision: u64,
) -> Result<()> {
    let Ok((network_id, source, destination)) =
        parse_session_routing_header(packet, RELAY_SESSION_INIT)
    else {
        return Ok(());
    };
    let (device_id, networks) = agent.relay_snapshot().await;
    if destination != device_id || source == device_id {
        return Ok(());
    }
    let Some(network) = networks
        .iter()
        .find(|network| network.network.id == network_id)
    else {
        return Ok(());
    };
    if !local_network_is_authorized(network, now()) {
        return Ok(());
    }
    let peer_key = (network_id, source);
    let Some(peer_public_key) = peers
        .get(&peer_key)
        .map(|route| route.device_public_key.clone())
        .filter(|key| key.len() == 32)
    else {
        trace_transport(format!(
            "dropped session initiation from member {} because its authenticated identity is unknown",
            source.0
        ));
        return Ok(());
    };
    let Ok(session_id) = session_handshake_id(packet, RELAY_SESSION_INIT) else {
        return Ok(());
    };
    let cached_response = sessions.get(&peer_key).and_then(|session| match session {
        PeerSessionState::Established {
            keys,
            cached_response: Some(response),
            ..
        } if keys.session_id() == session_id => Some(response.clone()),
        _ => None,
    });
    if let Some(response) = cached_response {
        if let Some(session) = sessions.get_mut(&peer_key) {
            session.set_path(if relay_endpoints.contains(&remote) {
                SessionPath::Relay
            } else {
                SessionPath::Direct
            });
            publish_session(agent, configuration_revision, peer_key, session);
        }
        sockets.send_to(&response, remote).await;
        return Ok(());
    }
    if matches!(
        sessions.get(&peer_key),
        Some(PeerSessionState::Pending { .. })
    ) && device_id.0 < source.0
    {
        // When both peers initiate simultaneously, the lower DeviceId remains
        // the initiator so both sides converge on one session.
        return Ok(());
    }
    let (queued_packets, dropped_packets, handshake_attempts, handshake_retries, rejected_packets) =
        match sessions.get(&peer_key) {
            Some(PeerSessionState::Pending {
                queued_packets,
                dropped_packets,
                handshake_attempts,
                handshake_retries,
                rejected_packets_received,
                ..
            }) => (
                queued_packets.clone(),
                *dropped_packets,
                *handshake_attempts,
                *handshake_retries,
                *rejected_packets_received,
            ),
            _ => (VecDeque::new(), 0, 1, 0, 0),
        };
    let Ok(network_key) = NetworkKey::from_slice(&network.network_key) else {
        return Ok(());
    };
    let Ok((keys, response)) = accept_pairwise_handshake(
        packet,
        &peer_public_key,
        identity,
        &network_key,
        now(),
        HANDSHAKE_CLOCK_SKEW_SECONDS,
    ) else {
        if let Some(session) = sessions.get_mut(&peer_key) {
            session.record_rejected_packet();
            publish_session(agent, configuration_revision, peer_key, session);
        }
        trace_transport(format!(
            "rejected an invalid pairwise session initiation from member {}",
            source.0
        ));
        return Ok(());
    };
    if !record_session_handshake(seen_handshakes, peer_key, session_id, Instant::now()) {
        if let Some(session) = sessions.get_mut(&peer_key) {
            session.record_rejected_packet();
            publish_session(agent, configuration_revision, peer_key, session);
        }
        trace_transport(format!(
            "rejected replayed pairwise session initiation from member {}",
            source.0
        ));
        return Ok(());
    }
    let (next_sequence, queued_encrypted) =
        seal_queued_packets(&keys, network_id, device_id, source, queued_packets)?;
    sessions.insert(
        peer_key,
        PeerSessionState::Established {
            keys,
            peer_public_key,
            next_sequence,
            replay_window: ReplayWindow::default(),
            established_at: Instant::now(),
            cached_response: Some(response.clone()),
            path: if relay_endpoints.contains(&remote) {
                SessionPath::Relay
            } else {
                SessionPath::Direct
            },
            dropped_packets,
            handshake_attempts,
            handshake_retries,
            encrypted_packets_sent: 0,
            authenticated_packets_received: 0,
            rejected_packets_received: rejected_packets,
        },
    );
    sockets.send_to(&response, remote).await;
    let mut queued_send_results = Vec::with_capacity(queued_encrypted.len());
    for encrypted in queued_encrypted {
        queued_send_results.push(sockets.send_to(&encrypted, remote).await);
    }
    if let Some(session) = sessions.get_mut(&peer_key) {
        session.record_encrypted_send_results(queued_send_results);
        publish_session(agent, configuration_revision, peer_key, session);
    }
    trace_transport(format!(
        "accepted pairwise session {} from member {} via {}",
        Uuid::from_bytes(session_id),
        source.0,
        if relay_endpoints.contains(&remote) {
            "relay"
        } else {
            "direct path"
        }
    ));
    Ok(())
}

async fn receive_session_response(
    agent: &Agent,
    sockets: &TransportSockets,
    relay_endpoints: &[SocketAddr],
    remote: SocketAddr,
    packet: &[u8],
    peers: &HashMap<PeerKey, PeerRoute>,
    sessions: &mut HashMap<PeerKey, PeerSessionState>,
    configuration_revision: u64,
) -> Result<()> {
    let Ok((network_id, source, destination)) =
        parse_session_routing_header(packet, RELAY_SESSION_RESPONSE)
    else {
        return Ok(());
    };
    let (device_id, networks) = agent.relay_snapshot().await;
    if destination != device_id || source == device_id {
        return Ok(());
    }
    let peer_key = (network_id, source);
    let Some(route) = peers.get(&peer_key) else {
        return Ok(());
    };
    let Some(network) = networks
        .iter()
        .find(|network| network.network.id == network_id)
    else {
        return Ok(());
    };
    if !local_network_is_authorized(network, now()) {
        return Ok(());
    }
    let Ok(network_key) = NetworkKey::from_slice(&network.network_key) else {
        return Ok(());
    };
    let (
        completed,
        queued_packets,
        dropped_packets,
        handshake_attempts,
        handshake_retries,
        rejected_packets,
    ) = match sessions.get(&peer_key) {
        Some(PeerSessionState::Pending {
            handshake,
            peer_public_key,
            queued_packets,
            dropped_packets,
            handshake_attempts,
            handshake_retries,
            rejected_packets_received,
            ..
        }) if peer_public_key == &route.device_public_key => (
            handshake.complete(
                packet,
                &route.device_public_key,
                &network_key,
                now(),
                HANDSHAKE_CLOCK_SKEW_SECONDS,
            ),
            queued_packets.clone(),
            *dropped_packets,
            *handshake_attempts,
            *handshake_retries,
            *rejected_packets_received,
        ),
        _ => return Ok(()),
    };
    let Ok(keys) = completed else {
        if let Some(session) = sessions.get_mut(&peer_key) {
            session.record_rejected_packet();
            publish_session(agent, configuration_revision, peer_key, session);
        }
        trace_transport(format!(
            "rejected an invalid pairwise session response from member {}",
            source.0
        ));
        return Ok(());
    };
    let session_id = keys.session_id();
    let (next_sequence, queued_encrypted) =
        seal_queued_packets(&keys, network_id, device_id, source, queued_packets)?;
    sessions.insert(
        peer_key,
        PeerSessionState::Established {
            keys,
            peer_public_key: route.device_public_key.clone(),
            next_sequence,
            replay_window: ReplayWindow::default(),
            established_at: Instant::now(),
            cached_response: None,
            path: if relay_endpoints.contains(&remote) {
                SessionPath::Relay
            } else {
                SessionPath::Direct
            },
            dropped_packets,
            handshake_attempts,
            handshake_retries,
            encrypted_packets_sent: 0,
            authenticated_packets_received: 0,
            rejected_packets_received: rejected_packets,
        },
    );
    let mut queued_send_results = Vec::with_capacity(queued_encrypted.len());
    for encrypted in queued_encrypted {
        queued_send_results.push(sockets.send_to(&encrypted, remote).await);
    }
    if let Some(session) = sessions.get_mut(&peer_key) {
        session.record_encrypted_send_results(queued_send_results);
        publish_session(agent, configuration_revision, peer_key, session);
    }
    trace_transport(format!(
        "completed pairwise session {} with member {}",
        Uuid::from_bytes(session_id),
        source.0
    ));
    Ok(())
}

async fn receive_session_data(
    agent: &Agent,
    relay_endpoints: &[SocketAddr],
    remote: SocketAddr,
    packet: &[u8],
    peers: &mut HashMap<PeerKey, PeerRoute>,
    sessions: &mut HashMap<PeerKey, PeerSessionState>,
    configuration_revision: u64,
) -> Result<()> {
    let Ok((network_id, source, destination)) =
        parse_session_routing_header(packet, RELAY_SESSION_DATA)
    else {
        return Ok(());
    };
    let (device_id, networks) = agent.relay_snapshot().await;
    if destination != device_id || source == device_id {
        return Ok(());
    }
    let peer_key = (network_id, source);
    let opened = match sessions.get_mut(&peer_key) {
        Some(PeerSessionState::Established {
            keys,
            replay_window,
            ..
        }) => keys.open(replay_window, packet),
        _ => return Ok(()),
    };
    let Ok(opened) = opened else {
        if let Some(session) = sessions.get_mut(&peer_key) {
            session.record_rejected_packet();
            publish_session(agent, configuration_revision, peer_key, session);
        }
        trace_transport(format!(
            "dropped unauthenticated or replayed session packet from member {}",
            source.0
        ));
        return Ok(());
    };
    if let Some(session) = sessions.get_mut(&peer_key) {
        session.record_authenticated_packet();
        session.set_path(if relay_endpoints.contains(&remote) {
            SessionPath::Relay
        } else {
            SessionPath::Direct
        });
        publish_session(agent, configuration_revision, peer_key, session);
    }
    if opened.network_id != network_id
        || opened.source != source
        || opened.destination != destination
    {
        return Ok(());
    }
    let Some(network) = networks
        .iter()
        .find(|network| network.network.id == network_id)
    else {
        return Ok(());
    };
    if !local_network_is_authorized(network, now()) {
        return Ok(());
    }
    let Some(source_route) = peers.get(&peer_key) else {
        trace_transport(format!(
            "dropped packet from member {} because no authenticated address directory is available",
            source.0
        ));
        return Ok(());
    };
    if !packet_is_authorized_for_delivery(
        network,
        source,
        source_route,
        destination,
        device_id,
        &opened.plaintext,
    ) {
        trace_transport(format!(
            "dropped packet from member {} because its virtual source or destination is unauthorized",
            source.0
        ));
        return Ok(());
    }
    if !relay_endpoints.contains(&remote) {
        if let Some(route) = peers.get_mut(&peer_key) {
            route.add_candidate(remote);
            route.mark_success(remote, Instant::now());
        }
    }
    if agent.adapter.is_active() {
        agent.adapter.write_packet(&opened.plaintext)?;
        trace_transport("injected pairwise-decrypted packet into the virtual adapter");
    }
    Ok(())
}

/// Emits transport metadata only when explicitly enabled for diagnostics.
/// Packet payloads, controller certificates and network keys are never logged.
fn trace_transport(message: impl std::fmt::Display) {
    if std::env::var_os("MESHLAKE_TRACE").is_some() {
        eprintln!("[meshlake transport] {message}");
    }
}

/// Resolves a small, administrator-configured STUN server list. Resolution
/// failure is non-fatal because the authenticated MeshLake relay remains a
/// transport fallback.
async fn resolve_stun_servers(configured: &[String]) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for configured_server in configured {
        if let Ok(endpoint) = configured_server.parse::<SocketAddr>() {
            servers.push(endpoint);
            continue;
        }
        match tokio::net::lookup_host(configured_server).await {
            Ok(resolved) => servers.extend(resolved),
            Err(error) => {
                eprintln!("MeshLake could not resolve STUN server {configured_server:?}: {error}")
            }
        }
    }
    servers.sort_unstable();
    servers.dedup();
    servers
}

/// RFC 5389 Binding Request. The request is deliberately minimal: the socket
/// is already the socket used for peer traffic, so the response reveals the
/// NAT mapping relevant to MeshLake itself.
fn stun_binding_request(transaction_id: [u8; 12]) -> [u8; 20] {
    let mut request = [0_u8; 20];
    request[..2].copy_from_slice(&0x0001_u16.to_be_bytes());
    request[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    request
}

fn new_stun_transaction_id() -> [u8; 12] {
    let uuid = Uuid::new_v4();
    uuid.as_bytes()[..12].try_into().expect("UUID has 16 bytes")
}

fn new_root_nonce() -> [u8; 16] {
    *Uuid::new_v4().as_bytes()
}

/// Parses `XOR-MAPPED-ADDRESS` (preferred) or `MAPPED-ADDRESS` from an RFC
/// 5389 Binding Success response. Only a transaction that was sent to the
/// same configured server is subsequently accepted.
fn parse_stun_binding_success(packet: &[u8]) -> Option<([u8; 12], SocketAddr)> {
    if packet.len() < 20
        || packet[..2] != 0x0101_u16.to_be_bytes()
        || packet[4..8] != 0x2112_A442_u32.to_be_bytes()
    {
        return None;
    }
    let body_length = u16::from_be_bytes(packet[2..4].try_into().ok()?) as usize;
    let body_end = 20_usize.checked_add(body_length)?;
    if body_end > packet.len() {
        return None;
    }
    let transaction_id: [u8; 12] = packet[8..20].try_into().ok()?;
    let mut offset = 20_usize;
    while offset.checked_add(4)? <= body_end {
        let kind = u16::from_be_bytes(packet[offset..offset + 2].try_into().ok()?);
        let length = u16::from_be_bytes(packet[offset + 2..offset + 4].try_into().ok()?) as usize;
        let value_start = offset + 4;
        let value_end = value_start.checked_add(length)?;
        if value_end > body_end {
            return None;
        }
        if kind == 0x0020 || kind == 0x0001 {
            if let Some(address) = parse_stun_address(
                &packet[value_start..value_end],
                kind == 0x0020,
                &transaction_id,
            ) {
                return Some((transaction_id, address));
            }
        }
        offset = value_end.checked_add((4 - length % 4) % 4)?;
    }
    None
}

fn parse_stun_address(value: &[u8], xor: bool, transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 8 || value[0] != 0 {
        return None;
    }
    let cookie = 0x2112_A442_u32.to_be_bytes();
    let mut port = u16::from_be_bytes(value[2..4].try_into().ok()?);
    if xor {
        port ^= u16::from_be_bytes(cookie[..2].try_into().ok()?);
    }
    match value[1] {
        0x01 if value.len() == 8 => {
            let mut octets: [u8; 4] = value[4..8].try_into().ok()?;
            if xor {
                for (octet, mask) in octets.iter_mut().zip(cookie) {
                    *octet ^= mask;
                }
            }
            Some(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                port,
            ))
        }
        0x02 if value.len() == 20 => {
            let mut octets: [u8; 16] = value[4..20].try_into().ok()?;
            if xor {
                for (index, octet) in octets.iter_mut().enumerate() {
                    let mask = if index < 4 {
                        cookie[index]
                    } else {
                        transaction_id[index - 4]
                    };
                    *octet ^= mask;
                }
            }
            Some(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                port,
            ))
        }
        _ => None,
    }
}

fn candidate_announcement(network: NetworkId, device: DeviceId, endpoint: SocketAddr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(56);
    packet.extend_from_slice(&RELAY_MAGIC);
    packet.push(RELAY_CANDIDATE);
    packet.extend_from_slice(network.0.as_bytes());
    packet.extend_from_slice(device.0.as_bytes());
    match endpoint.ip() {
        std::net::IpAddr::V4(ip) => {
            packet.push(4);
            packet.extend_from_slice(&endpoint.port().to_be_bytes());
            packet.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            packet.push(6);
            packet.extend_from_slice(&endpoint.port().to_be_bytes());
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet
}

fn parse_registration_ack(packet: &[u8]) -> Option<(NetworkId, DeviceId, [u8; 16])> {
    if packet.len() != 53 || packet[..4] != RELAY_MAGIC || packet[4] != RELAY_REGISTER_ACK {
        return None;
    }
    Some((
        NetworkId(Uuid::from_slice(&packet[5..21]).ok()?),
        DeviceId(Uuid::from_slice(&packet[21..37]).ok()?),
        packet[37..53].try_into().ok()?,
    ))
}

fn acknowledge_relay_registration(
    transactions: &mut HashMap<[u8; 16], RelayRegistrationTransaction>,
    endpoint_health: &mut EndpointHealthTable,
    network_id: NetworkId,
    device_id: DeviceId,
    nonce: [u8; 16],
    endpoint: SocketAddr,
    now: Instant,
) -> bool {
    let Some(transaction) = transactions.get(&nonce) else {
        return false;
    };
    if transaction.network_id != network_id
        || transaction.device_id != device_id
        || transaction.endpoint != endpoint
        || !matches!(transaction.planet_manifest_version, Some(1 | 2))
        || transaction.identity.is_some()
        || now.saturating_duration_since(transaction.issued_at) >= TRANSPORT_TRANSACTION_TTL
    {
        return false;
    }
    transactions.remove(&nonce);
    endpoint_health.mark_relay_acknowledged(network_id, endpoint, now);
    true
}

fn acknowledge_signed_relay_registration(
    transactions: &mut HashMap<[u8; 16], RelayRegistrationTransaction>,
    endpoint_health: &mut EndpointHealthTable,
    acknowledgement: &SignedRelayRegistrationAck,
    endpoint: SocketAddr,
    now_instant: Instant,
    now_unix_seconds: u64,
) -> Option<(NetworkId, Option<AuthorizationEpochHint>)> {
    let nonce = acknowledgement.payload.request_nonce;
    let transaction = transactions.get(&nonce)?;
    let identity = transaction.identity.as_ref()?;
    if transaction.planet_manifest_version != Some(3)
        || transaction.endpoint != endpoint
        || now_instant.saturating_duration_since(transaction.issued_at) >= TRANSPORT_TRANSACTION_TTL
        || acknowledgement
            .verify(
                identity,
                transaction.network_id,
                transaction.device_id,
                nonce,
                now_unix_seconds,
                5,
            )
            .is_err()
    {
        return None;
    }
    let network_id = transaction.network_id;
    transactions.remove(&nonce);
    endpoint_health.mark_relay_acknowledged(network_id, endpoint, now_instant);
    Some((
        network_id,
        acknowledgement.payload.authorization_hint.clone(),
    ))
}

fn parse_peer_announcement(packet: &[u8]) -> Option<(NetworkId, DeviceId, SocketAddr)> {
    if packet.len() < 40 || packet[..4] != RELAY_MAGIC || packet[4] != RELAY_PEER {
        return None;
    }
    let network = NetworkId(Uuid::from_slice(&packet[5..21]).ok()?);
    let device = DeviceId(Uuid::from_slice(&packet[21..37]).ok()?);
    let port = u16::from_be_bytes(packet[38..40].try_into().ok()?);
    let address = match packet[37] {
        4 if packet.len() == 44 => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                packet[40], packet[41], packet[42], packet[43],
            )),
            port,
        ),
        6 if packet.len() == 56 => {
            let octets: [u8; 16] = packet[40..56].try_into().ok()?;
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
        }
        _ => return None,
    };
    Some((network, device, address))
}

fn punch_packet(network: NetworkId, source: DeviceId, kind: u8) -> Vec<u8> {
    debug_assert!(matches!(kind, RELAY_PUNCH | RELAY_PUNCH_ACK));
    let mut packet = Vec::with_capacity(37);
    packet.extend_from_slice(&RELAY_MAGIC);
    packet.push(kind);
    packet.extend_from_slice(network.0.as_bytes());
    packet.extend_from_slice(source.0.as_bytes());
    packet
}

fn punch_response_kind(kind: u8) -> Option<u8> {
    (kind == RELAY_PUNCH).then_some(RELAY_PUNCH_ACK)
}

fn parse_punch(packet: &[u8], kind: u8) -> Option<(NetworkId, DeviceId)> {
    if packet.len() != 37
        || packet[..4] != RELAY_MAGIC
        || packet[4] != kind
        || !matches!(kind, RELAY_PUNCH | RELAY_PUNCH_ACK)
    {
        return None;
    }
    Some((
        NetworkId(Uuid::from_slice(&packet[5..21]).ok()?),
        DeviceId(Uuid::from_slice(&packet[21..37]).ok()?),
    ))
}

fn peer_targets_for_packet(
    peers: &HashMap<PeerKey, PeerRoute>,
    network: &JoinedNetwork,
    gateway: Option<DeviceId>,
    packet: &[u8],
) -> Vec<(DeviceId, PeerRoute)> {
    let Some((_, destination)) = packet_addresses(packet) else {
        return Vec::new();
    };
    let mut targets = peers
        .iter()
        .filter_map(|((network_id, device_id), route)| {
            if *network_id != network.network.id || route.assigned_addresses.is_empty() {
                return None;
            }
            (gateway == Some(*device_id)
                || (gateway.is_none()
                    && (is_group_destination(network, destination)
                        || route.assigned_addresses.contains(&destination))))
            .then_some((*device_id, route.clone()))
        })
        .collect::<Vec<_>>();
    targets.sort_by_key(|(device_id, _)| device_id.0);
    targets
}

fn packet_is_authorized_for_delivery(
    network: &JoinedNetwork,
    source_device: DeviceId,
    source_route: &PeerRoute,
    outer_destination: DeviceId,
    local_device: DeviceId,
    packet: &[u8],
) -> bool {
    if !outer_destination.0.is_nil() && outer_destination != local_device {
        return false;
    }
    let Some((source_address, destination_address)) = packet_addresses(packet) else {
        return false;
    };
    if !source_route.assigned_addresses.contains(&source_address)
        && !peer_is_gateway_for_source(network, source_device, source_address)
    {
        return false;
    }
    let group_destination = is_group_destination(network, destination_address);
    if outer_destination.0.is_nil() {
        return group_destination;
    }
    group_destination
        || network.assigned_addresses.contains(&destination_address)
        || local_device_is_gateway_for(network, local_device, destination_address)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::{
        AuthorizedMembership, DnsPolicy, MembershipClaims, NetworkAuthorizationManifest,
        NetworkPolicyManifest, PolicyRoute, RelayPolicy, RootPeer,
    };
    use std::cell::Cell;

    #[test]
    fn adapter_activation_failure_skips_configuration_and_rollback() {
        let configured = Cell::new(false);
        let rolled_back = Cell::new(false);
        let result = activate_adapter_transaction(
            false,
            || Err("activation failed"),
            || {
                configured.set(true);
                Ok(())
            },
            || rolled_back.set(true),
        );

        assert_eq!(result, Err("activation failed"));
        assert!(!configured.get());
        assert!(!rolled_back.get());
    }

    #[test]
    fn new_adapter_session_rolls_back_when_configuration_fails() {
        let activated = Cell::new(false);
        let rolled_back = Cell::new(false);
        let result = activate_adapter_transaction(
            false,
            || {
                activated.set(true);
                Ok(())
            },
            || Err("configuration failed"),
            || rolled_back.set(true),
        );

        assert_eq!(result, Err("configuration failed"));
        assert!(activated.get());
        assert!(rolled_back.get());
    }

    #[test]
    fn existing_adapter_session_is_not_closed_by_reconfiguration_failure() {
        let rolled_back = Cell::new(false);
        let result = activate_adapter_transaction(
            true,
            || Ok(()),
            || Err("configuration failed"),
            || rolled_back.set(true),
        );

        assert_eq!(result, Err("configuration failed"));
        assert!(!rolled_back.get());
    }

    #[test]
    fn successful_adapter_activation_keeps_the_new_session() {
        let activated = Cell::new(false);
        let configured = Cell::new(false);
        let rolled_back = Cell::new(false);
        let result: std::result::Result<(), &str> = activate_adapter_transaction(
            false,
            || {
                activated.set(true);
                Ok(())
            },
            || {
                configured.set(true);
                Ok(())
            },
            || rolled_back.set(true),
        );

        assert_eq!(result, Ok(()));
        assert!(activated.get());
        assert!(configured.get());
        assert!(!rolled_back.get());
    }

    #[test]
    fn adapter_activation_is_refused_after_shutdown_begins() {
        assert!(ensure_adapter_activation_allowed(false).is_ok());
        let error = ensure_adapter_activation_allowed(true).unwrap_err();
        assert_eq!(error.0, StatusCode::CONFLICT);
        assert_eq!(error.1, "MeshLake agent is shutting down");
    }

    fn suffixed_state_path(path: &FsPath, suffix: &str) -> PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    }

    fn cleanup_test_state(path: &FsPath, directory: &FsPath) {
        for candidate in [
            path.to_path_buf(),
            suffixed_state_path(path, ".bak"),
            suffixed_state_path(path, ".lock"),
        ] {
            if candidate.exists() {
                fs::remove_file(&candidate).unwrap();
            }
        }
        let temporary_prefix = format!(
            "{}.tmp-",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(&temporary_prefix)
            {
                fs::remove_file(entry.path()).unwrap();
            }
        }
        fs::remove_dir(directory).unwrap();
    }

    fn has_temporary_state_file(path: &FsPath) -> bool {
        let temporary_prefix = format!(
            "{}.tmp-",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        path.parent()
            .and_then(|parent| fs::read_dir(parent).ok())
            .is_some_and(|entries| {
                entries.filter_map(Result::ok).any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(&temporary_prefix)
                })
            })
    }

    async fn spawn_json_server(
        responses: Vec<Vec<u8>>,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 2048];
                    let read = stream.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                requests.push(request);
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
            requests
        });
        (address, server)
    }

    async fn spawn_blocked_json_server(
        body: Vec<u8>,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_received_tx, request_received_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 2048];
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = request_received_tx.send(());
            release_rx.await.unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });
        (address, request_received_rx, release_tx, server)
    }

    fn joined_network_with_authorization(
        controller: &SigningKey,
        identity: &SigningKey,
        device_id: DeviceId,
        network_id: NetworkId,
        certificate_id: Uuid,
        network_key_epoch: u64,
        authorization_epoch: u64,
        controller_url: String,
    ) -> JoinedNetwork {
        let timestamp = now();
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id,
                device_id,
                device_public_key: identity.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.90.1".parse().unwrap()],
                allowed_routes: vec!["100.64.90.0/24".into()],
                issued_at_unix_seconds: timestamp,
                expires_at_unix_seconds: Some(timestamp + 86_400),
            },
            certificate_id,
            network_key_epoch,
            controller,
        )
        .unwrap();
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            authorization_epoch,
            network_key_epoch,
            vec![AuthorizedMembership {
                device_id,
                certificate_id,
                device_public_key: identity.verifying_key().to_bytes().to_vec(),
                network_key_epoch,
            }],
            vec![],
            timestamp,
            timestamp + 90,
            controller,
        )
        .unwrap();
        JoinedNetwork {
            network: VirtualNetwork {
                id: network_id,
                name: "authorization-test".into(),
                ipv4_prefix: "100.64.90.0/24".into(),
                ipv6_prefix: None,
                relay_policy: RelayPolicy::Preferred,
            },
            assigned_addresses: certificate.claims.assigned_addresses.clone(),
            certificate: Some(certificate),
            network_key: vec![network_key_epoch as u8; 32],
            control_plane: NetworkControlPlane {
                controller_url: Some(controller_url),
                pinned_controller_public_key: controller.verifying_key().to_bytes().to_vec(),
                authorization_manifest: Some(authorization),
                ..NetworkControlPlane::default()
            },
        }
    }

    fn signed_planet_v3(
        controller: &SigningKey,
        controller_url: &str,
        issued_at_unix_seconds: u64,
        root_endpoint: SocketAddr,
        root_identity: ServiceIdentityPolicy,
        relay_endpoint: SocketAddr,
        relay_identity: ServiceIdentityPolicy,
    ) -> PlanetManifest {
        PlanetManifest::sign_v3(
            controller_url.into(),
            vec![PlanetRoot {
                public_key: root_identity.current_public_key.clone(),
                endpoints: vec![root_endpoint],
                priority: 0,
                identity: Some(root_identity),
            }],
            vec![PlanetRelay {
                endpoint: relay_endpoint,
                priority: 0,
                identity: Some(relay_identity),
            }],
            vec!["stun.example:3478".into()],
            issued_at_unix_seconds,
            Some(issued_at_unix_seconds + 300),
            controller,
        )
        .unwrap()
    }

    fn signed_planet_v2(
        controller: &SigningKey,
        controller_url: &str,
        issued_at_unix_seconds: u64,
        root_endpoint: SocketAddr,
        relay_endpoint: SocketAddr,
    ) -> PlanetManifest {
        PlanetManifest::sign_v2(
            controller_url.into(),
            vec![PlanetRoot {
                public_key: vec![12; 32],
                endpoints: vec![root_endpoint],
                priority: 0,
                identity: None,
            }],
            vec![PlanetRelay {
                endpoint: relay_endpoint,
                priority: 0,
                identity: None,
            }],
            vec!["stun.example:3478".into()],
            issued_at_unix_seconds,
            Some(issued_at_unix_seconds + 300),
            controller,
        )
        .unwrap()
    }

    #[test]
    fn planet_version_selects_target_bound_or_legacy_registration_explicitly() {
        let controller = SigningKey::from_bytes(&[94; 32]);
        let device_identity = SigningKey::from_bytes(&[95; 32]);
        let device_id = DeviceId(Uuid::from_u128(940));
        let network_id = NetworkId(Uuid::from_u128(941));
        let joined = joined_network_with_authorization(
            &controller,
            &device_identity,
            device_id,
            network_id,
            Uuid::from_u128(942),
            1,
            1,
            "http://controller.example".into(),
        );
        let certificate = joined.certificate.as_ref().unwrap();
        let authorization = joined
            .control_plane
            .authorization_manifest
            .as_ref()
            .unwrap();
        let root_identity = ServiceIdentityPolicy::stable(
            Uuid::from_u128(943),
            SigningKey::from_bytes(&[96; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        );
        let relay_identity = ServiceIdentityPolicy::stable(
            Uuid::from_u128(944),
            SigningKey::from_bytes(&[97; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        );
        let nonce = [98; 16];

        let root = sign_registration_for_planet_service(
            Some(3),
            RootRegistrationServiceKind::Root,
            Some(&root_identity),
            device_id,
            certificate,
            authorization,
            &[],
            now(),
            nonce,
            &device_identity,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            root.payload.target,
            Some(meshlake_core::RootRegistrationTarget {
                service_kind: RootRegistrationServiceKind::Root,
                service_id: root_identity.service_id,
            })
        );

        let relay = sign_registration_for_planet_service(
            Some(3),
            RootRegistrationServiceKind::Relay,
            Some(&relay_identity),
            device_id,
            certificate,
            authorization,
            &[],
            now(),
            nonce,
            &device_identity,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            relay.payload.target,
            Some(meshlake_core::RootRegistrationTarget {
                service_kind: RootRegistrationServiceKind::Relay,
                service_id: relay_identity.service_id,
            })
        );
        assert_ne!(root.payload.target, relay.payload.target);

        for version in [None, Some(1), Some(2)] {
            let legacy = sign_registration_for_planet_service(
                version,
                RootRegistrationServiceKind::Root,
                None,
                device_id,
                certificate,
                authorization,
                &[],
                now(),
                nonce,
                &device_identity,
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                legacy.payload.version,
                meshlake_core::ROOT_REGISTRATION_PROTOCOL_VERSION_LEGACY
            );
            assert_eq!(legacy.payload.target, None);
        }
        assert!(sign_registration_for_planet_service(
            Some(3),
            RootRegistrationServiceKind::Relay,
            None,
            device_id,
            certificate,
            authorization,
            &[],
            now(),
            nonce,
            &device_identity,
        )
        .unwrap()
        .is_none());
        assert!(sign_registration_for_planet_service(
            Some(4),
            RootRegistrationServiceKind::Root,
            Some(&root_identity),
            device_id,
            certificate,
            authorization,
            &[],
            now(),
            nonce,
            &device_identity,
        )
        .unwrap()
        .is_none());
    }

    fn refresh_target(network: &JoinedNetwork) -> AuthorizationRefreshTarget {
        AuthorizationRefreshTarget {
            network_id: network.network.id,
            controller_url: network.control_plane.controller_url.clone().unwrap(),
            controller_tls_ca_pem: network.control_plane.controller_tls_ca_pem.clone(),
            pinned_controller_public_key: network
                .control_plane
                .pinned_controller_public_key
                .clone(),
            certificate: network.certificate.clone().unwrap(),
            authorization_epoch: network
                .control_plane
                .authorization_manifest
                .as_ref()
                .map(|authorization| authorization.authorization_epoch),
        }
    }

    fn test_joined_network() -> JoinedNetwork {
        JoinedNetwork {
            network: VirtualNetwork {
                id: NetworkId(Uuid::from_u128(90)),
                name: "dual-stack".into(),
                ipv4_prefix: "100.64.90.0/24".into(),
                ipv6_prefix: Some("fd42:4d4c:90::/64".into()),
                relay_policy: RelayPolicy::Preferred,
            },
            assigned_addresses: vec![
                "100.64.90.1".parse().unwrap(),
                "fd42:4d4c:90::1".parse().unwrap(),
            ],
            certificate: None,
            network_key: vec![7; 32],
            control_plane: NetworkControlPlane::default(),
        }
    }

    fn test_established_session(
        network: &JoinedNetwork,
        local_device: DeviceId,
        peer_device: DeviceId,
        local_identity: &SigningKey,
        peer_identity: &SigningKey,
    ) -> PeerSessionState {
        let network_key = NetworkKey::from_slice(&network.network_key).unwrap();
        let (handshake, init_packet) = InitiatorHandshake::start(
            network.network.id,
            local_device,
            peer_device,
            local_identity,
            now(),
        )
        .unwrap();
        let (_, response) = accept_pairwise_handshake(
            &init_packet,
            &local_identity.verifying_key().to_bytes(),
            peer_identity,
            &network_key,
            now(),
            HANDSHAKE_CLOCK_SKEW_SECONDS,
        )
        .unwrap();
        let keys = handshake
            .complete(
                &response,
                &peer_identity.verifying_key().to_bytes(),
                &network_key,
                now(),
                HANDSHAKE_CLOCK_SKEW_SECONDS,
            )
            .unwrap();
        PeerSessionState::Established {
            keys,
            peer_public_key: peer_identity.verifying_key().to_bytes().to_vec(),
            next_sequence: 0,
            replay_window: ReplayWindow::default(),
            established_at: Instant::now(),
            cached_response: None,
            path: SessionPath::Unknown,
            dropped_packets: 0,
            handshake_attempts: 1,
            handshake_retries: 0,
            encrypted_packets_sent: 0,
            authenticated_packets_received: 0,
            rejected_packets_received: 0,
        }
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn ipv6_packet(source: &str, destination: &str) -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[8..24].copy_from_slice(&source.parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[24..40]
            .copy_from_slice(&destination.parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet
    }

    #[test]
    fn exit_selection_requires_a_current_signed_candidate_and_a_gateway_for_kill_switch() {
        let network = test_joined_network();
        assert!(validate_exit_selection(
            &network,
            &ExitNodeSelection {
                ipv4_gateway: None,
                ipv6_gateway: None,
                kill_switch: true,
            },
        )
        .is_err());
        assert!(validate_exit_selection(
            &network,
            &ExitNodeSelection {
                ipv4_gateway: Some(DeviceId(Uuid::from_u128(900))),
                ipv6_gateway: None,
                kill_switch: false,
            },
        )
        .is_err());
        assert!(validate_exit_selection(&network, &ExitNodeSelection::default()).is_ok());
    }

    #[test]
    fn unusable_exit_selection_is_cleared_with_its_kill_switch() {
        let mut network = test_joined_network();
        network.control_plane.exit_node_selection = ExitNodeSelection {
            ipv4_gateway: Some(DeviceId(Uuid::from_u128(901))),
            ipv6_gateway: None,
            kill_switch: true,
        };
        assert!(clear_unusable_exit_selection(&mut network));
        assert!(network.control_plane.exit_node_selection.is_empty());
    }

    #[test]
    fn parses_xor_mapped_ipv4_stun_response() {
        let transaction = [9_u8; 12];
        let cookie = 0x2112_A442_u32.to_be_bytes();
        let port = 34_789_u16;
        let address = [203_u8, 0, 113, 7];
        let mut response = vec![0_u8; 32];
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response[4..8].copy_from_slice(&cookie);
        response[8..20].copy_from_slice(&transaction);
        response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
        response[22..24].copy_from_slice(&8_u16.to_be_bytes());
        response[25] = 1;
        response[26..28].copy_from_slice(
            &(port ^ u16::from_be_bytes(cookie[..2].try_into().unwrap())).to_be_bytes(),
        );
        for (index, value) in address.iter().enumerate() {
            response[28 + index] = value ^ cookie[index];
        }
        assert_eq!(
            parse_stun_binding_success(&response),
            Some((transaction, "203.0.113.7:34789".parse().unwrap()))
        );
    }

    #[test]
    fn selects_virtual_network_for_ipv4_and_ipv6_packets() {
        let network = test_joined_network();
        let network_id = network.network.id;
        let networks = [network];

        let ipv4 = ipv4_packet([100, 64, 90, 1], [100, 64, 90, 9]);
        assert_eq!(
            network_for_ip_packet(&networks, &ipv4).map(|network| network.network.id),
            Some(network_id)
        );

        let ipv6 = ipv6_packet("fd42:4d4c:90::1", "fd42:4d4c:90::9");
        assert_eq!(
            network_for_ip_packet(&networks, &ipv6).map(|network| network.network.id),
            Some(network_id)
        );
    }

    #[test]
    fn peer_directory_rejects_conflicts_and_out_of_prefix_addresses() {
        let network = test_joined_network();
        let networks = [network.clone()];
        let self_id = DeviceId(Uuid::from_u128(100));
        let peer_two = (network.network.id, DeviceId(Uuid::from_u128(102)));
        let peer_three = (network.network.id, DeviceId(Uuid::from_u128(103)));
        let mut peers = HashMap::new();
        assert!(update_peer_addresses(
            &mut peers,
            peer_two,
            &[
                "100.64.90.2".parse().unwrap(),
                "fd42:4d4c:90::2".parse().unwrap()
            ],
            self_id,
            &networks,
        ));
        assert!(!update_peer_addresses(
            &mut peers,
            peer_three,
            &["100.64.90.2".parse().unwrap()],
            self_id,
            &networks,
        ));
        assert!(!update_peer_addresses(
            &mut peers,
            peer_three,
            &["100.65.90.3".parse().unwrap()],
            self_id,
            &networks,
        ));
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn stale_peer_directory_addresses_expire() {
        let started = Instant::now();
        let mut route = PeerRoute::empty();
        route.set_assigned_addresses_at(vec!["100.64.90.2".parse().unwrap()], started);
        route.expire_directory(started + Duration::from_secs(119));
        assert_eq!(route.assigned_addresses.len(), 1);
        route.expire_directory(started + Duration::from_secs(121));
        assert!(route.assigned_addresses.is_empty());
        assert!(route.directory_last_seen.is_none());
    }

    #[test]
    fn unicast_selects_one_peer_while_group_traffic_fans_out() {
        let network = test_joined_network();
        let peer_two = DeviceId(Uuid::from_u128(102));
        let peer_three = DeviceId(Uuid::from_u128(103));
        let mut route_two = PeerRoute::empty();
        route_two.set_assigned_addresses(vec!["100.64.90.2".parse().unwrap()]);
        let mut route_three = PeerRoute::empty();
        route_three.set_assigned_addresses(vec!["100.64.90.3".parse().unwrap()]);
        let peers = HashMap::from([
            ((network.network.id, peer_two), route_two),
            ((network.network.id, peer_three), route_three),
        ]);

        let unicast = ipv4_packet([100, 64, 90, 1], [100, 64, 90, 2]);
        assert_eq!(
            peer_targets_for_packet(&peers, &network, None, &unicast)
                .into_iter()
                .map(|(device, _)| device)
                .collect::<Vec<_>>(),
            vec![peer_two]
        );

        let broadcast = ipv4_packet([100, 64, 90, 1], [100, 64, 90, 255]);
        assert_eq!(
            peer_targets_for_packet(&peers, &network, None, &broadcast).len(),
            2
        );
        let multicast = ipv6_packet("fd42:4d4c:90::1", "ff02::1");
        assert_eq!(
            network_for_ip_packet(&[network.clone()], &multicast),
            Some(&network)
        );
        assert_eq!(
            peer_targets_for_packet(&peers, &network, None, &multicast).len(),
            2
        );
    }

    #[test]
    fn inbound_packet_requires_authorized_source_and_local_destination() {
        let network = test_joined_network();
        let local_device = DeviceId(Uuid::from_u128(100));
        let source_device = DeviceId(Uuid::from_u128(101));
        let mut source_route = PeerRoute::empty();
        source_route.set_assigned_addresses(vec!["100.64.90.2".parse().unwrap()]);

        let valid = ipv4_packet([100, 64, 90, 2], [100, 64, 90, 1]);
        assert!(packet_is_authorized_for_delivery(
            &network,
            source_device,
            &source_route,
            local_device,
            local_device,
            &valid,
        ));
        let forged_source = ipv4_packet([100, 64, 90, 9], [100, 64, 90, 1]);
        assert!(!packet_is_authorized_for_delivery(
            &network,
            source_device,
            &source_route,
            local_device,
            local_device,
            &forged_source,
        ));
        let wrong_destination = ipv4_packet([100, 64, 90, 2], [100, 64, 90, 3]);
        assert!(!packet_is_authorized_for_delivery(
            &network,
            source_device,
            &source_route,
            local_device,
            local_device,
            &wrong_destination,
        ));
        let broadcast = ipv4_packet([100, 64, 90, 2], [100, 64, 90, 255]);
        assert!(packet_is_authorized_for_delivery(
            &network,
            source_device,
            &source_route,
            DeviceId(Uuid::nil()),
            local_device,
            &broadcast,
        ));
        assert!(!packet_is_authorized_for_delivery(
            &network,
            source_device,
            &source_route,
            DeviceId(Uuid::nil()),
            local_device,
            &valid,
        ));
    }

    #[test]
    fn inbound_custom_route_is_delivered_only_to_the_signed_gateway() {
        let mut network = test_joined_network();
        let signing = SigningKey::from_bytes(&[62; 32]);
        let gateway = DeviceId(Uuid::from_u128(620));
        let gateway_certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id: network.network.id,
                device_id: gateway,
                device_public_key: vec![8; 32],
                assigned_addresses: vec!["100.64.90.254".parse().unwrap()],
                allowed_routes: vec!["10.62.0.0/16".into()],
                issued_at_unix_seconds: now(),
                expires_at_unix_seconds: Some(now() + 300),
            },
            Uuid::from_u128(621),
            1,
            &signing,
        )
        .unwrap();
        let policy = NetworkPolicyManifest::sign(
            network.network.id,
            1,
            vec![PolicyRoute {
                prefix: "10.62.0.0/16".into(),
                gateway_certificate,
            }],
            DnsPolicy::default(),
            now(),
            now() + 300,
            &signing,
        )
        .unwrap();
        network.control_plane.authorization_manifest = Some(
            NetworkAuthorizationManifest::sign(
                network.network.id,
                1,
                1,
                vec![AuthorizedMembership {
                    device_id: gateway,
                    certificate_id: policy.routes[0].gateway_certificate.certificate_id,
                    device_public_key: policy.routes[0]
                        .gateway_certificate
                        .claims
                        .device_public_key
                        .clone(),
                    network_key_epoch: 1,
                }],
                vec![],
                now(),
                now() + 300,
                &signing,
            )
            .unwrap(),
        );
        network.control_plane.pinned_controller_public_key =
            signing.verifying_key().to_bytes().to_vec();
        network.control_plane.policy_manifest = Some(policy);
        let mut source_route = PeerRoute::empty();
        source_route.set_assigned_addresses(vec!["100.64.90.2".parse().unwrap()]);
        let source_member = DeviceId(Uuid::from_u128(623));
        let packet = ipv4_packet([100, 64, 90, 2], [10, 62, 1, 9]);
        assert!(packet_is_authorized_for_delivery(
            &network,
            source_member,
            &source_route,
            gateway,
            gateway,
            &packet,
        ));
        let other = DeviceId(Uuid::from_u128(622));
        assert!(!packet_is_authorized_for_delivery(
            &network,
            source_member,
            &source_route,
            other,
            other,
            &packet,
        ));
    }

    #[test]
    fn gateway_return_source_requires_current_signed_route_authorization() {
        let mut network = test_joined_network();
        let signing = SigningKey::from_bytes(&[63; 32]);
        let gateway = DeviceId(Uuid::from_u128(630));
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id: network.network.id,
                device_id: gateway,
                device_public_key: vec![9; 32],
                assigned_addresses: vec!["100.64.90.254".parse().unwrap()],
                allowed_routes: vec!["10.63.0.0/16".into()],
                issued_at_unix_seconds: now(),
                expires_at_unix_seconds: Some(now() + 300),
            },
            Uuid::from_u128(631),
            1,
            &signing,
        )
        .unwrap();
        let authorization = NetworkAuthorizationManifest::sign(
            network.network.id,
            1,
            1,
            vec![AuthorizedMembership {
                device_id: gateway,
                certificate_id: certificate.certificate_id,
                device_public_key: certificate.claims.device_public_key.clone(),
                network_key_epoch: 1,
            }],
            vec![],
            now(),
            now() + 300,
            &signing,
        )
        .unwrap();
        network.control_plane.policy_manifest = Some(
            NetworkPolicyManifest::sign(
                network.network.id,
                1,
                vec![PolicyRoute {
                    prefix: "10.63.0.0/16".into(),
                    gateway_certificate: certificate,
                }],
                DnsPolicy::default(),
                now(),
                now() + 300,
                &signing,
            )
            .unwrap(),
        );
        network.control_plane.authorization_manifest = Some(authorization);
        network.control_plane.pinned_controller_public_key =
            signing.verifying_key().to_bytes().to_vec();
        let mut gateway_route = PeerRoute::empty();
        gateway_route.set_assigned_addresses(vec!["100.64.90.254".parse().unwrap()]);
        let returned = ipv4_packet([10, 63, 1, 9], [100, 64, 90, 1]);
        assert!(packet_is_authorized_for_delivery(
            &network,
            gateway,
            &gateway_route,
            DeviceId(Uuid::from_u128(100)),
            DeviceId(Uuid::from_u128(100)),
            &returned,
        ));
        assert!(!packet_is_authorized_for_delivery(
            &network,
            DeviceId(Uuid::from_u128(632)),
            &gateway_route,
            DeviceId(Uuid::from_u128(100)),
            DeviceId(Uuid::from_u128(100)),
            &returned,
        ));
        let outside = ipv4_packet([10, 64, 1, 9], [100, 64, 90, 1]);
        assert!(!packet_is_authorized_for_delivery(
            &network,
            gateway,
            &gateway_route,
            DeviceId(Uuid::from_u128(100)),
            DeviceId(Uuid::from_u128(100)),
            &outside,
        ));
        network.control_plane.authorization_manifest = None;
        assert!(!packet_is_authorized_for_delivery(
            &network,
            gateway,
            &gateway_route,
            DeviceId(Uuid::from_u128(100)),
            DeviceId(Uuid::from_u128(100)),
            &returned,
        ));
    }

    #[test]
    fn first_packets_are_bounded_and_queued_while_the_session_is_pending() {
        let network = test_joined_network();
        let local_device = DeviceId(Uuid::from_u128(201));
        let peer_device = DeviceId(Uuid::from_u128(202));
        let local_identity = SigningKey::from_bytes(&[21_u8; 32]);
        let peer_identity = SigningKey::from_bytes(&[22_u8; 32]);
        let first_packet = ipv4_packet([100, 64, 90, 1], [100, 64, 90, 2]);
        let mut sessions = HashMap::new();

        assert!(matches!(
            prepare_outbound_peer_packet(
                &mut sessions,
                &network,
                local_device,
                peer_device,
                &peer_identity.verifying_key().to_bytes(),
                &local_identity,
                &first_packet,
            )
            .unwrap(),
            Some(PreparedPeerPacket::Handshake(_))
        ));
        for suffix in 0_u8..12 {
            let packet = ipv4_packet([100, 64, 90, 1], [100, 64, 90, suffix]);
            let _ = prepare_outbound_peer_packet(
                &mut sessions,
                &network,
                local_device,
                peer_device,
                &peer_identity.verifying_key().to_bytes(),
                &local_identity,
                &packet,
            )
            .unwrap();
        }
        let Some(PeerSessionState::Pending { queued_packets, .. }) =
            sessions.get(&(network.network.id, peer_device))
        else {
            panic!("expected a pending pairwise session");
        };
        assert_eq!(queued_packets.len(), 8);
        assert_eq!(queued_packets.front(), Some(&first_packet));
    }

    #[test]
    fn established_send_counter_requires_a_successful_transport_send() {
        let network = test_joined_network();
        let local_device = DeviceId(Uuid::from_u128(231));
        let peer_device = DeviceId(Uuid::from_u128(232));
        let local_identity = SigningKey::from_bytes(&[31_u8; 32]);
        let peer_identity = SigningKey::from_bytes(&[32_u8; 32]);
        let mut sessions = HashMap::from([(
            (network.network.id, peer_device),
            test_established_session(
                &network,
                local_device,
                peer_device,
                &local_identity,
                &peer_identity,
            ),
        )]);

        assert!(matches!(
            prepare_outbound_peer_packet(
                &mut sessions,
                &network,
                local_device,
                peer_device,
                &peer_identity.verifying_key().to_bytes(),
                &local_identity,
                &ipv4_packet([100, 64, 90, 1], [100, 64, 90, 2]),
            )
            .unwrap(),
            Some(PreparedPeerPacket::Data(_))
        ));
        let session = sessions
            .get_mut(&(network.network.id, peer_device))
            .unwrap();
        let PeerSessionState::Established { next_sequence, .. } = session else {
            panic!("expected an established session");
        };
        assert_eq!(*next_sequence, 1, "sealing must consume the nonce");
        session.record_encrypted_send_results([false]);
        assert_eq!(session.telemetry().security.encrypted_packets_sent, 0);
        session.record_encrypted_send_results([true]);
        assert_eq!(session.telemetry().security.encrypted_packets_sent, 1);
        let PeerSessionState::Established { next_sequence, .. } = session else {
            unreachable!();
        };
        assert_eq!(*next_sequence, 1, "send results must not reuse a nonce");
    }

    #[test]
    fn handshake_queue_counts_only_successfully_sent_encrypted_packets() {
        let network = test_joined_network();
        let local_device = DeviceId(Uuid::from_u128(241));
        let peer_device = DeviceId(Uuid::from_u128(242));
        let local_identity = SigningKey::from_bytes(&[41_u8; 32]);
        let peer_identity = SigningKey::from_bytes(&[42_u8; 32]);
        let mut session = test_established_session(
            &network,
            local_device,
            peer_device,
            &local_identity,
            &peer_identity,
        );
        let PeerSessionState::Established {
            keys,
            next_sequence,
            ..
        } = &mut session
        else {
            panic!("expected an established session");
        };
        let queued_packets = VecDeque::from([
            ipv4_packet([100, 64, 90, 1], [100, 64, 90, 2]),
            ipv4_packet([100, 64, 90, 1], [100, 64, 90, 3]),
            ipv4_packet([100, 64, 90, 1], [100, 64, 90, 4]),
        ]);
        let (consumed_sequences, encrypted) = seal_queued_packets(
            keys,
            network.network.id,
            local_device,
            peer_device,
            queued_packets,
        )
        .unwrap();
        *next_sequence = consumed_sequences;

        assert_eq!(encrypted.len(), 3);
        assert_eq!(*next_sequence, 3, "all sealed packets consume nonces");
        session.record_encrypted_send_results([true, false, true]);
        assert_eq!(session.telemetry().security.encrypted_packets_sent, 2);
        let PeerSessionState::Established { next_sequence, .. } = session else {
            unreachable!();
        };
        assert_eq!(
            next_sequence, 3,
            "failed sends must not roll nonce state back"
        );
    }

    #[test]
    fn membership_directory_binds_the_peer_identity_key() {
        let controller = SigningKey::from_bytes(&[23_u8; 32]);
        let first_identity = SigningKey::from_bytes(&[24_u8; 32]);
        let second_identity = SigningKey::from_bytes(&[25_u8; 32]);
        let network = test_joined_network();
        let local_device = DeviceId(Uuid::from_u128(211));
        let peer_device = DeviceId(Uuid::from_u128(212));
        let make_certificate = |identity: &SigningKey| {
            MembershipCertificate::sign(
                MembershipClaims {
                    network_id: network.network.id,
                    device_id: peer_device,
                    device_public_key: identity.verifying_key().to_bytes().to_vec(),
                    assigned_addresses: vec!["100.64.90.2".parse().unwrap()],
                    allowed_routes: vec!["100.64.90.0/24".into()],
                    issued_at_unix_seconds: now(),
                    expires_at_unix_seconds: None,
                },
                &controller,
            )
            .unwrap()
        };
        let mut peers = HashMap::new();
        assert_eq!(
            update_peer_membership(
                &mut peers,
                &make_certificate(&first_identity),
                local_device,
                std::slice::from_ref(&network),
            ),
            Some(false)
        );
        assert_eq!(
            peers
                .get(&(network.network.id, peer_device))
                .unwrap()
                .device_public_key,
            first_identity.verifying_key().to_bytes()
        );
        assert_eq!(
            update_peer_membership(
                &mut peers,
                &make_certificate(&second_identity),
                local_device,
                std::slice::from_ref(&network),
            ),
            Some(true)
        );
    }

    #[test]
    fn verified_session_handshake_ids_cannot_be_replayed() {
        let started = Instant::now();
        let peer = (
            NetworkId(Uuid::from_u128(221)),
            DeviceId(Uuid::from_u128(222)),
        );
        let session_id = [23_u8; 16];
        let mut seen = HashMap::new();
        assert!(record_session_handshake(
            &mut seen, peer, session_id, started
        ));
        assert!(!record_session_handshake(
            &mut seen,
            peer,
            session_id,
            started + Duration::from_secs(1)
        ));
        assert!(record_session_handshake(
            &mut seen,
            peer,
            session_id,
            started + HANDSHAKE_REPLAY_TTL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn parses_transaction_bound_relay_acknowledgement() {
        let network = NetworkId(Uuid::from_u128(51));
        let device = DeviceId(Uuid::from_u128(52));
        let nonce = [53_u8; 16];
        let mut packet = Vec::from(RELAY_MAGIC);
        packet.push(RELAY_REGISTER_ACK);
        packet.extend_from_slice(network.0.as_bytes());
        packet.extend_from_slice(device.0.as_bytes());
        let legacy = packet.clone();
        packet.extend_from_slice(&nonce);
        assert_eq!(
            parse_registration_ack(&packet),
            Some((network, device, nonce))
        );
        assert_eq!(legacy.len(), 37);
        assert_eq!(parse_registration_ack(&legacy), None);
    }

    #[test]
    fn relay_acknowledgement_requires_the_matching_pending_transaction() {
        let network = NetworkId(Uuid::from_u128(61));
        let other_network = NetworkId(Uuid::from_u128(62));
        let device = DeviceId(Uuid::from_u128(63));
        let relay: SocketAddr = "203.0.113.61:51820".parse().unwrap();
        let other_relay: SocketAddr = "203.0.113.62:51820".parse().unwrap();
        let nonce = [64_u8; 16];
        let issued_at = Instant::now();
        let transaction = RelayRegistrationTransaction {
            network_id: network,
            device_id: device,
            endpoint: relay,
            planet_manifest_version: Some(2),
            identity: None,
            issued_at,
        };

        let mut transactions = HashMap::from([(nonce, transaction)]);
        let mut health = EndpointHealthTable::default();

        assert!(!acknowledge_relay_registration(
            &mut transactions,
            &mut health,
            network,
            device,
            [65_u8; 16],
            relay,
            issued_at,
        ));
        assert!(!acknowledge_relay_registration(
            &mut transactions,
            &mut health,
            other_network,
            device,
            nonce,
            relay,
            issued_at,
        ));
        assert!(!acknowledge_relay_registration(
            &mut transactions,
            &mut health,
            network,
            device,
            nonce,
            other_relay,
            issued_at,
        ));
        assert!(!health.relay_is_healthy(network, relay, issued_at));
        assert_eq!(transactions.len(), 1);

        assert!(acknowledge_relay_registration(
            &mut transactions,
            &mut health,
            network,
            device,
            nonce,
            relay,
            issued_at,
        ));
        assert!(transactions.is_empty());
        assert!(health.relay_is_healthy(network, relay, issued_at));

        assert!(!acknowledge_relay_registration(
            &mut transactions,
            &mut health,
            network,
            device,
            nonce,
            relay,
            issued_at,
        ));
    }

    #[test]
    fn expired_relay_acknowledgement_does_not_consume_or_mark_health() {
        let network = NetworkId(Uuid::from_u128(71));
        let device = DeviceId(Uuid::from_u128(72));
        let relay: SocketAddr = "203.0.113.71:51820".parse().unwrap();
        let nonce = [73_u8; 16];
        let issued_at = Instant::now();
        let mut transactions = HashMap::from([(
            nonce,
            RelayRegistrationTransaction {
                network_id: network,
                device_id: device,
                endpoint: relay,
                planet_manifest_version: Some(2),
                identity: None,
                issued_at,
            },
        )]);
        let now = issued_at + TRANSPORT_TRANSACTION_TTL;
        let mut health = EndpointHealthTable::default();

        assert!(!acknowledge_relay_registration(
            &mut transactions,
            &mut health,
            network,
            device,
            nonce,
            relay,
            now,
        ));
        assert_eq!(transactions.len(), 1);
        assert!(!health.relay_is_healthy(network, relay, now));
    }

    #[test]
    fn signed_relay_acknowledgement_rejects_replay_cross_relay_and_out_of_order() {
        let relay_key = SigningKey::from_bytes(&[74; 32]);
        let relay_id = Uuid::from_u128(75);
        let network = NetworkId(Uuid::from_u128(76));
        let device = DeviceId(Uuid::from_u128(77));
        let relay: SocketAddr = "203.0.113.76:51820".parse().unwrap();
        let other_relay: SocketAddr = "203.0.113.77:51820".parse().unwrap();
        let nonce = [78; 16];
        let issued_at = Instant::now();
        let identity =
            ServiceIdentityPolicy::stable(relay_id, relay_key.verifying_key().to_bytes().to_vec());
        let transaction = RelayRegistrationTransaction {
            network_id: network,
            device_id: device,
            endpoint: relay,
            planet_manifest_version: Some(3),
            identity: Some(identity),
            issued_at,
        };
        let acknowledgement = SignedRelayRegistrationAck::sign(
            network,
            device,
            relay_id,
            nonce,
            "198.51.100.76:41000".parse().unwrap(),
            100,
            115,
            None,
            &[&relay_key],
        )
        .unwrap();
        let mut transactions = HashMap::from([(nonce, transaction.clone())]);
        let mut health = EndpointHealthTable::default();
        assert!(acknowledge_signed_relay_registration(
            &mut transactions,
            &mut health,
            &acknowledgement,
            other_relay,
            issued_at,
            105,
        )
        .is_none());
        assert_eq!(transactions.len(), 1);

        let out_of_order = SignedRelayRegistrationAck::sign(
            network,
            device,
            relay_id,
            [79; 16],
            "198.51.100.76:41000".parse().unwrap(),
            100,
            115,
            None,
            &[&relay_key],
        )
        .unwrap();
        assert!(acknowledge_signed_relay_registration(
            &mut transactions,
            &mut health,
            &out_of_order,
            relay,
            issued_at,
            105,
        )
        .is_none());
        assert_eq!(transactions.len(), 1);

        assert!(acknowledge_signed_relay_registration(
            &mut transactions,
            &mut health,
            &acknowledgement,
            relay,
            issued_at,
            105,
        )
        .is_some());
        assert!(transactions.is_empty());
        assert!(acknowledge_signed_relay_registration(
            &mut transactions,
            &mut health,
            &acknowledgement,
            relay,
            issued_at,
            105,
        )
        .is_none());
    }

    #[tokio::test]
    async fn root_response_cannot_inject_a_peer_from_another_network() {
        let directory =
            env::temp_dir().join(format!("meshlake-root-scope-test-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let state = agent.state.read().await;
        let local_device = state.device_id;
        let local_identity = identity_signing_key(&state).unwrap();
        drop(state);

        let controller = SigningKey::from_bytes(&[51_u8; 32]);
        let root_identity = SigningKey::from_bytes(&[52_u8; 32]);
        let peer_identity = SigningKey::from_bytes(&[53_u8; 32]);
        let requested_network = NetworkId(Uuid::from_u128(510));
        let foreign_network = NetworkId(Uuid::from_u128(520));
        let peer_device = DeviceId(Uuid::from_u128(521));
        let requested = joined_network_with_authorization(
            &controller,
            &local_identity,
            local_device,
            requested_network,
            Uuid::from_u128(511),
            1,
            1,
            String::new(),
        );
        let mut foreign = joined_network_with_authorization(
            &controller,
            &local_identity,
            local_device,
            foreign_network,
            Uuid::from_u128(522),
            1,
            1,
            String::new(),
        );
        let timestamp = now();
        let peer_certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id: foreign_network,
                device_id: peer_device,
                device_public_key: peer_identity.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.90.2".parse().unwrap()],
                allowed_routes: vec!["100.64.90.0/24".into()],
                issued_at_unix_seconds: timestamp,
                expires_at_unix_seconds: Some(timestamp + 86_400),
            },
            Uuid::from_u128(523),
            1,
            &controller,
        )
        .unwrap();
        let local_foreign_certificate = foreign.certificate.as_ref().unwrap();
        foreign.control_plane.authorization_manifest = Some(
            NetworkAuthorizationManifest::sign(
                foreign_network,
                2,
                1,
                vec![
                    AuthorizedMembership {
                        device_id: local_foreign_certificate.claims.device_id,
                        certificate_id: local_foreign_certificate.certificate_id,
                        device_public_key: local_foreign_certificate
                            .claims
                            .device_public_key
                            .clone(),
                        network_key_epoch: local_foreign_certificate.network_key_epoch,
                    },
                    AuthorizedMembership {
                        device_id: peer_device,
                        certificate_id: peer_certificate.certificate_id,
                        device_public_key: peer_certificate.claims.device_public_key.clone(),
                        network_key_epoch: peer_certificate.network_key_epoch,
                    },
                ],
                vec![],
                timestamp,
                timestamp + 90,
                &controller,
            )
            .unwrap(),
        );
        agent.state.write().await.networks = vec![requested, foreign];

        let root_endpoint: SocketAddr = "127.0.0.1:51819".parse().unwrap();
        let nonce = [54_u8; 16];
        let response = SignedRootResponse::sign(
            nonce,
            RootResponse::Registered {
                observed_endpoint: "198.51.100.54:40000".parse().unwrap(),
                peers: vec![RootPeer {
                    network_id: foreign_network,
                    device_id: peer_device,
                    candidates: vec!["127.0.0.1:52000".parse().unwrap()],
                    assigned_addresses: peer_certificate.claims.assigned_addresses.clone(),
                    certificate: Some(peer_certificate),
                }],
                refresh_after_seconds: 20,
                authorization_hints: Vec::new(),
            },
            &root_identity,
        )
        .unwrap();
        let mut root_transactions = HashMap::from([(
            nonce,
            RootTransaction {
                network_id: requested_network,
                endpoint: root_endpoint,
                public_key: root_identity.verifying_key().to_bytes().to_vec(),
                identity: None,
                issued_at: Instant::now(),
            },
        )]);
        let roots = vec![PlanetRoot {
            public_key: root_identity.verifying_key().to_bytes().to_vec(),
            endpoints: vec![root_endpoint],
            priority: 0,
            identity: None,
        }];
        let configuration = TransportConfiguration {
            networks: HashMap::from([(
                requested_network,
                NetworkTransportConfiguration {
                    root_servers: roots,
                    ..NetworkTransportConfiguration::default()
                },
            )]),
            ..TransportConfiguration::default()
        };
        let sockets = TransportSockets::bind().await.unwrap();
        let mut peers = HashMap::<PeerKey, PeerRoute>::new();
        let mut sessions = HashMap::<PeerKey, PeerSessionState>::new();

        assert!(handle_root_response(
            &agent,
            &sockets,
            root_endpoint,
            &serde_json::to_vec(&response).unwrap(),
            &mut peers,
            &mut sessions,
            1,
            &configuration,
            &mut root_transactions,
            &mut HashMap::new(),
        )
        .await
        .unwrap());
        assert!(!peers.contains_key(&(foreign_network, peer_device)));
        let health = agent.transport_health.read().await;
        let health_time = Instant::now();
        assert!(health
            .endpoints
            .root_is_responsive(requested_network, root_endpoint, health_time));
        assert!(!health
            .endpoints
            .root_is_responsive(foreign_network, root_endpoint, health_time));
        drop(health);
        drop(sockets);
        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[tokio::test]
    async fn root_response_transaction_survives_rejection_then_is_single_use() {
        let directory =
            env::temp_dir().join(format!("meshlake-root-transaction-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let root = SigningKey::from_bytes(&[55; 32]);
        let attacker = SigningKey::from_bytes(&[56; 32]);
        let network_id = NetworkId(Uuid::from_u128(550));
        let root_endpoint: SocketAddr = "127.0.0.1:51819".parse().unwrap();
        let wrong_endpoint: SocketAddr = "127.0.0.1:51818".parse().unwrap();
        let nonce = [57; 16];
        let response = SignedRootResponse::sign(
            nonce,
            RootResponse::Registered {
                observed_endpoint: "198.51.100.57:40000".parse().unwrap(),
                peers: Vec::new(),
                refresh_after_seconds: 20,
                authorization_hints: Vec::new(),
            },
            &root,
        )
        .unwrap();
        let mut invalid_signature = response.clone();
        invalid_signature.signature[0] ^= 1;
        let configured_root = PlanetRoot {
            public_key: root.verifying_key().to_bytes().to_vec(),
            endpoints: vec![root_endpoint],
            priority: 0,
            identity: None,
        };
        let wrong_pinned_root = PlanetRoot {
            public_key: attacker.verifying_key().to_bytes().to_vec(),
            endpoints: vec![root_endpoint],
            priority: 0,
            identity: None,
        };
        let configuration =
            |configured_network: NetworkId, roots: Vec<PlanetRoot>| TransportConfiguration {
                networks: HashMap::from([(
                    configured_network,
                    NetworkTransportConfiguration {
                        root_servers: roots.clone(),
                        ..NetworkTransportConfiguration::default()
                    },
                )]),
                root_servers: roots,
                ..TransportConfiguration::default()
            };
        let mut root_transactions = HashMap::from([(
            nonce,
            RootTransaction {
                network_id,
                endpoint: root_endpoint,
                public_key: root.verifying_key().to_bytes().to_vec(),
                identity: None,
                issued_at: Instant::now(),
            },
        )]);
        let sockets = TransportSockets::bind().await.unwrap();
        let mut peers = HashMap::<PeerKey, PeerRoute>::new();
        let mut sessions = HashMap::<PeerKey, PeerSessionState>::new();
        let mut schedules = HashMap::new();
        let encoded = serde_json::to_vec(&response).unwrap();
        let invalid_encoded = serde_json::to_vec(&invalid_signature).unwrap();

        for (remote, packet, configured_network, roots) in [
            (
                wrong_endpoint,
                encoded.as_slice(),
                network_id,
                vec![configured_root.clone()],
            ),
            (
                root_endpoint,
                encoded.as_slice(),
                NetworkId(Uuid::from_u128(551)),
                vec![configured_root.clone()],
            ),
            (
                root_endpoint,
                encoded.as_slice(),
                network_id,
                vec![wrong_pinned_root],
            ),
            (
                root_endpoint,
                invalid_encoded.as_slice(),
                network_id,
                vec![configured_root.clone()],
            ),
        ] {
            let current_configuration = configuration(configured_network, roots);
            assert!(handle_root_response(
                &agent,
                &sockets,
                remote,
                packet,
                &mut peers,
                &mut sessions,
                1,
                &current_configuration,
                &mut root_transactions,
                &mut schedules,
            )
            .await
            .unwrap());
            assert!(root_transactions.contains_key(&nonce));
            assert!(!agent
                .transport_health
                .read()
                .await
                .endpoints
                .root_is_responsive(network_id, root_endpoint, Instant::now()));
        }

        root_transactions.get_mut(&nonce).unwrap().issued_at =
            Instant::now() - TRANSPORT_TRANSACTION_TTL;
        let active_configuration = configuration(network_id, vec![configured_root.clone()]);
        assert!(handle_root_response(
            &agent,
            &sockets,
            root_endpoint,
            &encoded,
            &mut peers,
            &mut sessions,
            1,
            &active_configuration,
            &mut root_transactions,
            &mut schedules,
        )
        .await
        .unwrap());
        assert!(root_transactions.contains_key(&nonce));
        assert!(!agent
            .transport_health
            .read()
            .await
            .endpoints
            .root_is_responsive(network_id, root_endpoint, Instant::now()));

        root_transactions.get_mut(&nonce).unwrap().issued_at = Instant::now();
        let active_configuration = configuration(network_id, vec![configured_root]);
        assert!(handle_root_response(
            &agent,
            &sockets,
            root_endpoint,
            &encoded,
            &mut peers,
            &mut sessions,
            1,
            &active_configuration,
            &mut root_transactions,
            &mut schedules,
        )
        .await
        .unwrap());
        assert!(!root_transactions.contains_key(&nonce));
        {
            let health = agent.transport_health.read().await;
            assert!(health
                .endpoints
                .root_is_responsive(network_id, root_endpoint, Instant::now()));
        }
        *agent.transport_health.write().await = TransportHealth::default();
        assert!(handle_root_response(
            &agent,
            &sockets,
            root_endpoint,
            &encoded,
            &mut peers,
            &mut sessions,
            1,
            &active_configuration,
            &mut root_transactions,
            &mut schedules,
        )
        .await
        .unwrap());
        assert!(!agent
            .transport_health
            .read()
            .await
            .endpoints
            .root_is_responsive(network_id, root_endpoint, Instant::now()));

        drop(sockets);
        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[tokio::test]
    async fn root_response_v3_rechecks_current_identity_policy_before_consuming_nonce() {
        let directory =
            env::temp_dir().join(format!("meshlake-root-v3-transaction-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let current = SigningKey::from_bytes(&[58; 32]);
        let next = SigningKey::from_bytes(&[59; 32]);
        let network_id = NetworkId(Uuid::from_u128(580));
        let root_id = Uuid::from_u128(581);
        let root_endpoint: SocketAddr = "127.0.0.1:51819".parse().unwrap();
        let nonce = [60; 16];
        let stable_identity =
            ServiceIdentityPolicy::stable(root_id, current.verifying_key().to_bytes().to_vec());
        let response = SignedRootResponse::sign_with_identity(
            nonce,
            RootResponse::Registered {
                observed_endpoint: "198.51.100.60:40000".parse().unwrap(),
                peers: Vec::new(),
                refresh_after_seconds: 20,
                authorization_hints: Vec::new(),
            },
            root_id,
            &[&current],
        )
        .unwrap();
        let configured_root = |identity: ServiceIdentityPolicy| PlanetRoot {
            public_key: current.verifying_key().to_bytes().to_vec(),
            endpoints: vec![root_endpoint],
            priority: 0,
            identity: Some(identity),
        };
        let configuration = |identity: ServiceIdentityPolicy| TransportConfiguration {
            networks: HashMap::from([(
                network_id,
                NetworkTransportConfiguration {
                    root_servers: vec![configured_root(identity)],
                    planet_manifest_version: Some(3),
                    ..NetworkTransportConfiguration::default()
                },
            )]),
            ..TransportConfiguration::default()
        };
        let mut root_transactions = HashMap::from([(
            nonce,
            RootTransaction {
                network_id,
                endpoint: root_endpoint,
                public_key: current.verifying_key().to_bytes().to_vec(),
                identity: Some(stable_identity.clone()),
                issued_at: Instant::now(),
            },
        )]);
        let sockets = TransportSockets::bind().await.unwrap();
        let mut peers = HashMap::<PeerKey, PeerRoute>::new();
        let mut sessions = HashMap::<PeerKey, PeerSessionState>::new();
        let mut schedules = HashMap::new();

        let mut tampered = response.clone();
        tampered.identity_signatures[0].signature[0] ^= 1;
        let stable_configuration = configuration(stable_identity.clone());
        assert!(handle_root_response(
            &agent,
            &sockets,
            root_endpoint,
            &serde_json::to_vec(&tampered).unwrap(),
            &mut peers,
            &mut sessions,
            1,
            &stable_configuration,
            &mut root_transactions,
            &mut schedules,
        )
        .await
        .unwrap());
        assert!(root_transactions.contains_key(&nonce));

        let timestamp = now();
        let changed_identity = ServiceIdentityPolicy {
            service_id: root_id,
            current_public_key: current.verifying_key().to_bytes().to_vec(),
            next_public_key: Some(next.verifying_key().to_bytes().to_vec()),
            transition_not_before_unix_seconds: Some(timestamp + 60),
            transition_not_after_unix_seconds: Some(timestamp + 120),
            revoked_public_keys: Vec::new(),
        };
        let changed_configuration = configuration(changed_identity);
        assert!(handle_root_response(
            &agent,
            &sockets,
            root_endpoint,
            &serde_json::to_vec(&response).unwrap(),
            &mut peers,
            &mut sessions,
            1,
            &changed_configuration,
            &mut root_transactions,
            &mut schedules,
        )
        .await
        .unwrap());
        assert!(root_transactions.contains_key(&nonce));
        assert!(!agent
            .transport_health
            .read()
            .await
            .endpoints
            .root_is_responsive(network_id, root_endpoint, Instant::now()));

        assert!(handle_root_response(
            &agent,
            &sockets,
            root_endpoint,
            &serde_json::to_vec(&response).unwrap(),
            &mut peers,
            &mut sessions,
            1,
            &stable_configuration,
            &mut root_transactions,
            &mut schedules,
        )
        .await
        .unwrap());
        assert!(!root_transactions.contains_key(&nonce));
        assert!(agent
            .transport_health
            .read()
            .await
            .endpoints
            .root_is_responsive(network_id, root_endpoint, Instant::now()));

        drop(sockets);
        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[test]
    fn route_prefers_low_rtt_then_penalizes_probe_timeout() {
        let fast: SocketAddr = "203.0.113.20:51820".parse().unwrap();
        let slow: SocketAddr = "[2001:db8::20]:51820".parse().unwrap();
        let started = Instant::now();
        let mut route = PeerRoute::new(fast);
        route.add_candidate(slow);

        route.mark_probe_sent(fast, started);
        assert!(route.mark_success(fast, started + Duration::from_millis(20)));
        route.mark_probe_sent(slow, started);
        assert!(route.mark_success(slow, started + Duration::from_millis(100)));
        assert_eq!(
            route.best_endpoint(started + Duration::from_millis(100)),
            Some(fast)
        );

        route.mark_probe_sent(fast, started + Duration::from_millis(200));
        route.expire_probes(started + Duration::from_secs(4));
        assert_eq!(route.candidates[0].consecutive_failures, 1);
        assert_eq!(
            route.best_endpoint(started + Duration::from_secs(4)),
            Some(slow)
        );

        // An already-expired probe must not be charged again on the next scan.
        route.expire_probes(started + Duration::from_secs(8));
        assert_eq!(route.candidates[0].consecutive_failures, 1);
    }

    #[test]
    fn route_discards_candidates_after_liveness_window() {
        let endpoint: SocketAddr = "203.0.113.21:51820".parse().unwrap();
        let started = Instant::now();
        let mut route = PeerRoute::new(endpoint);
        assert!(route.mark_success(endpoint, started));
        assert_eq!(
            route.best_endpoint(started + Duration::from_secs(44)),
            Some(endpoint)
        );
        assert_eq!(route.best_endpoint(started + Duration::from_secs(46)), None);
    }

    #[test]
    fn rtt_uses_seven_eighths_ewma() {
        assert_eq!(
            weighted_rtt(Duration::from_millis(100), Duration::from_millis(20)),
            Duration::from_millis(90)
        );
    }

    #[test]
    fn punch_ack_is_not_answered_again() {
        assert_eq!(punch_response_kind(RELAY_PUNCH), Some(RELAY_PUNCH_ACK));
        assert_eq!(punch_response_kind(RELAY_PUNCH_ACK), None);
    }

    #[test]
    fn transport_configuration_keeps_planet_relays_scoped_per_network() {
        let mut first = test_joined_network();
        let first_id = first.network.id;
        first.control_plane.verified_relays = vec![PlanetRelay {
            endpoint: "203.0.113.10:51820".parse().unwrap(),
            priority: 0,
            identity: None,
        }];
        first.control_plane.verified_roots = vec![PlanetRoot {
            public_key: vec![1; 32],
            endpoints: vec!["203.0.113.10:51819".parse().unwrap()],
            priority: 0,
            identity: None,
        }];
        first.control_plane.verified_stun_servers = vec!["stun-a.example:3478".into()];

        let mut second = test_joined_network();
        second.network.id = NetworkId(Uuid::from_u128(91));
        second.network.name = "planet-b".into();
        second.control_plane.verified_relays = vec![PlanetRelay {
            endpoint: "198.51.100.20:51820".parse().unwrap(),
            priority: 0,
            identity: None,
        }];
        second.control_plane.verified_roots = vec![PlanetRoot {
            public_key: vec![2; 32],
            endpoints: vec!["198.51.100.20:51819".parse().unwrap()],
            priority: 0,
            identity: None,
        }];
        second.control_plane.verified_stun_servers = vec!["stun-b.example:3478".into()];
        let second_id = second.network.id;

        let mut state = PersistedState::new();
        state.relay_endpoints = vec!["192.0.2.50:51820".parse().unwrap()];
        state.networks = vec![first, second];
        let configuration = transport_configuration_from_state(&state);

        assert_eq!(
            configuration.relay_endpoints_for(first_id),
            &["203.0.113.10:51820".parse().unwrap()]
        );
        assert_eq!(
            configuration.relay_endpoints_for(second_id),
            &["198.51.100.20:51820".parse().unwrap()]
        );
        assert_eq!(configuration.relay_endpoints.len(), 2);
        assert_eq!(configuration.root_servers.len(), 2);
        assert_eq!(
            configuration.stun_servers,
            vec!["stun-a.example:3478", "stun-b.example:3478"]
        );
    }

    #[test]
    fn expired_planet_discovery_fails_closed_without_legacy_fallback() {
        let mut joined = test_joined_network();
        let network_id = joined.network.id;
        joined.control_plane.planet_manifest_version = Some(3);
        joined.control_plane.planet_last_issued_at_unix_seconds = Some(now().saturating_sub(100));
        joined.control_plane.planet_expires_at_unix_seconds = Some(now().saturating_sub(1));
        joined.control_plane.planet_semantic_digest = vec![1; 32];
        joined.control_plane.verified_relays = vec![PlanetRelay {
            endpoint: "203.0.113.95:51820".parse().unwrap(),
            priority: 0,
            identity: None,
        }];
        joined.control_plane.verified_roots = vec![PlanetRoot {
            public_key: vec![2; 32],
            endpoints: vec!["203.0.113.95:51819".parse().unwrap()],
            priority: 0,
            identity: None,
        }];

        let mut state = PersistedState::new();
        state.relay_endpoints = vec!["192.0.2.95:51820".parse().unwrap()];
        state.root_servers = vec![PlanetRoot {
            public_key: vec![3; 32],
            endpoints: vec!["192.0.2.95:51819".parse().unwrap()],
            priority: 0,
            identity: None,
        }];
        state.networks.push(joined);

        let configuration = transport_configuration_from_state(&state);
        assert!(configuration.relay_endpoints_for(network_id).is_empty());
        assert!(configuration.root_servers_for(network_id).is_empty());
        assert!(configuration.relay_endpoints.is_empty());
        assert!(configuration.root_servers.is_empty());
    }

    #[test]
    fn legacy_global_planet_state_migrates_into_each_network() {
        let controller = SigningKey::from_bytes(&[31_u8; 32]);
        let mut state = PersistedState::new();
        let joined = test_joined_network();
        let network_id = joined.network.id;
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            3,
            4,
            Vec::new(),
            Vec::new(),
            now(),
            now() + 90,
            &controller,
        )
        .unwrap();
        state.networks.push(joined);
        state.relay_endpoints = vec!["203.0.113.30:51820".parse().unwrap()];
        state.root_servers = vec![PlanetRoot {
            public_key: vec![9; 32],
            endpoints: vec!["203.0.113.30:51819".parse().unwrap()],
            priority: 0,
            identity: None,
        }];
        state.stun_servers = vec!["stun.example:3478".into()];
        state.planet = Some(PersistedPlanet {
            manifest_url: "https://planet.example/v1/planet".into(),
            controller_url: "https://planet.example".into(),
            controller_public_key_base64: STANDARD.encode(controller.verifying_key().to_bytes()),
            controller_tls_ca_pem: None,
        });
        state
            .authorizations
            .insert(network_id, authorization.clone());

        assert!(migrate_legacy_network_control_planes(&mut state));
        let control_plane = &state.networks[0].control_plane;
        assert_eq!(
            control_plane.controller_url.as_deref(),
            Some("https://planet.example")
        );
        assert_eq!(
            control_plane.planet_manifest_url.as_deref(),
            Some("https://planet.example/v1/planet")
        );
        assert_eq!(control_plane.verified_relays.len(), 1);
        assert_eq!(control_plane.verified_roots.len(), 1);
        assert_eq!(
            control_plane.authorization_manifest.as_ref(),
            Some(&authorization)
        );
        assert_eq!(control_plane.planet_manifest_version, Some(2));
        assert_eq!(control_plane.planet_last_issued_at_unix_seconds, Some(0));
        assert_eq!(control_plane.planet_expires_at_unix_seconds, None);
        assert_eq!(control_plane.planet_semantic_digest.len(), 32);
        assert!(state.authorizations.is_empty());
    }

    #[test]
    fn planet_update_rejects_version_time_and_equal_time_semantic_rollbacks() {
        let controller = SigningKey::from_bytes(&[82; 32]);
        let root = SigningKey::from_bytes(&[83; 32]);
        let relay = SigningKey::from_bytes(&[84; 32]);
        let other_relay = SigningKey::from_bytes(&[85; 32]);
        let timestamp = now();
        let controller_url = "https://controller.example";
        let root_endpoint = "203.0.113.82:51819".parse().unwrap();
        let relay_endpoint = "203.0.113.82:51820".parse().unwrap();
        let current = signed_planet_v3(
            &controller,
            controller_url,
            timestamp,
            root_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(83),
                root.verifying_key().to_bytes().to_vec(),
            ),
            relay_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(84),
                relay.verifying_key().to_bytes().to_vec(),
            ),
        );
        let mut control_plane = NetworkControlPlane::default();
        let update = validate_planet_update(
            &control_plane,
            &current,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap();
        apply_planet_update(&mut control_plane, None, &update);

        let downgraded = PlanetManifest::sign_v2(
            controller_url.into(),
            vec![PlanetRoot {
                public_key: root.verifying_key().to_bytes().to_vec(),
                endpoints: vec![root_endpoint],
                priority: 0,
                identity: None,
            }],
            vec![PlanetRelay {
                endpoint: relay_endpoint,
                priority: 0,
                identity: None,
            }],
            vec![],
            timestamp + 1,
            Some(timestamp + 300),
            &controller,
        )
        .unwrap();
        let error = validate_planet_update(
            &control_plane,
            &downgraded,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp + 1,
        )
        .unwrap_err();
        assert!(error.1.contains("version rollback"));

        let older = signed_planet_v3(
            &controller,
            controller_url,
            timestamp.saturating_sub(1),
            root_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(83),
                root.verifying_key().to_bytes().to_vec(),
            ),
            relay_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(84),
                relay.verifying_key().to_bytes().to_vec(),
            ),
        );
        let error = validate_planet_update(
            &control_plane,
            &older,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap_err();
        assert!(error.1.contains("issued_at rollback"));

        let changed_at_equal_time = signed_planet_v3(
            &controller,
            controller_url,
            timestamp,
            root_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(83),
                root.verifying_key().to_bytes().to_vec(),
            ),
            "203.0.113.85:51820".parse().unwrap(),
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(85),
                other_relay.verifying_key().to_bytes().to_vec(),
            ),
        );
        let error = validate_planet_update(
            &control_plane,
            &changed_at_equal_time,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap_err();
        assert!(error.1.contains("without advancing issued_at"));
    }

    #[tokio::test]
    async fn configured_planet_ca_replaces_the_matching_network_refresh_target() {
        let directory =
            env::temp_dir().join(format!("meshlake-planet-ca-target-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let controller = SigningKey::from_bytes(&[97; 32]);
        let foreign_controller = SigningKey::from_bytes(&[98; 32]);
        let timestamp = now();
        let controller_url = "https://controller.example";
        let manifest_url = "https://controller.example/v1/planet".to_owned();
        let manifest = signed_planet_v2(
            &controller,
            controller_url,
            timestamp,
            "203.0.113.97:51819".parse().unwrap(),
            "203.0.113.97:51820".parse().unwrap(),
        );

        let mut matching = test_joined_network();
        let matching_id = matching.network.id;
        matching.control_plane.controller_url = Some(controller_url.into());
        matching.control_plane.pinned_controller_public_key =
            controller.verifying_key().to_bytes().to_vec();
        matching.control_plane.controller_tls_ca_pem = Some("old-private-ca".into());
        let update = validate_planet_update(
            &matching.control_plane,
            &manifest,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap();
        apply_configured_planet_update(
            &mut matching.control_plane,
            manifest_url.clone(),
            Some("normalized-new-private-ca".into()),
            &update,
        );

        let mut foreign = test_joined_network();
        foreign.network.id = NetworkId(Uuid::from_u128(980));
        let foreign_id = foreign.network.id;
        foreign.control_plane.controller_url = Some("https://foreign.example".into());
        foreign.control_plane.planet_manifest_url =
            Some("https://foreign.example/v1/planet".into());
        foreign.control_plane.pinned_controller_public_key =
            foreign_controller.verifying_key().to_bytes().to_vec();
        foreign.control_plane.controller_tls_ca_pem = Some("foreign-private-ca".into());
        agent.state.write().await.networks = vec![matching, foreign];

        let targets = agent.planet_refresh_targets().await;
        assert_eq!(
            targets
                .iter()
                .find(|target| target.network_id == matching_id)
                .unwrap()
                .controller_tls_ca_pem
                .as_deref(),
            Some("normalized-new-private-ca")
        );
        assert_eq!(
            targets
                .iter()
                .find(|target| target.network_id == foreign_id)
                .unwrap()
                .controller_tls_ca_pem
                .as_deref(),
            Some("foreign-private-ca")
        );

        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[test]
    fn failed_planet_state_persistence_keeps_live_global_and_network_trust() {
        let controller = SigningKey::from_bytes(&[102; 32]);
        let foreign_controller = SigningKey::from_bytes(&[103; 32]);
        let old_root: SocketAddr = "203.0.113.102:51819".parse().unwrap();
        let old_relay: SocketAddr = "203.0.113.102:51820".parse().unwrap();
        let mut matching = test_joined_network();
        matching.control_plane.controller_url = Some("https://old-controller.example".into());
        matching.control_plane.planet_manifest_url =
            Some("https://old-controller.example/v1/planet".into());
        matching.control_plane.controller_tls_ca_pem = Some("old-private-ca".into());
        matching.control_plane.pinned_controller_public_key =
            controller.verifying_key().to_bytes().to_vec();
        matching.control_plane.planet_manifest_version = Some(2);
        matching.control_plane.planet_last_issued_at_unix_seconds = Some(100);
        matching.control_plane.planet_semantic_digest = vec![1; 32];
        matching.control_plane.verified_roots = vec![PlanetRoot {
            public_key: vec![1; 32],
            endpoints: vec![old_root],
            priority: 0,
            identity: None,
        }];
        matching.control_plane.verified_relays = vec![PlanetRelay {
            endpoint: old_relay,
            priority: 0,
            identity: None,
        }];
        let mut foreign = test_joined_network();
        foreign.network.id = NetworkId(Uuid::from_u128(1030));
        foreign.control_plane.controller_url = Some("https://foreign.example".into());
        foreign.control_plane.planet_manifest_url =
            Some("https://foreign.example/v1/planet".into());
        foreign.control_plane.controller_tls_ca_pem = Some("foreign-private-ca".into());
        foreign.control_plane.pinned_controller_public_key =
            foreign_controller.verifying_key().to_bytes().to_vec();
        foreign.control_plane.planet_manifest_version = Some(3);
        foreign.control_plane.planet_last_issued_at_unix_seconds = Some(101);
        foreign.control_plane.planet_semantic_digest = vec![2; 32];
        let mut live = PersistedState::new();
        live.relay_endpoint = Some(old_relay);
        live.relay_endpoints = vec![old_relay];
        live.root_servers = matching.control_plane.verified_roots.clone();
        live.stun_servers = vec!["old-stun.example:3478".into()];
        live.planet = Some(PersistedPlanet {
            manifest_url: "https://old-controller.example/v1/planet".into(),
            controller_url: "https://old-controller.example".into(),
            controller_public_key_base64: STANDARD.encode(controller.verifying_key().to_bytes()),
            controller_tls_ca_pem: Some("old-private-ca".into()),
        });
        live.networks = vec![matching, foreign];
        let mut candidate = live.clone();
        candidate.relay_endpoint = Some("203.0.113.104:51820".parse().unwrap());
        candidate.relay_endpoints = vec![candidate.relay_endpoint.unwrap()];
        candidate.root_servers = vec![PlanetRoot {
            public_key: vec![3; 32],
            endpoints: vec!["203.0.113.104:51819".parse().unwrap()],
            priority: 0,
            identity: None,
        }];
        candidate.planet.as_mut().unwrap().controller_url = "https://new-controller.example".into();
        candidate.planet.as_mut().unwrap().controller_tls_ca_pem = None;
        let control_plane = &mut candidate.networks[0].control_plane;
        control_plane.controller_url = Some("https://new-controller.example".into());
        control_plane.controller_tls_ca_pem = None;
        control_plane.planet_manifest_version = Some(3);
        control_plane.planet_last_issued_at_unix_seconds = Some(200);
        control_plane.planet_semantic_digest = vec![4; 32];

        assert!(persist_state_candidate(&mut live, candidate, |_| {
            anyhow::bail!("injected Planet state write failure")
        })
        .is_err());
        let global = live.planet.as_ref().unwrap();
        assert_eq!(global.controller_url, "https://old-controller.example");
        assert_eq!(
            global.controller_tls_ca_pem.as_deref(),
            Some("old-private-ca")
        );
        assert_eq!(live.root_servers[0].endpoints, vec![old_root]);
        let matching = &live.networks[0].control_plane;
        assert_eq!(
            matching.controller_url.as_deref(),
            Some("https://old-controller.example")
        );
        assert_eq!(
            matching.controller_tls_ca_pem.as_deref(),
            Some("old-private-ca")
        );
        assert_eq!(matching.planet_manifest_version, Some(2));
        assert_eq!(matching.planet_last_issued_at_unix_seconds, Some(100));
        assert_eq!(matching.planet_semantic_digest, vec![1; 32]);
        let foreign = &live.networks[1].control_plane;
        assert_eq!(
            foreign.controller_url.as_deref(),
            Some("https://foreign.example")
        );
        assert_eq!(
            foreign.controller_tls_ca_pem.as_deref(),
            Some("foreign-private-ca")
        );
        assert_eq!(foreign.planet_manifest_version, Some(3));
        assert_eq!(foreign.planet_last_issued_at_unix_seconds, Some(101));
        assert_eq!(foreign.planet_semantic_digest, vec![2; 32]);
    }

    #[tokio::test]
    async fn configure_planet_clears_old_per_network_ca_atomically() {
        let directory =
            env::temp_dir().join(format!("meshlake-planet-ca-clear-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let controller = SigningKey::from_bytes(&[99; 32]);
        let foreign_controller = SigningKey::from_bytes(&[101; 32]);
        let timestamp = now();
        let controller_url = "http://controller.example";
        let manifest = signed_planet_v2(
            &controller,
            controller_url,
            timestamp,
            "203.0.113.99:51819".parse().unwrap(),
            "203.0.113.99:51820".parse().unwrap(),
        );
        let (address, server) =
            spawn_json_server(vec![serde_json::to_vec(&manifest).unwrap()]).await;
        let mut network = test_joined_network();
        let network_id = network.network.id;
        network.control_plane.controller_url = Some(controller_url.into());
        network.control_plane.pinned_controller_public_key =
            controller.verifying_key().to_bytes().to_vec();
        network.control_plane.controller_tls_ca_pem = Some("old-private-ca".into());
        let mut foreign = test_joined_network();
        foreign.network.id = NetworkId(Uuid::from_u128(990));
        let foreign_id = foreign.network.id;
        foreign.control_plane.controller_url = Some("https://foreign.example".into());
        foreign.control_plane.planet_manifest_url =
            Some("https://foreign.example/v1/planet".into());
        foreign.control_plane.pinned_controller_public_key =
            foreign_controller.verifying_key().to_bytes().to_vec();
        foreign.control_plane.controller_tls_ca_pem = Some("foreign-private-ca".into());
        agent.state.write().await.networks = vec![network, foreign];

        agent
            .configure_planet(PlanetConfig {
                manifest_url: format!("http://{address}/v1/planet"),
                controller_public_key_base64: STANDARD
                    .encode(controller.verifying_key().to_bytes()),
                tls_ca_certificate_pem: None,
            })
            .await
            .unwrap();
        server.await.unwrap();

        let state = agent.state.read().await;
        assert_eq!(state.networks[0].control_plane.controller_tls_ca_pem, None);
        let foreign = state
            .networks
            .iter()
            .find(|network| network.network.id == foreign_id)
            .unwrap();
        assert_eq!(
            foreign.control_plane.controller_tls_ca_pem.as_deref(),
            Some("foreign-private-ca")
        );
        assert_eq!(
            foreign.control_plane.planet_manifest_url.as_deref(),
            Some("https://foreign.example/v1/planet")
        );
        assert_eq!(state.planet.as_ref().unwrap().controller_tls_ca_pem, None);
        drop(state);
        assert_eq!(
            agent
                .planet_refresh_targets()
                .await
                .into_iter()
                .find(|target| target.network_id == network_id)
                .unwrap()
                .controller_tls_ca_pem,
            None
        );
        assert_eq!(
            agent
                .planet_refresh_targets()
                .await
                .into_iter()
                .find(|target| target.network_id == foreign_id)
                .unwrap()
                .controller_tls_ca_pem
                .as_deref(),
            Some("foreign-private-ca")
        );

        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    async fn assert_in_flight_planet_refresh_is_discarded(
        label: &str,
        mutate_trust: impl FnOnce(&mut NetworkControlPlane),
        assert_mutation: impl FnOnce(&NetworkControlPlane),
    ) {
        let directory = env::temp_dir().join(format!(
            "meshlake-in-flight-planet-{label}-{}",
            Uuid::new_v4()
        ));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let controller = SigningKey::from_bytes(&[100; 32]);
        let timestamp = now();
        let controller_url = "http://old-controller.example";
        let initial_relay: SocketAddr = "203.0.113.100:51820".parse().unwrap();
        let initial = signed_planet_v2(
            &controller,
            controller_url,
            timestamp,
            "203.0.113.100:51819".parse().unwrap(),
            initial_relay,
        );
        let replacement = signed_planet_v2(
            &controller,
            controller_url,
            timestamp + 1,
            "203.0.113.101:51819".parse().unwrap(),
            "203.0.113.101:51820".parse().unwrap(),
        );
        let (address, mut request_received, release_response, server) =
            spawn_blocked_json_server(serde_json::to_vec(&replacement).unwrap()).await;
        let manifest_url = format!("http://{address}/v1/planet");

        let mut network = test_joined_network();
        network.control_plane.controller_url = Some(controller_url.into());
        network.control_plane.pinned_controller_public_key =
            controller.verifying_key().to_bytes().to_vec();
        let update = validate_planet_update(
            &network.control_plane,
            &initial,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap();
        apply_planet_update(&mut network.control_plane, Some(manifest_url), &update);
        {
            let mut state = agent.state.write().await;
            state.networks.push(network);
            write_state_with_protection(&path, &state, &agent.state_protection).unwrap();
        }
        let target = agent.planet_refresh_targets().await.pop().unwrap();
        let previous_revision = agent.transport_revision.load(Ordering::Acquire);
        let client = reqwest::Client::new();
        {
            let refresh = agent.refresh_one_planet(&client, &target);
            tokio::pin!(refresh);
            tokio::select! {
                result = &mut refresh => panic!("Planet refresh finished before the response was released: {result:?}"),
                received = &mut request_received => received.unwrap(),
            }
            {
                let mut state = agent.state.write().await;
                mutate_trust(&mut state.networks[0].control_plane);
                write_state_with_protection(&path, &state, &agent.state_protection).unwrap();
            }
            release_response.send(()).unwrap();
            refresh.as_mut().await.unwrap();
        }
        server.await.unwrap();

        let state = agent.state.read().await;
        let control_plane = &state.networks[0].control_plane;
        assert_mutation(control_plane);
        assert_eq!(
            control_plane.planet_last_issued_at_unix_seconds,
            Some(timestamp)
        );
        assert_eq!(control_plane.verified_relays[0].endpoint, initial_relay);
        drop(state);
        assert_eq!(
            agent.transport_revision.load(Ordering::Acquire),
            previous_revision
        );

        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[tokio::test]
    async fn in_flight_planet_response_cannot_overwrite_changed_controller_url() {
        assert_in_flight_planet_refresh_is_discarded(
            "controller-url",
            |control_plane| {
                control_plane.controller_url = Some("http://new-controller.example".into());
            },
            |control_plane| {
                assert_eq!(
                    control_plane.controller_url.as_deref(),
                    Some("http://new-controller.example")
                );
            },
        )
        .await;
    }

    #[tokio::test]
    async fn in_flight_planet_response_cannot_overwrite_changed_tls_ca() {
        assert_in_flight_planet_refresh_is_discarded(
            "tls-ca",
            |control_plane| {
                control_plane.controller_tls_ca_pem = Some("replacement-private-ca".into());
            },
            |control_plane| {
                assert_eq!(
                    control_plane.controller_tls_ca_pem.as_deref(),
                    Some("replacement-private-ca")
                );
            },
        )
        .await;
    }

    #[tokio::test]
    async fn enrollment_control_plane_cannot_downgrade_an_accepted_v3_planet() {
        let controller = SigningKey::from_bytes(&[94; 32]);
        let root = SigningKey::from_bytes(&[95; 32]);
        let relay = SigningKey::from_bytes(&[96; 32]);
        let network_id = NetworkId(Uuid::from_u128(940));
        let timestamp = now();
        let controller_url = "http://controller.example";
        let root_endpoint = "203.0.113.94:51819".parse().unwrap();
        let relay_endpoint = "203.0.113.94:51820".parse().unwrap();
        let v3 = signed_planet_v3(
            &controller,
            controller_url,
            timestamp,
            root_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(941),
                root.verifying_key().to_bytes().to_vec(),
            ),
            relay_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(942),
                relay.verifying_key().to_bytes().to_vec(),
            ),
        );
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            2,
            1,
            Vec::new(),
            Vec::new(),
            timestamp,
            timestamp + 90,
            &controller,
        )
        .unwrap();
        let mut current = NetworkControlPlane {
            controller_url: Some(controller_url.into()),
            pinned_controller_public_key: controller.verifying_key().to_bytes().to_vec(),
            authorization_manifest: Some(authorization.clone()),
            ..NetworkControlPlane::default()
        };
        let update = validate_planet_update(
            &current,
            &v3,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap();
        apply_planet_update(&mut current, None, &update);

        let v2 = PlanetManifest::sign_v2(
            controller_url.into(),
            vec![PlanetRoot {
                public_key: root.verifying_key().to_bytes().to_vec(),
                endpoints: vec![root_endpoint],
                priority: 0,
                identity: None,
            }],
            vec![PlanetRelay {
                endpoint: relay_endpoint,
                priority: 0,
                identity: None,
            }],
            vec![],
            timestamp + 1,
            Some(timestamp + 300),
            &controller,
        )
        .unwrap();
        let (address, server) = spawn_json_server(vec![serde_json::to_vec(&v2).unwrap()]).await;
        let error = resolve_enrollment_control_plane(
            Some(EnrollmentControlPlane {
                controller_url: controller_url.into(),
                planet_manifest_url: Some(format!("http://{address}/v1/planet")),
                controller_tls_ca_pem: None,
            }),
            &controller.verifying_key().to_bytes(),
            authorization,
            Some(&current),
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(error.1.contains("version rollback"));
    }

    #[tokio::test]
    async fn periodic_planet_refresh_promotes_rotated_service_identities() {
        let directory = env::temp_dir().join(format!("meshlake-planet-refresh-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let (device_id, device_identity) = {
            let state = agent.state.read().await;
            (state.device_id, identity_signing_key(&state).unwrap())
        };
        let controller = SigningKey::from_bytes(&[86; 32]);
        let old_root = SigningKey::from_bytes(&[87; 32]);
        let new_root = SigningKey::from_bytes(&[88; 32]);
        let old_relay = SigningKey::from_bytes(&[89; 32]);
        let new_relay = SigningKey::from_bytes(&[90; 32]);
        let network_id = NetworkId(Uuid::from_u128(860));
        let controller_url = "http://controller.example";
        let timestamp = now();
        let old_root_endpoint = "203.0.113.86:51819".parse().unwrap();
        let new_root_endpoint = "203.0.113.87:51819".parse().unwrap();
        let old_relay_endpoint = "203.0.113.86:51820".parse().unwrap();
        let new_relay_endpoint = "203.0.113.87:51820".parse().unwrap();
        let current = signed_planet_v3(
            &controller,
            controller_url,
            timestamp,
            old_root_endpoint,
            ServiceIdentityPolicy {
                service_id: Uuid::from_u128(861),
                current_public_key: old_root.verifying_key().to_bytes().to_vec(),
                next_public_key: Some(new_root.verifying_key().to_bytes().to_vec()),
                transition_not_before_unix_seconds: Some(timestamp),
                transition_not_after_unix_seconds: Some(timestamp + 60),
                revoked_public_keys: Vec::new(),
            },
            old_relay_endpoint,
            ServiceIdentityPolicy {
                service_id: Uuid::from_u128(862),
                current_public_key: old_relay.verifying_key().to_bytes().to_vec(),
                next_public_key: Some(new_relay.verifying_key().to_bytes().to_vec()),
                transition_not_before_unix_seconds: Some(timestamp),
                transition_not_after_unix_seconds: Some(timestamp + 60),
                revoked_public_keys: Vec::new(),
            },
        );
        let promoted = signed_planet_v3(
            &controller,
            controller_url,
            timestamp + 1,
            new_root_endpoint,
            ServiceIdentityPolicy {
                service_id: Uuid::from_u128(861),
                current_public_key: new_root.verifying_key().to_bytes().to_vec(),
                next_public_key: None,
                transition_not_before_unix_seconds: None,
                transition_not_after_unix_seconds: None,
                revoked_public_keys: vec![old_root.verifying_key().to_bytes().to_vec()],
            },
            new_relay_endpoint,
            ServiceIdentityPolicy {
                service_id: Uuid::from_u128(862),
                current_public_key: new_relay.verifying_key().to_bytes().to_vec(),
                next_public_key: None,
                transition_not_before_unix_seconds: None,
                transition_not_after_unix_seconds: None,
                revoked_public_keys: vec![old_relay.verifying_key().to_bytes().to_vec()],
            },
        );
        let (address, server) =
            spawn_json_server(vec![serde_json::to_vec(&promoted).unwrap()]).await;
        let manifest_url = format!("http://{address}/v1/planet");
        let mut network = joined_network_with_authorization(
            &controller,
            &device_identity,
            device_id,
            network_id,
            Uuid::from_u128(863),
            1,
            1,
            controller_url.into(),
        );
        let update = validate_planet_update(
            &network.control_plane,
            &current,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap();
        apply_planet_update(
            &mut network.control_plane,
            Some(manifest_url.clone()),
            &update,
        );
        {
            let mut state = agent.state.write().await;
            state.networks.push(network);
            write_state_with_protection(&path, &state, &agent.state_protection).unwrap();
        }

        let previous_revision = agent.transport_revision.load(Ordering::Acquire);
        agent
            .refresh_planets_once(&reqwest::Client::new())
            .await
            .unwrap();
        server.await.unwrap();

        let state = agent.state.read().await;
        let refreshed = &state.networks[0].control_plane;
        assert_eq!(refreshed.planet_manifest_version, Some(3));
        assert_eq!(
            refreshed.planet_last_issued_at_unix_seconds,
            Some(timestamp + 1)
        );
        assert_eq!(
            refreshed.verified_roots[0].endpoints,
            vec![new_root_endpoint]
        );
        assert_eq!(refreshed.verified_relays[0].endpoint, new_relay_endpoint);
        assert_eq!(
            refreshed.verified_roots[0]
                .identity
                .as_ref()
                .unwrap()
                .revoked_public_keys,
            vec![old_root.verifying_key().to_bytes().to_vec()]
        );
        drop(state);
        assert!(agent.transport_revision.load(Ordering::Acquire) > previous_revision);
        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[tokio::test]
    async fn periodic_planet_refresh_keeps_live_state_when_persistence_fails() {
        let directory = env::temp_dir().join(format!(
            "meshlake-planet-refresh-write-failure-{}",
            Uuid::new_v4()
        ));
        let path = directory.join("agent.json");
        let mut agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let controller = SigningKey::from_bytes(&[107; 32]);
        let controller_url = "http://controller.example";
        let timestamp = now();
        let old_root: SocketAddr = "203.0.113.107:51819".parse().unwrap();
        let old_relay: SocketAddr = "203.0.113.107:51820".parse().unwrap();
        let new_root: SocketAddr = "203.0.113.108:51819".parse().unwrap();
        let new_relay: SocketAddr = "203.0.113.108:51820".parse().unwrap();
        let current = signed_planet_v2(&controller, controller_url, timestamp, old_root, old_relay);
        let refreshed = signed_planet_v2(
            &controller,
            controller_url,
            timestamp + 1,
            new_root,
            new_relay,
        );
        let (address, server) =
            spawn_json_server(vec![serde_json::to_vec(&refreshed).unwrap()]).await;
        let manifest_url = format!("http://{address}/v1/planet");
        let mut network = test_joined_network();
        network.control_plane.controller_url = Some(controller_url.into());
        network.control_plane.pinned_controller_public_key =
            controller.verifying_key().to_bytes().to_vec();
        let update = validate_planet_update(
            &network.control_plane,
            &current,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap();
        assert!(apply_planet_update(
            &mut network.control_plane,
            Some(manifest_url),
            &update,
        ));
        {
            let mut state = agent.state.write().await;
            state.networks.push(network);
            write_state_with_protection(&path, &state, &agent.state_protection).unwrap();
        }

        let previous_revision = agent.transport_revision.load(Ordering::Acquire);
        let persisted_path = agent.path.clone();
        agent.path = directory.clone();
        agent
            .refresh_planets_once(&reqwest::Client::new())
            .await
            .unwrap();
        agent.path = persisted_path;
        server.await.unwrap();

        let state = agent.state.read().await;
        let retained = &state.networks[0].control_plane;
        assert_eq!(retained.planet_manifest_version, Some(2));
        assert_eq!(retained.planet_last_issued_at_unix_seconds, Some(timestamp));
        assert_eq!(retained.verified_roots[0].endpoints, vec![old_root]);
        assert_eq!(retained.verified_relays[0].endpoint, old_relay);
        drop(state);
        assert_eq!(
            agent.transport_revision.load(Ordering::Acquire),
            previous_revision
        );
        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[tokio::test]
    async fn periodic_planet_refresh_keeps_last_verified_state_on_failure() {
        let directory = env::temp_dir().join(format!(
            "meshlake-planet-refresh-failure-{}",
            Uuid::new_v4()
        ));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let (device_id, device_identity) = {
            let state = agent.state.read().await;
            (state.device_id, identity_signing_key(&state).unwrap())
        };
        let controller = SigningKey::from_bytes(&[91; 32]);
        let root = SigningKey::from_bytes(&[92; 32]);
        let relay = SigningKey::from_bytes(&[93; 32]);
        let network_id = NetworkId(Uuid::from_u128(910));
        let controller_url = "http://controller.example";
        let timestamp = now();
        let root_endpoint = "203.0.113.91:51819".parse().unwrap();
        let relay_endpoint = "203.0.113.91:51820".parse().unwrap();
        let current = signed_planet_v3(
            &controller,
            controller_url,
            timestamp,
            root_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(911),
                root.verifying_key().to_bytes().to_vec(),
            ),
            relay_endpoint,
            ServiceIdentityPolicy::stable(
                Uuid::from_u128(912),
                relay.verifying_key().to_bytes().to_vec(),
            ),
        );
        let downgraded = PlanetManifest::sign_v2(
            controller_url.into(),
            vec![PlanetRoot {
                public_key: root.verifying_key().to_bytes().to_vec(),
                endpoints: vec![root_endpoint],
                priority: 0,
                identity: None,
            }],
            vec![PlanetRelay {
                endpoint: relay_endpoint,
                priority: 0,
                identity: None,
            }],
            vec![],
            timestamp + 1,
            Some(timestamp + 300),
            &controller,
        )
        .unwrap();
        let mut tampered = current.clone();
        tampered.issued_at_unix_seconds = timestamp + 2;
        let (address, server) = spawn_json_server(vec![
            serde_json::to_vec(&downgraded).unwrap(),
            serde_json::to_vec(&tampered).unwrap(),
        ])
        .await;
        let manifest_url = format!("http://{address}/v1/planet");
        let mut network = joined_network_with_authorization(
            &controller,
            &device_identity,
            device_id,
            network_id,
            Uuid::from_u128(913),
            1,
            1,
            controller_url.into(),
        );
        let update = validate_planet_update(
            &network.control_plane,
            &current,
            &controller.verifying_key().to_bytes(),
            Some(controller_url),
            timestamp,
        )
        .unwrap();
        apply_planet_update(&mut network.control_plane, Some(manifest_url), &update);
        {
            let mut state = agent.state.write().await;
            state.networks.push(network);
            write_state_with_protection(&path, &state, &agent.state_protection).unwrap();
        }
        let previous_revision = agent.transport_revision.load(Ordering::Acquire);

        agent
            .refresh_planets_once(&reqwest::Client::new())
            .await
            .unwrap();
        agent
            .refresh_planets_once(&reqwest::Client::new())
            .await
            .unwrap();
        server.await.unwrap();

        let state = agent.state.read().await;
        let retained = &state.networks[0].control_plane;
        assert_eq!(retained.planet_manifest_version, Some(3));
        assert_eq!(retained.planet_last_issued_at_unix_seconds, Some(timestamp));
        assert_eq!(retained.verified_roots[0].endpoints, vec![root_endpoint]);
        assert_eq!(retained.verified_relays[0].endpoint, relay_endpoint);
        drop(state);
        assert_eq!(
            agent.transport_revision.load(Ordering::Acquire),
            previous_revision
        );
        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[test]
    fn legacy_planet_trust_only_migrates_to_the_matching_controller() {
        let controller = SigningKey::from_bytes(&[35_u8; 32]);
        let mut matching = test_joined_network();
        matching.control_plane.controller_url = Some("https://PLANET.example/".into());

        let mut foreign = test_joined_network();
        foreign.network.id = NetworkId(Uuid::from_u128(92));
        foreign.network.name = "foreign-controller".into();
        foreign.control_plane.controller_url = Some("https://other.example".into());
        foreign.control_plane.controller_tls_ca_pem = Some("foreign-ca".into());

        let mut state = PersistedState::new();
        state.networks = vec![matching, foreign];
        state.relay_endpoints = vec!["203.0.113.35:51820".parse().unwrap()];
        state.root_servers = vec![PlanetRoot {
            public_key: vec![35; 32],
            endpoints: vec!["203.0.113.35:51819".parse().unwrap()],
            priority: 0,
            identity: None,
        }];
        state.stun_servers = vec!["stun.planet.example:3478".into()];
        state.planet = Some(PersistedPlanet {
            manifest_url: "https://planet.example/v1/planet/".into(),
            controller_url: "https://planet.example".into(),
            controller_public_key_base64: STANDARD.encode(controller.verifying_key().to_bytes()),
            controller_tls_ca_pem: Some("legacy-private-ca".into()),
        });

        assert!(migrate_legacy_network_control_planes(&mut state));

        let matching = &state.networks[0].control_plane;
        assert_eq!(
            matching.controller_tls_ca_pem.as_deref(),
            Some("legacy-private-ca")
        );
        assert_eq!(
            matching.planet_manifest_url.as_deref(),
            Some("https://planet.example/v1/planet")
        );
        assert_eq!(matching.verified_roots.len(), 1);
        assert_eq!(matching.verified_relays.len(), 1);
        assert_eq!(
            matching.verified_stun_servers,
            vec!["stun.planet.example:3478"]
        );
        assert_eq!(
            matching.pinned_controller_public_key,
            controller.verifying_key().to_bytes()
        );

        let foreign = &state.networks[1].control_plane;
        assert_eq!(
            foreign.controller_url.as_deref(),
            Some("https://other.example")
        );
        assert_eq!(foreign.controller_tls_ca_pem.as_deref(), Some("foreign-ca"));
        assert!(foreign.planet_manifest_url.is_none());
        assert!(foreign.pinned_controller_public_key.is_empty());
        assert!(foreign.verified_roots.is_empty());
        assert!(foreign.verified_relays.is_empty());
        assert!(foreign.verified_stun_servers.is_empty());
    }

    #[test]
    fn legacy_planet_migration_does_not_adopt_trust_for_a_foreign_certificate_without_url() {
        let legacy_controller = SigningKey::from_bytes(&[104; 32]);
        let foreign_controller = SigningKey::from_bytes(&[105; 32]);
        let device = SigningKey::from_bytes(&[106; 32]);
        let mut foreign = test_joined_network();
        let network_id = foreign.network.id;
        let device_id = DeviceId(Uuid::from_u128(1040));
        foreign.certificate = Some(
            MembershipCertificate::sign(
                MembershipClaims {
                    network_id,
                    device_id,
                    device_public_key: device.verifying_key().to_bytes().to_vec(),
                    assigned_addresses: vec!["100.64.90.1".parse().unwrap()],
                    allowed_routes: vec!["100.64.90.0/24".into()],
                    issued_at_unix_seconds: now(),
                    expires_at_unix_seconds: Some(now() + 90),
                },
                &foreign_controller,
            )
            .unwrap(),
        );
        assert!(foreign.control_plane.controller_url.is_none());
        assert!(foreign
            .control_plane
            .pinned_controller_public_key
            .is_empty());

        let mut state = PersistedState::new();
        state.networks = vec![foreign];
        state.relay_endpoints = vec!["203.0.113.104:51820".parse().unwrap()];
        state.root_servers = vec![PlanetRoot {
            public_key: vec![104; 32],
            endpoints: vec!["203.0.113.104:51819".parse().unwrap()],
            priority: 0,
            identity: None,
        }];
        state.stun_servers = vec!["stun.legacy.example:3478".into()];
        state.planet = Some(PersistedPlanet {
            manifest_url: "https://legacy.example/v1/planet".into(),
            controller_url: "https://legacy.example".into(),
            controller_public_key_base64: STANDARD
                .encode(legacy_controller.verifying_key().to_bytes()),
            controller_tls_ca_pem: Some("legacy-private-ca".into()),
        });

        assert!(!migrate_legacy_network_control_planes(&mut state));
        let control_plane = &state.networks[0].control_plane;
        assert!(control_plane.controller_url.is_none());
        assert!(control_plane.pinned_controller_public_key.is_empty());
        assert!(control_plane.controller_tls_ca_pem.is_none());
        assert!(control_plane.planet_manifest_url.is_none());
        assert!(control_plane.verified_roots.is_empty());
        assert!(control_plane.verified_relays.is_empty());
        assert!(control_plane.verified_stun_servers.is_empty());
    }

    #[test]
    fn normalize_http_url_is_strict_and_canonical() {
        assert_eq!(
            normalize_http_url(" HTTPS://Example.COM:443/api/// ", "test URL").unwrap(),
            "https://example.com/api"
        );
        for value in [
            "ftp://example.com",
            "https:///missing-host",
            "https://user:secret@example.com",
            "https://@example.com",
            "https://example.com\\unexpected",
            "https://example.com/path?token=secret",
            "https://example.com/path#fragment",
        ] {
            assert!(normalize_http_url(value, "test URL").is_err(), "{value}");
        }
    }

    #[tokio::test]
    async fn private_ca_rejects_plain_http_controller_and_manifest_urls() {
        let controller = SigningKey::from_bytes(&[36_u8; 32]);
        let network_id = NetworkId(Uuid::from_u128(360));
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            1,
            1,
            Vec::new(),
            Vec::new(),
            now(),
            now() + 90,
            &controller,
        )
        .unwrap();

        let controller_error = resolve_enrollment_control_plane(
            Some(EnrollmentControlPlane {
                controller_url: "http://controller.example".into(),
                planet_manifest_url: None,
                controller_tls_ca_pem: Some("private-ca".into()),
            }),
            &controller.verifying_key().to_bytes(),
            authorization.clone(),
            None,
        )
        .await
        .unwrap_err();
        assert!(controller_error.1.contains("https:// controller URL"));

        let manifest_error = resolve_enrollment_control_plane(
            Some(EnrollmentControlPlane {
                controller_url: "https://controller.example".into(),
                planet_manifest_url: Some("http://controller.example/v1/planet".into()),
                controller_tls_ca_pem: Some("private-ca".into()),
            }),
            &controller.verifying_key().to_bytes(),
            authorization,
            None,
        )
        .await
        .unwrap_err();
        assert!(manifest_error.1.contains("https:// Planet manifest URL"));
    }

    #[tokio::test]
    async fn enrollment_control_plane_fetches_and_pins_planet_manifest() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let controller = SigningKey::from_bytes(&[32_u8; 32]);
        let network_id = NetworkId(Uuid::from_u128(320));
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            1,
            1,
            Vec::new(),
            Vec::new(),
            now(),
            now() + 90,
            &controller,
        )
        .unwrap();
        let manifest = PlanetManifest::sign_v2(
            "http://controller.example".into(),
            vec![PlanetRoot {
                public_key: vec![4; 32],
                endpoints: vec!["203.0.113.40:51819".parse().unwrap()],
                priority: 0,
                identity: None,
            }],
            vec![PlanetRelay {
                endpoint: "203.0.113.40:51820".parse().unwrap(),
                priority: 0,
                identity: None,
            }],
            vec!["stun.example:3478".into()],
            now(),
            Some(now() + 90),
            &controller,
        )
        .unwrap();
        let body = serde_json::to_vec(&manifest).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 2048];
            let _ = stream.read(&mut request).await;
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });

        let control_plane = resolve_enrollment_control_plane(
            Some(EnrollmentControlPlane {
                controller_url: "http://controller.example".into(),
                planet_manifest_url: Some(format!("http://{address}/v1/planet")),
                controller_tls_ca_pem: None,
            }),
            &controller.verifying_key().to_bytes(),
            authorization.clone(),
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(
            control_plane.controller_url.as_deref(),
            Some("http://controller.example")
        );
        assert_eq!(control_plane.verified_roots.len(), 1);
        assert_eq!(control_plane.verified_relays.len(), 1);
        assert_eq!(
            control_plane.authorization_manifest.as_ref(),
            Some(&authorization)
        );
    }

    #[test]
    fn authorization_guards_fail_closed_for_expiry_and_unknown_peers() {
        let controller = SigningKey::from_bytes(&[41_u8; 32]);
        let local_identity = SigningKey::from_bytes(&[42_u8; 32]);
        let peer_identity = SigningKey::from_bytes(&[43_u8; 32]);
        let network_id = NetworkId(Uuid::from_u128(410));
        let network = joined_network_with_authorization(
            &controller,
            &local_identity,
            DeviceId(Uuid::from_u128(411)),
            network_id,
            Uuid::from_u128(412),
            1,
            1,
            "http://controller.invalid".into(),
        );
        let authorization = network
            .control_plane
            .authorization_manifest
            .as_ref()
            .unwrap();
        assert!(local_network_is_authorized(
            &network,
            authorization.issued_at_unix_seconds
        ));
        assert!(!local_network_is_authorized(
            &network,
            authorization.expires_at_unix_seconds + 1
        ));

        let unknown_peer = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id,
                device_id: DeviceId(Uuid::from_u128(413)),
                device_public_key: peer_identity.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.90.2".parse().unwrap()],
                allowed_routes: vec!["100.64.90.0/24".into()],
                issued_at_unix_seconds: authorization.issued_at_unix_seconds,
                expires_at_unix_seconds: Some(authorization.expires_at_unix_seconds + 600),
            },
            Uuid::from_u128(414),
            1,
            &controller,
        )
        .unwrap();
        assert!(!peer_certificate_is_authorized(
            &network,
            &unknown_peer,
            authorization.issued_at_unix_seconds
        ));
    }

    #[tokio::test]
    async fn current_authorization_only_updates_the_manifest() {
        let controller = SigningKey::from_bytes(&[44_u8; 32]);
        let identity = SigningKey::from_bytes(&[45_u8; 32]);
        let device_id = DeviceId(Uuid::from_u128(450));
        let network_id = NetworkId(Uuid::from_u128(451));
        let certificate_id = Uuid::from_u128(452);
        let mut network = joined_network_with_authorization(
            &controller,
            &identity,
            device_id,
            network_id,
            certificate_id,
            1,
            1,
            String::new(),
        );
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            2,
            1,
            vec![AuthorizedMembership {
                device_id,
                certificate_id,
                device_public_key: identity.verifying_key().to_bytes().to_vec(),
                network_key_epoch: 1,
            }],
            vec![],
            now(),
            now() + 90,
            &controller,
        )
        .unwrap();
        let (address, server) =
            spawn_json_server(vec![serde_json::to_vec(&authorization).unwrap()]).await;
        network.control_plane.controller_url = Some(format!("http://{address}"));
        let action = fetch_authorization_action(
            &reqwest::Client::new(),
            device_id,
            &identity,
            &refresh_target(&network),
        )
        .await
        .unwrap();
        assert!(matches!(
            action,
            AuthorizationRefreshAction::UpdateManifest(ref manifest)
                if manifest.authorization_epoch == 2
        ));
        let requests = server.await.unwrap();
        assert!(String::from_utf8_lossy(&requests[0])
            .starts_with(&format!("GET /v1/networks/{}/authorization ", network_id.0)));
    }

    #[tokio::test]
    async fn network_key_epoch_change_refreshes_certificate_and_key() {
        let controller = SigningKey::from_bytes(&[46_u8; 32]);
        let identity = SigningKey::from_bytes(&[47_u8; 32]);
        let device_id = DeviceId(Uuid::from_u128(470));
        let network_id = NetworkId(Uuid::from_u128(471));
        let certificate_id = Uuid::from_u128(472);
        let mut network = joined_network_with_authorization(
            &controller,
            &identity,
            device_id,
            network_id,
            certificate_id,
            1,
            1,
            String::new(),
        );
        let timestamp = now();
        let new_certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id,
                device_id,
                device_public_key: identity.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.90.1".parse().unwrap()],
                allowed_routes: vec!["100.64.90.0/24".into()],
                issued_at_unix_seconds: timestamp,
                expires_at_unix_seconds: Some(timestamp + 86_400),
            },
            certificate_id,
            2,
            &controller,
        )
        .unwrap();
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            2,
            2,
            vec![AuthorizedMembership {
                device_id,
                certificate_id,
                device_public_key: identity.verifying_key().to_bytes().to_vec(),
                network_key_epoch: 2,
            }],
            vec![],
            timestamp,
            timestamp + 90,
            &controller,
        )
        .unwrap();
        let refresh_response = MembershipRefreshResponse {
            revoked: false,
            authorization: authorization.clone(),
            certificate: Some(new_certificate.clone()),
            network_key: vec![9_u8; 32],
        };
        let (address, server) = spawn_json_server(vec![
            serde_json::to_vec(&authorization).unwrap(),
            serde_json::to_vec(&refresh_response).unwrap(),
        ])
        .await;
        network.control_plane.controller_url = Some(format!("http://{address}"));
        let action = fetch_authorization_action(
            &reqwest::Client::new(),
            device_id,
            &identity,
            &refresh_target(&network),
        )
        .await
        .unwrap();
        match action {
            AuthorizationRefreshAction::Update {
                certificate,
                network_key,
                authorization,
            } => {
                assert_eq!(certificate, new_certificate);
                assert_eq!(network_key, vec![9_u8; 32]);
                assert_eq!(authorization.network_key_epoch, 2);
            }
            _ => panic!("expected a certificate and network-key refresh"),
        }

        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(String::from_utf8_lossy(&requests[1]).starts_with("POST /v1/membership/refresh "));
        let body_start = requests[1]
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let refresh: MembershipRefreshRequest =
            serde_json::from_slice(&requests[1][body_start..]).unwrap();
        assert_eq!(refresh.payload.network_id, network_id);
        assert_eq!(refresh.payload.device_id, device_id);
        refresh
            .verify(&identity.verifying_key().to_bytes(), now(), 120)
            .unwrap();
    }

    #[tokio::test]
    async fn authorization_hint_only_requests_refresh_and_never_installs_authority() {
        let directory = env::temp_dir().join(format!("meshlake-auth-hint-test-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path, adapter::default_wintun_path()).unwrap();
        let (device_id, identity) = {
            let state = agent.state.read().await;
            (state.device_id, identity_signing_key(&state).unwrap())
        };
        let controller = SigningKey::from_bytes(&[79; 32]);
        let network_id = NetworkId(Uuid::from_u128(80));
        let network = joined_network_with_authorization(
            &controller,
            &identity,
            device_id,
            network_id,
            Uuid::from_u128(81),
            1,
            1,
            "http://127.0.0.1:1".into(),
        );
        agent.state.write().await.networks.push(network);
        let timestamp = now();
        let hint =
            AuthorizationEpochHint::sign(network_id, 2, 2, timestamp, timestamp + 30, &controller)
                .unwrap();
        assert!(agent.consider_authorization_hint(&hint).await);
        assert_eq!(
            agent.state.read().await.networks[0]
                .control_plane
                .authorization_manifest
                .as_ref()
                .unwrap()
                .authorization_epoch,
            1
        );
        let old_hint =
            AuthorizationEpochHint::sign(network_id, 1, 1, timestamp, timestamp + 30, &controller)
                .unwrap();
        assert!(!agent.consider_authorization_hint(&old_hint).await);
        drop(agent);
        let _ = fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn signed_member_removal_revokes_network_and_reloads_transport() {
        let directory = env::temp_dir().join(format!("meshlake-revoke-test-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let (device_id, identity) = {
            let state = agent.state.read().await;
            (state.device_id, identity_signing_key(&state).unwrap())
        };
        let controller = SigningKey::from_bytes(&[48_u8; 32]);
        let network_id = NetworkId(Uuid::from_u128(480));
        let certificate_id = Uuid::from_u128(481);
        let timestamp = now();
        let revoked = NetworkAuthorizationManifest::sign(
            network_id,
            2,
            2,
            vec![],
            vec![certificate_id],
            timestamp,
            timestamp + 90,
            &controller,
        )
        .unwrap();
        let (address, server) =
            spawn_json_server(vec![serde_json::to_vec(&revoked).unwrap()]).await;
        let network = joined_network_with_authorization(
            &controller,
            &identity,
            device_id,
            network_id,
            certificate_id,
            1,
            1,
            format!("http://{address}"),
        );
        {
            let mut state = agent.state.write().await;
            state.networks.push(network);
        }
        let previous_revision = agent.transport_revision.load(Ordering::Acquire);
        agent
            .refresh_authorizations_once(&reqwest::Client::new())
            .await
            .unwrap();
        server.await.unwrap();

        assert!(agent.state.read().await.networks.is_empty());
        assert!(agent.transport_revision.load(Ordering::Acquire) > previous_revision);
        let persisted: PersistedState =
            decode_protected_state(&fs::read(&path).unwrap(), AGENT_STATE_PROTECTION_PURPOSE)
                .unwrap()
                .value;
        assert!(persisted.networks.is_empty());
        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[tokio::test]
    async fn authorization_epoch_cannot_roll_back() {
        let controller = SigningKey::from_bytes(&[49_u8; 32]);
        let identity = SigningKey::from_bytes(&[50_u8; 32]);
        let device_id = DeviceId(Uuid::from_u128(490));
        let network_id = NetworkId(Uuid::from_u128(491));
        let certificate_id = Uuid::from_u128(492);
        let mut network = joined_network_with_authorization(
            &controller,
            &identity,
            device_id,
            network_id,
            certificate_id,
            1,
            5,
            String::new(),
        );
        let stale = NetworkAuthorizationManifest::sign(
            network_id,
            4,
            1,
            vec![AuthorizedMembership {
                device_id,
                certificate_id,
                device_public_key: identity.verifying_key().to_bytes().to_vec(),
                network_key_epoch: 1,
            }],
            vec![],
            now(),
            now() + 90,
            &controller,
        )
        .unwrap();
        let (address, server) = spawn_json_server(vec![serde_json::to_vec(&stale).unwrap()]).await;
        network.control_plane.controller_url = Some(format!("http://{address}"));
        let error = fetch_authorization_action(
            &reqwest::Client::new(),
            device_id,
            &identity,
            &refresh_target(&network),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("older authorization epoch"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn repeated_enrollment_from_the_same_controller_is_idempotent() {
        let directory = env::temp_dir().join(format!("meshlake-enroll-test-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let state = agent.state.read().await;
        let device_id = state.device_id;
        let device_public_key = identity_signing_key(&state)
            .unwrap()
            .verifying_key()
            .to_bytes()
            .to_vec();
        drop(state);

        let controller = SigningKey::from_bytes(&[33_u8; 32]);
        let network_id = NetworkId(Uuid::from_u128(330));
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id,
                device_id,
                device_public_key: device_public_key.clone(),
                assigned_addresses: vec!["100.64.33.2".parse().unwrap()],
                allowed_routes: vec!["100.64.33.0/24".into()],
                issued_at_unix_seconds: now(),
                expires_at_unix_seconds: Some(now() + 86_400),
            },
            Uuid::from_u128(331),
            1,
            &controller,
        )
        .unwrap();
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            1,
            1,
            vec![AuthorizedMembership {
                device_id,
                certificate_id: certificate.certificate_id,
                device_public_key,
                network_key_epoch: 1,
            }],
            Vec::new(),
            now(),
            now() + 90,
            &controller,
        )
        .unwrap();
        let trusted = TrustedEnrollment {
            enrollment: EnrollmentResponse {
                network: VirtualNetwork {
                    id: network_id,
                    name: "retry".into(),
                    ipv4_prefix: "100.64.33.0/24".into(),
                    ipv6_prefix: None,
                    relay_policy: RelayPolicy::Preferred,
                },
                certificate,
                network_key: vec![3; 32],
                authorization,
            },
            controller_public_key: controller.verifying_key().to_bytes().to_vec(),
            control_plane: Some(EnrollmentControlPlane {
                controller_url: "https://controller.example".into(),
                planet_manifest_url: None,
                controller_tls_ca_pem: None,
            }),
        };

        agent.enroll_network(trusted.clone()).await.unwrap();
        agent.enroll_network(trusted).await.unwrap();
        let state = agent.state.read().await;
        assert_eq!(state.networks.len(), 1);
        assert_eq!(state.networks[0].network.id, network_id);
        drop(state);

        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[tokio::test]
    async fn authorization_refresh_keeps_private_ca_scoped_per_network() {
        let directory = env::temp_dir().join(format!("meshlake-ca-scope-test-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let (device_id, identity) = {
            let state = agent.state.read().await;
            (state.device_id, identity_signing_key(&state).unwrap())
        };
        let first_controller = SigningKey::from_bytes(&[37_u8; 32]);
        let second_controller = SigningKey::from_bytes(&[38_u8; 32]);
        let first_id = NetworkId(Uuid::from_u128(370));
        let second_id = NetworkId(Uuid::from_u128(380));
        let mut first = joined_network_with_authorization(
            &first_controller,
            &identity,
            device_id,
            first_id,
            Uuid::from_u128(371),
            1,
            1,
            "https://first.example".into(),
        );
        first.control_plane.controller_tls_ca_pem = Some("first-private-ca".into());
        let mut second = joined_network_with_authorization(
            &second_controller,
            &identity,
            device_id,
            second_id,
            Uuid::from_u128(381),
            1,
            1,
            "https://second.example".into(),
        );
        second.control_plane.controller_tls_ca_pem = Some("second-private-ca".into());
        agent.state.write().await.networks = vec![first, second];

        let (_, _, targets) = agent.authorization_refresh_material().await.unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets
                .iter()
                .find(|target| target.network_id == first_id)
                .unwrap()
                .controller_tls_ca_pem
                .as_deref(),
            Some("first-private-ca")
        );
        assert_eq!(
            targets
                .iter()
                .find(|target| target.network_id == second_id)
                .unwrap()
                .controller_tls_ca_pem
                .as_deref(),
            Some("second-private-ca")
        );

        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[tokio::test]
    async fn transport_supervisor_hot_starts_after_configuration_change() {
        let directory = env::temp_dir().join(format!("meshlake-reload-test-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let agent = Arc::new(Agent::open(path.clone(), adapter::default_wintun_path()).unwrap());
        agent.start_relay_worker().await.unwrap();
        tokio::task::yield_now().await;
        assert!(!agent.relay_running.load(Ordering::Acquire));

        {
            let mut state = agent.state.write().await;
            state.upnp_enabled = false;
            state.relay_endpoint = Some("127.0.0.1:9".parse().unwrap());
            state.relay_endpoints = vec!["127.0.0.1:9".parse().unwrap()];
        }
        agent.request_transport_reload();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !agent.relay_running.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("transport worker should hot-start after configuration changes");

        agent.shutting_down.store(true, Ordering::Release);
        agent.shutdown.notify_waiters();
        tokio::time::timeout(Duration::from_secs(2), async {
            while agent.transport_supervisor_running.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("transport supervisor should stop cleanly");
        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[test]
    fn state_rewrite_and_backup_recovery_preserve_identity() {
        let directory = env::temp_dir().join(format!("meshlake-state-test-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let state_lock = StateFileLock::acquire(&path).unwrap();
        let protection = StateProtection::platform_default();
        let mut state = PersistedState::new();
        let original_device = state.device_id;
        write_state_with_protection(&path, &state, &protection).unwrap();
        state.schema_version += 1;
        write_state_with_protection(&path, &state, &protection).unwrap();
        assert!(!has_temporary_state_file(&path));
        assert!(!suffixed_state_path(&path, ".bak").exists());

        let decoded: PersistedState =
            decode_protected_state(&fs::read(&path).unwrap(), AGENT_STATE_PROTECTION_PURPOSE)
                .unwrap()
                .value;
        assert_eq!(decoded.device_id, original_device);
        assert_eq!(decoded.schema_version, state.schema_version);

        let backup = suffixed_state_path(&path, ".bak");
        fs::rename(&path, &backup).unwrap();
        recover_protected_state_file(&path).unwrap();
        assert!(path.exists());
        assert!(!backup.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        drop(state_lock);
        cleanup_test_state(&path, &directory);
    }

    #[test]
    fn agent_holds_the_state_lock_until_it_is_dropped() {
        let directory = env::temp_dir().join(format!("meshlake-lock-test-{}", Uuid::new_v4()));
        let path = directory.join("agent.json");
        let first = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        let error = match Agent::open(path.clone(), adapter::default_wintun_path()) {
            Ok(_) => panic!("a second agent unexpectedly acquired the same state lock"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("cannot exclusively lock MeshLake state"));
        drop(first);

        let reopened = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        drop(reopened);
        cleanup_test_state(&path, &directory);
    }

    #[cfg(windows)]
    #[test]
    fn agent_open_upgrades_legacy_plaintext_state() {
        let directory = env::temp_dir().join(format!("meshlake-plaintext-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.json");
        let state = PersistedState::new();
        let original_device = state.device_id;
        fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        assert_eq!(agent.state.blocking_read().device_id, original_device);
        let bytes = fs::read(&path).unwrap();
        assert!(serde_json::from_slice::<PersistedState>(&bytes).is_err());
        let decoded: meshlake_core::DecodedState<PersistedState> =
            decode_protected_state(&bytes, AGENT_STATE_PROTECTION_PURPOSE).unwrap();
        assert_eq!(decoded.value.device_id, original_device);
        assert!(!decoded.needs_protection_upgrade);

        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[cfg(windows)]
    #[test]
    fn agent_open_removes_plaintext_backup_after_validating_protected_primary_state() {
        let directory =
            env::temp_dir().join(format!("meshlake-stale-backup-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.json");
        let backup = suffixed_state_path(&path, ".bak");
        let protection = StateProtection::platform_default();
        let state = PersistedState::new();
        let original_device = state.device_id;
        write_state_with_protection(&path, &state, &protection).unwrap();
        fs::write(&backup, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        assert!(String::from_utf8_lossy(&fs::read(&backup).unwrap())
            .contains(&original_device.0.to_string()));

        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        assert_eq!(agent.state.blocking_read().device_id, original_device);
        assert!(!backup.exists());

        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[cfg(windows)]
    #[test]
    fn agent_open_keeps_backup_when_current_primary_identity_is_invalid() {
        let directory =
            env::temp_dir().join(format!("meshlake-invalid-primary-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.json");
        let backup = suffixed_state_path(&path, ".bak");
        let valid_backup = PersistedState::new();
        let mut invalid_primary = valid_backup.clone();
        invalid_primary.identity_secret_key.clear();
        let protected =
            meshlake_core::encode_protected_state(&invalid_primary, AGENT_STATE_PROTECTION_PURPOSE)
                .unwrap();
        fs::write(&path, protected).unwrap();
        fs::write(&backup, serde_json::to_vec_pretty(&valid_backup).unwrap()).unwrap();

        let error = match Agent::open(path.clone(), adapter::default_wintun_path()) {
            Ok(_) => panic!("agent unexpectedly accepted an invalid current-schema identity"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("refusing automatic identity rotation"));
        assert!(backup.exists());

        cleanup_test_state(&path, &directory);
    }

    #[cfg(unix)]
    #[test]
    fn agent_open_restricts_an_existing_state_file_to_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let directory =
            env::temp_dir().join(format!("meshlake-permission-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&PersistedState::new()).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let agent = Agent::open(path.clone(), adapter::default_wintun_path()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        drop(agent);
        cleanup_test_state(&path, &directory);
    }

    #[cfg(unix)]
    #[test]
    fn linux_provider_migrates_agent_plaintext_without_rotating_identity() {
        use meshlake_core::{
            create_restricted_secret_file, decode_protected_state_with, StateKeyProvider,
        };

        let directory =
            env::temp_dir().join(format!("meshlake-agent-linux-provider-{}", Uuid::new_v4()));
        let state_directory = directory.join("state");
        let key_directory = directory.join("keys");
        fs::create_dir_all(&state_directory).unwrap();
        fs::create_dir_all(&key_directory).unwrap();
        let path = state_directory.join("agent.json");
        let key_path = key_directory.join("state.key");
        let original = PersistedState::new();
        fs::write(&path, serde_json::to_vec_pretty(&original).unwrap()).unwrap();
        create_restricted_secret_file(&key_path, &[13; 32]).unwrap();

        let protection = StateProtection::from_provider(
            &path,
            StateKeyProvider::RestrictedFile(key_path.clone()),
        )
        .unwrap();
        let error = match Agent::open_with_protection(
            path.clone(),
            adapter::default_wintun_path(),
            protection,
        ) {
            Ok(_) => panic!("provider mode unexpectedly accepted plaintext"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("allow-plaintext-state-migration"));

        let protection = StateProtection::from_provider_with_plaintext_migration(
            &path,
            StateKeyProvider::RestrictedFile(key_path.clone()),
            true,
        )
        .unwrap();
        let agent =
            Agent::open_with_protection(path.clone(), adapter::default_wintun_path(), protection)
                .unwrap();
        drop(agent);

        let protection = StateProtection::from_provider(
            &path,
            StateKeyProvider::RestrictedFile(key_path.clone()),
        )
        .unwrap();
        let agent =
            Agent::open_with_protection(path.clone(), adapter::default_wintun_path(), protection)
                .expect("encrypted state must reopen without migration authorization");
        drop(agent);

        let bytes = fs::read(&path).unwrap();
        assert!(matches!(
            decode_protected_state::<PersistedState>(&bytes, AGENT_STATE_PROTECTION_PURPOSE),
            Err(meshlake_core::StateProtectionError::MissingMasterKey)
        ));
        let protection =
            StateProtection::from_provider(&path, StateKeyProvider::RestrictedFile(key_path))
                .unwrap();
        let decoded: meshlake_core::DecodedState<PersistedState> =
            decode_protected_state_with(&bytes, AGENT_STATE_PROTECTION_PURPOSE, &protection)
                .unwrap();
        assert_eq!(decoded.value.device_id, original.device_id);
        assert_eq!(
            decoded.value.identity_secret_key,
            original.identity_secret_key
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
