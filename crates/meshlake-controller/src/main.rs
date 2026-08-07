//! Self-hostable MeshLake membership controller.
//! It signs authorization documents but never handles virtual-network packets.

mod state_backup_command;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use meshlake_core::{
    cleanup_stale_state_backup, create_restricted_secret_file, decode_protected_state_with,
    recover_protected_state_file, resolve_state_backup_path, restrict_state_file_permissions,
    write_protected_state_file_with, AuthorizedMembership, DeviceId, DnsPolicy, EnrollmentResponse,
    ExitNode, MembershipCertificate, MembershipClaims, MembershipRefreshRequest,
    MembershipRefreshResponse, NetworkAuthorizationManifest, NetworkId, NetworkKey,
    NetworkPolicyManifest, PlanetManifest, PlanetRelay, PlanetRoot, PolicyRoute,
    ServiceIdentityPolicy, StateFileLock, StateKeyProvider, StateProtection, UpsertNetworkRequest,
    VirtualNetwork, CONTROLLER_STATE_PROTECTION_PURPOSE,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{self, BufReader, IsTerminal, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

use state_backup_command::StateCommand as StateBackupCommand;

#[cfg(test)]
use meshlake_core::{decode_protected_state, write_protected_state_file};

const CONTROLLER_STATE_SCHEMA_VERSION: u32 = 2;

#[derive(Parser)]
#[command(
    name = "meshlake-controller",
    about = "MeshLake controller and enrollment service"
)]
struct Cli {
    /// HTTP/HTTPS listener. Plain HTTP is restricted to loopback by default.
    #[arg(long, default_value = "127.0.0.1:51822")]
    bind: SocketAddr,
    /// PEM certificate chain used by the controller's native HTTPS listener.
    #[arg(long, value_name = "CERTIFICATE_PEM")]
    tls_certificate: Option<PathBuf>,
    /// PEM private key matching --tls-certificate.
    #[arg(long, value_name = "PRIVATE_KEY_PEM")]
    tls_private_key: Option<PathBuf>,
    /// Public PEM CA certificate embedded in invitations for private-PKI clients.
    #[arg(long, value_name = "CA_CERTIFICATE_PEM")]
    tls_client_ca_certificate: Option<PathBuf>,
    /// DANGEROUS: permit plain HTTP on a non-loopback address for isolated development only.
    #[arg(long)]
    allow_insecure_public_http: bool,
    #[arg(long)]
    state_file: Option<PathBuf>,
    /// Write the first administrator token to a newly created restricted file.
    #[arg(
        long,
        value_name = "SECRET_FILE",
        conflicts_with = "claim_initial_admin_token"
    )]
    initial_admin_token_file: Option<PathBuf>,
    /// Show the first administrator token only on the attached interactive terminal.
    #[arg(long, conflicts_with = "initial_admin_token_file")]
    claim_initial_admin_token: bool,
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
    /// Public controller URL published through the signed Planet manifest.
    #[arg(long)]
    planet_controller_url: Option<String>,
    /// Public MeshLake encrypted-UDP relay endpoint. Repeat for failover order.
    #[arg(long = "planet-relay-endpoint")]
    planet_relay_endpoints: Vec<SocketAddr>,
    /// Planet V3 Relay identity: RELAY_UUID@CURRENT_KEY_BASE64@IP:PORT, or
    /// RELAY_UUID@CURRENT_KEY_BASE64@NEXT_KEY_BASE64@NOT_BEFORE@NOT_AFTER@IP:PORT.
    #[arg(long = "planet-relay-identity", value_parser = parse_planet_relay_identity)]
    planet_relay_identities: Vec<PlanetRelay>,
    /// Root descriptor in BASE64_PUBLIC_KEY@IP:PORT form. Repeat for multiple roots.
    #[arg(long = "planet-root", value_parser = parse_planet_root)]
    planet_roots: Vec<PlanetRoot>,
    /// Planet V3 Root identity using the same rotation descriptor as Relay identities.
    #[arg(long = "planet-root-identity", value_parser = parse_planet_root_identity)]
    planet_root_identities: Vec<PlanetRoot>,
    /// Optional STUN server (`host:port`). Repeat for multiple servers.
    #[arg(long = "planet-stun")]
    planet_stun_servers: Vec<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Export or restore password-protected controller state.
    State {
        #[command(subcommand)]
        command: StateBackupCommand,
    },
}

#[derive(Clone, Serialize, Deserialize)]
struct ControllerState {
    schema_version: u32,
    signing_key: Vec<u8>,
    admin_token: String,
    networks: HashMap<NetworkId, ManagedNetwork>,
    enrollment_tokens: HashMap<Uuid, EnrollmentToken>,
}

impl std::fmt::Debug for ControllerState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerState")
            .field("schema_version", &self.schema_version)
            .field("signing_key", &"[REDACTED]")
            .field("admin_token", &"[REDACTED]")
            .field("networks", &self.networks)
            .field("enrollment_tokens", &self.enrollment_tokens)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedNetwork {
    network: VirtualNetwork,
    members: HashMap<DeviceId, MembershipClaims>,
    #[serde(default)]
    network_key: Vec<u8>,
    #[serde(default)]
    network_key_epoch: u64,
    #[serde(default)]
    authorization_epoch: u64,
    #[serde(default)]
    member_certificate_ids: HashMap<DeviceId, Uuid>,
    #[serde(default)]
    revoked_certificate_ids: HashMap<Uuid, u64>,
    #[serde(default)]
    policy_epoch: u64,
    #[serde(default)]
    policy: ManagedPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ManagedPolicy {
    #[serde(default)]
    routes: Vec<ManagedPolicyRoute>,
    #[serde(default)]
    exit_nodes: Vec<ManagedExitNode>,
    #[serde(default)]
    dns: DnsPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedPolicyRoute {
    prefix: String,
    gateway_device_id: DeviceId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedExitNode {
    gateway_device_id: DeviceId,
    supports_ipv4: bool,
    supports_ipv6: bool,
}

#[derive(Debug, Deserialize)]
struct PolicyUpdateRequest {
    #[serde(default)]
    routes: Vec<ManagedPolicyRoute>,
    #[serde(default)]
    exit_nodes: Vec<ManagedExitNode>,
    #[serde(default)]
    dns: DnsPolicy,
}

#[derive(Debug, Deserialize)]
struct MemberRouteAuthorizationRequest {
    #[serde(default)]
    allowed_routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnrollmentToken {
    network_id: NetworkId,
    expires_at_unix_seconds: u64,
    /// The first device that redeemed this token.  Keeping this record until
    /// expiry lets that same device retry after a local delivery failure,
    /// while preventing a second device from using the invitation.
    #[serde(default)]
    used_by: Option<DeviceId>,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    /// Clamped between 60 seconds and 24 hours.
    expires_in_seconds: Option<u64>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    expires_at_unix_seconds: u64,
    /// A one-time, self-contained join link. It includes the public controller
    /// identity so a joining device can verify enrollment material without a
    /// separate copy/paste step.
    invite_link: Option<String>,
}

/// The only controller identity material that clients need.  This is safe to
/// publish; the signing key itself always remains in the controller state file.
#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    public_key: String,
}

#[derive(Deserialize)]
struct EnrollmentRequest {
    network_id: NetworkId,
    device_id: DeviceId,
    #[serde(default)]
    device_public_key: Vec<u8>,
    token: String,
}

#[derive(Debug, Clone)]
struct PlanetSettings {
    version: u8,
    controller_url: String,
    tls_client_ca_pem: Option<String>,
    roots: Vec<PlanetRoot>,
    relays: Vec<PlanetRelay>,
    stun_servers: Vec<String>,
}

struct Controller {
    path: PathBuf,
    state: RwLock<ControllerState>,
    state_protection: StateProtection,
    planet: Option<PlanetSettings>,
    refresh_nonces: Mutex<HashMap<[u8; 16], Instant>>,
    _state_lock: StateFileLock,
}

enum InitialAdminTokenOutput {
    Interactive,
    RestrictedFile(PathBuf),
}

impl Controller {
    #[cfg(test)]
    fn open(
        path: PathBuf,
        planet: Option<PlanetSettings>,
        initial_token_output: Option<&InitialAdminTokenOutput>,
        interactive_terminal: bool,
        output: &mut dyn Write,
    ) -> Result<Self> {
        Self::open_with_protection(
            path,
            planet,
            StateProtection::platform_default(),
            initial_token_output,
            interactive_terminal,
            output,
        )
    }

    fn open_with_protection(
        path: PathBuf,
        planet: Option<PlanetSettings>,
        state_protection: StateProtection,
        initial_token_output: Option<&InitialAdminTokenOutput>,
        interactive_terminal: bool,
        output: &mut dyn Write,
    ) -> Result<Self> {
        let state_lock = StateFileLock::acquire(&path)?;
        recover_protected_state_file(&path)?;
        let (mut state, mut migrated) = if path.exists() {
            if initial_token_output.is_some() {
                anyhow::bail!(
                    "initial administrator-token output options are valid only when creating a new controller state"
                );
            }
            restrict_state_file_permissions(&path)?;
            let bytes =
                fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            let decoded = decode_protected_state_with(
                &bytes,
                CONTROLLER_STATE_PROTECTION_PURPOSE,
                &state_protection,
            )
            .with_context(|| {
                format!("invalid or unreadable controller state {}", path.display())
            })?;
            (decoded.value, decoded.needs_protection_upgrade)
        } else {
            let initial_token_output = initial_token_output.context(
                "new controller initialization requires --claim-initial-admin-token or --initial-admin-token-file",
            )?;
            let resolved_initial_token_file;
            let initial_token_output = match initial_token_output {
                InitialAdminTokenOutput::RestrictedFile(output_path) => {
                    resolved_initial_token_file = resolve_state_backup_path(&path, output_path)
                        .context(
                            "initial administrator-token file conflicts with a reserved controller state path",
                        )?;
                    InitialAdminTokenOutput::RestrictedFile(resolved_initial_token_file)
                }
                InitialAdminTokenOutput::Interactive => InitialAdminTokenOutput::Interactive,
            };
            let state = initialize_new_controller_state(
                &initial_token_output,
                interactive_terminal,
                output,
                |state| write_state_with_protection(&path, state, &state_protection),
            )?;
            (state, false)
        };
        migrated |= migrate_and_validate_controller_state(&mut state)?;
        if migrated {
            write_state_with_protection(&path, &state, &state_protection)?;
        }
        cleanup_stale_state_backup(&path)?;
        Ok(Self {
            path,
            state: RwLock::new(state),
            state_protection,
            planet,
            refresh_nonces: Mutex::new(HashMap::new()),
            _state_lock: state_lock,
        })
    }

    async fn create_network(
        &self,
        headers: &HeaderMap,
        request: UpsertNetworkRequest,
    ) -> Result<VirtualNetwork, ApiError> {
        request.validate().map_err(ApiError::bad_request)?;
        let mut state = self.state.write().await;
        require_admin(&state, headers)?;
        let id = request.id.unwrap_or(NetworkId(Uuid::new_v4()));
        if state.networks.contains_key(&id) {
            return Err(ApiError::conflict("network id already exists"));
        }
        let network = VirtualNetwork {
            id,
            name: request.name,
            ipv4_prefix: request.ipv4_prefix,
            ipv6_prefix: request.ipv6_prefix,
            relay_policy: request.relay_policy,
        };
        state.networks.insert(
            id,
            ManagedNetwork {
                network: network.clone(),
                members: HashMap::new(),
                network_key: NetworkKey::generate()
                    .map_err(ApiError::internal)?
                    .to_bytes()
                    .to_vec(),
                network_key_epoch: 1,
                authorization_epoch: 1,
                member_certificate_ids: HashMap::new(),
                revoked_certificate_ids: HashMap::new(),
                policy_epoch: 1,
                policy: ManagedPolicy::default(),
            },
        );
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        Ok(network)
    }

    async fn issue_token(
        &self,
        headers: &HeaderMap,
        network_id: NetworkId,
        request: TokenRequest,
    ) -> Result<TokenResponse, ApiError> {
        let mut state = self.state.write().await;
        require_admin(&state, headers)?;
        if !state.networks.contains_key(&network_id) {
            return Err(ApiError::not_found("network does not exist"));
        }
        let expires_at_unix_seconds =
            now() + request.expires_in_seconds.unwrap_or(900).clamp(60, 86_400);
        let token = Uuid::new_v4();
        state.enrollment_tokens.insert(
            token,
            EnrollmentToken {
                network_id,
                expires_at_unix_seconds,
                used_by: None,
            },
        );
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        let controller_public_key = signing_key(&state)
            .map_err(ApiError::internal)?
            .verifying_key()
            .to_bytes();
        Ok(TokenResponse {
            token: token.to_string(),
            expires_at_unix_seconds,
            invite_link: self.planet.as_ref().map(|planet| {
                make_invite_link(
                    &planet.controller_url,
                    network_id.0,
                    &token.to_string(),
                    &STANDARD.encode(controller_public_key),
                    planet.tls_client_ca_pem.as_deref(),
                )
            }),
        })
    }

    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentResponse, ApiError> {
        if request.device_public_key.len() != 32 {
            return Err(ApiError::bad_request(
                "device public key must contain exactly 32 bytes",
            ));
        }
        let token_id = request
            .token
            .parse::<Uuid>()
            .map_err(|_| ApiError::bad_request("token format is invalid"))?;
        let mut state = self.state.write().await;
        let token = state
            .enrollment_tokens
            .get_mut(&token_id)
            .ok_or_else(|| ApiError::unauthorized("token is invalid or expired"))?;
        if token.network_id != request.network_id || now() > token.expires_at_unix_seconds {
            return Err(ApiError::unauthorized("token is invalid or expired"));
        }
        if token
            .used_by
            .is_some_and(|device| device != request.device_id)
        {
            return Err(ApiError::unauthorized(
                "token is already bound to another device",
            ));
        }
        token.used_by = Some(request.device_id);
        let signing_bytes: [u8; 32] = state
            .signing_key
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::internal("controller signing key is invalid"))?;
        let signing_key = SigningKey::from_bytes(&signing_bytes);
        let managed = state
            .networks
            .get_mut(&request.network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        let assigned_addresses =
            assigned_addresses_for_device(&managed.network, &managed.members, request.device_id)
                .map_err(ApiError::bad_request)?;
        let mut allowed_routes = vec![managed.network.ipv4_prefix.clone()];
        if let Some(prefix) = &managed.network.ipv6_prefix {
            allowed_routes.push(prefix.clone());
        }
        let certificate_id = *managed
            .member_certificate_ids
            .entry(request.device_id)
            .or_insert_with(Uuid::new_v4);
        let claims = MembershipClaims {
            network_id: request.network_id,
            device_id: request.device_id,
            device_public_key: request.device_public_key,
            assigned_addresses,
            allowed_routes,
            issued_at_unix_seconds: now(),
            expires_at_unix_seconds: Some(now() + 86_400),
        };
        let certificate = MembershipCertificate::sign_authorized(
            claims.clone(),
            certificate_id,
            managed.network_key_epoch,
            &signing_key,
        )
        .map_err(ApiError::internal)?;
        let network = managed.network.clone();
        let network_key = managed.network_key.clone();
        managed.members.insert(request.device_id, claims);
        managed.authorization_epoch = managed.authorization_epoch.saturating_add(1);
        let authorization =
            sign_authorization(managed, &signing_key).map_err(ApiError::internal)?;
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        Ok(EnrollmentResponse {
            network,
            certificate,
            network_key,
            authorization,
        })
    }

    async fn networks(&self) -> Vec<VirtualNetwork> {
        self.state
            .read()
            .await
            .networks
            .values()
            .map(|entry| entry.network.clone())
            .collect()
    }

    async fn delete_network(
        &self,
        headers: &HeaderMap,
        network_id: NetworkId,
    ) -> Result<(), ApiError> {
        let mut state = self.state.write().await;
        require_admin(&state, headers)?;
        if state.networks.remove(&network_id).is_none() {
            return Err(ApiError::not_found("network does not exist"));
        }
        state
            .enrollment_tokens
            .retain(|_, token| token.network_id != network_id);
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)
    }

    async fn members(
        &self,
        headers: &HeaderMap,
        network_id: NetworkId,
    ) -> Result<Vec<MembershipClaims>, ApiError> {
        let state = self.state.read().await;
        require_admin(&state, headers)?;
        let network = state
            .networks
            .get(&network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        Ok(network.members.values().cloned().collect())
    }

    async fn authorize_member_routes(
        &self,
        headers: &HeaderMap,
        network_id: NetworkId,
        device_id: DeviceId,
        request: MemberRouteAuthorizationRequest,
    ) -> Result<MembershipClaims, ApiError> {
        let mut state = self.state.write().await;
        require_admin(&state, headers)?;
        let signing_key = signing_key(&state).map_err(ApiError::internal)?;
        let network = state
            .networks
            .get_mut(&network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        let mut candidate = network.clone();
        let mut allowed_routes = vec![candidate.network.ipv4_prefix.clone()];
        if let Some(prefix) = &candidate.network.ipv6_prefix {
            allowed_routes.push(prefix.clone());
        }
        for raw in request.allowed_routes {
            let prefix = raw
                .parse::<IpNet>()
                .map_err(|_| ApiError::bad_request(format!("invalid allowed route {raw:?}")))?;
            if prefix.prefix_len() == 0 {
                return Err(ApiError::bad_request(
                    "default routes are not supported in this stage",
                ));
            }
            allowed_routes.push(prefix.to_string());
        }
        allowed_routes.sort();
        allowed_routes.dedup();
        if allowed_routes.len() > 258 {
            return Err(ApiError::bad_request(
                "too many member route authorizations",
            ));
        }
        let claims = candidate
            .members
            .get_mut(&device_id)
            .ok_or_else(|| ApiError::not_found("member does not exist"))?;
        claims.allowed_routes = allowed_routes;
        claims.issued_at_unix_seconds = now();
        claims.expires_at_unix_seconds = Some(now() + 86_400);
        let updated = claims.clone();
        sign_policy(&candidate, &signing_key).map_err(ApiError::bad_request)?;
        *network = candidate;
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        Ok(updated)
    }

    async fn remove_member(
        &self,
        headers: &HeaderMap,
        network_id: NetworkId,
        device_id: DeviceId,
    ) -> Result<(), ApiError> {
        let mut state = self.state.write().await;
        require_admin(&state, headers)?;
        let network = state
            .networks
            .get_mut(&network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        if network.members.remove(&device_id).is_none() {
            return Err(ApiError::not_found("member does not exist"));
        }
        if let Some(certificate_id) = network.member_certificate_ids.remove(&device_id) {
            network
                .revoked_certificate_ids
                .insert(certificate_id, now());
        }
        let previous_route_count = network.policy.routes.len();
        let previous_exit_count = network.policy.exit_nodes.len();
        network
            .policy
            .routes
            .retain(|route| route.gateway_device_id != device_id);
        network
            .policy
            .exit_nodes
            .retain(|exit_node| exit_node.gateway_device_id != device_id);
        if network.policy.routes.len() != previous_route_count
            || network.policy.exit_nodes.len() != previous_exit_count
        {
            network.policy_epoch = network.policy_epoch.saturating_add(1).max(1);
        }
        network.network_key = NetworkKey::generate()
            .map_err(ApiError::internal)?
            .to_bytes()
            .to_vec();
        network.network_key_epoch = network.network_key_epoch.saturating_add(1).max(1);
        network.authorization_epoch = network.authorization_epoch.saturating_add(1).max(1);
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)
    }

    async fn authorization(
        &self,
        network_id: NetworkId,
    ) -> Result<NetworkAuthorizationManifest, ApiError> {
        let state = self.state.read().await;
        let signing_key = signing_key(&state).map_err(ApiError::internal)?;
        let network = state
            .networks
            .get(&network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        sign_authorization(network, &signing_key).map_err(ApiError::internal)
    }

    async fn policy(&self, network_id: NetworkId) -> Result<NetworkPolicyManifest, ApiError> {
        let state = self.state.read().await;
        let signing_key = signing_key(&state).map_err(ApiError::internal)?;
        let network = state
            .networks
            .get(&network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        sign_policy(network, &signing_key).map_err(ApiError::internal)
    }

    async fn update_policy(
        &self,
        headers: &HeaderMap,
        network_id: NetworkId,
        request: PolicyUpdateRequest,
    ) -> Result<NetworkPolicyManifest, ApiError> {
        let mut state = self.state.write().await;
        require_admin(&state, headers)?;
        let signing_key = signing_key(&state).map_err(ApiError::internal)?;
        let network = state
            .networks
            .get_mut(&network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        let mut candidate = network.clone();
        candidate.policy.routes = request.routes;
        candidate.policy.exit_nodes = request.exit_nodes;
        candidate.policy.dns = request.dns;
        candidate.policy_epoch = candidate.policy_epoch.saturating_add(1).max(1);
        let manifest = sign_policy(&candidate, &signing_key).map_err(ApiError::bad_request)?;
        candidate.policy.routes = manifest
            .routes
            .iter()
            .map(|route| ManagedPolicyRoute {
                prefix: route.prefix.clone(),
                gateway_device_id: route.gateway_certificate.claims.device_id,
            })
            .collect();
        candidate.policy.exit_nodes = manifest
            .exit_nodes
            .iter()
            .map(|exit_node| ManagedExitNode {
                gateway_device_id: exit_node.gateway_certificate.claims.device_id,
                supports_ipv4: exit_node.supports_ipv4,
                supports_ipv6: exit_node.supports_ipv6,
            })
            .collect();
        candidate.policy.dns = manifest.dns.clone();
        *network = candidate;
        write_state_with_protection(&self.path, &state, &self.state_protection)
            .map_err(ApiError::internal)?;
        Ok(manifest)
    }

    async fn refresh_membership(
        &self,
        request: MembershipRefreshRequest,
    ) -> Result<MembershipRefreshResponse, ApiError> {
        let state = self.state.read().await;
        let network = state
            .networks
            .get(&request.payload.network_id)
            .ok_or_else(|| ApiError::not_found("network does not exist"))?;
        let claims = network
            .members
            .get(&request.payload.device_id)
            .ok_or_else(|| ApiError::unauthorized("membership is revoked or unknown"))?;
        let certificate_id = network
            .member_certificate_ids
            .get(&request.payload.device_id)
            .copied()
            .ok_or_else(|| ApiError::unauthorized("membership certificate is unknown"))?;
        if request.payload.certificate_id != certificate_id {
            return Err(ApiError::unauthorized("membership certificate is revoked"));
        }
        request
            .verify(&claims.device_public_key, now(), 120)
            .map_err(|error| ApiError::unauthorized(error.to_string()))?;
        {
            let mut nonces = self
                .refresh_nonces
                .lock()
                .map_err(|_| ApiError::internal("refresh nonce cache is unavailable"))?;
            nonces.retain(|_, seen| seen.elapsed() <= Duration::from_secs(300));
            if nonces
                .insert(request.payload.nonce, Instant::now())
                .is_some()
            {
                return Err(ApiError::unauthorized("refresh request was already used"));
            }
        }
        let signing_key = signing_key(&state).map_err(ApiError::internal)?;
        let mut refreshed_claims = claims.clone();
        refreshed_claims.issued_at_unix_seconds = now();
        refreshed_claims.expires_at_unix_seconds = Some(now() + 86_400);
        let certificate = MembershipCertificate::sign_authorized(
            refreshed_claims,
            certificate_id,
            network.network_key_epoch,
            &signing_key,
        )
        .map_err(ApiError::internal)?;
        Ok(MembershipRefreshResponse {
            revoked: false,
            authorization: sign_authorization(network, &signing_key).map_err(ApiError::internal)?,
            certificate: Some(certificate),
            network_key: network.network_key.clone(),
        })
    }

    async fn public_key_base64(&self) -> Result<String> {
        let state = self.state.read().await;
        let bytes: [u8; 32] = state
            .signing_key
            .as_slice()
            .try_into()
            .context("controller signing key is invalid")?;
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(STANDARD.encode(signing_key.verifying_key().to_bytes()))
    }

    async fn planet_manifest(&self) -> Result<Option<PlanetManifest>> {
        let Some(planet) = &self.planet else {
            return Ok(None);
        };
        let state = self.state.read().await;
        let signing_key = signing_key(&state)?;
        let manifest = if planet.version == 3 {
            PlanetManifest::sign_v3(
                planet.controller_url.clone(),
                planet.roots.clone(),
                planet.relays.clone(),
                planet.stun_servers.clone(),
                now(),
                None,
                &signing_key,
            )?
        } else {
            PlanetManifest::sign_v2(
                planet.controller_url.clone(),
                planet.roots.clone(),
                planet.relays.clone(),
                planet.stun_servers.clone(),
                now(),
                None,
                &signing_key,
            )?
        };
        Ok(Some(manifest))
    }
}

fn deliver_initial_admin_token(
    token: &str,
    destination: &InitialAdminTokenOutput,
    interactive_terminal: bool,
    output: &mut dyn Write,
) -> Result<()> {
    match destination {
        InitialAdminTokenOutput::Interactive => {
            if !interactive_terminal {
                anyhow::bail!(
                    "--claim-initial-admin-token requires an attached interactive terminal"
                );
            }
            writeln!(output, "Initial administrator token (save it now): {token}")
                .context("cannot write initial administrator token to the interactive terminal")?;
            output
                .flush()
                .context("cannot flush the interactive administrator-token output")?;
        }
        InitialAdminTokenOutput::RestrictedFile(path) => {
            let mut contents = zeroize::Zeroizing::new(token.as_bytes().to_vec());
            contents.push(b'\n');
            create_restricted_secret_file(path, &contents)
                .context("cannot create restricted initial administrator-token file")?;
        }
    }
    Ok(())
}

fn initialize_new_controller_state<F>(
    destination: &InitialAdminTokenOutput,
    interactive_terminal: bool,
    output: &mut dyn Write,
    write_state: F,
) -> Result<ControllerState>
where
    F: FnOnce(&ControllerState) -> Result<()>,
{
    let mut signing_key = [0_u8; 32];
    getrandom::fill(&mut signing_key)
        .map_err(|error| anyhow::anyhow!("cannot generate controller signing key: {error:?}"))?;
    let admin_token = Uuid::new_v4().to_string();
    let state = ControllerState {
        schema_version: CONTROLLER_STATE_SCHEMA_VERSION,
        signing_key: signing_key.to_vec(),
        admin_token: admin_token.clone(),
        networks: HashMap::new(),
        enrollment_tokens: HashMap::new(),
    };
    deliver_initial_admin_token(&admin_token, destination, interactive_terminal, output)?;
    if let Err(state_error) = write_state(&state) {
        if let InitialAdminTokenOutput::RestrictedFile(path) = destination {
            match fs::remove_file(path) {
                Ok(()) => {
                    return Err(state_error.context(
                        "controller state creation failed; the newly created initial administrator-token file was removed",
                    ));
                }
                Err(cleanup_error) => {
                    return Err(state_error.context(format!(
                        "controller state creation failed and the newly created initial administrator-token file could not be removed: {cleanup_error}"
                    )));
                }
            }
        }
        return Err(
            state_error.context("controller state creation failed after interactive token claim")
        );
    }
    Ok(state)
}

fn signing_key(state: &ControllerState) -> Result<SigningKey> {
    let bytes: [u8; 32] = state
        .signing_key
        .as_slice()
        .try_into()
        .context("controller signing key is invalid")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn validate_controller_state(state: &ControllerState) -> Result<()> {
    let signing_key = signing_key(state)?;
    if state.admin_token.trim().is_empty() {
        anyhow::bail!("controller administrator token is empty");
    }
    for (network_id, managed) in &state.networks {
        NetworkKey::from_slice(&managed.network_key).with_context(|| {
            format!(
                "controller network {} contains an invalid network key",
                network_id.0
            )
        })?;
        sign_policy(managed, &signing_key).with_context(|| {
            format!(
                "controller network {} contains an invalid policy",
                network_id.0
            )
        })?;
    }
    Ok(())
}

fn migrate_and_validate_controller_state(state: &mut ControllerState) -> Result<bool> {
    if state.schema_version > CONTROLLER_STATE_SCHEMA_VERSION {
        anyhow::bail!(
            "controller state schema {} is newer than supported schema {}",
            state.schema_version,
            CONTROLLER_STATE_SCHEMA_VERSION
        );
    }
    let mut migrated = false;
    for managed in state.networks.values_mut() {
        if managed.network_key.len() != 32 {
            if state.schema_version >= CONTROLLER_STATE_SCHEMA_VERSION {
                anyhow::bail!(
                    "controller network {} contains an invalid network key",
                    managed.network.id.0
                );
            }
            managed.network_key = NetworkKey::generate()?.to_bytes().to_vec();
            migrated = true;
        }
        if managed.network_key_epoch == 0 {
            managed.network_key_epoch = 1;
            migrated = true;
        }
        if managed.authorization_epoch == 0 {
            managed.authorization_epoch = 1;
            migrated = true;
        }
        if managed.policy_epoch == 0 {
            managed.policy_epoch = 1;
            migrated = true;
        }
        for device_id in managed.members.keys().copied().collect::<Vec<_>>() {
            if let std::collections::hash_map::Entry::Vacant(entry) =
                managed.member_certificate_ids.entry(device_id)
            {
                entry.insert(Uuid::new_v4());
                migrated = true;
            }
        }
    }
    if state.schema_version < CONTROLLER_STATE_SCHEMA_VERSION {
        state.schema_version = CONTROLLER_STATE_SCHEMA_VERSION;
        migrated = true;
    }
    validate_controller_state(state)?;
    Ok(migrated)
}

fn sign_authorization(
    network: &ManagedNetwork,
    signing_key: &SigningKey,
) -> Result<NetworkAuthorizationManifest> {
    let active_members = network
        .members
        .iter()
        .filter_map(|(device_id, claims)| {
            network
                .member_certificate_ids
                .get(device_id)
                .copied()
                .map(|certificate_id| AuthorizedMembership {
                    device_id: *device_id,
                    certificate_id,
                    device_public_key: claims.device_public_key.clone(),
                    network_key_epoch: network.network_key_epoch,
                })
        })
        .collect();
    NetworkAuthorizationManifest::sign(
        network.network.id,
        network.authorization_epoch,
        network.network_key_epoch,
        active_members,
        network.revoked_certificate_ids.keys().copied().collect(),
        now(),
        now() + 90,
        signing_key,
    )
    .map_err(Into::into)
}

fn sign_policy(
    network: &ManagedNetwork,
    signing_key: &SigningKey,
) -> Result<NetworkPolicyManifest> {
    let mut routes = Vec::with_capacity(network.policy.routes.len());
    for route in &network.policy.routes {
        let claims = network
            .members
            .get(&route.gateway_device_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "policy gateway {} is not an active member",
                    route.gateway_device_id.0
                )
            })?;
        let certificate_id = network
            .member_certificate_ids
            .get(&route.gateway_device_id)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("policy gateway certificate is missing"))?;
        let mut policy_claims = claims.clone();
        if !policy_claims
            .allowed_routes
            .iter()
            .any(|allowed| route_prefix_covers(allowed, &route.prefix))
        {
            anyhow::bail!(
                "policy gateway {} is not authorized for route {}",
                route.gateway_device_id.0,
                route.prefix
            );
        }
        policy_claims.issued_at_unix_seconds = now();
        policy_claims.expires_at_unix_seconds = Some(now() + 86_400);
        let certificate = MembershipCertificate::sign_authorized(
            policy_claims,
            certificate_id,
            network.network_key_epoch,
            signing_key,
        )?;
        routes.push(PolicyRoute {
            prefix: route.prefix.clone(),
            gateway_certificate: certificate,
        });
    }
    let mut exit_nodes = Vec::with_capacity(network.policy.exit_nodes.len());
    for exit_node in &network.policy.exit_nodes {
        let claims = network
            .members
            .get(&exit_node.gateway_device_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "exit gateway {} is not an active member",
                    exit_node.gateway_device_id.0
                )
            })?;
        let certificate_id = network
            .member_certificate_ids
            .get(&exit_node.gateway_device_id)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("exit gateway certificate is missing"))?;
        let mut exit_claims = claims.clone();
        exit_claims.issued_at_unix_seconds = now();
        exit_claims.expires_at_unix_seconds = Some(now() + 86_400);
        let certificate = MembershipCertificate::sign_authorized(
            exit_claims,
            certificate_id,
            network.network_key_epoch,
            signing_key,
        )?;
        exit_nodes.push(ExitNode {
            gateway_certificate: certificate,
            supports_ipv4: exit_node.supports_ipv4,
            supports_ipv6: exit_node.supports_ipv6,
        });
    }
    NetworkPolicyManifest::sign_with_exit_nodes(
        network.network.id,
        network.policy_epoch,
        routes,
        exit_nodes,
        network.policy.dns.clone(),
        now(),
        now() + 90,
        signing_key,
    )
    .map_err(Into::into)
}

fn route_prefix_covers(allowed: &str, target: &str) -> bool {
    match (allowed.parse::<IpNet>(), target.parse::<IpNet>()) {
        (Ok(IpNet::V4(allowed)), Ok(IpNet::V4(target))) => {
            allowed.prefix_len() <= target.prefix_len() && allowed.contains(&target.network())
        }
        (Ok(IpNet::V6(allowed)), Ok(IpNet::V6(target))) => {
            allowed.prefix_len() <= target.prefix_len() && allowed.contains(&target.network())
        }
        _ => false,
    }
}

fn assigned_addresses_for_device(
    network: &VirtualNetwork,
    members: &HashMap<DeviceId, MembershipClaims>,
    device_id: DeviceId,
) -> Result<Vec<IpAddr>, String> {
    let mut addresses = members
        .get(&device_id)
        .map(|claims| claims.assigned_addresses.clone())
        .unwrap_or_default();
    if !addresses.iter().any(IpAddr::is_ipv4) {
        addresses.push(IpAddr::V4(allocate_ipv4_address(network, members)?));
    }
    if network.ipv6_prefix.is_some() && !addresses.iter().any(IpAddr::is_ipv6) {
        addresses.push(IpAddr::V6(allocate_ipv6_address(network, members)?));
    }
    Ok(addresses)
}

fn allocate_ipv4_address(
    network: &VirtualNetwork,
    members: &HashMap<DeviceId, MembershipClaims>,
) -> Result<Ipv4Addr, String> {
    let prefix = network
        .ipv4_prefix
        .parse::<Ipv4Net>()
        .map_err(|_| "network has an invalid IPv4 prefix".to_string())?;
    if prefix.prefix_len() >= 31 {
        return Err("network prefix must leave usable host addresses".into());
    }
    let used: HashSet<Ipv4Addr> = members
        .values()
        .flat_map(|member| member.assigned_addresses.iter())
        .filter_map(|address| match address {
            IpAddr::V4(ip) => Some(*ip),
            _ => None,
        })
        .collect();
    let first = u32::from(prefix.network()) + 1;
    let last = u32::from(prefix.broadcast()) - 1;
    for candidate in first..=last {
        let candidate = Ipv4Addr::from(candidate);
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err("network address pool is exhausted".into())
}

fn allocate_ipv6_address(
    network: &VirtualNetwork,
    members: &HashMap<DeviceId, MembershipClaims>,
) -> Result<Ipv6Addr, String> {
    let prefix = network
        .ipv6_prefix
        .as_deref()
        .ok_or_else(|| "network does not define an IPv6 prefix".to_string())?
        .parse::<Ipv6Net>()
        .map_err(|_| "network has an invalid IPv6 prefix".to_string())?;
    if prefix.prefix_len() == 128 {
        return Err("IPv6 network prefix must leave a usable host address".into());
    }
    let used: HashSet<Ipv6Addr> = members
        .values()
        .flat_map(|member| member.assigned_addresses.iter())
        .filter_map(|address| match address {
            IpAddr::V6(ip) => Some(*ip),
            IpAddr::V4(_) => None,
        })
        .collect();
    let network_address = u128::from(prefix.network());
    // The first missing positive host ID is at most used.len() + 1, so a /64
    // never requires iterating its enormous address space.
    for offset in 1..=used.len() as u128 + 1 {
        let Some(raw) = network_address.checked_add(offset) else {
            break;
        };
        let candidate = Ipv6Addr::from(raw);
        if !prefix.contains(&candidate) {
            break;
        }
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err("IPv6 network address pool is exhausted".into())
}

fn require_admin(state: &ControllerState, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = headers
        .get("x-meshlake-admin-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if bool::from(supplied.as_bytes().ct_eq(state.admin_token.as_bytes())) {
        Ok(())
    } else {
        Err(ApiError::unauthorized("administrator token is required"))
    }
}

#[cfg(test)]
fn write_state(path: &FsPath, state: &ControllerState) -> Result<()> {
    write_protected_state_file(path, state, CONTROLLER_STATE_PROTECTION_PURPOSE)
        .with_context(|| format!("cannot securely write controller state {}", path.display()))
}

fn write_state_with_protection(
    path: &FsPath,
    state: &ControllerState,
    protection: &StateProtection,
) -> Result<()> {
    write_protected_state_file_with(path, state, CONTROLLER_STATE_PROTECTION_PURPOSE, protection)
        .with_context(|| format!("cannot securely write controller state {}", path.display()))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_secs()
}

/// Builds the only value an administrator needs to send to a new member.
/// The token is intentionally embedded: treat the resulting URL like a
/// password and deliver it only over a trusted channel.
fn make_invite_link(
    controller_url: &str,
    network_id: Uuid,
    token: &str,
    controller_public_key_base64: &str,
    tls_client_ca_pem: Option<&str>,
) -> String {
    let mut link = Url::parse("meshlake://join").expect("static invitation URL is valid");
    link.query_pairs_mut()
        .append_pair("controller", controller_url.trim_end_matches('/'))
        .append_pair("network_id", &network_id.to_string())
        .append_pair("token", token)
        .append_pair("public_key", controller_public_key_base64)
        // The controller publishes a signed Planet manifest at this stable
        // location when started with the Planet options. A joining node can
        // therefore receive root, relay and STUN configuration automatically.
        .append_pair(
            "planet",
            &format!("{}/v1/planet", controller_url.trim_end_matches('/')),
        );
    if let Some(tls_client_ca_pem) = tls_client_ca_pem {
        link.query_pairs_mut()
            .append_pair("tls_ca", &STANDARD.encode(tls_client_ca_pem.as_bytes()));
    }
    link.into()
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
    fn unauthorized(error: impl Into<String>) -> Self {
        Self(StatusCode::UNAUTHORIZED, error.into())
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

async fn health() -> &'static str {
    "MeshLake controller is running"
}
async fn public_key(
    State(controller): State<Arc<Controller>>,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    Ok(Json(PublicKeyResponse {
        public_key: controller
            .public_key_base64()
            .await
            .map_err(ApiError::internal)?,
    }))
}
async fn planet_manifest(
    State(controller): State<Arc<Controller>>,
) -> Result<Json<PlanetManifest>, ApiError> {
    controller
        .planet_manifest()
        .await
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("Planet endpoint is not configured on this controller"))
}
async fn list_networks(State(controller): State<Arc<Controller>>) -> Json<Vec<VirtualNetwork>> {
    Json(controller.networks().await)
}
async fn create_network(
    State(controller): State<Arc<Controller>>,
    headers: HeaderMap,
    Json(request): Json<UpsertNetworkRequest>,
) -> Result<(StatusCode, Json<VirtualNetwork>), ApiError> {
    Ok((
        StatusCode::CREATED,
        Json(controller.create_network(&headers, request).await?),
    ))
}
async fn create_token(
    State(controller): State<Arc<Controller>>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    Ok(Json(
        controller
            .issue_token(&headers, NetworkId(network_id), request)
            .await?,
    ))
}
async fn delete_network(
    State(controller): State<Arc<Controller>>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    controller
        .delete_network(&headers, NetworkId(network_id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn list_members(
    State(controller): State<Arc<Controller>>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
) -> Result<Json<Vec<MembershipClaims>>, ApiError> {
    Ok(Json(
        controller.members(&headers, NetworkId(network_id)).await?,
    ))
}
async fn remove_member(
    State(controller): State<Arc<Controller>>,
    headers: HeaderMap,
    Path((network_id, device_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    controller
        .remove_member(&headers, NetworkId(network_id), DeviceId(device_id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn authorize_member_routes(
    State(controller): State<Arc<Controller>>,
    headers: HeaderMap,
    Path((network_id, device_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<MemberRouteAuthorizationRequest>,
) -> Result<Json<MembershipClaims>, ApiError> {
    Ok(Json(
        controller
            .authorize_member_routes(
                &headers,
                NetworkId(network_id),
                DeviceId(device_id),
                request,
            )
            .await?,
    ))
}
async fn enroll(
    State(controller): State<Arc<Controller>>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, ApiError> {
    Ok(Json(controller.enroll(request).await?))
}

async fn network_authorization(
    State(controller): State<Arc<Controller>>,
    Path(network_id): Path<Uuid>,
) -> Result<Json<NetworkAuthorizationManifest>, ApiError> {
    Ok(Json(controller.authorization(NetworkId(network_id)).await?))
}

async fn network_policy(
    State(controller): State<Arc<Controller>>,
    Path(network_id): Path<Uuid>,
) -> Result<Json<NetworkPolicyManifest>, ApiError> {
    Ok(Json(controller.policy(NetworkId(network_id)).await?))
}

async fn update_network_policy(
    State(controller): State<Arc<Controller>>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
    Json(request): Json<PolicyUpdateRequest>,
) -> Result<Json<NetworkPolicyManifest>, ApiError> {
    Ok(Json(
        controller
            .update_policy(&headers, NetworkId(network_id), request)
            .await?,
    ))
}

async fn refresh_membership(
    State(controller): State<Arc<Controller>>,
    Json(request): Json<MembershipRefreshRequest>,
) -> Result<Json<MembershipRefreshResponse>, ApiError> {
    Ok(Json(controller.refresh_membership(request).await?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let path = cli.state_file.clone().unwrap_or_else(default_state_path);
    let state_key_provider = cli
        .state_key_file
        .clone()
        .map(StateKeyProvider::RestrictedFile)
        .or_else(|| {
            cli.state_key_systemd_credential
                .clone()
                .map(StateKeyProvider::SystemdCredential)
        });
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
    if let Some(Command::State { command }) = cli.command.take() {
        return state_backup_command::run(command, &path, &state_protection);
    }
    install_rustls_crypto_provider()?;
    let tls_files = controller_tls_configuration(&cli)?;
    // Load and validate the complete chain/key pair before opening the state.
    // A broken TLS deployment must never create a fresh controller identity
    // whose one-time administrator token is then lost in the startup error.
    let tls = load_controller_tls_configuration(tls_files).await?;
    let tls_client_ca_pem = load_tls_client_ca(cli.tls_client_ca_certificate.as_deref())?;
    if tls_client_ca_pem.is_some() && cli.planet_controller_url.is_none() {
        anyhow::bail!(
            "--tls-client-ca-certificate requires --planet-controller-url so the CA can be embedded in invitations"
        );
    }
    if !cli.planet_relay_endpoints.is_empty() && !cli.planet_relay_identities.is_empty() {
        anyhow::bail!(
            "legacy --planet-relay-endpoint cannot be mixed with Planet V3 Relay identities"
        );
    }
    if !cli.planet_roots.is_empty() && !cli.planet_root_identities.is_empty() {
        anyhow::bail!("legacy --planet-root cannot be mixed with Planet V3 Root identities");
    }
    let uses_planet_v3 = !cli.planet_relay_identities.is_empty();
    if uses_planet_v3 && !cli.planet_roots.is_empty()
        || !uses_planet_v3 && !cli.planet_root_identities.is_empty()
    {
        anyhow::bail!(
            "Planet V3 service identities must be used consistently for Roots and Relays"
        );
    }
    let has_relays =
        !cli.planet_relay_endpoints.is_empty() || !cli.planet_relay_identities.is_empty();
    let planet = match (cli.planet_controller_url, has_relays) {
        (Some(controller_url), true) => Some(PlanetSettings {
            version: if uses_planet_v3 { 3 } else { 2 },
            controller_url: validate_controller_url(
                &controller_url,
                cli.allow_insecure_public_http,
            )?,
            tls_client_ca_pem,
            roots: if uses_planet_v3 {
                cli.planet_root_identities
            } else {
                cli.planet_roots
            }
                .into_iter()
                .enumerate()
                .map(|(priority, mut root)| {
                    root.priority = priority.min(u16::MAX as usize) as u16;
                    root
                })
                .collect(),
            relays: if uses_planet_v3 {
                cli.planet_relay_identities
            } else {
                cli.planet_relay_endpoints
                    .into_iter()
                    .map(|endpoint| PlanetRelay {
                        endpoint,
                        priority: 0,
                        identity: None,
                    })
                    .collect()
            }
            .into_iter()
            .enumerate()
            .map(|(priority, mut relay)| {
                relay.priority = priority.min(u16::MAX as usize) as u16;
                relay
            })
            .collect(),
            stun_servers: cli
                .planet_stun_servers
                .into_iter()
                .map(|server| server.trim().to_owned())
                .filter(|server| !server.is_empty())
                .take(8)
                .collect(),
        }),
        (None, false)
            if cli.planet_roots.is_empty()
                && cli.planet_root_identities.is_empty()
                && cli.planet_stun_servers.is_empty() =>
        {
            None
        }
        _ => anyhow::bail!(
            "--planet-controller-url and at least one --planet-relay-endpoint must be provided together"
        ),
    };
    let initial_token_output = cli
        .initial_admin_token_file
        .map(InitialAdminTokenOutput::RestrictedFile)
        .or_else(|| {
            cli.claim_initial_admin_token
                .then_some(InitialAdminTokenOutput::Interactive)
        });
    let mut stderr = io::stderr().lock();
    let interactive_terminal = stderr.is_terminal();
    let controller = Controller::open_with_protection(
        path.clone(),
        planet,
        state_protection,
        initial_token_output.as_ref(),
        interactive_terminal,
        &mut stderr,
    )?;
    eprintln!(
        "Controller public key (share through a trusted channel): {}",
        controller.public_key_base64().await?
    );
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/public-key", get(public_key))
        .route("/v1/planet", get(planet_manifest))
        .route("/v1/networks", get(list_networks).post(create_network))
        .route("/v1/networks/{id}", delete(delete_network))
        .route(
            "/v1/networks/{id}/authorization",
            get(network_authorization),
        )
        .route(
            "/v1/networks/{id}/policy",
            get(network_policy).post(update_network_policy),
        )
        .route("/v1/networks/{id}/enrollment-tokens", post(create_token))
        .route("/v1/networks/{id}/members", get(list_members))
        .route(
            "/v1/networks/{id}/members/{device_id}",
            delete(remove_member),
        )
        .route(
            "/v1/networks/{id}/members/{device_id}/allowed-routes",
            post(authorize_member_routes),
        )
        .route("/v1/enroll", post(enroll))
        .route("/v1/membership/refresh", post(refresh_membership))
        .with_state(Arc::new(controller));
    println!("State file: {}", path.display());
    if let Some(tls) = tls {
        println!("MeshLake controller listening on https://{}", cli.bind);
        axum_server::bind_rustls(cli.bind, tls)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(cli.bind).await?;
        println!("MeshLake controller listening on http://{}", cli.bind);
        if cli.allow_insecure_public_http && !cli.bind.ip().is_loopback() {
            eprintln!(
                "WARNING: MeshLake controller is serving plaintext HTTP on a non-loopback address"
            );
        }
        axum::serve(listener, app).await?;
    }
    Ok(())
}

fn install_rustls_crypto_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    // MeshLake standardizes on Ring. Installing it explicitly avoids Rustls'
    // ambiguous-provider panic when dependencies enable another provider.
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default();
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        anyhow::bail!("cannot install the Rustls Ring crypto provider");
    }
    Ok(())
}

async fn load_controller_tls_configuration(
    tls_files: Option<(PathBuf, PathBuf)>,
) -> Result<Option<axum_server::tls_rustls::RustlsConfig>> {
    let Some((certificate, private_key)) = tls_files else {
        return Ok(None);
    };
    Ok(Some(
        axum_server::tls_rustls::RustlsConfig::from_pem_file(
            certificate.clone(),
            private_key.clone(),
        )
        .await
        .with_context(|| {
            format!(
                "cannot load TLS certificate {} and private key {}",
                certificate.display(),
                private_key.display()
            )
        })?,
    ))
}

fn controller_tls_configuration(cli: &Cli) -> Result<Option<(PathBuf, PathBuf)>> {
    let tls = match (&cli.tls_certificate, &cli.tls_private_key) {
        (Some(certificate), Some(private_key)) => Some((certificate.clone(), private_key.clone())),
        (None, None) => None,
        _ => anyhow::bail!(
            "--tls-certificate and --tls-private-key must always be provided together"
        ),
    };
    if cli.allow_insecure_public_http && (tls.is_some() || cli.tls_client_ca_certificate.is_some())
    {
        anyhow::bail!(
            "--allow-insecure-public-http cannot be combined with TLS certificate options"
        );
    }
    if tls.is_none() && !cli.bind.ip().is_loopback() && !cli.allow_insecure_public_http {
        anyhow::bail!(
            "refusing plaintext controller HTTP on non-loopback {}; configure --tls-certificate and --tls-private-key, bind to loopback behind an HTTPS reverse proxy, or explicitly use --allow-insecure-public-http for isolated development",
            cli.bind
        );
    }
    Ok(tls)
}

fn validate_controller_url(value: &str, allow_insecure_public_http: bool) -> Result<String> {
    let value = value.trim();
    let Some((raw_scheme, authority_and_path)) = value.split_once("://") else {
        anyhow::bail!("--planet-controller-url must start with http:// or https://");
    };
    let raw_authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if !matches!(raw_scheme.to_ascii_lowercase().as_str(), "http" | "https")
        || authority_and_path.is_empty()
        || authority_and_path.starts_with('/')
        || value.contains('\\')
        || raw_authority.contains('@')
    {
        anyhow::bail!("--planet-controller-url must include a valid HTTP authority");
    }
    let mut parsed = Url::parse(value).context("--planet-controller-url is not a valid URL")?;
    if parsed.host_str().is_none() || !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("--planet-controller-url must be an http:// or https:// URL with a host");
    }
    if parsed.username() != "" || parsed.password().is_some() {
        anyhow::bail!("--planet-controller-url must not contain embedded credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!("--planet-controller-url must not contain a query or fragment");
    }
    if parsed.path() != "/" {
        anyhow::bail!("--planet-controller-url must not contain a path");
    }
    if parsed.scheme() != "https" && !allow_insecure_public_http {
        anyhow::bail!(
            "--planet-controller-url must use https:// by default; plain http:// is only available with --allow-insecure-public-http for isolated development"
        );
    }
    parsed.set_path("");
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn load_tls_client_ca(path: Option<&FsPath>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = fs::read(path)
        .with_context(|| format!("cannot read client CA certificate {}", path.display()))?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        anyhow::bail!("client CA certificate must contain between 1 byte and 64 KiB");
    }
    let pem = String::from_utf8(bytes).context("client CA certificate is not UTF-8 PEM")?;
    let mut reader = BufReader::new(pem.as_bytes());
    let items = rustls_pemfile::read_all(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("client CA certificate is not valid PEM")?;
    let mut certificate_count = 0_usize;
    let mut roots = rustls::RootCertStore::empty();
    for item in items {
        match item {
            rustls_pemfile::Item::X509Certificate(certificate) => {
                roots
                    .add(certificate)
                    .context("client CA certificate contains invalid X.509 data")?;
                certificate_count += 1;
            }
            _ => anyhow::bail!(
                "client CA certificate bundle may contain only PEM CERTIFICATE blocks"
            ),
        }
    }
    if certificate_count == 0 {
        anyhow::bail!("client CA certificate does not contain a valid PEM certificate block");
    }
    Ok(Some(pem))
}

fn parse_planet_root(value: &str) -> Result<PlanetRoot, String> {
    let (public_key, endpoint) = value
        .rsplit_once('@')
        .ok_or_else(|| "root must use BASE64_PUBLIC_KEY@IP:PORT format".to_string())?;
    let public_key = STANDARD
        .decode(public_key.trim())
        .map_err(|_| "root public key is not valid Base64".to_string())?;
    if public_key.len() != 32 {
        return Err("root public key must contain exactly 32 bytes".into());
    }
    let endpoint = endpoint
        .parse::<SocketAddr>()
        .map_err(|_| "root endpoint must be a numeric IP:PORT socket address".to_string())?;
    Ok(PlanetRoot {
        public_key,
        endpoints: vec![endpoint],
        priority: 0,
        identity: None,
    })
}

fn parse_planet_relay_identity(value: &str) -> Result<PlanetRelay, String> {
    let (identity, endpoint) = parse_service_identity_descriptor(value)?;
    Ok(PlanetRelay {
        endpoint,
        priority: 0,
        identity: Some(identity),
    })
}

fn parse_planet_root_identity(value: &str) -> Result<PlanetRoot, String> {
    let (identity, endpoint) = parse_service_identity_descriptor(value)?;
    Ok(PlanetRoot {
        public_key: identity.current_public_key.clone(),
        endpoints: vec![endpoint],
        priority: 0,
        identity: Some(identity),
    })
}

fn parse_service_identity_descriptor(
    value: &str,
) -> Result<(ServiceIdentityPolicy, SocketAddr), String> {
    let parts = value.split('@').collect::<Vec<_>>();
    if !matches!(parts.len(), 3 | 4 | 6) {
        return Err("service identity must use UUID@CURRENT_KEY@IP:PORT, UUID@CURRENT_KEY@REVOKED_KEY@IP:PORT, or UUID@CURRENT_KEY@NEXT_KEY@NOT_BEFORE@NOT_AFTER@IP:PORT".into());
    }
    let service_id = parts[0]
        .parse::<Uuid>()
        .map_err(|_| "service identity UUID is invalid".to_string())?;
    let current_public_key = decode_service_public_key(parts[1])?;
    let endpoint = parts[parts.len() - 1]
        .parse::<SocketAddr>()
        .map_err(|_| "service endpoint must be a numeric IP:PORT socket address".to_string())?;
    let (next_public_key, not_before, not_after, revoked_public_keys) = if parts.len() == 6 {
        (
            Some(decode_service_public_key(parts[2])?),
            Some(
                parts[3]
                    .parse::<u64>()
                    .map_err(|_| "rotation NOT_BEFORE must be Unix seconds".to_string())?,
            ),
            Some(
                parts[4]
                    .parse::<u64>()
                    .map_err(|_| "rotation NOT_AFTER must be Unix seconds".to_string())?,
            ),
            Vec::new(),
        )
    } else if parts.len() == 4 {
        (None, None, None, vec![decode_service_public_key(parts[2])?])
    } else {
        (None, None, None, Vec::new())
    };
    let identity = ServiceIdentityPolicy {
        service_id,
        current_public_key,
        next_public_key,
        transition_not_before_unix_seconds: not_before,
        transition_not_after_unix_seconds: not_after,
        revoked_public_keys,
    };
    identity
        .required_public_keys(now())
        .map_err(|error| error.to_string())?;
    Ok((identity, endpoint))
}

fn decode_service_public_key(encoded: &str) -> Result<Vec<u8>, String> {
    let key = STANDARD
        .decode(encoded.trim())
        .map_err(|_| "service public key is not valid Base64".to_string())?;
    if key.len() != 32 {
        return Err("service public key must contain exactly 32 bytes".into());
    }
    Ok(key)
}

fn default_state_path() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().expect("current directory unavailable"))
        .join("MeshLake")
        .join("controller.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::RelayPolicy;
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path =
                env::temp_dir().join(format!("meshlake-controller-{label}-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_cli(bind: SocketAddr) -> Cli {
        Cli {
            bind,
            tls_certificate: None,
            tls_private_key: None,
            tls_client_ca_certificate: None,
            allow_insecure_public_http: false,
            state_file: None,
            initial_admin_token_file: None,
            claim_initial_admin_token: false,
            state_key_file: None,
            state_key_systemd_credential: None,
            allow_plaintext_state_migration: false,
            planet_controller_url: None,
            planet_relay_endpoints: Vec::new(),
            planet_relay_identities: Vec::new(),
            planet_roots: Vec::new(),
            planet_root_identities: Vec::new(),
            planet_stun_servers: Vec::new(),
            command: None,
        }
    }

    fn test_state(schema_version: u32) -> ControllerState {
        ControllerState {
            schema_version,
            signing_key: vec![7; 32],
            admin_token: "preserved-administrator-token".into(),
            networks: HashMap::new(),
            enrollment_tokens: HashMap::new(),
        }
    }

    fn backup_path(path: &FsPath) -> PathBuf {
        let mut backup = path.as_os_str().to_os_string();
        backup.push(".bak");
        backup.into()
    }

    fn generated_certificate(subject_alt_name: &str) -> (String, String) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![subject_alt_name.to_owned()]).unwrap();
        (cert.pem(), signing_key.serialize_pem())
    }

    #[test]
    fn fresh_controller_requires_a_safe_initial_token_destination() {
        let directory = TestDirectory::new("initial-token-required");
        let path = directory.file("controller.json");
        let mut output = Vec::new();
        let error = match Controller::open(path.clone(), None, None, false, &mut output) {
            Ok(_) => panic!("controller unexpectedly initialized without a token destination"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("requires --claim-initial-admin-token"));
        assert!(output.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn non_tty_initial_token_claim_fails_without_disclosure_or_state_creation() {
        let directory = TestDirectory::new("initial-token-non-tty");
        let path = directory.file("controller.json");
        let mut output = Vec::new();
        let error = match Controller::open(
            path.clone(),
            None,
            Some(&InitialAdminTokenOutput::Interactive),
            false,
            &mut output,
        ) {
            Ok(_) => panic!("non-TTY token claim unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("requires an attached interactive terminal"));
        assert!(output.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn restricted_initial_token_file_matches_state_and_refuses_overwrite() {
        let directory = TestDirectory::new("initial-token-file");
        let path = directory.file("controller.json");
        let token_path = directory.file("administrator.token");
        let destination = InitialAdminTokenOutput::RestrictedFile(token_path.clone());
        let controller = Controller::open(
            path.clone(),
            None,
            Some(&destination),
            false,
            &mut io::sink(),
        )
        .unwrap();
        drop(controller);

        let token = String::from_utf8(fs::read(&token_path).unwrap()).unwrap();
        let decoded: meshlake_core::DecodedState<ControllerState> = decode_protected_state(
            &fs::read(&path).unwrap(),
            CONTROLLER_STATE_PROTECTION_PURPOSE,
        )
        .unwrap();
        assert_eq!(decoded.value.admin_token, token.trim_end());
        assert!(!format!("{:?}", decoded.value).contains(token.trim_end()));

        let second_state = directory.file("second-controller.json");
        let error = match Controller::open(
            second_state.clone(),
            None,
            Some(&destination),
            false,
            &mut io::sink(),
        ) {
            Ok(_) => panic!("initial token file was unexpectedly overwritten"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("cannot create restricted initial administrator-token file"));
        assert!(!error.to_string().contains(token.trim_end()));
        assert!(!second_state.exists());
    }

    #[test]
    fn state_write_failure_removes_the_new_initial_token_file_without_disclosure() {
        let directory = TestDirectory::new("initial-token-state-write-failure");
        let token_path = directory.file("administrator.token");
        let destination = InitialAdminTokenOutput::RestrictedFile(token_path.clone());
        let mut generated_token = None;
        let error =
            initialize_new_controller_state(&destination, false, &mut io::sink(), |state| {
                generated_token = Some(state.admin_token.clone());
                anyhow::bail!("injected state write failure")
            })
            .expect_err("injected state write failure must abort initialization");

        let generated_token = generated_token.expect("the test must observe the generated token");
        assert!(!token_path.exists());
        assert!(error
            .to_string()
            .contains("newly created initial administrator-token file was removed"));
        assert!(!error.to_string().contains(&generated_token));
    }

    #[test]
    fn initial_token_file_cannot_alias_controller_state_or_be_reused_on_existing_state() {
        let directory = TestDirectory::new("initial-token-reserved-path");
        let path = directory.file("controller.json");
        let destination = InitialAdminTokenOutput::RestrictedFile(path.clone());
        let error = match Controller::open(
            path.clone(),
            None,
            Some(&destination),
            false,
            &mut io::sink(),
        ) {
            Ok(_) => panic!("initial token unexpectedly overwrote the controller state path"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("reserved controller state path"));
        assert!(!path.exists());

        let token_path = directory.file("administrator.token");
        let destination = InitialAdminTokenOutput::RestrictedFile(token_path);
        let controller = Controller::open(
            path.clone(),
            None,
            Some(&destination),
            false,
            &mut io::sink(),
        )
        .unwrap();
        drop(controller);
        let error = match Controller::open(
            path,
            None,
            Some(&InitialAdminTokenOutput::Interactive),
            true,
            &mut io::sink(),
        ) {
            Ok(_) => panic!("existing state unexpectedly accepted bootstrap output options"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("valid only when creating"));
    }

    async fn start_https_server(
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> (
        TestDirectory,
        SocketAddr,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        install_rustls_crypto_provider().unwrap();
        let directory = TestDirectory::new("https");
        let certificate = directory.file("certificate.pem");
        let private_key = directory.file("private-key.pem");
        fs::write(&certificate, certificate_pem).unwrap();
        fs::write(&private_key, private_key_pem).unwrap();
        let tls = load_controller_tls_configuration(Some((certificate, private_key)))
            .await
            .unwrap()
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let handle = axum_server::Handle::<SocketAddr>::new();
        let server = axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .handle(handle.clone())
            .serve(
                Router::new()
                    .route("/health", get(health))
                    .into_make_service(),
            );
        let task = tokio::spawn(server);
        let address = tokio::time::timeout(Duration::from_secs(5), handle.listening())
            .await
            .expect("HTTPS listener did not start in time")
            .expect("HTTPS listener failed to bind");
        (directory, address, task)
    }

    async fn https_get_with_private_ca(
        address: SocketAddr,
        server_name: &str,
        certificate_pem: &str,
    ) -> Result<String> {
        let server_name = server_name.to_owned();
        let certificate_pem = certificate_pem.to_owned();
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || -> Result<String> {
                use rustls::pki_types::ServerName;
                use std::io::{Read, Write};

                let mut reader = BufReader::new(certificate_pem.as_bytes());
                let certificates = rustls_pemfile::certs(&mut reader)
                    .collect::<std::io::Result<Vec<_>>>()
                    .context("test CA is not valid PEM")?;
                let mut roots = rustls::RootCertStore::empty();
                for certificate in certificates {
                    roots
                        .add(certificate)
                        .context("test CA is not valid X.509")?;
                }
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let server_name_value = ServerName::try_from(server_name.clone())
                    .context("test server name is invalid")?;
                let connection =
                    rustls::ClientConnection::new(Arc::new(config), server_name_value)?;
                let socket =
                    std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                let mut stream = rustls::StreamOwned::new(connection, socket);
                write!(
                    stream,
                    "GET /health HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n"
                )?;
                stream.flush()?;

                let mut response = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => response.extend_from_slice(&buffer[..read]),
                        Err(error)
                            if !response.is_empty()
                                && matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                        {
                            break;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                String::from_utf8(response).context("HTTPS response is not UTF-8")
            }),
        )
        .await
        .context("HTTPS smoke-test request timed out")?
        .context("HTTPS smoke-test worker panicked")?
    }

    async fn stop_https_server(task: tokio::task::JoinHandle<std::io::Result<()>>) {
        task.abort();
        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("aborted HTTPS server task did not stop within five seconds");
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn allocation_skips_assigned_addresses() {
        let network = VirtualNetwork {
            id: NetworkId(Uuid::nil()),
            name: "test".into(),
            ipv4_prefix: "100.64.0.0/29".into(),
            ipv6_prefix: None,
            relay_policy: RelayPolicy::Preferred,
        };
        let device = DeviceId(Uuid::new_v4());
        let claims = MembershipClaims {
            network_id: network.id,
            device_id: device,
            device_public_key: vec![],
            assigned_addresses: vec!["100.64.0.1".parse().unwrap()],
            allowed_routes: vec![],
            issued_at_unix_seconds: 0,
            expires_at_unix_seconds: None,
        };
        assert_eq!(
            allocate_ipv4_address(&network, &HashMap::from([(device, claims)])).unwrap(),
            "100.64.0.2".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn dual_stack_allocation_preserves_existing_ipv4_and_adds_ipv6() {
        let network = VirtualNetwork {
            id: NetworkId(Uuid::nil()),
            name: "dual-stack".into(),
            ipv4_prefix: "100.64.1.0/29".into(),
            ipv6_prefix: Some("fd42:4d4c::/126".into()),
            relay_policy: RelayPolicy::Preferred,
        };
        let existing_device = DeviceId(Uuid::from_u128(1));
        let new_device = DeviceId(Uuid::from_u128(2));
        let existing = MembershipClaims {
            network_id: network.id,
            device_id: existing_device,
            device_public_key: vec![],
            assigned_addresses: vec!["100.64.1.1".parse().unwrap()],
            allowed_routes: vec![],
            issued_at_unix_seconds: 0,
            expires_at_unix_seconds: None,
        };
        let mut members = HashMap::from([(existing_device, existing)]);
        let upgraded = assigned_addresses_for_device(&network, &members, existing_device).unwrap();
        assert_eq!(
            upgraded,
            vec![
                "100.64.1.1".parse::<IpAddr>().unwrap(),
                "fd42:4d4c::1".parse::<IpAddr>().unwrap()
            ]
        );
        members
            .get_mut(&existing_device)
            .unwrap()
            .assigned_addresses = upgraded;
        assert_eq!(
            assigned_addresses_for_device(&network, &members, new_device).unwrap(),
            vec![
                "100.64.1.2".parse::<IpAddr>().unwrap(),
                "fd42:4d4c::2".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn invitation_carries_planet_bootstrap_information() {
        let tls_ca = "-----BEGIN CERTIFICATE-----\nprivate-ca\n-----END CERTIFICATE-----\n";
        let link = make_invite_link(
            "https://planet.example.com/",
            Uuid::from_u128(1),
            "single-use-token",
            "public-key",
            Some(tls_ca),
        );
        let link = Url::parse(&link).unwrap();
        assert_eq!(link.scheme(), "meshlake");
        assert_eq!(link.host_str(), Some("join"));
        let parameters = link.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(
            parameters.get("controller").map(|value| value.as_ref()),
            Some("https://planet.example.com")
        );
        assert_eq!(
            parameters.get("planet").map(|value| value.as_ref()),
            Some("https://planet.example.com/v1/planet")
        );
        assert_eq!(
            parameters
                .get("tls_ca")
                .and_then(|value| STANDARD.decode(value.as_bytes()).ok()),
            Some(tls_ca.as_bytes().to_vec())
        );
    }

    #[test]
    fn tls_arguments_must_be_complete_and_exclude_the_dangerous_http_switch() {
        let bind = "127.0.0.1:51822".parse().unwrap();
        let mut cli = test_cli(bind);
        assert!(controller_tls_configuration(&cli).unwrap().is_none());

        cli.tls_certificate = Some("certificate.pem".into());
        assert!(controller_tls_configuration(&cli).is_err());

        cli.tls_certificate = None;
        cli.tls_private_key = Some("private-key.pem".into());
        assert!(controller_tls_configuration(&cli).is_err());

        cli.tls_certificate = Some("certificate.pem".into());
        assert!(controller_tls_configuration(&cli).unwrap().is_some());

        cli.allow_insecure_public_http = true;
        assert!(controller_tls_configuration(&cli).is_err());

        cli.tls_certificate = None;
        cli.tls_private_key = None;
        cli.tls_client_ca_certificate = Some("ca.pem".into());
        assert!(controller_tls_configuration(&cli).is_err());
    }

    #[test]
    fn non_loopback_plain_http_requires_the_explicit_development_switch() {
        let mut cli = test_cli("0.0.0.0:51822".parse().unwrap());
        assert!(controller_tls_configuration(&cli).is_err());
        cli.allow_insecure_public_http = true;
        assert!(controller_tls_configuration(&cli).unwrap().is_none());
    }

    #[test]
    fn published_controller_url_is_https_by_default() {
        assert_eq!(
            validate_controller_url(" HTTPS://PLANET.EXAMPLE.COM:443/ ", false).unwrap(),
            "https://planet.example.com"
        );
        assert!(validate_controller_url("http://203.0.113.10:51822", false).is_err());
        assert_eq!(
            validate_controller_url("http://192.0.2.10:51822/", true).unwrap(),
            "http://192.0.2.10:51822"
        );
    }

    #[test]
    fn published_controller_url_rejects_credentials_query_and_fragment() {
        for value in [
            "https://user:password@planet.example.com",
            "https://@planet.example.com",
            "https://planet.example.com\\",
            "https://planet.example.com?token=secret",
            "https://planet.example.com#fragment",
            "https://planet.example.com/controller",
            "ftp://planet.example.com",
            "https:///missing-host",
        ] {
            assert!(
                validate_controller_url(value, false).is_err(),
                "unexpectedly accepted {value}"
            );
        }
    }

    #[test]
    fn client_ca_loader_accepts_a_real_bundle_and_rejects_fake_or_secret_pem() {
        let directory = TestDirectory::new("client-ca");
        let (first_certificate, first_private_key) = generated_certificate("first.example");
        let (second_certificate, _) = generated_certificate("second.example");
        let valid_path = directory.file("bundle.pem");
        let bundle = format!("{first_certificate}{second_certificate}");
        fs::write(&valid_path, &bundle).unwrap();
        assert_eq!(load_tls_client_ca(Some(&valid_path)).unwrap(), Some(bundle));

        let fake_path = directory.file("fake.pem");
        fs::write(
            &fake_path,
            "-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(load_tls_client_ca(Some(&fake_path)).is_err());

        let secret_path = directory.file("contains-private-key.pem");
        fs::write(
            &secret_path,
            format!("{first_certificate}{first_private_key}"),
        )
        .unwrap();
        assert!(load_tls_client_ca(Some(&secret_path)).is_err());
    }

    #[tokio::test]
    async fn native_tls_configuration_rejects_a_mismatched_key() {
        install_rustls_crypto_provider().unwrap();
        let directory = TestDirectory::new("mismatched-tls");
        let (certificate, _) = generated_certificate("127.0.0.1");
        let (_, wrong_private_key) = generated_certificate("127.0.0.1");
        let certificate_path = directory.file("certificate.pem");
        let private_key_path = directory.file("private-key.pem");
        fs::write(&certificate_path, certificate).unwrap();
        fs::write(&private_key_path, wrong_private_key).unwrap();
        assert!(
            load_controller_tls_configuration(Some((certificate_path, private_key_path)))
                .await
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_https_uses_the_selected_provider_and_private_ca() {
        let (certificate, private_key) = generated_certificate("127.0.0.1");
        let (_directory, address, task) = start_https_server(&certificate, &private_key).await;
        let response = https_get_with_private_ca(address, "127.0.0.1", &certificate)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("MeshLake controller is running"));

        let (wrong_certificate, _) = generated_certificate("127.0.0.1");
        assert!(
            https_get_with_private_ca(address, "127.0.0.1", &wrong_certificate)
                .await
                .is_err()
        );

        stop_https_server(task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_https_rejects_a_certificate_with_the_wrong_san() {
        let (certificate, private_key) = generated_certificate("localhost");
        let (_directory, address, task) = start_https_server(&certificate, &private_key).await;
        assert!(
            https_get_with_private_ca(address, "127.0.0.1", &certificate)
                .await
                .is_err()
        );
        stop_https_server(task).await;
    }

    #[cfg(windows)]
    #[test]
    fn plaintext_controller_state_is_dpapi_protected_without_rotating_credentials() {
        let directory = TestDirectory::new("legacy-state");
        let path = directory.file("controller.json");
        let original = test_state(2);
        fs::write(&path, serde_json::to_vec_pretty(&original).unwrap()).unwrap();

        let controller =
            Controller::open(path.clone(), None, None, false, &mut io::sink()).unwrap();
        let bytes = fs::read(&path).unwrap();
        let decoded: meshlake_core::DecodedState<ControllerState> =
            decode_protected_state(&bytes, CONTROLLER_STATE_PROTECTION_PURPOSE).unwrap();
        assert_eq!(decoded.value.schema_version, 2);
        assert_eq!(decoded.value.signing_key, original.signing_key);
        assert_eq!(decoded.value.admin_token, original.admin_token);
        assert!(!String::from_utf8_lossy(&bytes).contains("preserved-administrator-token"));
        drop(controller);
    }

    #[cfg(windows)]
    #[test]
    fn controller_open_removes_plaintext_backup_after_validating_protected_primary_state() {
        let directory = TestDirectory::new("stale-plaintext-backup");
        let path = directory.file("controller.json");
        let backup = backup_path(&path);
        let original = test_state(2);
        write_state(&path, &original).unwrap();
        fs::write(&backup, serde_json::to_vec_pretty(&original).unwrap()).unwrap();
        assert!(String::from_utf8_lossy(&fs::read(&backup).unwrap())
            .contains("preserved-administrator-token"));

        let controller =
            Controller::open(path.clone(), None, None, false, &mut io::sink()).unwrap();
        assert!(!backup.exists());
        let decoded: meshlake_core::DecodedState<ControllerState> = decode_protected_state(
            &fs::read(&path).unwrap(),
            CONTROLLER_STATE_PROTECTION_PURPOSE,
        )
        .unwrap();
        assert_eq!(decoded.value.signing_key, original.signing_key);
        assert_eq!(decoded.value.admin_token, original.admin_token);

        drop(controller);
    }

    #[cfg(windows)]
    #[test]
    fn controller_open_keeps_backup_when_primary_state_fails_validation() {
        let directory = TestDirectory::new("invalid-primary-keeps-backup");
        let path = directory.file("controller.json");
        let backup = backup_path(&path);
        let mut invalid = test_state(2);
        invalid.signing_key.clear();
        write_state(&path, &invalid).unwrap();
        let recovery = test_state(2);
        fs::write(&backup, serde_json::to_vec_pretty(&recovery).unwrap()).unwrap();

        let error = match Controller::open(path.clone(), None, None, false, &mut io::sink()) {
            Ok(_) => panic!("invalid controller state unexpectedly opened"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("controller signing key is invalid"));
        assert!(backup.exists());
        assert!(String::from_utf8_lossy(&fs::read(&backup).unwrap())
            .contains("preserved-administrator-token"));
    }

    #[test]
    fn legacy_controller_schema_migrates_without_rotating_credentials() {
        let directory = TestDirectory::new("legacy-schema");
        let path = directory.file("controller.json");
        let original = test_state(1);
        fs::write(&path, serde_json::to_vec_pretty(&original).unwrap()).unwrap();

        let controller =
            Controller::open(path.clone(), None, None, false, &mut io::sink()).unwrap();
        let bytes = fs::read(&path).unwrap();
        let decoded: meshlake_core::DecodedState<ControllerState> =
            decode_protected_state(&bytes, CONTROLLER_STATE_PROTECTION_PURPOSE).unwrap();
        assert_eq!(decoded.value.schema_version, 2);
        assert_eq!(decoded.value.signing_key, original.signing_key);
        assert_eq!(decoded.value.admin_token, original.admin_token);
        drop(controller);
    }

    #[test]
    fn interrupted_state_replacement_recovers_the_backup() {
        let directory = TestDirectory::new("state-recovery");
        let path = directory.file("controller.json");
        let backup = backup_path(&path);
        let original = test_state(2);
        fs::write(&backup, serde_json::to_vec_pretty(&original).unwrap()).unwrap();

        let controller =
            Controller::open(path.clone(), None, None, false, &mut io::sink()).unwrap();
        assert!(path.exists());
        assert!(!backup.exists());
        let bytes = fs::read(&path).unwrap();
        let decoded: meshlake_core::DecodedState<ControllerState> =
            decode_protected_state(&bytes, CONTROLLER_STATE_PROTECTION_PURPOSE).unwrap();
        assert_eq!(decoded.value.admin_token, original.admin_token);
        drop(controller);
    }

    #[test]
    fn signed_policy_embeds_gateway_route_authorization() {
        let signing_key = SigningKey::from_bytes(&[61; 32]);
        let network_id = NetworkId(Uuid::from_u128(61));
        let gateway = DeviceId(Uuid::from_u128(62));
        let certificate_id = Uuid::from_u128(63);
        let managed = ManagedNetwork {
            network: VirtualNetwork {
                id: network_id,
                name: "policy-test".into(),
                ipv4_prefix: "100.64.61.0/24".into(),
                ipv6_prefix: Some("fd42:4d4c:61::/64".into()),
                relay_policy: RelayPolicy::Preferred,
            },
            members: HashMap::from([(
                gateway,
                MembershipClaims {
                    network_id,
                    device_id: gateway,
                    device_public_key: vec![6; 32],
                    assigned_addresses: vec!["100.64.61.2".parse().unwrap()],
                    allowed_routes: vec!["100.64.61.0/24".into(), "10.61.0.0/16".into()],
                    issued_at_unix_seconds: now(),
                    expires_at_unix_seconds: Some(now() + 86_400),
                },
            )]),
            network_key: vec![7; 32],
            network_key_epoch: 1,
            authorization_epoch: 1,
            member_certificate_ids: HashMap::from([(gateway, certificate_id)]),
            revoked_certificate_ids: HashMap::new(),
            policy_epoch: 2,
            policy: ManagedPolicy {
                routes: vec![ManagedPolicyRoute {
                    prefix: "10.61.0.0/16".into(),
                    gateway_device_id: gateway,
                }],
                exit_nodes: vec![ManagedExitNode {
                    gateway_device_id: gateway,
                    supports_ipv4: true,
                    supports_ipv6: true,
                }],
                dns: DnsPolicy {
                    servers: vec!["10.61.0.53".parse().unwrap()],
                    search_domains: vec!["corp.example".into()],
                },
            },
        };
        let policy = sign_policy(&managed, &signing_key).unwrap();
        let authorization = sign_authorization(&managed, &signing_key).unwrap();
        assert_eq!(
            policy.verify_for_network(
                network_id,
                &signing_key.verifying_key().to_bytes(),
                &authorization,
                now(),
                Some(1),
            ),
            Ok(())
        );
        assert!(policy.routes[0]
            .gateway_certificate
            .claims
            .allowed_routes
            .contains(&"10.61.0.0/16".into()));
        assert_eq!(policy.exit_nodes.len(), 1);
        assert_eq!(
            policy.exit_nodes[0].gateway_certificate.claims.device_id,
            gateway
        );
        assert!(policy.exit_nodes[0].supports_ipv4);
        assert!(policy.exit_nodes[0].supports_ipv6);
    }

    #[test]
    fn policy_cannot_implicitly_expand_gateway_allowed_routes() {
        let signing_key = SigningKey::from_bytes(&[64; 32]);
        let network_id = NetworkId(Uuid::from_u128(64));
        let gateway = DeviceId(Uuid::from_u128(65));
        let managed = ManagedNetwork {
            network: VirtualNetwork {
                id: network_id,
                name: "no-implicit-expansion".into(),
                ipv4_prefix: "100.64.64.0/24".into(),
                ipv6_prefix: None,
                relay_policy: RelayPolicy::Preferred,
            },
            members: HashMap::from([(
                gateway,
                MembershipClaims {
                    network_id,
                    device_id: gateway,
                    device_public_key: vec![6; 32],
                    assigned_addresses: vec!["100.64.64.2".parse().unwrap()],
                    allowed_routes: vec!["100.64.64.0/24".into()],
                    issued_at_unix_seconds: now(),
                    expires_at_unix_seconds: Some(now() + 86_400),
                },
            )]),
            network_key: vec![7; 32],
            network_key_epoch: 1,
            authorization_epoch: 1,
            member_certificate_ids: HashMap::from([(gateway, Uuid::from_u128(66))]),
            revoked_certificate_ids: HashMap::new(),
            policy_epoch: 2,
            policy: ManagedPolicy {
                routes: vec![ManagedPolicyRoute {
                    prefix: "10.64.0.0/16".into(),
                    gateway_device_id: gateway,
                }],
                exit_nodes: vec![],
                dns: DnsPolicy::default(),
            },
        };
        assert!(sign_policy(&managed, &signing_key)
            .unwrap_err()
            .to_string()
            .contains("not authorized"));
        assert_eq!(
            managed.members[&gateway].allowed_routes,
            vec!["100.64.64.0/24"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_controller_state_is_always_restricted_to_mode_0600() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = TestDirectory::new("state-permissions");
        let path = directory.file("controller.json");
        fs::write(&path, serde_json::to_vec_pretty(&test_state(2)).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let controller =
            Controller::open(path.clone(), None, None, false, &mut io::sink()).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        drop(controller);
    }

    #[cfg(unix)]
    #[test]
    fn linux_provider_migrates_controller_plaintext_without_rotating_credentials() {
        use meshlake_core::{
            create_restricted_secret_file, decode_protected_state_with, StateKeyProvider,
        };

        let directory = TestDirectory::new("linux-provider-migration");
        let state_directory = directory.path.join("state");
        let key_directory = directory.path.join("keys");
        fs::create_dir_all(&state_directory).unwrap();
        fs::create_dir_all(&key_directory).unwrap();
        let path = state_directory.join("controller.json");
        let key_path = key_directory.join("state.key");
        let original = test_state(CONTROLLER_STATE_SCHEMA_VERSION);
        fs::write(&path, serde_json::to_vec_pretty(&original).unwrap()).unwrap();
        create_restricted_secret_file(&key_path, &[11; 32]).unwrap();

        let protection = StateProtection::from_provider(
            &path,
            StateKeyProvider::RestrictedFile(key_path.clone()),
        )
        .unwrap();
        let error = match Controller::open_with_protection(
            path.clone(),
            None,
            protection,
            None,
            false,
            &mut io::sink(),
        ) {
            Ok(_) => panic!("provider mode unexpectedly accepted plaintext"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("allow-plaintext-state-migration"));
        assert!(String::from_utf8_lossy(&fs::read(&path).unwrap()).contains(&original.admin_token));

        let protection = StateProtection::from_provider_with_plaintext_migration(
            &path,
            StateKeyProvider::RestrictedFile(key_path.clone()),
            true,
        )
        .unwrap();
        let controller = Controller::open_with_protection(
            path.clone(),
            None,
            protection,
            None,
            false,
            &mut io::sink(),
        )
        .unwrap();
        drop(controller);

        let protection = StateProtection::from_provider(
            &path,
            StateKeyProvider::RestrictedFile(key_path.clone()),
        )
        .unwrap();
        let controller = Controller::open_with_protection(
            path.clone(),
            None,
            protection,
            None,
            false,
            &mut io::sink(),
        )
        .expect("encrypted state must reopen without migration authorization");
        drop(controller);

        let bytes = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(&original.admin_token));
        assert!(matches!(
            decode_protected_state::<ControllerState>(&bytes, CONTROLLER_STATE_PROTECTION_PURPOSE),
            Err(meshlake_core::StateProtectionError::MissingMasterKey)
        ));
        let protection =
            StateProtection::from_provider(&path, StateKeyProvider::RestrictedFile(key_path))
                .unwrap();
        let decoded: meshlake_core::DecodedState<ControllerState> =
            decode_protected_state_with(&bytes, CONTROLLER_STATE_PROTECTION_PURPOSE, &protection)
                .unwrap();
        assert_eq!(decoded.value.signing_key, original.signing_key);
        assert_eq!(decoded.value.admin_token, original.admin_token);
    }
}
