//! Self-hostable MeshLake membership controller.
//! It signs authorization documents but never handles virtual-network packets.

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use ed25519_dalek::SigningKey;
use ipnet::{Ipv4Net, Ipv6Net};
use meshlake_core::{
    cleanup_stale_state_backup, decode_protected_state, recover_protected_state_file,
    restrict_state_file_permissions, write_protected_state_file, AuthorizedMembership, DeviceId,
    EnrollmentResponse, MembershipCertificate, MembershipClaims, MembershipRefreshRequest,
    MembershipRefreshResponse, NetworkAuthorizationManifest, NetworkId, NetworkKey, PlanetManifest,
    PlanetRelay, PlanetRoot, StateFileLock, UpsertNetworkRequest, VirtualNetwork,
    CONTROLLER_STATE_PROTECTION_PURPOSE,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

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
    /// Public controller URL published through the signed Planet manifest.
    #[arg(long)]
    planet_controller_url: Option<String>,
    /// Public MeshLake encrypted-UDP relay endpoint. Repeat for failover order.
    #[arg(long = "planet-relay-endpoint")]
    planet_relay_endpoints: Vec<SocketAddr>,
    /// Root descriptor in BASE64_PUBLIC_KEY@IP:PORT form. Repeat for multiple roots.
    #[arg(long = "planet-root", value_parser = parse_planet_root)]
    planet_roots: Vec<PlanetRoot>,
    /// Optional STUN server (`host:port`). Repeat for multiple servers.
    #[arg(long = "planet-stun")]
    planet_stun_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControllerState {
    schema_version: u32,
    signing_key: Vec<u8>,
    admin_token: String,
    networks: HashMap<NetworkId, ManagedNetwork>,
    enrollment_tokens: HashMap<Uuid, EnrollmentToken>,
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

#[derive(Debug, Serialize)]
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

#[derive(Debug, Deserialize)]
struct EnrollmentRequest {
    network_id: NetworkId,
    device_id: DeviceId,
    #[serde(default)]
    device_public_key: Vec<u8>,
    token: String,
}

#[derive(Debug, Clone)]
struct PlanetSettings {
    controller_url: String,
    tls_client_ca_pem: Option<String>,
    roots: Vec<PlanetRoot>,
    relays: Vec<PlanetRelay>,
    stun_servers: Vec<String>,
}

struct Controller {
    path: PathBuf,
    state: RwLock<ControllerState>,
    planet: Option<PlanetSettings>,
    refresh_nonces: Mutex<HashMap<[u8; 16], Instant>>,
    _state_lock: StateFileLock,
}

impl Controller {
    fn open(path: PathBuf, planet: Option<PlanetSettings>) -> Result<(Self, Option<String>)> {
        let state_lock = StateFileLock::acquire(&path)?;
        recover_protected_state_file(&path)?;
        let (mut state, initial_token, mut migrated) = if path.exists() {
            restrict_state_file_permissions(&path)?;
            let bytes =
                fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            let decoded = decode_protected_state(&bytes, CONTROLLER_STATE_PROTECTION_PURPOSE)
                .with_context(|| {
                    format!("invalid or unreadable controller state {}", path.display())
                })?;
            (decoded.value, None, decoded.needs_protection_upgrade)
        } else {
            let mut signing_key = [0_u8; 32];
            getrandom::fill(&mut signing_key).map_err(|error| {
                anyhow::anyhow!("cannot generate controller signing key: {error:?}")
            })?;
            let admin_token = Uuid::new_v4().to_string();
            let state = ControllerState {
                schema_version: 2,
                signing_key: signing_key.to_vec(),
                admin_token: admin_token.clone(),
                networks: HashMap::new(),
                enrollment_tokens: HashMap::new(),
            };
            write_state(&path, &state)?;
            (state, Some(admin_token), false)
        };
        for managed in state.networks.values_mut() {
            if managed.network_key.len() != 32 {
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
            for device_id in managed.members.keys().copied().collect::<Vec<_>>() {
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    managed.member_certificate_ids.entry(device_id)
                {
                    entry.insert(Uuid::new_v4());
                    migrated = true;
                }
            }
        }
        if state.schema_version < 2 {
            state.schema_version = 2;
            migrated = true;
        }
        validate_controller_state(&state)?;
        if migrated {
            write_state(&path, &state)?;
        }
        cleanup_stale_state_backup(&path)?;
        Ok((
            Self {
                path,
                state: RwLock::new(state),
                planet,
                refresh_nonces: Mutex::new(HashMap::new()),
                _state_lock: state_lock,
            },
            initial_token,
        ))
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
            },
        );
        write_state(&self.path, &state).map_err(ApiError::internal)?;
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
        write_state(&self.path, &state).map_err(ApiError::internal)?;
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
        write_state(&self.path, &state).map_err(ApiError::internal)?;
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
        write_state(&self.path, &state).map_err(ApiError::internal)
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
        network.network_key = NetworkKey::generate()
            .map_err(ApiError::internal)?
            .to_bytes()
            .to_vec();
        network.network_key_epoch = network.network_key_epoch.saturating_add(1).max(1);
        network.authorization_epoch = network.authorization_epoch.saturating_add(1).max(1);
        write_state(&self.path, &state).map_err(ApiError::internal)
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
        Ok(Some(PlanetManifest::sign_v2(
            planet.controller_url.clone(),
            planet.roots.clone(),
            planet.relays.clone(),
            planet.stun_servers.clone(),
            now(),
            None,
            &signing_key,
        )?))
    }
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
    signing_key(state)?;
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
    }
    Ok(())
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

fn write_state(path: &FsPath, state: &ControllerState) -> Result<()> {
    write_protected_state_file(path, state, CONTROLLER_STATE_PROTECTION_PURPOSE)
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

async fn refresh_membership(
    State(controller): State<Arc<Controller>>,
    Json(request): Json<MembershipRefreshRequest>,
) -> Result<Json<MembershipRefreshResponse>, ApiError> {
    Ok(Json(controller.refresh_membership(request).await?))
}

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_crypto_provider()?;
    let cli = Cli::parse();
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
    let path = cli.state_file.unwrap_or_else(default_state_path);
    let planet = match (
        cli.planet_controller_url,
        cli.planet_relay_endpoints.is_empty(),
    ) {
        (Some(controller_url), false) => Some(PlanetSettings {
            controller_url: validate_controller_url(
                &controller_url,
                cli.allow_insecure_public_http,
            )?,
            tls_client_ca_pem,
            roots: cli
                .planet_roots
                .into_iter()
                .enumerate()
                .map(|(priority, mut root)| {
                    root.priority = priority.min(u16::MAX as usize) as u16;
                    root
                })
                .collect(),
            relays: cli
                .planet_relay_endpoints
                .into_iter()
                .enumerate()
                .map(|(priority, endpoint)| PlanetRelay {
                    endpoint,
                    priority: priority.min(u16::MAX as usize) as u16,
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
        (None, true) if cli.planet_roots.is_empty() && cli.planet_stun_servers.is_empty() => None,
        _ => anyhow::bail!(
            "--planet-controller-url and at least one --planet-relay-endpoint must be provided together"
        ),
    };
    let (controller, initial_token) = Controller::open(path.clone(), planet)?;
    if let Some(token) = initial_token {
        eprintln!("Initial administrator token (save it now): {token}");
    }
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
        .route("/v1/networks/{id}/enrollment-tokens", post(create_token))
        .route("/v1/networks/{id}/members", get(list_members))
        .route(
            "/v1/networks/{id}/members/{device_id}",
            delete(remove_member),
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
    })
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
            planet_controller_url: None,
            planet_relay_endpoints: Vec::new(),
            planet_roots: Vec::new(),
            planet_stun_servers: Vec::new(),
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

        let (controller, initial_token) = Controller::open(path.clone(), None).unwrap();
        assert!(initial_token.is_none());
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

        let (controller, initial_token) = Controller::open(path.clone(), None).unwrap();
        assert!(initial_token.is_none());
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

        let error = match Controller::open(path.clone(), None) {
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

        let (controller, initial_token) = Controller::open(path.clone(), None).unwrap();
        assert!(initial_token.is_none());
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

        let (controller, initial_token) = Controller::open(path.clone(), None).unwrap();
        assert!(initial_token.is_none());
        assert!(path.exists());
        assert!(!backup.exists());
        let bytes = fs::read(&path).unwrap();
        let decoded: meshlake_core::DecodedState<ControllerState> =
            decode_protected_state(&bytes, CONTROLLER_STATE_PROTECTION_PURPOSE).unwrap();
        assert_eq!(decoded.value.admin_token, original.admin_token);
        drop(controller);
    }

    #[cfg(unix)]
    #[test]
    fn existing_controller_state_is_always_restricted_to_mode_0600() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = TestDirectory::new("state-permissions");
        let path = directory.file("controller.json");
        fs::write(&path, serde_json::to_vec_pretty(&test_state(2)).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let (controller, _) = Controller::open(path.clone(), None).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        drop(controller);
    }
}
