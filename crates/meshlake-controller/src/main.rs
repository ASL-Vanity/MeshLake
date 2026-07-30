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
    AuthorizedMembership, DeviceId, EnrollmentResponse, MembershipCertificate, MembershipClaims,
    MembershipRefreshRequest, MembershipRefreshResponse, NetworkAuthorizationManifest, NetworkId,
    NetworkKey, PlanetManifest, PlanetRelay, PlanetRoot, UpsertNetworkRequest, VirtualNetwork,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
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
    /// Keep the loopback default until a reverse proxy and TLS are configured.
    #[arg(long, default_value = "127.0.0.1:51822")]
    bind: SocketAddr,
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
    roots: Vec<PlanetRoot>,
    relays: Vec<PlanetRelay>,
    stun_servers: Vec<String>,
}

struct Controller {
    path: PathBuf,
    state: RwLock<ControllerState>,
    planet: Option<PlanetSettings>,
    refresh_nonces: Mutex<HashMap<[u8; 16], Instant>>,
}

impl Controller {
    fn open(path: PathBuf, planet: Option<PlanetSettings>) -> Result<(Self, Option<String>)> {
        let (mut state, initial_token) = if path.exists() {
            let bytes =
                fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            let state = serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid controller state {}", path.display()))?;
            (state, None)
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
            (state, Some(admin_token))
        };
        let mut migrated = false;
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
        if migrated {
            write_state(&path, &state)?;
        }
        Ok((
            Self {
                path,
                state: RwLock::new(state),
                planet,
                refresh_nonces: Mutex::new(HashMap::new()),
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
    let parent = path
        .parent()
        .context("state path has no parent directory")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)?;
    Ok(())
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
    let cli = Cli::parse();
    let path = cli.state_file.unwrap_or_else(default_state_path);
    let planet = match (
        cli.planet_controller_url,
        cli.planet_relay_endpoints.is_empty(),
    ) {
        (Some(controller_url), false) => Some(PlanetSettings {
            controller_url: controller_url.trim_end_matches('/').to_owned(),
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
    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    println!("MeshLake controller listening on http://{}", cli.bind);
    println!("State file: {}", path.display());
    axum::serve(listener, app).await?;
    Ok(())
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
        let link = make_invite_link(
            "https://planet.example.com/",
            Uuid::from_u128(1),
            "single-use-token",
            "public-key",
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
    }
}
