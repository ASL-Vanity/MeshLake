//! Minimal standards-compliant UDP TURN client transport.
//!
//! MeshLake traffic remains end-to-end encrypted before it enters TURN.  This
//! module implements the RFC 5766 UDP allocation path (Allocate,
//! CreatePermission, Send Indication, and Data Indication) with coturn REST
//! credentials supplied by the controller.  Credentials are held only in the
//! owning route and are never formatted into errors or telemetry.

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use meshlake_core::{NetworkId, PlanetTurnServer, TurnCredential, TurnTransport};
use sha1::Sha1;
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    time::timeout,
};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;
const OUTBOUND_QUEUE_CAPACITY: usize = 128;
const ALLOCATION_TIMEOUT: Duration = Duration::from_secs(5);
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
const DEFAULT_LIFETIME: Duration = Duration::from_secs(300);

const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;
const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const SEND_INDICATION: u16 = 0x0016;
const DATA_INDICATION: u16 = 0x0017;
const REFRESH_REQUEST: u16 = 0x0004;
const REFRESH_SUCCESS: u16 = 0x0104;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_LIFETIME: u16 = 0x000d;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TurnUdpRoute {
    pub(crate) network_id: NetworkId,
    pub(crate) server: PlanetTurnServer,
    pub(crate) credential: TurnCredential,
}

impl fmt::Debug for TurnUdpRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnUdpRoute")
            .field("network_id", &self.network_id)
            .field("server", &self.server)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct TurnInbound {
    pub(crate) relay_endpoint: SocketAddr,
    pub(crate) packet: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct TurnTelemetry {
    configured: AtomicU64,
    allocated: AtomicU64,
    allocation_failures: AtomicU64,
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
    queue_drops: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TurnTelemetrySnapshot {
    pub(crate) configured: u64,
    pub(crate) allocated: u64,
    pub(crate) allocation_failures: u64,
    pub(crate) frames_sent: u64,
    pub(crate) frames_received: u64,
    pub(crate) queue_drops: u64,
}

impl TurnTelemetry {
    pub(crate) fn reset(&self, configured: usize) {
        self.configured.store(configured as u64, Ordering::Relaxed);
        self.allocated.store(0, Ordering::Relaxed);
        self.allocation_failures.store(0, Ordering::Relaxed);
        self.frames_sent.store(0, Ordering::Relaxed);
        self.frames_received.store(0, Ordering::Relaxed);
        self.queue_drops.store(0, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> TurnTelemetrySnapshot {
        TurnTelemetrySnapshot {
            configured: self.configured.load(Ordering::Relaxed),
            allocated: self.allocated.load(Ordering::Relaxed),
            allocation_failures: self.allocation_failures.load(Ordering::Relaxed),
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct RouteKey {
    network_id: NetworkId,
    endpoint: SocketAddr,
}

impl From<&TurnUdpRoute> for RouteKey {
    fn from(route: &TurnUdpRoute) -> Self {
        Self {
            network_id: route.network_id,
            endpoint: route.server.endpoint,
        }
    }
}

#[derive(Debug)]
struct TurnOutbound {
    peer: SocketAddr,
    packet: Vec<u8>,
}

#[derive(Clone)]
struct OutboundRoute {
    sender: mpsc::Sender<TurnOutbound>,
    allocated: Arc<AtomicBool>,
}

/// Bounded reconnecting UDP TURN allocations. Only public UDP TURN servers
/// appear here; TCP/TLS server descriptors remain signed Planet metadata but
/// are intentionally not silently downgraded to UDP.
pub(crate) struct TurnUdpTransport {
    routes: HashMap<RouteKey, OutboundRoute>,
    incoming: mpsc::Receiver<TurnInbound>,
    shutdown: watch::Sender<bool>,
    telemetry: Arc<TurnTelemetry>,
}

impl TurnUdpTransport {
    pub(crate) fn start(routes: Vec<TurnUdpRoute>, telemetry: Arc<TurnTelemetry>) -> Result<Self> {
        let routes = routes
            .into_iter()
            .filter(|route| matches!(route.server.transport, TurnTransport::Udp))
            .collect::<Vec<_>>();
        telemetry.reset(routes.len());
        let (incoming_tx, incoming) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let mut configured = HashMap::new();
        for route in routes {
            let key = RouteKey::from(&route);
            if configured.contains_key(&key) {
                continue;
            }
            let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
            let allocated = Arc::new(AtomicBool::new(false));
            tokio::spawn(run_route(
                route,
                receiver,
                incoming_tx.clone(),
                allocated.clone(),
                shutdown_rx.clone(),
                telemetry.clone(),
            ));
            configured.insert(key, OutboundRoute { sender, allocated });
        }
        Ok(Self {
            routes: configured,
            incoming,
            shutdown,
            telemetry,
        })
    }

    /// Sends through any ready allocation. TURN authentication belongs to the
    /// local device, while the encrypted MeshLake relay frame still carries
    /// its own network and membership authorization; selecting a ready route
    /// never grants cross-network access.
    pub(crate) fn try_send_any(&self, relay_endpoint: SocketAddr, packet: &[u8]) -> bool {
        if packet.is_empty() || packet.len() > MAX_MESSAGE_LEN {
            return false;
        }
        for outbound in self.routes.values() {
            if !outbound.allocated.load(Ordering::Acquire) {
                continue;
            }
            if outbound
                .sender
                .try_send(TurnOutbound {
                    peer: relay_endpoint,
                    packet: packet.to_vec(),
                })
                .is_ok()
            {
                return true;
            }
        }
        self.telemetry.queue_drops.fetch_add(1, Ordering::Relaxed);
        false
    }

    pub(crate) async fn receive(&mut self) -> Option<TurnInbound> {
        self.incoming.recv().await
    }
}

impl Drop for TurnUdpTransport {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn run_route(
    route: TurnUdpRoute,
    mut outbound: mpsc::Receiver<TurnOutbound>,
    incoming: mpsc::Sender<TurnInbound>,
    allocated: Arc<AtomicBool>,
    mut shutdown: watch::Receiver<bool>,
    telemetry: Arc<TurnTelemetry>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let result = connect_and_forward(
            &route,
            &mut outbound,
            &incoming,
            &allocated,
            &mut shutdown,
            telemetry.clone(),
        )
        .await;
        if allocated.swap(false, Ordering::AcqRel) {
            telemetry.allocated.fetch_sub(1, Ordering::Relaxed);
        }
        if *shutdown.borrow() || outbound.is_closed() {
            return;
        }
        telemetry
            .allocation_failures
            .fetch_add(1, Ordering::Relaxed);
        trace_turn(format!(
            "TURN allocation changed state: {}",
            result
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "closed".into())
        ));
        tokio::select! {
            _ = tokio::time::sleep(RECONNECT_DELAY) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return; }
            }
        }
    }
}

async fn connect_and_forward(
    route: &TurnUdpRoute,
    outbound: &mut mpsc::Receiver<TurnOutbound>,
    incoming: &mpsc::Sender<TurnInbound>,
    allocated: &AtomicBool,
    shutdown: &mut watch::Receiver<bool>,
    telemetry: Arc<TurnTelemetry>,
) -> Result<()> {
    if !matches!(route.server.transport, TurnTransport::Udp) {
        bail!("TURN UDP transport received a non-UDP server route");
    }
    let bind_address = if route.server.endpoint.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_address)
        .await
        .context("cannot bind local TURN UDP socket")?;
    let mut authentication = allocate(&socket, route).await?;
    if !allocated.swap(true, Ordering::AcqRel) {
        telemetry.allocated.fetch_add(1, Ordering::Relaxed);
    }
    let mut permissions = HashMap::<SocketAddr, Instant>::new();
    let refresh_after = Instant::now() + authentication.lifetime / 2;
    let mut refresh_deadline = tokio::time::Instant::from_std(refresh_after);
    let mut buffer = vec![0_u8; MAX_MESSAGE_LEN];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return Ok(()); }
            }
            outbound_packet = outbound.recv() => {
                let Some(outbound_packet) = outbound_packet else { return Ok(()); };
                let permission_due = permissions
                    .get(&outbound_packet.peer)
                    .is_none_or(|expiry| *expiry <= Instant::now() + Duration::from_secs(30));
                if permission_due {
                    create_permission(&socket, route, &authentication, outbound_packet.peer).await?;
                    permissions.insert(outbound_packet.peer, Instant::now() + Duration::from_secs(240));
                }
                let bytes = encode_authenticated(
                    SEND_INDICATION,
                    new_transaction_id()?,
                    vec![
                        (ATTR_XOR_PEER_ADDRESS, encode_xor_address(outbound_packet.peer)?),
                        (ATTR_DATA, outbound_packet.packet),
                    ],
                    &route.credential,
                    &authentication,
                )?;
                socket.send_to(&bytes, route.server.endpoint).await?;
                telemetry.frames_sent.fetch_add(1, Ordering::Relaxed);
            }
            received = socket.recv_from(&mut buffer) => {
                let (size, source) = received?;
                if source != route.server.endpoint { continue; }
                let message = parse_message(&buffer[..size])?;
                if message.message_type != DATA_INDICATION { continue; }
                let Some(peer) = message.xor_peer_address()? else { continue; };
                let Some(packet) = message.attribute(ATTR_DATA) else { continue; };
                if packet.is_empty() { continue; }
                if incoming.send(TurnInbound {
                    relay_endpoint: peer,
                    packet: packet.to_vec(),
                }).await.is_err() {
                    return Ok(());
                }
                telemetry.frames_received.fetch_add(1, Ordering::Relaxed);
            }
            _ = tokio::time::sleep_until(refresh_deadline) => {
                authentication = refresh(&socket, route, &authentication).await?;
                refresh_deadline = tokio::time::Instant::from_std(Instant::now() + authentication.lifetime / 2);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Authentication {
    realm: Vec<u8>,
    nonce: Vec<u8>,
    lifetime: Duration,
}

async fn allocate(socket: &UdpSocket, route: &TurnUdpRoute) -> Result<Authentication> {
    let transaction = new_transaction_id()?;
    let initial = encode_message(
        ALLOCATE_REQUEST,
        transaction,
        vec![(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
        None,
    )?;
    socket.send_to(&initial, route.server.endpoint).await?;
    let response = receive_response(socket, route.server.endpoint, transaction).await?;
    let authentication = match response.message_type {
        ALLOCATE_ERROR => authentication_from_challenge(&response)?,
        ALLOCATE_SUCCESS => {
            return Err(anyhow::anyhow!(
                "TURN server accepted unauthenticated allocation"
            ))
        }
        _ => bail!("TURN server returned an unexpected Allocate response"),
    };
    allocate_authenticated(socket, route, authentication).await
}

async fn allocate_authenticated(
    socket: &UdpSocket,
    route: &TurnUdpRoute,
    mut authentication: Authentication,
) -> Result<Authentication> {
    for _ in 0..2 {
        let transaction = new_transaction_id()?;
        let bytes = encode_authenticated(
            ALLOCATE_REQUEST,
            transaction,
            vec![(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
            &route.credential,
            &authentication,
        )?;
        socket.send_to(&bytes, route.server.endpoint).await?;
        let response = receive_response(socket, route.server.endpoint, transaction).await?;
        match response.message_type {
            ALLOCATE_SUCCESS => {
                authentication.lifetime = response
                    .lifetime()
                    .unwrap_or(DEFAULT_LIFETIME)
                    .clamp(Duration::from_secs(60), DEFAULT_LIFETIME);
                return Ok(authentication);
            }
            ALLOCATE_ERROR if response.error_code() == Some(438) => {
                authentication = authentication_from_challenge(&response)?;
            }
            ALLOCATE_ERROR => bail!("TURN Allocate request was rejected"),
            _ => bail!("TURN server returned an unexpected Allocate response"),
        }
    }
    bail!("TURN server repeatedly rejected the authentication nonce")
}

async fn create_permission(
    socket: &UdpSocket,
    route: &TurnUdpRoute,
    authentication: &Authentication,
    peer: SocketAddr,
) -> Result<()> {
    let transaction = new_transaction_id()?;
    let bytes = encode_authenticated(
        CREATE_PERMISSION_REQUEST,
        transaction,
        vec![(ATTR_XOR_PEER_ADDRESS, encode_xor_address(peer)?)],
        &route.credential,
        authentication,
    )?;
    socket.send_to(&bytes, route.server.endpoint).await?;
    let response = receive_response(socket, route.server.endpoint, transaction).await?;
    if response.message_type != CREATE_PERMISSION_SUCCESS {
        bail!("TURN CreatePermission request was rejected");
    }
    Ok(())
}

async fn refresh(
    socket: &UdpSocket,
    route: &TurnUdpRoute,
    authentication: &Authentication,
) -> Result<Authentication> {
    let transaction = new_transaction_id()?;
    let bytes = encode_authenticated(
        REFRESH_REQUEST,
        transaction,
        vec![(
            ATTR_LIFETIME,
            (DEFAULT_LIFETIME.as_secs() as u32).to_be_bytes().to_vec(),
        )],
        &route.credential,
        authentication,
    )?;
    socket.send_to(&bytes, route.server.endpoint).await?;
    let response = receive_response(socket, route.server.endpoint, transaction).await?;
    if response.message_type != REFRESH_SUCCESS {
        bail!("TURN Refresh request was rejected");
    }
    let mut next = authentication.clone();
    next.lifetime = response
        .lifetime()
        .unwrap_or(DEFAULT_LIFETIME)
        .clamp(Duration::from_secs(60), DEFAULT_LIFETIME);
    Ok(next)
}

async fn receive_response(
    socket: &UdpSocket,
    server: SocketAddr,
    transaction: [u8; 12],
) -> Result<Message> {
    let mut buffer = vec![0_u8; MAX_MESSAGE_LEN];
    timeout(ALLOCATION_TIMEOUT, async {
        loop {
            let (size, source) = socket.recv_from(&mut buffer).await?;
            if source != server {
                continue;
            }
            let message = parse_message(&buffer[..size])?;
            if message.transaction == transaction {
                return Ok(message);
            }
        }
    })
    .await
    .context("TURN response timed out")?
}

fn authentication_from_challenge(message: &Message) -> Result<Authentication> {
    if message.error_code() != Some(401) && message.error_code() != Some(438) {
        bail!("TURN server rejected authentication without a supported challenge");
    }
    let realm = message
        .attribute(ATTR_REALM)
        .filter(|value| !value.is_empty())
        .context("TURN authentication challenge did not include a realm")?
        .to_vec();
    let nonce = message
        .attribute(ATTR_NONCE)
        .filter(|value| !value.is_empty())
        .context("TURN authentication challenge did not include a nonce")?
        .to_vec();
    Ok(Authentication {
        realm,
        nonce,
        lifetime: DEFAULT_LIFETIME,
    })
}

fn encode_authenticated(
    message_type: u16,
    transaction: [u8; 12],
    mut attributes: Vec<(u16, Vec<u8>)>,
    credential: &TurnCredential,
    authentication: &Authentication,
) -> Result<Vec<u8>> {
    attributes.push((ATTR_USERNAME, credential.username.as_bytes().to_vec()));
    attributes.push((ATTR_REALM, authentication.realm.clone()));
    attributes.push((ATTR_NONCE, authentication.nonce.clone()));
    let mut key_material = Vec::with_capacity(
        credential.username.len() + authentication.realm.len() + credential.password.len() + 2,
    );
    key_material.extend_from_slice(credential.username.as_bytes());
    key_material.push(b':');
    key_material.extend_from_slice(&authentication.realm);
    key_material.push(b':');
    key_material.extend_from_slice(credential.password.as_bytes());
    let key = md5::compute(key_material);
    encode_message(message_type, transaction, attributes, Some(key.as_ref()))
}

fn encode_message(
    message_type: u16,
    transaction: [u8; 12],
    attributes: Vec<(u16, Vec<u8>)>,
    integrity_key: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for (kind, value) in attributes {
        append_attribute(&mut body, kind, &value)?;
    }
    let integrity_len = integrity_key.map_or(0, |_| 24);
    let total_body_len = body.len() + integrity_len;
    if total_body_len > u16::MAX as usize {
        bail!("TURN message exceeds the protocol length limit");
    }
    let mut message = Vec::with_capacity(HEADER_LEN + total_body_len);
    message.extend_from_slice(&message_type.to_be_bytes());
    message.extend_from_slice(&(total_body_len as u16).to_be_bytes());
    message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message.extend_from_slice(&transaction);
    message.extend_from_slice(&body);
    if let Some(key) = integrity_key {
        let mut mac = Hmac::<Sha1>::new_from_slice(key)
            .map_err(|_| anyhow::anyhow!("TURN integrity key is invalid"))?;
        mac.update(&message);
        append_attribute(
            &mut message,
            ATTR_MESSAGE_INTEGRITY,
            &mac.finalize().into_bytes(),
        )?;
    }
    Ok(message)
}

fn append_attribute(target: &mut Vec<u8>, kind: u16, value: &[u8]) -> Result<()> {
    if value.len() > u16::MAX as usize {
        bail!("TURN attribute exceeds the protocol length limit");
    }
    target.extend_from_slice(&kind.to_be_bytes());
    target.extend_from_slice(&(value.len() as u16).to_be_bytes());
    target.extend_from_slice(value);
    target.resize((target.len() + 3) & !3, 0);
    Ok(())
}

fn encode_xor_address(address: SocketAddr) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    value.push(0);
    value.push(if address.is_ipv4() { 0x01 } else { 0x02 });
    value.extend_from_slice(&(address.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
    match address.ip() {
        IpAddr::V4(address) => {
            value.extend_from_slice(&(u32::from(address) ^ MAGIC_COOKIE).to_be_bytes());
        }
        IpAddr::V6(address) => {
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for (index, byte) in address.octets().iter().enumerate() {
                let mask = if index < 4 { cookie[index] } else { 0 };
                value.push(byte ^ mask);
            }
        }
    }
    Ok(value)
}

fn new_transaction_id() -> Result<[u8; 12]> {
    let mut transaction = [0_u8; 12];
    getrandom::fill(&mut transaction)
        .map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))?;
    Ok(transaction)
}

#[derive(Debug)]
struct Message {
    message_type: u16,
    transaction: [u8; 12],
    attributes: Vec<(u16, Vec<u8>)>,
}

impl Message {
    fn attribute(&self, kind: u16) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|(candidate, _)| *candidate == kind)
            .map(|(_, value)| value.as_slice())
    }

    fn error_code(&self) -> Option<u16> {
        let value = self.attribute(ATTR_ERROR_CODE)?;
        (value.len() >= 4).then(|| u16::from(value[2] & 0x07) * 100 + u16::from(value[3]))
    }

    fn lifetime(&self) -> Option<Duration> {
        let value: [u8; 4] = self.attribute(ATTR_LIFETIME)?.try_into().ok()?;
        Some(Duration::from_secs(u32::from_be_bytes(value) as u64))
    }

    fn xor_peer_address(&self) -> Result<Option<SocketAddr>> {
        let Some(value) = self.attribute(ATTR_XOR_PEER_ADDRESS) else {
            return Ok(None);
        };
        if value.len() < 8 || value[0] != 0 {
            bail!("TURN XOR-PEER-ADDRESS attribute is malformed");
        }
        let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
        let address = match value[1] {
            0x01 if value.len() == 8 => {
                let encoded: [u8; 4] = value[4..8].try_into().unwrap();
                IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(encoded) ^ MAGIC_COOKIE))
            }
            0x02 if value.len() == 20 => {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                let mut decoded = [0_u8; 16];
                for (index, byte) in value[4..20].iter().enumerate() {
                    decoded[index] = byte ^ if index < 4 { cookie[index] } else { 0 };
                }
                IpAddr::V6(Ipv6Addr::from(decoded))
            }
            _ => bail!("TURN XOR-PEER-ADDRESS family is malformed"),
        };
        Ok(Some(SocketAddr::new(address, port)))
    }
}

fn parse_message(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < HEADER_LEN || bytes.len() > MAX_MESSAGE_LEN {
        bail!("TURN message length is invalid");
    }
    let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if message_type & 0xc000 != 0 {
        bail!("TURN message type is invalid");
    }
    let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if body_len + HEADER_LEN != bytes.len() || body_len % 4 != 0 {
        bail!("TURN message body length is invalid");
    }
    if u32::from_be_bytes(bytes[4..8].try_into().unwrap()) != MAGIC_COOKIE {
        bail!("TURN message magic cookie is invalid");
    }
    let transaction = bytes[8..20].try_into().unwrap();
    let mut attributes = Vec::new();
    let mut cursor = HEADER_LEN;
    while cursor < bytes.len() {
        if cursor + 4 > bytes.len() {
            bail!("TURN attribute header is truncated");
        }
        let kind = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap());
        let length = u16::from_be_bytes(bytes[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let end = cursor
            .checked_add(length)
            .context("TURN attribute length overflows")?;
        if end > bytes.len() {
            bail!("TURN attribute is truncated");
        }
        attributes.push((kind, bytes[cursor..end].to_vec()));
        cursor = (end + 3) & !3;
        if cursor > bytes.len() {
            bail!("TURN attribute padding is truncated");
        }
    }
    Ok(Message {
        message_type,
        transaction,
        attributes,
    })
}

fn trace_turn(message: impl fmt::Display) {
    if std::env::var_os("MESHLAKE_TRACE").is_some() {
        eprintln!("[meshlake turn] {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::{DeviceId, TurnTransport};
    use tokio::{net::UdpSocket, time::timeout};
    use uuid::Uuid;

    #[test]
    fn authenticated_message_has_correct_length_and_integrity_attribute() {
        let credential = TurnCredential {
            version: 1,
            username: "100:device".into(),
            password: "secret".into(),
            expires_at_unix_seconds: 100,
        };
        let authentication = Authentication {
            realm: b"coturn".to_vec(),
            nonce: b"nonce".to_vec(),
            lifetime: DEFAULT_LIFETIME,
        };
        let bytes = encode_authenticated(
            ALLOCATE_REQUEST,
            [7; 12],
            vec![(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
            &credential,
            &authentication,
        )
        .unwrap();
        assert_eq!(
            u16::from_be_bytes([bytes[2], bytes[3]]) as usize + HEADER_LEN,
            bytes.len()
        );
        assert_eq!(
            parse_message(&bytes)
                .unwrap()
                .attribute(ATTR_MESSAGE_INTEGRITY)
                .unwrap()
                .len(),
            20
        );
    }

    #[test]
    fn xor_peer_address_round_trips_for_ipv4_and_ipv6() {
        for endpoint in ["198.51.100.42:51820", "[2001:db8::42]:51820"] {
            let endpoint = endpoint.parse().unwrap();
            let encoded = encode_xor_address(endpoint).unwrap();
            let bytes = encode_message(
                DATA_INDICATION,
                [8; 12],
                vec![(ATTR_XOR_PEER_ADDRESS, encoded)],
                None,
            )
            .unwrap();
            assert_eq!(
                parse_message(&bytes).unwrap().xor_peer_address().unwrap(),
                Some(endpoint)
            );
        }
    }

    #[test]
    fn route_debug_redacts_turn_password() {
        let route = TurnUdpRoute {
            network_id: NetworkId(Uuid::new_v4()),
            server: PlanetTurnServer {
                endpoint: "198.51.100.1:3478".parse().unwrap(),
                transport: TurnTransport::Udp,
                server_name: None,
                certificate_sha256: Vec::new(),
                priority: 0,
            },
            credential: TurnCredential {
                version: 1,
                username: DeviceId(Uuid::new_v4()).0.to_string(),
                password: "do-not-log".into(),
                expires_at_unix_seconds: 1,
            },
        };
        assert!(!format!("{route:?}").contains("do-not-log"));
    }

    #[tokio::test]
    async fn udp_transport_allocates_creates_permission_and_forwards_data() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_endpoint = server.local_addr().unwrap();
        let relay_endpoint: SocketAddr = "198.51.100.70:51820".parse().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; MAX_MESSAGE_LEN];
            let (size, client) = server.recv_from(&mut buffer).await.unwrap();
            let allocate = parse_message(&buffer[..size]).unwrap();
            assert_eq!(allocate.message_type, ALLOCATE_REQUEST);
            let challenge = encode_message(
                ALLOCATE_ERROR,
                allocate.transaction,
                vec![
                    (ATTR_ERROR_CODE, vec![0, 0, 4, 1]),
                    (ATTR_REALM, b"turn.test".to_vec()),
                    (ATTR_NONCE, b"nonce-1".to_vec()),
                ],
                None,
            )
            .unwrap();
            server.send_to(&challenge, client).await.unwrap();

            let (size, client) = server.recv_from(&mut buffer).await.unwrap();
            let allocate = parse_message(&buffer[..size]).unwrap();
            assert_eq!(allocate.message_type, ALLOCATE_REQUEST);
            assert!(allocate.attribute(ATTR_MESSAGE_INTEGRITY).is_some());
            let success = encode_message(
                ALLOCATE_SUCCESS,
                allocate.transaction,
                vec![(ATTR_LIFETIME, 120_u32.to_be_bytes().to_vec())],
                None,
            )
            .unwrap();
            server.send_to(&success, client).await.unwrap();

            let (size, client) = server.recv_from(&mut buffer).await.unwrap();
            let permission = parse_message(&buffer[..size]).unwrap();
            assert_eq!(permission.message_type, CREATE_PERMISSION_REQUEST);
            let permission_success = encode_message(
                CREATE_PERMISSION_SUCCESS,
                permission.transaction,
                Vec::new(),
                None,
            )
            .unwrap();
            server.send_to(&permission_success, client).await.unwrap();

            let (size, client) = server.recv_from(&mut buffer).await.unwrap();
            let send = parse_message(&buffer[..size]).unwrap();
            assert_eq!(send.message_type, SEND_INDICATION);
            assert_eq!(send.xor_peer_address().unwrap(), Some(relay_endpoint));
            let data = send.attribute(ATTR_DATA).unwrap().to_vec();
            let indication = encode_message(
                DATA_INDICATION,
                [9; 12],
                vec![
                    (
                        ATTR_XOR_PEER_ADDRESS,
                        encode_xor_address(relay_endpoint).unwrap(),
                    ),
                    (ATTR_DATA, data),
                ],
                None,
            )
            .unwrap();
            server.send_to(&indication, client).await.unwrap();
        });
        let route = TurnUdpRoute {
            network_id: NetworkId(Uuid::from_u128(12)),
            server: PlanetTurnServer {
                endpoint: server_endpoint,
                transport: TurnTransport::Udp,
                server_name: None,
                certificate_sha256: Vec::new(),
                priority: 0,
            },
            credential: TurnCredential {
                version: 1,
                username: "120:device".into(),
                password: "test-password".into(),
                expires_at_unix_seconds: 120,
            },
        };
        let telemetry = Arc::new(TurnTelemetry::default());
        let mut transport = TurnUdpTransport::start(vec![route], telemetry.clone()).unwrap();
        timeout(Duration::from_secs(2), async {
            while telemetry.snapshot().allocated != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("TURN allocation did not complete");
        let encrypted_frame = vec![0x4d, 0x4c, 0x52, 0x31, 6, 7, 8];
        assert!(transport.try_send_any(relay_endpoint, &encrypted_frame));
        let inbound = timeout(Duration::from_secs(2), transport.receive())
            .await
            .expect("TURN data indication did not arrive")
            .unwrap();
        assert_eq!(inbound.relay_endpoint, relay_endpoint);
        assert_eq!(inbound.packet, encrypted_frame);
        assert_eq!(telemetry.snapshot().frames_sent, 1);
        assert_eq!(telemetry.snapshot().frames_received, 1);
        server_task.await.unwrap();
    }
}
