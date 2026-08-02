//! Blind UDP relay for MeshLake encrypted overlay frames.
//!
//! The relay authenticates controller-signed membership certificates during registration,
//! then forwards opaque ciphertext only. It never receives MeshLake network keys.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use ed25519_dalek::SigningKey;
use meshlake_core::{
    load_or_create_service_identity, peer_identity_announcement, AuthorizationEpochHint, DeviceId,
    MembershipCertificate, NetworkId, RootRegistration, SignedRelayRegistrationAck,
    RELAY_CANDIDATE, RELAY_DATA, RELAY_DATA_HEADER_LEN, RELAY_MAGIC, RELAY_PEER,
    RELAY_REGISTER_ACK_SIGNED, RELAY_REGISTER_SIGNED, RELAY_SESSION_DATA, RELAY_SESSION_INIT,
    RELAY_SESSION_RESPONSE,
};
use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "meshlake-relay", about = "MeshLake encrypted UDP relay")]
struct Cli {
    /// Public listener. Keep the loopback default for development.
    #[arg(long, default_value = "127.0.0.1:51820")]
    bind: SocketAddr,
    /// Base64 Ed25519 controller public key distributed through a trusted channel.
    #[arg(long)]
    controller_public_key_base64: String,
    /// Persistent Ed25519 Relay service identity. Generated on first start.
    #[arg(long)]
    identity_file: Option<PathBuf>,
    /// Optional next identity used to dual-sign during a Planet V3 rotation window.
    #[arg(long)]
    transition_identity_file: Option<PathBuf>,
    /// Print the public Relay identity document and exit.
    #[arg(long)]
    print_identity: bool,
}

type PeerKey = (NetworkId, DeviceId);
const PEER_TTL: Duration = Duration::from_secs(90);
const REGISTRATION_NONCE_TTL: Duration = Duration::from_secs(300);
const MAX_CANDIDATES_PER_PEER: usize = 16;

#[derive(Debug, Clone)]
struct PeerRecord {
    endpoint: SocketAddr,
    candidates: Vec<SocketAddr>,
    assigned_addresses: Vec<IpAddr>,
    certificate: MembershipCertificate,
    authorization_expires_at_unix_seconds: u64,
    last_seen: Instant,
}

struct AuthenticatedRegistration {
    key: PeerKey,
    certificate: MembershipCertificate,
    nonce: [u8; 16],
    authorization_expires_at_unix_seconds: u64,
    authorization_hint: Option<AuthorizationEpochHint>,
    candidates: Vec<SocketAddr>,
}

struct RelayIdentity {
    relay_id: Uuid,
    current: SigningKey,
    next: Option<SigningKey>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let trusted_key = decode_controller_key(&cli.controller_public_key_base64)?;
    let identity_path = cli.identity_file.unwrap_or_else(default_identity_path);
    let current = load_or_create_service_identity(&identity_path, None)?;
    let next = cli
        .transition_identity_file
        .as_deref()
        .map(|path| load_or_create_service_identity(path, Some(current.service_id)))
        .transpose()?;
    let identity = RelayIdentity {
        relay_id: current.service_id,
        current: current.signing_key,
        next: next.map(|identity| identity.signing_key),
    };
    if cli.print_identity {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "relay_id": identity.relay_id,
                "current_public_key_base64": STANDARD.encode(identity.current.verifying_key().to_bytes()),
                "next_public_key_base64": identity.next.as_ref().map(|key| STANDARD.encode(key.verifying_key().to_bytes())),
            }))?
        );
        return Ok(());
    }
    let socket = UdpSocket::bind(cli.bind).await?;
    println!("MeshLake relay listening on udp://{}", cli.bind);
    println!("The relay forwards encrypted payloads only.");

    let mut peers: HashMap<PeerKey, PeerRecord> = HashMap::new();
    let mut seen_nonces = HashMap::<(NetworkId, DeviceId, [u8; 16]), Instant>::new();
    let mut authorization_hints = HashMap::<NetworkId, AuthorizationEpochHint>::new();
    let mut buffer = vec![0_u8; u16::MAX as usize];
    loop {
        let (length, remote) = socket.recv_from(&mut buffer).await?;
        let packet = &buffer[..length];
        if packet.len() < 5 || packet[..4] != RELAY_MAGIC {
            continue;
        }
        let timestamp = now();
        peers.retain(|_, peer| {
            peer.last_seen.elapsed() <= PEER_TTL
                && timestamp <= peer.authorization_expires_at_unix_seconds
        });
        handle_packet(
            &socket,
            &trusted_key,
            &identity,
            &mut peers,
            &mut seen_nonces,
            &mut authorization_hints,
            remote,
            packet,
        )
        .await?;
    }
}

async fn handle_packet(
    socket: &UdpSocket,
    trusted_key: &Vec<u8>,
    identity: &RelayIdentity,
    peers: &mut HashMap<PeerKey, PeerRecord>,
    seen_nonces: &mut HashMap<(NetworkId, DeviceId, [u8; 16]), Instant>,
    authorization_hints: &mut HashMap<NetworkId, AuthorizationEpochHint>,
    remote: SocketAddr,
    packet: &[u8],
) -> Result<()> {
    match packet[4] {
        RELAY_REGISTER_SIGNED => {
            if let Some(registration) = parse_signed_registration(&packet[5..], trusted_key) {
                let AuthenticatedRegistration {
                    key,
                    certificate,
                    nonce,
                    authorization_expires_at_unix_seconds,
                    authorization_hint,
                    candidates: advertised_candidates,
                } = registration;
                seen_nonces.retain(|_, seen| seen.elapsed() <= REGISTRATION_NONCE_TTL);
                if seen_nonces
                    .insert((key.0, key.1, nonce), Instant::now())
                    .is_some()
                {
                    trace_transport(format!(
                        "rejected replayed registration for member {}",
                        key.1 .0
                    ));
                    return Ok(());
                }
                let candidates = accepted_candidates(remote, advertised_candidates);
                let previous_candidates = peers
                    .get(&key)
                    .map(|peer| peer.candidates.as_slice())
                    .unwrap_or_default();
                let new_candidates = candidate_delta(previous_candidates, &candidates);
                let assigned_addresses = authorized_addresses(&certificate);
                if has_address_conflict(peers, key, &assigned_addresses) {
                    trace_transport(format!(
                        "rejected member {} because a virtual address is already in use",
                        key.1 .0
                    ));
                    return Ok(());
                }
                let existing = peers
                    .iter()
                    .filter_map(|(peer_key, peer)| {
                        (peer_key.0 == key.0 && *peer_key != key)
                            .then_some((*peer_key, peer.clone()))
                    })
                    .collect::<Vec<_>>();
                peers.insert(
                    key,
                    PeerRecord {
                        endpoint: remote,
                        candidates: candidates.clone(),
                        assigned_addresses: assigned_addresses.clone(),
                        certificate: certificate.clone(),
                        authorization_expires_at_unix_seconds,
                        last_seen: Instant::now(),
                    },
                );
                if let Some(hint) = authorization_hint {
                    let replace = authorization_hints.get(&key.0).is_none_or(|current| {
                        hint.authorization_epoch > current.authorization_epoch
                    });
                    if replace {
                        authorization_hints.insert(key.0, hint);
                    }
                }
                let issued_at = now();
                let signing_keys = identity
                    .next
                    .as_ref()
                    .map(|next| vec![&identity.current, next])
                    .unwrap_or_else(|| vec![&identity.current]);
                let acknowledgement = SignedRelayRegistrationAck::sign(
                    key.0,
                    key.1,
                    identity.relay_id,
                    nonce,
                    remote,
                    issued_at,
                    issued_at + 15,
                    authorization_hints.get(&key.0).cloned(),
                    &signing_keys,
                )?;
                let mut acknowledgement_packet = Vec::from(RELAY_MAGIC);
                acknowledgement_packet.push(RELAY_REGISTER_ACK_SIGNED);
                acknowledgement_packet.extend_from_slice(&serde_json::to_vec(&acknowledgement)?);
                socket.send_to(&acknowledgement_packet, remote).await?;
                trace_transport(format!(
                    "registered member {} for network {} from {remote}",
                    key.1 .0, key.0 .0
                ));
                for (target, announcement) in
                    registration_candidate_fanout(key, &new_candidates, remote, &existing)
                {
                    socket.send_to(&announcement, target).await?;
                }
                for (_, peer) in existing {
                    socket
                        .send_to(&peer_identity_announcement(&certificate)?, peer.endpoint)
                        .await?;
                    socket
                        .send_to(&peer_identity_announcement(&peer.certificate)?, remote)
                        .await?;
                }
            }
        }
        RELAY_DATA | RELAY_SESSION_INIT | RELAY_SESSION_RESPONSE | RELAY_SESSION_DATA => {
            if let Some((network, source, destination)) = parse_data_header(packet) {
                let source_key = (network, source);
                if peers.get(&source_key).map(|peer| peer.endpoint) != Some(remote) {
                    return Ok(());
                }
                for target in relay_targets(peers, source_key, destination) {
                    socket.send_to(packet, target).await?;
                    trace_transport(format!("forwarded encrypted packet to {target}"));
                }
            }
        }
        RELAY_CANDIDATE => {
            // Candidate claims must be covered by the device signature in the
            // next RootRegistration. Endpoint-bound but unsigned updates could
            // otherwise make every member probe an attacker-chosen third party.
            trace_transport(format!("ignored unsigned candidate update from {remote}"));
        }
        _ => {}
    }
    Ok(())
}

/// Emits routing metadata only when `MESHLAKE_TRACE` is set.  The relay never
/// logs opaque encrypted packet bodies or MeshLake network keys.
fn trace_transport(message: impl std::fmt::Display) {
    if std::env::var_os("MESHLAKE_TRACE").is_some() {
        eprintln!("[meshlake relay] {message}");
    }
}

/// Relay control frame: magic + kind + network UUID + device UUID + address
/// family + port (big endian) + IP address. It contains no network key or
/// virtual-network payload.
fn peer_announcement(peer: PeerKey, address: SocketAddr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(56);
    packet.extend_from_slice(&RELAY_MAGIC);
    packet.push(RELAY_PEER);
    packet.extend_from_slice((peer.0).0.as_bytes());
    packet.extend_from_slice((peer.1).0.as_bytes());
    match address.ip() {
        IpAddr::V4(ip) => {
            packet.push(4);
            packet.extend_from_slice(&address.port().to_be_bytes());
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(6);
            packet.extend_from_slice(&address.port().to_be_bytes());
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet
}

fn valid_candidate(candidate: SocketAddr) -> bool {
    candidate.port() != 0
        && !candidate.ip().is_unspecified()
        && !candidate.ip().is_multicast()
        && !candidate.ip().is_loopback()
        && candidate.ip() != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
}

fn accepted_candidates(
    observed_endpoint: SocketAddr,
    advertised_candidates: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    let mut candidates = Vec::with_capacity(MAX_CANDIDATES_PER_PEER);
    candidates.push(observed_endpoint);
    for candidate in advertised_candidates {
        if candidate.ip() == observed_endpoint.ip()
            && valid_candidate(candidate)
            && !candidates.contains(&candidate)
        {
            candidates.push(candidate);
            if candidates.len() == MAX_CANDIDATES_PER_PEER {
                break;
            }
        }
    }
    candidates
}

fn candidate_delta(previous: &[SocketAddr], current: &[SocketAddr]) -> Vec<SocketAddr> {
    current
        .iter()
        .copied()
        .filter(|candidate| !previous.contains(candidate))
        .collect()
}

fn registration_candidate_fanout(
    registering: PeerKey,
    registering_candidates: &[SocketAddr],
    registering_endpoint: SocketAddr,
    existing: &[(PeerKey, PeerRecord)],
) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut outbound = Vec::new();
    for (peer_key, peer) in existing {
        if peer_key.0 != registering.0 || *peer_key == registering {
            continue;
        }
        outbound.extend(
            registering_candidates
                .iter()
                .map(|candidate| (peer.endpoint, peer_announcement(registering, *candidate))),
        );
        outbound.extend(peer.candidates.iter().map(|candidate| {
            (
                registering_endpoint,
                peer_announcement(*peer_key, *candidate),
            )
        }));
    }
    outbound
}

fn relay_targets(
    peers: &HashMap<PeerKey, PeerRecord>,
    source: PeerKey,
    destination: DeviceId,
) -> Vec<SocketAddr> {
    if destination.0.is_nil() {
        peers
            .iter()
            .filter_map(|(key, peer)| {
                (key.0 == source.0 && *key != source).then_some(peer.endpoint)
            })
            .collect()
    } else {
        peers
            .get(&(source.0, destination))
            .map(|peer| peer.endpoint)
            .into_iter()
            .collect()
    }
}

fn authorized_addresses(certificate: &MembershipCertificate) -> Vec<IpAddr> {
    let mut addresses = certificate
        .claims
        .assigned_addresses
        .iter()
        .copied()
        .filter(|address| !address.is_unspecified() && !address.is_multicast())
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    addresses.truncate(meshlake_core::RELAY_MAX_ASSIGNED_ADDRESSES);
    addresses
}

fn has_address_conflict(
    peers: &HashMap<PeerKey, PeerRecord>,
    registering: PeerKey,
    assigned_addresses: &[IpAddr],
) -> bool {
    peers.iter().any(|(key, peer)| {
        key.0 == registering.0
            && key.1 != registering.1
            && peer
                .assigned_addresses
                .iter()
                .any(|address| assigned_addresses.contains(address))
    })
}

fn decode_controller_key(encoded: &str) -> Result<Vec<u8>> {
    let key = STANDARD
        .decode(encoded)
        .context("controller public key is not valid base64")?;
    if key.len() != 32 {
        bail!("controller public key must contain exactly 32 bytes");
    }
    Ok(key)
}

fn parse_signed_registration(
    bytes: &[u8],
    trusted_controller_key: &Vec<u8>,
) -> Option<AuthenticatedRegistration> {
    let registration: RootRegistration = serde_json::from_slice(bytes).ok()?;
    registration
        .verify_authorized(std::slice::from_ref(trusted_controller_key), now(), 120)
        .ok()?;
    if registration.payload.certificates.len() != 1 {
        return None;
    }
    let nonce = registration.payload.nonce;
    let candidates = registration.payload.candidates.clone();
    let certificate = registration.payload.certificates.into_iter().next()?;
    let authorization_expires_at_unix_seconds = registration
        .payload
        .authorization_manifests
        .iter()
        .find(|authorization| authorization.network_id == certificate.claims.network_id)?
        .expires_at_unix_seconds;
    let authorization_hint = registration
        .payload
        .authorization_manifests
        .iter()
        .find(|authorization| authorization.network_id == certificate.claims.network_id)
        .and_then(|authorization| authorization.epoch_hint.clone());
    let key = (certificate.claims.network_id, certificate.claims.device_id);
    (certificate.claims.device_id == registration.payload.device_id).then_some(
        AuthenticatedRegistration {
            key,
            certificate,
            nonce,
            authorization_expires_at_unix_seconds,
            authorization_hint,
            candidates,
        },
    )
}

fn parse_data_header(packet: &[u8]) -> Option<(NetworkId, DeviceId, DeviceId)> {
    if packet.len() < RELAY_DATA_HEADER_LEN {
        return None;
    }
    let network = NetworkId(Uuid::from_slice(&packet[5..21]).ok()?);
    let source = DeviceId(Uuid::from_slice(&packet[21..37]).ok()?);
    let destination = DeviceId(Uuid::from_slice(&packet[37..53]).ok()?);
    Some((network, source, destination))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_secs()
}

fn default_identity_path() -> PathBuf {
    if let Some(directory) = env::var_os("MESHLAKE_STATE_DIR") {
        return PathBuf::from(directory).join("relay-identity.json");
    }
    if let Some(directory) = env::var_os("LOCALAPPDATA") {
        return PathBuf::from(directory)
            .join("MeshLake")
            .join("relay-identity.json");
    }
    if let Some(directory) = env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(directory)
            .join("meshlake")
            .join("relay-identity.json");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().expect("current directory unavailable"))
        .join(".local")
        .join("state")
        .join("meshlake")
        .join("relay-identity.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use meshlake_core::{
        accept_pairwise_handshake, parse_peer_identity, relay_associated_data,
        AuthorizedMembership, InitiatorHandshake, MembershipClaims, NetworkAuthorizationManifest,
        NetworkKey, ReplayWindow,
    };

    fn test_relay_identity() -> RelayIdentity {
        RelayIdentity {
            relay_id: Uuid::from_u128(0xfeed),
            current: SigningKey::from_bytes(&[90; 32]),
            next: None,
        }
    }

    async fn handle_packet(
        socket: &UdpSocket,
        trusted_key: &Vec<u8>,
        peers: &mut HashMap<PeerKey, PeerRecord>,
        seen_nonces: &mut HashMap<(NetworkId, DeviceId, [u8; 16]), Instant>,
        remote: SocketAddr,
        packet: &[u8],
    ) -> Result<()> {
        super::handle_packet(
            socket,
            trusted_key,
            &test_relay_identity(),
            peers,
            seen_nonces,
            &mut HashMap::new(),
            remote,
            packet,
        )
        .await
    }

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

    fn signed_registration_packet(
        controller: &SigningKey,
        node: &SigningKey,
        certificate: MembershipCertificate,
    ) -> Vec<u8> {
        signed_registration_packet_with_candidates(controller, node, certificate, vec![])
    }

    fn signed_registration_packet_with_candidates(
        controller: &SigningKey,
        node: &SigningKey,
        certificate: MembershipCertificate,
        candidates: Vec<SocketAddr>,
    ) -> Vec<u8> {
        let timestamp = now();
        let authorization = NetworkAuthorizationManifest::sign(
            certificate.claims.network_id,
            1,
            certificate.network_key_epoch,
            vec![AuthorizedMembership {
                device_id: certificate.claims.device_id,
                certificate_id: certificate.certificate_id,
                device_public_key: certificate.claims.device_public_key.clone(),
                network_key_epoch: certificate.network_key_epoch,
            }],
            vec![],
            timestamp,
            timestamp + 90,
            controller,
        )
        .unwrap();
        let registration = RootRegistration::sign_authorized(
            certificate.claims.device_id,
            vec![certificate],
            vec![authorization],
            candidates,
            timestamp,
            *Uuid::new_v4().as_bytes(),
            node,
        )
        .unwrap();
        let mut packet = Vec::from(RELAY_MAGIC);
        packet.push(RELAY_REGISTER_SIGNED);
        packet.extend_from_slice(&serde_json::to_vec(&registration).unwrap());
        packet
    }

    async fn receive_datagram(socket: &UdpSocket) -> Vec<u8> {
        let mut buffer = vec![0_u8; u16::MAX as usize];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
                .await
                .expect("relay test timed out")
                .unwrap();
        buffer.truncate(length);
        buffer
    }

    #[test]
    fn registration_is_bound_to_the_certificate_identity() {
        let controller = SigningKey::from_bytes(&[7; 32]);
        let node = SigningKey::from_bytes(&[8; 32]);
        let network = NetworkId(Uuid::from_u128(1));
        let device = DeviceId(Uuid::from_u128(2));
        let certificate = test_certificate(&controller, &node, network, device, "100.64.0.2");
        let packet = signed_registration_packet(&controller, &node, certificate.clone());
        let registration: RootRegistration = serde_json::from_slice(&packet[5..]).unwrap();
        let raw = serde_json::to_vec(&registration).unwrap();
        let decoded =
            parse_signed_registration(&raw, &controller.verifying_key().to_bytes().to_vec())
                .unwrap();
        assert_eq!(
            decoded.key,
            (certificate.claims.network_id, certificate.claims.device_id)
        );
        assert_eq!(decoded.certificate, certificate);
        assert_eq!(decoded.nonce, registration.payload.nonce);
        assert!(decoded.authorization_expires_at_unix_seconds >= now());

        let legacy = RootRegistration::sign(
            device,
            vec![decoded.certificate.clone()],
            vec![],
            now(),
            [1_u8; 16],
            &node,
        )
        .unwrap();
        assert!(parse_signed_registration(
            &serde_json::to_vec(&legacy).unwrap(),
            &controller.verifying_key().to_bytes().to_vec(),
        )
        .is_none());

        let attacker = SigningKey::from_bytes(&[9; 32]);
        let replay = RootRegistration::sign_authorized(
            device,
            vec![decoded.certificate],
            registration.payload.authorization_manifests,
            vec![],
            now(),
            [2_u8; 16],
            &attacker,
        )
        .unwrap();
        assert!(parse_signed_registration(
            &serde_json::to_vec(&replay).unwrap(),
            &controller.verifying_key().to_bytes().to_vec(),
        )
        .is_none());
    }

    #[test]
    fn broadcast_excludes_the_sending_member() {
        let network = NetworkId(Uuid::from_u128(1));
        let source = (network, DeviceId(Uuid::from_u128(2)));
        let other = (network, DeviceId(Uuid::from_u128(3)));
        let controller = SigningKey::from_bytes(&[10; 32]);
        let source_node = SigningKey::from_bytes(&[11; 32]);
        let other_node = SigningKey::from_bytes(&[12; 32]);
        let peers = HashMap::from([
            (
                source,
                PeerRecord {
                    endpoint: "127.0.0.1:5001".parse().unwrap(),
                    candidates: vec!["127.0.0.1:5001".parse().unwrap()],
                    assigned_addresses: vec!["100.64.0.1".parse().unwrap()],
                    certificate: test_certificate(
                        &controller,
                        &source_node,
                        network,
                        source.1,
                        "100.64.0.1",
                    ),
                    authorization_expires_at_unix_seconds: now() + 90,
                    last_seen: Instant::now(),
                },
            ),
            (
                other,
                PeerRecord {
                    endpoint: "127.0.0.1:5002".parse().unwrap(),
                    candidates: vec!["127.0.0.1:5002".parse().unwrap()],
                    assigned_addresses: vec!["100.64.0.2".parse().unwrap()],
                    certificate: test_certificate(
                        &controller,
                        &other_node,
                        network,
                        other.1,
                        "100.64.0.2",
                    ),
                    authorization_expires_at_unix_seconds: now() + 90,
                    last_seen: Instant::now(),
                },
            ),
        ]);
        assert_eq!(
            relay_targets(&peers, source, DeviceId(Uuid::nil())),
            vec!["127.0.0.1:5002".parse().unwrap()]
        );
        assert_eq!(
            relay_targets(&peers, source, other.1),
            vec!["127.0.0.1:5002".parse().unwrap()]
        );
    }

    #[test]
    fn virtual_address_conflict_is_rejected_per_network() {
        let network = NetworkId(Uuid::from_u128(31));
        let existing = (network, DeviceId(Uuid::from_u128(32)));
        let registering = (network, DeviceId(Uuid::from_u128(33)));
        let controller = SigningKey::from_bytes(&[13; 32]);
        let existing_node = SigningKey::from_bytes(&[14; 32]);
        let peers = HashMap::from([(
            existing,
            PeerRecord {
                endpoint: "127.0.0.1:5032".parse().unwrap(),
                candidates: vec!["127.0.0.1:5032".parse().unwrap()],
                assigned_addresses: vec!["100.64.31.2".parse().unwrap()],
                certificate: test_certificate(
                    &controller,
                    &existing_node,
                    network,
                    existing.1,
                    "100.64.31.2",
                ),
                authorization_expires_at_unix_seconds: now() + 90,
                last_seen: Instant::now(),
            },
        )]);
        assert!(has_address_conflict(
            &peers,
            registering,
            &["100.64.31.2".parse().unwrap()]
        ));
        assert!(!has_address_conflict(
            &peers,
            registering,
            &["100.64.31.3".parse().unwrap()]
        ));
    }

    #[test]
    fn registration_ack_binds_identity_transaction_endpoint_and_time() {
        let peer = (
            NetworkId(Uuid::from_u128(41)),
            DeviceId(Uuid::from_u128(42)),
        );
        let nonce = [43_u8; 16];
        let identity = test_relay_identity();
        let policy = meshlake_core::ServiceIdentityPolicy::stable(
            identity.relay_id,
            identity.current.verifying_key().to_bytes().to_vec(),
        );
        let acknowledgement = SignedRelayRegistrationAck::sign(
            peer.0,
            peer.1,
            identity.relay_id,
            nonce,
            "198.51.100.42:41000".parse().unwrap(),
            100,
            115,
            None,
            &[&identity.current],
        )
        .unwrap();
        assert_eq!(
            acknowledgement.verify(&policy, peer.0, peer.1, nonce, 105, 5),
            Ok(())
        );
        assert!(acknowledgement
            .verify(&policy, peer.0, peer.1, [44; 16], 105, 5)
            .is_err());
    }

    #[test]
    fn signed_registration_candidates_reject_invalid_values_and_are_bounded() {
        let observed: SocketAddr = "198.51.100.10:41000".parse().unwrap();
        let special = [
            "0.0.0.0:42000".parse().unwrap(),
            "[::]:42001".parse().unwrap(),
            "224.0.0.1:42002".parse().unwrap(),
            "[ff02::1]:42003".parse().unwrap(),
            "127.0.0.1:42004".parse().unwrap(),
            "[::1]:42005".parse().unwrap(),
            "255.255.255.255:42006".parse().unwrap(),
            "198.51.100.10:0".parse().unwrap(),
        ];
        assert!(special.iter().all(|candidate| !valid_candidate(*candidate)));
        let third_party: SocketAddr = "203.0.113.10:42007".parse().unwrap();
        let mut advertised = vec![
            special[0],
            special[1],
            special[2],
            special[3],
            special[4],
            special[5],
            special[6],
            special[7],
            third_party,
            observed,
        ];
        advertised.extend(
            (0..20).map(|offset| SocketAddr::new(observed.ip(), 43000_u16.saturating_add(offset))),
        );

        let candidates = accepted_candidates(observed, advertised);
        assert_eq!(candidates.len(), MAX_CANDIDATES_PER_PEER);
        assert_eq!(candidates[0], observed);
        assert!(candidates
            .iter()
            .all(|candidate| valid_candidate(*candidate)));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.ip() == observed.ip()));
        assert!(!candidates.contains(&third_party));
        assert_eq!(
            candidates
                .iter()
                .filter(|candidate| **candidate == observed)
                .count(),
            1
        );
    }

    #[test]
    fn signed_same_public_ip_mapping_candidate_is_distributed_once() {
        let controller = SigningKey::from_bytes(&[15; 32]);
        let node_one = SigningKey::from_bytes(&[16; 32]);
        let node_two = SigningKey::from_bytes(&[17; 32]);
        let network = NetworkId(Uuid::from_u128(51));
        let device_one = DeviceId(Uuid::from_u128(52));
        let device_two = DeviceId(Uuid::from_u128(53));
        let key_one = (network, device_one);
        let key_two = (network, device_two);
        let observed: SocketAddr = "198.51.100.51:45000".parse().unwrap();
        let mapping: SocketAddr = "198.51.100.51:45100".parse().unwrap();
        let certificate_one =
            test_certificate(&controller, &node_one, network, device_one, "100.64.51.1");
        let packet = signed_registration_packet_with_candidates(
            &controller,
            &node_one,
            certificate_one,
            vec![mapping, mapping, "203.0.113.51:45101".parse().unwrap()],
        );
        let registration = parse_signed_registration(
            &packet[5..],
            &controller.verifying_key().to_bytes().to_vec(),
        )
        .unwrap();
        let candidates = accepted_candidates(observed, registration.candidates);
        assert_eq!(candidates, vec![observed, mapping]);
        assert_eq!(
            candidate_delta(&candidates, &candidates),
            Vec::<SocketAddr>::new()
        );

        let peer_endpoint: SocketAddr = "192.0.2.53:45200".parse().unwrap();
        let certificate_two =
            test_certificate(&controller, &node_two, network, device_two, "100.64.51.2");
        let existing = vec![(
            key_two,
            PeerRecord {
                endpoint: peer_endpoint,
                candidates: vec![peer_endpoint],
                assigned_addresses: vec!["100.64.51.2".parse().unwrap()],
                certificate: certificate_two,
                authorization_expires_at_unix_seconds: now() + 90,
                last_seen: Instant::now(),
            },
        )];
        let fanout = registration_candidate_fanout(key_one, &candidates, observed, &existing);
        let expected = (peer_endpoint, peer_announcement(key_one, mapping));
        assert_eq!(
            fanout
                .iter()
                .filter(|outbound| **outbound == expected)
                .count(),
            1
        );
        assert!(fanout
            .iter()
            .any(|(target, packet)| *target == peer_endpoint
                && *packet == peer_announcement(key_one, observed)));
        assert!(registration_candidate_fanout(
            key_one,
            &candidate_delta(&candidates, &candidates),
            observed,
            &existing,
        )
        .iter()
        .all(|(target, packet)| *target == observed
            && *packet == peer_announcement(key_two, peer_endpoint)));
    }

    #[tokio::test]
    async fn unsigned_dynamic_candidate_cannot_alter_state_or_cause_fanout() {
        let controller = SigningKey::from_bytes(&[31; 32]);
        let source_node = SigningKey::from_bytes(&[32; 32]);
        let target_node = SigningKey::from_bytes(&[33; 32]);
        let network = NetworkId(Uuid::from_u128(54));
        let source = (network, DeviceId(Uuid::from_u128(55)));
        let target = (network, DeviceId(Uuid::from_u128(56)));
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source_endpoint = source_socket.local_addr().unwrap();
        let target_endpoint = target_socket.local_addr().unwrap();
        let mut peers = HashMap::from([
            (
                source,
                PeerRecord {
                    endpoint: source_endpoint,
                    candidates: vec![source_endpoint],
                    assigned_addresses: vec!["100.64.54.1".parse().unwrap()],
                    certificate: test_certificate(
                        &controller,
                        &source_node,
                        network,
                        source.1,
                        "100.64.54.1",
                    ),
                    authorization_expires_at_unix_seconds: now() + 90,
                    last_seen: Instant::now(),
                },
            ),
            (
                target,
                PeerRecord {
                    endpoint: target_endpoint,
                    candidates: vec![target_endpoint],
                    assigned_addresses: vec!["100.64.54.2".parse().unwrap()],
                    certificate: test_certificate(
                        &controller,
                        &target_node,
                        network,
                        target.1,
                        "100.64.54.2",
                    ),
                    authorization_expires_at_unix_seconds: now() + 90,
                    last_seen: Instant::now(),
                },
            ),
        ]);
        let original_candidates = peers.get(&source).unwrap().candidates.clone();
        let mut unsigned = peer_announcement(source, "203.0.113.54:45400".parse().unwrap());
        unsigned[4] = RELAY_CANDIDATE;

        handle_packet(
            &relay_socket,
            &controller.verifying_key().to_bytes().to_vec(),
            &mut peers,
            &mut HashMap::new(),
            source_endpoint,
            &unsigned,
        )
        .await
        .unwrap();

        assert_eq!(peers.get(&source).unwrap().candidates, original_candidates);
        let mut unexpected = [0_u8; 64];
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            target_socket.recv_from(&mut unexpected)
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn signed_registration_candidates_do_not_cross_networks() {
        let controller = SigningKey::from_bytes(&[18; 32]);
        let node_one = SigningKey::from_bytes(&[19; 32]);
        let node_two = SigningKey::from_bytes(&[20; 32]);
        let first_network = NetworkId(Uuid::from_u128(61));
        let second_network = NetworkId(Uuid::from_u128(62));
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let trusted_key = controller.verifying_key().to_bytes().to_vec();
        let mut peers = HashMap::new();
        let mut seen_nonces = HashMap::new();

        let first_certificate = test_certificate(
            &controller,
            &node_one,
            first_network,
            DeviceId(Uuid::from_u128(63)),
            "100.64.61.1",
        );
        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            client_one.local_addr().unwrap(),
            &signed_registration_packet_with_candidates(
                &controller,
                &node_one,
                first_certificate,
                vec!["203.0.113.61:46100".parse().unwrap()],
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            receive_datagram(&client_one).await[4],
            RELAY_REGISTER_ACK_SIGNED
        );

        let second_certificate = test_certificate(
            &controller,
            &node_two,
            second_network,
            DeviceId(Uuid::from_u128(64)),
            "100.64.62.1",
        );
        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            client_two.local_addr().unwrap(),
            &signed_registration_packet(&controller, &node_two, second_certificate),
        )
        .await
        .unwrap();
        assert_eq!(
            receive_datagram(&client_two).await[4],
            RELAY_REGISTER_ACK_SIGNED
        );

        for client in [&client_one, &client_two] {
            let mut unexpected = [0_u8; 64];
            assert!(tokio::time::timeout(
                Duration::from_millis(50),
                client.recv_from(&mut unexpected)
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn signed_members_discover_identity_and_receive_only_targeted_relay_data() {
        let controller = SigningKey::from_bytes(&[21; 32]);
        let node_one = SigningKey::from_bytes(&[22; 32]);
        let node_two = SigningKey::from_bytes(&[23; 32]);
        let network = NetworkId(Uuid::from_u128(71));
        let device_one = DeviceId(Uuid::from_u128(72));
        let device_two = DeviceId(Uuid::from_u128(73));
        let certificate_one =
            test_certificate(&controller, &node_one, network, device_one, "100.64.71.1");
        let certificate_two =
            test_certificate(&controller, &node_two, network, device_two, "100.64.71.2");
        let trusted_key = controller.verifying_key().to_bytes().to_vec();
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let replay_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut peers = HashMap::new();
        let mut seen_nonces = HashMap::new();
        let registration_one =
            signed_registration_packet(&controller, &node_one, certificate_one.clone());
        let registration_nonce = serde_json::from_slice::<RootRegistration>(&registration_one[5..])
            .unwrap()
            .payload
            .nonce;

        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            client_one.local_addr().unwrap(),
            &registration_one,
        )
        .await
        .unwrap();
        let acknowledgement = receive_datagram(&client_one).await;
        assert_eq!(acknowledgement[4], RELAY_REGISTER_ACK_SIGNED);
        let signed_ack: SignedRelayRegistrationAck =
            serde_json::from_slice(&acknowledgement[5..]).unwrap();
        assert_eq!(signed_ack.payload.request_nonce, registration_nonce);

        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            replay_client.local_addr().unwrap(),
            &registration_one,
        )
        .await
        .unwrap();
        assert_eq!(
            peers.get(&(network, device_one)).unwrap().endpoint,
            client_one.local_addr().unwrap()
        );
        let mut unexpected_ack = [0_u8; 64];
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            replay_client.recv_from(&mut unexpected_ack)
        )
        .await
        .is_err());

        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            client_two.local_addr().unwrap(),
            &signed_registration_packet(&controller, &node_two, certificate_two.clone()),
        )
        .await
        .unwrap();
        assert_eq!(
            receive_datagram(&client_two).await[4],
            RELAY_REGISTER_ACK_SIGNED
        );
        let one_messages = [
            receive_datagram(&client_one).await,
            receive_datagram(&client_one).await,
        ];
        assert!(one_messages.iter().any(|packet| packet[4] == RELAY_PEER));
        assert!(one_messages
            .iter()
            .filter_map(|packet| parse_peer_identity(packet))
            .any(|certificate| certificate == certificate_two));
        let two_messages = [
            receive_datagram(&client_two).await,
            receive_datagram(&client_two).await,
        ];
        assert!(two_messages.iter().any(|packet| packet[4] == RELAY_PEER));
        assert!(two_messages
            .iter()
            .filter_map(|packet| parse_peer_identity(packet))
            .any(|certificate| certificate == certificate_one));

        let mut targeted = relay_associated_data(network, device_one, device_two).to_vec();
        targeted.extend_from_slice(b"opaque-ciphertext");
        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            client_one.local_addr().unwrap(),
            &targeted,
        )
        .await
        .unwrap();
        assert_eq!(receive_datagram(&client_two).await, targeted);

        let network_key = NetworkKey::from_bytes([31_u8; 32]);
        let (pending, session_init) =
            InitiatorHandshake::start(network, device_one, device_two, &node_one, now()).unwrap();
        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            client_one.local_addr().unwrap(),
            &session_init,
        )
        .await
        .unwrap();
        let relayed_init = receive_datagram(&client_two).await;
        assert_eq!(relayed_init, session_init);
        let (two_keys, session_response) = accept_pairwise_handshake(
            &relayed_init,
            &node_one.verifying_key().to_bytes(),
            &node_two,
            &network_key,
            now(),
            120,
        )
        .unwrap();
        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            client_two.local_addr().unwrap(),
            &session_response,
        )
        .await
        .unwrap();
        let relayed_response = receive_datagram(&client_one).await;
        let one_keys = pending
            .complete(
                &relayed_response,
                &node_two.verifying_key().to_bytes(),
                &network_key,
                now(),
                120,
            )
            .unwrap();
        let session_data = one_keys
            .seal(network, device_one, device_two, 0, b"pairwise-over-relay")
            .unwrap();
        handle_packet(
            &relay_socket,
            &trusted_key,
            &mut peers,
            &mut seen_nonces,
            client_one.local_addr().unwrap(),
            &session_data,
        )
        .await
        .unwrap();
        let relayed_data = receive_datagram(&client_two).await;
        assert_eq!(
            two_keys
                .open(&mut ReplayWindow::default(), &relayed_data)
                .unwrap()
                .plaintext,
            b"pairwise-over-relay"
        );
        let mut unexpected = [0_u8; 64];
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            client_one.recv_from(&mut unexpected)
        )
        .await
        .is_err());
    }
}
