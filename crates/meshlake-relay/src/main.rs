//! Blind UDP relay for MeshLake encrypted overlay frames.
//!
//! The relay authenticates controller-signed membership certificates during registration,
//! then forwards opaque ciphertext only. It never receives MeshLake network keys.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use meshlake_core::{
    peer_identity_announcement, DeviceId, MembershipCertificate, NetworkId, RootRegistration,
    RELAY_CANDIDATE, RELAY_DATA, RELAY_DATA_HEADER_LEN, RELAY_MAGIC, RELAY_PEER,
    RELAY_REGISTER_ACK, RELAY_REGISTER_SIGNED, RELAY_SESSION_DATA, RELAY_SESSION_INIT,
    RELAY_SESSION_RESPONSE,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
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
}

type PeerKey = (NetworkId, DeviceId);
const PEER_TTL: Duration = Duration::from_secs(90);
const REGISTRATION_NONCE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct PeerRecord {
    endpoint: SocketAddr,
    assigned_addresses: Vec<IpAddr>,
    certificate: MembershipCertificate,
    authorization_expires_at_unix_seconds: u64,
    last_seen: Instant,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let trusted_key = decode_controller_key(&cli.controller_public_key_base64)?;
    let socket = UdpSocket::bind(cli.bind).await?;
    println!("MeshLake relay listening on udp://{}", cli.bind);
    println!("The relay forwards encrypted payloads only.");

    let mut peers: HashMap<PeerKey, PeerRecord> = HashMap::new();
    let mut seen_nonces = HashMap::<[u8; 16], Instant>::new();
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
            &mut peers,
            &mut seen_nonces,
            remote,
            packet,
        )
        .await?;
    }
}

async fn handle_packet(
    socket: &UdpSocket,
    trusted_key: &Vec<u8>,
    peers: &mut HashMap<PeerKey, PeerRecord>,
    seen_nonces: &mut HashMap<[u8; 16], Instant>,
    remote: SocketAddr,
    packet: &[u8],
) -> Result<()> {
    match packet[4] {
        RELAY_REGISTER_SIGNED => {
            if let Some((key, certificate, nonce, authorization_expires_at_unix_seconds)) =
                parse_signed_registration(&packet[5..], trusted_key)
            {
                seen_nonces.retain(|_, seen| seen.elapsed() <= REGISTRATION_NONCE_TTL);
                if seen_nonces.insert(nonce, Instant::now()).is_some() {
                    trace_transport(format!(
                        "rejected replayed registration for member {}",
                        key.1 .0
                    ));
                    return Ok(());
                }
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
                        assigned_addresses: assigned_addresses.clone(),
                        certificate: certificate.clone(),
                        authorization_expires_at_unix_seconds,
                        last_seen: Instant::now(),
                    },
                );
                socket.send_to(&registration_ack(key), remote).await?;
                trace_transport(format!(
                    "registered member {} for network {} from {remote}",
                    key.1 .0, key.0 .0
                ));
                for (peer_key, peer) in existing {
                    socket
                        .send_to(&peer_announcement(key, remote), peer.endpoint)
                        .await?;
                    socket
                        .send_to(&peer_announcement(peer_key, peer.endpoint), remote)
                        .await?;
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
            if let Some((key, candidate)) = parse_candidate(packet) {
                if peers.get(&key).map(|peer| peer.endpoint) != Some(remote) {
                    return Ok(());
                }
                for (peer_key, peer) in peers {
                    if peer_key.0 == key.0 && *peer_key != key {
                        socket
                            .send_to(&peer_announcement(key, candidate), peer.endpoint)
                            .await?;
                    }
                }
                trace_transport(format!(
                    "distributed a server-reflexive candidate for member {}",
                    key.1 .0
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn registration_ack(peer: PeerKey) -> [u8; 37] {
    let mut packet = [0_u8; 37];
    packet[..4].copy_from_slice(&RELAY_MAGIC);
    packet[4] = RELAY_REGISTER_ACK;
    packet[5..21].copy_from_slice((peer.0).0.as_bytes());
    packet[21..37].copy_from_slice((peer.1).0.as_bytes());
    packet
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

/// Candidate control frame: magic + kind + network UUID + device UUID +
/// address family + port (big endian) + IP address. It intentionally shares
/// the endpoint encoding of [`peer_announcement`].
fn parse_candidate(packet: &[u8]) -> Option<(PeerKey, SocketAddr)> {
    if packet.len() < 40 || packet[..4] != RELAY_MAGIC || packet[4] != RELAY_CANDIDATE {
        return None;
    }
    let network = NetworkId(Uuid::from_slice(&packet[5..21]).ok()?);
    let device = DeviceId(Uuid::from_slice(&packet[21..37]).ok()?);
    let port = u16::from_be_bytes(packet[38..40].try_into().ok()?);
    let endpoint = match packet[37] {
        4 if packet.len() == 44 => SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(
                packet[40], packet[41], packet[42], packet[43],
            )),
            port,
        ),
        6 if packet.len() == 56 => {
            let octets: [u8; 16] = packet[40..56].try_into().ok()?;
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
        }
        _ => return None,
    };
    Some(((network, device), endpoint))
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
) -> Option<(PeerKey, MembershipCertificate, [u8; 16], u64)> {
    let registration: RootRegistration = serde_json::from_slice(bytes).ok()?;
    registration
        .verify_authorized(std::slice::from_ref(trusted_controller_key), now(), 120)
        .ok()?;
    if registration.payload.certificates.len() != 1 {
        return None;
    }
    let nonce = registration.payload.nonce;
    let certificate = registration.payload.certificates.into_iter().next()?;
    let authorization_expires_at_unix_seconds = registration
        .payload
        .authorization_manifests
        .iter()
        .find(|authorization| authorization.network_id == certificate.claims.network_id)?
        .expires_at_unix_seconds;
    let key = (certificate.claims.network_id, certificate.claims.device_id);
    (certificate.claims.device_id == registration.payload.device_id).then_some((
        key,
        certificate,
        nonce,
        authorization_expires_at_unix_seconds,
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use meshlake_core::{
        accept_pairwise_handshake, parse_peer_identity, relay_associated_data,
        AuthorizedMembership, InitiatorHandshake, MembershipClaims, NetworkAuthorizationManifest,
        NetworkKey, ReplayWindow,
    };

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
            vec![],
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
        let (key, decoded, nonce, authorization_expires_at) =
            parse_signed_registration(&raw, &controller.verifying_key().to_bytes().to_vec())
                .unwrap();
        assert_eq!(
            key,
            (certificate.claims.network_id, certificate.claims.device_id)
        );
        assert_eq!(decoded, certificate);
        assert_eq!(nonce, registration.payload.nonce);
        assert!(authorization_expires_at >= now());

        let legacy = RootRegistration::sign(
            device,
            vec![decoded.clone()],
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
            vec![decoded],
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
    fn registration_ack_contains_authenticated_peer_identity() {
        let peer = (
            NetworkId(Uuid::from_u128(41)),
            DeviceId(Uuid::from_u128(42)),
        );
        let packet = registration_ack(peer);
        assert_eq!(&packet[..5], b"MLR1\x06");
        assert_eq!(Uuid::from_slice(&packet[5..21]).unwrap(), peer.0 .0);
        assert_eq!(Uuid::from_slice(&packet[21..37]).unwrap(), peer.1 .0);
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
        assert_eq!(receive_datagram(&client_one).await[4], RELAY_REGISTER_ACK);

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
        assert_eq!(receive_datagram(&client_two).await[4], RELAY_REGISTER_ACK);
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
