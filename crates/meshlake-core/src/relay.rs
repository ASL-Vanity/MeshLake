//! UDP relay envelope definitions.
//!
//! Relay routing metadata is deliberately small and plaintext. The payload following a
//! [`RELAY_DATA_HEADER_LEN`] byte header must be encrypted by the originating device.

use crate::{DeviceId, MembershipCertificate, NetworkId};

pub const RELAY_MAGIC: [u8; 4] = *b"MLR1";
pub const RELAY_REGISTER: u8 = 1;
pub const RELAY_DATA: u8 = 2;
/// Sent by a trusted relay to reveal another authenticated member's observed
/// public UDP endpoint. Clients use it to start UDP hole punching.
pub const RELAY_PEER: u8 = 3;
/// Stateless UDP hole-punch probe sent directly between members.
pub const RELAY_PUNCH: u8 = 4;
/// An authenticated member's server-reflexive (STUN) UDP candidate. The relay
/// distributes it as an ordinary [`RELAY_PEER`] announcement; no network key is
/// included in this control frame.
pub const RELAY_CANDIDATE: u8 = 5;
/// Registration acknowledgement emitted only after the relay has verified a
/// controller-signed membership certificate. The 53-byte frame carries the
/// network ID, device ID, and the 16-byte nonce from the signed registration so
/// clients can bind relay health to one fresh registration transaction.
/// This is a transaction-bound liveness response, not a relay-signed identity
/// assertion.
pub const RELAY_REGISTER_ACK: u8 = 6;
/// Direct response to a punch request. Unlike [`RELAY_PUNCH`], acknowledgements
/// are never answered again, preventing an infinite UDP echo loop.
pub const RELAY_PUNCH_ACK: u8 = 7;
/// Controller-authorized virtual addresses owned by one authenticated peer.
/// This is sent in addition to [`RELAY_PEER`] so older clients retain endpoint
/// discovery while newer clients can build a true unicast routing directory.
pub const RELAY_PEER_IDENTITY: u8 = 8;
/// Device-signed registration carrying one controller-authorized membership.
/// Unlike the legacy [`RELAY_REGISTER`] frame, this proves possession of the
/// device identity secret and prevents certificate replay from another endpoint.
pub const RELAY_REGISTER_SIGNED: u8 = 9;
/// Device-signed ephemeral X25519 handshake initiation routed to one member.
pub const RELAY_SESSION_INIT: u8 = 10;
/// Device-signed response that completes an ephemeral X25519 handshake.
pub const RELAY_SESSION_RESPONSE: u8 = 11;
/// Pairwise-encrypted data carrying a session identifier and packet sequence.
pub const RELAY_SESSION_DATA: u8 = 12;
pub const RELAY_DATA_HEADER_LEN: usize = 53;
pub const RELAY_MAX_ASSIGNED_ADDRESSES: usize = 16;

/// Returns the immutable UDP relay header that must be supplied as AEAD associated data.
pub fn relay_associated_data(
    network_id: NetworkId,
    source: DeviceId,
    destination: DeviceId,
) -> [u8; RELAY_DATA_HEADER_LEN] {
    let mut header = [0_u8; RELAY_DATA_HEADER_LEN];
    header[..4].copy_from_slice(&RELAY_MAGIC);
    header[4] = RELAY_DATA;
    header[5..21].copy_from_slice(network_id.0.as_bytes());
    header[21..37].copy_from_slice(source.0.as_bytes());
    header[37..53].copy_from_slice(destination.0.as_bytes());
    header
}

pub fn peer_identity_announcement(
    certificate: &MembershipCertificate,
) -> Result<Vec<u8>, serde_json::Error> {
    let encoded = serde_json::to_vec(certificate)?;
    let mut packet = Vec::with_capacity(5 + encoded.len());
    packet.extend_from_slice(&RELAY_MAGIC);
    packet.push(RELAY_PEER_IDENTITY);
    packet.extend_from_slice(&encoded);
    Ok(packet)
}

pub fn parse_peer_identity(packet: &[u8]) -> Option<MembershipCertificate> {
    if packet.len() <= 5 || packet[..4] != RELAY_MAGIC || packet[4] != RELAY_PEER_IDENTITY {
        return None;
    }
    serde_json::from_slice(&packet[5..]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MembershipClaims;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    #[test]
    fn associated_data_binds_all_routing_fields() {
        let header = relay_associated_data(
            NetworkId(Uuid::from_u128(1)),
            DeviceId(Uuid::from_u128(2)),
            DeviceId(Uuid::from_u128(3)),
        );
        assert_eq!(&header[..5], b"MLR1\x02");
        assert_ne!(
            header,
            relay_associated_data(
                NetworkId(Uuid::from_u128(1)),
                DeviceId(Uuid::from_u128(2)),
                DeviceId(Uuid::from_u128(4)),
            )
        );
    }

    #[test]
    fn peer_identity_round_trip_carries_dual_stack_addresses() {
        let controller = SigningKey::from_bytes(&[9_u8; 32]);
        let network = NetworkId(Uuid::from_u128(11));
        let device = DeviceId(Uuid::from_u128(12));
        let certificate = MembershipCertificate::sign(
            MembershipClaims {
                network_id: network,
                device_id: device,
                device_public_key: vec![7; 32],
                assigned_addresses: vec![
                    "100.64.11.2".parse().unwrap(),
                    "fd42:4d4c:11::2".parse().unwrap(),
                ],
                allowed_routes: vec!["100.64.11.0/24".into(), "fd42:4d4c:11::/64".into()],
                issued_at_unix_seconds: 10,
                expires_at_unix_seconds: None,
            },
            &controller,
        )
        .unwrap();
        let packet = peer_identity_announcement(&certificate).unwrap();
        assert_eq!(parse_peer_identity(&packet), Some(certificate));

        let mut trailing = packet;
        trailing.push(0);
        assert!(parse_peer_identity(&trailing).is_none());
    }
}
