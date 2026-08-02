//! UDP relay envelope definitions.
//!
//! Relay routing metadata is deliberately small and plaintext. The payload following a
//! [`RELAY_DATA_HEADER_LEN`] byte header must be encrypted by the originating device.

use crate::{
    AuthorizationEpochHint, DeviceId, MembershipCertificate, NetworkId, ServiceIdentityError,
    ServiceIdentityPolicy, ServiceSignature,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use thiserror::Error;
use uuid::Uuid;

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
/// Versioned JSON acknowledgement signed by the Planet-pinned Relay identity.
pub const RELAY_REGISTER_ACK_SIGNED: u8 = 13;
pub const RELAY_ACK_PROTOCOL_VERSION: u8 = 2;
const RELAY_ACK_DOMAIN: &[u8] = b"MeshLake relay registration acknowledgement v2\0";
const MAX_RELAY_ACK_LIFETIME_SECONDS: u64 = 30;
pub const RELAY_DATA_HEADER_LEN: usize = 53;
pub const RELAY_MAX_ASSIGNED_ADDRESSES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayReceiverEndpoint {
    /// The public source endpoint observed when the Relay accepted the signed
    /// registration. It is descriptive NAT state, not an authorization input.
    ObservedRegistrationSource { endpoint: SocketAddr },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRegistrationAckPayload {
    pub version: u8,
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub relay_id: Uuid,
    pub request_nonce: [u8; 16],
    pub receiver: RelayReceiverEndpoint,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub authorization_hint: Option<AuthorizationEpochHint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRelayRegistrationAck {
    pub payload: RelayRegistrationAckPayload,
    pub signatures: Vec<ServiceSignature>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayProtocolError {
    #[error("relay acknowledgement has an unsupported version")]
    UnsupportedVersion,
    #[error("relay acknowledgement does not match the registration transaction")]
    TransactionMismatch,
    #[error("relay acknowledgement is expired, from the future, or has an excessive lifetime")]
    InvalidLifetime,
    #[error("relay acknowledgement endpoint semantics are invalid")]
    InvalidReceiverEndpoint,
    #[error("relay acknowledgement cannot be encoded")]
    EncodingFailed,
    #[error(transparent)]
    InvalidServiceIdentity(#[from] ServiceIdentityError),
}

impl SignedRelayRegistrationAck {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        network_id: NetworkId,
        device_id: DeviceId,
        relay_id: Uuid,
        request_nonce: [u8; 16],
        observed_registration_source: SocketAddr,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        authorization_hint: Option<AuthorizationEpochHint>,
        signing_keys: &[&SigningKey],
    ) -> Result<Self, RelayProtocolError> {
        let payload = RelayRegistrationAckPayload {
            version: RELAY_ACK_PROTOCOL_VERSION,
            network_id,
            device_id,
            relay_id,
            request_nonce,
            receiver: RelayReceiverEndpoint::ObservedRegistrationSource {
                endpoint: observed_registration_source,
            },
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            authorization_hint,
        };
        let message = relay_ack_message(&payload)?;
        Ok(Self {
            payload,
            signatures: signing_keys
                .iter()
                .map(|key| ServiceSignature {
                    public_key: key.verifying_key().to_bytes().to_vec(),
                    signature: key.sign(&message).to_bytes().to_vec(),
                })
                .collect(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        identity: &ServiceIdentityPolicy,
        expected_network_id: NetworkId,
        expected_device_id: DeviceId,
        expected_nonce: [u8; 16],
        now_unix_seconds: u64,
        maximum_future_skew_seconds: u64,
    ) -> Result<(), RelayProtocolError> {
        if self.payload.version != RELAY_ACK_PROTOCOL_VERSION {
            return Err(RelayProtocolError::UnsupportedVersion);
        }
        if self.payload.network_id != expected_network_id
            || self.payload.device_id != expected_device_id
            || self.payload.relay_id != identity.service_id
            || self.payload.request_nonce != expected_nonce
        {
            return Err(RelayProtocolError::TransactionMismatch);
        }
        if self.payload.expires_at_unix_seconds < self.payload.issued_at_unix_seconds
            || self
                .payload
                .expires_at_unix_seconds
                .saturating_sub(self.payload.issued_at_unix_seconds)
                > MAX_RELAY_ACK_LIFETIME_SECONDS
            || self.payload.issued_at_unix_seconds
                > now_unix_seconds.saturating_add(maximum_future_skew_seconds)
            || now_unix_seconds > self.payload.expires_at_unix_seconds
        {
            return Err(RelayProtocolError::InvalidLifetime);
        }
        match self.payload.receiver {
            RelayReceiverEndpoint::ObservedRegistrationSource { endpoint }
                if endpoint.port() != 0
                    && !endpoint.ip().is_unspecified()
                    && !endpoint.ip().is_multicast() => {}
            _ => return Err(RelayProtocolError::InvalidReceiverEndpoint),
        }
        identity.verify_signatures(
            &relay_ack_message(&self.payload)?,
            &self.signatures,
            now_unix_seconds,
        )?;
        Ok(())
    }
}

fn relay_ack_message(payload: &RelayRegistrationAckPayload) -> Result<Vec<u8>, RelayProtocolError> {
    let mut message = Vec::from(RELAY_ACK_DOMAIN);
    message.extend_from_slice(
        &serde_json::to_vec(payload).map_err(|_| RelayProtocolError::EncodingFailed)?,
    );
    Ok(message)
}

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
    use crate::{MembershipClaims, ServiceIdentityPolicy};
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

    fn signed_ack(
        relay: &SigningKey,
        relay_id: Uuid,
        network: NetworkId,
        device: DeviceId,
        nonce: [u8; 16],
    ) -> SignedRelayRegistrationAck {
        SignedRelayRegistrationAck::sign(
            network,
            device,
            relay_id,
            nonce,
            "198.51.100.10:41000".parse().unwrap(),
            100,
            115,
            None,
            &[relay],
        )
        .unwrap()
    }

    #[test]
    fn signed_ack_rejects_tampering_wrong_pin_and_cross_scope_reuse() {
        let relay = SigningKey::from_bytes(&[10; 32]);
        let other_relay = SigningKey::from_bytes(&[11; 32]);
        let relay_id = Uuid::from_u128(12);
        let network = NetworkId(Uuid::from_u128(13));
        let device = DeviceId(Uuid::from_u128(14));
        let nonce = [15; 16];
        let policy =
            ServiceIdentityPolicy::stable(relay_id, relay.verifying_key().to_bytes().to_vec());
        let acknowledgement = signed_ack(&relay, relay_id, network, device, nonce);
        assert_eq!(
            acknowledgement.verify(&policy, network, device, nonce, 105, 5),
            Ok(())
        );
        assert!(acknowledgement
            .verify(
                &ServiceIdentityPolicy::stable(
                    relay_id,
                    other_relay.verifying_key().to_bytes().to_vec(),
                ),
                network,
                device,
                nonce,
                105,
                5,
            )
            .is_err());
        assert!(acknowledgement
            .verify(
                &policy,
                NetworkId(Uuid::from_u128(16)),
                device,
                nonce,
                105,
                5,
            )
            .is_err());
        let mut tampered = acknowledgement;
        tampered.payload.device_id = DeviceId(Uuid::from_u128(17));
        assert!(tampered
            .verify(&policy, network, tampered.payload.device_id, nonce, 105, 5)
            .is_err());
    }

    #[test]
    fn signed_ack_rejects_expired_future_and_nonce_values() {
        let relay = SigningKey::from_bytes(&[20; 32]);
        let relay_id = Uuid::from_u128(21);
        let network = NetworkId(Uuid::from_u128(22));
        let device = DeviceId(Uuid::from_u128(23));
        let nonce = [24; 16];
        let policy =
            ServiceIdentityPolicy::stable(relay_id, relay.verifying_key().to_bytes().to_vec());
        let acknowledgement = signed_ack(&relay, relay_id, network, device, nonce);
        assert!(acknowledgement
            .verify(&policy, network, device, nonce, 116, 5)
            .is_err());
        assert!(acknowledgement
            .verify(&policy, network, device, nonce, 90, 5)
            .is_err());
        assert!(acknowledgement
            .verify(&policy, network, device, [25; 16], 105, 5)
            .is_err());
    }
}
