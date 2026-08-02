//! Sanitized, versioned local API types for pairwise-session observability.
//!
//! These structures intentionally contain identifiers, coarse path/state
//! metadata and counters only. Session keys, network keys, packet bytes and
//! handshake material must never be added to this API.

use crate::{DeviceId, NetworkId};
use serde::{Deserialize, Serialize};

pub const SESSION_API_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionList {
    pub schema_version: u32,
    pub generated_at_unix_ms: u64,
    pub transport_revision: u64,
    pub sessions: Vec<SessionObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionObservation {
    pub network_id: NetworkId,
    pub peer_device_id: DeviceId,
    pub state: SessionState,
    pub path: SessionPath,
    pub age_ms: u64,
    pub queue: SessionQueueCounters,
    pub security: SessionSecurityCounters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Pending,
    Established,
    Expired,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPath {
    #[default]
    Unknown,
    Direct,
    Relay,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionQueueCounters {
    pub queued_packets: u64,
    pub queue_capacity: u64,
    pub dropped_packets: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSecurityCounters {
    pub handshake_attempts: u64,
    pub handshake_retries: u64,
    /// Pairwise-encrypted data packets accepted by the local UDP transport.
    /// Sealed packets whose `send_to` fails are not counted.
    pub encrypted_packets_sent: u64,
    pub authenticated_packets_received: u64,
    pub rejected_packets_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn serialized_observation_has_only_sanitized_metadata() {
        let observation = SessionObservation {
            network_id: NetworkId(Uuid::from_u128(1)),
            peer_device_id: DeviceId(Uuid::from_u128(2)),
            state: SessionState::Established,
            path: SessionPath::Direct,
            age_ms: 1250,
            queue: SessionQueueCounters::default(),
            security: SessionSecurityCounters {
                encrypted_packets_sent: 3,
                authenticated_packets_received: 4,
                ..SessionSecurityCounters::default()
            },
        };

        let value = serde_json::to_value(observation).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "age_ms",
                "network_id",
                "path",
                "peer_device_id",
                "queue",
                "security",
                "state"
            ]
        );
        let encoded = serde_json::to_string(&value).unwrap();
        for forbidden in [
            "session_key",
            "network_key",
            "private_key",
            "handshake_packet",
            "plaintext",
            "ciphertext",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
