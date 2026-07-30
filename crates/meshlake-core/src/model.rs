use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;
use uuid::Uuid;

/// Stable identity of an overlay device. In a production controller this is bound to a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub Uuid);

/// Stable identity of one isolated MeshLake virtual network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NetworkId(pub Uuid);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayPolicy {
    /// Try a direct encrypted path when available; use a relay as a reliable fallback.
    Preferred,
    /// Always forward encrypted traffic through a selected relay.
    Required,
    /// Never relay; connectivity requires a direct path.
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualNetwork {
    pub id: NetworkId,
    pub name: String,
    pub ipv4_prefix: String,
    pub ipv6_prefix: Option<String>,
    pub relay_policy: RelayPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub assigned_addresses: Vec<IpAddr>,
    pub allowed_routes: Vec<String>,
}

/// A network currently enrolled on this device. It contains no enrollment secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinedNetwork {
    pub network: VirtualNetwork,
    pub assigned_addresses: Vec<IpAddr>,
    /// Present for controller-enrolled networks. Older local development records omit it.
    #[serde(default)]
    pub certificate: Option<crate::crypto::MembershipCertificate>,
    /// Persisted only by a device agent. It is never returned by the controller network list.
    #[serde(default)]
    pub network_key: Vec<u8>,
}

/// JSON request accepted by the local MeshLake agent to create or join a network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpsertNetworkRequest {
    pub id: Option<NetworkId>,
    pub name: String,
    pub ipv4_prefix: String,
    pub ipv6_prefix: Option<String>,
    pub relay_policy: RelayPolicy,
}

/// One-time enrollment proof. The agent deliberately does not persist the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    #[serde(flatten)]
    pub network: UpsertNetworkRequest,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatus {
    pub device_id: DeviceId,
    /// Public Ed25519 node identity. The corresponding secret never leaves
    /// the local agent state.
    #[serde(default)]
    pub identity_public_key: Vec<u8>,
    pub adapter_state: String,
    pub networks: Vec<JoinedNetwork>,
    #[serde(default)]
    pub transport: TransportStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportStatus {
    pub worker_running: bool,
    pub configured_roots: Vec<SocketAddr>,
    pub responsive_roots: Vec<SocketAddr>,
    pub configured_relays: Vec<SocketAddr>,
    pub healthy_relays: Vec<SocketAddr>,
    #[serde(default)]
    pub peer_paths: Vec<PeerPathStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerPathStatus {
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub endpoint: SocketAddr,
    pub smoothed_rtt_ms: Option<u64>,
    pub consecutive_failures: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("network name must contain at least one non-whitespace character")]
    EmptyNetworkName,
    #[error("a membership needs at least one virtual address")]
    MissingAddress,
    #[error("ipv4 prefix must look like 100.64.0.0/24")]
    InvalidIpv4Prefix,
    #[error("ipv6 prefix must look like fd00::/64")]
    InvalidIpv6Prefix,
}

impl VirtualNetwork {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.name.trim().is_empty() {
            return Err(ModelError::EmptyNetworkName);
        }
        Ok(())
    }
}

impl Membership {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.assigned_addresses.is_empty() {
            return Err(ModelError::MissingAddress);
        }
        Ok(())
    }
}

impl UpsertNetworkRequest {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.name.trim().is_empty() {
            return Err(ModelError::EmptyNetworkName);
        }
        if self.ipv4_prefix.parse::<Ipv4Net>().is_err() {
            return Err(ModelError::InvalidIpv4Prefix);
        }
        if self
            .ipv6_prefix
            .as_deref()
            .is_some_and(|prefix| prefix.parse::<Ipv6Net>().is_err())
        {
            return Err(ModelError::InvalidIpv6Prefix);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_empty_network_name() {
        let network = VirtualNetwork {
            id: NetworkId(Uuid::nil()),
            name: " ".into(),
            ipv4_prefix: "100.64.0.0/24".into(),
            ipv6_prefix: None,
            relay_policy: RelayPolicy::Preferred,
        };
        assert_eq!(network.validate(), Err(ModelError::EmptyNetworkName));
    }

    #[test]
    fn validates_an_ipv4_prefix() {
        let request = UpsertNetworkRequest {
            id: None,
            name: "home".into(),
            ipv4_prefix: "100.64.12.0/24".into(),
            ipv6_prefix: None,
            relay_policy: RelayPolicy::Preferred,
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn validates_and_rejects_ipv6_prefixes() {
        let mut request = UpsertNetworkRequest {
            id: None,
            name: "dual-stack".into(),
            ipv4_prefix: "100.64.12.0/24".into(),
            ipv6_prefix: Some("fd42:4d4c::/64".into()),
            relay_policy: RelayPolicy::Preferred,
        };
        assert!(request.validate().is_ok());
        request.ipv6_prefix = Some("not-an-ipv6-prefix".into());
        assert_eq!(request.validate(), Err(ModelError::InvalidIpv6Prefix));
    }

    #[test]
    fn older_transport_status_defaults_peer_paths() {
        let status: TransportStatus = serde_json::from_str(
            r#"{
                "worker_running": true,
                "configured_roots": [],
                "responsive_roots": [],
                "configured_relays": [],
                "healthy_relays": []
            }"#,
        )
        .unwrap();
        assert!(status.peer_paths.is_empty());
    }
}
