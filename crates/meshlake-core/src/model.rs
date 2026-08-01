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

/// Verified control-plane data owned by one joined virtual network.
///
/// This deliberately lives with the network instead of in device-global
/// state: one MeshLake agent may join networks that use different controllers
/// and Planet deployments. Values in this structure are written only after
/// their signed source data has been verified against the pinned controller
/// public key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkControlPlane {
    /// Controller URL used for enrollment and later authorization refreshes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_url: Option<String>,
    /// Raw 32-byte Ed25519 controller public key pinned during enrollment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_controller_public_key: Vec<u8>,
    /// Optional PEM trust anchor carried by a trusted invitation. When set,
    /// controller HTTPS clients trust only this CA instead of system roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_tls_ca_pem: Option<String>,
    /// URL from which the currently verified Planet manifest was obtained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planet_manifest_url: Option<String>,
    /// Roots copied from a verified Planet manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_roots: Vec<crate::crypto::PlanetRoot>,
    /// Relays copied from a verified Planet manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_relays: Vec<crate::crypto::PlanetRelay>,
    /// STUN server names copied from a verified Planet manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_stun_servers: Vec<String>,
    /// Latest controller-signed authorization state for this network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_manifest: Option<crate::authorization::NetworkAuthorizationManifest>,
}

impl NetworkControlPlane {
    /// Returns whether this contains no persisted control-plane information.
    pub fn is_empty(&self) -> bool {
        self.controller_url.is_none()
            && self.pinned_controller_public_key.is_empty()
            && self.controller_tls_ca_pem.is_none()
            && self.planet_manifest_url.is_none()
            && self.verified_roots.is_empty()
            && self.verified_relays.is_empty()
            && self.verified_stun_servers.is_empty()
            && self.authorization_manifest.is_none()
    }
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
    /// Per-network controller and Planet state. Older device records omit it.
    #[serde(default, skip_serializing_if = "NetworkControlPlane::is_empty")]
    pub control_plane: NetworkControlPlane,
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
    use crate::{NetworkAuthorizationManifest, PlanetRelay, PlanetRoot};

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

    #[test]
    fn older_joined_network_defaults_control_plane_metadata() {
        let joined: JoinedNetwork = serde_json::from_str(
            r#"{
                "network": {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "legacy-network",
                    "ipv4_prefix": "100.64.1.0/24",
                    "ipv6_prefix": null,
                    "relay_policy": "Preferred"
                },
                "assigned_addresses": ["100.64.1.2"],
                "certificate": null,
                "network_key": [1, 2, 3]
            }"#,
        )
        .unwrap();

        assert_eq!(joined.control_plane, NetworkControlPlane::default());
        assert!(joined.control_plane.is_empty());

        let serialized = serde_json::to_value(&joined).unwrap();
        assert!(serialized.get("control_plane").is_none());
    }

    #[test]
    fn control_plane_round_trips_verified_per_network_metadata() {
        let joined = JoinedNetwork {
            network: VirtualNetwork {
                id: NetworkId(Uuid::from_u128(2)),
                name: "planet-a".into(),
                ipv4_prefix: "100.64.2.0/24".into(),
                ipv6_prefix: Some("fd42:4d4c:2::/64".into()),
                relay_policy: RelayPolicy::Preferred,
            },
            assigned_addresses: vec!["100.64.2.2".parse().unwrap()],
            certificate: None,
            network_key: vec![9; 32],
            control_plane: NetworkControlPlane {
                controller_url: Some("https://controller.example".into()),
                pinned_controller_public_key: vec![7; 32],
                controller_tls_ca_pem: Some(
                    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".into(),
                ),
                planet_manifest_url: Some("https://planet.example/manifest.json".into()),
                verified_roots: vec![PlanetRoot {
                    public_key: vec![8; 32],
                    endpoints: vec!["203.0.113.1:51819".parse().unwrap()],
                    priority: 10,
                }],
                verified_relays: vec![PlanetRelay {
                    endpoint: "203.0.113.2:51820".parse().unwrap(),
                    priority: 20,
                }],
                verified_stun_servers: vec!["stun.example:3478".into()],
                authorization_manifest: Some(NetworkAuthorizationManifest {
                    version: 1,
                    network_id: NetworkId(Uuid::from_u128(2)),
                    authorization_epoch: 3,
                    network_key_epoch: 4,
                    active_members: Vec::new(),
                    revoked_certificate_ids: Vec::new(),
                    issued_at_unix_seconds: 100,
                    expires_at_unix_seconds: 200,
                    controller_public_key: vec![7; 32],
                    signature: vec![6; 64],
                }),
            },
        };

        let serialized = serde_json::to_value(&joined).unwrap();
        assert_eq!(
            serialized["control_plane"]["controller_url"],
            "https://controller.example"
        );
        assert_eq!(
            serialized["control_plane"]["planet_manifest_url"],
            "https://planet.example/manifest.json"
        );
        assert!(serialized["control_plane"]["controller_tls_ca_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert_eq!(
            serialized["control_plane"]["authorization_manifest"]["authorization_epoch"],
            3
        );

        let restored: JoinedNetwork = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored, joined);
    }
}
