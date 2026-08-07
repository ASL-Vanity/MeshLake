//! Controller-signed routes and split-DNS policy for one virtual network.

use crate::{MembershipCertificate, NetworkAuthorizationManifest, NetworkId};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};
use thiserror::Error;

/// The current policy manifest version. Version 1 remains valid for split
/// routing-only policies so an Agent can safely read persisted pre-exit-node
/// state during a rolling upgrade.
pub const NETWORK_POLICY_MANIFEST_VERSION: u8 = 2;
const NETWORK_POLICY_MANIFEST_VERSION_V1: u8 = 1;
const MAX_ROUTES: usize = 256;
const MAX_EXIT_NODES: usize = 16;
const MAX_DNS_SERVERS: usize = 8;
const MAX_SEARCH_DOMAINS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRoute {
    /// Canonical IPv4 or IPv6 destination prefix. Default routes are forbidden
    /// until the separate exit-node design is implemented.
    pub prefix: String,
    /// Controller-signed certificate for the member that may forward this
    /// prefix. Its `allowed_routes` claim must cover `prefix`.
    pub gateway_certificate: MembershipCertificate,
}

/// A controller-authorized member that may be selected locally as an Internet
/// exit gateway. This is deliberately separate from `PolicyRoute`: publishing
/// an exit candidate never installs a default route on other members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitNode {
    /// Controller-signed membership certificate for the gateway member.
    pub gateway_certificate: MembershipCertificate,
    /// The gateway is authorized to carry an IPv4 default route when a member
    /// explicitly selects it locally.
    pub supports_ipv4: bool,
    /// The gateway is authorized to carry an IPv6 default route when a member
    /// explicitly selects it locally.
    pub supports_ipv6: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPolicy {
    #[serde(default)]
    pub servers: Vec<IpAddr>,
    #[serde(default)]
    pub search_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyManifest {
    pub version: u8,
    pub network_id: NetworkId,
    pub policy_epoch: u64,
    pub routes: Vec<PolicyRoute>,
    /// Exit candidates are present only in version 2 manifests. A candidate is
    /// not active until a member makes a separate local selection.
    #[serde(default)]
    pub exit_nodes: Vec<ExitNode>,
    #[serde(default)]
    pub dns: DnsPolicy,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub controller_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct PolicyPayloadV1<'a> {
    version: u8,
    network_id: NetworkId,
    policy_epoch: u64,
    routes: &'a [PolicyRoute],
    dns: &'a DnsPolicy,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    controller_public_key: &'a [u8],
}

#[derive(Serialize)]
struct PolicyPayloadV2<'a> {
    version: u8,
    network_id: NetworkId,
    policy_epoch: u64,
    routes: &'a [PolicyRoute],
    exit_nodes: &'a [ExitNode],
    dns: &'a DnsPolicy,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    controller_public_key: &'a [u8],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    #[error("network policy was not issued by the pinned controller")]
    UntrustedController,
    #[error("network policy is malformed or has an invalid signature")]
    InvalidSignature,
    #[error("network policy is expired or not yet valid")]
    Expired,
    #[error("network policy belongs to another network")]
    CrossNetwork,
    #[error("network policy epoch is not newer than the applied policy")]
    Rollback,
    #[error("network policy contains an invalid or non-canonical route prefix")]
    InvalidRoute,
    #[error("default routes are not supported in this stage")]
    DefaultRoute,
    #[error("network policy uses an unsupported version")]
    UnsupportedVersion,
    #[error("network policy assigns the same prefix more than once")]
    AmbiguousRoute,
    #[error("route gateway certificate is invalid, inactive, or unauthorized for the prefix")]
    UnauthorizedGateway,
    #[error("exit node certificate is invalid, inactive, cross-network, or ambiguous")]
    InvalidExitNode,
    #[error("network policy DNS settings are invalid")]
    InvalidDns,
    #[error("network policy cannot be encoded")]
    EncodingFailed,
}

impl NetworkPolicyManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        network_id: NetworkId,
        policy_epoch: u64,
        routes: Vec<PolicyRoute>,
        dns: DnsPolicy,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, PolicyError> {
        Self::sign_with_exit_nodes(
            network_id,
            policy_epoch,
            routes,
            Vec::new(),
            dns,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            signing_key,
        )
    }

    /// Signs a version 2 manifest containing controller-authorized exit
    /// candidates. Callers must still make a local selection before a default
    /// route can be projected onto the host.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_exit_nodes(
        network_id: NetworkId,
        policy_epoch: u64,
        mut routes: Vec<PolicyRoute>,
        mut exit_nodes: Vec<ExitNode>,
        mut dns: DnsPolicy,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, PolicyError> {
        if policy_epoch == 0 {
            return Err(PolicyError::Rollback);
        }
        normalize_policy(&mut routes, &mut dns)?;
        normalize_exit_nodes(&mut exit_nodes)?;
        let controller_public_key = signing_key.verifying_key().to_bytes().to_vec();
        let version = if exit_nodes.is_empty() {
            NETWORK_POLICY_MANIFEST_VERSION_V1
        } else {
            NETWORK_POLICY_MANIFEST_VERSION
        };
        let payload = encoded_policy_payload(
            version,
            network_id,
            policy_epoch,
            &routes,
            &exit_nodes,
            &dns,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            &controller_public_key,
        )?;
        Ok(Self {
            version,
            network_id,
            policy_epoch,
            routes,
            exit_nodes,
            dns,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key,
            signature: signing_key.sign(&payload).to_bytes().to_vec(),
        })
    }

    /// Verifies controller trust, freshness, monotonicity, gateway membership,
    /// and every gateway's signed route authorization.
    pub fn verify_for_network(
        &self,
        expected_network_id: NetworkId,
        trusted_controller_public_key: &[u8],
        authorization: &NetworkAuthorizationManifest,
        now_unix_seconds: u64,
        previous_policy_epoch: Option<u64>,
    ) -> Result<(), PolicyError> {
        if !matches!(
            self.version,
            NETWORK_POLICY_MANIFEST_VERSION_V1 | NETWORK_POLICY_MANIFEST_VERSION
        ) {
            return Err(PolicyError::UnsupportedVersion);
        }
        if self.controller_public_key != trusted_controller_public_key {
            return Err(PolicyError::UntrustedController);
        }
        if self.network_id != expected_network_id || authorization.network_id != expected_network_id
        {
            return Err(PolicyError::CrossNetwork);
        }
        if self.policy_epoch == 0 {
            return Err(PolicyError::Rollback);
        }
        authorization
            .verify_from_controller(trusted_controller_public_key, now_unix_seconds)
            .map_err(|_| PolicyError::UnauthorizedGateway)?;
        if previous_policy_epoch.is_some_and(|epoch| self.policy_epoch <= epoch) {
            return Err(PolicyError::Rollback);
        }
        if now_unix_seconds > self.expires_at_unix_seconds
            || self.issued_at_unix_seconds > now_unix_seconds.saturating_add(120)
            || self.expires_at_unix_seconds <= self.issued_at_unix_seconds
        {
            return Err(PolicyError::Expired);
        }
        validate_normalized_policy(&self.routes, &self.dns)?;
        validate_exit_nodes(&self.exit_nodes)?;
        if self.version == NETWORK_POLICY_MANIFEST_VERSION_V1 && !self.exit_nodes.is_empty() {
            return Err(PolicyError::UnsupportedVersion);
        }

        let public_key: [u8; 32] = self
            .controller_public_key
            .as_slice()
            .try_into()
            .map_err(|_| PolicyError::InvalidSignature)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| PolicyError::InvalidSignature)?;
        let encoded = encoded_policy_payload(
            self.version,
            self.network_id,
            self.policy_epoch,
            &self.routes,
            &self.exit_nodes,
            &self.dns,
            self.issued_at_unix_seconds,
            self.expires_at_unix_seconds,
            &self.controller_public_key,
        )?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| PolicyError::InvalidSignature)?
            .verify(&encoded, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| PolicyError::InvalidSignature)?;

        for route in &self.routes {
            let certificate = &route.gateway_certificate;
            certificate
                .verify_from_controller(trusted_controller_public_key, now_unix_seconds)
                .map_err(|_| PolicyError::UnauthorizedGateway)?;
            if certificate.claims.network_id != expected_network_id
                || !authorization.authorizes(certificate)
                || !certificate
                    .claims
                    .allowed_routes
                    .iter()
                    .any(|allowed| prefix_covers(allowed, &route.prefix))
            {
                return Err(PolicyError::UnauthorizedGateway);
            }
        }
        for exit_node in &self.exit_nodes {
            let certificate = &exit_node.gateway_certificate;
            certificate
                .verify_from_controller(trusted_controller_public_key, now_unix_seconds)
                .map_err(|_| PolicyError::InvalidExitNode)?;
            if certificate.claims.network_id != expected_network_id
                || !authorization.authorizes(certificate)
            {
                return Err(PolicyError::InvalidExitNode);
            }
        }
        Ok(())
    }

    pub fn gateway_for(&self, destination: IpAddr) -> Option<crate::DeviceId> {
        self.routes
            .iter()
            .filter_map(|route| {
                let prefix = route.prefix.parse::<IpNet>().ok()?;
                prefix.contains(&destination).then_some((
                    prefix.prefix_len(),
                    route.gateway_certificate.claims.device_id,
                ))
            })
            .max_by_key(|(prefix_len, _)| *prefix_len)
            .map(|(_, gateway)| gateway)
    }

    /// Returns whether one controller-authorized exit candidate can carry the
    /// requested address family. This deliberately says nothing about local
    /// selection; the Agent owns that separate, user-controlled preference.
    pub fn exit_node_supports(&self, device_id: crate::DeviceId, destination: IpAddr) -> bool {
        self.exit_nodes.iter().any(|exit_node| {
            exit_node.gateway_certificate.claims.device_id == device_id
                && match destination {
                    IpAddr::V4(_) => exit_node.supports_ipv4,
                    IpAddr::V6(_) => exit_node.supports_ipv6,
                }
        })
    }
}

fn normalize_policy(routes: &mut Vec<PolicyRoute>, dns: &mut DnsPolicy) -> Result<(), PolicyError> {
    for route in routes.iter_mut() {
        let prefix = parse_route(&route.prefix)?;
        route.prefix = prefix.to_string();
    }
    routes.sort_by(|left, right| left.prefix.cmp(&right.prefix));
    dns.servers.sort();
    dns.servers.dedup();
    for domain in &mut dns.search_domains {
        *domain = normalize_domain(domain)?;
    }
    dns.search_domains.sort();
    dns.search_domains.dedup();
    validate_normalized_policy(routes, dns)
}

fn normalize_exit_nodes(exit_nodes: &mut Vec<ExitNode>) -> Result<(), PolicyError> {
    exit_nodes.sort_by_key(|exit_node| exit_node.gateway_certificate.claims.device_id.0);
    validate_exit_nodes(exit_nodes)
}

fn validate_exit_nodes(exit_nodes: &[ExitNode]) -> Result<(), PolicyError> {
    if exit_nodes.len() > MAX_EXIT_NODES {
        return Err(PolicyError::InvalidExitNode);
    }
    let mut devices = BTreeSet::new();
    for exit_node in exit_nodes {
        let device_id = exit_node.gateway_certificate.claims.device_id.0;
        if (!exit_node.supports_ipv4 && !exit_node.supports_ipv6) || !devices.insert(device_id) {
            return Err(PolicyError::InvalidExitNode);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encoded_policy_payload(
    version: u8,
    network_id: NetworkId,
    policy_epoch: u64,
    routes: &[PolicyRoute],
    exit_nodes: &[ExitNode],
    dns: &DnsPolicy,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    controller_public_key: &[u8],
) -> Result<Vec<u8>, PolicyError> {
    match version {
        NETWORK_POLICY_MANIFEST_VERSION_V1 if exit_nodes.is_empty() => {
            serde_json::to_vec(&PolicyPayloadV1 {
                version,
                network_id,
                policy_epoch,
                routes,
                dns,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
                controller_public_key,
            })
            .map_err(|_| PolicyError::EncodingFailed)
        }
        NETWORK_POLICY_MANIFEST_VERSION => serde_json::to_vec(&PolicyPayloadV2 {
            version,
            network_id,
            policy_epoch,
            routes,
            exit_nodes,
            dns,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key,
        })
        .map_err(|_| PolicyError::EncodingFailed),
        _ => Err(PolicyError::UnsupportedVersion),
    }
}

fn validate_normalized_policy(routes: &[PolicyRoute], dns: &DnsPolicy) -> Result<(), PolicyError> {
    if routes.len() > MAX_ROUTES {
        return Err(PolicyError::InvalidRoute);
    }
    let mut prefixes = BTreeSet::new();
    for route in routes {
        let prefix = parse_route(&route.prefix)?;
        if prefix.to_string() != route.prefix {
            return Err(PolicyError::InvalidRoute);
        }
        if !prefixes.insert(route.prefix.as_str()) {
            return Err(PolicyError::AmbiguousRoute);
        }
    }
    if dns.servers.len() > MAX_DNS_SERVERS
        || dns.search_domains.len() > MAX_SEARCH_DOMAINS
        || (!dns.search_domains.is_empty() && dns.servers.is_empty())
        || dns.servers.iter().copied().collect::<BTreeSet<_>>().len() != dns.servers.len()
    {
        return Err(PolicyError::InvalidDns);
    }
    if dns.servers.iter().any(|server| match server {
        IpAddr::V4(server) => {
            server.is_unspecified() || server.is_multicast() || server.is_broadcast()
        }
        IpAddr::V6(server) => server.is_unspecified() || server.is_multicast(),
    }) {
        return Err(PolicyError::InvalidDns);
    }
    let mut domains = BTreeSet::new();
    for domain in &dns.search_domains {
        if normalize_domain(domain).as_deref() != Ok(domain.as_str()) || !domains.insert(domain) {
            return Err(PolicyError::InvalidDns);
        }
    }
    Ok(())
}

fn parse_route(raw: &str) -> Result<IpNet, PolicyError> {
    let prefix = raw
        .parse::<IpNet>()
        .map_err(|_| PolicyError::InvalidRoute)?;
    if matches!(prefix, IpNet::V4(prefix) if prefix.prefix_len() == 0)
        || matches!(prefix, IpNet::V6(prefix) if prefix.prefix_len() == 0)
    {
        return Err(PolicyError::DefaultRoute);
    }
    Ok(prefix)
}

fn prefix_covers(allowed: &str, target: &str) -> bool {
    match (allowed.parse::<IpNet>(), target.parse::<IpNet>()) {
        (Ok(IpNet::V4(allowed)), Ok(IpNet::V4(target))) => {
            allowed.prefix_len() <= target.prefix_len() && allowed.contains(&target.network())
        }
        (Ok(IpNet::V6(allowed)), Ok(IpNet::V6(target))) => {
            allowed.prefix_len() <= target.prefix_len() && allowed.contains(&target.network())
        }
        _ => false,
    }
}

fn normalize_domain(raw: &str) -> Result<String, PolicyError> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(PolicyError::InvalidDns);
    }
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizedMembership, DeviceId, MembershipClaims};
    use uuid::Uuid;

    fn fixture(
        allowed_routes: Vec<String>,
    ) -> (
        SigningKey,
        NetworkId,
        MembershipCertificate,
        NetworkAuthorizationManifest,
    ) {
        let signing = SigningKey::from_bytes(&[31; 32]);
        let network_id = NetworkId(Uuid::from_u128(1));
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id,
                device_id: DeviceId(Uuid::from_u128(2)),
                device_public_key: vec![9; 32],
                assigned_addresses: vec!["100.64.1.2".parse().unwrap()],
                allowed_routes,
                issued_at_unix_seconds: 10,
                expires_at_unix_seconds: Some(1000),
            },
            Uuid::from_u128(3),
            1,
            &signing,
        )
        .unwrap();
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            1,
            1,
            vec![AuthorizedMembership {
                device_id: certificate.claims.device_id,
                certificate_id: certificate.certificate_id,
                device_public_key: certificate.claims.device_public_key.clone(),
                network_key_epoch: 1,
            }],
            vec![],
            10,
            1000,
            &signing,
        )
        .unwrap();
        (signing, network_id, certificate, authorization)
    }

    #[test]
    fn signed_policy_verifies_gateway_authorization_and_longest_prefix() {
        let (signing, network_id, certificate, authorization) =
            fixture(vec!["10.0.0.0/8".into(), "2001:db8:10::/48".into()]);
        let policy = NetworkPolicyManifest::sign(
            network_id,
            4,
            vec![
                PolicyRoute {
                    prefix: "10.20.0.0/16".into(),
                    gateway_certificate: certificate.clone(),
                },
                PolicyRoute {
                    prefix: "10.20.30.0/24".into(),
                    gateway_certificate: certificate.clone(),
                },
                PolicyRoute {
                    prefix: "2001:db8:10:1::/64".into(),
                    gateway_certificate: certificate,
                },
            ],
            DnsPolicy {
                servers: vec!["10.20.0.53".parse().unwrap()],
                search_domains: vec!["Corp.Example.".into()],
            },
            20,
            900,
            &signing,
        )
        .unwrap();
        assert_eq!(
            policy.verify_for_network(
                network_id,
                &signing.verifying_key().to_bytes(),
                &authorization,
                30,
                Some(3)
            ),
            Ok(())
        );
        assert_eq!(policy.dns.search_domains, vec!["corp.example"]);
        assert_eq!(
            policy.gateway_for("10.20.30.9".parse().unwrap()),
            Some(DeviceId(Uuid::from_u128(2)))
        );
    }

    #[test]
    fn rejects_defaults_duplicates_cross_network_expiry_rollback_and_uncovered_routes() {
        let (signing, network_id, certificate, authorization) = fixture(vec!["10.0.0.0/9".into()]);
        for prefix in ["0.0.0.0/0", "::/0"] {
            assert_eq!(
                NetworkPolicyManifest::sign(
                    network_id,
                    1,
                    vec![PolicyRoute {
                        prefix: prefix.into(),
                        gateway_certificate: certificate.clone()
                    }],
                    DnsPolicy::default(),
                    1,
                    10,
                    &signing
                ),
                Err(PolicyError::DefaultRoute)
            );
        }
        let policy = NetworkPolicyManifest::sign(
            network_id,
            2,
            vec![PolicyRoute {
                prefix: "10.128.0.0/9".into(),
                gateway_certificate: certificate,
            }],
            DnsPolicy::default(),
            10,
            100,
            &signing,
        )
        .unwrap();
        assert_eq!(
            policy.verify_for_network(
                network_id,
                &signing.verifying_key().to_bytes(),
                &authorization,
                20,
                Some(2)
            ),
            Err(PolicyError::Rollback)
        );
        assert_eq!(
            policy.verify_for_network(
                NetworkId(Uuid::from_u128(99)),
                &signing.verifying_key().to_bytes(),
                &authorization,
                20,
                None
            ),
            Err(PolicyError::CrossNetwork)
        );
        assert_eq!(
            policy.verify_for_network(
                network_id,
                &signing.verifying_key().to_bytes(),
                &authorization,
                101,
                None
            ),
            Err(PolicyError::Expired)
        );
        assert_eq!(
            policy.verify_for_network(
                network_id,
                &signing.verifying_key().to_bytes(),
                &authorization,
                20,
                None
            ),
            Err(PolicyError::UnauthorizedGateway)
        );
    }

    #[test]
    fn rejects_invalid_dns_domains() {
        let (signing, network_id, _, _) = fixture(vec![]);
        assert_eq!(
            NetworkPolicyManifest::sign(
                network_id,
                1,
                vec![],
                DnsPolicy {
                    servers: vec![],
                    search_domains: vec!["bad_domain".into()]
                },
                1,
                2,
                &signing
            ),
            Err(PolicyError::InvalidDns)
        );
    }

    #[test]
    fn signed_exit_candidates_are_versioned_authorized_and_not_default_routes() {
        let (signing, network_id, certificate, authorization) = fixture(vec![]);
        let legacy = NetworkPolicyManifest::sign(
            network_id,
            1,
            vec![],
            DnsPolicy::default(),
            10,
            100,
            &signing,
        )
        .unwrap();
        assert_eq!(legacy.version, NETWORK_POLICY_MANIFEST_VERSION_V1);
        assert!(legacy.exit_nodes.is_empty());

        let policy = NetworkPolicyManifest::sign_with_exit_nodes(
            network_id,
            2,
            vec![],
            vec![ExitNode {
                gateway_certificate: certificate.clone(),
                supports_ipv4: true,
                supports_ipv6: false,
            }],
            DnsPolicy::default(),
            10,
            100,
            &signing,
        )
        .unwrap();
        assert_eq!(policy.version, NETWORK_POLICY_MANIFEST_VERSION);
        assert_eq!(
            policy.verify_for_network(
                network_id,
                &signing.verifying_key().to_bytes(),
                &authorization,
                20,
                Some(1),
            ),
            Ok(())
        );
        assert!(
            policy.exit_node_supports(certificate.claims.device_id, "203.0.113.9".parse().unwrap())
        );
        assert!(!policy
            .exit_node_supports(certificate.claims.device_id, "2001:db8::9".parse().unwrap()));
        assert_eq!(
            NetworkPolicyManifest::sign_with_exit_nodes(
                network_id,
                2,
                vec![],
                vec![ExitNode {
                    gateway_certificate: certificate.clone(),
                    supports_ipv4: false,
                    supports_ipv6: false,
                }],
                DnsPolicy::default(),
                10,
                100,
                &signing,
            ),
            Err(PolicyError::InvalidExitNode)
        );
        assert_eq!(
            NetworkPolicyManifest::sign_with_exit_nodes(
                network_id,
                2,
                vec![],
                vec![
                    ExitNode {
                        gateway_certificate: certificate.clone(),
                        supports_ipv4: true,
                        supports_ipv6: false,
                    },
                    ExitNode {
                        gateway_certificate: certificate,
                        supports_ipv4: false,
                        supports_ipv6: true,
                    },
                ],
                DnsPolicy::default(),
                10,
                100,
                &signing,
            ),
            Err(PolicyError::InvalidExitNode)
        );
    }
}
