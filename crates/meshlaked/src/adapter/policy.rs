//! Pure, platform-neutral projection of verified per-network policy.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use meshlake_core::{DeviceId, JoinedNetwork, NetworkId};
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedRoute {
    pub prefix: String,
    pub network_id: NetworkId,
    pub gateway_device_id: DeviceId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct PolicyPlan {
    pub routes: Vec<PlannedRoute>,
    pub dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

impl PolicyPlan {
    pub fn from_networks(networks: &[JoinedNetwork], now_unix_seconds: u64) -> Result<Self> {
        let mut routes = BTreeMap::<String, PlannedRoute>::new();
        let mut dns_servers = Vec::new();
        let mut search_domains = Vec::new();
        let mut dns_owner: Option<NetworkId> = None;
        for joined in networks {
            let Some(policy) = &joined.control_plane.policy_manifest else {
                continue;
            };
            if policy.network_id != joined.network.id
                || now_unix_seconds > policy.expires_at_unix_seconds
            {
                bail!(
                    "network {} contains a stale or cross-network policy",
                    joined.network.id.0
                );
            }
            for route in &policy.routes {
                let parsed = route
                    .prefix
                    .parse::<IpNet>()
                    .with_context(|| format!("invalid policy route {}", route.prefix))?;
                if route.gateway_certificate.claims.network_id != joined.network.id {
                    bail!(
                        "policy route {} uses a gateway from another network",
                        route.prefix
                    );
                }
                if overlaps_virtual_prefix(joined, parsed)? {
                    bail!(
                        "policy route {} overlaps network {} virtual address space",
                        route.prefix,
                        joined.network.id.0
                    );
                }
                let planned = PlannedRoute {
                    prefix: parsed.to_string(),
                    network_id: joined.network.id,
                    gateway_device_id: route.gateway_certificate.claims.device_id,
                };
                if let Some(previous) = routes.insert(planned.prefix.clone(), planned.clone()) {
                    if previous.network_id != planned.network_id
                        || previous.gateway_device_id != planned.gateway_device_id
                    {
                        bail!(
                            "policy route {} is ambiguous across networks or gateways",
                            planned.prefix
                        );
                    }
                }
            }
            if !policy.dns.servers.is_empty() || !policy.dns.search_domains.is_empty() {
                if let Some(owner) = dns_owner {
                    bail!(
                        "DNS policy is present on both network {} and network {}; refusing cross-network DNS mixing",
                        owner.0,
                        joined.network.id.0
                    );
                }
                dns_owner = Some(joined.network.id);
                dns_servers.extend(policy.dns.servers.iter().copied());
                search_domains.extend(policy.dns.search_domains.iter().cloned());
            }
        }
        dns_servers.sort();
        dns_servers.dedup();
        search_domains.sort();
        search_domains.dedup();
        if !search_domains.is_empty() && dns_servers.is_empty() {
            bail!("search domains require at least one policy DNS server");
        }
        Ok(Self {
            routes: routes.into_values().collect(),
            dns_servers,
            search_domains,
        })
    }
}

fn overlaps_virtual_prefix(joined: &JoinedNetwork, route: IpNet) -> Result<bool> {
    let ipv4 = joined
        .network
        .ipv4_prefix
        .parse::<IpNet>()
        .context("invalid joined-network IPv4 prefix")?;
    let ipv6 = joined
        .network
        .ipv6_prefix
        .as_deref()
        .map(str::parse::<IpNet>)
        .transpose()
        .context("invalid joined-network IPv6 prefix")?;
    Ok(nets_overlap(route, ipv4) || ipv6.is_some_and(|prefix| nets_overlap(route, prefix)))
}

fn nets_overlap(left: IpNet, right: IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V6(left), IpNet::V6(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use meshlake_core::{
        DnsPolicy, MembershipCertificate, MembershipClaims, NetworkControlPlane,
        NetworkPolicyManifest, PolicyRoute, RelayPolicy, VirtualNetwork,
    };
    use uuid::Uuid;

    fn network(id: u128, route: &str, gateway: u128) -> JoinedNetwork {
        let signing = SigningKey::from_bytes(&[id as u8; 32]);
        let network_id = NetworkId(Uuid::from_u128(id));
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id,
                device_id: DeviceId(Uuid::from_u128(gateway)),
                device_public_key: vec![1; 32],
                assigned_addresses: vec!["100.64.1.2".parse().unwrap()],
                allowed_routes: vec![route.into()],
                issued_at_unix_seconds: 1,
                expires_at_unix_seconds: Some(100),
            },
            Uuid::from_u128(gateway + 100),
            1,
            &signing,
        )
        .unwrap();
        let policy = NetworkPolicyManifest::sign(
            network_id,
            1,
            vec![PolicyRoute {
                prefix: route.into(),
                gateway_certificate: certificate,
            }],
            DnsPolicy {
                servers: vec!["10.0.0.53".parse().unwrap()],
                search_domains: vec![format!("n{id}.example")],
            },
            1,
            100,
            &signing,
        )
        .unwrap();
        JoinedNetwork {
            network: VirtualNetwork {
                id: network_id,
                name: format!("n{id}"),
                ipv4_prefix: format!("100.64.{id}.0/24"),
                ipv6_prefix: None,
                relay_policy: RelayPolicy::Preferred,
            },
            assigned_addresses: vec![format!("100.64.{id}.1").parse().unwrap()],
            certificate: None,
            network_key: vec![1; 32],
            control_plane: NetworkControlPlane {
                policy_manifest: Some(policy),
                ..NetworkControlPlane::default()
            },
        }
    }

    #[test]
    fn combines_non_conflicting_dual_network_policy() {
        let first = network(1, "10.1.0.0/16", 10);
        let mut second = network(2, "2001:db8:2::/64", 20);
        second.control_plane.policy_manifest.as_mut().unwrap().dns = DnsPolicy::default();
        let plan = PolicyPlan::from_networks(&[first, second], 50).unwrap();
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.search_domains, vec!["n1.example"]);
    }

    #[test]
    fn rejects_dns_policy_from_multiple_networks() {
        assert!(PolicyPlan::from_networks(
            &[network(5, "10.5.0.0/16", 50), network(6, "10.6.0.0/16", 60),],
            50,
        )
        .is_err());
    }

    #[test]
    fn rejects_cross_network_same_prefix_and_stale_policy() {
        assert!(PolicyPlan::from_networks(
            &[network(1, "10.0.0.0/8", 10), network(2, "10.0.0.0/8", 20)],
            50,
        )
        .is_err());
        assert!(PolicyPlan::from_networks(&[network(3, "10.3.0.0/16", 30)], 101).is_err());
    }

    #[test]
    fn rejects_routes_overlapping_overlay_address_space() {
        assert!(PolicyPlan::from_networks(&[network(4, "100.64.4.0/25", 40)], 50).is_err());
    }
}
