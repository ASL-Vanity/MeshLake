//! Pure, platform-neutral projection of verified per-network policy.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use meshlake_core::{DeviceId, JoinedNetwork, NetworkId};
use std::{collections::BTreeMap, fmt, net::IpAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedRoute {
    pub prefix: String,
    pub network_id: NetworkId,
    pub gateway_device_id: DeviceId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct PolicyPlan {
    pub routes: Vec<PlannedRoute>,
    /// Locally selected, controller-authorized default routes. Kept separate
    /// from split routes so platform adapters can apply stronger safeguards.
    pub exit_routes: Vec<PlannedRoute>,
    pub exit_kill_switch: bool,
    pub dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

impl PolicyPlan {
    pub fn from_networks(networks: &[JoinedNetwork], now_unix_seconds: u64) -> Result<Self> {
        let mut routes = BTreeMap::<String, PlannedRoute>::new();
        let mut exit_routes = BTreeMap::<String, PlannedRoute>::new();
        let mut exit_kill_switch = false;
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
            let selection = &joined.control_plane.exit_node_selection;
            if selection.kill_switch
                && selection.ipv4_gateway.is_none()
                && selection.ipv6_gateway.is_none()
            {
                bail!(
                    "network {} enables an exit kill switch without selecting an exit gateway",
                    joined.network.id.0
                );
            }
            for (gateway, prefix, probe) in [
                (
                    selection.ipv4_gateway,
                    "0.0.0.0/0",
                    "192.0.2.1".parse::<IpAddr>().expect("literal IPv4 address"),
                ),
                (
                    selection.ipv6_gateway,
                    "::/0",
                    "2001:db8::1"
                        .parse::<IpAddr>()
                        .expect("literal IPv6 address"),
                ),
            ] {
                let Some(gateway_device_id) = gateway else {
                    continue;
                };
                policy
                    .verify_for_network(
                        joined.network.id,
                        &joined.control_plane.pinned_controller_public_key,
                        joined
                            .control_plane
                            .authorization_manifest
                            .as_ref()
                            .context("exit selection requires controller authorization")?,
                        now_unix_seconds,
                        None,
                    )
                    .with_context(|| {
                        format!(
                            "network {} exit selection has no current verified policy",
                            joined.network.id.0
                        )
                    })?;
                if !policy.exit_node_supports(gateway_device_id, probe) {
                    bail!(
                        "network {} selected gateway {} is not authorized for exit route {prefix}",
                        joined.network.id.0,
                        gateway_device_id.0
                    );
                }
                let planned = PlannedRoute {
                    prefix: prefix.into(),
                    network_id: joined.network.id,
                    gateway_device_id,
                };
                if let Some(previous) = exit_routes.insert(planned.prefix.clone(), planned.clone())
                {
                    if previous.network_id != planned.network_id
                        || previous.gateway_device_id != planned.gateway_device_id
                    {
                        bail!(
                            "exit route {} is ambiguous across networks or gateways",
                            planned.prefix
                        );
                    }
                }
                exit_kill_switch |= selection.kill_switch;
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
            exit_routes: exit_routes.into_values().collect(),
            exit_kill_switch,
            dns_servers,
            search_domains,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PolicyTransactionError {
    RolledBack {
        stage: &'static str,
        primary: String,
    },
    FailClosed {
        stage: &'static str,
        primary: String,
        recovery_failures: Vec<String>,
    },
}

impl PolicyTransactionError {
    pub fn is_fail_closed(&self) -> bool {
        matches!(self, Self::FailClosed { .. })
    }
}

impl fmt::Display for PolicyTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RolledBack { stage, primary } => write!(
                formatter,
                "policy transaction failed while {stage}: {primary}; previous policy was restored"
            ),
            Self::FailClosed {
                stage,
                primary,
                recovery_failures,
            } => write!(
                formatter,
                "policy transaction failed while {stage}: {primary}; recovery failed: {}; adapter must fail closed",
                recovery_failures.join("; ")
            ),
        }
    }
}

impl std::error::Error for PolicyTransactionError {}

pub(super) fn apply_policy_transaction(
    mut remove_previous: impl FnMut() -> std::result::Result<(), String>,
    mut apply_desired: impl FnMut() -> std::result::Result<(), String>,
    mut remove_desired: impl FnMut() -> std::result::Result<(), String>,
    mut restore_previous: impl FnMut() -> std::result::Result<(), String>,
) -> std::result::Result<(), PolicyTransactionError> {
    if let Err(primary) = remove_previous() {
        return recover_policy_transaction(
            "removing the previous policy",
            primary,
            &mut remove_desired,
            &mut remove_previous,
            &mut restore_previous,
        );
    }
    if let Err(primary) = apply_desired() {
        return recover_policy_transaction(
            "applying the desired policy",
            primary,
            &mut remove_desired,
            &mut remove_previous,
            &mut restore_previous,
        );
    }
    Ok(())
}

pub(super) fn finalize_policy_transaction(
    current: &mut PolicyPlan,
    desired: PolicyPlan,
    result: std::result::Result<(), PolicyTransactionError>,
) -> std::result::Result<(), PolicyTransactionError> {
    match result {
        Ok(()) => {
            *current = desired;
            Ok(())
        }
        Err(error) => {
            if error.is_fail_closed() {
                *current = PolicyPlan::default();
            }
            Err(error)
        }
    }
}

fn recover_policy_transaction(
    stage: &'static str,
    primary: String,
    remove_desired: &mut impl FnMut() -> std::result::Result<(), String>,
    remove_previous: &mut impl FnMut() -> std::result::Result<(), String>,
    restore_previous: &mut impl FnMut() -> std::result::Result<(), String>,
) -> std::result::Result<(), PolicyTransactionError> {
    let mut recovery_failures = Vec::new();
    if let Err(error) = remove_desired() {
        recovery_failures.push(format!("desired-policy cleanup: {error}"));
    }
    if let Err(error) = remove_previous() {
        recovery_failures.push(format!("previous-policy cleanup: {error}"));
    }
    if let Err(error) = restore_previous() {
        recovery_failures.push(format!("previous-policy restore: {error}"));
    }
    if recovery_failures.is_empty() {
        Err(PolicyTransactionError::RolledBack { stage, primary })
    } else {
        Err(PolicyTransactionError::FailClosed {
            stage,
            primary,
            recovery_failures,
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
        AuthorizedMembership, DnsPolicy, ExitNode, ExitNodeSelection, MembershipCertificate,
        MembershipClaims, NetworkAuthorizationManifest, NetworkControlPlane, NetworkPolicyManifest,
        PolicyRoute, RelayPolicy, VirtualNetwork,
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
    fn projects_only_explicitly_selected_signed_exit_routes() {
        let signing = SigningKey::from_bytes(&[71; 32]);
        let network_id = NetworkId(Uuid::from_u128(71));
        let gateway = DeviceId(Uuid::from_u128(72));
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id,
                device_id: gateway,
                device_public_key: vec![7; 32],
                assigned_addresses: vec!["100.64.71.2".parse().unwrap()],
                allowed_routes: vec!["100.64.71.0/24".into()],
                issued_at_unix_seconds: 1,
                expires_at_unix_seconds: Some(100),
            },
            Uuid::from_u128(73),
            1,
            &signing,
        )
        .unwrap();
        let authorization = NetworkAuthorizationManifest::sign(
            network_id,
            1,
            1,
            vec![AuthorizedMembership {
                device_id: gateway,
                certificate_id: certificate.certificate_id,
                device_public_key: certificate.claims.device_public_key.clone(),
                network_key_epoch: 1,
            }],
            vec![],
            1,
            100,
            &signing,
        )
        .unwrap();
        let policy = NetworkPolicyManifest::sign_with_exit_nodes(
            network_id,
            1,
            vec![],
            vec![ExitNode {
                gateway_certificate: certificate,
                supports_ipv4: true,
                supports_ipv6: true,
            }],
            DnsPolicy::default(),
            1,
            100,
            &signing,
        )
        .unwrap();
        let joined = JoinedNetwork {
            network: VirtualNetwork {
                id: network_id,
                name: "exit".into(),
                ipv4_prefix: "100.64.71.0/24".into(),
                ipv6_prefix: Some("fd42:4d4c:71::/64".into()),
                relay_policy: RelayPolicy::Preferred,
            },
            assigned_addresses: vec!["100.64.71.1".parse().unwrap()],
            certificate: None,
            network_key: vec![1; 32],
            control_plane: NetworkControlPlane {
                pinned_controller_public_key: signing.verifying_key().to_bytes().to_vec(),
                authorization_manifest: Some(authorization),
                policy_manifest: Some(policy),
                exit_node_selection: ExitNodeSelection {
                    ipv4_gateway: Some(gateway),
                    ipv6_gateway: Some(gateway),
                    kill_switch: true,
                },
                ..NetworkControlPlane::default()
            },
        };
        let plan = PolicyPlan::from_networks(&[joined], 50).unwrap();
        assert_eq!(
            plan.exit_routes
                .iter()
                .map(|route| route.prefix.as_str())
                .collect::<Vec<_>>(),
            vec!["0.0.0.0/0", "::/0"]
        );
        assert!(plan.exit_kill_switch);
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

    #[test]
    fn command_failure_during_apply_restores_previous_policy() {
        let calls = std::cell::RefCell::new(Vec::new());
        let result = apply_policy_transaction(
            || {
                calls.borrow_mut().push("remove-previous");
                Ok(())
            },
            || {
                calls.borrow_mut().push("apply-desired");
                Err("injected apply failure".into())
            },
            || {
                calls.borrow_mut().push("remove-desired");
                Ok(())
            },
            || {
                calls.borrow_mut().push("restore-previous");
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(PolicyTransactionError::RolledBack { .. })
        ));
        assert_eq!(
            calls.into_inner(),
            vec![
                "remove-previous",
                "apply-desired",
                "remove-desired",
                "remove-previous",
                "restore-previous"
            ]
        );
    }

    #[test]
    fn command_failure_during_old_removal_attempts_full_restore() {
        let attempts = std::cell::Cell::new(0_u8);
        let result = apply_policy_transaction(
            || {
                let attempt = attempts.get();
                attempts.set(attempt + 1);
                if attempt == 0 {
                    Err("injected old-policy removal failure".into())
                } else {
                    Ok(())
                }
            },
            || Ok(()),
            || Ok(()),
            || Ok(()),
        );
        assert!(matches!(
            result,
            Err(PolicyTransactionError::RolledBack { .. })
        ));
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn restore_failure_requires_adapter_fail_closed() {
        let result = apply_policy_transaction(
            || Ok(()),
            || Err("injected apply failure".into()),
            || Ok(()),
            || Err("injected restore failure".into()),
        );
        let error = result.unwrap_err();
        assert!(error.is_fail_closed());
        assert!(error.to_string().contains("adapter must fail closed"));
        assert!(error.to_string().contains("previous-policy restore"));

        let mut current = PolicyPlan {
            routes: vec![PlannedRoute {
                prefix: "10.70.0.0/16".into(),
                network_id: NetworkId(Uuid::from_u128(70)),
                gateway_device_id: DeviceId(Uuid::from_u128(71)),
            }],
            ..PolicyPlan::default()
        };
        assert!(
            finalize_policy_transaction(&mut current, PolicyPlan::default(), Err(error),).is_err()
        );
        assert_eq!(current, PolicyPlan::default());
    }
}
