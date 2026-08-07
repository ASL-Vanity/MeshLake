//! Platform-neutral validation and planning for locally operated exit gateways.
//!
//! This module intentionally models only the local forwarding/NAT boundary.
//! Controller policy separately determines whether this device may be selected
//! as an exit candidate by other members.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use meshlake_core::{JoinedNetwork, NetworkId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExitGatewayConfig {
    pub network_id: NetworkId,
    /// Physical egress interface selected explicitly by the local operator.
    /// It is passed to platform process APIs as one argument, never interpolated
    /// into a shell command.
    pub egress_interface: String,
    #[serde(default)]
    pub enable_ipv4: bool,
    #[serde(default)]
    pub enable_ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewayRoute {
    pub network_id: NetworkId,
    pub prefix: String,
    pub egress_interface: String,
    pub ipv6: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ExitGatewayPlan {
    pub routes: Vec<GatewayRoute>,
}

impl ExitGatewayPlan {
    pub fn from_configs(configs: &[ExitGatewayConfig], networks: &[JoinedNetwork]) -> Result<Self> {
        let mut configured_networks = BTreeSet::new();
        let mut routes = Vec::new();
        for config in configs {
            validate_egress_interface(&config.egress_interface)?;
            if !config.enable_ipv4 && !config.enable_ipv6 {
                bail!(
                    "exit gateway for network {} enables neither IPv4 nor IPv6",
                    config.network_id.0
                );
            }
            if !configured_networks.insert(config.network_id.0) {
                bail!(
                    "network {} has more than one local exit-gateway configuration",
                    config.network_id.0
                );
            }
            let joined = networks
                .iter()
                .find(|joined| joined.network.id == config.network_id)
                .with_context(|| {
                    format!(
                        "exit gateway references unknown local network {}",
                        config.network_id.0
                    )
                })?;
            if config.enable_ipv4 {
                let prefix = joined
                    .network
                    .ipv4_prefix
                    .parse::<IpNet>()
                    .context("exit gateway network has an invalid IPv4 prefix")?;
                if !matches!(prefix, IpNet::V4(_)) {
                    bail!("exit gateway network has a non-IPv4 IPv4 prefix");
                }
                routes.push(GatewayRoute {
                    network_id: config.network_id,
                    prefix: prefix.to_string(),
                    egress_interface: config.egress_interface.clone(),
                    ipv6: false,
                });
            }
            if config.enable_ipv6 {
                let prefix = joined
                    .network
                    .ipv6_prefix
                    .as_deref()
                    .context("IPv6 exit gateway requires an IPv6 virtual-network prefix")?
                    .parse::<IpNet>()
                    .context("exit gateway network has an invalid IPv6 prefix")?;
                if !matches!(prefix, IpNet::V6(_)) {
                    bail!("exit gateway network has a non-IPv6 IPv6 prefix");
                }
                routes.push(GatewayRoute {
                    network_id: config.network_id,
                    prefix: prefix.to_string(),
                    egress_interface: config.egress_interface.clone(),
                    ipv6: true,
                });
            }
        }
        routes.sort_by_key(|route| (route.network_id.0, route.ipv6, route.prefix.clone()));
        Ok(Self { routes })
    }
}

pub(crate) fn validate_egress_interface(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || value.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("egress interface must contain 1 to 128 non-control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::{NetworkControlPlane, RelayPolicy, VirtualNetwork};
    use std::net::IpAddr;
    use uuid::Uuid;

    fn network(id: u128, ipv6_prefix: Option<&str>) -> JoinedNetwork {
        JoinedNetwork {
            network: VirtualNetwork {
                id: NetworkId(Uuid::from_u128(id)),
                name: format!("network-{id}"),
                ipv4_prefix: format!("100.64.{id}.0/24"),
                ipv6_prefix: ipv6_prefix.map(str::to_owned),
                relay_policy: RelayPolicy::Preferred,
            },
            assigned_addresses: vec![IpAddr::from([100, 64, id as u8, 1])],
            certificate: None,
            network_key: vec![id as u8; 32],
            control_plane: NetworkControlPlane::default(),
        }
    }

    #[test]
    fn plans_explicit_dual_stack_gateway_without_shell_interpolation() {
        let config = ExitGatewayConfig {
            network_id: NetworkId(Uuid::from_u128(12)),
            egress_interface: "Ethernet 2".into(),
            enable_ipv4: true,
            enable_ipv6: true,
        };
        let plan =
            ExitGatewayPlan::from_configs(&[config], &[network(12, Some("fd42:4d4c:12::/64"))])
                .unwrap();
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.routes[0].egress_interface, "Ethernet 2");
        assert_eq!(plan.routes[0].prefix, "100.64.12.0/24");
        assert_eq!(plan.routes[1].prefix, "fd42:4d4c:12::/64");
    }

    #[test]
    fn rejects_ambiguous_invalid_or_unknown_gateway_configs() {
        let network = network(13, None);
        let base = ExitGatewayConfig {
            network_id: network.network.id,
            egress_interface: "eth0".into(),
            enable_ipv4: true,
            enable_ipv6: false,
        };
        assert!(
            ExitGatewayPlan::from_configs(&[base.clone(), base.clone()], &[network.clone()])
                .is_err()
        );
        assert!(ExitGatewayPlan::from_configs(
            &[ExitGatewayConfig {
                egress_interface: "bad\nname".into(),
                ..base.clone()
            }],
            &[network.clone()],
        )
        .is_err());
        assert!(ExitGatewayPlan::from_configs(
            &[ExitGatewayConfig {
                enable_ipv4: false,
                enable_ipv6: false,
                ..base.clone()
            }],
            &[network.clone()],
        )
        .is_err());
        assert!(ExitGatewayPlan::from_configs(
            &[ExitGatewayConfig {
                enable_ipv4: false,
                enable_ipv6: true,
                ..base
            }],
            &[network],
        )
        .is_err());
    }
}
