//! Platform-neutral planning for the local exit kill switch.
//!
//! The plan carries only already-resolved control-plane endpoints.  This keeps
//! the platform adapters from accepting host names or broad network ranges as
//! bypasses around the physical-network leak guard.

use anyhow::{bail, Result};
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BootstrapTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BootstrapEndpoint {
    pub endpoint: SocketAddr,
    pub transport: BootstrapTransport,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KillSwitchPlan {
    pub enabled: bool,
    pub bootstrap_endpoints: Vec<BootstrapEndpoint>,
}

impl KillSwitchPlan {
    /// Constructs the exact exception set required to keep MeshLake's signed
    /// controller, root, relay, and NAT-discovery control traffic alive while
    /// blocking all other physical-network egress.
    pub fn new(
        enabled: bool,
        endpoints: impl IntoIterator<Item = BootstrapEndpoint>,
    ) -> Result<Self> {
        if !enabled {
            return Ok(Self::default());
        }
        let mut unique = BTreeSet::new();
        for endpoint in endpoints {
            let address = endpoint.endpoint.ip();
            if address.is_unspecified() || address.is_multicast() || address.is_loopback() {
                bail!(
                    "kill-switch bootstrap endpoint {} must be a concrete non-local unicast address",
                    endpoint.endpoint
                );
            }
            unique.insert(endpoint);
        }
        if unique.is_empty() {
            bail!(
                "an exit kill switch requires at least one resolved controller, root, relay, or STUN endpoint"
            );
        }
        Ok(Self {
            enabled,
            bootstrap_endpoints: unique.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_broad_or_local_bypasses_and_deduplicates_exact_endpoints() {
        let endpoint = BootstrapEndpoint {
            endpoint: "198.51.100.10:443".parse().unwrap(),
            transport: BootstrapTransport::Tcp,
        };
        let plan = KillSwitchPlan::new(true, [endpoint, endpoint]).unwrap();
        assert_eq!(plan.bootstrap_endpoints, vec![endpoint]);
        assert!(KillSwitchPlan::new(true, std::iter::empty()).is_err());
        assert!(KillSwitchPlan::new(
            true,
            [BootstrapEndpoint {
                endpoint: "127.0.0.1:51821".parse().unwrap(),
                transport: BootstrapTransport::Tcp,
            }]
        )
        .is_err());
    }
}
