use meshlake_core::NetworkId;
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

const RELAY_ACKNOWLEDGEMENT_TTL: Duration = Duration::from_secs(45);
const ROOT_RESPONSE_TTL: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NetworkEndpoint {
    network_id: NetworkId,
    endpoint: SocketAddr,
}

impl NetworkEndpoint {
    fn new(network_id: NetworkId, endpoint: SocketAddr) -> Self {
        Self {
            network_id,
            endpoint,
        }
    }
}

/// Runtime liveness learned from authenticated Root responses and Relay
/// registration acknowledgements. Entries are scoped by network because the
/// same endpoint may accept one controller/network while rejecting another.
#[derive(Debug, Default)]
pub(crate) struct EndpointHealthTable {
    relay_acknowledgements: HashMap<NetworkEndpoint, Instant>,
    root_responses: HashMap<NetworkEndpoint, Instant>,
}

impl EndpointHealthTable {
    pub(crate) fn mark_relay_acknowledged(
        &mut self,
        network_id: NetworkId,
        endpoint: SocketAddr,
        now: Instant,
    ) {
        self.relay_acknowledgements
            .insert(NetworkEndpoint::new(network_id, endpoint), now);
    }

    pub(crate) fn mark_root_responsive(
        &mut self,
        network_id: NetworkId,
        endpoint: SocketAddr,
        now: Instant,
    ) {
        self.root_responses
            .insert(NetworkEndpoint::new(network_id, endpoint), now);
    }

    pub(crate) fn relay_is_healthy(
        &self,
        network_id: NetworkId,
        endpoint: SocketAddr,
        now: Instant,
    ) -> bool {
        self.relay_acknowledgements
            .get(&NetworkEndpoint::new(network_id, endpoint))
            .is_some_and(|seen| now.saturating_duration_since(*seen) < RELAY_ACKNOWLEDGEMENT_TTL)
    }

    pub(crate) fn root_is_responsive(
        &self,
        network_id: NetworkId,
        endpoint: SocketAddr,
        now: Instant,
    ) -> bool {
        self.root_responses
            .get(&NetworkEndpoint::new(network_id, endpoint))
            .is_some_and(|seen| now.saturating_duration_since(*seen) < ROOT_RESPONSE_TTL)
    }

    pub(crate) fn healthy_relay_endpoints(&self, now: Instant) -> Vec<SocketAddr> {
        self.relay_acknowledgements
            .iter()
            .filter_map(|(key, _)| {
                self.relay_is_healthy(key.network_id, key.endpoint, now)
                    .then_some(key.endpoint)
            })
            .collect()
    }

    pub(crate) fn responsive_root_endpoints(&self, now: Instant) -> Vec<SocketAddr> {
        self.root_responses
            .iter()
            .filter_map(|(key, _)| {
                self.root_is_responsive(key.network_id, key.endpoint, now)
                    .then_some(key.endpoint)
            })
            .collect()
    }
}

/// Select the highest-priority healthy relay for one network. Planet order is
/// authoritative. If all entries are unknown or stale, retain the first
/// configured endpoint as the deterministic bootstrap/fallback.
pub(crate) fn select_relay_endpoint(
    network_id: NetworkId,
    configured: &[SocketAddr],
    health: &EndpointHealthTable,
    now: Instant,
) -> Option<SocketAddr> {
    configured
        .iter()
        .copied()
        .find(|endpoint| health.relay_is_healthy(network_id, *endpoint, now))
        .or_else(|| configured.first().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn network(value: u128) -> NetworkId {
        NetworkId(Uuid::from_u128(value))
    }

    #[test]
    fn relay_health_is_isolated_when_networks_share_an_endpoint() {
        let first_network = network(1);
        let second_network = network(2);
        let shared: SocketAddr = "203.0.113.10:51820".parse().unwrap();
        let second_primary: SocketAddr = "203.0.113.11:51820".parse().unwrap();
        let now = Instant::now();
        let mut health = EndpointHealthTable::default();

        health.mark_relay_acknowledged(first_network, shared, now);

        assert!(health.relay_is_healthy(first_network, shared, now));
        assert!(!health.relay_is_healthy(second_network, shared, now));
        assert_eq!(
            select_relay_endpoint(second_network, &[second_primary, shared], &health, now),
            Some(second_primary)
        );
    }

    #[test]
    fn healthy_primary_relay_keeps_planet_priority() {
        let network = network(3);
        let primary: SocketAddr = "203.0.113.20:51820".parse().unwrap();
        let secondary: SocketAddr = "203.0.113.21:51820".parse().unwrap();
        let now = Instant::now();
        let mut health = EndpointHealthTable::default();
        health.mark_relay_acknowledged(network, secondary, now);
        health.mark_relay_acknowledged(network, primary, now);

        assert_eq!(
            select_relay_endpoint(network, &[primary, secondary], &health, now),
            Some(primary)
        );
    }

    #[test]
    fn expired_primary_fails_over_to_healthy_secondary() {
        let network = network(4);
        let primary: SocketAddr = "203.0.113.30:51820".parse().unwrap();
        let secondary: SocketAddr = "203.0.113.31:51820".parse().unwrap();
        let started = Instant::now();
        let now = started + RELAY_ACKNOWLEDGEMENT_TTL + Duration::from_secs(1);
        let mut health = EndpointHealthTable::default();
        health.mark_relay_acknowledged(network, primary, started);
        health.mark_relay_acknowledged(network, secondary, now);

        assert_eq!(
            select_relay_endpoint(network, &[primary, secondary], &health, now),
            Some(secondary)
        );
    }

    #[test]
    fn unknown_or_expired_relays_keep_planet_order() {
        let network = network(5);
        let primary: SocketAddr = "203.0.113.40:51820".parse().unwrap();
        let secondary: SocketAddr = "203.0.113.41:51820".parse().unwrap();
        let started = Instant::now();
        let later = started + RELAY_ACKNOWLEDGEMENT_TTL + Duration::from_secs(1);
        let mut health = EndpointHealthTable::default();

        assert_eq!(
            select_relay_endpoint(network, &[primary, secondary], &health, started),
            Some(primary)
        );

        health.mark_relay_acknowledged(network, secondary, started);
        health.mark_relay_acknowledged(network, primary, started);
        assert_eq!(
            select_relay_endpoint(network, &[primary, secondary], &health, later),
            Some(primary)
        );
    }

    #[test]
    fn root_health_is_scoped_and_uses_injected_time() {
        let first_network = network(6);
        let second_network = network(7);
        let root: SocketAddr = "203.0.113.50:51819".parse().unwrap();
        let started = Instant::now();
        let mut health = EndpointHealthTable::default();
        health.mark_root_responsive(first_network, root, started);

        assert!(health.root_is_responsive(first_network, root, started));
        assert!(!health.root_is_responsive(second_network, root, started));
        assert!(!health.root_is_responsive(
            first_network,
            root,
            started + ROOT_RESPONSE_TTL + Duration::from_secs(1)
        ));
    }
}
