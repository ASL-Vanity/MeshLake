use meshlake_core::{DeviceId, NetworkId};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

const RELAY_ACKNOWLEDGEMENT_TTL: Duration = Duration::from_secs(45);
const ROOT_RESPONSE_TTL: Duration = Duration::from_secs(90);
const REGISTRATION_BASE_DELAY: Duration = Duration::from_secs(20);
const REGISTRATION_MAX_DELAY: Duration = Duration::from_secs(120);

/// Exponential retry with deterministic 0-25% jitter. The stable per-device
/// seed spreads a recovering fleet without relying on test-host randomness.
pub(crate) fn registration_retry_delay(seed: &[u8], consecutive_failures: u8) -> Duration {
    let exponent = consecutive_failures.min(3) as u32;
    let base_seconds = REGISTRATION_BASE_DELAY
        .as_secs()
        .saturating_mul(1_u64 << exponent)
        .min(REGISTRATION_MAX_DELAY.as_secs());
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ consecutive_failures as u64;
    for byte in seed {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    let jitter_limit = (base_seconds / 4).max(1);
    Duration::from_secs(
        base_seconds
            .saturating_add(hash % (jitter_limit + 1))
            .min(REGISTRATION_MAX_DELAY.as_secs()),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NetworkEndpoint {
    network_id: NetworkId,
    endpoint: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RegistrationServiceKind {
    Root,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RegistrationTarget {
    pub(crate) network_id: NetworkId,
    pub(crate) endpoint: SocketAddr,
    pub(crate) kind: RegistrationServiceKind,
}

#[derive(Debug, Clone)]
pub(crate) struct RegistrationSchedule {
    seed: [u8; 8],
    consecutive_failures: u8,
    awaiting_since: Option<Instant>,
    next_attempt: Instant,
    last_delay: Duration,
}

impl RegistrationSchedule {
    pub(crate) fn new(device_id: DeviceId, target: RegistrationTarget, now: Instant) -> Self {
        Self {
            seed: registration_seed(device_id, target),
            consecutive_failures: 0,
            awaiting_since: None,
            next_attempt: now,
            last_delay: Duration::ZERO,
        }
    }

    pub(crate) fn is_due(&self, now: Instant) -> bool {
        self.awaiting_since.is_none() && now >= self.next_attempt
    }

    pub(crate) fn mark_sent(&mut self, now: Instant) {
        self.awaiting_since = Some(now);
    }

    pub(crate) fn mark_send_failure(&mut self, now: Instant) {
        self.awaiting_since = None;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.schedule_next(now);
    }

    pub(crate) fn expire_if_timed_out(&mut self, now: Instant, timeout: Duration) -> bool {
        let Some(sent) = self.awaiting_since else {
            return false;
        };
        if now.saturating_duration_since(sent) < timeout {
            return false;
        }
        self.mark_send_failure(now);
        true
    }

    pub(crate) fn mark_success(&mut self, now: Instant) {
        self.awaiting_since = None;
        self.consecutive_failures = 0;
        self.schedule_next(now);
    }

    pub(crate) fn last_delay(&self) -> Duration {
        self.last_delay
    }

    fn schedule_next(&mut self, now: Instant) {
        self.last_delay = registration_retry_delay(&self.seed, self.consecutive_failures);
        self.next_attempt = now + self.last_delay;
    }
}

fn registration_seed(device_id: DeviceId, target: RegistrationTarget) -> [u8; 8] {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in device_id
        .0
        .as_bytes()
        .iter()
        .chain(target.network_id.0.as_bytes())
        .chain(target.endpoint.to_string().as_bytes())
        .chain(
            [match target.kind {
                RegistrationServiceKind::Root => 1,
                RegistrationServiceKind::Relay => 2,
            }]
            .iter(),
        )
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash.to_be_bytes()
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

    pub(crate) fn healthy_relay_endpoints(
        &self,
        configured: &[(NetworkId, SocketAddr)],
        now: Instant,
    ) -> Vec<SocketAddr> {
        aggregate_configured_endpoints(configured, |network_id, endpoint| {
            self.relay_is_healthy(network_id, endpoint, now)
        })
    }

    pub(crate) fn responsive_root_endpoints(
        &self,
        configured: &[(NetworkId, SocketAddr)],
        now: Instant,
    ) -> Vec<SocketAddr> {
        aggregate_configured_endpoints(configured, |network_id, endpoint| {
            self.root_is_responsive(network_id, endpoint, now)
        })
    }
}

/// The public status API predates per-network endpoint health and exposes only
/// a flat endpoint list. Report a shared endpoint as healthy only when every
/// configured network using it has current authenticated liveness. This avoids
/// presenting network A's acknowledgement as evidence for network B.
fn aggregate_configured_endpoints(
    configured: &[(NetworkId, SocketAddr)],
    mut is_healthy: impl FnMut(NetworkId, SocketAddr) -> bool,
) -> Vec<SocketAddr> {
    let mut requirements = HashMap::<SocketAddr, Vec<NetworkId>>::new();
    for (network_id, endpoint) in configured {
        let networks = requirements.entry(*endpoint).or_default();
        if !networks.contains(network_id) {
            networks.push(*network_id);
        }
    }
    requirements
        .into_iter()
        .filter_map(|(endpoint, networks)| {
            networks
                .into_iter()
                .all(|network_id| is_healthy(network_id, endpoint))
                .then_some(endpoint)
        })
        .collect()
}

/// Select the highest-priority healthy relay for one network. Planet order is
/// authoritative. If all entries are unknown or stale, retain the first
/// configured endpoint as the deterministic bootstrap/fallback.
pub(crate) fn select_relay_endpoint(
    network_id: NetworkId,
    configured: &[SocketAddr],
    health: &EndpointHealthTable,
    now: Instant,
    require_authenticated_health: bool,
) -> Option<SocketAddr> {
    let healthy = configured
        .iter()
        .copied()
        .find(|endpoint| health.relay_is_healthy(network_id, *endpoint, now));
    healthy.or_else(|| {
        (!require_authenticated_health)
            .then(|| configured.first().copied())
            .flatten()
    })
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
            select_relay_endpoint(
                second_network,
                &[second_primary, shared],
                &health,
                now,
                false,
            ),
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
            select_relay_endpoint(network, &[primary, secondary], &health, now, false),
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
            select_relay_endpoint(network, &[primary, secondary], &health, now, false),
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
            select_relay_endpoint(network, &[primary, secondary], &health, started, false),
            Some(primary)
        );

        health.mark_relay_acknowledged(network, secondary, started);
        health.mark_relay_acknowledged(network, primary, started);
        assert_eq!(
            select_relay_endpoint(network, &[primary, secondary], &health, later, false),
            Some(primary)
        );
        assert_eq!(
            select_relay_endpoint(network, &[primary, secondary], &health, later, true),
            None
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

    #[test]
    fn global_status_hides_a_shared_endpoint_until_every_network_is_healthy() {
        let first_network = network(8);
        let second_network = network(9);
        let relay: SocketAddr = "203.0.113.60:51820".parse().unwrap();
        let root: SocketAddr = "203.0.113.60:51819".parse().unwrap();
        let now = Instant::now();
        let relay_requirements = [(first_network, relay), (second_network, relay)];
        let root_requirements = [(first_network, root), (second_network, root)];
        let mut health = EndpointHealthTable::default();

        health.mark_relay_acknowledged(first_network, relay, now);
        health.mark_root_responsive(first_network, root, now);
        assert!(health
            .healthy_relay_endpoints(&relay_requirements, now)
            .is_empty());
        assert!(health
            .responsive_root_endpoints(&root_requirements, now)
            .is_empty());

        health.mark_relay_acknowledged(second_network, relay, now);
        health.mark_root_responsive(second_network, root, now);
        assert_eq!(
            health.healthy_relay_endpoints(&relay_requirements, now),
            vec![relay]
        );
        assert_eq!(
            health.responsive_root_endpoints(&root_requirements, now),
            vec![root]
        );
    }

    #[test]
    fn registration_backoff_is_deterministic_bounded_and_resets() {
        let first = registration_retry_delay(b"device-a", 2);
        assert_eq!(first, registration_retry_delay(b"device-a", 2));
        assert!(first >= Duration::from_secs(80));
        assert!(first <= REGISTRATION_MAX_DELAY);
        assert!(registration_retry_delay(b"device-a", 20) <= REGISTRATION_MAX_DELAY);
        assert!(registration_retry_delay(b"device-a", 0) < first);
    }

    #[test]
    fn registration_jitter_spreads_distinct_devices() {
        assert_ne!(
            registration_retry_delay(b"device-a", 1),
            registration_retry_delay(b"device-b", 1)
        );
    }

    #[test]
    fn endpoint_backoff_is_independent_and_success_resets_only_its_target() {
        let device = DeviceId(Uuid::from_u128(10));
        let network = network(11);
        let started = Instant::now();
        let healthy_target = RegistrationTarget {
            network_id: network,
            endpoint: "203.0.113.70:51820".parse().unwrap(),
            kind: RegistrationServiceKind::Relay,
        };
        let failing_target = RegistrationTarget {
            network_id: network,
            endpoint: "203.0.113.71:51820".parse().unwrap(),
            kind: RegistrationServiceKind::Relay,
        };
        let mut healthy = RegistrationSchedule::new(device, healthy_target, started);
        let mut failing = RegistrationSchedule::new(device, failing_target, started);
        healthy.mark_sent(started);
        failing.mark_sent(started);
        healthy.mark_success(started + Duration::from_secs(1));
        assert!(
            failing.expire_if_timed_out(started + Duration::from_secs(31), Duration::from_secs(30))
        );
        assert!(healthy.last_delay() < failing.last_delay());
        let failing_delay = failing.last_delay();
        healthy.mark_success(started + Duration::from_secs(32));
        assert_eq!(failing.last_delay(), failing_delay);
    }
}
