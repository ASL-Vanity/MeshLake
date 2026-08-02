use meshlake_core::{
    DeviceId, NetworkId, SessionList, SessionObservation, SessionPath, SessionQueueCounters,
    SessionSecurityCounters, SessionState, SESSION_API_SCHEMA_VERSION,
};
use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const EXPIRED_OBSERVATION_TTL: Duration = Duration::from_secs(300);
const MAX_EXPIRED_OBSERVATIONS: usize = 256;

type ObservationKey = (NetworkId, DeviceId);

#[derive(Clone)]
pub(crate) struct SessionTelemetry {
    pub(crate) state: SessionState,
    pub(crate) path: SessionPath,
    pub(crate) started_at: Instant,
    pub(crate) queue: SessionQueueCounters,
    pub(crate) security: SessionSecurityCounters,
}

#[derive(Clone)]
struct StoredObservation {
    telemetry: SessionTelemetry,
    recorded_at: Instant,
}

#[derive(Default)]
struct ObservationState {
    transport_revision: u64,
    active: HashMap<ObservationKey, StoredObservation>,
    expired: HashMap<ObservationKey, StoredObservation>,
}

#[derive(Default)]
pub(crate) struct SessionObservability {
    state: RwLock<ObservationState>,
}

impl SessionObservability {
    pub(crate) fn reset(&self, transport_revision: u64) {
        let mut state = self
            .state
            .write()
            .expect("session observation lock poisoned");
        state.transport_revision = transport_revision;
        state.active.clear();
        state.expired.clear();
    }

    pub(crate) fn clear_if_revision(&self, transport_revision: u64) {
        let mut state = self
            .state
            .write()
            .expect("session observation lock poisoned");
        if state.transport_revision == transport_revision {
            state.active.clear();
            state.expired.clear();
        }
    }

    pub(crate) fn publish(
        &self,
        transport_revision: u64,
        network_id: NetworkId,
        peer_device_id: DeviceId,
        telemetry: SessionTelemetry,
    ) {
        let mut state = self
            .state
            .write()
            .expect("session observation lock poisoned");
        if state.transport_revision != transport_revision {
            return;
        }
        let key = (network_id, peer_device_id);
        state.expired.remove(&key);
        state.active.insert(
            key,
            StoredObservation {
                telemetry,
                recorded_at: Instant::now(),
            },
        );
    }

    pub(crate) fn expire(
        &self,
        transport_revision: u64,
        network_id: NetworkId,
        peer_device_id: DeviceId,
    ) {
        let mut state = self
            .state
            .write()
            .expect("session observation lock poisoned");
        if state.transport_revision != transport_revision {
            return;
        }
        let key = (network_id, peer_device_id);
        let Some(mut observation) = state.active.remove(&key) else {
            return;
        };
        observation.telemetry.state = SessionState::Expired;
        observation.telemetry.queue.queued_packets = 0;
        observation.recorded_at = Instant::now();
        state.expired.insert(key, observation);
        trim_expired(&mut state);
    }

    /// Removes all metadata for a peer immediately. Use this for authorization,
    /// identity and transport-revision invalidation rather than retaining an
    /// expired tombstone from the superseded security context.
    pub(crate) fn remove(
        &self,
        transport_revision: u64,
        network_id: NetworkId,
        peer_device_id: DeviceId,
    ) {
        let mut state = self
            .state
            .write()
            .expect("session observation lock poisoned");
        if state.transport_revision != transport_revision {
            return;
        }
        let key = (network_id, peer_device_id);
        state.active.remove(&key);
        state.expired.remove(&key);
    }

    pub(crate) fn snapshot(&self) -> SessionList {
        let generated_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let current_time = Instant::now();
        let mut state = self
            .state
            .write()
            .expect("session observation lock poisoned");
        state.expired.retain(|_, observation| {
            current_time.saturating_duration_since(observation.recorded_at)
                <= EXPIRED_OBSERVATION_TTL
        });
        let mut sessions = state
            .active
            .iter()
            .chain(state.expired.iter())
            .map(
                |((network_id, peer_device_id), observation)| SessionObservation {
                    network_id: *network_id,
                    peer_device_id: *peer_device_id,
                    state: observation.telemetry.state,
                    path: observation.telemetry.path,
                    age_ms: current_time
                        .saturating_duration_since(observation.telemetry.started_at)
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64,
                    queue: observation.telemetry.queue.clone(),
                    security: observation.telemetry.security.clone(),
                },
            )
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| (session.network_id.0, session.peer_device_id.0));
        SessionList {
            schema_version: SESSION_API_SCHEMA_VERSION,
            generated_at_unix_ms,
            transport_revision: state.transport_revision,
            sessions,
        }
    }
}

fn trim_expired(state: &mut ObservationState) {
    while state.expired.len() > MAX_EXPIRED_OBSERVATIONS {
        let Some(oldest) = state
            .expired
            .iter()
            .max_by_key(|(_, observation)| observation.recorded_at.elapsed())
            .map(|(key, _)| *key)
        else {
            break;
        };
        state.expired.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn telemetry(state: SessionState) -> SessionTelemetry {
        SessionTelemetry {
            state,
            path: SessionPath::Relay,
            started_at: Instant::now(),
            queue: SessionQueueCounters {
                queued_packets: 2,
                queue_capacity: 8,
                dropped_packets: 1,
            },
            security: SessionSecurityCounters {
                handshake_attempts: 1,
                ..SessionSecurityCounters::default()
            },
        }
    }

    #[test]
    fn same_device_is_isolated_by_network_id() {
        let observations = SessionObservability::default();
        let device = DeviceId(Uuid::from_u128(3));
        observations.reset(7);
        observations.publish(
            7,
            NetworkId(Uuid::from_u128(1)),
            device,
            telemetry(SessionState::Pending),
        );
        observations.publish(
            7,
            NetworkId(Uuid::from_u128(2)),
            device,
            telemetry(SessionState::Established),
        );

        let snapshot = observations.snapshot();
        assert_eq!(snapshot.sessions.len(), 2);
        assert_ne!(
            snapshot.sessions[0].network_id,
            snapshot.sessions[1].network_id
        );
    }

    #[test]
    fn transport_revision_reset_removes_old_security_context() {
        let observations = SessionObservability::default();
        observations.reset(9);
        observations.publish(
            9,
            NetworkId(Uuid::from_u128(1)),
            DeviceId(Uuid::from_u128(2)),
            telemetry(SessionState::Established),
        );
        observations.reset(10);
        observations.publish(
            9,
            NetworkId(Uuid::from_u128(1)),
            DeviceId(Uuid::from_u128(2)),
            telemetry(SessionState::Established),
        );

        let snapshot = observations.snapshot();
        assert_eq!(snapshot.transport_revision, 10);
        assert!(snapshot.sessions.is_empty());
    }

    #[test]
    fn natural_expiry_keeps_only_sanitized_tombstone() {
        let observations = SessionObservability::default();
        let network = NetworkId(Uuid::from_u128(1));
        let device = DeviceId(Uuid::from_u128(2));
        observations.reset(1);
        observations.publish(1, network, device, telemetry(SessionState::Pending));
        observations.expire(1, network, device);

        let session = observations.snapshot().sessions.pop().unwrap();
        assert_eq!(session.state, SessionState::Expired);
        assert_eq!(session.queue.queued_packets, 0);
        assert_eq!(session.queue.dropped_packets, 1);
    }
}
