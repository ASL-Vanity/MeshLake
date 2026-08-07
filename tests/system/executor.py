"""Safety-gated execution support for MeshLake system scenarios.

Only the deterministic simulation backend is enabled here. It exercises the
same orchestration, timeout, assertion, and cleanup paths as a future lab
transport without starting processes or opening network connections.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import pathlib
import platform
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable


DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 900
KNOWN_TRANSPORT_CAPABILITIES = frozenset({"local-process", "ssh", "winrm"})
SINGLE_USE_RUN_RECEIPT_CAPABILITY = "single-use-run-receipt"

SUPPORTED_ACTION_TYPES = {
    "apply_network_policy",
    "block_direct_path",
    "block_udp_relay",
    "capture_session_snapshot",
    "close_sessions",
    "configure_controller_tls",
    "configure_ordered_relays",
    "configure_ordered_roots",
    "create_network",
    "create_state_backup",
    "delete_network",
    "enroll_nodes",
    "ensure_daemon_running",
    "establish_pairwise_session",
    "establish_sessions",
    "inject_dns_apply_failure",
    "inject_policy_rollback_failure",
    "inject_route_apply_failure",
    "replace_state_from_backup",
    "remove_temporary_backup",
    "remove_test_ca",
    "restart_daemon",
    "restore_controller_tls",
    "restore_direct_path",
    "restore_udp_relay",
    "restore_member_authorization",
    "restore_network_policy",
    "restore_original_state",
    "restore_relay_configuration",
    "restore_root_configuration",
    "revoke_member",
    "send_overlay_probe",
    "shutdown_adapter",
    "start_adapter",
    "start_service",
    "stop_adapter",
    "stop_service",
    "unenroll_nodes",
    "verify_backup",
    "wait_authorization_refresh",
    "wait_health_convergence",
    "wait_local_api",
    "wait_transport_ready",
}

SUPPORTED_ASSERTION_TYPES = {
    "adapter_stopped",
    "backup_verified",
    "dns_policy_unchanged",
    "fault_injection_removed",
    "fresh_session_age",
    "network_absent",
    "network_isolation_key",
    "no_cross_network_session_reuse",
    "no_secret_fields",
    "old_security_context_absent",
    "overlay_probe_succeeds",
    "policy_restored",
    "queue_bounded",
    "relay_healthy",
    "restored_state_matches",
    "rollback_failure_reported",
    "root_responsive",
    "route_policy_absent",
    "same_network_and_peer",
    "security_counters_monotonic",
    "service_running",
    "session",
    "session_absent",
    "session_count_by_network",
    "session_list_empty",
    "tls_handshake_succeeds",
    "tls_rejects_untrusted_peer",
    "transport_revision_present",
}

IDEMPOTENT_CLEANUP_TYPES = {
    "close_sessions",
    "delete_network",
    "ensure_daemon_running",
    "remove_temporary_backup",
    "remove_test_ca",
    "restore_controller_tls",
    "restore_direct_path",
    "restore_udp_relay",
    "restore_member_authorization",
    "restore_network_policy",
    "restore_original_state",
    "restore_relay_configuration",
    "restore_root_configuration",
    "shutdown_adapter",
    "start_service",
    "unenroll_nodes",
}

_CLEANUP_TARGET_BINDINGS = {
    "apply_network_policy": {"restore_network_policy": (("role", "role"),)},
    "block_direct_path": {"restore_direct_path": (("roles", "roles"),)},
    "block_udp_relay": {"restore_udp_relay": (("roles", "roles"),)},
    "configure_controller_tls": {
        "restore_controller_tls": (("roles", "roles"),),
        "remove_test_ca": (("roles", "roles"),),
    },
    "configure_ordered_relays": {
        "restore_relay_configuration": (("target_roles", "target_roles"),)
    },
    "configure_ordered_roots": {
        "restore_root_configuration": (("target_roles", "target_roles"),)
    },
    "create_network": {"delete_network": (("network", "network"),)},
    "create_state_backup": {
        "remove_temporary_backup": (("role", "role"), ("name", "name"))
    },
    "enroll_nodes": {
        "unenroll_nodes": (("network", "network"), ("roles", "roles"))
    },
    "establish_pairwise_session": {
        "close_sessions": (("peer_roles", "roles"),)
    },
    "establish_sessions": {"close_sessions": (("networks", "networks"),)},
    "inject_dns_apply_failure": {
        "restore_network_policy": (("role", "role"),)
    },
    "inject_policy_rollback_failure": {
        "restore_network_policy": (("role", "role"),),
        "shutdown_adapter": (("role", "role"),),
    },
    "inject_route_apply_failure": {
        "restore_network_policy": (("role", "role"),)
    },
    "replace_state_from_backup": {
        "restore_original_state": (("role", "role"), ("name", "name"))
    },
    "restart_daemon": {"ensure_daemon_running": (("role", "role"),)},
    "revoke_member": {
        "restore_member_authorization": (("network", "network"), ("role", "role"))
    },
    "start_adapter": {"shutdown_adapter": (("role", "role"),)},
    "stop_service": {
        "start_service": (("role", "role"), ("service", "service"))
    },
}

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "privatekey",
    "private_key",
    "psk",
    "joinlink",
    "join_link",
    "credential",
    "bearer",
    "apikey",
    "api_key",
)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"meshlake://join", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
)
_SENSITIVE_EXACT_KEYS = {"authorization"}
_FORBIDDEN_RAW_EXECUTION_FIELDS = {
    "argv",
    "command",
    "env",
    "environment",
    "script",
    "shell",
    "stdin",
}


class ExecutionValidationError(ValueError):
    pass


_AUTHORIZATION_SEAL = object()


@dataclass(frozen=True, repr=False)
class ExecutionAuthorization:
    """Validated execution grant created only by validate_execution_gate."""

    scenario_id: str
    scenario_digest: str
    backend_name: str
    required_capabilities: frozenset[str]
    role_targets: tuple[tuple[str, str, str, str, str], ...]
    lab_id: str
    _seal: object = field(repr=False, compare=False)


@dataclass(frozen=True)
class TransportRequest:
    """Non-secret request passed to a future transport implementation."""

    target_ref: str
    operation: str
    arguments: tuple[str, ...] = ()


class Transport:
    """Narrow transport contract; this branch intentionally ships no transports.

    A future real transport must expose ``single-use-run-receipt`` only after it
    atomically consumes a persistent run nonce/receipt before the first action.
    """

    capabilities: frozenset[str] = frozenset()

    def invoke(self, request: TransportRequest, timeout_seconds: int) -> BackendOutcome:
        del request, timeout_seconds
        raise NotImplementedError


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", value.lower())


def _scenario_digest(scenario: dict[str, Any]) -> str:
    canonical = json.dumps(
        scenario,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def reject_sensitive_inventory(value: Any, location: str = "inventory") -> None:
    """Reject suspected secret material without echoing its value."""

    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            normalized = _normalized_key(key_text)
            if normalized in _SENSITIVE_EXACT_KEYS or any(
                part in normalized for part in _SENSITIVE_KEY_PARTS
            ):
                raise ExecutionValidationError(
                    f"{location}: suspected secret field at {location}.{key_text}"
                )
            reject_sensitive_inventory(item, f"{location}.{key_text}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_sensitive_inventory(item, f"{location}[{index}]")
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in _SENSITIVE_VALUE_PATTERNS):
            raise ExecutionValidationError(
                f"{location}: suspected secret value at {location}"
            )


def action_timeout(action: dict[str, Any]) -> int:
    timeout = action.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise ExecutionValidationError("action timeout_seconds must be an integer")
    if timeout < 1 or timeout > MAX_TIMEOUT_SECONDS:
        raise ExecutionValidationError(
            f"action timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}"
        )
    return timeout


def cleanup_actions(action: dict[str, Any]) -> list[dict[str, Any]]:
    raw = action.get("cleanup", [])
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise ExecutionValidationError("action cleanup must be an object or array")
    cleanups: list[dict[str, Any]] = []
    for cleanup in raw:
        if not isinstance(cleanup, dict):
            raise ExecutionValidationError("cleanup entries must be objects")
        cleanup_type = cleanup.get("type")
        if cleanup_type not in IDEMPOTENT_CLEANUP_TYPES:
            raise ExecutionValidationError(
                f"cleanup action has unsupported type: {cleanup_type!r}"
            )
        if cleanup.get("idempotent") is not True:
            raise ExecutionValidationError(
                f"cleanup action {cleanup_type} must declare idempotent=true"
            )
        action_timeout(cleanup)
        cleanups.append(cleanup)
    return cleanups


def _validate_target_roles(
    source: str, phase_name: str, item: dict[str, Any], declared_roles: set[str]
) -> None:
    forbidden = sorted(set(item) & _FORBIDDEN_RAW_EXECUTION_FIELDS)
    if forbidden:
        raise ExecutionValidationError(
            f"{source}: phase {phase_name} contains forbidden raw execution fields: "
            + ", ".join(forbidden)
        )
    for field in ("role", "source", "destination"):
        value = item.get(field)
        if value is not None and value not in declared_roles:
            raise ExecutionValidationError(
                f"{source}: phase {phase_name} references undeclared role {value!r}"
            )
    for field in ("roles", "target_roles", "root_roles", "relay_roles"):
        roles = item.get(field)
        if roles is not None and (
            not isinstance(roles, list)
            or not roles
            or any(role not in declared_roles for role in roles)
        ):
            raise ExecutionValidationError(
                f"{source}: phase {phase_name} has invalid {field} target list"
            )


def _identity_value(item: dict[str, Any], field: str) -> Any:
    if field == "peer_roles":
        if "source" not in item or "destination" not in item:
            raise ExecutionValidationError(
                "pairwise action must declare source and destination"
            )
        return tuple(sorted((item["source"], item["destination"])))
    if field not in item:
        raise ExecutionValidationError(f"execution item must declare target field {field}")
    value = item[field]
    if isinstance(value, list):
        return tuple(sorted(value))
    return value


def _validate_cleanup_bindings(
    source: str,
    phase_name: str,
    action: dict[str, Any],
    cleanups: list[dict[str, Any]],
) -> None:
    action_type = action["type"]
    expected = _CLEANUP_TARGET_BINDINGS.get(action_type, {})
    by_type: dict[str, list[dict[str, Any]]] = {}
    for cleanup in cleanups:
        by_type.setdefault(cleanup["type"], []).append(cleanup)

    missing = sorted(set(expected) - set(by_type))
    unexpected = sorted(set(by_type) - set(expected))
    duplicates = sorted(
        cleanup_type for cleanup_type, values in by_type.items() if len(values) != 1
    )
    if missing:
        raise ExecutionValidationError(
            f"{source}: phase {phase_name} action {action_type} lacks cleanup: "
            + ", ".join(missing)
        )
    if unexpected:
        raise ExecutionValidationError(
            f"{source}: phase {phase_name} action {action_type} has unexpected cleanup: "
            + ", ".join(unexpected)
        )
    if duplicates:
        raise ExecutionValidationError(
            f"{source}: phase {phase_name} action {action_type} repeats cleanup: "
            + ", ".join(duplicates)
        )

    for cleanup_type, bindings in expected.items():
        cleanup = by_type[cleanup_type][0]
        for action_field, cleanup_field in bindings:
            try:
                action_value = _identity_value(action, action_field)
                cleanup_value = _identity_value(cleanup, cleanup_field)
            except ExecutionValidationError as error:
                raise ExecutionValidationError(
                    f"{source}: phase {phase_name} action {action_type}: {error}"
                ) from error
            if action_value != cleanup_value:
                raise ExecutionValidationError(
                    f"{source}: phase {phase_name} action {action_type} cleanup "
                    f"{cleanup_type} target mismatch for {cleanup_field}"
                )


def validate_execution_schema(source: str, scenario: dict[str, Any]) -> None:
    execution = scenario.get("execution")
    if not isinstance(execution, dict) or execution.get("allowed") is not True:
        raise ExecutionValidationError(
            f"{source}: scenario must explicitly set execution.allowed=true"
        )
    required_capabilities = execution.get("required_capabilities", ["simulation"])
    if (
        not isinstance(required_capabilities, list)
        or not required_capabilities
        or any(not isinstance(item, str) or not item for item in required_capabilities)
    ):
        raise ExecutionValidationError(
            f"{source}: execution.required_capabilities must be a non-empty string array"
        )
    known_capabilities = {
        "simulation",
        SINGLE_USE_RUN_RECEIPT_CAPABILITY,
    } | KNOWN_TRANSPORT_CAPABILITIES
    unknown_capabilities = sorted(set(required_capabilities) - known_capabilities)
    if unknown_capabilities:
        raise ExecutionValidationError(
            f"{source}: unknown execution capabilities: "
            + ", ".join(unknown_capabilities)
        )
    requested_transports = set(required_capabilities) & KNOWN_TRANSPORT_CAPABILITIES
    if requested_transports and SINGLE_USE_RUN_RECEIPT_CAPABILITY not in required_capabilities:
        raise ExecutionValidationError(
            f"{source}: real transport capabilities require "
            f"{SINGLE_USE_RUN_RECEIPT_CAPABILITY}"
        )
    declared_roles = {
        host.get("role") for host in scenario.get("hosts", []) if isinstance(host, dict)
    }

    for phase in scenario.get("phases", []):
        phase_name = phase.get("name", "<unknown>")
        for action in phase.get("actions", []):
            action_type = action.get("type")
            if action_type not in SUPPORTED_ACTION_TYPES:
                raise ExecutionValidationError(
                    f"{source}: phase {phase_name} has unsupported action {action_type!r}"
                )
            action_timeout(action)
            _validate_target_roles(source, phase_name, action, declared_roles)
            cleanups = cleanup_actions(action)
            for cleanup in cleanups:
                _validate_target_roles(source, phase_name, cleanup, declared_roles)
            _validate_cleanup_bindings(source, phase_name, action, cleanups)
        for assertion in phase.get("assertions", []):
            assertion_type = assertion.get("type")
            if assertion_type not in SUPPORTED_ASSERTION_TYPES:
                raise ExecutionValidationError(
                    f"{source}: phase {phase_name} has unsupported assertion "
                    f"{assertion_type!r}"
                )
            _validate_target_roles(source, phase_name, assertion, declared_roles)


def validate_inventory_shape(source: str, inventory: dict[str, Any]) -> None:
    reject_sensitive_inventory(inventory, source)
    extra_top = set(inventory) - {"schema_version", "lab_id", "hosts"}
    if extra_top:
        raise ExecutionValidationError(
            f"{source}: unsupported inventory fields: {', '.join(sorted(extra_top))}"
        )
    hosts = inventory.get("hosts")
    if not isinstance(hosts, list):
        return
    for index, host in enumerate(hosts):
        if not isinstance(host, dict):
            continue
        extra_host = set(host) - {
            "role",
            "name",
            "platform",
            "disposable",
            "connection",
        }
        if extra_host:
            raise ExecutionValidationError(
                f"{source}: host[{index}] has unsupported fields: "
                + ", ".join(sorted(extra_host))
            )
        connection = host.get("connection")
        if connection is not None:
            if not isinstance(connection, dict):
                raise ExecutionValidationError(
                    f"{source}: host[{index}] connection must be an object"
                )
            extra_connection = set(connection) - {"type", "ref"}
            if extra_connection:
                raise ExecutionValidationError(
                    f"{source}: host[{index}] connection has unsupported fields: "
                    + ", ".join(sorted(extra_connection))
                )


def validate_execution_gate(
    source: str,
    scenario: dict[str, Any],
    inventory: dict[str, Any],
    inventory_hosts: dict[str, dict[str, Any]],
    allow_targets: Iterable[str],
    confirmed_lab_id: str | None,
    backend_name: str,
) -> ExecutionAuthorization:
    reject_sensitive_inventory(scenario, f"{source}: scenario")
    validate_execution_schema(f"{source}: scenario", scenario)
    raw_lab_id = inventory.get("lab_id")
    if not isinstance(raw_lab_id, str):
        raise ExecutionValidationError(f"{source}: execution requires lab_id")
    try:
        parsed_lab_id = uuid.UUID(raw_lab_id)
    except ValueError as error:
        raise ExecutionValidationError(f"{source}: lab_id must be a UUID") from error
    if parsed_lab_id.version != 4:
        raise ExecutionValidationError(f"{source}: lab_id must be a version 4 UUID")
    if not confirmed_lab_id or not hmac.compare_digest(raw_lab_id, confirmed_lab_id):
        raise ExecutionValidationError(f"{source}: lab_id confirmation is missing or wrong")

    required_targets = {host["name"] for host in inventory_hosts.values()}
    allowed_targets = set(allow_targets)
    if "*" in allowed_targets:
        raise ExecutionValidationError(f"{source}: wildcard target allowlists are forbidden")
    if allowed_targets != required_targets:
        raise ExecutionValidationError(
            f"{source}: target allowlist must exactly match assigned host names"
        )

    if backend_name != "simulated":
        raise ExecutionValidationError(f"unsupported execution backend: {backend_name}")
    for role, host in inventory_hosts.items():
        if host.get("disposable") is not True:
            raise ExecutionValidationError(
                f"{source}: role {role} must be explicitly marked disposable=true"
            )
        connection = host.get("connection")
        if not isinstance(connection, dict):
            raise ExecutionValidationError(
                f"{source}: role {role} needs a non-secret connection reference"
            )
        if connection.get("type") != "simulated":
            raise ExecutionValidationError(
                f"{source}: role {role} is not assigned to the simulated backend"
            )
        reference = connection.get("ref")
        if not isinstance(reference, str) or not reference.strip():
            raise ExecutionValidationError(
                f"{source}: role {role} has an invalid connection reference"
            )
    scenario_roles = {requirement["role"] for requirement in scenario["hosts"]}
    if scenario_roles != set(inventory_hosts):
        raise ExecutionValidationError(
            f"{source}: inventory assignments do not match scenario roles"
        )
    required_capabilities = frozenset(scenario["execution"]["required_capabilities"])
    role_targets = tuple(
        sorted(
            (
                role,
                host["name"],
                host["platform"],
                host["connection"]["type"],
                host["connection"]["ref"],
            )
            for role, host in inventory_hosts.items()
        )
    )
    return ExecutionAuthorization(
        scenario_id=scenario["id"],
        scenario_digest=_scenario_digest(scenario),
        backend_name=backend_name,
        required_capabilities=required_capabilities,
        role_targets=role_targets,
        lab_id=raw_lab_id,
        _seal=_AUTHORIZATION_SEAL,
    )


@dataclass(frozen=True)
class BackendOutcome:
    ok: bool
    code: str = "ok"
    modeled: bool = True


class ExecutionBackend:
    """Backend contract. Implementations must honor the supplied timeout."""

    name = "abstract"
    capabilities: frozenset[str] = frozenset()
    network_access_performed = False
    processes_started = 0

    def run_action(
        self, action: dict[str, Any], timeout_seconds: int, *, cleanup: bool = False
    ) -> BackendOutcome:
        raise NotImplementedError

    def evaluate_assertion(self, assertion: dict[str, Any]) -> BackendOutcome:
        raise NotImplementedError

    def session_counts(self) -> dict[str, int]:
        return {"total": 0}


@dataclass
class SimulatedBackend(ExecutionBackend):
    """Deterministic backend used by local tests and ordinary CI."""

    fail_actions: set[str] = field(default_factory=set)
    fail_cleanups: set[str] = field(default_factory=set)
    fail_assertions: set[str] = field(default_factory=set)
    calls: list[tuple[str, bool]] = field(default_factory=list)
    sessions: dict[str, int] = field(default_factory=dict)
    snapshots: dict[str, dict[str, int]] = field(default_factory=dict)
    session_paths: dict[str, str] = field(default_factory=dict)
    snapshot_paths: dict[str, dict[str, str]] = field(default_factory=dict)
    direct_path_blocked: bool = False
    udp_relay_blocked: bool = False

    name = "simulated"
    capabilities = frozenset({"simulation"})
    network_access_performed = False
    processes_started = 0

    def run_action(
        self, action: dict[str, Any], timeout_seconds: int, *, cleanup: bool = False
    ) -> BackendOutcome:
        del timeout_seconds
        action_type = action["type"]
        self.calls.append((action_type, cleanup))
        failures = self.fail_cleanups if cleanup else self.fail_actions
        if action_type in failures:
            return BackendOutcome(False, "simulated_failure")

        if action_type == "establish_pairwise_session":
            network = str(action.get("network", "default"))
            self.sessions[network] = max(1, self.sessions.get(network, 0))
            self.session_paths[network] = "direct"
        elif action_type == "establish_sessions":
            for network in action.get("networks", ["default"]):
                self.sessions[str(network)] = max(1, self.sessions.get(str(network), 0))
                self.session_paths[str(network)] = "direct"
        elif action_type in {"close_sessions", "restart_daemon"}:
            network = action.get("network")
            if network is None:
                self.sessions.clear()
                self.session_paths.clear()
            else:
                self.sessions[str(network)] = 0
                self.session_paths.pop(str(network), None)
        elif action_type == "revoke_member":
            network = str(action.get("network", "default"))
            self.sessions[network] = 0
            self.session_paths.pop(network, None)
        elif action_type == "block_direct_path":
            self.direct_path_blocked = True
        elif action_type == "restore_direct_path":
            self.direct_path_blocked = False
        elif action_type == "block_udp_relay":
            self.udp_relay_blocked = True
        elif action_type == "restore_udp_relay":
            self.udp_relay_blocked = False
        elif action_type == "send_overlay_probe":
            network = str(action.get("network", "default"))
            self.sessions[network] = max(1, self.sessions.get(network, 0))
            self.session_paths[network] = (
                "tls_relay"
                if self.direct_path_blocked and self.udp_relay_blocked
                else "relay"
                if self.direct_path_blocked
                else self.session_paths.get(network, "direct")
            )
        elif action_type == "capture_session_snapshot":
            name = str(action.get("name", "snapshot"))
            self.snapshots[name] = dict(self.sessions)
            self.snapshot_paths[name] = dict(self.session_paths)
        return BackendOutcome(True)

    def evaluate_assertion(self, assertion: dict[str, Any]) -> BackendOutcome:
        assertion_type = assertion["type"]
        if assertion_type in self.fail_assertions:
            return BackendOutcome(False, "simulated_assertion_failure")
        if assertion_type not in {
            "session",
            "session_absent",
            "session_count_by_network",
            "session_list_empty",
        }:
            return BackendOutcome(True, "simulated_not_modeled", modeled=False)

        counts = self.sessions
        paths = self.session_paths
        snapshot = assertion.get("snapshot")
        if snapshot is not None:
            counts = self.snapshots.get(str(snapshot))
            if counts is None:
                return BackendOutcome(False, "simulated_snapshot_missing")
            paths = self.snapshot_paths.get(str(snapshot), {})

        network = assertion.get("network")
        if network is None:
            count = sum(counts.values())
        else:
            count = counts.get(str(network), 0)

        if assertion_type == "session":
            state = assertion.get("state", "established")
            if state == "established":
                if count <= 0:
                    return BackendOutcome(False, "simulated_session_missing")
                expected_path = assertion.get("path")
                if expected_path is not None:
                    actual_paths = (
                        {paths.get(str(network))}
                        if network is not None
                        else set(paths.values())
                    )
                    if expected_path not in actual_paths:
                        return BackendOutcome(False, "simulated_session_path_mismatch")
                return BackendOutcome(True)
            if state == "absent":
                return BackendOutcome(
                    count == 0,
                    "ok" if count == 0 else "simulated_session_present",
                )
            return BackendOutcome(False, "simulated_session_state_unsupported")
        if assertion_type == "session_absent":
            return BackendOutcome(
                count == 0,
                "ok" if count == 0 else "simulated_session_present",
            )
        if assertion_type == "session_list_empty":
            total = sum(counts.values())
            return BackendOutcome(
                total == 0,
                "ok" if total == 0 else "simulated_session_list_not_empty",
            )

        if not isinstance(network, str) or not network:
            return BackendOutcome(False, "simulated_network_missing")
        minimum = assertion.get("minimum", 0)
        maximum = assertion.get("maximum")
        if isinstance(minimum, bool) or not isinstance(minimum, int):
            return BackendOutcome(False, "simulated_count_bounds_invalid")
        if maximum is not None and (
            isinstance(maximum, bool) or not isinstance(maximum, int)
        ):
            return BackendOutcome(False, "simulated_count_bounds_invalid")
        matches = count >= minimum and (maximum is None or count <= maximum)
        return BackendOutcome(
            matches,
            "ok" if matches else "simulated_session_count_mismatch",
        )

    def session_counts(self) -> dict[str, int]:
        by_network = {
            network: count
            for network, count in sorted(self.sessions.items())
            if count > 0
        }
        return {"total": sum(by_network.values()), "by_network": by_network}


def _result_entry(kind: str, item_type: str, outcome: BackendOutcome, elapsed: float) -> dict[str, Any]:
    return {
        "kind": kind,
        "type": item_type,
        "status": "passed" if outcome.ok else "failed",
        "code": outcome.code,
        "modeled": outcome.modeled,
        "duration_ms": round(elapsed * 1000),
    }


def _failure(phase: str, entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": phase,
        "kind": entry["kind"],
        "type": entry["type"],
        "code": entry["code"],
    }


def _validate_execution_authorization(
    scenario: dict[str, Any],
    authorization: ExecutionAuthorization,
    backend: ExecutionBackend,
) -> None:
    if (
        type(authorization) is not ExecutionAuthorization
        or authorization._seal is not _AUTHORIZATION_SEAL
    ):
        raise ExecutionValidationError(
            "execution requires authorization returned by validate_execution_gate"
        )
    reject_sensitive_inventory(scenario, "scenario")
    validate_execution_schema("scenario", scenario)
    if authorization.scenario_id != scenario["id"]:
        raise ExecutionValidationError("execution authorization scenario mismatch")
    if authorization.scenario_digest != _scenario_digest(scenario):
        raise ExecutionValidationError("execution authorization scenario digest mismatch")
    if authorization.backend_name != backend.name:
        raise ExecutionValidationError("execution authorization backend mismatch")
    required_capabilities = frozenset(
        scenario["execution"].get("required_capabilities", ["simulation"])
    )
    if authorization.required_capabilities != required_capabilities:
        raise ExecutionValidationError("execution authorization capability mismatch")
    authorized_roles = {binding[0] for binding in authorization.role_targets}
    platform_requirements = {
        requirement["role"]: set(requirement["platforms"])
        for requirement in scenario["hosts"]
    }
    scenario_roles = set(platform_requirements)
    if authorized_roles != scenario_roles:
        raise ExecutionValidationError("execution authorization target mismatch")
    target_names: set[str] = set()
    for role, name, target_platform, connection_type, reference in authorization.role_targets:
        if not role or not name or not target_platform or not connection_type or not reference:
            raise ExecutionValidationError("execution authorization target is incomplete")
        if name in target_names:
            raise ExecutionValidationError("execution authorization target names are not unique")
        target_names.add(name)
        if target_platform not in platform_requirements[role]:
            raise ExecutionValidationError("execution authorization platform mismatch")
        if connection_type != backend.name:
            raise ExecutionValidationError("execution authorization target backend mismatch")
    missing_capabilities = sorted(required_capabilities - backend.capabilities)
    if missing_capabilities:
        raise ExecutionValidationError(
            "backend lacks required capabilities: " + ", ".join(missing_capabilities)
        )


def execute_scenario(
    scenario: dict[str, Any],
    authorization: ExecutionAuthorization,
    backend: ExecutionBackend,
) -> dict[str, Any]:
    _validate_execution_authorization(scenario, authorization, backend)
    started = time.monotonic()
    cleanup_stack: list[tuple[str, dict[str, Any]]] = []
    phase_results: list[dict[str, Any]] = []
    logs: list[dict[str, str]] = []
    primary_failure: dict[str, Any] | None = None

    for phase in scenario["phases"]:
        phase_name = phase["name"]
        phase_result = {"name": phase_name, "actions": [], "assertions": []}
        phase_results.append(phase_result)
        logs.append({"level": "info", "event": "phase_started", "phase": phase_name})

        for action in phase["actions"]:
            cleanups = cleanup_actions(action)
            for cleanup in reversed(cleanups):
                cleanup_stack.append((phase_name, cleanup))
            before = time.monotonic()
            try:
                outcome = backend.run_action(action, action_timeout(action), cleanup=False)
            except Exception:
                outcome = BackendOutcome(False, "backend_exception")
            entry = _result_entry("action", action["type"], outcome, time.monotonic() - before)
            phase_result["actions"].append(entry)
            logs.append(
                {
                    "level": "info" if outcome.ok else "error",
                    "event": "action_finished",
                    "phase": phase_name,
                    "type": action["type"],
                    "status": entry["status"],
                }
            )
            if not outcome.ok:
                primary_failure = _failure(phase_name, entry)
                break
        if primary_failure:
            break

        for assertion in phase["assertions"]:
            before = time.monotonic()
            try:
                outcome = backend.evaluate_assertion(assertion)
            except Exception:
                outcome = BackendOutcome(False, "backend_exception")
            entry = _result_entry(
                "assertion", assertion["type"], outcome, time.monotonic() - before
            )
            phase_result["assertions"].append(entry)
            logs.append(
                {
                    "level": "info" if outcome.ok else "error",
                    "event": "assertion_finished",
                    "phase": phase_name,
                    "type": assertion["type"],
                    "status": entry["status"],
                }
            )
            if not outcome.ok:
                primary_failure = _failure(phase_name, entry)
                break
        if primary_failure:
            break

    cleanup_results: list[dict[str, Any]] = []
    cleanup_failures: list[dict[str, Any]] = []
    while cleanup_stack:
        source_phase, cleanup = cleanup_stack.pop()
        before = time.monotonic()
        try:
            outcome = backend.run_action(
                cleanup, action_timeout(cleanup), cleanup=True
            )
        except Exception:
            outcome = BackendOutcome(False, "backend_exception")
        entry = _result_entry(
            "cleanup", cleanup["type"], outcome, time.monotonic() - before
        )
        entry["source_phase"] = source_phase
        cleanup_results.append(entry)
        logs.append(
            {
                "level": "info" if outcome.ok else "error",
                "event": "cleanup_finished",
                "phase": source_phase,
                "type": cleanup["type"],
                "status": entry["status"],
            }
        )
        if not outcome.ok:
            cleanup_failures.append(_failure(source_phase, entry))

    failed = primary_failure is not None or bool(cleanup_failures)
    assertion_results = [
        assertion
        for phase in phase_results
        for assertion in phase["assertions"]
    ]
    modeled_assertions = sum(
        1 for assertion in assertion_results if assertion["modeled"]
    )
    unmodeled_assertions = len(assertion_results) - modeled_assertions
    return {
        "schema_version": 1,
        "mode": "executed",
        "commit": current_commit(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
        },
        "scenario": {
            "id": scenario["id"],
            "status": "failed" if failed else "passed",
            "duration_ms": round((time.monotonic() - started) * 1000),
            "primary_failure": primary_failure,
            "cleanup_failures": cleanup_failures,
            "modeled_assertions": modeled_assertions,
            "unmodeled_assertions": unmodeled_assertions,
            "phases": phase_results,
            "cleanup": cleanup_results,
        },
        "session_counts": backend.session_counts(),
        "logs": logs,
        "safety": {
            "backend": backend.name,
            "network_access_performed": backend.network_access_performed,
            "processes_started": backend.processes_started,
        },
    }


def current_commit() -> str:
    repository = pathlib.Path(__file__).resolve().parents[2]
    dot_git = repository / ".git"
    try:
        if dot_git.is_file():
            marker = dot_git.read_text(encoding="utf-8").strip()
            if not marker.startswith("gitdir: "):
                return "unknown"
            git_dir = pathlib.Path(marker.removeprefix("gitdir: "))
            if not git_dir.is_absolute():
                git_dir = (repository / git_dir).resolve()
        else:
            git_dir = dot_git
        head = (git_dir / "HEAD").read_text(encoding="ascii").strip()
        if re.fullmatch(r"[0-9a-fA-F]{40}", head):
            return head.lower()
        if not head.startswith("ref: "):
            return "unknown"
        reference = head.removeprefix("ref: ")
        candidates = [git_dir / reference]
        common_dir_file = git_dir / "commondir"
        common_dir = git_dir
        if common_dir_file.exists():
            common_dir = (git_dir / common_dir_file.read_text(encoding="utf-8").strip()).resolve()
            candidates.append(common_dir / reference)
        for candidate in candidates:
            if candidate.exists():
                commit = candidate.read_text(encoding="ascii").strip().lower()
                if re.fullmatch(r"[0-9a-f]{40}", commit):
                    return commit
        packed_refs = common_dir / "packed-refs"
        if packed_refs.exists():
            for line in packed_refs.read_text(encoding="ascii").splitlines():
                if line.startswith(("#", "^")):
                    continue
                parts = line.split(" ", 1)
                if len(parts) == 2 and parts[1] == reference:
                    commit = parts[0].lower()
                    if re.fullmatch(r"[0-9a-f]{40}", commit):
                        return commit
    except OSError:
        return "unknown"
    return "unknown"
