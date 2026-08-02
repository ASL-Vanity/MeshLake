"""Safety-gated execution support for MeshLake system scenarios.

Only the deterministic simulation backend is enabled here. It exercises the
same orchestration, timeout, assertion, and cleanup paths as a future lab
transport without starting processes or opening network connections.
"""

from __future__ import annotations

import hmac
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

SUPPORTED_ACTION_TYPES = {
    "apply_network_policy",
    "block_direct_path",
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
    "restore_member_authorization",
    "restore_network_policy",
    "restore_original_state",
    "restore_relay_configuration",
    "restore_root_configuration",
    "shutdown_adapter",
    "start_service",
    "unenroll_nodes",
}

DESTRUCTIVE_ACTION_CLEANUPS = {
    "apply_network_policy": {"restore_network_policy"},
    "block_direct_path": {"restore_direct_path"},
    "configure_controller_tls": {"restore_controller_tls", "remove_test_ca"},
    "configure_ordered_relays": {"restore_relay_configuration"},
    "configure_ordered_roots": {"restore_root_configuration"},
    "create_network": {"delete_network"},
    "create_state_backup": {"remove_temporary_backup"},
    "enroll_nodes": {"unenroll_nodes"},
    "establish_pairwise_session": {"close_sessions"},
    "establish_sessions": {"close_sessions"},
    "inject_dns_apply_failure": {"restore_network_policy"},
    "inject_policy_rollback_failure": {"restore_network_policy", "shutdown_adapter"},
    "inject_route_apply_failure": {"restore_network_policy"},
    "replace_state_from_backup": {"restore_original_state"},
    "restart_daemon": {"ensure_daemon_running"},
    "revoke_member": {"restore_member_authorization"},
    "start_adapter": {"shutdown_adapter"},
    "stop_service": {"start_service"},
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


@dataclass(frozen=True)
class TransportRequest:
    """Non-secret request passed to a future transport implementation."""

    target_ref: str
    operation: str
    arguments: tuple[str, ...] = ()


class Transport:
    """Narrow transport contract; this branch intentionally ships no transports."""

    capabilities: frozenset[str] = frozenset()

    def invoke(self, request: TransportRequest, timeout_seconds: int) -> BackendOutcome:
        del request, timeout_seconds
        raise NotImplementedError


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", value.lower())


def reject_sensitive_inventory(value: Any, location: str = "inventory") -> None:
    """Reject suspected secret material without echoing its value."""

    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            normalized = _normalized_key(key_text)
            if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
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
    roles = item.get("roles")
    if roles is not None:
        if not isinstance(roles, list) or any(role not in declared_roles for role in roles):
            raise ExecutionValidationError(
                f"{source}: phase {phase_name} has invalid roles target list"
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
    unknown_capabilities = sorted(
        set(required_capabilities) - ({"simulation"} | KNOWN_TRANSPORT_CAPABILITIES)
    )
    if unknown_capabilities:
        raise ExecutionValidationError(
            f"{source}: unknown execution capabilities: "
            + ", ".join(unknown_capabilities)
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
            required = DESTRUCTIVE_ACTION_CLEANUPS.get(action_type, set())
            present = {cleanup["type"] for cleanup in cleanups}
            missing = sorted(required - present)
            if missing:
                raise ExecutionValidationError(
                    f"{source}: phase {phase_name} action {action_type} lacks cleanup: "
                    + ", ".join(missing)
                )
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
    inventory: dict[str, Any],
    inventory_hosts: dict[str, dict[str, Any]],
    allow_targets: Iterable[str],
    confirmed_lab_id: str | None,
    backend_name: str,
) -> None:
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


@dataclass(frozen=True)
class BackendOutcome:
    ok: bool
    code: str = "ok"


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
    snapshots: dict[str, int] = field(default_factory=dict)

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
        elif action_type == "establish_sessions":
            for network in action.get("networks", ["default"]):
                self.sessions[str(network)] = max(1, self.sessions.get(str(network), 0))
        elif action_type in {"close_sessions", "restart_daemon"}:
            network = action.get("network")
            if network is None:
                self.sessions.clear()
            else:
                self.sessions[str(network)] = 0
        elif action_type == "revoke_member":
            self.sessions[str(action.get("network", "default"))] = 0
        elif action_type == "capture_session_snapshot":
            self.snapshots[str(action.get("name", "snapshot"))] = sum(
                self.sessions.values()
            )
        return BackendOutcome(True)

    def evaluate_assertion(self, assertion: dict[str, Any]) -> BackendOutcome:
        assertion_type = assertion["type"]
        if assertion_type in self.fail_assertions:
            return BackendOutcome(False, "simulated_assertion_failure")
        return BackendOutcome(True)

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
        "duration_ms": round(elapsed * 1000),
    }


def _failure(phase: str, entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": phase,
        "kind": entry["kind"],
        "type": entry["type"],
        "code": entry["code"],
    }


def execute_scenario(
    scenario: dict[str, Any], backend: ExecutionBackend
) -> dict[str, Any]:
    required_capabilities = set(
        scenario.get("execution", {}).get("required_capabilities", ["simulation"])
    )
    missing_capabilities = sorted(required_capabilities - backend.capabilities)
    if missing_capabilities:
        raise ExecutionValidationError(
            "backend lacks required capabilities: " + ", ".join(missing_capabilities)
        )
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
