from __future__ import annotations

import contextlib
import io
import pathlib
import sys
import unittest
from unittest import mock


SYSTEM_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SYSTEM_DIR))

import runner  # noqa: E402
from executor import (  # noqa: E402
    ExecutionAuthorization,
    ExecutionValidationError,
    SimulatedBackend,
    execute_scenario,
    reject_sensitive_inventory,
    validate_execution_gate,
    validate_execution_schema,
)


LAB_ID = "18cf45b4-2df2-47ee-aefb-a97fcbac2554"


def scenario_with(
    actions: list[dict[str, object]], assertions: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "id": "test-scenario",
        "description": "test",
        "execution": {"allowed": True, "required_capabilities": ["simulation"]},
        "hosts": [{"role": "node_a", "platforms": ["windows"]}],
        "phases": [
            {
                "name": "phase",
                "actions": actions,
                "assertions": assertions,
            }
        ],
    }


def executable_scenario(action: dict[str, object]) -> dict[str, object]:
    return scenario_with([action], [{"type": "adapter_stopped", "role": "node_a"}])


def execution_inventory() -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    host = {
        "role": "node_a",
        "name": "sim-node-a",
        "platform": "windows",
        "disposable": True,
        "connection": {"type": "simulated", "ref": "lab/node-a"},
    }
    inventory = {
        "schema_version": 2,
        "lab_id": LAB_ID,
        "hosts": [host],
    }
    return inventory, {"node_a": host}


def authorize(scenario: dict[str, object]) -> ExecutionAuthorization:
    inventory, hosts = execution_inventory()
    return validate_execution_gate(
        "inventory.json",
        scenario,
        inventory,
        hosts,
        ["sim-node-a"],
        LAB_ID,
        "simulated",
    )


class RunnerSafetyTests(unittest.TestCase):
    def test_planner_does_not_construct_execution_backend(self) -> None:
        scenario = executable_scenario(
            {
                "type": "start_adapter",
                "role": "node_a",
                "cleanup": {
                    "type": "shutdown_adapter",
                    "role": "node_a",
                    "idempotent": True,
                },
            }
        )
        argv = ["runner.py", "--scenario", "test-scenario", "--json"]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(runner, "load_scenarios", return_value={"test-scenario": scenario}),
            mock.patch.object(
                runner,
                "SimulatedBackend",
                side_effect=AssertionError("planner entered execution path"),
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(runner.main(), 0)

    def test_execution_gate_returns_required_authorization(self) -> None:
        scenario = executable_scenario({"type": "wait_transport_ready", "roles": ["node_a"]})
        authorization = authorize(scenario)
        self.assertIsInstance(authorization, ExecutionAuthorization)
        self.assertEqual(authorization.scenario_id, "test-scenario")

        with self.assertRaisesRegex(ExecutionValidationError, "requires authorization"):
            execute_scenario(scenario, {}, SimulatedBackend())  # type: ignore[arg-type]

    def test_execution_authorization_is_bound_to_scenario(self) -> None:
        scenario = executable_scenario({"type": "wait_transport_ready", "roles": ["node_a"]})
        authorization = authorize(scenario)
        scenario["id"] = "changed-scenario"
        with self.assertRaisesRegex(ExecutionValidationError, "scenario mismatch"):
            execute_scenario(scenario, authorization, SimulatedBackend())

        scenario = executable_scenario({"type": "wait_transport_ready", "roles": ["node_a"]})
        authorization = authorize(scenario)
        scenario["description"] = "changed after authorization"
        with self.assertRaisesRegex(ExecutionValidationError, "digest mismatch"):
            execute_scenario(scenario, authorization, SimulatedBackend())

    def test_execution_gate_requires_exact_lab_confirmation(self) -> None:
        scenario = executable_scenario({"type": "wait_transport_ready", "roles": ["node_a"]})
        inventory, hosts = execution_inventory()
        with self.assertRaisesRegex(ExecutionValidationError, "confirmation"):
            validate_execution_gate(
                "inventory.json",
                scenario,
                inventory,
                hosts,
                ["sim-node-a"],
                None,
                "simulated",
            )

    def test_execution_gate_requires_disposable_exact_allowlist(self) -> None:
        scenario = executable_scenario({"type": "wait_transport_ready", "roles": ["node_a"]})
        inventory, hosts = execution_inventory()
        hosts["node_a"]["disposable"] = False
        with self.assertRaisesRegex(ExecutionValidationError, "disposable"):
            validate_execution_gate(
                "inventory.json",
                scenario,
                inventory,
                hosts,
                ["sim-node-a"],
                LAB_ID,
                "simulated",
            )
        hosts["node_a"]["disposable"] = True
        with self.assertRaisesRegex(ExecutionValidationError, "allowlist"):
            validate_execution_gate(
                "inventory.json",
                scenario,
                inventory,
                hosts,
                ["*"],
                LAB_ID,
                "simulated",
            )

    def test_primary_failure_still_runs_cleanup(self) -> None:
        scenario = executable_scenario(
            {
                "type": "start_adapter",
                "role": "node_a",
                "cleanup": {
                    "type": "shutdown_adapter",
                    "role": "node_a",
                    "idempotent": True,
                },
            }
        )
        backend = SimulatedBackend(fail_actions={"start_adapter"})
        result = execute_scenario(scenario, authorize(scenario), backend)
        self.assertEqual(result["scenario"]["status"], "failed")
        self.assertEqual(result["scenario"]["primary_failure"]["type"], "start_adapter")
        self.assertEqual(result["scenario"]["cleanup_failures"], [])
        self.assertIn(("shutdown_adapter", True), backend.calls)

    def test_cleanup_failure_is_separate_from_primary_failure(self) -> None:
        scenario = executable_scenario(
            {
                "type": "start_adapter",
                "role": "node_a",
                "cleanup": {
                    "type": "shutdown_adapter",
                    "role": "node_a",
                    "idempotent": True,
                },
            }
        )
        backend = SimulatedBackend(
            fail_actions={"start_adapter"}, fail_cleanups={"shutdown_adapter"}
        )
        result = execute_scenario(scenario, authorize(scenario), backend)
        self.assertEqual(result["scenario"]["primary_failure"]["type"], "start_adapter")
        self.assertEqual(
            result["scenario"]["cleanup_failures"][0]["type"], "shutdown_adapter"
        )

    def test_sensitive_inventory_fields_and_join_links_are_rejected(self) -> None:
        for inventory in (
            {"hosts": [{"password": "not-printed"}]},
            {"hosts": [{"connection": {"ref": "meshlake://join/example"}}]},
        ):
            with self.assertRaises(ExecutionValidationError) as raised:
                reject_sensitive_inventory(inventory)
            self.assertNotIn("not-printed", str(raised.exception))
            self.assertNotIn("meshlake://join/example", str(raised.exception))

    def test_sensitive_scenario_content_is_rejected_without_echo(self) -> None:
        private_key = "-----BEGIN PRIVATE KEY-----\nnot-printed\n-----END PRIVATE KEY-----"
        cases = (
            ("token-value", {"token": "token-value"}, {}),
            ("meshlake://join/not-safe", {"link": "meshlake://join/not-safe"}, {}),
            (private_key, {}, {"payload": private_key}),
            ("authorization-value", {}, {"Authorization": "authorization-value"}),
        )
        for secret, action_extra, assertion_extra in cases:
            action = {"type": "wait_transport_ready", "roles": ["node_a"]}
            action.update(action_extra)
            assertion = {"type": "adapter_stopped", "role": "node_a"}
            assertion.update(assertion_extra)
            scenario = scenario_with([action], [assertion])
            with self.assertRaises(runner.ValidationError) as raised:
                runner.validate_scenario(pathlib.Path("test-scenario.json"), scenario)
            self.assertNotIn(secret, str(raised.exception))

    def test_destructive_action_without_cleanup_is_rejected(self) -> None:
        scenario = executable_scenario({"type": "start_adapter", "role": "node_a"})
        with self.assertRaisesRegex(ExecutionValidationError, "lacks cleanup"):
            validate_execution_schema("scenario.json", scenario)

    def test_cleanup_identity_fields_must_match(self) -> None:
        role_mismatch = executable_scenario(
            {
                "type": "start_adapter",
                "role": "node_a",
                "cleanup": {
                    "type": "shutdown_adapter",
                    "role": "node_b",
                    "idempotent": True,
                },
            }
        )
        role_mismatch["hosts"].append(
            {"role": "node_b", "platforms": ["windows"]}
        )
        with self.assertRaisesRegex(ExecutionValidationError, "target mismatch"):
            validate_execution_schema("scenario.json", role_mismatch)

        cases = (
            (
                {
                    "type": "create_network",
                    "network": "network-a",
                    "cleanup": {
                        "type": "delete_network",
                        "network": "network-b",
                        "idempotent": True,
                    },
                },
                "target mismatch",
            ),
            (
            {
                "type": "stop_service",
                "role": "node_a",
                "service": "meshlaked",
                "cleanup": {
                    "type": "start_service",
                    "role": "node_a",
                    "service": "other-service",
                    "idempotent": True,
                },
            },
                "target mismatch",
            ),
            (
                {
                "type": "create_state_backup",
                "role": "node_a",
                "name": "backup-a",
                "cleanup": {
                    "type": "remove_temporary_backup",
                    "role": "node_a",
                    "name": "backup-b",
                    "idempotent": True,
                },
            },
                "target mismatch",
            ),
        )
        for action, expected_error in cases:
            scenario = executable_scenario(action)
            with self.assertRaisesRegex(ExecutionValidationError, expected_error):
                validate_execution_schema("scenario.json", scenario)

    def test_real_transport_requires_single_use_receipt_capability(self) -> None:
        scenario = executable_scenario({"type": "wait_transport_ready", "roles": ["node_a"]})
        scenario["execution"] = {"allowed": True, "required_capabilities": ["ssh"]}
        with self.assertRaisesRegex(ExecutionValidationError, "single-use-run-receipt"):
            validate_execution_schema("scenario.json", scenario)

    def test_raw_commands_and_undeclared_roles_are_rejected(self) -> None:
        raw_command = executable_scenario(
            {"type": "wait_transport_ready", "roles": ["node_a"], "command": "whoami"}
        )
        with self.assertRaisesRegex(ExecutionValidationError, "raw execution fields"):
            validate_execution_schema("scenario.json", raw_command)

        undeclared_role = executable_scenario(
            {"type": "wait_transport_ready", "roles": ["node_b"]}
        )
        with self.assertRaisesRegex(ExecutionValidationError, "invalid roles"):
            validate_execution_schema("scenario.json", undeclared_role)

    def test_session_assertions_use_simulated_state(self) -> None:
        backend = SimulatedBackend()
        self.assertFalse(
            backend.evaluate_assertion(
                {"type": "session", "network": "network-a", "state": "established"}
            ).ok
        )
        backend.run_action(
            {"type": "establish_sessions", "networks": ["network-a"]}, 30
        )
        self.assertFalse(
            backend.evaluate_assertion(
                {
                    "type": "session",
                    "network": "network-a",
                    "state": "established",
                    "path": "relay",
                }
            ).ok
        )
        self.assertTrue(
            backend.evaluate_assertion(
                {"type": "session_count_by_network", "network": "network-a", "minimum": 1}
            ).ok
        )
        self.assertFalse(
            backend.evaluate_assertion({"type": "session_list_empty"}).ok
        )
        backend.run_action({"type": "revoke_member", "network": "network-a"}, 30)
        self.assertTrue(
            backend.evaluate_assertion(
                {"type": "session_absent", "network": "network-a"}
            ).ok
        )

    def test_unmodeled_assertion_is_explicit_in_result(self) -> None:
        scenario = executable_scenario(
            {"type": "wait_transport_ready", "roles": ["node_a"]}
        )
        result = execute_scenario(
            scenario, authorize(scenario), SimulatedBackend()
        )
        assertion = result["scenario"]["phases"][0]["assertions"][0]
        self.assertEqual(assertion["code"], "simulated_not_modeled")
        self.assertFalse(assertion["modeled"])
        self.assertEqual(result["scenario"]["unmodeled_assertions"], 1)


if __name__ == "__main__":
    unittest.main()
