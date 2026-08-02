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
    ExecutionValidationError,
    SimulatedBackend,
    execute_scenario,
    reject_sensitive_inventory,
    validate_execution_gate,
    validate_execution_schema,
)


def executable_scenario(action: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "id": "test-scenario",
        "description": "test",
        "execution": {"allowed": True, "required_capabilities": ["simulation"]},
        "hosts": [{"role": "node_a", "platforms": ["windows"]}],
        "phases": [
            {
                "name": "phase",
                "actions": [action],
                "assertions": [{"type": "adapter_stopped"}],
            }
        ],
    }


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
        "lab_id": "18cf45b4-2df2-47ee-aefb-a97fcbac2554",
        "hosts": [host],
    }
    return inventory, {"node_a": host}


class RunnerSafetyTests(unittest.TestCase):
    def test_planner_does_not_construct_execution_backend(self) -> None:
        scenario = executable_scenario(
            {
                "type": "start_adapter",
                "cleanup": {
                    "type": "shutdown_adapter",
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

    def test_execution_gate_requires_exact_lab_confirmation(self) -> None:
        inventory, hosts = execution_inventory()
        with self.assertRaisesRegex(ExecutionValidationError, "confirmation"):
            validate_execution_gate(
                "inventory.json",
                inventory,
                hosts,
                ["sim-node-a"],
                None,
                "simulated",
            )

    def test_execution_gate_requires_disposable_exact_allowlist(self) -> None:
        inventory, hosts = execution_inventory()
        hosts["node_a"]["disposable"] = False
        with self.assertRaisesRegex(ExecutionValidationError, "disposable"):
            validate_execution_gate(
                "inventory.json",
                inventory,
                hosts,
                ["sim-node-a"],
                str(inventory["lab_id"]),
                "simulated",
            )
        hosts["node_a"]["disposable"] = True
        with self.assertRaisesRegex(ExecutionValidationError, "allowlist"):
            validate_execution_gate(
                "inventory.json",
                inventory,
                hosts,
                ["*"],
                str(inventory["lab_id"]),
                "simulated",
            )

    def test_primary_failure_still_runs_cleanup(self) -> None:
        scenario = executable_scenario(
            {
                "type": "start_adapter",
                "cleanup": {
                    "type": "shutdown_adapter",
                    "idempotent": True,
                },
            }
        )
        backend = SimulatedBackend(fail_actions={"start_adapter"})
        result = execute_scenario(scenario, backend)
        self.assertEqual(result["scenario"]["status"], "failed")
        self.assertEqual(result["scenario"]["primary_failure"]["type"], "start_adapter")
        self.assertEqual(result["scenario"]["cleanup_failures"], [])
        self.assertIn(("shutdown_adapter", True), backend.calls)

    def test_cleanup_failure_is_separate_from_primary_failure(self) -> None:
        scenario = executable_scenario(
            {
                "type": "start_adapter",
                "cleanup": {
                    "type": "shutdown_adapter",
                    "idempotent": True,
                },
            }
        )
        backend = SimulatedBackend(
            fail_actions={"start_adapter"}, fail_cleanups={"shutdown_adapter"}
        )
        result = execute_scenario(scenario, backend)
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

    def test_destructive_action_without_cleanup_is_rejected(self) -> None:
        scenario = executable_scenario({"type": "start_adapter"})
        with self.assertRaisesRegex(ExecutionValidationError, "lacks cleanup"):
            validate_execution_schema("scenario.json", scenario)

    def test_unimplemented_transport_capability_fails_closed(self) -> None:
        scenario = executable_scenario(
            {
                "type": "start_adapter",
                "cleanup": {"type": "shutdown_adapter", "idempotent": True},
            }
        )
        scenario["execution"] = {
            "allowed": True,
            "required_capabilities": ["ssh"],
        }
        with self.assertRaisesRegex(ExecutionValidationError, "lacks required capabilities"):
            execute_scenario(scenario, SimulatedBackend())

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


if __name__ == "__main__":
    unittest.main()
