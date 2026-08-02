#!/usr/bin/env python3
"""Offline planner/validator for MeshLake cross-host system scenarios.

This stage deliberately performs no SSH, WinRM, VM or cloud operations. It
validates declarative scenarios and an optional inventory, then emits a stable
execution plan for a future executor.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent
SCENARIO_DIR = ROOT / "scenarios"
SCHEMA_VERSION = 1
SUPPORTED_PLATFORMS = {"windows", "linux"}


class ValidationError(ValueError):
    pass


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValidationError(f"{path} must contain a JSON object")
    return value


def scenario_files() -> list[pathlib.Path]:
    return sorted(SCENARIO_DIR.glob("*.json"))


def validate_scenario(path: pathlib.Path, scenario: dict[str, Any]) -> None:
    required = {"schema_version", "id", "description", "hosts", "phases"}
    missing = sorted(required - scenario.keys())
    if missing:
        raise ValidationError(f"{path}: missing fields: {', '.join(missing)}")
    if scenario["schema_version"] != SCHEMA_VERSION:
        raise ValidationError(f"{path}: unsupported schema_version")
    if not isinstance(scenario["id"], str) or not scenario["id"]:
        raise ValidationError(f"{path}: id must be a non-empty string")
    if path.stem != scenario["id"]:
        raise ValidationError(f"{path}: file name must match scenario id")
    hosts = scenario["hosts"]
    if not isinstance(hosts, list) or not hosts:
        raise ValidationError(f"{path}: hosts must be a non-empty array")
    roles: set[str] = set()
    for host in hosts:
        if not isinstance(host, dict):
            raise ValidationError(f"{path}: each host requirement must be an object")
        role = host.get("role")
        platforms = host.get("platforms")
        if not isinstance(role, str) or not role or role in roles:
            raise ValidationError(f"{path}: host roles must be unique non-empty strings")
        roles.add(role)
        if (
            not isinstance(platforms, list)
            or not platforms
            or any(platform not in SUPPORTED_PLATFORMS for platform in platforms)
        ):
            raise ValidationError(f"{path}: role {role} has invalid platforms")
    phases = scenario["phases"]
    if not isinstance(phases, list) or not phases:
        raise ValidationError(f"{path}: phases must be a non-empty array")
    phase_names: set[str] = set()
    for phase in phases:
        if not isinstance(phase, dict):
            raise ValidationError(f"{path}: every phase must be an object")
        name = phase.get("name")
        if not isinstance(name, str) or not name or name in phase_names:
            raise ValidationError(f"{path}: phase names must be unique non-empty strings")
        phase_names.add(name)
        for field in ("actions", "assertions"):
            values = phase.get(field)
            if not isinstance(values, list) or not values:
                raise ValidationError(f"{path}: phase {name} needs non-empty {field}")
            for value in values:
                if not isinstance(value, dict) or not isinstance(value.get("type"), str):
                    raise ValidationError(
                        f"{path}: phase {name} {field} entries need a string type"
                    )


def load_scenarios() -> dict[str, dict[str, Any]]:
    scenarios: dict[str, dict[str, Any]] = {}
    for path in scenario_files():
        scenario = load_json(path)
        validate_scenario(path, scenario)
        identifier = scenario["id"]
        if identifier in scenarios:
            raise ValidationError(f"duplicate scenario id: {identifier}")
        scenarios[identifier] = scenario
    if not scenarios:
        raise ValidationError(f"no scenarios found under {SCENARIO_DIR}")
    return scenarios


def validate_inventory(
    path: pathlib.Path, inventory: dict[str, Any], scenario: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    if inventory.get("schema_version") != SCHEMA_VERSION:
        raise ValidationError(f"{path}: unsupported inventory schema_version")
    hosts = inventory.get("hosts")
    if not isinstance(hosts, list):
        raise ValidationError(f"{path}: hosts must be an array")
    by_role: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for host in hosts:
        if not isinstance(host, dict):
            raise ValidationError(f"{path}: every host must be an object")
        role = host.get("role")
        name = host.get("name")
        platform = host.get("platform")
        if not isinstance(role, str) or not role or role in by_role:
            raise ValidationError(f"{path}: host roles must be unique non-empty strings")
        if not isinstance(name, str) or not name or name in names:
            raise ValidationError(f"{path}: host names must be unique non-empty strings")
        if platform not in SUPPORTED_PLATFORMS:
            raise ValidationError(f"{path}: host {name} has unsupported platform")
        if "address" in host and not isinstance(host["address"], str):
            raise ValidationError(f"{path}: host {name} address must be a string")
        names.add(name)
        by_role[role] = host
    for requirement in scenario["hosts"]:
        role = requirement["role"]
        host = by_role.get(role)
        if host is None:
            raise ValidationError(f"{path}: missing required role {role}")
        if host["platform"] not in requirement["platforms"]:
            raise ValidationError(
                f"{path}: role {role} platform {host['platform']} is not allowed"
            )
    return by_role


def build_plan(
    scenario: dict[str, Any], inventory_hosts: dict[str, dict[str, Any]] | None
) -> dict[str, Any]:
    assignments = []
    for requirement in scenario["hosts"]:
        role = requirement["role"]
        if inventory_hosts is None:
            assignments.append(
                {"role": role, "platforms": requirement["platforms"], "assigned": False}
            )
        else:
            host = inventory_hosts[role]
            assignments.append(
                {
                    "role": role,
                    "platform": host["platform"],
                    "name": host["name"],
                    "address": host.get("address"),
                    "assigned": True,
                }
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "offline_plan",
        "scenario": scenario["id"],
        "description": scenario["description"],
        "hosts": assignments,
        "phases": scenario["phases"],
        "network_access_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list validated scenarios")
    parser.add_argument("--scenario", help="scenario id to validate and plan")
    parser.add_argument("--inventory", type=pathlib.Path, help="optional host inventory JSON")
    parser.add_argument("--json", action="store_true", help="emit stable JSON")
    parser.add_argument(
        "--validate-all", action="store_true", help="validate every scenario and exit"
    )
    args = parser.parse_args()

    try:
        scenarios = load_scenarios()
        if args.validate_all:
            result: Any = {
                "schema_version": SCHEMA_VERSION,
                "valid": True,
                "scenarios": sorted(scenarios),
                "network_access_performed": False,
            }
        elif args.list:
            result = [
                {"id": item["id"], "description": item["description"]}
                for item in scenarios.values()
            ]
        elif args.scenario:
            if args.scenario not in scenarios:
                raise ValidationError(f"unknown scenario: {args.scenario}")
            scenario = scenarios[args.scenario]
            inventory_hosts = None
            if args.inventory:
                inventory = load_json(args.inventory)
                inventory_hosts = validate_inventory(args.inventory, inventory, scenario)
            result = build_plan(scenario, inventory_hosts)
        else:
            parser.error("choose --list, --validate-all or --scenario")
            return 2
    except ValidationError as error:
        print(f"system test validation failed: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif isinstance(result, list):
        for item in result:
            print(f"{item['id']}: {item['description']}")
    elif result.get("mode") == "offline_plan":
        print(f"Scenario: {result['scenario']}")
        print("Mode: offline plan (no network access)")
        for host in result["hosts"]:
            if host["assigned"]:
                print(f"  {host['role']}: {host['name']} ({host['platform']})")
            else:
                print(f"  {host['role']}: unassigned ({'/'.join(host['platforms'])})")
        for phase in result["phases"]:
            print(
                f"  phase {phase['name']}: "
                f"{len(phase['actions'])} action(s), {len(phase['assertions'])} assertion(s)"
            )
    else:
        print(f"Validated {len(result['scenarios'])} scenario(s); no network access performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
