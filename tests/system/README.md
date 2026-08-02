# MeshLake cross-host system-test framework

This directory contains an offline scenario planner for later Windows/Linux
acceptance testing. The current runner validates JSON and emits plans only: it
does not connect to hosts, start daemons, alter adapters, or require elevation.

Examples:

```powershell
.\tests\system\run.ps1 -ValidateAll
.\tests\system\run.ps1 -Scenario direct-relay-fallback -Json
```

```sh
./tests/system/run.sh --validate-all
./tests/system/run.sh --scenario daemon-restart --json
```

An inventory is optional for planning. Copy `inventory.example.json` outside
the repository, replace every placeholder, and pass it with `--inventory` or
`-Inventory`. Inventory files must not contain passwords, tokens, invitation
links, network PSKs, private keys, or session material.

Future executors should implement the declarative action/assertion types while
preserving these invariants:

- `/v1/sessions` is used only for sanitized metadata and counters.
- `(network_id, peer_device_id)` is the session isolation key.
- revocation, identity changes, transport revision changes and daemon restarts
  invalidate observations from the old security context.
- destructive/fault actions target only explicitly assigned disposable hosts.
