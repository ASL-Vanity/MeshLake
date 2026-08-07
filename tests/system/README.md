# MeshLake system-test framework

This directory contains the offline planner and the safety-gated stage 3
scenario executor. Planner commands remain side-effect free. Execution requires
an explicit `--execute` and currently supports only `backend=simulated`; it does
not start host processes, open network connections, or perform real host work.

Planner examples:

```powershell
.\tests\system\run.ps1 -ValidateAll
.\tests\system\run.ps1 -Scenario direct-relay-fallback -Json
```

```sh
./tests/system/run.sh --validate-all
./tests/system/run.sh --scenario daemon-restart --json
```

Inventory schema version 1 remains accepted for offline planning. Executions
require schema version 2, which stores only host roles and non-secret connection
references. Every assigned target must be marked `disposable: true`, named in
an exact allowlist, and use `connection.type=simulated`. Passwords, tokens,
private keys, PSKs, credentials, and `meshlake://join` content are rejected
before execution.

Example simulated execution:

```powershell
.\tests\system\run.ps1 `
  -Scenario adapter-shutdown `
  -Inventory .\tests\system\inventory.example.json `
  -Execute `
  -Backend simulated `
  -AllowTarget sim-node-a `
  -ConfirmLabId 8e92b54e-3df6-4f44-9098-b26ffdf1af54 `
  -Json
```

The `lab_id` must be a version 4 UUID and must exactly match
`--confirm-lab-id`. This is an exact lab confirmation, not a one-time or
replay-resistant authorization. A wildcard allowlist is forbidden. Future real
transports must atomically consume a persistent run nonce/receipt and expose the
`single-use-run-receipt` capability before execution. Scenarios must explicitly
allow execution and declare backend capabilities. Destructive actions have
bounded timeouts and must include complete, target-matched, idempotent cleanup
actions. Cleanup runs in reverse registration order after success, primary
failure, or assertion failure; its failures are reported separately from the
primary failure.

Execution output contains only commit and platform metadata, sanitized event
records, scenario/action/assertion results, cleanup status, session counters,
and explicit simulator safety counters. It does not contain command lines,
packet data, connection references, host addresses, credentials, or keys.

The executor defines a narrow transport request/interface for later local,
SSH, or WinRM adapters. This branch provides no transport implementation and
fails closed when a scenario requests a capability other than `simulation`.
Session presence, absence, per-network counts, and empty session lists are
modeled by the simulator. Other assertions are orchestration placeholders and
are reported with `modeled=false` and `code=simulated_not_modeled`; they do not
claim that real platform or protocol semantics were verified.

Run the framework tests with:

```powershell
python -m unittest discover -s tests\system -p "test_*.py"
```

On Windows, `run.ps1` uses `MESHLAKE_PYTHON` when set, then `py -3`, then
`python`. This avoids treating the Microsoft Store command alias as the only
available runtime.

The declarative scenarios preserve these invariants:

- `/v1/sessions` is used only for sanitized metadata and counters.
- `(network_id, peer_device_id)` is the session isolation key.
- revocation, identity changes, transport revision changes, and daemon restarts
  invalidate observations from the old security context.
- destructive and fault actions target only assigned disposable lab hosts.
- `turn-fallback` expresses the complete intended order: direct UDP, UDP TURN, pinned TLS TURN, authenticated MeshLake UDP Relay, then Planet V4 pinned TLS Relay. The public session path intentionally reports both TURN transports as `turn`, so the scenario records the selected tier through its ordered fault phases rather than exposing endpoints or credentials.
- `tls-relay-fallback` remains a focused direct/UDP Relay/TLS Relay scenario. The simulator verifies orchestration only; real validation must still verify certificate pin rejection, TURN allocation and refresh, TCP/TLS framing, IPv4/IPv6 and cleanup.
