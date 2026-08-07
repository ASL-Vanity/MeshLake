# Session observability

`GET http://127.0.0.1:51821/v1/sessions` returns a versioned, sanitized view of
the daemon's process-local pairwise sessions. The CLI exposes the same data:

```text
meshlake-cli sessions
meshlake-cli sessions --json
```

The JSON response is a `schema_version: 1` object containing the current
transport revision and a deterministically sorted `sessions` array. Each entry
contains:

- `network_id` and `peer_device_id` (the complete isolation key)
- `state`: `pending`, `established`, or a short-lived `expired` tombstone
- `path`: `unknown`, `direct`, `relay`, `turn`, or `tls_relay`
- `age_ms`
- bounded queue depth/capacity/drop counters
- handshake, successful encrypted-send, authenticated-receive and
  rejected-receive counts

It never returns session keys, network PSKs, private identity material, raw
handshake packets, endpoints, packet payloads, plaintext, or ciphertext.

Expired observations are retained for at most five minutes and are not
persistent. Authorization changes, peer identity changes, transport revision
changes, daemon restarts and worker restarts remove observations from the old
security context immediately instead of retaining tombstones.
