# Testing

All integration tests require the binaries to be built first (`make all`). Most tests require root.

## Test targets

| Makefile target | Script | Root | Description |
|---|---|---|---|
| `make test` | `scripts/test_e2e.sh` | ✅ | End-to-end smoke test on loopback: blocked before knock, allowed after AUTH+BIND, deauth closes session, timeout re-blocks, replay rejected |
| `make test-netns` | `scripts/test_e2e_netns.sh` | ✅ | Two-host scenario using Linux network namespaces and a virtual L2 topology |
| `make test-ssh` | `scripts/test_e2e_netns_ssh.sh` | ✅ | Real SSH client/server flow through the protected port in a netns (requires `sshd`) |
| `make test-user-auth` | `scripts/test_e2e_user_auth.sh` | ✅ | Per-user registration and isolation: user A's key must not authorize user B |
| `make test-user-rotation` | `scripts/test_e2e_user_rotation.sh` | ✅ | Key rotation with grace window: old key still works during grace, rejected after |
| `make test-user-admin` | `scripts/test_e2e_user_admin.sh` | ✅ | Live admin commands: register, rotate, revoke while daemon is running |
| `make test-user-pressure` | `scripts/test_e2e_user_pressure.sh` | ✅ | Rate-limit and session-count enforcement |
| `make test-config` | `scripts/test_cli_replay_window_validation.sh` | ❌ | CLI validation: daemon rejects `--replay-window-ms` below 30000 |
| `make test-user-all` | runs auth + rotation + admin | ✅ | All per-user feature tests |
| `make all-test` | runs all suites | ✅ | Full test suite |

## What `make test` (smoke test) covers

The `test_e2e.sh` script exercises 11 numbered scenarios on the loopback interface:

1. Unauthorized access to the protected port is blocked.
2. Sending a valid signed AUTH knock packet.
3. Sending a BIND packet and confirming authorized access succeeds.
4. Sending a DEAUTH packet with a **wrong** session ID — must be ignored.
5. Verifying the wrong-session DEAUTH incremented `deauth_miss` and the session is still active.
6. Sending a DEAUTH packet with the **correct** session ID.
7. Verifying access is immediately blocked after deauth.
8. Re-authenticating with a fresh AUTH+BIND.
9. Replaying the old DEAUTH packet for the previous session — must not revoke the new session.
10. Confirming the new session is still active.
11. Waiting for the authorization timeout and confirming access is blocked again.
12. Replaying the original AUTH knock — must be rejected by the nonce table.

## Diagnostic output

On test failure the script dumps:

- `knockd` daemon log (`/tmp/knockd_test.log`)
- knock-client output logs
- `bpftool map dump` for `stats_map`, `pending_auth_map`, `active_session_map`, `replay_nonce_map`

## Running a single test manually

```bash
make all
sudo bash scripts/test_e2e.sh
```

```bash
make all
sudo bash scripts/test_e2e_user_auth.sh
```

## Admin panel tests

```bash
cd admin-panel
bash run-tests.sh
```

Or separately:

```bash
cd admin-panel/backend && python3 -m pytest tests/ -v
cd admin-panel/frontend && npm run test
```

## Viewing BPF stats after a test

```bash
bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map
```

Key counters to check:

| Counter | What a healthy run shows |
|---|---|
| `knock_seen` | ≥ number of AUTH/BIND/DEAUTH packets sent |
| `knock_valid` | Equals the number of valid AUTH + BIND packets |
| `knock_deauth` | Equals the number of successful DEAUTH packets |
| `replay_drop` | > 0 after replay tests |
| `deauth_miss` | > 0 after wrong-session deauth test |
| `protected_drop` | > 0 for unauthenticated connection attempts |
| `protected_pass` | > 0 for authorized connection attempts |
