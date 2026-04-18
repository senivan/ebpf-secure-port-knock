# Configuration

Configuration is split between **daemon CLI flags** (passed at startup) and **compiled-in constants** in `include/shared.h`.

## Daemon flags — `knockd daemon`

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--ifname <iface>` | ✅ | — | Network interface to attach XDP on (e.g. `eth0`, `lo`) |
| `--protect <ports>` | ✅ | — | Comma-separated list of TCP ports to protect (e.g. `22,443`) |
| `--users-file <path>` | ✅* | — | Path to a CSV file containing `user_id,hmac_key_hex` entries |
| `--hmac-key <64 hex>` | ✅* | — | Single 32-byte key in hex. Registers as user ID `0`. Use instead of `--users-file` |
| `--knock-port <port>` | | `40000` | TCP port on which knock packets are expected |
| `--timeout-ms <ms>` | | `5000` | How long an authorized session stays active after a successful BIND knock |
| `--replay-window-ms <ms>` | | `30000` | Nonce replay-protection window. **Must be ≥ 30000 (30 s)** — the daemon rejects smaller values at startup |
| `--bind-window-ms <ms>` | | `3000` | How long the kernel waits for a BIND packet after an AUTH knock |
| `--duration-sec <sec>` | | indefinite | Auto-detach after this many seconds (useful for testing) |

\* Exactly one of `--users-file` or `--hmac-key` must be provided.

### Example — full options

```bash
sudo ./build/knockd daemon \
  --ifname eth0 \
  --users-file /etc/knock/users.csv \
  --protect 22,80,443 \
  --knock-port 40000 \
  --timeout-ms 10000 \
  --replay-window-ms 60000 \
  --bind-window-ms 5000
```

## Knock client flags — `knock-client`

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--ifname <iface>` | ✅ | — | Interface to send the raw Ethernet frame on |
| `--src-ip <ip>` | ✅ | — | Source IPv4 address |
| `--dst-ip <ip>` | ✅ | — | Destination (server) IPv4 address |
| `--dst-port <port>` | ✅ | — | Knock port on the server |
| `--hmac-key <64 hex>` | ✅ | — | 32-byte HMAC key in hex |
| `--user-id <id>` | | auto | Numeric user ID embedded in bits 31-16 of `session_id_hi`. Required for AUTH unless `--session-id` is given |
| `--session-id <id>` | | generated | Override the full 64-bit session ID (needed for BIND and DEAUTH) |
| `--packet-type <type>` | | `auth` | One of `auth`, `bind`, `deauth` |
| `--src-port <port>` | | random | Source TCP port (for BIND, must match the port your real connection will use) |
| `--bind-port <port>` | | — | Protected port to bind to (required for BIND packets) |
| `--timestamp-sec <ts>` | | current time | Unix timestamp override (for testing) |
| `--nonce <n>` | | random | 32-bit nonce override (for testing) |

## `make run` variable map

| Makefile variable | Daemon flag |
|---|---|
| `IFACE` | `--ifname` |
| `USERS_FILE` | `--users-file` |
| `PROTECT` | `--protect` |
| `HMAC_KEY` | `--hmac-key` |
| `KNOCK_PORT` | `--knock-port` |
| `TIMEOUT_MS` | `--timeout-ms` |
| `REPLAY_WINDOW_MS` | `--replay-window-ms` |
| `DURATION_SEC` | `--duration-sec` |

```bash
make run IFACE=eth0 USERS_FILE=/etc/knock/users.csv PROTECT=22,443 KNOCK_PORT=40000 TIMEOUT_MS=5000
```

## Compiled-in constants (`include/shared.h`)

These values are baked into both the kernel object and user-space binaries at compile time and cannot be changed at runtime.

| Constant | Value | Description |
|---|---|---|
| `KNOCK_MAGIC` | `0x4b4e4f43` (`"KNOC"`) | 4-byte magic at the start of every knock packet |
| `KNOCK_HMAC_KEY_LEN` | `32` | Key length in bytes |
| `KNOCK_SIGNATURE_WORDS` | `4` | 32-bit words in the signature (= 128 bits total) |
| `KNOCK_MAX_PROTECTED_PORTS` | `16` | Max number of ports that can be protected simultaneously |
| `KNOCK_MAX_USERS` | `1024` | Max registered users in `user_key_map` |
| `KNOCK_MAX_CLOCK_SKEW_SEC` | `30` | Max ±timestamp drift accepted |
| `KNOCK_MIN_REPLAY_WINDOW_MS` | `30000` | Minimum `--replay-window-ms` (enforced by daemon) |
| `KNOCK_DEFAULT_PORT` | `40000` | Default knock port |
| `KNOCK_DEFAULT_TIMEOUT_MS` | `5000` | Default session timeout |
| `KNOCK_DEFAULT_BIND_WINDOW_MS` | `3000` | Default pending-auth TTL |
| `KNOCK_DEFAULT_REPLAY_WINDOW_MS` | `30000` | Default replay window |
| `KNOCK_SOURCE_PRESSURE_WINDOW_NS` | `10,000,000,000` | Rate-limit measurement window (10 s in nanoseconds) |
| `KNOCK_MAX_KNOCKS_PER_SOURCE_WINDOW` | `128` | Max knocks per source IP per 10 s window |
| `KNOCK_MAX_ACTIVE_SESSIONS_PER_SOURCE` | `32` | Max concurrent active sessions per source IP |

## BPF map mount path

Pinned maps are written to `/sys/fs/bpf/knock_gate/` by default. All admin sub-commands (`register-user`, `rotate-user-key`, `revoke-user`, `list-users`) operate on maps at this path without requiring a daemon restart.

## Users file format

```
# user_id,hmac_key_hex
100,00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
101,aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
```

Lines beginning with `#` are comments. Each `hmac_key_hex` must be exactly 64 hexadecimal characters (32 bytes).
