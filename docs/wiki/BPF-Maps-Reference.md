# BPF Maps Reference

All maps are pinned under `/sys/fs/bpf/knock_gate/` at daemon startup and can be inspected with `bpftool map dump pinned <path>`.

---

## `config_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_ARRAY` |
| Max entries | 1 |
| Key | `__u32` (always `0`) |
| Value | `struct knock_config` |

Holds the single active gate configuration. Seeded by the daemon at attach time.

### `struct knock_config`

| Field | Type | Description |
|---|---|---|
| `knock_port` | `__u16` | Port that knock packets are sent to |
| `protected_count` | `__u16` | Number of ports in `protected_ports` |
| `protected_ports[16]` | `__u16[]` | List of protected TCP ports |
| `timeout_ms` | `__u32` | Active session TTL in milliseconds |
| `bind_window_ms` | `__u32` | Pending-auth TTL in milliseconds |
| `replay_window_ms` | `__u32` | Nonce replay window in milliseconds |
| `hmac_key[32]` | `__u8[]` | Legacy single-user HMAC key (unused in multi-user mode) |

---

## `user_key_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_HASH` |
| Max entries | 1024 (`KNOCK_MAX_USERS`) |
| Key | `__u32` (user_id) |
| Value | `struct user_key_state` |

Stores per-user HMAC keys. Written by `register-user` / `rotate-user-key` / `revoke-user`.

### `struct user_key_state`

| Field | Type | Description |
|---|---|---|
| `active_key[32]` | `__u8[]` | Current HMAC key (validated first) |
| `previous_key[32]` | `__u8[]` | Previous key after rotation (validated during grace window) |
| `key_version` | `__u32` | Monotonically increasing rotation counter |
| `grace_until_ns` | `__u64` | Monotonic timestamp until which `previous_key` is accepted |

---

## `pending_auth_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_HASH` |
| Max entries | 4096 |
| Key | `struct session_lookup_key` |
| Value | `struct pending_auth_state` |

Stores short-lived pending authorizations created by valid AUTH knock packets. Cleared when a corresponding BIND knock is received or the TTL expires.

### `struct session_lookup_key`

| Field | Type | Description |
|---|---|---|
| `src_ip` | `__u32` | Source IPv4 of the knock |
| `session_id_hi` | `__u32` | Upper 32 bits of the session ID |
| `session_id_lo` | `__u32` | Lower 32 bits of the session ID |

### `struct pending_auth_state`

| Field | Type | Description |
|---|---|---|
| `session_id_hi` | `__u32` | Echoed session ID (hi) |
| `session_id_lo` | `__u32` | Echoed session ID (lo) |
| `expires_at_ns` | `__u64` | Monotonic expiry timestamp (ns) |

---

## `active_session_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_HASH` |
| Max entries | 32768 |
| Key | `struct flow_key` |
| Value | `struct active_session_state` |

The primary enforcement map. Each entry represents an authorized `(src_ip, src_port, dst_port)` flow. All protected-port traffic is checked against this map.

### `struct flow_key`

| Field | Type | Description |
|---|---|---|
| `src_ip` | `__u32` | Source IPv4 |
| `dst_ip` | `__u32` | Destination IPv4 |
| `src_port` | `__u16` | Source TCP port (as bound) |
| `dst_port` | `__u16` | Destination TCP port (protected port) |
| `l4_proto` | `__u8` | L4 protocol (always `6` = TCP) |

### `struct active_session_state`

| Field | Type | Description |
|---|---|---|
| `session_id_hi` | `__u32` | Session ID (used for deauth lookup) |
| `session_id_lo` | `__u32` | Session ID |
| `expires_at_ns` | `__u64` | Monotonic expiry timestamp (ns) |

---

## `session_index_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_HASH` |
| Max entries | 32768 |
| Key | `struct session_lookup_key` |
| Value | `struct flow_key` |

Reverse index from `(src_ip, session_id)` to the flow key. Used by DEAUTH packets to locate and delete the corresponding entry in `active_session_map`.

---

## `replay_nonce_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_HASH` |
| Max entries | 8192 |
| Key | `struct replay_nonce_key` |
| Value | `struct replay_nonce_state` |

Anti-replay table. Each validated knock packet adds its nonce tuple here for the replay window duration.

### `struct replay_nonce_key`

| Field | Type | Description |
|---|---|---|
| `src_ip` | `__u32` | Source IPv4 |
| `nonce` | `__u32` | Packet nonce |
| `packet_type` | `__u8` | AUTH / BIND / DEAUTH |
| `session_id_hi` | `__u32` | Session ID (hi) |
| `session_id_lo` | `__u32` | Session ID (lo) |

### `struct replay_nonce_state`

| Field | Type | Description |
|---|---|---|
| `expires_at_ns` | `__u64` | Monotonic expiry timestamp (ns) |

---

## `source_pressure_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_LRU_HASH` |
| Max entries | 4096 |
| Key | `__u32` (src_ip) |
| Value | `struct source_pressure_state` |

Per-source-IP rate-limiting and session-count tracking. LRU eviction prevents map exhaustion from spoofed source IPs.

### `struct source_pressure_state`

| Field | Type | Description |
|---|---|---|
| `window_start_ns` | `__u64` | Start of the current measurement window (ns) |
| `knock_count` | `__u32` | Knocks received in the current window |
| `active_sessions` | `__u32` | Currently active sessions from this source |

Limits: 128 knocks per 10 s window, 32 concurrent sessions per source IP.

---

## `stats_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_ARRAY` |
| Max entries | 1 |
| Key | `__u32` (always `0`) |
| Value | `struct debug_counters` |

Atomic 64-bit counters incremented by the XDP program. Read by the admin panel and `bpftool`.

### `struct debug_counters`

| Field | Description |
|---|---|
| `knock_seen` | Total knock packets received on the knock port |
| `knock_short` | Knock packets too short to contain a full `knock_packet` struct |
| `knock_valid` | Valid AUTH + BIND knocks (signature correct, not a replay) |
| `knock_deauth` | Successful DEAUTH packets |
| `replay_drop` | Packets dropped because the nonce was already seen |
| `bind_drop` | BIND packets rejected (no matching pending auth, or expired, or port mismatch) |
| `session_timeout_drop` | Packets dropped because the active session had expired |
| `deauth_miss` | DEAUTH packets with no matching active session |
| `unknown_user` | Knock packets with a user_id not in `user_key_map` |
| `key_mismatch` | Knock packets that failed signature verification |
| `grace_key_used` | Knock packets authenticated via the previous (grace) key |
| `knock_rate_drop` | Packets dropped due to per-source knock rate limit |
| `session_limit_drop` | Packets dropped due to per-source session count limit |
| `map_update_fail` | BPF map update failures (should be 0 in normal operation) |
| `protected_drop` | Packets to protected ports dropped (no active session) |
| `protected_pass` | Packets to protected ports passed (active session found) |

---

## `time_offset_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_ARRAY` |
| Max entries | 1 |
| Key | `__u32` (always `0`) |
| Value | `struct time_offset_state` |

Stores the offset between the kernel's monotonic clock (`bpf_ktime_get_ns()`) and Unix epoch seconds. Written once at daemon startup.

### `struct time_offset_state`

| Field | Type | Description |
|---|---|---|
| `realtime_offset_sec` | `__s64` | `realtime_now_sec - monotonic_now_sec` |

---

## `debug_knock_map`

| Attribute | Value |
|---|---|
| Type | `BPF_MAP_TYPE_ARRAY` |
| Max entries | 1 |
| Key | `__u32` (always `0`) |
| Value | `struct debug_knock_snapshot` |

Overwritten on every knock packet received. Useful for debugging incorrect packet construction.

### `struct debug_knock_snapshot`

| Field | Type | Description |
|---|---|---|
| `magic` | `__u32` | Raw magic field from the last knock |
| `timestamp_sec` | `__u32` | Raw timestamp field |
| `nonce` | `__u32` | Raw nonce field |
| `packet_type` | `__u32` | Raw packet type |
| `session_id_hi` | `__u32` | Raw session_id_hi |
| `session_id_lo` | `__u32` | Raw session_id_lo |
| `sig0`–`sig3` | `__u32` | Raw signature words |

```bash
bpftool map dump pinned /sys/fs/bpf/knock_gate/debug_knock_map
```
