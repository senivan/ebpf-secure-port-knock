# Architecture

## Component overview

```
┌─────────────────────────────────────────────────────────┐
│  Linux kernel (XDP layer)                               │
│                                                         │
│  knock_kern.bpf.c  ──  port_knock_xdp()                │
│      │                                                  │
│      ├── config_map          (knock port, protected     │
│      │                        ports, timeouts)          │
│      ├── user_key_map        (per-user active + prev    │
│      │                        key with grace window)    │
│      ├── pending_auth_map    (AUTH knock → pending TTL) │
│      ├── active_session_map  (bound flow → session TTL) │
│      ├── session_index_map   (session ID → flow key)    │
│      ├── replay_nonce_map    (nonce expiry, anti-replay)│
│      ├── source_pressure_map (rate-limit per source IP) │
│      ├── stats_map           (debug counters)           │
│      ├── time_offset_map     (realtime clock anchor)    │
│      └── debug_knock_map     (last knock snapshot)      │
└──────────────────────┬──────────────────────────────────┘
                       │ libbpf / bpffs pinned maps
          ┌────────────┴───────────────────────────┐
          │  User-space (build/)                   │
          │                                        │
          │  knockd  ──  daemon + admin CLI         │
          │    ├── xdp_loader.c  (attach/detach,   │
          │    │                  map pin, config)  │
          │    └── knock_user.c  (user mgmt cmds)  │
          │                                        │
          │  knock-client  ──  raw packet sender   │
          │    ├── knock_client.c                  │
          │    ├── net_checksum.c                  │
          │    └── cli_common.c                    │
          └────────────────────────────────────────┘
                       │
          ┌────────────┴───────────────────────────┐
          │  Admin panel (admin-panel/)             │
          │                                        │
          │  Flask backend  ←→  React/Vite UI      │
          │  (JWT auth, reads pinned BPF maps)     │
          └────────────────────────────────────────┘
```

## Source file map

| File | Role |
|------|------|
| `src/bpf/knock_kern.bpf.c` | XDP kernel program — all packet processing logic |
| `src/user/knock_user.c` | Daemon entry point and user admin sub-commands |
| `src/user/xdp_loader.c` | libbpf loader: attach XDP, pin maps, seed config |
| `src/user/knock_client.c` | Raw packet builder and sender |
| `src/user/cli_common.c` | Shared CLI flag parsing (HMAC key, port lists) |
| `src/user/net_checksum.c` | IPv4/TCP checksum helpers |
| `include/shared.h` | Types and constants shared between kernel and user space |
| `include/knock_crypto.h` | Inline SipHash-based signature primitive (header-only) |
| `scripts/gen_vmlinux_h.sh` | Generates `include/vmlinux.h` from kernel BTF |

## Two-packet knock protocol

The gate uses a two-packet handshake so the kernel can bind authorization to an exact `(src_port, dst_port)` pair. This prevents a passive observer from replaying an observed knock to open a different port.

```
Client                                       Server (XDP)
  │                                               │
  │  [1] AUTH knock packet                        │
  │  TCP dst = knock_port                         │
  │  payload: knock_packet {                      │
  │    magic, type=AUTH, timestamp, nonce,        │
  │    session_id, signature }                    │
  │──────────────────────────────────────────────▶│
  │                                               │ validate sig
  │                                               │ insert pending_auth_map
  │                                               │   (TTL = bind_window_ms)
  │  [2] BIND knock packet                        │
  │  TCP dst = knock_port                         │
  │  payload: knock_packet {                      │
  │    type=BIND, same session_id,                │
  │    bind_src_port, bind_dst_port,              │
  │    new nonce, signature }                     │
  │──────────────────────────────────────────────▶│
  │                                               │ validate sig, match pending
  │                                               │ insert active_session_map
  │                                               │   keyed by (src_ip,
  │                                               │   src_port, dst_port)
  │                                               │   (TTL = timeout_ms)
  │  [3] Normal TCP to protected port             │
  │  src_port = bind_src_port                     │
  │  dst_port = bind_dst_port                     │
  │──────────────────────────────────────────────▶│ XDP_PASS
  │                                               │
  │  [4] DEAUTH knock (optional, any time)        │
  │  type=DEAUTH, same session_id                 │
  │──────────────────────────────────────────────▶│ delete active session
```

> All knock packets (AUTH, BIND, DEAUTH) are **always dropped** at the XDP layer after processing — the knock port is never exposed to a user-space listener.

## Packet type values

| Constant | Value | Description |
|---|---|---|
| `KNOCK_PKT_AUTH` | `1` | First knock — creates a pending authorization |
| `KNOCK_PKT_BIND` | `3` | Second knock — binds the authorization to a flow |
| `KNOCK_PKT_DEAUTH` | `2` | Immediately revokes an active session |

## Clock and timestamp handling

The XDP program uses `bpf_ktime_get_ns()` (monotonic clock) and adds a realtime offset loaded at daemon startup into `time_offset_map`. This lets the kernel compare knock packet timestamps against Unix epoch seconds without relying on `bpf_ktime_get_real_ns()` (unavailable on older kernels).

The maximum accepted clock skew is ±30 seconds (`KNOCK_MAX_CLOCK_SKEW_SEC`). The replay window must be at least 30 seconds to cover this range.

## Anti-replay

Every knock packet carries a random `nonce` field. After validation, the tuple `(src_ip, nonce, packet_type, session_id_hi, session_id_lo)` is stored in `replay_nonce_map` for the replay window duration. Any duplicate tuple is silently dropped and the `replay_drop` counter is incremented.

## Source rate limiting

`source_pressure_map` tracks per source IP:

| Limit | Constant | Value |
|---|---|---|
| Max knock packets per 10 s window | `KNOCK_MAX_KNOCKS_PER_SOURCE_WINDOW` | 128 |
| Max concurrent active sessions | `KNOCK_MAX_ACTIVE_SESSIONS_PER_SOURCE` | 32 |

Exceeding either limit causes an immediate `XDP_DROP` with no ICMP response.
