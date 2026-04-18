# Usage

## Starting the daemon

The daemon attaches the XDP program to a network interface, loads user keys, seeds the realtime clock offset into a BPF map, and pins all maps under `/sys/fs/bpf/knock_gate/`. Root is required.

### Multi-user mode (recommended)

```bash
sudo ./build/knockd daemon \
  --ifname eth0 \
  --users-file /etc/knock/users.csv \
  --protect 22,443
```

### Single-user mode (fallback)

Registers a single user with ID `0` from a key provided directly:

```bash
sudo ./build/knockd daemon \
  --ifname eth0 \
  --hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --protect 22,443
```

The daemon runs until `SIGINT` or `SIGTERM`, which triggers XDP detach and map cleanup.

> `--replay-window-ms` values below 30000 are rejected at startup.

---

## Sending a knock

Root or `CAP_NET_RAW` is required because the client sends raw Ethernet frames.

### Step 1 — Send AUTH knock

```bash
sudo ./build/knock-client \
  --ifname eth0 \
  --src-ip 192.0.2.10 \
  --dst-ip 192.0.2.20 \
  --dst-port 40000 \
  --user-id 100 \
  --hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

The client prints a line such as:

```
session_id=4718592000000001
```

Save this value for the next step.

### Step 2 — Send BIND knock

The BIND packet tells the kernel exactly which `(src_port, dst_port)` flow to authorize. Use the same source port that your real TCP connection will use.

```bash
sudo ./build/knock-client \
  --ifname eth0 \
  --src-ip 192.0.2.10 \
  --dst-ip 192.0.2.20 \
  --dst-port 40000 \
  --packet-type bind \
  --session-id 4718592000000001 \
  --src-port 55000 \
  --bind-port 22 \
  --hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

After both packets are processed, XDP will pass any TCP from `192.0.2.10:55000` → `192.0.2.20:22` for `timeout-ms` milliseconds.

### Step 3 — Connect

```bash
ssh -p 22 -b 192.0.2.10 user@192.0.2.20
```

Use `SO_BINDTODEVICE` or `--src-ip` / `bind()` to ensure the TCP SYN originates from the same source IP and port as the BIND knock.

### Step 4 — DEAUTH (optional)

Revoke the session immediately instead of waiting for timeout:

```bash
sudo ./build/knock-client \
  --ifname eth0 \
  --src-ip 192.0.2.10 \
  --dst-ip 192.0.2.20 \
  --dst-port 40000 \
  --packet-type deauth \
  --session-id 4718592000000001 \
  --hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

---

## Makefile targets

| Target | Description |
|---|---|
| `make all` | Build eBPF object + user-space binaries |
| `make run IFACE= USERS_FILE= PROTECT= …` | Build then start the daemon |
| `make test` | Integration smoke test on loopback (root required) |
| `make test-netns` | Network-namespace integration scenario (root required) |
| `make test-ssh` | SSH functional test in a netns (root + sshd required) |
| `make test-user-auth` | Per-user registration and isolation tests |
| `make test-user-rotation` | Per-user key rotation tests |
| `make test-user-admin` | Live admin-command tests |
| `make test-user-pressure` | Rate-limiting and session-limit pressure tests |
| `make test-config` | CLI replay-window validation (no root required) |
| `make test-user-all` | All per-user feature tests |
| `make all-test` | Full test suite |
| `make clean` | Remove `build/` |
| `make help` | Print target summary |

---

## Inspecting state with bpftool

While the daemon is running, any pinned map can be inspected directly:

```bash
# debug counters
bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map

# active authorized sessions
bpftool map dump pinned /sys/fs/bpf/knock_gate/active_session_map

# pending AUTH knocks waiting for a BIND
bpftool map dump pinned /sys/fs/bpf/knock_gate/pending_auth_map

# anti-replay nonce table
bpftool map dump pinned /sys/fs/bpf/knock_gate/replay_nonce_map

# last knock packet snapshot (for debugging)
bpftool map dump pinned /sys/fs/bpf/knock_gate/debug_knock_map
```

See [[BPF-Maps-Reference]] for a full description of every map and counter field.
