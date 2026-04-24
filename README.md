# eBPF Signed Knock Stealth Gate

This repository is a starter for a stealth gate model:

- Device appears closed to unauthorized clients.
- A client sends one special TCP packet to a dedicated knock port.
- The knock includes an HMAC-SHA256-based keyed signature over packet metadata.
- If signature is valid for a registered user, that source IP is temporarily allowed to reach protected service ports.
- Knock timestamps use Unix epoch seconds, with the XDP program comparing against a loader-seeded realtime offset derived from host clocks.

## Project layout

- `src/bpf/knock_kern.bpf.c`: kernel-side XDP gate with per-user signed knock validation and auth maps
- `src/user/knock_user.c`: daemon and admin CLI (attach lifecycle, user register/rotate/revoke/list)
- `src/user/xdp_loader.c`: libbpf loader + map pinning + XDP attach/detach module
- `src/user/knock_client.c`: knock frame sender entrypoint
- `src/user/cli_common.c`: shared CLI parsing helpers (HMAC key, port lists)
- `src/user/net_checksum.c`: reusable IPv4/TCP checksum routines
- `include/shared.h`: shared constants/types between user and kernel code
- `include/knock_crypto.h`: shared signature primitive used by both kernel and userspace sender
- `scripts/gen_vmlinux_h.sh`: generates `include/vmlinux.h` from kernel BTF
- `Makefile`: build and run entrypoints

## Prerequisites

- Linux with BTF available at `/sys/kernel/btf/vmlinux`
- `clang` with BPF target support
- `bpftool`
- Build tools (`make`, `cc`)
- Root privileges to attach and manage eBPF programs

## Quick start

```bash
make all
make run \
	IFACE=eth0 \
	USERS_FILE=/etc/knock/users.csv \
	PROTECT=22,443 \
	KNOCK_PORT=40000 \
	TIMEOUT_MS=5000 \
	REPLAY_WINDOW_MS=30000
```

Send a signed knock packet manually:

```bash
sudo ./build/knock-client \
	--ifname eth0 \
	--src-ip 192.0.2.10 \
	--dst-ip 192.0.2.20 \
	--dst-port 40000 \
	--user-id 100 \
	--hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

For SSH, use the wrapper so it performs the auth knock, bind knock, and SSH socket bind in one step:

```bash
./scripts/knock_ssh.sh \
	--ifname eth0 \
	--src-ip 192.0.2.10 \
	--dst-ip 192.0.2.20 \
	--ssh-target user@192.0.2.20 \
	--user-id 100 \
	--hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

If you are using the multi-user daemon, make sure `--user-id` matches the registered user. The wrapper defaults to password login; use `--ssh-auth publickey` if you want key-based SSH instead. It sends a keepalive renew packet every second so the SSH session stays authorized; override that with `--renew-interval-sec` if needed. The SSH source port defaults to `55411`; override it with `--ssh-src-port` if that port is busy.

For HTTP(S), use the similar wrapper that performs auth/bind/renew and then runs one `curl` request from a fixed source port:

```bash
./scripts/knock_http.sh \
	--ifname eth0 \
	--src-ip 192.0.2.10 \
	--dst-ip 192.0.2.20 \
	--url https://192.0.2.20/health \
	--user-id 100 \
	--hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

The HTTP wrapper keeps the session alive with `renew` packets while `curl` runs. Pass additional curl flags with `--curl-arg` or after `--`.

Run integration smoke test (root required):

```bash
make test
make test-netns
make test-ssh
```

The daemon rejects `--replay-window-ms` values below the 30-second clock-skew window at startup.

## Current status

Implemented in the starter XDP program:

- IPv4/TCP packet parsing.
- Knock packet extraction on `knock_port`.
- Signature check against per-user key selected from encoded user ID in session ID.
- Temporary source-IP authorization map with timeout.
- User-key map with rotation support (active key + previous key grace window).
- Drop-by-default behavior for protected ports when source is unauthorized.

Implemented in userspace:

- `build/knockd`: daemon mode loader plus user admin commands (`register-user`, `rotate-user-key`, `revoke-user`, `list-users`).
- `build/knock-client`: raw packet sender for signed knock packets; auth packets require `--user-id` unless explicit `--session-id` is provided. Supports explicit `renew` keepalive packets for session refresh.
- `scripts/test_e2e.sh`: smoke test that checks blocked-before-knock and allowed-after-knock behavior on loopback.
- `scripts/test_e2e_netns.sh`: network-namespace scenario with separate client and attacker hosts over a virtual L2 topology.
- `scripts/test_e2e_netns_ssh.sh`: network-namespace functional scenario using real SSH client/server flow through the protected port.

## Per-user registration

User file format:

```text
# user_id,hmac_key_hex
100,00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
101,aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
```

Run daemon mode directly:

```bash
sudo ./build/knockd daemon \
	--ifname eth0 \
	--users-file /etc/knock/users.csv \
	--protect 22,443

# optional compatibility fallback: single registered user_id 0 from one key
sudo ./build/knockd daemon \
	--ifname eth0 \
	--hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
	--protect 22,443
```

## Runtime user key management

All admin commands operate on pinned maps (default `/sys/fs/bpf/knock_gate`) and do not require daemon restart.

```bash
# register a new user
sudo ./build/knockd register-user --user-id 102 --hmac-key <64hex>

# rotate key with optional grace window
sudo ./build/knockd rotate-user-key --user-id 102 --hmac-key <new64hex> --grace-ms 5000

# revoke user
sudo ./build/knockd revoke-user --user-id 102

# list users
sudo ./build/knockd list-users
```

<!-- ## next milestones

1. Add integration tests in Linux network namespaces to validate behavior across virtual hosts.
2. Add key rotation support with dual active keys for zero-downtime updates.
3. Export structured observability (map stats scrape + optional userspace metrics endpoint). -->
