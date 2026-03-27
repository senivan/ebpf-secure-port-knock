# eBPF Signed Knock Stealth Gate

This repository is a starter for a stealth gate model:

- Device appears closed to unauthorized clients.
- A client sends one special TCP packet to a dedicated knock port.
- The knock includes a keyed signature over packet metadata.
- If signature is valid, that source IP is temporarily allowed to reach protected service ports.

## Project layout

- `src/bpf/knock_kern.bpf.c`: kernel-side XDP gate with signed knock validation and per-source auth map
- `src/user/knock_user.c`: CLI/orchestration entrypoint for attach lifecycle
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
	HMAC_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
	PROTECT=22,443 \
	KNOCK_PORT=40000 \
	TIMEOUT_MS=5000
```

Send a signed knock packet manually:

```bash
sudo ./build/knock-client \
	--ifname eth0 \
	--src-ip 192.0.2.10 \
	--dst-ip 192.0.2.20 \
	--dst-port 40000 \
	--hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Run integration smoke test (root required):

```bash
make test
make test-netns
make test-ssh
```

## Current status

Implemented in the starter XDP program:

- IPv4/TCP packet parsing.
- Knock packet extraction on `knock_port`.
- Signature check against configured key and payload fields.
- Temporary source-IP authorization map with timeout.
- Drop-by-default behavior for protected ports when source is unauthorized.

Implemented in userspace:

- `build/knockd`: libbpf loader that loads object, populates `config_map`, attaches XDP, and detaches on timeout/signal.
- `build/knock-client`: raw packet sender for signed knock packets (default timestamp source is `CLOCK_MONOTONIC` to match kernel-side freshness checks).
- `scripts/test_e2e.sh`: smoke test that checks blocked-before-knock and allowed-after-knock behavior on loopback.
- `scripts/test_e2e_netns.sh`: network-namespace scenario with separate client and attacker hosts over a virtual L2 topology.
- `scripts/test_e2e_netns_ssh.sh`: network-namespace functional scenario using real SSH client/server flow through the protected port.

<!-- ## next milestones

1. Add RFC HMAC-SHA256 mode as an optional protocol variant for interoperability.
2. Add integration tests in Linux network namespaces to validate behavior across virtual hosts.
3. Add key rotation support with dual active keys for zero-downtime updates.
4. Export structured observability (map stats scrape + optional userspace metrics endpoint). -->
