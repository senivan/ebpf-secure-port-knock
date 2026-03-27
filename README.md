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
- Root privileges to attach and manage eBPF programs (for future full implementation)

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

TODO:

- Stronger cryptographic primitive depending on kernel capabilities.
- Replay cache map keyed by nonce to harden against packet replay.

## Suggested next milestones

1. Add libbpf bootstrap (`bpf_object__open_file`, map updates, `bpf_xdp_attach`).
2. Add a knock client utility that generates signatures with the same shared key.
3. Add replay protection with nonce cache map and stricter timestamp windows.
4. Add integration tests in network namespaces that verify unauthorized scans see closed behavior.
