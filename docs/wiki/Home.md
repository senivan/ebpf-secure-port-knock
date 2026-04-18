# eBPF Signed Knock Stealth Gate — Wiki

Welcome to the project wiki. This system implements a cryptographically authenticated port-knocking firewall using an eBPF XDP program that runs entirely in the Linux kernel fast path.

## How it works in one paragraph

A client that wants to reach a protected service (e.g. SSH on port 22) first sends a specially-crafted TCP packet to a dedicated **knock port**. That packet carries a SipHash-based signature computed over a per-user 32-byte key, a timestamp, a nonce, and a session ID. The XDP program on the server validates the signature in kernel space, records a pending authorization, and then expects a second **bind** packet that pins the authorized flow to a specific source/destination port pair. Once bound, the `(src_ip, src_port, dst_port)` flow key is admitted through the firewall for the configured timeout. Any traffic that does not match an active authorized flow is dropped at the XDP layer — the service never sees the unauthenticated attempt.

## Pages

| Page | Description |
|------|-------------|
| [[Architecture]] | Components, data flow, and eBPF maps |
| [[Installation]] | Prerequisites and build steps |
| [[Configuration]] | All daemon and XDP configuration parameters |
| [[Usage]] | Running the daemon, sending knocks, Makefile targets |
| [[User-Management]] | Registering, rotating, and revoking per-user keys |
| [[Security-Model]] | Cryptographic design, anti-replay, threat model |
| [[Admin-Panel]] | Web UI and REST API reference |
| [[Testing]] | All test suites and how to run them |
| [[BPF-Maps-Reference]] | Every eBPF map in the XDP program |

## Quick start (TL;DR)

```bash
# 1. build everything
make all

# 2. start the daemon
sudo ./build/knockd daemon \
  --ifname eth0 \
  --users-file /etc/knock/users.csv \
  --protect 22,443 \
  --knock-port 40000 \
  --timeout-ms 5000

# 3. send AUTH knock from the client host
sudo ./build/knock-client \
  --ifname eth0 \
  --src-ip <client-ip> \
  --dst-ip <server-ip> \
  --dst-port 40000 \
  --user-id 100 \
  --hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

# 4. send BIND knock with the returned session_id
sudo ./build/knock-client \
  --ifname eth0 \
  --src-ip <client-ip> \
  --dst-ip <server-ip> \
  --dst-port 40000 \
  --packet-type bind \
  --session-id <session_id> \
  --src-port 55000 \
  --bind-port 22 \
  --hmac-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

See [[Usage]] for the full two-packet (AUTH → BIND) flow and deauth.
