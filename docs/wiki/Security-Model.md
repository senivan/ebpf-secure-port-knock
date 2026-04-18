# Security Model

## Goals

1. **Stealth** — Protected ports are invisible. All traffic to them is silently dropped unless an authorized session exists.
2. **Authentication** — Only clients with the correct per-user HMAC key can open a session.
3. **Anti-replay** — A captured valid knock packet cannot be reused.
4. **Rate limiting** — A source IP cannot flood knock packets to exhaust kernel map space.
5. **Session isolation** — Each authorized session is bound to a specific `(src_ip, src_port, dst_port)` 5-tuple; authorization cannot be transferred.

## Signature primitive

The gate uses a custom construction based on **SipHash-2-4**, implemented entirely in `include/knock_crypto.h` so it can be compiled for both BPF and user space without external dependencies.

### Inputs to the signature

| Field | Width | Source |
|---|---|---|
| `timestamp_sec` | 32 bits | Unix epoch seconds |
| `packet_type` | 8 bits | AUTH / BIND / DEAUTH |
| `nonce` | 32 bits | Random per packet |
| `session_id_hi` | 32 bits | Encodes user_id in upper 16 bits |
| `session_id_lo` | 32 bits | Random |
| `bind_src_port` | 16 bits | Source port for BIND (0 for AUTH/DEAUTH) |
| `bind_dst_port` | 16 bits | Protected port for BIND (0 for AUTH/DEAUTH) |

All inputs are serialized into a `knock_sig_input` struct and fed into two independent SipHash-2-4 invocations (each with a different 64-bit key pair derived from the 256-bit HMAC key and a domain-separation tweak). The 128-bit output is stored as four 32-bit `signature` words in the knock packet.

### Key schedule

The 32-byte per-user key is split into four 64-bit sub-keys `k0…k3`:

```
k0 = bytes  0–7   (big-endian)
k1 = bytes  8–15
k2 = bytes 16–23
k3 = bytes 24–31
```

Two SipHash instances are derived:

```
h0 = SipHash-2-4(k0 ^ k2, k1 ^ k3, m0 || m1,  tweak=0x01…)
h1 = SipHash-2-4(k0 ^ ~k2, k1 ^ ~k3, m2 || m3, tweak=0x02…)
```

The 128-bit output `h0 || h1` forms the four signature words.

### Comparison

Signature comparison in the XDP program is **constant-time**: all four words are XOR-ed with the expected values and the results are OR-ed together. The knock is accepted only if the final OR is `0`.

```c
for (i = 0; i < KNOCK_SIGNATURE_WORDS; i++) {
    diff |= sig[i] ^ bpf_ntohl(pkt->signature[i]);
}
return diff == 0;
```

## Replay protection

Every validated knock packet records the tuple `(src_ip, nonce, packet_type, session_id)` in `replay_nonce_map` with a TTL equal to `max(replay_window_ms, clock_skew_window)`. Any subsequent packet with the same tuple is dropped immediately. The nonce is 32 bits, so the collision probability over a 30-second window per source IP is negligible.

## Timestamp validation

Knock packets include a Unix epoch timestamp (seconds). The XDP program rejects packets where:

```
abs(packet.timestamp_sec - now_sec) > KNOCK_MAX_CLOCK_SKEW_SEC (30 s)
```

This provides a time-bounded replay window independent of the nonce, so even if the nonce table were exhausted, old captured packets would still be rejected.

## Two-packet bind

The AUTH → BIND two-packet design ensures:

- Authorization is bound to a specific `(src_port, dst_port)` pair.
- A passive attacker who captures the AUTH knock cannot open a session without sending the BIND knock, which requires the same key and a fresh nonce.
- The BIND window is short (`bind_window_ms`, default 3 s), limiting the exposure time.

## Session isolation

Active sessions are keyed on `flow_key`:

```c
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  l4_proto;
};
```

A session that was bound for port 22 with source port 55000 cannot be used to reach port 443 or any other port.

## Threat model

| Threat | Mitigation |
|---|---|
| Port scanning | All protected ports silently drop unauthenticated traffic at XDP (before the kernel network stack) |
| Knock replay | Nonce + timestamp window + replay_nonce_map |
| Knock forgery | SipHash-2-4 with a 32-byte secret key |
| Session hijacking | 5-tuple binding; session_id must match |
| Key exhaustion / DoS | Rate-limit via source_pressure_map (128 knocks/10 s, 32 sessions/IP) |
| Key leakage | Keys are stored in a BPF map, accessible only to root/`CAP_BPF`; never transmitted in plaintext |
| Clock skew abuse | ±30 s window; replay window ≥ 30 s enforced at startup |

## What this system does NOT provide

- **Confidentiality of traffic** — Once a session is authorized, the data stream is not encrypted by this system (rely on TLS/SSH for that).
- **Perfect forward secrecy for keys** — HMAC keys are long-lived; rotate them with `rotate-user-key` to reduce exposure.
- **Protection against insider threats** — A user with root access can read the BPF maps directly.
- **IPv6 support** — The current XDP program only handles IPv4.
