#ifndef SHARED_H
#define SHARED_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define KNOCK_DEFAULT_TIMEOUT_MS 5000U
#define KNOCK_MAX_PROTECTED_PORTS 16U
#define KNOCK_HMAC_KEY_LEN 32U
#define KNOCK_SIGNATURE_WORDS 4U

#define KNOCK_MAGIC 0x4b4e4f43U /* "KNOC" */
#define KNOCK_DEFAULT_PORT 40000U
#define KNOCK_MAX_CLOCK_SKEW_SEC 30U

struct knock_packet {
    __u32 magic;
    __u32 timestamp_sec;
    __u32 nonce;
    __u32 signature[KNOCK_SIGNATURE_WORDS];
} __attribute__((packed));

struct knock_config {
    __u16 knock_port;
    __u16 protected_count;
    __u16 protected_ports[KNOCK_MAX_PROTECTED_PORTS];
    __u32 timeout_ms;
    __u8 hmac_key[KNOCK_HMAC_KEY_LEN];
};

struct auth_state {
    __u64 expires_at_ns;
};

struct debug_counters {
    __u64 knock_seen;
    __u64 knock_short;
    __u64 knock_valid;
    __u64 protected_drop;
    __u64 protected_pass;
};

struct debug_knock_snapshot {
    __u32 magic;
    __u32 timestamp_sec;
    __u32 nonce;
    __u32 sig0;
    __u32 sig1;
    __u32 sig2;
    __u32 sig3;
};

#endif /* SHARED_H */
