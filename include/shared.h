#ifndef SHARED_H
#define SHARED_H

#ifndef __BPF__
#if defined(__linux__)
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int64_t __s64;
#endif
#endif

#define KNOCK_DEFAULT_TIMEOUT_MS 5000U
#define KNOCK_MAX_PROTECTED_PORTS 16U
#define KNOCK_HMAC_KEY_LEN 32U
#define KNOCK_SIGNATURE_WORDS 4U

#define KNOCK_MAGIC 0x4b4e4f43U /* "KNOC" */
#define KNOCK_DEFAULT_PORT 40000U
#define KNOCK_MAX_CLOCK_SKEW_SEC 30U
#define KNOCK_MIN_REPLAY_WINDOW_MS (KNOCK_MAX_CLOCK_SKEW_SEC * 1000U)
#define KNOCK_DEFAULT_BIND_WINDOW_MS 3000U
#define KNOCK_DEFAULT_REPLAY_WINDOW_MS 30000U
#define KNOCK_SOURCE_PRESSURE_WINDOW_NS 10000000000ULL
#define KNOCK_MAX_KNOCKS_PER_SOURCE_WINDOW 128U
#define KNOCK_MAX_ACTIVE_SESSIONS_PER_SOURCE 32U
#define KNOCK_MAX_USERS 1024U

#define KNOCK_PKT_AUTH 1U
#define KNOCK_PKT_DEAUTH 2U
#define KNOCK_PKT_BIND 3U
#define KNOCK_PKT_RENEW 4U

#define KNOCK_USER_ID_SHIFT 16U
#define KNOCK_USER_ID_MASK 0xffff0000U

struct knock_packet {
    __u32 magic;
    __u32 timestamp_sec;
    __u32 nonce;
    __u8 packet_type;
    __u8 reserved[3];
    __u32 session_id_hi;
    __u32 session_id_lo;
    __u16 bind_src_port;
    __u16 bind_dst_port;
    __u32 bind_reserved;
    __u32 signature[KNOCK_SIGNATURE_WORDS];
} __attribute__((packed));

struct knock_config {
    __u16 knock_port;
    __u16 protected_count;
    __u16 protected_ports[KNOCK_MAX_PROTECTED_PORTS];
    __u32 timeout_ms;
    __u32 bind_window_ms;
    __u32 replay_window_ms;
    __u8 hmac_key[KNOCK_HMAC_KEY_LEN];
};

struct time_offset_state {
    __s64 realtime_offset_sec;
};

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 l4_proto;
    __u8 pad[3];
};

struct pending_auth_state {
    __u32 session_id_hi;
    __u32 session_id_lo;
    __u64 expires_at_ns;
};

struct active_session_state {
    __u32 session_id_hi;
    __u32 session_id_lo;
    __u64 expires_at_ns;
    __u8 deleting;
};

struct replay_nonce_key {
    __u32 src_ip;
    __u32 nonce;
    __u8 packet_type;
    __u8 pad[3];
    __u32 session_id_hi;
    __u32 session_id_lo;
};

struct session_lookup_key {
    __u32 src_ip;
    __u32 session_id_hi;
    __u32 session_id_lo;
};

struct replay_nonce_state {
    __u64 expires_at_ns;
};

struct source_pressure_state {
    __u64 window_start_ns;
    __u32 knock_count;
    __u32 active_sessions;
};

struct user_key_state {
    __u8 active_key[KNOCK_HMAC_KEY_LEN];
    __u8 previous_key[KNOCK_HMAC_KEY_LEN];
    __u32 key_version;
    __u64 grace_until_ns;
};

struct knock_user_record {
    __u32 user_id;
    __u8 hmac_key[KNOCK_HMAC_KEY_LEN];
};

struct debug_counters {
    __u64 knock_seen;
    __u64 knock_short;
    __u64 knock_valid;
    __u64 knock_deauth;
    __u64 replay_drop;
    __u64 bind_drop;
    __u64 session_timeout_drop;
    __u64 deauth_miss;
    __u64 unknown_user;
    __u64 key_mismatch;
    __u64 grace_key_used;
    __u64 knock_rate_drop;
    __u64 session_limit_drop;
    __u64 map_update_fail;
    __u64 protected_drop;
    __u64 protected_pass;
};

struct debug_knock_snapshot {
    __u32 magic;
    __u32 timestamp_sec;
    __u32 nonce;
    __u32 packet_type;
    __u32 session_id_hi;
    __u32 session_id_lo;
    __u32 sig0;
    __u32 sig1;
    __u32 sig2;
    __u32 sig3;
};

#endif /* SHARED_H */
