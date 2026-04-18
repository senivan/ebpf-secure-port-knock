#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "knock_crypto.h"
#include "shared.h"

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct knock_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct pending_auth_state);
} pending_auth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow_key);
    __type(value, struct active_session_state);
} active_session_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct session_lookup_key);
    __type(value, struct flow_key);
} session_index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct replay_nonce_key);
    __type(value, struct replay_nonce_state);
} replay_nonce_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KNOCK_MAX_USERS);
    __type(key, __u32);
    __type(value, struct user_key_state);
} user_key_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct debug_counters);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct debug_knock_snapshot);
} debug_knock_map SEC(".maps");

static __always_inline void bump(__u64 *counter)
{
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline bool ptr_ok(const void *ptr, const void *data_end, __u64 len)
{
    return ((__u64)ptr + len) <= (__u64)data_end;
}

static __always_inline bool is_protected_port(const struct knock_config *cfg, __u16 port_host)
{
    __u32 i;

#pragma clang loop unroll(full)
    for (i = 0; i < KNOCK_MAX_PROTECTED_PORTS; i++) {
        if (i >= cfg->protected_count) {
            break;
        }
        if (cfg->protected_ports[i] == port_host) {
            return true;
        }
    }

    return false;
}

static __always_inline bool knock_is_valid_with_key(const __u8 key[KNOCK_HMAC_KEY_LEN],
                                                    const struct knock_packet *pkt)
{
    __u64 now_ns = bpf_ktime_get_ns();
    __u32 now_sec = (__u32)(now_ns / 1000000000ULL);
    __u32 ts_sec = bpf_ntohl(pkt->timestamp_sec);
    __u32 nonce = bpf_ntohl(pkt->nonce);
    __u8 packet_type = pkt->packet_type;
    __u32 session_id_hi = bpf_ntohl(pkt->session_id_hi);
    __u32 session_id_lo = bpf_ntohl(pkt->session_id_lo);
    struct knock_sig_input in = {};
    __u32 sig[KNOCK_SIGNATURE_WORDS];
    __u32 i;

    if (pkt->magic != bpf_htonl(KNOCK_MAGIC)) {
        return false;
    }

    if (packet_type != KNOCK_PKT_AUTH && packet_type != KNOCK_PKT_DEAUTH) {
        return false;
    }

    if (ts_sec + KNOCK_MAX_CLOCK_SKEW_SEC < now_sec) {
        return false;
    }
    if (now_sec + KNOCK_MAX_CLOCK_SKEW_SEC < ts_sec) {
        return false;
    }

    in.timestamp_sec = ts_sec;
    in.packet_type = packet_type;
    in.session_id_hi = session_id_hi;
    in.session_id_lo = session_id_lo;
    in.nonce = nonce;

    knock_signature_words(key, &in, sig);
#pragma clang loop unroll(full)
    for (i = 0; i < KNOCK_SIGNATURE_WORDS; i++) {
        if (sig[i] != bpf_ntohl(pkt->signature[i])) {
            return false;
        }
    }

    return true;
}

static __always_inline __u32 knock_user_id_from_session_hi(__u32 session_id_hi)
{
    return (session_id_hi & KNOCK_USER_ID_MASK) >> KNOCK_USER_ID_SHIFT;
}

SEC("xdp")
int port_knock_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct knock_packet *kpkt;
    struct active_session_state *sess;
    struct pending_auth_state *pending;
    struct pending_auth_state new_pending = {};
    struct active_session_state new_sess = {};
    struct session_lookup_key lookup_key = {};
    struct flow_key flow = {};
    struct flow_key *bound_flow;
    struct knock_config *cfg;
    __u16 dst_port;
    __u16 src_port;
    __u64 now_ns;
    __u32 key = 0;
    struct debug_counters *stats;
    struct debug_knock_snapshot *snap;

    stats = bpf_map_lookup_elem(&stats_map, &key);
    snap = bpf_map_lookup_elem(&debug_knock_map, &key);

    if (!ptr_ok(eth, data_end, sizeof(*eth))) {
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    iph = (struct iphdr *)(eth + 1);
    if (!ptr_ok(iph, data_end, sizeof(*iph))) {
        return XDP_PASS;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    if (iph->ihl < 5) {
        return XDP_PASS;
    }
    if (!ptr_ok(iph, data_end, (__u64)iph->ihl * 4U)) {
        return XDP_PASS;
    }

    tcph = (struct tcphdr *)((void *)iph + ((__u64)iph->ihl * 4U));
    if (!ptr_ok(tcph, data_end, sizeof(*tcph))) {
        return XDP_PASS;
    }
    if (tcph->doff < 5) {
        return XDP_PASS;
    }
    if (!ptr_ok(tcph, data_end, (__u64)tcph->doff * 4U)) {
        return XDP_PASS;
    }

    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) {
        return XDP_PASS;
    }

    dst_port = bpf_ntohs(tcph->dest);
    src_port = bpf_ntohs(tcph->source);
    now_ns = bpf_ktime_get_ns();

    flow.src_ip = iph->saddr;
    flow.dst_ip = iph->daddr;
    flow.src_port = src_port;
    flow.dst_port = dst_port;
    flow.l4_proto = iph->protocol;

    if (dst_port == cfg->knock_port) {
        __u32 nonce_host;
        __u32 session_id_hi;
        __u32 session_id_lo;
        __u8 packet_type;
        __u64 replay_window_ns;
        struct replay_nonce_key replay_key = {};
        struct replay_nonce_state replay_state = {};
        struct session_lookup_key deauth_key = {};
        struct replay_nonce_state *seen;

        bump(stats ? &stats->knock_seen : NULL);
        kpkt = (struct knock_packet *)((void *)tcph + ((__u64)tcph->doff * 4U));
        if (!ptr_ok(kpkt, data_end, sizeof(*kpkt))) {
            bump(stats ? &stats->knock_short : NULL);
            return XDP_DROP;
        }

        nonce_host = bpf_ntohl(kpkt->nonce);
        packet_type = kpkt->packet_type;
        session_id_hi = bpf_ntohl(kpkt->session_id_hi);
        session_id_lo = bpf_ntohl(kpkt->session_id_lo);

        if (snap) {
            snap->magic = kpkt->magic;
            snap->timestamp_sec = kpkt->timestamp_sec;
            snap->nonce = kpkt->nonce;
            snap->packet_type = (__u32)packet_type;
            snap->session_id_hi = kpkt->session_id_hi;
            snap->session_id_lo = kpkt->session_id_lo;
            snap->sig0 = kpkt->signature[0];
            snap->sig1 = kpkt->signature[1];
            snap->sig2 = kpkt->signature[2];
            snap->sig3 = kpkt->signature[3];
        }

        {
            __u32 user_id = knock_user_id_from_session_hi(session_id_hi);
            struct user_key_state *user_key = bpf_map_lookup_elem(&user_key_map, &user_id);
            bool valid = false;

            if (!user_key) {
                bump(stats ? &stats->unknown_user : NULL);
                return XDP_DROP;
            }

            if (knock_is_valid_with_key(user_key->active_key, kpkt)) {
                valid = true;
            } else if (user_key->grace_until_ns >= now_ns &&
                       knock_is_valid_with_key(user_key->previous_key, kpkt)) {
                bump(stats ? &stats->grace_key_used : NULL);
                valid = true;
            } else {
                bump(stats ? &stats->key_mismatch : NULL);
            }

            if (!valid) {
                return XDP_DROP;
            }

            replay_key.src_ip = iph->saddr;
            replay_key.nonce = nonce_host;
            replay_key.packet_type = packet_type;
            replay_key.session_id_hi = session_id_hi;
            replay_key.session_id_lo = session_id_lo;

            seen = bpf_map_lookup_elem(&replay_nonce_map, &replay_key);
            if (seen) {
                if (seen->expires_at_ns >= now_ns) {
                    bump(stats ? &stats->replay_drop : NULL);
                    return XDP_DROP;
                }
                bpf_map_delete_elem(&replay_nonce_map, &replay_key);
            }

            replay_window_ns = (__u64)cfg->replay_window_ms * 1000000ULL;
            if (replay_window_ns < ((__u64)KNOCK_MAX_CLOCK_SKEW_SEC * 1000000000ULL)) {
                replay_window_ns = (__u64)KNOCK_MAX_CLOCK_SKEW_SEC * 1000000000ULL;
            }
            replay_state.expires_at_ns = now_ns + replay_window_ns;
            bpf_map_update_elem(&replay_nonce_map, &replay_key, &replay_state, BPF_ANY);

            if (packet_type == KNOCK_PKT_AUTH) {
                new_pending.session_id_hi = session_id_hi;
                new_pending.session_id_lo = session_id_lo;
                new_pending.expires_at_ns = now_ns + ((__u64)cfg->bind_window_ms * 1000000ULL);
                bpf_map_update_elem(&pending_auth_map, &iph->saddr, &new_pending, BPF_ANY);
                bump(stats ? &stats->knock_valid : NULL);
            } else {
                deauth_key.src_ip = iph->saddr;
                deauth_key.session_id_hi = session_id_hi;
                deauth_key.session_id_lo = session_id_lo;
                bound_flow = bpf_map_lookup_elem(&session_index_map, &deauth_key);
                if (!bound_flow) {
                    bump(stats ? &stats->deauth_miss : NULL);
                    return XDP_DROP;
                }
                bpf_map_delete_elem(&active_session_map, bound_flow);
                bpf_map_delete_elem(&session_index_map, &deauth_key);
                bump(stats ? &stats->knock_deauth : NULL);
            }
        }

        /* Knock channel should not expose any service behavior. */
        return XDP_DROP;
    }

    if (!is_protected_port(cfg, dst_port)) {
        return XDP_PASS;
    }

    sess = bpf_map_lookup_elem(&active_session_map, &flow);
    if (!sess) {
        pending = bpf_map_lookup_elem(&pending_auth_map, &iph->saddr);
        if (!pending) {
            bump(stats ? &stats->protected_drop : NULL);
            return XDP_DROP;
        }
        if (pending->expires_at_ns < now_ns) {
            bpf_map_delete_elem(&pending_auth_map, &iph->saddr);
            bump(stats ? &stats->bind_drop : NULL);
            bump(stats ? &stats->protected_drop : NULL);
            return XDP_DROP;
        }

        new_sess.session_id_hi = pending->session_id_hi;
        new_sess.session_id_lo = pending->session_id_lo;
        new_sess.expires_at_ns = now_ns + ((__u64)cfg->timeout_ms * 1000000ULL);
        bpf_map_update_elem(&active_session_map, &flow, &new_sess, BPF_ANY);

        lookup_key.src_ip = iph->saddr;
        lookup_key.session_id_hi = pending->session_id_hi;
        lookup_key.session_id_lo = pending->session_id_lo;
        bpf_map_update_elem(&session_index_map, &lookup_key, &flow, BPF_ANY);
        bpf_map_delete_elem(&pending_auth_map, &iph->saddr);

        bump(stats ? &stats->protected_pass : NULL);
        return XDP_PASS;
    }
    if (sess->expires_at_ns < now_ns) {
        lookup_key.src_ip = iph->saddr;
        lookup_key.session_id_hi = sess->session_id_hi;
        lookup_key.session_id_lo = sess->session_id_lo;
        bpf_map_delete_elem(&session_index_map, &lookup_key);
        bpf_map_delete_elem(&active_session_map, &flow);
        bump(stats ? &stats->session_timeout_drop : NULL);
        bump(stats ? &stats->protected_drop : NULL);
        return XDP_DROP;
    }

    bump(stats ? &stats->protected_pass : NULL);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
