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
    __type(key, struct session_lookup_key);
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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct source_pressure_state);
} source_pressure_map SEC(".maps");

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
    __type(value, struct time_offset_state);
} time_offset_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct debug_knock_snapshot);
} debug_knock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct knock_sig_scratch);
} crypto_scratch_map SEC(".maps");

struct knock_path_scratch {
    struct knock_sig_input sig_in;
    struct replay_nonce_key replay_key;
    struct replay_nonce_state replay_state;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct knock_path_scratch);
} knock_path_scratch_map SEC(".maps");

static __always_inline void bump(__u64 *counter)
{
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline bool update_map_or_fail(__u64 *counter,
                                               void *map,
                                               const void *key,
                                               const void *value)
{
    int ret = bpf_map_update_elem(map, key, value, BPF_ANY);

    if (ret != 0) {
        bump(counter);
        return false;
    }

    return true;
}

static __always_inline bool source_pressure_allow_knock(__u32 src_ip,
                                                        __u64 now_ns,
                                                        struct debug_counters *stats)
{
    struct source_pressure_state current = {};
    struct source_pressure_state *state = bpf_map_lookup_elem(&source_pressure_map, &src_ip);

    if (state) {
        current = *state;
    }

    if (!state || now_ns - current.window_start_ns >= KNOCK_SOURCE_PRESSURE_WINDOW_NS) {
        current.window_start_ns = now_ns;
        current.knock_count = 0;
    }

    if (current.knock_count >= KNOCK_MAX_KNOCKS_PER_SOURCE_WINDOW) {
        bump(stats ? &stats->knock_rate_drop : NULL);
        return false;
    }

    current.knock_count++;
    return update_map_or_fail(stats ? &stats->map_update_fail : NULL,
                              &source_pressure_map,
                              &src_ip,
                              &current);
}

static __always_inline bool source_pressure_reserve_session(__u32 src_ip,
                                                            struct debug_counters *stats)
{
    struct source_pressure_state current = {};
    struct source_pressure_state *state = bpf_map_lookup_elem(&source_pressure_map, &src_ip);

    if (state) {
        current = *state;
    }

    if (current.active_sessions >= KNOCK_MAX_ACTIVE_SESSIONS_PER_SOURCE) {
        bump(stats ? &stats->session_limit_drop : NULL);
        return false;
    }

    current.active_sessions++;
    return update_map_or_fail(stats ? &stats->map_update_fail : NULL,
                              &source_pressure_map,
                              &src_ip,
                              &current);
}

static __always_inline void source_pressure_release_session(__u32 src_ip)
{
    struct source_pressure_state *state = bpf_map_lookup_elem(&source_pressure_map, &src_ip);

    if (!state || state->active_sessions == 0) {
        return;
    }

    state->active_sessions--;
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

static __always_inline bool get_realtime_sec(__u32 *now_sec)
{
    __u32 key = 0;
    __u64 mono_sec = bpf_ktime_get_ns() / 1000000000ULL;
    const struct time_offset_state *offset;
    __s64 realtime_sec;

    offset = bpf_map_lookup_elem(&time_offset_map, &key);
    if (!offset) {
        return false;
    }

    realtime_sec = (__s64)mono_sec + offset->realtime_offset_sec;
    if (realtime_sec < 0) {
        return false;
    }

    *now_sec = (__u32)realtime_sec;
    return true;
}

static __always_inline bool knock_signature_matches(const __u8 key[KNOCK_HMAC_KEY_LEN],
                                                    const struct knock_sig_input *in,
                                                    const __u32 pkt_sig[KNOCK_SIGNATURE_WORDS])
{
    __u32 scratch_key = 0;
    struct knock_sig_scratch *scratch;
    __u32 diff = 0;
    __u32 sig[KNOCK_SIGNATURE_WORDS];
    __u32 i;

    scratch = bpf_map_lookup_elem(&crypto_scratch_map, &scratch_key);
    if (!scratch) {
        return false;
    }

    knock_signature_words_scratch(key, in, sig, scratch);
#pragma clang loop unroll(full)
    for (i = 0; i < KNOCK_SIGNATURE_WORDS; i++) {
        diff |= sig[i] ^ bpf_ntohl(pkt_sig[i]);
    }

    return diff == 0;
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
    struct flow_key flow = {};
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
        __u32 scratch_key = 0;
        struct knock_path_scratch *knock_scratch;
        __u32 nonce_host;
        __u32 ts_sec;
        __u32 now_sec;
        __u32 session_id_hi;
        __u32 session_id_lo;
        __u8 packet_type;
        __u16 bind_src_port;
        __u16 bind_dst_port;
        __u64 replay_window_ns;
        struct replay_nonce_state *seen;

        if (!source_pressure_allow_knock(iph->saddr, now_ns, stats)) {
            return XDP_DROP;
        }

        knock_scratch = bpf_map_lookup_elem(&knock_path_scratch_map, &scratch_key);
        if (!knock_scratch) {
            bump(stats ? &stats->map_update_fail : NULL);
            return XDP_DROP;
        }

        bump(stats ? &stats->knock_seen : NULL);
        kpkt = (struct knock_packet *)((void *)tcph + ((__u64)tcph->doff * 4U));
        if (!ptr_ok(kpkt, data_end, sizeof(*kpkt))) {
            bump(stats ? &stats->knock_short : NULL);
            return XDP_DROP;
        }

        nonce_host = bpf_ntohl(kpkt->nonce);
        ts_sec = bpf_ntohl(kpkt->timestamp_sec);
        packet_type = kpkt->packet_type;
        session_id_hi = bpf_ntohl(kpkt->session_id_hi);
        session_id_lo = bpf_ntohl(kpkt->session_id_lo);
        bind_src_port = bpf_ntohs(kpkt->bind_src_port);
        bind_dst_port = bpf_ntohs(kpkt->bind_dst_port);

        if (kpkt->magic != bpf_htonl(KNOCK_MAGIC)) {
            bump(stats ? &stats->key_mismatch : NULL);
            return XDP_DROP;
        }

        if (packet_type != KNOCK_PKT_AUTH && packet_type != KNOCK_PKT_DEAUTH && packet_type != KNOCK_PKT_BIND) {
            bump(stats ? &stats->key_mismatch : NULL);
            return XDP_DROP;
        }

        if (!get_realtime_sec(&now_sec)) {
            bump(stats ? &stats->key_mismatch : NULL);
            return XDP_DROP;
        }

        if (ts_sec + KNOCK_MAX_CLOCK_SKEW_SEC < now_sec ||
            now_sec + KNOCK_MAX_CLOCK_SKEW_SEC < ts_sec) {
            bump(stats ? &stats->key_mismatch : NULL);
            return XDP_DROP;
        }

        knock_scratch->sig_in.timestamp_sec = ts_sec;
        knock_scratch->sig_in.packet_type = packet_type;
        knock_scratch->sig_in.session_id_hi = session_id_hi;
        knock_scratch->sig_in.session_id_lo = session_id_lo;
        knock_scratch->sig_in.nonce = nonce_host;
        knock_scratch->sig_in.bind_src_port = bind_src_port;
        knock_scratch->sig_in.bind_dst_port = bind_dst_port;

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

            if (knock_signature_matches(user_key->active_key, &knock_scratch->sig_in, kpkt->signature)) {
                valid = true;
            } else if (user_key->grace_until_ns >= now_ns &&
                       knock_signature_matches(user_key->previous_key, &knock_scratch->sig_in, kpkt->signature)) {
                bump(stats ? &stats->grace_key_used : NULL);
                valid = true;
            } else {
                bump(stats ? &stats->key_mismatch : NULL);
            }

            if (!valid) {
                return XDP_DROP;
            }

            knock_scratch->replay_key.src_ip = iph->saddr;
            knock_scratch->replay_key.nonce = nonce_host;
            knock_scratch->replay_key.packet_type = packet_type;
            knock_scratch->replay_key.session_id_hi = session_id_hi;
            knock_scratch->replay_key.session_id_lo = session_id_lo;

            seen = bpf_map_lookup_elem(&replay_nonce_map, &knock_scratch->replay_key);
            if (seen) {
                if (seen->expires_at_ns >= now_ns) {
                    bump(stats ? &stats->replay_drop : NULL);
                    return XDP_DROP;
                }
                bpf_map_delete_elem(&replay_nonce_map, &knock_scratch->replay_key);
            }

            replay_window_ns = (__u64)cfg->replay_window_ms * 1000000ULL;
            if (replay_window_ns < ((__u64)KNOCK_MAX_CLOCK_SKEW_SEC * 1000000000ULL)) {
                replay_window_ns = (__u64)KNOCK_MAX_CLOCK_SKEW_SEC * 1000000000ULL;
            }
            knock_scratch->replay_state.expires_at_ns = now_ns + replay_window_ns;
            if (!update_map_or_fail(stats ? &stats->map_update_fail : NULL,
                                    &replay_nonce_map,
                                    &knock_scratch->replay_key,
                                    &knock_scratch->replay_state)) {
                return XDP_DROP;
            }

            if (packet_type == KNOCK_PKT_AUTH) {
                struct pending_auth_state new_pending = {};
                struct session_lookup_key pending_key = {};

                pending_key.src_ip = iph->saddr;
                pending_key.session_id_hi = session_id_hi;
                pending_key.session_id_lo = session_id_lo;
                new_pending.session_id_hi = session_id_hi;
                new_pending.session_id_lo = session_id_lo;
                new_pending.expires_at_ns = now_ns + ((__u64)cfg->bind_window_ms * 1000000ULL);
                if (!update_map_or_fail(stats ? &stats->map_update_fail : NULL,
                                        &pending_auth_map,
                                        &pending_key,
                                        &new_pending)) {
                    return XDP_DROP;
                }
                bump(stats ? &stats->knock_valid : NULL);
            } else if (packet_type == KNOCK_PKT_BIND) {
                struct pending_auth_state *pending;
                struct active_session_state new_sess = {};
                struct session_lookup_key pending_key = {};
                struct session_lookup_key lookup_key = {};

                pending_key.src_ip = iph->saddr;
                pending_key.session_id_hi = session_id_hi;
                pending_key.session_id_lo = session_id_lo;
                pending = bpf_map_lookup_elem(&pending_auth_map, &pending_key);
                if (!pending) {
                    bump(stats ? &stats->bind_drop : NULL);
                    return XDP_DROP;
                }
                if (pending->expires_at_ns < now_ns) {
                    bpf_map_delete_elem(&pending_auth_map, &pending_key);
                    bump(stats ? &stats->bind_drop : NULL);
                    return XDP_DROP;
                }
                if (bind_src_port != src_port || bind_dst_port == 0 || !is_protected_port(cfg, bind_dst_port)) {
                    bump(stats ? &stats->bind_drop : NULL);
                    return XDP_DROP;
                }

                if (!source_pressure_reserve_session(iph->saddr, stats)) {
                    return XDP_DROP;
                }

                flow.src_port = bind_src_port;
                flow.dst_port = bind_dst_port;
                new_sess.session_id_hi = session_id_hi;
                new_sess.session_id_lo = session_id_lo;
                new_sess.expires_at_ns = now_ns + ((__u64)cfg->timeout_ms * 1000000ULL);
                if (!update_map_or_fail(stats ? &stats->map_update_fail : NULL,
                                        &active_session_map,
                                        &flow,
                                        &new_sess)) {
                    source_pressure_release_session(iph->saddr);
                    return XDP_DROP;
                }

                lookup_key.src_ip = iph->saddr;
                lookup_key.session_id_hi = session_id_hi;
                lookup_key.session_id_lo = session_id_lo;
                if (bpf_map_update_elem(&session_index_map, &lookup_key, &flow, 0) != 0) {
                    bpf_map_delete_elem(&active_session_map, &flow);
                    source_pressure_release_session(iph->saddr);
                    return XDP_DROP;
                }
                bpf_map_delete_elem(&pending_auth_map, &pending_key);
                bump(stats ? &stats->knock_valid : NULL);
            } else {
                struct session_lookup_key deauth_key = {};
                struct flow_key *bound_flow;

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
                source_pressure_release_session(iph->saddr);
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
        bump(stats ? &stats->protected_drop : NULL);
        return XDP_DROP;
    }
    if (sess->expires_at_ns < now_ns) {
        struct session_lookup_key lookup_key = {};

        lookup_key.src_ip = iph->saddr;
        lookup_key.session_id_hi = sess->session_id_hi;
        lookup_key.session_id_lo = sess->session_id_lo;
        bpf_map_delete_elem(&session_index_map, &lookup_key);
        bpf_map_delete_elem(&active_session_map, &flow);
        source_pressure_release_session(iph->saddr);
        bump(stats ? &stats->session_timeout_drop : NULL);
        bump(stats ? &stats->protected_drop : NULL);
        return XDP_DROP;
    }

    bump(stats ? &stats->protected_pass : NULL);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
