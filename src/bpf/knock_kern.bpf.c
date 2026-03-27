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
    __type(value, struct auth_state);
} auth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct replay_nonce_key);
    __type(value, struct replay_nonce_state);
} replay_nonce_map SEC(".maps");

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

static __always_inline bool knock_is_valid(const struct knock_config *cfg,
                                           const struct knock_packet *pkt)
{
    __u64 now_ns = bpf_ktime_get_ns();
    __u32 now_sec = (__u32)(now_ns / 1000000000ULL);
    __u32 ts_sec = bpf_ntohl(pkt->timestamp_sec);
    __u32 nonce = bpf_ntohl(pkt->nonce);
    __u32 sig[KNOCK_SIGNATURE_WORDS];
    __u32 i;

    if (pkt->magic != bpf_htonl(KNOCK_MAGIC)) {
        return false;
    }

    if (ts_sec + KNOCK_MAX_CLOCK_SKEW_SEC < now_sec) {
        return false;
    }
    if (now_sec + KNOCK_MAX_CLOCK_SKEW_SEC < ts_sec) {
        return false;
    }

    knock_signature_words(cfg->hmac_key, ts_sec, nonce, sig);
#pragma clang loop unroll(full)
    for (i = 0; i < KNOCK_SIGNATURE_WORDS; i++) {
        if (sig[i] != bpf_ntohl(pkt->signature[i])) {
            return false;
        }
    }

    return true;
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
    struct auth_state *auth;
    struct auth_state new_auth = {};
    struct knock_config *cfg;
    __u16 dst_port;
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
    now_ns = bpf_ktime_get_ns();

    if (dst_port == cfg->knock_port) {
        __u32 nonce_host;
        __u64 replay_window_ns;
        struct replay_nonce_key replay_key;
        struct replay_nonce_state replay_state = {};
        struct replay_nonce_state *seen;

        bump(stats ? &stats->knock_seen : NULL);
        kpkt = (struct knock_packet *)((void *)tcph + ((__u64)tcph->doff * 4U));
        if (!ptr_ok(kpkt, data_end, sizeof(*kpkt))) {
            bump(stats ? &stats->knock_short : NULL);
            return XDP_DROP;
        }

        nonce_host = bpf_ntohl(kpkt->nonce);

        if (snap) {
            snap->magic = kpkt->magic;
            snap->timestamp_sec = kpkt->timestamp_sec;
            snap->nonce = kpkt->nonce;
            snap->sig0 = kpkt->signature[0];
            snap->sig1 = kpkt->signature[1];
            snap->sig2 = kpkt->signature[2];
            snap->sig3 = kpkt->signature[3];
        }

        if (knock_is_valid(cfg, kpkt)) {
            replay_key.src_ip = iph->saddr;
            replay_key.nonce = nonce_host;

            seen = bpf_map_lookup_elem(&replay_nonce_map, &replay_key);
            if (seen) {
                if (seen->expires_at_ns >= now_ns) {
                    bump(stats ? &stats->replay_drop : NULL);
                    return XDP_DROP;
                }
                bpf_map_delete_elem(&replay_nonce_map, &replay_key);
            }

            replay_window_ns = (__u64)cfg->timeout_ms * 1000000ULL;
            if (replay_window_ns < ((__u64)KNOCK_MAX_CLOCK_SKEW_SEC * 1000000000ULL)) {
                replay_window_ns = (__u64)KNOCK_MAX_CLOCK_SKEW_SEC * 1000000000ULL;
            }
            replay_state.expires_at_ns = now_ns + replay_window_ns;
            bpf_map_update_elem(&replay_nonce_map, &replay_key, &replay_state, BPF_ANY);

            new_auth.expires_at_ns = now_ns + ((__u64)cfg->timeout_ms * 1000000ULL);
            bpf_map_update_elem(&auth_map, &iph->saddr, &new_auth, BPF_ANY);
            bump(stats ? &stats->knock_valid : NULL);
        }

        /* Knock channel should not expose any service behavior. */
        return XDP_DROP;
    }

    if (!is_protected_port(cfg, dst_port)) {
        return XDP_PASS;
    }

    auth = bpf_map_lookup_elem(&auth_map, &iph->saddr);
    if (!auth) {
        bump(stats ? &stats->protected_drop : NULL);
        return XDP_DROP;
    }
    if (auth->expires_at_ns < now_ns) {
        bpf_map_delete_elem(&auth_map, &iph->saddr);
        bump(stats ? &stats->protected_drop : NULL);
        return XDP_DROP;
    }

    bump(stats ? &stats->protected_pass : NULL);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
