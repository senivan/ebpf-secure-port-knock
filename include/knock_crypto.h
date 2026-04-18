#ifndef KNOCK_CRYPTO_H
#define KNOCK_CRYPTO_H

#include "shared.h"

struct knock_sig_input {
    __u32 timestamp_sec;
    __u8 packet_type;
    __u8 pad[3];
    __u32 session_id_hi;
    __u32 session_id_lo;
    __u32 nonce;
    __u16 bind_src_port;
    __u16 bind_dst_port;
};

static __inline __u64 knock_rotl64(__u64 x, __u8 b)
{
    return (x << b) | (x >> (64U - b));
}

static __inline __u64 knock_load_be64(const __u8 *p)
{
    return ((__u64)p[0] << 56) | ((__u64)p[1] << 48) |
           ((__u64)p[2] << 40) | ((__u64)p[3] << 32) |
           ((__u64)p[4] << 24) | ((__u64)p[5] << 16) |
           ((__u64)p[6] << 8) | (__u64)p[7];
}

#define KNOCK_SIPROUND(v0, v1, v2, v3) \
    do { \
        (v0) += (v1); \
        (v1) = knock_rotl64((v1), 13); \
        (v1) ^= (v0); \
        (v0) = knock_rotl64((v0), 32); \
        (v2) += (v3); \
        (v3) = knock_rotl64((v3), 16); \
        (v3) ^= (v2); \
        (v0) += (v3); \
        (v3) = knock_rotl64((v3), 21); \
        (v3) ^= (v0); \
        (v2) += (v1); \
        (v1) = knock_rotl64((v1), 17); \
        (v1) ^= (v2); \
        (v2) = knock_rotl64((v2), 32); \
    } while (0)

static __inline __u64 knock_siphash24_16b(__u64 k0, __u64 k1, __u64 m0, __u64 m1, __u64 tweak)
{
    __u64 v0 = 0x736f6d6570736575ULL ^ k0 ^ tweak;
    __u64 v1 = 0x646f72616e646f6dULL ^ k1;
    __u64 v2 = 0x6c7967656e657261ULL ^ k0;
    __u64 v3 = 0x7465646279746573ULL ^ k1 ^ (~tweak);
    __u64 b = 16ULL << 56;

    v3 ^= m0;
    KNOCK_SIPROUND(v0, v1, v2, v3);
    KNOCK_SIPROUND(v0, v1, v2, v3);
    v0 ^= m0;

    v3 ^= m1;
    KNOCK_SIPROUND(v0, v1, v2, v3);
    KNOCK_SIPROUND(v0, v1, v2, v3);
    v0 ^= m1;

    v3 ^= b;
    KNOCK_SIPROUND(v0, v1, v2, v3);
    KNOCK_SIPROUND(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xff;
    KNOCK_SIPROUND(v0, v1, v2, v3);
    KNOCK_SIPROUND(v0, v1, v2, v3);
    KNOCK_SIPROUND(v0, v1, v2, v3);
    KNOCK_SIPROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

static __inline void knock_signature_words(const __u8 key[KNOCK_HMAC_KEY_LEN],
                                           const struct knock_sig_input *in,
                                           __u32 out[KNOCK_SIGNATURE_WORDS])
{
    __u64 k0 = knock_load_be64(&key[0]);
    __u64 k1 = knock_load_be64(&key[8]);
    __u64 k2 = knock_load_be64(&key[16]);
    __u64 k3 = knock_load_be64(&key[24]);
    __u64 m0 = ((__u64)in->timestamp_sec << 32) | (__u64)in->nonce;
    __u64 m1 = ((__u64)KNOCK_MAGIC << 32) |
               ((__u64)in->packet_type << 24) |
               ((in->session_id_hi >> 8) & 0x00ffffffU);
    __u64 m2 = ((__u64)(in->session_id_hi & 0x000000ffU) << 56) |
               ((__u64)in->session_id_lo << 24) |
               ((__u64)in->bind_src_port << 8) |
               (__u64)(in->bind_dst_port >> 8);
    __u64 m3 = ((__u64)(in->bind_dst_port & 0x00ffU) << 56) |
               0x0053474e31ULL;
    __u64 h0 = knock_siphash24_16b(k0 ^ k2, k1 ^ k3, m0, m1, 0x0101010101010101ULL);
    __u64 h1 = knock_siphash24_16b(k0 ^ ~k2, k1 ^ ~k3, m2, m3, 0x0202020202020202ULL);

    out[0] = (__u32)(h0 >> 32);
    out[1] = (__u32)(h0 & 0xffffffffU);
    out[2] = (__u32)(h1 >> 32);
    out[3] = (__u32)(h1 & 0xffffffffU);
}

#undef KNOCK_SIPROUND

#endif /* KNOCK_CRYPTO_H */
