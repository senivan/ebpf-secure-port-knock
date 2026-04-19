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

static const __u32 knock_sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static __inline __u32 knock_rotr32(__u32 x, __u8 n)
{
    return (x >> n) | (x << (32U - n));
}

static __inline __u32 knock_load_be32(const __u8 *p)
{
    return ((__u32)p[0] << 24) | ((__u32)p[1] << 16) |
           ((__u32)p[2] << 8) | (__u32)p[3];
}

static __inline void knock_store_be32(__u8 *dst, __u32 v)
{
    dst[0] = (__u8)(v >> 24);
    dst[1] = (__u8)(v >> 16);
    dst[2] = (__u8)(v >> 8);
    dst[3] = (__u8)(v & 0xffU);
}

static __inline void knock_store_be64(__u8 *dst, __u64 v)
{
    dst[0] = (__u8)(v >> 56);
    dst[1] = (__u8)(v >> 48);
    dst[2] = (__u8)(v >> 40);
    dst[3] = (__u8)(v >> 32);
    dst[4] = (__u8)(v >> 24);
    dst[5] = (__u8)(v >> 16);
    dst[6] = (__u8)(v >> 8);
    dst[7] = (__u8)(v & 0xffU);
}

static __inline __u32 knock_sha256_ch(__u32 x, __u32 y, __u32 z)
{
    return (x & y) ^ ((~x) & z);
}

static __inline __u32 knock_sha256_maj(__u32 x, __u32 y, __u32 z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static __inline __u32 knock_sha256_big_sigma0(__u32 x)
{
    return knock_rotr32(x, 2) ^ knock_rotr32(x, 13) ^ knock_rotr32(x, 22);
}

static __inline __u32 knock_sha256_big_sigma1(__u32 x)
{
    return knock_rotr32(x, 6) ^ knock_rotr32(x, 11) ^ knock_rotr32(x, 25);
}

static __inline __u32 knock_sha256_small_sigma0(__u32 x)
{
    return knock_rotr32(x, 7) ^ knock_rotr32(x, 18) ^ (x >> 3);
}

static __inline __u32 knock_sha256_small_sigma1(__u32 x)
{
    return knock_rotr32(x, 17) ^ knock_rotr32(x, 19) ^ (x >> 10);
}

static __inline void knock_sha256_init(__u32 state[8])
{
    state[0] = 0x6a09e667U;
    state[1] = 0xbb67ae85U;
    state[2] = 0x3c6ef372U;
    state[3] = 0xa54ff53aU;
    state[4] = 0x510e527fU;
    state[5] = 0x9b05688cU;
    state[6] = 0x1f83d9abU;
    state[7] = 0x5be0cd19U;
}

static __inline void knock_sha256_transform_words(__u32 state[8], __u32 w[16])
{
    __u32 a = state[0];
    __u32 b = state[1];
    __u32 c = state[2];
    __u32 d = state[3];
    __u32 e = state[4];
    __u32 f = state[5];
    __u32 g = state[6];
    __u32 h = state[7];
    __u32 i;

    for (i = 0; i < 64; i++) {
        __u32 s0;
        __u32 s1;
        __u32 t1;
        __u32 t2;
        __u32 wi;

        if (i >= 16) {
            s0 = knock_sha256_small_sigma0(w[(i - 15) & 15]);
            s1 = knock_sha256_small_sigma1(w[(i - 2) & 15]);
            w[i & 15] = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
        }
        wi = w[i & 15];
        t1 = h + knock_sha256_big_sigma1(e) + knock_sha256_ch(e, f, g) +
             knock_sha256_k[i] + wi;
        t2 = knock_sha256_big_sigma0(a) + knock_sha256_maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static __inline void knock_signature_words(const __u8 key[KNOCK_HMAC_KEY_LEN],
                                           const struct knock_sig_input *in,
                                           __u32 out[KNOCK_SIGNATURE_WORDS])
{
    __u32 state[8];
    __u32 inner_digest[8];
    __u32 w[16] = {};
    __u64 padded_len_bits = (64ULL + 32ULL) * 8ULL;
    __u32 ipad_word = 0x36363636U;
    __u32 opad_word = 0x5c5c5c5cU;
    __u32 i;
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

    for (i = 0; i < 8; i++) {
        __u32 kword = ((__u32)key[i * 4] << 24) |
                      ((__u32)key[i * 4 + 1] << 16) |
                      ((__u32)key[i * 4 + 2] << 8) |
                      (__u32)key[i * 4 + 3];
        w[i] = kword ^ ipad_word;
    }
    for (i = 8; i < 16; i++) {
        w[i] = ipad_word;
    }

    knock_sha256_init(state);
    knock_sha256_transform_words(state, w);

    w[0] = (__u32)(m0 >> 32);
    w[1] = (__u32)m0;
    w[2] = (__u32)(m1 >> 32);
    w[3] = (__u32)m1;
    w[4] = (__u32)(m2 >> 32);
    w[5] = (__u32)m2;
    w[6] = (__u32)(m3 >> 32);
    w[7] = (__u32)m3;
    w[8] = 0x80000000U;
    w[9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = (__u32)(padded_len_bits >> 32);
    w[15] = (__u32)padded_len_bits;
    knock_sha256_transform_words(state, w);

    for (i = 0; i < 8; i++) {
        inner_digest[i] = state[i];
    }

    for (i = 0; i < 8; i++) {
        __u32 kword = ((__u32)key[i * 4] << 24) |
                      ((__u32)key[i * 4 + 1] << 16) |
                      ((__u32)key[i * 4 + 2] << 8) |
                      (__u32)key[i * 4 + 3];
        w[i] = kword ^ opad_word;
    }
    for (i = 8; i < 16; i++) {
        w[i] = opad_word;
    }

    knock_sha256_init(state);
    knock_sha256_transform_words(state, w);

    for (i = 0; i < 8; i++) {
        w[i] = inner_digest[i];
    }
    w[8] = 0x80000000U;
    w[9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = (__u32)(padded_len_bits >> 32);
    w[15] = (__u32)padded_len_bits;
    knock_sha256_transform_words(state, w);

    out[0] = state[0];
    out[1] = state[1];
    out[2] = state[2];
    out[3] = state[3];
}

#endif /* KNOCK_CRYPTO_H */
