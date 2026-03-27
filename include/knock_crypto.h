#ifndef KNOCK_CRYPTO_H
#define KNOCK_CRYPTO_H

#include "shared.h"

static __inline void knock_signature_words(const __u8 key[KNOCK_HMAC_KEY_LEN],
                                           __u32 timestamp_sec,
                                           __u32 nonce,
                                           __u32 out[KNOCK_SIGNATURE_WORDS])
{
    __u32 k0 = ((__u32)key[0] << 24) | ((__u32)key[1] << 16) |
               ((__u32)key[2] << 8) | (__u32)key[3];
    __u32 k1 = ((__u32)key[4] << 24) | ((__u32)key[5] << 16) |
               ((__u32)key[6] << 8) | (__u32)key[7];
    __u32 k2 = ((__u32)key[8] << 24) | ((__u32)key[9] << 16) |
               ((__u32)key[10] << 8) | (__u32)key[11];
    __u32 k3 = ((__u32)key[12] << 24) | ((__u32)key[13] << 16) |
               ((__u32)key[14] << 8) | (__u32)key[15];
    __u32 k4 = ((__u32)key[16] << 24) | ((__u32)key[17] << 16) |
               ((__u32)key[18] << 8) | (__u32)key[19];
    __u32 k5 = ((__u32)key[20] << 24) | ((__u32)key[21] << 16) |
               ((__u32)key[22] << 8) | (__u32)key[23];
    __u32 k6 = ((__u32)key[24] << 24) | ((__u32)key[25] << 16) |
               ((__u32)key[26] << 8) | (__u32)key[27];
    __u32 k7 = ((__u32)key[28] << 24) | ((__u32)key[29] << 16) |
               ((__u32)key[30] << 8) | (__u32)key[31];

    out[0] = timestamp_sec ^ k0 ^ k4 ^ 0xa5a5a5a5U;
    out[1] = nonce ^ k1 ^ k5 ^ 0x3c6ef372U;
    out[2] = (timestamp_sec + nonce) ^ k2 ^ k6 ^ 0xbb67ae85U;
    out[3] = (out[0] ^ out[1] ^ out[2]) + k3 + k7;
}

#endif /* KNOCK_CRYPTO_H */
