#include "knock_crypto.h"
#include "test_common.h"

static void test_knock_signature_words_matches_known_vector(void)
{
    static const __u8 key[KNOCK_HMAC_KEY_LEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    struct knock_sig_input in = {
        .timestamp_sec = 1710000000U,
        .packet_type = KNOCK_PKT_AUTH,
        .session_id_hi = 0x00640012U,
        .session_id_lo = 0x89abcdefU,
        .nonce = 0x13572468U,
        .bind_src_port = 50000U,
        .bind_dst_port = 22U,
    };
    __u32 out[KNOCK_SIGNATURE_WORDS] = {0};

    knock_signature_words(key, &in, out);

    ASSERT_EQ_U32(0x314ff370U, out[0]);
    ASSERT_EQ_U32(0x4b58cb8aU, out[1]);
    ASSERT_EQ_U32(0xe8106c83U, out[2]);
    ASSERT_EQ_U32(0x1d13b0a4U, out[3]);
}

static void test_knock_signature_words_changes_with_packet_type(void)
{
    static const __u8 key[KNOCK_HMAC_KEY_LEN] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    struct knock_sig_input auth = {
        .timestamp_sec = 1710001234U,
        .packet_type = KNOCK_PKT_AUTH,
        .session_id_hi = 0x00010002U,
        .session_id_lo = 0x00030004U,
        .nonce = 0x11223344U,
        .bind_src_port = 12345U,
        .bind_dst_port = 443U,
    };
    struct knock_sig_input deauth = auth;
    __u32 sig_auth[KNOCK_SIGNATURE_WORDS] = {0};
    __u32 sig_deauth[KNOCK_SIGNATURE_WORDS] = {0};

    deauth.packet_type = KNOCK_PKT_DEAUTH;

    knock_signature_words(key, &auth, sig_auth);
    knock_signature_words(key, &deauth, sig_deauth);

    ASSERT_TRUE(sig_auth[0] != sig_deauth[0] ||
                sig_auth[1] != sig_deauth[1] ||
                sig_auth[2] != sig_deauth[2] ||
                sig_auth[3] != sig_deauth[3]);
}

static void test_knock_signature_words_changes_with_bind_ports(void)
{
    static const __u8 key[KNOCK_HMAC_KEY_LEN] = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    struct knock_sig_input in_a = {
        .timestamp_sec = 1710002222U,
        .packet_type = KNOCK_PKT_BIND,
        .session_id_hi = 0x00070008U,
        .session_id_lo = 0x0009000aU,
        .nonce = 0x55667788U,
        .bind_src_port = 34567U,
        .bind_dst_port = 8080U,
    };
    struct knock_sig_input in_b = in_a;
    __u32 sig_a[KNOCK_SIGNATURE_WORDS] = {0};
    __u32 sig_b[KNOCK_SIGNATURE_WORDS] = {0};

    in_b.bind_dst_port = 8443U;

    knock_signature_words(key, &in_a, sig_a);
    knock_signature_words(key, &in_b, sig_b);

    ASSERT_TRUE(sig_a[0] != sig_b[0] ||
                sig_a[1] != sig_b[1] ||
                sig_a[2] != sig_b[2] ||
                sig_a[3] != sig_b[3]);
}

int main(void)
{
    test_knock_signature_words_matches_known_vector();
    test_knock_signature_words_changes_with_packet_type();
    test_knock_signature_words_changes_with_bind_ports();
    puts("test_knock_crypto: ok");
    return 0;
}
