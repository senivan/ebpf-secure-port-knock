#include <getopt.h>

#include "net_checksum.h"
#include "test_common.h"

#define main knock_client_entry
#include "../src/user/knock_client.c"
#undef main

uint16_t csum16(const void *data, size_t len)
{
    (void)data;
    (void)len;
    return 0;
}

uint16_t tcp_checksum(const struct iphdr *iph, const struct tcphdr *tcph, const void *payload, size_t payload_len)
{
    (void)iph;
    (void)tcph;
    (void)payload;
    (void)payload_len;
    return 0;
}

static void reset_getopt_state(void)
{
    optind = 1;
    opterr = 0;
}

static int run_knock_client(int argc, char **argv)
{
    reset_getopt_state();
    return knock_client_entry(argc, argv);
}

static void test_missing_required_arguments_returns_error(void)
{
    char *argv[] = {(char *)"knock-client", NULL};

    ASSERT_EQ_INT(1, run_knock_client(1, argv));
}

static void test_rejects_invalid_packet_type(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knock-client", (char *)"--ifname", (char *)"lo", (char *)"--src-ip", (char *)"127.0.0.1",
                    (char *)"--dst-ip", (char *)"127.0.0.1", (char *)"--hmac-key", (char *)key, (char *)"--packet-type",
                    (char *)"invalid", NULL};

    ASSERT_EQ_INT(1, run_knock_client(11, argv));
}

static void test_rejects_invalid_dst_port(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knock-client", (char *)"--ifname", (char *)"lo", (char *)"--src-ip", (char *)"127.0.0.1",
                    (char *)"--dst-ip", (char *)"127.0.0.1", (char *)"--hmac-key", (char *)key, (char *)"--dst-port",
                    (char *)"0", NULL};

    ASSERT_EQ_INT(1, run_knock_client(11, argv));
}

static void test_rejects_invalid_src_port(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knock-client", (char *)"--ifname", (char *)"lo", (char *)"--src-ip", (char *)"127.0.0.1",
                    (char *)"--dst-ip", (char *)"127.0.0.1", (char *)"--hmac-key", (char *)key, (char *)"--src-port",
                    (char *)"70000", NULL};

    ASSERT_EQ_INT(1, run_knock_client(11, argv));
}

static void test_rejects_invalid_bind_port(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knock-client", (char *)"--ifname", (char *)"lo", (char *)"--src-ip", (char *)"127.0.0.1",
                    (char *)"--dst-ip", (char *)"127.0.0.1", (char *)"--hmac-key", (char *)key, (char *)"--bind-port",
                    (char *)"0", NULL};

    ASSERT_EQ_INT(1, run_knock_client(11, argv));
}

static void test_rejects_invalid_hmac_key_length(void)
{
    char *argv[] = {(char *)"knock-client", (char *)"--ifname", (char *)"lo", (char *)"--src-ip", (char *)"127.0.0.1",
                    (char *)"--dst-ip", (char *)"127.0.0.1", (char *)"--hmac-key", (char *)"abcd", NULL};

    ASSERT_EQ_INT(1, run_knock_client(9, argv));
}

static void test_rejects_invalid_interface_name(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knock-client", (char *)"--ifname", (char *)"no_such_iface", (char *)"--src-ip", (char *)"127.0.0.1",
                    (char *)"--dst-ip", (char *)"127.0.0.1", (char *)"--hmac-key", (char *)key, NULL};

    ASSERT_EQ_INT(1, run_knock_client(9, argv));
}

static void test_deauth_requires_session_id(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knock-client", (char *)"--ifname", (char *)"lo", (char *)"--src-ip", (char *)"127.0.0.1",
                    (char *)"--dst-ip", (char *)"127.0.0.1", (char *)"--hmac-key", (char *)key, (char *)"--packet-type",
                    (char *)"deauth", NULL};

    ASSERT_EQ_INT(1, run_knock_client(11, argv));
}

static void test_bind_requires_bind_port(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knock-client", (char *)"--ifname", (char *)"lo", (char *)"--src-ip", (char *)"127.0.0.1",
                    (char *)"--dst-ip", (char *)"127.0.0.1", (char *)"--hmac-key", (char *)key, (char *)"--packet-type",
                    (char *)"bind", (char *)"--session-id", (char *)"123", NULL};

    ASSERT_EQ_INT(1, run_knock_client(13, argv));
}

int main(void)
{
    test_missing_required_arguments_returns_error();
    test_rejects_invalid_packet_type();
    test_rejects_invalid_dst_port();
    test_rejects_invalid_src_port();
    test_rejects_invalid_bind_port();
    test_rejects_invalid_hmac_key_length();
    test_rejects_invalid_interface_name();
    test_deauth_requires_session_id();
    test_bind_requires_bind_port();
    puts("test_knock_client: ok");
    return 0;
}
