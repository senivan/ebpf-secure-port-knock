#include <arpa/inet.h>
#include <string.h>

#include "net_checksum.h"
#include "test_common.h"

static uint16_t reference_checksum(const void *data, size_t len)
{
    const unsigned char *bytes = data;
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)bytes[i] | ((uint32_t)bytes[i + 1] << 8);
    }
    if (i < len) {
        sum += bytes[i];
    }

    while (sum >> 16) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

static uint16_t reference_tcp_checksum(const struct iphdr *iph,
                                       const struct tcphdr *tcph,
                                       const void *payload,
                                       size_t payload_len)
{
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t proto;
        uint16_t tcp_len;
    } pseudo = {
        .src_addr = iph->saddr,
        .dst_addr = iph->daddr,
        .zero = 0,
        .proto = IPPROTO_TCP,
        .tcp_len = htons((uint16_t)(sizeof(*tcph) + payload_len)),
    };
    unsigned char buf[sizeof(pseudo) + sizeof(*tcph) + 16] = {0};

    ASSERT_TRUE(payload_len <= 16);
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, sizeof(*tcph));
    memcpy(buf + sizeof(pseudo) + sizeof(*tcph), payload, payload_len);

    return reference_checksum(buf, sizeof(pseudo) + sizeof(*tcph) + payload_len);
}

static void test_csum16_matches_reference_for_even_length(void)
{
    static const unsigned char bytes[] = {0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00};

    ASSERT_EQ_U16(reference_checksum(bytes, sizeof(bytes)), csum16(bytes, sizeof(bytes)));
}

static void test_csum16_matches_reference_for_odd_length(void)
{
    static const unsigned char bytes[] = {0xde, 0xad, 0xbe, 0xef, 0x11};

    ASSERT_EQ_U16(reference_checksum(bytes, sizeof(bytes)), csum16(bytes, sizeof(bytes)));
}

static void test_tcp_checksum_matches_reference(void)
{
    struct iphdr iph = {0};
    struct tcphdr tcph = {0};
    static const unsigned char payload[] = {'K', 'N', 'O', 'C', 'K'};

    iph.saddr = inet_addr("192.0.2.10");
    iph.daddr = inet_addr("198.51.100.20");

    tcph.source = htons(12345);
    tcph.dest = htons(40000);
    tcph.seq = htonl(1);
    tcph.ack_seq = htonl(0);
    tcph.doff = 5;
    tcph.syn = 1;
    tcph.window = htons(4096);

    ASSERT_EQ_U16(reference_tcp_checksum(&iph, &tcph, payload, sizeof(payload)),
                  tcp_checksum(&iph, &tcph, payload, sizeof(payload)));
}

static void test_tcp_checksum_changes_with_payload(void)
{
    struct iphdr iph = {0};
    struct tcphdr tcph = {0};
    static const unsigned char payload_a[] = {'A', 'A', 'A', 'A'};
    static const unsigned char payload_b[] = {'A', 'A', 'A', 'B'};

    iph.saddr = inet_addr("203.0.113.1");
    iph.daddr = inet_addr("203.0.113.2");

    tcph.source = htons(1111);
    tcph.dest = htons(2222);
    tcph.doff = 5;
    tcph.ack = 1;
    tcph.window = htons(2048);

    ASSERT_TRUE(tcp_checksum(&iph, &tcph, payload_a, sizeof(payload_a)) !=
                tcp_checksum(&iph, &tcph, payload_b, sizeof(payload_b)));
}

int main(void)
{
    test_csum16_matches_reference_for_even_length();
    test_csum16_matches_reference_for_odd_length();
    test_tcp_checksum_matches_reference();
    test_tcp_checksum_changes_with_payload();
    puts("test_net_checksum: ok");
    return 0;
}
