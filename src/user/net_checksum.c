#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "net_checksum.h"

struct pseudo_tcp_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tcp_len;
};

uint16_t csum16(const void *data, size_t len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)p;
    }

    while (sum >> 16) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint16_t tcp_checksum(const struct iphdr *iph, const struct tcphdr *tcph, const void *payload, size_t payload_len)
{
    struct pseudo_tcp_header psh = {
        .src_addr = iph->saddr,
        .dst_addr = iph->daddr,
        .zero = 0,
        .proto = IPPROTO_TCP,
        .tcp_len = htons((uint16_t)(sizeof(*tcph) + payload_len)),
    };

    size_t buf_len = sizeof(psh) + sizeof(*tcph) + payload_len;
    uint8_t *buf = calloc(1, buf_len);
    uint16_t sum;

    if (!buf) {
        return 0;
    }

    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), tcph, sizeof(*tcph));
    if (payload_len > 0) {
        memcpy(buf + sizeof(psh) + sizeof(*tcph), payload, payload_len);
    }

    sum = csum16(buf, buf_len);
    free(buf);
    return sum;
}
