#ifndef NET_CHECKSUM_H
#define NET_CHECKSUM_H

#include <stdint.h>
#include <stdlib.h>

#if defined(__linux__)
#include <netinet/ip.h>
#include <netinet/tcp.h>
#else
#include <arpa/inet.h>

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t ihl : 4;
    uint8_t version : 4;
#else
    uint8_t version : 4;
    uint8_t ihl : 4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint16_t res1 : 4;
    uint16_t doff : 4;
    uint16_t fin : 1;
    uint16_t syn : 1;
    uint16_t rst : 1;
    uint16_t psh : 1;
    uint16_t ack : 1;
    uint16_t urg : 1;
    uint16_t ece : 1;
    uint16_t cwr : 1;
#else
    uint16_t doff : 4;
    uint16_t res1 : 4;
    uint16_t cwr : 1;
    uint16_t ece : 1;
    uint16_t urg : 1;
    uint16_t ack : 1;
    uint16_t psh : 1;
    uint16_t rst : 1;
    uint16_t syn : 1;
    uint16_t fin : 1;
#endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#endif

uint16_t csum16(const void *data, size_t len);
uint16_t tcp_checksum(const struct iphdr *iph, const struct tcphdr *tcph, const void *payload, size_t payload_len);

#endif /* NET_CHECKSUM_H */
