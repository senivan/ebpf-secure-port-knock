#ifndef NET_CHECKSUM_H
#define NET_CHECKSUM_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>

uint16_t csum16(const void *data, size_t len);
uint16_t tcp_checksum(const struct iphdr *iph, const struct tcphdr *tcph, const void *payload, size_t payload_len);

#endif /* NET_CHECKSUM_H */
