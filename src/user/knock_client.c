#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "cli_common.h"
#include "knock_crypto.h"
#include "net_checksum.h"
#include "shared.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --ifname <iface> --src-ip <ip> --dst-ip <ip> --dst-port <port> --hmac-key <64-hex> [options]\n"
            "Options:\n"
            "  --src-port <port>            Source TCP port (default: 50000)\n"
            "  --nonce <u32>                Explicit nonce (default: random)\n"
            "  --timestamp-sec <u32>        Explicit monotonic timestamp (default: CLOCK_MONOTONIC)\n",
            prog);
}


int main(int argc, char **argv)
{
    static struct option long_opts[] = {
        {"ifname", required_argument, NULL, 'i'},
        {"src-ip", required_argument, NULL, 's'},
        {"dst-ip", required_argument, NULL, 'd'},
        {"dst-port", required_argument, NULL, 'p'},
        {"src-port", required_argument, NULL, 'q'},
        {"hmac-key", required_argument, NULL, 'k'},
        {"nonce", required_argument, NULL, 'n'},
        {"timestamp-sec", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0},
    };

    const char *ifname = NULL;
    const char *src_ip_str = NULL;
    const char *dst_ip_str = NULL;
    const char *hmac_hex = NULL;
    uint16_t src_port = 50000;
    uint16_t dst_port = KNOCK_DEFAULT_PORT;
    uint32_t nonce = 0;
    uint32_t ts = 0;
    int have_nonce = 0;
    int have_ts = 0;
    __u8 key[KNOCK_HMAC_KEY_LEN] = {0};
    struct knock_packet kpkt;
    __u32 sig[KNOCK_SIGNATURE_WORDS];
    uint8_t frame[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct knock_packet)] = {0};
    struct ethhdr *eth = (struct ethhdr *)frame;
    struct iphdr *iph = (struct iphdr *)(frame + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    struct knock_packet *payload = (struct knock_packet *)(frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    struct sockaddr_ll sll;
    int fd;
    int ctl_fd;
    int ifindex;
    int opt;
    struct ifreq ifr;

    while ((opt = getopt_long(argc, argv, "i:s:d:p:q:k:n:t:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 's':
            src_ip_str = optarg;
            break;
        case 'd':
            dst_ip_str = optarg;
            break;
        case 'p': {
            unsigned long v = strtoul(optarg, NULL, 10);
            if (v == 0 || v > 65535UL) {
                fprintf(stderr, "error: invalid --dst-port\n");
                return 1;
            }
            dst_port = (uint16_t)v;
            break;
        }
        case 'q': {
            unsigned long v = strtoul(optarg, NULL, 10);
            if (v == 0 || v > 65535UL) {
                fprintf(stderr, "error: invalid --src-port\n");
                return 1;
            }
            src_port = (uint16_t)v;
            break;
        }
        case 'k':
            hmac_hex = optarg;
            break;
        case 'n':
            nonce = (uint32_t)strtoul(optarg, NULL, 10);
            have_nonce = 1;
            break;
        case 't':
            ts = (uint32_t)strtoul(optarg, NULL, 10);
            have_ts = 1;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!ifname || !src_ip_str || !dst_ip_str || !hmac_hex) {
        usage(argv[0]);
        return 1;
    }

    if (parse_hmac_key_hex(hmac_hex, key) != 0) {
        fprintf(stderr, "error: --hmac-key must be exactly 64 hex characters\n");
        return 1;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        fprintf(stderr, "error: invalid --ifname %s\n", ifname);
        return 1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl_fd < 0) {
        fprintf(stderr, "error: control socket failed: %s\n", strerror(errno));
        return 1;
    }
    if (ioctl(ctl_fd, SIOCGIFHWADDR, &ifr) != 0) {
        fprintf(stderr, "error: cannot read MAC for %s: %s\n", ifname, strerror(errno));
        close(ctl_fd);
        return 1;
    }
    close(ctl_fd);

    if (!have_ts) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            fprintf(stderr, "error: clock_gettime(CLOCK_MONOTONIC) failed: %s\n", strerror(errno));
            return 1;
        }
        ts = (uint32_t)now.tv_sec;
    }
    if (!have_nonce) {
        srand((unsigned int)(time(NULL) ^ getpid()));
        nonce = (uint32_t)rand();
    }

    memset(&kpkt, 0, sizeof(kpkt));
    kpkt.magic = htonl(KNOCK_MAGIC);
    kpkt.timestamp_sec = htonl(ts);
    kpkt.nonce = htonl(nonce);

    {
        struct in_addr src_addr;
        struct in_addr dst_addr;

        if (inet_pton(AF_INET, src_ip_str, &src_addr) != 1 || inet_pton(AF_INET, dst_ip_str, &dst_addr) != 1) {
            fprintf(stderr, "error: invalid source or destination IP\n");
            return 1;
        }

        knock_signature_words(key, ts, nonce, sig);

        for (size_t i = 0; i < KNOCK_SIGNATURE_WORDS; i++) {
            kpkt.signature[i] = htonl(sig[i]);
        }

        eth->h_proto = htons(ETH_P_IP);
        memcpy(eth->h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        memset(eth->h_dest, 0xff, ETH_ALEN);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = 0;
        iph->tot_len = htons((uint16_t)(sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct knock_packet)));
        iph->id = htons((uint16_t)(rand() & 0xffffU));
        iph->frag_off = htons(0x4000);
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = src_addr.s_addr;
        iph->daddr = dst_addr.s_addr;
        iph->check = csum16(iph, sizeof(*iph));
    }

    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(1);
    tcph->ack_seq = htonl(0);
    tcph->doff = 5;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->window = htons(1024);
    tcph->urg_ptr = 0;

    memcpy(payload, &kpkt, sizeof(kpkt));
    tcph->check = tcp_checksum(iph, tcph, payload, sizeof(kpkt));

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) {
        fprintf(stderr, "error: AF_PACKET socket failed: %s\n", strerror(errno));
        return 1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_IP);

    if (sendto(fd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "error: sendto failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    close(fd);
    printf("Knock frame sent on %s to %s:%u from %s:%u\n", ifname, dst_ip_str, dst_port, src_ip_str, src_port);
    printf("timestamp=%u nonce=%u sig=%08x:%08x:%08x:%08x\n",
           ts, nonce, sig[0], sig[1], sig[2], sig[3]);
    return 0;
}
