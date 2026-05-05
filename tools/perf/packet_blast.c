#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "knock_crypto.h"
#include "net_checksum.h"
#include "shared.h"

enum payload_mode {
    PAYLOAD_EMPTY,
    PAYLOAD_INVALID_KNOCK,
    PAYLOAD_VALID_KNOCK,
    PAYLOAD_VALID_KNOCK_FIXED,
};

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --ifname <iface> --src-ip <ip> --dst-ip <ip> --dst-port <port> [options]\n"
            "Options:\n"
            "  --src-port <port>       First TCP source port (default: 50000)\n"
            "  --src-port-span <n>     Number of source ports to rotate through (default: 1)\n"
            "  --src-ip-span <n>       Number of IPv4 source addresses to rotate through (default: 1)\n"
            "  --duration-sec <sec>    Measurement duration (default: 10)\n"
            "  --target-pps <pps>      Best-effort rate cap; 0 means unlimited (default: 0)\n"
            "  --payload <empty|invalid-knock|valid-knock|valid-knock-fixed>  TCP payload mode (default: empty)\n"
            "  --hmac-key <64hex>     Key for valid knock payload modes\n"
            "  --user-id <u16>        User ID encoded in valid knock session IDs (default: 0)\n"
            "  --nonce <u32>          First nonce for knock payloads (default: 1)\n"
            "  --label <name>          Label copied into JSON output\n",
            prog);
}

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static int parse_u16(const char *s, uint16_t *out)
{
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);

    if (!end || *end != '\0' || v == 0 || v > 65535UL) {
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

static int parse_hmac_key_hex(const char *hex, uint8_t out[KNOCK_HMAC_KEY_LEN])
{
    size_t len;
    size_t i;

    if (!hex) {
        return -1;
    }
    len = strlen(hex);
    if (len != KNOCK_HMAC_KEY_LEN * 2U) {
        return -1;
    }
    for (i = 0; i < KNOCK_HMAC_KEY_LEN; i++) {
        char buf[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        char *end = NULL;
        unsigned long v = strtoul(buf, &end, 16);

        if (!end || *end != '\0' || v > 0xffUL) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int get_iface_mac(const char *ifname, unsigned char mac[ETH_ALEN])
{
    struct ifreq ifr;
    int fd;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    if (ret != 0) {
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

static size_t fill_invalid_knock(uint8_t *payload, uint32_t nonce)
{
    struct knock_packet kpkt;

    memset(&kpkt, 0, sizeof(kpkt));
    kpkt.magic = htonl(KNOCK_MAGIC);
    kpkt.timestamp_sec = htonl((uint32_t)time(NULL));
    kpkt.nonce = htonl(nonce);
    kpkt.packet_type = KNOCK_PKT_AUTH;
    kpkt.session_id_hi = htonl(0x03e80000U);
    kpkt.session_id_lo = htonl(nonce);
    kpkt.signature[0] = htonl(0x11111111U ^ nonce);
    kpkt.signature[1] = htonl(0x22222222U);
    kpkt.signature[2] = htonl(0x33333333U);
    kpkt.signature[3] = htonl(0x44444444U);
    memcpy(payload, &kpkt, sizeof(kpkt));
    return sizeof(kpkt);
}

static size_t fill_valid_knock(uint8_t *payload,
                               const uint8_t key[KNOCK_HMAC_KEY_LEN],
                               uint32_t user_id,
                               uint32_t nonce,
                               uint32_t session_lo)
{
    struct knock_packet kpkt;
    struct knock_sig_input sig_in = {};
    uint32_t sig[KNOCK_SIGNATURE_WORDS];
    uint32_t session_hi = ((user_id & 0xffffU) << KNOCK_USER_ID_SHIFT) | 0x1234U;
    size_t i;

    sig_in.timestamp_sec = (uint32_t)time(NULL);
    sig_in.packet_type = KNOCK_PKT_AUTH;
    sig_in.session_id_hi = session_hi;
    sig_in.session_id_lo = session_lo;
    sig_in.nonce = nonce;
    knock_signature_words(key, &sig_in, sig);

    memset(&kpkt, 0, sizeof(kpkt));
    kpkt.magic = htonl(KNOCK_MAGIC);
    kpkt.timestamp_sec = htonl(sig_in.timestamp_sec);
    kpkt.nonce = htonl(nonce);
    kpkt.packet_type = KNOCK_PKT_AUTH;
    kpkt.session_id_hi = htonl(session_hi);
    kpkt.session_id_lo = htonl(session_lo);
    for (i = 0; i < KNOCK_SIGNATURE_WORDS; i++) {
        kpkt.signature[i] = htonl(sig[i]);
    }

    memcpy(payload, &kpkt, sizeof(kpkt));
    return sizeof(kpkt);
}

int main(int argc, char **argv)
{
    static struct option opts[] = {
        {"ifname", required_argument, NULL, 'i'},
        {"src-ip", required_argument, NULL, 's'},
        {"dst-ip", required_argument, NULL, 'd'},
        {"dst-port", required_argument, NULL, 'p'},
        {"src-port", required_argument, NULL, 'q'},
        {"src-port-span", required_argument, NULL, 'S'},
        {"src-ip-span", required_argument, NULL, 'A'},
        {"duration-sec", required_argument, NULL, 'D'},
        {"target-pps", required_argument, NULL, 'r'},
        {"payload", required_argument, NULL, 'P'},
        {"hmac-key", required_argument, NULL, 'k'},
        {"user-id", required_argument, NULL, 'u'},
        {"nonce", required_argument, NULL, 'n'},
        {"label", required_argument, NULL, 'l'},
        {NULL, 0, NULL, 0},
    };
    const char *ifname = NULL;
    const char *src_ip_str = NULL;
    const char *dst_ip_str = NULL;
    const char *label = "packet_blast";
    uint16_t src_port = 50000;
    uint16_t dst_port = 0;
    uint32_t src_port_span = 1;
    uint32_t src_ip_span = 1;
    double duration_sec = 10.0;
    uint64_t target_pps = 0;
    enum payload_mode payload_mode = PAYLOAD_EMPTY;
    uint8_t hmac_key[KNOCK_HMAC_KEY_LEN] = {0};
    bool have_hmac_key = false;
    uint32_t user_id = 0;
    uint32_t nonce_base = 1;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    unsigned char src_mac[ETH_ALEN];
    int ifindex;
    int fd;
    struct sockaddr_ll sll;
    uint8_t frame[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct knock_packet)] = {0};
    struct ethhdr *eth = (struct ethhdr *)frame;
    struct iphdr *iph = (struct iphdr *)(frame + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    uint8_t *payload = frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    uint64_t sent = 0;
    uint64_t errors = 0;
    bool fatal_error = false;
    uint64_t start_ns;
    uint64_t end_ns;
    size_t frame_len = 0;
    int opt;

    while ((opt = getopt_long(argc, argv, "i:s:d:p:q:S:A:D:r:P:k:u:n:l:", opts, NULL)) != -1) {
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
        case 'p':
            if (parse_u16(optarg, &dst_port) != 0) {
                fprintf(stderr, "error: invalid --dst-port\n");
                return 1;
            }
            break;
        case 'q':
            if (parse_u16(optarg, &src_port) != 0) {
                fprintf(stderr, "error: invalid --src-port\n");
                return 1;
            }
            break;
        case 'S':
            src_port_span = (uint32_t)strtoul(optarg, NULL, 10);
            if (src_port_span == 0 || src_port_span > 60000U) {
                fprintf(stderr, "error: invalid --src-port-span\n");
                return 1;
            }
            break;
        case 'A':
            src_ip_span = (uint32_t)strtoul(optarg, NULL, 10);
            if (src_ip_span == 0 || src_ip_span > 65535U) {
                fprintf(stderr, "error: invalid --src-ip-span\n");
                return 1;
            }
            break;
        case 'D':
            duration_sec = strtod(optarg, NULL);
            if (duration_sec <= 0.0) {
                fprintf(stderr, "error: invalid --duration-sec\n");
                return 1;
            }
            break;
        case 'r':
            target_pps = strtoull(optarg, NULL, 10);
            break;
        case 'P':
            if (strcmp(optarg, "empty") == 0) {
                payload_mode = PAYLOAD_EMPTY;
            } else if (strcmp(optarg, "invalid-knock") == 0) {
                payload_mode = PAYLOAD_INVALID_KNOCK;
            } else if (strcmp(optarg, "valid-knock") == 0) {
                payload_mode = PAYLOAD_VALID_KNOCK;
            } else if (strcmp(optarg, "valid-knock-fixed") == 0) {
                payload_mode = PAYLOAD_VALID_KNOCK_FIXED;
            } else {
                fprintf(stderr, "error: invalid --payload\n");
                return 1;
            }
            break;
        case 'k':
            if (parse_hmac_key_hex(optarg, hmac_key) != 0) {
                fprintf(stderr, "error: --hmac-key must be exactly 64 hex characters\n");
                return 1;
            }
            have_hmac_key = true;
            break;
        case 'u':
            user_id = (uint32_t)strtoul(optarg, NULL, 10);
            if (user_id > 65535U) {
                fprintf(stderr, "error: invalid --user-id\n");
                return 1;
            }
            break;
        case 'n':
            nonce_base = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'l':
            label = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!ifname || !src_ip_str || !dst_ip_str || dst_port == 0) {
        usage(argv[0]);
        return 1;
    }
    if ((payload_mode == PAYLOAD_VALID_KNOCK || payload_mode == PAYLOAD_VALID_KNOCK_FIXED) && !have_hmac_key) {
        fprintf(stderr, "error: --hmac-key is required for valid knock payload modes\n");
        return 1;
    }
    if (inet_pton(AF_INET, src_ip_str, &src_addr) != 1 ||
        inet_pton(AF_INET, dst_ip_str, &dst_addr) != 1) {
        fprintf(stderr, "error: invalid source or destination IP\n");
        return 1;
    }
    ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        fprintf(stderr, "error: invalid --ifname %s\n", ifname);
        return 1;
    }
    if (get_iface_mac(ifname, src_mac) != 0) {
        fprintf(stderr, "error: cannot read MAC for %s: %s\n", ifname, strerror(errno));
        return 1;
    }

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) {
        fprintf(stderr, "error: AF_PACKET socket failed: %s\n", strerror(errno));
        return 1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_IP);

    eth->h_proto = htons(ETH_P_IP);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    memset(eth->h_dest, 0xff, ETH_ALEN);

    iph->version = 4;
    iph->ihl = 5;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->frag_off = htons(0x4000);
    iph->daddr = dst_addr.s_addr;

    tcph->dest = htons(dst_port);
    tcph->seq = htonl(1);
    tcph->doff = 5;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->window = htons(1024);

    start_ns = now_ns();
    end_ns = start_ns + (uint64_t)(duration_sec * 1000000000.0);
    while (now_ns() < end_ns) {
        uint32_t sport_value = (uint32_t)src_port + (uint32_t)(sent % src_port_span);
        uint32_t src_ip_host = ntohl(src_addr.s_addr) + (uint32_t)(sent % src_ip_span);
        uint16_t sport;
        size_t payload_len = 0;
        uint16_t total_len;
        uint64_t due_ns;

        if (sport_value == 0 || sport_value > 65535U) {
            sport_value = src_port;
        }
        sport = (uint16_t)sport_value;

        if (payload_mode == PAYLOAD_INVALID_KNOCK) {
            payload_len = fill_invalid_knock(payload, (uint32_t)(sent + 1U));
        } else if (payload_mode == PAYLOAD_VALID_KNOCK || payload_mode == PAYLOAD_VALID_KNOCK_FIXED) {
            uint32_t nonce = payload_mode == PAYLOAD_VALID_KNOCK_FIXED ? nonce_base : (uint32_t)(nonce_base + sent);
            uint32_t session_lo = payload_mode == PAYLOAD_VALID_KNOCK_FIXED ? 0xabcdef01U : (uint32_t)(0xabcdef01U + sent);

            payload_len = fill_valid_knock(payload, hmac_key, user_id, nonce, session_lo);
        }

        total_len = (uint16_t)(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
        iph->tot_len = htons(total_len);
        iph->id = htons((uint16_t)(sent & 0xffffU));
        iph->saddr = htonl(src_ip_host);
        iph->check = 0;
        iph->check = csum16(iph, sizeof(*iph));

        tcph->source = htons(sport);
        tcph->check = 0;
        tcph->check = tcp_checksum(iph, tcph, payload, payload_len);
        frame_len = sizeof(struct ethhdr) + total_len;

        if (sendto(fd, frame, frame_len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            errors++;
            if (errno == ENOBUFS || errno == EAGAIN || errno == EINTR) {
                continue;
            }
            fatal_error = true;
            break;
        }
        sent++;

        if (target_pps > 0) {
            due_ns = start_ns + ((sent * 1000000000ULL) / target_pps);
            while (now_ns() < due_ns) {
                struct timespec req = {.tv_sec = 0, .tv_nsec = 50000};
                nanosleep(&req, NULL);
            }
        }
    }

    {
        uint64_t stop_ns = now_ns();
        double elapsed = (double)(stop_ns - start_ns) / 1000000000.0;
        double pps = elapsed > 0.0 ? (double)sent / elapsed : 0.0;
        double mbps = elapsed > 0.0 ? (((double)sent * (double)frame_len * 8.0) / elapsed) / 1000000.0 : 0.0;

        printf("{\"label\":\"%s\",\"sent\":%" PRIu64 ",\"errors\":%" PRIu64
               ",\"elapsed_sec\":%.6f,\"pps\":%.3f,\"mbps\":%.3f,\"frame_len\":%zu}\n",
               label,
               sent,
               errors,
               elapsed,
               pps,
               mbps,
               frame_len);
    }

    close(fd);
    return fatal_error ? 2 : 0;
}
