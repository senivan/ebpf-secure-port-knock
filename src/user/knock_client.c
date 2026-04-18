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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/random.h>
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
            "  --packet-type <auth|deauth|bind>  Control packet type (default: auth)\n"
            "  --user-id <u16>              Numeric user ID (default for auth: 0)\n"
            "  --session-id <u64>           Session id (required for deauth/bind, random for auth)\n"
            "  --bind-port <port>           Protected service port (required for bind)\n"
            "  --nonce <u32>                Explicit nonce (default: random)\n"
            "  --timestamp-sec <u32>        Explicit Unix epoch timestamp (default: CLOCK_REALTIME)\n",
            prog);
}

static int parse_packet_type(const char *s, __u8 *packet_type)
{
    if (strcmp(s, "auth") == 0) {
        *packet_type = KNOCK_PKT_AUTH;
        return 0;
    }
    if (strcmp(s, "deauth") == 0) {
        *packet_type = KNOCK_PKT_DEAUTH;
        return 0;
    }
    if (strcmp(s, "bind") == 0) {
        *packet_type = KNOCK_PKT_BIND;
        return 0;
    }
    return -1;
}

static int random_fill(void *buf, size_t len)
{
    __u8 *p = (__u8 *)buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = getrandom(p + done, len - done, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t)n;
    }

    return 0;
}

static int random_u32(__u32 *out)
{
    return random_fill(out, sizeof(*out));
}

static int random_u64(__u64 *out)
{
    return random_fill(out, sizeof(*out));
}


int main(int argc, char **argv)
{
    static struct option long_opts[] = {
        {"ifname", required_argument, NULL, 'i'},
        {"src-ip", required_argument, NULL, 's'},
        {"dst-ip", required_argument, NULL, 'd'},
        {"dst-port", required_argument, NULL, 'p'},
        {"src-port", required_argument, NULL, 'q'},
        {"packet-type", required_argument, NULL, 'm'},
        {"user-id", required_argument, NULL, 'u'},
        {"session-id", required_argument, NULL, 'x'},
        {"hmac-key", required_argument, NULL, 'k'},
        {"nonce", required_argument, NULL, 'n'},
        {"timestamp-sec", required_argument, NULL, 't'},
        {"bind-port", required_argument, NULL, 'b'},
        {NULL, 0, NULL, 0},
    };

    const char *ifname = NULL;
    const char *src_ip_str = NULL;
    const char *dst_ip_str = NULL;
    const char *hmac_hex = NULL;
    uint16_t src_port = 50000;
    uint16_t dst_port = KNOCK_DEFAULT_PORT;
    uint16_t bind_port = 0;
    __u8 packet_type = KNOCK_PKT_AUTH;
    __u32 user_id = 0;
    __u64 session_id = 0;
    uint32_t nonce = 0;
    uint32_t ts = 0;
    int have_session_id = 0;
    int have_user_id = 0;
    int have_nonce = 0;
    int have_ts = 0;
    __u8 key[KNOCK_HMAC_KEY_LEN] = {0};
    struct knock_sig_input sig_in = {};
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

    while ((opt = getopt_long(argc, argv, "i:s:d:p:q:m:u:x:k:n:t:b:", long_opts, NULL)) != -1) {
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
        case 'm':
            if (parse_packet_type(optarg, &packet_type) != 0) {
                fprintf(stderr, "error: --packet-type must be auth, deauth, or bind\n");
                return 1;
            }
            break;
        case 'u': {
            unsigned long v = strtoul(optarg, NULL, 10);
            if (v > 65535UL) {
                fprintf(stderr, "error: invalid --user-id (must be 0..65535)\n");
                return 1;
            }
            user_id = (__u32)v;
            have_user_id = 1;
            break;
        }
        case 'x': {
            char *end = NULL;
            unsigned long long v = strtoull(optarg, &end, 0);
            if (!end || *end != '\0') {
                fprintf(stderr, "error: invalid --session-id\n");
                return 1;
            }
            session_id = (__u64)v;
            have_session_id = 1;
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
        case 'b': {
            unsigned long v = strtoul(optarg, NULL, 10);
            if (v == 0 || v > 65535UL) {
                fprintf(stderr, "error: invalid --bind-port\n");
                return 1;
            }
            bind_port = (uint16_t)v;
            break;
        }
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
        if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
            fprintf(stderr, "error: clock_gettime(CLOCK_REALTIME) failed: %s\n", strerror(errno));
            return 1;
        }
        ts = (uint32_t)now.tv_sec;
    }
    if (packet_type == KNOCK_PKT_DEAUTH && !have_session_id) {
        fprintf(stderr, "error: --session-id is required for --packet-type deauth\n");
        return 1;
    }
    if (packet_type == KNOCK_PKT_BIND) {
        if (!have_session_id) {
            fprintf(stderr, "error: --session-id is required for --packet-type bind\n");
            return 1;
        }
        if (bind_port == 0) {
            fprintf(stderr, "error: --bind-port is required for --packet-type bind\n");
            return 1;
        }
    }
    if (!have_nonce) {
        if (random_u32(&nonce) != 0) {
            fprintf(stderr, "error: failed to generate random nonce: %s\n", strerror(errno));
            return 1;
        }
    }
    if (!have_session_id) {
        if (random_u64(&session_id) != 0) {
            fprintf(stderr, "error: failed to generate random session id: %s\n", strerror(errno));
            return 1;
        }
        if (packet_type == KNOCK_PKT_AUTH) {
            if (!have_user_id) {
                user_id = 0;
            }
            session_id &= 0x0000ffffffffffffULL;
            session_id |= ((__u64)user_id << 48);
        }
    }

    memset(&kpkt, 0, sizeof(kpkt));
    kpkt.magic = htonl(KNOCK_MAGIC);
    kpkt.timestamp_sec = htonl(ts);
    kpkt.nonce = htonl(nonce);
    kpkt.packet_type = packet_type;
    kpkt.session_id_hi = htonl((__u32)(session_id >> 32));
    kpkt.session_id_lo = htonl((__u32)(session_id & 0xffffffffULL));
    if (packet_type == KNOCK_PKT_BIND) {
        kpkt.bind_src_port = htons(src_port);
        kpkt.bind_dst_port = htons(bind_port);
    }

    {
        struct in_addr src_addr;
        struct in_addr dst_addr;

        if (inet_pton(AF_INET, src_ip_str, &src_addr) != 1 || inet_pton(AF_INET, dst_ip_str, &dst_addr) != 1) {
            fprintf(stderr, "error: invalid source or destination IP\n");
            return 1;
        }

        sig_in.timestamp_sec = ts;
        sig_in.packet_type = packet_type;
        sig_in.session_id_hi = (__u32)(session_id >> 32);
        sig_in.session_id_lo = (__u32)(session_id & 0xffffffffULL);
        sig_in.nonce = nonce;
        if (packet_type == KNOCK_PKT_BIND) {
            sig_in.bind_src_port = src_port;
            sig_in.bind_dst_port = bind_port;
        }
        knock_signature_words(key, &sig_in, sig);

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
        {
            __u32 ipid = 0;
            if (random_u32(&ipid) != 0) {
                fprintf(stderr, "error: failed to generate IPv4 ID: %s\n", strerror(errno));
                return 1;
            }
            iph->id = htons((uint16_t)(ipid & 0xffffU));
        }
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
         printf("type=%s timestamp=%u session_id=%" PRIu64 " nonce=%u sig=%08x:%08x:%08x:%08x\n",
             packet_type == KNOCK_PKT_DEAUTH ? "deauth" :
             (packet_type == KNOCK_PKT_BIND ? "bind" : "auth"),
            ts,
            (uint64_t)session_id,
            nonce,
            sig[0],
            sig[1],
            sig[2],
            sig[3]);
    return 0;
}
