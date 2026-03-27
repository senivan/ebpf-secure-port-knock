#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>

#include "cli_common.h"
#include "shared.h"
#include "xdp_loader.h"

static volatile sig_atomic_t g_stop;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --ifname <iface> --hmac-key <64-hex> [options]\n"
            "Options:\n"
            "  --bpf-obj <path>             eBPF object path (default: build/knock_kern.bpf.o)\n"
            "  --knock-port <port>          Knock packet destination port (default: %u)\n"
            "  --protect <p1,p2,...>        Comma-separated protected service ports\n"
            "  --timeout-ms <ms>            Authorization lifetime (default: %u)\n",
            prog,
            KNOCK_DEFAULT_PORT,
            KNOCK_DEFAULT_TIMEOUT_MS);
}

int main(int argc, char **argv)
{
    static struct option long_opts[] = {
        {"ifname", required_argument, NULL, 'i'},
        {"bpf-obj", required_argument, NULL, 'o'},
        {"knock-port", required_argument, NULL, 'k'},
        {"protect", required_argument, NULL, 'p'},
        {"timeout-ms", required_argument, NULL, 't'},
        {"hmac-key", required_argument, NULL, 's'},
        {"duration-sec", required_argument, NULL, 'd'},
        {"pin-dir", required_argument, NULL, 'P'},
        {NULL, 0, NULL, 0},
    };

    const char *ifname = NULL;
    const char *hmac_hex = NULL;
    struct knock_config cfg = {
        .knock_port = KNOCK_DEFAULT_PORT,
        .protected_count = 0,
        .timeout_ms = KNOCK_DEFAULT_TIMEOUT_MS,
    };
    struct knock_loader_opts loader_opts = {
        .ifname = NULL,
        .bpf_obj_path = "build/knock_kern.bpf.o",
        .pin_dir = "/sys/fs/bpf/knock_gate",
        .xdp_flags = XDP_FLAGS_SKB_MODE,
    };
    struct knock_loader_handle loader_handle;
    int duration_sec = 60;

    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:k:p:t:s:d:P:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'o':
            loader_opts.bpf_obj_path = optarg;
            break;
        case 'k': {
            unsigned long v = strtoul(optarg, NULL, 10);
            if (v == 0 || v > 65535UL) {
                fprintf(stderr, "error: invalid --knock-port value\n");
                return 1;
            }
            cfg.knock_port = (__u16)v;
            break;
        }
        case 'p':
            if (parse_ports_csv(optarg, cfg.protected_ports, &cfg.protected_count) != 0) {
                fprintf(stderr, "error: invalid --protect list\n");
                return 1;
            }
            break;
        case 't':
            cfg.timeout_ms = (__u32)strtoul(optarg, NULL, 10);
            if (cfg.timeout_ms == 0) {
                fprintf(stderr, "error: --timeout-ms must be > 0\n");
                return 1;
            }
            break;
        case 's':
            hmac_hex = optarg;
            break;
        case 'd':
            duration_sec = (int)strtol(optarg, NULL, 10);
            if (duration_sec <= 0) {
                fprintf(stderr, "error: --duration-sec must be > 0\n");
                return 1;
            }
            break;
        case 'P':
            loader_opts.pin_dir = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (ifname == NULL || cfg.protected_count == 0 || hmac_hex == NULL) {
        usage(argv[0]);
        return 1;
    }

    if (parse_hmac_key_hex(hmac_hex, cfg.hmac_key) != 0) {
        fprintf(stderr, "error: --hmac-key must be exactly 64 hex characters\n");
        usage(argv[0]);
        return 1;
    }

    loader_opts.ifname = ifname;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (knock_loader_attach(&loader_opts, &cfg, &loader_handle) != 0) {
        return 1;
    }

    printf("Interface: %s\n", ifname);
    printf("Knock port: %u\n", cfg.knock_port);
    printf("Protected ports (%u):", cfg.protected_count);
    for (__u16 i = 0; i < cfg.protected_count; i++) {
        printf(" %u", cfg.protected_ports[i]);
    }
    printf("\n");
    printf("Knock timeout: %u ms\n", cfg.timeout_ms);
    printf("Signed knock mode selected (HMAC key loaded).\n");
    printf("XDP program attached for %d second(s). Press Ctrl+C to stop early.\n", duration_sec);

    {
        time_t end_time = time(NULL) + duration_sec;
        while (!g_stop && time(NULL) < end_time) {
            sleep(1);
        }
    }

    knock_loader_detach(&loader_handle);
    printf("XDP program detached.\n");

    return 0;
}
