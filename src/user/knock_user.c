#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
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
            "Usage:\n"
            "  %s daemon --ifname <iface> [--users-file <path> | --hmac-key <64-hex>] [options]\n"
            "  %s register-user --user-id <id> --hmac-key <64-hex> [--pin-dir <path>]\n"
            "  %s rotate-user-key --user-id <id> --hmac-key <64-hex> [--grace-ms <ms>] [--pin-dir <path>]\n"
            "  %s revoke-user --user-id <id> [--pin-dir <path>]\n"
            "  %s list-users [--pin-dir <path>]\n"
            "Options:\n"
            "  --bpf-obj <path>             eBPF object path (default: build/knock_kern.bpf.o)\n"
            "  --knock-port <port>          Knock packet destination port (default: %u)\n"
            "  --protect <p1,p2,...>        Comma-separated protected service ports\n"
            "  --timeout-ms <ms>            Session lifetime after bind (default: %u)\n"
            "  --bind-window-ms <ms>        Time to bind first protected flow (default: %u)\n"
            "  --replay-window-ms <ms>      Replay reject window for control packets (default: %u)\n",
            prog,
            prog,
            prog,
            prog,
            prog,
            KNOCK_DEFAULT_PORT,
            KNOCK_DEFAULT_TIMEOUT_MS,
            KNOCK_DEFAULT_BIND_WINDOW_MS,
            KNOCK_DEFAULT_REPLAY_WINDOW_MS);
}

static int open_user_map(const char *pin_dir)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/user_key_map", pin_dir);
    return bpf_obj_get(path);
}

static int parse_user_id_arg(const char *s, __u32 *out)
{
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);

    if (!end || *end != '\0' || v > 65535UL) {
        return -1;
    }
    *out = (__u32)v;
    return 0;
}

static int cmd_register_or_rotate(int argc, char **argv, int rotate)
{
    static struct option opts[] = {
        {"user-id", required_argument, NULL, 'u'},
        {"hmac-key", required_argument, NULL, 'k'},
        {"grace-ms", required_argument, NULL, 'g'},
        {"pin-dir", required_argument, NULL, 'P'},
        {NULL, 0, NULL, 0},
    };
    const char *hex = NULL;
    const char *pin_dir = "/sys/fs/bpf/knock_gate";
    __u32 user_id = 0;
    __u32 grace_ms = 0;
    __u8 key[KNOCK_HMAC_KEY_LEN];
    struct user_key_state state = {};
    int have_user_id = 0;
    int map_fd;
    int opt;

    optind = 1;
    while ((opt = getopt_long(argc, argv, "u:k:g:P:", opts, NULL)) != -1) {
        switch (opt) {
        case 'u':
            if (parse_user_id_arg(optarg, &user_id) != 0) {
                fprintf(stderr, "error: invalid --user-id\n");
                return 1;
            }
            have_user_id = 1;
            break;
        case 'k':
            hex = optarg;
            break;
        case 'g':
            grace_ms = (__u32)strtoul(optarg, NULL, 10);
            break;
        case 'P':
            pin_dir = optarg;
            break;
        default:
            return 1;
        }
    }

    if (!have_user_id || !hex || parse_hmac_key_hex(hex, key) != 0) {
        fprintf(stderr, "error: --user-id and --hmac-key are required\n");
        return 1;
    }

    map_fd = open_user_map(pin_dir);
    if (map_fd < 0) {
        fprintf(stderr, "error: failed to open user_key_map in %s: %s\n", pin_dir, strerror(errno));
        return 1;
    }

    if (rotate) {
        struct timespec now;

        if (bpf_map_lookup_elem(map_fd, &user_id, &state) != 0) {
            fprintf(stderr, "error: user %u not found\n", user_id);
            close(map_fd);
            return 1;
        }
        memcpy(state.previous_key, state.active_key, KNOCK_HMAC_KEY_LEN);
        memcpy(state.active_key, key, KNOCK_HMAC_KEY_LEN);
        state.key_version += 1;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            fprintf(stderr, "error: clock_gettime(CLOCK_MONOTONIC) failed\n");
            close(map_fd);
            return 1;
        }
        state.grace_until_ns = (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec + ((__u64)grace_ms * 1000000ULL);
    } else {
        if (bpf_map_lookup_elem(map_fd, &user_id, &state) == 0) {
            fprintf(stderr, "error: user %u already exists\n", user_id);
            close(map_fd);
            return 1;
        }
        memcpy(state.active_key, key, KNOCK_HMAC_KEY_LEN);
        state.key_version = 1;
        state.grace_until_ns = 0;
    }

    if (bpf_map_update_elem(map_fd, &user_id, &state, BPF_ANY) != 0) {
        fprintf(stderr, "error: failed to update user %u: %s\n", user_id, strerror(errno));
        close(map_fd);
        return 1;
    }

    close(map_fd);
    printf("ok: user %u %s\n", user_id, rotate ? "rotated" : "registered");
    return 0;
}

static int cmd_revoke_user(int argc, char **argv)
{
    static struct option opts[] = {
        {"user-id", required_argument, NULL, 'u'},
        {"pin-dir", required_argument, NULL, 'P'},
        {NULL, 0, NULL, 0},
    };
    const char *pin_dir = "/sys/fs/bpf/knock_gate";
    __u32 user_id = 0;
    int have_user_id = 0;
    int map_fd;
    int opt;

    optind = 1;
    while ((opt = getopt_long(argc, argv, "u:P:", opts, NULL)) != -1) {
        switch (opt) {
        case 'u':
            if (parse_user_id_arg(optarg, &user_id) != 0) {
                fprintf(stderr, "error: invalid --user-id\n");
                return 1;
            }
            have_user_id = 1;
            break;
        case 'P':
            pin_dir = optarg;
            break;
        default:
            return 1;
        }
    }

    if (!have_user_id) {
        fprintf(stderr, "error: --user-id is required\n");
        return 1;
    }

    map_fd = open_user_map(pin_dir);
    if (map_fd < 0) {
        fprintf(stderr, "error: failed to open user_key_map in %s: %s\n", pin_dir, strerror(errno));
        return 1;
    }

    if (bpf_map_delete_elem(map_fd, &user_id) != 0) {
        fprintf(stderr, "error: failed to revoke user %u: %s\n", user_id, strerror(errno));
        close(map_fd);
        return 1;
    }

    close(map_fd);
    printf("ok: user %u revoked\n", user_id);
    return 0;
}

static int cmd_list_users(int argc, char **argv)
{
    static struct option opts[] = {
        {"pin-dir", required_argument, NULL, 'P'},
        {NULL, 0, NULL, 0},
    };
    const char *pin_dir = "/sys/fs/bpf/knock_gate";
    struct user_key_state state;
    __u32 key;
    __u32 next_key;
    int map_fd;
    int opt;

    optind = 1;
    while ((opt = getopt_long(argc, argv, "P:", opts, NULL)) != -1) {
        if (opt == 'P') {
            pin_dir = optarg;
        } else {
            return 1;
        }
    }

    map_fd = open_user_map(pin_dir);
    if (map_fd < 0) {
        fprintf(stderr, "error: failed to open user_key_map in %s: %s\n", pin_dir, strerror(errno));
        return 1;
    }

    printf("user_id,key_version,grace_until_ns\n");
    if (bpf_map_get_next_key(map_fd, NULL, &next_key) != 0) {
        close(map_fd);
        return 0;
    }

    while (1) {
        key = next_key;
        if (bpf_map_lookup_elem(map_fd, &key, &state) == 0) {
            printf("%u,%u,%llu\n", key, state.key_version, (unsigned long long)state.grace_until_ns);
        }
        if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
            break;
        }
    }

    close(map_fd);
    return 0;
}

static int cmd_daemon(int argc, char **argv)
{
    static struct option long_opts[] = {
        {"ifname", required_argument, NULL, 'i'},
        {"bpf-obj", required_argument, NULL, 'o'},
        {"knock-port", required_argument, NULL, 'k'},
        {"protect", required_argument, NULL, 'p'},
        {"timeout-ms", required_argument, NULL, 't'},
        {"bind-window-ms", required_argument, NULL, 'w'},
        {"replay-window-ms", required_argument, NULL, 'r'},
        {"hmac-key", required_argument, NULL, 's'},
        {"users-file", required_argument, NULL, 'f'},
        {"duration-sec", required_argument, NULL, 'd'},
        {"pin-dir", required_argument, NULL, 'P'},
        {NULL, 0, NULL, 0},
    };

    const char *ifname = NULL;
    const char *hmac_hex = NULL;
    const char *users_file = NULL;
    struct knock_user_record users[KNOCK_MAX_USERS] = {};
    __u32 user_count = 0;
    struct knock_config cfg = {
        .knock_port = KNOCK_DEFAULT_PORT,
        .protected_count = 0,
        .timeout_ms = KNOCK_DEFAULT_TIMEOUT_MS,
        .bind_window_ms = KNOCK_DEFAULT_BIND_WINDOW_MS,
        .replay_window_ms = KNOCK_DEFAULT_REPLAY_WINDOW_MS,
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

    optind = 1;
    while ((opt = getopt_long(argc, argv, "i:o:k:p:t:w:r:s:f:d:P:", long_opts, NULL)) != -1) {
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
        case 'w':
            cfg.bind_window_ms = (__u32)strtoul(optarg, NULL, 10);
            if (cfg.bind_window_ms == 0) {
                fprintf(stderr, "error: --bind-window-ms must be > 0\n");
                return 1;
            }
            break;
        case 'r':
            cfg.replay_window_ms = (__u32)strtoul(optarg, NULL, 10);
            if (cfg.replay_window_ms == 0) {
                fprintf(stderr, "error: --replay-window-ms must be > 0\n");
                return 1;
            }
            break;
        case 's':
            hmac_hex = optarg;
            break;
        case 'f':
            users_file = optarg;
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

    if (ifname == NULL || cfg.protected_count == 0) {
        usage(argv[0]);
        return 1;
    }

    if (hmac_hex != NULL && parse_hmac_key_hex(hmac_hex, cfg.hmac_key) != 0) {
        fprintf(stderr, "error: --hmac-key must be exactly 64 hex characters\n");
        usage(argv[0]);
        return 1;
    }

    if (users_file != NULL) {
        if (load_users_file(users_file, users, KNOCK_MAX_USERS, &user_count) != 0) {
            fprintf(stderr, "error: failed to load --users-file (expected lines: user_id,64hex_key)\n");
            return 1;
        }
    } else if (hmac_hex != NULL) {
        users[0].user_id = 0;
        memcpy(users[0].hmac_key, cfg.hmac_key, KNOCK_HMAC_KEY_LEN);
        user_count = 1;
        fprintf(stderr, "warn: no --users-file provided, using a single fallback user_id=0 from --hmac-key\n");
    } else {
        fprintf(stderr, "error: provide --users-file or --hmac-key\n");
        return 1;
    }

    loader_opts.ifname = ifname;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (knock_loader_attach(&loader_opts, &cfg, users, user_count, &loader_handle) != 0) {
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
    printf("Bind window: %u ms\n", cfg.bind_window_ms);
    printf("Replay window: %u ms\n", cfg.replay_window_ms);
    printf("Loaded users: %u\n", user_count);
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

int main(int argc, char **argv)
{
    if (argc > 1 && argv[1][0] != '-') {
        if (strcmp(argv[1], "daemon") == 0) {
            return cmd_daemon(argc - 1, argv + 1);
        }
        if (strcmp(argv[1], "register-user") == 0) {
            return cmd_register_or_rotate(argc - 1, argv + 1, 0);
        }
        if (strcmp(argv[1], "rotate-user-key") == 0) {
            return cmd_register_or_rotate(argc - 1, argv + 1, 1);
        }
        if (strcmp(argv[1], "revoke-user") == 0) {
            return cmd_revoke_user(argc - 1, argv + 1);
        }
        if (strcmp(argv[1], "list-users") == 0) {
            return cmd_list_users(argc - 1, argv + 1);
        }
        usage(argv[0]);
        return 1;
    }

    return cmd_daemon(argc, argv);
}
