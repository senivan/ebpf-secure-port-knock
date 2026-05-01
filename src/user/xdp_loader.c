#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_loader.h"

static void raise_memlock_limit(void)
{
    struct rlimit rl = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        fprintf(stderr, "warn: failed to raise RLIMIT_MEMLOCK: %s\n", strerror(errno));
    }
}

static int ensure_dir(const char *path)
{
    struct stat st;

    if (mkdir(path, 0700) == 0) {
        return 0;
    }

    if (errno != EEXIST) {
        return -1;
    }

    if (stat(path, &st) != 0) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    if ((st.st_mode & 0777) != 0700 && chmod(path, 0700) != 0) {
        return -1;
    }

    return 0;
}

static int pin_map_fd(int map_fd, const char *path)
{
    unlink(path);
    return bpf_obj_pin(map_fd, path);
}

int knock_loader_validate_config(const struct knock_config *cfg)
{
    if (!cfg) {
        return -1;
    }

    if (cfg->replay_window_ms < KNOCK_MIN_REPLAY_WINDOW_MS) {
        fprintf(stderr,
                "error: --replay-window-ms must be at least %u ms to match the clock-skew window\n",
                KNOCK_MIN_REPLAY_WINDOW_MS);
        return -1;
    }

    return 0;
}

static void pin_maps_if_possible(struct bpf_object *obj, const char *pin_dir)
{
    int config_fd;
    int pending_fd;
    int active_fd;
    int session_idx_fd;
    int replay_fd;
    int source_pressure_fd;
    int stats_fd;
    int time_offset_fd;
    int snap_fd;
    int user_key_fd;
    char config_pin[256];
    char pending_pin[256];
    char active_pin[256];
    char session_idx_pin[256];
    char replay_pin[256];
    char source_pressure_pin[256];
    char stats_pin[256];
    char time_offset_pin[256];
    char snap_pin[256];
    char user_key_pin[256];

    if (ensure_dir("/sys/fs/bpf") != 0 || ensure_dir(pin_dir) != 0) {
        return;
    }

    config_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    pending_fd = bpf_object__find_map_fd_by_name(obj, "pending_auth_map");
    active_fd = bpf_object__find_map_fd_by_name(obj, "active_session_map");
    session_idx_fd = bpf_object__find_map_fd_by_name(obj, "session_index_map");
    replay_fd = bpf_object__find_map_fd_by_name(obj, "replay_nonce_map");
    source_pressure_fd = bpf_object__find_map_fd_by_name(obj, "source_pressure_map");
    stats_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    time_offset_fd = bpf_object__find_map_fd_by_name(obj, "time_offset_map");
    snap_fd = bpf_object__find_map_fd_by_name(obj, "debug_knock_map");
    user_key_fd = bpf_object__find_map_fd_by_name(obj, "user_key_map");

    snprintf(config_pin, sizeof(config_pin), "%s/config_map", pin_dir);
    snprintf(pending_pin, sizeof(pending_pin), "%s/pending_auth_map", pin_dir);
    snprintf(active_pin, sizeof(active_pin), "%s/active_session_map", pin_dir);
    snprintf(session_idx_pin, sizeof(session_idx_pin), "%s/session_index_map", pin_dir);
    snprintf(replay_pin, sizeof(replay_pin), "%s/replay_nonce_map", pin_dir);
    snprintf(source_pressure_pin, sizeof(source_pressure_pin), "%s/source_pressure_map", pin_dir);
    snprintf(stats_pin, sizeof(stats_pin), "%s/stats_map", pin_dir);
    snprintf(time_offset_pin, sizeof(time_offset_pin), "%s/time_offset_map", pin_dir);
    snprintf(snap_pin, sizeof(snap_pin), "%s/debug_knock_map", pin_dir);
    snprintf(user_key_pin, sizeof(user_key_pin), "%s/user_key_map", pin_dir);

    if (config_fd >= 0 && pin_map_fd(config_fd, config_pin) != 0) {
        fprintf(stderr, "warn: failed to pin config_map at %s: %s\n", config_pin, strerror(errno));
    }
    if (pending_fd >= 0 && pin_map_fd(pending_fd, pending_pin) != 0) {
        fprintf(stderr, "warn: failed to pin pending_auth_map at %s: %s\n", pending_pin, strerror(errno));
    }
    if (active_fd >= 0 && pin_map_fd(active_fd, active_pin) != 0) {
        fprintf(stderr, "warn: failed to pin active_session_map at %s: %s\n", active_pin, strerror(errno));
    }
    if (session_idx_fd >= 0 && pin_map_fd(session_idx_fd, session_idx_pin) != 0) {
        fprintf(stderr, "warn: failed to pin session_index_map at %s: %s\n", session_idx_pin, strerror(errno));
    }
    if (replay_fd >= 0 && pin_map_fd(replay_fd, replay_pin) != 0) {
        fprintf(stderr, "warn: failed to pin replay_nonce_map at %s: %s\n", replay_pin, strerror(errno));
    }
    if (source_pressure_fd >= 0 && pin_map_fd(source_pressure_fd, source_pressure_pin) != 0) {
        fprintf(stderr, "warn: failed to pin source_pressure_map at %s: %s\n", source_pressure_pin, strerror(errno));
    }
    if (stats_fd >= 0 && pin_map_fd(stats_fd, stats_pin) != 0) {
        fprintf(stderr, "warn: failed to pin stats_map at %s: %s\n", stats_pin, strerror(errno));
    }
    if (time_offset_fd >= 0 && pin_map_fd(time_offset_fd, time_offset_pin) != 0) {
        fprintf(stderr, "warn: failed to pin time_offset_map at %s: %s\n", time_offset_pin, strerror(errno));
    }
    if (snap_fd >= 0 && pin_map_fd(snap_fd, snap_pin) != 0) {
        fprintf(stderr, "warn: failed to pin debug_knock_map at %s: %s\n", snap_pin, strerror(errno));
    }
    if (user_key_fd >= 0 && pin_map_fd(user_key_fd, user_key_pin) != 0) {
        fprintf(stderr, "warn: failed to pin user_key_map at %s: %s\n", user_key_pin, strerror(errno));
    }
}


int knock_loader_refresh_time_offset(struct bpf_object *obj)
{
    struct timespec mono_now;
    struct timespec real_now;
    struct time_offset_state time_offset = {};
    __u32 key = 0;
    int map_fd;

    if (!obj) {
        return -1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &mono_now) != 0 ||
        clock_gettime(CLOCK_REALTIME, &real_now) != 0) {
        fprintf(stderr, "error: failed to read system clocks: %s\n", strerror(errno));
        return -1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "time_offset_map");
    if (map_fd < 0) {
        fprintf(stderr, "error: failed to find time_offset_map\n");
        return -1;
    }

    time_offset.realtime_offset_sec = (__s64)real_now.tv_sec - (__s64)mono_now.tv_sec;

    if (bpf_map_update_elem(map_fd, &key, &time_offset, BPF_ANY) != 0) {
        fprintf(stderr, "error: failed to refresh time_offset_map: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int knock_loader_attach(const struct knock_loader_opts *opts,
                        const struct knock_config *cfg,
                        const struct knock_user_record *users,
                        __u32 user_count,
                        struct knock_loader_handle *handle)
{
    struct bpf_program *prog;
    struct timespec mono_now;
    struct timespec real_now;
    struct time_offset_state time_offset = {};
    int map_fd;
    int prog_fd;
    __u32 key = 0;

    memset(handle, 0, sizeof(*handle));

    if (knock_loader_validate_config(cfg) != 0) {
        return -1;
    }

    handle->ifindex = if_nametoindex(opts->ifname);
    if (handle->ifindex == 0) {
        fprintf(stderr, "error: failed to resolve ifname '%s': %s\n", opts->ifname, strerror(errno));
        return -1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    raise_memlock_limit();

    handle->obj = bpf_object__open_file(opts->bpf_obj_path, NULL);
    if (!handle->obj) {
        fprintf(stderr, "error: unable to open BPF object %s\n", opts->bpf_obj_path);
        return -1;
    }
    if (bpf_object__load(handle->obj) != 0) {
        fprintf(stderr, "error: failed to load BPF object %s\n", opts->bpf_obj_path);
        bpf_object__close(handle->obj);
        handle->obj = NULL;
        return -1;
    }

    map_fd = bpf_object__find_map_fd_by_name(handle->obj, "config_map");
    if (map_fd < 0) {
        fprintf(stderr, "error: failed to find config_map\n");
        bpf_object__close(handle->obj);
        handle->obj = NULL;
        return -1;
    }
    if (bpf_map_update_elem(map_fd, &key, cfg, BPF_ANY) != 0) {
        fprintf(stderr, "error: failed to push config into config_map: %s\n", strerror(errno));
        bpf_object__close(handle->obj);
        handle->obj = NULL;
        return -1;
    }

    if (knock_loader_refresh_time_offset(handle->obj) != 0) {
        bpf_object__close(handle->obj);
        handle->obj = NULL;
        return -1;
    }
    
    if (users && user_count > 0) {
        int user_map_fd = bpf_object__find_map_fd_by_name(handle->obj, "user_key_map");
        __u32 i;

        if (user_map_fd < 0) {
            fprintf(stderr, "error: failed to find user_key_map\n");
            bpf_object__close(handle->obj);
            handle->obj = NULL;
            return -1;
        }

        for (i = 0; i < user_count; i++) {
            struct user_key_state state = {};

            memcpy(state.active_key, users[i].hmac_key, KNOCK_HMAC_KEY_LEN);
            state.key_version = 1;
            state.grace_until_ns = 0;

            if (bpf_map_update_elem(user_map_fd, &users[i].user_id, &state, BPF_ANY) != 0) {
                fprintf(stderr, "error: failed to insert user %u into user_key_map: %s\n",
                        users[i].user_id,
                        strerror(errno));
                bpf_object__close(handle->obj);
                handle->obj = NULL;
                return -1;
            }
        }
    }

    prog = bpf_object__find_program_by_name(handle->obj, "port_knock_xdp");
    if (!prog) {
        fprintf(stderr, "error: failed to find program port_knock_xdp\n");
        bpf_object__close(handle->obj);
        handle->obj = NULL;
        return -1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "error: invalid program fd\n");
        bpf_object__close(handle->obj);
        handle->obj = NULL;
        return -1;
    }

    handle->xdp_flags = opts->xdp_flags;
    if (bpf_xdp_attach(handle->ifindex, prog_fd, handle->xdp_flags, NULL) != 0) {
        fprintf(stderr, "error: failed to attach XDP to %s (ifindex=%d): %s\n",
                opts->ifname, handle->ifindex, strerror(errno));
        bpf_object__close(handle->obj);
        handle->obj = NULL;
        return -1;
    }

    pin_maps_if_possible(handle->obj, opts->pin_dir);
    return 0;
}

void knock_loader_detach(struct knock_loader_handle *handle)
{
    if (!handle) {
        return;
    }

    if (handle->ifindex > 0) {
        if (bpf_xdp_detach(handle->ifindex, handle->xdp_flags, NULL) != 0) {
            fprintf(stderr, "warn: failed to detach XDP ifindex=%d: %s\n",
                    handle->ifindex, strerror(errno));
        }
    }

    if (handle->obj) {
        bpf_object__close(handle->obj);
        handle->obj = NULL;
    }
}
