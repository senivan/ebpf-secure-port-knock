#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_loader.h"

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0755) == 0 || errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int pin_map_fd(int map_fd, const char *path)
{
    unlink(path);
    return bpf_obj_pin(map_fd, path);
}

static void pin_maps_if_possible(struct bpf_object *obj, const char *pin_dir)
{
    int config_fd;
    int auth_fd;
    int replay_fd;
    int stats_fd;
    int snap_fd;
    char config_pin[256];
    char auth_pin[256];
    char replay_pin[256];
    char stats_pin[256];
    char snap_pin[256];

    if (ensure_dir("/sys/fs/bpf") != 0 || ensure_dir(pin_dir) != 0) {
        return;
    }

    config_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    auth_fd = bpf_object__find_map_fd_by_name(obj, "auth_map");
    replay_fd = bpf_object__find_map_fd_by_name(obj, "replay_nonce_map");
    stats_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    snap_fd = bpf_object__find_map_fd_by_name(obj, "debug_knock_map");

    snprintf(config_pin, sizeof(config_pin), "%s/config_map", pin_dir);
    snprintf(auth_pin, sizeof(auth_pin), "%s/auth_map", pin_dir);
    snprintf(replay_pin, sizeof(replay_pin), "%s/replay_nonce_map", pin_dir);
    snprintf(stats_pin, sizeof(stats_pin), "%s/stats_map", pin_dir);
    snprintf(snap_pin, sizeof(snap_pin), "%s/debug_knock_map", pin_dir);

    if (config_fd >= 0 && pin_map_fd(config_fd, config_pin) != 0) {
        fprintf(stderr, "warn: failed to pin config_map at %s: %s\n", config_pin, strerror(errno));
    }
    if (auth_fd >= 0 && pin_map_fd(auth_fd, auth_pin) != 0) {
        fprintf(stderr, "warn: failed to pin auth_map at %s: %s\n", auth_pin, strerror(errno));
    }
    if (replay_fd >= 0 && pin_map_fd(replay_fd, replay_pin) != 0) {
        fprintf(stderr, "warn: failed to pin replay_nonce_map at %s: %s\n", replay_pin, strerror(errno));
    }
    if (stats_fd >= 0 && pin_map_fd(stats_fd, stats_pin) != 0) {
        fprintf(stderr, "warn: failed to pin stats_map at %s: %s\n", stats_pin, strerror(errno));
    }
    if (snap_fd >= 0 && pin_map_fd(snap_fd, snap_pin) != 0) {
        fprintf(stderr, "warn: failed to pin debug_knock_map at %s: %s\n", snap_pin, strerror(errno));
    }
}

int knock_loader_attach(const struct knock_loader_opts *opts,
                        const struct knock_config *cfg,
                        struct knock_loader_handle *handle)
{
    struct bpf_program *prog;
    int map_fd;
    int prog_fd;
    __u32 key = 0;

    memset(handle, 0, sizeof(*handle));

    handle->ifindex = if_nametoindex(opts->ifname);
    if (handle->ifindex == 0) {
        fprintf(stderr, "error: failed to resolve ifname '%s': %s\n", opts->ifname, strerror(errno));
        return -1;
    }

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
