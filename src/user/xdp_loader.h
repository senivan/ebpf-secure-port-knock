#ifndef XDP_LOADER_H
#define XDP_LOADER_H

#include <linux/if_link.h>
#include <bpf/libbpf.h>

#include "shared.h"

struct knock_loader_opts {
    const char *ifname;
    const char *bpf_obj_path;
    const char *pin_dir;
    int xdp_flags;
};

struct knock_loader_handle {
    int ifindex;
    int xdp_flags;
    struct bpf_object *obj;
};

int knock_loader_attach(const struct knock_loader_opts *opts,
                        const struct knock_config *cfg,
                        const struct knock_user_record *users,
                        __u32 user_count,
                        struct knock_loader_handle *handle);

int knock_loader_validate_config(const struct knock_config *cfg);

int knock_loader_refresh_time_offset(struct bpf_object *obj);

void knock_loader_detach(struct knock_loader_handle *handle);

#endif /* XDP_LOADER_H */
