#ifndef CLI_COMMON_H
#define CLI_COMMON_H

#include "shared.h"

int parse_hmac_key_hex(const char *hex, __u8 out[KNOCK_HMAC_KEY_LEN]);
int parse_ports_csv(const char *csv, __u16 *ports, __u16 *count);
int load_users_file(const char *path,
					struct knock_user_record *records,
					__u32 max_records,
					__u32 *out_count);

#endif /* CLI_COMMON_H */
