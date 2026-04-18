#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_common.h"

int parse_hmac_key_hex(const char *hex, __u8 out[KNOCK_HMAC_KEY_LEN])
{
    size_t i;

    if (strlen(hex) != (KNOCK_HMAC_KEY_LEN * 2U)) {
        return -1;
    }

    for (i = 0; i < KNOCK_HMAC_KEY_LEN; i++) {
        char byte_hex[3] = {hex[i * 2U], hex[i * 2U + 1U], '\0'};
        char *end = NULL;
        unsigned long v = strtoul(byte_hex, &end, 16);
        if (!end || *end != '\0' || v > 0xffUL) {
            return -1;
        }
        out[i] = (__u8)v;
    }

    return 0;
}

int parse_ports_csv(const char *csv, __u16 *ports, __u16 *count)
{
    char *buf = strdup(csv);
    char *tok;
    char *save = NULL;
    __u16 n = 0;

    if (!buf) {
        return -1;
    }

    for (tok = strtok_r(buf, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        unsigned long v;
        char *end = NULL;

        if (n >= KNOCK_MAX_PROTECTED_PORTS) {
            free(buf);
            return -1;
        }

        errno = 0;
        v = strtoul(tok, &end, 10);
        if (errno != 0 || !end || *end != '\0' || v == 0 || v > 65535UL) {
            free(buf);
            return -1;
        }

        ports[n++] = (__u16)v;
    }

    free(buf);
    *count = n;
    return n == 0 ? -1 : 0;
}

int load_users_file(const char *path,
                    struct knock_user_record *records,
                    __u32 max_records,
                    __u32 *out_count)
{
    FILE *fp;
    char line[256];
    __u32 n = 0;

    if (!path || !records || !out_count || max_records == 0) {
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *comma;
        char *id_str;
        char *key_str;
        char *end;
        unsigned long user_id;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0' || *p == '\n' || *p == '#') {
            continue;
        }

        comma = strchr(p, ',');
        if (!comma) {
            fclose(fp);
            return -1;
        }
        *comma = '\0';
        id_str = p;
        key_str = comma + 1;

        end = strchr(key_str, '\n');
        if (end) {
            *end = '\0';
        }

        while (*key_str == ' ' || *key_str == '\t') {
            key_str++;
        }

        errno = 0;
        user_id = strtoul(id_str, &end, 10);
        if (errno != 0 || !end || *end != '\0' || user_id > 65535UL) {
            fclose(fp);
            return -1;
        }

        if (n >= max_records || parse_hmac_key_hex(key_str, records[n].hmac_key) != 0) {
            fclose(fp);
            return -1;
        }

        records[n].user_id = (__u32)user_id;
        n++;
    }

    fclose(fp);
    *out_count = n;
    return n == 0 ? -1 : 0;
}
