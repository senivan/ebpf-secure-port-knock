#include <errno.h>
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
