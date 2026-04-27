#include <errno.h>
#include <getopt.h>
#include <string.h>

#include "shared.h"
#include "test_common.h"
#include "xdp_loader.h"

#define main knock_user_entry
#include "../src/user/knock_user.c"
#undef main

static int stub_validate_config_rc = 0;
static int stub_attach_rc = -1;
static int stub_attach_called = 0;
static __u32 stub_attach_user_count = 0;
static struct knock_user_record stub_attach_users[KNOCK_MAX_USERS];

int bpf_obj_get(const char *path)
{
    (void)path;
    errno = ENOENT;
    return -1;
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    (void)fd;
    (void)key;
    (void)value;
    errno = ENOENT;
    return -1;
}

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
    (void)fd;
    (void)key;
    (void)value;
    (void)flags;
    errno = EPERM;
    return -1;
}

int bpf_map_delete_elem(int fd, const void *key)
{
    (void)fd;
    (void)key;
    errno = ENOENT;
    return -1;
}

int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    (void)fd;
    (void)key;
    (void)next_key;
    errno = ENOENT;
    return -1;
}

int knock_loader_validate_config(const struct knock_config *cfg)
{
    (void)cfg;
    return stub_validate_config_rc;
}

int knock_loader_attach(const struct knock_loader_opts *opts,
                        const struct knock_config *cfg,
                        const struct knock_user_record *users,
                        __u32 user_count,
                        struct knock_loader_handle *handle)
{
    (void)opts;
    (void)cfg;
    (void)handle;

    stub_attach_called = 1;
    stub_attach_user_count = user_count;
    if (users && user_count > 0) {
        memcpy(stub_attach_users, users, sizeof(struct knock_user_record) * user_count);
    }

    return stub_attach_rc;
}

void knock_loader_detach(struct knock_loader_handle *handle)
{
    (void)handle;
}

static void reset_test_state(void)
{
    optind = 1;
    opterr = 0;
    stub_validate_config_rc = 0;
    stub_attach_rc = -1;
    stub_attach_called = 0;
    stub_attach_user_count = 0;
    memset(stub_attach_users, 0, sizeof(stub_attach_users));
}

static int run_knock_user(int argc, char **argv)
{
    reset_test_state();
    return knock_user_entry(argc, argv);
}

static void test_unknown_subcommand_returns_error(void)
{
    char *argv[] = {(char *)"knockd", (char *)"unknown", NULL};

    ASSERT_EQ_INT(1, run_knock_user(2, argv));
}

static void test_daemon_requires_ifname_and_protect(void)
{
    char *argv[] = {(char *)"knockd", (char *)"daemon", NULL};

    ASSERT_EQ_INT(1, run_knock_user(2, argv));
}

static void test_daemon_rejects_invalid_knock_port(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knockd", (char *)"daemon", (char *)"--ifname", (char *)"lo", (char *)"--protect",
                    (char *)"22", (char *)"--hmac-key", (char *)key, (char *)"--knock-port", (char *)"0", NULL};

    ASSERT_EQ_INT(1, run_knock_user(10, argv));
}

static void test_daemon_rejects_negative_duration(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knockd", (char *)"daemon", (char *)"--ifname", (char *)"lo", (char *)"--protect",
                    (char *)"22", (char *)"--hmac-key", (char *)key, (char *)"--duration-sec", (char *)"-1", NULL};

    ASSERT_EQ_INT(1, run_knock_user(10, argv));
}

static void test_daemon_rejects_invalid_hmac_key(void)
{
    char *argv[] = {(char *)"knockd", (char *)"daemon", (char *)"--ifname", (char *)"lo", (char *)"--protect",
                    (char *)"22", (char *)"--hmac-key", (char *)"1234", NULL};

    ASSERT_EQ_INT(1, run_knock_user(8, argv));
}

static void test_daemon_requires_users_file_or_hmac_key(void)
{
    char *argv[] = {(char *)"knockd", (char *)"daemon", (char *)"--ifname", (char *)"lo", (char *)"--protect",
                    (char *)"22", NULL};

    ASSERT_EQ_INT(1, run_knock_user(6, argv));
}

static void test_daemon_returns_loader_validate_failure(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knockd", (char *)"daemon", (char *)"--ifname", (char *)"lo", (char *)"--protect",
                    (char *)"22", (char *)"--hmac-key", (char *)key, NULL};

    reset_test_state();
    stub_validate_config_rc = -1;
    ASSERT_EQ_INT(1, knock_user_entry(8, argv));
}

static void test_daemon_uses_fallback_user_when_hmac_is_provided(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knockd", (char *)"daemon", (char *)"--ifname", (char *)"lo", (char *)"--protect",
                    (char *)"22,443", (char *)"--hmac-key", (char *)key, NULL};

    reset_test_state();
    stub_attach_rc = -1;
    ASSERT_EQ_INT(1, knock_user_entry(8, argv));
    ASSERT_TRUE(stub_attach_called == 1);
    ASSERT_EQ_U32(1, stub_attach_user_count);
    ASSERT_EQ_U32(0, stub_attach_users[0].user_id);
}

static void test_register_user_requires_fields(void)
{
    char *argv[] = {(char *)"knockd", (char *)"register-user", NULL};

    ASSERT_EQ_INT(1, run_knock_user(2, argv));
}

static void test_register_user_with_missing_map_returns_error(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knockd", (char *)"register-user", (char *)"--user-id", (char *)"42", (char *)"--hmac-key",
                    (char *)key, NULL};

    ASSERT_EQ_INT(1, run_knock_user(6, argv));
}

static void test_rotate_user_rejects_invalid_user_id(void)
{
    static const char key[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char *argv[] = {(char *)"knockd", (char *)"rotate-user-key", (char *)"--user-id", (char *)"70000", (char *)"--hmac-key",
                    (char *)key, NULL};

    ASSERT_EQ_INT(1, run_knock_user(6, argv));
}

static void test_revoke_user_requires_user_id(void)
{
    char *argv[] = {(char *)"knockd", (char *)"revoke-user", NULL};

    ASSERT_EQ_INT(1, run_knock_user(2, argv));
}

static void test_list_users_with_missing_map_returns_error(void)
{
    char *argv[] = {(char *)"knockd", (char *)"list-users", NULL};

    ASSERT_EQ_INT(1, run_knock_user(2, argv));
}

int main(void)
{
    test_unknown_subcommand_returns_error();
    test_daemon_requires_ifname_and_protect();
    test_daemon_rejects_invalid_knock_port();
    test_daemon_rejects_negative_duration();
    test_daemon_rejects_invalid_hmac_key();
    test_daemon_requires_users_file_or_hmac_key();
    test_daemon_returns_loader_validate_failure();
    test_daemon_uses_fallback_user_when_hmac_is_provided();
    test_register_user_requires_fields();
    test_register_user_with_missing_map_returns_error();
    test_rotate_user_rejects_invalid_user_id();
    test_revoke_user_requires_user_id();
    test_list_users_with_missing_map_returns_error();
    puts("test_knock_user: ok");
    return 0;
}
