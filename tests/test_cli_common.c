#include <fcntl.h>
#include <unistd.h>

#include "cli_common.h"
#include "test_common.h"

static void test_parse_hmac_key_hex_accepts_valid_key(void)
{
    static const char hex[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    __u8 out[KNOCK_HMAC_KEY_LEN] = {0};
    __u8 expected[KNOCK_HMAC_KEY_LEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    ASSERT_EQ_INT(0, parse_hmac_key_hex(hex, out));
    ASSERT_MEM_EQ(expected, out, sizeof(out));
}

static void test_parse_hmac_key_hex_rejects_wrong_length(void)
{
    __u8 out[KNOCK_HMAC_KEY_LEN] = {0};

    ASSERT_EQ_INT(-1, parse_hmac_key_hex("001122", out));
}

static void test_parse_hmac_key_hex_rejects_non_hex(void)
{
    static const char invalid[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeezz";
    __u8 out[KNOCK_HMAC_KEY_LEN] = {0};

    ASSERT_EQ_INT(-1, parse_hmac_key_hex(invalid, out));
}

static void test_parse_ports_csv_accepts_valid_list(void)
{
    __u16 ports[KNOCK_MAX_PROTECTED_PORTS] = {0};
    __u16 count = 0;

    ASSERT_EQ_INT(0, parse_ports_csv("22,443,8080", ports, &count));
    ASSERT_EQ_U16(3, count);
    ASSERT_EQ_U16(22, ports[0]);
    ASSERT_EQ_U16(443, ports[1]);
    ASSERT_EQ_U16(8080, ports[2]);
}

static void test_parse_ports_csv_rejects_empty_list(void)
{
    __u16 ports[KNOCK_MAX_PROTECTED_PORTS] = {0};
    __u16 count = 99;

    ASSERT_EQ_INT(-1, parse_ports_csv("", ports, &count));
}

static void test_parse_ports_csv_rejects_invalid_port(void)
{
    __u16 ports[KNOCK_MAX_PROTECTED_PORTS] = {0};
    __u16 count = 0;

    ASSERT_EQ_INT(-1, parse_ports_csv("22,0,443", ports, &count));
    ASSERT_EQ_INT(-1, parse_ports_csv("22,70000,443", ports, &count));
    ASSERT_EQ_INT(-1, parse_ports_csv("22,abc,443", ports, &count));
}

static void test_parse_ports_csv_rejects_too_many_ports(void)
{
    __u16 ports[KNOCK_MAX_PROTECTED_PORTS] = {0};
    __u16 count = 0;
    char csv[128] = {0};
    size_t offset = 0;
    __u16 i;

    for (i = 0; i < (KNOCK_MAX_PROTECTED_PORTS + 1U); i++) {
        offset += (size_t)snprintf(csv + offset, sizeof(csv) - offset, "%s%u", i == 0 ? "" : ",", 1000U + i);
    }

    ASSERT_EQ_INT(-1, parse_ports_csv(csv, ports, &count));
}

static int write_temp_file(char *path_buf, size_t path_len, const char *content)
{
    int fd;
    ssize_t written;

    snprintf(path_buf, path_len, "/tmp/knock-users-XXXXXX");
    fd = mkstemp(path_buf);
    if (fd < 0) {
        return -1;
    }

    written = write(fd, content, strlen(content));
    close(fd);
    if (written < 0 || (size_t)written != strlen(content)) {
        unlink(path_buf);
        return -1;
    }

    return 0;
}

static void test_load_users_file_accepts_valid_file(void)
{
    static const char file_data[] =
        "# comment\n"
        "100,00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
        "  101,aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n";
    char path[64];
    struct knock_user_record records[4] = {0};
    __u32 count = 0;

    ASSERT_EQ_INT(0, write_temp_file(path, sizeof(path), file_data));
    ASSERT_EQ_INT(0, load_users_file(path, records, 4, &count));
    ASSERT_EQ_U32(2, count);
    ASSERT_EQ_U32(100, records[0].user_id);
    ASSERT_EQ_U32(101, records[1].user_id);
    unlink(path);
}

static void test_load_users_file_rejects_malformed_file(void)
{
    static const char file_data[] = "100 not-a-valid-line\n";
    char path[64];
    struct knock_user_record records[2] = {0};
    __u32 count = 0;

    ASSERT_EQ_INT(0, write_temp_file(path, sizeof(path), file_data));
    ASSERT_EQ_INT(-1, load_users_file(path, records, 2, &count));
    unlink(path);
}

static void test_load_users_file_rejects_invalid_key(void)
{
    static const char file_data[] = "100,nothex\n";
    char path[64];
    struct knock_user_record records[2] = {0};
    __u32 count = 0;

    ASSERT_EQ_INT(0, write_temp_file(path, sizeof(path), file_data));
    ASSERT_EQ_INT(-1, load_users_file(path, records, 2, &count));
    unlink(path);
}

static void test_load_users_file_rejects_when_max_records_exceeded(void)
{
    static const char file_data[] =
        "100,00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
        "101,aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n";
    char path[64];
    struct knock_user_record records[1] = {0};
    __u32 count = 0;

    ASSERT_EQ_INT(0, write_temp_file(path, sizeof(path), file_data));
    ASSERT_EQ_INT(-1, load_users_file(path, records, 1, &count));
    unlink(path);
}

int main(void)
{
    test_parse_hmac_key_hex_accepts_valid_key();
    test_parse_hmac_key_hex_rejects_wrong_length();
    test_parse_hmac_key_hex_rejects_non_hex();
    test_parse_ports_csv_accepts_valid_list();
    test_parse_ports_csv_rejects_empty_list();
    test_parse_ports_csv_rejects_invalid_port();
    test_parse_ports_csv_rejects_too_many_ports();
    test_load_users_file_accepts_valid_file();
    test_load_users_file_rejects_malformed_file();
    test_load_users_file_rejects_invalid_key();
    test_load_users_file_rejects_when_max_records_exceeded();
    puts("test_cli_common: ok");
    return 0;
}
