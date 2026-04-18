#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT_TRUE(cond)                                                            \
    do {                                                                             \
        if (!(cond)) {                                                               \
            fprintf(stderr, "assertion failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

#define ASSERT_EQ_INT(expected, actual)                                              \
    do {                                                                             \
        int test_expected__ = (expected);                                            \
        int test_actual__ = (actual);                                                \
        if (test_expected__ != test_actual__) {                                      \
            fprintf(stderr,                                                          \
                    "assertion failed: expected %d got %d (%s:%d)\n",               \
                    test_expected__,                                                  \
                    test_actual__,                                                    \
                    __FILE__,                                                         \
                    __LINE__);                                                        \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

#define ASSERT_EQ_U16(expected, actual)                                              \
    do {                                                                             \
        unsigned int test_expected__ = (expected);                                   \
        unsigned int test_actual__ = (actual);                                       \
        if (test_expected__ != test_actual__) {                                      \
            fprintf(stderr,                                                          \
                    "assertion failed: expected %u got %u (%s:%d)\n",               \
                    test_expected__,                                                  \
                    test_actual__,                                                    \
                    __FILE__,                                                         \
                    __LINE__);                                                        \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

#define ASSERT_EQ_U32(expected, actual)                                              \
    do {                                                                             \
        unsigned int test_expected__ = (expected);                                   \
        unsigned int test_actual__ = (actual);                                       \
        if (test_expected__ != test_actual__) {                                      \
            fprintf(stderr,                                                          \
                    "assertion failed: expected %u got %u (%s:%d)\n",               \
                    test_expected__,                                                  \
                    test_actual__,                                                    \
                    __FILE__,                                                         \
                    __LINE__);                                                        \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

#define ASSERT_MEM_EQ(expected, actual, len)                                         \
    do {                                                                             \
        if (memcmp((expected), (actual), (len)) != 0) {                              \
            fprintf(stderr, "assertion failed: memory differs (%s:%d)\n", __FILE__, __LINE__); \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

#endif
