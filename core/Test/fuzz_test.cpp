#include "fuzz_test.h"

#include <cstring>

void test_demo(uint8_t *buf, size_t len)
{
    uint8_t *cmk = (uint8_t *)malloc(len);

    memcpy(cmk, buf, len);

    CreateKey((ehsm_keyblob_t *)cmk);
}