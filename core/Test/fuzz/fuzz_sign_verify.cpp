#include "fuzz.h"

// test random plaintext and aad input
void fuzz_one_input(uint8_t *buf)
{
    // test fuzz cmk
    ehsm_data_t *signature = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(1024));
    signature->datalen = 1024;
    bool *result;

    Sign((ehsm_keyblob_t *)buf, (ehsm_data_t *)buf, signature);
    Verify((ehsm_keyblob_t *)buf, (ehsm_data_t *)buf, (ehsm_data_t *)buf, result);

    SAFE_FREE(signature);
}
