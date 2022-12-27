#include "fuzz.h"

// test random plaintext and aad input
void fuzz_one_input(uint8_t *buf)
{
    // test fuzz cmk
    ehsm_data_t *ciphertext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(1024));
    ciphertext->datalen = 1024;
    ehsm_data_t *plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(1024));
    plaintext->datalen = 1024;

    Encrypt((ehsm_keyblob_t *)buf, (ehsm_data_t *)buf, (ehsm_data_t *)buf, ciphertext);
    Decrypt((ehsm_keyblob_t *)buf, (ehsm_data_t *)buf, (ehsm_data_t *)buf, plaintext);

    SAFE_FREE(ciphertext);
    SAFE_FREE(plaintext);
}
