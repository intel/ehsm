#include "../App/ehsm_provider.h"
#include "fuzz.h"
#include "../App/base64.h"

#include <assert.h>
#include <string.h>
#include <signal.h>

// test random plaintext and aad input
void fuzz_one_input(uint8_t *buf)
{
    char temp_plaintext[] = "test_plaintext";
    char temp_aad[] = "test_aad";

    ehsm_data_t *_plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(sizeof(temp_plaintext)));
    _plaintext->datalen = sizeof(temp_plaintext);

    ehsm_data_t *plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(sizeof(temp_plaintext)));
    plaintext->datalen = sizeof(temp_plaintext);
    memcpy_s(plaintext->data, plaintext->datalen, temp_plaintext, sizeof(temp_plaintext));

    ehsm_data_t *aad = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(sizeof(temp_aad)));
    aad->datalen = sizeof(temp_aad);
    memcpy_s(aad->data, aad->datalen, temp_aad, sizeof(temp_aad));

    ehsm_data_t *ciphertext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(256));
    ciphertext->datalen = 256;

    ehsm_status_t ret = Encrypt((ehsm_keyblob_t *)buf, plaintext, aad, ciphertext);
    if (ret == EH_OK)
    {
        Decrypt((ehsm_keyblob_t *)buf, ciphertext, aad, _plaintext);
        assert(memcmp(plaintext, _plaintext, 4) == 0);
    }
    else
        goto out;

out:
    SAFE_FREE(plaintext);
    SAFE_FREE(_plaintext);
    SAFE_FREE(ciphertext);
    SAFE_FREE(aad);
}
