#include "enclave_self_test.h"
#include <string.h>
#include <vector>
#include <map>
#include "datatypes.h"

using namespace std;

#define GET_PARAMETER(x) \
    uint8_t *x = (uint8_t *)get_parameter(#x, test_vector);

#define CHECK_EQUAL(x)                              \
    if (VECTOR_LENGTH(#x) > 0)                      \
        for (int i = 0; i < VECTOR_LENGTH(#x); i++) \
            if (x[i] != _##x[i])                    \
                return false;

EHSM_TEST_VECTOR aes_gcm_test_vectors = {
    {// case1
     {"key", "5e7709524474167905eab6cda9fe0a2c"},
     {"plaintext", "5aa34a0b76e656d50e7e0105bf"},
     {"aad", "072bf43f13d3eed3b79cdc991a702ebdc896b69f86c9543831a36a18f6562ef309a45a2b8798b51aa7f8c84af80f01cf"},
     {"iv", "f5"},
     {"ciphertext", "1e8429efd2dbae20ac0e5bce2e"},
     {"tag", "66f21323825af553ba8681d347883199"}},
    {// case2
     {"key", "58ce5714f6da3eb3ad6b46d36083b699"},
     {"plaintext", "e2f8cf5f794e749caa3aa5ccea"},
     {"aad", "6073bea7e46861b8a5010a6658fc0793"},
     {"iv", "84060061bc5ce669fadb7339f785f45eedbad18e4047989fd63ba078b3a7ebd9d81a896c0b48e208ca79e123c7e2e3c93411c96af97ff9fa485624cbf1f3657a40ab96078e12b95b49d71b79e8d9e2efaf93f288b3ae2d263b270ca06574cf4a5ce4abcc357667a8d5f000139bb74cabfcb7e3e9a991074a2e5ce7863771ed36"},
     {"ciphertext", "4f68dfc5de9fd949093c350a6e"},
     {"tag", "b5a33d33c56ba35ebd5f9e18206743c4"}},
    {// case3
     {"key", "2d265491712fe6d7087a5545852f4f44"},
     {"plaintext", "301873be69f05a84f22408aa0862d19a"},
     {"aad", "67105634ac9fbf849970dc416de7ad30"},
     {"iv", "c59868b8701fbf88e6343262"},
     {"ciphertext", "98b03c77a67831bcf16b1dd96c324e1c"},
     {"tag", "39152e26bdc4d17e8c00493fa0be92f2"}},
    {// case4
     {"key", "1fd1e536a1c39c75fd583bc8e3372029"},
     {"plaintext", "f801e0839619d2c1465f0245869360da"},
     {"aad", "bf12a140d86727f67b860bcf6f34e55f"},
     {"iv", "281f2552f8c34fb9b3ec85aa"},
     {"ciphertext", "35371f2779f4140dfdb1afe79d563ed9"},
     {"tag", "cc2b0b0f1f8b3db5dc1b41ce73f5c221"}}};

/**
 * @brief make string to hex array, string length needs to be a even number
 *
 * @param str "a0b23d" will change to "/xa0/xb2/x3d"
 * @param buf buffer for saving the result
 * @param len str length / 2
 */
void Str2Hex(const char *pbSrc, unsigned char *pbDest, int nLen)
{
    char h1, h2;
    char s1, s2;
    int i;

    for (i = 0; i < nLen; i++)
    {
        h1 = pbSrc[2 * i];
        h2 = pbSrc[2 * i + 1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9)
            s1 -= 7;
        s2 = toupper(h2) - 0x30;
        if (s2 > 9)
            s2 -= 7;

        pbDest[i] = s1 * 16 + s2;
    }
}

void *get_parameter(string key_name, map<string, string> test_vector)
{
    string target = test_vector[key_name];
    int len = strlen(target.c_str()) / 2;
    uint8_t *value = (uint8_t *)malloc(len);
    Str2Hex(target.c_str(), value, len);
    return value;
}

bool aes_gcm_encrypt(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("aad"));
    uint8_t *_tag = (uint8_t *)malloc(VECTOR_LENGTH("tag"));
    (void)aes_gcm_encrypt(key, _ciphertext, EVP_aes_128_gcm(), plaintext, VECTOR_LENGTH("plaintext"),
                          aad, VECTOR_LENGTH("aad"), iv, VECTOR_LENGTH("iv"), _tag, VECTOR_LENGTH("tag"));

    CHECK_EQUAL(ciphertext);
    CHECK_EQUAL(tag);

    return true;
}

bool aes_gcm_decrypt(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)aes_gcm_decrypt(key, _plaintext, EVP_aes_128_gcm(), ciphertext, VECTOR_LENGTH("ciphertext"),
                          aad, VECTOR_LENGTH("aad"), iv, VECTOR_LENGTH("iv"), tag, VECTOR_LENGTH("tag"));

    CHECK_EQUAL(plaintext);

    return true;
}

sgx_status_t aes_gcm_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 0;
    for (auto test_vector : aes_gcm_test_vectors)
    {
        if (!aes_gcm_encrypt(test_vector))
        {
            printf("fail at %d\n", index);
            return SGX_ERROR_INVALID_FUNCTION;
        }
        index++;
        if (!aes_gcm_decrypt(test_vector))
        {
            printf("fail at %d\n", index);
            return SGX_ERROR_INVALID_FUNCTION;
        }
        index++;
    }

    ret = SGX_SUCCESS;

    return ret;
}

sgx_status_t ehsm_self_test()
{
    sgx_status_t ret;

    ret = aes_gcm_crypto_test();

    return ret;
}
