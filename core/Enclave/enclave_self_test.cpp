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
     {"key", "cf063a34d4a9a76c2c86787d3f96db71"},
     {"plaintext", ""},
     {"aad", ""},
     {"iv", "113b9785971864c83b01c787"},
     {"ciphertext", ""},
     {"tag", "72ac8493e3a5228b5d130a69d2510e42"}},
    {// case2
     {"key", "599eb65e6b2a2a7fcc40e51c4f6e3257"},
     {"plaintext", "a6c9e0f248f07a3046ece12125666921"},
     {"aad", "10e72efe048648d40139477a2016f8ce"},
     {"iv", "d407301cfa29af8525981c17"},
     {"ciphertext", "1be9359a543fd7ec3c4bc6f3c9395e89"},
     {"tag", "e2e9c07d4c3c10a6137ca433da42f9a8"}},
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
static bool StrToHex(const char *str, unsigned char buf[], int len)
{
    if ((len % 2) != 0)
    {
        return false;
    }
    if (str != NULL && buf != NULL && len != 0)
    {
        int Length = sizeof(str);
        if (Length % 2 == 0)
        {
            int i = 0;
            int n = 0;
            while (*str != 0 && (n = ((i++) >> 1)) < len)
            {
                buf[n] <<= 4;
                if (*str >= '0' && *str <= '9')
                {
                    buf[n] |= *str - '0';
                }
                else if (*str >= 'a' && *str <= 'f')
                {
                    buf[n] |= *str - 'a' + 10;
                }
                else if (*str >= 'A' && *str <= 'F')
                {
                    buf[n] |= *str - 'A' + 10;
                }
                str++;
            }
            len = n;
        }
    }
    return true;
}

void *get_parameter(string key_name, map<string, string> test_vector)
{
    string target = test_vector[key_name];
    int len = strlen(target.c_str()) / 2;
    uint8_t *value = (uint8_t *)malloc(len);
    StrToHex(target.c_str(), value, len);
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

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
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
