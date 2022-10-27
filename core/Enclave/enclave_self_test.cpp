#include "enclave_self_test.h"
#include <string.h>
#include <vector>
#include <map>
#include "datatypes.h"
#include "crypto_test_vector.h"

using namespace std;

#define GET_PARAMETER(x) \
    uint8_t *x = (uint8_t *)get_parameter(#x, test_vector);

#define CHECK_EQUAL(x)                              \
    if (VECTOR_LENGTH(#x) > 0)                      \
        for (int i = 0; i < VECTOR_LENGTH(#x); i++) \
            if (x[i] != _##x[i])                    \
                return false;

// TODO : add test vector for sm4 crypto
// TODO : add test vector for rsa crypto
// TODO : add test vector for rsa sign/verify
// TODO : add test vector for ec sign/verify
// TODO : add test vector for sm2 crypto
// TODO : add test vector for sm2 sign/verify

/**
 * @brief make string to hex array, string length needs to be a even number
 *
 * @param str "a0b23d" will change to "/xa0/xb2/x3d"
 * @param buf buffer for saving the result
 * @param len str length / 2
 */
static void Str2Hex(const char *pbSrc, unsigned char *pbDest, int nLen)
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

static void *get_parameter(string key_name, map<string, string> test_vector)
{
    string target = test_vector[key_name];
    int len = strlen(target.c_str()) / 2;
    uint8_t *value = (uint8_t *)malloc(len);
    Str2Hex(target.c_str(), value, len);
    return value;
}

static const EVP_CIPHER *get_block_mode(uint32_t key_length)
{
    switch (key_length)
    {
    case 16:
        return EVP_aes_128_gcm();
    case 24:
        return EVP_aes_192_gcm();
    case 32:
        return EVP_aes_256_gcm();
    default:
        return EVP_aes_256_gcm(); // return 256 block mode for unexpected key length
    }
}

static bool aes_gcm_encrypt(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("aad"));
    uint8_t *_tag = (uint8_t *)malloc(VECTOR_LENGTH("tag"));
    (void)aes_gcm_encrypt(key, _ciphertext, get_block_mode(VECTOR_LENGTH("key")), plaintext, VECTOR_LENGTH("plaintext"),
                          aad, VECTOR_LENGTH("aad"), iv, VECTOR_LENGTH("iv"), _tag, VECTOR_LENGTH("tag"));

    CHECK_EQUAL(ciphertext);
    CHECK_EQUAL(tag);

    free(_ciphertext);
    free(_tag);

    return true;
}

static bool aes_gcm_decrypt(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)aes_gcm_decrypt(key, _plaintext, get_block_mode(VECTOR_LENGTH("key")), ciphertext, VECTOR_LENGTH("ciphertext"),
                          aad, VECTOR_LENGTH("aad"), iv, VECTOR_LENGTH("iv"), tag, VECTOR_LENGTH("tag"));

    CHECK_EQUAL(plaintext);

    free(_plaintext);

    return true;
}

static sgx_status_t aes_gcm_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;
    for (auto test_vector : aes_gcm_encryption_test_vectors)
    {
        if (!aes_gcm_encrypt(test_vector))
        {
            printf("fail at %s case %d\n", __FUNCTION__, index);
        }
        index++;
    }
    for (auto test_vector : aes_gcm_decryption_test_vectors)
    {
        if (!aes_gcm_decrypt(test_vector))
        {
            printf("fail at %s case %d\n", __FUNCTION__, index);
        }
        index++;
    }

    if (index != SELF_TEST_NUM + 1)
    {
        return SGX_ERROR_INVALID_FUNCTION;
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
