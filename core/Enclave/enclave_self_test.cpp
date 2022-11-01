#include "enclave_self_test.h"
#include <string.h>
#include <vector>
#include <map>
#include "datatypes.h"
#include "self_test_vector.h"

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

static bool sm4_ctr_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)sm4_ctr_encrypt(key, _ciphertext, plaintext, VECTOR_LENGTH("plaintext"), iv);

    CHECK_EQUAL(ciphertext);

    free(_ciphertext);

    return true;
}

static bool sm4_ctr_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)sm4_ctr_decrypt(key, _plaintext, ciphertext, VECTOR_LENGTH("plaintext"), iv);

    CHECK_EQUAL(plaintext);

    free(_plaintext);

    return true;
}

static bool sm4_cbc_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)sm4_cbc_encrypt(key, _ciphertext, plaintext, VECTOR_LENGTH("plaintext"), iv);

    CHECK_EQUAL(ciphertext);

    free(_ciphertext);

    return true;
}

static bool sm4_cbc_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)sm4_cbc_decrypt(key, _plaintext, ciphertext, VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("iv"), iv);

    CHECK_EQUAL(plaintext);

    free(_plaintext);

    return true;
}

static bool rsa_crypto(map<string, string> test_vector)
{
    GET_PARAMETER(n);
    GET_PARAMETER(e);
    GET_PARAMETER(d);
    GET_PARAMETER(p);
    GET_PARAMETER(q);
    GET_PARAMETER(dmp1);
    GET_PARAMETER(dmq1);
    GET_PARAMETER(iqmp);

    GET_PARAMETER(plaintext);
    GET_PARAMETER(ciphertext);

    RSA *key = RSA_new();

    RSA_set0_key(key,
                 BN_bin2bn(n, VECTOR_LENGTH("n"), NULL),
                 BN_bin2bn(e, VECTOR_LENGTH("e"), NULL),
                 BN_bin2bn(d, VECTOR_LENGTH("d"), NULL));
    RSA_set0_factors(key,
                     BN_bin2bn(p, VECTOR_LENGTH("p"), NULL),
                     BN_bin2bn(q, VECTOR_LENGTH("q"), NULL));
    RSA_set0_crt_params(key,
                        BN_bin2bn(dmp1, VECTOR_LENGTH("dmp1"), NULL),
                        BN_bin2bn(dmq1, VECTOR_LENGTH("dmq1"), NULL),
                        BN_bin2bn(iqmp, VECTOR_LENGTH("iqmp"), NULL));

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));

    RSA_private_decrypt(RSA_size(key), ciphertext, _plaintext, key, 1);

    CHECK_EQUAL(plaintext);

    return true;
}

static sgx_status_t aes_gcm_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;
    for (auto test_vector : aes_gcm_crypto_test_vectors)
    {
        if (!aes_gcm_encrypt(test_vector))
        {
            printf("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!aes_gcm_decrypt(test_vector))
        {
            printf("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != aes_gcm_crypto_test_vectors.size() + 1)
    {
        return SGX_ERROR_INVALID_FUNCTION;
    }

    ret = SGX_SUCCESS;

    return ret;
}

static sgx_status_t sm4_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;

    for (auto test_vector : sm4_ctr_crypto_test_vectors)
    {
        if (!sm4_ctr_encryption(test_vector))
        {
            printf("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!sm4_ctr_decryption(test_vector))
        {
            printf("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }
    for (auto test_vector : sm4_cbc_crypto_test_vectors)
    {
        if (!sm4_cbc_encryption(test_vector))
        {
            printf("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!sm4_cbc_decryption(test_vector))
        {
            printf("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != sm4_ctr_crypto_test_vectors.size() + sm4_cbc_crypto_test_vectors.size() + 1)
    {
        return SGX_ERROR_INVALID_FUNCTION;
    }

    ret = SGX_SUCCESS;

    return ret;
}

static sgx_status_t rsa_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;

    for (auto test_vector : rsa_crypto_test_vectors)
    {
        if (!rsa_crypto(test_vector))
        {
            printf("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != rsa_crypto_test_vectors.size() + 1)
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
    ret = sm4_crypto_test();
    ret = rsa_crypto_test();

    return ret;
}
