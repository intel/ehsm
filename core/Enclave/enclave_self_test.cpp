// test vector comes from ：
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

#include "enclave_self_test.h"
#include <string.h>
#include <vector>
#include <map>
#include "datatypes.h"
#include "key_operation.h"

using namespace std;

typedef vector<map<string, string>> EHSM_TEST_VECTOR;

#define GET_PARAMETER(x) \
    uint8_t *x = (uint8_t *)get_parameter(#x, test_vector);

EHSM_TEST_VECTOR aes_gcm_test_vectors =
    {
        {// case1
            {"key", "feffe9928665731c6d6a8f9467308308"},
            {"plaintext", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"},
            {"aad", "feedfacedeadbeeffeedfacedeadbeefabaddad2"},
            {"iv", "cafebabefacedbaddecaf888"},
            {"ciphertext", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"},
            {"tag", "5bc94fbc3221a5db94fae95ae7121a47"}
        },
        {// case2
            {"key", "c939cc13397c1d37de6ae0e1cb7c423c"},
            {"plaintext", "c3b3c41f113a31b73d9a5cd432103069"},
            {"aad", "24825602bd12a984e0092d3e448eda5f"},
            {"iv", "b3d8cc017cbb89b39e0f67e2"},
            {"ciphertext", "93fe7d9e9bfd10348a5606e5cafa7354"},
            {"tag", "0032a1dc85f1c9786925a2e71d8272dd"}
        }
    };

bool StrToHex(const char *str, unsigned char buf[], int len)
{
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
    return 1;
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

    int temp_len = 0;
    EVP_CIPHER_CTX *pctx = NULL;

    if (!(pctx = EVP_CIPHER_CTX_new()))
    {
        return false;
    }

    if (1 != EVP_EncryptInit_ex(pctx, EVP_aes_128_gcm(), NULL, key, iv))
    {
        return false;
    }

    if (VECTOR_LENGTH("aad") > 0)
    {
        if (1 != EVP_EncryptUpdate(pctx, NULL, &temp_len, aad, VECTOR_LENGTH("aad")))
        {
            return false;
        }
    }

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    uint8_t *_tag = (uint8_t *)malloc(VECTOR_LENGTH("tag"));

    if (1 != EVP_EncryptUpdate(pctx, _ciphertext, &temp_len, plaintext, VECTOR_LENGTH("plaintext")))
    {
        return false;
    }

    if (1 != EVP_EncryptFinal_ex(pctx, _ciphertext, &temp_len))
    {
        return false;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(pctx, EVP_CTRL_GCM_GET_TAG, VECTOR_LENGTH("tag"), _tag))
    {
        return false;
    }

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

    int temp_len = 0;
    EVP_CIPHER_CTX *pctx = NULL;

    if (!(pctx = EVP_CIPHER_CTX_new()))
    {
        return false;
    }

    if (!EVP_DecryptInit_ex(pctx, EVP_aes_128_gcm(), NULL, key, iv))
    {
        return false;
    }

    if (VECTOR_LENGTH("aad") > 0)
    {
        if (!EVP_DecryptUpdate(pctx, NULL, &temp_len, aad, VECTOR_LENGTH("aad")))
        {
            return false;
        }
    }

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));

    if (!EVP_DecryptUpdate(pctx, _plaintext, &temp_len, ciphertext, VECTOR_LENGTH("plaintext")))
    {
        return false;
    }

    if (!EVP_CIPHER_CTX_ctrl(pctx, EVP_CTRL_GCM_SET_TAG, VECTOR_LENGTH("tag"), tag))
    {
        return false;
    }

    if (EVP_DecryptFinal_ex(pctx, _plaintext + temp_len, &temp_len) <= 0)
    {
        return false;
    }

    for (int i = 0; i < VECTOR_LENGTH("plaintext"); i++)
    {
        printf("%02x", plaintext[i]);
    }
    
    for (int i = 0; i < VECTOR_LENGTH("plaintext"); i++)
    {
        printf("%02x", _plaintext[i]);
    }
    
    EVP_CIPHER_CTX_free(pctx);
    
    CHECK_EQUAL(plaintext);

    return true;
}

sgx_status_t aes_gcm_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    for (auto test_vector : aes_gcm_test_vectors)
    {
        if (!aes_gcm_encrypt(test_vector) || !aes_gcm_decrypt(test_vector))
        {
            return SGX_ERROR_INVALID_FUNCTION;
        }
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
