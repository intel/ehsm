#include "enclave_self_test.h"

using namespace std;

EHSM_TEST_VECTOR sm4_ctr_crypto_test_vectors = {
    {// case1
     {"key", "0123456789abcdeffedcba9876543210"},
     {"plaintext", "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"},
     {"iv", "000102030405060708090a0b0c0d0e0f"},
     {"ciphertext", "ac3236cb970cc20791364c395a1342d1a3cbc1878c6f30cd074cce385cdd70c7f234bc0e24c11980fd1286310ce37b926e02fcd0faa0baf38b2933851d824514"}},
    {// case2
     {"key", "fedcba98765432100123456789abcdef"},
     {"plaintext", "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"},
     {"iv", "000102030405060708090a0b0c0d0e0f"},
     {"ciphertext", "5dcccd25b95ab07417a08512ee160e2f8f661521cbbab44cc87138445bc29e5c0ae0297205d62704173b21239b887f6c8cb5b800917a2488284bde9e16ea2906"}}};

EHSM_TEST_VECTOR sm4_cbc_crypto_test_vectors = {
    {// case1
     {"key", "0123456789abcdeffedcba9876543210"},
     {"plaintext", "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb"},
     {"iv", "000102030405060708090a0b0c0d0e0f"},
     {"ciphertext", "78ebb11cc40b0a48312aaeb2040244cb4cb7016951909226979b0d15dc6a8f6d"}},
    {// case2
     {"key", "fedcba98765432100123456789abcdef"},
     {"plaintext", "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb"},
     {"iv", "000102030405060708090a0b0c0d0e0f"},
     {"ciphertext", "0d3a6ddc2d21c698857215587b7bb59a91f2c147911a4144665e1fa1d40bae38"}}};

static bool sm4_ctr_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t _ciphertext[VECTOR_LENGTH("plaintext")] = {0};
    (void)sm4_ctr_encrypt(&*key,
                          _ciphertext,
                          &*plaintext,
                          VECTOR_LENGTH("plaintext"),
                          &*iv);

    return TEST_COMPARE(ciphertext);
}

static bool sm4_ctr_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t _plaintext[VECTOR_LENGTH("plaintext")] = {0};
    (void)sm4_ctr_decrypt(&*key,
                          _plaintext,
                          &*ciphertext,
                          VECTOR_LENGTH("plaintext"),
                          &*iv);

    return TEST_COMPARE(plaintext);
}

static bool sm4_cbc_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t _ciphertext[VECTOR_LENGTH("plaintext")] = {0};
    (void)sm4_cbc_encrypt(&*key,
                          _ciphertext,
                          &*plaintext,
                          VECTOR_LENGTH("plaintext"),
                          &*iv);

    return TEST_COMPARE(ciphertext);
}

static bool sm4_cbc_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t _plaintext[VECTOR_LENGTH("plaintext")] = {0};
    uint32_t actual_plaintext_len = 0;
    (void)sm4_cbc_decrypt(&*key,
                          _plaintext,
                          actual_plaintext_len,
                          &*ciphertext,
                          VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("iv"),
                          &*iv);

    return TEST_COMPARE(plaintext);
}

/***
 * setup1. load key, iv, aad
 * setup2. decrypt ciphertext or encrypt plaintext
 * setup3. compare mac and crypto result
 */
bool sm4_crypto_test()
{
    log_i("%s start", __func__);
    int index = 1;

    for (auto &test_vector : sm4_ctr_crypto_test_vectors)
    {
        if (!sm4_ctr_encryption(test_vector))
        {
            log_e("self test failed");
            for (auto &item : test_vector)
                log_e("[%s]: [%s]", item.first.c_str(), item.second.c_str());
            continue;
        }

        if (!sm4_ctr_decryption(test_vector))
        {
            log_e("self test failed");
            for (auto &item : test_vector)
                log_e("[%s]: [%s]", item.first.c_str(), item.second.c_str());
            continue;
        }

        index++;
    }
    for (auto &test_vector : sm4_cbc_crypto_test_vectors)
    {
        if (!sm4_cbc_encryption(test_vector))
        {
            log_e("self test failed");
            for (auto &item : test_vector)
                log_e("[%s]: [%s]", item.first.c_str(), item.second.c_str());
            continue;
        }

        if (!sm4_cbc_decryption(test_vector))
        {
            log_e("self test failed");
            for (auto &item : test_vector)
                log_e("[%s]: [%s]", item.first.c_str(), item.second.c_str());
            continue;
        }

        index++;
    }

    if (index != sm4_ctr_crypto_test_vectors.size() + sm4_cbc_crypto_test_vectors.size() + 1)
    {
        return false;
    }
    log_i("%s end", __func__);
    return true;
}
