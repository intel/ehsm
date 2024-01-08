/*
 * Copyright (C) 2020-2021 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "enclave_hsm_t.h"

#include <type_traits>

#include "datatypes.h"

#include "key_factory.h"
#include "key_operation.h"
#include "openssl_operation.h"

extern sgx_aes_gcm_256bit_key_t g_domain_key;

using namespace std;

static sgx_status_t encode_keypair_to_pem(EVP_PKEY *pkey, ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *pem_keypair = NULL;
    size_t key_size = 0;
    BIO *bio = NULL;
    OSSL_ENCODER_CTX *ectx_pubkey;
    OSSL_ENCODER_CTX *ectx_prikey;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        goto out;

    ectx_pubkey = OSSL_ENCODER_CTX_new_for_pkey(pkey,
                                                OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                                "PEM", NULL,
                                                NULL);
    if (ectx_pubkey == NULL)
        goto out;

    if (!OSSL_ENCODER_to_bio(ectx_pubkey, bio))
        goto out;

    ectx_prikey = OSSL_ENCODER_CTX_new_for_pkey(pkey,
                                                OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                                "PEM", NULL,
                                                NULL);
    if (ectx_prikey == NULL)
        goto out;

    if (!OSSL_ENCODER_to_bio(ectx_prikey, bio))
        goto out;

    key_size = BIO_pending(bio);
    pem_keypair = (uint8_t *)malloc(key_size);
    if (pem_keypair == NULL)
        goto out;

    if (BIO_read(bio, pem_keypair, key_size) < 0)
        goto out;

    ret = ehsm_create_keyblob(pem_keypair, key_size, (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

out:
    BIO_free(bio);
    OSSL_ENCODER_CTX_free(ectx_prikey);
    OSSL_ENCODER_CTX_free(ectx_pubkey);

    SAFE_MEMSET(pem_keypair, key_size, 0, key_size);
    SAFE_FREE(pem_keypair);

    return ret;
}

sgx_status_t ehsm_calc_keyblob_size(const uint32_t keyspec, uint32_t &key_size)
{
    switch (keyspec)
    {
    case EH_RSA_2048:
        key_size = PEM_BUFSIZE * 3 + sizeof(sgx_aes_gcm_data_ex_t);
        break;
    case EH_RSA_3072:
        key_size = PEM_BUFSIZE * 4 + sizeof(sgx_aes_gcm_data_ex_t);
        break;
    case EH_RSA_4096:
        key_size = PEM_BUFSIZE * 5 + sizeof(sgx_aes_gcm_data_ex_t);
        break;
    case EH_EC_P224:
    case EH_EC_P256:
    case EH_EC_P256K:
    case EH_EC_P384:
    case EH_EC_P521:
    case EH_SM2:
        key_size = PEM_BUFSIZE + sizeof(sgx_aes_gcm_data_ex_t);
        break;
    case EH_AES_GCM_128:
    case EH_SM4_CTR:
    case EH_SM4_CBC:
        key_size = 16 + sizeof(sgx_aes_gcm_data_ex_t);
        break;
    case EH_AES_GCM_192:
        key_size = 24 + sizeof(sgx_aes_gcm_data_ex_t);
        break;
    case EH_AES_GCM_256:
        key_size = 32 + sizeof(sgx_aes_gcm_data_ex_t);
        break;
    default:
        return SGX_ERROR_UNEXPECTED;
        break;
    }

    return SGX_SUCCESS;
}

uint32_t ehsm_get_gcm_ciphertext_size(const sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data)
        return UINT32_MAX;

    return gcm_data->ciphertext_size;
}

// use the g_domain_key to encrypt the cmk and get it ciphertext
sgx_status_t ehsm_create_keyblob(uint8_t *plaintext,
                                 uint32_t plaintext_size,
                                 sgx_aes_gcm_data_ex_t *keyblob_data)
{
    if (keyblob_data == NULL || plaintext == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_read_rand(keyblob_data->iv, sizeof(keyblob_data->iv));
    if (ret != SGX_SUCCESS)
    {
        log_d("error generating iv.\n");
        return ret;
    }

    ret = aes_gcm_encrypt((uint8_t *)g_domain_key,
                          keyblob_data->payload, EVP_aes_256_gcm(),
                          plaintext, plaintext_size,
                          NULL, 0,
                          keyblob_data->iv, SGX_AESGCM_IV_SIZE,
                          keyblob_data->mac, SGX_AESGCM_MAC_SIZE);

    if (SGX_SUCCESS != ret)
    {
        log_e("gcm encrypting failed.\n");
    }
    else
    {
        keyblob_data->ciphertext_size = plaintext_size;
        keyblob_data->aad_size = 0;
    }

    return ret;
}

// use the g_domain_key to decrypt the cmk and get it plaintext
sgx_status_t ehsm_parse_keyblob(uint8_t *plaintext, sgx_aes_gcm_data_ex_t *keyblob_data)
{
    if (NULL == keyblob_data || NULL == plaintext)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = aes_gcm_decrypt((uint8_t *)g_domain_key,
                                       plaintext, EVP_aes_256_gcm(),
                                       keyblob_data->payload,
                                       keyblob_data->ciphertext_size,
                                       NULL,
                                       0,
                                       keyblob_data->iv,
                                       SGX_AESGCM_IV_SIZE,
                                       keyblob_data->mac,
                                       SGX_AESGCM_MAC_SIZE);

    if (SGX_SUCCESS != ret)
        log_e("gcm decrypting failed.\n");

    return ret;
}

bool ehsm_get_symmetric_key_size(ehsm_keyspec_t key_spec, uint32_t &key_size)
{
    switch (key_spec)
    {
    case EH_AES_GCM_128:
    case EH_SM4_CTR:
    case EH_SM4_CBC:
        key_size = 16;
        break;
    case EH_AES_GCM_192:
        key_size = 24;
        break;
    case EH_AES_GCM_256:
        key_size = 32;
        break;
    default:
        return false;
    }
    return true;
}

/**
 * @brief generate aes_gcm key with openssl api
 * @param cmk_blob storage key information
 * @param APPEND_SIZE_TO_KEYBLOB_T the size of cmk_blob
 * @param req_blob_size the gcm data size
 * @param keyspec key type, refer to [ehsm_keyspec_t]
 * @return sgx_status_t
 */
sgx_status_t ehsm_create_aes_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return ret;

    if (cmk->keybloblen == 0)
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);

    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_AES_GCM_192 &&
        cmk->metadata.keyspec != EH_AES_GCM_256)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = sgx_read_rand(key, keysize);
    if (ret != SGX_SUCCESS)
    {
        free(key);
        return ret;
    }

    ret = ehsm_create_keyblob(key,
                              keysize,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    SAFE_MEMSET(key, keysize, 0, keysize);
    free(key);

    return ret;
}

#ifdef ENABLE_PAIR_WISE_TEST
static bool pair_wise_test_for_rsa(EVP_PKEY *pkey)
{
    uint8_t data2sign[] = "pair_wise_test_for_rsa";
    uint8_t signature[EVP_PKEY_size(pkey)] = {0};
    uint32_t data2sign_size = sizeof(data2sign) / sizeof(data2sign[0]);
    bool result = false;
    if (rsa_sign(pkey,
                 EVP_sha256(),
                 RSA_PKCS1_PSS_PADDING,
                 EH_RAW,
                 data2sign,
                 data2sign_size,
                 signature,
                 EVP_PKEY_size(pkey)) != SGX_SUCCESS)
        return false;

    if (rsa_verify(pkey,
                   EVP_sha256(),
                   RSA_PKCS1_PSS_PADDING,
                   EH_RAW,
                   data2sign,
                   data2sign_size,
                   signature,
                   EVP_PKEY_size(pkey),
                   &result) != SGX_SUCCESS)
        return false;

    return result;
}
#endif

sgx_status_t ehsm_create_rsa_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
        return ret;

    if (cmk->keybloblen == 0)
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pkey_ctx == NULL)
        goto out;

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0)
        goto out;

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_2048_KEY_BITS);
        break;
    case EH_RSA_3072:
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_3072_KEY_BITS);
        break;
    case EH_RSA_4096:
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_4096_KEY_BITS);
        break;
    default:
        goto out;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0)
        goto out;

#ifdef ENABLE_PAIR_WISE_TEST
    if (!pair_wise_test_for_rsa(pkey))
    {
        log_e("rsa keypair test failed, exit");
        goto out;
    }
#endif

    ret = encode_keypair_to_pem(pkey, cmk);

out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);

    return ret;
}

sgx_status_t ehsm_create_rsa_key_for_BYOK(ehsm_keyblob_t *cmk, ehsm_data_t *pubkey, ehsm_keyspec_t keyspec)
{
    // 1. generate a RSA keypair
    // 2. return pubkey length
    // 3. export pubkey
    
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    uint8_t *pem_keypair = NULL;
    size_t key_size = 0;
    BIO *bio = NULL;
    OSSL_ENCODER_CTX *ectx_pubkey;
    OSSL_ENCODER_CTX *ectx_prikey;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pkey_ctx == NULL)
        goto out;

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0)
        goto out;

    switch (keyspec)
    {
    case EH_RSA_2048:
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_2048_KEY_BITS);
        break;
    case EH_RSA_3072:
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_3072_KEY_BITS);
        break;
    case EH_RSA_4096:
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_4096_KEY_BITS);
        break;
    default:
        goto out;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0)
        goto out;

#ifdef ENABLE_PAIR_WISE_TEST
    if (!pair_wise_test_for_rsa(pkey))
    {
        log_e("rsa keypair test failed, exit");
        goto out;
    }
#endif

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        goto out;

    ectx_pubkey = OSSL_ENCODER_CTX_new_for_pkey(pkey,
                                                OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                                "PEM", NULL,
                                                NULL);
    if (ectx_pubkey == NULL)
        goto out;

    if (!OSSL_ENCODER_to_bio(ectx_pubkey, bio))
        goto out;

    if (pubkey->datalen == 0)
    {
        pubkey->datalen = BIO_pending(bio);
        return SGX_SUCCESS;
    }

    ectx_prikey = OSSL_ENCODER_CTX_new_for_pkey(pkey,
                                                OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                                "PEM", NULL,
                                                NULL);
    if (ectx_prikey == NULL)
        goto out;

    if (!OSSL_ENCODER_to_bio(ectx_prikey, bio))
        goto out;

    key_size = BIO_pending(bio);
    pem_keypair = (uint8_t *)malloc(key_size);
    if (pem_keypair == NULL)
        goto out;

    if (BIO_read(bio, pem_keypair, key_size) < 0)
        goto out;

    memcpy_s(pubkey->data, pubkey->datalen, pem_keypair, pubkey->datalen);

    ret = ehsm_create_keyblob(pem_keypair, key_size, (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    OSSL_ENCODER_CTX_free(ectx_prikey);
    OSSL_ENCODER_CTX_free(ectx_pubkey);

    SAFE_MEMSET(pem_keypair, key_size, 0, key_size);
    SAFE_FREE(pem_keypair);

    return ret;
}

#ifdef ENABLE_PAIR_WISE_TEST
static bool pair_wise_test_for_ecc(EVP_PKEY *pkey, ehsm_keyspec_t keyspec)
{
    uint8_t data2sign[] = "test_ec_keypair";
    uint32_t data2sign_size = sizeof(data2sign) / sizeof(data2sign[0]);
    uint32_t signature_size = 0;
    bool result = false;

    switch (keyspec)
    {
    case EH_EC_P256:
    case EH_EC_P256K:
        signature_size = EC_P256_SIGNATURE_MAX_SIZE;
        break;
    case EH_EC_P224:
        signature_size = EC_P224_SIGNATURE_MAX_SIZE;
        break;
    case EH_EC_P384:
        signature_size = EC_P384_SIGNATURE_MAX_SIZE;
        break;
    case EH_EC_P521:
        signature_size = EC_P521_SIGNATURE_MAX_SIZE;
        break;
    default:
        return false;
    }

    uint8_t signature[signature_size] = {0};

    if (ecc_sign(pkey,
                 EVP_sha256(),
                 EH_RAW,
                 data2sign,
                 data2sign_size,
                 signature,
                 &signature_size) != SGX_SUCCESS)
    {
        return false;
    }

    ecc_verify(pkey,
               EVP_sha256(),
               EH_RAW,
               data2sign,
               data2sign_size,
               signature,
               signature_size,
               &result);

    return result;
}
#endif

sgx_status_t ehsm_create_ecc_key(ehsm_keyblob_t *cmk) // https://github.com/intel/linux-sgx/blob/master/SampleCode/SampleAttestedTLS/common/utility.cpp
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
        return ret;

    if (cmk->keybloblen == 0)
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pkey_ctx == NULL)
        goto out;

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0)
        goto out;

    uint32_t nid;
    switch (cmk->metadata.keyspec)
    {
    case EH_EC_P224:
        nid = NID_secp224r1;
        break;
    case EH_EC_P256:
        nid = NID_X9_62_prime256v1;
        break;
    case EH_EC_P256K:
        nid = NID_secp256k1;
        break;
    case EH_EC_P384:
        nid = NID_secp384r1;
        break;
    case EH_EC_P521:
        nid = NID_secp521r1;
        break;
    default:
        goto out;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, nid) <= 0)
        goto out;

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0)
        goto out;

#ifdef ENABLE_PAIR_WISE_TEST
    if (!pair_wise_test_for_ecc(pkey, cmk->metadata.keyspec))
    {
        log_e("ecc keypair test failed, exit");
        goto out;
    }
#endif

    ret = encode_keypair_to_pem(pkey, cmk);

out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);

    return ret;
}

#ifdef ENABLE_PAIR_WISE_TEST
static bool pair_wise_test_for_sm2(EVP_PKEY *pkey)
{
    uint8_t data2sign[] = "test_SM2_keypair";
    uint32_t signature_size = EC_SM2_SIGNATURE_MAX_SIZE;
    uint8_t signature[signature_size] = {0};
    uint32_t data2sign_size = sizeof(data2sign) / sizeof(data2sign[0]);
    bool result = false;
    if (sm2_sign(pkey,
                 EVP_sm3(),
                 EH_RAW,
                 data2sign,
                 data2sign_size,
                 signature,
                 &signature_size,
                 (uint8_t *)SM2_DEFAULT_USERID,
                 strlen(SM2_DEFAULT_USERID)) != SGX_SUCCESS)
        return false;

    if (sm2_verify(pkey,
                   EVP_sm3(),
                   EH_RAW,
                   data2sign,
                   data2sign_size,
                   signature,
                   signature_size,
                   &result,
                   (uint8_t *)SM2_DEFAULT_USERID,
                   strlen(SM2_DEFAULT_USERID)) != SGX_SUCCESS)
        return false;

    return result;
}
#endif

sgx_status_t ehsm_create_sm2_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
        return ret;

    if (cmk->keybloblen == 0)
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (pkey_ctx == NULL)
        goto out;

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0)
        goto out;

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_sm2) <= 0)
        goto out;

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0)
        goto out;

#ifdef ENABLE_PAIR_WISE_TEST
    if (!pair_wise_test_for_sm2(pkey))
    {
        log_e("sm2 keypair test failed, exit");
        goto out;
    }
#endif

    ret = encode_keypair_to_pem(pkey, cmk);

    if (ret != SGX_SUCCESS)
        goto out;
out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);

    return ret;
}

sgx_status_t ehsm_create_sm4_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return ret;

    if (cmk->keybloblen == 0)
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);

    if (cmk->metadata.keyspec != EH_SM4_CTR &&
        cmk->metadata.keyspec != EH_SM4_CBC)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = sgx_read_rand(key, keysize);
    if (ret != SGX_SUCCESS)
    {
        free(key);
        return ret;
    }
    ret = ehsm_create_keyblob(key,
                              keysize,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    SAFE_MEMSET(key, keysize, 0, keysize);

    free(key);
    return ret;
}