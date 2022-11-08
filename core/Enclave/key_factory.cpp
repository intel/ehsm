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
#include "log_utils.h"
#include "sgx_tseal.h"

#include <string>
#include <stdio.h>
#include <stdbool.h>
#include <mbusafecrt.h>
#include <type_traits>

#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"

#include "datatypes.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/rand.h"

#include "key_factory.h"
#include "key_operation.h"

#define DUMMY_SIZE 128

sgx_aes_gcm_128bit_key_t g_domain_key = {0};

using namespace std;

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
    case EH_EC_P256:
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
sgx_status_t ehsm_create_keyblob(uint8_t *plaintext, uint32_t plaintext_size,
                                 sgx_aes_gcm_data_ex_t *keyblob_data)
{
    if (keyblob_data == NULL || plaintext == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t ret = sgx_read_rand(keyblob_data->iv, sizeof(keyblob_data->iv));
    if (ret != SGX_SUCCESS)
    {
        log_d("error generating iv.\n");
        return ret;
    }

    ret = aes_gcm_encrypt((uint8_t *)g_domain_key,
                          keyblob_data->payload, EVP_aes_128_gcm(),
                          plaintext, plaintext_size,
                          NULL, 0,
                          keyblob_data->iv, SGX_AESGCM_IV_SIZE,
                          keyblob_data->mac, SGX_AESGCM_MAC_SIZE);
    if (SGX_SUCCESS != ret)
    {
        printf("gcm encrypting failed.\n");
    }
    else
    {
        keyblob_data->ciphertext_size = plaintext_size;
        keyblob_data->aad_size = 0;
    }

    return ret;
}

// use the g_domain_key to decrypt the cmk and get it plaintext
sgx_status_t ehsm_parse_keyblob(uint8_t *plaintext, uint32_t plaintext_size,
                                sgx_aes_gcm_data_ex_t *keyblob_data)
{
    if (NULL == keyblob_data || NULL == plaintext || NULL == plaintext_size || plaintext_size < keyblob_data->ciphertext_size)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = aes_gcm_decrypt((uint8_t *)g_domain_key,
                                       plaintext, EVP_aes_128_gcm(),
                                       keyblob_data->payload, keyblob_data->ciphertext_size,
                                       NULL, 0,
                                       keyblob_data->iv, SGX_AESGCM_IV_SIZE,
                                       keyblob_data->mac, SGX_AESGCM_MAC_SIZE);

    if (SGX_SUCCESS != ret)
        printf("gcm decrypting failed.\n");
    else
        plaintext_size = keyblob_data->ciphertext_size;

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

    if (cmk == NULL)
    {
        return ret;
    }

    if (cmk->keybloblen == 0)
    {
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);
    }

    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_AES_GCM_192 &&
        cmk->metadata.keyspec != EH_AES_GCM_256)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ret = sgx_read_rand(key, keysize);
    if (ret != SGX_SUCCESS)
    {
        free(key);
        return ret;
    }
    ret = ehsm_create_keyblob(key,
                              keysize,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    memset_s(key, keysize, 0, keysize);

    free(key);
    return ret;
}

static bool test_RSA_keypair(RSA *keypair)
{
    uint8_t plaintext[] = "test_rsa_keypair";
    uint8_t ciphertext[RSA_size(keypair)] = {0};
    uint8_t _plaintext[sizeof(plaintext) / sizeof(plaintext[0])] = {0};
    RSA_public_encrypt(sizeof(plaintext) / sizeof(plaintext[0]), (unsigned char *)plaintext, ciphertext, keypair, 4);
    RSA_private_decrypt(RSA_size(keypair), ciphertext, _plaintext, keypair, 4);

    return (memcmp(plaintext, _plaintext, sizeof(plaintext) / sizeof(plaintext[0])) == 0);
}

sgx_status_t ehsm_create_rsa_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
    {
        return ret;
    }

    if (cmk->keybloblen == 0)
    {
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);
    }

    RSA *rsa_keypair = NULL;
    BIO *bio = NULL;
    uint8_t *pem_keypair = NULL;
    uint32_t key_size = 0;

    rsa_keypair = RSA_new();
    if (rsa_keypair == NULL)
    {
        goto out;
    }

    switch (cmk->metadata.keyspec) // https://github.com/intel/linux-sgx/blob/master/SampleCode/SampleAttestedTLS/common/utility.cpp
    {
    case EH_RSA_2048:
        rsa_keypair = RSA_generate_key(RSA_2048_KEY_BITS, RSA_F4, NULL, NULL);
        break;
    case EH_RSA_3072:
        rsa_keypair = RSA_generate_key(RSA_3072_KEY_BITS, RSA_F4, NULL, NULL);
        break;
    case EH_RSA_4096:
        rsa_keypair = RSA_generate_key(RSA_4096_KEY_BITS, RSA_F4, NULL, NULL);
        break;
    default:
        goto out;
    }
    if (rsa_keypair == NULL) // https://doc.ecoscentric.com/ref/openssl-crypto-rsa-generate-key.html
    {
        goto out;
    }

    if (!test_RSA_keypair(rsa_keypair))
    {
        goto out;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        goto out;
    }

    if (!PEM_write_bio_RSAPublicKey(bio, rsa_keypair))
    {
        goto out;
    }

    if (!PEM_write_bio_RSAPrivateKey(bio, rsa_keypair, NULL, NULL, 0, NULL, NULL))
    {
        goto out;
    }

    key_size = BIO_pending(bio);
    if (key_size <= 0)
    {
        goto out;
    }

    pem_keypair = (uint8_t *)malloc(key_size);
    if (pem_keypair == NULL)
    {
        goto out;
    }

    if (BIO_read(bio, pem_keypair, key_size) < 0)
    {
        goto out;
    }

    ret = ehsm_create_keyblob(pem_keypair, key_size, (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    if (ret != SGX_SUCCESS)
    {
        goto out;
    }
out:
    if (rsa_keypair)
        RSA_free(rsa_keypair);
    if (bio)
        BIO_free(bio);

    memset_s(pem_keypair, key_size, 0, key_size);
    SAFE_FREE(pem_keypair);
    return ret;
}

sgx_status_t ehsm_create_ec_key(ehsm_keyblob_t *cmk) // https://github.com/intel/linux-sgx/blob/master/SampleCode/SampleAttestedTLS/common/utility.cpp
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
    {
        return ret;
    }

    if (cmk->keybloblen == 0)
    {
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);
    }

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    uint8_t *pem_keypair = NULL;
    uint32_t key_size = 0;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pkey_ctx == NULL)
    {
        goto out;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0)
    {
        goto out;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_X9_62_prime256v1) <= 0)
    {
        goto out;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0)
    {
        goto out;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        goto out;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey))
    {
        goto out;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL))
    {
        goto out;
    }

    key_size = BIO_pending(bio);
    if (key_size <= 0)
    {
        goto out;
    }

    pem_keypair = (uint8_t *)malloc(key_size);
    if (pem_keypair == NULL)
    {
        goto out;
    }

    if (BIO_read(bio, pem_keypair, key_size) < 0)
    {
        goto out;
    }

    ret = ehsm_create_keyblob(pem_keypair, key_size, (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    if (ret != SGX_SUCCESS)
    {
        goto out;
    }
out:
    if (pkey_ctx)
        EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (bio)
        BIO_free(bio);

    memset_s(pem_keypair, key_size, 0, key_size);
    SAFE_FREE(pem_keypair);
    return ret;
}

sgx_status_t ehsm_create_sm2_key(ehsm_keyblob_t *cmk) // https://github.com/intel/intel-sgx-ssl/blob/master/Linux/sgx/test_app/enclave/tests/evp_smx.c
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
    {
        return ret;
    }

    if (cmk->keybloblen == 0)
    {
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);
    }

    BIO *bio = NULL;
    uint8_t *pem_keypair = NULL;
    uint32_t key_size = 0;
    EC_GROUP *ec_group = NULL;
    EC_KEY *ec_key = NULL;

    ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (ec_group == NULL)
    {
        printf("Error: fail to create an EC_GROUP object for SM2\n");
        goto out;
    }

    ec_key = EC_KEY_new();
    if (ec_key == NULL)
    {
        printf("Error: fail to create a new EC key\n");
        goto out;
    }

    if (EC_KEY_set_group(ec_key, ec_group) != 1)
    {
        printf("Error: fail to set the new EC key's curve\n");
        goto out;
    }

    if (!EC_KEY_generate_key(ec_key))
    {
        printf("Error: fail to generate key pair based on the curve\n");
        goto out;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        goto out;
    }

    if (!PEM_write_bio_EC_PUBKEY(bio, ec_key))
    {
        goto out;
    }

    if (!PEM_write_bio_ECPrivateKey(bio, ec_key, NULL, NULL, 0, NULL, NULL))
    {
        goto out;
    }

    key_size = BIO_pending(bio);
    if (key_size <= 0)
    {
        goto out;
    }

    pem_keypair = (uint8_t *)malloc(key_size);
    if (pem_keypair == NULL)
    {
        goto out;
    }

    if (BIO_read(bio, pem_keypair, key_size) < 0)
    {
        goto out;
    }

    ret = ehsm_create_keyblob(pem_keypair, key_size, (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    if (ret != SGX_SUCCESS)
    {
        goto out;
    }
out:
    if (ec_key)
        EC_KEY_free(ec_key);
    if (bio)
        BIO_free(bio);

    memset_s(pem_keypair, key_size, 0, key_size);
    SAFE_FREE(pem_keypair);
    return ret;
}

sgx_status_t ehsm_create_sm4_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
    {
        return ret;
    }

    if (cmk->keybloblen == 0)
    {
        return ehsm_calc_keyblob_size(cmk->metadata.keyspec, cmk->keybloblen);
    }

    if (cmk->metadata.keyspec != EH_SM4_CTR &&
        cmk->metadata.keyspec != EH_SM4_CBC)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ret = sgx_read_rand(key, keysize);
    if (ret != SGX_SUCCESS)
    {
        free(key);
        return ret;
    }
    ret = ehsm_create_keyblob(key,
                              keysize,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    memset_s(key, keysize, 0, keysize);

    free(key);
    return ret;
}