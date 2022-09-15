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
#include "openssl/err.h"

#include "key_factory.h"
#include "key_operation.h"

#define SGX_DOMAIN_KEY_SIZE     16

#define RSA_2048_KEY_BITS   2048
#define RSA_3072_KEY_BITS   3072
#define RSA_4096_KEY_BITS   4096

#define ECC_MAX_PLAINTEXT_SIZE      256

sgx_aes_gcm_128bit_key_t g_domain_key = {0};

using namespace std;

uint32_t ehsm_calc_keyblob_len(const uint32_t payload_size)
{
    if (payload_size > UINT32_MAX - sizeof(sgx_aes_gcm_data_ex_t))
        return UINT32_MAX;

    if (sizeof(sgx_aes_gcm_data_ex_t) > UINT32_MAX - payload_size)
        return UINT32_MAX;

    return (payload_size + sizeof(sgx_aes_gcm_data_ex_t));
}

uint32_t ehsm_get_gcm_ciphertext_size(const sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data)
        return UINT32_MAX;

    return gcm_data->ciphertext_size;
}

// use the g_domain_key to encrypt the cmk and get it ciphertext
sgx_status_t ehsm_create_keyblob(const uint8_t *plaintext, const uint32_t plaintext_size,
                                 const uint8_t *aad, const uint32_t aad_size,
                                 sgx_aes_gcm_data_ex_t *keyblob_data)
{
    uint32_t real_aad_size = aad_size;
    if (NULL == aad)
        real_aad_size = 0;

    sgx_status_t ret = sgx_read_rand(keyblob_data->iv, sizeof(keyblob_data->iv));
    if (ret != SGX_SUCCESS) {
        printf("error generating iv.\n");
        return ret;
    }

    ret = sgx_rijndael128GCM_encrypt(&g_domain_key,
                                     plaintext, plaintext_size,
                                     keyblob_data->payload,
                                     keyblob_data->iv, sizeof(keyblob_data->iv),
                                     &(keyblob_data->payload[keyblob_data->ciphertext_size]), real_aad_size,
                                     reinterpret_cast<uint8_t (*)[16]>(keyblob_data->mac));
    if (SGX_SUCCESS != ret) {
        printf("gcm encrypting failed.\n");
    }
    else {
        keyblob_data->ciphertext_size = plaintext_size;
        keyblob_data->aad_size = real_aad_size;
    }

    return ret;
}

// use the g_domain_key to decrypt the cmk and get it plaintext
sgx_status_t ehsm_parse_keyblob(uint8_t *plaintext, uint32_t plaintext_size,
                                        const sgx_aes_gcm_data_ex_t *keyblob_data)
{
    if (NULL == keyblob_data || NULL == plaintext || NULL == plaintext_size
                 || plaintext_size < keyblob_data->ciphertext_size)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_rijndael128GCM_decrypt(&g_domain_key,
                                                  keyblob_data->payload, keyblob_data->ciphertext_size,
                                                  plaintext,
                                                  keyblob_data->iv, sizeof(keyblob_data->iv),
                                                  &(keyblob_data->payload[keyblob_data->ciphertext_size]), keyblob_data->aad_size,
                                                  (const sgx_aes_gcm_128bit_tag_t*)keyblob_data->mac);
    if (SGX_SUCCESS != ret)
        printf("gcm decrypting failed.\n");
    else
        plaintext_size = keyblob_data->ciphertext_size;

    return ret;
}

uint32_t ehsm_get_symmetric_key_size(ehsm_keyspec_t key_spec)
{
    switch (key_spec)
    {
    case EH_AES_GCM_128:
    case EH_SM4_CTR:
    case EH_SM4_CBC:
        return 16;
    case EH_AES_GCM_192:
        return 24;
    case EH_AES_GCM_256:
        return 32;
    default:
        return 0;
    }
    return 0;
}

/**
 * @brief generate aes_gcm key with openssl api
 * @param cmk_blob storage key information
 * @param APPEND_SIZE_TO_KEYBOB_T the size of cmk_blob
 * @param req_blob_size the gcm data size
 * @param keyspec key type, refer to [ehsm_keyspec_t]
 * @return sgx_status_t
 */
sgx_status_t ehsm_create_aes_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_AES_GCM_192 &&
        cmk->metadata.keyspec != EH_AES_GCM_256)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = ehsm_get_symmetric_key_size(cmk->metadata.keyspec);
    if (keysize == 0)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    uint32_t real_blob_len = ehsm_calc_keyblob_len(keysize);

    if (real_blob_len == UINT32_MAX)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    if (cmk->keybloblen == 0)
    {
        cmk->keybloblen = real_blob_len;
        return SGX_SUCCESS;
    }

    uint8_t *tmp = (uint8_t *)malloc(keysize);
    if (tmp == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ret = sgx_read_rand(tmp, keysize);
    if (ret != SGX_SUCCESS)
    {
        free(tmp);
        return ret;
    }
    ret = ehsm_create_keyblob(tmp,
                              keysize,
                              NULL,
                              0,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    memset_s(tmp, keysize, 0, keysize);

    free(tmp);
    return ret;
}

sgx_status_t ehsm_create_rsa_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk->keybloblen == 0) {
        cmk->keybloblen = PEM_BUFSIZE * 5;
        return SGX_SUCCESS;
    }

    EVP_PKEY_CTX        *pkey_ctx        = NULL;
    EVP_PKEY            *pkey           = NULL;
    BIO                 *bio            = NULL;
    uint8_t             *pem_keypair    = NULL;
    uint32_t            key_len         = 0;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pkey_ctx == NULL) {
        goto out;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        goto out;
    }

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
            key_len = RSA_2048_KEY_BITS;
            break;
        case EH_RSA_3072:
            key_len = RSA_3072_KEY_BITS;
            break;
        case EH_RSA_4096:
            key_len = RSA_4096_KEY_BITS;
            break;
        default:
            break;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, key_len) <= 0) {
        goto out;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        goto out;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        goto out;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        goto out;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        goto out;
    }

    key_len = BIO_pending(bio);
    if (key_len <= 0) {
        goto out;
    }

    pem_keypair = (uint8_t*)malloc(key_len + 1);
    if (pem_keypair == NULL) {
        goto out;
    }

    if (BIO_read(bio, pem_keypair, key_len) < 0) {
        goto out;
    }
    pem_keypair[key_len] = '\0';

    ret = ehsm_create_keyblob(pem_keypair, key_len, NULL, 0, (sgx_aes_gcm_data_ex_t*)cmk->keyblob);

    if (ret != SGX_SUCCESS) {
        goto out;
    }
out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    SAFE_FREE(pem_keypair);
    return ret;
}

sgx_status_t ehsm_create_ec_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk->keybloblen == 0) {
        cmk->keybloblen = PEM_BUFSIZE * 5;
        return SGX_SUCCESS;
    }

    EVP_PKEY_CTX        *pkey_ctx       = NULL;
    EVP_PKEY            *pkey           = NULL;
    BIO                 *bio            = NULL;
    uint8_t             *pem_keypair    = NULL;
    uint32_t            key_len         = 0;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pkey_ctx == NULL) {
        goto out;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        goto out;
    }

    switch (cmk->metadata.keyspec) {
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_X9_62_prime256v1) <= 0) {
                goto out;
            }
            break;
        case EH_SM2:
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_sm2) <= 0) {
                goto out;
            }
            break;
        default:
            break;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        goto out;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        goto out;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        goto out;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        goto out;
    }

    key_len = BIO_pending(bio);
    if (key_len <= 0) {
        goto out;
    }

    pem_keypair = (uint8_t*)malloc(key_len + 1);
    if (pem_keypair == NULL) {
        goto out;
    }

    if (BIO_read(bio, pem_keypair, key_len) < 0) {
        goto out;
    }
    pem_keypair[key_len] = '\0';

    ret = ehsm_create_keyblob(pem_keypair, key_len, NULL, 0, (sgx_aes_gcm_data_ex_t*)cmk->keyblob);

    if (ret != SGX_SUCCESS) {
        goto out;
    }
out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    SAFE_FREE(pem_keypair);
    return ret;
}

sgx_status_t ehsm_create_sm4_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk->metadata.keyspec != EH_SM4_CTR &&
        cmk->metadata.keyspec != EH_SM4_CBC)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = ehsm_get_symmetric_key_size(cmk->metadata.keyspec);
    if (keysize == 0)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    uint32_t real_blob_len = ehsm_calc_keyblob_len(keysize);

    if (real_blob_len == UINT32_MAX)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    if (cmk->keybloblen == 0)
    {
        cmk->keybloblen = real_blob_len;
        return SGX_SUCCESS;
    }

    uint8_t *tmp = (uint8_t *)malloc(keysize);
    if (tmp == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ret = sgx_read_rand(tmp, keysize);
    if (ret != SGX_SUCCESS)
    {
        free(tmp);
        return ret;
    }
    ret = ehsm_create_keyblob(tmp,
                              keysize,
                              NULL,
                              0,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    memset_s(tmp, keysize, 0, keysize);

    free(tmp);
    return ret;
}
sgx_status_t ehsm_generate_datakey_aes(const ehsm_keyblob_t *cmk,
                                           const ehsm_data_t *aad,
                                           ehsm_data_t *plaintext,
                                           ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *temp_datakey =NULL;
    temp_datakey = (uint8_t *)malloc(plaintext->datalen);
    if (temp_datakey == NULL)
    {
        free(temp_datakey);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    if(RAND_bytes(temp_datakey, plaintext->datalen) != 1)
    {
        free(temp_datakey);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    memcpy_s(plaintext->data, plaintext->datalen, temp_datakey, plaintext->datalen);

    ret = ehsm_aes_gcm_encrypt(aad,
                               cmk,
                               plaintext,
                               ciphertext);

   free(temp_datakey);

    return ret;
}

sgx_status_t ehsm_generate_datakey_sm4(const ehsm_keyblob_t *cmk,
                                       ehsm_data_t *plaintext,
                                       ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *temp_datakey =NULL;
    temp_datakey = (uint8_t *)malloc(plaintext->datalen);
    if (temp_datakey == NULL)
    {
        free(temp_datakey);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    if(RAND_bytes(temp_datakey, plaintext->datalen) != 1)
    {
        free(temp_datakey);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    memcpy_s(plaintext->data, plaintext->datalen, temp_datakey, plaintext->datalen);


    if (cmk->metadata.keyspec == EH_SM4_CTR)
    {
        ret = ehsm_sm4_ctr_encrypt(cmk,
                                   plaintext,
                                   ciphertext);
    }
    else
    {
        ret = ehsm_sm4_cbc_encrypt(cmk,
                                   plaintext,
                                   ciphertext);
    }

    free(temp_datakey);

    return ret;
}