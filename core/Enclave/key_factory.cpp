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

uint32_t ehsm_calc_keyblob_len(const uint32_t aad_size, const uint32_t plaintext_size)
{
    if (aad_size > UINT32_MAX - sizeof(sgx_aes_gcm_data_ex_t))
        return UINT32_MAX;

    if (plaintext_size > UINT32_MAX - sizeof(sgx_aes_gcm_data_ex_t))
        return UINT32_MAX;

    if (aad_size > UINT32_MAX - plaintext_size)
        return UINT32_MAX;

    if (sizeof(sgx_aes_gcm_data_ex_t) > UINT32_MAX - plaintext_size - aad_size)
        return UINT32_MAX;

    return (aad_size + plaintext_size + sizeof(sgx_aes_gcm_data_ex_t));
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
 * @param SIZE_OF_KEYBLOB_T the size of cmk_blob
 * @param req_blob_size the gcm data size
 * @param keyspec key type, refer to [ehsm_keyspec_t]
 * @return sgx_status_t
 */
sgx_status_t ehsm_create_aes_key(uint8_t *cmk_blob, uint32_t SIZE_OF_KEYBLOB_T,
                                 uint32_t *req_blob_size, ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (keyspec != EH_AES_GCM_128 &&
        keyspec != EH_AES_GCM_192 &&
        keyspec != EH_AES_GCM_256)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = ehsm_get_symmetric_key_size(keyspec);
    if (keysize == 0)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    uint32_t real_blob_len = ehsm_calc_keyblob_len(0, keysize);

    if (real_blob_len == UINT32_MAX)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    if (req_blob_size != NULL)
    {
        *req_blob_size = real_blob_len;
        return SGX_SUCCESS;
    }
    if (cmk_blob == NULL || SIZE_OF_KEYBLOB_T != real_blob_len)
    {
        return SGX_ERROR_INVALID_PARAMETER;
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
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);

    memset_s(tmp, keysize, 0, keysize);

    free(tmp);
    return ret;
}

sgx_status_t ehsm_create_asymmetric_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    EVP_PKEY_CTX        *pkey_ctx        = NULL;
    EVP_PKEY            *pkey           = NULL;
    EC_GROUP            *ec_group       = NULL;
    BIO                 *bio            = NULL;
    uint8_t             *pem_keypair    = NULL;
    uint32_t            key_len         = 0;

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
        case EH_RSA_3072:
        case EH_RSA_4096:
            pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            break;
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
        case EH_SM2:
            pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            break;
        default:
            break;
    }
    if (!pkey_ctx) {
        goto out;
    }

    if (!EVP_PKEY_keygen_init(pkey_ctx)) {
        goto out;
    }

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_2048_KEY_BITS);
            break;
        case EH_RSA_3072:
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_3072_KEY_BITS);
            break;
        case EH_RSA_4096:
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_4096_KEY_BITS);
            break;
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_X9_62_prime256v1);
            break;
        case EH_SM2:
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_sm2);
                        
            break;
        default:
            break;
    }
   
    if (!EVP_PKEY_keygen(pkey_ctx, &pkey)) {
        goto out;
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    if (!(bio = BIO_new(BIO_s_mem()))) {
        goto out;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        goto out;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        goto out;
    }

    key_len = BIO_pending(bio);
    if (key_len == 0) {
        goto out;
    }
    if (cmk->keybloblen == 0) {
        cmk->keybloblen = ehsm_calc_keyblob_len(0, key_len);
        if (cmk->keybloblen != UINT32_MAX) {
            ret = SGX_SUCCESS;
            goto out;
        } else {
            goto out;
        }
    } else if (key_len > (cmk->keybloblen - sizeof(sgx_aes_gcm_data_ex_t))) {
        cmk->keybloblen = ehsm_calc_keyblob_len(0, key_len);
        if (cmk->keybloblen != UINT32_MAX) {
            ret = SGX_SUCCESS;
            goto out;
        } else {
            goto out;
        }
    }

    if (!(pem_keypair = (uint8_t*)malloc(key_len + 1))) {
        goto out;
    }

    if (!BIO_read(bio, pem_keypair, key_len)) {
        goto out;
    }
    pem_keypair[key_len] = '\0';

    ret = ehsm_create_keyblob(pem_keypair, key_len, NULL, 0, (sgx_aes_gcm_data_ex_t*)cmk->keyblob);

    if (ret != SGX_SUCCESS) {
        goto out;
    }
out:
    return ret;
}


sgx_status_t ehsm_create_sm4_key(uint8_t *cmk_blob, uint32_t SIZE_OF_KEYBLOB_T,
                                 uint32_t *req_blob_size, ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (keyspec != EH_SM4_CTR &&
        keyspec != EH_SM4_CBC)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = ehsm_get_symmetric_key_size(keyspec);
    if (keysize == 0)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    uint32_t real_blob_len = ehsm_calc_keyblob_len(0, keysize);

    if (real_blob_len == UINT32_MAX)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    if (req_blob_size != NULL)
    {
        *req_blob_size = real_blob_len;
        return SGX_SUCCESS;
    }
    if (cmk_blob == NULL || SIZE_OF_KEYBLOB_T != real_blob_len)
    {
        return SGX_ERROR_INVALID_PARAMETER;
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
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);

    memset_s(tmp, keysize, 0, keysize);

    free(tmp);
    return ret;
}
sgx_status_t ehsm_aes_gcm_generate_datakey(const ehsm_keyblob_t *cmk,
                                           const ehsm_data_t *aad,
                                           ehsm_data_t *plaintext,
                                           ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *datakey = NULL;
    datakey = (uint8_t *)malloc(plaintext->datalen);
    if (datakey == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    if(RAND_bytes(datakey, plaintext->datalen) != 1) 
    {
        free(datakey);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ret = ehsm_aes_gcm_encrypt(aad->data, 
                              aad->datalen, 
                              cmk->keyblob, 
                              cmk->keybloblen, 
                              datakey, 
                              plaintext->datalen, 
                              ciphertext->data, 
                              ciphertext->datalen, 
                              cmk->metadata.keyspec);
    if (plaintext->data != NULL)
        memcpy_s(plaintext->data, plaintext->datalen, datakey, plaintext->datalen);

    memset_s(datakey, plaintext->datalen, 0, plaintext->datalen);

    free(datakey);

    return ret;
}

sgx_status_t ehsm_generate_datakey_sm4(const ehsm_keyblob_t *cmk,
                                       const ehsm_data_t *aad,
                                       ehsm_data_t *plaintext,
                                       ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *datakey = NULL;
    datakey = (uint8_t *)malloc(plaintext->datalen);
    if (datakey == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    if(RAND_bytes(datakey, plaintext->datalen) != 1) 
    {
        free(datakey);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ret = ehsm_sm4_encrypt(aad->data, 
                           aad->datalen, 
                           cmk->keyblob, 
                           cmk->keybloblen, 
                           datakey, 
                           plaintext->datalen, 
                           ciphertext->data, 
                           ciphertext->datalen, 
                           cmk->metadata.keyspec);
    if (plaintext->data != NULL)
        memcpy_s(plaintext->data, plaintext->datalen, datakey, plaintext->datalen);

    memset_s(datakey, plaintext->datalen, 0, plaintext->datalen);

    free(datakey);

    return ret;
}