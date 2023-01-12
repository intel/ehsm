/*
 * Copyright (C) 2020-2022 Intel Corporation
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
#include "elog_utils.h"
#include "sgx_tseal.h"

#include <string>
#include <stdio.h>
#include <stdbool.h>
#include <mbusafecrt.h>

#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"

#include "datatypes.h"
#include "domainkey_factory.h"
#include "enclave_t.h"

extern void log_printf(uint32_t log_level, const char* filename, uint32_t line, const char *fmt, ...);

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

uint32_t ehsm_get_gcm_ciphertext_size(const sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data)
        return UINT32_MAX;

    return gcm_data->ciphertext_size;
}

// https://github.com/openssl/openssl/blob/master/test/aesgcmtest.c#L38
sgx_status_t aes_gcm_encrypt(uint8_t *key,
                             uint8_t *cipherblob,
                             const EVP_CIPHER *block_mode,
                             uint8_t *plaintext,
                             uint32_t plaintext_len,
                             uint8_t *aad,
                             uint32_t aad_len,
                             uint8_t *iv,
                             uint32_t iv_len,
                             uint8_t *tag,
                             uint32_t tag_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int temp_len = 0;
    EVP_CIPHER_CTX *pctx = NULL;

    // Create and init ctx
    if (!(pctx = EVP_CIPHER_CTX_new()))
        goto out;

    if (1 != EVP_EncryptInit_ex(pctx, block_mode, NULL, NULL, NULL))
        goto out;

    if (iv_len != SGX_AESGCM_IV_SIZE)
        if (1 != EVP_CIPHER_CTX_ctrl(pctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
            goto out;

    // Initialise encrypt/decrpty, key and IV
    if (1 != EVP_EncryptInit_ex(pctx, NULL, NULL, key, iv))
        goto out;

    // Provide AAD data if exist
    if (aad != NULL && aad_len > 0)
        if (1 != EVP_EncryptUpdate(pctx, NULL, &temp_len, aad, aad_len))
            goto out;

    if (plaintext != NULL && plaintext_len > 0)
    {
        // Provide the message to be encrypted, and obtain the encrypted output.
        if (1 != EVP_EncryptUpdate(pctx, cipherblob, &temp_len, plaintext, plaintext_len))
            goto out;
    }
    else
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    // Finalise the encryption/decryption
    if (1 != EVP_EncryptFinal_ex(pctx, cipherblob + temp_len, &temp_len))
        goto out;

    // Get tag
    if (1 != EVP_CIPHER_CTX_ctrl(pctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
        goto out;

    ret = SGX_SUCCESS;

out:
    EVP_CIPHER_CTX_free(pctx);
    return ret;
}

sgx_status_t aes_gcm_decrypt(uint8_t *key,
                             uint8_t *plaintext,
                             const EVP_CIPHER *block_mode,
                             uint8_t *ciphertext,
                             uint32_t ciphertext_len,
                             uint8_t *aad,
                             uint32_t aad_len,
                             uint8_t *iv,
                             uint32_t iv_len,
                             uint8_t *tag,
                             uint32_t tag_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int temp_len = 0;
    EVP_CIPHER_CTX *pctx = NULL;
    // Create and initialise the context
    if (!(pctx = EVP_CIPHER_CTX_new()))
        goto out;

    if (1 != EVP_EncryptInit_ex(pctx, block_mode, NULL, NULL, NULL))
        goto out;

    if (iv_len != SGX_AESGCM_IV_SIZE)
        if (1 != EVP_CIPHER_CTX_ctrl(pctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
            goto out;

    // Initialise decrypt, key and IV
    if (!EVP_DecryptInit_ex(pctx, NULL, NULL, key, iv))
        goto out;

    if (aad != NULL && aad_len > 0)
        if (!EVP_DecryptUpdate(pctx, NULL, &temp_len, aad, aad_len))
            goto out;

    // Decrypt message, obtain the plaintext output
    if (ciphertext != NULL && ciphertext_len > 0)
    {
        if (!EVP_DecryptUpdate(pctx, plaintext, &temp_len, ciphertext, ciphertext_len))
            goto out;
    }
    else
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    // Update expected tag value
    if (!EVP_CIPHER_CTX_ctrl(pctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
        goto out;

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.
    if (EVP_DecryptFinal_ex(pctx, plaintext + temp_len, &temp_len) <= 0)
    {
        ret = SGX_ERROR_MAC_MISMATCH;
        goto out;
    }

    ret = SGX_SUCCESS;

out:
    EVP_CIPHER_CTX_free(pctx);
    return ret;
}

// use the g_domain_key to decrypt the cmk and get it plaintext
sgx_status_t ehsm_parse_keyblob(uint8_t *plaintext, 
                                sgx_aes_gcm_data_ex_t *keyblob_data,
                                uint8_t *domainkey)
{
    if (NULL == keyblob_data || NULL == plaintext)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = aes_gcm_decrypt(domainkey,
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

// use the g_domain_key to encrypt the cmk and get it ciphertext
sgx_status_t ehsm_create_keyblob(uint8_t *plaintext,
                                 uint32_t plaintext_size,
                                 sgx_aes_gcm_data_ex_t *keyblob_data,
                                 uint8_t *domainkey)
{
    if (keyblob_data == NULL || plaintext == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_read_rand(keyblob_data->iv, sizeof(keyblob_data->iv));
    if (ret != SGX_SUCCESS)
    {
        log_d("error generating iv.\n");
        return ret;
    }

    ret = aes_gcm_encrypt(domainkey,
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
