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

#include "enclave_hsm_t.h"
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
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/param_build.h"

#include "datatypes.h"
#include "key_operation.h"
#include "openssl_operation.h"

#define MAX_DIGEST_LENGTH 64

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

// https://github.com/openssl/openssl/blob/master/test/aesgcmtest.c#L66
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

sgx_status_t sm4_ctr_encrypt(uint8_t *key,
                             uint8_t *cipherblob,
                             uint8_t *plaintext,
                             uint32_t plaintext_len,
                             uint8_t *iv)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int temp_len = 0;
    EVP_CIPHER_CTX *pctx = NULL;

    // Create and initialize pState
    if (!(pctx = EVP_CIPHER_CTX_new()))
    {
        log_e("Error: failed to initialize EVP_CIPHER_CTX\n");
        goto out;
    }
    // Initialize encrypt, key and ctr
    if (EVP_EncryptInit_ex(pctx, EVP_sm4_ctr(), NULL, key, iv) != 1)
    {
        log_e("Error: failed to initialize encrypt, key and ctr\n");
        goto out;
    }

    // 3. Encrypt the plaintext and obtain the encrypted output
    if (EVP_EncryptUpdate(pctx, cipherblob, &temp_len, plaintext, plaintext_len) != 1)
    {
        log_e("Error: failed to encrypt the plaintext\n");
        goto out;
    }

    // 4. Finalize the encryption
    if (EVP_EncryptFinal_ex(pctx, cipherblob + temp_len, &temp_len) != 1)
    {
        log_e("Error: failed to finalize the encryption\n");
        goto out;
    }

    ret = SGX_SUCCESS;

out:
    EVP_CIPHER_CTX_free(pctx);
    return ret;
}

sgx_status_t sm4_ctr_decrypt(uint8_t *key,
                             uint8_t *plaintext,
                             uint8_t *cipherblob,
                             uint32_t ciphertext_len,
                             uint8_t *iv)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int temp_len = 0;
    EVP_CIPHER_CTX *pctx = NULL;

    // Create and initialize ctx
    if (!(pctx = EVP_CIPHER_CTX_new()))
    {
        log_e("Error: failed to initialize EVP_CIPHER_CTX\n");
        goto out;
    }
    // Initialize decrypt, key and ctr
    if (!EVP_DecryptInit_ex(pctx, EVP_sm4_ctr(), NULL, (unsigned char *)key, iv))
    {
        log_e("Error: failed to initialize decrypt, key and ctr\n");
        goto out;
    }

    // Decrypt the ciphertext and obtain the decrypted output
    if (!EVP_DecryptUpdate(pctx, plaintext, &temp_len, cipherblob, ciphertext_len))
    {
        log_e("Error: failed to decrypt the ciphertext\n");
        goto out;
    }

    // Finalize the decryption:
    // - A positive return value indicates success;
    // - Anything else is a failure - the msg is not trustworthy.
    if (EVP_DecryptFinal_ex(pctx, plaintext + temp_len, &temp_len) <= 0)
    {
        log_e("Error: failed to finalize the decryption\n");
        goto out;
    }

    ret = SGX_SUCCESS;

out:
    EVP_CIPHER_CTX_free(pctx);
    return ret;
}

sgx_status_t sm4_cbc_encrypt(uint8_t *key,
                             uint8_t *cipherblob,
                             uint8_t *plaintext,
                             uint32_t plaintext_len,
                             uint8_t *iv)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int temp_len = 0;
    EVP_CIPHER_CTX *pctx = NULL;

    // Create and initialize ctx
    if (!(pctx = EVP_CIPHER_CTX_new()))
    {
        log_e("Error: failed to initialize EVP_CIPHER_CTX\n");
        goto out;
    }
    // Initialize encrypt, key and ctr
    if (EVP_EncryptInit_ex(pctx, EVP_sm4_cbc(), NULL, key, iv) != 1)
    {
        log_e("Error: failed to initialize encrypt, key and ctr\n");
        goto out;
    }

    // Encrypt the plaintext and obtain the encrypted output
    if (EVP_EncryptUpdate(pctx, cipherblob, &temp_len, plaintext, plaintext_len) != 1)
    {
        log_e("Error: failed to encrypt the plaintext\n");
        goto out;
    }

    // Finalize the encryption
    if (EVP_EncryptFinal_ex(pctx, cipherblob + temp_len, &temp_len) != 1)
    {
        log_e("Error: failed to finalize the encryption\n");
        goto out;
    }

    ret = SGX_SUCCESS;

out:
    EVP_CIPHER_CTX_free(pctx);
    return ret;
}

sgx_status_t sm4_cbc_decrypt(uint8_t *key,
                             uint8_t *plaintext,
                             uint32_t &actual_plaintext_len,
                             uint8_t *ciphertext,
                             uint32_t ciphertext_len,
                             uint8_t *iv)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int temp_len = 0;
    EVP_CIPHER_CTX *pctx = NULL;

    // Create and initialize ctx
    if (!(pctx = EVP_CIPHER_CTX_new()))
    {
        log_e("Error: failed to initialize EVP_CIPHER_CTX\n");
        goto out;
    }
    // Initialize decrypt, key and IV
    if (!EVP_DecryptInit_ex(pctx, EVP_sm4_cbc(), NULL, key, iv))
    {
        log_e("Error: failed to initialize decrypt, key and IV\n");
        goto out;
    }

    // Decrypt the ciphertext and obtain the decrypted output
    if (!EVP_DecryptUpdate(pctx, plaintext, &temp_len, ciphertext, ciphertext_len - 16))
    {
        log_e("Error: failed to decrypt the ciphertext\n");
        goto out;
    }

    actual_plaintext_len = temp_len;

    if (EVP_DecryptFinal_ex(pctx, plaintext + temp_len, &temp_len) <= 0)
    {
        log_e("Error: failed to finalize the decryption\n");
        goto out;
    }

    actual_plaintext_len += temp_len;

    ret = SGX_SUCCESS;

out:
    EVP_CIPHER_CTX_free(pctx);
    return ret;
}

sgx_status_t rsa_sign(EVP_PKEY *evpkey,
                      const EVP_MD *digestMode,
                      uint32_t padding_mode,
                      ehsm_message_type_t message_type,
                      const uint8_t *message,
                      uint32_t message_len,
                      uint8_t *signature,
                      uint32_t signature_len,
                      int saltlen)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    size_t temp_signature_size = 0;

    pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (pkey_ctx == NULL)
    {
        log_e("ecall rsa_sign generate pkey_ctx failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    switch (message_type)
    {
    case EH_DIGEST:
        if (message_len != EVP_MD_size(digestMode))
        {
            log_e("ecall digest size error.\n");
            goto out;
        }

        if (EVP_PKEY_sign_init(pkey_ctx) <= 0)
        {
            log_e("ecall rsa_sign EVP_PKEY_sign_init failed.\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, digestMode) <= 0)
        {
            log_e("ecall rsa_sign EVP_PKEY_CTX_set_signature_md failed.\n");
            goto out;
        }

        // set padding mode
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode) != 1)
        {
            log_e("ecall rsa_sign EVP_PKEY_CTX_set_rsa_padding failed.\n");
            goto out;
        }

        if (padding_mode == RSA_PKCS1_PSS_PADDING)
        {
            if (saltlen == -1)
            {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(digestMode)) != 1)
                {
                    log_e("ecall rsa_sign EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                    goto out;
                }
            }
            else
            {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, saltlen) != 1)
                {
                    log_e("ecall rsa_sign EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                    goto out;
                }
            }
        }

        if (EVP_PKEY_sign(pkey_ctx, NULL, &temp_signature_size, message, message_len) <= 0)
        {
            log_e("ecall rsa_sign EVP_PKEY_sign failed.\n");
            goto out;
        }

        if (EVP_PKEY_sign(pkey_ctx, signature, &temp_signature_size, message, message_len) <= 0)
        {
            log_e("ecall rsa_sign EVP_PKEY_sign failed.\n");
            goto out;
        }

        ret = SGX_SUCCESS;
        break;
    case EH_RAW:
        // verify digestmode and padding mode
        if (padding_mode == RSA_PKCS1_PSS_PADDING)
        {
            // https://android.googlesource.com/platform/system/keymaster/+/refs/heads/master/km_openssl/rsa_operation.cpp#264
            if (EVP_MD_size(digestMode) * 2 + 2 > (size_t)EVP_PKEY_size(evpkey))
            {
                log_e("ecall rsa_sign unsupported padding mode.\n");
                ret = SGX_ERROR_INVALID_PARAMETER;
                goto out;
            }
        }

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
        {
            log_e("ecall rsa_sign failed to create a EVP_MD_CTX.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            goto out;
        }

        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            log_e("ecall rsa_sign EVP_MD_CTX initialize failed.\n");
            goto out;
        }

        // Signature initialization, set digest mode
        EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);
        if (EVP_DigestSignInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            log_e("ecall rsa_sign EVP_DigestSignInit failed.\n");
            goto out;
        }

        // set padding mode
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode) != 1)
        {
            log_e("ecall rsa_sign EVP_PKEY_CTX_set_rsa_padding failed.\n");
            goto out;
        }

        if (padding_mode == RSA_PKCS1_PSS_PADDING)
        {
            if (saltlen == -1)
            {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(digestMode)) != 1)
                {
                    log_e("ecall rsa_sign EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                    goto out;
                }
            }
            else
            {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, saltlen) != 1)
                {
                    log_e("ecall rsa_sign EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                    goto out;
                }
            }
        }

        if (EVP_DigestSignUpdate(mdctx, message, message_len) != 1)
        {
            log_e("ecall rsa_sign EVP_DigestSignUpdate failed.\n");
            goto out;
        }

        if (EVP_DigestSignFinal(mdctx, NULL, &temp_signature_size) != 1)
        {
            log_e("ecall rsa_sign first EVP_DigestSignFinal failed.\n");
            goto out;
        }

        if (EVP_DigestSignFinal(mdctx, signature, &temp_signature_size) != 1)
        {
            log_e("ecall rsa_sign last EVP_DigestSignFinal failed.\n");
            goto out;
        }

        ret = SGX_SUCCESS;
        break;
    default:
        ret = SGX_ERROR_UNEXPECTED;
    }

out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_free(mdctx);

    return ret;
}

sgx_status_t rsa_verify(EVP_PKEY *evpkey,
                        const EVP_MD *digestMode,
                        uint32_t padding_mode,
                        ehsm_message_type_t message_type,
                        const uint8_t *message,
                        uint32_t message_len,
                        const uint8_t *signature,
                        uint32_t signature_len,
                        bool *result,
                        int saltlen)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    size_t temp_signature_size = 0;

    pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (pkey_ctx == NULL)
    {
        log_e("ecall rsa_verify generate pkey_ctx failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    switch (message_type)
    {
    case EH_DIGEST:
        if (EVP_PKEY_verify_init(pkey_ctx) <= 0)
        {
            log_e("ecall rsa_verify EVP_PKEY_sign_init failed.\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, digestMode) <= 0)
        {
            log_e("ecall rsa_verify EVP_PKEY_CTX_set_signature_md failed.\n");
            goto out;
        }
        // set padding mode
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode) != 1)
        {
            log_e("ecall rsa_verify EVP_PKEY_CTX_set_rsa_padding failed.\n");
            goto out;
        }

        if (padding_mode == RSA_PKCS1_PSS_PADDING)
        {
            if (saltlen == -1)
            {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(digestMode)) != 1)
                {
                    log_e("ecall rsa_verify EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                    goto out;
                }
            }
            else
            {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, saltlen) != 1)
                {
                    log_e("ecall rsa_verify EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                    goto out;
                }
            }
        }

        if (EVP_PKEY_verify(pkey_ctx, signature, signature_len, message, message_len) <= 0)
        {
            *result = false;
        }
        else
        {
            *result = true;
        }

        ret = SGX_SUCCESS;
        break;
    case EH_RAW:
        // verify digestmode and padding mode
        if (padding_mode == RSA_PKCS1_PSS_PADDING)
        {
            // https://android.googlesource.com/platform/system/keymaster/+/refs/heads/master/km_openssl/rsa_operation.cpp#264
            if (EVP_MD_size(digestMode) * 2 + 2 > (size_t)EVP_PKEY_size(evpkey))
            {
                log_e("ecall rsa_verify unsupported padding mode.\n");
                ret = SGX_ERROR_INVALID_PARAMETER;
                goto out;
            }
        }

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
        {
            log_e("ecall rsa_verify failed to create a EVP_MD_CTX.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            goto out;
        }

        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            log_e("ecall rsa_verify EVP_MD_CTX initialize failed.\n");
            goto out;
        }

        // verify initialization, set digest mode
        EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);
        if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            log_e("ecall rsa_verify EVP_DigestVerifyInit failed.\n");
            goto out;
        }

        // set padding mode
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode) != 1)
        {
            log_e("ecall rsa_verify EVP_PKEY_CTX_set_rsa_padding failed(%d).\n", padding_mode);
            goto out;
        }

        if (padding_mode == RSA_PKCS1_PSS_PADDING)
        {
            if (saltlen == -1)
            {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(digestMode)) != 1)
                {
                    log_e("ecall rsa_verify EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                    goto out;
                }
            }
            else
            {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, saltlen) != 1)
                {
                    log_e("ecall rsa_verify EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                    goto out;
                }
            }
        }

        // update verify
        if (EVP_DigestVerifyUpdate(mdctx, message, message_len) != 1)
        {
            log_e("ecall rsa_verify EVP_DigestVerifyUpdate failed.\n");
            goto out;
        }

        // start verify
        switch (EVP_DigestVerifyFinal(mdctx, signature, signature_len))
        {
        case 1:
            *result = true;
            break;
        case 0:
            // data digest did not match the original data or the signature had an invalid form
            *result = false;
            break;
        default:
            log_e("ecall rsa_verify EVP_DigestVerifyFinal failed.\n");
            goto out;
        }

        ret = SGX_SUCCESS;
        break;
    default:
        ret = SGX_ERROR_UNEXPECTED;
    }
out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_free(mdctx);

    return ret;
}

sgx_status_t ecc_sign(EVP_PKEY *evpkey,
                      const EVP_MD *digestMode,
                      ehsm_message_type_t message_type,
                      const uint8_t *message,
                      uint32_t message_len,
                      uint8_t *signature,
                      uint32_t *signature_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    EVP_PKEY_CTX *pkey_ctx = NULL;
    size_t temp_signature_size = 0;
    EVP_MD_CTX *mdctx = NULL;

    pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (pkey_ctx == NULL)
    {
        log_e("ecall ecc_sign EVP_PKEY_CTX_new failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    switch (message_type)
    {
    case EH_DIGEST:
        if (message_len != EVP_MD_size(digestMode))
        {
            log_e("ecall digest size error.\n");
            goto out;
        }

        if (EVP_PKEY_sign_init(pkey_ctx) <= 0)
        {
            log_e("ecall ecc_sign EVP_PKEY_sign_init failed.\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, digestMode) <= 0)
        {
            log_e("ecall ecc_sign EVP_PKEY_CTX_set_signature_md failed.\n");
            goto out;
        }

        if (EVP_PKEY_sign(pkey_ctx, NULL, &temp_signature_size, message, message_len) <= 0)
        {
            log_e("ecall ecc_sign EVP_PKEY_sign failed.\n");
            goto out;
        }

        if (EVP_PKEY_sign(pkey_ctx, signature, &temp_signature_size, message, message_len) <= 0)
        {
            log_e("ecall ecc_sign EVP_PKEY_sign failed.\n");
            goto out;
        }

        // return the exact length
        *signature_len = (uint32_t)temp_signature_size;

        ret = SGX_SUCCESS;
        break;
    case EH_RAW:
        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
        {
            log_e("ecall ecc_sign failed to create a EVP_MD_CTX.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            goto out;
        }

        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            log_e("ecall ecc_sign EVP_MD_CTX initialize failed.\n");
            goto out;
        }

        EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);
        if (EVP_DigestSignInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            log_e("ecall ecc_sign EVP_DigestSignInit failed.\n");
            goto out;
        }

        if (EVP_DigestSignUpdate(mdctx, message, message_len) != 1)
        {
            log_e("ecall ecc_sign EVP_DigestSignUpdate data failed.\n");
            goto out;
        }

        if (EVP_DigestSignFinal(mdctx, NULL, &temp_signature_size) != 1)
        {
            log_e("ecall ecc_sign EVP_DigestSignFinal1 failed.\n");
            goto out;
        }

        if (EVP_DigestSignFinal(mdctx, signature, &temp_signature_size) != 1)
        {
            log_e("ecall ecc_sign EVP_DigestSignFinal failed.\n");
            goto out;
        }

        // return the exact length
        *signature_len = (uint32_t)temp_signature_size;

        ret = SGX_SUCCESS;
        break;
    default:
        ret = SGX_ERROR_UNEXPECTED;
    }
out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_free(mdctx);

    return ret;
}

sgx_status_t ecc_verify(EVP_PKEY *evpkey,
                        const EVP_MD *digestMode,
                        ehsm_message_type_t message_type,
                        const uint8_t *message,
                        uint32_t message_len,
                        const uint8_t *signature,
                        uint32_t signature_len,
                        bool *result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX *mdctx = NULL;

    pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (pkey_ctx == NULL)
    {
        log_e("ecall ecc_verify failed to create a EVP_PKEY_CTX\n");
        goto out;
    }

    switch (message_type)
    {
    case EH_DIGEST:

        if (EVP_PKEY_verify_init(pkey_ctx) <= 0)
        {
            log_e("ecall ecc_verify EVP_PKEY_verify_init failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, digestMode) <= 0)
        {
            log_e("ecall ecc_verify EVP_PKEY_CTX_set_signature_md failed\n");
            goto out;
        }

        if (EVP_PKEY_verify(pkey_ctx, signature, signature_len, message, message_len) <= 0)
        {
            *result = false;
        }
        else
        {
            *result = true;
        }

        ret = SGX_SUCCESS;
        break;
    case EH_RAW:
        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
        {
            log_e("ecall ecc_verify failed to create a EVP_MD_CTX.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            goto out;
        }

        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            log_e("ecall ecc_verify EVP_MD_CTX initialize failed.\n");
            goto out;
        }

        EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);

        if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            log_e("ecall ecc_verify EVP_DigestVerifyInit failed.\n");
            goto out;
        }

        if (EVP_DigestVerifyUpdate(mdctx, message, message_len) != 1)
        {
            log_e("ecall ecc_verify EVP_DigestVerifyUpdate failed.\n");
            goto out;
        }

        switch (EVP_DigestVerifyFinal(mdctx, signature, signature_len))
        {
        case 1:
            *result = true;
            break;
        case 0:
            // tbs did not match the original data or the signature had an invalid form
            *result = false;
            break;
        default:
            log_e("ecall ecc_verify EVP_DigestVerifyFinal failed.\n");
            goto out;
        }
        ret = SGX_SUCCESS;
        break;

    default:
        ret = SGX_ERROR_UNEXPECTED;
    }

out:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(pkey_ctx);

    return ret;
}

sgx_status_t sm2_sign(EVP_PKEY *evpkey,
                      const EVP_MD *digestMode,
                      ehsm_message_type_t message_type,
                      const uint8_t *message,
                      uint32_t message_len,
                      uint8_t *signature,
                      uint32_t *signature_len,
                      const uint8_t *id,
                      uint32_t id_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    size_t temp_signature_size = 0;

    pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (pkey_ctx == NULL)
    {
        log_e("ecall sm2_sign failed to create a EVP_PKEY_CTX\n");
        goto out;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        log_e("ecall sm2_sign failed to create a EVP_MD_CTX.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    switch (message_type)
    {
    case EH_DIGEST:

        if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sm3(), NULL, evpkey))
        {
            log_e("ecall sm2_sign EVP_DigestSignInit failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set1_id(EVP_MD_CTX_pkey_ctx(mdctx), id, id_len) <= 0)
        {
            log_e("ecall sm2_sign EVP_PKEY_CTX_set1_id failed\n");
            goto out;
        }

        if (1 != EVP_DigestSign(mdctx, NULL, &temp_signature_size, message, message_len))
        {
            log_e("ecall sm2_sign EVP_DigestSign1 failed\n");
            goto out;
        }

        if (1 != EVP_DigestSign(mdctx, signature, &temp_signature_size, message, message_len))
        {
            log_e("ecall sm2_sign EVP_DigestSign2 failed\n");
            goto out;
        }

        // return the exact length
        *signature_len = (uint32_t)temp_signature_size;

        ret = SGX_SUCCESS;
        break;
    case EH_RAW:

        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            log_e("ecall sm2_sign EVP_MD_CTX initialize failed.\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set1_id(pkey_ctx, id, id_len) != 1)
        {
            log_e("ecall sm2_sign failed to set sm2_user_id to the EVP_PKEY_CTX\n");
            goto out;
        }

        EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);
        if (EVP_DigestSignInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            log_e("ecall sm2_sign EVP_DigestSignInit failed.\n");
            goto out;
        }

        if (EVP_DigestSignUpdate(mdctx, message, message_len) != 1)
        {
            log_e("ecall sm2_sign EVP_DigestSignUpdate data failed.\n");
            goto out;
        }

        if (EVP_DigestSignFinal(mdctx, NULL, &temp_signature_size) != 1)
        {
            log_e("ecall sm2_sign EVP_DigestSignFinal1 failed.\n");
            goto out;
        }

        if (EVP_DigestSignFinal(mdctx, signature, &temp_signature_size) != 1)
        {
            log_e("ecall sm2_sign EVP_DigestSignFinal failed.\n");
            goto out;
        }

        // return the exact length
        *signature_len = (uint32_t)temp_signature_size;

        ret = SGX_SUCCESS;
        break;

    default:
        ret = SGX_ERROR_UNEXPECTED;
    }
out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_free(mdctx);

    return ret;
}

sgx_status_t sm2_verify(EVP_PKEY *evpkey,
                        const EVP_MD *digestMode,
                        ehsm_message_type_t message_type,
                        const uint8_t *message,
                        uint32_t message_len,
                        const uint8_t *signature,
                        uint32_t signature_len,
                        bool *result,
                        const uint8_t *id,
                        uint32_t id_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (pkey_ctx == NULL)
    {
        log_e("ecall sm2_verify failed to create a EVP_PKEY_CTX\n");
        goto out;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        log_e("ecall sm2_verify failed to create a EVP_MD_CTX.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    switch (message_type)
    {
    case EH_DIGEST:

        if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sm3(), NULL, evpkey))
        {
            log_e("ecall sm2_verify EVP_DigestVerifyInit failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set1_id(EVP_MD_CTX_pkey_ctx(mdctx), id, id_len) <= 0)
        {
            log_e("ecall sm2_verify EVP_PKEY_CTX_set1_id failed\n");
            goto out;
        }

        if (1 != EVP_DigestVerify(mdctx, signature, signature_len, message, message_len))
        {
            *result = false;
        }
        else
        {
            *result = true;
        }

        ret = SGX_SUCCESS;
        break;
    case EH_RAW:

        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            log_e("ecall sm2_verify EVP_MD_CTX initialize failed.\n");
            goto out;
        }

        // set sm2 id and len to pkeyctx
        if (EVP_PKEY_CTX_set1_id(pkey_ctx, id, id_len) != 1)
        {
            log_e("ecall sm2_verify failed to set sm2_user_id to the EVP_PKEY_CTX\n");
            goto out;
        }

        EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);

        if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            log_e("ecall sm2_verify EVP_DigestVerifyInit failed.\n");
            goto out;
        }

        if (EVP_DigestVerifyUpdate(mdctx, message, message_len) != 1)
        {
            log_e("ecall sm2_verify EVP_DigestVerifyUpdate failed.\n");
            goto out;
        }

        switch (EVP_DigestVerifyFinal(mdctx, signature, signature_len))
        {
        case 1:
            *result = true;
            break;
        case 0:
            // tbs did not match the original data or the signature had an invalid form
            *result = false;
            break;
        default:
            log_e("ecall sm2_verify EVP_DigestVerifyFinal failed.\n");
            goto out;
        }
        ret = SGX_SUCCESS;
        break;

    default:
        ret = SGX_ERROR_UNEXPECTED;
    }

out:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_free(mdctx);

    return ret;
}