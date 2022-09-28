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
#include "openssl/err.h"

#include "key_operation.h"
#include "key_factory.h"

#define SM4_NO_PAD 0
#define SM4_PAD 1

using namespace std;

static char g_default_userid[] = "1234567812345678";
static size_t g_default_userid_len = sizeof(g_default_userid) - 1;

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

/**
 * @brief Get the block mode by keyspec
 * @param keyspec the type of key
 * @return const CHIPER* (openssl callback, tempoary)
 */
static const EVP_CIPHER *ehsm_get_symmetric_block_mode(ehsm_keyspec_t keyspec)
{
    switch (keyspec)
    {
    case EH_AES_GCM_128:
        return EVP_aes_128_gcm();
    case EH_AES_GCM_192:
        return EVP_aes_192_gcm();
    case EH_AES_GCM_256:
        return EVP_aes_256_gcm();
    case EH_SM4_CTR:
        return EVP_sm4_ctr();
    case EH_SM4_CBC:
        return EVP_sm4_cbc();
    default:
        return NULL;
    }
    return NULL;
}

/**
 * @brief Get the digest mode from cmk
 *
 * @param digestMode use the digestMode passed in by cmk to get the struct for key
 * @return const EVP_MD* (openssl callback, tempoary)
 */
static const EVP_MD *GetDigestMode(ehsm_digest_mode_t digestMode)
{
    switch (digestMode)
    {
    case EH_SHA_2_224:
        return EVP_sha224();
    case EH_SHA_2_256:
        return EVP_sha256();
    case EH_SHA_2_384:
        return EVP_sha384();
    case EH_SHA_2_512:
        return EVP_sha512();
    case EH_SM3:
        return EVP_sm3();
    default:
        return NULL;
    }
}

/**
 * @brief verify Padding Mode from cmk
 *
 * @param paddingMode the paddingMode passed in by cmk
 * @param digestMode the digestMode passed in by cmk
 * @param evpkey EVP_PKEY created by the context
 * @return [false] unsupported padding mode/ [true] supported padding mode
 */
static bool verifyPaddingMode(uint8_t paddingMode, const EVP_MD *digestMode, EVP_PKEY *evpkey)
{
    switch (paddingMode)
    {
    case EH_PAD_RSA_PKCS1:
        return true;
    case EH_PAD_RSA_NO:
        return false;
    case EH_PAD_RSA_PKCS1_OAEP:
        return false;
    case EH_PAD_RSA_PKCS1_PSS:
        if (EVP_MD_size(digestMode) * 2 + 2 > (size_t)EVP_PKEY_size(evpkey))
        {
            return false;
        }
        return true;
    default:
        return false;
    }
}

/**
 * @brief Check parameters and encrypted data
 * @param aad Additional data
 * @param cmk Key information
 * @param plaintext Data to be encrypted
 * @param cipherblob The information of ciphertext
 */
sgx_status_t ehsm_aes_gcm_encrypt(const ehsm_data_t *aad,
                                  const ehsm_keyblob_t *cmk,
                                  const ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int temp_len = 0;
    EVP_CIPHER_CTX *pState = NULL;

    /* this api only support for symmetric keys */
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

    /* calculate the ciphertext length */
    if (cipherblob->datalen == 0)
    {
        cipherblob->datalen = plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t enc_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (enc_key_size == UINT32_MAX || enc_key_size != keysize)
    {
        printf("enc_key_size:%d is not expected: %lu.\n", enc_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen < plaintext->datalen + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    uint8_t *mac = (uint8_t *)(cipherblob->data + plaintext->datalen + SGX_AESGCM_IV_SIZE);
    uint8_t *enc_key = (uint8_t *)malloc(keysize);
    if (enc_key == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = sgx_read_rand(iv, SGX_AESGCM_IV_SIZE);
    if (ret != SGX_SUCCESS)
    {
        printf("error generating IV\n");
        goto out;
    }

    ret = ehsm_parse_keyblob(enc_key, enc_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        printf("failed to decrypt key\n");
        goto out;
    }

    // Create and init ctx
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise encrypt/decrpty, key and IV
    if (1 != EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char *)enc_key, iv))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Provide AAD data if exist
    if (aad != NULL && aad->datalen > 0)
    {
        if (1 != EVP_EncryptUpdate(pState, NULL, &temp_len, aad->data, aad->datalen))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    if (plaintext->datalen > 0)
    {
        // Provide the message to be encrypted, and obtain the encrypted output.
        if (1 != EVP_EncryptUpdate(pState, cipherblob->data, &temp_len, plaintext->data, plaintext->datalen))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Finalise the encryption/decryption
    if (1 != EVP_EncryptFinal_ex(pState, cipherblob->data + temp_len, &temp_len))
    {
        ret = SGX_ERROR_MAC_MISMATCH;
        goto out;
    }

    // Get tag
    if (1 != EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_GET_TAG, SGX_AESGCM_MAC_SIZE, mac))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
out:
    if (pState)
    {
        EVP_CIPHER_CTX_free(pState);
    }
    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));
    SAFE_FREE(enc_key);
    return ret;
}

/**
 * @brief Check parameters and decrypted data
 * @param aad Additional data
 * @param cmk_blob Key information
 * @param cipherblob The ciphertext to be decrypted
 * @param plaintext Decrypted plaintext
 */
sgx_status_t ehsm_aes_gcm_decrypt(const ehsm_data_t *aad,
                                  const ehsm_keyblob_t *cmk,
                                  const ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t l_tag[SGX_AESGCM_MAC_SIZE];
    int temp_len = 0;
    EVP_CIPHER_CTX *pState = NULL;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_AES_GCM_192 &&
        cmk->metadata.keyspec != EH_AES_GCM_256)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* calculate the ciphertext length */
    if (plaintext->datalen == 0)
    {
        plaintext->datalen = cipherblob->datalen - EH_AES_GCM_IV_SIZE - EH_AES_GCM_MAC_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    uint32_t dec_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (dec_key_size == UINT32_MAX || dec_key_size != keysize)
    {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cipherblob->datalen < plaintext->datalen + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t *iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    uint8_t *mac = (uint8_t *)(cipherblob->data + plaintext->datalen + SGX_AESGCM_IV_SIZE);
    uint8_t *dec_key = (uint8_t *)malloc(keysize);
    if (dec_key == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(dec_key, dec_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        goto out;
    }

    // Autenthication Tag returned by Decrypt to be compared with Tag created during seal
    memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    memcpy(l_tag, mac, SGX_AESGCM_MAC_SIZE);

    // Create and initialise the context
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise decrypt, key and IV
    if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char *)dec_key, iv))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    if (aad != NULL && aad->datalen > 0)
    {
        if (!EVP_DecryptUpdate(pState, NULL, &temp_len, aad->data, aad->datalen))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Decrypt message, obtain the plaintext output
    if (!EVP_DecryptUpdate(pState, plaintext->data, &temp_len, cipherblob->data, plaintext->datalen))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Update expected tag value
    if (!EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_SET_TAG, SGX_AESGCM_MAC_SIZE, l_tag))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.
    if (EVP_DecryptFinal_ex(pState, plaintext->data + temp_len, &temp_len) <= 0)
    {
        ret = SGX_ERROR_MAC_MISMATCH;
        goto out;
    }
out:
    if (pState != NULL)
    {
        EVP_CIPHER_CTX_free(pState);
    }
    memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    memset_s(dec_key, sizeof(dec_key), 0, sizeof(dec_key));
    SAFE_FREE(dec_key);
    return ret;
}

/**
 * @brief Check parameters and encrypted data
 * @param cmk Key information
 * @param plaintext Data to be encrypted
 * @param cipherblob The information of ciphertext
 */
sgx_status_t ehsm_sm4_ctr_encrypt(const ehsm_keyblob_t *cmk,
                                  const ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int temp_len = 0;
    EVP_CIPHER_CTX *pState = NULL;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_SM4_CTR)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
    {
        return SGX_ERROR_UNEXPECTED;
    }
    /* calculate the ciphertext length */
    if (cipherblob->datalen == 0)
    {
        cipherblob->datalen = plaintext->datalen + SGX_SM4_IV_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t enc_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (enc_key_size == UINT32_MAX || enc_key_size != keysize)
    {
        printf("enc_key_size:%d is not expected: %lu.\n", enc_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen < plaintext->datalen + SGX_SM4_IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    uint8_t *enc_key = (uint8_t *)malloc(keysize);
    if (enc_key == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = sgx_read_rand(iv, SGX_SM4_IV_SIZE);
    if (ret != SGX_SUCCESS)
    {
        printf("error generating IV\n");
        goto out;
    }

    ret = ehsm_parse_keyblob(enc_key, enc_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        printf("failed to decrypt key\n");
        goto out;
    }
    // Create and initialize pState
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        printf("Error: fail to initialize EVP_CIPHER_CTX\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    // Initialize encrypt, key and ctr
    if (EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char *)enc_key, iv) != 1)
    {
        printf("Error: fail to initialize encrypt, key and ctr\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // 3. Encrypt the plaintext and obtain the encrypted output
    if (EVP_EncryptUpdate(pState, cipherblob->data, &temp_len, plaintext->data, plaintext->datalen) != 1)
    {
        printf("Error: fail to encrypt the plaintext\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // 4. Finalize the encryption
    if (EVP_EncryptFinal_ex(pState, cipherblob->data + temp_len, &temp_len) != 1)
    {
        printf("Error: fail to finalize the encryption\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

out:
    if (pState)
    {
        EVP_CIPHER_CTX_free(pState);
    }
    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));
    SAFE_FREE(enc_key);
    return ret;
}

sgx_status_t ehsm_sm4_ctr_decrypt(const ehsm_keyblob_t *cmk,
                                  const ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int temp_len = 0;
    EVP_CIPHER_CTX *pState = NULL;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_SM4_CTR)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* calculate the ciphertext length */
    if (plaintext->datalen == 0)
    {
        plaintext->datalen = cipherblob->datalen - SGX_SM4_IV_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    uint32_t dec_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (dec_key_size == UINT32_MAX || dec_key_size != keysize)
    {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cipherblob->datalen < plaintext->datalen + SGX_SM4_IV_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t *iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    uint8_t *dec_key = (uint8_t *)malloc(keysize);
    if (dec_key == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(dec_key, dec_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        printf("error(%d) unsealing key.\n", ret);
        goto out;
    }

    // Create and initialize ctx
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        printf("Error: fail to initialize EVP_CIPHER_CTX\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    // Initialize decrypt, key and ctr
    if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char *)dec_key, iv))
    {
        printf("Error: fail to initialize decrypt, key and ctr\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Decrypt the ciphertext and obtain the decrypted output
    if (!EVP_DecryptUpdate(pState, plaintext->data, &temp_len, cipherblob->data, plaintext->datalen))
    {
        printf("Error: fail to decrypt the ciphertext\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Finalize the decryption:
    // - A positive return value indicates success;
    // - Anything else is a failure - the msg is not trustworthy.
    if (EVP_DecryptFinal_ex(pState, plaintext->data + temp_len, &temp_len) <= 0)
    {
        printf("Error: fail to finalize the decryption\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

out:
    if (pState != NULL)
    {
        EVP_CIPHER_CTX_free(pState);
    }
    memset_s(dec_key, sizeof(dec_key), 0, sizeof(dec_key));
    SAFE_FREE(dec_key);
    return ret;
}

sgx_status_t ehsm_sm4_cbc_encrypt(const ehsm_keyblob_t *cmk,
                                  const ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int temp_len = 0;
    int pad = -1;
    uint8_t *iv = NULL;
    EVP_CIPHER_CTX *pState = NULL;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_SM4_CBC)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    /* calculate the ciphertext length */
    if (cipherblob->datalen == 0)
    {
        if (plaintext->datalen % 16 != 0)
        {
            cipherblob->datalen = (plaintext->datalen / 16 + 1) * 16 + SGX_SM4_IV_SIZE;
            return SGX_SUCCESS;
        }
        cipherblob->datalen = plaintext->datalen + SGX_SM4_IV_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t enc_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (enc_key_size == UINT32_MAX || enc_key_size != keysize)
    {
        printf("enc_key_size:%d is not expected: %lu.\n", enc_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen < plaintext->datalen + SGX_SM4_IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext->datalen % 16 != 0 &&
        (cipherblob->datalen < (plaintext->datalen / 16 + 1) * 16 + SGX_SM4_IV_SIZE))
        return SGX_ERROR_UNEXPECTED;

    if (plaintext->datalen % 16 == 0 &&
        (cipherblob->datalen < plaintext->datalen + SGX_SM4_IV_SIZE))
        return SGX_ERROR_UNEXPECTED;

    if (plaintext->datalen % 16 != 0)
    {
        iv = (uint8_t *)(cipherblob->data + ((plaintext->datalen / 16) + 1) * 16);
    }
    else
    {
        iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    }
    uint8_t *enc_key = (uint8_t *)malloc(keysize);
    if (enc_key == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = sgx_read_rand(iv, SGX_SM4_IV_SIZE);
    if (ret != SGX_SUCCESS)
    {
        printf("error generating IV\n");
        goto out;
    }

    ret = ehsm_parse_keyblob(enc_key, enc_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        printf("failed to decrypt key\n");
        goto out;
    }

    // set padding mode
    pad = (plaintext->datalen % 16 == 0) ? SM4_NO_PAD : SM4_PAD;

    // Create and initialize ctx
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        printf("Error: fail to initialize EVP_CIPHER_CTX\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    // Initialize encrypt, key and ctr
    if (EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char *)enc_key, iv) != 1)
    {
        printf("Error: fail to initialize encrypt, key and ctr\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (EVP_CIPHER_CTX_set_padding(pState, pad) != 1)
    {
        printf("Error: fail to set padding\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Encrypt the plaintext and obtain the encrypted output
    if (EVP_EncryptUpdate(pState, cipherblob->data, &temp_len, plaintext->data, plaintext->datalen) != 1)
    {
        printf("Error: fail to encrypt the plaintext\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    // Finalize the encryption
    if (EVP_EncryptFinal_ex(pState, cipherblob->data + temp_len, &temp_len) != 1)
    {
        printf("Error: fail to finalize the encryption\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

out:
    if (pState)
    {
        EVP_CIPHER_CTX_free(pState);
    }
    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));
    SAFE_FREE(enc_key);
    return ret;
}

sgx_status_t ehsm_sm4_cbc_decrypt(const ehsm_keyblob_t *cmk,
                                  const ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int temp_len = 0;
    int pad = -1;
    EVP_CIPHER_CTX *pState = NULL;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_SM4_CBC)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* calculate the ciphertext length */
    if (plaintext->datalen == 0)
    {
        plaintext->datalen = cipherblob->datalen - SGX_SM4_IV_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    uint32_t dec_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (dec_key_size == UINT32_MAX || dec_key_size != keysize)
    {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cipherblob->datalen < plaintext->datalen + SGX_SM4_IV_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t *iv = (uint8_t *)(cipherblob->data + cipherblob->datalen - SGX_SM4_IV_SIZE);
    uint8_t *dec_key = (uint8_t *)malloc(keysize);
    if (dec_key == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(dec_key, dec_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        goto out;
    }
    pad = (plaintext->datalen % 16 == 0) ? 0 : 1;
    // Create and initialize ctx
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        printf("Error: fail to initialize EVP_CIPHER_CTX\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    // Initialize decrypt, key and IV
    if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char *)dec_key, iv))
    {
        printf("Error: fail to initialize decrypt, key and IV\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (EVP_CIPHER_CTX_set_padding(pState, pad) != 1)
    {
        printf("Error: fail to set padding\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Decrypt the ciphertext and obtain the decrypted output
    if (!EVP_DecryptUpdate(pState, plaintext->data, &temp_len, cipherblob->data, cipherblob->datalen - 16))
    {
        printf("Error: fail to decrypt the ciphertext\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Finalize the decryption:
    // If length of decrypted data is integral multiple of 16, do not execute EVP_DecryptFinal_ex(), or it will fail to decrypt
    // - A positive return value indicates success;
    // - Anything else is a failure - the plaintext is not trustworthy.
    if (plaintext->datalen % 16 != 0)
    {
        if (EVP_DecryptFinal_ex(pState, plaintext->data + temp_len, &temp_len) <= 0)
        {
            printf("Error: fail to finalize the decryption\n");
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }
out:
    if (pState != NULL)
    {
        EVP_CIPHER_CTX_free(pState);
    }
    memset_s(dec_key, sizeof(dec_key), 0, sizeof(dec_key));
    SAFE_FREE(dec_key);
    return ret;
}

sgx_status_t ehsm_rsa_encrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *rsa_keypair = NULL;
    BIO *bio = NULL;
    RSA *rsa_pubkey = NULL;

    // load rsa public key
    rsa_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (rsa_keypair == NULL)
    {
        goto out;
    }

    ret = ehsm_parse_keyblob(rsa_keypair, cmk->keybloblen,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    bio = BIO_new_mem_buf(rsa_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load public key pem\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // make encryption
    PEM_read_bio_RSA_PUBKEY(bio, &rsa_pubkey, NULL, NULL);
    if (rsa_pubkey == NULL)
    {
        printf("failed to load rsa key\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (ciphertext->datalen == 0)
    {
        ciphertext->datalen = RSA_size(rsa_pubkey);
        ret = SGX_SUCCESS;
        goto out;
    }
    if (RSA_public_encrypt(plaintext->datalen, plaintext->data, ciphertext->data, rsa_pubkey, cmk->metadata.padding_mode) != RSA_size(rsa_pubkey))
    {
        printf("failed to make rsa encryption\n");
        goto out;
    }

    ret = SGX_SUCCESS;
out:
    BIO_free(bio);
    RSA_free(rsa_pubkey);
    SAFE_FREE(rsa_keypair);

    return ret;
}

sgx_status_t ehsm_sm2_encrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *sm2_keypair = NULL;
    BIO *bio = NULL;
    RSA *sm2_pubkey = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ectx = NULL;

    // load sm2 public key
    sm2_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (sm2_keypair == NULL)
    {
        goto out;
    }

    ret = ehsm_parse_keyblob(sm2_keypair, cmk->keybloblen,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    bio = BIO_new_mem_buf(sm2_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load public key pem\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // make encryption
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pkey == NULL)
    {
        printf("failed to load sm2 key\n");
        goto out;
    }
    if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ectx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ectx == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (EVP_PKEY_encrypt_init(ectx) != 1)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    size_t strLen;
    if (EVP_PKEY_encrypt(ectx, NULL, &strLen, plaintext->data, (size_t)plaintext->datalen) <= 0)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (ciphertext->datalen == 0)
    {
        ciphertext->datalen = strLen;
        ret = SGX_SUCCESS;
        goto out;
    }

    if (plaintext->data != NULL)
    {
        if (EVP_PKEY_encrypt(ectx, ciphertext->data, &strLen, plaintext->data, (size_t)plaintext->datalen) <= 0)
        {
            printf("failed to make sm2 encryption\n");
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }
    else
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    ret = SGX_SUCCESS;
out:
    BIO_free(bio);
    RSA_free(sm2_pubkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ectx);
    SAFE_FREE(sm2_keypair);

    return ret;
}

sgx_status_t ehsm_rsa_decrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *ciphertext,
                              ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *rsa_keypair = NULL;
    BIO *bio = NULL;
    RSA *rsa_prikey = NULL;

    // load private key
    rsa_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (rsa_keypair == NULL)
    {
        goto out;
    }

    ret = ehsm_parse_keyblob(rsa_keypair, cmk->keybloblen,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    bio = BIO_new_mem_buf(rsa_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load key pem\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    PEM_read_bio_RSAPrivateKey(bio, &rsa_prikey, NULL, NULL);
    if (rsa_prikey == NULL)
    {
        printf("failed to load private key\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (plaintext->datalen == 0)
    {
        uint8_t *temp_plaintext = (uint8_t *)malloc(RSA_size(rsa_prikey));
        plaintext->datalen = RSA_private_decrypt(ciphertext->datalen, ciphertext->data, temp_plaintext, rsa_prikey, cmk->metadata.padding_mode);
        ret = SGX_SUCCESS;
        goto out;
    }

    if (!RSA_private_decrypt(ciphertext->datalen, ciphertext->data, plaintext->data, rsa_prikey, cmk->metadata.padding_mode))
    {
        printf("failed to make rsa decrypt\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

out:
    BIO_free(bio);
    RSA_free(rsa_prikey);
    SAFE_FREE(rsa_keypair);

    return ret;
}

sgx_status_t ehsm_sm2_decrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *ciphertext,
                              ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *sm2_keypair = NULL;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *dctx = NULL;

    // load private key
    sm2_keypair = (uint8_t *)malloc(cmk->keybloblen);
    ret = ehsm_parse_keyblob(sm2_keypair, cmk->keybloblen,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    bio = BIO_new_mem_buf(sm2_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load key pem\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL)
    {
        printf("failed to load sm2 key\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // make decryption and compute plaintext length
    if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (!(dctx = EVP_PKEY_CTX_new(pkey, NULL)))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (EVP_PKEY_decrypt_init(dctx) != 1)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (plaintext->datalen == 0)
    {
        size_t strLen;
        if (EVP_PKEY_decrypt(dctx, NULL, &strLen, ciphertext->data, (size_t)ciphertext->datalen) != 1)
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
        plaintext->datalen = strLen;
        ret = SGX_SUCCESS;
        goto out;
    }

    if (ciphertext->data != NULL)
    {
        size_t strLen = plaintext->datalen;
        if (EVP_PKEY_decrypt(dctx, plaintext->data, &strLen, ciphertext->data, (size_t)ciphertext->datalen) != 1)
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }
    else
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

out:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(dctx);
    SAFE_FREE(sm2_keypair);

    return ret;
}

/**
 * @brief make rsa sign with the designated digest mode and padding mode
 * digest mode and padding mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param data data to be signed
 * @param signature used to receive signature
 * @return sgx_status_t
 */
sgx_status_t ehsm_rsa_sign(const ehsm_keyblob_t *cmk,
                           const ehsm_data_t *data,
                           ehsm_data_t *signature)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *rsa_keypair = NULL;
    BIO *bio = NULL;
    RSA *rsa_prikey = NULL;
    EVP_PKEY *evpkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    size_t temp_signature_size = 0;
    // Get Digest Mode
    const EVP_MD *digestMode = GetDigestMode(cmk->metadata.digest_mode);
    if (digestMode == NULL)
    {
        printf("ecall rsa_sign digest Mode error.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    // load private key
    rsa_keypair = (uint8_t *)malloc(cmk->keybloblen);
    ret = ehsm_parse_keyblob(rsa_keypair, cmk->keybloblen,
                                (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    ret = SGX_ERROR_UNEXPECTED;

    bio = BIO_new_mem_buf(rsa_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load rsa key pem\n");
        goto out;
    }

    PEM_read_bio_RSAPrivateKey(bio, &rsa_prikey, NULL, NULL);
    if (rsa_prikey == NULL)
    {
        printf("failed to load rsa key\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    evpkey = EVP_PKEY_new();
    if (evpkey == NULL)
    {
        printf("ecall rsa_sign generate evpkey failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    // use EVP_PKEY store RSA private key
    if (EVP_PKEY_set1_RSA(evpkey, rsa_prikey) != 1)
    {
        printf("ecall rsa_sign fail to set the evpkey by RSA_KEY\n");
        goto out;
    }
    // verify Padding Mode
    if (!verifyPaddingMode(cmk->metadata.padding_mode, digestMode, evpkey))
    {
        printf("ecall rsa_sign unsupported padding mode.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        printf("ecall rsa_sign fail to create a EVP_MD_CTX.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_MD_CTX_init(mdctx) != 1)
    {
        printf("ecall rsa_sign EVP_MD_CTX initialize failed.\n");
        goto out;
    }
    // Signature initialization, set digest mode
    if (EVP_DigestSignInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
    {
        printf("ecall rsa_sign EVP_DigestSignInit failed.\n");
        goto out;
    }
    // set padding mode
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, cmk->metadata.padding_mode) != 1)
    {
        printf("ecall rsa_sign EVP_PKEY_CTX_set_rsa_padding failed.\n");
        goto out;
    }
    if (cmk->metadata.padding_mode == RSA_PKCS1_PSS_PADDING)
    {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(digestMode)) != 1)
        {
            printf("ecall rsa_sign EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
            goto out;
        }
    }
    // update sign
    if (EVP_DigestUpdate(mdctx, data->data, data->datalen) != 1)
    {
        printf("ecall rsa_sign EVP_DigestSignUpdate failed.\n");
        goto out;
    }
    // start sign
    if (EVP_DigestSignFinal(mdctx, NULL, &temp_signature_size) != 1)
    {
        printf("ecall rsa_sign first EVP_DigestSignFinal failed.\n");
        goto out;
    }
    if (EVP_DigestSignFinal(mdctx, signature->data, &temp_signature_size) != 1)
    {
        printf("ecall rsa_sign last EVP_DigestSignFinal failed.\n");
        goto out;
    }

    ret = SGX_SUCCESS;
    
out:
    RSA_free(rsa_prikey);
    BIO_free(bio);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    SAFE_FREE(rsa_keypair);

    return ret;
}

/**
 * @brief make rsa verify with the designated digest mode and padding mode
 * digest mode and padding mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param data data to be signed
 * @param signature generated signature
 * @param result match result
 * @return sgx_status_t
 */
sgx_status_t ehsm_rsa_verify(const ehsm_keyblob_t *cmk,
                             const ehsm_data_t *data,
                             const ehsm_data_t *signature,
                             bool *result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *rsa_keypair = NULL;
    BIO *bio = NULL;
    RSA *rsa_pubkey = NULL;
    EVP_PKEY *evpkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    // get digest mode
    const EVP_MD *digestMode = GetDigestMode(cmk->metadata.digest_mode);
    if (digestMode == NULL)
    {
        printf("ecall rsa_verify digestMode error.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    // load rsa public key
    rsa_keypair = (uint8_t *)malloc(cmk->keybloblen);

    ret = ehsm_parse_keyblob(rsa_keypair, cmk->keybloblen,
                                (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    ret = SGX_ERROR_UNEXPECTED;

    bio = BIO_new_mem_buf(rsa_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load rsa key pem\n");
        goto out;
    }
    PEM_read_bio_RSA_PUBKEY(bio, &rsa_pubkey, NULL, NULL);
    if (rsa_pubkey == NULL)
    {
        printf("failed to load rsa key\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    evpkey = EVP_PKEY_new();
    if (evpkey == NULL)
    {
        printf("ecall rsa_verify generate evpkey failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    // use EVP_PKEY store RSA public key
    if (EVP_PKEY_set1_RSA(evpkey, rsa_pubkey) != 1)
    {
        printf("ecall rsa_verify fail to set the evpkey by RSA_KEY\n");
        goto out;
    }

    // verify Padding Mode
    if (!verifyPaddingMode(cmk->metadata.padding_mode, digestMode, evpkey))
    {
        printf("ecall rsa_verify unsupported padding mode.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        printf("ecall rsa_verify fail to create a EVP_MD_CTX.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_MD_CTX_init(mdctx) != 1)
    {
        printf("ecall rsa_verify EVP_MD_CTX initialize failed.\n");
        goto out;
    }
    // verify initialization, set digest mode
    if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
    {
        printf("ecall rsa_verify EVP_DigestVerifyInit failed.\n");
        goto out;
    }
    // set padding mode
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, cmk->metadata.padding_mode) != 1)
    {
        printf("ecall rsa_verify EVP_PKEY_CTX_set_rsa_padding failed.\n");
        goto out;
    }
    if (cmk->metadata.padding_mode == RSA_PKCS1_PSS_PADDING)
    {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(digestMode)) != 1)
        {
            printf("ecall rsa_verify EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
            goto out;
        }
    }
    // update verify
    if (EVP_DigestVerifyUpdate(mdctx, data->data, data->datalen) != 1)
    {
        printf("ecall rsa_verify EVP_DigestVerifyUpdate failed.\n");
        goto out;
    }
    // start verify
    if (EVP_DigestVerifyFinal(mdctx, signature->data, signature->datalen) != 1)
    {
        printf("ecall rsa_verify EVP_DigestVerifyFinal failed.\n");
        goto out;
    }

    ret = SGX_SUCCESS;

out:
    RSA_free(rsa_pubkey);
    BIO_free(bio);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    SAFE_FREE(rsa_keypair);

    if (ret != SGX_SUCCESS)
    {
        *result = false;
    }
    else
    {
        *result = true;
    }
    return ret;
}

sgx_status_t ehsm_ecc_encrypt(const ehsm_keyblob_t *cmk)
{
}

sgx_status_t ehsm_ecc_decrypt(const ehsm_keyblob_t *cmk)
{
}

/**
 * @brief make ec sign with the designated digest mode
 * digest mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param data data to be signed
 * @param signature used to receive signature
 * @return sgx_status_t
 */
sgx_status_t ehsm_ecc_sign(const ehsm_keyblob_t *cmk,
                           const ehsm_data_t *data,
                           ehsm_data_t *signature)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *ec_keypair = NULL;
    BIO *bio = NULL;
    EVP_PKEY *evpkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EC_KEY *ec_key = NULL;
    size_t temp_signature_size = 0;

    const EVP_MD *digestMode = GetDigestMode(cmk->metadata.digest_mode);
    if (digestMode == NULL)
    {
        printf("ecall ec_sign digestMode error.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    ec_keypair = (uint8_t *)malloc(cmk->keybloblen);
    ret = ehsm_parse_keyblob(ec_keypair, cmk->keybloblen,
                                (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    ret = SGX_ERROR_UNEXPECTED;

    bio = BIO_new_mem_buf(ec_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load ecc key pem\n");
        goto out;
    }

    PEM_read_bio_ECPrivateKey(bio, &ec_key, NULL, NULL);
    if (ec_key == NULL)
    {
        printf("failed to load ecc key\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    evpkey = EVP_PKEY_new();
    if (evpkey == NULL)
    {
        printf("ecall ecc_sign generate evpkey failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(evpkey, ec_key) != 1)
    {
        printf("ecall ecc_sign fail to set the evpkey by EC_KEY\n");
        goto out;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        printf("ecall ec_sign fail to create a EVP_MD_CTX.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_MD_CTX_init(mdctx) != 1)
    {
        printf("ecall ec_sign EVP_MD_CTX initialize failed.\n");
        goto out;
    }

    if (EVP_DigestSignInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
    {
        printf("ecall ec_sign EVP_DigestSignInit failed.\n");
        goto out;
    }

    if (EVP_DigestUpdate(mdctx, data->data, data->datalen) != 1)
    {
        printf("ecall ec_sign EVP_DigestSignUpdate failed.\n");
        goto out;
    }
    if (EVP_DigestSignFinal(mdctx, NULL, &temp_signature_size) != 1)
    {
        printf("ecall ec_sign EVP_DigestSignFinal1 failed.\n");
        goto out;
    }
    if (EVP_DigestSignFinal(mdctx, signature->data, &temp_signature_size) != 1)
    {
        printf("ecall ec_sign EVP_DigestSignFinal failed.\n");
        goto out;
    }
    // return the exact length
    signature->datalen = (uint32_t)temp_signature_size;

    ret = SGX_SUCCESS;

out:

    BIO_free(bio);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    SAFE_FREE(ec_keypair);

    return ret;
}

/**
 * @brief make ec verify with the designated digest mode
 * digest mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param data data to be signed
 * @param signature generated signature
 * @param result match result
 * @return sgx_status_t
 */
sgx_status_t ehsm_ecc_verify(const ehsm_keyblob_t *cmk,
                             const ehsm_data_t *data,
                             const ehsm_data_t *signature,
                             bool *result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *ec_keypair = NULL;
    BIO *bio = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY *evpkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    const EVP_MD *digestMode = GetDigestMode(cmk->metadata.digest_mode);
    if (digestMode == NULL)
    {
        printf("ecall ec_verify digestMode error.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    ec_keypair = (uint8_t *)malloc(cmk->keybloblen);

    ret = ehsm_parse_keyblob(ec_keypair, cmk->keybloblen,
                                (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;
    
    ret = SGX_ERROR_UNEXPECTED;

    bio = BIO_new_mem_buf(ec_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load ec key pem\n");
        goto out;
    }
    PEM_read_bio_EC_PUBKEY(bio, &ec_key, NULL, NULL);
    if (ec_key == NULL)
    {
        printf("failed to load ec key\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    evpkey = EVP_PKEY_new();
    if (evpkey == NULL)
    {
        printf("ecall ec_verify generate evpkey failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(evpkey, ec_key) != 1)
    {
        printf("ecall ec_verify fail to set the evpkey by RSA_KEY\n");
        goto out;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        printf("ecall ec_verify fail to create a EVP_MD_CTX.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_MD_CTX_init(mdctx) != 1)
    {
        printf("ecall ec_verify EVP_MD_CTX initialize failed.\n");
        goto out;
    }
    if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
    {
        printf("ecall ec_verify EVP_DigestVerifyInit failed.\n");
        goto out;
    }

    if (EVP_DigestVerifyUpdate(mdctx, data->data, data->datalen) != 1)
    {
        printf("ecall ec_verify EVP_DigestVerifyUpdate failed.\n");
        goto out;
    }
    if (EVP_DigestVerifyFinal(mdctx, signature->data, signature->datalen) != 1)
    {
        printf("ecall ec_verify EVP_DigestVerifyFinal failed.\n");
        goto out;
    }

    ret = SGX_SUCCESS;

out:
    BIO_free(bio);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    SAFE_FREE(ec_keypair);

    if (ret != SGX_SUCCESS)
    {
        *result = false;
    }
    else
    {
        *result = true;
    }

    return ret;
}

/**
 * @brief make sm2 sign with the designated digest mode
 * digest mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param data data to be signed
 * @param signature used to receive signature
 * @return sgx_status_t
 */
sgx_status_t ehsm_sm2_sign(const ehsm_keyblob_t *cmk,
                           const ehsm_data_t *data,
                           ehsm_data_t *signature)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *ec_keypair = NULL;
    BIO *bio = NULL;
    EVP_PKEY *evpkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EC_KEY *ec_key = NULL;
    size_t temp_signature_size = 0;

    const EVP_MD *digestMode = GetDigestMode(cmk->metadata.digest_mode);
    if (digestMode == NULL)
    {
        printf("ecall sm2_sign digestMode error.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    ec_keypair = (uint8_t *)malloc(cmk->keybloblen);
    ret = ehsm_parse_keyblob(ec_keypair, cmk->keybloblen,
                                (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    ret = SGX_ERROR_UNEXPECTED;

    bio = BIO_new_mem_buf(ec_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load ec key pem\n");
        goto out;
    }

    PEM_read_bio_ECPrivateKey(bio, &ec_key, NULL, NULL);
    if (ec_key == NULL)
    {
        printf("failed to load ec key\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    evpkey = EVP_PKEY_new();
    if (evpkey == NULL)
    {
        printf("ecall sm2_sign generate evpkey failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(evpkey, ec_key) != 1)
    {
        printf("ecall sm2_sign fail to set the evpkey by EC_KEY\n");
        goto out;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        printf("ecall sm2_sign fail to create a EVP_MD_CTX.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_MD_CTX_init(mdctx) != 1)
    {
        printf("ecall sm2_sign EVP_MD_CTX initialize failed.\n");
        goto out;
    }

    // set sm2 evp pkey
    if (EVP_PKEY_set_alias_type(evpkey, EVP_PKEY_SM2) != 1)
    {
        printf("ecall sm2_sign fail to modify the evpkey to use SM2\n");
        goto out;
    }
    pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (pkey_ctx == NULL)
    {
        printf("ecall sm2_sign fail to create a EVP_PKEY_CTX\n");
        goto out;
    }
    if (EVP_PKEY_CTX_set1_id(pkey_ctx, g_default_userid, g_default_userid_len) != 1)
    {
        printf("ecall sm2_sign fail to set sm2_user_id to the EVP_PKEY_CTX\n");
        goto out;
    }
    EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);

    if (EVP_DigestSignInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
    {
        printf("ecall sm2_sign EVP_DigestSignInit failed.\n");
        goto out;
    }

    if (EVP_DigestUpdate(mdctx, data->data, data->datalen) != 1)
    {
        printf("ecall sm2_sign EVP_DigestSignUpdate failed.\n");
        goto out;
    }
    if (EVP_DigestSignFinal(mdctx, NULL, &temp_signature_size) != 1)
    {
        printf("ecall sm2_sign EVP_DigestSignFinal1 failed.\n");
        goto out;
    }
    if (EVP_DigestSignFinal(mdctx, signature->data, &temp_signature_size) != 1)
    {
        printf("ecall sm2_sign EVP_DigestSignFinal failed.\n");
        goto out;
    }
    // return the exact length
    signature->datalen = (uint32_t)temp_signature_size;

    ret = SGX_SUCCESS;


 out:
    BIO_free(bio);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    SAFE_FREE(ec_keypair);

    return ret;
}

/**
 * @brief make sm2 verify with the designated digest mode
 * digest mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param data data to be signed
 * @param signature generated signature
 * @param result match result
 * @return sgx_status_t
 */
sgx_status_t ehsm_sm2_verify(const ehsm_keyblob_t *cmk,
                             const ehsm_data_t *data,
                             const ehsm_data_t *signature,
                             bool *result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *ec_keypair = NULL;
    BIO *bio = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY *evpkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    const EVP_MD *digestMode = GetDigestMode(cmk->metadata.digest_mode);
    if (digestMode == NULL)
    {
        printf("ecall sm2_verify digestMode error.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    ec_keypair = (uint8_t *)malloc(cmk->keybloblen);

    ret = ehsm_parse_keyblob(ec_keypair, cmk->keybloblen,
                                (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    ret = SGX_ERROR_UNEXPECTED;

    bio = BIO_new_mem_buf(ec_keypair, -1); // use -1 to auto compute length
    if (bio == NULL)
    {
        printf("failed to load ec key pem\n");
        goto out;
    }
    PEM_read_bio_EC_PUBKEY(bio, &ec_key, NULL, NULL);
    if (ec_key == NULL)
    {
        printf("failed to load ec key\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    evpkey = EVP_PKEY_new();
    if (evpkey == NULL)
    {
        printf("ecall sm2_verify generate evpkey failed.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(evpkey, ec_key) != 1)
    {
        printf("ecall sm2_verify fail to set the evpkey by RSA_KEY\n");
        goto out;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        printf("ecall sm2_verify fail to create a EVP_MD_CTX.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (EVP_MD_CTX_init(mdctx) != 1)
    {
        printf("ecall sm2_verify EVP_MD_CTX initialize failed.\n");
        goto out;
    }

    // set sm2 evp pkey
    if (EVP_PKEY_set_alias_type(evpkey, EVP_PKEY_SM2) != 1)
    {
        printf("ecall sm2_verify fail to modify the evpkey to use SM2\n");
        goto out;
    }
    pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (pkey_ctx == NULL)
    {
        printf("ecall sm2_verify fail to create a EVP_PKEY_CTX\n");
        goto out;
    }
    // set sm2 id and len to pkeyctx
    if (EVP_PKEY_CTX_set1_id(pkey_ctx, g_default_userid, g_default_userid_len) != 1)
    {
        printf("ecall sm2_verify fail to set sm2_user_id to the EVP_PKEY_CTX\n");
        goto out;
    }
    EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);

    if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
    {
        printf("ecall sm2_verify EVP_DigestVerifyInit failed.\n");
        goto out;
    }

    if (EVP_DigestVerifyUpdate(mdctx, data->data, data->datalen) != 1)
    {
        printf("ecall sm2_verify EVP_DigestVerifyUpdate failed.\n");
        goto out;
    }
    if (EVP_DigestVerifyFinal(mdctx, signature->data, signature->datalen) != 1)
    {
        printf("ecall sm2_verify EVP_DigestVerifyFinal failed.\n");
        goto out;
    }

    ret = SGX_SUCCESS;

out:

    BIO_free(bio);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    SAFE_FREE(ec_keypair);

    if (ret != SGX_SUCCESS)
    {
        *result = false;
    }
    else
    {
        *result = true;
    }

    return ret;
}