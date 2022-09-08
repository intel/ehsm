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

using namespace std;

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
    case EH_SM4:
        return EVP_sm4_ecb();
    default:
        return NULL;
    }
    return NULL;
}

/**
 * @brief Check parameters and encrypted data
 * @param aad Additional data
 * @param aad_len Lenghth of aad
 * @param cmk_blob Key information
 * @param SIZE_OF_KEYBLOB_T Lenghth of cmk_blob
 * @param plaintext Data to be encrypted
 * @param plaintext_len Lenghth of plaintext
 * @param cipherblob The information of ciphertext
 * @param cipherblob_len Lenghth of cipherblob
 * @param keyspec The type of key
 */
sgx_status_t ehsm_aes_gcm_encrypt(const uint8_t *aad, size_t aad_len,
                                  const uint8_t *cmk_blob, size_t SIZE_OF_KEYBLOB_T,
                                  const uint8_t *plaintext, size_t plaintext_len,
                                  uint8_t *cipherblob, size_t cipherblob_len,
                                  ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int len = 0;
    EVP_CIPHER_CTX *pState = NULL;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    /* this api only support for symmetric keys */
    if (keyspec != EH_AES_GCM_128 &&
        keyspec != EH_AES_GCM_192 &&
        keyspec != EH_AES_GCM_256)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t keysize = ehsm_get_symmetric_key_size(keyspec);
    if (keysize == UINT32_MAX)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t real_SIZE_OF_KEYBLOB_T = ehsm_calc_keyblob_len(0, keysize);
    if (UINT32_MAX == real_SIZE_OF_KEYBLOB_T || SIZE_OF_KEYBLOB_T < real_SIZE_OF_KEYBLOB_T)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t enc_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (enc_key_size == UINT32_MAX || enc_key_size != keysize)
    {
        printf("enc_key_size:%d is not expected: %lu.\n", enc_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob == NULL ||
        cipherblob_len < plaintext_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if ((aad_len > 0) && (aad == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *mac = (uint8_t *)(cipherblob + plaintext_len + SGX_AESGCM_IV_SIZE);
    uint8_t *enc_key = (uint8_t *)malloc(keysize);

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(keyspec);
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

    if (mac == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if ((iv == NULL))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(enc_key, enc_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS)
    {
        printf("failed to decrypt key\n");
        goto out;
    }

    // Create and init ctx
    //
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise encrypt/decrpty, key and IV
    //
    if (1 != EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char *)enc_key, iv))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Provide AAD data if exist
    //
    if (NULL != aad)
    {
        if (1 != EVP_EncryptUpdate(pState, NULL, &len, aad, aad_len))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    if (plaintext_len > 0)
    {
        // Provide the message to be encrypted, and obtain the encrypted output.
        //
        if (1 != EVP_EncryptUpdate(pState, cipherblob, &len, plaintext, plaintext_len))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Finalise the encryption/decryption
    //
    if (1 != EVP_EncryptFinal_ex(pState, cipherblob + len, &len))
    {
        ret = SGX_ERROR_MAC_MISMATCH;
        goto out;
    }

    // Get tag
    //
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
 * @param aad_len Lenghth of aad
 * @param cmk_blob Key information
 * @param SIZE_OF_KEYBLOB_T Lenghth of cmk_blob
 * @param cipherblob The ciphertext to be decrypted
 * @param cipherblob_len Lenghth of cipherblob
 * @param plaintext Decrypted plaintext
 * @param plaintext_len Lenghth of plaintext
 * @param keyspec The type of key
 */
sgx_status_t ehsm_aes_gcm_decrypt(const uint8_t *aad, size_t aad_len,
                                  const uint8_t *cmk_blob, size_t SIZE_OF_KEYBLOB_T,
                                  const uint8_t *cipherblob, size_t cipherblob_len,
                                  uint8_t *plaintext, size_t plaintext_len,
                                  ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t l_tag[SGX_AESGCM_MAC_SIZE];
    int len = 0;
    EVP_CIPHER_CTX *pState = NULL;
    if (cmk_blob == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* this api only support for symmetric keys */
    if (keyspec != EH_AES_GCM_128 &&
        keyspec != EH_AES_GCM_192 &&
        keyspec != EH_AES_GCM_256)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = ehsm_get_symmetric_key_size(keyspec);
    if (keysize == UINT32_MAX)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t real_SIZE_OF_KEYBLOB_T = ehsm_calc_keyblob_len(0, keysize);
    if (UINT32_MAX == real_SIZE_OF_KEYBLOB_T || SIZE_OF_KEYBLOB_T < real_SIZE_OF_KEYBLOB_T)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t dec_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (dec_key_size == UINT32_MAX || dec_key_size != keysize)
    {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cipherblob == NULL || cipherblob_len < plaintext_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if ((aad_len > 0) && (aad == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *mac = (uint8_t *)(cipherblob + plaintext_len + SGX_AESGCM_IV_SIZE);
    uint8_t *dec_key = (uint8_t *)malloc(keysize);

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (mac == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if ((iv == NULL))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(dec_key, dec_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS)
    {
        printf("error(%d) unsealing key.\n", ret);
        goto out;
    }

    // Autenthication Tag returned by Decrypt to be compared with Tag created during seal
    //
    memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    memcpy(l_tag, mac, SGX_AESGCM_MAC_SIZE);

    // Create and initialise the context
    //
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise decrypt, key and IV
    //
    if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char *)dec_key, iv))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    if (NULL != aad)
    {
        if (!EVP_DecryptUpdate(pState, NULL, &len, aad, aad_len))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Decrypt message, obtain the plaintext output
    //
    if (!EVP_DecryptUpdate(pState, plaintext, &len, cipherblob, plaintext_len))
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
    //
    if (EVP_DecryptFinal_ex(pState, plaintext + len, &len) <= 0)
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

sgx_status_t ehsm_sm4_encrypt(const uint8_t *aad, size_t aad_len,
                              const uint8_t *cmk_blob, size_t SIZE_OF_KEYBLOB_T,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *cipherblob, size_t cipherblob_len,
                              ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int len = 0;
    EVP_CIPHER_CTX *pState = NULL;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    /* this api only support for symmetric keys */
    if (keyspec != EH_SM4)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t keysize = ehsm_get_symmetric_key_size(keyspec);
    if (keysize == UINT32_MAX)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t real_SIZE_OF_KEYBLOB_T = ehsm_calc_keyblob_len(0, keysize);
    if (UINT32_MAX == real_SIZE_OF_KEYBLOB_T || SIZE_OF_KEYBLOB_T < real_SIZE_OF_KEYBLOB_T)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t enc_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (enc_key_size == UINT32_MAX || enc_key_size != keysize)
    {
        printf("enc_key_size:%d is not expected: %lu.\n", enc_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob == NULL ||
        cipherblob_len < plaintext_len + SGX_SM4_IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if ((aad_len > 0) && (aad == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *enc_key = (uint8_t *)malloc(keysize);

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(keyspec);
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

    if ((iv == NULL))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(enc_key, enc_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS)
    {
        printf("failed to decrypt key\n");
        goto out;
    }

    // Create and init ctx
    //
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise encrypt/decrpty, key and IV
    //
    if (1 != EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char *)enc_key, iv))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Provide AAD data if exist
    //
    if (NULL != aad)
    {
        if (1 != EVP_EncryptUpdate(pState, NULL, &len, aad, aad_len))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    if (plaintext_len > 0)
    {
        // Provide the message to be encrypted, and obtain the encrypted output.
        //
        if (1 != EVP_EncryptUpdate(pState, cipherblob, &len, plaintext, plaintext_len))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Finalise the encryption/decryption
    //
    if (1 != EVP_EncryptFinal_ex(pState, cipherblob + len, &len))
    {
        ret = SGX_ERROR_MAC_MISMATCH;
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

sgx_status_t ehsm_sm4_decrypt(const uint8_t *aad, size_t aad_len,
                              const uint8_t *cmk_blob, size_t SIZE_OF_KEYBLOB_T,
                              const uint8_t *cipherblob, size_t cipherblob_len,
                              uint8_t *plaintext, size_t plaintext_len,
                              ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int len = 0;
    EVP_CIPHER_CTX *pState = NULL;
    if (cmk_blob == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* this api only support for symmetric keys */
    if (keyspec != EH_SM4)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t keysize = ehsm_get_symmetric_key_size(keyspec);
    if (keysize == UINT32_MAX)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t real_SIZE_OF_KEYBLOB_T = ehsm_calc_keyblob_len(0, keysize);
    if (UINT32_MAX == real_SIZE_OF_KEYBLOB_T || SIZE_OF_KEYBLOB_T < real_SIZE_OF_KEYBLOB_T)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t dec_key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (dec_key_size == UINT32_MAX || dec_key_size != keysize)
    {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cipherblob == NULL || cipherblob_len < plaintext_len + SGX_SM4_IV_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if ((aad_len > 0) && (aad == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *dec_key = (uint8_t *)malloc(keysize);

    const EVP_CIPHER *block_mode = ehsm_get_symmetric_block_mode(keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if ((iv == NULL))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(dec_key, dec_key_size,
                             (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS)
    {
        printf("error(%d) unsealing key.\n", ret);
        goto out;
    }


    // Create and initialise the context
    //
    if (!(pState = EVP_CIPHER_CTX_new()))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise decrypt, key and IV
    //
    if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char *)dec_key, iv))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    if (NULL != aad)
    {
        if (!EVP_DecryptUpdate(pState, NULL, &len, aad, aad_len))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Decrypt message, obtain the plaintext output
    //
    if (!EVP_DecryptUpdate(pState, plaintext, &len, cipherblob, plaintext_len))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.
    //
    if (EVP_DecryptFinal_ex(pState, plaintext + len, &len) <= 0)
    {
        ret = SGX_ERROR_MAC_MISMATCH;
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


sgx_status_t ehsm_asymmetric_encrypt(const ehsm_keyblob_t *cmk, ehsm_data_t *plaintext, ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
            
    uint8_t         *rsa_keypair    = NULL;
    BIO             *bio            = NULL;
    RSA             *rsa_pubkey     = NULL;
    EVP_PKEY        *pkey           = NULL;
    EVP_PKEY_CTX    *ectx           = NULL;

    // load rsa public key
    rsa_keypair = (uint8_t*)malloc(cmk->keybloblen);

    ret = ehsm_parse_keyblob(rsa_keypair, cmk->keybloblen, 
                            (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    bio = BIO_new_mem_buf(rsa_keypair, -1); // use -1 to auto compute length
    if (bio == NULL) {
        printf("failed to load public key pem\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // make encryption
    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        PEM_read_bio_RSA_PUBKEY(bio, &rsa_pubkey, NULL, NULL);
        if (rsa_pubkey == NULL) {
            printf("failed to load rsa key\n");
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }

        if (ciphertext->datalen == 0) {
            ciphertext->datalen = RSA_size(rsa_pubkey); // TODO : compute padding size
            ret = SGX_SUCCESS;
            goto out;
        }
        if (RSA_public_encrypt(plaintext->datalen, plaintext->data, ciphertext->data, rsa_pubkey, cmk->metadata.padding_mode) != RSA_size(rsa_pubkey)) {
            printf("failed to make rsa encryption\n");
            goto out;
        }
        break;
    case EH_SM2:
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (pkey == NULL) {
            printf("failed to load sm2 key\n");
            goto out;
        }
        if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
        
        if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL))) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
        
        if (EVP_PKEY_encrypt_init(ectx) != 1) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }

        size_t strLen;
        if (EVP_PKEY_encrypt(ectx, NULL, &strLen, plaintext->data, (size_t)plaintext->datalen) != 1) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }

        if (ciphertext->datalen == 0) {
            ciphertext->datalen = strLen;
            ret = SGX_SUCCESS;
            goto out;
        }

        if (plaintext->data != NULL) {
            if (EVP_PKEY_encrypt(ectx, ciphertext->data, &strLen, plaintext->data, (size_t)plaintext->datalen) != 1) {
                printf("failed to make sm2 encryption\n");
                ret = SGX_ERROR_UNEXPECTED;
                goto out;
            }
        } else {
            ret = SGX_ERROR_INVALID_PARAMETER;
            goto out;
        }
    default:
        ret = SGX_ERROR_UNEXPECTED;
        break;
    }

    ret = SGX_SUCCESS;
out:
    BIO_free(bio);
    RSA_free(rsa_pubkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ectx);
    SAFE_FREE(rsa_keypair);

    return ret;
}

sgx_status_t ehsm_asymmetric_decrypt(const ehsm_keyblob_t *cmk, ehsm_data_t *ciphertext, ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t         *rsa_keypair    = NULL;
    BIO             *bio            = NULL;
    RSA             *rsa_prikey     = NULL;
    EVP_PKEY        *pkey           = NULL;
    EVP_PKEY_CTX    *dctx           = NULL;

    // load private key
    rsa_keypair = (uint8_t*)malloc(cmk->keybloblen);
    ret = ehsm_parse_keyblob(rsa_keypair, cmk->keybloblen, 
                            (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    bio = BIO_new_mem_buf(rsa_keypair, -1); // use -1 to auto compute length
    if (bio == NULL) {
        printf("failed to load key pem\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        PEM_read_bio_RSAPrivateKey(bio, &rsa_prikey, NULL, NULL);
        if (rsa_prikey == NULL) {
            printf("failed to load private key\n");
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }

        if (plaintext->datalen == 0) {
            uint8_t* temp_plaintext = (uint8_t*)malloc(RSA_size(rsa_prikey));
            plaintext->datalen = RSA_private_decrypt(ciphertext->datalen, ciphertext->data, temp_plaintext, rsa_prikey, cmk->metadata.padding_mode);
            ret = SGX_SUCCESS;
            goto out;
        }

        if (!RSA_private_decrypt(ciphertext->datalen, ciphertext->data, plaintext->data, rsa_prikey, cmk->metadata.padding_mode)) {
            printf("failed to make rsa decrypt\n");
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
        break;
    case EH_SM2:
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (pkey == NULL) {
            printf("failed to load sm2 key\n");
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }

        // make decryption and compute plaintext length
        if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }

        if (!(dctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }

        if (EVP_PKEY_decrypt_init(dctx) != 1) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }

        if (plaintext->datalen == 0) {
            size_t strLen;
            if (EVP_PKEY_decrypt(dctx, NULL, &strLen, ciphertext->data, (size_t)ciphertext->datalen) != 1) {
                ret = SGX_ERROR_UNEXPECTED;
                goto out;
            }
            plaintext->datalen = strLen;
            ret = SGX_SUCCESS;
            goto out;
        }

        if (ciphertext->data != NULL) {
            size_t strLen = plaintext->datalen;
            if (EVP_PKEY_decrypt(dctx, plaintext->data, &strLen, ciphertext->data, (size_t)ciphertext->datalen) != 1) { 
                ret = SGX_ERROR_UNEXPECTED;
                goto out;
            }
        } else {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
        break;
    default:
        ret = SGX_ERROR_INVALID_PARAMETER;
        break;
    }
    
out:
    BIO_free(bio);
    RSA_free(rsa_prikey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(dctx);
    SAFE_FREE(rsa_keypair);

    return ret;
}

sgx_status_t ehsm_rsa_sign(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_rsa_verify(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_ec_sign(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_ec_verify(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_sm2_sign(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_sm2_verify(const ehsm_keyblob_t *cmk)
{
    
}

sgx_status_t ehsm_aes_gcm_generate_datakey(const ehsm_keyblob_t *cmk)
{
    
}

sgx_status_t ehsm_sm4_generate_datakey(const ehsm_keyblob_t *cmk)
{
    
}