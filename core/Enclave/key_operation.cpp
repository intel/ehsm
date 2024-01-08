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
#include "datatypes.h"
#include "key_operation.h"
#include "key_factory.h"
#include "openssl_operation.h"

using namespace std;

void log_printf(uint32_t log_level, const char *filename, uint32_t line, const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(log_level, buf, filename, line);
}

/**
 * @brief Get the block mode by keyspec
 * @param keyspec the type of key
 * @return const CHIPER* (openssl callback, tempoary)
 */
static const EVP_CIPHER *get_symmetric_block_mode(ehsm_keyspec_t keyspec)
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
 * @brief Get the Digest from the value user specified
 *
 * @param digest_mode
 * @return const EVP_MD*
 */
static const EVP_MD *getDigestMode(ehsm_digest_mode_t digest_mode)
{
    switch (digest_mode)
    {
    case EH_SHA_224:
        return EVP_sha224();
    case EH_SHA_256:
        return EVP_sha256();
    case EH_SHA_384:
        return EVP_sha384();
    case EH_SHA_512:
        return EVP_sha512();
    case EH_SM3:
        return EVP_sm3();
    default:
        return NULL;
    }
}

/**
 * @brief Get the Padding from the value user specified
 *
 * @param padding_mode
 * @return uint32_t
 */
uint32_t getPaddingMode(ehsm_padding_mode_t padding_mode)
{
    switch (padding_mode)
    {
    case EH_RSA_PKCS1:
        return RSA_PKCS1_PADDING;
    case EH_RSA_PKCS1_PSS:
        return RSA_PKCS1_PSS_PADDING;
    case EH_RSA_PKCS1_OAEP:
        return RSA_PKCS1_OAEP_PADDING;
    default:
        return RSA_NO_PADDING;
    }
}

/**
 * @brief Check parameters and encrypted data
 * @param aad Additional data
 * @param cmk Key information
 * @param plaintext Data to be encrypted
 * @param cipherblob The information of ciphertext
 * cipherblob.data {ciphertext|iv|mac}
 */
sgx_status_t ehsm_aes_gcm_encrypt(ehsm_data_t *aad,
                                  ehsm_keyblob_t *cmk,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_AES_GCM_192 &&
        cmk->metadata.keyspec != EH_AES_GCM_256)
        return SGX_ERROR_INVALID_PARAMETER;

    /* calculate the ciphertext length */
    if (cipherblob->datalen == 0)
    {
        cipherblob->datalen = plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint32_t key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (key_size == UINT32_MAX || key_size != keysize)
    {
        log_d("key_size:%u is not expected: %u.\n", key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen < plaintext->datalen + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    uint8_t *mac = (uint8_t *)(cipherblob->data + plaintext->datalen + SGX_AESGCM_IV_SIZE);
    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    const EVP_CIPHER *block_mode = get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = sgx_read_rand(iv, SGX_AESGCM_IV_SIZE);
    if (ret != SGX_SUCCESS)
    {
        log_d("error generating IV\n");
        goto out;
    }

    ret = ehsm_parse_keyblob(key,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        log_d("failed to decrypt key\n");
        goto out;
    }

    ret = aes_gcm_encrypt(key,
                          cipherblob->data,
                          block_mode,
                          plaintext->data,
                          plaintext->datalen,
                          aad ? aad->data : NULL,
                          aad ? aad->datalen : 0,
                          iv,
                          SGX_AESGCM_IV_SIZE,
                          mac,
                          EH_AES_GCM_MAC_SIZE);

out:
    SAFE_MEMSET(key, keysize, 0, keysize);
    SAFE_FREE(key);
    return ret;
}

/**
 * @brief get public key from asymmetric keypair
 * @param cmk Key information
 * @param pubkey asymmetric public key
 */
sgx_status_t ehsm_get_public_key(ehsm_keyblob_t *cmk,
                                 ehsm_data_t *pubkey)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *keypair = NULL;

    // load asymmetric key pair
    keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    if (pubkey->datalen == 0)
    {
        // Key Pair Length (total) = |------------------------|
        // Public Key Length       = |---------|
        // Private Key Length      =            |-------------|
        // length of public key calculated as total - private key
        switch (cmk->metadata.keyspec)
        {
        case EH_SM2:
            pubkey->datalen = strlen((char *)keypair) - strlen(strstr((char *)keypair, "-----BEGIN PRIVATE KEY-----"));
            break;
        case EH_EC_P224:
        case EH_EC_P256K:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P521:
            pubkey->datalen = strlen((char *)keypair) - strlen(strstr((char *)keypair, "-----BEGIN EC PRIVATE KEY-----"));
            break;
        case EH_RSA_2048:
        case EH_RSA_3072:
        case EH_RSA_4096:
            pubkey->datalen = strlen((char *)keypair) - strlen(strstr((char *)keypair, "-----BEGIN RSA PRIVATE KEY-----"));
            break;
        }
        ret = SGX_SUCCESS;
        goto out;
    }

    memcpy_s(pubkey->data, pubkey->datalen, keypair, pubkey->datalen);

    ret = SGX_SUCCESS;

out:
    SAFE_MEMSET(keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(keypair);

    return ret;
}

/**
 * @brief Check parameters and decrypted data
 * @param aad Additional data
 * @param cmk_blob Key information
 * @param cipherblob The ciphertext to be decrypted
 * cipherblob.data {ciphertext|iv|mac}
 * @param plaintext Decrypted plaintext
 */
sgx_status_t ehsm_aes_gcm_decrypt(ehsm_data_t *aad,
                                  ehsm_keyblob_t *cmk,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t l_tag[SGX_AESGCM_MAC_SIZE];

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_AES_GCM_192 &&
        cmk->metadata.keyspec != EH_AES_GCM_256)
        return SGX_ERROR_INVALID_PARAMETER;

    /* calculate the ciphertext length */
    if (plaintext->datalen == 0)
    {
        plaintext->datalen = cipherblob->datalen - EH_AES_GCM_IV_SIZE - EH_AES_GCM_MAC_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint32_t key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (key_size == UINT32_MAX || key_size != keysize)
    {
        log_d("key_size size:%u is not expected: %u.\n", key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen < plaintext->datalen + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    uint8_t *mac = (uint8_t *)(cipherblob->data + plaintext->datalen + SGX_AESGCM_IV_SIZE);
    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    const EVP_CIPHER *block_mode = get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(key,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    // Autenthication Tag returned by Decrypt to be compared with Tag created during seal
    SAFE_MEMSET(l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    memcpy_s(l_tag, SGX_AESGCM_MAC_SIZE, mac, SGX_AESGCM_MAC_SIZE);

    ret = aes_gcm_decrypt(key,
                          plaintext->data,
                          block_mode,
                          cipherblob->data,
                          cipherblob->datalen - EH_AES_GCM_IV_SIZE - EH_AES_GCM_MAC_SIZE,
                          aad ? aad->data : NULL,
                          aad ? aad->datalen : 0,
                          iv,
                          SGX_AESGCM_IV_SIZE,
                          l_tag,
                          SGX_AESGCM_MAC_SIZE);
out:
    SAFE_MEMSET(l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    SAFE_MEMSET(key, keysize, 0, keysize);
    SAFE_FREE(key);
    return ret;
}

/**
 * @brief Check parameters and encrypted data
 * @param cmk Key information
 * @param plaintext Data to be encrypted
 * @param cipherblob The information of ciphertext
 */
sgx_status_t ehsm_sm4_ctr_encrypt(ehsm_keyblob_t *cmk,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_SM4_CTR)
        return SGX_ERROR_INVALID_PARAMETER;

    /* calculate the ciphertext length */
    if (cipherblob->datalen == 0)
    {
        cipherblob->datalen = plaintext->datalen + SGX_SM4_IV_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint32_t key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (key_size == UINT32_MAX || key_size != keysize)
    {
        log_d("key_size:%u is not expected: %u.\n", key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen < plaintext->datalen + SGX_SM4_IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = sgx_read_rand(iv, SGX_SM4_IV_SIZE);
    if (ret != SGX_SUCCESS)
    {
        log_d("error generating IV\n");
        goto out;
    }

    ret = ehsm_parse_keyblob(key,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        log_d("failed to decrypt key\n");
        goto out;
    }

    ret = sm4_ctr_encrypt(key,
                          cipherblob->data,
                          plaintext->data,
                          plaintext->datalen,
                          iv);
out:
    SAFE_MEMSET(key, keysize, 0, keysize);
    SAFE_FREE(key);
    return ret;
}

sgx_status_t ehsm_sm4_ctr_decrypt(ehsm_keyblob_t *cmk,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_SM4_CTR)
        return SGX_ERROR_INVALID_PARAMETER;

    /* calculate the ciphertext length */
    if (plaintext->datalen == 0)
    {
        plaintext->datalen = cipherblob->datalen - SGX_SM4_IV_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint32_t key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (key_size == UINT32_MAX || key_size != keysize)
    {
        log_d("key_size size:%u is not expected: %u.\n", key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen < plaintext->datalen + SGX_SM4_IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob->data + plaintext->datalen);
    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = ehsm_parse_keyblob(key,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        log_d("error(%d) unsealing key.\n", ret);
        goto out;
    }

    ret = sm4_ctr_decrypt(key, plaintext->data, cipherblob->data, plaintext->datalen, iv);

out:
    SAFE_MEMSET(key, keysize, 0, keysize);
    SAFE_FREE(key);
    return ret;
}

sgx_status_t ehsm_sm4_cbc_encrypt(ehsm_keyblob_t *cmk,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *iv = NULL;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_SM4_CBC)
        return SGX_ERROR_INVALID_PARAMETER;

    /* calculate the ciphertext length */
    if (cipherblob->datalen == 0)
    {
        /*
            padded plaintext length:
            1. mod(plaintext, 16) = 0, ciphertext length will add extra 16B
            2. mod(plaintext, 16) != 0, ciphertext length will fill in the part less than 16B
        */
        cipherblob->datalen = (plaintext->datalen / 16 + 1) * 16 + SGX_SM4_IV_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint32_t key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (key_size == UINT32_MAX || key_size != keysize)
    {
        log_d("key_size:%u is not expected: %u.\n", key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen != (plaintext->datalen / 16 + 1) * 16 + SGX_SM4_IV_SIZE)
        return SGX_ERROR_UNEXPECTED;

    iv = (uint8_t *)(cipherblob->data + ((plaintext->datalen / 16) + 1) * 16);

    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = sgx_read_rand(iv, SGX_SM4_IV_SIZE);
    if (ret != SGX_SUCCESS)
    {
        log_d("error generating IV\n");
        goto out;
    }

    ret = ehsm_parse_keyblob(key,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
    {
        log_d("failed to decrypt key\n");
        goto out;
    }

    ret = sm4_cbc_encrypt(key,
                          cipherblob->data,
                          plaintext->data,
                          plaintext->datalen,
                          iv);

out:
    SAFE_MEMSET(key, keysize, 0, keysize);
    SAFE_FREE(key);
    return ret;
}

sgx_status_t ehsm_sm4_cbc_decrypt(ehsm_keyblob_t *cmk,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t actual_plaintext_len = 0;

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_SM4_CBC)
        return SGX_ERROR_INVALID_PARAMETER;

    /* calculate the ciphertext length */
    if (plaintext->datalen == 0)
    {
        plaintext->datalen = cipherblob->datalen - SGX_SM4_IV_SIZE;
        return SGX_SUCCESS;
    }

    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(cmk->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint32_t key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (key_size == UINT32_MAX || key_size != keysize)
    {
        log_d("key_size size:%u is not expected: %u.\n", key_size, keysize);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob->datalen != plaintext->datalen + SGX_SM4_IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob->data + cipherblob->datalen - SGX_SM4_IV_SIZE);
    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    const EVP_CIPHER *block_mode = get_symmetric_block_mode(cmk->metadata.keyspec);
    if (block_mode == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = ehsm_parse_keyblob(key,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    ret = sm4_cbc_decrypt(key,
                          plaintext->data,
                          actual_plaintext_len,
                          cipherblob->data,
                          cipherblob->datalen,
                          iv);

    /* reset the unpad plaintext length from actual_plaintext_len */
    plaintext->datalen = actual_plaintext_len;

out:
    SAFE_MEMSET(key, keysize, 0, keysize);
    SAFE_FREE(key);
    return ret;
}

sgx_status_t ehsm_rsa_encrypt(const ehsm_keyblob_t *cmk,
                              ehsm_padding_mode_t padding_mode,
                              const ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // verify padding mode
    int paddingMode = getPaddingMode(padding_mode);
    if (paddingMode != RSA_PKCS1_PADDING && paddingMode != RSA_PKCS1_OAEP_PADDING)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *rsa_keypair = NULL;
    uint8_t *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t dataLen = 0;
    size_t outLen = 0;

    // load rsa public key
    rsa_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (rsa_keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(rsa_keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    dataLen = strlen((const char *)rsa_keypair) + 1;
    data = rsa_keypair;
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "RSA",
                                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    if (!OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
        goto out;

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL)
        goto out;

    if (EVP_PKEY_encrypt_init(pkey_ctx) != 1)
        goto out;

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, paddingMode) <= 0)
        goto out;

    if (EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, EVP_sha256()) <= 0)
        goto out;

    if (ciphertext->datalen == 0)
    {
        if (EVP_PKEY_encrypt(pkey_ctx, NULL, &outLen, plaintext->data, (size_t)plaintext->datalen) <= 0)
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
        ciphertext->datalen = outLen;
        ret = SGX_SUCCESS;
        goto out;
    }

    outLen = ciphertext->datalen;
    if (EVP_PKEY_encrypt(pkey_ctx,
                         ciphertext->data,
                         &outLen,
                         plaintext->data,
                         (size_t)plaintext->datalen) <= 0)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    ret = SGX_SUCCESS;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_DECODER_CTX_free(dctx);

    SAFE_MEMSET(rsa_keypair, dataLen, 0, dataLen);
    SAFE_FREE(rsa_keypair);

    return ret;
}

sgx_status_t ehsm_rsa_decrypt(const ehsm_keyblob_t *cmk,
                              ehsm_padding_mode_t padding_mode,
                              const ehsm_data_t *ciphertext,
                              ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;

    int paddingMode = getPaddingMode(padding_mode);
    if (paddingMode != RSA_PKCS1_PADDING && paddingMode != RSA_PKCS1_OAEP_PADDING)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *rsa_keypair = NULL;
    uint8_t *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    size_t outLen = 0;
    size_t dataLen = 0;

    // load private key
    rsa_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (rsa_keypair == NULL)
        goto out;

    ret = ehsm_parse_keyblob(rsa_keypair,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "RSA",
                                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    data = (unsigned char *)strstr((char *)rsa_keypair, "-----BEGIN RSA PRIVATE KEY-----");
    dataLen = strlen((char *)data) + 1;

    if (!OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
        goto out;

    if (!(pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        goto out;

    if (EVP_PKEY_decrypt_init(pkey_ctx) != 1)
        goto out;

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, paddingMode) <= 0)
        goto out;

    if (EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, EVP_sha256()) <= 0)
        goto out;

    if (plaintext->datalen == 0)
    {
        if (EVP_PKEY_decrypt(pkey_ctx,
                             NULL,
                             &outLen,
                             ciphertext->data,
                             (size_t)ciphertext->datalen) != 1)
        {
            goto out;
        }
        plaintext->datalen = outLen;
        ret = SGX_SUCCESS;
        goto out;
    }

    outLen = plaintext->datalen;
    if (EVP_PKEY_decrypt(pkey_ctx,
                         plaintext->data,
                         &outLen,
                         ciphertext->data,
                         (size_t)ciphertext->datalen) != 1)
    {
        goto out;
    }
    plaintext->datalen = outLen;
    ret = SGX_SUCCESS;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_DECODER_CTX_free(dctx);

    SAFE_MEMSET(rsa_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(rsa_keypair);

    return ret;
}

sgx_status_t ehsm_sm2_encrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *sm2_keypair = NULL;
    uint8_t *data = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    size_t outLen = 0;
    size_t dataLen = 0;

    // load sm2 public key
    sm2_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (sm2_keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(sm2_keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    dataLen = strlen((const char *)sm2_keypair) + 1;
    data = sm2_keypair;
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "SM2",
                                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    if (!OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
        goto out;

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL)
        goto out;

    if (EVP_PKEY_encrypt_init(pkey_ctx) != 1)
        goto out;

    if (ciphertext->datalen == 0)
    {
        if (EVP_PKEY_encrypt(pkey_ctx, NULL, &outLen, plaintext->data, (size_t)plaintext->datalen) <= 0)
            goto out;
        ciphertext->datalen = outLen;
        ret = SGX_SUCCESS;
        goto out;
    }

    outLen = ciphertext->datalen;
    if (EVP_PKEY_encrypt(pkey_ctx,
                         ciphertext->data,
                         &outLen,
                         plaintext->data,
                         (size_t)plaintext->datalen) <= 0)
        goto out;

    ret = SGX_SUCCESS;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_DECODER_CTX_free(dctx);

    SAFE_MEMSET(sm2_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(sm2_keypair);

    return ret;
}

sgx_status_t ehsm_sm2_decrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *ciphertext,
                              ehsm_data_t *plaintext)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *sm2_keypair = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    size_t outLen = 0;
    size_t dataLen = 0;
    unsigned char *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;

    // load private key
    sm2_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (sm2_keypair == NULL)
        goto out;

    ret = ehsm_parse_keyblob(sm2_keypair,
                             (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "SM2",
                                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    data = (unsigned char *)strstr((char *)sm2_keypair, "-----BEGIN PRIVATE KEY-----");
    dataLen = strlen((char *)data) + 1;

    if (!OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
        goto out;

    if (!(pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        goto out;

    if (EVP_PKEY_decrypt_init(pkey_ctx) != 1)
        goto out;

    if (plaintext->datalen == 0)
    {
        if (EVP_PKEY_decrypt(pkey_ctx,
                             NULL,
                             &outLen,
                             ciphertext->data,
                             (size_t)ciphertext->datalen) != 1)
            goto out;
        plaintext->datalen = outLen;
        ret = SGX_SUCCESS;
        goto out;
    }

    outLen = plaintext->datalen;
    if (EVP_PKEY_decrypt(pkey_ctx,
                         plaintext->data,
                         &outLen,
                         ciphertext->data,
                         (size_t)ciphertext->datalen) != 1)
        goto out;

    ret = SGX_SUCCESS;

out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_DECODER_CTX_free(dctx);

    SAFE_MEMSET(sm2_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(sm2_keypair);

    return ret;
}

/**
 * @brief make rsa sign with the designated digest mode and padding mode
 * digest mode and padding mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param message data to be signed
 * @param signature used to receive signature
 * @return sgx_status_t
 */
sgx_status_t ehsm_rsa_sign(const ehsm_keyblob_t *cmk,
                           ehsm_digest_mode_t digest_mode,
                           ehsm_padding_mode_t padding_mode,
                           ehsm_message_type_t message_type,
                           const ehsm_data_t *message,
                           ehsm_data_t *signature)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *rsa_keypair = NULL;
    uint8_t *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t dataLen = 0;

    // Get padding mode and digest mode
    const EVP_MD *digest = getDigestMode(digest_mode);
    if (digest == NULL)
        return ret;

    int padding = getPaddingMode(padding_mode);
    if (padding != RSA_PKCS1_PADDING && padding != RSA_PKCS1_PSS_PADDING)
        return ret;

    // load private key
    rsa_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (rsa_keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(rsa_keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "RSA",
                                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    data = (unsigned char *)strstr((char *)rsa_keypair, "-----BEGIN RSA PRIVATE KEY-----");
    dataLen = strlen((char *)data) + 1;

    if (OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
    {
        ret = rsa_sign(pkey,
                       digest,
                       padding,
                       message_type,
                       message->data,
                       message->datalen,
                       signature->data,
                       signature->datalen);
    }
    else
        goto out;

out:
    EVP_PKEY_free(pkey);
    OSSL_DECODER_CTX_free(dctx);

    SAFE_MEMSET(rsa_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(rsa_keypair);

    return ret;
}

/**
 * @brief make rsa verify with the designated digest mode and padding mode
 * digest mode and padding mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param message data to be signed
 * @param signature generated signature
 * @param result match result
 * @return sgx_status_t
 */
sgx_status_t ehsm_rsa_verify(const ehsm_keyblob_t *cmk,
                             ehsm_digest_mode_t digest_mode,
                             ehsm_padding_mode_t padding_mode,
                             ehsm_message_type_t message_type,
                             const ehsm_data_t *message,
                             const ehsm_data_t *signature,
                             bool *result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *rsa_keypair = NULL;
    uint8_t *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t dataLen = 0;

    // Get padding mode and digest mode
    const EVP_MD *digest = getDigestMode(digest_mode);
    if (digest == NULL)
        digest = EVP_sha256();

    int padding = getPaddingMode(padding_mode);
    if (padding != RSA_PKCS1_PADDING && padding != RSA_PKCS1_PSS_PADDING)
        return ret;

    // load rsa public key
    rsa_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (rsa_keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(rsa_keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    dataLen = strlen((const char *)rsa_keypair) + 1;
    data = rsa_keypair;
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "RSA",
                                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    if (OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
    {

        ret = rsa_verify(pkey,
                         digest,
                         padding,
                         message_type,
                         message->data,
                         message->datalen,
                         signature->data,
                         signature->datalen,
                         result);
    }
    else
        goto out;

out:
    OSSL_DECODER_CTX_free(dctx);
    EVP_PKEY_free(pkey);

    SAFE_MEMSET(rsa_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(rsa_keypair);

    return ret;
}

/**
 * @brief make ec sign with the designated digest mode
 * digest mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param message data to be signed
 * @param signature used to receive signature
 * @return sgx_status_t
 */
sgx_status_t ehsm_ecc_sign(const ehsm_keyblob_t *cmk,
                           ehsm_digest_mode_t digest_mode,
                           ehsm_message_type_t message_type,
                           const ehsm_data_t *message,
                           ehsm_data_t *signature)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *ec_keypair = NULL;
    uint8_t *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t dataLen = 0;

    // Get padding mode and digest mode
    const EVP_MD *digest = getDigestMode(digest_mode);
    if (digest == NULL)
        digest = EVP_sha256();

    ec_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (ec_keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(ec_keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "EC",
                                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    data = (unsigned char *)strstr((char *)ec_keypair, "-----BEGIN EC PRIVATE KEY-----");
    dataLen = strlen((char *)data) + 1;

    if (OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
    {
        ret = ecc_sign(pkey,
                       digest,
                       message_type,
                       message->data,
                       message->datalen,
                       signature->data,
                       &signature->datalen);
    }
    else
        goto out;

out:
    EVP_PKEY_free(pkey);
    OSSL_DECODER_CTX_free(dctx);

    SAFE_MEMSET(ec_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(ec_keypair);

    return ret;
}

/**
 * @brief make ec verify with the designated digest mode
 * digest mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param message data to be signed
 * @param signature generated signature
 * @param result match result
 * @return sgx_status_t
 */
sgx_status_t ehsm_ecc_verify(const ehsm_keyblob_t *cmk,
                             ehsm_digest_mode_t digest_mode,
                             ehsm_message_type_t message_type,
                             const ehsm_data_t *message,
                             const ehsm_data_t *signature,
                             bool *result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *ec_keypair = NULL;
    uint8_t *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t dataLen = 0;

    // Get padding mode and digest mode
    const EVP_MD *digest = getDigestMode(digest_mode);
    if (digest == NULL)
        digest = EVP_sha256();

    ec_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (ec_keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(ec_keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    dataLen = strlen((const char *)ec_keypair) + 1;
    data = ec_keypair;
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "EC",
                                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    if (OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
    {
        ret = ecc_verify(pkey,
                         digest,
                         message_type,
                         message->data,
                         message->datalen,
                         signature->data,
                         signature->datalen,
                         result);
    }
    else
        goto out;

out:
    OSSL_DECODER_CTX_free(dctx);
    EVP_PKEY_free(pkey);

    SAFE_MEMSET(ec_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(ec_keypair);

    return ret;
}

/**
 * @brief make sm2 sign with the designated digest mode
 * digest mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param message data to be signed
 * @param signature used to receive signature
 * @return sgx_status_t
 */
sgx_status_t ehsm_sm2_sign(const ehsm_keyblob_t *cmk,
                           ehsm_digest_mode_t digest_mode,
                           ehsm_message_type_t message_type,
                           const ehsm_data_t *message,
                           ehsm_data_t *signature)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *ec_keypair = NULL;
    uint8_t *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t dataLen = 0;

    // Get padding mode and digest mode
    const EVP_MD *digest = getDigestMode(digest_mode);
    if (digest != EVP_sm3())
        digest = EVP_sm3();

    ec_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (ec_keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(ec_keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "SM2",
                                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    data = (unsigned char *)strstr((char *)ec_keypair, "-----BEGIN PRIVATE KEY-----");
    dataLen = strlen((char *)data) + 1;

    if (OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
    {
        ret = sm2_sign(pkey,
                       digest,
                       message_type,
                       message->data,
                       message->datalen,
                       signature->data,
                       &signature->datalen,
                       (uint8_t *)SM2_DEFAULT_USERID,
                       strlen(SM2_DEFAULT_USERID));
    }
    else
        goto out;

out:
    EVP_PKEY_free(pkey);
    OSSL_DECODER_CTX_free(dctx);

    SAFE_MEMSET(ec_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(ec_keypair);

    return ret;
}

/**
 * @brief make sm2 verify with the designated digest mode
 * digest mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param message data to be signed
 * @param signature generated signature
 * @param result match result
 * @return sgx_status_t
 */
sgx_status_t ehsm_sm2_verify(const ehsm_keyblob_t *cmk,
                             ehsm_digest_mode_t digest_mode,
                             ehsm_message_type_t message_type,
                             const ehsm_data_t *message,
                             const ehsm_data_t *signature,
                             bool *result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint8_t *ec_keypair = NULL;
    uint8_t *data = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t dataLen = 0;

    // Get padding mode and digest mode
    const EVP_MD *digest = getDigestMode(digest_mode);
    if (digest != EVP_sm3())
        goto out;

    ec_keypair = (uint8_t *)malloc(cmk->keybloblen);
    if (ec_keypair == NULL)
        goto out;

    if (SGX_SUCCESS != ehsm_parse_keyblob(ec_keypair,
                                          (sgx_aes_gcm_data_ex_t *)cmk->keyblob))
        goto out;

    dataLen = strlen((const char *)ec_keypair) + 1;
    data = ec_keypair;
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL,
                                         "SM2",
                                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        goto out;

    if (OSSL_DECODER_from_data(dctx, (const unsigned char **)&data, &dataLen))
    {
        ret = sm2_verify(pkey,
                         digest,
                         message_type,
                         message->data,
                         message->datalen,
                         signature->data,
                         signature->datalen,
                         result,
                         (uint8_t *)SM2_DEFAULT_USERID,
                         strlen(SM2_DEFAULT_USERID));
    }
    else
        goto out;

out:
    EVP_PKEY_free(pkey);
    OSSL_DECODER_CTX_free(dctx);

    SAFE_MEMSET(ec_keypair, cmk->keybloblen, 0, cmk->keybloblen);
    SAFE_FREE(ec_keypair);
    return ret;
}