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
#include "sgx_tseal.h"

#include <string>
#include <stdio.h>
#include <stdbool.h>
#include <mbusafecrt.h>

#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"
#include "datatypes.h"

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/err.h"

#define SGX_DOMAIN_KEY_SIZE     16

#define RSA_OAEP_3072_MOD_SIZE      384
#define RSA_OAEP_3072_EXP_SIZE      4

#define EH_ENCRYPT_MAX_SIZE (6*1024)

#define EH_DATA_KEY_MAX_SIZE 1024

#define EH_AES_GCM_IV_SIZE  12
#define EH_AES_GCM_MAC_SIZE 16

#define RSA_OAEP_2048_SHA_256_MAX_ENCRYPTION_SIZE       190
//#define RSA_2048_OAEP_SHA_1_MAX_ENCRYPTION_SIZE       214

#define RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE       318
//#define RSA_3072_OAEP_SHA_1_MAX_ENCRYPTION_SIZE       342

#define SM2PKE_MAX_ENCRYPTION_SIZE                      6047

#define RSA_OAEP_3072_CIPHER_LENGTH       384
#define RSA_OAEP_3072_SIGNATURE_SIZE      384


// Used to store the secret passed by the SP in the sample code.
sgx_aes_gcm_128bit_key_t g_domain_key = {0};

static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

typedef struct _aes_gcm_data_ex_t
{
    uint32_t  ciphertext_size;
    uint32_t  aad_size;
    uint8_t   reserve1[8];
    uint8_t   iv[SGX_AESGCM_IV_SIZE];
    uint8_t   reserve2[4];
    uint8_t   mac[SGX_AESGCM_MAC_SIZE];
    uint8_t   payload[];   /* ciphertext + aad */
} sgx_aes_gcm_data_ex_t;

static uint32_t sgx_calc_gcm_data_size(const uint32_t aad_size, const uint32_t plaintext_size)
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

static uint32_t sgx_get_gcm_ciphertext_size(const sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data)
        return UINT32_MAX;

    return gcm_data->ciphertext_size;
}

/**
 * @brief get key size according to the encryption/decryption medthod
 * 
 * @param keyspec encryption/decryption medthod
 * @return uint32_t  key size
 */
static uint32_t sgx_get_key_size(const ehsm_keyspec_t keyspec)
{       
    switch (keyspec)
    {
        case EH_AES_GCM_128:
            return 16;
        case EH_AES_GCM_256:
            return 32;
        default:
            return UINT32_MAX;
    }
}

/**
 * @brief get openssl api for the corresponding encryption/decryption method
 * 
 * @param keyspec encryption/decryption medthod
 * @return const EVP_CIPHER* openssl function
 */
static const EVP_CIPHER * sgx_get_openssl_api(const ehsm_keyspec_t keyspec)
{       
    switch (keyspec)
    {
        case EH_AES_GCM_128:
            return EVP_aes_128_gcm();
        case EH_AES_GCM_256:
            return EVP_aes_256_gcm();
        default:
            return NULL;
    }
}

/**
 * @brief decrypt the ciphertext with the specified method
 * 
 * @param keyspec the specified api in openssl
 * @return sgx_status_t status code
 */
sgx_status_t ssl_aes_gcm_decrypt(const unsigned char *p_key, const uint8_t *p_src,
                                        uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len,
                                        const uint8_t *p_aad, uint32_t aad_len, const sgx_aes_gcm_128bit_tag_t *p_in_mac,
                                        ehsm_keyspec_t keyspec)
{
    uint8_t l_tag[SGX_AESGCM_MAC_SIZE];

    if ((src_len >= INT_MAX) || (aad_len >= INT_MAX) || (p_key == NULL) || ((src_len > 0) && (p_dst == NULL)) || ((src_len > 0) && (p_src == NULL))
        || (p_in_mac == NULL) || (iv_len != SGX_AESGCM_IV_SIZE) || ((aad_len > 0) && (p_aad == NULL))
        || (p_iv == NULL) || ((p_src == NULL) && (p_aad == NULL)))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    int len = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    EVP_CIPHER_CTX * pState = NULL;

    const EVP_CIPHER *EVP_aes_n_gcm = sgx_get_openssl_api(keyspec);
    if (EVP_aes_n_gcm == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    memcpy_s(l_tag, SGX_AESGCM_MAC_SIZE, p_in_mac, SGX_AESGCM_MAC_SIZE);

    do {
        if (!(pState = EVP_CIPHER_CTX_new())) {
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        // init key, iv and aad for decryption
        if (!EVP_DecryptInit_ex(pState, EVP_aes_n_gcm, NULL, p_key, p_iv)) {
            break;
        }

        if (NULL != p_aad) {
            if (!EVP_DecryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
                break;
            }
        }
        // get decryption result for p_dst
        if (!EVP_DecryptUpdate(pState, p_dst, &len, p_src, src_len)) {
            break;
        }
        // update mac value
        if (!EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_SET_TAG, SGX_AESGCM_MAC_SIZE, l_tag)) {
            break;
        }

        if (EVP_DecryptFinal_ex(pState, p_dst + len, &len) <= 0) {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }
        ret = SGX_SUCCESS;
    } while (0);

    if (pState != NULL) {
        EVP_CIPHER_CTX_free(pState);
    }
    memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    return ret;
}

/**
 * @brief encrypt the ciphertext with the specified method
 * 
 * @param keyspec the specified api in openssl
 * @return sgx_status_t status code
 */
sgx_status_t ssl_aes_gcm_encrypt(const unsigned char *p_key, const uint8_t *p_src, uint32_t src_len,
                                        uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len,
                                        sgx_aes_gcm_128bit_tag_t *p_out_mac, ehsm_keyspec_t keyspec)
{
    if ((src_len >= INT_MAX) || (aad_len >= INT_MAX) || (p_key == NULL) || ((src_len > 0) && (p_dst == NULL)) || ((src_len > 0) && (p_src == NULL))
        || (p_out_mac == NULL) || (iv_len != SGX_AESGCM_IV_SIZE) || ((aad_len > 0) && (p_aad == NULL))
        || (p_iv == NULL) || ((p_src == NULL) && (p_aad == NULL)))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int len = 0;
    EVP_CIPHER_CTX * pState = NULL;

    const EVP_CIPHER *EVP_aes_n_gcm = sgx_get_openssl_api(keyspec);
    if (EVP_aes_n_gcm == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    do {
        if (!(pState = EVP_CIPHER_CTX_new())) {
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        // init encryption function, iv, key and aad
        if (1 != EVP_EncryptInit_ex(pState, EVP_aes_n_gcm, NULL, NULL, NULL)) {
            break;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL)) {
            break;
        }

        if (1 != EVP_EncryptInit_ex(pState, NULL, NULL, p_key, p_iv)) {
            break;
        }

        if (NULL != p_aad) {
            if (1 != EVP_EncryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
                break;
            }
        }
        // get encryption result for p_dst
        if (src_len > 0) {
            if (1 != EVP_EncryptUpdate(pState, p_dst, &len, p_src, src_len)) {
                break;
            }
        }

        if (1 != EVP_EncryptFinal_ex(pState, p_dst + len, &len)) {
            break;
        }
        // update mac value
        if (1 != EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_GET_TAG, SGX_AESGCM_MAC_SIZE, p_out_mac)) {
            break;
        }
        ret = SGX_SUCCESS;
    } while (0);

    if (pState) {
            EVP_CIPHER_CTX_free(pState);
    }
    return ret;
}

static sgx_status_t sgx_gcm_encrypt(const sgx_aes_gcm_128bit_key_t *key,
                                    const uint32_t plaintext_size, const uint8_t *plaintext,
                                    const uint32_t aad_size, const uint8_t *aad,
                                    const uint32_t gcm_data_size, sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data || gcm_data_size < sgx_calc_gcm_data_size(aad_size, plaintext_size))
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext_size == 0 || NULL == plaintext)
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext_size > UINT32_MAX - aad_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_aad_size = aad_size;
    if (NULL == aad)
        real_aad_size = 0;

    sgx_status_t ret = sgx_read_rand(gcm_data->iv, sizeof(gcm_data->iv));
    if (ret != SGX_SUCCESS) {
        printf("error generating iv.\n");
        return ret;
    }

    ret = sgx_rijndael128GCM_encrypt(key,
                                     plaintext, plaintext_size,
                                     gcm_data->payload,
                                     gcm_data->iv, sizeof(gcm_data->iv),
                                     &(gcm_data->payload[gcm_data->ciphertext_size]), real_aad_size,
                                     reinterpret_cast<uint8_t (*)[16]>(gcm_data->mac));
    if (SGX_SUCCESS != ret) {
        printf("gcm encrypting failed.\n");
    }
    else {
        gcm_data->ciphertext_size = plaintext_size;
        gcm_data->aad_size = real_aad_size;
    }

    return ret;
}

static sgx_status_t sgx_gcm_decrypt(const sgx_aes_gcm_128bit_key_t *key,
                                    uint32_t *plaintext_size, uint8_t *plaintext,
                                    const sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data || NULL == plaintext || NULL == *plaintext_size
                 || *plaintext_size < sgx_get_gcm_ciphertext_size(gcm_data))
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_rijndael128GCM_decrypt(key,
                                                  gcm_data->payload, gcm_data->ciphertext_size,
                                                  plaintext,
                                                  gcm_data->iv, sizeof(gcm_data->iv),
                                                  &(gcm_data->payload[gcm_data->ciphertext_size]), gcm_data->aad_size,
                                                  (const sgx_aes_gcm_128bit_tag_t*)gcm_data->mac);
    if (SGX_SUCCESS != ret)
        printf("gcm decrypting failed.\n");
    else
        *plaintext_size = sgx_get_gcm_ciphertext_size(gcm_data);

    return ret;
}

sgx_status_t enclave_create_aes_key(uint8_t *cmk_blob, uint32_t cmk_blob_size, uint32_t *req_blob_size, ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t key_size = sgx_get_key_size(keyspec);
    if (key_size == UINT32_MAX)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_blob_len = sgx_calc_gcm_data_size(0, key_size);

    if (real_blob_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    if (req_blob_size != NULL) {
        *req_blob_size = real_blob_len;
        return SGX_SUCCESS;
    }

    if (cmk_blob == NULL || cmk_blob_size != real_blob_len)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t* tmp = (uint8_t *)malloc(key_size);
    if (tmp == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = sgx_read_rand(tmp, key_size);
    if (ret != SGX_SUCCESS) {
        free(tmp);
        return ret;
    }

    ret = sgx_gcm_encrypt(&g_domain_key, key_size, tmp, 0, NULL, cmk_blob_size, (sgx_aes_gcm_data_ex_t *)cmk_blob);

    memset_s(tmp, key_size, 0, key_size);

    free(tmp);

    return ret;
}

/*
 * struct cipherblob {
 *    OUT uint8_t ciphertext[KEY_SIZE];
 *    OUT uint8_t iv[EH_AES_GCM_IV_SIZE];   // 12B
 *    OUT uint8_t mac[EH_AES_GCM_MAC_SIZE]; // 16B
 * }
 */
sgx_status_t enclave_aes_encrypt(const uint8_t *aad, size_t aad_len,
                                 const uint8_t *cmk_blob, size_t cmk_blob_size,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t *cipherblob, size_t cipherblob_len, ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t key_size = sgx_get_key_size(keyspec);
    if (key_size == UINT32_MAX)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_cmk_blob_size = sgx_calc_gcm_data_size(0, key_size);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t enc_key_size = sgx_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (enc_key_size == UINT32_MAX || enc_key_size != key_size) {
        printf("enc_key_size:%d is not expected: %lu.\n", enc_key_size, key_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob == NULL ||
            cipherblob_len < plaintext_len + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *mac = (uint8_t *)(cipherblob + plaintext_len + EH_AES_GCM_IV_SIZE);

    ret = sgx_read_rand(iv, EH_AES_GCM_IV_SIZE);
    if (ret != SGX_SUCCESS) {
        printf("error generating IV\n");
        return ret;
    }

    uint8_t * enc_key = (uint8_t*)malloc(key_size);
    ret = sgx_gcm_decrypt(&g_domain_key,
                          &enc_key_size, enc_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        printf("failed to decrypt key\n");
		return ret;
    }

    ret = ssl_aes_gcm_encrypt(enc_key, plaintext, plaintext_len,
            cipherblob, iv, EH_AES_GCM_IV_SIZE, aad, aad_len,
            reinterpret_cast<uint8_t (*)[16]>(mac), keyspec);
    if (SGX_SUCCESS != ret) {
        printf("error encrypting plain text\n");
    }
    
    memset_s(enc_key, key_size, 0, key_size);

    free(enc_key);

    return ret;
}

sgx_status_t enclave_aes_decrypt(const uint8_t *aad, size_t aad_len,
                                 const uint8_t *cmk_blob, size_t cmk_blob_size,
                                 const uint8_t *cipherblob, size_t cipherblob_len,
                                 uint8_t *plaintext, size_t plaintext_len, ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t key_size = sgx_get_key_size(keyspec);
    if (key_size == UINT32_MAX)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_cmk_blob_size = sgx_calc_gcm_data_size(0, key_size);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t dec_key_size = sgx_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (dec_key_size == UINT32_MAX || dec_key_size != key_size) {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, key_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob == NULL ||
            cipherblob_len < plaintext_len + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *mac = (uint8_t *)(cipherblob + plaintext_len + EH_AES_GCM_IV_SIZE );

    uint8_t * dec_key = (uint8_t*)malloc(key_size);
    ret = sgx_gcm_decrypt(&g_domain_key,
                          &dec_key_size, dec_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        printf("error(%d) unsealing key.\n", ret);
        return ret;
    }

    ret = ssl_aes_gcm_decrypt(dec_key, cipherblob, plaintext_len, plaintext,
            iv, EH_AES_GCM_IV_SIZE, aad, aad_len,
            reinterpret_cast<uint8_t (*)[16]>(mac), keyspec);
    if (SGX_SUCCESS != ret) {
        printf("error decrypting encrypted text\n");
    }

    memset_s(dec_key, key_size, 0, key_size);

    free(dec_key);

    return ret;
}

sgx_status_t enclave_generate_datakey(uint32_t key_spec,
                                  const uint8_t *cmk_blob,
                                  size_t cmk_blob_size,
                                  const uint8_t *context,
                                  size_t context_len,
                                  uint8_t *plain_key,
                                  size_t plain_key_len,
                                  uint8_t *encrypted_key,
                                  size_t encrypted_key_len)
{ }

sgx_status_t enclave_export_datakey(uint32_t cmk_key_spec,
                                  const uint8_t *cmk_blob,
                                  size_t cmk_blob_size,
                                  const uint8_t *context,
                                  size_t context_len,
                                  uint8_t *encrypted_key,
                                  size_t encrypted_key_len,
                                  uint32_t uk_key_spec,
                                  const uint8_t *uk_blob,
                                  size_t uk_blob_size,
                                  uint8_t *new_encrypted_key,
                                  size_t new_encrypted_key_len)
{ }

/*
 * struct cmk_blob {
 *     sgx_rsa3072_public_key_t;
 *     enc(rsa_params_t);
 * }
*/
sgx_status_t enclave_create_rsa_key(uint8_t *cmk_blob, uint32_t cmk_blob_size, uint32_t *req_blob_size)
{ }

sgx_status_t enclave_rsa_sign(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *data, uint32_t data_len, uint8_t *signature, uint32_t signature_len)
{ }

sgx_status_t enclave_rsa_verify(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *data, uint32_t data_len, const uint8_t *signature, uint32_t signature_len, bool* result)
{ }

sgx_status_t enclave_rsa_encrypt(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t ciphertext_len)
{ }

sgx_status_t enclave_rsa_decrypt(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t plaintext_len, uint32_t *req_plaintext_len)
{ }

sgx_status_t enclave_get_target_info(sgx_target_info_t* target_info)
{
    return sgx_self_target(target_info);
}

sgx_status_t enclave_create_report(const sgx_target_info_t* p_qe3_target, sgx_report_t* p_report)
{ }

sgx_status_t enclave_get_rand(uint8_t *data, uint32_t datalen)
{
    if (data == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    return sgx_read_rand(data, datalen);
}

sgx_status_t enclave_generate_apikey(sgx_ra_context_t context,
                                     uint8_t *p_apikey, uint32_t apikey_len,
                                     uint8_t *cipherapikey, uint32_t cipherapikey_len)
{ }

sgx_status_t enclave_get_apikey(uint8_t *apikey, uint32_t keylen)
{ }
// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    return ret;
}

// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t enclave_verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{ }
