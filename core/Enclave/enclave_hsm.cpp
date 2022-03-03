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

#include "sgx_tkey_exchange.h"

typedef enum {
    EH_AES_GCM_128 = 0x00000000UL,
    EH_AES_GCM_256,
    EH_RSA_2048,
    EH_RSA_3072,
    EH_EC_P256,
    EH_EC_P512,
    EH_EC_SM2,
    EH_SM4,
} ehsm_keyspec_t;


#define SGX_AES_KEY_SIZE 16

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


sgx_status_t enclave_create_aes_key(uint8_t *cmk_blob, uint32_t cmk_blob_size, uint32_t *req_blob_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t real_blob_len = sgx_calc_gcm_data_size(0, SGX_AES_KEY_SIZE);

    if (real_blob_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    if (req_blob_size != NULL) {
        *req_blob_size = real_blob_len;
        return SGX_SUCCESS;
    }

    if (cmk_blob == NULL || cmk_blob_size != real_blob_len)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t* tmp = (uint8_t *)malloc(SGX_AES_KEY_SIZE);
    if (tmp == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = sgx_read_rand(tmp, SGX_AES_KEY_SIZE);
    if (ret != SGX_SUCCESS) {
        free(tmp);
        return ret;
    }

    ret = sgx_gcm_encrypt(&g_domain_key, SGX_AES_KEY_SIZE, tmp, 0, NULL, cmk_blob_size, (sgx_aes_gcm_data_ex_t *)cmk_blob);

    memset_s(tmp, SGX_AES_KEY_SIZE, 0, SGX_AES_KEY_SIZE);

    free(tmp);

    return ret;
}

/*
 * struct cipherblob {
 *    OUT uint8_t ciphertext[SGX_AES_KEY_SIZE];
 *    OUT uint8_t iv[EH_AES_GCM_IV_SIZE];   // 12B
 *    OUT uint8_t mac[EH_AES_GCM_MAC_SIZE]; // 16B
 * }
 */
sgx_status_t enclave_aes_encrypt(const uint8_t *aad, size_t aad_len,
                             const uint8_t *cmk_blob, size_t cmk_blob_size,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *cipherblob, size_t cipherblob_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_cmk_blob_size = sgx_calc_gcm_data_size(0, SGX_AES_KEY_SIZE);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t enc_key_size = sgx_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (enc_key_size == UINT32_MAX || enc_key_size != sizeof(sgx_key_128bit_t)) {
        printf("enc_key_size:%d is not expected: %lu.\n", enc_key_size, sizeof(sgx_key_128bit_t));
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

    sgx_key_128bit_t enc_key;
    ret = sgx_gcm_decrypt(&g_domain_key,
                          &enc_key_size, (uint8_t *)&enc_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        printf("failed to decrypt key\n");
		return ret;
    }

    ret = sgx_rijndael128GCM_encrypt(&enc_key, plaintext, plaintext_len,
            cipherblob, iv, EH_AES_GCM_IV_SIZE, aad, aad_len,
            reinterpret_cast<uint8_t (*)[16]>(mac));
    if (SGX_SUCCESS != ret) {
        printf("error encrypting plain text\n");
    }

    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));

    return ret;
}

sgx_status_t enclave_aes_decrypt(const uint8_t *aad, size_t aad_len,
                             const uint8_t *cmk_blob, size_t cmk_blob_size,
                             const uint8_t *cipherblob, size_t cipherblob_len,
                             uint8_t *plaintext, size_t plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_cmk_blob_size = sgx_calc_gcm_data_size(0, SGX_AES_KEY_SIZE);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t dec_key_size = sgx_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (dec_key_size == UINT32_MAX || dec_key_size != sizeof(sgx_key_128bit_t)) {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, sizeof(sgx_key_128bit_t));
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob == NULL ||
            cipherblob_len < plaintext_len + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *mac = (uint8_t *)(cipherblob + plaintext_len + EH_AES_GCM_IV_SIZE );

    sgx_key_128bit_t dec_key;
    ret = sgx_gcm_decrypt(&g_domain_key,
                          &dec_key_size, (uint8_t *)&dec_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        printf("error(%d) unsealing key.\n", ret);
        return ret;
    }

    ret = sgx_rijndael128GCM_decrypt(&dec_key, cipherblob, plaintext_len, plaintext,
            iv, EH_AES_GCM_IV_SIZE, aad, aad_len,
            reinterpret_cast<uint8_t (*)[16]>(mac));
    if (SGX_SUCCESS != ret) {
        printf("error decrypting encrypted text\n");
    }

    memset_s(&dec_key, sizeof(dec_key), 0, sizeof(dec_key));

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
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *datakey = NULL;

    if (cmk_blob == NULL || encrypted_key ==  NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    if (plain_key_len > 1024 || plain_key_len == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    datakey = (uint8_t *)malloc(plain_key_len);
    if (datakey == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ret = sgx_read_rand(datakey, plain_key_len);
    if (ret != SGX_SUCCESS) {
        free(datakey);
        return ret;
    }

    switch(key_spec) {
        case EH_AES_GCM_128:
            ret = enclave_aes_encrypt(context, context_len, cmk_blob, cmk_blob_size,
                    datakey, plain_key_len, encrypted_key, encrypted_key_len);
            break;
        default:
            return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plain_key != NULL)
        memcpy_s(plain_key, plain_key_len, datakey, plain_key_len);

    memset_s(datakey, plain_key_len, 0, plain_key_len);

    free(datakey);

    return ret;
}

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
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *tmp_datakey = NULL;
    uint32_t tmp_datakey_len = 0;

    if (cmk_blob == NULL || uk_blob == NULL || encrypted_key ==  NULL || new_encrypted_key == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    if (encrypted_key_len > 1024 ||
        encrypted_key_len < EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (new_encrypted_key_len > RSA_OAEP_3072_CIPHER_LENGTH || new_encrypted_key_len == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cmk_key_spec != EH_AES_GCM_128)
        return SGX_ERROR_INVALID_PARAMETER;

    if (uk_key_spec != EH_RSA_3072)
        return SGX_ERROR_INVALID_PARAMETER;

    tmp_datakey_len = encrypted_key_len - EH_AES_GCM_IV_SIZE - EH_AES_GCM_MAC_SIZE;
    tmp_datakey = (uint8_t *)malloc(tmp_datakey_len);
    if (tmp_datakey == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    // use the cmk to decrypt the datakey cipher text
    ret = enclave_aes_decrypt(context, context_len, cmk_blob, cmk_blob_size,
                    encrypted_key, encrypted_key_len, tmp_datakey, tmp_datakey_len);
    if (SGX_SUCCESS != ret) {
        printf("error decrypting encrypted text with cmk!\n");
        goto out;
    }

    // use the user-suplied rsa key to encrypt the datakey plaint text again.
    ret = enclave_rsa_encrypt(uk_blob, uk_blob_size, tmp_datakey, tmp_datakey_len,
                    new_encrypted_key, new_encrypted_key_len);
    if (SGX_SUCCESS != ret) {
        printf("error enrypting plaint text!\n");
        goto out;
    }

out:
    memset_s(tmp_datakey, tmp_datakey_len, 0, tmp_datakey_len);

    if (tmp_datakey)
        free(tmp_datakey);

    return ret;
}

/*
 * struct cmk_blob {
 *     sgx_rsa3072_public_key_t;
 *     enc(rsa_params_t);
 * }
*/
sgx_status_t enclave_create_rsa_key(uint8_t *cmk_blob, uint32_t cmk_blob_size, uint32_t *req_blob_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t real_keyblob_size = sgx_calc_gcm_data_size(0, sizeof(rsa_params_t));
    if (UINT32_MAX == real_keyblob_size)
        return SGX_ERROR_UNEXPECTED;

    real_keyblob_size += sizeof(sgx_rsa3072_public_key_t);

    if (req_blob_size) {
        *req_blob_size = real_keyblob_size;
        return SGX_SUCCESS;
    }

    if (cmk_blob == NULL || cmk_blob_size < real_keyblob_size) {
        printf("ecall create_rsa_key cmk_keyblob_size:%lu < key_blob_size:%d.\n", cmk_blob_size, real_keyblob_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* common/inc/sgx_tcrypto.h */
    rsa_params_t rsa_key = {0};
    rsa_key.e[0] = 0x10001;

    ret = sgx_create_rsa_key_pair(RSA_OAEP_3072_MOD_SIZE,
                                  RSA_OAEP_3072_EXP_SIZE,
                                  (unsigned char*)rsa_key.n,
                                  (unsigned char*)rsa_key.d,
                                  (unsigned char*)rsa_key.e,
                                  (unsigned char*)rsa_key.p,
                                  (unsigned char*)rsa_key.q,
                                  (unsigned char*)rsa_key.dmp1,
                                  (unsigned char*)rsa_key.dmq1,
                                  (unsigned char*)rsa_key.iqmp);
    if (ret != SGX_SUCCESS) {
        printf("ecall create_rsa_key sgx_create_rsa_key_pair failed: %d\n", ret);
        return ret;
    }

    sgx_rsa3072_public_key_t pub_verify_key = {0};
    memcpy_s(pub_verify_key.mod, sizeof(pub_verify_key.mod), rsa_key.n, sizeof(rsa_key.n));
    memcpy_s(pub_verify_key.exp, sizeof(pub_verify_key.exp), rsa_key.e, sizeof(rsa_key.e));
    memcpy_s(cmk_blob, sizeof(sgx_rsa3072_public_key_t), &pub_verify_key, sizeof(sgx_rsa3072_public_key_t));

    ret = sgx_gcm_encrypt(&g_domain_key, sizeof(rsa_params_t), (uint8_t*)&rsa_key, 0, NULL,
                         real_keyblob_size - sizeof(sgx_rsa3072_public_key_t),
                         (sgx_aes_gcm_data_ex_t *)((uint8_t*)cmk_blob + sizeof(sgx_rsa3072_public_key_t)));
    if (ret != SGX_SUCCESS) {
        printf("create rsa_key failed to seal cmk.\n");
    }

    memset_s(&rsa_key, sizeof(rsa_params_t), 0, sizeof(rsa_params_t));

    return ret;
}

sgx_status_t enclave_rsa_sign(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *data, uint32_t data_len, uint8_t *signature, uint32_t signature_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_rsa_len = sgx_calc_gcm_data_size(0, sizeof(rsa_params_t));
    if (UINT32_MAX == sealed_rsa_len) {
        printf("ecall rsa_sign failed to calculate sealed data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (cmk_blob == NULL || cmk_blob_size < sealed_rsa_len + sizeof(sgx_rsa3072_public_key_t)) {
        printf("ecall rsa_sign cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (data == NULL || data_len == 0) {
        printf("ecall rsa_sign data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (signature_len < RSA_OAEP_3072_SIGNATURE_SIZE) {
        printf("ecall rsa_sign signature_len is too small than the expected 384.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const sgx_aes_gcm_data_ex_t *rsa_key_blob = (sgx_aes_gcm_data_ex_t *)(cmk_blob + sizeof(sgx_rsa3072_public_key_t));
    uint32_t rsa_key_len = sgx_get_gcm_ciphertext_size(rsa_key_blob);
    if (rsa_key_len == UINT32_MAX || rsa_key_len != sizeof(rsa_params_t)) {
        printf("ecall rsa_sign rsa key size:%d is not expected: %lu.\n", rsa_key_len, sizeof(rsa_params_t));
        return SGX_ERROR_INVALID_PARAMETER;
    }

    rsa_params_t rsa_key = {0};
    ret = sgx_gcm_decrypt(&g_domain_key, &rsa_key_len, (uint8_t*)&rsa_key, (sgx_aes_gcm_data_ex_t *)rsa_key_blob);
    if (SGX_SUCCESS != ret) {
        printf("ecall rsa_sign unseal rsa_key failed: %d.\n", ret);
        return ret;
    }

    sgx_rsa3072_key_t pri_key = {0};
    memcpy_s(pri_key.mod, sizeof(pri_key.mod), rsa_key.n, sizeof(rsa_key.n));
    memcpy_s(pri_key.d, sizeof(pri_key.d), rsa_key.d, sizeof(rsa_key.d));
    memcpy_s(pri_key.e, sizeof(pri_key.e), rsa_key.e, sizeof(rsa_key.e));

    ret = sgx_rsa3072_sign(data, data_len, (const sgx_rsa3072_key_t*)&pri_key, (sgx_rsa3072_signature_t*)signature);
    if (ret != SGX_SUCCESS) {
        printf("ecall rsa_sign sgx_rsa3072_sign failed: %d.\n", ret);
    }

    memset_s(&rsa_key, sizeof(rsa_params_t), 0, sizeof(rsa_params_t));
    memset_s(&pri_key, sizeof(sgx_rsa3072_key_t), 0, sizeof(sgx_rsa3072_key_t));

    return ret;
}

sgx_status_t enclave_rsa_verify(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *data, uint32_t data_len, const uint8_t *signature, uint32_t signature_len, bool* result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_rsa_len = sgx_calc_gcm_data_size(0, sizeof(rsa_params_t));
    if (UINT32_MAX == sealed_rsa_len) {
        printf("ecall rsa_verify failed to calculate sealed data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (cmk_blob == NULL || cmk_blob_size < sealed_rsa_len + sizeof(sgx_rsa3072_public_key_t)) {
        printf("ecall rsa_verify cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (data == NULL || data_len == 0) {
        printf("ecall rsa_verify data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (result == NULL) {
        printf("ecall rsa_verify result is NULL.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (signature == NULL || signature_len < RSA_OAEP_3072_SIGNATURE_SIZE) {
        printf("ecall rsa_verify signature_len is too small than the expected 384.\n");
        *result = false;
        return SGX_SUCCESS;
    }

    const sgx_rsa3072_public_key_t *pub_key = (sgx_rsa3072_public_key_t *)cmk_blob;

    sgx_rsa_result_t verifed_result = SGX_RSA_INVALID_SIGNATURE;
    ret = sgx_rsa3072_verify(data, data_len, pub_key, (sgx_rsa3072_signature_t *)signature, &verifed_result);
    if (ret != SGX_SUCCESS) {
        printf("ecall rsa_verify sgx_rsa3072_verify failed: %d.\n", ret);
        return ret;
    }

    if (verifed_result == SGX_RSA_VALID)
        *result = true;
    else // SGX_RSA_INVALID_SIGNATURE
        *result = false;

    return SGX_SUCCESS;
}

sgx_status_t enclave_rsa_encrypt(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_rsa_len = sgx_calc_gcm_data_size(0, sizeof(rsa_params_t));
    if (UINT32_MAX == sealed_rsa_len) {
        printf("ecall rsa_encrypt failed to calculate sealed data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (cmk_blob == NULL || cmk_blob_size < sealed_rsa_len + sizeof(sgx_rsa3072_public_key_t)) {
        printf("ecall rsa_encrypt cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len == 0) {
        printf("ecall rsa_encrypt plaintext or len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext_len > RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE) {
        printf("ecall rsa_encrypt plain len is up to 318B.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ciphertext == NULL || ciphertext_len < RSA_OAEP_3072_CIPHER_LENGTH) {
        printf("ecall rsa_encrypt ciphertext len is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const sgx_rsa3072_public_key_t *temp_pub_key = (sgx_rsa3072_public_key_t *)cmk_blob;
    void *pub_key = NULL;
    ret = sgx_create_rsa_pub1_key(RSA_OAEP_3072_MOD_SIZE,
                                  RSA_OAEP_3072_EXP_SIZE,
                                  (const unsigned char*)temp_pub_key->mod,
                                  (const unsigned char*)temp_pub_key->exp,
                                  &pub_key);
    if (ret != SGX_SUCCESS) {
        printf("ecall rsa_encrypt sgx_create_rsa_pub1_key failed: %d.\n", ret);
        return ret;
    }

    size_t encrypted_len = 0;
    /* Get output buffer size */
    ret = sgx_rsa_pub_encrypt_sha256(pub_key, NULL, &encrypted_len, plaintext, plaintext_len);
    if (SGX_SUCCESS != ret) {
        printf("ecall rsa_encrypt sgx_create_rsa_pub1_key failed: %d.\n", ret);
        goto out;
    }

    if (ciphertext_len < encrypted_len) {
        printf("ecall rsa_encrypt ciphertext is too small!! \n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    ret = sgx_rsa_pub_encrypt_sha256(pub_key, ciphertext, &encrypted_len, plaintext, plaintext_len);
    if (ret != SGX_SUCCESS) {
        printf("ecall rsa_encrypt sgx_rsa_pub_encrypt_sha256 failed: %d.\n", ret);
        goto out;
    }

out:
    if (pub_key)
        sgx_free_rsa_key(pub_key, SGX_RSA_PUBLIC_KEY, RSA_OAEP_3072_MOD_SIZE, RSA_OAEP_3072_EXP_SIZE);

    return ret;
}

sgx_status_t enclave_rsa_decrypt(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t plaintext_len, uint32_t *req_plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_rsa_len = sgx_calc_gcm_data_size(0, sizeof(rsa_params_t));
    if (UINT32_MAX == sealed_rsa_len) {
        printf("ecall rsa_decrypt failed to calculate sealed data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (cmk_blob == NULL || cmk_blob_size < sealed_rsa_len + sizeof(sgx_rsa3072_public_key_t)) {
        printf("ecall rsa_decrypt cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* if ciphertext_len > 384, only decrypt the first 384 */
    if (ciphertext == NULL || ciphertext_len < RSA_OAEP_3072_CIPHER_LENGTH) {
        printf("ecall rsa_decrypt ciphertext len is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const sgx_aes_gcm_data_ex_t *rsa_key_blob = (sgx_aes_gcm_data_ex_t *)(cmk_blob + sizeof(sgx_rsa3072_public_key_t));
    uint32_t rsa_key_len = sgx_get_gcm_ciphertext_size(rsa_key_blob);
    if (rsa_key_len == UINT32_MAX || rsa_key_len != sizeof(rsa_params_t)) {
        printf("ecall rsa_decrypt rsa key size:%d is not expected: %lu.\n", rsa_key_len, sizeof(rsa_params_t));
        return SGX_ERROR_INVALID_PARAMETER;
    }

    rsa_params_t rsa_key = {0};
    ret = sgx_gcm_decrypt(&g_domain_key, &rsa_key_len, (uint8_t *)&rsa_key, (sgx_aes_gcm_data_ex_t *)rsa_key_blob);
    if (SGX_SUCCESS != ret) {
        printf("ecall rsa_decrypt unseal rsa_key failed: %d.\n", ret);
        return ret;
    }

    size_t real_plaintext_len = 0;
    void *pri_key = NULL;
    ret = sgx_create_rsa_priv2_key(RSA_OAEP_3072_MOD_SIZE,
                                   RSA_OAEP_3072_EXP_SIZE,
                                   (const unsigned char*)rsa_key.e,
                                   (const unsigned char*)rsa_key.p,
                                   (const unsigned char*)rsa_key.q,
                                   (const unsigned char*)rsa_key.dmp1,
                                   (const unsigned char*)rsa_key.dmq1,
                                   (const unsigned char*)rsa_key.iqmp,
                                   &pri_key);
    if (ret != SGX_SUCCESS) {
        printf("ecall rsa_decrypt sgx_create_rsa_priv2_key failed: %d.\n", ret);
        goto out;
    }

    ret = sgx_rsa_priv_decrypt_sha256(pri_key, NULL, &real_plaintext_len, ciphertext, ciphertext_len);
    if (ret != SGX_SUCCESS) {
        printf("ecall rsa_decrypt sgx_rsa_priv_decrypt_sha256 failed: %d.\n", ret);
        goto out;
    }

    /* return the plaintext len */
    if (req_plaintext_len) {
        printf("ecall rsa_decrypt real_plaintext_len is %d.\n", real_plaintext_len);
        *req_plaintext_len = real_plaintext_len;
        ret = SGX_SUCCESS;
        goto out;
    }

    if (plaintext == NULL || plaintext_len < real_plaintext_len) {
        printf("ecall rsa_decrypt plaintext_len(%d) is smaller than expected: %d.\n", plaintext_len, real_plaintext_len);
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    ret = sgx_rsa_priv_decrypt_sha256(pri_key, plaintext, &real_plaintext_len, ciphertext, ciphertext_len);
    if (ret != SGX_SUCCESS) {
        printf("ecall rsa_decrypt sgx_rsa_priv_decrypt_sha256 failed: %d.\n", ret);
        goto out;
    }

out:
    if (pri_key)
        sgx_free_rsa_key(pri_key, SGX_RSA_PRIVATE_KEY, RSA_OAEP_3072_MOD_SIZE, RSA_OAEP_3072_EXP_SIZE);
    memset_s(&rsa_key, sizeof(rsa_params_t), 0, sizeof(rsa_params_t));

    return ret;
}

sgx_status_t enclave_generate_apikey(sgx_ra_context_t context,
                                     uint8_t *p_apikey, uint32_t apikey_len,
                                     uint8_t *cipherkey, uint32_t cipherkey_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (p_apikey == NULL || apikey_len > EH_API_KEY_SIZE){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (cipherkey == NULL || cipherkey_len < EH_API_KEY_SIZE + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE){
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate apikey
    std::string psw_chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
    uint8_t temp[apikey_len];
    ret = sgx_read_rand(temp, apikey_len);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    for (int i = 0; i < apikey_len; i++) {
        p_apikey[i] = psw_chars[temp[i] % psw_chars.length()];
    }

    // struct cipherkey{
    //     uint8_t apikey[32]
    //     uint8_t iv[12]
    //     uint8_t mac[16]  
    // }
    uint8_t *iv = (uint8_t *)(cipherkey + apikey_len);
    uint8_t *mac = (uint8_t *)(cipherkey + apikey_len + EH_AES_GCM_IV_SIZE);
    // get sk and encrypt apikey 
    sgx_ec_key_128bit_t sk_key;
    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                     p_apikey, apikey_len,
                                     cipherkey,
                                     iv, EH_AES_GCM_IV_SIZE,
                                     NULL, 0,
                                     reinterpret_cast<uint8_t (*)[EH_AES_GCM_MAC_SIZE]>(mac));
    if (ret != SGX_SUCCESS) {
        printf("error encrypting plain text\n");
    }

    memset_s(temp, apikey_len, 0, apikey_len);
    return ret;
}

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
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    }
    while(0);

    return ret;
}