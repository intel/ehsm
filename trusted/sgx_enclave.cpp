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

#include "common_ehsm.h"
#include "enclave_hsm_t.h"
#include "sgx_tseal.h"

#include <string>
#include <stdio.h>
#include <stdbool.h>
#include <mbusafecrt.h>

#define SGX_AES_KEY_SIZE 16

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

sgx_status_t sgx_create_aes_key(uint8_t *cmk_blob, size_t cmk_blob_size, size_t *req_blob_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t real_blob_len = sgx_calc_sealed_data_size(0, SGX_AES_KEY_SIZE);

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

    ret = sgx_seal_data(0, NULL, SGX_AES_KEY_SIZE, tmp, cmk_blob_size, (sgx_sealed_data_t *)cmk_blob);

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
sgx_status_t sgx_aes_encrypt(const uint8_t *aad, size_t aad_len,
                             const uint8_t *cmk_blob, size_t cmk_blob_size,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *cipherblob, size_t cipherblob_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_cmk_blob_size = sgx_calc_sealed_data_size(0, SGX_AES_KEY_SIZE);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t enc_key_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)cmk_blob);
    if (enc_key_size == UINT32_MAX || enc_key_size != sizeof(sgx_key_128bit_t)) {
        printf("enc_key_size:%d is not expected: %d.\n", enc_key_size, sizeof(sgx_key_128bit_t));
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
    ret = sgx_unseal_data((sgx_sealed_data_t *)cmk_blob, NULL, 0, (uint8_t *)&enc_key, &enc_key_size);
    if (ret != SGX_SUCCESS) {
        printf("error unsealing key 0x%lx\n", ret);
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

sgx_status_t sgx_aes_decrypt(const uint8_t *aad, size_t aad_len,
                             const uint8_t *cmk_blob, size_t cmk_blob_size,
                             const uint8_t *cipherblob, size_t cipherblob_len,
                             uint8_t *plaintext, size_t plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_cmk_blob_size = sgx_calc_sealed_data_size(0, SGX_AES_KEY_SIZE);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t dec_key_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)cmk_blob);
    if (dec_key_size == UINT32_MAX || dec_key_size != sizeof(sgx_key_128bit_t)) {
        printf("dec_key_size size:%d is not expected: %d.\n", dec_key_size, sizeof(sgx_key_128bit_t));
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
    ret = sgx_unseal_data((sgx_sealed_data_t *)cmk_blob, NULL, 0, (uint8_t *)&dec_key, &dec_key_size);
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

sgx_status_t sgx_generate_datakey(uint32_t key_spec,
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
        case EHM_AES_GCM_128:
            ret = sgx_aes_encrypt(context, context_len, cmk_blob, cmk_blob_size,
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

/*
 * struct cmk_blob {
 *     sgx_rsa3072_public_key_t;
 *     enc(rsa_params_t);
 * }
*/
#define RSA_OAEP_3072_MOD_SIZE      384
#define RSA_OAEP_3072_EXP_SIZE      4

sgx_status_t sgx_create_rsa_key(uint8_t *cmk_blob, size_t cmk_blob_size, size_t *req_blob_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t real_keyblob_size = sgx_calc_sealed_data_size(0, sizeof(rsa_params_t));
    if (UINT32_MAX == real_keyblob_size)
        return SGX_ERROR_UNEXPECTED;

    real_keyblob_size += sizeof(sgx_rsa3072_public_key_t);

    if (req_blob_size) {
        *req_blob_size = real_keyblob_size;
        return SGX_SUCCESS;
    }

    if (cmk_blob == NULL || cmk_blob_size < real_keyblob_size) {
        printf("ecall create_rsa_key cmk_keyblob_size:%d < key_blob_size:%d.\n", cmk_blob_size, real_keyblob_size);
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

    ret = sgx_seal_data(0, NULL, sizeof(rsa_params_t), (uint8_t*)&rsa_key,
                        real_keyblob_size - sizeof(sgx_rsa3072_public_key_t),
                        (sgx_sealed_data_t *)((uint8_t*)cmk_blob + sizeof(sgx_rsa3072_public_key_t)));
    if (ret != SGX_SUCCESS) {
        printf("create rsa_key failed to seal cmk.\n");
    }

    memset_s(&rsa_key, sizeof(rsa_params_t), 0, sizeof(rsa_params_t));

    return ret;
}

sgx_status_t sgx_rsa_sign(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *data, uint32_t data_len, uint8_t *signature, uint32_t signature_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_rsa_len = sgx_calc_sealed_data_size(0, sizeof(rsa_params_t));
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

    const sgx_sealed_data_t *rsa_key_blob = (sgx_sealed_data_t *)(cmk_blob + sizeof(sgx_rsa3072_public_key_t));
    uint32_t rsa_key_len = sgx_get_encrypt_txt_len(rsa_key_blob);
    if (rsa_key_len == UINT32_MAX || rsa_key_len != sizeof(rsa_params_t)) {
        printf("ecall rsa_sign rsa key size:%d is not expected: %d.\n", rsa_key_len, sizeof(rsa_params_t));
        return SGX_ERROR_INVALID_PARAMETER;
    }

    rsa_params_t rsa_key = {0};
    ret= sgx_unseal_data((sgx_sealed_data_t *)rsa_key_blob, NULL, NULL, (uint8_t*)&rsa_key, &rsa_key_len);
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

sgx_status_t sgx_rsa_verify(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *data, uint32_t data_len, const uint8_t *signature, uint32_t signature_len, bool* result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_rsa_len = sgx_calc_sealed_data_size(0, sizeof(rsa_params_t));
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

sgx_status_t sgx_rsa_encrypt(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_rsa_len = sgx_calc_sealed_data_size(0, sizeof(rsa_params_t));
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

    if (plaintext_len > RSA_OAEP_3072_MAX_ENCRYPTION_SIZE) {
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

sgx_status_t sgx_rsa_decrypt(const uint8_t *cmk_blob, size_t cmk_blob_size, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t plaintext_len, uint32_t *req_plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint32_t sealed_rsa_len = sgx_calc_sealed_data_size(0, sizeof(rsa_params_t));
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

    const sgx_sealed_data_t *rsa_key_blob = (sgx_sealed_data_t *)(cmk_blob + sizeof(sgx_rsa3072_public_key_t));
    uint32_t rsa_key_len = sgx_get_encrypt_txt_len(rsa_key_blob);
    if (rsa_key_len == UINT32_MAX || rsa_key_len != sizeof(rsa_params_t)) {
        printf("ecall rsa_decrypt rsa key size:%d is not expected: %d.\n", rsa_key_len, sizeof(rsa_params_t));
        return SGX_ERROR_INVALID_PARAMETER;
    }

    rsa_params_t rsa_key = {0};
    ret= sgx_unseal_data((sgx_sealed_data_t *)rsa_key_blob, NULL, NULL, (uint8_t*)&rsa_key, &rsa_key_len);
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
