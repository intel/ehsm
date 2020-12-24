/*
 * Copyright (C) 2019-2020 Intel Corporation
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

#include "EnclaveHsm.h"
#include "EnclaveSecureUtils.h"
#include "seal.h"
#include "enclave_hsm_t.h"

#include <string>
#include <stdio.h>
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

sgx_status_t sgx_create_aes_key(uint8_t *cmk_blob, size_t cmk_blob_size,
        size_t *req_blob_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t real_blob_len = sgx_calc_sealed_data_size(0, SGX_AES_KEY_SIZE);

    if (real_blob_len == 0xFFFFFFFF)
        return SGX_ERROR_UNEXPECTED;

    if (req_blob_size != NULL) {
        *req_blob_size = real_blob_len;
        return SGX_SUCCESS;
    }

    if (cmk_blob == NULL || cmk_blob_size != real_blob_len)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t* tmp = (uint8_t *) malloc(SGX_AES_KEY_SIZE);
    if (tmp == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = sgx_read_rand(tmp, SGX_AES_KEY_SIZE);
    if (ret != SGX_SUCCESS) {
        free(tmp);
        return ret;
    }

    ret = seal(cmk_blob, cmk_blob_size, tmp, SGX_AES_KEY_SIZE);

    memset_s(tmp, SGX_AES_KEY_SIZE, 0, SGX_AES_KEY_SIZE);

    free(tmp);

    return ret;
}

sgx_status_t sgx_aes_encrypt(const uint8_t *aad, size_t aad_len,
                             const uint8_t *cmk_blob, size_t cmk_blob_size,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *ciphertext, size_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk_blob == NULL ||
            cmk_blob_size < sgx_calc_sealed_data_size(0, SGX_AES_KEY_SIZE))
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (ciphertext == NULL ||
            ciphertext_len < plaintext_len + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(ciphertext + plaintext_len);
    uint8_t *mac = (uint8_t *)(ciphertext + plaintext_len + EH_AES_GCM_IV_SIZE);

    ret = sgx_read_rand(iv, EH_AES_GCM_IV_SIZE);
    if (ret != SGX_SUCCESS) {
        printf("error generating IV\n");
        return ret;
    }

    sgx_key_128bit_t enc_key;

    ret = unseal(cmk_blob, cmk_blob_size, (uint8_t *) &enc_key, sizeof(sgx_key_128bit_t));
    if (ret != SGX_SUCCESS) {
        printf("error unsealing key 0x%lx\n", ret);
        return ret;
    }

    ret = sgx_rijndael128GCM_encrypt(&enc_key, plaintext, plaintext_len,
            ciphertext, iv, EH_AES_GCM_IV_SIZE, aad, aad_len,
            reinterpret_cast<uint8_t (*)[16]>(mac));
    if (SGX_SUCCESS != ret) {
        printf("error encrypting plain text\n");
    }

    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));

    return ret;
}

sgx_status_t sgx_aes_decrypt(const uint8_t *aad, size_t aad_len,
                             const uint8_t *cmk_blob, size_t cmk_blob_size,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *plaintext, size_t plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk_blob == NULL ||
            cmk_blob_size < sgx_calc_sealed_data_size(0, SGX_AES_KEY_SIZE))
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (ciphertext == NULL ||
            ciphertext_len < plaintext_len + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(ciphertext + plaintext_len);
    uint8_t *mac = (uint8_t *)(ciphertext + plaintext_len + EH_AES_GCM_IV_SIZE );

    sgx_key_128bit_t dec_key;

    ret = unseal(cmk_blob, cmk_blob_size, (uint8_t *) &dec_key, sizeof(sgx_key_128bit_t));
    if (ret != SGX_SUCCESS) {
        printf("error unsealing key");
        return ret;
    }

    ret = sgx_rijndael128GCM_decrypt(&dec_key, ciphertext, plaintext_len, plaintext,
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

