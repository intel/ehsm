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

#include "key_factory.h"
#include "key_operation.h"

#define SGX_DOMAIN_KEY_SIZE     16

#define RSA_2048_KEY_BITS   2048
#define RSA_3072_KEY_BITS   3072
#define RSA_4096_KEY_BITS   4096

#define RSA_2048_PUBLIC_KEY_PEM_SIZE    426
#define RSA_2048_PRIVATE_KEY_PEM_SIZE    1679

#define RSA_3072_PUBLIC_KEY_PEM_SIZE    625
#define RSA_3072_PRIVATE_KEY_PEM_SIZE    2484

#define RSA_4096_PUBLIC_KEY_PEM_SIZE    775
#define RSA_4096_PRIVATE_KEY_PEM_SIZE    3247

#define ECC_PUBLIC_KEY_PEM_SIZE     178
#define ECC_PRIVATE_KEY_PEM_SIZE    227
#define ECC_MAX_PLAINTEXT_SIZE      256

sgx_aes_gcm_128bit_key_t g_domain_key = {0};

static uint32_t ehsm_get_key_pem_size(const uint32_t keyspec)
{
    switch (keyspec)
    {
        case EH_RSA_2048:
            return RSA_2048_PUBLIC_KEY_PEM_SIZE + RSA_2048_PRIVATE_KEY_PEM_SIZE;
        case EH_RSA_3072:
            return RSA_3072_PUBLIC_KEY_PEM_SIZE + RSA_3072_PRIVATE_KEY_PEM_SIZE;
        case EH_RSA_4096:
            return RSA_4096_PUBLIC_KEY_PEM_SIZE + RSA_4096_PRIVATE_KEY_PEM_SIZE;
        case EH_EC_P256:
        case EH_SM2:
            return ECC_PUBLIC_KEY_PEM_SIZE + ECC_PRIVATE_KEY_PEM_SIZE;
        default:
            return UINT32_MAX;
    }
}

static uint32_t ehsm_calc_gcm_data_size(const uint32_t aad_size, const uint32_t plaintext_size)
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

static uint32_t ehsm_get_public_key_pem_size(const uint32_t keyspec)
{
    switch(keyspec)
    {
        case EH_RSA_2048:
            return RSA_2048_PUBLIC_KEY_PEM_SIZE;
        case EH_RSA_3072:
            return RSA_3072_PUBLIC_KEY_PEM_SIZE;
        case EH_RSA_4096:
            return RSA_4096_PUBLIC_KEY_PEM_SIZE;
        case EH_EC_P256:
        case EH_SM2:
            return ECC_PUBLIC_KEY_PEM_SIZE;
        default:
            return 0;
    }
}

sgx_status_t ehsm_create_keyblob(const uint32_t plaintext_size, const uint8_t *plaintext,
                                        const uint32_t aad_size, const uint8_t *aad,
                                        const uint32_t gcm_data_size, sgx_aes_gcm_data_ex_t *gcm_data)
{
    uint32_t real_aad_size = aad_size;
    if (NULL == aad)
        real_aad_size = 0;

    sgx_status_t ret = sgx_read_rand(gcm_data->iv, sizeof(gcm_data->iv));
    if (ret != SGX_SUCCESS) {
        printf("error generating iv.\n");
        return ret;
    }

    ret = sgx_rijndael128GCM_encrypt(&g_domain_key,
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

sgx_status_t ehsm_parse_keyblob(uint32_t plaintext_size, uint8_t *plaintext,
                                        const sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data || NULL == plaintext || NULL == plaintext_size
                 || plaintext_size < gcm_data->ciphertext_size)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_rijndael128GCM_decrypt(&g_domain_key,
                                                  gcm_data->payload, gcm_data->ciphertext_size,
                                                  plaintext,
                                                  gcm_data->iv, sizeof(gcm_data->iv),
                                                  &(gcm_data->payload[gcm_data->ciphertext_size]), gcm_data->aad_size,
                                                  (const sgx_aes_gcm_128bit_tag_t*)gcm_data->mac);
    if (SGX_SUCCESS != ret)
        printf("gcm decrypting failed.\n");
    else
        plaintext_size = gcm_data->ciphertext_size;

    return ret;
}

sgx_status_t ehsm_create_aes_key(ehsm_keyblob_t *cmk)
{
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t ehsm_create_asymmetric_key(ehsm_keyblob_t *cmk)
{
    sgx_status_t ret = SGX_SUCCESS;

    EVP_PKEY_CTX        *keypair        = NULL;
    EVP_PKEY            *pkey           = NULL;
    EC_GROUP            *ec_group       = NULL;
    BIO                 *bio            = NULL;
    uint8_t             *pem_keypair    = NULL;
    uint32_t            key_len         = 0;

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
        case EH_RSA_3072:
        case EH_RSA_4096:
            keypair = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            break;
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
            keypair = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            break;
        case EH_SM2:
            keypair = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
            break;
        default:
            break;
    }
    if (!keypair) {
        goto out;
    }

    if (!EVP_PKEY_keygen_init(keypair)) {
        goto out;
    }

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
            EVP_PKEY_CTX_set_rsa_keygen_bits(keypair, RSA_2048_KEY_BITS);
            break;
        case EH_RSA_3072:
            EVP_PKEY_CTX_set_rsa_keygen_bits(keypair, RSA_3072_KEY_BITS);
            break;
        case EH_RSA_4096:
            EVP_PKEY_CTX_set_rsa_keygen_bits(keypair, RSA_4096_KEY_BITS);
            break;
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keypair, NID_X9_62_prime256v1);
            break;
        case EH_SM2:
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keypair, NID_sm2);
            break;
        default:
            break;
    }
    
    if (!EVP_PKEY_keygen(keypair, &pkey)) {
        goto out;
    }

    EVP_PKEY_CTX_free(keypair);

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
        cmk->keybloblen = ehsm_calc_gcm_data_size(0, key_len);
        if (cmk->keybloblen != UINT32_MAX) {
            ret = SGX_SUCCESS;
            goto out;
        } else {
            goto out;
        }
    } else if (key_len > (cmk->keybloblen - sizeof(sgx_aes_gcm_data_ex_t))) {
        cmk->keybloblen = ehsm_calc_gcm_data_size(0, key_len);
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

    ret = ehsm_create_keyblob(key_len, pem_keypair, 0, NULL, cmk->keybloblen, (sgx_aes_gcm_data_ex_t*)cmk->keyblob);

    if (ret != SGX_SUCCESS) {
        goto out;
    }
out:
    return ret;
}

sgx_status_t ehsm_create_sm4_key(ehsm_keyblob_t *cmk)
{
    return SGX_ERROR_UNEXPECTED;
}