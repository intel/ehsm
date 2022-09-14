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
#include "key_factory.h"
#include "key_operation.h"

using namespace std;

#define SGX_AES_KEY_SIZE 16

#define SGX_DOMAIN_KEY_SIZE 16

#define RSA_OAEP_3072_MOD_SIZE 384
#define RSA_OAEP_3072_EXP_SIZE 4

#define EH_ENCRYPT_MAX_SIZE (6 * 1024)

#define EH_DATA_KEY_MAX_SIZE 1024

#define EH_AES_GCM_IV_SIZE 12
#define EH_AES_GCM_MAC_SIZE 16

#define RSA_OAEP_2048_SHA_256_MAX_ENCRYPTION_SIZE 190
//#define RSA_2048_OAEP_SHA_1_MAX_ENCRYPTION_SIZE       214

#define RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE 318
//#define RSA_3072_OAEP_SHA_1_MAX_ENCRYPTION_SIZE       342

#define SM2PKE_MAX_ENCRYPTION_SIZE 6047

#define RSA_OAEP_3072_CIPHER_LENGTH 384
#define RSA_OAEP_3072_SIGNATURE_SIZE 384

// Used to store the secret passed by the SP in the sample code.

static const sgx_ec256_public_t g_sp_pub_key = {
    {0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
     0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
     0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
     0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38},
    {0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
     0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
     0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
     0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06}

};

sgx_status_t enclave_create_key(ehsm_keyblob_t *cmk, size_t cmk_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cmk->metadata.keyspec >= INVALID_VALUE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        if (cmk->keybloblen == 0)
        {
            ret = ehsm_create_aes_key(NULL,
                                      0,
                                      &(cmk->keybloblen),
                                      (ehsm_keyspec_t)(cmk->metadata.keyspec));
        }
        else
        {
            ret = ehsm_create_aes_key(cmk->keyblob,
                                      cmk->keybloblen,
                                      NULL,
                                      (ehsm_keyspec_t)(cmk->metadata.keyspec));
        }
        break;
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_create_rsa_key(cmk);
        break;
    case EH_EC_P224:
    case EH_EC_P256:
    case EH_EC_P384:
    case EH_EC_P512:
    case EH_SM2:
        ret = ehsm_create_ec_key(cmk);
        break;
        case EH_SM4_CTR:
        case EH_SM4_CBC:
        if (cmk->keybloblen == 0)
        {
            ret = ehsm_create_sm4_key(NULL,
                                      0,
                                      &(cmk->keybloblen),
                                      (ehsm_keyspec_t)(cmk->metadata.keyspec));
        }
        else
        {
            ret = ehsm_create_sm4_key(cmk->keyblob,
                                      cmk->keybloblen,
                                      NULL,
                                      (ehsm_keyspec_t)(cmk->metadata.keyspec));
        }
        break;
    default:
        break;
    }

    return ret;
}

sgx_status_t enclave_encrypt(const ehsm_keyblob_t *cmk, size_t cmk_len,
                             const ehsm_data_t *aad, size_t aad_len,
                             const ehsm_data_t *plaintext, size_t plaintext_len,
                             ehsm_data_t *ciphertext, size_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY || plaintext == NULL || ciphertext == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_AES_GCM_192 &&
        cmk->metadata.keyspec != EH_AES_GCM_256 &&
        cmk->metadata.keyspec != EH_SM4_CTR &&
        cmk->metadata.keyspec != EH_SM4_CBC)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* only support to directly encrypt data of less than 6 KB */
    if (plaintext->data == NULL || plaintext->datalen == 0 ||
        plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        ret = ehsm_aes_gcm_encrypt(aad, cmk, plaintext, ciphertext);
        break;
    case EH_SM4_CTR:
        ret = ehsm_sm4_ctr_encrypt(cmk, plaintext, ciphertext);
        break;
    case EH_SM4_CBC:
        ret = ehsm_sm4_cbc_encrypt(cmk, plaintext, ciphertext);
        break;
    default:
        break;
    }

    return ret;
}

sgx_status_t enclave_decrypt(const ehsm_keyblob_t *cmk, size_t cmk_len,
                             const ehsm_data_t *aad, size_t aad_len,
                             const ehsm_data_t *ciphertext, size_t ciphertext_len,
                             ehsm_data_t *plaintext, size_t plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY || plaintext == NULL || ciphertext == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_AES_GCM_192 &&
        cmk->metadata.keyspec != EH_AES_GCM_256 &&
        cmk->metadata.keyspec != EH_SM4_CTR &&
        cmk->metadata.keyspec != EH_SM4_CBC)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ciphertext->data == NULL || ciphertext->datalen == 0)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        ret = ehsm_aes_gcm_decrypt(aad, cmk, ciphertext, plaintext);
        break;
    case EH_SM4_CTR:
        ret = ehsm_sm4_ctr_decrypt(cmk, ciphertext, plaintext);
        break;
    case EH_SM4_CBC:
        ret = ehsm_sm4_cbc_decrypt(cmk, ciphertext, plaintext);
        break;
    default:
        break;
    }

    return ret;
}

sgx_status_t enclave_asymmetric_encrypt(const ehsm_keyblob_t *cmk, size_t cmk_len,
                                        ehsm_data_t *plaintext, size_t plaintext_len,
                                        ehsm_data_t *ciphertext, size_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    if (cmk == NULL || plaintext == NULL || ciphertext == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_rsa_encrypt(cmk, plaintext, ciphertext);
        /* code */
        break;
    case EH_SM2:
        ret = ehsm_sm2_encrypt(cmk, plaintext, ciphertext);
    default:
        break;
    }
    return ret;
}

sgx_status_t enclave_asymmetric_decrypt(const ehsm_keyblob_t *cmk, size_t cmk_len,
                                        ehsm_data_t *ciphertext, uint32_t ciphertext_len,
                                        ehsm_data_t *plaintext, uint32_t plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // TODO : check parameter like enclave_create_key
    if (cmk == NULL || plaintext == NULL || ciphertext == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_rsa_decrypt(cmk, ciphertext, plaintext);
        break;
    case EH_SM2:
        ret = ehsm_sm2_decrypt(cmk, ciphertext, plaintext);
    default:
        break;
    }
    return ret;
}

sgx_status_t enclave_sign(const ehsm_keyblob_t* cmk, size_t cmk_len,
                          const ehsm_data_t *data, size_t data_len,
                          const ehsm_data_t *appid, size_t appid_len,
                          ehsm_data_t *signature, size_t signature_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // Verify parameters
    if (cmk->metadata.digest_mode == NULL || cmk->metadata.padding_mode == NULL || cmk->metadata.keyspec >= INVALID_VALUE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (signature == NULL || signature_len == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // check signatrue length
    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
        if (signature->datalen < RSA_OAEP_2048_SIGNATURE_SIZE)
        {
            printf("ecall rsa_sign 2048 signature_len is too small than the expected 256.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    case EH_RSA_3072:
        if (signature->datalen < RSA_OAEP_3072_SIGNATURE_SIZE)
        {
            printf("ecall rsa_sign 3072 signature_len is too small than the expected 384.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    case EH_RSA_4096:
        if (signature->datalen < RSA_OAEP_4096_SIGNATURE_SIZE)
        {
            printf("ecall rsa_sign 4096 signature_len is too small than the expected 512.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    case EH_EC_P256:
        if (signature->datalen > EC_P256_SIGNATURE_MAX_SIZE)
        {
            printf("ecall ec_sign 256 or sm2 signature_len is too large than the expected 64.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    case EH_SM2:
        if (signature->datalen > EC_SM2_SIGNATURE_MAX_SIZE)
        {
            printf("ecall ec_sign sm2 signature_len is too large than the expected 64.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        if (cmk->metadata.digest_mode != EH_SM3)
        {
            printf("ecall ec_sign sm2 digest made not support.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    }

    // check cmk_blob and cmk_blob_size
    if (cmk == NULL || cmk_len == NULL || cmk->keybloblen == NULL || cmk->keyblob == NULL)
    {
        printf("ecall sign cmk or cmk len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (data == NULL || data_len == 0)
    {
        printf("ecall sign data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_rsa_sign(cmk,
                            cmk->metadata.padding_mode,
                            cmk->metadata.digest_mode,
                            cmk->metadata.keyspec,
                            data,
                            signature);
        break;
    // case EH_EC_P224:
    case EH_EC_P256:
        // case EH_EC_P384:
        // case EH_EC_P512:
            ret = ehsm_ecc_sign(cmk,
                                cmk->metadata.digest_mode,
                                cmk->metadata.keyspec,
                                data,
                                signature,
                                &signature->datalen);
            break;
        case EH_SM2:
            ret = ehsm_sm2_sign(cmk,
                                cmk->metadata.digest_mode,
                                cmk->metadata.keyspec,
                                data,
                                appid,
                                signature,
                                &signature->datalen);
            break;
        default:
            printf("ecall sign unsupport keyspec.\n");
            return SGX_ERROR_INVALID_PARAMETER;
            
    }

    return ret;
}
                                    
sgx_status_t enclave_verify(const ehsm_keyblob_t* cmk, size_t cmk_len,
                            const ehsm_data_t *data, size_t data_len,
                            const ehsm_data_t *appid, size_t appid_len,
                            const ehsm_data_t *signature, size_t signature_len,
                            bool* result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // Verify parameters
    if (cmk->metadata.digest_mode == NULL || cmk->metadata.padding_mode == NULL || cmk->metadata.keyspec >= INVALID_VALUE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // check signature length
    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
        if (signature->datalen < RSA_OAEP_2048_SIGNATURE_SIZE)
        {
            printf("ecall rsa_verify 2048 signature_len is too small than the expected 256.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    case EH_RSA_3072:
        if (signature->datalen < RSA_OAEP_3072_SIGNATURE_SIZE)
        {
            printf("ecall rsa_verify 3072 signature_len is too small than the expected 384.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    case EH_RSA_4096:
        if (signature->datalen < RSA_OAEP_4096_SIGNATURE_SIZE)
        {
            printf("ecall rsa_verify 4096 signature_len is too small than the expected 512.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    case EH_EC_P256:
        if (signature->datalen > EC_P256_SIGNATURE_MAX_SIZE)
        {
            printf("ecall ec_sign 256 signature_len is too large than the expected.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    case EH_SM2:
        if (signature->datalen > EC_SM2_SIGNATURE_MAX_SIZE)
        {
            printf("ecall ec_sign sm2 signature_len is too large than the expected.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        if (cmk->metadata.digest_mode != EH_SM3)
        {
            printf("ecall ec_sign sm2 digest made not support.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        break;
    }

    if (cmk == NULL || cmk_len == NULL || cmk->keybloblen == NULL || cmk->keyblob == NULL)
    {
        printf("ecall verify cmk or cmk len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (data == NULL || data_len == 0)
    {
        printf("ecall verify data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (result == NULL)
    {
        printf("ecall verify result is NULL.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_rsa_verify(cmk,
                              cmk->metadata.padding_mode,
                              cmk->metadata.digest_mode,
                              cmk->metadata.keyspec,
                              data,
                              signature,
                              result);
        break;
    // case EH_EC_P224:
    case EH_EC_P256:
        // case EH_EC_P384:
        // case EH_EC_P512:
            ret = ehsm_ecc_verify(cmk,
                                  cmk->metadata.digest_mode,
                                  cmk->metadata.keyspec,
                                  data,
                                  signature,
                                  result);
            break;
        case EH_SM2:
            ret = ehsm_sm2_verify(cmk,
                                  cmk->metadata.digest_mode,
                                  cmk->metadata.keyspec,
                                  data,
                                  appid,
                                  signature,
                                  result);
            break;
        default:
            printf("ecall verify unsupport keyspec.\n");
            return SGX_ERROR_INVALID_PARAMETER;
            
    }

    return ret;
}

sgx_status_t enclave_generate_datakey(const ehsm_keyblob_t *cmk, size_t cmk_len,
                                      const ehsm_data_t *aad, size_t aad_len,
                                      ehsm_data_t *plaintext, size_t plaintext_len,
                                      ehsm_data_t *ciphertext, size_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk->metadata.keyspec >= INVALID_VALUE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (plaintext == NULL || ciphertext == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (plaintext->datalen > 1024 || plaintext->datalen == 0)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        ret = ehsm_aes_gcm_generate_datakey(cmk,
                                            aad,
                                            plaintext,
                                            ciphertext);
        break;
    case EH_SM4:
        ret = ehsm_generate_datakey_sm4(cmk,
                                        aad,
                                        plaintext,
                                        ciphertext);
        break;
    default:
        break;
    }

    return ret;
}

sgx_status_t enclave_export_datakey(const ehsm_keyblob_t *cmk, size_t cmk_len,
                                    const ehsm_data_t *aad, size_t aad_len,
                                    ehsm_data_t *olddatakey, size_t olddatakey_len,
                                    const ehsm_keyblob_t *ukey, size_t ukey_len,
                                    ehsm_data_t *newdatakey, size_t newdatakey_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ehsm_data_t *tmp_datakey = NULL;
    size_t tmp_datakey_len = 0;
    tmp_datakey = (ehsm_data_t *)malloc(SIZE_OF_DATA_T(0));
    if (tmp_datakey == NULL)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    if (cmk->keyblob == NULL || ukey->keyblob == NULL || olddatakey->data == NULL || newdatakey->data == NULL)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    // datakey plaintext
    // to calc the plaintext len
    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
        tmp_datakey->datalen = olddatakey->datalen - EH_AES_GCM_IV_SIZE - EH_AES_GCM_MAC_SIZE;
        tmp_datakey_len = SIZE_OF_DATA_T(tmp_datakey->datalen);
        break;
    case EH_SM4:
        // TODO :
        // tmp_datakey->datalen = olddatakey->datalen - SGX_SM4_IV_SIZE;
        // tmp_datakey_len = SIZE_OF_DATA_T(tmp_datakey->datalen);
        // break;
    default:
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    tmp_datakey = (ehsm_data_t *)realloc(tmp_datakey, SIZE_OF_DATA_T(tmp_datakey->datalen));
    if (tmp_datakey == NULL)
    {
        tmp_datakey_len = 0;
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    // decrypt olddatakey using cmk
    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
        ret = enclave_decrypt(cmk, cmk_len, aad, aad_len, olddatakey, olddatakey_len, tmp_datakey, tmp_datakey_len);
        break;
    case EH_SM4:
        // TODO :
        // ret = enclave_decrypt(cmk, cmk_len, aad, aad_len, olddatakey, olddatakey_len, tmp_datakey, tmp_datakey_len);
        // break;
    default:
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    // check enclave_decrypt status
    if (ret == SGX_ERROR_UNEXPECTED || ret == SGX_ERROR_INVALID_PARAMETER)
    {
        goto out;
    }
    // calc length
    if (newdatakey->datalen == 0)
    {
        ret = enclave_asymmetric_encrypt(ukey, ukey_len, tmp_datakey, tmp_datakey_len, newdatakey, newdatakey_len);
        goto out;
    }

    // encrypt datakey using ukey
    // or just ret = enclave_asymmetric_encrypt(ukey, ukey_len, tmp_datakey, tmp_datakey_len, newdatakey, newdatakey_len);
    switch (ukey->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
        ret = enclave_asymmetric_encrypt(ukey, ukey_len, tmp_datakey, tmp_datakey_len, newdatakey, newdatakey_len);
        break;
    case EH_SM2:
        ret = enclave_asymmetric_encrypt(ukey, ukey_len, tmp_datakey, tmp_datakey_len, newdatakey, newdatakey_len);
        break;
    case EH_EC_P256:
        /* TODO : break;*/
    case EH_EC_P512:
        /* TODO :break;*/

    default:
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
out:
    if (tmp_datakey_len != 0)
    {
        memset_s(tmp_datakey, tmp_datakey_len, 0, tmp_datakey_len);
    }
    SAFE_FREE(tmp_datakey);
    return ret;
}

sgx_status_t enclave_get_target_info(sgx_target_info_t *target_info)
{
    return sgx_self_target(target_info);
}

sgx_status_t enclave_create_report(const sgx_target_info_t *p_qe3_target, sgx_report_t *p_report)
{
    sgx_status_t ret = SGX_SUCCESS;

    sgx_report_data_t report_data = {0};

    // Generate the report for the app_enclave
    ret = sgx_create_report(p_qe3_target, &report_data, p_report);

    return ret;
}

sgx_status_t enclave_get_rand(uint8_t *data, uint32_t datalen)
{
    if (data == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    return sgx_read_rand(data, datalen);
}

sgx_status_t enclave_generate_apikey(sgx_ra_context_t context,
                                     uint8_t *p_apikey, uint32_t apikey_len,
                                     uint8_t *cipherapikey, uint32_t cipherapikey_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (p_apikey == NULL || apikey_len > EH_API_KEY_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (cipherapikey == NULL || cipherapikey_len < EH_API_KEY_SIZE + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate apikey
    std::string psw_chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
    uint8_t temp[apikey_len];
    ret = sgx_read_rand(temp, apikey_len);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }
    for (int i = 0; i < apikey_len; i++)
    {
        p_apikey[i] = psw_chars[temp[i] % psw_chars.length()];
    }

    // struct cipherapikey{
    //     uint8_t apikey[32]
    //     uint8_t iv[12]
    //     uint8_t mac[16]
    // }
    uint8_t *iv = (uint8_t *)(cipherapikey + apikey_len);
    uint8_t *mac = (uint8_t *)(cipherapikey + apikey_len + EH_AES_GCM_IV_SIZE);
    // get sk and encrypt apikey
    sgx_ec_key_128bit_t sk_key;
    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }
    ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                     p_apikey, apikey_len,
                                     cipherapikey,
                                     iv, EH_AES_GCM_IV_SIZE,
                                     NULL, 0,
                                     reinterpret_cast<uint8_t(*)[EH_AES_GCM_MAC_SIZE]>(mac));
    if (ret != SGX_SUCCESS)
    {
        printf("error encrypting plain text\n");
    }
    memset_s(sk_key, sizeof(sgx_ec_key_128bit_t), 0, sizeof(sgx_ec_key_128bit_t));
    memset_s(temp, apikey_len, 0, apikey_len);
    return ret;
}

sgx_status_t enclave_get_apikey(uint8_t *apikey, uint32_t keylen)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (apikey == NULL || keylen != EH_API_KEY_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate apikey
    std::string psw_chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
    uint8_t temp[keylen];
    ret = sgx_read_rand(temp, keylen);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }
    for (int i = 0; i < keylen; i++)
    {
        apikey[i] = psw_chars[temp[i] % psw_chars.length()];
    }

    memset_s(temp, keylen, 0, keylen);
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
                                           uint8_t *p_message,
                                           size_t message_size,
                                           uint8_t *p_mac,
                                           size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if (mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if (message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do
    {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if (SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if (SGX_SUCCESS != ret)
        {
            break;
        }
        if (0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    } while (0);

    return ret;
}

/*
 *  @brief check mr_signer and mr_enclave
 *  @param quote quote data
 *  @param quote_len the length of quote
 *  @param mr_signer_good the mr_signer
 *  @param mr_signer_good_len the length of mr_signer_good
 *  @param mr_enclave_good the mr_enclave
 *  @param mr_enclave_good_len the length of mr_enclave_good
 *  @return SGX_ERROR_INVALID_PARAMETER paramater is incorrect
 *  @return SGX_ERROR_UNEXPECTED mr_signer or mr_enclave is invalid
 */
sgx_status_t enclave_verify_quote_policy(uint8_t *quote, uint32_t quote_len,
                                         const char *mr_signer_good, uint32_t mr_signer_good_len,
                                         const char *mr_enclave_good, uint32_t mr_enclave_good_len)
{
    if (quote == NULL || mr_signer_good == NULL || mr_enclave_good == NULL)
    {
        printf("quote or mr_signer_good or mr_enclave_good is null");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    string mr_signer_str;
    string mr_enclave_str;
    char mr_signer_temp[3] = {0};
    char mr_enclave_temp[3] = {0};
    sgx_quote3_t *p_sgx_quote = (sgx_quote3_t *)quote;
    for (int i = 0; i < SGX_HASH_SIZE; i++)
    {
        snprintf(mr_signer_temp, sizeof(mr_signer_temp), "%02x", p_sgx_quote->report_body.mr_signer.m[i]);
        snprintf(mr_enclave_temp, sizeof(mr_enclave_temp), "%02x", p_sgx_quote->report_body.mr_enclave.m[i]);
        mr_signer_str += mr_signer_temp;
        mr_enclave_str += mr_enclave_temp;
    }
    if ((mr_signer_str.size() != mr_signer_good_len) ||
        (mr_enclave_str.size() != mr_enclave_good_len))
    {
        printf("mr_signer_str length is not same with mr_signer_good_len or\ 
                mr_enclave_str length is not same with mr_enclave_good_len!\n");
        return SGX_ERROR_UNEXPECTED;
    }
    if (strncmp(mr_signer_good, mr_signer_str.c_str(), mr_signer_str.size()) != 0 ||
        strncmp(mr_enclave_good, mr_enclave_str.c_str(), mr_enclave_str.size()) != 0)
    {
        printf("mr_signer or mr_enclave is invalid!\n");
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}