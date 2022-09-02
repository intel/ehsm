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

using namespace std;

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

sgx_status_t enclave_create_key(ehsm_keyblob_t *cmk, size_t cmk_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cmk->keybloblen == 0) {
        ret = ehsm_calc_keyblob_len(cmk->metadata);
        return ret;
    }

    switch (cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
        case EH_AES_GCM_192:
        case EH_AES_GCM_256:
            ret = ehsm_create_aes_key(cmk);
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
            ret = ehsm_create_ec_key(cmk);
            break;
        case EH_SM2:
            ret = ehsm_create_sm2_key(cmk);
            break;
        case EH_SM4:
            ret = ehsm_create_sm4_key(cmk);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;

    return ret;
}

sgx_status_t enclave_encrypt(const ehsm_keyblob_t* cmk, size_t cmk_len,
                        const ehsm_data_t *aad, size_t aad_len,
                        const ehsm_data_t *plaintext, size_t plaintext_len,
                        ehsm_data_t *ciphertext, size_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // todo: check parameter like enclave_create_key

    switch (cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
        case EH_AES_GCM_192:
        case EH_AES_GCM_256:
            ret = ehsm_aes_gcm_encrypt(cmk);
            break;
        case EH_SM4:
            ret = ehsm_sm4_encrypt(cmk);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;

    return ret;
}
        
sgx_status_t enclave_decrypt(const ehsm_keyblob_t* cmk, size_t cmk_len,
                    const ehsm_data_t *aad, size_t aad_len,
                    const ehsm_data_t *ciphertext, size_t ciphertext_len,
                    ehsm_data_t *plaintext, size_t plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // todo: check parameter like enclave_create_key

    switch (cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
        case EH_AES_GCM_192:
        case EH_AES_GCM_256:
            ret = ehsm_aes_gcm_derypt(cmk);
            break;
        case EH_SM4:
            ret = ehsm_sm4_decrypt(cmk);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;

    return ret;
}

sgx_status_t enclave_asymmetric_encrypt(const ehsm_keyblob_t* cmk, size_t cmk_len,
                    const ehsm_data_t *plaintext, size_t plaintext_len,
                    ehsm_data_t *ciphertext, size_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // todo: check parameter like enclave_create_key

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
        case EH_RSA_3072:
        case EH_RSA_4096:
            ret = ehsm_rsa_encrypt(cmk);
            break;
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
            ret = ehsm_ec_encrypt(cmk);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;

    return ret;
}

sgx_status_t enclave_asymmetric_decrypt(const ehsm_keyblob_t* cmk, size_t cmk_len,
                    const ehsm_data_t *ciphertext, uint32_t ciphertext_len,
                    ehsm_data_t *plaintext, uint32_t plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // todo: check parameter like enclave_create_key

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
        case EH_RSA_3072:
        case EH_RSA_4096:
            ret = ehsm_rsa_decrypt(cmk);
            break;
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
            ret = ehsm_ec_decrypt(cmk);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
        
    return ret;
}

sgx_status_t enclave_sign(const ehsm_keyblob_t* cmk, size_t cmk_len,
                    const ehsm_data_t *data, size_t data_len,
                    ehsm_data_t *signature, size_t signature_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // todo: check parameter like enclave_create_key

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
        case EH_RSA_3072:
        case EH_RSA_4096:
            ret = ehsm_rsa_sign(cmk);
            break;
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
            ret = ehsm_ec_sign(cmk);
            break;
        case EH_SM2:
            ret = ehsm_sm2_sign(cmk);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;

    return ret;
}
                                    
sgx_status_t enclave_verify(const ehsm_keyblob_t* cmk, size_t cmk_len,
                    const ehsm_data_t *data, size_t data_len,
                    const ehsm_data_t *signature, size_t signature_len,
                    bool* result)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // todo: check parameter like enclave_create_key

    switch (cmk->metadata.keyspec) {
        case EH_RSA_2048:
        case EH_RSA_3072:
        case EH_RSA_4096:
            ret = ehsm_rsa_verify(cmk);
            break;
        case EH_EC_P224:
        case EH_EC_P256:
        case EH_EC_P384:
        case EH_EC_P512:
            ret = ehsm_ec_verify(cmk);
            break;
        case EH_SM2:
            ret = ehsm_sm2_verify(cmk);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;

    return ret;
}

sgx_status_t enclave_generate_datakey(const ehsm_keyblob_t* cmk, size_t cmk_len,
                    const ehsm_data_t *aad, size_t aad_len,
                    ehsm_data_t *plaintext, size_t plaintext_len,
                    ehsm_data_t *ciphertext, size_t ciphertext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // todo: check parameter like enclave_create_key

    switch (cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
        case EH_AES_GCM_192:
        case EH_AES_GCM_256:
            ret = ehsm_aes_gcm_generate_datakey(cmk);
            break;
        case EH_SM4:
            ret = ehsm_sm4_generate_datakey(cmk);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;

    return ret;
}

sgx_status_t enclave_export_datakey(const ehsm_keyblob_t* s_cmk, size_t s_cmk_len,
                    const ehsm_data_t *aad, size_t aad_len,
                    ehsm_data_t *oldkey, size_t oldkey_len,
                    const ehsm_keyblob_t* d_cmk, size_t d_cmk_len,
                    ehsm_data_t *newkey, size_t newkey_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    return ret;
}

sgx_status_t enclave_get_target_info(sgx_target_info_t* target_info)
{
    return sgx_self_target(target_info);
}

sgx_status_t enclave_create_report(const sgx_target_info_t* p_qe3_target, sgx_report_t* p_report)
{
    sgx_status_t ret = SGX_SUCCESS;

    sgx_report_data_t report_data = { 0 };

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
    if (p_apikey == NULL || apikey_len > EH_API_KEY_SIZE){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (cipherapikey == NULL || cipherapikey_len < EH_API_KEY_SIZE + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE){
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
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                     p_apikey, apikey_len,
                                     cipherapikey,
                                     iv, EH_AES_GCM_IV_SIZE,
                                     NULL, 0,
                                     reinterpret_cast<uint8_t (*)[EH_AES_GCM_MAC_SIZE]>(mac));
    if (ret != SGX_SUCCESS) {
        printf("error encrypting plain text\n");
    }
    memset_s(sk_key, sizeof(sgx_ec_key_128bit_t), 0, sizeof(sgx_ec_key_128bit_t));
    memset_s(temp, apikey_len, 0, apikey_len);
    return ret;
}

sgx_status_t enclave_get_apikey(uint8_t *apikey, uint32_t keylen)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (apikey == NULL || keylen != EH_API_KEY_SIZE){
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate apikey
    std::string psw_chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
    uint8_t temp[keylen];
    ret = sgx_read_rand(temp, keylen);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    for (int i = 0; i < keylen; i++) {
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
sgx_status_t enclave_verify_quote_policy(uint8_t* quote, uint32_t quote_len, 
                            const char* mr_signer_good, uint32_t mr_signer_good_len, 
                            const char* mr_enclave_good, uint32_t mr_enclave_good_len)
{
    if(quote == NULL || mr_signer_good == NULL || mr_enclave_good == NULL) {
        printf("quote or mr_signer_good or mr_enclave_good is null");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    string mr_signer_str;
    string mr_enclave_str;
    char mr_signer_temp[3] = {0};
    char mr_enclave_temp[3] = {0};
    sgx_quote3_t *p_sgx_quote = (sgx_quote3_t *)quote;
    for(int i = 0; i < SGX_HASH_SIZE; i++) {
        snprintf(mr_signer_temp, sizeof(mr_signer_temp) , "%02x", p_sgx_quote->report_body.mr_signer.m[i]);
        snprintf(mr_enclave_temp, sizeof(mr_enclave_temp), "%02x", p_sgx_quote->report_body.mr_enclave.m[i]);
        mr_signer_str += mr_signer_temp;
        mr_enclave_str += mr_enclave_temp;
    }
    if((mr_signer_str.size() != mr_signer_good_len) || 
       (mr_enclave_str.size() != mr_enclave_good_len)) {
        printf("mr_signer_str length is not same with mr_signer_good_len or\ 
                mr_enclave_str length is not same with mr_enclave_good_len!\n");
        return SGX_ERROR_UNEXPECTED;
    }
    if(strncmp(mr_signer_good, mr_signer_str.c_str(), mr_signer_str.size()) != 0 || 
       strncmp(mr_enclave_good, mr_enclave_str.c_str(), mr_enclave_str.size()) != 0) {
        printf("mr_signer or mr_enclave is invalid!\n");
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}