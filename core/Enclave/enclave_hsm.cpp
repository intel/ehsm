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

// sgx-ssl-framework start

/**
 * @brief Get the Key Size from cmk
 * 
 * @param cmk use the keyblob passed in by cmk to get the struct for key
 * @return uint32_t 
 */
uint32_t GetKeySize(ehsm_keyblob_t cmk)
{
    //TODO: return key size from keyblob
}

/**
 * @brief Get the padding mode from cmk
 * 
 * @param cmk use the keyblob passed in by cmk to get the struct for key
 * @return uint32_t (tempoary)
 */
uint8_t GetPaddingMode(ehsm_keyblob_t cmk)
{
    //TODO: return padding mode enum
}

/**
 * @brief Get the digest mode from cmk
 * 
 * @param cmk use the keyblob passed in by cmk to get the struct for key
 * @return const EVP_MD* (openssl callback, tempoary)
 */
const EVP_MD* GetDigestMode(ehsm_keyblob_t cmk)
{
    //TODO: return EVP_MD function
    switch (keyblob.digestMode)
    {
        case EH_SHA1:
            return EVP_sha1; 
        //TODO
    }
}

/**
 * @brief Get the rsa public exponent from cmk
 * rsa key only
 * 
 * @param cmk use the keyblob passed in by cmk to get the struct for key
 * @return uint64_t, the prime number from 3 to 2^64-1
 */
uint64_t GetRsaExponent(ehsm_keyblob_t cmk)
{
    //TODO: return rsa public exponent from keyblob

}

/**
 * @brief Get the digest mode from cmk
 * aes_gcm and sm4 only
 * 
 * @param cmk use the keyblob passed in by cmk to get the struct for key
 * @return const CHIPER* (openssl callback, tempoary)
 */
const CHIPER* GetAesGcmBlockMode(aes_gcm_key_data_t &keyblob)
{
    //TODO: return EVP method
}

//TODO: get other parameters

static uint32_t sgx_calc_gcm_data_size(const uint32_t aad_size, const uint32_t plaintext_size)
{
    if (aad_size > UINT32_MAX - sizeof(aes_gcm_key_data_t))
        return UINT32_MAX;

    if (plaintext_size > UINT32_MAX - sizeof(aes_gcm_key_data_t))
        return UINT32_MAX;

    if (aad_size > UINT32_MAX - plaintext_size)
        return UINT32_MAX;

    if (sizeof(aes_gcm_key_data_t) > UINT32_MAX - plaintext_size - aad_size)
        return UINT32_MAX;

    return (aad_size + plaintext_size + sizeof(aes_gcm_key_data_t));
}

static uint32_t sgx_get_gcm_ciphertext_size(const aes_gcm_key_data_t *gcm_data)
{
    if (NULL == gcm_data)
        return UINT32_MAX;

    return gcm_data->ciphertext_size;
}

/**
 * @brief encrypt the key with sgx_rijndael128GCM_encrypt
 * use to encrypt the key that will send to dkeyserver only
 * sgx_rijndael128GCM_encrypt() is running in enclave
 * 
 */
static sgx_status_t sgx_gcm_encrypt(/* param */)
{
    //TODO: call sgx_rijndael128GCM_encrypt()
    
    sgx_status_t ret;
    
    return ret;
}

/**
 * @brief decrypt the key with sgx_rijndael128GCM_decrypt
 * use to decrypt the domain_key from dkeyserver only 
 * sgx_rijndael128GCM_decrypt() is running in enclave
 * 
 */
static sgx_status_t sgx_gcm_decrypt(/* param */)
{
    //TODO:call sgx_rijndael128GCM_decrypt()

    sgx_status_t ret;
    
    return ret;
}

/**
 * @brief generate aes_gcm key with openssl api
 * running in enclave
 * 
 */
sgx_status_t enclave_create_aes_key(/* param */)
{
    //TODO: create aes_gcm key
    sgx_status_t ret;
    ret = sgx_gcm_encrypt(/* param */);

    return ret;
}

/**
 * @brief generate rsa key with openssl api
 * running in enclave
 * 
 */
sgx_status_t enclave_create_rsa_key(/* param */)
{
    //TODO: create rsa key
    sgx_status_t ret;
    ret = sgx_gcm_encrypt(/* param */);

    return ret;
}

/**
 * @brief generate ec key with openssl api
 * running in enclave
 * 
 */
sgx_status_t enclave_create_ec_key(/* param */)
{
    //TODO: create ec key
    sgx_status_t ret;
    ret = sgx_gcm_encrypt(/* param */);

    return ret;
}

/**
 * @brief generate hmac key with openssl api
 * running in enclave
 * 
 */
sgx_status_t enclave_create_hmac_key(/* param */)
{
    //TODO: create hmac key
    sgx_status_t ret;
    ret = sgx_gcm_encrypt(/* param */);

    return ret;
}

/**
 * @brief generate sm2 key with openssl api
 * running in enclave
 * 
 */
sgx_status_t enclave_create_sm2_key(uint8_t *cmk_blob, uint32_t cmk_blob_size, uint32_t *req_blob_size)
{
    //TODO: create sm2 key
    sgx_status_t ret;
    ret = sgx_gcm_encrypt(/* param */);

    return ret;
}

/**
 * @brief generate sm4 key with openssl api
 * running in enclave
 * 
 */
sgx_status_t enclave_create_sm4_key(uint8_t *cmk_blob, uint32_t cmk_blob_size, uint32_t *req_blob_size)
{
    //TODO: create sm4 key
    sgx_status_t ret;
    ret = sgx_gcm_encrypt(/* param */);

    return ret;
}

/**
 * @brief encrypt plaintext with aes_gcm key
 * key needs to decrypt with sgx_gcm_decrypt() firstly
 * running in enclave
 * 
 */
sgx_status_t enclave_aes_encrypt(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: encrypt by aes_gcm key

    return ret;
}

/**
 * @brief encrypt plaintext with sm2 key
 * key needs to decrypt with sgx_gcm_decrypt() firstly
 * running in enclave
 * 
 */
sgx_status_t enclave_sm2_encrypt(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: encrypt by sm2 key

    return ret;
}

/**
 * @brief decrypt ciphertext with aes_gcm key
 * key needs to decrypt with sgx_gcm_decrypt() firstly
 * running in enclave
 * 
 */
sgx_status_t enclave_aes_decrypt(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: encrypt by aes key

    return ret;
}

/**
 * @brief decrypt ciphertext with sm4 key
 * key needs to decrypt with sgx_gcm_decrypt() firstly
 * running in enclave
 * 
 */
sgx_status_t enclave_sm4_decrypt(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: encrypt by sm4 key

    return ret;
}

sgx_status_t enclave_rsa_encrypt(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: encrypt by rsa key

    return ret;
}

sgx_status_t enclave_rsa_decrypt(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: decrypt by rsa key
    
    return ret;
}

sgx_status_t enclave_sm2_decrypt(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: decrypt by sm2 key
    
    return ret;
}

/**
 * @brief generate a random array and encrypt with cmk
 * key needs to decrypt with sgx_gcm_decrypt() firstly
 * running in enclave
 * 
 */
sgx_status_t enclave_generate_datakey(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *datakey = NULL;

    //TODO: generate random number

    //TODO: encrypt key plaintext
    switch(key_spec) {
        case EH_AES_GCM_128:
        case EH_AES_GCM_192:
        case EH_AES_GCM_256:
            //TODO: encrypt
            break;
        case EH_SM4:
            /TODO: encrypt
            break;
        default:
            return SGX_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

sgx_status_t enclave_export_datakey(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: use the cmk to decrypt the datakey cipher text

    //TODO: use the user-suplied rsa key to encrypt the datakey plaint text again.

    return ret;
}

/**
 * @brief make rsa sign with the designated digest mode
 * digest mode is optional (temporary)
 * running in enclave 
 * 
 */
sgx_status_t enclave_rsa_sign(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: create rsa key sign

    return ret;
}

/**
 * @brief make rsa verify with the designated digest mode
 * digest mode is optional (temporary)
 * running in enclave 
 * 
 */
sgx_status_t enclave_rsa_verify(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: verify rsa key

    return ret;
}

/**
 * @brief make ec sign with the designated digest mode
 * digest mode is necessary
 * running in enclave 
 * 
 */
sgx_status_t enclave_ec_sign(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: create ec key sign

    return ret;
}

/**
 * @brief make rsa verify with the designated digest mode
 * digest mode is necessary
 * running in enclave 
 * 
 */
sgx_status_t enclave_ec_verify(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: verify ec key

    return ret;
}

/**
 * @brief make rsa sign with the designated digest mode
 * running in enclave 
 * 
 */
sgx_status_t enclave_sm2_sign(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: create sm2 key sign

    return ret;
}

/**
 * @brief make sm2 verify with the designated digest mode
 * running in enclave 
 * 
 */
sgx_status_t enclave_sm2_verify(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    //TODO: verify sm2 key

    return ret;
}

// sgx-ssl-framework end

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