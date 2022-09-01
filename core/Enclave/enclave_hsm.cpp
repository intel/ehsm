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
#include <cstring>

#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"

#include "datatypes.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/aes.h"
#include "openssl/err.h"

using namespace std;

#define SGX_DOMAIN_KEY_SIZE     16

#define RSA_2048_KEY_BITS   2048
#define RSA_3072_KEY_BITS   3072
#define RSA_4096_KEY_BITS   4096

#define RSA_2048_PUBLIC_KEY_PEM_SIZE    426
#define RSA_2048_PRIVATE_KEY_PEM_SIZE    1679

#define RSA_3072_PUBLIC_KEY_PEM_SIZE    601
#define RSA_3072_PRIVATE_KEY_PEM_SIZE    2459

#define RSA_4096_PUBLIC_KEY_PEM_SIZE    775
#define RSA_4096_PRIVATE_KEY_PEM_SIZE    3247

#define ECC_PUBLIC_KEY_PEM_SIZE     178
#define ECC_PRIVATE_KEY_PEM_SIZE    227
#define ECC_MAX_PLAINTEXT_SIZE      256

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
const EVP_CIPHER * get_symmetric_block_mode(ehsm_keyspec_t keyspec)
{
    switch(keyspec) {
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

static uint32_t sgx_get_gcm_ciphertext_size(const sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data)
        return UINT32_MAX;

    return gcm_data->ciphertext_size;
}

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
        case EH_EC_SM2:
            return ECC_PUBLIC_KEY_PEM_SIZE + ECC_PRIVATE_KEY_PEM_SIZE;
        default:
            return UINT32_MAX;
    }
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
        case EH_EC_SM2:
            return ECC_PUBLIC_KEY_PEM_SIZE;
        default:
            return 0;
    }
}

// sgx-ssl-framework start

/* Rijndael AES-GCM
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Inputs: sgx_aes_gcm_128bit_key_t *p_key - Pointer to key used in encryption/decryption operation
*           uint8_t *p_src - Pointer to input stream to be encrypted/decrypted
*           uint32_t src_len - Length of input stream to be encrypted/decrypted
*           uint8_t *p_iv - Pointer to initialization vector to use
*           uint32_t iv_len - Length of initialization vector
*           uint8_t *p_aad - Pointer to input stream of additional authentication data
*           uint32_t aad_len - Length of additional authentication data stream
*           sgx_aes_gcm_128bit_tag_t *p_in_mac - Pointer to expected MAC in decryption process
*   Output: uint8_t *p_dst - Pointer to cipher text. Size of buffer should be >= src_len.
*           sgx_aes_gcm_128bit_tag_t *p_out_mac - Pointer to MAC generated from encryption process
* NOTE: Wrapper is responsible for confirming decryption tag matches encryption tag */
sgx_status_t aes_gcm_encrypt(const uint8_t *p_key, const uint8_t *p_src, uint32_t src_len,
                             uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad,
                             uint32_t aad_len, sgx_aes_gcm_128bit_tag_t *p_out_mac, ehsm_keyspec_t keyspec)
{
    if(src_len >= INT_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(aad_len >= INT_MAX) {
       return SGX_ERROR_INVALID_PARAMETER;
    }

    if(p_key == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((src_len > 0) && (p_dst == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((src_len > 0) && (p_src == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(p_out_mac == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(iv_len != SGX_AESGCM_IV_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((aad_len > 0) && (p_aad == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((p_iv == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((p_src == NULL) && (p_aad == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(keyspec != EH_AES_GCM_128 &&
       keyspec != EH_AES_GCM_192 &&
       keyspec != EH_AES_GCM_256) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t ret = SGX_SUCCESS;
    int len = 0;
    EVP_CIPHER_CTX * pState = NULL;

    const EVP_CIPHER * block_mode = get_symmetric_block_mode(keyspec);
    if(block_mode == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // Create and init ctx
    //
    if (!(pState = EVP_CIPHER_CTX_new())) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise encrypt/decrpty, key and IV
    //
    if (1 != EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char*)p_key, p_iv)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Provide AAD data if exist
    //
    if (NULL != p_aad) {
        if (1 != EVP_EncryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    if (src_len > 0) {
        // Provide the message to be encrypted, and obtain the encrypted output.
        //
        if (1 != EVP_EncryptUpdate(pState, p_dst, &len, p_src, src_len)) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Finalise the encryption/decryption
    //
    if (1 != EVP_EncryptFinal_ex(pState, p_dst + len, &len)) {
        ret = SGX_ERROR_MAC_MISMATCH;
        goto out;
    }

    // Get tag
    //
    if (1 != EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_GET_TAG, SGX_AESGCM_MAC_SIZE, p_out_mac)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

out:
    // Clean up and return
    //
    if (pState) {
        EVP_CIPHER_CTX_free(pState);
    }
    return ret;
}

sgx_status_t aes_gcm_decrypt(const uint8_t *p_key, const uint8_t *p_src,
                             uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len,
                             const uint8_t *p_aad, uint32_t aad_len, const sgx_aes_gcm_128bit_tag_t *p_in_mac,
                             ehsm_keyspec_t keyspec)
{
	uint8_t l_tag[SGX_AESGCM_MAC_SIZE];

    if(src_len >= INT_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(aad_len >= INT_MAX) {
       return SGX_ERROR_INVALID_PARAMETER;
    }

    if(p_key == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((src_len > 0) && (p_dst == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((src_len > 0) && (p_src == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(p_in_mac == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(iv_len != SGX_AESGCM_IV_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((aad_len > 0) && (p_aad == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((p_iv == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((p_src == NULL) && (p_aad == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(keyspec != EH_AES_GCM_128 &&
       keyspec != EH_AES_GCM_192 &&
       keyspec != EH_AES_GCM_256) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    int len = 0;
    sgx_status_t ret = SGX_SUCCESS;
    EVP_CIPHER_CTX * pState = NULL;

    const EVP_CIPHER * block_mode = get_symmetric_block_mode(keyspec);
    if(block_mode == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }

    // Autenthication Tag returned by Decrypt to be compared with Tag created during seal
    //
    memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    memcpy(l_tag, p_in_mac, SGX_AESGCM_MAC_SIZE);

    // Create and initialise the context
    //
    if (!(pState = EVP_CIPHER_CTX_new())) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise decrypt, key and IV
    //
    if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char*)p_key, p_iv)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    if (NULL != p_aad) {
        if (!EVP_DecryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Decrypt message, obtain the plaintext output
    //
    if (!EVP_DecryptUpdate(pState, p_dst, &len, p_src, src_len)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Update expected tag value
    if (!EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_SET_TAG, SGX_AESGCM_MAC_SIZE, l_tag)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.
    //
    if (EVP_DecryptFinal_ex(pState, p_dst + len, &len) <= 0) {
        ret = SGX_ERROR_MAC_MISMATCH;
        goto out;
    }
out:
    // Clean up and return
    //
    if (pState != NULL) {
        EVP_CIPHER_CTX_free(pState);
    }
    memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
    return ret;
}
sgx_status_t sm4_encrypt(const uint8_t *p_key, const uint8_t *p_src, uint32_t src_len,
                         uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad,
                         uint32_t aad_len, ehsm_keyspec_t keyspec)
{
    if(src_len >= INT_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(aad_len >= INT_MAX) {
       return SGX_ERROR_INVALID_PARAMETER;
    }

    if(p_key == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((src_len > 0) && (p_dst == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((src_len > 0) && (p_src == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(iv_len != SGX_SM4_IV_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if((aad_len > 0) && (p_aad == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((p_iv == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((p_src == NULL) && (p_aad == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(keyspec != EH_SM4) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

	sgx_status_t ret = SGX_SUCCESS;
	int len = 0;
	EVP_CIPHER_CTX * pState = NULL;

    const EVP_CIPHER * block_mode = get_symmetric_block_mode(keyspec);
    if(block_mode == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // Create and init ctx
    //
    if (!(pState = EVP_CIPHER_CTX_new())) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise encrypt, key and IV
    //
    if (1 != EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char*)p_key, p_iv)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Provide AAD data if exist
    //
    if (NULL != p_aad) {
        if (1 != EVP_EncryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }
    if (src_len > 0) {
        // Provide the message to be encrypted, and obtain the encrypted output.
        //
        if (1 != EVP_EncryptUpdate(pState, p_dst, &len, p_src, src_len)) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }
    // Finalise the encryption
    //
    if (1 != EVP_EncryptFinal_ex(pState, p_dst + len, &len)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
out:
	// Clean up and return
	//
	if (pState) {
        EVP_CIPHER_CTX_free(pState);
	}
	return ret;
}

sgx_status_t sm4_decrypt(const uint8_t *p_key, const uint8_t *p_src,
                         uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len,
                         const uint8_t *p_aad, uint32_t aad_len,
                         ehsm_keyspec_t keyspec)
{
    if(src_len >= INT_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(aad_len >= INT_MAX) {
       return SGX_ERROR_INVALID_PARAMETER;
    }

    if(p_key == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((src_len > 0) && (p_dst == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((src_len > 0) && (p_src == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(iv_len != SGX_SM4_IV_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((aad_len > 0) && (p_aad == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((p_iv == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if((p_src == NULL) && (p_aad == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(keyspec != EH_SM4) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    int len = 0;
    sgx_status_t ret = SGX_SUCCESS;
    EVP_CIPHER_CTX * pState = NULL;

    const EVP_CIPHER * block_mode = get_symmetric_block_mode(keyspec);
    if(block_mode == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }
    // Autenthication Tag returned by Decrypt to be compared with Tag created during seal
    //
    // Create and initialise the context
    //
    if (!(pState = EVP_CIPHER_CTX_new())) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Initialise decrypt, key and IV
    //
    if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char*)p_key, p_iv)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }


    if (NULL != p_aad) {
        if (!EVP_DecryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
            ret = SGX_ERROR_UNEXPECTED;
            goto out;
        }
    }

    // Decrypt message, obtain the plaintext output
    //
    if (!EVP_DecryptUpdate(pState, p_dst, &len, p_src, src_len)) {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.

    if (EVP_DecryptFinal_ex(pState, p_dst + len, &len) <= 0) {
        ret = SGX_ERROR_MAC_MISMATCH;
        string errstr = ERR_error_string(ERR_get_error(), NULL);
        errstr = "ERROR: EVP_DecryptFinal_ex failed. OpenSSL error:" + errstr;
        printf("error: %s\n",errstr.c_str());
        unsigned long errornum =  ERR_get_error();
        printf("errornum: %ld\n",errornum);
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
out:
    // Clean up and return
    //
    if (pState != NULL) {
    EVP_CIPHER_CTX_free(pState);
    }
    return ret;
}

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
 * @brief Get the digest mode from cmk
 *
 * @param digestMode use the digestMode passed in by cmk to get the struct for key
 * @return const EVP_MD* (openssl callback, tempoary)
 */
const EVP_MD* GetDigestMode(uint32_t digestMode)
{
     switch (digestMode)
    {
    case EH_SHA1:
        return EVP_sha1();
    case EH_MD5:
        return EVP_md5();
    case EH_SHA_2_224:
        return EVP_sha224();
    case EH_SHA_2_256:
        return EVP_sha256();
    case EH_SHA_2_384:
        return EVP_sha384();
    case EH_SHA_2_512:
        return EVP_sha512();
    case EH_SM3:
        return EVP_sm3();
    default:
        return NULL;
    }
}

/**
 * @brief verify Padding Mode from cmk
 *
 * @param paddingMode the paddingMode passed in by cmk
 * @param digestMode the digestMode passed in by cmk
 * @param evpkey EVP_PKEY created by the context
 * @return [false] unsupported padding mode/ [true] supported padding mode
 */
bool verifyPaddingMode(uint8_t paddingMode, const EVP_MD *digestMode, EVP_PKEY *evpkey)
{
    switch (paddingMode)
    {
    case RSA_PKCS1_PADDING:
        return true;
    case RSA_SSLV23_PADDING:
        return false;
    case RSA_NO_PADDING:
        return false;
    case RSA_PKCS1_OAEP_PADDING:
        return false;
    case RSA_X931_PADDING:
        return false;
    case RSA_PKCS1_PSS_PADDING:
        if (EVP_MD_size(digestMode) * 2 + 2 > (size_t)EVP_PKEY_size(evpkey))
        {
            return false;
        }
        return true;
    default:
        return -1;
    }
}

/**
 * @brief Get the digest mode from cmk
 * aes_gcm and sm4 only
 *
 * @param cmk use the keyblob passed in by cmk to get the struct for key
 * @return const CHIPER* (openssl callback, tempoary)
 */
// const CHIPER* GetAesGcmBlockMode(aes_gcm_key_data_t &keyblob)
// {
//     //TODO: return EVP method
// }

//TODO: get other parameters

/**
 * @brief encrypt the key with sgx_rijndael128GCM_encrypt
 * use to encrypt the key that will send to dkeyserver only
 * sgx_rijndael128GCM_encrypt() is running in enclave
 *
 */
static sgx_status_t ehsm_gcm_encrypt(const sgx_aes_gcm_128bit_key_t *key,
                                    const uint32_t plaintext_size, const uint8_t *plaintext,
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

/**
 * @brief decrypt the key with sgx_rijndael128GCM_decrypt
 * use to decrypt the domain_key from dkeyserver only
 * sgx_rijndael128GCM_decrypt() is running in enclave
 *
 */
static sgx_status_t ehsm_gcm_decrypt(const sgx_aes_gcm_128bit_key_t *key,
                                    uint32_t plaintext_size, uint8_t *plaintext,
                                    const sgx_aes_gcm_data_ex_t *gcm_data)
{
    if (NULL == gcm_data || NULL == plaintext || NULL == plaintext_size
                 || plaintext_size < sgx_get_gcm_ciphertext_size(gcm_data))
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
        plaintext_size = sgx_get_gcm_ciphertext_size(gcm_data);

    return ret;
}

/**
 * @brief generate sm4 key with openssl api
 * running in enclave
 *
 */
sgx_status_t enclave_create_sm4_key(uint8_t *cmk_blob, uint32_t cmk_blob_size, uint32_t *req_blob_size, uint32_t key_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t real_blob_len = ehsm_calc_gcm_data_size(0, key_size);
    if (real_blob_len == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (req_blob_size != NULL) {
        *req_blob_size = real_blob_len;
        return SGX_SUCCESS;
    }
    if (cmk_blob == NULL || cmk_blob_size != real_blob_len) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if(key_size == UINT32_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t* tmp = (uint8_t *)malloc(key_size);
    if (tmp == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ret = sgx_read_rand(tmp, key_size);
    if (ret != SGX_SUCCESS) {
        free(tmp);
        return ret;
    }
    ret = ehsm_gcm_encrypt(&g_domain_key, key_size, tmp,
                            0, NULL,
                            cmk_blob_size, (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (SGX_SUCCESS != ret) {
        printf("gcm encrypting failed.\n");
    }
    memset_s(tmp, key_size, 0, key_size);
    free(tmp);
    return ret;
}

/**
 * struct cipherblob {
 *    OUT uint8_t ciphertext[SGX_AES_KEY_SIZE];
 *    OUT uint8_t iv[SGX_AESGCM_IV_SIZE];   // 12B
 *    OUT uint8_t mac[SGX_AESGCM_MAC_SIZE]; // 16B
 * }
 */
sgx_status_t enclave_sm4_encrypt(const uint8_t *aad, size_t aad_len,
                                 const uint8_t *cmk_blob, size_t cmk_blob_size,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t *cipherblob, size_t cipherblob_len,
                                 ehsm_keyspec_t keyspec, uint32_t key_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_aes_gcm_data_ex_t* sm4_data = (sgx_aes_gcm_data_ex_t*)cmk_blob;
    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_cmk_blob_size = ehsm_calc_gcm_data_size(0, key_size);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size)
        return SGX_ERROR_INVALID_PARAMETER;

    if(key_size == UINT32_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t enc_key_size = sm4_data->ciphertext_size;
    if (enc_key_size == UINT32_MAX || enc_key_size != key_size) {
        printf("enc_key_size:%d is not expected: %lu.\n", enc_key_size, key_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (cipherblob == NULL ||
        cipherblob_len < plaintext_len + SGX_SM4_IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    /* this api only support for symmetric keys */
    if (keyspec != EH_SM4) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    ret = sgx_read_rand(iv, SGX_SM4_IV_SIZE);
    if (ret != SGX_SUCCESS) {
        printf("error generating IV\n");
        return ret;
    }
    uint8_t* enc_key = (uint8_t*)malloc(key_size);

    ret = ehsm_gcm_decrypt(&g_domain_key,
                           enc_key_size, enc_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        free(enc_key);
        printf("failed to decrypt key\n");
		return ret;
    }

    ret = sm4_encrypt(enc_key,
                      plaintext,
                      plaintext_len,
                      cipherblob,
                      iv,
                      SGX_SM4_IV_SIZE,
                      aad,
                      aad_len,
                      keyspec);
    if (SGX_SUCCESS != ret) {
        printf("error encrypting plain text, ret: %d\n", ret);
    }

    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));
    free(enc_key);

    return ret;
}

/**
 * @brief decrypt ciphertext with sm4 key
 * key needs to decrypt with ehsm_gcm_decrypt() firstly
 * running in enclave
 *
 */
sgx_status_t enclave_sm4_decrypt(const uint8_t *aad, size_t aad_len,
                                 const uint8_t *cmk_blob, size_t cmk_blob_size,
                                 const uint8_t *cipherblob, size_t cipherblob_len,
                                 uint8_t *plaintext, size_t plaintext_len,
                                 ehsm_keyspec_t keyspec, uint32_t key_size)
{
   sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_aes_gcm_data_ex_t* sm4_data = (sgx_aes_gcm_data_ex_t*)cmk_blob;
    if (cmk_blob == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(key_size == UINT32_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t real_cmk_blob_size = ehsm_calc_gcm_data_size(0, key_size);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t dec_key_size = sm4_data->ciphertext_size;
    if (dec_key_size == UINT32_MAX || dec_key_size != key_size) {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, key_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cipherblob == NULL || cipherblob_len < plaintext_len + SGX_SM4_IV_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* this api only support for symmetric keys */
    if (keyspec != EH_SM4) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t* dec_key = (uint8_t*)malloc(key_size);
    ret = ehsm_gcm_decrypt(&g_domain_key,
                           dec_key_size, dec_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        free(dec_key);
        printf("failed to decrypt key\n");
		return ret;
    }
    ret = sm4_decrypt(dec_key,
                      cipherblob,
                      plaintext_len,
                      plaintext,
                      iv,
                      SGX_SM4_IV_SIZE,
                      aad,
                      aad_len,
                      keyspec);
    if (SGX_SUCCESS != ret) {
        printf("error decrypting encrypted text\n");
    }

    memset_s(dec_key, sizeof(dec_key), 0, sizeof(dec_key));
    free(dec_key);

    return ret;
}

/**
 * @brief generate aes_gcm key with openssl api
 * @param cmk_blob storage key information
 * @param cmk_blob_size the size of cmk_blob
 * @param req_blob_size the gcm data size
 * @param key_size the size of aes key
 * @return sgx_status_t
 */
sgx_status_t enclave_create_aes_key(uint8_t *cmk_blob, uint32_t cmk_blob_size, uint32_t *req_blob_size, uint32_t key_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    if(key_size == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }
    uint32_t real_blob_len = ehsm_calc_gcm_data_size(0, key_size);

    if (real_blob_len == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (req_blob_size != NULL) {
        *req_blob_size = real_blob_len;
        return SGX_SUCCESS;
    }
    if (cmk_blob == NULL || cmk_blob_size != real_blob_len) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t* tmp = (uint8_t *)malloc(key_size);
    if (tmp == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ret = sgx_read_rand(tmp, key_size);
    if (ret != SGX_SUCCESS) {
        free(tmp);
        return ret;
    }
    ret = ehsm_gcm_encrypt(&g_domain_key, key_size, tmp, 0, NULL, cmk_blob_size, (sgx_aes_gcm_data_ex_t *)cmk_blob);

    memset_s(tmp, key_size, 0, key_size);

    free(tmp);
    return ret;
}

/**
 * @brief keybloblen = 0: get keybloblen; keybloblen != 0: create rsa key
 * public key storages with plaintext and private key will be encrypted with domain_key
 * @param cmk_blob
 * @param cmk_blob_size
 * @param req_blob_size
 * @param keyspec
 * @param padding_mode
 * @return sgx_status_t
 */
sgx_status_t enclave_create_rsa_key(uint8_t *cmk_blob,
                                    uint32_t cmk_blob_size,
                                    uint32_t *req_blob_size,
                                    uint8_t keyspec)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // get keybloblen
    //
    int32_t key_size = ehsm_get_key_pem_size(keyspec);
    if (key_size == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t real_keyblob_size = ehsm_calc_gcm_data_size(0, key_size);

    if (UINT32_MAX == real_keyblob_size)
        return SGX_ERROR_UNEXPECTED;

    if (req_blob_size) {
        *req_blob_size = real_keyblob_size;
        return SGX_SUCCESS;
    }

    // check cmk_blob and cmk_blob_size
    //
    if (cmk_blob == NULL || cmk_blob_size < real_keyblob_size) {
        printf("ecall create_rsa_key cmk_keyblob_size:%lu < key_blob_size:%d.\n", cmk_blob_size, real_keyblob_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (keyspec == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    RSA     *rsa            = NULL;
    BIGNUM  *bne            = NULL;
    BIO     *bio            = NULL;
    uint8_t *key_len        = NULL;
    uint8_t *p_key          = NULL;
    // create rsa key
    //
    do {
        // init rsa key struct
        rsa = RSA_new();
        if (rsa == NULL) {
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }

        bne = BN_new();
        if (bne == NULL) {
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }

        if(!BN_set_word(bne, RSA_F4)) {
            break;
        }

        // generate rsa key
        switch (keyspec) {
            case EH_RSA_2048:
                if(!RSA_generate_key_ex(rsa, RSA_2048_KEY_BITS, bne, nullptr))
                    break;
                break;
            case EH_RSA_3072:
                if(!RSA_generate_key_ex(rsa, RSA_3072_KEY_BITS, bne, nullptr))
                    break;
                break;
            case EH_RSA_4096:
                if(!RSA_generate_key_ex(rsa, RSA_4096_KEY_BITS, bne, nullptr))
                    break;
                break;
            default:
                break;
        }

        // storage rsa key with pem format
        bio = BIO_new(BIO_s_mem());
        if (bio == NULL) {
            break;
        }

        if(!PEM_write_bio_RSAPublicKey(bio, rsa))
            break;
        if(!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL))
            break;
        
        int key_len = BIO_pending(bio);
        if (key_len == 0)
            break;

        p_key = (uint8_t*)malloc(key_len + 1); // add '\0'

        p_key[key_len] = '\0';

        BIO_read(bio, (char*)p_key, key_len);

        if (p_key == NULL)
            break;

        ret = ehsm_gcm_encrypt(&g_domain_key, key_size, p_key, 0, NULL, cmk_blob_size, (sgx_aes_gcm_data_ex_t *)cmk_blob);
    } while(0);

    RSA_free(rsa);
    BIO_free(bio);
    BN_free(bne);

    SAFE_FREE(p_key);

    return ret;
}

/**
 * @brief generate ec key with openssl api
 * running in enclave
 *
 */
sgx_status_t enclave_create_ecc_key(uint8_t *cmk_blob,
                                    uint32_t cmk_blob_size,
                                    uint32_t *req_blob_size,
                                    uint8_t keyspec)
{
    //temporary
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    EC_GROUP    *ec_group   = NULL;
    EC_KEY      *ec_key     = NULL;
    BIO         *bio        = NULL;
    uint8_t     *p_key      = NULL;

    uint32_t key_len = 0;

    // get keybloblen
    //
    int32_t key_size = ECC_PUBLIC_KEY_PEM_SIZE + ECC_PRIVATE_KEY_PEM_SIZE;
    uint32_t real_keyblob_size = ehsm_calc_gcm_data_size(0, key_size);

    if (UINT32_MAX == real_keyblob_size)
        return SGX_ERROR_UNEXPECTED;

    if (req_blob_size) {
        *req_blob_size = real_keyblob_size;
        return SGX_SUCCESS;
    }

    do {
        // Create an EC_GROUP object with a curve specified by SM2 NID
        //
        switch (keyspec)
        {
        case EH_EC_P256:
            ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            break;
        case EH_EC_SM2:
            ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
            break;
        default:
            break;
        }

        if (ec_group == NULL) {
            printf("Error: fail to create an EC_GROUP object for SM2\n");
            break;
        }

        // Create a new EC key
        //
        ec_key = EC_KEY_new();
        if (ec_key == NULL) {
            printf("Error: fail to create a new EC key\n");
            break;
        }

        // Set the new EC key's curve
        //
        if (EC_KEY_set_group(ec_key, ec_group) != 1) {
            printf("Error: fail to set the new EC key's curve\n");
            break;
        }

        // Generate key pair based on the curve
        //
        if (!EC_KEY_generate_key(ec_key)) {
            printf("Error: fail to generate key pair based on the curve\n");
            break;
        }

        // Generate SM2 key pair
        //
        bio = BIO_new(BIO_s_mem());
        if (bio == NULL) {
            printf("Error: fail to create a BIO for SM2 private key\n");
            break;
        }

        if (!PEM_write_bio_EC_PUBKEY(bio, ec_key)) {
            printf("Error: fail to write SM2 public key from ec_key to the BIO\n");
            break;
        }
        if (!PEM_write_bio_ECPrivateKey(bio, ec_key, NULL, NULL, 0, NULL, NULL)) {
            printf("Error: fail to write SM2 private key from ec_key to the BIO\n");
            break;
        }
        
        key_len = BIO_pending(bio);
        if (key_len == 0) {
            printf("Error: fail to get size of the BIO for SM2 public key\n");
            break;
        }
        p_key = (uint8_t*)malloc(key_len+1);
        if (BIO_read(bio, p_key, key_len) <= 0) {
            printf("Error: fail to read SM2 public key from the BIO\n");
            break;
        }
        p_key[key_len] = '\0';

        ret = ehsm_gcm_encrypt(&g_domain_key, key_size, p_key, 0, NULL, cmk_blob_size, (sgx_aes_gcm_data_ex_t *)cmk_blob);
    } while(0);

    BIO_free(bio);
    EC_GROUP_free(ec_group);
    EC_KEY_free(ec_key);

    SAFE_FREE(p_key);

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
    // ret = ehsm_gcm_encrypt(/* param */);

    return ret;
}

/**
 * @brief Check parameters and encrypted data
 * @param aad Additional data
 * @param aad_len Lenghth of aad
 * @param cmk_blob Key information
 * @param cmk_blob_size Lenghth of cmk_blob
 * @param plaintext Data to be encrypted
 * @param plaintext_len Lenghth of plaintext
 * @param cipherblob The information of ciphertext
 * @param cipherblob_len Lenghth of cipherblob
 * @param keyspec The type of key
 * @param key_size The size of key
 */
sgx_status_t enclave_aes_encrypt(const uint8_t *aad, size_t aad_len,
                             const uint8_t *cmk_blob, size_t cmk_blob_size,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *cipherblob, size_t cipherblob_len,
                             ehsm_keyspec_t keyspec, uint32_t key_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk_blob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    /* this api only support for symmetric keys */
    if (keyspec != EH_AES_GCM_128 &&
        keyspec != EH_AES_GCM_192 &&
        keyspec != EH_AES_GCM_256) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(key_size == UINT32_MAX) {
       return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t real_cmk_blob_size = ehsm_calc_gcm_data_size(0, key_size);
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
            cipherblob_len < plaintext_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *mac = (uint8_t *)(cipherblob + plaintext_len + SGX_AESGCM_IV_SIZE);

    ret = sgx_read_rand(iv, SGX_AESGCM_IV_SIZE);
    if (ret != SGX_SUCCESS) {
        printf("error generating IV\n");
        return ret;
    }

    uint8_t* key = (uint8_t*)malloc(key_size);
    ret = ehsm_gcm_decrypt(&g_domain_key,
                           enc_key_size, key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        free(key);
        printf("failed to decrypt key\n");
		return ret;
    }

    ret = aes_gcm_encrypt(key,
                          plaintext,
                          plaintext_len,
                          cipherblob,
                          iv,
                          SGX_AESGCM_IV_SIZE,
                          aad,
                          aad_len,
                          reinterpret_cast<uint8_t (*)[16]>(mac),
                          keyspec);
    if (SGX_SUCCESS != ret) {
        printf("error encrypting plain text, ret: %d\n", ret);
    }

    memset_s(&key, sizeof(key), 0, sizeof(key));
    free(key);

    return ret;
}

/**
 * @brief Check parameters and decrypted data
 * @param aad Additional data
 * @param aad_len Lenghth of aad
 * @param cmk_blob Key information
 * @param cmk_blob_size Lenghth of cmk_blob
 * @param cipherblob The ciphertext to be decrypted
 * @param cipherblob_len Lenghth of cipherblob
 * @param plaintext Decrypted plaintext
 * @param plaintext_len Lenghth of plaintext
 * @param keyspec The type of key
 * @param key_size The size of key
 */
sgx_status_t enclave_aes_decrypt(const uint8_t *aad, size_t aad_len,
                                 const uint8_t *cmk_blob, size_t cmk_blob_size,
                                 const uint8_t *cipherblob, size_t cipherblob_len,
                                 uint8_t *plaintext, size_t plaintext_len,
                                 ehsm_keyspec_t keyspec, uint32_t key_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk_blob == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* this api only support for symmetric keys */
    if (keyspec != EH_AES_GCM_128 &&
        keyspec != EH_AES_GCM_192 &&
        keyspec != EH_AES_GCM_256) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(key_size == UINT32_MAX) {
       return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t real_cmk_blob_size = ehsm_calc_gcm_data_size(0, key_size);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t dec_key_size = sgx_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (dec_key_size == UINT32_MAX || dec_key_size != key_size) {
        printf("dec_key_size size:%d is not expected: %lu.\n", dec_key_size, key_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext == NULL || plaintext_len > EH_ENCRYPT_MAX_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (cipherblob == NULL || cipherblob_len < plaintext_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *mac = (uint8_t *)(cipherblob + plaintext_len + SGX_AESGCM_IV_SIZE);

    uint8_t* dec_key = (uint8_t*)malloc(key_size);
    ret = ehsm_gcm_decrypt(&g_domain_key,
                           dec_key_size, dec_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        free(dec_key);
        printf("error(%d) unsealing key.\n", ret);
        return ret;
    }

    ret = aes_gcm_decrypt(dec_key,
                          cipherblob,
                          plaintext_len,
                          plaintext,
                          iv,
                          SGX_AESGCM_IV_SIZE,
                          aad,
                          aad_len,
                          reinterpret_cast<uint8_t (*)[16]>(mac),
                          keyspec);

    if (SGX_SUCCESS != ret) {
        printf("error decrypting encrypted text\n");
    }

    memset_s(dec_key, sizeof(dec_key), 0, sizeof(dec_key));
    free(dec_key);

    return ret;
}

/**
 * @brief encrypt plaintext with sm2 key
 * key needs to decrypt with ehsm_gcm_decrypt() firstly
 * running in enclave
 *
 */
sgx_status_t enclave_sm2_encrypt(const uint8_t *cmk_blob,
                                 size_t cmk_blob_size,
                                 const uint8_t *plaintext,
                                 uint32_t plaintext_len,
                                 uint8_t *ciphertext,
                                 uint32_t ciphertext_len,
                                 uint32_t *req_blob_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // check plaintext and plaintext_len
    //
    if (plaintext == NULL || plaintext_len == 0) {
        printf("ecall sm2_encrypt plaintext or len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext_len > ECC_MAX_PLAINTEXT_SIZE) {
        printf("ecall sm2_encrypt plaintext_len is up to %d.\n", ECC_MAX_PLAINTEXT_SIZE);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // check cmk_blob and cmk_blob_size
    //
    uint32_t encrypted_sm2_len = ehsm_calc_gcm_data_size(0, ECC_PRIVATE_KEY_PEM_SIZE + ECC_PUBLIC_KEY_PEM_SIZE); // ehsm_get_key_pem_size() will return INT_MAX if keyspec is invalid
    if (UINT32_MAX == encrypted_sm2_len) {
        printf("ecall rsa_encrypt failed to calculate encrypted data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (cmk_blob == NULL || cmk_blob_size < encrypted_sm2_len) {
        printf("ecall rsa_encrypt cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // do rsa public key encrypt
    //
    uint8_t         *sm2_keypair    = NULL;
    uint8_t         *sm2_public_key = NULL;
    BIO             *bio            = NULL;

    EVP_PKEY        *pkey           = NULL;
    EVP_PKEY_CTX    *ectx           = NULL;

    do {
        // load rsa public key
        //
        sm2_keypair = (uint8_t*)malloc(encrypted_sm2_len);
        ret = ehsm_gcm_decrypt(&g_domain_key,
                              encrypted_sm2_len, sm2_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);
        if (ret != SGX_SUCCESS)
            break;

        sm2_public_key = (uint8_t*)malloc(ECC_PUBLIC_KEY_PEM_SIZE);
        memcpy_s(sm2_public_key, ECC_PUBLIC_KEY_PEM_SIZE, sm2_keypair, ECC_PUBLIC_KEY_PEM_SIZE);

        bio = BIO_new_mem_buf(sm2_public_key, -1); // use -1 to auto compute length
        if (bio == NULL) {
            printf("failed to load sm2 key pem\n");
            break;
        }

        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (pkey == NULL) {
            printf("failed to load sm2 key\n");
            break;
        }

        // make encryption
        //
        if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1)
            break;
        
        if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL)))
            break;
        
        if (EVP_PKEY_encrypt_init(ectx) != 1)
            break;

        size_t strLen;
        if (EVP_PKEY_encrypt(ectx, NULL, &strLen, plaintext, (size_t)plaintext_len) != 1) {
            break;
        }

        if (ciphertext_len == 0) {
            *req_blob_size = strLen;
            return SGX_SUCCESS;
        }

        if (ciphertext != NULL) {
            if (EVP_PKEY_encrypt(ectx, ciphertext, &strLen, plaintext, (size_t)plaintext_len) != 1) {
                break;
            }
        } else {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        ret = SGX_SUCCESS;
    } while(0);

    BIO_free(bio);
    SAFE_FREE(sm2_keypair);
    SAFE_FREE(sm2_public_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ectx);

    return ret;
}

sgx_status_t enclave_rsa_encrypt(const uint8_t *cmk_blob,
                                 size_t cmk_blob_size,
                                 const uint8_t *plaintext,
                                 uint32_t plaintext_len,
                                 uint8_t *ciphertext,
                                 uint32_t ciphertext_len,
                                 uint8_t keyspec,
                                 uint8_t padding_mode)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // check padding_mode and keyspec
    //
    if (keyspec == NULL || padding_mode == NULL) {
        printf("ecall rsa_encrypt keyspec or padding_mode is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // check plaintext and plaintext_len
    //
    if (plaintext == NULL || plaintext_len == 0) {
        printf("ecall rsa_encrypt plaintext or len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t max_plaintext_len = ehsm_get_rsa_max_encryption_size(keyspec, padding_mode);
    if (max_plaintext_len == 0)
        return SGX_ERROR_INVALID_PARAMETER;
    if (plaintext_len > max_plaintext_len) {
        printf("ecall rsa_encrypt plaintext_len is up to %d.\n", max_plaintext_len);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // check ciphertext and ciphertext_len
    //
    if (ciphertext == NULL || ciphertext_len < ehsm_get_rsa_cipher_len(keyspec)) {
        printf("ecall rsa_encrypt ciphertext len is too small, it should be %d\n", ehsm_get_rsa_cipher_len(keyspec));
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // check cmk_blob and cmk_blob_size
    //
    uint32_t encrypted_rsa_len = ehsm_calc_gcm_data_size(0, ehsm_get_key_pem_size(keyspec)); // ehsm_get_key_pem_size() will return INT_MAX if keyspec is invalid
    if (UINT32_MAX == encrypted_rsa_len) {
        printf("ecall rsa_encrypt failed to calculate encrypted data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (cmk_blob == NULL || cmk_blob_size < encrypted_rsa_len) {
        printf("ecall rsa_encrypt cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // do rsa public key encrypt
    //
    uint8_t* rsa_keypair = NULL;
    uint8_t* rsa_public_key = NULL;
    BIO *bio = NULL;
    RSA* rsa_pubkey = NULL;
    uint32_t public_key_size;

    do {
        // load rsa public key
        //
        public_key_size = ehsm_get_public_key_pem_size(keyspec);

        rsa_keypair = (uint8_t*)malloc(encrypted_rsa_len);
        ret = ehsm_gcm_decrypt(&g_domain_key,
                              encrypted_rsa_len, rsa_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);
        if (ret != SGX_SUCCESS)
            break;

        rsa_public_key = (uint8_t*)malloc(public_key_size);
        memcpy_s(rsa_public_key, public_key_size, rsa_keypair, public_key_size);

        bio = BIO_new_mem_buf(rsa_public_key, -1); // use -1 to auto compute length
        if (bio == NULL) {
            printf("failed to load rsa key pem\n");
            break;
        }

        rsa_pubkey = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        if (rsa_pubkey == NULL) {
            printf("failed to load rsa key\n");
            break;
        }

        // make encryption
        //
        int encryption_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa_pubkey, padding_mode);

        if (encryption_len == -1 || encryption_len != ciphertext_len)
            ret = SGX_ERROR_UNEXPECTED;
        else
            ret = SGX_SUCCESS;

    } while(0);

    RSA_free(rsa_pubkey);
    BIO_free(bio);
    SAFE_FREE(rsa_keypair);
    SAFE_FREE(rsa_public_key);

    return ret;
}

sgx_status_t enclave_rsa_decrypt(const uint8_t *cmk_blob, size_t cmk_blob_size,
                                 const uint8_t *ciphertext, uint32_t ciphertext_len,
                                 uint8_t *plaintext, uint32_t plaintext_len,
                                 uint32_t *req_plaintext_len,
                                 uint8_t keyspec, uint8_t padding_mode)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // check padding_mode and keyspec
    //
    if (keyspec == NULL || padding_mode == NULL) {
        printf("ecall rsa_encrypt keyspec or padding_mode is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // check ciphertext and ciphertext_len
    //
    uint32_t encrypted_rsa_len = ehsm_calc_gcm_data_size(0, ehsm_get_key_pem_size(keyspec)); // ehsm_get_key_pem_size() will return INT_MAX if keyspec is invalid
    if (UINT32_MAX == encrypted_rsa_len) {
        printf("ecall rsa_encrypt failed to calculate encrypted data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (ciphertext == NULL || ciphertext_len <  ehsm_get_rsa_cipher_len(keyspec)) {
        printf("ecall rsa_encrypt ciphertext len is too small, it should be %d\n", ehsm_get_rsa_cipher_len(keyspec));
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // check cmk_blob and cmk_blob_size
    //
    if (cmk_blob == NULL || cmk_blob_size < encrypted_rsa_len) {
        printf("ecall rsa_decrypt cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // do rsa private key decrypt
    //
    uint8_t* rsa_keypair = NULL;
    uint8_t* rsa_private_key = NULL;
    uint32_t private_key_size;
    uint32_t public_key_size;
    BIO *bio = NULL;
    RSA *rsa_prikey = NULL;

    do {
        // load private key
        //
        public_key_size = ehsm_get_public_key_pem_size(keyspec);
        private_key_size = ehsm_get_key_pem_size(keyspec) - public_key_size;

        rsa_keypair = (uint8_t*)malloc(encrypted_rsa_len);
        ret = ehsm_gcm_decrypt(&g_domain_key,
                              encrypted_rsa_len, rsa_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);
        if (ret != SGX_SUCCESS)
            break;

        rsa_private_key = (uint8_t*)malloc(private_key_size);
        memcpy_s(rsa_private_key, private_key_size, rsa_keypair + public_key_size, private_key_size);

        bio = BIO_new_mem_buf(rsa_private_key, -1); // use -1 to auto compute length
        if (bio == NULL) {
            printf("failed to load rsa key pem\n");
            break;
        }

        rsa_prikey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        if (rsa_prikey == NULL) {
            printf("failed to load rsa key\n");
            break;
        }

        // make decryption and compute plaintext length
        //
        if (plaintext_len == 0) {
            // compute plaintext length
            //
            uint8_t* temp_plaintext = (uint8_t*)malloc(RSA_size(rsa_prikey));

            int plaintext_len = RSA_private_decrypt(ciphertext_len, ciphertext, temp_plaintext, rsa_prikey, padding_mode); // will return the plaintext length after decrypt

            *req_plaintext_len = plaintext_len;

            SAFE_FREE(temp_plaintext);

            ret = SGX_SUCCESS;
        } else {
            // make decryption
            //
            int decryption_len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa_prikey, padding_mode);

            if (decryption_len == -1 || plaintext_len != decryption_len) // delete '\0'
                ret = SGX_ERROR_UNEXPECTED;
            else
                ret = SGX_SUCCESS;;
        }
    } while(0);

    RSA_free(rsa_prikey);
    BIO_free(bio);
    SAFE_FREE(rsa_keypair);
    SAFE_FREE(rsa_private_key);

    return ret;
}

sgx_status_t enclave_sm2_decrypt(const uint8_t *cmk_blob, size_t cmk_blob_size,
                                 const uint8_t *ciphertext, uint32_t ciphertext_len,
                                 uint8_t *plaintext, uint32_t plaintext_len,
                                 uint32_t *req_plaintext_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // check ciphertext and ciphertext_len
    //
    uint32_t encrypted_sm2_len = ehsm_calc_gcm_data_size(0, ECC_PRIVATE_KEY_PEM_SIZE + ECC_PUBLIC_KEY_PEM_SIZE); // ehsm_get_key_pem_size() will return INT_MAX if keyspec is invalid
    if (UINT32_MAX == encrypted_sm2_len) {
        printf("ecall sm2_encrypt failed to calculate encrypted data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    // if (ciphertext == NULL || ciphertext_len < (ECC_MAX_PLAINTEXT_SIZE + 96*8)) {
    //     printf("ecall rsa_encrypt ciphertext len is too small, it should be %d\n", ECC_MAX_PLAINTEXT_SIZE + 96*8);
    //     return SGX_ERROR_INVALID_PARAMETER;
    // }

    // check cmk_blob and cmk_blob_size
    //
    if (cmk_blob == NULL || cmk_blob_size < encrypted_sm2_len) {
        printf("ecall sm2_decrypt cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // do rsa private key decrypt
    //
    uint8_t* sm2_keypair = NULL;
    uint8_t* sm2_private_key = NULL;
    BIO *bio = NULL;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *ectx = NULL;

    do {
        // load private key
        //
        sm2_keypair = (uint8_t*)malloc(encrypted_sm2_len);
        ret = ehsm_gcm_decrypt(&g_domain_key,
                              encrypted_sm2_len, sm2_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);
        if (ret != SGX_SUCCESS)
            break;

        sm2_private_key = (uint8_t*)malloc(ECC_PRIVATE_KEY_PEM_SIZE);
        memcpy_s(sm2_private_key, ECC_PRIVATE_KEY_PEM_SIZE, sm2_keypair + ECC_PUBLIC_KEY_PEM_SIZE, ECC_PRIVATE_KEY_PEM_SIZE);

        bio = BIO_new_mem_buf(sm2_private_key, -1); // use -1 to auto compute length
        if (bio == NULL) {
            printf("failed to load rsa key pem\n");
            break;
        }

        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (pkey == NULL) {
            printf("failed to load rsa key\n");
            break;
        }

        // make decryption and compute plaintext length
        //
         if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1)
            break;
        
        if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL)))
            break;
        
        if (EVP_PKEY_decrypt_init(ectx) != 1)
            break;
        
        size_t strLen;
        if (EVP_PKEY_decrypt(ectx, NULL, &strLen, ciphertext, (size_t)ciphertext_len) != 1) {
            break;
        }

        if (plaintext_len == 0) {
            *req_plaintext_len = strLen;
            return SGX_SUCCESS;
        }

        if (ciphertext != NULL) {
            if (EVP_PKEY_decrypt(ectx, plaintext, &strLen, ciphertext, (size_t)ciphertext_len) != 1) {
                break;
            }
        } else {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        ret = SGX_SUCCESS;
    } while(0);

    BIO_free(bio);
    SAFE_FREE(sm2_keypair);
    SAFE_FREE(sm2_private_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ectx);

    return ret;
}

/**
 * @brief generate a random array and encrypt with cmk
 * key needs to decrypt with ehsm_gcm_decrypt() firstly
 * running in enclave
 *
 */
sgx_status_t enclave_generate_datakey(/* param */)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *datakey = NULL;

    //TODO: generate random number

    //TODO: encrypt key plaintext
    // switch(key_spec) {
    //     case EH_AES_GCM_128:
    //     case EH_AES_GCM_192:
    //     case EH_AES_GCM_256:
    //         //TODO: encrypt
    //         break;
    //     case EH_SM4:
    //         //TODO: encrypt
    //         break;
    //     default:
    //         return SGX_ERROR_INVALID_PARAMETER;
    // }

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
 * @brief make rsa sign with the designated digest mode and padding mode
 * digest mode and padding mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param cmk_blob_size cipher block size
 * @param digest_mode digest mode set when creating the key
 * @param keyspec keyspec set when creating the key
 * @param padding_mode padding_mode set when creating the key
 * @param data data to be signed
 * @param data_len data length
 * @param signature used to receive signature
 * @param signature_len signature length
 * @return sgx_status_t
 */
sgx_status_t enclave_rsa_sign(const uint8_t *cmk_blob,
                              size_t cmk_blob_size,
                              uint8_t padding_mode,
                              uint32_t digest_mode,
                              uint8_t keyspec,
                              const uint8_t *data,
                              size_t data_len,
                              uint8_t *signature,
                              size_t signature_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    //Verify parameters
    if (digest_mode == NULL || padding_mode == NULL || keyspec == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t sign_rsa_len = ehsm_calc_gcm_data_size(0, ehsm_get_key_pem_size(keyspec)); // ehsm_get_key_pem_size() will return INT_MAX if keyspec is invalid
    if (UINT32_MAX == sign_rsa_len) {
        printf("ecall rsa_sign failed to calculate sign data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    //check signatrue length
    switch(keyspec)
    {
        case EH_RSA_2048:
            if (signature_len < RSA_OAEP_2048_SIGNATURE_SIZE) {
                printf("ecall rsa_sign 2048 signature_len is too small than the expected 256.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
        case EH_RSA_3072:
            if (signature_len < RSA_OAEP_3072_SIGNATURE_SIZE) {
                printf("ecall rsa_sign 3072 signature_len is too small than the expected 384.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
        case EH_RSA_4096:
            if (signature_len < RSA_OAEP_4096_SIGNATURE_SIZE) {
                printf("ecall rsa_sign 4096 signature_len is too small than the expected 512.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
    }

    // check cmk_blob and cmk_blob_size
    if (cmk_blob == NULL || cmk_blob_size < sign_rsa_len) {
        printf("ecall rsa_sign cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (data == NULL || data_len == 0) {
        printf("ecall rsa_sign data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t private_key_size;
    uint32_t public_key_size;
    uint8_t* rsa_keypair     = NULL;
    uint8_t* rsa_private_key = NULL;
    BIO *bio                 = NULL;
    RSA* rsa_prikey          = NULL;
    EVP_PKEY *evpkey         = NULL;
    EVP_MD_CTX *mdctx        = NULL;
    EVP_PKEY_CTX *pkey_ctx   = NULL;
    //rsa sign
    do
    {
        // load private key
        public_key_size = ehsm_get_public_key_pem_size(keyspec);
        private_key_size = ehsm_get_key_pem_size(keyspec) - public_key_size;

        rsa_keypair = (uint8_t*)malloc(sign_rsa_len);
        ret = ehsm_gcm_decrypt(&g_domain_key,
                              sign_rsa_len, rsa_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);
        if (ret != SGX_SUCCESS)
            break;
        rsa_private_key = (uint8_t*)malloc(private_key_size);
        memcpy_s(rsa_private_key, private_key_size, rsa_keypair + public_key_size, private_key_size);

        bio = BIO_new_mem_buf(rsa_private_key, -1);
        if (bio == NULL) {
            printf("ecall rsa_sign failed to load rsa key pem\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        rsa_prikey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        if(rsa_prikey == NULL)
        {
            printf("ecall rsa_sign fail to read RSA key using bio\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        evpkey = EVP_PKEY_new();
        if (evpkey == NULL)
        {
            printf("ecall rsa_sign generate evpkey failed.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        //use EVP_PKEY store RSA private key
        if (EVP_PKEY_set1_RSA(evpkey, rsa_prikey) != 1)
        {
            printf("ecall rsa_sign fail to set the evpkey by RSA_KEY\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        //Get Digest Mode
        const EVP_MD *digestMode = GetDigestMode(digest_mode);
        if (digestMode == NULL)
        {
            printf("ecall rsa_sign digest Mode error.\n");
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        //verify Padding Mode
        if(!verifyPaddingMode(padding_mode, digestMode, evpkey))
        {
            printf("ecall rsa_sign unsupported padding mode.\n");
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
        {
            printf("ecall rsa_sign fail to create a EVP_MD_CTX.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            printf("ecall rsa_sign EVP_MD_CTX initialize failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        //Signature initialization, set digest mode
        if (EVP_DigestSignInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            printf("ecall rsa_sign EVP_DigestSignInit failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        //set padding mode
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode) != 1)
        {
            printf("ecall rsa_sign EVP_PKEY_CTX_set_rsa_padding failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        if (padding_mode == RSA_PKCS1_PSS_PADDING)
        {
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(digestMode)) != 1)
            {
                printf("ecall rsa_sign EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                ret = SGX_ERROR_UNEXPECTED;
                break;
            }
        }
        //update sign
        if (EVP_DigestUpdate(mdctx, data, data_len) != 1)
        {
            printf("ecall rsa_sign EVP_DigestSignUpdate failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        //start sign
        if (EVP_DigestSignFinal(mdctx, NULL, &signature_len) != 1)
        {
            printf("ecall rsa_sign first EVP_DigestSignFinal failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        if (EVP_DigestSignFinal(mdctx, signature, &signature_len) != 1)
        {
            printf("ecall rsa_sign last EVP_DigestSignFinal failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
    } while (0);
    RSA_free(rsa_prikey);
    BIO_free(bio);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    SAFE_FREE(rsa_keypair);
    SAFE_FREE(rsa_private_key);

    return ret;
}

/**
 * @brief make rsa verify with the designated digest mode and padding mode
 * digest mode and padding mode is optional
 * running in enclave
 * @param cmk_blob cipher block for storing keys
 * @param cmk_blob_size cipher block size
 * @param digest_mode digest mode set when creating the key
 * @param keyspec keyspec set when creating the key
 * @param padding_mode padding_mode set when creating the key
 * @param data data to be signed
 * @param data_len data length
 * @param signature generated signature
 * @param signature_len signature length
 * @param result match result
 * @return sgx_status_t
 */
sgx_status_t enclave_rsa_verify(const uint8_t *cmk_blob,
                                size_t cmk_blob_size,
                                uint8_t padding_mode,
                                uint32_t digest_mode,
                                uint8_t keyspec,
                                const uint8_t *data,
                                size_t data_len,
                                const uint8_t *signature,
                                size_t signature_len,
                                bool *result)
{
    sgx_status_t ret = SGX_SUCCESS;
    //Verify parameters
    if (digest_mode == NULL || padding_mode == NULL || keyspec == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    //check signature length
    switch(keyspec)
    {
        case EH_RSA_2048:
            if (signature_len < RSA_OAEP_2048_SIGNATURE_SIZE) {
                printf("ecall rsa_verify 2048 signature_len is too small than the expected 256.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
        case EH_RSA_3072:
            if (signature_len < RSA_OAEP_3072_SIGNATURE_SIZE) {
                printf("ecall rsa_verify 3072 signature_len is too small than the expected 384.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
        case EH_RSA_4096:
            if (signature_len < RSA_OAEP_4096_SIGNATURE_SIZE) {
                printf("ecall rsa_verify 4096 signature_len is too small than the expected 512.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
    }

    uint32_t verify_rsa_len = ehsm_calc_gcm_data_size(0, ehsm_get_key_pem_size(keyspec)); // ehsm_get_key_pem_size() will return INT_MAX if keyspec is invalid
    if (UINT32_MAX == verify_rsa_len) {
        printf("ecall rsa_sign failed to calculate verify data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (cmk_blob == NULL || cmk_blob_size < verify_rsa_len) {
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

    uint8_t* rsa_keypair    = NULL;
    uint8_t* rsa_public_key = NULL;
    BIO *bio                = NULL;
    RSA* rsa_pubkey         = NULL;
    EVP_PKEY *evpkey        = NULL;
    EVP_MD_CTX *mdctx       = NULL;
    EVP_PKEY_CTX *pkey_ctx  = NULL;
    uint32_t public_key_size;

    //rsa verify
    do
    {
        // load rsa public key
        public_key_size = ehsm_get_public_key_pem_size(keyspec);

        rsa_keypair = (uint8_t*)malloc(verify_rsa_len);
        ret = ehsm_gcm_decrypt(&g_domain_key,
                              verify_rsa_len, rsa_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);
        if (ret != SGX_SUCCESS)
            break;

        rsa_public_key = (uint8_t*)malloc(public_key_size);
        memcpy_s(rsa_public_key, public_key_size, rsa_keypair, public_key_size);

        bio = BIO_new_mem_buf(rsa_public_key, -1);
        if (bio == NULL) {
            printf("ecall rsa_verify failed to load rsa key pem\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        rsa_pubkey = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        if(rsa_pubkey == NULL)
        {
            printf("ecall rsa_verify fail to read RSA key using bio\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        evpkey = EVP_PKEY_new();
        if (evpkey == NULL)
        {
            printf("ecall rsa_verify generate evpkey failed.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        //use EVP_PKEY store RSA public key
        if (EVP_PKEY_set1_RSA(evpkey, rsa_pubkey) != 1)
        {
            printf("ecall rsa_verify fail to set the evpkey by RSA_KEY\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        //get digest mode
        const EVP_MD *digestMode = GetDigestMode(digest_mode);
        if (digestMode == NULL)
        {
            printf("ecall rsa_verify digestMode error.\n");
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        //verify Padding Mode
        if(!verifyPaddingMode(padding_mode, digestMode, evpkey))
        {
            printf("ecall rsa_verify unsupported padding mode.\n");
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
        {
            printf("ecall rsa_verify fail to create a EVP_MD_CTX.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            printf("ecall rsa_verify EVP_MD_CTX initialize failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        //verify initialization, set digest mode
        if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            printf("ecall rsa_verify EVP_DigestVerifyInit failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        //set padding mode
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode) != 1)
        {
            printf("ecall rsa_verify EVP_PKEY_CTX_set_rsa_padding failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        if (padding_mode == RSA_PKCS1_PSS_PADDING)
        {
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(digestMode)) != 1)
            {
                printf("ecall rsa_verify EVP_PKEY_CTX_set_rsa_pss_saltlen failed.\n");
                ret = SGX_ERROR_UNEXPECTED;
                break;
            }
        }
        //update verify
        if (EVP_DigestVerifyUpdate(mdctx, data, data_len) != 1)
        {
            printf("ecall rsa_verify EVP_DigestVerifyUpdate failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        //start verify
        if (EVP_DigestVerifyFinal(mdctx, signature, signature_len) != 1)
        {
            printf("ecall rsa_verify EVP_DigestVerifyFinal failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
    } while (0);
    RSA_free(rsa_pubkey);
    BIO_free(bio);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    SAFE_FREE(rsa_keypair);
    SAFE_FREE(rsa_public_key);

    if (ret != SGX_SUCCESS)
    {
        *result = false;
    }
    else
    {
        *result = true;
    }
    return ret;
}

/**
 * @brief make ec or sm2 sign with the designated digest mode
 * digest mode is optional
 * running in enclave 
 * @param cmk_blob cipher block for storing keys
 * @param cmk_blob_size cipher block size
 * @param digest_mode digest mode set when creating the key
 * @param keyspec keyspec set when creating the key
 * @param data data to be signed
 * @param data_len data length
 * @param signature used to receive signature
 * @param signature_len signature length
 * @return sgx_status_t 
 */
sgx_status_t enclave_ec_sign(const uint8_t *cmk_blob,
                             size_t cmk_blob_size, 
                             uint32_t digest_mode,
                             uint8_t keyspec,
                             const uint8_t *data,
                             uint32_t data_len,
                             uint8_t *signature,
                             size_t signature_len)
{
    sgx_status_t ret = SGX_SUCCESS;

    if (digest_mode == NULL || keyspec == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t sign_ec_len = ehsm_calc_gcm_data_size(0, ehsm_get_key_pem_size(keyspec)); // ehsm_get_key_pem_size() will return INT_MAX if keyspec is invalid
    if (UINT32_MAX == sign_ec_len) {
        printf("ecall ec_sign failed to calculate sign data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    //check signatrue length
    switch(keyspec)
    {
        case EH_EC_P256:
            if (signature_len > EC_P256_SIGNATURE_SIZE) {
                printf("ecall ec_sign 256 or sm2 signature_len is too large than the expected 64.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
        case EH_EC_SM2:
            if (signature_len > EC_SM2_SIGNATURE_SIZE) {
                printf("ecall ec_sign sm2 signature_len is too large than the expected 64.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            if (digest_mode != EH_SM3) {
                printf("ecall ec_sign sm2 digest made not support.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
    }


    // check cmk_blob and cmk_blob_size
    if (cmk_blob == NULL || cmk_blob_size < sign_ec_len) {
        printf("ecall ec_sign cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (data == NULL || data_len == 0) {
        printf("ecall ec_sign data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t private_key_size;
    uint32_t public_key_size;
    uint8_t* ec_keypair      = NULL;
    uint8_t* ec_private_key  = NULL;
    BIO *bio                 = NULL;
    EVP_PKEY *evpkey         = NULL;
    EVP_MD_CTX *mdctx        = NULL;
    EVP_PKEY_CTX *pkey_ctx   = NULL;
    EC_KEY *ec_key           = NULL;

    do 
    {
        public_key_size = ehsm_get_public_key_pem_size(keyspec);
        private_key_size = ehsm_get_key_pem_size(keyspec) - public_key_size;

        ec_keypair = (uint8_t*)malloc(sign_ec_len);
        ret = ehsm_gcm_decrypt(&g_domain_key,
                              sign_ec_len, ec_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);
        if (ret != SGX_SUCCESS) {
            printf("ecall ec_sign failed to ehsm_gcm_decrypt\n");
            break;
        }
        ec_private_key = (uint8_t*)malloc(private_key_size);
        memcpy_s(ec_private_key, private_key_size, ec_keypair + public_key_size, private_key_size);

        bio = BIO_new_mem_buf(ec_private_key, -1);
        if (bio == NULL) {
            printf("ecall ec_sign failed to load rsa key pem\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        ec_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
        if(ec_key == NULL)
        {
            printf("Eecall ec_sign fail to read ec_key using bio\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        evpkey = EVP_PKEY_new();
        if (evpkey == NULL)
        {
            printf("ecall ec_sign generate evpkey failed.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        if (EVP_PKEY_set1_EC_KEY(evpkey, ec_key) != 1)
        {
            printf("ecall ec_sign fail to set the evpkey by EC_KEY\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        const EVP_MD *digestMode = GetDigestMode(digest_mode);
        if (digestMode == NULL)
        {
            printf("ecall ec_sign digestMode error.\n");
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
        {
            printf("ecall ec_sign fail to create a EVP_MD_CTX.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            printf("ecall ec_sign EVP_MD_CTX initialize failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        if(keyspec == EH_EC_SM2)
        {
            //set sm2 id and id len
            unsigned char sm2_id[] = "12345";
            unsigned int sm2_id_len = sizeof(sm2_id)-1;

            if (EVP_PKEY_set_alias_type(evpkey, EVP_PKEY_SM2) != 1)
            {
                printf("ecall ec_sign fail to modify the evpkey to use SM2\n");
                ret = SGX_ERROR_UNEXPECTED;
                break;
            }
            pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
            if (pkey_ctx == NULL) {
                printf("ecall ec_sign fail to create a EVP_PKEY_CTX\n");
                ret = SGX_ERROR_UNEXPECTED;
                break;
            }
            if (EVP_PKEY_CTX_set1_id(pkey_ctx, sm2_id, sm2_id_len) != 1) {
                printf("ecall ec_sign fail to set sm2_user_id to the EVP_PKEY_CTX\n");
                ret = SGX_ERROR_UNEXPECTED;
                break;
            }
            EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);
        }

        if (EVP_DigestSignInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            printf("ecall ec_sign EVP_DigestSignInit failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        if (EVP_DigestUpdate(mdctx, data, data_len) != 1)
        {
            printf("ecall ec_sign EVP_DigestSignUpdate failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        if (EVP_DigestSignFinal(mdctx, NULL, &signature_len) != 1)
        {
            printf("ecall ec_sign EVP_DigestSignFinal1 failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        if (EVP_DigestSignFinal(mdctx, signature, &signature_len) != 1)
        {
            printf("ecall ec_sign EVP_DigestSignFinal failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        // unsigned int lsize = 72;
        // if(ECDSA_sign(0, data, data_len, signature, &lsize, ec_key) != 1)
        // {
        //     printf("ecall ec_sign ECDSA_sign failed.\n");
        //     ret = SGX_ERROR_UNEXPECTED;
        //     break;
        // }
    } while (0);
    BIO_free(bio);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    if(keyspec == EH_EC_SM2) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    SAFE_FREE(ec_keypair);
    SAFE_FREE(ec_private_key);

    return ret;
}

/**
 * @brief make ec or sm2 verify with the designated digest mode
 * digest mode is optional
 * running in enclave 
 * @param cmk_blob cipher block for storing keys
 * @param cmk_blob_size cipher block size
 * @param digest_mode digest mode set when creating the key
 * @param keyspec keyspec set when creating the key
 * @param data data to be signed
 * @param data_len data length
 * @param signature generated signature
 * @param signature_len signature length
 * @param result match result
 * @return sgx_status_t 
 */
sgx_status_t enclave_ec_verify(const uint8_t *cmk_blob,
                               size_t cmk_blob_size,
                               uint32_t digest_mode,
                               uint8_t keyspec,
                               const uint8_t *data,
                               uint32_t data_len,
                               const uint8_t *signature,
                               size_t signature_len,
                               bool *result)
{
    sgx_status_t ret = SGX_SUCCESS;

    if (digest_mode == NULL || keyspec == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t verify_ec_len = ehsm_calc_gcm_data_size(0, ehsm_get_key_pem_size(keyspec)); // ehsm_get_key_pem_size() will return INT_MAX if keyspec is invalid
    if (UINT32_MAX == verify_ec_len) {
        printf("ecall ec_verify failed to calculate sign data size.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    //check signatrue length and digest mode
    switch(keyspec)
    {
        case EH_EC_P256:
            if (signature_len < EC_P256_SIGNATURE_SIZE) {
                printf("ecall ec_sign 256 or sm2 signature_len is too small than the expected 64.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
        case EH_EC_SM2:
            if (signature_len < EC_SM2_SIGNATURE_SIZE) {
                printf("ecall ec_sign sm2 signature_len is too small than the expected 64.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            if (digest_mode != EH_SM3) {
                printf("ecall ec_sign sm2 digest made not support.\n");
                return SGX_ERROR_INVALID_PARAMETER;
            }
            break;
    }

    // check cmk_blob and cmk_blob_size
    if (cmk_blob == NULL || cmk_blob_size < verify_ec_len) {
        printf("ecall ec_verify cmk_blob_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (data == NULL || data_len == 0) {
        printf("ecall ec_verify data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (result == NULL) {
        printf("ecall ec_verify result is NULL.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t* ec_keypair    = NULL;
    uint8_t* ec_public_key = NULL;
    BIO *bio               = NULL;
    EC_KEY *ec_key         = NULL;
    EVP_PKEY *evpkey       = NULL;
    EVP_MD_CTX *mdctx      = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    uint32_t public_key_size;

    do
    {
        public_key_size = ehsm_get_public_key_pem_size(keyspec);
        
        ec_keypair = (uint8_t*)malloc(verify_ec_len);
        ret = ehsm_gcm_decrypt(&g_domain_key,
                              verify_ec_len, ec_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk_blob);
        if (ret != SGX_SUCCESS) {
            printf("ecall ec_verify failed to ehsm_gcm_decrypt\n");
            break;
        }
        ec_public_key = (uint8_t*)malloc(public_key_size);
        memcpy_s(ec_public_key, public_key_size, ec_keypair, public_key_size);

        bio = BIO_new_mem_buf(ec_public_key, -1);
        if (bio == NULL) {
            printf("ecall ec_verify failed to load rsa key pem\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
        if(ec_key == NULL)
        {
            printf("ecall ec_verify fail to read ec_key using bio\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        evpkey = EVP_PKEY_new();
        if (evpkey == NULL)
        {
            printf("ecall ec_verify generate evpkey failed.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        if (EVP_PKEY_set1_EC_KEY(evpkey, ec_key) != 1)
        {
            printf("ecall ec_verify fail to set the evpkey by RSA_KEY\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        const EVP_MD *digestMode = GetDigestMode(digest_mode);
        if (digestMode == NULL)
        {
            printf("ecall ec_verify digestMode error.\n");
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
        {
            printf("ecall ec_verify fail to create a EVP_MD_CTX.\n");
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        if (EVP_MD_CTX_init(mdctx) != 1)
        {
            printf("ecall ec_verify EVP_MD_CTX initialize failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        //sm2 add
        if(keyspec == EH_EC_SM2)
        {
            //set sm2 id and id len
            unsigned char sm2_id[] = "12345";
            unsigned int sm2_id_len = sizeof(sm2_id)-1;

            if (EVP_PKEY_set_alias_type(evpkey, EVP_PKEY_SM2) != 1)
            {
                printf("ecall ec_verify fail to modify the evpkey to use SM2\n");
                ret = SGX_ERROR_UNEXPECTED;
                break;
            }
            pkey_ctx = EVP_PKEY_CTX_new(evpkey, NULL);
            if (pkey_ctx == NULL) {
                printf("ecall ec_verify fail to create a EVP_PKEY_CTX\n");
                ret = SGX_ERROR_UNEXPECTED;
                break;
            }
            //set sm2 id and len for pkeyctx
            if (EVP_PKEY_CTX_set1_id(pkey_ctx, sm2_id, sm2_id_len) != 1) {
                printf("ecall ec_verify fail to set sm2_user_id to the EVP_PKEY_CTX\n");
                ret = SGX_ERROR_UNEXPECTED;
                break;
            }
            EVP_MD_CTX_set_pkey_ctx(mdctx, pkey_ctx);
        }

        if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, digestMode, nullptr, evpkey) != 1)
        {
            printf("ecall ec_verify EVP_DigestVerifyInit failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        if (EVP_DigestVerifyUpdate(mdctx, data, data_len) != 1)
        {
            printf("ecall ec_verify EVP_DigestVerifyUpdate failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }  
        if (EVP_DigestVerifyFinal(mdctx, signature, signature_len) != 1)
        {
            printf("ecall ec_verify EVP_DigestVerifyFinal failed.\n");
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        // printf("in verify\n");
        // if(ECDSA_verify(0, data, data_len, signature, 72, ec_key) != 1)
        // {
        //     printf("ecall ec_verify ECDSA_verify failed.\n");
        //     ret = SGX_ERROR_UNEXPECTED;
        //     break;
        // }
    } while (0);
    BIO_free(bio);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(mdctx);
    if(keyspec == EH_EC_SM2) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    SAFE_FREE(ec_keypair);
    SAFE_FREE(ec_public_key);

    if (ret != SGX_SUCCESS)
    {
        *result = false;
    }
    else
    {
        *result = true;
    }

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