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
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/aes.h"

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

#define RSA_3072_KEY_BITS   3072
#define RSA_2048_KEY_BITS   2048


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
sgx_status_t sgx_aes_gcm_encrypt(const uint8_t *p_key, const uint8_t *p_src, uint32_t src_len,
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
    const EVP_CIPHER * block_mode = get_symmetric_block_mode(keyspec);
    if(block_mode == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }
	do {
		// Create and init ctx
		//
		if (!(pState = EVP_CIPHER_CTX_new())) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		// Initialise encrypt, key and IV
		//
		if (1 != EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char*)p_key, p_iv)) {
			break;
		}
		// Provide AAD data if exist
		//
		if (NULL != p_aad) {
			if (1 != EVP_EncryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
				break;
			}
            
		}
        if (src_len > 0) {
            // Provide the message to be encrypted, and obtain the encrypted output.
            //
            if (1 != EVP_EncryptUpdate(pState, p_dst, &len, p_src, src_len)) {
                break;
            }
        }
		// Finalise the encryption
		//
		if (1 != EVP_EncryptFinal_ex(pState, p_dst + len, &len)) {
			break;
		}

		if (1 != EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_AEAD_GET_TAG, SGX_AESGCM_MAC_SIZE, p_out_mac)) {
			break;
		}
		ret = SGX_SUCCESS;
	} while (0);

	// Clean up and return
	//
	if (pState) {
			EVP_CIPHER_CTX_free(pState);
	}
	return ret;
}

sgx_status_t sgx_aes_gcm_decrypt(const uint8_t *p_key, const uint8_t *p_src,
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
    const EVP_CIPHER * block_mode = get_symmetric_block_mode(keyspec);
    if(block_mode == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }
	// Autenthication Tag returned by Decrypt to be compared with Tag created during seal
	//
	memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
	memcpy(l_tag, p_in_mac, SGX_AESGCM_MAC_SIZE);

	do {
		// Create and initialise the context
		//
		if (!(pState = EVP_CIPHER_CTX_new())) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		// Initialise decrypt, key and IV
		//
		if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char*)p_key, p_iv)) {
			break;
		}
		if (NULL != p_aad) {
			if (!EVP_DecryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
				break;
			}
		}

		// Decrypt message, obtain the plaintext output
		//
		if (!EVP_DecryptUpdate(pState, p_dst, &len, p_src, src_len)) {
			break;
		}

		// Update expected tag value
		if (!EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_SET_TAG, SGX_AESGCM_MAC_SIZE, l_tag)) {
			break;
		}

		// Finalise the decryption. A positive return value indicates success,
		// anything else is a failure - the plaintext is not trustworthy.
		//
        if (EVP_DecryptFinal_ex(pState, p_dst + len, &len) <= 0) {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }
		ret = SGX_SUCCESS;
	} while (0);

	// Clean up and return
	//
	if (pState != NULL) {
		EVP_CIPHER_CTX_free(pState);
	}
	memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
	return ret;
}


sgx_status_t sgx_sm4_encrypt(const uint8_t *p_key, const uint8_t *p_src, uint32_t src_len,
                                        uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len,
                                        ehsm_keyspec_t keyspec)
{
	if ((src_len >= INT_MAX) || (aad_len >= INT_MAX) || (p_key == NULL) || ((src_len > 0) && (p_dst == NULL)) || ((src_len > 0) && (p_src == NULL))
		||(iv_len != SGX_SM4_IV_SIZE) || ((aad_len > 0) && (p_aad == NULL))
		|| (p_iv == NULL) || ((p_src == NULL) && (p_aad == NULL)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int len = 0;
	EVP_CIPHER_CTX * pState = NULL;
    const EVP_CIPHER * block_mode = get_symmetric_block_mode(keyspec);
    if(block_mode == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }
	do {
		// Create and init ctx
		//
		if (!(pState = EVP_CIPHER_CTX_new())) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		// Initialise encrypt, key and IV
		//
		if (1 != EVP_EncryptInit_ex(pState, block_mode, NULL, (unsigned char*)p_key, p_iv)) {
			break;
		}

        if(!EVP_CIPHER_CTX_set_padding(pState, 1)){
            break; 
        }

		// Provide AAD data if exist
		//
		if (NULL != p_aad) {
			if (1 != EVP_EncryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
				break;
			}
            
		}
        if (src_len > 0) {
            // Provide the message to be encrypted, and obtain the encrypted output.
            //
            if (1 != EVP_EncryptUpdate(pState, p_dst, &len, p_src, src_len)) {
                break;
            }
        }
		// Finalise the encryption
		//
		if (1 != EVP_EncryptFinal_ex(pState, p_dst + len, &len)) {
			break;
		}

		ret = SGX_SUCCESS;
	} while (0);

	// Clean up and return
	//
	if (pState) {
			EVP_CIPHER_CTX_free(pState);
	}
	return ret;
}

sgx_status_t sgx_sm4_decrypt(const uint8_t *p_key, const uint8_t *p_src,
                                        uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len,
                                        const uint8_t *p_aad, uint32_t aad_len,
                                        ehsm_keyspec_t keyspec)
{
	uint8_t l_tag[SGX_AESGCM_MAC_SIZE];

	if ((src_len >= INT_MAX) || (aad_len >= INT_MAX) || (p_key == NULL) || ((src_len > 0) && (p_dst == NULL)) || ((src_len > 0) && (p_src == NULL))
		||(iv_len != SGX_SM4_IV_SIZE) || ((aad_len > 0) && (p_aad == NULL))
		|| (p_iv == NULL) || ((p_src == NULL) && (p_aad == NULL)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	int len = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	EVP_CIPHER_CTX * pState = NULL;
    const EVP_CIPHER * block_mode = get_symmetric_block_mode(keyspec);
    if(block_mode == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }
	// Autenthication Tag returned by Decrypt to be compared with Tag created during seal
	//
	do {
		// Create and initialise the context
		//
		if (!(pState = EVP_CIPHER_CTX_new())) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		// Initialise decrypt, key and IV
		//
		if (!EVP_DecryptInit_ex(pState, block_mode, NULL, (unsigned char*)p_key, p_iv)) {
			break;
		}

        if(!EVP_CIPHER_CTX_set_padding(pState, 1)){
            break; 
        }

		if (NULL != p_aad) {
			if (!EVP_DecryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
				break;
			}
		}

		// Decrypt message, obtain the plaintext output
		//
		if (!EVP_DecryptUpdate(pState, p_dst, &len, p_src, src_len)) {
			break;
		}

		// Finalise the decryption. A positive return value indicates success,
		// anything else is a failure - the plaintext is not trustworthy.
        
        if (EVP_DecryptFinal_ex(pState, p_dst + len, &len) <= 0) {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

		ret = SGX_SUCCESS;
	} while (0);

	// Clean up and return
	//
	if (pState != NULL) {
		EVP_CIPHER_CTX_free(pState);
	}
	memset_s(&l_tag, SGX_AESGCM_MAC_SIZE, 0, SGX_AESGCM_MAC_SIZE);
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
    if (SGX_SUCCESS != ret) {
        printf("gcm decrypting failed.\n");
    }

    else
        *plaintext_size = sgx_get_gcm_ciphertext_size(gcm_data);

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
    // switch (keyblob.digestMode)
    // {
    //     case EH_SHA1:
    //         return EVP_sha1; 
    //     //TODO
    // }
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
static sgx_status_t sgx_gcm_encrypt(const sgx_aes_gcm_128bit_key_t *key,
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
static sgx_status_t sgx_gcm_decrypt(/* param */)
{
    //TODO:call sgx_rijndael128GCM_decrypt()

    sgx_status_t ret;
    
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
    uint32_t real_blob_len = sgx_calc_gcm_data_size(0, key_size);
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
    ret = sgx_gcm_encrypt(&g_domain_key, key_size, tmp,
                                    0, NULL,
                                    cmk_blob_size, (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (SGX_SUCCESS != ret) {
        printf("gcm encrypting failed.\n");
    }
    memset_s(tmp, key_size, 0, key_size);
    free(tmp);
    return ret;
}

/*
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

    uint32_t real_cmk_blob_size = sgx_calc_gcm_data_size(0, key_size);
    if (UINT32_MAX == real_cmk_blob_size || cmk_blob_size < real_cmk_blob_size)
        return SGX_ERROR_INVALID_PARAMETER;

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

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    ret = sgx_read_rand(iv, SGX_SM4_IV_SIZE);
    if (ret != SGX_SUCCESS) {
        printf("error generating IV\n");
        return ret;
    }
    uint8_t* enc_key = (uint8_t*)malloc(key_size);
    
    ret = sgx_gcm_decrypt(&g_domain_key,
                          &enc_key_size, enc_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        free(enc_key);
        printf("failed to decrypt key\n");
		return ret;
    }

    ret = sgx_sm4_encrypt(enc_key, plaintext, plaintext_len,
            cipherblob, iv, SGX_SM4_IV_SIZE, aad, aad_len,
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
 * key needs to decrypt with sgx_gcm_decrypt() firstly
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
        
    uint32_t real_cmk_blob_size = sgx_calc_gcm_data_size(0, key_size);
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

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);

    uint8_t* dec_key = (uint8_t*)malloc(key_size);
    ret = sgx_gcm_decrypt(&g_domain_key,
                          &dec_key_size, dec_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        free(dec_key);
        printf("failed to decrypt key\n");
		return ret;
    }
    ret = sgx_sm4_decrypt(dec_key, cipherblob, plaintext_len, plaintext,
            iv, SGX_SM4_IV_SIZE, aad, aad_len, keyspec);
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
    uint32_t real_blob_len = sgx_calc_gcm_data_size(0, key_size);

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
    ret = sgx_gcm_encrypt(&g_domain_key, key_size, tmp, 0, NULL, cmk_blob_size, (sgx_aes_gcm_data_ex_t *)cmk_blob);

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
                                    uint8_t keyspec, 
                                    uint8_t padding_mode)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // get keybloblen
    uint32_t real_keyblob_size = sgx_calc_gcm_data_size(0, sizeof(rsa_key_data_t));
    if (UINT32_MAX == real_keyblob_size)
        return SGX_ERROR_UNEXPECTED;

    if (req_blob_size) {
        *req_blob_size = real_keyblob_size;
        return SGX_SUCCESS;
    }
    // create rsa key
    if (cmk_blob == NULL || cmk_blob_size < real_keyblob_size) {
        printf("ecall create_rsa_key cmk_keyblob_size:%lu < key_blob_size:%d.\n", cmk_blob_size, real_keyblob_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }
        rsa_key_data_t *keyblob = (rsa_key_data_t *)cmk_blob;
     
    do {
        RSA *rsa = RSA_new();
        BIGNUM *bne = BN_new();
        BN_set_word(bne, RSA_F4);
        switch (keyspec)
        {
            case EH_RSA_2048:
                RSA_generate_key_ex(rsa, RSA_2048_KEY_BITS, bne, nullptr);
                break;
            case EH_RSA_3072:
                RSA_generate_key_ex(rsa, RSA_3072_KEY_BITS, bne, nullptr);
                break;
        }
        
        BIO *public_key = BIO_new(BIO_s_mem());
        BIO *private_key = BIO_new(BIO_s_mem());

        PEM_write_bio_RSAPrivateKey(private_key, rsa, EVP_des_ede3_ofb(), (unsigned char*)g_domain_key, sizeof(g_domain_key), NULL, NULL);
        PEM_write_bio_RSAPublicKey(public_key, rsa);
        
        size_t public_key_len = BIO_pending(public_key);
        size_t private_key_len = BIO_pending(private_key);
        char* p_public_key = new char[public_key_len];
        char* p_private_key = new char[private_key_len];
        
        BIO_read(public_key, p_public_key, public_key_len);
        BIO_read(private_key, p_private_key, private_key_len);

        keyblob->rsa_private_key = p_private_key;
        keyblob->rsa_public_key = p_public_key;
        
        break;
    } while (0);

    return SGX_SUCCESS;
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
    // ret = sgx_gcm_encrypt(/* param */);

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
    // ret = sgx_gcm_encrypt(/* param */);

    return ret;
}

/**
 * @brief generate sm2 key with openssl api
 * running in enclave
 * 
 */
sgx_status_t enclave_create_sm2_key(/* param */)
{
    //TODO: create sm2 key
    sgx_status_t ret;
    // ret = sgx_gcm_encrypt(/* param */);

    return ret;
}


/*
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
            cipherblob_len < plaintext_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *iv = (uint8_t *)(cipherblob + plaintext_len);
    uint8_t *mac = (uint8_t *)(cipherblob + plaintext_len + SGX_AESGCM_IV_SIZE);

    ret = sgx_read_rand(iv, SGX_AESGCM_IV_SIZE);
    if (ret != SGX_SUCCESS) {
        printf("error generating IV\n");
        return ret;
    }

    uint8_t* enc_key = (uint8_t*)malloc(key_size);
    ret = sgx_gcm_decrypt(&g_domain_key,
                          &enc_key_size, enc_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        free(enc_key);
        printf("failed to decrypt key\n");
		return ret;
    }

    ret = sgx_aes_gcm_encrypt(enc_key, plaintext, plaintext_len,
            cipherblob, iv, SGX_AESGCM_IV_SIZE, aad, aad_len,
            reinterpret_cast<uint8_t (*)[16]>(mac), keyspec);
    if (SGX_SUCCESS != ret) {
        printf("error encrypting plain text, ret: %d\n", ret);
    }

    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));
    free(enc_key);

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

/*
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

    uint32_t real_cmk_blob_size = sgx_calc_gcm_data_size(0, key_size);
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
    ret = sgx_gcm_decrypt(&g_domain_key,
                          &dec_key_size, dec_key,
                          (sgx_aes_gcm_data_ex_t *)cmk_blob);
    if (ret != SGX_SUCCESS) {
        free(dec_key);
        printf("error(%d) unsealing key.\n", ret);
        return ret;
    }

    ret = sgx_aes_gcm_decrypt(dec_key, cipherblob, plaintext_len, plaintext,
            iv, SGX_AESGCM_IV_SIZE, aad, aad_len, reinterpret_cast<uint8_t (*)[16]>(mac), keyspec);

    if (SGX_SUCCESS != ret) {
        printf("error decrypting encrypted text\n");
    }

    memset_s(dec_key, sizeof(dec_key), 0, sizeof(dec_key));
    free(dec_key);

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
    const rsa_key_data_t *temp_pub_key = (rsa_key_data_t *)cmk_blob;

    BIO *bio = BIO_new_mem_buf(temp_pub_key->rsa_public_key, -1);

    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, g_domain_key);

    if(rsa == NULL)
    {
        printf("failed to load rsa key\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    switch (keyspec)
    {
        case RSA_NO_PADDING:
            RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, RSA_NO_PADDING);
        case RSA_PKCS1_OAEP_PADDING:
            RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
    }

    return SGX_SUCCESS;
}

sgx_status_t enclave_rsa_decrypt(const uint8_t *cmk_blob, size_t cmk_blob_size,
                                 const uint8_t *ciphertext, uint32_t ciphertext_len,
                                 uint8_t *plaintext, uint32_t plaintext_len,
                                 uint32_t *req_plaintext_len,
                                 uint8_t keyspec, uint8_t padding_mode)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    rsa_key_data_t *temp = (rsa_key_data_t*)cmk_blob;

    BIO *bio = BIO_new_mem_buf(temp->rsa_private_key, -1);
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, g_domain_key);
    

    if(rsa == NULL)
    {
        printf("failed to load rsa key\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (plaintext_len == 0)
    {
        unsigned char* to;
        RSA_private_decrypt(ciphertext_len, ciphertext, to, rsa, RSA_PKCS1_OAEP_PADDING);
        *req_plaintext_len = strlen((char*)to);
    }
    else
    {    
        RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
    }

    return SGX_SUCCESS;
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
    if (cipherapikey == NULL || cipherapikey_len < EH_API_KEY_SIZE + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE){
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
    uint8_t *mac = (uint8_t *)(cipherapikey + apikey_len + SGX_AESGCM_IV_SIZE);
    // get sk and encrypt apikey 
    sgx_ec_key_128bit_t sk_key;
    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                     p_apikey, apikey_len,
                                     cipherapikey,
                                     iv, SGX_AESGCM_IV_SIZE,
                                     NULL, 0,
                                     reinterpret_cast<uint8_t (*)[SGX_AESGCM_MAC_SIZE]>(mac));
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