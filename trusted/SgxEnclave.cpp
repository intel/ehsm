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

#include "sgx_tseal.h"

void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

static EH_RV generateAES(size_t key_len_in, EH_KEY_BLOB_PTR pKeyBlob)
{
	EH_RV rv = EHR_FUNCTION_FAILED;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;

	uint8_t* tmp = (uint8_t *) malloc(key_len_in);
	if (tmp == NULL)
		return EHR_DEVICE_MEMORY;

	status = sgx_read_rand(tmp, key_len_in);
	if (status != SGX_SUCCESS) {
		free(tmp);
		return EHR_SGX_FAILED;
	}

	rv = seal(pKeyBlob->pKeyData, pKeyBlob->ulKeyLen, tmp, key_len_in);

	pKeyBlob->ulKeyType = EHM_AES_GCM_128;
	
	memset_s(tmp, key_len_in, 0, key_len_in);
    free(tmp);

    return rv;
}

static EH_RV encryptAES(EH_MECHANISM_PTR    pMechanism,
                        EH_KEY_BLOB_PTR     pKeyBlob,
                        EH_BYTE_PTR         pData,
                        EH_ULONG            ulDataLen,
                        EH_BYTE_PTR         pEncryptedData,
                        EH_ULONG_PTR        pulEncryptedDataLen)
{
	EH_RV rv = EHR_FUNCTION_FAILED;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;

    if (pMechanism->pParameter == NULL ||
			pMechanism->ulParameterLen != sizeof(EH_GCM_PARAMS)) {
        return EHR_ARGUMENTS_BAD;
    }

    if ((0 != EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) &&
			(NULL == EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD)) {
        return EHR_ARGUMENTS_BAD;
    }

    if ((0 == EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) &&
			(NULL != EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD)) {
        return EHR_ARGUMENTS_BAD;
    }

	if (*pulEncryptedDataLen != ulDataLen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE) {
        return EHR_ARGUMENTS_BAD;
    } 

    uint8_t *aad = EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD;
    uint32_t aad_len = EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen;
    uint8_t *iv = (uint8_t *)(pEncryptedData + ulDataLen);
    uint8_t *mac = (uint8_t *)(pEncryptedData + ulDataLen + EH_AES_GCM_IV_SIZE);

    status = sgx_read_rand(iv, EH_AES_GCM_IV_SIZE);
    if (status != SGX_SUCCESS) {
        printf("error generating IV\n");
        return EHR_SGX_FAILED;
    }

    sgx_key_128bit_t enc_key;

    rv = unseal(pKeyBlob->pKeyData, pKeyBlob->ulKeyLen, (uint8_t *) &enc_key, sizeof(sgx_key_128bit_t));
    if (rv != EHR_OK) {
        printf("error unsealing key");
        return rv;
    }

    status = sgx_rijndael128GCM_encrypt(&enc_key, pData, ulDataLen,
			pEncryptedData, iv, EH_AES_GCM_IV_SIZE, aad, aad_len,
			reinterpret_cast<uint8_t (*)[16]>(mac));
    if (SGX_SUCCESS != status) {
        printf("error encrypting plain text\n");
        return EHR_SGX_FAILED;
    }

    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));

	return EHR_OK;
}

EH_RV sgx_GenerateKey(EH_MECHANISM_TYPE ulKeySpec, EH_KEY_BLOB_PTR pKeyBlob)
{
	EH_RV rv = EHR_FUNCTION_FAILED;

	if (pKeyBlob == NULL) {
		return EHR_ARGUMENTS_BAD;
	}

	if (pKeyBlob->ulKeyLen == 0)
	{
		return EHR_ARGUMENTS_BAD;
	} 
	else if (pKeyBlob->pKeyData == NULL)
	{
		pKeyBlob->ulKeyLen = sgx_calc_sealed_data_size(0, pKeyBlob->ulKeyLen);
		if (pKeyBlob->ulKeyLen != 0xFFFFFFFF)
			return EHR_OK;
	}

    if (!validate_user_check_ptr(pKeyBlob->pKeyData, pKeyBlob->ulKeyLen))
    {
        return EHR_DEVICE_MEMORY;
    }

	switch (ulKeySpec)
	{
		case EHM_AES_GCM_128:
			rv = generateAES(16, pKeyBlob);
			break;
		default:
			return EHR_MECHANISM_INVALID;
	}

	return rv;
}

EH_RV sgx_Encrypt(EH_MECHANISM_PTR    pMechanism,
				  EH_KEY_BLOB_PTR     pKeyBlob,
                  EH_BYTE_PTR         pData,
                  EH_ULONG            ulDataLen,
                  EH_BYTE_PTR         pEncryptedData,
				  EH_ULONG_PTR        pulEncryptedDataLen)
{
	EH_RV rv = EHR_FUNCTION_FAILED;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;

	if (pMechanism == NULL || pKeyBlob ==  NULL || pEncryptedData ==  NULL ||
			pulEncryptedDataLen == NULL) {
		return EHR_ARGUMENTS_BAD;
	}

	if (pMechanism->mechanism != pKeyBlob->ulKeyType) {
        return EHR_ARGUMENTS_BAD;
	}

	switch(pMechanism->mechanism) {
		case EHM_AES_GCM_128:
            rv = encryptAES(pMechanism, pKeyBlob, pData, ulDataLen,
					pEncryptedData, pulEncryptedDataLen);
			break;
		default:
			return EHR_MECHANISM_INVALID;
	}

    return rv;
}

EH_RV sgx_Decrypt(EH_MECHANISM_PTR  pMechanism,
		          EH_KEY_BLOB_PTR   pKeyBlob,
                  EH_BYTE_PTR       pEncryptedData,
                  EH_ULONG          ulEncryptedDataLen,
                  EH_BYTE_PTR       pData,
                  EH_ULONG_PTR      pulDataLen)
{
	EH_RV rv = EHR_FUNCTION_FAILED;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1)) {
		return EHR_DEVICE_MEMORY;
	}

	if (pKeyBlob == NULL || pEncryptedData == NULL || pData == NULL || pulDataLen == NULL) {
		return EHR_ARGUMENTS_BAD;
	}

	switch(pMechanism->mechanism) {
		case EHM_AES_GCM_128:
		{
			if (pMechanism->pParameter == NULL ||
			    pMechanism->ulParameterLen != sizeof(EH_GCM_PARAMS)) {
				return EHR_ARGUMENTS_BAD;
			}
            if ((0 != EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) && (NULL == EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD)) {
                return EHR_ARGUMENTS_BAD;
            }
            if ((0 == EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) && (NULL != EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD)) {
                return EHR_ARGUMENTS_BAD;
            }
			if (ulEncryptedDataLen != *pulDataLen + EH_AES_GCM_IV_SIZE +
					EH_AES_GCM_MAC_SIZE)
			{
				return EHR_ARGUMENTS_BAD; 
			}

			uint8_t *aad = EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD;
			uint32_t aad_len = EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen;
			uint8_t *iv = (uint8_t *)(pEncryptedData + *pulDataLen);
		    uint8_t *mac = (uint8_t *)(pEncryptedData + *pulDataLen +
					EH_AES_GCM_IV_SIZE );

			sgx_key_128bit_t dec_key;

	        rv = unseal(pKeyBlob->pKeyData, pKeyBlob->ulKeyLen, (uint8_t *) &dec_key, sizeof(sgx_key_128bit_t));
            if (rv != EHR_OK) {
                printf("error unsealing key");
                return rv;
            }

            status = sgx_rijndael128GCM_decrypt(&dec_key,
					pEncryptedData, *pulDataLen, pData,
					iv, EH_AES_GCM_IV_SIZE, aad, aad_len,
					reinterpret_cast<uint8_t (*)[16]>(mac));
            if (SGX_SUCCESS != status) {
                printf("error decrypting encrypted text\n");
                return EHR_SGX_FAILED;
            }

            memset_s(&dec_key, sizeof(dec_key), 0, sizeof(dec_key));

			break;
		}
		default:
			return EHR_MECHANISM_INVALID;
	}

    return rv;
}

EH_RV sgx_GenerateDataKey(EH_MECHANISM_PTR  pMechanism,
		                  EH_KEY_BLOB_PTR   pMasterKeyBlob,
                          EH_BYTE_PTR       pPlainDataKey,
                          EH_ULONG          ulPlainDataKeyLen,
                          EH_BYTE_PTR       pEncryptedDataKey,
                          EH_ULONG_PTR      pulEncryptedDataKeyLen)
{
	EH_RV rv = EHR_FUNCTION_FAILED;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	uint8_t *plain_datakey = NULL;

	if (pMechanism == NULL || pMasterKeyBlob == NULL || pEncryptedDataKey ==  NULL ||
			pulEncryptedDataKeyLen == NULL) {
		return EHR_ARGUMENTS_BAD;
	}

	plain_datakey = (uint8_t *)malloc(ulPlainDataKeyLen);
    if (plain_datakey == NULL) {
		return EHR_DEVICE_MEMORY;
	}

    status = sgx_read_rand(plain_datakey, ulPlainDataKeyLen);
    if (status != SGX_SUCCESS) {
        free(plain_datakey);
        return EHR_SGX_FAILED;
    }

    rv = sgx_Encrypt(pMechanism, pMasterKeyBlob, plain_datakey, ulPlainDataKeyLen,
			pEncryptedDataKey, pulEncryptedDataKeyLen);

    if (pPlainDataKey != NULL) {
        memcpy(pPlainDataKey, plain_datakey, ulPlainDataKeyLen);
    }

	memset_s(plain_datakey, ulPlainDataKeyLen, 0, ulPlainDataKeyLen);

	free(plain_datakey);

	return rv;
}

