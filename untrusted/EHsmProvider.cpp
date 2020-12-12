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

#include "EnclaveHelpers.h"
#include "enclave_hsm_u.h"

namespace EHsmProvider
{
    EH_RV Initialize()
    {
        SgxCrypto::EnclaveHelpers enclaveHelpers;

        if (!enclaveHelpers.isSgxEnclaveLoaded())
        {
			if (SGX_SUCCESS != enclaveHelpers.loadSgxEnclave())
            {
                return EHR_DEVICE_ERROR;
            }
        }

        return EHR_OK;
    }

    void Finalize()
    {
        SgxCrypto::EnclaveHelpers enclaveHelpers;

        if (enclaveHelpers.isSgxEnclaveLoaded())
        {
            enclaveHelpers.unloadSgxEnclave();
        }
    }

	EH_RV CreateKey(EH_MECHANISM_TYPE ulKeySpec, EH_KEY_ORIGIN eOrigin,
			EH_KEY_BLOB_PTR pKeyBlob)
	{
		EH_RV rv = EHR_FUNCTION_FAILED;
		sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
        SgxCrypto::EnclaveHelpers enclaveHelpers;

		if (eOrigin == EHO_EXTERNAL_KEY) {
			return EHR_ARGUMENTS_BAD;
		}

		sgxStatus = sgx_GenerateKey(enclaveHelpers.getSgxEnclaveId(),
                                    &rv,
                                    ulKeySpec,
                                    pKeyBlob);

		return rv;
	}

	EH_RV Encrypt(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
			EH_BYTE_PTR pData, EH_ULONG ulDataLen,
			EH_BYTE_PTR pEncryptedData, EH_ULONG_PTR pulEncryptedDataLen)
	{
		EH_RV rv = EHR_FUNCTION_FAILED;
		sgx_status_t sgxStatus = sgx_status_t::SGX_ERROR_UNEXPECTED;
		SgxCrypto::EnclaveHelpers enclaveHelpers;

		if (pMechanism != NULL && pEncryptedData == NULL &&
				pulEncryptedDataLen != NULL) {
			if (pMechanism->mechanism == EHM_AES_GCM_128) {
				*pulEncryptedDataLen = ulDataLen + EH_AES_GCM_IV_SIZE +
					EH_AES_GCM_MAC_SIZE;
				return EHR_OK;
			}
		}

		if (pMechanism ==  NULL || pKeyBlob == NULL ||
				pData == NULL || ulDataLen > EH_ENCRYPT_MAX_SIZE ||
				pEncryptedData == NULL || pulEncryptedDataLen == NULL) {
			return EHR_ARGUMENTS_BAD;
		}

		sgxStatus = sgx_Encrypt(enclaveHelpers.getSgxEnclaveId(),
                                &rv,
                                pMechanism,
								pKeyBlob,
                                pData,
                                ulDataLen,
                                pEncryptedData,
								pulEncryptedDataLen);

		return rv;
	}

	EH_RV Decrypt(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
			EH_BYTE_PTR pEncryptedData, EH_ULONG ulEncryptedDataLen,
			EH_BYTE_PTR pData, EH_ULONG_PTR pulDataLen)
	{
		EH_RV rv = EHR_FUNCTION_FAILED;
		sgx_status_t sgxStatus = sgx_status_t::SGX_ERROR_UNEXPECTED;
		SgxCrypto::EnclaveHelpers enclaveHelpers;

		if (pMechanism != NULL && pData == NULL &&
				pulDataLen != NULL) {
			if (pMechanism->mechanism == EHM_AES_GCM_128) {
				if (ulEncryptedDataLen > EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE) {
					*pulDataLen = ulEncryptedDataLen - EH_AES_GCM_IV_SIZE -
					EH_AES_GCM_MAC_SIZE;
				    return EHR_OK;
				}
			}
		}

		if (pMechanism ==  NULL || pKeyBlob == NULL || pData == NULL ||
				pEncryptedData == NULL || pulDataLen == NULL) {
			return EHR_ARGUMENTS_BAD;
		}

		sgxStatus = sgx_Decrypt(enclaveHelpers.getSgxEnclaveId(),
                                &rv,
                                pMechanism,
								pKeyBlob,
                                pEncryptedData,
                                ulEncryptedDataLen,
                                pData,
								pulDataLen);

		return rv;
	}
}
