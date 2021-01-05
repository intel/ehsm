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

#include "enclave_helpers.h"

// Globals with file scope.
namespace SgxCrypto
{
    sgx_enclave_id_t    EnclaveHelpers::mEnclaveInvalidId       = 0;
    volatile long       EnclaveHelpers::mSgxEnclaveLoadedCount  = 0;
    sgx_enclave_id_t    EnclaveHelpers::mSgxEnclaveId           = 0;

    EnclaveHelpers::EnclaveHelpers()
    {

    }

    sgx_status_t EnclaveHelpers::loadSgxEnclave()
    {
        sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
        sgx_enclave_id_t sgxEnclaveId = mEnclaveInvalidId;

        if (isSgxEnclaveLoaded())
        {
            // The Intel SGX enclave is already loaded so return success.
            __sync_add_and_fetch(&mSgxEnclaveLoadedCount, 1);
            return SGX_SUCCESS;
        }

        std::string enclaveFileName = ENCLAVE_PATH;
        enclaveFileName = enclaveFileName + ENCLAVE_NAME;

        sgxStatus = sgx_create_enclave(enclaveFileName.data(),
                                       SGX_DEBUG_FLAG,
                                       NULL,
                                       NULL,
                                       &sgxEnclaveId,
                                       NULL);

        // Save the SGX enclave ID for later.
        if (sgxStatus == SGX_SUCCESS)
        {
            setSgxEnclaveId(sgxEnclaveId);
            __sync_add_and_fetch(&mSgxEnclaveLoadedCount, 1);
        }
        else
        {
            __sync_lock_test_and_set(&mSgxEnclaveLoadedCount, 0);
            sgx_destroy_enclave(sgxEnclaveId);
            setSgxEnclaveId(mEnclaveInvalidId);
        }

        return sgxStatus;
    }

    sgx_status_t EnclaveHelpers::unloadSgxEnclave()
    {
        sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;

        do
        {
            if (false == isSgxEnclaveLoaded())
            {
                sgxStatus = SGX_SUCCESS;
                break;
            }

            __sync_sub_and_fetch(&mSgxEnclaveLoadedCount, 1);

            // The Intel SGX enclave is already
            // in use so return success.
            if (mSgxEnclaveLoadedCount > 0)
            {
                sgxStatus = SGX_SUCCESS;
                break;
            }

            sgxStatus = sgx_destroy_enclave(getSgxEnclaveId());

            if (sgxStatus == SGX_SUCCESS)
            {
                setSgxEnclaveId(mEnclaveInvalidId);
                __sync_lock_test_and_set(&mSgxEnclaveLoadedCount, 0);
            }

        } while (false);

        return sgxStatus;
    }

    EH_RV EnclaveHelpers::getEncryptLen(EH_MECHANISM_TYPE ulKeyType,
                                        EH_ULONG ulDataLen, EH_ULONG_PTR pulEncryptLen)
    {
        if (pulEncryptLen == NULL)
            return EHR_ARGUMENTS_BAD;

        switch(ulKeyType) {
            case EHM_AES_GCM_128:
                *pulEncryptLen = ulDataLen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE;
                return EHR_OK;
            case EHM_RSA_3072:
                *pulEncryptLen = RSA_OAEP_3072_MAX_ENCRYPTION_SIZE;
                return EHR_OK;
            default:
                return EHR_MECHANISM_INVALID;
        }
    }
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}
