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
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "enclave_helpers.h"
#include "enclave_hsm_u.h"
#include "ehsm_provider.h"

namespace EHsmProvider
{

EH_RV Initialize()
{
    sgx_status_t status;
    uint32_t ret_status;

    SgxCrypto::EnclaveHelpers enclaveHelpers;

    if (!enclaveHelpers.isSgxEnclaveLoaded())
    {
        if (SGX_SUCCESS != enclaveHelpers.loadSgxEnclave())
        {
            return EHR_DEVICE_ERROR;
        }
    }

    // create ECDH session using initiator enclave, it would create ECDH session with responder enclave running in another process
    /*status = enclave_la_create_session(enclaveHelpers.getSgxEnclaveId(), &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        enclaveHelpers.unloadSgxEnclave();
        return -1;
    }
    printf("succeed to establish secure channel.\n");

    // Test message exchange between initiator enclave and responder enclave running in another process
    status = enclave_la_message_exchange(enclaveHelpers.getSgxEnclaveId(), &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("test_message_exchange Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        enclaveHelpers.unloadSgxEnclave();
        return -1;
    }
    printf("Succeed to exchange secure message...\n");

    // close ECDH session
    status = enclave_la_close_session(enclaveHelpers.getSgxEnclaveId(), &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        enclaveHelpers.unloadSgxEnclave();
        return -1;
    }*/
    printf("Succeed to close Session...\n");

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
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SgxCrypto::EnclaveHelpers enclaveHelpers;
    printf("==========CreateKey IN==========\n");
    printf("ulKeySpec : %lu\n", ulKeySpec);
    printf("eOrigin : %d\n", eOrigin);
    printf("pKeyBlob : %p\n", pKeyBlob);

    if (eOrigin != EHO_INTERNAL_KEY || pKeyBlob == NULL) {
        return EHR_ARGUMENTS_BAD;
    }
    printf("==========CreateKey 1==========\n");
    pKeyBlob->ulKeyType = ulKeySpec;

    switch (ulKeySpec) {
        case EHM_AES_GCM_128:
            if (pKeyBlob->pKeyData == NULL) {
                printf("==========CreateKey 2.1==========\n");
                ret = enclave_create_aes_key(enclaveHelpers.getSgxEnclaveId(),
                                         &sgxStatus,
                                         pKeyBlob->pKeyData,
                                         pKeyBlob->ulKeyLen,
                                         &(pKeyBlob->ulKeyLen));
            } else {
                printf("==========CreateKey 2.2==========\n");
                ret = enclave_create_aes_key(enclaveHelpers.getSgxEnclaveId(),
                                         &sgxStatus,
                                         pKeyBlob->pKeyData,
                                         pKeyBlob->ulKeyLen,
                                         NULL);
            }
            break;
        case EHM_RSA_3072:
            if (pKeyBlob->pKeyData == NULL)
                ret  = enclave_create_rsa_key(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                          pKeyBlob->pKeyData, pKeyBlob->ulKeyLen, &(pKeyBlob->ulKeyLen));
            else
                ret  = enclave_create_rsa_key(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                          pKeyBlob->pKeyData, pKeyBlob->ulKeyLen, NULL);
            break;
        default:
            return EHR_MECHANISM_INVALID;
    }
    printf("==========CreateKey 3========== %d | %d\n", ret, sgxStatus);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EHR_FUNCTION_FAILED;
    else
        return EHR_OK;
}

EH_RV Encrypt(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
        EH_BYTE_PTR pData, EH_ULONG ulDataLen,
        EH_BYTE_PTR pEncryptedData, EH_ULONG_PTR pulEncryptedDataLen)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SgxCrypto::EnclaveHelpers enclaveHelpers;

    if (pMechanism != NULL && pEncryptedData == NULL &&
            pulEncryptedDataLen != NULL) {
        return enclaveHelpers.getEncryptLen(pMechanism->mechanism,
                ulDataLen, pulEncryptedDataLen);
    }

    if (pMechanism ==  NULL || pKeyBlob == NULL ||
            pData == NULL || ulDataLen == 0 ||
            pEncryptedData == NULL || pulEncryptedDataLen == NULL ||
            pMechanism->mechanism != pKeyBlob->ulKeyType) {
        return EHR_ARGUMENTS_BAD;
    }

    switch(pMechanism->mechanism) {
        case EHM_AES_GCM_128:
            // todo: refine later
            if (ulDataLen > EH_ENCRYPT_MAX_SIZE) {
                return EHR_ARGUMENTS_BAD;
            }

            if (pMechanism->ulParameterLen != sizeof(EH_GCM_PARAMS)) {
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

            ret = enclave_aes_encrypt(enclaveHelpers.getSgxEnclaveId(),
                                  &sgxStatus,
                                  EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD,
                                  EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen,
                                  pKeyBlob->pKeyData,
                                  pKeyBlob->ulKeyLen,
                                  pData,
                                  ulDataLen,
                                  pEncryptedData,
                                  *pulEncryptedDataLen);
            break;
        case EHM_RSA_3072:
            if (ulDataLen > RSA_OAEP_3072_MAX_ENCRYPTION_SIZE) {
                printf("Error data len(%lu) for rsa encryption, max is 318.\n", ulDataLen);
                return EHR_ARGUMENTS_BAD;
            }

            ret = enclave_rsa_encrypt(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                  pKeyBlob->pKeyData, pKeyBlob->ulKeyLen,
                                  pData, ulDataLen, pEncryptedData, *pulEncryptedDataLen);
            break;
        default:
            return EHR_MECHANISM_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EHR_FUNCTION_FAILED;
    else
        return EHR_OK;
}

EH_RV Decrypt(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
        EH_BYTE_PTR pEncryptedData, EH_ULONG ulEncryptedDataLen,
        EH_BYTE_PTR pData, EH_ULONG_PTR pulDataLen)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SgxCrypto::EnclaveHelpers enclaveHelpers;

    if (pMechanism == NULL)
        return EHR_ARGUMENTS_BAD;

    if (pData == NULL && pulDataLen != NULL) {
        if (pMechanism->mechanism == EHM_AES_GCM_128) {
            if (ulEncryptedDataLen > EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE) {
                *pulDataLen = ulEncryptedDataLen - EH_AES_GCM_IV_SIZE -
                    EH_AES_GCM_MAC_SIZE;
                return EHR_OK;
            }
        }
    }

    if (pKeyBlob == NULL || pEncryptedData == NULL || pulDataLen == NULL ||
            pMechanism->mechanism != pKeyBlob->ulKeyType) {
        return EHR_ARGUMENTS_BAD;
    }

    switch(pMechanism->mechanism) {
        case EHM_AES_GCM_128:
            if (pData == NULL)
                return EHR_ARGUMENTS_BAD;

            if (pMechanism->ulParameterLen != sizeof(EH_GCM_PARAMS)) {
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

            ret = enclave_aes_decrypt(enclaveHelpers.getSgxEnclaveId(),
                                  &sgxStatus,
                                  EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD,
                                  EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen,
                                  pKeyBlob->pKeyData,
                                  pKeyBlob->ulKeyLen,
                                  pEncryptedData,
                                  ulEncryptedDataLen,
                                  pData,
                                  *pulDataLen);
            break;
        case EHM_RSA_3072:
            if (ulEncryptedDataLen > RSA_OAEP_3072_CIPHER_LENGTH) {
                printf("Error data len(%lu) for rsa decryption, max is 384.\n", ulEncryptedDataLen);
                return EHR_ARGUMENTS_BAD;
            }

            if (pData != NULL) {
                ret = enclave_rsa_decrypt(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                      pKeyBlob->pKeyData, pKeyBlob->ulKeyLen,
                                      pEncryptedData, ulEncryptedDataLen,
                                      pData, *pulDataLen, NULL);
            }
            else {
                uint32_t req_plaintext_len = 0;
                ret = enclave_rsa_decrypt(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                      pKeyBlob->pKeyData, pKeyBlob->ulKeyLen,
                                      pEncryptedData, ulEncryptedDataLen,
                                      pData, *pulDataLen, &req_plaintext_len);
                *pulDataLen = req_plaintext_len;
            }
            break;
        default:
            return EHR_MECHANISM_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EHR_FUNCTION_FAILED;
    else
        return EHR_OK;
}

EH_RV Sign(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
           EH_BYTE_PTR pData, EH_ULONG ulDataLen,
           EH_BYTE_PTR pSignature, EH_ULONG_PTR pulSignatureLen)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SgxCrypto::EnclaveHelpers enclaveHelpers;

    if (pMechanism == NULL)
        return EHR_ARGUMENTS_BAD;

    if (pulSignatureLen != NULL && pSignature == NULL) {
        if (pMechanism->mechanism == EHM_RSA_3072)
            *pulSignatureLen = RSA_OAEP_3072_SIGNATURE_SIZE;
        else
            return EHR_MECHANISM_INVALID;
        return EHR_OK;
    }

    if (pKeyBlob == NULL || pData == NULL || ulDataLen == 0 ||
        pSignature == NULL || pulSignatureLen == NULL) {
        return EHR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism) {
        case EHM_RSA_3072:
            if (ulDataLen > 256) {
                printf("rsa 3072 sign requires a <=256B digest.\n");
                return EHR_ARGUMENTS_BAD;
            }
            if (*pulSignatureLen != RSA_OAEP_3072_SIGNATURE_SIZE) {
                printf("rsa 3072 sign requires a 384B signature.\n");
                return EHR_ARGUMENTS_BAD;
            }
            ret = enclave_rsa_sign(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                               pKeyBlob->pKeyData, pKeyBlob->ulKeyLen,
                               pData, ulDataLen, pSignature, *pulSignatureLen);
            break;
        default:
            return EHR_MECHANISM_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EHR_FUNCTION_FAILED;
    else
        return EHR_OK;
}


EH_RV Verify(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
             EH_BYTE_PTR pData, EH_ULONG ulDataLen,
             EH_BYTE_PTR pSignature, EH_ULONG ulSignatureLen, bool* result)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SgxCrypto::EnclaveHelpers enclaveHelpers;

    if (pMechanism ==  NULL || pKeyBlob == NULL || pData == NULL || ulDataLen == 0 ||
        pSignature == NULL || ulSignatureLen == 0 || result == NULL) {
        return EHR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism) {
        case EHM_RSA_3072:
            if (ulDataLen > 256) {
                printf("rsa 3072 verify requires a <=256B digest.\n");
                return EHR_ARGUMENTS_BAD;
            }
            if (ulSignatureLen != RSA_OAEP_3072_SIGNATURE_SIZE) {
                printf("rsa 3072 verify requires a 384B signature.\n");
                return EHR_ARGUMENTS_BAD;
            }
            ret = enclave_rsa_verify(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                 pKeyBlob->pKeyData, pKeyBlob->ulKeyLen,
                                 pData, ulDataLen, pSignature, ulSignatureLen, result);
            break;
        default:
            return EHR_MECHANISM_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EHR_FUNCTION_FAILED;
    else
        return EHR_OK;
}

EH_RV GenerateDataKey(EH_MECHANISM_PTR  pMechanism,
                      EH_KEY_BLOB_PTR   pMasterKeyBlob,
                      EH_BYTE_PTR       pPlainDataKey,
                      EH_ULONG          ulPlainDataKeyLen,
                      EH_BYTE_PTR       pEncryptedDataKey,
                      EH_ULONG_PTR      pulEncryptedDataKeyLen)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SgxCrypto::EnclaveHelpers enclaveHelpers;
    EH_BYTE_PTR pContext = NULL;
    EH_ULONG ulContextLen = 0;

    if (pMasterKeyBlob != NULL && pEncryptedDataKey == NULL &&
            pulEncryptedDataKeyLen != NULL) {
        return enclaveHelpers.getEncryptLen(pMasterKeyBlob->ulKeyType,
                ulPlainDataKeyLen, pulEncryptedDataKeyLen);
    }

    if (ulPlainDataKeyLen > 1024 || ulPlainDataKeyLen == 0) {
        return EHR_ARGUMENTS_BAD;
    }

    if (pMechanism == NULL || pMasterKeyBlob ==  NULL ||
            pEncryptedDataKey == NULL || pulEncryptedDataKeyLen == NULL ||
            pMechanism->mechanism != pMasterKeyBlob->ulKeyType) {
        return EHR_ARGUMENTS_BAD;
    }

    switch(pMechanism->mechanism) {
        case EHM_AES_GCM_128:
            if (pMechanism->ulParameterLen != sizeof(EH_GCM_PARAMS)) {
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

            pContext = EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD;
            ulContextLen = EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen;

            break;
        default:
            return EHR_MECHANISM_INVALID;
    }

    ret = enclave_generate_datakey(enclaveHelpers.getSgxEnclaveId(),
                               &sgxStatus,
                               pMechanism->mechanism,
                               pMasterKeyBlob->pKeyData,
                               pMasterKeyBlob->ulKeyLen,
                               pContext,
                               ulContextLen,
                               pPlainDataKey,
                               ulPlainDataKeyLen,
                               pEncryptedDataKey,
                               *pulEncryptedDataKeyLen);

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EHR_FUNCTION_FAILED;
    else
        return EHR_OK;
}

EH_RV GenerateDataKeyWithoutPlaintext(EH_MECHANISM_PTR  pMechanism,
                                      EH_KEY_BLOB_PTR   pMasterKeyBlob,
                                      EH_ULONG          ulPlainDataKeyLen,
                                      EH_BYTE_PTR       pEncryptedDataKey,
                                      EH_ULONG_PTR      pulEncryptedDataKeyLen)
{
    return GenerateDataKey(pMechanism, pMasterKeyBlob, NULL, ulPlainDataKeyLen,
            pEncryptedDataKey, pulEncryptedDataKeyLen);
}

EH_RV ExportDataKey(EH_MECHANISM_PTR pMechanism,
            EH_KEY_BLOB_PTR pUsrKeyBlob, EH_KEY_BLOB_PTR pMasterKeyBlob,
            EH_BYTE_PTR pEncryptedDataKey, EH_ULONG ulEncryptedDataKeyLen,
            EH_BYTE_PTR pNewEncryptedDataKey, EH_ULONG_PTR pulNewEncryptedDataKeyLen)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SgxCrypto::EnclaveHelpers enclaveHelpers;
    EH_BYTE_PTR pContext = NULL;
    EH_ULONG ulContextLen = 0;

    if (pNewEncryptedDataKey == NULL && pulNewEncryptedDataKeyLen != NULL) {
        *pulNewEncryptedDataKeyLen = RSA_OAEP_3072_CIPHER_LENGTH;
        return EHR_OK;
    }

    if (ulEncryptedDataKeyLen > 1024 || ulEncryptedDataKeyLen == 0) {
        return EHR_ARGUMENTS_BAD;
    }

    if (pMechanism == NULL || pUsrKeyBlob ==  NULL || pMasterKeyBlob ==  NULL ||
            pEncryptedDataKey == NULL || pNewEncryptedDataKey == NULL ||
            pulNewEncryptedDataKeyLen == NULL ||
            pMechanism->mechanism != pMasterKeyBlob->ulKeyType) {
        return EHR_ARGUMENTS_BAD;
    }

	if (pUsrKeyBlob->ulKeyType != EHM_RSA_3072) {
        return EHR_ARGUMENTS_BAD;
    }

	switch(pMechanism->mechanism) {
        case EHM_AES_GCM_128:
            if (pMechanism->ulParameterLen != sizeof(EH_GCM_PARAMS)) {
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

            pContext = EH_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD;
            ulContextLen = EH_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen;

            break;
        default:
            return EHR_MECHANISM_INVALID;
    }

    ret = enclave_export_datakey(enclaveHelpers.getSgxEnclaveId(),
                               &sgxStatus,
                               pMasterKeyBlob->ulKeyType,
                               pMasterKeyBlob->pKeyData,
                               pMasterKeyBlob->ulKeyLen,
                               pContext,
                               ulContextLen,
                               pEncryptedDataKey,
                               ulEncryptedDataKeyLen,
                               pUsrKeyBlob->ulKeyType,
                               pUsrKeyBlob->pKeyData,
                               pUsrKeyBlob->ulKeyLen,
                               pNewEncryptedDataKey,
                               *pulNewEncryptedDataKeyLen);

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS) {
        return EHR_FUNCTION_FAILED;
    }
    else
        return EHR_OK;
}

}
