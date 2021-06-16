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

static int32_t g_sock = -1;

static void Connect()
{
    int32_t retry_count = 360;
    struct sockaddr_in serAddr;
    int32_t sockFd = -1;

    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockFd < 0) {
        printf("Create socket failed\n");
        exit(1);
    }
    bzero(&serAddr, sizeof(serAddr));
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(prov_port);
    serAddr.sin_addr.s_addr = inet_addr(prov_ip_addr);

    do {
        if(connect(sockFd, (struct sockaddr*)&serAddr, sizeof(serAddr)) >= 0) {
            printf("Connect socket server suucess!\n");
            break;
        }
        else if (retry_count > 0) {
            printf("Connect socket server failed, sleep 0.5s and try again...\n");
            usleep(500000); // 0.5 s
        }
        else {
            printf("Fail to connect socket server.\n");
            return;
        }
    } while (retry_count-- > 0);

    g_sock = sockFd;
}

bool IsConnected()
{
    if (g_sock > 0)
        return true;
    else
        return false;
}

static void Disconnect()
{
    close(g_sock);
    g_sock = -1;
}

static bool SendAll(int32_t sock, const void *data, int32_t data_size)
{
    const char *data_ptr = (const char*) data;
    int32_t bytes_sent;

    while (data_size > 0)
    {
        bytes_sent = send(sock, data_ptr, data_size, 0);
        if (bytes_sent < 1)
            return false;

        data_ptr += bytes_sent;
        data_size -= bytes_sent;
    }

    return true;
}

static bool RecvAll(int32_t sock, void *data, int32_t data_size)
{
    char *data_ptr = (char*) data;
    int32_t bytes_recv;

    while (data_size > 0)
    {
        bytes_recv = recv(sock, data_ptr, data_size, 0);
        if (bytes_recv == 0) {
            printf("the server side may closed...\n");
            return true;
        }
        if (bytes_recv < 0) {
            printf("failed to read data\n");
            return false;
        }

        data_ptr += bytes_recv;
        data_size -= bytes_recv;
    }

    return true;
}

static EH_RV SendAndRecvMsg(const ra_samp_request_header_t *p_req,
    ra_samp_response_header_t **p_resp)
{
    ra_samp_response_header_t* out_msg;
    int req_size, resp_size = 0;
    EH_RV err = EHR_OK;

    if((NULL == p_req) ||
        (NULL == p_resp))
    {
        return -1;
    }

    /* Send a message to server */
    req_size = sizeof(ra_samp_request_header_t)+p_req->size;

    if (!SendAll(g_sock, &req_size, sizeof(req_size))) {
        printf("send req_size failed\n");
        err = EHR_GENERAL_ERROR;
        goto out;
    }
    if (!SendAll(g_sock, p_req, req_size)) {
        printf("send req buffer failed\n");
        err = EHR_GENERAL_ERROR;
        goto out;
    }

    /* Receive a message from server */
    if (!RecvAll(g_sock, &resp_size, sizeof(resp_size))) {
        printf("failed to get the resp size\n");
        err = EHR_GENERAL_ERROR;
        goto out;
    }

    if (resp_size <= 0) {
        printf("no msg need to read\n");
        err = EHR_GENERAL_ERROR;
        goto out;
    }
    out_msg = (ra_samp_response_header_t *)malloc(resp_size);
    if (!out_msg) {
        printf("allocate out_msg failed\n");
        err = EHR_DEVICE_MEMORY;
        goto out;
    }
    if (!RecvAll(g_sock, out_msg, resp_size)) {
        printf("failed to get the data\n");
        err = EHR_GENERAL_ERROR;
        goto out;
    }

    *p_resp = out_msg;
out:
    return err;
}

EH_RV RetrieveDomainKey()
{
    SgxCrypto::EnclaveHelpers enclaveHelpers;
    ra_samp_request_header_t *p_req = NULL;
    ra_samp_response_header_t *p_resp = NULL;
    sample_key_blob_t *p_dk = NULL;

    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

    EH_RV ret = EHR_OK;

    if (!IsConnected())
        Connect();

    p_req = (ra_samp_request_header_t *)malloc(sizeof(ra_samp_request_header_t));
    if (!p_req) {
        printf("allocate memory failed\n");
        ret = EHR_DEVICE_MEMORY;
        goto out;
    }

    /* retrieve the domainkey blob through the socket */

    //no extra payload need to sent
    p_req->size = 0;
    p_req->type = TYPE_RA_RETRIEVE_DK;
    SendAndRecvMsg(p_req, &p_resp);

    if (!p_resp || (p_resp->status[0] != 0) || (p_resp->status[1] != 0)) {
        printf("failed to get the resp message.\n");
        ret = EHR_ARGUMENTS_BAD;
        goto out;
    }

    if (TYPE_RA_RETRIEVE_DK != p_resp->type) {
        printf("the resp msg type is not matched.\n");
        ret = EHR_ARGUMENTS_BAD;
        goto out;
    }

    p_dk = (sample_key_blob_t*)p_resp->body;

    /* store the domainkey blob into enclave */
    sgx_ret = sgx_store_domainkey(enclaveHelpers.getSgxEnclaveId(),
                         &sgxStatus,
                         p_dk->blob,
                         p_dk->blob_size);
    if (sgx_ret != SGX_SUCCESS || sgxStatus) {
        printf("failed(%d) to store domainkey into enclave\n", sgx_ret);
        ret = EHR_FUNCTION_FAILED;
        goto out;
    }

out:
    if (IsConnected())
        Disconnect();

    SAFE_FREE(p_req);
    SAFE_FREE(p_resp);

    return ret;
}

EH_RV UpgradeDomainKey()
{
    //TODO
    return EHR_OK;
}


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

    if (EHR_OK != RetrieveDomainKey())
        return EHR_DEVICE_ERROR;

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

    if (eOrigin != EHO_INTERNAL_KEY || pKeyBlob == NULL) {
        return EHR_ARGUMENTS_BAD;
    }

    pKeyBlob->ulKeyType = ulKeySpec;

    switch (ulKeySpec) {
        case EHM_AES_GCM_128:
            if (pKeyBlob->pKeyData == NULL) {
                ret = sgx_create_aes_key(enclaveHelpers.getSgxEnclaveId(),
                                         &sgxStatus,
                                         pKeyBlob->pKeyData,
                                         pKeyBlob->ulKeyLen,
                                         &(pKeyBlob->ulKeyLen));
            } else {
                ret = sgx_create_aes_key(enclaveHelpers.getSgxEnclaveId(),
                                         &sgxStatus,
                                         pKeyBlob->pKeyData,
                                         pKeyBlob->ulKeyLen,
                                         NULL);
            }
            break;
        case EHM_RSA_3072:
            if (pKeyBlob->pKeyData == NULL)
                ret  = sgx_create_rsa_key(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                          pKeyBlob->pKeyData, pKeyBlob->ulKeyLen, &(pKeyBlob->ulKeyLen));
            else
                ret  = sgx_create_rsa_key(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                          pKeyBlob->pKeyData, pKeyBlob->ulKeyLen, NULL);
            break;
        default:
            return EHR_MECHANISM_INVALID;
    }

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

            ret = sgx_aes_encrypt(enclaveHelpers.getSgxEnclaveId(),
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

            ret = sgx_rsa_encrypt(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
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

            ret = sgx_aes_decrypt(enclaveHelpers.getSgxEnclaveId(),
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
                ret = sgx_rsa_decrypt(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
                                      pKeyBlob->pKeyData, pKeyBlob->ulKeyLen,
                                      pEncryptedData, ulEncryptedDataLen,
                                      pData, *pulDataLen, NULL);
            }
            else {
                uint32_t req_plaintext_len = 0;
                ret = sgx_rsa_decrypt(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
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
            ret = sgx_rsa_sign(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
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
            ret = sgx_rsa_verify(enclaveHelpers.getSgxEnclaveId(), &sgxStatus,
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

    ret = sgx_generate_datakey(enclaveHelpers.getSgxEnclaveId(),
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

    if (pUsrKeyBlob->ulKeyType != EHM_RSA_3072) {
        return EHR_ARGUMENTS_BAD;
    }

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

    ret = sgx_export_datakey(enclaveHelpers.getSgxEnclaveId(),
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
