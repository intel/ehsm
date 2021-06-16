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

#ifndef EHSM_RPOVIDER_H
#define EHSM_PROVIDER_H

#include "common_ehsm.h"

typedef enum _ra_msg_type_t
{
     TYPE_RA_MSG0 = 0,
     TYPE_RA_MSG1,
     TYPE_RA_MSG2,
     TYPE_RA_MSG3,
     TYPE_RA_ATT_RESULT,
     TYPE_RA_RETRIEVE_DK,
}ra_msg_type_t;

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

const char prov_ip_addr[] = "127.0.0.1";
const uint32_t prov_port = 8887;

#pragma pack(1)

typedef struct _ra_samp_request_header_t{
    uint8_t  type;     /* set to one of ra_msg_type_t*/
    uint32_t size;     /*size of request body*/
    uint8_t  align[3];
    uint8_t body[];
} ra_samp_request_header_t;

typedef struct _ra_samp_response_header_t{
    uint8_t  type;      /* set to one of ra_msg_type_t*/
    uint8_t  status[2];
    uint32_t size;      /*size of the response body*/
    uint8_t  align[1];
    uint8_t  body[];
} ra_samp_response_header_t;

typedef struct sample_key_blob_t {
    uint32_t        blob_size;
    uint8_t         blob[];
} sample_key_blob_t;

#pragma pack()


namespace EHsmProvider
{
    EH_RV Initialize();

    void Finalize();

    EH_RV RetrieveDomainKey();

    EH_RV UpgradeDomainKey();

    EH_RV CreateKey(EH_MECHANISM_TYPE ulKeySpec, EH_KEY_ORIGIN eOrigin,
            EH_KEY_BLOB_PTR pKeyBlob);

    EH_RV Encrypt(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
            EH_BYTE_PTR pData, EH_ULONG ulDataLen,
            EH_BYTE_PTR pEncryptedData, EH_ULONG_PTR pulEncryptedDataLen);

    EH_RV Decrypt(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
            EH_BYTE_PTR pEncryptedData, EH_ULONG ulEncryptedDataLen,
            EH_BYTE_PTR pData, EH_ULONG_PTR pulDataLen);

    EH_RV GenerateDataKey(EH_MECHANISM_PTR pMechanism,
            EH_KEY_BLOB_PTR pMasterKeyBlob,
            EH_BYTE_PTR pPlainDataKey, EH_ULONG ulPlainDataKeyLen,
            EH_BYTE_PTR pEncryptedDataKey, EH_ULONG_PTR pulEncryptedDataKeyLen);

    EH_RV GenerateDataKeyWithoutPlaintext(EH_MECHANISM_PTR pMechanism,
            EH_KEY_BLOB_PTR pMasterKeyBlob, EH_ULONG ulPlainDataKeyLen,
            EH_BYTE_PTR pEncryptedDataKey, EH_ULONG_PTR pulEncryptedDataKeyLen);

    EH_RV ExportDataKey(EH_MECHANISM_PTR pMechanism,
            EH_KEY_BLOB_PTR pUsrKeyBlob, EH_KEY_BLOB_PTR pMasterKeyBlob,
            EH_BYTE_PTR pEncryptedDataKey, EH_ULONG pEncryptedDataKeyLen,
            EH_BYTE_PTR pEncryptedDataKey_new, EH_ULONG_PTR pulEncryptedDataKeyLen_new);

    EH_RV Sign(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
               EH_BYTE_PTR pData, EH_ULONG ulDataLen,
               EH_BYTE_PTR pSignature, EH_ULONG_PTR pulSignatureLen);

    EH_RV Verify(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
                 EH_BYTE_PTR pData, EH_ULONG ulDataLen,
                 EH_BYTE_PTR pSignature, EH_ULONG ulSignatureLen, bool* result);
}

#endif
