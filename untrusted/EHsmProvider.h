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

typedef unsigned long int EH_ULONG;
typedef unsigned char     EH_BYTE;

typedef EH_BYTE*     EH_BYTE_PTR;
typedef EH_ULONG*    EH_ULONG_PTR;
typedef void*        EH_VOID_PTR;

enum EH_KEY_ORIGIN {
    EHO_INTERNAL_KEY,
    EHO_EXTERNAL_KEY,
};

/*
 * EH_MECHANISM_TYPE is a value that identifies a key spec
 * type
 */
typedef unsigned long int    EH_MECHANISM_TYPE;

/* the following key spec types are defined: */
#define EHM_AES_GCM_128  0x00000000UL
#define EHM_SM4          0x00000001UL
#define EHM_RSA_3072     0x00000002UL

typedef struct EH_MECHANISM {
    EH_MECHANISM_TYPE   mechanism;
    EH_VOID_PTR         pParameter;
    EH_ULONG            ulParameterLen;  /* in bytes */
} EH_MECHANISM;

typedef EH_MECHANISM* EH_MECHANISM_PTR;

typedef struct EH_GCM_PARAMS {
    EH_BYTE_PTR       pAAD;
    EH_ULONG          ulAADLen;
} EH_GCM_PARAMS;

typedef EH_GCM_PARAMS* EH_GCM_PARAMS_PTR;

typedef struct EH_KEY_BLOB {
    EH_MECHANISM_TYPE ulKeyType;
    EH_ULONG          ulKeyLen;
    EH_BYTE_PTR       pKeyData;
} EH_KEY_BLOB;

typedef EH_KEY_BLOB* EH_KEY_BLOB_PTR;

typedef EH_ULONG          EH_RV;

#define EHR_OK                                0x00000000UL
#define EHR_MECHANISM_INVALID                 0x00000001UL
#define EHR_DEVICE_MEMORY                     0x00000002UL
#define EHR_DEVICE_ERROR                      0x00000003UL
#define EHR_GENERAL_ERROR                     0x00000005UL
#define EHR_FUNCTION_FAILED                   0x00000006UL
#define EHR_ARGUMENTS_BAD                     0x00000007UL

namespace EHsmProvider
{
    EH_RV Initialize();

    void Finalize();

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

    EH_RV Sign(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
               EH_BYTE_PTR pData, EH_ULONG ulDataLen,
               EH_BYTE_PTR pSignature, EH_ULONG_PTR pulSignatureLen);

    EH_RV Verify(EH_MECHANISM_PTR pMechanism, EH_KEY_BLOB_PTR pKeyBlob,
                 EH_BYTE_PTR pData, EH_ULONG ulDataLen,
                 EH_BYTE_PTR pSignature, EH_ULONG ulSignatureLen, bool* result);
}

#endif
