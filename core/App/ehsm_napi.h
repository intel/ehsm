/*
 * Copyright (C) 2021-2022 Intel Corporation
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

#ifndef _EHSM_NAPI_H
#define _EHSM_NAPI_H

using namespace std;

extern "C" {

/*
create the enclave
*/
char* NAPI_Initialize();

/*
destory the enclave
*/
char* NAPI_Finalize();

/*
@return
[char*] cmk -- the customer master key.
*/
char* NAPI_CreateKey(const uint32_t keyspec, const uint32_t origin);

/*
@return
[char*] ciphertext -- the encrypted datas
*/
char* NAPI_Encrypt(const char* cmk,
        const char* plaintext,
        const char* aad);

/*
@return
[char*] plaintext -- the plaintext datas
*/
char* NAPI_Decrypt(const char* cmk,
        const char* ciphertext,
        const char* aad);

/*
@return
[char*] ciphertext -- the encrypted datas
*/
char* NAPI_AsymmetricEncrypt(const char* cmk,
    const char* plaintext);

/*
@return
[char*] plaintext -- the plaintext datas
*/
char* NAPI_AsymmetricDecrypt(const char* cmk,
        const char* ciphertext);

/*
@return
[char*] plaintext --the plaintext datakey
[char*] ciphertext -- the cipher datakey
*/
char* NAPI_GenerateDataKey(const char* cmk,
        const char* aad,
        char* plaintext,
        char* *ciphertext);

/*
@return
[char*] ciphertext -- the cipher datakey
*/
char* NAPI_GenerateDataKeyWithoutPlaintext(const char* cmk,
        const char* aad,
        const char* plaintext);

/*
@return
[char*] newdatakey -- the newdatakey wrapped by the ukey
*/
char* NAPI_ExportDataKey(const char* cmk,
        const char* ukey,
        const char* aad,
        const char* olddatakey);

/*
@return
[char*] signature -- the signature of the digest
*/
char* NAPI_Sign(const char* cmk,
        const char* digest);

/*
@return
[bool] result -- the result (true/false) of verification
*/
char* NAPI_Verify(const char* cmk,
        const char* digest,
        const char* signature);


}  // extern "C"


#endif