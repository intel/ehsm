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


extern "C" {

/*
create the enclave
@return
[string] json string
    {
        code: int,
        message: string,
        result: {}
    }
*/
char* NAPI_Initialize();

/*
destory the enclave
*/
void NAPI_Finalize();

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            cmk_base64 : string
        }
    }
*/
char* NAPI_CreateKey(const uint32_t keyspec, const uint32_t origin);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            cipherText_base64 : string
        }
    }
*/
char* NAPI_Encrypt(const char* cmk_base64,
        const char* plaintext,
        const char* aad);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            plaintext_base64 : string
        }
    }
*/
char* NAPI_Decrypt(const char* cmk_base64,
        const char* ciphertext_base64,
        const char* aad);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            ciphertext_base64 : string,
        }
    }
*/
char* NAPI_AsymmetricEncrypt(const char* cmk_base64,
    const char* plaintext);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            plaintext_base64 : string,
        }
    }
*/
char* NAPI_AsymmetricDecrypt(const char* cmk_base64,
        const char* ciphertext_base64);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            plaintext_base64 : string,
            cipherText_base64 : string
        }
    }
*/
char* NAPI_GenerateDataKey(const char* cmk_base64,
        const uint32_t keylen,
        const char* aad);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            ciphertext_base64 : string
        }
    }
*/
char* NAPI_GenerateDataKeyWithoutPlaintext(const char* cmk_base64,
        const uint32_t keylen,
        const char* aad);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            newdatakey_base64 : string,
        }
    }
*/
char* NAPI_ExportDataKey(const char* cmk_base64,
        const char* ukey_base64,
        const char* aad,
        const char* olddatakey_base64);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            signature_base64 : string
        }
    }
*/
char* NAPI_Sign(const char* cmk_base64,
        const char* digest);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            result : bool
        }
    }
*/
char* NAPI_Verify(const char* cmk_base64,
        const char* digest,
        const char* signature_base64);

/*
 *  @param p_msg0 : msg0 json string
 *  @return
 *  [string] json string
 *      {
 *          code: int,
 *          message: string,
 *          result: {
 *              "challenge" : string,
 *              "g_a" : Json::Value
 *                  {
 *                      gx : array(int),
 *                      gy : array(int)
 *                  }
 *          }
 *      }
 */
char* NAPI_RA_HANDSHAKE_MSG0(const char *p_msg0);

/*
 *  @param p_msg2 : msg2 json string
 *  @return
 *  [string] json string
 *      {
 *          code: int,
 *          message: string,
 *          result: {
 *              msg3_base64 : string
 *          }
 *      }
 */
char* NAPI_RA_HANDSHAKE_MSG2(const char *p_msg2);

/*
 *  @param p_msg4 : msg4 json string
 *  @return
 *  [string] json string
 *      {
 *          code: int,
 *          message: string,
 *          result: {
 *              appid : string
 *              apikey : string
 *          }
 *      }
 */
char* NAPI_RA_GET_API_KEY(const char *p_msg4);

}  // extern "C"


#endif