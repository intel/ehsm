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

#ifndef _EHSM_FFI_H
#define _EHSM_FFI_H
#include "json_utils.h"

extern "C"
{

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
    uint32_t ffi_initialize(JsonObj payloadJson, char *respJson);

    /*
    destory the enclave
    */
    uint32_t ffi_finalize(char *respJson);

    /**
     * @brief Create key and save the parameters when using the key for encrypt, decrypt, sign and verify
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    keyspec : int,
                    purpose : int,
                    origin : int,
                    padding_mode : int,
                    digest_mode : int
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                cmk : a base64 string
            }
        }
     */
    uint32_t ffi_createKey(JsonObj payloadJson, char *respJson);

    /**
     * @brief Get public key from asymmetric keypair
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                pubkey : a base64 string
            }
        }
     */
    uint32_t ffi_getPublicKey(JsonObj payloadJson, char *respJson);

    /**
     * @brief encrypt plaintext with specicied key
     * this function is used for aes_gcm and sm4
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    plaintext : a base64 string,
                    aad : a base64 string
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                ciphertext : a base64 string
            }
        }
     */
    uint32_t ffi_encrypt(JsonObj payloadJson, char *respJson);

    /**
     * @brief decrypt ciphertext with specicied key
     * this function is used for aes_gcm and sm4
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    ciphertext : a base64 string,
                    aad : a base64 string
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                plaintext : a base64 string
            }
        }
     */
    uint32_t ffi_decrypt(JsonObj payloadJson, char *respJson);

    /**
     * @brief encrypt plaintext with specicied key
     * this function is used for aes_gcm and sm4
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    plaintext : a base64 string
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                ciphertext : a base64 string
            }
        }
     */
    uint32_t ffi_asymmetricEncrypt(JsonObj payloadJson, char *respJson);

    /**
     * @brief decrypt ciphertext with specicied key
     * this function is used for aes_gcm and sm4
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    ciphertext : a base64 string,
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                plaintext : a base64 string
            }
        }
     */
    uint32_t ffi_asymmetricDecrypt(JsonObj payloadJson, char *respJson);

    /**
     * @brief generate key and encrypt with specicied function
     * only support symmetric key
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    keylen : int,
                    aad : a base64 string
                }
     *
     * @return char* return value have key plaintext and ciphertext
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                plaintext : a base64 string,
                ciphertext : a base64 string
            }
        }
     */
    uint32_t ffi_generateDataKey(JsonObj payloadJson, char *respJson);

    /**
     * @brief generate key and encrypt with specicied function
     * only support symmetric key
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    keylen : int,
                    aad : a base64 string
                }
     *
     * @return char* return value have key plaintext and ciphertext
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                ciphertext : a base64 string
            }
        }
     */
    uint32_t ffi_generateDataKeyWithoutPlaintext(JsonObj payloadJson, char *respJson);

    /**
     * @brief pass in a key to decrypt the data key
     * use after ffi_GenerateDataKeyWithoutPlaintext
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    ukey : a base64 string,
                    aad : a base64 string,
                    olddatakey : a base64 string
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                newdatakey : a base64 string
            }
        }
     */
    uint32_t ffi_exportDataKey(JsonObj payloadJson, char *respJson);

    /**
     * @brief create key sign with rsa/ec/sm2
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    digest : a base64 string,
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                signature : a base64 string
            }
        }
     */
    uint32_t ffi_sign(JsonObj payloadJson, char *respJson);

    /**
     * @brief verify key sign
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    digest : a base64 string,
                    signature ： a base64 string
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                result : bool
            }
        }
     */
    uint32_t ffi_verify(JsonObj payloadJson, char *respJson);

    /*
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
    uint32_t ffi_enroll(char *respJson);

    /**
     * @brief Generate a quote of the eHSM-KMS core enclave for user used to do the SGX DCAP Remote Attestation.
     * User may send it to a remote reliable third party or directly send it to eHSM-KMS via VerifyQuote API to do the quote verification.
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    challenge : a base64 string
                }
     *  @return
     *  [string] json string
     *      {
     *          code: int,
     *          message: string,
     *          result: {
     *              "challenge" : a base64 string,
     *              "quote" : a base64 string
     *          }
     *      }
     */
    uint32_t ffi_generateQuote(JsonObj payloadJson, char *respJson);

    /**
     * @brief Users are expected already got a valid DCAP format QUOTE.
     * And it could use this API to send it to eHSM-KMS to do a quote verification.
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    quote : a base64 string,
                    mr_signer : string,
                    mr_enclave : string,
                    nonce : a base64 string
                }
     *  @return
     *  [string] json string
     *      {
     *          code: int,
     *          message: string,
     *          result: {
     *              result : bool,
     *              "nonce" : a base64 string
     *          }
     *      }
     */
    uint32_t ffi_verifyQuote(JsonObj payloadJson, char *respJson);

    /*
     *  @return
     *  [string] json string
     *      {
     *          code: int,
     *          message: string,
     *          result: {
     *              "version" : string,
     *              "git_sha" : string
     *          }
     *      }
     */
    uint32_t ffi_getVersion(char *respJson);

    /**
     * @brief Generate Hmac (SHA-256) with given apikey(encrypted), cmk and payload
     * @param payload : Pass in the cmk, apikey(encrypted) and payload in the form of JSON string
                {
                    cmk : a base64 string,
                    apikey : a base64 string,
                    payload : a base64 string,
                }
     * @return [string] json string
                {
                    code: int,
                    hmac: string,
                }
     */
    uint32_t ffi_generateHmac(JsonObj payloadJson, char *respJson);

    /**
     * @brief Generate Token Hmac (SHA-256) with given cmk and payload.
     *        Only using for BYOK.
     * @param payload : Pass in the cmk, apikey(encrypted) and payload in the form of JSON string
                {
                    sessionkey : a base64 string,
                    importToken : string,
                }
     * @return [string] json string
                {
                    code: int,
                    message: string,
                    result: {
                        hmac: string,
                    }
                }
     */
    uint32_t ffi_generateTokenHmac(JsonObj payloadJson, char *respJson);

    /**
     * @brief Decrypt user's key and store as an external key.
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    padding_mode : int,
                    importToken : a base64 string,
                    key_material : a base64 string,
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {}
        }
     */
    uint32_t ffi_importKeyMaterial(JsonObj payloadJson, char *respJson);

    /**
     * @brief generate RSA keypair, store in external key and return public key.
     *
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    cmk : a base64 string,
                    keyspec : int,
                }
     *
     * @return char*
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                pubkey : a base64 string
                sessionkey : a base64 string,
            }
        }
     */
    uint32_t ffi_getParametersForImport(JsonObj payloadJson, char *respJson);
} // extern "C"

#endif