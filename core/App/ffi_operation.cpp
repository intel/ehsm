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
#include <uuid/uuid.h>
#include <typeinfo>
#include <string.h>

#include "auto_version.h"

#include "base64.h"
#include "ffi_operation.h"
#include "ehsm_provider.h"
#include "ulog_utils.h"

#include "sgx_qve_header.h"

using namespace std;

#define JSON2STRUCT(x, y) import_struct_from_json(x, &y, #y)
#define STRUCT2JSON(x, y) export_json_from_struct(x, y, #y)
#define RUN_MODE_SINGLE "single"
#define RUN_MODE_CLUSTER "cluster"

template <typename T>
void import_struct_from_json(JsonObj payloadJson, T **out, string key)
{
    if (key.empty())
        return;

    if (typeid(**out) == typeid(ehsm_data_t))
    {
        string data_str = base64_decode(payloadJson.readData_string(key));
        size_t data_size = data_str.size();

        ehsm_data_t *out_data = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(data_size));
        if (out_data == NULL)
            return;
        out_data->datalen = data_size;
        memcpy_s(out_data->data, data_size, (uint8_t *)data_str.data(), data_size);

        *out = (T *)malloc(APPEND_SIZE_TO_DATA_T(data_size));
        if (*out == NULL)
        {
            explicit_bzero(out_data, APPEND_SIZE_TO_DATA_T(data_size));
            return;
        }
        memcpy_s(*out, APPEND_SIZE_TO_DATA_T(data_size), out_data, APPEND_SIZE_TO_DATA_T(data_size));

        explicit_bzero(out_data, APPEND_SIZE_TO_DATA_T(data_size));
        free(out_data);
    }
    else if (typeid(**out) == typeid(ehsm_keyblob_t))
    {
        string cmk_str = base64_decode(payloadJson.readData_string(key));
        size_t cmk_size = cmk_str.size();

        *out = (T *)malloc(cmk_size);
        if (*out == NULL)
            return;

        memcpy_s(*out, cmk_size, (ehsm_keyblob_t *)cmk_str.data(), cmk_size);
    }
    else if (typeid(**out) == typeid(ehsm_keymetadata_t))
    {
        ehsm_keymetadata_t *out_data = (ehsm_keymetadata_t *)malloc(sizeof(ehsm_keymetadata_t));
        if (out_data == NULL)
            return;
        out_data->keyspec = (ehsm_keyspec_t)payloadJson.readData_uint32("keyspec");
        out_data->digest_mode = (ehsm_digest_mode_t)payloadJson.readData_uint32("digest_mode");
        out_data->padding_mode = (ehsm_padding_mode_t)payloadJson.readData_uint32("padding_mode");
        out_data->origin = (ehsm_keyorigin_t)payloadJson.readData_uint32("origin");
        out_data->purpose = (ehsm_keypurpose_t)payloadJson.readData_uint32("purpose");

        *out = (T *)malloc(sizeof(ehsm_keymetadata_t));
        if (*out == NULL)
        {
            explicit_bzero(out_data, sizeof(ehsm_keymetadata_t));
            return;
        }
        memcpy_s(*out, sizeof(ehsm_keymetadata_t), out_data, sizeof(ehsm_keymetadata_t));

        explicit_bzero(out_data, sizeof(ehsm_keymetadata_t));
        free(out_data);
    }
    else
    {
        log_e("no such item:%s\n", key.c_str());
        return;
    }
}

template <typename T>
void export_json_from_struct(RetJsonObj &retJsonObj, T *in, string key)
{
    if (key.empty() || in == NULL)
    {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        return;
    }

    string data_base64;
    size_t data_size = 0;

    if (typeid(*in) == typeid(ehsm_keyblob_t))
    {
        data_size = APPEND_SIZE_TO_KEYBLOB_T(((ehsm_keyblob_t *)in)->keybloblen);
        data_base64 = base64_encode((uint8_t *)in, data_size);
    }
    else if (typeid(*in) == typeid(ehsm_data_t))
    {
        data_size = ((ehsm_data_t *)in)->datalen;
        data_base64 = base64_encode((uint8_t *)((ehsm_data_t *)in)->data, data_size);
    }
    else
    {
        log_e("export item:%s failed\n", key.c_str());
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        return;
    }

    if (data_base64.size() > 0)
        retJsonObj.addData_string(key, data_base64);
}

extern "C"
{
    /*
     * create the enclave
     * @param payload : Pass in the key parameter in the form of JSON string
                {
                    run_mode : string
                }
     * @return
     * [string] json string
        {
            code: int,
            message: string,
            result: {}
        }
    */
    uint32_t ffi_initialize(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        bool run_on_cluter = true;

        ehsm_data_t *run_mode = NULL;
        JSON2STRUCT(payloadJson, run_mode);

        if (run_mode != NULL)
        {
            // std::string run_mode_str;
            // memcpy_s(&run_mode_str, run_mode->datalen, run_mode->data, run_mode->datalen);
            if (strncmp((char *)run_mode->data, RUN_MODE_SINGLE, run_mode->datalen) == 0)
            {
                run_on_cluter = false;
            }
            else if (strncmp((char *)run_mode->data, RUN_MODE_CLUSTER, run_mode->datalen) == 0)
            {
                run_on_cluter = true;
            }
            else
            {
                retJsonObj.setCode(retJsonObj.CODE_FAILED);
                retJsonObj.setMessage("The run mode error, it must be single or cluster.");
                retJsonObj.toChar(respJson);
                return ret;
            }
        }

        ret = Initialize(run_on_cluter);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        retJsonObj.toChar(respJson);
        return ret;
    }

    /*
    destory the enclave
    */
    uint32_t ffi_finalize(char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;

        ret = Finalize();
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_createKey(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        string cmk_base64;

        ehsm_keymetadata_t *key_metadata = NULL;
        ehsm_keyblob_t *master_key = NULL;
        JSON2STRUCT(payloadJson, key_metadata);

        if (key_metadata == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        master_key = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
        if (master_key == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        master_key->keybloblen = 0;
        memcpy(&master_key->metadata, key_metadata, sizeof(ehsm_keymetadata_t));

        ret = CreateKey(master_key);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (master_key->keybloblen == 0 || master_key->keybloblen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        master_key = (ehsm_keyblob_t *)realloc(master_key, APPEND_SIZE_TO_KEYBLOB_T(master_key->keybloblen));
        if (master_key == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = CreateKey(master_key);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        export_json_from_struct(retJsonObj, master_key, "cmk");
    out:
        SAFE_FREE(key_metadata); 
        SAFE_FREE(master_key);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_encrypt(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;

        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *plaintext = NULL;
        ehsm_data_t *aad = NULL;
        ehsm_data_t *ciphertext = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, plaintext);
        JSON2STRUCT(payloadJson, aad);

        if (cmk == NULL || plaintext == NULL || aad == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        ciphertext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (ciphertext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        ciphertext->datalen = 0;

        ret = Encrypt(cmk, plaintext, aad, ciphertext);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (ciphertext->datalen == 0 || ciphertext->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ciphertext = (ehsm_data_t *)realloc(ciphertext, APPEND_SIZE_TO_DATA_T(ciphertext->datalen));
        if (ciphertext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = Encrypt(cmk, plaintext, aad, ciphertext);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        STRUCT2JSON(retJsonObj, ciphertext);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad);
        SAFE_FREE(plaintext);
        SAFE_FREE(ciphertext);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_decrypt(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *ciphertext = NULL;
        ehsm_data_t *aad = NULL;
        ehsm_data_t *plaintext = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, ciphertext);
        JSON2STRUCT(payloadJson, aad);

        if (cmk == NULL || ciphertext == NULL || aad == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (plaintext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plaintext->datalen = 0;

        ret = Decrypt(cmk, ciphertext, aad, plaintext);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception");
            goto out;
        }

        if (plaintext->datalen == 0 || plaintext->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        plaintext = (ehsm_data_t *)realloc(plaintext, plaintext->datalen);
        if (plaintext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = Decrypt(cmk, ciphertext, aad, plaintext);
        if (ret != EH_OK)
        {
            if (ret == EH_FUNCTION_FAILED)
            {
                retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
                retJsonObj.setMessage("Decryption failed, Please confirm that your parameters are correct.");
            }
            else
            {
                retJsonObj.setCode(retJsonObj.CODE_FAILED);
                retJsonObj.setMessage("Server exception.");
            }
            goto out;
        }

        STRUCT2JSON(retJsonObj, plaintext);
       
    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad);
        SAFE_FREE(plaintext);
        SAFE_FREE(ciphertext);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_asymmetricEncrypt(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *plaintext = NULL;
        ehsm_data_t *ciphertext = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, plaintext);

        if (cmk == NULL || plaintext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        ciphertext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (ciphertext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        ciphertext->datalen = 0;

        ret = AsymmetricEncrypt(cmk, plaintext, ciphertext);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (ciphertext->datalen == 0 || ciphertext->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ciphertext = (ehsm_data_t *)realloc(ciphertext, APPEND_SIZE_TO_DATA_T(ciphertext->datalen));
        if (ciphertext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = AsymmetricEncrypt(cmk, plaintext, ciphertext);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        STRUCT2JSON(retJsonObj, ciphertext);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(plaintext);
        SAFE_FREE(ciphertext);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_asymmetricDecrypt(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *plaintext = NULL;
        ehsm_data_t *ciphertext = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, ciphertext);

        if (cmk == NULL || ciphertext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (plaintext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plaintext->datalen = 0;

        ret = AsymmetricDecrypt(cmk, ciphertext, plaintext);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (plaintext->datalen == 0 || plaintext->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        plaintext = (ehsm_data_t *)realloc(plaintext, APPEND_SIZE_TO_DATA_T(plaintext->datalen));
        if (plaintext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = AsymmetricDecrypt(cmk, ciphertext, plaintext);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        STRUCT2JSON(retJsonObj, plaintext);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(plaintext);
        SAFE_FREE(ciphertext);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_generateDataKey(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *aad = NULL;
        uint32_t keylen = payloadJson.readData_uint32("keylen");
        ehsm_data_t *plain_datakey = NULL;
        ehsm_data_t *cipher_datakey = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, aad);

        if (cmk == NULL || aad == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        plain_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(keylen));
        cipher_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (plain_datakey == NULL || cipher_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plain_datakey->datalen = keylen;
        cipher_datakey->datalen = 0;

        ret = GenerateDataKey(cmk, aad, plain_datakey, cipher_datakey);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (cipher_datakey->datalen == 0 || cipher_datakey->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        cipher_datakey = (ehsm_data_t *)realloc(cipher_datakey, APPEND_SIZE_TO_DATA_T(cipher_datakey->datalen));
        if (cipher_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = GenerateDataKey(cmk, aad, plain_datakey, cipher_datakey);
        if (ret != EH_OK)
        {
            if (ret == EH_ARGUMENTS_BAD)
            {
                retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
                retJsonObj.setMessage("Failed, Please confirm that your parameters are correct.");
            }
            else
            {
                retJsonObj.setCode(retJsonObj.CODE_FAILED);
                retJsonObj.setMessage("Server exception.");
            }
            goto out;
        }

        export_json_from_struct(retJsonObj, plain_datakey, "plaintext");
        export_json_from_struct(retJsonObj, cipher_datakey, "ciphertext");

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad);
        SAFE_FREE(plain_datakey);
        SAFE_FREE(cipher_datakey);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_generateDataKeyWithoutPlaintext(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        uint32_t keylen = payloadJson.readData_uint32("keylen");
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *aad = NULL;
        ehsm_data_t *plain_datakey = NULL;
        ehsm_data_t *cipher_datakey = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, aad);

        if (cmk == NULL || aad == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        plain_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(keylen));
        cipher_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (plain_datakey == NULL || cipher_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plain_datakey->datalen = keylen;
        cipher_datakey->datalen = 0;

        ret = GenerateDataKeyWithoutPlaintext(cmk, aad, plain_datakey, cipher_datakey);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (cipher_datakey->datalen == 0 || cipher_datakey->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        cipher_datakey = (ehsm_data_t *)realloc(cipher_datakey, APPEND_SIZE_TO_DATA_T(cipher_datakey->datalen));
        if (cipher_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = GenerateDataKeyWithoutPlaintext(cmk, aad, plain_datakey, cipher_datakey);
        if (ret != EH_OK)
        {
            if (ret == EH_ARGUMENTS_BAD)
            {
                retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
                retJsonObj.setMessage("Failed, Please confirm that your parameters are correct.");
            }
            else
            {
                retJsonObj.setCode(retJsonObj.CODE_FAILED);
                retJsonObj.setMessage("Server exception.");
            }
            goto out;
        }

        export_json_from_struct(retJsonObj, cipher_datakey, "ciphertext");

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad);
        SAFE_FREE(plain_datakey);
        SAFE_FREE(cipher_datakey);
        retJsonObj.toChar(respJson);
        return ret;
    }

    /**
     * @brief pass in a key to decrypt the data key then wrap it up using user key
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
    uint32_t ffi_exportDataKey(JsonObj payloadJson, char *respJson)
    {
        ehsm_status_t ret = EH_OK;
        RetJsonObj retJsonObj;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_keyblob_t *ukey = NULL;
        ehsm_data_t *aad = NULL;
        ehsm_data_t *olddatakey = NULL;
        ehsm_data_t *newdatakey = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, ukey);
        JSON2STRUCT(payloadJson, aad);
        JSON2STRUCT(payloadJson, olddatakey);

        if (cmk == NULL || ukey == NULL || aad == NULL || olddatakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        newdatakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (newdatakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        newdatakey->datalen = 0;

        ret = ExportDataKey(cmk, ukey, aad, olddatakey, newdatakey);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            if (ret == EH_ARGUMENTS_BAD)
            {
                retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
                retJsonObj.setMessage("Failed, Please confirm that your parameters are correct.");
            }
            else if (ret == EH_KEYSPEC_INVALID)
            {
                retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
                retJsonObj.setMessage("key invalid.");
            }
            else
            {
                retJsonObj.setCode(retJsonObj.CODE_FAILED);
                retJsonObj.setMessage("Server exception.");
            }
            goto out;
        }

        if (newdatakey->datalen == 0 || newdatakey->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        newdatakey = (ehsm_data_t *)realloc(newdatakey, APPEND_SIZE_TO_DATA_T(newdatakey->datalen));
        if (newdatakey == NULL)
        {
            ret = EH_DEVICE_MEMORY;
            goto out;
        }

        if (newdatakey->datalen == 0)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("Failed datakeylen unavailable.");
        }

        ret = ExportDataKey(cmk, ukey, aad, olddatakey, newdatakey);
        if (ret != EH_OK)
        {
            if (ret == EH_ARGUMENTS_BAD)
            {
                retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
                retJsonObj.setMessage("Failed, Please confirm that your parameters are correct.");
            }
            else if (ret == EH_KEYSPEC_INVALID)
            {
                retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
                retJsonObj.setMessage("key invalid.");
            }
            else
            {
                retJsonObj.setCode(retJsonObj.CODE_FAILED);
                retJsonObj.setMessage("Server exception.");
            }
            goto out;
        }

        STRUCT2JSON(retJsonObj, newdatakey);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(ukey);
        SAFE_FREE(aad);
        SAFE_FREE(olddatakey);
        SAFE_FREE(newdatakey);
        retJsonObj.toChar(respJson);
        return ret;
    }

    /**
     * @brief create key sign with rsa/ec/sm2
     *
     * @param payload Pass in the key parameter in the form of JSON string
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                cmk : string,
                digest : string
            }
        }
    *
     *
    *
    * @return char*
    * [string] json string
        {
            code: int,
            message: string,
            result: {
                signature_base64 : string
            }
        }
    */
    uint32_t ffi_sign(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *digest = NULL;
        ehsm_data_t *signature = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, digest);

        if (cmk == NULL || digest == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        signature = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (signature == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        signature->datalen = 0;

        ret = Sign(cmk, digest, signature);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (signature->datalen == 0 || signature->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        signature = (ehsm_data_t *)realloc(signature, APPEND_SIZE_TO_DATA_T(signature->datalen));
        if (signature == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        // sign
        ret = Sign(cmk, digest, signature);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        STRUCT2JSON(retJsonObj, signature);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(signature);
        SAFE_FREE(digest);
        retJsonObj.toChar(respJson);
        return ret;
    }

    /**
     * @brief verify key sign
     *
     * @param payload Pass in the key parameter in the form of JSON string
     * [string] json string
        {
            code: int,
            message: string,
            result: {
                cmk : string,
                digest : string,
                signature ： string
            }
        }
    *
     *
    *
    * @return char*
    * [string] json string
        {
            code: int,
            message: string,
            result: {
                result : bool,
            }
        }
    */
    uint32_t ffi_verify(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        bool result = false;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *digest = NULL;
        ehsm_data_t *signature = NULL;

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, digest);
        JSON2STRUCT(payloadJson, signature);

        if (cmk == NULL || digest == NULL || signature == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }
        // verify sign
        ret = Verify(cmk, digest, signature, &result);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        retJsonObj.addData_bool("result", result);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(signature);
        SAFE_FREE(digest);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_enroll(char *respJson)
    {
        RetJsonObj retJsonObj;
        log_d("%s start.", __func__);

        ehsm_status_t ret = EH_OK;

        ehsm_data_t *apikey = NULL;
        ehsm_data_t *appid = NULL;

        appid = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(UUID_STR_LEN));
        if (appid == NULL)
        {
            ret = EH_DEVICE_MEMORY;
            goto OUT;
        }
        appid->datalen = UUID_STR_LEN;

        apikey = (ehsm_data_t *)calloc(APPEND_SIZE_TO_DATA_T(EH_API_KEY_SIZE + 1), sizeof(uint8_t));
        if (apikey == NULL)
        {
            ret = EH_DEVICE_MEMORY;
            goto OUT;
        }
        apikey->datalen = EH_API_KEY_SIZE;

        ret = Enroll(appid, apikey);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto OUT;
        }

        retJsonObj.addData_string("appid", (char *)appid->data);
        retJsonObj.addData_string("apikey", (char *)apikey->data);

        log_d("%s end.", __func__);

    OUT:
        SAFE_FREE(apikey);
        SAFE_FREE(appid);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_generateQuote(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;

        char *challenge_base64 = payloadJson.readData_cstr("challenge");

        if (challenge_base64 == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("paramter invalid.");
            retJsonObj.toChar(respJson);
            return EH_ARGUMENTS_BAD;
        }
        log_d("challenge: \n %s", challenge_base64);

        ehsm_status_t ret = EH_OK;
        ehsm_data_t *quote;
        string quote_base64;

        quote = (ehsm_data_t *)malloc(sizeof(ehsm_data_t));
        if (quote == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("The cmk's length is invalid.");
            goto out;
        }

        quote->datalen = 0;
        ret = GenerateQuote(quote);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        log_d("get the quote size successfuly\n");

        if (quote->datalen == 0 || quote->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        quote = (ehsm_data_t *)realloc(quote, APPEND_SIZE_TO_DATA_T(quote->datalen));
        if (quote == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = GenerateQuote(quote);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        log_d("GenerateQuote successfuly\n");

        quote_base64 = base64_encode(quote->data, quote->datalen);
        if (quote_base64.size() <= 0)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        retJsonObj.addData_string("challenge", challenge_base64);
        retJsonObj.addData_string("quote", quote_base64);

    out:
        SAFE_FREE(challenge_base64);
        SAFE_FREE(quote);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_verifyQuote(JsonObj payloadJson, char *respJson)
    {
        ehsm_status_t ret = EH_OK;
        int result = SGX_QL_QV_RESULT_UNSPECIFIED;
        ehsm_data_t *quote = NULL;
        string quote_str;
        int quote_size = 0;
        RetJsonObj retJsonObj;

        char *quote_base64 = payloadJson.readData_cstr("quote");
        char *mr_signer = payloadJson.readData_cstr("mr_signer");
        char *mr_enclave = payloadJson.readData_cstr("mr_enclave");
        char *nonce_base64 = payloadJson.readData_cstr("nonce");

        if (quote_base64 == NULL || nonce_base64 == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("paramter invalid.");
            goto out;
        }

        quote_str = base64_decode(quote_base64);
        quote_size = quote_str.size();
        if (quote_size == 0 || quote_size > EH_QUOTE_MAX_SIZE)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("The quote's length is invalid.");
            goto out;
        }
        quote = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(quote_size));
        if (quote == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("The cmk's length is invalid.");
            goto out;
        }
        quote->datalen = quote_size;
        memcpy_s(quote->data, quote_size, (uint8_t *)quote_str.data(), quote_size);

        ret = VerifyQuote(quote, mr_signer, mr_enclave, &result);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        log_d("VerifyQuote successfuly\n");

        retJsonObj.addData_uint32("result", result);
        retJsonObj.addData_string("nonce", nonce_base64);

    out:
        SAFE_FREE(quote_base64);
        SAFE_FREE(mr_signer);
        SAFE_FREE(mr_enclave);
        SAFE_FREE(nonce_base64);
        SAFE_FREE(quote);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_getVersion(char *respJson)
    {
        RetJsonObj retJsonObj;
        retJsonObj.addData_string("version", EHSM_VERSION);
        retJsonObj.addData_string("git_sha", EHSM_GIT_SHA);
        retJsonObj.toChar(respJson);
        return EH_OK;
    }

} // extern "C"
