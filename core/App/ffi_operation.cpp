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
#include <cstring>
#include <uuid/uuid.h>

#include "base64.h"
#include "ffi_operation.h"
#include "serialize.h"
#include "log_utils.h"
#include "datatypes.h"
#include "ehsm_marshal.h"

#include "sample_ra_msg.h"
#include "sgx_dcap_ql_wrapper.h"

#include "ehsm_marshal.h"
#include "auto_version.h"

#include "openssl/rsa.h"
#include "ehsm_provider.h"

using namespace std;
// using namespace EHsmProvider;

extern "C"
{
    static void *import_struct_from_json(JsonObj payloadJson, ehsm_data_type_t type, string key = "")
    {
        switch (type)
        {
        case EH_DATA_T:
        {
            ehsm_data_t *data;
            string data_str = base64_decode(payloadJson.readData_string(key));
            size_t data_size = data_str.size();

            data = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(data_size));
            if (data == NULL)
            {
                return NULL;
            }
            data->datalen = data_size;
            if (data_size > 0)
            {
                memcpy_s(data->data, data_size, (uint8_t *)data_str.data(), data_size);
            }

            return data;
        }
        case EH_KEYBLOB_T:
        {
            ehsm_keyblob_t *cmk;
            string cmk_str = base64_decode(payloadJson.readData_string(key));
            size_t cmk_size = cmk_str.size();
            if (cmk_size == 0)
            {
                return NULL;
            }
            cmk = (ehsm_keyblob_t *)malloc(cmk_size);
            if (cmk == NULL)
            {
                return NULL;
            }
            memcpy_s(cmk, cmk_size, (ehsm_keyblob_t *)cmk_str.data(), cmk_size);

            return cmk;
        }
        case EH_METADATA_T:
        {
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                return NULL;
            }
            cmk->metadata.keyspec = (ehsm_keyspec_t)payloadJson.readData_uint32("keyspec");
            cmk->metadata.digest_mode = (ehsm_digest_mode_t)payloadJson.readData_uint32("digest_mode");
            cmk->metadata.padding_mode = (ehsm_padding_mode_t)payloadJson.readData_uint32("padding_mode");
            cmk->metadata.origin = (ehsm_keyorigin_t)payloadJson.readData_uint32("origin");
            cmk->metadata.purpose = (ehsm_keypurpose_t)payloadJson.readData_uint32("purpose");
            cmk->keybloblen = 0;
            return cmk;
        }
        default:
            return NULL;
        }
    }

    static ehsm_status_t export_struct_to_json(void *data, RetJsonObj &retJsonObj, std::string key)
    {
        if (data == NULL)
        {
            return EH_KEYSPEC_INVALID;
        }

        std::string data_base64;
        size_t data_size = 0;

        if (key == "cmk")
        {
            data_size = APPEND_SIZE_TO_KEYBLOB_T(((ehsm_keyblob_t *)data)->keybloblen);
            data_base64 = base64_encode((uint8_t *)data, data_size);
        }
        else
        {
            data_size = ((ehsm_data_t *)data)->datalen;
            data_base64 = base64_encode((uint8_t *)((ehsm_data_t *)data)->data, data_size);
        }

        if (data_base64.size() > 0)
        {
            retJsonObj.addData_string(key, data_base64);
        }
        
        return EH_OK;
    }
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
    char *ffi_initialize()
    {
        log_i("Service name:\t\teHSM-KMS service %s", EHSM_VERSION);
        log_i("Service built:\t\t%s", EHSM_DATE);
        log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);

        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;

        ret = Initialize();
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        return retJsonObj.toChar();
    }

    /*
    destory the enclave
    */
    char *ffi_finalize()
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;

        ret = Finalize();
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        return retJsonObj.toChar();
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
    char *ffi_createKey(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        string cmk_base64;

        ehsm_keyblob_t *master_key = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_METADATA_T);
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

        ret = export_struct_to_json(master_key, retJsonObj, "cmk");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
    out:
        SAFE_FREE(master_key);
        return retJsonObj.toChar();
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
    char *ffi_encrypt(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;

        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *plain_data = NULL;
        ehsm_data_t *aad_data = NULL;
        ehsm_data_t *cipher_data = NULL;

        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        plain_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "plaintext");
        aad_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "aad");
        cipher_data = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (cmk == NULL || plain_data == NULL || aad_data == NULL || cipher_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        cipher_data->datalen = 0;

        ret = Encrypt(cmk, plain_data, aad_data, cipher_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception1.");
            goto out;
        }

        if (cipher_data->datalen == 0 || cipher_data->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        cipher_data = (ehsm_data_t *)realloc(cipher_data, APPEND_SIZE_TO_DATA_T(cipher_data->datalen));
        if (cipher_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception2.");
            goto out;
        }

        ret = Encrypt(cmk, plain_data, aad_data, cipher_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception3.");
            goto out;
        }

        ret = export_struct_to_json(cipher_data, retJsonObj, "ciphertext");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception4.");
            goto out;
        }

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad_data);
        SAFE_FREE(plain_data);
        SAFE_FREE(cipher_data);
        return retJsonObj.toChar();
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
    char *ffi_decrypt(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *cipher_data = NULL;
        ehsm_data_t *aad_data = NULL;
        ehsm_data_t *plain_data = NULL;

        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        cipher_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "ciphertext");
        aad_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "aad");
        plain_data = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (cmk == NULL || cipher_data == NULL || aad_data == NULL || plain_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception2.");
            goto out;
        }
        plain_data->datalen = 0;

        ret = Decrypt(cmk, cipher_data, aad_data, plain_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception");
            goto out;
        }

        if (plain_data->datalen == 0 || plain_data->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        plain_data = (ehsm_data_t *)realloc(plain_data, plain_data->datalen);
        if (plain_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = Decrypt(cmk, cipher_data, aad_data, plain_data);
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

        ret = export_struct_to_json(plain_data, retJsonObj, "plaintext");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception");
            goto out;
        }
    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad_data);
        SAFE_FREE(plain_data);
        SAFE_FREE(cipher_data);
        return retJsonObj.toChar();
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
    char *ffi_asymmetricEncrypt(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *plain_data = NULL;
        ehsm_data_t *cipher_data = NULL;

        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        plain_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "plaintext");
        cipher_data = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (cmk == NULL || plain_data == NULL || cipher_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        cipher_data->datalen = 0;

        ret = AsymmetricEncrypt(cmk, plain_data, cipher_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (cipher_data->datalen == 0 || cipher_data->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        cipher_data = (ehsm_data_t *)realloc(cipher_data, APPEND_SIZE_TO_DATA_T(cipher_data->datalen));
        if (cipher_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = AsymmetricEncrypt(cmk, plain_data, cipher_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = export_struct_to_json(cipher_data, retJsonObj, "ciphertext");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
    out:
        SAFE_FREE(cmk);
        SAFE_FREE(plain_data);
        SAFE_FREE(cipher_data);
        return retJsonObj.toChar();
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
    char *ffi_asymmetricDecrypt(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *plain_data = NULL;
        ehsm_data_t *cipher_data = NULL;

        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        cipher_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "ciphertext");
        plain_data = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (cmk == NULL || cipher_data == NULL || plain_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plain_data->datalen = 0;

        ret = AsymmetricDecrypt(cmk, cipher_data, plain_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (plain_data->datalen == 0 || plain_data->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        plain_data = (ehsm_data_t *)realloc(plain_data, APPEND_SIZE_TO_DATA_T(plain_data->datalen));
        if (plain_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = AsymmetricDecrypt(cmk, cipher_data, plain_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        ret = export_struct_to_json(plain_data, retJsonObj, "plaintext");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(plain_data);
        SAFE_FREE(cipher_data);
        return retJsonObj.toChar();
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
    char *ffi_generateDataKey(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *aad_data = NULL;
        uint32_t keylen = payloadJson.readData_uint32("keylen");
        ehsm_data_t *plain_datakey = NULL;
        ehsm_data_t *cipher_datakey = NULL;
        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        aad_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "aad");
        plain_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(keylen));
        cipher_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (cmk == NULL || aad_data == NULL || plain_datakey == NULL || cipher_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plain_datakey->datalen = keylen;
        cipher_datakey->datalen = 0;

        ret = GenerateDataKey(cmk, aad_data, plain_datakey, cipher_datakey);
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

        ret = GenerateDataKey(cmk, aad_data, plain_datakey, cipher_datakey);
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

        ret = export_struct_to_json(plain_datakey, retJsonObj, "plaintext");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = export_struct_to_json(cipher_datakey, retJsonObj, "ciphertext");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad_data);
        SAFE_FREE(plain_datakey);
        SAFE_FREE(cipher_datakey);
        return retJsonObj.toChar();
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
    char *ffi_generateDataKeyWithoutPlaintext(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        uint32_t keylen = payloadJson.readData_uint32("keylen");
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *aad_data = NULL;
        ehsm_data_t *plain_datakey = NULL;
        ehsm_data_t *cipher_datakey = NULL;
        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        aad_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "aad");
        plain_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(keylen));
        cipher_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (cmk == NULL || aad_data == NULL || plain_datakey == NULL || cipher_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plain_datakey->datalen = keylen;
        cipher_datakey->datalen = 0;

        ret = GenerateDataKeyWithoutPlaintext(cmk, aad_data, plain_datakey, cipher_datakey);
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

        ret = GenerateDataKeyWithoutPlaintext(cmk, aad_data, plain_datakey, cipher_datakey);
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

        ret = export_struct_to_json(cipher_datakey, retJsonObj, "ciphertext");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad_data);
        SAFE_FREE(plain_datakey);
        SAFE_FREE(cipher_datakey);
        return retJsonObj.toChar();
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
    char *ffi_exportDataKey(JsonObj payloadJson)
    {
        ehsm_status_t ret = EH_OK;
        RetJsonObj retJsonObj;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_keyblob_t *ukey = NULL;
        ehsm_data_t *aad = NULL;
        ehsm_data_t *olddatakey = NULL;
        ehsm_data_t *newdatakey = NULL;
        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        ukey = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "ukey");
        aad = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "aad");
        olddatakey = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "olddatakey");
        newdatakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (cmk == NULL || ukey == NULL || aad == NULL || olddatakey == NULL || newdatakey == NULL)
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

        ret = export_struct_to_json(newdatakey, retJsonObj, "newdatakey");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
    out:
        SAFE_FREE(cmk);
        SAFE_FREE(ukey);
        SAFE_FREE(aad);
        SAFE_FREE(olddatakey);
        SAFE_FREE(newdatakey);
        return retJsonObj.toChar();
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
    char *ffi_sign(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *digest_data = NULL;
        ehsm_data_t *signature_data = NULL;
        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        digest_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "digest");
        signature_data = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
        if (cmk == NULL || digest_data == NULL || signature_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        signature_data->datalen = 0;

        ret = Sign(cmk, digest_data, signature_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (signature_data->datalen == 0 || signature_data->datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        signature_data = (ehsm_data_t *)realloc(signature_data, APPEND_SIZE_TO_DATA_T(signature_data->datalen));
        if (signature_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        // sign
        ret = Sign(cmk, digest_data, signature_data);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ret = export_struct_to_json(signature_data, retJsonObj, "signature");
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(signature_data);
        SAFE_FREE(digest_data);
        return retJsonObj.toChar();
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
    char *ffi_verify(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;
        bool result = false;
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *digest_data = NULL;
        ehsm_data_t *signature_data = NULL;
        cmk = (ehsm_keyblob_t *)import_struct_from_json(payloadJson, EH_KEYBLOB_T, "cmk");
        digest_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "digest");
        signature_data = (ehsm_data_t *)import_struct_from_json(payloadJson, EH_DATA_T, "signature");
        if (cmk == NULL || digest_data == NULL || signature_data == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        // verify sign
        ret = Verify(cmk, digest_data, signature_data, &result);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        retJsonObj.addData_bool("result", result);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(signature_data);
        SAFE_FREE(digest_data);
        return retJsonObj.toChar();
    }

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
    char *ffi_RA_HANDSHAKE_MSG0(const char *p_msg0)
    {
        RetJsonObj retJsonObj;
        //     log_d("***ffi_RA_HANDSHAKE_MSG0 start.");
        //     if (p_msg0 == NULL)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        //         retJsonObj.setMessage("paramter invalid.");
        //         return retJsonObj.toChar();
        //     }
        //     log_d("msg0: \n %s", p_msg0);

        //     ehsm_status_t ret = EH_OK;
        //     sgx_ra_msg1_t *p_msg1;
        //     JsonObj msg0_json;

        //     std::string json_key;

        //     memset(&p_msg1, 0, sizeof(p_msg1));

        //     std::string challenge;
        //     if (p_msg0 != nullptr)
        //     {
        //         std::string response = p_msg0;
        //         msg0_json.parse(response);
        //         challenge = msg0_json.readData_string("challenge");
        //     }
        //     if (challenge.empty())
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        //         retJsonObj.setMessage("paramter invalid.");
        //         goto out;
        //     }

        //     retJsonObj.addData_string("challenge", challenge);

        //     p_msg1 = (sgx_ra_msg1_t *)malloc(sizeof(sgx_ra_msg1_t));
        //     if (p_msg1 == NULL)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_FAILED);
        //         retJsonObj.setMessage("Server exception.");
        //         goto out;
        //     }

        //     ret = ra_get_msg1(p_msg1);
        //     if (ret != EH_OK)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_FAILED);
        //         retJsonObj.setMessage("Server exception.");
        //         goto out;
        //     }

        //     json_key.clear();
        //     json_key = json_key + "g_a" + LAYERED_CHARACTER + "gx";
        //     retJsonObj.addData_uint8Array(json_key, p_msg1->g_a.gx, SGX_ECP256_KEY_SIZE);
        //     json_key.clear();
        //     json_key = json_key + "g_a" + LAYERED_CHARACTER + "gy";
        //     retJsonObj.addData_uint8Array(json_key, p_msg1->g_a.gy, SGX_ECP256_KEY_SIZE);

        // out:
        //     SAFE_FREE(p_msg1);
        //     log_d("msg1: \n%s", retJsonObj.toChar());
        //     log_d("***ffi_RA_HANDSHAKE_MSG0 end.");
        return retJsonObj.toChar();
    }

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
    char *ffi_RA_HANDSHAKE_MSG2(const char *p_msg2)
    {
        RetJsonObj retJsonObj;
        //     log_d("***ffi_RA_HANDSHAKE_MSG2 start.");
        //     if (p_msg2 == NULL)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        //         retJsonObj.setMessage("paramter invalid.");
        //         return retJsonObj.toChar();
        //     }
        //     log_d("msg2: \n %s", p_msg2);

        //     ehsm_status_t ret = EH_OK;
        //     sgx_ra_msg2_t ra_msg2;
        //     std::string msg2_str;
        //     uint32_t msg2_size = 0;

        //     quote3_error_t qe3_ret;
        //     sgx_ra_msg3_t *p_msg3;
        //     uint32_t quote_size = 0;
        //     uint32_t p_msg3_size = 0;

        //     // process msg2
        //     msg2_str = p_msg2;
        //     ret = unmarshal_msg2_from_json(msg2_str, &ra_msg2, &msg2_size);
        //     if (ret != EH_OK)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_FAILED);
        //         retJsonObj.setMessage("Server exception.");
        //         goto out;
        //     }

        //     // build msg3
        //     qe3_ret = sgx_qe_get_quote_size(&quote_size);
        //     if (SGX_QL_SUCCESS != qe3_ret)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_FAILED);
        //         retJsonObj.setMessage("Server exception.");
        //         goto out;
        //     }
        //     p_msg3_size = static_cast<uint32_t>(sizeof(sgx_ra_msg3_t)) + quote_size;
        //     ret = ra_get_msg3(&ra_msg2, msg2_size, &p_msg3, p_msg3_size);
        //     if (ret != EH_OK)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_FAILED);
        //         retJsonObj.setMessage("Server exception.");
        //         goto out;
        //     }

        //     ret = marshal_msg3_to_json(p_msg3, &retJsonObj, quote_size);
        //     if (ret != EH_OK)
        //     {
        //         log_e("ra_proc_msg2 failed(%d).", ret);
        //         goto out;
        //     }

        // out:
        //     SAFE_FREE(p_msg3);
        //     log_d("msg3: \n%s", retJsonObj.toChar());
        //     log_d("***ffi_RA_HANDSHAKE_MSG2 end.");
        return retJsonObj.toChar();
    }

    /*
     *  @param p_att_result_msg : att_result_msg json string
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
    char *ffi_RA_GET_API_KEY(const char *p_att_result_msg)
    {
        RetJsonObj retJsonObj;
        //     log_d("***ffi_RA_GET_API_KEY start.");
        //     if (p_att_result_msg == NULL)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        //         retJsonObj.setMessage("paramter invalid.");
        //         return retJsonObj.toChar();
        //     }
        //     log_d("att_result_msg: \n %s", p_att_result_msg);

        //     ehsm_status_t ret = EH_OK;
        //     sample_ra_att_result_msg_t *pt_att_result_msg;
        //     std::string att_result_msg_str;

        //     char p_appid[UUID_STR_LEN] = {0};
        //     ehsm_data_t p_apikey;
        //     ehsm_data_t cipherapikey;

        //     memset(&pt_att_result_msg, 0, sizeof(pt_att_result_msg));

        //     // process att_result_msg
        //     uint32_t att_result_msg_size = sizeof(sample_ra_att_result_msg_t) + SGX_DOMAIN_KEY_SIZE;
        //     pt_att_result_msg = (sample_ra_att_result_msg_t *)malloc(att_result_msg_size);
        //     if (pt_att_result_msg == NULL)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_FAILED);
        //         retJsonObj.setMessage("Server exception.");
        //         goto OUT;
        //     }

        //     att_result_msg_str = p_att_result_msg;
        //     ret = unmarshal_att_result_msg_from_json(att_result_msg_str, pt_att_result_msg);
        //     if (ret != EH_OK)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_FAILED);
        //         retJsonObj.setMessage("Server exception.");
        //         goto OUT;
        //     }

        //     // Verify att_result_msg
        //     ret = verify_att_result_msg(pt_att_result_msg);
        //     if (ret != EH_OK)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        //         retJsonObj.setMessage("Verify att_result_msg failed.");
        //         goto OUT;
        //     }
        //     log_d("Verify att_result_msg SUCCESS.");

        //     // create appid
        //     uuid_t uu;
        //     uuid_generate(uu);
        //     uuid_unparse(uu, p_appid);

        //     // create apikey
        //     p_apikey.datalen = EH_API_KEY_SIZE;
        //     p_apikey.data = (uint8_t *)calloc(p_apikey.datalen + 1, sizeof(uint8_t));
        //     if (p_apikey.data == NULL)
        //     {
        //         ret = EH_DEVICE_MEMORY;
        //         goto OUT;
        //     }

        //     // create cipherapikey
        //     cipherapikey.datalen = EH_API_KEY_SIZE + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
        //     cipherapikey.data = (uint8_t *)calloc(cipherapikey.datalen, sizeof(uint8_t));
        //     if (cipherapikey.data == NULL)
        //     {
        //         ret = EH_DEVICE_MEMORY;
        //         goto OUT;
        //     }

        //     ret = generate_apikey(&p_apikey, &cipherapikey);
        //     if (ret != EH_OK)
        //     {
        //         retJsonObj.setCode(retJsonObj.CODE_FAILED);
        //         retJsonObj.setMessage("Server exception.");
        //         goto OUT;
        //     }

        //     retJsonObj.addData_uint8Array("nonce", pt_att_result_msg->platform_info_blob.nonce.rand, 16);
        //     retJsonObj.addData_string("appid", p_appid);
        //     retJsonObj.addData_string("apikey", (char *)p_apikey.data);
        //     retJsonObj.addData_uint8Array("cipherapikey", cipherapikey.data, cipherapikey.datalen);

        //     log_d("apikey_result_msg: \n%s", retJsonObj.toChar());
        //     log_d("***ffi_RA_GET_API_KEY end.");

        // OUT:
        //     explicit_bzero(p_apikey.data, p_apikey.datalen);
        //     SAFE_FREE(pt_att_result_msg);
        //     SAFE_FREE(cipherapikey.data);
        return retJsonObj.toChar();
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
    char *ffi_enroll()
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

        apikey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(EH_API_KEY_SIZE + 1));
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
        return retJsonObj.toChar();
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
    char *ffi_generateQuote(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;

        const char *challenge_base64 = payloadJson.readData_cstr("challenge");

        if (challenge_base64 == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("paramter invalid.");
            return retJsonObj.toChar();
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
        SAFE_FREE(quote);
        return retJsonObj.toChar();
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
    char *ffi_verifyQuote(JsonObj payloadJson)
    {
        RetJsonObj retJsonObj;

        const char *quote_base64 = payloadJson.readData_cstr("quote");
        const char *mr_signer = payloadJson.readData_cstr("mr_signer");
        const char *mr_enclave = payloadJson.readData_cstr("mr_enclave");
        const char *nonce_base64 = payloadJson.readData_cstr("nonce");

        if (quote_base64 == NULL || nonce_base64 == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("paramter invalid.");
            return retJsonObj.toChar();
        }

        ehsm_status_t ret = EH_OK;
        sgx_ql_qv_result_t verifyresult;
        bool result = false;
        ehsm_data_t *quote;

        string quote_str = base64_decode(quote_base64);
        int quote_size = quote_str.size();
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

        ret = VerifyQuote(quote, mr_signer, mr_enclave, &verifyresult);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        log_d("VerifyQuote successfuly\n");

        if (verifyresult == SGX_QL_QV_RESULT_OK)
            result = true;

        retJsonObj.addData_bool("result", result);
        retJsonObj.addData_string("nonce", nonce_base64);

    out:
        return retJsonObj.toChar();
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
    char *ffi_getVersion()
    {
        RetJsonObj retJsonObj;
        retJsonObj.addData_string("version", EHSM_VERSION);
        retJsonObj.addData_string("git_sha", EHSM_GIT_SHA);
        return retJsonObj.toChar();
    }

} // extern "C"
