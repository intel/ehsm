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
        if (*out != NULL)
            memcpy_s(*out, APPEND_SIZE_TO_DATA_T(data_size), out_data, APPEND_SIZE_TO_DATA_T(data_size));

        explicit_bzero(out_data, APPEND_SIZE_TO_DATA_T(data_size));
        free(out_data);
    }
    else if (typeid(**out) == typeid(ehsm_keyblob_t))
    {
        string cmk_str = base64_decode(payloadJson.readData_string(key));
        size_t cmk_size = cmk_str.size();

        *out = (T *)malloc(cmk_size);
        if (*out != NULL)
            memcpy_s(*out, cmk_size, (ehsm_keyblob_t *)cmk_str.data(), cmk_size);
    }
    else if (typeid(**out) == typeid(ehsm_keymetadata_t))
    {
        ehsm_keymetadata_t *out_data = (ehsm_keymetadata_t *)malloc(sizeof(ehsm_keymetadata_t));
        if (out_data == NULL)
            return;
        try
        {
            out_data->keyspec = (ehsm_keyspec_t)payloadJson.readData_uint32("keyspec");
            out_data->origin = (ehsm_keyorigin_t)payloadJson.readData_uint32("origin");
            out_data->keyusage = (ehsm_keyusage_t)payloadJson.readData_uint32("keyusage");
        }
        catch (const Json::LogicError &e)
        {
            log_e("convert to ehsm_keymetadata_t failed: %s\n", e.what());
            goto cleanup;
        }

        *out = (T *)malloc(sizeof(ehsm_keymetadata_t));
        if (*out != NULL)
            memcpy_s(*out, sizeof(ehsm_keymetadata_t), out_data, sizeof(ehsm_keymetadata_t));
    cleanup:
        explicit_bzero(out_data, sizeof(ehsm_keymetadata_t));
        free(out_data);
    }
    else
    {
        log_e("no such item:%s\n", key.c_str());
    }

    return;
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
        ehsm_keyblob_t master_key_tmp;
        memset(&master_key_tmp, 0, sizeof(master_key_tmp));
        JSON2STRUCT(payloadJson, key_metadata);

        if (key_metadata == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        memcpy_s(&master_key_tmp.metadata, sizeof(ehsm_keymetadata_t), key_metadata, sizeof(ehsm_keymetadata_t));

        ret = CreateKey(&master_key_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        // When creating an external key, the keybloblen of the key is 0.
        if ((master_key_tmp.keybloblen == 0 && master_key_tmp.metadata.origin != EH_EXTERNAL_KEY) || master_key_tmp.keybloblen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        master_key = (ehsm_keyblob_t *)malloc(APPEND_SIZE_TO_KEYBLOB_T(master_key_tmp.keybloblen));
        if (master_key == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        master_key->keybloblen = master_key_tmp.keybloblen;
        master_key->metadata = master_key_tmp.metadata;

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
                ciphertext : a base64 string
            }
        }
     */
    uint32_t ffi_getPublicKey(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        ehsm_status_t ret = EH_OK;

        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *pubkey = NULL;
        ehsm_data_t pubkey_tmp = {0};
        char *publicKey = NULL;

        JSON2STRUCT(payloadJson, cmk);

        if (cmk == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        ret = GetPublicKey(cmk, &pubkey_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (pubkey_tmp.datalen == 0 || pubkey_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        pubkey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(pubkey_tmp.datalen));
        if (pubkey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        pubkey->datalen = pubkey_tmp.datalen;

        ret = GetPublicKey(cmk, pubkey);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        publicKey = (char *)malloc(pubkey->datalen);
        memcpy_s(publicKey, pubkey->datalen, pubkey->data, pubkey->datalen);
        publicKey[pubkey->datalen] = '\0';
        retJsonObj.addData_string("pubkey", publicKey);

    out:
        SAFE_FREE(publicKey);
        SAFE_FREE(cmk);
        SAFE_FREE(pubkey);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
            result: {
                cmk : a base64 string
            }
        }
     */
    uint32_t ffi_importKeyMaterial(JsonObj payloadJson, char *respJson)
    {
        RetJsonObj retJsonObj;
        JsonObj tokenJsonObj;

        ehsm_keyblob_t *cmk = NULL;
        ehsm_status_t ret = EH_OK;
        ehsm_data_t *key_material = NULL;

        JSON2STRUCT(payloadJson, cmk);

        string key_material_str_base64 = payloadJson.readData_string("key_material");
        string key_material_str = base64_decode(key_material_str_base64);

        key_material = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(key_material_str.length()));
        key_material->datalen = key_material_str.length();
        memcpy_s(key_material->data, key_material->datalen, key_material_str.c_str(), key_material->datalen);

        ehsm_padding_mode_t padding_mode = (ehsm_padding_mode_t)payloadJson.readData_uint32("padding_mode");

        ret = ImportKeyMaterial(cmk, padding_mode, key_material);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Import key failed.");
            goto out;
        }

        STRUCT2JSON(retJsonObj, cmk);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(key_material);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
                pubkey : a base64 string，
                sessionkey : a base64 string,
            }
        }
     */
    uint32_t ffi_getParametersForImport(JsonObj payloadJson, char *respJson)
    {
        ehsm_status_t ret = EH_OK;
        ehsm_keyblob_t *cmk = NULL;
        
        ehsm_keyblob_t cmk_tmp;
        ehsm_data_t *pubkey = NULL;
        ehsm_data_t pubkey_tmp = {0};

        char *publicKey = NULL;
        ehsm_keyblob_t *sessionkey = NULL;
        RetJsonObj retJsonObj;

        memset(&cmk_tmp, 0, sizeof(cmk_tmp));

        JSON2STRUCT(payloadJson, cmk);

        ehsm_keyspec_t keyspec = (ehsm_keyspec_t)payloadJson.readData_uint32("keyspec");

        memcpy_s(&cmk_tmp, sizeof(ehsm_keyblob_t), cmk, sizeof(ehsm_keyblob_t));

        ret = GetParametersForImport(&cmk_tmp, keyspec, &pubkey_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (pubkey_tmp.datalen == 0 || pubkey_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        cmk = (ehsm_keyblob_t *)malloc(APPEND_SIZE_TO_KEYBLOB_T(cmk_tmp.keybloblen));
        if (cmk == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        pubkey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(pubkey_tmp.datalen));
        if (pubkey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        pubkey->datalen = pubkey_tmp.datalen;
        cmk->keybloblen = cmk_tmp.keybloblen;
        cmk->metadata = cmk_tmp.metadata;

        ret = GetParametersForImport(cmk, keyspec, pubkey);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        publicKey = (char *)malloc(pubkey->datalen);
        memcpy_s(publicKey, pubkey->datalen, pubkey->data, pubkey->datalen);
        publicKey[pubkey->datalen] = '\0';
        retJsonObj.addData_string("pubkey", publicKey);

        // generate a 32B cmk for hmac sign.
        sessionkey = (ehsm_keyblob_t *)malloc(APPEND_SIZE_TO_KEYBLOB_T(EH_AES_GCM_256_SIZE));

        sessionkey->metadata.keyspec = EH_AES_GCM_256;
        sessionkey->metadata.origin = EH_INTERNAL_KEY;
        sessionkey->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
        sessionkey->keybloblen = EH_AES_GCM_256_SIZE;
        ret = CreateKey(sessionkey);

        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        STRUCT2JSON(retJsonObj, sessionkey);
        STRUCT2JSON(retJsonObj, cmk);

    out:
        SAFE_FREE(publicKey);
        SAFE_FREE(cmk);
        SAFE_FREE(pubkey);
        SAFE_FREE(sessionkey);
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
        ehsm_data_t ciphertext_tmp = {0};

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, plaintext);
        JSON2STRUCT(payloadJson, aad);

        if (cmk == NULL || plaintext == NULL || aad == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        ret = Encrypt(cmk, plaintext, aad, &ciphertext_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (ciphertext_tmp.datalen == 0 || ciphertext_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ciphertext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(ciphertext_tmp.datalen));
        if (ciphertext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        ciphertext->datalen = ciphertext_tmp.datalen;

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
        ehsm_data_t plaintext_tmp = {0};

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, ciphertext);
        JSON2STRUCT(payloadJson, aad);

        if (cmk == NULL || ciphertext == NULL || aad == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        ret = Decrypt(cmk, ciphertext, aad, &plaintext_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception");
            goto out;
        }

        if (plaintext_tmp.datalen == 0 || plaintext_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_tmp.datalen));
        if (plaintext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plaintext->datalen = plaintext_tmp.datalen;

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
        ehsm_data_t ciphertext_tmp = {0};

        ehsm_padding_mode_t padding_mode = (ehsm_padding_mode_t)payloadJson.readData_uint32("padding_mode");

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, plaintext);

        if (cmk == NULL || plaintext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        ret = AsymmetricEncrypt(cmk, padding_mode, plaintext, &ciphertext_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (ciphertext_tmp.datalen == 0 || ciphertext_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        ciphertext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(ciphertext_tmp.datalen));
        if (ciphertext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        ciphertext->datalen = ciphertext_tmp.datalen;

        ret = AsymmetricEncrypt(cmk, padding_mode, plaintext, ciphertext);
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
        ehsm_data_t plaintext_tmp = {0};

        ehsm_padding_mode_t padding_mode = (ehsm_padding_mode_t)payloadJson.readData_uint32("padding_mode");

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, ciphertext);

        if (cmk == NULL || ciphertext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        ret = AsymmetricDecrypt(cmk, padding_mode, ciphertext, &plaintext_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (plaintext_tmp.datalen == 0 || plaintext_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_tmp.datalen));
        if (plaintext == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plaintext->datalen = plaintext_tmp.datalen;

        ret = AsymmetricDecrypt(cmk, padding_mode, ciphertext, plaintext);
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
        ehsm_data_t cipher_datakey_tmp = {0};

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, aad);

        if (cmk == NULL || aad == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        plain_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(keylen));
        if (plain_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plain_datakey->datalen = keylen;

        ret = GenerateDataKey(cmk, aad, plain_datakey, &cipher_datakey_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (cipher_datakey_tmp.datalen == 0 || cipher_datakey_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        cipher_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(cipher_datakey_tmp.datalen));
        if (cipher_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        cipher_datakey->datalen = cipher_datakey_tmp.datalen;

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
        ehsm_data_t cipher_datakey_tmp = {0};

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, aad);

        if (cmk == NULL || aad == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        plain_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(keylen));
        if (plain_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        plain_datakey->datalen = keylen;

        ret = GenerateDataKeyWithoutPlaintext(cmk, aad, plain_datakey, &cipher_datakey_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (cipher_datakey_tmp.datalen == 0 || cipher_datakey_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        cipher_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(cipher_datakey_tmp.datalen));
        if (cipher_datakey == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        cipher_datakey->datalen = cipher_datakey_tmp.datalen;

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
        ehsm_data_t newdatakey_tmp = {0};

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

        ret = ExportDataKey(cmk, ukey, aad, olddatakey, &newdatakey_tmp);
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

        if (newdatakey_tmp.datalen == 0 || newdatakey_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        newdatakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(newdatakey_tmp.datalen));
        if (newdatakey == NULL)
        {
            ret = EH_DEVICE_MEMORY;
            goto out;
        }
        newdatakey->datalen = newdatakey_tmp.datalen;

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
        ehsm_data_t *message = NULL;
        ehsm_data_t *signature = NULL;
        ehsm_data_t signature_tmp = {0};

        ehsm_digest_mode_t digest_mode = (ehsm_digest_mode_t)payloadJson.readData_uint32("digest_mode");
        ehsm_padding_mode_t padding_mode = (ehsm_padding_mode_t)payloadJson.readData_uint32("padding_mode");
        ehsm_message_type_t message_type = (ehsm_message_type_t)payloadJson.readData_uint32("message_type");

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, message);

        if (cmk == NULL || message == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }

        ret = Sign(cmk, digest_mode, padding_mode, message_type, message, &signature_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        if (signature_tmp.datalen == 0 || signature_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        signature = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(signature_tmp.datalen));
        if (signature == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        signature->datalen = signature_tmp.datalen;

        // sign
        ret = Sign(cmk, digest_mode, padding_mode, message_type, message, signature);
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
        SAFE_FREE(message);
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
        ehsm_data_t *message = NULL;
        ehsm_data_t *signature = NULL;

        ehsm_digest_mode_t digest_mode = (ehsm_digest_mode_t)payloadJson.readData_uint32("digest_mode");
        ehsm_padding_mode_t padding_mode = (ehsm_padding_mode_t)payloadJson.readData_uint32("padding_mode");
        ehsm_message_type_t message_type = (ehsm_message_type_t)payloadJson.readData_uint32("message_type");

        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, message);
        JSON2STRUCT(payloadJson, signature);

        if (cmk == NULL || message == NULL || signature == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Invalid Parameter.");
            goto out;
        }
        // verify sign
        ret = Verify(cmk, digest_mode, padding_mode, message_type, message, signature, &result);
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
        SAFE_FREE(message);
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
        ehsm_data_t *quote = NULL;
        ehsm_data_t quote_tmp = {0};
        string quote_base64;

        ret = GenerateQuote(&quote_tmp);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        log_d("get the quote size successfuly\n");

        if (quote_tmp.datalen == 0 || quote_tmp.datalen > UINT16_MAX)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        quote = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(quote_tmp.datalen));
        if (quote == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        quote->datalen = quote_tmp.datalen;

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

    /**
     * @brief Generate Hmac (SHA-256) with given apikey(encrypted), cmk and payload
     * @param payload : Pass in the cmk, apikey(encrypted) and payload in the form of JSON string
                {
                    cmk : a base64 string,
                    apikey: a base64 string
                    payload : a base64 string,
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
    uint32_t ffi_generateHmac(JsonObj payloadJson, char *respJson)
    {
        ehsm_status_t ret;
        // input params
        ehsm_keyblob_t *cmk = NULL;
        ehsm_data_t *apikey = NULL;
        ehsm_data_t *payload = NULL;
        // immediate vars
        size_t payload_size;
        std::string payload_str;
        // output params
        ehsm_data_t *hmac = NULL;
        std::string hmac_str;
        RetJsonObj retJsonObj;

        // 0. prepare data
        JSON2STRUCT(payloadJson, cmk);
        JSON2STRUCT(payloadJson, apikey);
        JSON2STRUCT(payloadJson, payload);

        if (cmk == NULL || apikey == NULL || payload == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("paramter invalid.");
            goto out;
        }

        // 1. generate hmac
        hmac = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(EH_HMAC_SHA256_SIZE));
        if (hmac == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        hmac->datalen = EH_HMAC_SHA256_SIZE;

        ret = GenerateHmac(cmk, apikey, payload, hmac);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }

        hmac_str = base64_encode(hmac->data, hmac->datalen);
        retJsonObj.setCode(retJsonObj.CODE_SUCCESS);
        retJsonObj.addData_string("hmac", hmac_str);

    out:
        SAFE_FREE(cmk);
        SAFE_FREE(apikey);
        SAFE_FREE(payload);
        SAFE_FREE(hmac);
        retJsonObj.toChar(respJson);
        return ret;
    }

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
    uint32_t ffi_generateTokenHmac(JsonObj payloadJson, char *respJson)
    {
        ehsm_status_t ret;

        ehsm_data_t *importToken = NULL;
        ehsm_data_t *hmac = NULL;
        RetJsonObj retJsonObj;
        ehsm_keyblob_t *sessionkey = NULL;
        std::string hmac_str;

        JSON2STRUCT(payloadJson, sessionkey);

        //importToken: {keyid | timestamp}
        char *import_token = payloadJson.readData_cstr("importToken");

        uint32_t importToken_size = string(import_token).size();
        importToken = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(importToken_size));
        importToken->datalen = importToken_size;

        memcpy_s(importToken->data, importToken->datalen, import_token, importToken->datalen);
        importToken->data[importToken_size - 1] = 0;

        hmac = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(EH_HMAC_SHA256_SIZE));
        if (hmac == NULL)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        hmac->datalen = EH_HMAC_SHA256_SIZE;

        ret = GenerateTokenHmac(sessionkey, importToken, hmac);
        if (ret != EH_OK)
        {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
            goto out;
        }
        hmac_str = base64_encode(hmac->data, hmac->datalen);
        retJsonObj.addData_string("hmac", hmac_str);

    out:
        SAFE_FREE(importToken);
        SAFE_FREE(sessionkey);
        SAFE_FREE(import_token);
        SAFE_FREE(hmac);
        retJsonObj.toChar(respJson);
        return ret;
    }

} // extern "C"
