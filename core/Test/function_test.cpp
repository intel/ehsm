/*
 * Copyright (C) 2020-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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

#include "../App/ehsm_provider.h"
#include "base64.h"
#include "dsohandle.h"
#include "json_utils.h"
#include "function_test.h"
#include "ulog_utils.h"

int case_number = 0;
int success_number = 0;

/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. encrypt a plaintext by the CMK

step3. decrypt the cipher text by CMK correctly

*/
void test_symmertric_encrypt_decrypt()
{
    log_i("============test_AES_SM_encrypt_decrypt start==========\n");
    std::string plaintext[] = {"Test1234-AES128", "Test1234-AES192",
                               "Test1234-AES256", "Test1234-SM4-CTR", "Test1234-SM4-CBC"};
    uint32_t keyspec[] = {EH_AES_GCM_128, EH_AES_GCM_192, EH_AES_GCM_256, EH_SM4_CTR, EH_SM4_CBC};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);

    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));
        char aad[] = "challenge";
        log_i("============%s start==========\n", plaintext[i].c_str());

        char *cmk_base64 = nullptr;
        char *ciphertext_base64 = nullptr;
        char *plaintext_base64 = nullptr;
        std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext[i].c_str(), plaintext[i].length());
        std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

        RetJsonObj retJsonObj;
        JsonObj param_json;
        JsonObj payload_json;
        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Createkey with aes-gcm failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json = %s\n", returnJsonChar);
        log_i("Create CMK with AES SUCCESSFULLY!\n");
        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("plaintext", input_plaintext_base64);
        payload_json.addData_string("aad", input_aad_base64);

        param_json.addData_uint32("action", EH_ENCRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Encrypt json = %s\n", returnJsonChar);
        log_i("Encrypt data SUCCESSFULLY!\n");

        ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
        payload_json.addData_string("ciphertext", ciphertext_base64);

        param_json.addData_uint32("action", EH_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Decrypt json = %s\n", returnJsonChar);
        plaintext_base64 = retJsonObj.readData_cstr("plaintext");
        if (plaintext_base64 == input_plaintext_base64)
        {
            success_number++;
            log_i("decode64 plaintext = %s\n", base64_decode(plaintext_base64).c_str());
            log_i("Decrypt data SUCCESSFULLY!\n");
        }
        else
        {
            log_e("Failed to Decrypt the data, result = %s \n", base64_decode(plaintext_base64).c_str());
        }

    cleanup:
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(ciphertext_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        log_i("============%s end==========\n", plaintext[i].c_str());
    }

    log_i("============test_AES_SM_encrypt_decrypt end==========\n");
}

void test_symmertric_encrypt_decrypt_without_aad()
{
    log_i("============test_AES_encrypt_decrypt_without_aad start==========\n");
    std::string plaintext[] = {"Test1234-AES128", "Test1234-AES192",
                               "Test1234-AES256"};
    uint32_t keyspec[] = {EH_AES_GCM_128, EH_AES_GCM_192, EH_AES_GCM_256};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);

    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));
        char aad[] = "";
        log_i("============%s start==========\n", plaintext[i].c_str());

        char *cmk_base64 = nullptr;
        char *ciphertext_base64 = nullptr;
        char *plaintext_base64 = nullptr;
        std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext[i].c_str(), plaintext[i].length());
        std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

        RetJsonObj retJsonObj;
        JsonObj param_json;
        JsonObj payload_json;
        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Createkey with aes-gcm failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json = %s\n", returnJsonChar);
        log_i("Create CMK with AES SUCCESSFULLY!\n");
        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("plaintext", input_plaintext_base64);
        payload_json.addData_string("aad", input_aad_base64);

        param_json.addData_uint32("action", EH_ENCRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Encrypt json = %s\n", returnJsonChar);
        log_i("Encrypt data SUCCESSFULLY!\n");

        ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
        payload_json.addData_string("ciphertext", ciphertext_base64);

        param_json.addData_uint32("action", EH_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Decrypt json = %s\n", returnJsonChar);
        plaintext_base64 = retJsonObj.readData_cstr("plaintext");
        if (plaintext_base64 == input_plaintext_base64)
        {
            success_number++;
            log_i("decode64 plaintext = %s\n", base64_decode(plaintext_base64).c_str());
            log_i("Decrypt data SUCCESSFULLY!\n");
        }
        else
        {
            log_e("Failed to Decrypt the data, result = %s \n", base64_decode(plaintext_base64).c_str());
        }

    cleanup:
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(ciphertext_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        log_i("============%s end==========\n", plaintext[i].c_str());
    }

    log_i("============test_AES_encrypt_decrypt_without_aad end==========\n");
}

void test_RSA_encrypt_decrypt()
{
    log_i("============test_RSA_encrypt_decrypt start==========\n");
    std::string plaintext[] = {"Test1234-RSA2048", "Test1234-RSA3072", "Test1234-RSA4096"};
    uint32_t keyspec[] = {EH_RSA_2048, EH_RSA_3072, EH_RSA_4096};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);

    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));
        log_i("============%s start==========\n", plaintext[i].c_str());

        char *cmk_base64 = nullptr;
        char *ciphertext_base64 = nullptr;
        char *plaintext_base64 = nullptr;
        std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext[i].c_str(), plaintext[i].length());

        RetJsonObj retJsonObj;
        JsonObj param_json;
        JsonObj payload_json;
        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Createkey with rsa failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json = %s\n", returnJsonChar);
        log_i("Create CMK with RSA SUCCESSFULLY!\n");
        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("plaintext", input_plaintext_base64);
        payload_json.addData_uint32("padding_mode", EH_RSA_PKCS1);

        param_json.addData_uint32("action", EH_ASYMMETRIC_ENCRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Encrypt the plaintext data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Encrypt json = %s\n", returnJsonChar);
        log_i("Encrypt data SUCCESSFULLY!\n");

        ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
        payload_json.addData_string("ciphertext", ciphertext_base64);

        param_json.addData_uint32("action", EH_ASYMMETRIC_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Decrypt json = %s\n", returnJsonChar);
        plaintext_base64 = retJsonObj.readData_cstr("plaintext");
        if (plaintext_base64 == input_plaintext_base64)
        {
            success_number++;
            log_i("decode64 plaintext = %s\n", base64_decode(plaintext_base64).c_str());
            log_i("Decrypt data SUCCESSFULLY!\n");
        }
        else
        {
            log_e("Failed to Decrypt the data, result = %s \n", base64_decode(plaintext_base64).c_str());
        }

    cleanup:
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(ciphertext_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        log_i("============%s end==========\n", plaintext[i].c_str());
    }

    log_i("============test_RSA_encrypt_decrypt end==========\n");
}

void test_SM2_encrypt_decrypt()
{
    log_i("============test_SM2_encrypt_decrypt start==========\n");
    std::string plaintext[] = {"Test1234-SM2"};
    uint32_t keyspec[] = {EH_SM2};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);

    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));
        log_i("============%s start==========\n", plaintext[i].c_str());

        char *cmk_base64 = nullptr;
        char *ciphertext_base64 = nullptr;
        char *plaintext_base64 = nullptr;
        std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext[i].c_str(), plaintext[i].length());

        RetJsonObj retJsonObj;
        JsonObj param_json;
        JsonObj payload_json;
        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Createkey with sm2 failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json = %s\n", returnJsonChar);
        log_i("Create CMK with SM2 SUCCESSFULLY!\n");
        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("plaintext", input_plaintext_base64);

        param_json.addData_uint32("action", EH_ASYMMETRIC_ENCRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Encrypt json = %s\n", returnJsonChar);
        log_i("Encrypt data SUCCESSFULLY!\n");

        ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
        payload_json.addData_string("ciphertext", ciphertext_base64);

        param_json.addData_uint32("action", EH_ASYMMETRIC_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Decrypt json = %s\n", returnJsonChar);
        plaintext_base64 = retJsonObj.readData_cstr("plaintext");
        if (plaintext_base64 == input_plaintext_base64)
        {
            success_number++;
            log_i("decode64 plaintext = %s\n", base64_decode(plaintext_base64).c_str());
            log_i("Decrypt data SUCCESSFULLY!\n");
        }
        else
        {
            log_e("Failed to Decrypt the data, result = %s \n", base64_decode(plaintext_base64).c_str());
        }

    cleanup:
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(ciphertext_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        log_i("============%s end==========\n", plaintext[i].c_str());
    }

    log_i("============test_SM2_encrypt_decrypt end==========\n");
}

void test_get_pubkey()
{
    log_i("============test_get_public_key==========\n");
    uint32_t keyspec[] = {EH_SM2, EH_EC_P224, EH_EC_P256, EH_EC_P256K, EH_EC_P384, EH_EC_P521, EH_RSA_2048, EH_RSA_3072, EH_RSA_4096};

    case_number += sizeof(keyspec) / sizeof(keyspec[0]);

    for (int i = 0; i < sizeof(keyspec) / sizeof(keyspec[0]); i++)
    {
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));

        char *cmk_base64 = nullptr;
        char *pubkey_base64 = nullptr;

        RetJsonObj retJsonObj;
        JsonObj param_json;
        JsonObj payload_json;
        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_SIGN_VERIFY);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Createkey failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json = %s\n", returnJsonChar);
        log_i("Create CMK SUCCESSFULLY!\n");
        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);

        param_json.addData_uint32("action", EH_GET_PUBLIC_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            log_e("Failed to Get the public key, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_getPublicKey json = %s\n", returnJsonChar);

        if ((std::string::npos != retJsonObj.readData_string("pubkey").find("-----END PUBLIC KEY-----")) ||
            (std::string::npos != retJsonObj.readData_string("pubkey").find("-----END RSA PUBLIC KEY-----")))
            success_number++;
        else
            log_i("Failed to get public key at %d", i);

        log_i("Get public key SUCCESSFULLY!\n");

    cleanup:
        SAFE_FREE(pubkey_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
    }

    log_i("============test_get_public_key end==========\n");
}

/*

step1. generate an rsa 3072 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_RSA_sign_verify_RAW()
{
    log_i("============test_RSA_sign_verify_RAW start==========\n");
    std::string plaintext[] = {"Test1234-RSA2048", "Test1234-RSA3072", "Test1234-RSA4096"};
    uint32_t keyspec[] = {EH_RSA_2048, EH_RSA_3072, EH_RSA_4096};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);
    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        log_i("============%s start==========\n", plaintext[i].c_str());
        ehsm_status_t ret = EH_OK;
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));
        char data2sign[] = "SIGN";

        char *cmk_base64 = nullptr;
        char *signature_base64 = nullptr;
        bool result = false;
        RetJsonObj retJsonObj;

        JsonObj param_json;
        JsonObj payload_json;

        std::string input_data2sign_base64 = base64_encode((const uint8_t *)data2sign, sizeof(data2sign) / sizeof(data2sign[0]));

        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_SIGN_VERIFY);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json : %s\n", returnJsonChar);
        log_i("Create CMK with RAS SUCCESSFULLY!\n");

        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("message", input_data2sign_base64);
        payload_json.addData_uint32("padding_mode", EH_RSA_PKCS1_PSS);
        payload_json.addData_uint32("digest_mode", EH_SHA_256);
        payload_json.addData_uint32("message_type", EH_RAW);

        param_json.addData_uint32("action", EH_SIGN);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Sign Json = %s\n", returnJsonChar);
        signature_base64 = retJsonObj.readData_cstr("signature");
        log_i("Sign data SUCCESSFULLY!\n");

        payload_json.addData_string("signature", signature_base64);

        param_json.addData_uint32("action", EH_VERIFY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Verify Json = %s\n", returnJsonChar);
        result = retJsonObj.readData_bool("result");
        log_i("Verify result : %s\n", result ? "true" : "false");
        if (result == true)
        {
            success_number++;
            log_i("Verify signature SUCCESSFULLY!\n");
        }

    cleanup:
        SAFE_FREE(signature_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        log_i("============%s end==========\n", plaintext[i].c_str());
    }
    log_i("============test_RSA_sign_verify_RAW end==========\n");
}

/*

step1. generate an rsa 3072 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_RSA_sign_verify_DIGEST()
{
    log_i("============test_RSA_sign_verify_DIGEST start==========\n");
    uint32_t keyspec[] = {EH_RSA_2048, EH_RSA_3072, EH_RSA_4096};

    case_number += sizeof(keyspec) / sizeof(keyspec[0]);
    for (int i = 0; i < sizeof(keyspec) / sizeof(keyspec[0]); i++)
    {
        ehsm_status_t ret = EH_OK;
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));

        char *cmk_base64 = nullptr;
        char *signature_base64 = nullptr;
        bool result = false;
        RetJsonObj retJsonObj;

        JsonObj param_json;
        JsonObj payload_json;

        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_SIGN_VERIFY);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json : %s\n", returnJsonChar);
        log_i("Create CMK with RAS SUCCESSFULLY!\n");

        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("message", "JVAPBOYcL7HFfJhtEwqL1lDoMZnUVwxYpCa6atFTH0E=");
        payload_json.addData_uint32("padding_mode", EH_RSA_PKCS1);
        payload_json.addData_uint32("digest_mode", EH_SHA_256);
        payload_json.addData_uint32("message_type", EH_DIGEST);

        param_json.addData_uint32("action", EH_SIGN);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Sign Json = %s\n", returnJsonChar);
        signature_base64 = retJsonObj.readData_cstr("signature");
        log_i("Sign data SUCCESSFULLY!\n");

        payload_json.addData_string("signature", signature_base64);

        param_json.addData_uint32("action", EH_VERIFY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Verify Json = %s\n", returnJsonChar);
        result = retJsonObj.readData_bool("result");
        log_i("Verify result : %s\n", result ? "true" : "false");
        if (result == true)
        {
            success_number++;
            log_i("Verify signature SUCCESSFULLY!\n");
        }

    cleanup:
        SAFE_FREE(signature_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
    }
    log_i("============test_RSA_sign_verify_DIGEST end==========\n");
}

/*

step1. generate an ec p256 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_ec_sign_verify_RAW()
{
    log_i("============test_ec_sign_verify_RAW start==========\n");
    std::string plaintext[] = {"Testsign-EC-p224", "Testsign-EC-p256", "Testsign-EC-p256k", "Testsign-EC-p384", "Testsign-EC-p521"};
    uint32_t keyspec[] = {EH_EC_P224, EH_EC_P256, EH_EC_P256K, EH_EC_P384, EH_EC_P521};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);
    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        log_i("============%s start==========\n", plaintext[i].c_str());
        ehsm_status_t ret = EH_OK;
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));
        char data2sign[] = "SIGN";

        char *cmk_base64 = nullptr;
        char *signature_base64 = nullptr;
        bool result = false;
        RetJsonObj retJsonObj;

        JsonObj param_json;
        JsonObj payload_json;

        std::string input_data2sign_base64 = base64_encode((const uint8_t *)data2sign, sizeof(data2sign) / sizeof(data2sign[0]));

        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_SIGN_VERIFY);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json : %s\n", returnJsonChar);
        log_i("Create CMK with ECC SUCCESSFULLY!\n");

        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("message", input_data2sign_base64);
        payload_json.addData_uint32("digest_mode", EH_SHA_256);
        payload_json.addData_uint32("message_type", EH_RAW);

        param_json.addData_uint32("action", EH_SIGN);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Sign Json = %s\n", returnJsonChar);
        signature_base64 = retJsonObj.readData_cstr("signature");
        log_i("Sign data SUCCESSFULLY!\n");

        payload_json.addData_string("signature", signature_base64);

        param_json.addData_uint32("action", EH_VERIFY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Verify Json = %s\n", returnJsonChar);
        result = retJsonObj.readData_bool("result");
        log_i("Verify result : %s\n", result ? "true" : "false");
        if (result == true)
        {
            success_number++;
            log_i("Verify signature SUCCESSFULLY!\n");
        }

    cleanup:
        SAFE_FREE(signature_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        log_i("============%s end==========\n", plaintext[i].c_str());
        log_i("\n");
    }
    log_i("============test_ec_sign_verify_RAW end==========\n");
}

/*

step1. generate an ec p256 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_ec_sign_verify_DIGEST()
{
    log_i("============test_ec_sign_verify_RAW start==========\n");
    uint32_t keyspec[] = {EH_EC_P224, EH_EC_P256, EH_EC_P256K, EH_EC_P384, EH_EC_P521};

    case_number += sizeof(keyspec) / sizeof(keyspec[0]);
    for (int i = 0; i < sizeof(keyspec) / sizeof(keyspec[0]); i++)
    {
        ehsm_status_t ret = EH_OK;
        char *returnJsonChar = (char *)calloc(10000, sizeof(char));

        char *cmk_base64 = nullptr;
        char *signature_base64 = nullptr;
        bool result = false;
        RetJsonObj retJsonObj;

        JsonObj param_json;
        JsonObj payload_json;

        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_SIGN_VERIFY);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_CreateKey Json : %s\n", returnJsonChar);
        log_i("Create CMK with ECC SUCCESSFULLY!\n");

        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("message", "JVAPBOYcL7HFfJhtEwqL1lDoMZnUVwxYpCa6atFTH0E");
        payload_json.addData_uint32("digest_mode", EH_SHA_256);
        payload_json.addData_uint32("message_type", EH_DIGEST);

        param_json.addData_uint32("action", EH_SIGN);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Sign Json = %s\n", returnJsonChar);
        signature_base64 = retJsonObj.readData_cstr("signature");
        log_i("Sign data SUCCESSFULLY!\n");

        payload_json.addData_string("signature", signature_base64);

        param_json.addData_uint32("action", EH_VERIFY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("FFI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        log_i("FFI_Verify Json = %s\n", returnJsonChar);
        result = retJsonObj.readData_bool("result");
        log_i("Verify result : %s\n", result ? "true" : "false");
        if (result == true)
        {
            success_number++;
            log_i("Verify signature SUCCESSFULLY!\n");
        }

    cleanup:
        SAFE_FREE(signature_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        log_i("\n");
    }
    log_i("============test_ec_sign_verify_RAW end==========\n");
}

/*

step1. generate an sm2 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_sm2_sign_verify_RAW()
{
    case_number++;
    ehsm_status_t ret = EH_OK;
    char *returnJsonChar = (char *)calloc(10000, sizeof(char));
    char data2sign[] = "SIGN";

    char *cmk_base64 = nullptr;
    char *signature_base64 = nullptr;
    bool result = false;
    RetJsonObj retJsonObj;

    JsonObj param_json;
    JsonObj payload_json;

    std::string input_data2sign_base64 = base64_encode((const uint8_t *)data2sign, sizeof(data2sign) / sizeof(data2sign[0]));

    payload_json.addData_uint32("keyspec", EH_SM2);
    payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
    payload_json.addData_uint32("keyusage", EH_KEYUSAGE_SIGN_VERIFY);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());
    log_i("============test_sm2_sign_verify_RAW start==========\n");

    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_CreateKey Json : %s\n", returnJsonChar);
    log_i("Create CMK with SM2 SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_string("message", input_data2sign_base64);
    payload_json.addData_uint32("digest_mode", EH_SM3);
    payload_json.addData_uint32("message_type", EH_RAW);

    param_json.addData_uint32("action", EH_SIGN);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_Sign Json = %s\n", returnJsonChar);
    signature_base64 = retJsonObj.readData_cstr("signature");
    log_i("Sign data SUCCESSFULLY!\n");

    payload_json.addData_string("signature", signature_base64);

    param_json.addData_uint32("action", EH_VERIFY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_i("FFI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_Verify Json = %s\n", returnJsonChar);
    result = retJsonObj.readData_bool("result");
    log_i("Verify result : %s\n", result ? "true" : "false");
    if (result == true)
    {
        success_number++;
        log_i("Verify signature SUCCESSFULLY!\n");
    }

cleanup:
    SAFE_FREE(signature_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    log_i("============test_sm2_sign_verify_RAW end==========\n");
    log_i("\n");
}

/*

step1. generate an sm2 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_sm2_sign_verify_DIGEST()
{
    case_number++;
    ehsm_status_t ret = EH_OK;
    char *returnJsonChar = (char *)calloc(10000, sizeof(char));

    char *cmk_base64 = nullptr;
    char *signature_base64 = nullptr;
    bool result = false;
    RetJsonObj retJsonObj;

    JsonObj param_json;
    JsonObj payload_json;

    payload_json.addData_uint32("keyspec", EH_SM2);
    payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
    payload_json.addData_uint32("keyusage", EH_KEYUSAGE_SIGN_VERIFY);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());
    log_i("============test_sm2_sign_verify_RAW start==========\n");

    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_CreateKey Json : %s\n", returnJsonChar);
    log_i("Create CMK with SM2 SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_string("message", "JVAPBOYcL7HFfJhtEwqL1lDoMZnUVwxYpCa6atFTH0E");
    payload_json.addData_uint32("digest_mode", EH_SM3);
    payload_json.addData_uint32("message_type", EH_DIGEST);

    param_json.addData_uint32("action", EH_SIGN);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_Sign Json = %s\n", returnJsonChar);
    signature_base64 = retJsonObj.readData_cstr("signature");
    log_i("Sign data SUCCESSFULLY!\n");

    payload_json.addData_string("signature", signature_base64);

    param_json.addData_uint32("action", EH_VERIFY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_i("FFI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_Verify Json = %s\n", returnJsonChar);
    result = retJsonObj.readData_bool("result");
    log_i("Verify result : %s\n", result ? "true" : "false");
    if (result == true)
    {
        success_number++;
        log_i("Verify signature SUCCESSFULLY!\n");
    }

cleanup:
    SAFE_FREE(signature_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    log_i("============test_sm2_sign_verify_RAW end==========\n");
    log_i("\n");
}

/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. generate a 16 bytes random data key and with plaint text returned

step3. decrypt the cipher text by CMK

step4. generate a 48 bytes random data key and without plaint text returned

step5. decrypt the cipher text by CMK

*/
void test_generate_AES_datakey()
{
    case_number++;
    log_i("============test_generate_AES_datakey start==========\n");
    char *returnJsonChar = (char *)calloc(10000, sizeof(char));
    char aad[] = "challenge";
    char *cmk_base64 = nullptr;
    char *ciphertext_base64 = nullptr;
    char *ciphertext_without_base64 = nullptr;
    // generated datakey len
    int len_gdk = 16;
    int len_gdk_without = 48;
    RetJsonObj retJsonObj;
    std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

    JsonObj payload_json;
    JsonObj param_json;
    payload_json.addData_uint32("keyspec", EH_AES_GCM_128);
    payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
    payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);

    if (retJsonObj.getCode() != 200)
    {
        log_e("Createkey with aes-gcm-128 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("ckReturn_Json = %s\n", returnJsonChar);
    log_i("Create CMK with AES-128 SUCCESSFULLY!\n");

    /* generate a 16 bytes random data key and with plaint text returned */
    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_uint32("keylen", len_gdk);
    payload_json.addData_string("aad", input_aad_base64);

    param_json.addData_uint32("action", EH_GENERATE_DATAKEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);

    if (retJsonObj.getCode() != 200)
    {
        log_e("GenerateDataKey Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("GenerateDataKey_Json = %s\n", returnJsonChar);
    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
    log_i("GenerateDataKey SUCCESSFULLY!\n");

    payload_json.addData_string("ciphertext", ciphertext_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("step1 Decrypt_Json = %s\n", returnJsonChar);
    log_i("Decrypt step1 data SUCCESSFULLY!\n");

    /* generate a 48 bytes random data key and without plaint text returned */
    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_uint32("keylen", len_gdk_without);
    payload_json.addData_string("aad", input_aad_base64);

    param_json.addData_uint32("action", EH_GENERATE_DATAKEY_WITHOUT_PLAINTEXT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_GenerateDataKeyWithoutPlaintext Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("GenerateDataKeyWithoutPlaintext_Json = %s\n", returnJsonChar);

    ciphertext_without_base64 = retJsonObj.readData_cstr("ciphertext");
    log_i("GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");

    payload_json.addData_string("ciphertext", ciphertext_without_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("step2 Decrypt_Json = %s\n", returnJsonChar);
    log_i("Decrypt step2 data SUCCESSFULLY!\n");
    success_number++;

cleanup:
    SAFE_FREE(ciphertext_without_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    log_i("============test_generate_AES_datakey end==========\n");
}

/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. generate a 16 bytes random data key and with plaint text returned

step3. decrypt the cipher text by CMK

step4. generate a 48 bytes random data key and without plaint text returned

step5. decrypt the cipher text by CMK

*/
void test_generate_SM4_datakey()
{
    case_number++;
    log_i("============test_generate_SM4_datakey start==========\n");
    char *returnJsonChar = (char *)calloc(10000, sizeof(char));
    char *cmk_base64 = nullptr;
    char *ciphertext_base64 = nullptr;
    char *ciphertext_without_base64 = nullptr;
    int len_gdk = 16;
    int len_gdk_without = 111;
    RetJsonObj retJsonObj;

    JsonObj payload_json;
    JsonObj param_json;
    payload_json.addData_uint32("keyspec", EH_SM4_CBC);
    payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
    payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);

    if (retJsonObj.getCode() != 200)
    {
        log_e("Createkey with sm4 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("ckReturn_Json = %s\n", returnJsonChar);
    log_i("Create CMK with sm4 SUCCESSFULLY!\n");

    /* generate a 16 bytes random data key and with plaint text returned */
    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_uint32("keylen", len_gdk);

    param_json.addData_uint32("action", EH_GENERATE_DATAKEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);

    if (retJsonObj.getCode() != 200)
    {
        log_e("GenerateDataKey Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("GenerateDataKey_Json = %s\n", returnJsonChar);
    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
    log_i("GenerateDataKey SUCCESSFULLY!\n");

    payload_json.addData_string("ciphertext", ciphertext_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("step1 Decrypt_Json = %s\n", returnJsonChar);
    log_i("Decrypt step1 data SUCCESSFULLY!\n");

    /* generate a 48 bytes random data key and without plaint text returned */
    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_uint32("keylen", len_gdk_without);

    param_json.addData_uint32("action", EH_GENERATE_DATAKEY_WITHOUT_PLAINTEXT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_GenerateDataKeyWithoutPlaintext Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("GenerateDataKeyWithoutPlaintext_Json = %s\n", returnJsonChar);

    ciphertext_without_base64 = retJsonObj.readData_cstr("ciphertext");
    log_i("GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");

    payload_json.addData_string("ciphertext", ciphertext_without_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("step2 Decrypt_Json = %s\n", returnJsonChar);
    log_i("Decrypt step2 data SUCCESSFULLY!\n");
    success_number++;

cleanup:
    SAFE_FREE(ciphertext_without_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    log_i("============test_generate_SM4_datakey end==========\n");
}

// /*

// step1. generate an aes-gcm-128 key as the CM(customer master key)

// step2. generate a cipher datakey without plaintext which encrypted by the CMK

// step3. verify the cipher text could be decrypted by CMK correctly

// step4. generate a new rsa key pair as the user-supplied asymmetric keymeterials.

// step5. export the datakey with the new user public key

// step6. verify that the new datakey cipher text could be decrypt succeed by the user rsa key pair

void test_export_datakey()
{
    /*
     * current testcase support aes-gcm-128, aes-gcm-192, aes-gcm-256, sm4-cbc, sm4-ctr cmk encrypted olddatakey
     * export newdatakey using rsa2048, rsa3072, rsa4096, sm2 ukey
     */
    ehsm_keyspec_t cmk_keyspec_test[] = {EH_AES_GCM_128, EH_AES_GCM_192, EH_AES_GCM_256, EH_SM4_CBC, EH_SM4_CTR};
    int cmk_keyspec_test_num = sizeof(cmk_keyspec_test) / sizeof(cmk_keyspec_test[0]);
    ehsm_keyspec_t ukey_keyspec_test[] = {EH_RSA_2048, EH_RSA_3072, EH_RSA_4096, EH_SM2};
    int ukey_keyspec_test_num = sizeof(ukey_keyspec_test) / sizeof(ukey_keyspec_test[0]);

    case_number += (cmk_keyspec_test_num * ukey_keyspec_test_num);

    char *returnJsonChar = (char *)calloc(10000, sizeof(char));
    char *cmk_base64 = nullptr;
    char *ukey_base64 = nullptr;
    char aad[] = "";
    char *olddatakey_base64 = nullptr;
    char *newdatakey_base64 = nullptr;
    char *olddatakeyplaintext_base64 = nullptr;
    char *newdatakeyplaintext_base64 = nullptr;
    char *plaintext_base64 = nullptr;
    char *ciphertext_base64 = nullptr;
    uint32_t keylen = 48;
    RetJsonObj retJsonObj;
    std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

    log_i("============test_export_datakey start==========\n");

    /*step1. create an aes-128 key as the cmk to encrypt datakey*/
    JsonObj param_json;
    JsonObj payload_json;
    for (int i = 0; i < cmk_keyspec_test_num; i++)
    {
        payload_json.clear();
        param_json.clear();
        payload_json.addData_uint32("keyspec", cmk_keyspec_test[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());
        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("Createkey using keyspec code %d cmk failed, error message: %s \n", cmk_keyspec_test[i], retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        cmk_base64 = retJsonObj.readData_cstr("cmk");
        log_i("cmk_base64 : %s\n", cmk_base64);
        log_i("Create CMK with keyspec code %d SUCCESSFULLY!\n", cmk_keyspec_test[i]);

        /* step2. generate a 48 bytes random data key and without plaintext returned */
        payload_json.clear();
        param_json.clear();
        payload_json.addData_string("aad", input_aad_base64);
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_uint32("keylen", keylen);
        payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
        param_json.addData_uint32("action", EH_GENERATE_DATAKEY_WITHOUT_PLAINTEXT);
        param_json.addData_JsonValue("payload", payload_json.getJson());
        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("GenerateDataKeyWithoutPlaintext using keyspec code %d cmk Failed, error message: %s \n", cmk_keyspec_test[i], retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        olddatakey_base64 = retJsonObj.readData_cstr("ciphertext");
        log_i("olddatakey_base64 : %s\n", olddatakey_base64);
        log_i("GenerateDataKeyWithoutPlaintext using keyspec code %d cmk SUCCESSFULLY!\n", cmk_keyspec_test[i]);

        /* step3. try to use the cmk to decrypt the datakey */
        payload_json.clear();
        param_json.clear();
        payload_json.addData_string("aad", input_aad_base64);
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("ciphertext", olddatakey_base64);
        param_json.addData_uint32("action", EH_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());
        memset(returnJsonChar, 0, 10000);
        EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            log_e("DECEYPT using keyspec code %d cmk, failed, error message: %s \n", cmk_keyspec_test[i], retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        olddatakeyplaintext_base64 = retJsonObj.readData_cstr("plaintext");
        log_i("Decrypted using keyspec code %d cmk, datakeyplaintext_base64 : %s\n", cmk_keyspec_test[i], olddatakeyplaintext_base64);
        log_i("Decrypt datakey using keyspec code %d cmk SUCCESSFULLY!\n", cmk_keyspec_test[i]);
        for (int j = 0; j < ukey_keyspec_test_num; j++)
        {
            payload_json.clear();
            param_json.clear();
            payload_json.addData_uint32("keyspec", ukey_keyspec_test[j]);
            /*step4. create key as the ukey */
            payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
            payload_json.addData_uint32("keyusage", EH_KEYUSAGE_ENCRYPT_DECRYPT);
            param_json.addData_uint32("action", EH_CREATE_KEY);
            param_json.addData_JsonValue("payload", payload_json.getJson());
            memset(returnJsonChar, 0, 10000);
            EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
            retJsonObj.parse(returnJsonChar);
            if (retJsonObj.getCode() != 200)
            {
                log_e("CreateKey using keyspec code %d ukey failed, error message: %s \n", ukey_keyspec_test[j], retJsonObj.getMessage().c_str());
                goto cleanup;
            }
            ukey_base64 = retJsonObj.readData_cstr("cmk");
            log_i("keyspec code %d ukey_base64 : %s\n", ukey_keyspec_test[j], ukey_base64);
            log_i("CreateKey UKEY using keyspec code %d SUCCESSFULLY!\n", ukey_keyspec_test[j]);

            /*step5. export the datakey with the new user public key */
            payload_json.clear();
            param_json.clear();
            payload_json.addData_string("aad", input_aad_base64);
            payload_json.addData_string("cmk", cmk_base64);
            payload_json.addData_string("ukey", ukey_base64);
            payload_json.addData_string("olddatakey", olddatakey_base64);
            param_json.addData_uint32("action", EH_EXPORT_DATAKEY);
            param_json.addData_JsonValue("payload", payload_json.getJson());
            memset(returnJsonChar, 0, 10000);
            EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
            retJsonObj.parse(returnJsonChar);
            if (retJsonObj.getCode() != 200)
            {
                log_e("ExportDataKey using keyspec code %d cmk, keyspec code %d ukey failed, error message: %s \n", cmk_keyspec_test[i], ukey_keyspec_test[j], retJsonObj.getMessage().c_str());
                goto cleanup;
            }
            newdatakey_base64 = retJsonObj.readData_cstr("newdatakey");
            log_i("ExportDataKey SUCCESSFULLY!\n");
            // step6. verify that the newdatakey ciphertext could be decrypt succeed by the user rsa key pair
            payload_json.clear();
            param_json.clear();
            payload_json.addData_string("cmk", ukey_base64);
            payload_json.addData_string("ciphertext", newdatakey_base64);
            payload_json.addData_uint32("padding_mode", EH_RSA_PKCS1_OAEP);
            param_json.addData_uint32("action", EH_ASYMMETRIC_DECRYPT);
            param_json.addData_JsonValue("payload", payload_json.getJson());
            memset(returnJsonChar, 0, 10000);
            EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
            retJsonObj.parse(returnJsonChar);
            if (retJsonObj.getCode() != 200)
            {
                log_e("AsymmetricDecrypt newdatakey using keyspec code %d cmk, keyspec code %d ukey failed, error message: %s \n", cmk_keyspec_test[i], ukey_keyspec_test[j], retJsonObj.getMessage().c_str());
                goto cleanup;
            }
            newdatakeyplaintext_base64 = retJsonObj.readData_cstr("plaintext");
            log_i("AsymmetricDecrypt newdatakey using keyspec code %d ukey Json : %s\n", ukey_keyspec_test[j], returnJsonChar);
            log_i("newdatakey_plaintext_base64 : %s\n", newdatakeyplaintext_base64);
            log_i("Asymmetric Decrypt newdatakey using keyspec code %d ukey SUCCESSFULLY!\n", ukey_keyspec_test[j]);
            if (strcmp(olddatakeyplaintext_base64, newdatakeyplaintext_base64) == 0)
            {
                log_i("ExportDataKey with keyspec code %d cmk, keyspec code %d ukey SUCCESSFULLY.\n", cmk_keyspec_test[i], ukey_keyspec_test[j]);
            }
            else
            {
                log_i("ExportDataKey  with keyspec code %d cmk, keyspec code %d ukey failed. olddatakeyplaintext!=newdatakeyplaintext\n", cmk_keyspec_test[i], ukey_keyspec_test[j]);
            }
            SAFE_FREE(ukey_base64);
            SAFE_FREE(newdatakey_base64);
            SAFE_FREE(newdatakeyplaintext_base64)

            success_number++;
        }
        SAFE_FREE(cmk_base64);
        SAFE_FREE(ukey_base64);
        SAFE_FREE(olddatakey_base64);
        SAFE_FREE(newdatakey_base64);
        SAFE_FREE(olddatakeyplaintext_base64);
        SAFE_FREE(newdatakeyplaintext_base64);
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(ciphertext_base64);
    }
cleanup:
    SAFE_FREE(returnJsonChar);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(ukey_base64);
    SAFE_FREE(olddatakey_base64);
    SAFE_FREE(newdatakey_base64);
    SAFE_FREE(olddatakeyplaintext_base64);
    SAFE_FREE(newdatakeyplaintext_base64);
    SAFE_FREE(plaintext_base64);
    SAFE_FREE(ciphertext_base64);
    log_i("============test_export_datakey end==========\n");
}

void test_GenerateQuote_and_VerifyQuote()
{
    log_i("============test_GenerateQuote_and_VerifyQuote start==========\n");
    JsonObj param_json;
    JsonObj payload_json;

    RetJsonObj retJsonObj;
    char *returnJsonChar = (char *)calloc(10000, sizeof(char));
    char *quote_base64 = nullptr;

    char challenge[32] = "challenge123456";
    char nonce[16] = "nonce123456";

    std::string input_challenge_base64 = base64_encode((const uint8_t *)challenge, sizeof(challenge) / sizeof(challenge[0]));
    std::string input_nonce_base64 = base64_encode((const uint8_t *)nonce, sizeof(nonce) / sizeof(nonce[0]));

    // the string generated after converting the value of mr_signer and mr_enclave to hexadecimal
    // notice: these 2 values will be changed if our enclave has been updated. then the case may be failed.
    // you can get mr_signer and mr_enclave through cmd:
    // "/opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave libenclave-ehsm-core.signed.so -dumpfile out.log"
    std::string mr_enclave;
    std::string mr_signer;
    std::string signedEnclaveFileName = SIGNED_ENCLAVE_FILENAME;
    std::string sgxSignFileName = SGX_SIGNING_TOOL;
    std::string tmpFileName = "ehsm_enclave_out.log";
    log_i("NAPI_GenerateQuote signedEnclaveFileName : %s\n", signedEnclaveFileName.c_str());
    log_i("NAPI_GenerateQuote sgxSignFileName : %s\n", sgxSignFileName.c_str());
    std::string delTmpFileCMD = "rm " + tmpFileName;
    std::string CMD1 = " dump -enclave ";
    std::string CMD2 = " -dumpfile " + tmpFileName;
    std::string splicedCMD = sgxSignFileName + CMD1 + signedEnclaveFileName + CMD2;
    const char *dumpFileCMD = splicedCMD.data();
    system(dumpFileCMD);
    std::fstream ifs;
    std::string line;
    u_int32_t readEnclaveLineNum = 0;
    u_int32_t readSignerLineNum = 0;
    ifs.open(tmpFileName, std::ios::in);
    if (!ifs.is_open())
    {
        log_e("load mr_signer & mr_enclave faild. \n");
        goto cleanup;
    }
    while (getline(ifs, line))
    {
        if (readEnclaveLineNum > 0)
        {
            readEnclaveLineNum -= 1;
            mr_enclave += line;
        }
        if (readSignerLineNum > 0)
        {
            readSignerLineNum -= 1;
            mr_signer += line;
        }
        if (line.compare("metadata->enclave_css.body.enclave_hash.m:") == 0)
        {
            if (mr_enclave.length() == 0)
            {
                readEnclaveLineNum = 2;
            }
        }
        if (line.compare("mrsigner->value:") == 0)
        {
            if (mr_signer.length() == 0)
            {
                readSignerLineNum = 2;
            }
        }
    }
    while (mr_enclave.find("0x") != -1)
    {
        mr_enclave = mr_enclave.replace(mr_enclave.find("0x"), 2, "");
    }
    while (mr_enclave.find(" ") != -1)
    {
        mr_enclave = mr_enclave.replace(mr_enclave.find(" "), 1, "");
    }
    while (mr_signer.find("0x") != -1)
    {
        mr_signer = mr_signer.replace(mr_signer.find("0x"), 2, "");
    }
    while (mr_signer.find(" ") != -1)
    {
        mr_signer = mr_signer.replace(mr_signer.find(" "), 1, "");
    }
    system(delTmpFileCMD.data());

    payload_json.addData_string("challenge", input_challenge_base64);
    param_json.addData_uint32("action", EH_GENERATE_QUOTE);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_GenerateQuote failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_GenerateQuote Json : %s\n", returnJsonChar);
    log_i("FFI_GenerateQuote SUCCESSFULLY!\n");

    quote_base64 = retJsonObj.readData_cstr("quote");
    log_i("quote_base64 : %s\n", quote_base64);

    payload_json.clear();
    param_json.clear();
    payload_json.addData_string("quote", quote_base64);
    payload_json.addData_string("mr_signer", mr_signer);
    payload_json.addData_string("mr_enclave", mr_enclave);
    payload_json.addData_string("nonce", input_nonce_base64);
    param_json.addData_uint32("action", EH_VERIFY_QUOTE);
    param_json.addData_JsonValue("payload", payload_json.getJson());
    memset(returnJsonChar, 0, 10000);
    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_VerifyQuote failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_VerifyQuote Json : %s\n", returnJsonChar);
    log_i("FFI_VerifyQuote SUCCESSFULLY!\n");

cleanup:
    SAFE_FREE(returnJsonChar);
    SAFE_FREE(quote_base64);
    log_i("============test_GenerateQuote_and_VerifyQuote end==========\n");
}

void test_Enroll()
{
    log_i("============test_Enroll start==========\n");
    RetJsonObj retJsonObj;
    char *returnJsonChar = (char *)calloc(10000, sizeof(char));
    char *appid = nullptr;
    char *apikey = nullptr;

    JsonObj param_json;
    JsonObj payload_json;
    param_json.addData_uint32("action", EH_ENROLL);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    EHSM_FFI_CALL(param_json.toString().c_str(), returnJsonChar);
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        log_e("FFI_Enroll failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    log_i("FFI_Enroll Json : %s\n", returnJsonChar);
    log_i("FFI_Enroll SUCCESSFULLY!\n");

    appid = retJsonObj.readData_cstr("appid");
    apikey = retJsonObj.readData_cstr("apikey");
    log_i("appid : %s\n", appid);
    log_i("apikey : %s\n", apikey);

cleanup:
    SAFE_FREE(appid);
    SAFE_FREE(apikey);
    SAFE_FREE(returnJsonChar);
    log_i("============test_Enroll end==========\n");
}

void function_test()
{
    test_symmertric_encrypt_decrypt();

    test_symmertric_encrypt_decrypt_without_aad();

    test_RSA_encrypt_decrypt();

    test_RSA_sign_verify_RAW();

    test_RSA_sign_verify_DIGEST();

    test_sm2_sign_verify_RAW();

    test_sm2_sign_verify_DIGEST();

    test_ec_sign_verify_RAW();
    
    test_ec_sign_verify_DIGEST();

    test_SM2_encrypt_decrypt();

    test_get_pubkey();

    test_generate_AES_datakey();

    test_generate_SM4_datakey();

    test_export_datakey();

    test_GenerateQuote_and_VerifyQuote();

    test_Enroll();

    log_i("All of tests done. %d/%d success\n", success_number, case_number);
}