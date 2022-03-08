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

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <cstdint>
#include "ehsm_provider.h"
#include "base64.h"
#include "ehsm_napi.h"
#include "dsohandle.h"
#include "json_utils.h"

using namespace EHsmProvider;

/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. encrypt a plaintext by the CMK

step3. decrypt the cipher text by CMK correctly

*/
void test_AES128()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "Test1234-AES128";
    char aad[] = "challenge";
    printf("============test_AES128 start==========\n");
    
    char* cmk_base64 = nullptr;
    char* ciphertext_base64 = nullptr;
    char* plaintext_base64 = nullptr;
    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));
    std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

    RetJsonObj retJsonObj;
    returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Createkey with aes-gcm-128 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
    printf("Create CMK with AES-128 SUCCESSFULLY!\n");
    cmk_base64 = retJsonObj.readData_cstr("cmk");

    returnJsonChar = NAPI_Encrypt(cmk_base64, input_plaintext_base64.c_str(), input_aad_base64.c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup; 
    }
    printf("NAPI_Encrypt json = %s\n", returnJsonChar);
    printf("Encrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

    returnJsonChar = NAPI_Decrypt(cmk_base64, ciphertext_base64, input_aad_base64.c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup; 
    }
    printf("NAPI_Decrypt json = %s\n", returnJsonChar);
    plaintext_base64 = retJsonObj.readData_cstr("plaintext");
    printf("Check decrypt plaintext result with %s: %s\n", input_plaintext_base64.c_str(), (plaintext_base64 == input_plaintext_base64) ? "true" : "false");
    printf("decode64 plaintext = %s\n", base64_decode(plaintext_base64).c_str());
    printf("Decrypt data SUCCESSFULLY!\n");
    
cleanup:
    SAFE_FREE(plaintext_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_AES128 end==========\n");
}

void test_RSA3072_encrypt_decrypt()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "TestRSA-3072";
    char* cmk_base64 = nullptr;
    char* ciphertext_base64 = nullptr;
    char* plaintext_base64 = nullptr;
    RetJsonObj retJsonObj;
    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));

    printf("============test_RSA3072_encrypt_decrypt start==========\n");

    returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    returnJsonChar = NAPI_AsymmetricEncrypt(cmk_base64, input_plaintext_base64.c_str());
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricEncrypt json : %s\n", returnJsonChar);
    printf("NAPI_AsymmetricEncrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
    returnJsonChar = NAPI_AsymmetricDecrypt(cmk_base64, ciphertext_base64);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricDecrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricDecrypt json : %s\n", returnJsonChar);
    plaintext_base64 = retJsonObj.readData_cstr("plaintext");
    printf("Decrypted plaintext : %s\n", plaintext_base64);
    printf("NAPI_AsymmetricDecrypt data SUCCESSFULLY!\n");

cleanup:
        SAFE_FREE(cmk_base64);
        SAFE_FREE(ciphertext_base64);
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(returnJsonChar);
        printf("============test_RSA3072_encrypt_decrypt End==========\n");
}


/*

step1. generate an rsa 3072 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_RSA3072_sign_verify()
{
    printf("============test_RSA3072_sign_verify start==========\n");
    ehsm_status_t ret = EH_OK;
    char* returnJsonChar = nullptr;
    ehsm_data_t digest;

    char* cmk_base64 = nullptr;
    char* signature_base64 = nullptr;
    bool result = false;
    RetJsonObj retJsonObj;
    std::string input_digest_base64;


    returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    digest.datalen = 64;
    digest.data = (uint8_t*)malloc(digest.datalen);
    if (digest.data == NULL) {
    }
    memset(digest.data, 'B', digest.datalen);
    input_digest_base64 = base64_encode(digest.data, digest.datalen);

    returnJsonChar = NAPI_Sign(cmk_base64, input_digest_base64.c_str());
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Sign Json = %s\n", returnJsonChar);
    signature_base64 = retJsonObj.readData_cstr("signature");
    printf("Sign data SUCCESSFULLY!\n");

    returnJsonChar = NAPI_Verify(cmk_base64, input_digest_base64.c_str(), signature_base64);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Verify Json = %s\n", returnJsonChar);
    result = retJsonObj.readData_bool("result");
    printf("Verify result : %s\n", result ? "true" : "false");
    printf("Verify signature SUCCESSFULLY!\n");

cleanup:
    SAFE_FREE(signature_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(digest.data);
    SAFE_FREE(returnJsonChar);

}

/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. generate a 16 bytes random data key and with plaint text returned

step3. decrypt the cipher text by CMK 

step4. generate a 48 bytes random data key and without plaint text returned

step5. decrypt the cipher text by CMK 

*/
void test_generate_datakey()
{
    printf("============test_generate_datakey start==========\n");
    char* returnJsonChar = nullptr;
    char aad[] = "challenge";
    char* cmk_base64 = nullptr;
    char* ciphertext_base64 = nullptr;
    char* ciphertext_without_base64 = nullptr;
    int len_gdk = 16;  
    int len_gdk_without = 48;
    RetJsonObj retJsonObj;
    std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

    returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("Createkey with aes-gcm-128 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("ckReturn_Json = %s\n", returnJsonChar);
    printf("Create CMK with AES-128 SUCCESSFULLY!\n");

    /* generate a 16 bytes random data key and with plaint text returned */
    cmk_base64 = retJsonObj.readData_cstr("cmk");
    returnJsonChar = NAPI_GenerateDataKey(cmk_base64, len_gdk, input_aad_base64.c_str());
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("GenerateDataKey Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("GenerateDataKey_Json = %s\n", returnJsonChar);
	
    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
    printf("GenerateDataKey SUCCESSFULLY!\n");
	
    returnJsonChar = NAPI_Decrypt(cmk_base64, ciphertext_base64, input_aad_base64.c_str());
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("step1 Decrypt_Json = %s\n", returnJsonChar);
    printf("Decrypt step1 data SUCCESSFULLY!\n");

    /* generate a 48 bytes random data key and without plaint text returned */
    returnJsonChar = NAPI_GenerateDataKeyWithoutPlaintext(cmk_base64, len_gdk_without, input_aad_base64.c_str());
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_GenerateDataKeyWithoutPlaintext Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("GenerateDataKeyWithoutPlaintext_Json = %s\n", returnJsonChar);
	
    ciphertext_without_base64 = retJsonObj.readData_cstr("ciphertext");
    printf("GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");

    returnJsonChar = NAPI_Decrypt(cmk_base64, ciphertext_without_base64, input_aad_base64.c_str());
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("step2 Decrypt_Json = %s\n", returnJsonChar);
    printf("Decrypt step2 data SUCCESSFULLY!\n");
    
cleanup:
    SAFE_FREE(ciphertext_without_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_generate_datakey end==========\n");
}


/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. generate a cipher datakey without plaintext which encrypted by the CMK

step3. verify the cipher text could be decrypted by CMK correctly

step4. generate a new rsa key pair as the user-supplied asymmetric keymeterials.

step5. export the datakey with the new user public key

step6. verify that the new datakey cipher text could be decrypt succeed by the user rsa key pair

*/
void test_export_datakey()
{
    char* returnJsonChar = nullptr;

    char* cmk_base64 = nullptr;
    char* ukey_base64 = nullptr;
    char aad[] = "aadd";
    char* olddatakey_base64 = nullptr;

    char* plaintext_base64;
    uint32_t keylen = 48;
    RetJsonObj retJsonObj;
    std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

    printf("============test_export_datakey start==========\n");

    /* create an aes-128 key as the cmk */
    returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    cmk_base64 = retJsonObj.readData_cstr("cmk");
    printf("cmk_base64 : %s\n", cmk_base64);
    printf("Create CMK with AES 128 SUCCESSFULLY!\n");

    /* generate a 48 bytes random data key and without plaint text returned */
    returnJsonChar = NAPI_GenerateDataKeyWithoutPlaintext(cmk_base64, keylen, input_aad_base64.c_str());
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_GenerateDataKeyWithoutPlaintext Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    olddatakey_base64 = retJsonObj.readData_cstr("ciphertext");
    printf("olddatakey_base64 : %s\n", olddatakey_base64);
    printf("NAPI_GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");

    /* try to use the cmk to decrypt the datakey */
    returnJsonChar = NAPI_Decrypt(cmk_base64, olddatakey_base64, input_aad_base64.c_str());
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("Failed to NAPI_Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    plaintext_base64 = retJsonObj.readData_cstr("plaintext");
    printf("Decrypted plaintext_base64 : %s\n", plaintext_base64);
    printf("NAPI_Decrypt data SUCCESSFULLY!\n");

    /* create an EHM_RSA_3072 key as the ukey */
    returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    ukey_base64 = retJsonObj.readData_cstr("cmk");
    printf("ukey_base64 : %s\n", ukey_base64);
    printf("NAPI_CreateKey CMK with RSA SUCCESSFULLY!\n");

    /* export the datakey with the new user public key */
    returnJsonChar = NAPI_ExportDataKey(cmk_base64, ukey_base64, input_aad_base64.c_str(), olddatakey_base64);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_ExportDataKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_ExportDataKey Json : %s\n", returnJsonChar);
    printf("NAPI_ExportDataKey SUCCESSFULLY!\n");

cleanup:
    SAFE_FREE(returnJsonChar);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(ukey_base64);
    SAFE_FREE(olddatakey_base64);
    SAFE_FREE(plaintext_base64);
    printf("============test_export_datakey end==========\n");
}

void test_GenerateQuote_and_VerifyQuote()
{
    printf("============test_GenerateQuote_and_VerifyQuote start==========\n");
    char challenge[32] = "challenge123456";
    char nonce[16] = "nonce123456";

    RetJsonObj retJsonObj;
    char* returnJsonChar = nullptr;
    char* quote_base64 = nullptr;

    returnJsonChar = NAPI_GenerateQuote(challenge);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_GenerateQuote failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_GenerateQuote Json : %s\n", returnJsonChar);
    printf("NAPI_GenerateQuote SUCCESSFULLY!\n");

    quote_base64 = retJsonObj.readData_cstr("quote");
    printf("quote_base64 : %s\n", quote_base64);

    returnJsonChar = NAPI_VerifyQuote(quote_base64, nonce);
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_VerifyQuote failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_VerifyQuote Json : %s\n", returnJsonChar);
    printf("NAPI_VerifyQuote SUCCESSFULLY!\n");

cleanup:
    SAFE_FREE(returnJsonChar);
    printf("============test_GenerateQuote_and_VerifyQuote end==========\n");
}

int main(int argc, char* argv[])
{
    ehsm_status_t ret = EH_OK;

    ret = Initialize();
    if (ret != EH_OK) {
        printf("Initialize failed %d\n", ret);
        return ret;
    }
    printf("Initialize done\n");

    test_AES128();

    test_RSA3072_encrypt_decrypt();

    test_RSA3072_sign_verify();

    test_generate_datakey();

    test_export_datakey();

    test_GenerateQuote_and_VerifyQuote();

    Finalize();

    printf("All of tests done\n");

    return ret;
}