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

using namespace EHsmProvider;

/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. encrypt a plaintext by the CMK

step3. decrypt the cipher text by CMK correctly

*/
void test_AES128()
{
    RetJsonObj retJsonObj;
    char* returnJsonChar;
    char* plaintext = "Test1234-AES128";
    char* aad = "challenge";
    printf("============test_AES128 start==========\n");

    returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
    if(returnJsonChar == nullptr){
        printf("Createkey with aes-gcm-128 failed!\n");
        goto out;  
    }
    printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
    printf("Create CMK with AES-128 SUCCESSFULLY!\n");

    char* cmk_base64;
    cmk_base64 = retJsonObj.parseStringData(returnJsonChar, "cmk_base64");

    returnJsonChar = NAPI_Encrypt(cmk_base64, plaintext, aad);
    if(returnJsonChar == nullptr){
        printf("Failed to Encrypt the plaittext data\n");
        goto out; 
    }
    printf("NAPI_Encrypt json = %s\n", returnJsonChar);
    printf("Encrypt data SUCCESSFULLY!\n");

    char* ciphertext_base64;
    ciphertext_base64 = retJsonObj.parseStringData(returnJsonChar, "ciphertext_base64");

    returnJsonChar = NAPI_Decrypt(cmk_base64, ciphertext_base64, aad);
    if(returnJsonChar == nullptr){
        printf("Failed to Decrypt the data\n");
        goto out; 
    }
    printf("NAPI_Decrypt json = %s\n", returnJsonChar);
    char* plaintext_base64;
    plaintext_base64 = retJsonObj.parseStringData(returnJsonChar, "plaintext_base64");
    printf("plaintext = %s\n",base64_decode(plaintext_base64).c_str());
    printf("Decrypt data SUCCESSFULLY!\n");
    
out:
    printf("============test_AES128 end==========\n");
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

    Finalize();

    printf("All of tests done\n");

    return ret;
}

