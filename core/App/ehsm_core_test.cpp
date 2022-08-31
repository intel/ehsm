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
#include "openssl/rsa.h"

#include <pthread.h>
#include <chrono>

using namespace EHsmProvider;

#define PERF_NUM 1000

#define NUM_THREADS   100

void test_perf_createkey()
{
    // RetJsonObj retJsonObj;
    // char* returnJsonChar = nullptr;

    // // Start measuring time
    // auto begin = std::chrono::high_resolution_clock::now();

    // for (int i = 0; i < PERF_NUM*100; i++) {
    //     returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
    //     retJsonObj.parse(returnJsonChar);

    //     if(retJsonObj.getCode() != 200){
    //         printf("Createkey with aes-128 failed in time(%d)\n", i);
    //         SAFE_FREE(returnJsonChar);
    //         break;
    //     }
    //     SAFE_FREE(returnJsonChar);
    // }

    // // Stop measuring time and calculate the elapsed time
    // auto end = std::chrono::high_resolution_clock::now();
    // auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

    // printf("Time measured of CreateKey(AES_128) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM*100, elapsed.count() * 1e-9);

    // // Start measuring time
    // begin = std::chrono::high_resolution_clock::now();

    // for (int i = 0; i < PERF_NUM; i++) {
    //     returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
    //     retJsonObj.parse(returnJsonChar);

    //     if(retJsonObj.getCode() != 200){
    //         printf("Createkey with rsa-3072 failed in time(%d)\n", i);
    //         SAFE_FREE(returnJsonChar);
    //         break;
    //     }
    //     SAFE_FREE(returnJsonChar);
    // }

    // // Stop measuring time and calculate the elapsed time
    // end = std::chrono::high_resolution_clock::now();
    // elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    // printf("Time measured of CreateKey(RSA_3072) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM, elapsed.count() * 1e-9);
}

void test_perf_encrypt()
{
//     char* returnJsonChar = nullptr;
//     char plaintext[32] = "helloworld";
//     char aad[] = "challenge";

//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     char* cmk_base64 = nullptr;
//     char* plaintext_base64 = nullptr;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));
//     std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

//     RetJsonObj retJsonObj;
//     returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);

//     if(retJsonObj.getCode() != 200){
//         printf("Createkey with aes-gcm-128 failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     //printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for(int i=0; i<PERF_NUM*100; i++){
//         returnJsonChar = NAPI_Encrypt(cmk_base64, input_plaintext_base64.c_str(), input_aad_base64.c_str());
//         retJsonObj.parse(returnJsonChar);

//         if(retJsonObj.getCode() != 200){
//             printf("failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         //printf("NAPI_Encrypt json = %s\n", returnJsonChar);
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of Encrypt(AES_128) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM*100, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(plaintext_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);
}

void test_perf_decrypt()
{
//     char* returnJsonChar = nullptr;
//     char plaintext[32] = "helloworld";
//     char aad[] = "challenge";

//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     char* cmk_base64 = nullptr;
//     char* plaintext_base64 = nullptr;
//     char* ciphertext_base64 = nullptr;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));
//     std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

//     RetJsonObj retJsonObj;
//     returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);

//     if(retJsonObj.getCode() != 200){
//         printf("Createkey with aes-gcm-128 failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     //printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     returnJsonChar = NAPI_Encrypt(cmk_base64, input_plaintext_base64.c_str(), input_aad_base64.c_str());
//     retJsonObj.parse(returnJsonChar);

//     if(retJsonObj.getCode() != 200){
//         printf("failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }

//     //printf("NAPI_Encrypt json = %s\n", returnJsonChar);
//     //printf("Encrypt data SUCCESSFULLY!\n");

//     ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for(int i=0; i<PERF_NUM*100; i++){
//         returnJsonChar = NAPI_Decrypt(cmk_base64, ciphertext_base64, input_aad_base64.c_str());
//         retJsonObj.parse(returnJsonChar);

//         if(retJsonObj.getCode() != 200){
//             printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         //printf("NAPI_Encrypt json = %s\n", returnJsonChar);
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of Decrypt(AES_128) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM*100, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(ciphertext_base64);
//     SAFE_FREE(plaintext_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);
}

void test_perf_sign()
{
//     ehsm_status_t ret = EH_OK;
//     char* returnJsonChar = nullptr;
//     ehsm_data_t digest;

//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     char* cmk_base64 = nullptr;
//     bool result = false;
//     RetJsonObj retJsonObj;
//     std::string input_digest_base64;

//     returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     // printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
//     // printf("Create CMK with RAS SUCCESSFULLY!\n");

//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     digest.datalen = 256;
//     digest.data = (uint8_t*)malloc(digest.datalen);
//     if (digest.data == NULL) {
//     }
//     memset(digest.data, 'B', digest.datalen);
//     input_digest_base64 = base64_encode(digest.data, digest.datalen);

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for(int i=0; i<PERF_NUM; i++){
//         returnJsonChar = NAPI_Sign(cmk_base64, input_digest_base64.c_str());
//         retJsonObj.parse(returnJsonChar);
//         if(retJsonObj.getCode() != 200){
//             printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         //printf("NAPI_Encrypt json = %s\n", returnJsonChar);
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of Sign(RSA_3072) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(digest.data);
//     SAFE_FREE(returnJsonChar);
}

void test_perf_verify()
{
//     ehsm_status_t ret = EH_OK;
//     char* returnJsonChar = nullptr;
//     ehsm_data_t digest;

//     char* cmk_base64 = nullptr;
//     char* signature_base64 = nullptr;
//     bool result = false;
//     RetJsonObj retJsonObj;
//     std::string input_digest_base64;

//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     // printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
//     // printf("Create CMK with RAS SUCCESSFULLY!\n");

//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     digest.datalen = 256;
//     digest.data = (uint8_t*)malloc(digest.datalen);
//     if (digest.data == NULL) {
//     }
//     memset(digest.data, 'B', digest.datalen);
//     input_digest_base64 = base64_encode(digest.data, digest.datalen);

//     returnJsonChar = NAPI_Sign(cmk_base64, input_digest_base64.c_str());
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     // printf("NAPI_Sign Json = %s\n", returnJsonChar);
//     signature_base64 = retJsonObj.readData_cstr("signature");
//     // printf("Sign data SUCCESSFULLY!\n");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for(int i=0; i<PERF_NUM; i++){
//         returnJsonChar = NAPI_Verify(cmk_base64, input_digest_base64.c_str(), signature_base64);
//         retJsonObj.parse(returnJsonChar);
//         if(retJsonObj.getCode() != 200){
//             printf("NAPI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of Verify(RSA_3072) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(signature_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(digest.data);
//     SAFE_FREE(returnJsonChar);
}

void test_perf_asymmetricencrypt()
{
//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     char* returnJsonChar = nullptr;
//     char plaintext[32] = "TestRSA-3072";
//     char* cmk_base64 = nullptr;
//     RetJsonObj retJsonObj;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));

//     returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     // printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
//     // printf("Create CMK with RAS SUCCESSFULLY!\n");

//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for(int i=0; i<PERF_NUM; i++){
//         returnJsonChar = NAPI_AsymmetricEncrypt(cmk_base64, input_plaintext_base64.c_str());
//         retJsonObj.parse(returnJsonChar);
//         if(retJsonObj.getCode() != 200){
//             printf("NAPI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
//     printf("Time measured of AsymmetricEncrypt(RSA_3072) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);
}

void test_perf_asymmetricdecrypt()
{
//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     char* returnJsonChar = nullptr;
//     char plaintext[32] = "TestRSA-3072";
//     char* cmk_base64 = nullptr;
//     char* ciphertext_base64 = nullptr;
//     char* plaintext_base64 = nullptr;
//     RetJsonObj retJsonObj;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));

//     returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     // printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
//     // printf("Create CMK with RAS SUCCESSFULLY!\n");

//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     returnJsonChar = NAPI_AsymmetricEncrypt(cmk_base64, input_plaintext_base64.c_str());
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     // printf("NAPI_AsymmetricEncrypt json : %s\n", returnJsonChar);
//     // printf("NAPI_AsymmetricEncrypt data SUCCESSFULLY!\n");

//     ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

//         // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for(int i=0; i<PERF_NUM; i++){
//         returnJsonChar = NAPI_AsymmetricDecrypt(cmk_base64, ciphertext_base64);
//         retJsonObj.parse(returnJsonChar);
//         if(retJsonObj.getCode() != 200){
//             printf("NAPI_AsymmetricDecrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         // printf("NAPI_AsymmetricDecrypt json : %s\n", returnJsonChar);
//         // plaintext_base64 = retJsonObj.readData_cstr("plaintext");
//         // printf("Decrypted plaintext : %s\n", plaintext_base64);
//         // printf("(%d) NAPI_AsymmetricDecrypt data SUCCESSFULLY!\n", i);

//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
//     printf("Time measured of AsymmetricDecrypt(RSA_3072) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(ciphertext_base64);
//     SAFE_FREE(plaintext_base64);
//     SAFE_FREE(returnJsonChar);
}

void *test_createkey(void *threadid)
{
//     RetJsonObj retJsonObj;
//     char* returnJsonChar = nullptr;
//     long tid = (long)threadid;

//     for (int i = 0; i < PERF_NUM; i++) {
//         returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
//         retJsonObj.parse(returnJsonChar);

//         if(retJsonObj.getCode() != 200){
//             printf("Createkey with aes-128 failed in time(%d)\n", i);
//             SAFE_FREE(returnJsonChar);
//             break;
//         }
//         SAFE_FREE(returnJsonChar);
//         printf("Thread[%ld], CreateKey(AES-128) succeed in time[%d]\n", tid, i);
//     }

//    pthread_exit(NULL);
}

void test_multi_createkey()
{
    void *status;
    pthread_t threads[NUM_THREADS];
    int rc;
    int i;
    for( i=0; i < NUM_THREADS; i++ ){
        printf("creating thread [%d]\n", i);
        rc = pthread_create(&threads[i], NULL, test_createkey, (void *)i);
        if (rc){
            printf("Error(%d):unable to create thread\n", rc);
            exit(-1);
        }
    }

    for( i = 0; i < NUM_THREADS; i++ ) {
        rc = pthread_join(threads[i], &status);
        if (rc) {
            printf("Error(%d) to join with thread[%d]\n", rc, i);
            exit(-1);
        }
        printf("Main: completed thread[%d]\n", i);
    }
    pthread_exit(NULL);
}

void *test_encrypt(void *threadid)
{
//     long tid = (long)threadid;
//     char* returnJsonChar = nullptr;
//     char plaintext[32] = "helloworld";
//     char aad[] = "challenge";

//     printf("Thread[%ld]. plaintext is %s\n", tid, plaintext);

//     char* cmk_base64 = nullptr;
//     char* plaintext_base64 = nullptr;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));
//     std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

//     RetJsonObj retJsonObj;
//     returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);

//     if(retJsonObj.getCode() != 200){
//         printf("Thread[%ld], Createkey with aes-gcm-128 failed, error message: %s \n", tid, retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     printf("Thread[%ld], NAPI_CreateKey Json = %s\n",tid, returnJsonChar);
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     for(int i=0; i<PERF_NUM; i++){
//         returnJsonChar = NAPI_Encrypt(cmk_base64, input_plaintext_base64.c_str(), input_aad_base64.c_str());
//         retJsonObj.parse(returnJsonChar);

//         if(retJsonObj.getCode() != 200){
//             printf("Thread[%ld] with time[%d], failed to Encrypt the plaittext data, error message: %s \n", tid, i, retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }

//         printf("Thread[%ld] with time[%d], NAPI_Encrypt json = %s\n", tid, i, returnJsonChar);

//         SAFE_FREE(returnJsonChar);
//     }

// cleanup:
//     SAFE_FREE(plaintext_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);

//     pthread_exit(NULL);
}

void test_multi_encrypt()
{
    void *status;
    pthread_t threads[NUM_THREADS];
    int rc;
    int i;
    for( i=0; i < NUM_THREADS; i++ ){
        printf("creating thread [%d]\n", i);
        rc = pthread_create(&threads[i], NULL, test_encrypt, (void *)i);
        if (rc){
            printf("Error(%d):unable to create thread\n", rc);
            exit(-1);
        }
    }

    for( i = 0; i < NUM_THREADS; i++ ) {
        rc = pthread_join(threads[i], &status);
        if (rc) {
            printf("Error(%d) to join with thread[%d]\n", rc, i);
            exit(-1);
        }
        printf("Main: completed thread[%d]\n", i);
    }
    pthread_exit(NULL);
}

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
    std::string cmk_base64;
    std::string ciphertext_base64;
    char* plaintext_base64 = nullptr;
    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));
    std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

    RetJsonObj retJsonObj;
    JsonObj key_json;
    key_json.addData_uint16("keyspec", EH_AES_GCM_128);
    key_json.addData_uint16("origin", 0);
    key_json.addData_uint16("purpose", 1);
    returnJsonChar = NAPI_CreateKey((key_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Createkey with aes-gcm-128 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
    printf("Create CMK with AES-128 SUCCESSFULLY!\n");
    cmk_base64 = retJsonObj.readData_string("cmk");
    key_json.addData_string("cmk_base64", cmk_base64);
    key_json.addData_string("plaintext_base64", input_plaintext_base64);
    key_json.addData_string("aad_base64", input_aad_base64);

    returnJsonChar = NAPI_Encrypt((key_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Encrypt json = %s\n", returnJsonChar);
    printf("Encrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_string("ciphertext");
    key_json.addData_string("ciphertext_base64", ciphertext_base64);
    key_json.addData_uint16("purpose", 0);
    returnJsonChar = NAPI_Decrypt((key_json.toString()).c_str());
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
    SAFE_FREE(returnJsonChar);
    printf("============test_AES128 end==========\n");
}

void test_AES192()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "Test1234-AES192";
    char aad[] = "challenge";
    printf("============test_AES192start==========\n");
    std::string cmk_base64;
    std::string ciphertext_base64;
    char* plaintext_base64 = nullptr;
    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));
    std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

    RetJsonObj retJsonObj;
    JsonObj key_json;
    key_json.addData_uint16("keyspec", EH_AES_GCM_192);
    key_json.addData_uint16("origin", 0);
    key_json.addData_uint16("purpose", 0);
    returnJsonChar = NAPI_CreateKey((key_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Createkey with aes-gcm-192 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
    printf("Create CMK with AES-192 SUCCESSFULLY!\n");
    cmk_base64 = retJsonObj.readData_string("cmk");
    key_json.addData_string("cmk_base64", cmk_base64);
    key_json.addData_string("plaintext_base64", input_plaintext_base64);
    key_json.addData_string("aad_base64", input_aad_base64);

    returnJsonChar = NAPI_Encrypt((key_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Encrypt json = %s\n", returnJsonChar);
    printf("Encrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_string("ciphertext");
    key_json.addData_string("ciphertext_base64", ciphertext_base64);
    returnJsonChar = NAPI_Decrypt((key_json.toString()).c_str());
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
    SAFE_FREE(returnJsonChar);
    printf("============test_AES192 end==========\n");
}

void test_AES256()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "Test1234-AES256";
    char aad[] = "challenge";
    printf("============test_AES256 start==========\n");
    std::string cmk_base64;
    std::string ciphertext_base64;
    char* plaintext_base64 = nullptr;
    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));
    std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

    RetJsonObj retJsonObj;
    JsonObj key_json;
    key_json.addData_uint16("keyspec", EH_AES_GCM_256);
    key_json.addData_uint16("origin", 0);
    key_json.addData_uint16("purpose", 0);
    returnJsonChar = NAPI_CreateKey((key_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Createkey with aes-gcm-256 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
    printf("Create CMK with AES-256 SUCCESSFULLY!\n");
    cmk_base64 = retJsonObj.readData_string("cmk");
    key_json.addData_string("cmk_base64", cmk_base64);
    key_json.addData_string("plaintext_base64", input_plaintext_base64);
    key_json.addData_string("aad_base64", input_aad_base64);

    returnJsonChar = NAPI_Encrypt((key_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Encrypt json = %s\n", returnJsonChar);
    printf("Encrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_string("ciphertext");
    key_json.addData_string("ciphertext_base64", ciphertext_base64);
    returnJsonChar = NAPI_Decrypt((key_json.toString()).c_str());
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
    SAFE_FREE(returnJsonChar);
    printf("============test_AES256 end==========\n");
}

void test_SM4()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "Test1234-SM4";
    char aad[] = "challenge";
    printf("============test_SM4 start==========\n");
    std::string cmk_base64;
    std::string ciphertext_base64;
    char* plaintext_base64 = nullptr;
    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));
    std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

    RetJsonObj retJsonObj;
    JsonObj key_json;
    key_json.addData_uint16("keyspec", EH_SM4);
    key_json.addData_uint16("origin", 0);
    key_json.addData_uint16("purpose", 0);
    returnJsonChar = NAPI_CreateKey((key_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Createkey with sm4 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json = %s\n", returnJsonChar);
    printf("Create CMK with SM4 SUCCESSFULLY!\n");
    cmk_base64 = retJsonObj.readData_string("cmk");
    key_json.addData_string("cmk_base64", cmk_base64);
    key_json.addData_string("plaintext_base64", input_plaintext_base64);
    key_json.addData_string("aad_base64", input_aad_base64);

    returnJsonChar = NAPI_Encrypt((key_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if(retJsonObj.getCode() != 200){
        printf("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Encrypt json = %s\n", returnJsonChar);
    printf("Encrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_string("ciphertext");
    key_json.addData_string("ciphertext_base64", ciphertext_base64);
    returnJsonChar = NAPI_Decrypt((key_json.toString()).c_str());
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
    SAFE_FREE(returnJsonChar);
    printf("============test_SM4 end==========\n");
}


void test_RSA2048_encrypt_decrypt()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "TestRSA-2048";
    char* cmk_base64 = nullptr;
    char* ciphertext_base64 = nullptr;
    char* plaintext_base64 = nullptr;
    RetJsonObj retJsonObj;

    JsonObj paramJsonCreatekey;
    JsonObj paramJsonDecrypt;
    JsonObj paramJsonEncrypt;

    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));

    paramJsonCreatekey.addData_uint16("keyspec", EH_RSA_2048);
    paramJsonCreatekey.addData_uint16("padding_mode", RSA_PKCS1_OAEP_PADDING);

    printf("============test_RSA2048_encrypt_decrypt start==========\n");

    returnJsonChar = NAPI_CreateKey(paramJsonCreatekey.StringToChar(paramJsonCreatekey.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    paramJsonEncrypt.addData_string("cmk_base64", cmk_base64);
    paramJsonEncrypt.addData_string("plaintext_base64", input_plaintext_base64);

    returnJsonChar = NAPI_AsymmetricEncrypt(paramJsonEncrypt.StringToChar(paramJsonEncrypt.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricEncrypt json : %s\n", returnJsonChar);
    printf("NAPI_AsymmetricEncrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

    paramJsonDecrypt.addData_string("cmk_base64", cmk_base64);
    paramJsonDecrypt.addData_string("ciphertext_base64", ciphertext_base64);

    returnJsonChar = NAPI_AsymmetricDecrypt(paramJsonDecrypt.StringToChar(paramJsonDecrypt.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricDecrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricDecrypt json : %s\n", returnJsonChar);
    plaintext_base64 = retJsonObj.readData_cstr("plaintext");
    printf("Decrypted plaintext : %s\n", plaintext_base64);

    if (!strcmp(plaintext_base64, input_plaintext_base64.data()))
        printf("NAPI_AsymmetricDecrypt data SUCCESSFULLY!\n");
    else {
        printf("NAPI_AsymmetricDecrypt data FAILED!\n");
        goto cleanup;
    }

cleanup:
    SAFE_FREE(cmk_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(plaintext_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_RSA2048_encrypt_decrypt End==========\n");
}

void test_RSA3072_encrypt_decrypt()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "TestRSA-3072";
    char* cmk_base64 = nullptr;
    char* ciphertext_base64 = nullptr;
    char* plaintext_base64 = nullptr;
    RetJsonObj retJsonObj;

    JsonObj paramJsonCreatekey;
    JsonObj paramJsonEncrypt;
    JsonObj paramJsonDecrypt;

    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));

    paramJsonCreatekey.addData_uint16("keyspec", EH_RSA_3072);
    paramJsonCreatekey.addData_uint16("padding_mode", RSA_PKCS1_OAEP_PADDING);

    printf("============test_RSA3072_encrypt_decrypt start==========\n");

    returnJsonChar = NAPI_CreateKey(paramJsonCreatekey.StringToChar(paramJsonCreatekey.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    paramJsonEncrypt.addData_string("cmk_base64", cmk_base64);
    paramJsonEncrypt.addData_string("plaintext_base64", input_plaintext_base64);

    returnJsonChar = NAPI_AsymmetricEncrypt(paramJsonEncrypt.StringToChar(paramJsonEncrypt.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricEncrypt json : %s\n", returnJsonChar);
    printf("NAPI_AsymmetricEncrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

    paramJsonDecrypt.addData_string("cmk_base64", cmk_base64);
    paramJsonDecrypt.addData_string("ciphertext_base64", ciphertext_base64);

    returnJsonChar = NAPI_AsymmetricDecrypt(paramJsonDecrypt.StringToChar(paramJsonDecrypt.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricDecrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricDecrypt json : %s\n", returnJsonChar);
    plaintext_base64 = retJsonObj.readData_cstr("plaintext");
    printf("Decrypted plaintext : %s\n", plaintext_base64);
    if (!strcmp(plaintext_base64, input_plaintext_base64.data()))
        printf("NAPI_AsymmetricDecrypt data SUCCESSFULLY!\n");
    else {
        printf("NAPI_AsymmetricDecrypt data FAILED!\n");
        goto cleanup;
    }

cleanup:
    SAFE_FREE(cmk_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(plaintext_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_RSA3072_encrypt_decrypt End==========\n");
}

void test_RSA4096_encrypt_decrypt()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "TestRSA-4096";
    char* cmk_base64 = nullptr;
    char* ciphertext_base64 = nullptr;
    char* plaintext_base64 = nullptr;
    RetJsonObj retJsonObj;

    JsonObj paramJsonCreatekey;
    JsonObj paramJsonEncrypt;
    JsonObj paramJsonDecrypt;

    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));

    paramJsonCreatekey.addData_uint16("keyspec", EH_RSA_4096);
    paramJsonCreatekey.addData_uint16("padding_mode", RSA_PKCS1_OAEP_PADDING);

    printf("============test_RSA4096_encrypt_decrypt start==========\n");

    returnJsonChar = NAPI_CreateKey(paramJsonCreatekey.StringToChar(paramJsonCreatekey.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    paramJsonEncrypt.addData_string("cmk_base64", cmk_base64);
    paramJsonEncrypt.addData_string("plaintext_base64", input_plaintext_base64);

    returnJsonChar = NAPI_AsymmetricEncrypt(paramJsonEncrypt.StringToChar(paramJsonEncrypt.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricEncrypt json : %s\n", returnJsonChar);
    printf("NAPI_AsymmetricEncrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

    paramJsonDecrypt.addData_string("cmk_base64", cmk_base64);
    paramJsonDecrypt.addData_string("ciphertext_base64", ciphertext_base64);

    returnJsonChar = NAPI_AsymmetricDecrypt(paramJsonDecrypt.StringToChar(paramJsonDecrypt.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricDecrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricDecrypt json : %s\n", returnJsonChar);
    plaintext_base64 = retJsonObj.readData_cstr("plaintext");
    printf("Decrypted plaintext : %s\n", plaintext_base64);
    if (!strcmp(plaintext_base64, input_plaintext_base64.data()))
        printf("NAPI_AsymmetricDecrypt data SUCCESSFULLY!\n");
    else {
        printf("NAPI_AsymmetricDecrypt data FAILED!\n");
        goto cleanup;
    }

cleanup:
    SAFE_FREE(cmk_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(plaintext_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_RSA4096_encrypt_decrypt End==========\n");
}

void test_sm2_encrypt_decrypt()
{
    char* returnJsonChar = nullptr;
    char plaintext[] = "Test1234-SM2";
    char* cmk_base64 = nullptr;
    char* ciphertext_base64 = nullptr;
    char* plaintext_base64 = nullptr;
    RetJsonObj retJsonObj;

    JsonObj paramJsonCreatekey;
    JsonObj paramJsonEncrypt;
    JsonObj paramJsonDecrypt;

    std::string input_plaintext_base64 = base64_encode((const uint8_t*)plaintext, sizeof(plaintext)/sizeof(plaintext[0]));

    paramJsonCreatekey.addData_uint16("keyspec", EH_EC_SM2);
    paramJsonCreatekey.addData_uint16("padding_mode", RSA_PKCS1_OAEP_PADDING);

    printf("============test_sm2_encrypt_decrypt start==========\n");

    returnJsonChar = NAPI_CreateKey(paramJsonCreatekey.StringToChar(paramJsonCreatekey.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with SM2 SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    paramJsonEncrypt.addData_string("cmk_base64", cmk_base64);
    paramJsonEncrypt.addData_string("plaintext_base64", input_plaintext_base64);

    returnJsonChar = NAPI_AsymmetricEncrypt(paramJsonEncrypt.StringToChar(paramJsonEncrypt.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricEncrypt json : %s\n", returnJsonChar);
    printf("NAPI_AsymmetricEncrypt data SUCCESSFULLY!\n");

    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

    paramJsonDecrypt.addData_string("cmk_base64", cmk_base64);
    paramJsonDecrypt.addData_string("ciphertext_base64", ciphertext_base64);

    returnJsonChar = NAPI_AsymmetricDecrypt(paramJsonDecrypt.StringToChar(paramJsonDecrypt.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_AsymmetricDecrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_AsymmetricDecrypt json : %s\n", returnJsonChar);
    plaintext_base64 = retJsonObj.readData_cstr("plaintext");
    printf("Decrypted plaintext : %s\n", plaintext_base64);
    if (!strcmp(plaintext_base64, input_plaintext_base64.data()))
        printf("NAPI_AsymmetricDecrypt data SUCCESSFULLY!\n");
    else {
        printf("NAPI_AsymmetricDecrypt data FAILED!\n");
        goto cleanup;
    }

cleanup:
    SAFE_FREE(cmk_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(plaintext_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_sm2_encrypt_decrypt End==========\n");
}

/*

step1. generate an rsa 3072 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_RSA3072_sign_verify()
{
    ehsm_status_t ret = EH_OK;
    char* returnJsonChar = nullptr;
    ehsm_data_t digest;

    char* cmk_base64 = nullptr;
    char* signature_base64 = nullptr;
    bool result = false;
    RetJsonObj retJsonObj;
    std::string input_digest_base64;

    JsonObj paramJsonCreatekey;
    JsonObj paramJsonSign;
    JsonObj paramJsonVerify;

    paramJsonCreatekey.addData_uint16("keyspec", EH_RSA_3072);
    paramJsonCreatekey.addData_uint16("padding_mode", RSA_PKCS1_PSS_PADDING);
    paramJsonCreatekey.addData_uint16("digest_mode", EH_SHA_2_512);
    printf("============test_RSA3072_sign_verify start==========\n");
    returnJsonChar = NAPI_CreateKey(paramJsonCreatekey.StringToChar(paramJsonCreatekey.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    digest.datalen = 64;
    digest.data = (uint8_t*)malloc(digest.datalen);
    if (digest.data == NULL) {
    }
    memset(digest.data, 'D', digest.datalen);
    input_digest_base64 = base64_encode(digest.data, digest.datalen);

    paramJsonSign.addData_string("cmk_base64", cmk_base64);
    paramJsonSign.addData_string("digest_base64", input_digest_base64);

    returnJsonChar = NAPI_Sign(paramJsonSign.StringToChar(paramJsonSign.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Sign Json = %s\n", returnJsonChar);
    signature_base64 = retJsonObj.readData_cstr("signature");
    printf("Sign data SUCCESSFULLY!\n");

    paramJsonVerify.addData_string("cmk_base64", cmk_base64);
    paramJsonVerify.addData_string("digest_base64", input_digest_base64);
    paramJsonVerify.addData_string("signature_base64", signature_base64);

    returnJsonChar = NAPI_Verify(paramJsonVerify.StringToChar(paramJsonVerify.toString()));
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
    printf("============test_RSA3072_sign_verify end==========\n");
    printf("\n");
}

/*

step1. generate an rsa 2048 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_RSA2048_sign_verify()
{
    ehsm_status_t ret = EH_OK;
    char* returnJsonChar = nullptr;
    ehsm_data_t digest;

    char* cmk_base64 = nullptr;
    char* signature_base64 = nullptr;
    bool result = false;
    RetJsonObj retJsonObj;
    std::string input_digest_base64;

    JsonObj paramJsonCreatekey;
    JsonObj paramJsonSign;
    JsonObj paramJsonVerify;

    paramJsonCreatekey.addData_uint16("keyspec", EH_RSA_2048);
    paramJsonCreatekey.addData_uint16("padding_mode", RSA_PKCS1_PSS_PADDING);
    paramJsonCreatekey.addData_uint16("digest_mode", EH_SHA1);
    printf("============test_RSA2048_sign_verify start==========\n");
    returnJsonChar = NAPI_CreateKey(paramJsonCreatekey.StringToChar(paramJsonCreatekey.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    digest.datalen = 64;
    digest.data = (uint8_t*)malloc(digest.datalen);
    if (digest.data == NULL) {
    }
    memset(digest.data, 'D', digest.datalen);
    input_digest_base64 = base64_encode(digest.data, digest.datalen);

    paramJsonSign.addData_string("cmk_base64", cmk_base64);
    paramJsonSign.addData_string("digest_base64", input_digest_base64);

    returnJsonChar = NAPI_Sign(paramJsonSign.StringToChar(paramJsonSign.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Sign Json = %s\n", returnJsonChar);
    signature_base64 = retJsonObj.readData_cstr("signature");
    printf("Sign data SUCCESSFULLY!\n");

    paramJsonVerify.addData_string("cmk_base64", cmk_base64);
    paramJsonVerify.addData_string("digest_base64", input_digest_base64);
    paramJsonVerify.addData_string("signature_base64", signature_base64);

    returnJsonChar = NAPI_Verify(paramJsonVerify.StringToChar(paramJsonVerify.toString()));
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
    printf("============test_RSA2048_sign_verify end==========\n");
    printf("\n");
}

/*

step1. generate an rsa 4096 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_RSA4096_sign_verify()
{
    ehsm_status_t ret = EH_OK;
    char* returnJsonChar = nullptr;
    ehsm_data_t digest;

    char* cmk_base64 = nullptr;
    char* signature_base64 = nullptr;
    bool result = false;
    RetJsonObj retJsonObj;
    std::string input_digest_base64;

    JsonObj paramJsonCreatekey;
    JsonObj paramJsonSign;
    JsonObj paramJsonVerify;

    paramJsonCreatekey.addData_uint16("keyspec", EH_RSA_4096);
    paramJsonCreatekey.addData_uint16("padding_mode", RSA_PKCS1_PADDING);
    paramJsonCreatekey.addData_uint16("digest_mode", EH_MD5);
    printf("============test_RSA4096_sign_verify start==========\n");
    returnJsonChar = NAPI_CreateKey(paramJsonCreatekey.StringToChar(paramJsonCreatekey.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    digest.datalen = 64;
    digest.data = (uint8_t*)malloc(digest.datalen);
    if (digest.data == NULL) {
    }
    memset(digest.data, 'D', digest.datalen);
    input_digest_base64 = base64_encode(digest.data, digest.datalen);

    paramJsonSign.addData_string("cmk_base64", cmk_base64);
    paramJsonSign.addData_string("digest_base64", input_digest_base64);

    returnJsonChar = NAPI_Sign(paramJsonSign.StringToChar(paramJsonSign.toString()));
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Sign Json = %s\n", returnJsonChar);
    signature_base64 = retJsonObj.readData_cstr("signature");
    printf("Sign data SUCCESSFULLY!\n");

    paramJsonVerify.addData_string("cmk_base64", cmk_base64);
    paramJsonVerify.addData_string("digest_base64", input_digest_base64);
    paramJsonVerify.addData_string("signature_base64", signature_base64);

    returnJsonChar = NAPI_Verify(paramJsonVerify.StringToChar(paramJsonVerify.toString()));
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
    printf("============test_RSA4096_sign_verify end==========\n");
    printf("\n");
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
//     printf("============test_generate_datakey start==========\n");
//     char* returnJsonChar = nullptr;
//     char aad[] = "challenge";
//     char* cmk_base64 = nullptr;
//     char* ciphertext_base64 = nullptr;
//     char* ciphertext_without_base64 = nullptr;
//     int len_gdk = 16;
//     int len_gdk_without = 48;
//     RetJsonObj retJsonObj;
//     std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

//     returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("Createkey with aes-gcm-128 failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     printf("ckReturn_Json = %s\n", returnJsonChar);
//     printf("Create CMK with AES-128 SUCCESSFULLY!\n");

//     /* generate a 16 bytes random data key and with plaint text returned */
//     cmk_base64 = retJsonObj.readData_cstr("cmk");
//     returnJsonChar = NAPI_GenerateDataKey(cmk_base64, len_gdk, input_aad_base64.c_str());
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("GenerateDataKey Failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     printf("GenerateDataKey_Json = %s\n", returnJsonChar);

//     ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
//     printf("GenerateDataKey SUCCESSFULLY!\n");

//     returnJsonChar = NAPI_Decrypt(cmk_base64, ciphertext_base64, input_aad_base64.c_str());
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     printf("step1 Decrypt_Json = %s\n", returnJsonChar);
//     printf("Decrypt step1 data SUCCESSFULLY!\n");

//     /* generate a 48 bytes random data key and without plaint text returned */
//     returnJsonChar = NAPI_GenerateDataKeyWithoutPlaintext(cmk_base64, len_gdk_without, input_aad_base64.c_str());
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_GenerateDataKeyWithoutPlaintext Failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     printf("GenerateDataKeyWithoutPlaintext_Json = %s\n", returnJsonChar);

//     ciphertext_without_base64 = retJsonObj.readData_cstr("ciphertext");
//     printf("GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");

//     returnJsonChar = NAPI_Decrypt(cmk_base64, ciphertext_without_base64, input_aad_base64.c_str());
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     printf("step2 Decrypt_Json = %s\n", returnJsonChar);
//     printf("Decrypt step2 data SUCCESSFULLY!\n");

// cleanup:
//     SAFE_FREE(ciphertext_without_base64);
//     SAFE_FREE(ciphertext_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);
//     printf("============test_generate_datakey end==========\n");
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
//     char* returnJsonChar = nullptr;

//     char* cmk_base64 = nullptr;
//     char* ukey_base64 = nullptr;
//     char aad[] = "aadd";
//     char* olddatakey_base64 = nullptr;

//     char* plaintext_base64;
//     uint32_t keylen = 48;
//     RetJsonObj retJsonObj;
//     std::string input_aad_base64 = base64_encode((const uint8_t*)aad, sizeof(aad)/sizeof(aad[0]));

//     printf("============test_export_datakey start==========\n");

//     /* create an aes-128 key as the cmk */
//     returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     cmk_base64 = retJsonObj.readData_cstr("cmk");
//     printf("cmk_base64 : %s\n", cmk_base64);
//     printf("Create CMK with AES 128 SUCCESSFULLY!\n");

//     /* generate a 48 bytes random data key and without plaint text returned */
//     returnJsonChar = NAPI_GenerateDataKeyWithoutPlaintext(cmk_base64, keylen, input_aad_base64.c_str());
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_GenerateDataKeyWithoutPlaintext Failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     olddatakey_base64 = retJsonObj.readData_cstr("ciphertext");
//     printf("olddatakey_base64 : %s\n", olddatakey_base64);
//     printf("NAPI_GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");

//     /* try to use the cmk to decrypt the datakey */
//     returnJsonChar = NAPI_Decrypt(cmk_base64, olddatakey_base64, input_aad_base64.c_str());
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("Failed to NAPI_Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     plaintext_base64 = retJsonObj.readData_cstr("plaintext");
//     printf("Decrypted plaintext_base64 : %s\n", plaintext_base64);
//     printf("NAPI_Decrypt data SUCCESSFULLY!\n");

//     /* create an EHM_RSA_3072 key as the ukey */
//     returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     ukey_base64 = retJsonObj.readData_cstr("cmk");
//     printf("ukey_base64 : %s\n", ukey_base64);
//     printf("NAPI_CreateKey CMK with RSA SUCCESSFULLY!\n");

//     /* export the datakey with the new user public key */
//     returnJsonChar = NAPI_ExportDataKey(cmk_base64, ukey_base64, input_aad_base64.c_str(), olddatakey_base64);
//     retJsonObj.parse(returnJsonChar);
//     if(retJsonObj.getCode() != 200){
//         printf("NAPI_ExportDataKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     printf("NAPI_ExportDataKey Json : %s\n", returnJsonChar);
//     printf("NAPI_ExportDataKey SUCCESSFULLY!\n");

// cleanup:
//     SAFE_FREE(returnJsonChar);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(ukey_base64);
//     SAFE_FREE(olddatakey_base64);
//     SAFE_FREE(plaintext_base64);
//     printf("============test_export_datakey end==========\n");
}

void test_GenerateQuote_and_VerifyQuote()
{
    printf("============test_GenerateQuote_and_VerifyQuote start==========\n");
    char challenge[32] = "challenge123456";
    char nonce[16] = "nonce123456";
    // the string generated after converting the value of mr_signer and mr_enclave to hexadecimal
    // notice: these 2 values will be changed if our enclave has been updated. then the case may be failed.
    // you can get mr_signer and mr_enclave through cmd:
    // "/opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave libenclave-ehsm-core.signed.so -dumpfile out.log"
    char mr_signer[65] = "c30446b4be9baf0f69728423ea613ef81a63e72acf7439fa0549001fd5482835";
    char mr_enclave[65] = "3110bb76d4f73657fce77b148c04b2b59973fa7e8e77f4fbb6e433b58c88deb7";
    RetJsonObj retJsonObj;
    char* returnJsonChar = nullptr;
    char* quote_base64 = nullptr;
    std::string input_nonce_base64 = base64_encode((const uint8_t*)nonce, sizeof(nonce)/sizeof(nonce[0]));
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

    returnJsonChar = NAPI_VerifyQuote(quote_base64, mr_signer, mr_enclave, input_nonce_base64.c_str());
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

void test_Enroll()
{
    printf("============test_Enroll start==========\n");
    RetJsonObj retJsonObj;
    char* returnJsonChar = nullptr;
    char* appid = nullptr;
    char* apikey = nullptr;

    returnJsonChar = NAPI_Enroll();
    retJsonObj.parse(returnJsonChar);
    if(retJsonObj.getCode() != 200){
        printf("NAPI_Enroll failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Enroll Json : %s\n", returnJsonChar);
    printf("NAPI_Enroll SUCCESSFULLY!\n");

    appid = retJsonObj.readData_cstr("appid");
    apikey = retJsonObj.readData_cstr("apikey");
    printf("appid : %s\n", appid);
    printf("apikey : %s\n", apikey);

cleanup:
    SAFE_FREE(returnJsonChar);
    printf("============test_Enroll end==========\n");
}

void test_performance()
{
    // test_perf_createkey();
    // test_perf_encrypt();
    // test_perf_decrypt();
    // test_perf_sign();
    // test_perf_verify();
    // test_perf_asymmetricencrypt();
    // test_perf_asymmetricdecrypt();
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

    printf("%s", NAPI_GetVersion());

#if ENABLE_PERFORMANCE_TEST
    test_performance();
#endif

    test_AES128();

    test_AES192();

    test_AES256();

    // test_SM4();

    test_RSA2048_encrypt_decrypt();

    test_RSA3072_encrypt_decrypt();

    test_RSA4096_encrypt_decrypt();

    test_RSA2048_sign_verify();

    test_RSA3072_sign_verify();

    test_RSA4096_sign_verify();

    test_sm2_encrypt_decrypt();

    // test_generate_datakey();

    // test_export_datakey();

    // test_GenerateQuote_and_VerifyQuote();

    // test_Enroll();

    Finalize();

    printf("All of tests done\n");

    return ret;
}
