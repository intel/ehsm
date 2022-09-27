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
#include "dsohandle.h"
#include "json_utils.h"

#include <pthread.h>
#include <chrono>

// using namespace EHsmProvider;

#define PERF_NUM 1000

#define NUM_THREADS 100

int case_number = 0;
int success_number = 0;

// void test_perf_createkey()
// {
//     RetJsonObj retJsonObj;
//     char* returnJsonChar = nullptr;

//     // Start measuring time
//     auto begin = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < PERF_NUM*100; i++) {
//         returnJsonChar = NAPI_CreateKey(EH_AES_GCM_128, EH_INTERNAL_KEY);
//         retJsonObj.parse(returnJsonChar);

//         if(retJsonObj.getCode() != 200){
//             printf("Createkey with aes-128 failed in time(%d)\n", i);
//             SAFE_FREE(returnJsonChar);
//             break;
//         }
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     auto end = std::chrono::high_resolution_clock::now();
//     auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of CreateKey(AES_128) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM*100, elapsed.count() * 1e-9);

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < PERF_NUM; i++) {
//         returnJsonChar = NAPI_CreateKey(EH_RSA_3072, EH_INTERNAL_KEY);
//         retJsonObj.parse(returnJsonChar);

//         if(retJsonObj.getCode() != 200){
//             printf("Createkey with rsa-3072 failed in time(%d)\n", i);
//             SAFE_FREE(returnJsonChar);
//             break;
//         }
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
//     printf("Time measured of CreateKey(RSA_3072) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM, elapsed.count() * 1e-9);
// }

// void test_perf_encrypt()
// {
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
// }

// void test_perf_decrypt()
// {
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
// }

// void test_perf_sign()
// {
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
// }

// void test_perf_verify()
// {
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
// }

// void test_perf_asymmetricencrypt()
// {
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
// }

// void test_perf_asymmetricdecrypt()
// {
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
// }

// void *test_createkey(void *threadid)
// {
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
// }

// void test_multi_createkey()
// {
//     void *status;
//     pthread_t threads[NUM_THREADS];
//     int rc;
//     int i;
//     for( i=0; i < NUM_THREADS; i++ ){
//         printf("creating thread [%d]\n", i);
//         rc = pthread_create(&threads[i], NULL, test_createkey, (void *)i);
//         if (rc){
//             printf("Error(%d):unable to create thread\n", rc);
//             exit(-1);
//         }
//     }

//     for( i = 0; i < NUM_THREADS; i++ ) {
//         rc = pthread_join(threads[i], &status);
//         if (rc) {
//             printf("Error(%d) to join with thread[%d]\n", rc, i);
//             exit(-1);
//         }
//         printf("Main: completed thread[%d]\n", i);
//     }
//     pthread_exit(NULL);
// }

// void *test_encrypt(void *threadid)
// {
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
// }

// void test_multi_encrypt()
// {
//     void *status;
//     pthread_t threads[NUM_THREADS];
//     int rc;
//     int i;
//     for( i=0; i < NUM_THREADS; i++ ){
//         printf("creating thread [%d]\n", i);
//         rc = pthread_create(&threads[i], NULL, test_encrypt, (void *)i);
//         if (rc){
//             printf("Error(%d):unable to create thread\n", rc);
//             exit(-1);
//         }
//     }

//     for( i = 0; i < NUM_THREADS; i++ ) {
//         rc = pthread_join(threads[i], &status);
//         if (rc) {
//             printf("Error(%d) to join with thread[%d]\n", rc, i);
//             exit(-1);
//         }
//         printf("Main: completed thread[%d]\n", i);
//     }
//     pthread_exit(NULL);
// }

// /*

// step1. generate an aes-gcm-128 key as the CM(customer master key)

// step2. encrypt a plaintext by the CMK

// step3. decrypt the cipher text by CMK correctly

// */
void test_symmertric_encrypt_decrypt()
{
    printf("============test_AES_SM_encrypt_decrypt start==========\n");
    std::string plaintext[] = {"Test1234-AES128", "Test1234-AES192",
                               "Test1234-AES256", "Test1234-SM4-CTR", "Test1234-SM4-CBC"};
    uint32_t keyspec[] = {EH_AES_GCM_128, EH_AES_GCM_192, EH_AES_GCM_256, EH_SM4_CTR, EH_SM4_CBC};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);

    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        char *returnJsonChar = nullptr;
        char aad[] = "challenge";
        printf("============%s start==========\n", plaintext[i].c_str());

        char *cmk_base64 = nullptr;
        char *ciphertext_base64 = nullptr;
        char *plaintext_base64 = nullptr;
        std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext[i].c_str(), sizeof(plaintext[i]));
        std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

        RetJsonObj retJsonObj;
        JsonObj param_json;
        JsonObj payload_json;
        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Createkey with aes-gcm failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("FFI_CreateKey Json = %s\n", returnJsonChar);
        printf("Create CMK with AES SUCCESSFULLY!\n");
        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("plaintext", input_plaintext_base64);
        payload_json.addData_string("aad", input_aad_base64);

        param_json.addData_uint32("action", EH_ENCRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_Encrypt json = %s\n", returnJsonChar);
        printf("Encrypt data SUCCESSFULLY!\n");

        ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
        payload_json.addData_string("ciphertext", ciphertext_base64);

        param_json.addData_uint32("action", EH_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_Decrypt json = %s\n", returnJsonChar);
        plaintext_base64 = retJsonObj.readData_cstr("plaintext");
        if (plaintext_base64 == input_plaintext_base64)
        {
            success_number++;
            printf("decode64 plaintext = %s\n", base64_decode(plaintext_base64).c_str());
            printf("Decrypt data SUCCESSFULLY!\n");
        }
        else
        {
            printf("Failed to Decrypt the data, result = %s \n", base64_decode(plaintext_base64).c_str());
        }

    cleanup:
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(ciphertext_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        printf("============%s end==========\n", plaintext[i].c_str());
    }

    printf("============test_AES_SM_encrypt_decrypt end==========\n");
}

void test_RSA_encrypt_decrypt()
{
    printf("============test_RSA_encrypt_decrypt start==========\n");
    std::string plaintext[] = {"Test1234-RSA2048", "Test1234-RSA3072", "Test1234-RSA4096"};
    uint32_t keyspec[] = {EH_RSA_2048, EH_RSA_3072, EH_RSA_4096};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);

    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        char *returnJsonChar = nullptr;
        printf("============%s start==========\n", plaintext[i].c_str());

        char *cmk_base64 = nullptr;
        char *ciphertext_base64 = nullptr;
        char *plaintext_base64 = nullptr;
        std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext[i].c_str(), sizeof(plaintext[i]));

        RetJsonObj retJsonObj;
        JsonObj param_json;
        JsonObj payload_json;
        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("padding_mode", EH_PAD_RSA_PKCS1_OAEP);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Createkey with rsa failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("FFI_CreateKey Json = %s\n", returnJsonChar);
        printf("Create CMK with RSA SUCCESSFULLY!\n");
        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("plaintext", input_plaintext_base64);

        param_json.addData_uint32("action", EH_ASYMMETRIC_ENCRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_Encrypt json = %s\n", returnJsonChar);
        printf("Encrypt data SUCCESSFULLY!\n");

        ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
        payload_json.addData_string("ciphertext", ciphertext_base64);

        param_json.addData_uint32("action", EH_ASYMMETRIC_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_Decrypt json = %s\n", returnJsonChar);
        plaintext_base64 = retJsonObj.readData_cstr("plaintext");
        if (plaintext_base64 == input_plaintext_base64)
        {
            success_number++;
            printf("decode64 plaintext = %s\n", base64_decode(plaintext_base64).c_str());
            printf("Decrypt data SUCCESSFULLY!\n");
        }
        else
        {
            printf("Failed to Decrypt the data, result = %s \n", base64_decode(plaintext_base64).c_str());
        }

    cleanup:
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(ciphertext_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        printf("============%s end==========\n", plaintext[i].c_str());
    }

    printf("============test_RSA_encrypt_decrypt end==========\n");
}

void test_SM2_encrypt_decrypt()
{
    printf("============test_SM2_encrypt_decrypt start==========\n");
    std::string plaintext[] = {"Test1234-SM2"};
    uint32_t keyspec[] = {EH_SM2};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);

    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        char *returnJsonChar = nullptr;
        printf("============%s start==========\n", plaintext[i].c_str());

        char *cmk_base64 = nullptr;
        char *ciphertext_base64 = nullptr;
        char *plaintext_base64 = nullptr;
        std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext[i].c_str(), sizeof(plaintext[i]));

        RetJsonObj retJsonObj;
        JsonObj param_json;
        JsonObj payload_json;
        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Createkey with sm2 failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("FFI_CreateKey Json = %s\n", returnJsonChar);
        printf("Create CMK with SM2 SUCCESSFULLY!\n");
        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("plaintext", input_plaintext_base64);

        param_json.addData_uint32("action", EH_ASYMMETRIC_ENCRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_Encrypt json = %s\n", returnJsonChar);
        printf("Encrypt data SUCCESSFULLY!\n");

        ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
        payload_json.addData_string("ciphertext", ciphertext_base64);

        param_json.addData_uint32("action", EH_ASYMMETRIC_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);

        if (retJsonObj.getCode() != 200)
        {
            printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_Decrypt json = %s\n", returnJsonChar);
        plaintext_base64 = retJsonObj.readData_cstr("plaintext");
        if (plaintext_base64 == input_plaintext_base64)
        {
            success_number++;
            printf("decode64 plaintext = %s\n", base64_decode(plaintext_base64).c_str());
            printf("Decrypt data SUCCESSFULLY!\n");
        }
        else
        {
            printf("Failed to Decrypt the data, result = %s \n", base64_decode(plaintext_base64).c_str());
        }

    cleanup:
        SAFE_FREE(plaintext_base64);
        SAFE_FREE(ciphertext_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        printf("============%s end==========\n", plaintext[i].c_str());
    }

    printf("============test_SM2_encrypt_decrypt end==========\n");
}

/*

step1. generate an rsa 3072 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_RSA_sign_verify()
{
    printf("============test_RSA_sign_verify start==========\n");
    std::string plaintext[] = {"Test1234-RSA2048", "Test1234-RSA3072", "Test1234-RSA4096"};
    uint32_t keyspec[] = {EH_RSA_2048, EH_RSA_3072, EH_RSA_4096};

    case_number += sizeof(plaintext) / sizeof(plaintext[0]);
    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); i++)
    {
        printf("============%s start==========\n", plaintext[i].c_str());
        ehsm_status_t ret = EH_OK;
        char *returnJsonChar = nullptr;
        char digest[] = "SIGN";

        char *cmk_base64 = nullptr;
        char *signature_base64 = nullptr;
        bool result = false;
        RetJsonObj retJsonObj;

        JsonObj param_json;
        JsonObj payload_json;

        std::string input_digest_base64 = base64_encode((const uint8_t *)digest, sizeof(digest) / sizeof(digest[0]));

        payload_json.addData_uint32("keyspec", keyspec[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        payload_json.addData_uint32("padding_mode", EH_PAD_RSA_PKCS1_PSS);
        payload_json.addData_uint32("digest_mode", EH_SHA_2_256);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());
        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
        printf("Create CMK with RAS SUCCESSFULLY!\n");

        cmk_base64 = retJsonObj.readData_cstr("cmk");

        payload_json.clear();
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("digest", input_digest_base64);

        param_json.addData_uint32("action", EH_SIGN);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_Sign Json = %s\n", returnJsonChar);
        signature_base64 = retJsonObj.readData_cstr("signature");
        printf("Sign data SUCCESSFULLY!\n");

        payload_json.addData_string("signature", signature_base64);

        param_json.addData_uint32("action", EH_VERIFY);
        param_json.addData_JsonValue("payload", payload_json.getJson());

        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            printf("NAPI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        printf("NAPI_Verify Json = %s\n", returnJsonChar);
        result = retJsonObj.readData_bool("result");
        printf("Verify result : %s\n", result ? "true" : "false");
        if (result == true)
        {
            success_number++;
            printf("Verify signature SUCCESSFULLY!\n");
        }

    cleanup:
        SAFE_FREE(signature_base64);
        SAFE_FREE(cmk_base64);
        SAFE_FREE(returnJsonChar);
        printf("============%s end==========\n", plaintext[i].c_str());
    }
    printf("============test_RSA_sign_verify end==========\n");
}

/*

step1. generate an ec p256 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_ec_p256_sign_verify()
{
    case_number++;
    ehsm_status_t ret = EH_OK;
    char *returnJsonChar = nullptr;
    char digest[] = "SIGN";

    char *cmk_base64 = nullptr;
    char *signature_base64 = nullptr;
    bool result = false;
    RetJsonObj retJsonObj;

    JsonObj param_json;
    JsonObj payload_json;

    std::string input_digest_base64 = base64_encode((const uint8_t *)digest, sizeof(digest) / sizeof(digest[0]));

    payload_json.addData_uint32("keyspec", EH_EC_P256);
    payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
    payload_json.addData_uint32("padding_mode", EH_PAD_RSA_PKCS1);
    payload_json.addData_uint32("digest_mode", EH_SHA_2_256);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());
    printf("============test_ec_p256_sign_verify start==========\n");
    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_string("digest", input_digest_base64);

    param_json.addData_uint32("action", EH_SIGN);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Sign Json = %s\n", returnJsonChar);
    signature_base64 = retJsonObj.readData_cstr("signature");
    printf("Sign data SUCCESSFULLY!\n");

    payload_json.addData_string("signature", signature_base64);

    param_json.addData_uint32("action", EH_VERIFY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Verify Json = %s\n", returnJsonChar);
    result = retJsonObj.readData_bool("result");
    printf("Verify result : %s\n", result ? "true" : "false");
    if (result == true)
    {
        success_number++;
        printf("Verify signature SUCCESSFULLY!\n");
    }

cleanup:
    SAFE_FREE(signature_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_ec_p256_sign_verify end==========\n");
    printf("\n");
}

/*

step1. generate an sm2 key as the CM(customer master key)

step2. Sign the digest

step3. Verify the signature

*/
void test_sm2_sign_verify()
{
    case_number++;
    ehsm_status_t ret = EH_OK;
    char *returnJsonChar = nullptr;
    char digest[] = "SIGN";

    char *cmk_base64 = nullptr;
    char *signature_base64 = nullptr;
    bool result = false;
    RetJsonObj retJsonObj;

    JsonObj param_json;
    JsonObj payload_json;

    std::string input_digest_base64 = base64_encode((const uint8_t *)digest, sizeof(digest) / sizeof(digest[0]));

    payload_json.addData_uint32("keyspec", EH_SM2);
    payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
    payload_json.addData_uint32("padding_mode", EH_PAD_RSA_PKCS1_PSS);
    payload_json.addData_uint32("digest_mode", EH_SM3);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());
    printf("============test_SM2_sign_verify start==========\n");
    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_CreateKey Json : %s\n", returnJsonChar);
    printf("Create CMK with RAS SUCCESSFULLY!\n");

    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_string("digest", input_digest_base64);

    param_json.addData_uint32("action", EH_SIGN);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Sign Json = %s\n", returnJsonChar);
    signature_base64 = retJsonObj.readData_cstr("signature");
    printf("Sign data SUCCESSFULLY!\n");

    payload_json.addData_string("signature", signature_base64);

    param_json.addData_uint32("action", EH_VERIFY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_Verify Json = %s\n", returnJsonChar);
    result = retJsonObj.readData_bool("result");
    printf("Verify result : %s\n", result ? "true" : "false");
    if (result == true)
    {
        success_number++;
        printf("Verify signature SUCCESSFULLY!\n");
    }

cleanup:
    SAFE_FREE(signature_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_SM2_sign_verify end==========\n");
    printf("\n");
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
    printf("============test_generate_AES_datakey start==========\n");
    char *returnJsonChar = nullptr;
    char aad[] = "challenge";
    char *cmk_base64 = nullptr;
    char *ciphertext_base64 = nullptr;
    char *ciphertext_without_base64 = nullptr;
    int len_gdk = 16;
    int len_gdk_without = 48;
    RetJsonObj retJsonObj;
    std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

    JsonObj payload_json;
    JsonObj param_json;
    payload_json.addData_uint32("keyspec", EH_AES_GCM_128);
    payload_json.addData_uint32("origin", 0);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if (retJsonObj.getCode() != 200)
    {
        printf("Createkey with aes-gcm-128 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("ckReturn_Json = %s\n", returnJsonChar);
    printf("Create CMK with AES-128 SUCCESSFULLY!\n");

    /* generate a 16 bytes random data key and with plaint text returned */
    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_uint32("keylen", len_gdk);
    payload_json.addData_string("aad", input_aad_base64);

    param_json.addData_uint32("action", EH_GENERATE_DATAKEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if (retJsonObj.getCode() != 200)
    {
        printf("GenerateDataKey Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("GenerateDataKey_Json = %s\n", returnJsonChar);
    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
    printf("GenerateDataKey SUCCESSFULLY!\n");

    payload_json.addData_string("ciphertext", ciphertext_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("step1 Decrypt_Json = %s\n", returnJsonChar);
    printf("Decrypt step1 data SUCCESSFULLY!\n");

    /* generate a 48 bytes random data key and without plaint text returned */
    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_uint32("keylen", len_gdk_without);
    payload_json.addData_string("aad", input_aad_base64);

    param_json.addData_uint32("action", EH_GENERATE_DATAKEY_WITHOUT_PLAINTEXT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_GenerateDataKeyWithoutPlaintext Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("GenerateDataKeyWithoutPlaintext_Json = %s\n", returnJsonChar);

    ciphertext_without_base64 = retJsonObj.readData_cstr("ciphertext");
    printf("GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");

    payload_json.addData_string("ciphertext", ciphertext_without_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("step2 Decrypt_Json = %s\n", returnJsonChar);
    printf("Decrypt step2 data SUCCESSFULLY!\n");
    success_number++;

cleanup:
    SAFE_FREE(ciphertext_without_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_generate_AES_datakey end==========\n");
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
    printf("============test_generate_SM4_datakey start==========\n");
    char *returnJsonChar = nullptr;
    char *cmk_base64 = nullptr;
    char *ciphertext_base64 = nullptr;
    char *ciphertext_without_base64 = nullptr;
    int len_gdk = 16;
    int len_gdk_without = 111;
    RetJsonObj retJsonObj;

    JsonObj payload_json;
    JsonObj param_json;
    payload_json.addData_uint32("keyspec", EH_SM4_CBC);
    payload_json.addData_uint32("origin", 0);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if (retJsonObj.getCode() != 200)
    {
        printf("Createkey with sm4 failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("ckReturn_Json = %s\n", returnJsonChar);
    printf("Create CMK with sm4 SUCCESSFULLY!\n");

    /* generate a 16 bytes random data key and with plaint text returned */
    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_uint32("keylen", len_gdk);

    param_json.addData_uint32("action", EH_GENERATE_DATAKEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    if (retJsonObj.getCode() != 200)
    {
        printf("GenerateDataKey Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("GenerateDataKey_Json = %s\n", returnJsonChar);
    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
    printf("GenerateDataKey SUCCESSFULLY!\n");

    payload_json.addData_string("ciphertext", ciphertext_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("step1 Decrypt_Json = %s\n", returnJsonChar);
    printf("Decrypt step1 data SUCCESSFULLY!\n");

    /* generate a 48 bytes random data key and without plaint text returned */
    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_uint32("keylen", len_gdk_without);

    param_json.addData_uint32("action", EH_GENERATE_DATAKEY_WITHOUT_PLAINTEXT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_GenerateDataKeyWithoutPlaintext Failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("GenerateDataKeyWithoutPlaintext_Json = %s\n", returnJsonChar);

    ciphertext_without_base64 = retJsonObj.readData_cstr("ciphertext");
    printf("GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");

    payload_json.addData_string("ciphertext", ciphertext_without_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("step2 Decrypt_Json = %s\n", returnJsonChar);
    printf("Decrypt step2 data SUCCESSFULLY!\n");
    success_number++;

cleanup:
    SAFE_FREE(ciphertext_without_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
    printf("============test_generate_SM4_datakey end==========\n");
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

    char *returnJsonChar = nullptr;
    char *cmk_base64 = nullptr;
    char *ukey_base64 = nullptr;
    char aad[] = "aadd";
    char *olddatakey_base64 = nullptr;
    char *newdatakey_base64 = nullptr;
    char *olddatakeyplaintext_base64 = nullptr;
    char *newdatakeyplaintext_base64 = nullptr;
    char *plaintext_base64 = nullptr;
    char *ciphertext_base64 = nullptr;
    uint32_t keylen = 48;
    RetJsonObj retJsonObj;
    std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

    printf("============test_export_datakey start==========\n");

    /*step1. create an aes-128 key as the cmk to encrypt datakey*/
    JsonObj param_json;
    JsonObj payload_json;
    for (int i = 0; i < cmk_keyspec_test_num; i++)
    {
        payload_json.clear();
        param_json.clear();
        payload_json.addData_uint32("keyspec", cmk_keyspec_test[i]);
        payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
        param_json.addData_uint32("action", EH_CREATE_KEY);
        param_json.addData_JsonValue("payload", payload_json.getJson());
        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            printf("Createkey using keyspec code %d cmk failed, error message: %s \n", cmk_keyspec_test[i], retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        cmk_base64 = retJsonObj.readData_cstr("cmk");
        printf("cmk_base64 : %s\n", cmk_base64);
        printf("Create CMK with keyspec code %d SUCCESSFULLY!\n", cmk_keyspec_test[i]);

        /* step2. generate a 48 bytes random data key and without plaintext returned */
        payload_json.clear();
        param_json.clear();
        payload_json.addData_string("aad", input_aad_base64);
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_uint32("keylen", keylen);
        param_json.addData_uint32("action", EH_GENERATE_DATAKEY_WITHOUT_PLAINTEXT);
        param_json.addData_JsonValue("payload", payload_json.getJson());
        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            printf("GenerateDataKeyWithoutPlaintext using keyspec code %d cmk Failed, error message: %s \n", cmk_keyspec_test[i], retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        olddatakey_base64 = retJsonObj.readData_cstr("ciphertext");
        printf("olddatakey_base64 : %s\n", olddatakey_base64);
        printf("GenerateDataKeyWithoutPlaintext using keyspec code %d cmk SUCCESSFULLY!\n", cmk_keyspec_test[i]);

        /* step3. try to use the cmk to decrypt the datakey */
        payload_json.clear();
        param_json.clear();
        payload_json.addData_string("aad", input_aad_base64);
        payload_json.addData_string("cmk", cmk_base64);
        payload_json.addData_string("ciphertext", olddatakey_base64);
        param_json.addData_uint32("action", EH_DECRYPT);
        param_json.addData_JsonValue("payload", payload_json.getJson());
        returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
        retJsonObj.parse(returnJsonChar);
        if (retJsonObj.getCode() != 200)
        {
            printf("DECEYPT using keyspec code %d cmk, failed, error message: %s \n", cmk_keyspec_test[i], retJsonObj.getMessage().c_str());
            goto cleanup;
        }
        olddatakeyplaintext_base64 = retJsonObj.readData_cstr("plaintext");
        printf("Decrypted using keyspec code %d cmk, datakeyplaintext_base64 : %s\n", cmk_keyspec_test[i], olddatakeyplaintext_base64);
        printf("Decrypt datakey using keyspec code %d cmk SUCCESSFULLY!\n", cmk_keyspec_test[i]);
        for (int j = 0; j < ukey_keyspec_test_num; j++)
        {
            payload_json.clear();
            param_json.clear();
            payload_json.addData_uint32("keyspec", ukey_keyspec_test[j]);
            switch (ukey_keyspec_test[j])
            {
            case EH_RSA_2048:
            case EH_RSA_3072:
            case EH_RSA_4096:
                payload_json.addData_uint32("padding_mode", EH_PAD_RSA_PKCS1_OAEP);
                break;
            case EH_SM2:
                break;
            default:
                break;
            }
            /*step4. create key as the ukey */
            payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
            param_json.addData_uint32("action", EH_CREATE_KEY);
            param_json.addData_JsonValue("payload", payload_json.getJson());
            returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
            retJsonObj.parse(returnJsonChar);
            if (retJsonObj.getCode() != 200)
            {
                printf("CreateKey using keyspec code %d ukey failed, error message: %s \n", ukey_keyspec_test[j], retJsonObj.getMessage().c_str());
                goto cleanup;
            }
            ukey_base64 = retJsonObj.readData_cstr("cmk");
            printf("keyspec code %d ukey_base64 : %s\n", ukey_keyspec_test[j], ukey_base64);
            printf("CreateKey UKEY using keyspec code %d SUCCESSFULLY!\n", ukey_keyspec_test[j]);

            /*step5. export the datakey with the new user public key */
            payload_json.clear();
            param_json.clear();
            payload_json.addData_string("aad", input_aad_base64);
            payload_json.addData_string("cmk", cmk_base64);
            payload_json.addData_string("ukey", ukey_base64);
            payload_json.addData_string("olddatakey", olddatakey_base64);
            param_json.addData_uint32("action", EH_EXPORT_DATAKEY);
            param_json.addData_JsonValue("payload", payload_json.getJson());
            returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
            retJsonObj.parse(returnJsonChar);
            if (retJsonObj.getCode() != 200)
            {
                printf("ExportDataKey using keyspec code %d cmk, keyspec code %d ukey failed, error message: %s \n", cmk_keyspec_test[i], ukey_keyspec_test[j], retJsonObj.getMessage().c_str());
                goto cleanup;
            }
            newdatakey_base64 = retJsonObj.readData_cstr("newdatakey");
            printf("ExportDataKey SUCCESSFULLY!\n");
            // step6. verify that the newdatakey ciphertext could be decrypt succeed by the user rsa key pair
            payload_json.clear();
            param_json.clear();
            payload_json.addData_string("cmk", ukey_base64);
            payload_json.addData_string("ciphertext", newdatakey_base64);
            param_json.addData_uint32("action", EH_ASYMMETRIC_DECRYPT);
            param_json.addData_JsonValue("payload", payload_json.getJson());
            returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
            retJsonObj.parse(returnJsonChar);
            if (retJsonObj.getCode() != 200)
            {
                printf("AsymmetricDecrypt newdatakey using keyspec code %d cmk, keyspec code %d ukey failed, error message: %s \n", cmk_keyspec_test[i], ukey_keyspec_test[j], retJsonObj.getMessage().c_str());
                goto cleanup;
            }
            newdatakeyplaintext_base64 = retJsonObj.readData_cstr("plaintext");
            printf("AsymmetricDecrypt newdatakey using keyspec code %d ukey Json : %s\n", ukey_keyspec_test[j], returnJsonChar);
            printf("newdatakey_plaintext_base64 : %s\n", newdatakeyplaintext_base64);
            printf("Asymmetric Decrypt newdatakey using keyspec code %d ukey SUCCESSFULLY!\n", ukey_keyspec_test[j]);
            if (strcmp(olddatakeyplaintext_base64, newdatakeyplaintext_base64) == 0)
            {
                printf("ExportDataKey with keyspec code %d cmk, keyspec code %d ukey SUCCESSFULLY.\n", cmk_keyspec_test[i], ukey_keyspec_test[j]);
            }
            else
            {
                printf("ExportDataKey  with keyspec code %d cmk, keyspec code %d ukey failed. olddatakeyplaintext!=newdatakeyplaintext\n", cmk_keyspec_test[i], ukey_keyspec_test[j]);
            }
            SAFE_FREE(ukey_base64);
            SAFE_FREE(newdatakey_base64);
            SAFE_FREE(newdatakeyplaintext_base64)
        }
        SAFE_FREE(returnJsonChar);
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
    printf("============test_export_datakey end==========\n");
}

void test_GenerateQuote_and_VerifyQuote()
{
    printf("============test_GenerateQuote_and_VerifyQuote start==========\n");
    JsonObj param_json;
    JsonObj payload_json;

    char challenge[32] = "challenge123456";
    char nonce[16] = "nonce123456";
    // the string generated after converting the value of mr_signer and mr_enclave to hexadecimal
    // notice: these 2 values will be changed if our enclave has been updated. then the case may be failed.
    // you can get mr_signer and mr_enclave through cmd:
    // "/opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave libenclave-ehsm-core.signed.so -dumpfile out.log"
    char mr_signer[65] = "c30446b4be9baf0f69728423ea613ef81a63e72acf7439fa0549001fd5482835";
    char mr_enclave[65] = "c3113b289e296cc25b6756eac281f89d75270c8c3e38c7dc085c6f51c9823e85";
    RetJsonObj retJsonObj;
    char *returnJsonChar = nullptr;
    char *quote_base64 = nullptr;
    std::string input_challenge_base64 = base64_encode((const uint8_t *)challenge, sizeof(challenge) / sizeof(challenge[0]));
    std::string input_nonce_base64 = base64_encode((const uint8_t *)nonce, sizeof(nonce) / sizeof(nonce[0]));

    payload_json.addData_string("challenge", input_challenge_base64);
    param_json.addData_uint32("action", EH_GENERATE_QUOTE);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
        printf("NAPI_GenerateQuote failed, error message: %s \n", retJsonObj.getMessage().c_str());
        goto cleanup;
    }
    printf("NAPI_GenerateQuote Json : %s\n", returnJsonChar);
    printf("NAPI_GenerateQuote SUCCESSFULLY!\n");

    quote_base64 = retJsonObj.readData_cstr("quote");
    printf("quote_base64 : %s\n", quote_base64);

    payload_json.clear();
    param_json.clear();
    payload_json.addData_string("quote", quote_base64);
    payload_json.addData_string("mr_signer", mr_signer);
    payload_json.addData_string("mr_enclave", mr_enclave);
    payload_json.addData_string("nonce", input_nonce_base64);
    param_json.addData_uint32("action", EH_VERIFY_QUOTE);
    param_json.addData_JsonValue("payload", payload_json.getJson());
    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
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
    char *returnJsonChar = nullptr;
    char *appid = nullptr;
    char *apikey = nullptr;

    JsonObj param_json;
    JsonObj payload_json;
    param_json.addData_uint32("action", EH_ENROLL);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL(param_json.toString().c_str());
    retJsonObj.parse(returnJsonChar);
    if (retJsonObj.getCode() != 200)
    {
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

// void test_performance()
// {
//     test_perf_createkey();
//     test_perf_encrypt();
//     test_perf_decrypt();
//     test_perf_sign();
//     test_perf_verify();
//     test_perf_asymmetricencrypt();
//     test_perf_asymmetricdecrypt();
// }

int main(int argc, char *argv[])
{
    ehsm_status_t ret = EH_OK;

    ret = Initialize();
    if (ret != EH_OK)
    {
        printf("Initialize failed %d\n", ret);
        return ret;
    }
    printf("Initialize done\n");

    test_symmertric_encrypt_decrypt();

    test_RSA_encrypt_decrypt();

    test_RSA_sign_verify();

    test_sm2_sign_verify();

    test_ec_p256_sign_verify();

    test_SM2_encrypt_decrypt();

    test_generate_AES_datakey();

    test_generate_SM4_datakey();

    test_export_datakey();

    test_GenerateQuote_and_VerifyQuote();

    test_Enroll();

    Finalize();

    printf("All of tests done. %d/%d success\n", success_number, case_number);

    return ret;
}
