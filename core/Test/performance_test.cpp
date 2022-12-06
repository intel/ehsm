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

#include "performance_test.h"
#include "../App/ehsm_provider.h"
#include "base64.h"
#include "dsohandle.h"
#include "json_utils.h"

// void test_perf_createkey()
// {
//     RetJsonObj retJsonObj;
//     JsonObj param_json;
//     JsonObj payload_json;
//     char *returnJsonChar = nullptr;
//     ehsm_keyspec_t symmetry_keyspec_test[] = {EH_AES_GCM_128, EH_AES_GCM_192, EH_AES_GCM_256, EH_SM4_CBC, EH_SM4_CTR};
//     int symmetry_keyspec_test_num = sizeof(symmetry_keyspec_test) / sizeof(symmetry_keyspec_test[0]);
//     ehsm_keyspec_t asymmetry_keyspec_test[] = {EH_RSA_2048, EH_RSA_3072, EH_RSA_4096, EH_SM2, EH_EC_P224, EH_EC_P256, EH_EC_P384, EH_EC_P521};
//     int asymmetry_keyspec_test_num = sizeof(asymmetry_keyspec_test) / sizeof(asymmetry_keyspec_test[0]);
//     ehsm_padding_mode_t rsa_padding_test[] = {EH_PAD_RSA_PKCS1_OAEP, EH_PAD_RSA_PKCS1_PSS};
//     int rsa_padding_num = sizeof(rsa_padding_test) / sizeof(rsa_padding_test[0]);
//     for (int j = 0; j < symmetry_keyspec_test_num; j++)
//     { // Start measuring time
//         auto begin = std::chrono::high_resolution_clock::now();

//         for (int i = 0; i < PERF_NUM * 100; i++)
//         {
//             payload_json.clear();
//             param_json.clear();
//             payload_json.addData_uint32("keyspec", symmetry_keyspec_test[j]);
//             payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//             param_json.addData_uint32("action", EH_CREATE_KEY);
//             param_json.addData_JsonValue("payload", payload_json.getJson());

//             returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//             retJsonObj.parse(returnJsonChar);

//             if (retJsonObj.getCode() != 200)
//             {
//                 printf("Createkey with keyspec code %d failed in time(%d)\n", symmetry_keyspec_test[j], i);
//                 SAFE_FREE(returnJsonChar);
//                 break;
//             }
//             SAFE_FREE(returnJsonChar);
//         }

//         // Stop measuring time and calculate the elapsed time
//         auto end = std::chrono::high_resolution_clock::now();
//         auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//         printf("Time measured of CreateKey keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", symmetry_keyspec_test[j], PERF_NUM * 100, elapsed.count() * 1e-9);
//     }

//     for (int j = 0; j < asymmetry_keyspec_test_num; j++)
//     {
//         for (int k = 0; k < rsa_padding_num; k++)
//         { // Start measuring time
//             auto begin = std::chrono::high_resolution_clock::now();
//             /*The EVP_PKEY_keygen() function in RSA createkey runs for a long time
//             cannot be tested for PERF_NUM times */
//             for (int i = 0; i < 10; i++)
//             {
//                 payload_json.clear();
//                 param_json.clear();
//                 payload_json.addData_uint32("keyspec", asymmetry_keyspec_test[j]);
//                 payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//                 switch (asymmetry_keyspec_test[j])
//                 {
//                 case EH_RSA_2048:
//                 case EH_RSA_3072:
//                 case EH_RSA_4096:
//                     payload_json.addData_uint32("padding_mode", rsa_padding_test[k]);
//                     break;
//                 default:
//                     break;
//                 }

//                 param_json.addData_uint32("action", EH_CREATE_KEY);
//                 param_json.addData_JsonValue("payload", payload_json.getJson());

//                 returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//                 retJsonObj.parse(returnJsonChar);

//                 if (retJsonObj.getCode() != 200)
//                 {
//                     printf("Createkey with keyspec code %d failed in time(%d)\n", asymmetry_keyspec_test[j], i);
//                     SAFE_FREE(returnJsonChar);
//                     break;
//                 }
//                 SAFE_FREE(returnJsonChar);
//             }

//             // Stop measuring time and calculate the elapsed time
//             auto end = std::chrono::high_resolution_clock::now();
//             auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
//             printf("Time measured of CreateKey keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", asymmetry_keyspec_test[j], 10, elapsed.count() * 1e-9);
//         }
//     }
// }

// void test_perf_encrypt()
// {
//     char *returnJsonChar = nullptr;
//     char plaintext[32] = "helloworld";
//     char aad[] = "challenge";

//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     char *cmk_base64 = nullptr;
//     char *plaintext_base64 = nullptr;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext, sizeof(plaintext) / sizeof(plaintext[0]));
//     std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

//     RetJsonObj retJsonObj;
//     JsonObj param_json;
//     JsonObj payload_json;
//     payload_json.addData_uint32("keyspec", EH_AES_GCM_256);
//     payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//     param_json.addData_uint32("action", EH_CREATE_KEY);
//     param_json.addData_JsonValue("payload", payload_json.getJson());

//     returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//     retJsonObj.parse(returnJsonChar);

//     if (retJsonObj.getCode() != 200)
//     {
//         printf("Createkey with aes-gcm-256 failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < PERF_NUM * 100; i++)
//     {
//         payload_json.clear();
//         payload_json.addData_string("cmk", cmk_base64);
//         payload_json.addData_string("plaintext", input_plaintext_base64);
//         payload_json.addData_string("aad", input_aad_base64);

//         param_json.addData_uint32("action", EH_ENCRYPT);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);

//         if (retJsonObj.getCode() != 200)
//         {
//             printf("failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of Encrypt(AES_256) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM * 100, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(plaintext_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);
// }

// void test_perf_decrypt()
// {
//     char *returnJsonChar = nullptr;
//     char plaintext[32] = "helloworld";
//     char aad[] = "challenge";

//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;
//     char *cmk_base64 = nullptr;
//     char *ciphertext_base64 = nullptr;
//     char *plaintext_base64 = nullptr;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext, sizeof(plaintext) / sizeof(plaintext[0]));
//     std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

//     RetJsonObj retJsonObj;
//     JsonObj param_json;
//     JsonObj payload_json;
//     payload_json.addData_uint32("keyspec", EH_AES_GCM_256);
//     payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//     param_json.addData_uint32("action", EH_CREATE_KEY);
//     param_json.addData_JsonValue("payload", payload_json.getJson());

//     returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//     retJsonObj.parse(returnJsonChar);

//     if (retJsonObj.getCode() != 200)
//     {
//         printf("Createkey with aes-gcm-256 failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     payload_json.clear();
//     payload_json.addData_string("cmk", cmk_base64);
//     payload_json.addData_string("plaintext", input_plaintext_base64);
//     payload_json.addData_string("aad", input_aad_base64);

//     param_json.addData_uint32("action", EH_ENCRYPT);
//     param_json.addData_JsonValue("payload", payload_json.getJson());

//     returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//     retJsonObj.parse(returnJsonChar);

//     if (retJsonObj.getCode() != 200)
//     {
//         printf("failed to Encrypt the plaittext data, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < PERF_NUM * 100; i++)
//     {
//         payload_json.addData_string("ciphertext", ciphertext_base64);

//         param_json.addData_uint32("action", EH_DECRYPT);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);

//         if (retJsonObj.getCode() != 200)
//         {
//             printf("Failed to Decrypt the data, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of Decrypt(AES_256) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM * 100, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(ciphertext_base64);
//     SAFE_FREE(plaintext_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);
// }

// void test_perf_sign_verify()
// {
//     ehsm_status_t ret = EH_OK;
//     char *returnJsonChar = nullptr;
//     char data2sign[] = "SIGN";

//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     char *cmk_base64 = nullptr;
//     char *signature_base64 = nullptr;
//     bool result = false;
//     RetJsonObj retJsonObj;

//     JsonObj param_json;
//     JsonObj payload_json;

//     std::string input_data2sign_base64 = base64_encode((const uint8_t *)data2sign, sizeof(data2sign) / sizeof(data2sign[0]));

//     payload_json.addData_uint32("keyspec", EH_RSA_4096);
//     payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//     payload_json.addData_uint32("padding_mode", EH_PAD_RSA_PKCS1_PSS);
//     payload_json.addData_uint32("digest_mode", EH_SHA_2_256);
//     param_json.addData_uint32("action", EH_CREATE_KEY);
//     param_json.addData_JsonValue("payload", payload_json.getJson());
//     returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//     retJsonObj.parse(returnJsonChar);
//     if (retJsonObj.getCode() != 200)
//     {
//         printf("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < PERF_NUM; i++)
//     {
//         payload_json.clear();
//         payload_json.addData_string("cmk", cmk_base64);
//         payload_json.addData_string("digest", input_data2sign_base64);

//         param_json.addData_uint32("action", EH_SIGN);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);
//         if (retJsonObj.getCode() != 200)
//         {
//             printf("FFI_Sign failed, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of Sign(RSA_4096) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM, elapsed.count() * 1e-9);

//     signature_base64 = retJsonObj.readData_cstr("signature");
//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < PERF_NUM; i++)
//     {
//         payload_json.addData_string("signature", signature_base64);

//         param_json.addData_uint32("action", EH_VERIFY);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);
//         if (retJsonObj.getCode() != 200)
//         {
//             printf("FFI_Verify failed, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
//         SAFE_FREE(returnJsonChar);
//     }

//     // Stop measuring time and calculate the elapsed time
//     end = std::chrono::high_resolution_clock::now();
//     elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

//     printf("Time measured of Verify(RSA_4096) with Repeat NUM(%d): %.6f seconds.\n", PERF_NUM, elapsed.count() * 1e-9);

// cleanup:
//     SAFE_FREE(signature_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);
// }

// void test_perf_asymmetricencrypt()
// {
//     std::chrono::high_resolution_clock::time_point begin;
//     std::chrono::high_resolution_clock::time_point end;
//     std::chrono::nanoseconds elapsed;

//     char *returnJsonChar = nullptr;
//     char plaintext[32] = "TestRSA-4096";
//     char *cmk_base64 = nullptr;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext, sizeof(plaintext) / sizeof(plaintext[0]));

//     RetJsonObj retJsonObj;
//     JsonObj param_json;
//     JsonObj payload_json;
//     payload_json.addData_uint32("keyspec", EH_RSA_3072);
//     payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//     payload_json.addData_uint32("padding_mode", EH_PAD_RSA_PKCS1_OAEP);
//     param_json.addData_uint32("action", EH_CREATE_KEY);
//     param_json.addData_JsonValue("payload", payload_json.getJson());

//     returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//     retJsonObj.parse(returnJsonChar);
//     if (retJsonObj.getCode() != 200)
//     {
//         printf("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < PERF_NUM; i++)
//     {
//         payload_json.clear();
//         payload_json.addData_string("cmk", cmk_base64);
//         payload_json.addData_string("plaintext", input_plaintext_base64);

//         param_json.addData_uint32("action", EH_ASYMMETRIC_ENCRYPT);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);
//         if (retJsonObj.getCode() != 200)
//         {
//             printf("FFI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
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

//     char *returnJsonChar = nullptr;
//     char plaintext[32] = "TestRSA-3072";
//     char *cmk_base64 = nullptr;
//     char *ciphertext_base64 = nullptr;
//     char *plaintext_base64 = nullptr;
//     RetJsonObj retJsonObj;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext, sizeof(plaintext) / sizeof(plaintext[0]));

//     JsonObj param_json;
//     JsonObj payload_json;
//     payload_json.addData_uint32("keyspec", EH_RSA_3072);
//     payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//     payload_json.addData_uint32("padding_mode", EH_PAD_RSA_PKCS1_OAEP);
//     param_json.addData_uint32("action", EH_CREATE_KEY);
//     param_json.addData_JsonValue("payload", payload_json.getJson());

//     returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//     retJsonObj.parse(returnJsonChar);
//     if (retJsonObj.getCode() != 200)
//     {
//         printf("FFI_CreateKey failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     payload_json.clear();
//     payload_json.addData_string("cmk", cmk_base64);
//     payload_json.addData_string("plaintext", input_plaintext_base64);

//     param_json.addData_uint32("action", EH_ASYMMETRIC_ENCRYPT);
//     param_json.addData_JsonValue("payload", payload_json.getJson());

//     returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//     retJsonObj.parse(returnJsonChar);
//     if (retJsonObj.getCode() != 200)
//     {
//         printf("FFI_AsymmetricEncrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");

//     // Start measuring time
//     begin = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < PERF_NUM; i++)
//     {
//         payload_json.addData_string("ciphertext", ciphertext_base64);

//         param_json.addData_uint32("action", EH_ASYMMETRIC_DECRYPT);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);
//         if (retJsonObj.getCode() != 200)
//         {
//             printf("FFI_AsymmetricDecrypt failed, error message: %s \n", retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }
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
//     JsonObj param_json;
//     JsonObj payload_json;
//     char *returnJsonChar = nullptr;
//     long tid = (long)threadid;

//     for (int i = 0; i < PERF_NUM; i++)
//     {
//         payload_json.addData_uint32("keyspec", EH_AES_GCM_256);
//         payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//         param_json.addData_uint32("action", EH_CREATE_KEY);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);

//         if (retJsonObj.getCode() != 200)
//         {
//             printf("Createkey with aes-128 failed in time(%d)\n", i);
//             SAFE_FREE(returnJsonChar);
//             break;
//         }
//         SAFE_FREE(returnJsonChar);
//         printf("Thread[%ld], CreateKey(AES-128) succeed in time[%d]\n", tid, i);
//     }

//     pthread_exit(NULL);
// }

// void test_parallel_createkey()
// {
//     void *status;
//     pthread_t threads[NUM_THREADS];
//     int rc;
//     int i;
//     for (i = 0; i < NUM_THREADS; i++)
//     {
//         printf("creating thread [%d]\n", i);
//         rc = pthread_create(&threads[i], NULL, test_createkey, (void *)i);
//         if (rc)
//         {
//             printf("Error(%d):unable to create thread\n", rc);
//             exit(-1);
//         }
//     }

//     for (i = 0; i < NUM_THREADS; i++)
//     {
//         rc = pthread_join(threads[i], &status);
//         if (rc)
//         {
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
//     char *returnJsonChar = nullptr;
//     char plaintext[32] = "helloworld";
//     char aad[] = "challenge";

//     printf("Thread[%ld]. plaintext is %s\n", tid, plaintext);

//     char *cmk_base64 = nullptr;
//     char *plaintext_base64 = nullptr;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext, sizeof(plaintext) / sizeof(plaintext[0]));
//     std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

//     RetJsonObj retJsonObj;
//     JsonObj param_json;
//     JsonObj payload_json;
//     payload_json.addData_uint32("keyspec", EH_AES_GCM_256);
//     payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//     param_json.addData_uint32("action", EH_CREATE_KEY);
//     param_json.addData_JsonValue("payload", payload_json.getJson());

//     if (retJsonObj.getCode() != 200)
//     {
//         printf("Thread[%ld], Createkey with aes-gcm-128 failed, error message: %s \n", tid, retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     printf("Thread[%ld], FFI_CreateKey Json = %s\n", tid, returnJsonChar);
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     for (int i = 0; i < PERF_NUM; i++)
//     {
//         payload_json.clear();
//         payload_json.addData_string("cmk", cmk_base64);
//         payload_json.addData_string("plaintext", input_plaintext_base64);
//         payload_json.addData_string("aad", input_aad_base64);

//         param_json.addData_uint32("action", EH_ENCRYPT);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);

//         if (retJsonObj.getCode() != 200)
//         {
//             printf("Thread[%ld] with time[%d], failed to Encrypt the plaittext data, error message: %s \n", tid, i, retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }

//         printf("Thread[%ld] with time[%d], FFI_Encrypt json = %s\n", tid, i, returnJsonChar);

//         SAFE_FREE(returnJsonChar);
//     }

// cleanup:
//     SAFE_FREE(plaintext_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);

//     pthread_exit(NULL);
// }

// void test_parallel_encrypt()
// {
//     void *status;
//     pthread_t threads[NUM_THREADS];
//     int rc;
//     int i;
//     for (i = 0; i < NUM_THREADS; i++)
//     {
//         printf("creating thread [%d]\n", i);
//         rc = pthread_create(&threads[i], NULL, test_encrypt, (void *)i);
//         if (rc)
//         {
//             printf("Error(%d):unable to create thread\n", rc);
//             exit(-1);
//         }
//     }

//     for (i = 0; i < NUM_THREADS; i++)
//     {
//         rc = pthread_join(threads[i], &status);
//         if (rc)
//         {
//             printf("Error(%d) to join with thread[%d]\n", rc, i);
//             exit(-1);
//         }
//         printf("Main: completed thread[%d]\n", i);
//     }
//     pthread_exit(NULL);
// }

void performance_test()
{
    // test_perf_createkey();

    // test_perf_encrypt();

    // test_perf_decrypt();

    // test_perf_sign_verify();

    // test_perf_asymmetricencrypt();

    // test_perf_asymmetricdecrypt();
}