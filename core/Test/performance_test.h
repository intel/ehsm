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

#include <iostream>
#include <fstream>

#include <pthread.h>
#include <chrono>

#define PERF_NUM 1000

#define AESGCM_CREATEKEY_PERFNUM PERF_NUM*100
#define SM4_CREATEKEY_PERFNUM PERF_NUM*100

#define RSA_CREATEKEY_PERFNUM 10
#define EC_CREATEKEY_PERFNUM PERF_NUM
#define SM2_CREATEKEY_PERFNUM PERF_NUM
#define SM4_CREATEKEY_PERFNUM PERF_NUM*100

#define AESGCM_ENCRYPT_DECRYPT_PERFNUM PERF_NUM*100
#define SM4_ENCRYPT_DECRYPT_PERFNUM PERF_NUM*100

#define RSA_ENCRYPT_PERFNUM PERF_NUM
#define RSA_DECRYPT_PERFNUM PERF_NUM
#define SM2_ENCRYPT_DECRYPT_PERFNUM PERF_NUM

#define RSA_SIGN_VERIFY_PERFNUM PERF_NUM
#define EC_SIGN_PERFNUM PERF_NUM/10
#define EC_VERIFY_PERFNUM PERF_NUM/10
#define SM2_SIGN_VERIFY_PERFNUM PERF_NUM


#define NUM_THREADS 100

void performance_test();

/**
 * create symmetric key supported
 * aesgcm128, aesgcm192, aesgcm256;
 * sm4_cbc, sm4_ctr;
 */
void test_perf_create_symmetric_key();

/**
 * create asymmetric key supported
 * rsa2048, rsa3072, rsa4096;
 * ecc_p224, ecc_p256, ecc_p384, ecc_p521;
 * sm2;
 */
void test_perf_create_asymmetric_key();

/**
 * symmetric_encryption supported
 * aesgcm128, aesgcm192, aesgcm256;
 * sm4_cbc, sm4_ctr;
 *
 * symmetric_decryption supported
 * aesgcm128, aesgcm192, aesgcm256;
 * sm4_cbc, sm4_ctr;
 */
void test_perf_symmetric_encryption_decryption();

/**
 * asymmetric_encryption supported
 * rsa2048, rsa3072, rsa4096 with padding mode pkcs1_oaep;
 * sm2;
 *
 * asymmetric_decryption supported
 * rsa2048, rsa3072, rsa4096 with padding mode pkcs1_oaep;
 * sm2;
 */
void test_perf_asymmetric_encryption_decryption();

/**
 * sign_verify supported
 * rsa2048, rsa3072, rsa4096 with padding mode pkcs1_pss;
 * ecc_p224, ecc_p256, ecc_p384, ecc_p521;
 * sm2;
 */
void test_perf_sign_verify();
