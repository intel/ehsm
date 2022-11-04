/*
 * Copyright (C) 2020-2022 Intel Corporation
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
#include "log_utils.h"
#include "sgx_tseal.h"

#include <string>
#include <stdio.h>
#include <stdbool.h>
#include <mbusafecrt.h>

#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"

#ifndef _KEY_OPERATION_H_
#define _KEY_OPERATION_H_

void printf(const char *fmt, ...);

sgx_status_t ehsm_aes_gcm_encrypt(ehsm_data_t *aad,
                                  ehsm_keyblob_t *cmk,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob);

sgx_status_t ehsm_aes_gcm_decrypt(ehsm_data_t *aad,
                                  ehsm_keyblob_t *cmk,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext);

sgx_status_t aes_gcm_encrypt(uint8_t *key, uint8_t *cipherblob,
                             const EVP_CIPHER *block_mode,
                             uint8_t *plaintext, uint32_t plaintext_len,
                             uint8_t *aad, uint32_t aad_len,
                             uint8_t *iv, uint32_t iv_len,
                             uint8_t *tag, uint32_t tag_len);

sgx_status_t aes_gcm_decrypt(uint8_t *key, uint8_t *plaintext,
                             const EVP_CIPHER *block_mode,
                             uint8_t *ciphertext, uint32_t ciphertext_len,
                             uint8_t *aad, uint32_t aad_len,
                             uint8_t *iv, uint32_t iv_len,
                             uint8_t *tag, uint32_t tag_len);

sgx_status_t ehsm_sm4_ctr_encrypt(ehsm_keyblob_t *cmk_blob,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob);

sgx_status_t ehsm_sm4_ctr_decrypt(ehsm_keyblob_t *cmk_blob,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext);

sgx_status_t sm4_ctr_encrypt(uint8_t *key, uint8_t *cipherblob,
                             uint8_t *plaintext, uint32_t plaintext_len,
                             uint8_t *iv);

sgx_status_t sm4_ctr_decrypt(uint8_t *key, uint8_t *plaintext,
                             uint8_t *ciphertext, uint32_t ciphertext_len,
                             uint8_t *iv);

sgx_status_t ehsm_sm4_cbc_encrypt(ehsm_keyblob_t *cmk,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob);

sgx_status_t ehsm_sm4_cbc_decrypt(ehsm_keyblob_t *cmk,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext);

sgx_status_t sm4_cbc_encrypt(uint8_t *key, uint8_t *cipherblob,
                             uint8_t *plaintext, uint32_t plaintext_len,
                             uint8_t *iv);

sgx_status_t sm4_cbc_decrypt(uint8_t *key, uint8_t *plaintext,
                             uint8_t *ciphertext, uint32_t ciphertext_len,
                             uint8_t *iv);

sgx_status_t ehsm_rsa_encrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext);

sgx_status_t ehsm_rsa_decrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *ciphertext,
                              ehsm_data_t *plaintext);

sgx_status_t ehsm_sm2_encrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext);

sgx_status_t ehsm_sm2_decrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *ciphertext,
                              ehsm_data_t *plaintext);

sgx_status_t rsa_sign(RSA *rsa_prikey,
                      const EVP_MD *digestMode,
                      ehsm_padding_mode_t padding_mode,
                      const uint8_t *data,
                      uint32_t data_len,
                      uint8_t *signature,
                      uint32_t signature_len);

sgx_status_t ehsm_rsa_sign(const ehsm_keyblob_t *cmk_blob,
                           const ehsm_data_t *data,
                           ehsm_data_t *signature);

sgx_status_t rsa_verify(RSA *rsa_pubkey,
                       const EVP_MD *digestMode,
                       ehsm_padding_mode_t padding_mode,
                       const uint8_t *data,
                       uint32_t data_len,
                       const uint8_t *signature,
                       uint32_t signature_len,
                       bool *result,
                       int saltlen);

sgx_status_t ehsm_rsa_verify(const ehsm_keyblob_t *cmk,
                             const ehsm_data_t *data,
                             const ehsm_data_t *signature,
                             bool *result);

sgx_status_t ecc_sign(EC_KEY *ec_key,
                      const EVP_MD *digestMode,
                      const uint8_t *data,
                      uint32_t data_len,
                      uint8_t *signature,
                      uint32_t *signature_len);

sgx_status_t ehsm_ecc_sign(const ehsm_keyblob_t *cmk,
                           const ehsm_data_t *data,
                           ehsm_data_t *signature);

sgx_status_t ecc_verify(EC_KEY *ec_key,
                        const EVP_MD *digestMode,
                        const uint8_t *data,
                        uint32_t data_len,
                        const uint8_t *signature,
                        uint32_t signature_len,
                        bool *result);

sgx_status_t ehsm_ecc_verify(const ehsm_keyblob_t *cmk,
                             const ehsm_data_t *data,
                             const ehsm_data_t *signature,
                             bool *result);

sgx_status_t sm2_sign(EC_KEY *ec_key,
                      const EVP_MD *digestMode,
                      const uint8_t *data,
                      uint32_t data_len,
                      uint8_t *signature,
                      uint32_t *signature_len);

sgx_status_t ehsm_sm2_sign(const ehsm_keyblob_t *cmk,
                           const ehsm_data_t *data,
                           ehsm_data_t *signature);

sgx_status_t sm2_verify(EC_KEY *ec_key,
                        const EVP_MD *digestMode,
                        const uint8_t *data,
                        uint32_t data_len,
                        const uint8_t *signature,
                        uint32_t signature_len,
                        bool *result);

sgx_status_t ehsm_sm2_verify(const ehsm_keyblob_t *cmk,
                             const ehsm_data_t *data,
                             const ehsm_data_t *signature,
                             bool *result);

#endif