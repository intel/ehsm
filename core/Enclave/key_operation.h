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

sgx_status_t ehsm_aes_gcm_encrypt(const uint8_t *aad, size_t aad_len,
                                  const uint8_t *cmk_blob, size_t cmk_blob_size,
                                  const uint8_t *plaintext, size_t plaintext_len,
                                  uint8_t *cipherblob, size_t cipherblob_len,
                                  ehsm_keyspec_t keyspec);

sgx_status_t ehsm_aes_gcm_decrypt(const uint8_t *aad, size_t aad_len,
                                  const uint8_t *cmk_blob, size_t cmk_blob_size,
                                  const uint8_t *cipherblob, size_t cipherblob_len,
                                  uint8_t *plaintext, size_t plaintext_len,
                                  ehsm_keyspec_t keyspec);

sgx_status_t ehsm_sm4_encrypt(const uint8_t *aad, size_t aad_len,
                              const uint8_t *cmk_blob, size_t cmk_blob_size,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *cipherblob, size_t cipherblob_len,
                              ehsm_keyspec_t keyspec);

sgx_status_t ehsm_sm4_decrypt(const uint8_t *aad, size_t aad_len,
                              const uint8_t *cmk_blob, size_t cmk_blob_size,
                              const uint8_t *cipherblob, size_t cipherblob_len,
                              uint8_t *plaintext, size_t plaintext_len,
                              ehsm_keyspec_t keyspec);

sgx_status_t ehsm_asymmetric_encrypt(const ehsm_keyblob_t *cmk, ehsm_data_t *plaintext, ehsm_data_t *ciphertext);

sgx_status_t ehsm_rsa_decrypt(const ehsm_keyblob_t *cmk, ehsm_data_t *ciphertext, ehsm_data_t *plaintext);

sgx_status_t ehsm_rsa_sign(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_rsa_verify(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_ec_encrypt(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_ec_decrypt(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_ec_sign(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_ec_verify(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_sm2_sign(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_sm2_verify(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_aes_gcm_generate_datakey(const ehsm_keyblob_t *cmk);

sgx_status_t ehsm_sm4_generate_datakey(const ehsm_keyblob_t *cmk);

#endif