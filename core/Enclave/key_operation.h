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
#include "elog_utils.h"
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

void log_printf(uint32_t log_level, const char *filename, uint32_t line, const char *fmt, ...);
uint32_t getPaddingMode(ehsm_padding_mode_t padding_mode);

sgx_status_t ehsm_get_public_key(ehsm_keyblob_t *cmk_blob,
                                 ehsm_data_t *pubkey);

sgx_status_t ehsm_aes_gcm_encrypt(ehsm_data_t *aad,
                                  ehsm_keyblob_t *cmk,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob);

sgx_status_t ehsm_aes_gcm_decrypt(ehsm_data_t *aad,
                                  ehsm_keyblob_t *cmk,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext);

sgx_status_t ehsm_sm4_ctr_encrypt(ehsm_keyblob_t *cmk_blob,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob);

sgx_status_t ehsm_sm4_ctr_decrypt(ehsm_keyblob_t *cmk_blob,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext);

sgx_status_t ehsm_sm4_cbc_encrypt(ehsm_keyblob_t *cmk,
                                  ehsm_data_t *plaintext,
                                  ehsm_data_t *cipherblob);

sgx_status_t ehsm_sm4_cbc_decrypt(ehsm_keyblob_t *cmk,
                                  ehsm_data_t *cipherblob,
                                  ehsm_data_t *plaintext);

sgx_status_t ehsm_rsa_encrypt(const ehsm_keyblob_t *cmk,
                              ehsm_padding_mode_t padding_mode,
                              const ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext);

sgx_status_t ehsm_rsa_decrypt(const ehsm_keyblob_t *cmk,
                              ehsm_padding_mode_t padding_mode,
                              const ehsm_data_t *ciphertext,
                              ehsm_data_t *plaintext);

sgx_status_t ehsm_sm2_encrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext);

sgx_status_t ehsm_sm2_decrypt(const ehsm_keyblob_t *cmk,
                              const ehsm_data_t *ciphertext,
                              ehsm_data_t *plaintext);

sgx_status_t ehsm_rsa_sign(const ehsm_keyblob_t *cmk_blob,
                           ehsm_digest_mode_t digest_mode,
                           ehsm_padding_mode_t padding_mode,
                           ehsm_message_type_t message_type,
                           const ehsm_data_t *message,
                           ehsm_data_t *signature);

sgx_status_t ehsm_rsa_verify(const ehsm_keyblob_t *cmk,
                             ehsm_digest_mode_t digest_mode,
                             ehsm_padding_mode_t padding_mode,
                             ehsm_message_type_t message_type,
                             const ehsm_data_t *message,
                             const ehsm_data_t *signature,
                             bool *result);

sgx_status_t ehsm_ecc_sign(const ehsm_keyblob_t *cmk,
                           ehsm_digest_mode_t digest_mode,
                           ehsm_message_type_t message_type,
                           const ehsm_data_t *message,
                           ehsm_data_t *signature);

sgx_status_t ehsm_ecc_verify(const ehsm_keyblob_t *cmk,
                             ehsm_digest_mode_t digest_mode,
                             ehsm_message_type_t message_type,
                             const ehsm_data_t *message,
                             const ehsm_data_t *signature,
                             bool *result);

sgx_status_t ehsm_sm2_sign(const ehsm_keyblob_t *cmk,
                           ehsm_digest_mode_t digest_mode,
                           ehsm_message_type_t message_type,
                           const ehsm_data_t *message,
                           ehsm_data_t *signature);

sgx_status_t ehsm_sm2_verify(const ehsm_keyblob_t *cmk,
                             ehsm_digest_mode_t digest_mode,
                             ehsm_message_type_t message_type,
                             const ehsm_data_t *message,
                             const ehsm_data_t *signature,
                             bool *result);

#endif