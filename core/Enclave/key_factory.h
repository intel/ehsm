/*
 * Copyright (C) 2020-2021 Intel Corporation
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

#ifndef _KEY_FACTORY_H_
#define _KEY_FACTORY_H_

typedef struct _aes_gcm_data_ex_t
{
    uint32_t ciphertext_size;
    uint32_t aad_size;
    uint8_t reserve1[8];
    uint8_t iv[SGX_AESGCM_IV_SIZE];
    uint8_t reserve2[4];
    uint8_t mac[SGX_AESGCM_MAC_SIZE];
    uint8_t payload[]; /* ciphertext + aad */
} sgx_aes_gcm_data_ex_t;

// use the g_domain_key to encrypt the cmk and get it ciphertext
sgx_status_t ehsm_parse_keyblob(uint8_t *plaintext,
                                sgx_aes_gcm_data_ex_t *keyblob_data);

// use the g_domain_key to decrypt the cmk and get it plaintext
sgx_status_t ehsm_create_keyblob(uint8_t *plaintext, uint32_t plaintext_size,
                                 sgx_aes_gcm_data_ex_t *keyblob_data);

// calculate the keyblob size based on the key metadata infomations.
sgx_status_t ehsm_calc_keyblob_size(const uint32_t keyspec, uint32_t &key_size);

bool ehsm_get_symmetric_key_size(ehsm_keyspec_t key_spec, uint32_t &key_size);

uint32_t ehsm_get_gcm_ciphertext_size(const sgx_aes_gcm_data_ex_t *gcm_data);

sgx_status_t ehsm_create_aes_key(ehsm_keyblob_t *cmk);

sgx_status_t ehsm_create_rsa_key(ehsm_keyblob_t *cmk);

sgx_status_t ehsm_create_rsa_key_for_BYOK(ehsm_keyblob_t *cmk, ehsm_data_t *pubkey, ehsm_keyspec_t keyspec);

sgx_status_t ehsm_create_ecc_key(ehsm_keyblob_t *cmk);

sgx_status_t ehsm_create_sm2_key(ehsm_keyblob_t *cmk);

sgx_status_t ehsm_create_sm4_key(ehsm_keyblob_t *cmk);

#endif