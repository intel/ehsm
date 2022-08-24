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

#include "enclave_t.h"
#include "sgx_tseal.h"

#include <string>
#include <stdio.h>
#include <stdbool.h>
#include <mbusafecrt.h>

#define SGX_DOMAIN_KEY_SIZE 16

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

sgx_status_t sgx_get_domainkey(uint8_t *domain_key)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t dk_cipher_len = sgx_calc_sealed_data_size(0, SGX_DOMAIN_KEY_SIZE);

    if (dk_cipher_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    int retstatus;
    uint8_t dk_cipher[dk_cipher_len] = {0};
    uint8_t tmp[SGX_DOMAIN_KEY_SIZE] = {0};

    ret = ocall_read_domain_key(&retstatus, dk_cipher, dk_cipher_len);
    if (ret != SGX_SUCCESS)
        return ret;

    if (retstatus == 0) {
        uint32_t dk_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)dk_cipher);

        ret = sgx_unseal_data((const sgx_sealed_data_t *)dk_cipher, NULL, 0, tmp, &dk_len);
	if (ret != SGX_SUCCESS)
            return ret;
    }
    // -2: dk file does not exist.
    else if (retstatus == -2) {
        printf("enclave file does not exist.\n");
        ret = sgx_read_rand(tmp, SGX_DOMAIN_KEY_SIZE);
        if (ret != SGX_SUCCESS) {
            return ret;
        }

        ret = sgx_seal_data(0, NULL, SGX_DOMAIN_KEY_SIZE, tmp, dk_cipher_len, (sgx_sealed_data_t *)dk_cipher);
        if (ret != SGX_SUCCESS)
            return SGX_ERROR_UNEXPECTED;

        ret = ocall_store_domain_key(&retstatus, dk_cipher, dk_cipher_len);
        if (ret != SGX_SUCCESS || retstatus != 0)
            return SGX_ERROR_UNEXPECTED;
    }
    else
        return SGX_ERROR_UNEXPECTED;

    memcpy_s(domain_key, SGX_DOMAIN_KEY_SIZE, tmp, SGX_DOMAIN_KEY_SIZE);
    memset_s(tmp, SGX_DOMAIN_KEY_SIZE, 0, SGX_DOMAIN_KEY_SIZE);

    return ret;
}

/* encrypt dk with session key */
sgx_status_t sgx_wrap_domain_key(sgx_aes_gcm_128bit_key_t *p_key,
                                 uint8_t *p_dst, size_t p_dst_len,
                                 sgx_aes_gcm_128bit_tag_t *p_out_mac)
{
    uint8_t domain_key[SGX_DOMAIN_KEY_SIZE];
    uint8_t aes_gcm_iv[12] = {0};

    if (p_dst_len < SGX_DOMAIN_KEY_SIZE)
        return SGX_ERROR_UNEXPECTED;

    sgx_status_t ret = sgx_get_domainkey(domain_key);
    if (ret != SGX_SUCCESS) {
        printf("Failed to get domain:%d.\n", ret);
        return ret;
    }

    ret = sgx_rijndael128GCM_encrypt(p_key,
                                     domain_key, SGX_DOMAIN_KEY_SIZE,
                                     p_dst,
                                     aes_gcm_iv, sizeof(aes_gcm_iv),
                                     NULL, 0,
                                     p_out_mac);

    return ret;
}

