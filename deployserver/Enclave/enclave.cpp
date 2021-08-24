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

#define SGX_AES_KEY_SIZE 16

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

sgx_status_t sgx_create_domainkey(uint8_t *cmk_blob, size_t cmk_blob_size, size_t *req_blob_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t real_blob_len = sgx_calc_sealed_data_size(0, SGX_AES_KEY_SIZE);

    if (real_blob_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    if (req_blob_size != NULL) {
        *req_blob_size = real_blob_len;
        return SGX_SUCCESS;
    }

    if (cmk_blob == NULL || cmk_blob_size != real_blob_len)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t* tmp = (uint8_t *)malloc(SGX_AES_KEY_SIZE);
    if (tmp == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = sgx_read_rand(tmp, SGX_AES_KEY_SIZE);
    if (ret != SGX_SUCCESS) {
        free(tmp);
        return ret;
    }

    ret = sgx_seal_data(0, NULL, SGX_AES_KEY_SIZE, tmp, cmk_blob_size, (sgx_sealed_data_t *)cmk_blob);

    memset_s(tmp, SGX_AES_KEY_SIZE, 0, SGX_AES_KEY_SIZE);

    free(tmp);

    return ret;
}

