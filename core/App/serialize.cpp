/*
 * Copyright (C) 2021-2022 Intel Corporation
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
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <cstring>
#include "serialize.h"


uint8_t *append_to_buf(uint8_t *buf, const void *data, size_t data_len)
{
    if (data && data_len) {
        memcpy(buf, (void *)data, data_len);
    }
    return buf + data_len;
}

uint8_t *append_uint32_to_buf(uint8_t *buf, uint32_t val)
{
    return append_to_buf(buf, &val, sizeof(val));
}

uint8_t *append_sized_buf_to_buf(uint8_t *buf, const uint8_t *data,
                                 uint32_t data_len)
{
    return append_to_buf(buf, data, data_len);
}

ehsm_status_t ehsm_serialize_cmk(const ehsm_keyblob_t *cmk, uint8_t** out,
                             uint32_t *out_size)
{
    uint8_t *tmp;

    if (!out || !cmk || !out_size) {
        return EH_ARGUMENTS_BAD;
    }

    *out_size = sizeof(cmk->metadata) + cmk->keybloblen;
    *out = (uint8_t*)malloc(*out_size);
    if(!*out) {
        return EH_DEVICE_MEMORY;
    }

    tmp = append_sized_buf_to_buf(*out, (uint8_t*)&(cmk->metadata), sizeof(cmk->metadata));
    tmp = append_sized_buf_to_buf(tmp, cmk->keyblob, cmk->keybloblen);

    return EH_OK;
}

ehsm_status_t ehsm_deserialize_cmk(ehsm_keyblob_t *cmk, const uint8_t* data, uint32_t datalen)
{
    uint8_t *keyblob;
    uint32_t keybloblen;

    if (!cmk || !data || !datalen) {
        return EH_ARGUMENTS_BAD;
    }

    if (datalen < sizeof(ehsm_keyblob_t)) {
        return EH_ARGUMENTS_BAD;
    }

    memcpy(&(cmk->metadata), data, sizeof(ehsm_keymetadata_t));

    keybloblen = datalen - sizeof(ehsm_keymetadata_t);
    keyblob = (uint8_t *) malloc(keybloblen);
    if (!keyblob) {
        return EH_DEVICE_MEMORY;
    }

    memcpy(keyblob, data+sizeof(ehsm_keymetadata_t), keybloblen);

    cmk->keyblob = keyblob;
    cmk->keybloblen = keybloblen;

    return EH_OK;
}

