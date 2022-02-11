/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

#ifndef _ENROLL_MSG_H
#define _ENROLL_MSG_H

#include <cstring>

#include "json_utils.h"
#include "sgx_ukey_exchange.h"
#include "datatypes.h"

typedef enum
{
    ENL_OK = 0,
    ENL_CONFIG_INVALID = -1,
    ENL_POST_EXCEPTION = -2,
    ENL_NAPI_EXCEPTION = -3,
    ENL_SERIALIZE_FAILED = -4,
    ENL_DESERIALIZE_FAILED = -5,
    ENL_CHALLENGE_NO_COMPARE = -6,
    ENL_PARSE_MSG1_EXCEPTION = -7,
    ENL_HANDLE_MSG1_FAILED = -8,
    ENL_INTERNAL_ERROR = -9,
    ENL_ERROR_INVALID_PARAMETER = -10
} enroll_status_t;

enroll_status_t ra_get_msg0(std::string *p_msg0);
enroll_status_t ra_proc_msg1_get_msg2(RetJsonObj retJsonObj_msg1, std::string *p_msg2);
enroll_status_t ra_proc_msg3_get_msg4(RetJsonObj retJsonObj_msg3, std::string *p_msg4);

#endif
