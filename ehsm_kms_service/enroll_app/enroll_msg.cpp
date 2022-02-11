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

#include "enroll_msg.h"

#include <sys/time.h>

#include "log_utils.h"
#include "ecp.h"
#include "sample_ra_msg.h"
#include "sample_libcrypto.h"

std::string g_challenge;
static sp_db_item_t g_sp_db;
static sample_spid_t g_spid;

// This is the private EC key of SP, the corresponding public EC key is
// hard coded in isv_enclave. It is based on NIST P-256 curve.
static const sample_ec256_private_t g_sp_priv_key = {
    {0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
     0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
     0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
     0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01}};

enroll_status_t ra_get_msg0(std::string *p_msg0)
{
    enroll_status_t ret = ENL_OK;
    Json::Value msg0_json;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    g_challenge = std::to_string(tv.tv_sec) + std::to_string(tv.tv_usec);
    msg0_json["challenge"] = g_challenge;
    *p_msg0 = msg0_json.toStyledString();
    return ret;
}

/*
 * process eHSM-KMS return msg1 json
 *   1. Verify challenge
 *   2. process g_a
 */
enroll_status_t ra_proc_msg1(RetJsonObj retJsonObj_msg1, sample_ec_pub_t *g_a)
{
    enroll_status_t ret = ENL_OK;
    std::string challenge_response;
    std::string ga_str;

    challenge_response = retJsonObj_msg1.readData_cstr("challenge");

    // compare challenge
    if (g_challenge.compare(challenge_response) != 0)
    {
        ret = ENL_CHALLENGE_NO_COMPARE;
        log_e("ra_proc_msg1_get_msg2 challenge no compare.");
        goto OUT;
    }
    else
    {
        log_d("ra_proc_msg1_get_msg2 challenge compare success.")
    }
    retJsonObj_msg1.readSubData_uint8Array("g_a", "gx", g_a->gx);
    retJsonObj_msg1.readSubData_uint8Array("g_a", "gy", g_a->gy);
OUT:
    return ret;
}

enroll_status_t ra_proc_msg1_get_msg2(RetJsonObj retJsonObj_msg1, std::string *p_msg2)
{
    enroll_status_t ret = ENL_OK;
    sample_ec_pub_t *g_a;

    Json::Value msg2_json;
    msg2_json["msg2_base64"] = "msg2_base64";
    *p_msg2 = msg2_json.toStyledString();

    // process g_a
    g_a = (sample_ec_pub_t *)malloc(sizeof(sample_ec_pub_t));
    if (g_a == NULL)
    {
        ret = ENL_INTERNAL_ERROR;
        log_e("malloc failed.");
        goto OUT;
    }
    ret = ra_proc_msg1(retJsonObj_msg1, g_a);
    if (ret != ENL_OK || !g_a)
    {
        log_e("ra_proc_msg1 failed(%d).", ret);
        goto OUT;
    }

OUT:
    SAFE_FREE(g_a);
    return ret;
}

enroll_status_t ra_proc_msg3_get_msg4(RetJsonObj retJsonObj_msg3, std::string *p_msg4)
{
    enroll_status_t ret = ENL_OK;
    Json::Value msg4_json;
    msg4_json["msg4_base64"] = "msg4_base64";
    *p_msg4 = msg4_json.toStyledString();
    return ret;
}