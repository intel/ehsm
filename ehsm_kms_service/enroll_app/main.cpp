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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY CLEANUP OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

using namespace std;

#include <jsoncpp/json/json.h>
#include <sys/time.h>
#include <fstream>
#include <string>

#include "log_utils.h"
#include "rest_utils.h"
#include "enroll_msg.h"

int main(int argc, char *argv[])
{
    log_d("***enroll app start.");
    enroll_status_t ret = ENL_OK;
    RetJsonObj retJsonObj;

    std::string msg0_str;
    std::string msg2_str;
    std::string msg4_str;

    log_d("=> reading ehsm_kms_url .....");
    // only one parameter, it is ehsm_kms_url
    std::string ehsm_kms_url;
    if (argc == 2)
    {
        ehsm_kms_url = argv[1];
    }
    if (ehsm_kms_url.empty())
    {
        printf("\nusage: ehsm-kms_enroll_app [http://1.2.3.4:9009/ehsm/]\n\n");
        ret = ENL_CONFIG_INVALID;
        goto OUT;
    }
    log_d("ehsm_kms_url : %s", ehsm_kms_url.c_str());

    log_d("=> First handle send msg0,return msg1.");
    ret = ra_get_msg0(&msg0_str);
    log_d("msg0 : \n%s", msg0_str.c_str());

    log_d("post RA_HANDSHAKE_MSG0.....");
    post_KMS(ehsm_kms_url + "?Action=RA_HANDSHAKE_MSG0", msg0_str, &retJsonObj);
    if (!retJsonObj.isSuccess())
    {
        log_e("NAPI Exception: %s", retJsonObj.getMessage().c_str());
        ret = ENL_NAPI_EXCEPTION;
        goto OUT;
    }
    log_d("post success msg1 : \n%s", retJsonObj.toString().c_str());
    log_d("First handle success.");

    log_d("=> Second handle send msg2,return msg3.");
    ret = ra_proc_msg1_get_msg2(retJsonObj, &msg2_str);
    if (ret != ENL_OK || msg2_str.empty())
    {
        log_e("ra_proc_msg1_get_msg2 failed. error code [%d]\n", ret);
        goto OUT;
    }
    log_d("msg2 : \n%s", msg2_str.c_str());

    post_KMS(ehsm_kms_url + "?Action=RA_HANDSHAKE_MSG2", msg2_str, &retJsonObj);
    if (!retJsonObj.isSuccess())
    {
        log_e("NAPI Exception: %s", retJsonObj.getMessage().c_str());
        ret = ENL_NAPI_EXCEPTION;
        goto OUT;
    }
    log_d("post success msg3 : \n%s", retJsonObj.toString().c_str());
    log_d("Second handle success.");

    log_d("=> Third handle send msg4,return msg7.");
    ret = ra_proc_msg3_get_msg4(retJsonObj, &msg4_str);
    if (ret != ENL_OK || msg4_str.empty())
    {
        log_e("ra_proc_msg1_get_msg2 failed. error code [%d]\n", ret);
        ret = ENL_NAPI_EXCEPTION;
        goto OUT;
    }
    log_d("msg4 : \n%s", msg4_str.c_str());

    post_KMS(ehsm_kms_url + "?Action=RA_GET_API_KEY", msg4_str, &retJsonObj);
    if (!retJsonObj.isSuccess())
    {
        log_e("NAPI Exception: %s", retJsonObj.getMessage().c_str());
        ret = ENL_NAPI_EXCEPTION;
        goto OUT;
    }
    log_d("post success msg7 : \n%s", retJsonObj.toString().c_str());

    printf("\n**************** Enroll APP **********************");
    printf("\n\nappid: %s", retJsonObj.readData_cstr("appid"));
    printf("\n\napikey: %s", retJsonObj.readData_cstr("apikey"));
    printf("\n\n**************************************************\n\n");

    log_d("Third handle success.");
OUT:
    log_d("***enroll app end.");
    return ret;
}