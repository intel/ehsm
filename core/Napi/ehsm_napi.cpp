/*
 * Copyright (C) 2020-2021 Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <cstdint>
#include "ehsm_provider.h"
#include "dsohandle.h"
#include <cstring>
#include <iostream>
#include "base64.h"

#define EH_AES_CRE_KEY_SIZE  64
using namespace EHsmProvider;

std::string intToString(int value)
{
	char buf[32] = {0};
	snprintf(buf, sizeof(buf), "%u", value);
	std::string str = buf;
	return str;
}

struct RetJsonObj 
{
    const int CODE_FAILED = 500;
    const int CODE_SUCCESS = 200;
    int code = CODE_SUCCESS;
    std::string msg = "success!";
    std::string jsonStr;

    void addData(std::string key, std::string data)
    {
        if(jsonStr.size() > 0){
            jsonStr += ",";
        }
        jsonStr += "\""+key+"\" : " + "\""+data+"\"";
    };

    char* toChar()
    {
        std::string retString = "{";
        retString += "\"code\":" + intToString(code);
        retString += ",\"message\":\"" + msg;
        retString += "\"";
        retString += ",\"result\":{"+jsonStr+"}";
        retString += "}";

        char* retChar;
        const char* srcChar = retString.c_str();
        int len = retString.size();
        retChar = (char *)malloc(retString.size() * sizeof(uint8_t));
        if(retChar != nullptr){
            memset(retChar, 0, len);
            memcpy(retChar, srcChar, strlen(srcChar));
        }
        return retChar;
    };

};


extern "C" char* CreateKey_napi(int intMechanism, int intOrigin)
{
    ehsm_status_t rv = EH_FUNCTION_FAILED;
    ehsm_keyblob_t cmk;
    RetJsonObj retJsonObj;
    cmk.keyblob = nullptr;
    cmk.keybloblen = 0;
    cmk.metadata.origin = (ehsm_keyorigin_t)intOrigin;
    cmk.metadata.keyspec = (ehsm_keyspec_t)intMechanism;
    printf("========== CreateKey_napi start==========\n");

    rv = Initialize();
    if (rv != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Initialize failed!";
        return retJsonObj.toChar();
    }
    printf("Initialize done\n");

    if ((rv = CreateKey(&cmk)) == EH_OK) {
        cmk.keyblob = (uint8_t*)malloc(cmk.keybloblen * sizeof(uint8_t));
        if (cmk.keyblob == nullptr) {
            retJsonObj.code = retJsonObj.CODE_FAILED;
            retJsonObj.msg = "Can't load size!";
            return retJsonObj.toChar();
        }

        rv = CreateKey(&cmk);
        if (rv != EH_OK) {
            retJsonObj.code = retJsonObj.CODE_FAILED;
            retJsonObj.msg = "create key failed!";
            return retJsonObj.toChar();
        }
    } else {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "create key failed!";
        return retJsonObj.toChar();
    }

    std::string key_base64;
    key_base64 = base64_encode(cmk.keyblob, cmk.keybloblen);

    if(cmk.keyblob != NULL){   
      free(cmk.keyblob);
    }
    printf("========== CreateKey_napi done==========\n");
    if(key_base64.size() > 0){
        RetJsonObj retObj;
        retObj.addData("key", key_base64);
        return retObj.toChar();
    } 
    
    retJsonObj.code = retJsonObj.CODE_FAILED;
    retJsonObj.msg = "create key napi failed!";
    return retJsonObj.toChar();
}
