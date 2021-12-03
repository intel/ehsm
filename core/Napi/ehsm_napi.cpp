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


extern "C" char* Decrypt_napi(int intMechanism, char* key, char* plaintext)
{
    ehsm_status_t rv = EH_FUNCTION_FAILED;
    RetJsonObj retJsonObj;
    ehsm_data_t plain_text;
    ehsm_data_t outPuttext;
    ehsm_data_t aad;
    ehsm_keyblob_t cmk;

    std::string KeyInput = key;
    std::string decode_KeyInput;
    decode_KeyInput = base64_decode(KeyInput);
    cmk.keybloblen = EH_AES_CRE_KEY_SIZE;
    cmk.keyblob = (unsigned char *)decode_KeyInput.c_str();
    cmk.metadata.keyspec = (ehsm_keyspec_t)intMechanism;

    std::string plaintextInput = plaintext;
    std::string decode_plaintext;
    decode_plaintext = base64_decode(plaintextInput);
    plain_text.datalen = decode_plaintext.size();
    plain_text.data = (unsigned char *)decode_plaintext.c_str();
    
    printf("========== Decrypt_napi start==========\n");

    rv = Initialize();
    if (rv != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "decrypt failed!";
        return retJsonObj.toChar();
    }
    printf("Initialize done\n");

    aad.datalen = 0;
    aad.data = NULL;
    outPuttext.datalen = 0;

    rv = Decrypt(&cmk, &plain_text, &aad, &outPuttext);
    if (rv != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "decrypt failed!";
        return retJsonObj.toChar();
    }
    outPuttext.data = (uint8_t*)malloc(outPuttext.datalen);
    if (outPuttext.data == nullptr) {
        rv = EH_DEVICE_MEMORY;
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "decrypt failed!";
        return retJsonObj.toChar();
    }

    rv = Decrypt(&cmk, &plain_text, &aad, &outPuttext);
    if (rv != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "decrypt failed!";
        return retJsonObj.toChar();
    }
    std::string encode_outPuttext;
    encode_outPuttext = base64_encode(outPuttext.data, outPuttext.datalen);

    printf("========== Decrypt_napi done==========\n");
    if(outPuttext.data != nullptr){
        RetJsonObj retObj;
        retObj.addData("data", encode_outPuttext);
        return retObj.toChar();
    } 
    
    retJsonObj.code = retJsonObj.CODE_FAILED;
    retJsonObj.msg = "decrypt napi failed!";
    return retJsonObj.toChar();
}
