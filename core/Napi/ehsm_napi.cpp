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


extern "C" char* GenerateDataKey_napi(int intMechanism, char* master_key_blob)
{
    ehsm_status_t ret = EH_OK;
    RetJsonObj retJsonObj;
    ehsm_keyblob_t cmk;
    ehsm_data_t aad;
    ehsm_data_t plaint_datakey;
    ehsm_data_t cipher_datakey;

    std::string masterKeyInput = master_key_blob;
    std::string decode_masterKeyInput;
    decode_masterKeyInput = base64_decode(masterKeyInput);
    cmk.keybloblen = EH_AES_CRE_KEY_SIZE;
    cmk.keyblob = (unsigned char *)decode_masterKeyInput.c_str();
    cmk.metadata.keyspec = (ehsm_keyspec_t)intMechanism;
    cmk.metadata.origin = EH_INTERNAL_KEY;
    printf("============GenerateDataKey_napi start==========\n");
    aad.data = NULL;
    aad.datalen = 0;

    plaint_datakey.datalen = 16;
    plaint_datakey.data = (uint8_t*)malloc(plaint_datakey.datalen);
    if (plaint_datakey.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "generate data key failed!";
        return retJsonObj.toChar();
    }
    
    cipher_datakey.datalen = 0;
    ret = GenerateDataKey(&cmk, &aad, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "generate data key failed!";
        return retJsonObj.toChar();
    }

    cipher_datakey.data = (uint8_t*)malloc(cipher_datakey.datalen);
    if (cipher_datakey.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "generate data key failed!";
        return retJsonObj.toChar();
    }

    ret = GenerateDataKey(&cmk, &aad, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "generate data key failed!";
        return retJsonObj.toChar();
    }
    printf("============GenerateDataKey_napi done==========\n");
    std::string encode_plaintdatakey;
    encode_plaintdatakey = base64_encode(plaint_datakey.data, plaint_datakey.datalen);
    std::string encode_cipherdatakey;
    encode_cipherdatakey = base64_encode(cipher_datakey.data, cipher_datakey.datalen);

    RetJsonObj retObj;
    if(plaint_datakey.data != nullptr && cipher_datakey.data != nullptr){
        retObj.addData("dataKey", encode_plaintdatakey);
        retObj.addData("enKey", encode_cipherdatakey);
        return retObj.toChar();
    } 

    retJsonObj.code = retJsonObj.CODE_FAILED;
    retJsonObj.msg = "generate data key napi failed!";
    return retJsonObj.toChar();
}
