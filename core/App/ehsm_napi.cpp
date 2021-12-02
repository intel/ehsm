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
#include <cstring>
#include "base64.h"
#include "ehsm_napi.h"

#include "serialize.h"

//#include "ehsm_provider.h"

using namespace std;
using namespace EHsmProvider;

static char* StringToChar(std::string str)
{
    char *retChar = NULL;
    if (str.size() > 0) {
        int len = str.size();
        retChar = (char *)malloc(len * sizeof(uint8_t));
        if(retChar != nullptr){
            memset(retChar, 0, len);
            memcpy(retChar, str.c_str(), len);
        }
    }
    return retChar;
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
        retString += "\"code\":" + std::to_string(code);
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

extern "C" {

/*
@return
[string] cmk -- the customer master key.
*/
char* NAPI_CreateKey(const uint32_t keyspec, const uint32_t origin)
{
    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t master_key;

    string cmk_base64;
    RetJsonObj retJsonObj;

    uint8_t *resp = NULL;
    uint32_t resp_len = 0;

    master_key.metadata.keyspec = keyspec;
    master_key.metadata.origin = EH_INTERNAL_KEY;
    master_key.keybloblen = 0;
    ret = CreateKey(&master_key);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to get size of CreateKey";
        goto out;
    }

    master_key.keyblob = (uint8_t*)malloc(master_key.keybloblen);
    if (master_key.keyblob == NULL) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Can't load size!";
        goto out;

    }

    ret = CreateKey(&master_key);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to CreateKey";
        goto out;
    }

    ret = ehsm_serialize_cmk(&master_key, &resp, &resp_len);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to serialize the cmk";
        goto out;
    }

    cmk_base64 = base64_encode(resp, resp_len);
    if(cmk_base64.size() > 0){
        /*todo: make the unittest case happy, remove it later after added the c++ json parser*/
        SAFE_FREE(master_key.keyblob);
        SAFE_FREE(resp);
        return StringToChar(cmk_base64);
        //retJsonObj.code = retJsonObj.CODE_SUCCESS;
        //retJsonObj.addData("key", cmk_base64);
    }

out:
    SAFE_FREE(master_key.keyblob);
    SAFE_FREE(resp);

    return retJsonObj.toChar();
}

/*
@return
[string] ciphertext -- the encrypted datas
*/
char* NAPI_Encrypt(const char* cmk_base64,
        const char* plaintext,
        const char* aad)
{
    RetJsonObj retJsonObj;
    string decode_str;
    string cipher_base64;

    ehsm_status_t ret = EH_OK;

    ehsm_keyblob_t masterkey;

    ehsm_data_t plaint_data;
    ehsm_data_t aad_data;
    ehsm_data_t cipher_data;

    decode_str = base64_decode(cmk_base64);

    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)decode_str.data(), decode_str.size());
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to deserialize the cmk";
        goto out;
    }

    plaint_data.datalen = strlen(plaintext);
    plaint_data.data = (uint8_t*)plaintext;

    aad_data.datalen = strlen(aad);
    aad_data.data = (uint8_t*)aad;

    cipher_data.datalen = 0;
    ret = Encrypt(&masterkey, &plaint_data, &aad_data, &cipher_data);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to get size of Encrypt";
        goto out;
    }

    cipher_data.data = (uint8_t*)malloc(cipher_data.datalen);
    if (cipher_data.data == NULL) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to alloc memory";
        goto out;
    }

    ret = Encrypt(&masterkey, &plaint_data, &aad_data, &cipher_data);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to Encrypt data";
        goto out;
    }

    cipher_base64 = base64_encode(cipher_data.data, cipher_data.datalen);
    if(cipher_base64.size() > 0){
        /*todo: make the unittest case happy, remove it later after added the c++ json parser*/
        SAFE_FREE(masterkey.keyblob);
        SAFE_FREE(cipher_data.data);
        return StringToChar(cipher_base64);
        //retJsonObj.code = retJsonObj.CODE_SUCCESS;
        //retJsonObj.addData("key", cipher_base64);
    }

out:
    SAFE_FREE(masterkey.keyblob);
    SAFE_FREE(cipher_data.data);

    return retJsonObj.toChar();
}

/*
@return
[string] plaintext -- the plaintext datas
*/
char* NAPI_Decrypt(const char* cmk,
        const char* ciphertext,
        const char* aad)
{
    string decode_cmk;
    string decode_cipher;
    string plaintext_base64;

    RetJsonObj retJsonObj;
    ehsm_status_t ret = EH_OK;

    ehsm_keyblob_t masterkey;

    ehsm_data_t plaint_data;
    ehsm_data_t aad_data;
    ehsm_data_t cipher_data;

    decode_cmk = base64_decode(cmk);

    decode_cipher = base64_decode(ciphertext);

    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)decode_cmk.data(), decode_cmk.size());
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to deserialize cmk";
        goto out;
    }

    cipher_data.datalen = decode_cipher.size();
    cipher_data.data = (uint8_t*)decode_cipher.data();

    aad_data.datalen = strlen(aad);
    aad_data.data = (uint8_t*)aad;

    plaint_data.datalen = 0;
    ret = Decrypt(&masterkey, &cipher_data, &aad_data, &plaint_data);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to get size of Decrypt";
        goto out;
    }

    plaint_data.data = (uint8_t*)malloc(plaint_data.datalen);
    if (plaint_data.data == NULL) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to alloc memory";
        goto out;
    }

    ret = Decrypt(&masterkey, &cipher_data, &aad_data, &plaint_data);
    if (ret != EH_OK) {
        retJsonObj.code = retJsonObj.CODE_FAILED;
        retJsonObj.msg = "Failed to decrypt data";
        goto out;
    }

    plaintext_base64 = base64_encode(plaint_data.data, plaint_data.datalen);
    if(plaintext_base64.size() > 0){
        /*todo: make the unittest case happy, remove it later after added the c++ json parser*/
        SAFE_FREE(masterkey.keyblob);
        SAFE_FREE(plaint_data.data);
        return StringToChar(plaintext_base64);
        //retJsonObj.code = retJsonObj.CODE_SUCCESS;
        //retJsonObj.addData("key", plaintext_base64);
    }
out:
    SAFE_FREE(masterkey.keyblob);
    SAFE_FREE(plaint_data.data);

    return retJsonObj.toChar();
}
//TODO: add the implementation of each ehsm napi


}  // extern "C"
