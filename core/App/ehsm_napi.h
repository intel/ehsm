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

#ifndef _EHSM_NAPI_H
#define _EHSM_NAPI_H

#include "../../dkeycache/App/sample_ra_msg.h"
// Needed to create enclave and do ecall.
#include "sgx_urts.h"
#include "datatypes.h"
// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"
#include "sgx_tkey_exchange.h"
#include <json/json.h>

using namespace std;

extern "C" {

static char* StringToChar(string str)
{
    char *retChar = NULL;
    if (str.size() > 0) {
        int len = str.size() + 1;
        retChar = (char *)malloc(len * sizeof(uint8_t));
        if(retChar != nullptr){
            memset(retChar, 0, len);
            memcpy(retChar, str.c_str(), len);
        }
    }
    return retChar;
}

struct RetJsonObj{
    const int CODE_SUCCESS = 200;
    const int CODE_BAD_REQUEST = 400;
    const int CODE_FAILED = 500;

    Json::Value m_json;
    Json::Value result_json;

public:
    RetJsonObj(){
        m_json["code"] = CODE_SUCCESS;
        m_json["message"] = "success!";
    }
	
	void setCode(int code){m_json["code"] = code;};
	void setMessage(string message){m_json["message"] = message;};

	void addData(string key, bool data) {
        result_json[key] = data;
    };
    
	void addData(string key, int data) {
        result_json[key] = data;
    };

	void addData(string key, string data) {
        result_json[key] = data;
    };


    char* toChar() {
        m_json["result"] = result_json;
        return StringToChar(m_json.toStyledString());
	};

    void parse(std::string jsonStr){
        Json::CharReaderBuilder builder;
        const unique_ptr<Json::CharReader> reader(builder.newCharReader());
        string err;
        bool res = reader->parse(jsonStr.c_str(), jsonStr.c_str()+jsonStr.size(), &m_json, &err);
        if (!res || !err.empty()) {
            printf("Error: can't parse response json.%s\n", err.c_str());
        }
    }

    void parse(char* jsonChar){
        string jsonStr = jsonChar;
        return parse(jsonStr);
    }


    int getCode(){
        return m_json["code"].asInt();
    }

    std::string getMessage(){
        return m_json["message"].asString();
    }
 
    char* readData_string(std::string key){
        return StringToChar(result_json[key].asString());
	};
 
    bool readData_bool(std::string key){
        return result_json[key].asBool();
	};
} ;

/*
create the enclave
@return
[string] json string
    {
        code: int,
        message: string,
        result: {}
    }
*/
char* NAPI_Initialize();

/*
destory the enclave
*/
void NAPI_Finalize();

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            cmk_base64 : string
        }
    }
*/
char* NAPI_CreateKey(const uint32_t keyspec, const uint32_t origin);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            cipherText_base64 : string
        }
    }
*/
char* NAPI_Encrypt(const char* cmk_base64,
        const char* plaintext,
        const char* aad);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            plaintext_base64 : string
        }
    }
*/
char* NAPI_Decrypt(const char* cmk_base64,
        const char* ciphertext_base64,
        const char* aad);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            ciphertext_base64 : string,
        }
    }
*/
char* NAPI_AsymmetricEncrypt(const char* cmk_base64,
    const char* plaintext);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            plaintext_base64 : string,
        }
    }
*/
char* NAPI_AsymmetricDecrypt(const char* cmk_base64,
        const char* ciphertext_base64);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            plaintext_base64 : string,
            cipherText_base64 : string
        }
    }
*/
char* NAPI_GenerateDataKey(const char* cmk_base64,
        const uint32_t keylen,
        const char* aad);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            ciphertext_base64 : string
        }
    }
*/
char* NAPI_GenerateDataKeyWithoutPlaintext(const char* cmk_base64,
        const uint32_t keylen,
        const char* aad);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            newdatakey_base64 : string,
        }
    }
*/
char* NAPI_ExportDataKey(const char* cmk_base64,
        const char* ukey_base64,
        const char* aad,
        const char* olddatakey_base64);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            signature_base64 : string
        }
    }
*/
char* NAPI_Sign(const char* cmk_base64,
        const char* digest);

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            result : bool
        }
    }
*/
char* NAPI_Verify(const char* cmk_base64,
        const char* digest,
        const char* signature_base64);


char* NAPI_RA_HANDSHAKE_MSG0(const char* request);

// char* NAPI_RA_HANDSHAKE_MSG2(const char* request);

// char* NAPI_RA_GET_API_KEY(const char* request);

}  // extern "C"


#endif