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

typedef struct {
    const int CODE_SUCCESS = 200;
    const int CODE_FAILED = 500;

    int code = CODE_SUCCESS;
    std::string msg = "success!";
    std::string jsonStr;
	
	void setCode(int newCode){code = newCode;};
	void setMessage(string message){msg = message;};
	void addData(string key, uint32_t data) {
        if(jsonStr.size() > 0){
            jsonStr += ",";
        }
        jsonStr += "\""+key+"\":" + "\""+std::to_string(data)+"\"";
    };
	void addData(string key, string data) {
        if(jsonStr.size() > 0){
            jsonStr += ",";
        }
        jsonStr += "\""+key+"\":" + "\""+data+"\"";
    };
	void addData(string key, bool data) {
        if(jsonStr.size() > 0){
            jsonStr += ",";
        }
        if(data){
            jsonStr += "\""+key+"\":true";
        } else {
            jsonStr += "\""+key+"\":false";
        }
    };

    char* toChar() {
        std::string retString = "{";
        retString += "\"code\":" + std::to_string(code);
        retString += ",\"message\":\"" + msg;
        retString += "\"";
        retString += ",\"result\":{"+jsonStr+"}";
        retString += "}";
        return StringToChar(retString);
	};
 
    static char* readData_string(char* jsonChar, std::string key){
        std::string retVal;
        std::string jsonString = jsonChar;
        key = "\"" + key + "\"";

        int resultIndex = jsonString.find("\"result\"") + strlen("\"result\":");
        std::string resultStr = jsonString.substr(resultIndex);

        int startIndex = resultStr.find(key) + key.size() + 1;
        std::string subStr = resultStr.substr(startIndex);

        if(subStr[0] == '\"'){
            int endIndex = subStr.find_first_of("\"",1) - 1;
            retVal = subStr.substr(1,endIndex);
        }
        return StringToChar(retVal);
	};
 
    static bool readData_bool(char* jsonChar, std::string key){
        std::string retVal;
        std::string jsonString = jsonChar;
        key = "\"" + key + "\"";

        int resultIndex = jsonString.find("\"result\"") + strlen("\"result\":");
        std::string resultStr = jsonString.substr(resultIndex);

        int startIndex = resultStr.find(key) + key.size() + 1;
        std::string subStr = resultStr.substr(startIndex);

        if(subStr[0] == 't'){
            return true;
        } else {
            return false;
        }
	};
} RetJsonObj;

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
[char*] ciphertext -- the encrypted datas
*/
char* NAPI_AsymmetricEncrypt(const char* cmk_base64,
    const char* plaintext);

/*
@return
[char*] plaintext -- the plaintext datas
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
[char*] newdatakey -- the newdatakey wrapped by the ukey
*/
char* NAPI_ExportDataKey(const char* cmk,
        const char* ukey,
        const char* aad,
        const char* olddatakey);

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


}  // extern "C"


#endif