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
#ifndef _JSON_UTILS_H
#define _JSON_UTILS_H

#include <jsoncpp/json/json.h>

class RetJsonObj{
public:
    const int CODE_SUCCESS = 200;
    const int CODE_BAD_REQUEST = 400;
    const int CODE_FAILED = 500;
private:
    Json::Value m_json;
    Json::Value m_result_json;

public:
    RetJsonObj(){
        m_json["code"] = CODE_SUCCESS;
        m_json["message"] = "success!";
    }
    virtual ~RetJsonObj(){};
     
    void setCode(int code){
        m_json["code"] = code;
    }
    void setMessage(std::string message){
        m_json["message"] = message;
    }
    void addData(std::string key, bool data){
        m_result_json[key] = data;
    }
    void addData(std::string key, int data){
        m_result_json[key] = data;
    }
    void addData(std::string key, std::string data){
        m_result_json[key] = data;
    }

    char* StringToChar(std::string str)
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

    char* toChar() {
        m_json["result"] = m_result_json;
        return StringToChar(m_json.toStyledString());
    }

    void parse(std::string jsonStr){
        Json::Reader *pJsonParser = new Json::Reader();
        bool res = pJsonParser->parse(jsonStr, m_json);
        m_result_json = m_json["result"];
        if (!res) {
            printf("Error: can't parse json string :  %s \n", jsonStr.c_str());
        }
    }

    void parse(char* jsonChar){
        std::string jsonStr = jsonChar;
        parse(jsonStr);
    }

    int getCode(){
        return m_json["code"].asInt();
    }

    std::string getMessage(){
        return m_json["message"].asString();
    }
 
    char* readData_string(std::string key){
        return StringToChar(m_result_json[key].asString());
    }
 
    bool readData_bool(std::string key){
        return m_result_json[key].asBool();
    }
};

#endif