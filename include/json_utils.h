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

#include <cstring>
#include <jsoncpp/json/json.h>

/*
 *   Connector of key with multi-layer structure
 */
#define LAYERED_CHARACTER "&->"

class JsonObj
{
private:
    Json::Value m_json;
    template <typename T>

    void addData(std::string key, T data)
    {
        m_json[key] = data;
    }

    Json::Value readData(std::string key)
    {
        return m_json[key];
    }

public:
    virtual ~JsonObj(){};

    void setJson(Json::Value json)
    {
        m_json = json;
    }
    Json::Value getJson()
    {
        return m_json;
    }

    void clear()
    {
        m_json.clear();
    }

    char *StringToChar(std::string str)
    {
        char *retChar = NULL;
        if (str.size() > 0)
        {
            int len = str.size() + 1;
            retChar = (char *)malloc(len * sizeof(uint8_t));
            if (retChar != nullptr)
            {
                memset(retChar, 0, len);
                memcpy(retChar, str.c_str(), len);
            }
        }
        return retChar;
    }

    void addData_string(std::string key, std::string data)
    {
        addData(key, data);
    }
    void addData_bool(std::string key, bool data)
    {
        addData(key, data);
    }
    void addData_uint16(std::string key, uint16_t data)
    {
        addData(key, data);
    }
    void addData_uint32(std::string key, uint32_t data)
    {
        addData(key, data);
    }
    void addData_uint64(std::string key, uint64_t data)
    {
        std::string uint64_str = std::to_string(data);
        addData(key, uint64_str);
    }
    void addData_JsonValue(std::string key, Json::Value data)
    {
        addData(key, data);
    }

    void addData_uint8Array(std::string key, uint8_t *data, uint32_t data_len)
    {
        Json::Value jsonArray;
        for (int i = 0; i < data_len; i++)
        {
            jsonArray.append(data[i]);
        }
        addData(key, jsonArray);
    }

    void addData_uint32Array(std::string key, uint32_t *data, uint32_t data_len)
    {
        Json::Value jsonArray;
        for (int i = 0; i < data_len; i++)
        {
            jsonArray.append(data[i]);
        }
        addData(key, jsonArray);
    }

    std::string toString()
    {
        Json::FastWriter writer;
        return writer.write(m_json);
    }

    bool parse(std::string jsonStr)
    {
        Json::Reader *pJsonParser = new Json::Reader();
        return pJsonParser->parse(jsonStr, m_json);
    }

    void parse(char *jsonChar)
    {
        std::string jsonStr = jsonChar;
        parse(jsonStr);
    }

    char *readData_cstr(std::string key)
    {
        return StringToChar(readData(key).asString());
    }

    std::string readData_string(std::string key)
    {
        return readData(key).asString();
    }

    bool readData_bool(std::string key)
    {
        return readData(key).asBool();
    }

    uint16_t readData_uint16(std::string key)
    {
        return (uint16_t)readData(key).asUInt();
    }

    uint32_t readData_uint32(std::string key)
    {
        return readData(key).asUInt();
    }

    uint64_t readData_uint64(std::string key)
    {
        uint64_t u = std::strtoull(readData(key).asString().c_str(), NULL, 0);
        return u;
    }

    void readData_uint8Array(std::string key, uint8_t *data)
    {
        if (data != NULL)
        {
            Json::Value json = readData(key);
            for (int i = 0; i < json.size(); i++)
            {
                data[i] = (uint8_t)json[i].asUInt();
            }
        }
    }

    void readData_uint32Array(std::string key, uint32_t *data)
    {
        if (data != NULL)
        {
            Json::Value json = readData(key);
            for (int i = 0; i < json.size(); i++)
            {
                data[i] = (uint32_t)json[i].asUInt();
            }
        }
    }

    Json::Value readData_JsonValue(std::string key)
    {
        return readData(key);
    }

    bool hasOwnProperty(std::string key) { return !m_json[key].isNull(); }
};

class RetJsonObj
{
public:
    const int CODE_SUCCESS = 200;
    const int CODE_BAD_REQUEST = 400;
    const int CODE_FAILED = 500;

private:
    Json::Value m_json;
    JsonObj m_result_json;

public:
    RetJsonObj()
    {
        m_json["code"] = CODE_SUCCESS;
        m_json["message"] = "success!";
    }
    virtual ~RetJsonObj(){};

    void setCode(int code)
    {
        m_json["code"] = code;
    }
    void setMessage(std::string message)
    {
        m_json["message"] = message;
    }
    void setResult(JsonObj result_json)
    {
        m_result_json = result_json;
    }

    void addData_string(std::string key, std::string data)
    {
        m_result_json.addData_string(key, data);
    }
    void addData_bool(std::string key, bool data)
    {
        m_result_json.addData_bool(key, data);
    }
    void addData_uint16(std::string key, uint16_t data)
    {
        m_result_json.addData_uint16(key, data);
    }
    void addData_uint32(std::string key, uint32_t data)
    {
        m_result_json.addData_uint32(key, data);
    }
    void addData_uint64(std::string key, uint64_t data)
    {
        m_result_json.addData_uint64(key, data);
    }

    void addData_uint8Array(std::string key, uint8_t *data, uint32_t data_len)
    {
        m_result_json.addData_uint8Array(key, data, data_len);
    }

    void addData_uint32Array(std::string key, uint32_t *data, uint32_t data_len)
    {
        m_result_json.addData_uint32Array(key, data, data_len);
    }

    std::string toString()
    {
        m_json["result"] = m_result_json.getJson();
        Json::FastWriter writer;
        return writer.write(m_json);
    }

    void toChar(char *out){
        std::string str = toString();
        if (str.size() > 0)
        {
            int len = str.size() + 1;
            if (out != nullptr)
            {
                memset(out, 0, len);
                memcpy(out, str.c_str(), len);
            }
        }
    }

    void parse(std::string jsonStr)
    {
        Json::Value tmp_json;
        Json::Reader *pJsonParser = new Json::Reader();
        bool res = pJsonParser->parse(jsonStr, tmp_json);
        if (!res || tmp_json["code"].asInt() == 0)
        {
            setCode(CODE_BAD_REQUEST);
            setMessage("The returned JSON is malformed.");
        }
        else
        {
            m_json["code"] = tmp_json["code"];
            m_json["message"] = tmp_json["message"];
            m_result_json.setJson(tmp_json["result"]);
        }
    }

    void parse(char *jsonChar)
    {
        std::string jsonStr = jsonChar;
        parse(jsonStr);
    }

    int getCode()
    {
        return m_json["code"].asInt();
    }

    bool isSuccess()
    {
        return getCode() == CODE_SUCCESS;
    }

    std::string getMessage()
    {
        return m_json["message"].asString();
    }

    char *readData_cstr(std::string key)
    {
        return m_result_json.readData_cstr(key);
    }

    std::string readData_string(std::string key)
    {
        return m_result_json.readData_string(key);
    }

    bool readData_bool(std::string key)
    {
        return m_result_json.readData_bool(key);
    }

    uint32_t readData_uint16(std::string key)
    {
        return m_result_json.readData_uint16(key);
    }

    uint32_t readData_uint32(std::string key)
    {
        return m_result_json.readData_uint32(key);
    }

    uint32_t readData_uint64(std::string key)
    {
        return m_result_json.readData_uint64(key);
    }

    void readData_uint8Array(std::string key, uint8_t *data)
    {
        m_result_json.readData_uint8Array(key, data);
    }

    void readData_uint32Array(std::string key, uint32_t *data)
    {
        m_result_json.readData_uint32Array(key, data);
    }
};

#endif