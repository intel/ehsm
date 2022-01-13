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
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <curl/curl.h>
#include "../../include/json/json.h"
#include <sys/time.h>
#include <iostream>
#include<error.h>

#include "sgx_quote_3.h"
#include "sgx_urts.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"

#include "../../dkeyserver/App/ecp.h"
#include "../../dkeyserver/App/socket_server.h"
#include "../../dkeyserver/App/rand.h"
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>

using namespace std;
#ifndef SAMPLE_FEBITSIZE
    #define SAMPLE_FEBITSIZE                    256
#endif
#define SAMPLE_ECP_KEY_SIZE                     (SAMPLE_FEBITSIZE/8)
#define SAMPLE_ECP256_KEY_SIZE                  32
static sp_db_item_t g_sp_db;
static const string encode_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
sample_spid_t g_spid;

bool isDebug = true;

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}


typedef enum {
    ENL_OK                          = 0,
    ENL_CONFIG_INVALID              = -1,
    ENL_POST_EXCEPTION              = -2,
    ENL_PARSE_MSG1_EXCEPTION        = -3,
    ENL_NAPI_EXCEPTION              = -4,
    ENL_CHALLENGE_NO_COMPARE        = -5
} enroll_status_t;

typedef struct ecdsa256_private_t{
    uint8_t r[SAMPLE_ECP256_KEY_SIZE];
} ecdsa256_private_t;

typedef struct ecdsa_pub_t{
    uint8_t gx[SAMPLE_ECP_KEY_SIZE];
    uint8_t gy[SAMPLE_ECP_KEY_SIZE];
} ecdsa_pub_t;

// This is the private ECDSA key of SP, the corresponding public ECDSA key is
// hard coded in isv_enclave. It is based on NIST P-256 curve.
static const ecdsa256_private_t g_sp_priv_key = {
    {
        0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
    }
};

// This is the public ECDSA key of SP, this key is hard coded in isv_enclave.
// It is based on NIST P-256 curve. Not used in the SP code.
static const ecdsa_pub_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

string base64_decode(const string &encoded_string) {
    uint32_t in_len = encoded_string.size();
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    string decode_str;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = static_cast<unsigned char>(encode_table.find(char_array_4[i]));

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                decode_str += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = static_cast<unsigned char>(encode_table.find(char_array_4[j]));

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
            decode_str += char_array_3[j];
    }

    return decode_str;
}

static char* StringToChar(string str)
{
    char* returnChar = nullptr;
    if (str.size() > 0) {
        int len = str.size() + 1;
        returnChar = (char *)malloc(len * sizeof(uint8_t));
        if(returnChar != nullptr){
            memset(returnChar, 0, len);
            memcpy(returnChar, str.c_str(), len);
        }
    }
    return returnChar;
}


Json::Value readConfigJson()
{
    Json::Reader reader;
	Json::Value kmsConfigJson;
    string ehsm_kms_ip;

    ifstream inFile("config.json", ios::binary);
    if (!inFile.is_open()){
        cout << "Error: opening file"<< endl;
        return kmsConfigJson;
    }
	reader.parse(inFile, kmsConfigJson);
    inFile.close();
	return kmsConfigJson;
}


// curl callback func
size_t req_callback(void *ptr, size_t size, size_t nmem, void *stream)
{
	string *str = (string*)stream;
	(*str).append((char*)ptr, size*nmem);
	return size * nmem;
}

string post(string url, string content){
    if(isDebug){
        printf("Debug_enroll_main_cpp post: ******** in  post \n");
        printf("Debug_enroll_main_cpp post: url => %s\n", url.c_str());
        printf("Debug_enroll_main_cpp post: content => %s\n", content.c_str());
    }
    struct curl_slist* header_list = nullptr;
    // use curl post.
    string response;
    CURLcode res;
    CURL* curl = nullptr;
    curl = curl_easy_init();
    if(nullptr == curl) {
        printf("Error: curl init error\n");
        goto out;
    }

    curl_easy_setopt(curl, CURLOPT_URL, StringToChar(url));
    header_list = curl_slist_append(header_list, "Content-Type:application/json; charset=UTF-8");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, req_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, StringToChar(content));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, content.size());
    
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        printf("Error: curl easy perform error res = %d.\n", res);
        goto out;
    }
    if(isDebug){
        printf("Debug_enroll_main_cpp post: response => %s\n", response.c_str());
    }
out:
    curl_easy_cleanup(curl);
    printf("Debug_enroll_main_cpp post: ******** out  post \n");
    return response;
}

int main(int argc, char* argv[])
{
    Json::Value msg0_json;
	Json::Value kmsConfigJson = readConfigJson();
	string ehsm_kms_url = kmsConfigJson["ehsm_kms_url"].asString();
	if(ehsm_kms_url.empty()){
		printf("Error: ehsm_kms_url undefined.\n");
        return ENL_CONFIG_INVALID;
	}

    struct timeval tv;
    gettimeofday(&tv, NULL);
    string challenge = std::to_string(tv.tv_sec) + to_string(tv.tv_usec);
    msg0_json["challenge"]= challenge;

    if(isDebug){
        printf("Debug_enroll_main_cpp main: msg0_json => %s\n", msg0_json.toStyledString().c_str());
    }
    string msg1_json_str = post(ehsm_kms_url + "?Action=RA_HANDSHAKE_MSG0", msg0_json.toStyledString());
    if(msg1_json_str.empty()){
        printf("Error: can't post RA_HANDSHAKE_MSG0.\n");
        return ENL_POST_EXCEPTION;
    }
    if(isDebug){
        printf("Debug_enroll_main_cpp main: msg1_json_str => %s\n", msg1_json_str.c_str());
    }

    Json::Value msg1_json;
    string err;
    Json::CharReaderBuilder builder;
    const unique_ptr<Json::CharReader> reader(builder.newCharReader());
    bool res_parse_msg1_json = reader->parse(msg1_json_str.c_str(), msg1_json_str.c_str()+msg1_json_str.size(), &msg1_json, &err);
    if (!res_parse_msg1_json || !err.empty()) {
        printf("Error: can't parse msg1_json_str to json, %s\n", err.c_str());
        return ENL_PARSE_MSG1_EXCEPTION;
    }
    if(isDebug){
        printf("Debug_enroll_main_cpp main: msg1_json => %s\n", msg1_json.toStyledString().c_str());
    }
    if(msg1_json["code"].asInt() != 200){
        printf("Error: %s\n", msg1_json["message"].asString().c_str());
        return ENL_NAPI_EXCEPTION;
    }

    string challenge_response = base64_decode(msg1_json["result"]["challenge_base64"].asString());
    string ga = base64_decode(msg1_json["result"]["ga_base64"].asString());
    if(isDebug){
        printf("Debug_enroll_main_cpp main: challenge_response => %s\n", challenge_response.c_str());
        printf("Debug_enroll_main_cpp main: ga => %s\n", ga.c_str());
    }

    if(challenge.compare(challenge_response) != 0){
        printf("Error: challenge no compare, %s\n", err.c_str());
        return ENL_CHALLENGE_NO_COMPARE;
    }
    
    if(isDebug){
        printf("Debug_enroll_main_cpp main: validation challenge_response => %s.\n", (challenge.compare(challenge_response) != 0) ? "false" : "true");
    }


    
    return ENL_OK;
}
