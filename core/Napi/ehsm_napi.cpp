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

#define EH_AES_CRE_KEY_SIZE  64
using namespace EHsmProvider;

static char* BASE64_ENCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

unsigned char Decode_GetByte(char c)
{
    if(c == '+')
        return 62;
    else if(c == '/')
        return 63;
    else if(c <= '9')
        return (unsigned char)(c - '0' + 52);
    else if(c == '=')
        return 64;
    else if(c <= 'Z')
        return (unsigned char)(c - 'A');
    else if(c <= 'z')
        return (unsigned char)(c - 'a' + 26);
    return 64;
}

static size_t Base64Decode(char *pDest, const char *pSrc, size_t srclen)
{
    unsigned char input[4];
    size_t i, index = 0;
    for(i = 0; i < srclen; i += 4)
    {
        //byte[0]
        input[0] = Decode_GetByte(pSrc[i]);
        input[1] = Decode_GetByte(pSrc[i + 1]);
        pDest[index++] = (input[0] << 2) + (input[1] >> 4);
        
        //byte[1]
        if(pSrc[i + 2] != '=')
        {
            input[2] = Decode_GetByte(pSrc[i + 2]);
            pDest[index++] = ((input[1] & 0x0f) << 4) + (input[2] >> 2);
        }

        //byte[2]
        if(pSrc[i + 3] != '=')
        {
            input[3] = Decode_GetByte(pSrc[i + 3]);
            pDest[index++] = ((input[2] & 0x03) << 6) + (input[3]);
        }            
    }

    //null-terminator
    pDest[index] = 0;
    return index;
}

static unsigned int Base64Encode(char *pDest, unsigned char *pSrc, unsigned int srclen)
{
    unsigned char input[3], output[4];
    size_t i, index_src = 0, index_dest = 0;
    for(i = 0; i < srclen; i += 3)
    {
        //char [0]
        input[0] = pSrc[index_src++];
        output[0] = (char)(input[0] >> 2);
        pDest[index_dest++] = BASE64_ENCHARS[output[0]];
        
        //char [1]
        if(index_src < srclen)
        {
            input[1] = pSrc[index_src++];
            output[1] = (char)(((input[0] & 0x03) << 4) + (input[1] >> 4));
            pDest[index_dest++] = BASE64_ENCHARS[output[1]];
            }
        else
        {
            output[1] = (char)((input[0] & 0x03) << 4);
            pDest[index_dest++] =BASE64_ENCHARS[output[1]];
            pDest[index_dest++] = '=';
            pDest[index_dest++] = '=';
            break;
        }
        
        //char [2]
        if(index_src < srclen)
        {
            input[2] = pSrc[index_src++];
            output[2] = (char)(((input[1] & 0x0f) << 2) + (input[2] >> 6));
            pDest[index_dest++] = BASE64_ENCHARS[output[2]];
        }
        else
        {
            output[2] = (char)((input[1] & 0x0f) << 2);
            pDest[index_dest++] = BASE64_ENCHARS[output[2]];
            pDest[index_dest++] = '=';
            break;
        }

        //char [3]
        output[3] = (char)(input[2] & 0x3f);
        pDest[index_dest++] = BASE64_ENCHARS[output[3]];
    }
    //null-terminator
    pDest[index_dest] = '\n';
    return index_dest;
}

extern "C" char* Decrypt_napi(int intMechanism, char* key, char* cipherText)
{
    printf("========== Decrypt_napi start==========\n");
    char* rest_key;
    rest_key = (char *)malloc(128 * sizeof(uint8_t));
    if(rest_key != NULL)
    {
      memset(rest_key, 0, 128);
      Base64Decode(rest_key, key, strlen(key));
    }
    char* rest_cipherText;
    rest_cipherText = (char *)malloc(128 * sizeof(uint8_t));
    if(rest_cipherText != NULL)
    {
      memset(rest_cipherText, 0, 128);
      Base64Decode(rest_cipherText, cipherText, strlen(cipherText));
    }
    
    EH_RV rv = EHR_FUNCTION_FAILED;
    EH_MECHANISM me;
    EH_GCM_PARAMS gcm_para;
    
    EH_ULONG dec_len = 0;
    EH_ULONG enc_len = strlen(rest_cipherText);
    EH_BYTE_PTR dec_secret = NULL;
    
    EH_KEY_BLOB key_blob;
    key_blob.ulKeyType = 0;
    key_blob.ulKeyLen = EH_AES_CRE_KEY_SIZE;
    key_blob.pKeyData = (unsigned char *)rest_key;

    me.mechanism = intMechanism;
    me.pParameter = &gcm_para;
    me.ulParameterLen = sizeof(gcm_para);
    printf("========== Decrypt_napi start==========\n");
    printf("cipherText :%s, len is %ld\n", cipherText, enc_len);
    
    rv = Initialize();
    if (rv != EHR_OK) {
        printf("Initialize failed 0x%lx\n", rv);
        return "Initialize failed";
    }
    printf("Initialize done\n");
    
    gcm_para.ulAADLen = 0;
    gcm_para.pAAD = NULL;
    if ((rv = Decrypt(&me, &key_blob, (unsigned char*)rest_cipherText, enc_len, NULL, &dec_len) == EHR_OK)) {
            printf("get dec len done 0x%lx\n", dec_len);
            dec_secret = (EH_BYTE_PTR) malloc(dec_len * sizeof(EH_BYTE));
            if (dec_secret == NULL) {
                rv = EHR_DEVICE_MEMORY;
                return "Failed to allow memary\n";
            }
            
            rv = Decrypt(&me, &key_blob, (unsigned char*)rest_cipherText, enc_len, dec_secret, &dec_len);
            if (rv != EHR_OK) {
                printf("decrypt 1 failed 0x%lx\n", rv);
                return "decrypt 1 failed 0x%lx\n";
            }
    } else {
        printf("decrypt 2 failed 0x%lx\n", rv);
        return "decrypt 2 failed 0x%lx\n";
    }
    printf("decrypt_napi done:%s\n", dec_secret);
    
    Finalize();
    
    if(dec_secret != NULL){
      return (char*)dec_secret;
    }
    return "Decrypt_napi fail\n";
    
}


extern "C" char* Encrypt_napi(int intMechanism, char* key, char* plaintext)
{
    EH_KEY_BLOB key_blob;
    char* rest_key;
    char* rest_plaintext;

    rest_key = (char *)malloc(128 * sizeof(uint8_t));
    if(rest_key != NULL)
    {
      memset(rest_key, 0, 128);
      Base64Decode(rest_key, key, strlen(key));
    }

    EH_RV rv = EHR_FUNCTION_FAILED;
    EH_MECHANISM me;
    EH_GCM_PARAMS gcm_para;
    
    EH_ULONG secret_len = strlen((const char *)plaintext) + 1;
    EH_BYTE_PTR enc_secret = NULL;
    EH_ULONG enc_len = 0;
    
    key_blob.ulKeyType = 0;
    key_blob.ulKeyLen = EH_AES_CRE_KEY_SIZE;
    key_blob.pKeyData = (unsigned char *)rest_key;

    me.mechanism = intMechanism;
    me.pParameter = &gcm_para;
    me.ulParameterLen = sizeof(gcm_para);
    printf("========== Encrypt_napi start==========\n");
    printf("plaintext :%s, len is %ld\n", plaintext, secret_len);
    printf("rest:%s, len is %ld\n", key_blob.pKeyData, key_blob.ulKeyLen);
    rv = Initialize();
    if (rv != EHR_OK) {
        printf("Initialize failed 0x%lx\n", rv);
        return "Initialize failed";
    }
    
    printf("Initialize done\n");
    gcm_para.ulAADLen = 0;
    gcm_para.pAAD = NULL;
    if ((rv = Encrypt(&me, &key_blob, (unsigned char*)plaintext, secret_len, NULL, &enc_len) == EHR_OK)) {
            printf("get enc len done 0x%lx\n", enc_len);
            enc_secret = (EH_BYTE_PTR) malloc(enc_len * sizeof(EH_BYTE));
            if (enc_secret == NULL) {
                rv = EHR_DEVICE_MEMORY;
                return "Failed to allow memary\n";
            }
            
            rv = Encrypt(&me, &key_blob, (unsigned char*)plaintext, secret_len, enc_secret, &enc_len);
            if (rv != EHR_OK) {
                printf("encrypt 1 failed 0x%lx\n", rv);
                return "encrypt 1 failed 0x%lx\n";
            }
    } else {
        printf("encrypt 2 failed 0x%lx\n", rv);
        return "encrypt 2 failed 0x%lx\n";
    }
    printf("encrypt_napi done:%s\n", enc_secret);
    
    rest_plaintext = (char *)malloc(128 * sizeof(uint8_t));
    if(rest_plaintext != NULL)
    {
      memset(rest_plaintext, 0, 128);
      Base64Encode(rest_plaintext, enc_secret, key_blob.ulKeyLen);
    }
    if(enc_secret != NULL)
    {   
      free(enc_secret);
    }
    if(rest_plaintext != NULL){
      return (char*)rest_plaintext;
    }
    
    return "Encrypt_napi fail\n";
    
}

extern "C" char* CreateKey_napi(int intMechanism, int intOrigin)
{
    EH_RV rv = EHR_FUNCTION_FAILED;
    EH_KEY_BLOB key_blob;
    char* rest;
    key_blob.pKeyData = nullptr;
    key_blob.ulKeyLen = 0;
    
    rv = Initialize();
    if (rv != EHR_OK) {
        printf("Initialize failed 0x%lx\n", rv);
        return "Initialize failed\n";
    }
    printf("Initialize done\n");

    if ((rv = CreateKey(intMechanism, (EH_KEY_ORIGIN)intOrigin, &key_blob)) == EHR_OK) {
        printf("get key size done 0x%lx\n", key_blob.ulKeyLen);
        key_blob.pKeyData = (EH_BYTE_PTR)malloc(key_blob.ulKeyLen * sizeof(uint8_t));
        if (key_blob.pKeyData == NULL) {
            return "Failed to allow memary\n";
        }

        rv = CreateKey(intMechanism, (EH_KEY_ORIGIN)intOrigin, &key_blob);
        if (rv != EHR_OK) {
            printf("create key 1 failed 0x%lx\n", rv);
            return "create key 1 failed\n";
        }
    } else {
        printf("create key 2 failed 0x%lx\n", rv);
        return "create key 2 failed";
    }
    
    rest = (char *)malloc(128 * sizeof(uint8_t));
    if(rest != NULL)
    {
      memset(rest, 0, 128);
      Base64Encode(rest, key_blob.pKeyData, key_blob.ulKeyLen);
    }
    if(key_blob.pKeyData != NULL)
    {   
      free(key_blob.pKeyData);
    }
    
    if(rest != NULL)
    {
      return rest;
    }
    return "create key napi fail\n";
}


/*
extern "C" char* GenerateDataKey_napi(int intMechanism, char* master_key_blob)
{
    EH_RV rv = EHR_FUNCTION_FAILED;
    EH_KEY_BLOB master_key_blob;
    EH_MECHANISM me;
    EH_GCM_PARAMS gcm_para;
    EH_BYTE_PTR plain_key = NULL;
    EH_BYTE_PTR enc_key = NULL;
    EH_ULONG key_len = 0;
    EH_ULONG enc_key_len = 0;
    uint32_t i = 0;

    me.mechanism = intMechanism;
    me.pParameter = &gcm_para;
    me.ulParameterLen = sizeof(gcm_para);
    printf("============testGenerateDataKey_napi start==========\n");

    //Here need to call CreateKey twice.
    //On first time, set pData to NULL to get needed key blob size.
    gcm_para.ulAADLen = 0;
    gcm_para.pAAD = NULL;

    key_len = 16;
    plain_key = (EH_BYTE_PTR) malloc(key_len * sizeof(EH_BYTE));
    if (plain_key == NULL) {
        rv = EHR_DEVICE_MEMORY;
        return "Failed to allow memary";
    }

    if ((rv = GenerateDataKey(&me, &master_key_blob, plain_key, key_len, NULL, &enc_key_len) == EHR_OK)) {
        printf("get enc data key len done 0x%lx\n", enc_key_len);
        enc_key = (EH_BYTE_PTR) malloc(enc_key_len * sizeof(EH_BYTE));
        if (enc_key == NULL) {
            rv = EHR_DEVICE_MEMORY;
            return "Failed to allow memary\n";
        }

        rv = GenerateDataKey(&me, &master_key_blob, plain_key, key_len, enc_key, &enc_key_len);
        if (rv != EHR_OK) {
            printf("GenerateDataKey 1 failed 0x%lx\n", rv);
            return "GenerateDataKey 1 failed ;
        }
    } else {
        printf("GenerateDataKey 2 failed 0x%lx\n", rv);
        return "GenerateDataKey 2 failed\n";
    }

    for (i = 0; i < key_len; i++) {
        printf("0x%x:", *(plain_key + i));
    }
    if(plain_key != NULL){
      return plain_key;
    }
    printf("\nGenerateDataKey done\n");
}
*/







