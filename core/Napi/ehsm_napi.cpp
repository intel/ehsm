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

using namespace EHsmProvider;

static char* BASE64_ENCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

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

extern "C" char* CreateKey_napi(int intMechanism, int intOrigin)
{
    EH_RV rv = EHR_FUNCTION_FAILED;
    EH_KEY_BLOB key_blob;
    char* rest;
    int i = 0;

    key_blob.pKeyData = NULL;
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
        return "create key 2 failed\n";
    }
    printf("create key done\n");
    
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
    return "create key napi done\n";
}


