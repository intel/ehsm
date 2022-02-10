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
#include <uuid/uuid.h>

#include "base64.h"
#include "ehsm_napi.h"
#include "serialize.h"
#include "json_utils.h"
#include "log_utils.h"
#include "datatypes.h"


using namespace std;
using namespace EHsmProvider;


extern "C" {

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
char* NAPI_Initialize(){
    RetJsonObj retJsonObj;
    ehsm_status_t ret = EH_OK;
    
    ret = Initialize();
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
    }
    return retJsonObj.toChar();
}

/*
destory the enclave
*/
void NAPI_Finalize(){
    Finalize();
}

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            cmk_base64 : string,
        }
    }
*/
char* NAPI_CreateKey(const uint32_t keyspec, const uint32_t origin)
{
    RetJsonObj retJsonObj;
    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t master_key;

    memset(&master_key, 0, sizeof(master_key));

    string cmk_base64;

    uint8_t *resp = NULL;
    uint32_t resp_len = 0;

    master_key.metadata.keyspec = keyspec;
    master_key.metadata.origin = origin;
    master_key.keybloblen = 0;    

    ret = CreateKey(&master_key);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    master_key.keyblob = (uint8_t*)malloc(master_key.keybloblen);
    if (master_key.keyblob == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = CreateKey(&master_key);
    if (ret != EH_OK) {
        if(ret == EH_KEYSPEC_INVALID){
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("The cmk's keyspec is invalid.");
        } else {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        goto out;
    }

    ret = ehsm_serialize_cmk(&master_key, &resp, &resp_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cmk_base64 = base64_encode(resp, resp_len);
    if(cmk_base64.size() > 0){
        retJsonObj.addData_string("cmk_base64", cmk_base64);
    }

out:
    SAFE_FREE(master_key.keyblob);
    SAFE_FREE(resp);
    return retJsonObj.toChar();
}


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
char* NAPI_Encrypt(const char* cmk_base64,
        const char* plaintext,
        const char* aad)
{
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL || plaintext == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }
    if(aad == NULL){
        aad = "";
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_data_t plaint_data;
    ehsm_data_t aad_data;
    ehsm_data_t cipher_data;

    memset(&cmk, 0, sizeof(cmk));
    memset(&plaint_data, 0, sizeof(plaint_data));
    memset(&aad_data, 0, sizeof(aad_data));
    memset(&cipher_data, 0, sizeof(cipher_data));

    string cmk_str = base64_decode(cmk_base64);
    string cipherText_base64;
    int cmk_len = cmk_str.size();
    int plaintext_len = strlen(plaintext);
    int aad_len = strlen(aad);

    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }
    if(plaintext_len == 0 || plaintext_len > EH_ENCRYPT_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The plaintext's length is invalid.");
        goto out;
    }
    if(aad_len > EH_AAD_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The aad's length is invalid.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    plaint_data.datalen = plaintext_len;
    plaint_data.data = (uint8_t*)plaintext;

    aad_data.datalen = aad_len;
    if(aad_len > 0){
        aad_data.data = (uint8_t*)aad;
    } else {
        aad_data.data = NULL; 
    }
    
    cipher_data.datalen = 0;
    ret = Encrypt(&cmk, &plaint_data, &aad_data, &cipher_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipher_data.data = (uint8_t*)malloc(cipher_data.datalen);
    if (cipher_data.data == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = Encrypt(&cmk, &plaint_data, &aad_data, &cipher_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipherText_base64 = base64_encode(cipher_data.data, cipher_data.datalen);
    if(cipherText_base64.size() > 0){
        retJsonObj.addData_string("ciphertext_base64", cipherText_base64);
    }

out:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(cipher_data.data);
    return retJsonObj.toChar();
}

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
char* NAPI_Decrypt(const char* cmk_base64,
        const char* ciphertext_base64,
        const char* aad)
{
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL || ciphertext_base64 == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }
    if(aad == NULL){
        aad = "";
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_data_t plaint_data;
    ehsm_data_t aad_data;
    ehsm_data_t cipher_data;
    string plaintext_base64;
    
    memset(&cmk, 0, sizeof(cmk));
    memset(&plaint_data, 0, sizeof(plaint_data));
    memset(&aad_data, 0, sizeof(aad_data));
    memset(&cipher_data, 0, sizeof(cipher_data));
    
    string cmk_str = base64_decode(cmk_base64);
    string ciphertext_str = base64_decode(ciphertext_base64);
    int cmk_len = cmk_str.size();
    int ciphertext_len = ciphertext_str.size();
    int aad_len = strlen(aad);

    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }
    if(ciphertext_len == 0 || ciphertext_len > EH_ENCRYPT_MAX_SIZE + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The ciphertext's length is invalid.");
        goto out;
    }
    if(aad_len > EH_AAD_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The aad's length is invalid.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipher_data.datalen = ciphertext_len;
    cipher_data.data = (uint8_t*)ciphertext_str.data();

    aad_data.datalen = aad_len;
    if(aad_len > 0){
        aad_data.data = (uint8_t*)aad;
    }else{
        aad_data.data = NULL; 
    }

    plaint_data.datalen = 0;
    ret = Decrypt(&cmk, &cipher_data, &aad_data, &plaint_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception");
        goto out;
    }

    plaint_data.data = (uint8_t*)malloc(plaint_data.datalen);
    if (plaint_data.data == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = Decrypt(&cmk, &cipher_data, &aad_data, &plaint_data);
    if (ret != EH_OK){
        if(ret == EH_FUNCTION_FAILED){
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("Decryption failed, Please confirm that your parameters are correct.");
        } else {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        goto out;
    }

    plaintext_base64 = base64_encode(plaint_data.data, plaint_data.datalen);
    if(plaintext_base64.size() > 0){
        retJsonObj.addData_string("plaintext_base64", plaintext_base64);
    }
out:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(plaint_data.data);
    return retJsonObj.toChar();
}

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            plaintext_base64 : string,
            ciphertext_base64 : string,
        }
    }
*/
char* NAPI_GenerateDataKey(const char* cmk_base64,
        const uint32_t keylen,
        const char* aad)
{
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }
    if(aad == NULL){
        aad = "";
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_data_t aad_data;
    ehsm_data_t plaint_datakey;
    ehsm_data_t cipher_datakey;
    
    memset(&cmk, 0, sizeof(cmk));
    memset(&aad_data, 0, sizeof(aad_data));
    memset(&plaint_datakey, 0, sizeof(plaint_datakey));
    memset(&cipher_datakey, 0, sizeof(cipher_datakey));

    string cmk_str = base64_decode(cmk_base64);
    string plaintext_base64;
    string ciphertext_base64;
    int cmk_len = cmk_str.size();
    int aad_len = strlen(aad);

    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }
    if(keylen == 0 || keylen > EH_DATA_KEY_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The keylen's length is invalid.");
        goto out;
    }
    if(aad_len > EH_AAD_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The aad's length is invalid.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    aad_data.datalen = aad_len;
    if(aad_len > 0){
        aad_data.data = (uint8_t*)aad;
    }else{
        aad_data.data = NULL; 
    }

    plaint_datakey.datalen = keylen;
    plaint_datakey.data = (uint8_t*)malloc(plaint_datakey.datalen);
    if (plaint_datakey.data == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }
	cipher_datakey.datalen = 0;
    ret = GenerateDataKey(&cmk, &aad_data, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    plaint_datakey.data = (uint8_t*)malloc(plaint_datakey.datalen);
    if (plaint_datakey.data == nullptr) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out; 
    }

    cipher_datakey.data = (uint8_t*)malloc(cipher_datakey.datalen);
    if (cipher_datakey.data == nullptr) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = GenerateDataKey(&cmk, &aad_data, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK){
        if(ret == EH_ARGUMENTS_BAD){
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("Failed, Please confirm that your parameters are correct.");
        } else {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        goto out;
    }

    plaintext_base64 = base64_encode(plaint_datakey.data, plaint_datakey.datalen);
    ciphertext_base64 = base64_encode(cipher_datakey.data, cipher_datakey.datalen);
    if((plaintext_base64.size() > 0) && (ciphertext_base64.size() > 0) ){
        retJsonObj.addData_string("plaintext_base64", plaintext_base64); 
        retJsonObj.addData_string("ciphertext_base64", ciphertext_base64);
    }
    
out:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(plaint_datakey.data);
    SAFE_FREE(cipher_datakey.data);
    return retJsonObj.toChar();
}

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
char* NAPI_GenerateDataKeyWithoutPlaintext(const char* cmk_base64,
        const uint32_t keylen,
        const char* aad)
{
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }
    if(aad == NULL){
        aad = "";
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_data_t aad_data;
    ehsm_data_t plaint_datakey;
    ehsm_data_t cipher_datakey;
    
    memset(&cmk, 0, sizeof(cmk));
    memset(&aad_data, 0, sizeof(aad_data));
    memset(&plaint_datakey, 0, sizeof(plaint_datakey));
    memset(&cipher_datakey, 0, sizeof(cipher_datakey));

    string cmk_str = base64_decode(cmk_base64);
    string ciphertext_base64;
    int cmk_len = cmk_str.size();
    int aad_len = strlen(aad);

    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }
    if(keylen == 0 || keylen > EH_DATA_KEY_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The keylen's length is invalid.");
        goto out;
    }
    if(aad_len > EH_AAD_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The aad's length is invalid.");
        goto out;
    }	
	
    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    aad_data.datalen = aad_len;
    if(aad_len > 0){
        aad_data.data = (uint8_t*)aad;
    }else{
        aad_data.data = NULL; 
    }
    plaint_datakey.datalen = keylen;
    plaint_datakey.data = NULL;
    cipher_datakey.datalen = 0;
    ret = GenerateDataKeyWithoutPlaintext(&cmk, &aad_data, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipher_datakey.data = (uint8_t*)malloc(cipher_datakey.datalen);
    if (cipher_datakey.data == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = GenerateDataKeyWithoutPlaintext(&cmk, &aad_data, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK){
        if(ret == EH_ARGUMENTS_BAD){
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("Failed, Please confirm that your parameters are correct.");
        } else {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        goto out;
    }

    ciphertext_base64 = base64_encode(cipher_datakey.data, cipher_datakey.datalen);
    if(ciphertext_base64.size() > 0){
        retJsonObj.addData_string("ciphertext_base64", ciphertext_base64);
    }

out:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(plaint_datakey.data);
    SAFE_FREE(cipher_datakey.data);
    return retJsonObj.toChar();
}


/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            signature_base64 : string,
        }
    }
*/
char* NAPI_Sign(const char* cmk_base64,
        const char* digest)
{    
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL || digest == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_data_t digest_data;
    ehsm_data_t signature;
    
    memset(&cmk, 0, sizeof(cmk));
    memset(&digest_data, 0, sizeof(digest_data));
    memset(&signature, 0, sizeof(signature));

    string cmk_str = base64_decode(cmk_base64);
    string signature_base64;
    int cmk_len = cmk_str.size();
    int digest_len = strlen(digest);

    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }
    if(digest_len == 0 || digest_len > RSA_OAEP_3072_DIGEST_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The digest's length is invalid.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    digest_data.datalen = digest_len;
    digest_data.data = (uint8_t*)digest;

    signature.datalen = 0;
    ret = Sign(&cmk, &digest_data, &signature);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    signature.data = (uint8_t*)malloc(signature.datalen);
    if (signature.data == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = Sign(&cmk, &digest_data, &signature);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    signature_base64 = base64_encode(signature.data, signature.datalen);
    if(signature_base64.size() > 0){
        retJsonObj.addData_string("signature_base64", signature_base64);
    }

out:
    SAFE_FREE(cmk.keyblob);    
    SAFE_FREE(signature.data);
    return retJsonObj.toChar();
    
}

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            result : bool,
        }
    }
*/
char* NAPI_Verify(const char* cmk_base64,
        const char* digest,
        const char* signature_base64)
{
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL || digest == NULL || signature_base64 == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_data_t digest_data;
    ehsm_data_t signature_data;
    
    memset(&cmk, 0, sizeof(cmk));
    memset(&digest_data, 0, sizeof(digest_data));
    memset(&signature_data, 0, sizeof(signature_data));

    bool result  = false;
    string cmk_str = base64_decode(cmk_base64);
    string signatur_str = base64_decode(signature_base64);
    int cmk_len = cmk_str.size();
    int digest_len = strlen(digest);
    int signature_len = signatur_str.size();

    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }
    if(digest_len == 0 || digest_len > RSA_OAEP_3072_DIGEST_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The digest's length is invalid.");
        goto out;
    }
    if(signature_len == 0 || signature_len > RSA_OAEP_3072_SIGNATURE_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The signature's length is invalid.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    digest_data.datalen = digest_len;
    digest_data.data = (uint8_t*)digest;

    signature_data.datalen = signature_len;
    signature_data.data = (uint8_t*)signatur_str.data();

    ret = Verify(&cmk, &digest_data, &signature_data, &result);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }
    retJsonObj.addData_bool("result", result);

out:
    SAFE_FREE(cmk.keyblob);
    return retJsonObj.toChar();
}


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
        const char* plaintext)
{
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL || plaintext == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_data_t plaint_data;
    ehsm_data_t cipher_data;
    
    memset(&cmk, 0, sizeof(cmk));
    memset(&plaint_data, 0, sizeof(plaint_data));
    memset(&cipher_data, 0, sizeof(cipher_data));
    
    string cmk_str = base64_decode(cmk_base64);
    string cipherText_base64;
    int cmk_len = cmk_str.size();
    int plaintext_len = strlen(plaintext);
    int plaintext_maxLen = 0;

    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_str.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    switch (cmk.metadata.keyspec)
    {
        case EH_RSA_2048:
            // TODO
            break;
        case EH_RSA_3072:
            plaintext_maxLen = RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE;
            break;
        case EH_EC_P256:
            // TODO
            break;
        case EH_EC_P512:
            // TODO
            break;
        case EH_EC_SM2:
            // TODO
            break;
        default:
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("The cmk's keyspec is invalid.");
            goto out;
    }
    
    if(plaintext_len == 0 || plaintext_len > plaintext_maxLen){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The plaintext's length is invalid.");
        goto out;
    }

    plaint_data.datalen = plaintext_len;
    plaint_data.data = (uint8_t*)plaintext;

    cipher_data.datalen = 0;
    ret = AsymmetricEncrypt(&cmk, &plaint_data, &cipher_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipher_data.data = (uint8_t*)malloc(cipher_data.datalen);
    if (cipher_data.data == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = AsymmetricEncrypt(&cmk, &plaint_data, &cipher_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipherText_base64 = base64_encode(cipher_data.data, cipher_data.datalen);
    if(cipherText_base64.size() > 0){
        retJsonObj.addData_string("ciphertext_base64", cipherText_base64);
    }

out:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(cipher_data.data);
    return retJsonObj.toChar();
}

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
        const char* ciphertext_base64)
{
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL || ciphertext_base64 == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_data_t cipher_data;
    ehsm_data_t plaint_data;
    
    memset(&cmk, 0, sizeof(cmk));
    memset(&cipher_data, 0, sizeof(cipher_data));
    memset(&plaint_data, 0, sizeof(plaint_data));

    string cmk_str = base64_decode(cmk_base64);
    string ciphertext_str = base64_decode(ciphertext_base64);
    string plaintext_base64;
    int cmk_len = cmk_str.size();
    int ciphertext_len = ciphertext_str.size();
    int ciphertext_maxLen = 0;

    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    switch (cmk.metadata.keyspec)
    {
        case EH_RSA_2048:
            // TODO
            break;
        case EH_RSA_3072:
            ciphertext_maxLen = RSA_OAEP_3072_CIPHER_LENGTH;
            break;
        case EH_EC_P256:
            // TODO
            break;
        case EH_EC_P512:
            // TODO
            break;
        case EH_EC_SM2:
            // TODO
            break;
        default:
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("The cmk's keyspec is invalid.");
            goto out;
    }
    
    if(ciphertext_len == 0 || ciphertext_len > ciphertext_maxLen){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The ciphertext's length is invalid.");
        goto out;
    }

    cipher_data.datalen = ciphertext_len;
    cipher_data.data = (uint8_t*)ciphertext_str.data();

    plaint_data.datalen = 0;
    ret = AsymmetricDecrypt(&cmk, &cipher_data, &plaint_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    plaint_data.data = (uint8_t*)malloc(plaint_data.datalen);
    if (plaint_data.data == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = AsymmetricDecrypt(&cmk, &cipher_data, &plaint_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }
    
    plaintext_base64 = base64_encode(plaint_data.data, plaint_data.datalen);
    if(plaintext_base64.size() > 0){
        retJsonObj.addData_string("plaintext_base64", plaintext_base64);
    }
out:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(plaint_data.data);
    return retJsonObj.toChar();
}

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
        const char* olddatakey_base64)
{
    RetJsonObj retJsonObj;
    if (cmk_base64 == NULL || ukey_base64 == NULL || olddatakey_base64 == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("paramter invalid.");
        return retJsonObj.toChar();
    }
    if(aad == NULL){
        aad = "";
    }

    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t cmk;
    ehsm_keyblob_t ukey;
    ehsm_data_t aad_data;
    ehsm_data_t olddatakey_data;
    ehsm_data_t cipher_datakey_new;
    
    memset(&cmk, 0, sizeof(cmk));
    memset(&ukey, 0, sizeof(ukey));
    memset(&aad_data, 0, sizeof(aad_data));
    memset(&olddatakey_data, 0, sizeof(olddatakey_data));
    memset(&cipher_datakey_new, 0, sizeof(cipher_datakey_new));

    string cmk_str = base64_decode(cmk_base64);
    string ukey_str = base64_decode(ukey_base64);
    string olddatakey_str = base64_decode(olddatakey_base64);
    string newdatakey_base64;   
    int cmk_len = cmk_str.size();
    int ukey_len = ukey_str.size();
    int aad_len = strlen(aad);
    int olddatakey_len = olddatakey_str.size();

    
    if(cmk_len == 0 || cmk_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The cmk's length is invalid.");
        goto out;
    }
    if(ukey_len == 0 || ukey_len > EH_CMK_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The ukey's length is invalid.");
        goto out;
    }
    if(aad_len > EH_AAD_MAX_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The aad's length is invalid.");
        goto out;
    }
    if(olddatakey_len == 0 || olddatakey_len > RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE){
        retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
        retJsonObj.setMessage("The olddatakey's length is invalid.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&cmk, (const uint8_t*)cmk_str.data(), cmk_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ret = ehsm_deserialize_cmk(&ukey, (const uint8_t*)ukey_str.data(), ukey_len);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    olddatakey_data.datalen = olddatakey_len;
    olddatakey_data.data = (uint8_t*)olddatakey_str.data();
    
    aad_data.datalen = aad_len;
    if(aad_len > 0){
        aad_data.data = (uint8_t*)aad;
    }else{
        aad_data.data = NULL; 
    }

    cipher_datakey_new.datalen = 0;
    ret = ExportDataKey(&cmk, &ukey, &aad_data, &olddatakey_data, &cipher_datakey_new);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipher_datakey_new.data = (uint8_t*)malloc(cipher_datakey_new.datalen);
    if (cipher_datakey_new.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto out;
    }

    ret = ExportDataKey(&cmk, &ukey, &aad_data, &olddatakey_data, &cipher_datakey_new);
    if (ret != EH_OK){
        if(ret == EH_ARGUMENTS_BAD){
            retJsonObj.setCode(retJsonObj.CODE_BAD_REQUEST);
            retJsonObj.setMessage("Failed, Please confirm that your parameters are correct.");
        } else {
            retJsonObj.setCode(retJsonObj.CODE_FAILED);
            retJsonObj.setMessage("Server exception.");
        }
        goto out;
    }

    newdatakey_base64 = base64_encode(cipher_datakey_new.data, cipher_datakey_new.datalen);
    if(newdatakey_base64.size() > 0){
        retJsonObj.addData_string("newdatakey_base64", newdatakey_base64);
    }
out:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(ukey.keyblob);
    SAFE_FREE(cipher_datakey_new.data);
    return retJsonObj.toChar();
}

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            challenge_base64 : string,
            ga_base64 : string
        }
    }
*/
char *NAPI_RA_HANDSHAKE_MSG0(const char *p_msg0)
{
    log_d("***NAPI_RA_HANDSHAKE_MSG0 start.");

    log_d("msg0: \n %s", p_msg0);
    std::string challenge_base64 = "challenge_base64";
    std::string ga_base64 = "ga_base64";

    RetJsonObj retJsonObj;
    
    retJsonObj.addData_string("challenge_base64", challenge_base64);
    retJsonObj.addData_string("ga_base64", ga_base64);
    log_d("msg1: \n%s",retJsonObj.toChar());

    log_d("***NAPI_RA_HANDSHAKE_MSG0 end.");
    return retJsonObj.toChar();
}

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            msg3_base64 : string
        }
    }
*/
char *NAPI_RA_HANDSHAKE_MSG2(const char *p_msg2)
{
    log_d("***NAPI_RA_HANDSHAKE_MSG2 start.");

    log_d("msg2: \n %s", p_msg2);
    std::string msg3_base64 = "msg3_base64";

    RetJsonObj retJsonObj;
    retJsonObj.addData_string("msg3_base64", msg3_base64);
    log_d("msg3: \n%s",retJsonObj.toChar());

    log_d("***NAPI_RA_HANDSHAKE_MSG2 end.");
    return retJsonObj.toChar();
}

/*
@return
[string] json string
    {
        code: int,
        message: string,
        result: {
            appid : string
            apikey : string
        }
    }
*/
char *NAPI_RA_GET_API_KEY(const char *p_msg4)
{
    log_d("***NAPI_RA_GET_API_KEY start.");
    ehsm_status_t ret = EH_OK;
    RetJsonObj retJsonObj;

    char p_appid[UUID_STR_LEN] = {0};
    ehsm_data_t p_apikey;

    log_d("msg4: \n %s", p_msg4);

    // create appid
    uuid_t uu;
    uuid_generate(uu);
    uuid_unparse(uu, p_appid);

    // create apikey
    p_apikey.datalen = EH_API_KEY_SIZE;
    p_apikey.data = (uint8_t*)calloc(p_apikey.datalen + 1, sizeof(uint8_t));
    if (p_apikey.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto OUT;
    }

    ret = generate_apikey(&p_apikey);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto OUT;
    }

    retJsonObj.addData_string("appid", p_appid);
    retJsonObj.addData_string("apikey", (char*)p_apikey.data);

    log_d("msg7: \n%s",retJsonObj.toChar());
    log_d("***NAPI_RA_GET_API_KEY end.");

OUT:
    explicit_bzero(p_apikey.data, p_apikey.datalen);
    SAFE_FREE(p_apikey.data);
    return retJsonObj.toChar();
}

}  // extern "C"