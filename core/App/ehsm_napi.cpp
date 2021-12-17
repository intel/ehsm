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
    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t master_key;

    string cmk_base64;
    RetJsonObj retJsonObj;

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
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
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
        retJsonObj.addData("cmk_base64", cmk_base64);
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
    string decode_str;
    string cipherText_base64;

    ehsm_status_t ret = EH_OK;

    ehsm_keyblob_t masterkey;

    ehsm_data_t plaint_data;
    ehsm_data_t aad_data;
    ehsm_data_t cipher_data;

    decode_str = base64_decode(cmk_base64);

    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)decode_str.data(), decode_str.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    plaint_data.datalen = strlen(plaintext);
    plaint_data.data = (uint8_t*)plaintext;

    aad_data.datalen = strlen(aad);
    aad_data.data = (uint8_t*)aad;

    cipher_data.datalen = 0;
    ret = Encrypt(&masterkey, &plaint_data, &aad_data, &cipher_data);
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

    ret = Encrypt(&masterkey, &plaint_data, &aad_data, &cipher_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipherText_base64 = base64_encode(cipher_data.data, cipher_data.datalen);
    if(cipherText_base64.size() > 0){
        retJsonObj.addData("ciphertext_base64", cipherText_base64);
    }

out:
    SAFE_FREE(masterkey.keyblob);
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
    string decode_cmk;
    string decode_cipher;
    string plaintext_base64;

    RetJsonObj retJsonObj;
    ehsm_status_t ret = EH_OK;

    ehsm_keyblob_t masterkey;

    ehsm_data_t plaint_data;
    ehsm_data_t aad_data;
    ehsm_data_t cipher_data;

    decode_cmk = base64_decode(cmk_base64);

    decode_cipher = base64_decode(ciphertext_base64);

    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)decode_cmk.data(), decode_cmk.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipher_data.datalen = decode_cipher.size();
    cipher_data.data = (uint8_t*)decode_cipher.data();

    aad_data.datalen = strlen(aad);
    aad_data.data = (uint8_t*)aad;

    plaint_data.datalen = 0;
    ret = Decrypt(&masterkey, &cipher_data, &aad_data, &plaint_data);
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

    ret = Decrypt(&masterkey, &cipher_data, &aad_data, &plaint_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    plaintext_base64 = base64_encode(plaint_data.data, plaint_data.datalen);
    if(plaintext_base64.size() > 0){
        retJsonObj.addData("plaintext_base64", plaintext_base64);
    }
out:
    SAFE_FREE(masterkey.keyblob);
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
    string cmk_str;
    ehsm_status_t ret = EH_OK;
    RetJsonObj retJsonObj;
    ehsm_keyblob_t masterkey;

    ehsm_data_t plaint_datakey;
    ehsm_data_t aad_data;
    ehsm_data_t cipher_datakey;

    string plaintext_base64;
    string ciphertext_base64;
    
    cmk_str = base64_decode(cmk_base64);

    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)cmk_str.data(), cmk_str.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    aad_data.datalen = strlen(aad);
    aad_data.data = (uint8_t*)aad;

    plaint_datakey.datalen = keylen;
    plaint_datakey.data = (uint8_t*)malloc(plaint_datakey.datalen);
    if (plaint_datakey.data == NULL) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }
	cipher_datakey.datalen = 0;
    ret = GenerateDataKey(&masterkey, &aad_data, &plaint_datakey, &cipher_datakey);
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

    ret = GenerateDataKey(&masterkey, &aad_data, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    plaintext_base64 = base64_encode(plaint_datakey.data, plaint_datakey.datalen);
    ciphertext_base64 = base64_encode(cipher_datakey.data, cipher_datakey.datalen);
    if((plaintext_base64.size() > 0) && (ciphertext_base64.size() > 0) ){
        retJsonObj.addData("plaintext_base64", plaintext_base64); 
        retJsonObj.addData("ciphertext_base64", ciphertext_base64);
    }
    
out:
    SAFE_FREE(masterkey.keyblob);
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
    string cmk_str;
    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t masterkey;
    ehsm_data_t plaint_datakey;
    ehsm_data_t aad_data;
    ehsm_data_t cipher_datakey;
    string ciphertext_base64;
    
    cmk_str = base64_decode(cmk_base64);
    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)cmk_str.data(), cmk_str.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    aad_data.datalen = strlen(aad);
    aad_data.data = (uint8_t*)aad;
    plaint_datakey.datalen = keylen;
    plaint_datakey.data = NULL;
    cipher_datakey.datalen = 0;
    ret = GenerateDataKeyWithoutPlaintext(&masterkey, &aad_data, &plaint_datakey, &cipher_datakey);
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

    ret = GenerateDataKeyWithoutPlaintext(&masterkey, &aad_data, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    ciphertext_base64 = base64_encode(cipher_datakey.data, cipher_datakey.datalen);
    if(ciphertext_base64.size() > 0){
        retJsonObj.addData("ciphertext_base64", ciphertext_base64);
    }

out:
    SAFE_FREE(masterkey.keyblob);
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
    string cmk_str;
    ehsm_keyblob_t masterkey;
    ehsm_status_t ret = EH_OK;
    ehsm_data_t digest_data;
    ehsm_data_t signature;
    string signature_base64;

    cmk_str = base64_decode(cmk_base64);
    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)cmk_str.data(), cmk_str.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    digest_data.datalen = strlen(digest);
    digest_data.data = (uint8_t*)digest;

    signature.datalen = 0;
    ret = Sign(&masterkey, &digest_data, &signature);
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

    ret = Sign(&masterkey, &digest_data, &signature);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    signature_base64 = base64_encode(signature.data, signature.datalen);
    if(signature_base64.size() > 0){
        retJsonObj.addData("signature_base64", signature_base64);
    }

out:
    SAFE_FREE(masterkey.keyblob);    
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
    string cmk_str;
    string signatur_str;
    ehsm_status_t ret = EH_OK;
    ehsm_data_t digest_data;
    ehsm_data_t signature_data;
    ehsm_keyblob_t masterkey;
    bool result  = false;

    cmk_str = base64_decode(cmk_base64);
    signatur_str = base64_decode(signature_base64);
    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)cmk_str.data(), cmk_str.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    digest_data.datalen = strlen(digest);
    digest_data.data = (uint8_t*)digest;

    signature_data.datalen = signatur_str.size();
    signature_data.data = (uint8_t*)signatur_str.data();

    ret = Verify(&masterkey, &digest_data, &signature_data, &result);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }
    retJsonObj.addData("result", result);

out:
    SAFE_FREE(masterkey.keyblob);
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
    string cmk_str;
    string cipherText_base64;
    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t masterkey;
    ehsm_data_t plaint_data;
    ehsm_data_t cipher_data;

    cmk_str = base64_decode(cmk_base64);
    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)cmk_str.data(), cmk_str.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    plaint_data.datalen = strlen(plaintext);
    plaint_data.data = (uint8_t*)plaintext;

    cipher_data.datalen = 0;
    ret = AsymmetricEncrypt(&masterkey, &plaint_data, &cipher_data);
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

    ret = AsymmetricEncrypt(&masterkey, &plaint_data, &cipher_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipherText_base64 = base64_encode(cipher_data.data, cipher_data.datalen);
    if(cipherText_base64.size() > 0){
        retJsonObj.addData("ciphertext_base64", cipherText_base64);
    }

out:
    SAFE_FREE(masterkey.keyblob);
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
    string cmk_str;
    string decode_cipher;
    string plaintext_base64;
    string plaintest_str;
    RetJsonObj retJsonObj;
    ehsm_status_t ret = EH_OK;
    ehsm_keyblob_t masterkey;
    ehsm_data_t plaint_data;
    ehsm_data_t cipher_data;

    cmk_str = base64_decode(cmk_base64);
    decode_cipher = base64_decode(ciphertext_base64);
    ret = ehsm_deserialize_cmk(&masterkey, (const uint8_t*)cmk_str.data(), cmk_str.size());
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }

    cipher_data.datalen = decode_cipher.size();
    cipher_data.data = (uint8_t*)decode_cipher.data();

    plaint_data.datalen = 0;
    ret = AsymmetricDecrypt(&masterkey, &cipher_data, &plaint_data);
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

    ret = AsymmetricDecrypt(&masterkey, &cipher_data, &plaint_data);
    if (ret != EH_OK) {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        goto out;
    }
    
    plaintext_base64 = base64_encode(plaint_data.data, plaint_data.datalen);
    if(plaintext_base64.size() > 0){
        retJsonObj.addData("plaintext_base64", plaintext_base64);
    }
out:
    SAFE_FREE(masterkey.keyblob);
    SAFE_FREE(plaint_data.data);
    return retJsonObj.toChar();
}

//TODO: add the implementation of each ehsm napi

}  // extern "C"
