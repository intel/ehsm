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
#include "base64.h"
#include "ehsm_napi.h"
#include "dsohandle.h"

using namespace EHsmProvider;

static void dump_data(uint8_t *data, uint32_t datalen) {
    uint32_t i;
    std::string encode_str;

    printf("datalen=%d, data is:\n", datalen);

    encode_str = base64_encode(data, datalen);
    printf("%s\n", encode_str.c_str());

#if 0
    std::string decode_str;
    decode_str = base64_decode(encode_str);
    printf("decode_str.size=%ld, data is:\n", decode_str.size());

    for (i=1; i<=decode_str.size(); i++) {
        printf("%d\t", decode_str.data()[i-1]);
        if (i%16 == 0)
            printf("\n");
    }

    std::string encode_str2;
    encode_str2 = base64_encode((uint8_t*)decode_str.data(), decode_str.size());
    printf("str=%s\n", encode_str2.c_str());
#endif
}

ehsm_status_t testAES()
{
    ehsm_status_t ret = EH_OK;

    ehsm_keyblob_t cmk;
    ehsm_data_t aad;
    ehsm_data_t plaintext;
    ehsm_data_t ciphertext;
    ehsm_data_t plaintext2;

    cmk.metadata.origin = EH_INTERNAL_KEY;
    cmk.metadata.keyspec = EH_AES_GCM_128;
    cmk.keybloblen = 0;

    printf("============testAES start==========\n");

    ret = CreateKey(&cmk);
    if (ret != EH_OK) {
        printf("Failed(%d) to get the data size of CreateKey with AES key!\n", ret);
        goto cleanup;
    }

    cmk.keyblob = (uint8_t*)malloc(cmk.keybloblen);
    if (cmk.keyblob == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }

    ret = CreateKey(&cmk);
    if (ret != EH_OK) {
        printf("Createkey with aes-gcm-128 failed!\n");
        goto cleanup;
    }
    printf("Create CMK with AES-128 SUCCESSFULLY!\n");
    dump_data(cmk.keyblob, cmk.keybloblen);

    plaintext.datalen = 16;
    plaintext.data = (uint8_t*)malloc(plaintext.datalen);
    if (plaintext.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }
    memset(plaintext.data, 'A', plaintext.datalen);
    dump_data(plaintext.data, plaintext.datalen);

    aad.datalen = 0;
    aad.data = NULL;
    ciphertext.datalen = 0;
    ret = Encrypt(&cmk, &plaintext, &aad, &ciphertext);
    if (ret != EH_OK) {
        printf("Failed(%d) to get data size of Encrypt!\n", ret);
        goto cleanup;
    }

    ciphertext.data = (uint8_t*)malloc(ciphertext.datalen);
    if (ciphertext.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }

    ret = Encrypt(&cmk, &plaintext, &aad, &ciphertext);
    if (ret != EH_OK) {
        printf("Failed(%d) to Encrypt the plaittext data\n", ret);
        goto cleanup;
    }
    printf("Encrypt data SUCCESSFULLY!\n");
    dump_data(ciphertext.data, ciphertext.datalen);

    plaintext2.datalen = 0;
    ret = Decrypt(&cmk, &ciphertext, &aad, &plaintext2);
    if (ret != EH_OK) {
        printf("Failed(%d) to get data size of Decrypt!\n", ret);
        goto cleanup;
    }
    plaintext2.data = (uint8_t*)malloc(plaintext2.datalen);
    if (plaintext2.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }

    ret = Decrypt(&cmk, &ciphertext, &aad, &plaintext2);
    if (ret != EH_OK) {
        printf("Failed(%d) to Decrypt the data\n", ret);
        goto cleanup;
    }
    printf("Decrypt data SUCCESSFULLY!\n");
    dump_data(plaintext2.data, plaintext2.datalen);
cleanup:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(plaintext.data);
    SAFE_FREE(ciphertext.data);
    SAFE_FREE(plaintext2.data);

    printf("============testAES Done==========\n");

    return ret;
}

ehsm_status_t testRSA()
{
    ehsm_status_t ret = EH_OK;

    ehsm_keyblob_t cmk;
    ehsm_data_t aad;
    ehsm_data_t plaintext;
    ehsm_data_t ciphertext;
    ehsm_data_t plaintext2;

    ehsm_data_t digest;
    ehsm_data_t signature;
    bool result = false;

    printf("============testRSA start==========\n");

    cmk.metadata.origin = EH_INTERNAL_KEY;
    cmk.metadata.keyspec = EH_RSA_3072;
    cmk.keybloblen = 0;

    ret = CreateKey(&cmk);
    if (ret != EH_OK) {
        printf("Failed(%d) to get the data size of CreateKey with RSA-3072 key!\n", ret);
        goto cleanup;
    }

    cmk.keyblob = (uint8_t*)malloc(cmk.keybloblen);
    if (cmk.keyblob == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }

    ret = CreateKey(&cmk);
    if (ret != EH_OK) {
        printf("Createkey with RSA-3072 failed!\n");
        goto cleanup;
    }
    printf("Create CMK with RSA-3072 SUCCESSFULLY!\n");
    dump_data(cmk.keyblob, cmk.keybloblen);


    plaintext.datalen = 16;
    plaintext.data = (uint8_t*)malloc(plaintext.datalen);
    if (plaintext.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }
    memset(plaintext.data, 'A', plaintext.datalen);
    dump_data(plaintext.data, plaintext.datalen);

    ciphertext.datalen = 0;
    ret = AsymmetricEncrypt(&cmk, &plaintext, &ciphertext);
    if (ret != EH_OK) {
        printf("Failed(%d) to get data size of AsymmetricEncrypt!\n", ret);
        goto cleanup;
    }

    ciphertext.data = (uint8_t*)malloc(ciphertext.datalen);
    if (ciphertext.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }

    ret = AsymmetricEncrypt(&cmk, &plaintext, &ciphertext);
    if (ret != EH_OK) {
        printf("Failed(%d) to AsymmetricEncrypt data!\n", ret);
        goto cleanup;
    }
    printf("AsymmetricEncrypt data SUCCESSFULLY!\n");
    dump_data(ciphertext.data, ciphertext.datalen);

    plaintext2.datalen = 0;
    ret = AsymmetricDecrypt(&cmk, &ciphertext, &plaintext2);
    if (ret != EH_OK) {
        printf("Failed(%d) to get data size of AsymmetricDecrypt!\n", ret);
        goto cleanup;
    }
    plaintext2.data = (uint8_t*)malloc(plaintext2.datalen);
    if (plaintext2.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }

    ret = AsymmetricDecrypt(&cmk, &ciphertext, &plaintext2);
    if (ret != EH_OK) {
        printf("Failed(%d) to AsymmetricDecrypt the data\n", ret);
        goto cleanup;
    }
    printf("AsymmetricDecrypt data SUCCESSFULLY!\n");
    dump_data(plaintext2.data, plaintext2.datalen);

    digest.datalen = 64;
    digest.data = (uint8_t*)malloc(digest.datalen);
    if (digest.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }
    memset(digest.data, 'B', digest.datalen);
    dump_data(digest.data, digest.datalen);

    signature.datalen = 0;
    ret = Sign(&cmk, &digest, &signature);
    if (ret != EH_OK) {
        printf("Failed(%d) to get data size of Sign!\n", ret);
        goto cleanup;
    }

    signature.data = (uint8_t*)malloc(signature.datalen);
    if (signature.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }

    ret = Sign(&cmk, &digest, &signature);
    if (ret != EH_OK) {
        printf("Failed(%d) to Sign the digest!\n", ret);
        goto cleanup;
    }
    printf("Sign data SUCCESSFULLY!\n");
    dump_data(signature.data, signature.datalen);

    ret = Verify(&cmk, &digest, &signature, &result);
    if (ret != EH_OK || !result) {
        printf("Failed(%d) to Verify the signature!\n", ret);
        goto cleanup;
    }
    printf("Verify signature SUCCESSFULLY!\n");

cleanup:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(plaintext.data);
    SAFE_FREE(ciphertext.data);
    SAFE_FREE(plaintext2.data);
    SAFE_FREE(signature.data);

    printf("============testRSA done==========\n");
    return ret;
}

ehsm_status_t testGenerateDataKey()
{
    ehsm_status_t ret = EH_OK;

    ehsm_keyblob_t cmk;
    ehsm_data_t aad;
    ehsm_data_t plaint_datakey;
    ehsm_data_t cipher_datakey;
    ehsm_data_t plaint_datakey2;
    ehsm_data_t cipher_datakey2;
    ehsm_data_t plaintext1;
    ehsm_data_t plaintext2;

    printf("============testGenerateDataKey start==========\n");
    cmk.metadata.origin = EH_INTERNAL_KEY;
    cmk.metadata.keyspec = EH_AES_GCM_128;
    cmk.keybloblen = 0;

    /* create an aes-128 key as the cmk */
    ret = CreateKey(&cmk);
    if (ret != EH_OK) {
       printf("Failed(%d) to get the data size of CreateKey with AES key!\n", ret);
       goto cleanup;
    }

    cmk.keyblob = (uint8_t*)malloc(cmk.keybloblen);
    if (cmk.keyblob == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }

    ret = CreateKey(&cmk);
    if (ret != EH_OK) {
       printf("Createkey with aes-gcm-128 failed!\n");
       goto cleanup;
    }
    printf("Create CMK with AES-128 SUCCESSFULLY!\n");
    dump_data(cmk.keyblob, cmk.keybloblen);

    /* generate a 16 bytes random data key and with plaint text returned */
    aad.data = NULL;
    aad.datalen = 0;

    plaint_datakey.datalen = 16;
    plaint_datakey.data = (uint8_t*)malloc(plaint_datakey.datalen);
    if (plaint_datakey.data == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }
    dump_data(plaint_datakey.data, plaint_datakey.datalen);

    cipher_datakey.datalen = 0;
    ret = GenerateDataKey(&cmk, &aad, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of GenerateDataKey!\n", ret);
       goto cleanup;
    }

    cipher_datakey.data = (uint8_t*)malloc(cipher_datakey.datalen);
    if (cipher_datakey.data == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }

    ret = GenerateDataKey(&cmk, &aad, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of GenerateDataKey!\n", ret);
       goto cleanup;
    }
    printf("GenerateDataKey SUCCESSFULLY!\n");
    dump_data(plaint_datakey.data, plaint_datakey.datalen);
    dump_data(cipher_datakey.data, cipher_datakey.datalen);

    /* try to use the cmk to decrypt the datakey */
    plaintext1.datalen = 0;
    ret = Decrypt(&cmk, &cipher_datakey, &aad, &plaintext1);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of Decrypt!\n", ret);
       goto cleanup;
    }
    plaintext1.data = (uint8_t*)malloc(plaintext1.datalen);
    if (plaintext1.data == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }
    ret = Decrypt(&cmk, &cipher_datakey, &aad, &plaintext1);
    if (ret != EH_OK) {
       printf("Failed(%d) to Decrypt the datakey!\n", ret);
       goto cleanup;
    }
    printf("Decrypt datakey SUCCESSFULLY!\n");
    dump_data(plaintext1.data, plaintext1.datalen);

    /* generate a 48 bytes random data key and without plaint text returned */
    plaint_datakey2.datalen = 48;
    plaint_datakey2.data = NULL;
    cipher_datakey2.datalen = 0;
    ret = GenerateDataKeyWithoutPlaintext(&cmk, &aad, &plaint_datakey2, &cipher_datakey2);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of GenerateDataKeyWithoutPlaintext!\n", ret);
       goto cleanup;
    }
    cipher_datakey2.data = (uint8_t*)malloc(cipher_datakey2.datalen);
    if (cipher_datakey2.data == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }

    ret = GenerateDataKeyWithoutPlaintext(&cmk, &aad, &plaint_datakey2, &cipher_datakey2);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of GenerateDataKey!\n", ret);
       goto cleanup;
    }
    printf("GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");
    dump_data(cipher_datakey2.data, cipher_datakey2.datalen);

    /* try to use the cmk to decrypt the datakey2 */
    plaintext2.datalen = 0;
    ret = Decrypt(&cmk, &cipher_datakey2, &aad, &plaintext2);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of Decrypt!\n", ret);
       goto cleanup;
    }
    plaintext2.data = (uint8_t*)malloc(plaintext2.datalen);
    if (plaintext2.data == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }
    ret = Decrypt(&cmk, &cipher_datakey2, &aad, &plaintext2);
    if (ret != EH_OK) {
       printf("Failed(%d) to Decrypt the datakey!\n", ret);
       goto cleanup;
    }
    printf("Decrypt datakey SUCCESSFULLY!\n");
    dump_data(plaintext2.data, plaintext2.datalen);

cleanup:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(plaint_datakey.data);
    SAFE_FREE(cipher_datakey.data);
    SAFE_FREE(cipher_datakey2.data);
    SAFE_FREE(plaintext1.data);
    SAFE_FREE(plaintext2.data);

    printf("============testGenerateDataKey done==========\n");
    return ret;
}

/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. generate a cipher datakey without plaintext which encrypted by the CMK

step3. verify the cipher text could be decrypted by CMK correctly

step4. generate a new rsa key pair as the user-supplied asymmetric keymeterials.

step5. export the datakey with the new user public key

step6. verify that the new datakey cipher text could be decrypt succeed by the user rsa key pair

*/
ehsm_status_t testExportDataKey()
{
    ehsm_status_t ret = EH_OK;

    ehsm_keyblob_t cmk;
    ehsm_keyblob_t ukey;
    ehsm_data_t aad;
    ehsm_data_t plaint_datakey;
    ehsm_data_t cipher_datakey;
    ehsm_data_t cipher_datakey_new;

    ehsm_data_t plaintext1;



    printf("============testExportDataKey start==========\n");
    cmk.metadata.origin = EH_INTERNAL_KEY;
    cmk.metadata.keyspec = EH_AES_GCM_128;
    cmk.keybloblen = 0;

    /* create an aes-128 key as the cmk */
    ret = CreateKey(&cmk);
    if (ret != EH_OK) {
       printf("Failed(%d) to get the data size of CreateKey with AES key!\n", ret);
       goto cleanup;
    }

    cmk.keyblob = (uint8_t*)malloc(cmk.keybloblen);
    if (cmk.keyblob == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }

    ret = CreateKey(&cmk);
    if (ret != EH_OK) {
       printf("Createkey with aes-gcm-128 failed!\n");
       goto cleanup;
    }
    printf("Create CMK with AES-128 SUCCESSFULLY!\n");
    dump_data(cmk.keyblob, cmk.keybloblen);

    /* generate a 48 bytes random data key and without plaint text returned */
    aad.data = NULL;
    aad.datalen = 0;

    plaint_datakey.datalen = 48;
    plaint_datakey.data = NULL;

    cipher_datakey.datalen = 0;
    ret = GenerateDataKeyWithoutPlaintext(&cmk, &aad, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of GenerateDataKeyWithoutPlaintext!\n", ret);
       goto cleanup;
    }
    cipher_datakey.data = (uint8_t*)malloc(cipher_datakey.datalen);
    if (cipher_datakey.data == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }

    ret = GenerateDataKeyWithoutPlaintext(&cmk, &aad, &plaint_datakey, &cipher_datakey);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of GenerateDataKey!\n", ret);
       goto cleanup;
    }
    printf("GenerateDataKeyWithoutPlaintext SUCCESSFULLY!\n");
    dump_data(cipher_datakey.data, cipher_datakey.datalen);

    /* try to use the cmk to decrypt the datakey */
    plaintext1.datalen = 0;
    ret = Decrypt(&cmk, &cipher_datakey, &aad, &plaintext1);
    if (ret != EH_OK) {
       printf("Failed(%d) to get size of Decrypt!\n", ret);
       goto cleanup;
    }
    plaintext1.data = (uint8_t*)malloc(plaintext1.datalen);
    if (plaintext1.data == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }
    ret = Decrypt(&cmk, &cipher_datakey, &aad, &plaintext1);
    if (ret != EH_OK) {
       printf("Failed(%d) to Decrypt the datakey!\n", ret);
       goto cleanup;
    }
    printf("Decrypt datakey SUCCESSFULLY!\n");
    dump_data(plaintext1.data, plaintext1.datalen);


    /* create an EHM_RSA_3072 key as the ukey */
    ukey.metadata.origin = EH_INTERNAL_KEY;
    ukey.metadata.keyspec = EH_RSA_3072;
    ukey.keybloblen = 0;
    ret = CreateKey(&ukey);
    if (ret != EH_OK) {
       printf("Failed(%d) to get the data size of CreateKey with EH_RSA_3072 key!\n", ret);
       goto cleanup;
    }

    ukey.keyblob = (uint8_t*)malloc(ukey.keybloblen);
    if (ukey.keyblob == NULL) {
       ret = EH_DEVICE_MEMORY;
       goto cleanup;
    }

    ret = CreateKey(&ukey);
    if (ret != EH_OK) {
       printf("Createkey with RSA_3072 failed!\n");
       goto cleanup;
    }
    printf("Create UKEY with RSA_3072 SUCCESSFULLY!\n");
    dump_data(ukey.keyblob, ukey.keybloblen);

    /* export the datakey with the new user public key */
    cipher_datakey_new.datalen = 0;
    ret = ExportDataKey(&cmk, &ukey, &aad, &cipher_datakey, &cipher_datakey_new);
    if (ret != EH_OK) {
        printf("Failed to get the data size of ExportDataKey!\n");
        goto cleanup;
    }

    cipher_datakey_new.data = (uint8_t*)malloc(cipher_datakey_new.datalen);
    if (cipher_datakey_new.data == NULL) {
        ret = EH_DEVICE_MEMORY;
        goto cleanup;
    }

    ret = ExportDataKey(&cmk, &ukey, &aad, &cipher_datakey, &cipher_datakey_new);
    if (ret != EH_OK) {
        printf("Failed to ExportDataKey with ukey!\n");
        goto cleanup;
    }
    printf("ExportDataKey SUCCESSFULLY!\n");
    dump_data(cipher_datakey_new.data, cipher_datakey_new.datalen);

cleanup:
    SAFE_FREE(cmk.keyblob);
    SAFE_FREE(ukey.keyblob);
    SAFE_FREE(cipher_datakey.data);
    SAFE_FREE(cipher_datakey_new.data);
    SAFE_FREE(plaintext1.data);

    printf("============testExportDataKey end==========\n");
    return ret;
}

int main(int argc, char* argv[])
{
    ehsm_status_t ret = EH_OK;

    ret = Initialize();
    if (ret != EH_OK) {
        printf("Initialize failed %d\n", ret);
        return ret;
    }
    printf("Initialize done\n");

    testAES();

    testGenerateDataKey();

    testRSA();

    testExportDataKey();

    Finalize();

    printf("All of tests done\n");

    return ret;
}

