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

EH_RV testAES()
{
    EH_RV rv = EHR_FUNCTION_FAILED;
    EH_KEY_BLOB key_blob;
    EH_MECHANISM me;
    EH_GCM_PARAMS gcm_para;
    EH_KEY_ORIGIN origin;
    EH_BYTE plain_secret[] = "123";
    EH_ULONG secret_len = strlen((const char *)plain_secret) + 1;
    EH_BYTE_PTR enc_secret = NULL;
    EH_BYTE_PTR dec_secret = NULL;
    EH_ULONG enc_len = 0;
    EH_ULONG dec_len = 0;

    printf("plain secret:%s, len is %ld\n", plain_secret, secret_len);

    me.mechanism = EHM_AES_GCM_128;
    me.pParameter = &gcm_para;
    me.ulParameterLen = sizeof(gcm_para);

    //Here need to call CreateKey twice.
    //On first time, set pData to NULL to get needed key blob size.
    key_blob.pKeyData = NULL;
    key_blob.ulKeyLen = 0;
    origin = EHO_INTERNAL_KEY;

    if ((rv = CreateKey(EHM_AES_GCM_128, origin, &key_blob)) == EHR_OK) {
        printf("get key size done 0x%lx\n", key_blob.ulKeyLen);
        key_blob.pKeyData = (EH_BYTE_PTR)malloc(key_blob.ulKeyLen * sizeof(uint8_t));
        if (key_blob.pKeyData == NULL) {
            return EHR_DEVICE_MEMORY;
        }

        rv = CreateKey(EHM_AES_GCM_128, origin, &key_blob);
        if (rv != EHR_OK) {
            printf("create key 1 failed 0x%lx\n", rv);
            goto cleanup;
        }
    } else {
        printf("create key 2 failed 0x%lx\n", rv);
        return rv;
    }
    printf("create key done\n");

    gcm_para.ulAADLen = 0;
    gcm_para.pAAD = NULL;

    if ((rv = Encrypt(&me, &key_blob, plain_secret, secret_len, NULL, &enc_len) == EHR_OK)) {
        printf("get enc len done 0x%lx\n", enc_len);
        enc_secret = (EH_BYTE_PTR) malloc(enc_len * sizeof(EH_BYTE));
        if (enc_secret == NULL) {
            rv = EHR_DEVICE_MEMORY;
            goto cleanup;
        }

    rv = Encrypt(&me, &key_blob, plain_secret, secret_len, enc_secret, &enc_len);
    if (rv != EHR_OK) {
            printf("encrypt 1 failed 0x%lx\n", rv);
            goto cleanup;
        }
    } else {
        printf("encrypt 2 failed 0x%lx\n", rv);
        goto cleanup;
    }
    printf("encrypt done:%s\n", enc_secret);

    if ((rv = Decrypt(&me, &key_blob, enc_secret, enc_len, NULL, &dec_len)) == EHR_OK) {
        printf("get dec len done 0x%lx\n", dec_len);
        dec_secret = (EH_BYTE_PTR) malloc(dec_len * sizeof(EH_BYTE));
        if (dec_secret == NULL) {
            rv = EHR_DEVICE_MEMORY;
            goto cleanup;
        }

        rv = Decrypt(&me, &key_blob, enc_secret, enc_len, dec_secret, &dec_len);
        if (rv != EHR_OK) {
            printf("decrypt 1 failed 0x%lx\n", rv);
            goto cleanup;
        }
    } else {
        printf("decrypt 2 failed 0x%lx\n", rv);
        goto cleanup;
    }
    printf("decrypt done:%s\n", dec_secret);

cleanup:
    if (dec_secret != NULL)
        free(dec_secret);
    if (enc_secret != NULL)
        free(enc_secret);
    if (key_blob.pKeyData != NULL)
        free(key_blob.pKeyData);

    return rv;
}

EH_RV testRSA()
{
    EH_KEY_BLOB key_blob;
    EH_KEY_ORIGIN origin;

    key_blob.pKeyData = NULL;
    origin = EHO_INTERNAL_KEY;
    key_blob.ulKeyLen = 0;

    /* get size of rsa blob */
    if (CreateKey(EHM_RSA_3072, origin, &key_blob) != EHR_OK) {
        printf("untrusted test rsa CreateKey get size FAILED.\n");
        return EHR_FUNCTION_FAILED;
    }

    printf("untrusted test rsa CreateKey get size(%lu) SUCCESSFULLY.\n", key_blob.ulKeyLen);

    uint8_t rsa_blob[key_blob.ulKeyLen] = {0};
    key_blob.pKeyData = rsa_blob;
    key_blob.ulKeyLen = sizeof(rsa_blob);

    if (CreateKey(EHM_RSA_3072, origin, &key_blob) != EHR_OK) {
        printf("untrusted test rsa CreateKey FAILED.\n");
        return EHR_FUNCTION_FAILED;
    }

    printf("untrusted test rsa CreateKey SUCCESSFULLY.\n");

    EH_MECHANISM mechanism;
    mechanism.mechanism = EHM_RSA_3072;
    uint8_t rsa_data2encrypt[] = "QQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    uint8_t rsa_ciphertext[384];
    unsigned long int rsa_ciphertext_len = sizeof(rsa_ciphertext);

    printf("untrusted test rsa_encrypt, data to encrypt is %s.\n", rsa_data2encrypt);
    EH_RV ret1 = Encrypt(&mechanism, &key_blob,
                         rsa_data2encrypt, sizeof(rsa_data2encrypt),
                         rsa_ciphertext, &rsa_ciphertext_len);
    if (ret1 != EHR_OK) {
        printf("untrusted test rsa encryption FAILED:%lu.\n", ret1);
        return ret1;
    }

    printf("untrusted test rsa encryption is SUCCESSFUL.\n");

    unsigned long int rsa_plaintext_len = 0;

    /* get plaintext size */
    ret1 = Decrypt(&mechanism, &key_blob,
                   rsa_ciphertext, sizeof(rsa_ciphertext),
                   NULL, &rsa_plaintext_len);
    if (ret1 != EHR_OK)
        printf("untrusted test rsa decryption get plaintext size FAILED:%lu.\n", ret1);
    else {
        printf("untrusted test rsa decryption get plaintext size SUCCESSFUL, size is %lu.\n", rsa_plaintext_len);

        uint8_t rsa_plaintext[rsa_plaintext_len] = {0};
        ret1 = Decrypt(&mechanism, &key_blob,
                       rsa_ciphertext, sizeof(rsa_ciphertext),
                       rsa_plaintext, &rsa_plaintext_len);
        if (ret1 != EHR_OK)
            printf("untrusted test rsa decryption FAILED:%lu.\n", ret1);
        else
            printf("untrusted test rsa decryption is SUCCESSFUL, plain text is %s.\n", rsa_plaintext);
    }

    uint8_t data2sign[256] = "1234567890";
    uint8_t signature[384] = {0};
    unsigned long int signature_len = sizeof(signature);
    bool verified_result = false;

    printf("untrusted test rsa sign/verify, data to sign is %s.\n", data2sign);
    EH_RV ret2 = Sign(&mechanism, &key_blob, data2sign, sizeof(data2sign),
                      signature, &signature_len);
    if (ret2 != EHR_OK) {
        printf("untrusted test rsa sign FAILED:%lu.\n", ret2);
        return ret2;
    }

    printf("untrusted test rsa sign is SUCCESSFUL.\n");

    ret2 = Verify(&mechanism, &key_blob, data2sign, sizeof(data2sign),
                  signature, signature_len, &verified_result);
    if (ret2 != EHR_OK) {
        printf("untrusted test rsa verify FAILED:%lu.\n", ret2);
        return ret2;
    }

    printf("untrusted test rsa verify is SUCCESSFUL, verified result is %s.\n",
               verified_result ? "TRUE" : "FALSE");

    if (ret1 != EHR_OK)
        return ret1;
    if (ret2 != EHR_OK)
        return ret2;

    return EHR_OK;
}

EH_RV testGenerateDataKey()
{
    EH_RV rv = EHR_FUNCTION_FAILED;
    EH_KEY_BLOB master_key_blob;
    EH_MECHANISM me;
    EH_GCM_PARAMS gcm_para;
    EH_KEY_ORIGIN origin;
    EH_BYTE_PTR plain_key = NULL;
    EH_BYTE_PTR enc_key = NULL;
    EH_BYTE_PTR dec_key = NULL;
    EH_ULONG key_len = 0;
    EH_ULONG enc_key_len = 0;
    EH_ULONG dec_key_len = 0;
    uint32_t i = 0;

    me.mechanism = EHM_AES_GCM_128;
    me.pParameter = &gcm_para;
    me.ulParameterLen = sizeof(gcm_para);

    //Here need to call CreateKey twice.
    //On first time, set pData to NULL to get needed key blob size.
    master_key_blob.pKeyData = NULL;
    master_key_blob.ulKeyLen = 16;
    origin = EHO_INTERNAL_KEY;

    if ((rv = CreateKey(EHM_AES_GCM_128, origin, &master_key_blob)) == EHR_OK) {
        printf("get key size done 0x%lx\n", master_key_blob.ulKeyLen);
        master_key_blob.pKeyData = (EH_BYTE_PTR)malloc(master_key_blob.ulKeyLen * sizeof(uint8_t));
        if (master_key_blob.pKeyData == NULL) {
            return EHR_DEVICE_MEMORY;
        }

        rv = CreateKey(EHM_AES_GCM_128, origin, &master_key_blob);
        if (rv != EHR_OK) {
            printf("create key 1 failed 0x%lx\n", rv);
            goto cleanup;
        }
    } else {
        printf("create key 2 failed 0x%lx\n", rv);
        return rv;
    }
    printf("create key done\n");

    gcm_para.ulAADLen = 0;
    gcm_para.pAAD = NULL;

    key_len = 16;
    plain_key = (EH_BYTE_PTR) malloc(key_len * sizeof(EH_BYTE));
    if (plain_key == NULL) {
        rv = EHR_DEVICE_MEMORY;
        goto cleanup;
    }

    if ((rv = GenerateDataKey(&me, &master_key_blob, plain_key, key_len, NULL, &enc_key_len) == EHR_OK)) {
        printf("get enc data key len done 0x%lx\n", enc_key_len);
        enc_key = (EH_BYTE_PTR) malloc(enc_key_len * sizeof(EH_BYTE));
        if (enc_key == NULL) {
            rv = EHR_DEVICE_MEMORY;
            goto cleanup;
        }

        rv = GenerateDataKey(&me, &master_key_blob, plain_key, key_len, enc_key, &enc_key_len);
        if (rv != EHR_OK) {
            printf("GenerateDataKey 1 failed 0x%lx\n", rv);
            goto cleanup;
        }
    } else {
        printf("GenerateDataKey 2 failed 0x%lx\n", rv);
        goto cleanup;
    }

    for (i = 0; i < key_len; i++) {
        printf("0x%x:", *(plain_key + i));
    }
    printf("GenerateDataKey done\n");

    if ((rv = Decrypt(&me, &master_key_blob, enc_key, enc_key_len, NULL, &dec_key_len)) == EHR_OK) {
        printf("get dec key len done 0x%lx\n", dec_key_len);
        dec_key =  (EH_BYTE_PTR) malloc(dec_key_len * sizeof(EH_BYTE));
        if (dec_key == NULL) {
            rv = EHR_DEVICE_MEMORY;
            goto cleanup;
        }

        rv = Decrypt(&me, &master_key_blob, enc_key, enc_key_len, dec_key, &dec_key_len);
        if (rv != EHR_OK) {
            printf("decrypt 1 failed 0x%lx\n", rv);
            goto cleanup;
        }
    } else {
        printf("decrypt 2 failed 0x%lx\n", rv);
        goto cleanup;
    }

    for (i = 0; i < dec_key_len; i++) {
        printf("0x%x:", *(dec_key + i));
    }
    printf("decrypt done\n");

    if ((rv = GenerateDataKeyWithoutPlaintext(&me, &master_key_blob, key_len, NULL, &enc_key_len) == EHR_OK)) {
        printf("get enc data key len done 0x%lx\n", enc_key_len);
        enc_key = (EH_BYTE_PTR) malloc(enc_key_len * sizeof(EH_BYTE));
        if (enc_key == NULL) {
            rv = EHR_DEVICE_MEMORY;
            goto cleanup;
        }

        rv = GenerateDataKeyWithoutPlaintext(&me, &master_key_blob, key_len, enc_key, &enc_key_len);
        if (rv != EHR_OK) {
            printf("GenerateDataKeyWithoutPlaintext 1 failed 0x%lx\n", rv);
            goto cleanup;
        }
    } else {
        printf("GenerateDataKeyWithoutPlaintext 2 failed 0x%lx\n", rv);
        goto cleanup;
    }
    printf("GenerateDataKeyWithoutPlaintext done\n");

    if ((rv = Decrypt(&me, &master_key_blob, enc_key, enc_key_len, NULL, &dec_key_len)) == EHR_OK) {
        printf("get dec key len done 0x%lx\n", dec_key_len);
        dec_key = (EH_BYTE_PTR) malloc(dec_key_len * sizeof(EH_BYTE));
        if (dec_key == NULL) {
            rv = EHR_DEVICE_MEMORY;
            goto cleanup;
        }

        rv = Decrypt(&me, &master_key_blob, enc_key, enc_key_len, dec_key, &dec_key_len);
        if (rv != EHR_OK) {
            printf("decrypt 1 failed 0x%lx\n", rv);
            goto cleanup;
        }
    } else {
        printf("decrypt 2 failed 0x%lx\n", rv);
        goto cleanup;
    }

    for (i = 0; i < dec_key_len; i++) {
        printf("0x%x:", *(dec_key + i));
    }
    printf("decrypt done\n");

cleanup:
    if (plain_key != NULL)
        free(plain_key);
    if (dec_key != NULL)
        free(dec_key);
    if (enc_key != NULL)
        free(enc_key);
    if (master_key_blob.pKeyData != NULL)
        free(master_key_blob.pKeyData);

    return rv;
}

/*

step1. generate an aes-gcm-128 key as the CM(customer master key)

step2. generate a cipher datakey without plaintext which encrypted by the CMK

step3. verify the cipher text could be decrypted by CMK correctly

step4. generate a new rsa key pair as the user-supplied asymmetric keymeterials.

step5. export the datakey with the new user public key

step6. verify that the new datakey cipher text could be decrypt succeed by the user rsa key pair

*/
EH_RV testExportDataKey()
{
    EH_RV rv = EHR_FUNCTION_FAILED;
    EH_KEY_BLOB master_key_blob;
    EH_MECHANISM me;
    EH_GCM_PARAMS gcm_para;
    EH_KEY_ORIGIN origin;

    EH_ULONG datakey_len = 0;

    EH_BYTE_PTR datakey_plaintext = NULL;
    EH_ULONG datakey_plaintlen = 0;

    EH_BYTE_PTR datakey_ciphertext = NULL;
    EH_ULONG datakey_cipherlen = 0;

    EH_BYTE_PTR datakey_ciphertext_new = NULL;
    EH_ULONG datakey_cipherlen_new = 0;

    EH_BYTE_PTR datakey_plainttext_new = NULL;
    EH_ULONG datakey_plaintlen_new = 0;

    uint32_t i = 0;

    printf("============testExportDataKey start==========\n");

    //step1. generate a customer master key
    origin = EHO_INTERNAL_KEY;

    master_key_blob.pKeyData = NULL;
    master_key_blob.ulKeyLen = 16;
    rv = CreateKey(EHM_AES_GCM_128, origin, &master_key_blob);
    if (rv != EHR_OK) {
        printf("Failed to get the data size of CreateKey with AES key!\n");
        goto cleanup;
    }

    master_key_blob.pKeyData = (EH_BYTE_PTR)malloc(master_key_blob.ulKeyLen);
    if (master_key_blob.pKeyData == NULL) {
        rv = EHR_DEVICE_MEMORY;
        goto cleanup;
    }

    rv = CreateKey(EHM_AES_GCM_128, origin, &master_key_blob);
    if (rv != EHR_OK) {
        printf("Createkey with aes-gcm-128 failed!\n");
        goto cleanup;
    }
    printf("Create an aes-gcm-128 key as the CMK done!\n");

    //step2. generate a cipher datakey which encrypted by the CMK
    me.mechanism = EHM_AES_GCM_128;
    me.pParameter = &gcm_para;
    me.ulParameterLen = sizeof(gcm_para);

    gcm_para.ulAADLen = 0;
    gcm_para.pAAD = NULL;

    datakey_len = 16;

    rv = GenerateDataKeyWithoutPlaintext(&me, &master_key_blob, datakey_len, NULL, &datakey_cipherlen);
    if (rv != EHR_OK) {
        printf("Failed to get the data size of GenerateDataKeyWithoutPlaintext!\n");
        goto cleanup;
    }

    datakey_ciphertext = (EH_BYTE_PTR)malloc(datakey_cipherlen);
    if (datakey_ciphertext == NULL) {
        rv = EHR_DEVICE_MEMORY;
        goto cleanup;
    }

    rv = GenerateDataKeyWithoutPlaintext(&me, &master_key_blob, datakey_len, datakey_ciphertext, &datakey_cipherlen);
    if (rv != EHR_OK) {
        printf("Failed(%d) to generate the DataKey!\n", rv);
        goto cleanup;
    }
    printf("Generated a CipherDataKey that encrypted by the CMK succeed.\n");


    //step3. verify the cipher text could be decrypted by CMK correctly
    rv = Decrypt(&me, &master_key_blob, datakey_ciphertext, datakey_cipherlen, NULL, &datakey_plaintlen);
    if (rv != EHR_OK) {
        printf("Failed to get data size of Decrypt!\n");
        goto cleanup;
    }

    datakey_plaintext = (EH_BYTE_PTR)malloc(datakey_plaintlen);
    if (datakey_plaintext == NULL) {
        rv = EHR_DEVICE_MEMORY;
        goto cleanup;
    }

    rv = Decrypt(&me, &master_key_blob, datakey_ciphertext, datakey_cipherlen, datakey_plaintext, &datakey_plaintlen);
    if (rv != EHR_OK) {
        printf("Failed to Decrypt the DataKey!\n");
        goto cleanup;
    }

    for (i = 0; i < datakey_plaintlen; i++) {
        printf("0x%x:", *(datakey_plaintext + i));
    }
    printf("\nThe DataKey decrypted by the CMK succeed!\n");


    //step4. generate a new rsa key pair as the user-supplied asymmetric keymeterials.
    EH_KEY_BLOB user_key_blob;

    user_key_blob.pKeyData = NULL;
    user_key_blob.ulKeyLen = 0;

    rv = CreateKey(EHM_RSA_3072, origin, &user_key_blob);
    if (rv != EHR_OK) {
        printf("Failed to get data size of CreateKey with RSA key!\n");
        goto cleanup;
    }

    user_key_blob.pKeyData = (EH_BYTE_PTR)malloc(user_key_blob.ulKeyLen);
    if (user_key_blob.pKeyData == NULL) {
        rv = EHR_DEVICE_MEMORY;
        goto cleanup;
    }

    rv = CreateKey(EHM_RSA_3072, origin, &user_key_blob);
    if (rv != EHR_OK) {
        printf("Failed to create rsa key!\n");
        goto cleanup;
    }
    printf("Create a user rsa keypair succeed!\n");

    //step5. export the datakey with the new user public key
    rv = ExportDataKey(&me, &user_key_blob, &master_key_blob, datakey_ciphertext, datakey_cipherlen, NULL, &datakey_cipherlen_new);
    if (rv != EHR_OK) {
        printf("Failed to get the data size of ExportDataKey!\n");
        goto cleanup;
    }

    datakey_ciphertext_new = (EH_BYTE_PTR)malloc(datakey_cipherlen_new);
    if (datakey_ciphertext_new == NULL) {
        rv = EHR_DEVICE_MEMORY;
        goto cleanup;
    }

    rv = ExportDataKey(&me, &user_key_blob, &master_key_blob, datakey_ciphertext, datakey_cipherlen, datakey_ciphertext_new, &datakey_cipherlen_new);
    if (rv != EHR_OK) {
        printf("Failed(%d) to export the datakey with the user-supplied asymmetric key!\n", rv);
        goto cleanup;
    }

    printf("ExportDataKey succeed!\n");

    //step6. verify that the new datakey cipher text could be decrypt succeed by the user rsa key pair
    me.mechanism = EHM_RSA_3072;
    rv = Decrypt(&me, &user_key_blob, datakey_ciphertext_new, datakey_cipherlen_new, NULL, &datakey_plaintlen_new);
    if (rv != EHR_OK) {
        printf("Failed to get datasize of Decrypt!\n");
        goto cleanup;
    }

    datakey_plainttext_new = (EH_BYTE_PTR)malloc(datakey_plaintlen_new);
    if (datakey_plainttext_new == NULL) {
        rv = EHR_DEVICE_MEMORY;
        goto cleanup;
    }

    rv = Decrypt(&me, &user_key_blob, datakey_ciphertext_new, datakey_cipherlen_new, datakey_plainttext_new, &datakey_plaintlen_new);
    if (rv != EHR_OK) {
        printf("Failed to Decrypt the DataKey with user-supplied asymmetric key! !\n");
        goto cleanup;
    }

    for (i = 0; i < datakey_plaintlen_new; i++) {
        printf("0x%x:", *(datakey_plainttext_new + i));
    }
    printf("\nThe DataKey decrypted by the user-supplied asymmetric key succeed!\n");

cleanup:
    if (datakey_plaintext != NULL)
        free(datakey_plaintext);

    if (datakey_ciphertext != NULL)
        free(datakey_ciphertext);

    if (master_key_blob.pKeyData != NULL)
        free(master_key_blob.pKeyData);

    if (user_key_blob.pKeyData != NULL)
        free(user_key_blob.pKeyData);

    if (datakey_ciphertext_new != NULL)
        free(datakey_ciphertext_new);

    if (datakey_plainttext_new != NULL)
        free(datakey_plainttext_new);

    printf("============testExportDataKey end==========\n");
    return rv;
}

int main(int argc, char* argv[])
{
    int ret = 0;
    EH_RV rv = EHR_FUNCTION_FAILED;

    rv = Initialize();
    if (rv != EHR_OK) {
        printf("Initialize failed 0x%lx\n", rv);
        return -1;
    }
    printf("Initialize done\n");

    printf("AES test start\n");
    rv = testAES();
    if (rv != EHR_OK) {
        printf("AES test failed 0x%lx\n", rv);
        ret = -1;
    }
    printf("AES test done\n");

    printf("GenerateDataKey test start\n");
    rv = testGenerateDataKey();
    if (rv != EHR_OK) {
        printf("GenerateDataKey test failed 0x%lx\n", rv);
        ret = -1;
    }
    printf("GenerateDataKey test done\n");

    printf("RSA test start\n");
    rv = testRSA();
    if (rv != EHR_OK) {
        printf("untrusted print test rsa failed.\n");
        ret = -1;
    }
    printf("RSA test done.\n");

    testExportDataKey();

    Finalize();

    printf("All of tests done\n");

    return ret;
}

