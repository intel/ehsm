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

#include "performance_test.h"
#include "../App/ehsm_provider.h"
#include "base64.h"
#include "dsohandle.h"
#include "json_utils.h"
#include "ulog_utils.h"

ehsm_keyspec_t supported_symmetric_keyspec_aesgcm[] = {EH_AES_GCM_128, EH_AES_GCM_192, EH_AES_GCM_256};

size_t supported_symmetric_keyspec_aesgcm_num = sizeof(supported_symmetric_keyspec_aesgcm) / sizeof(supported_symmetric_keyspec_aesgcm[0]);

ehsm_keyspec_t supported_symmetric_keyspec_sm4[] = {EH_SM4_CBC, EH_SM4_CTR};

size_t supported_symmetric_keyspec_sm4_num = sizeof(supported_symmetric_keyspec_sm4) / sizeof(supported_symmetric_keyspec_sm4[0]);

ehsm_keyspec_t supported_asymmetric_keyspec_rsa[] = {EH_RSA_2048, EH_RSA_3072, EH_RSA_4096};

size_t supported_asymmetric_keyspec_rsa_num = sizeof(supported_asymmetric_keyspec_rsa) / sizeof(supported_asymmetric_keyspec_rsa[0]);

ehsm_keyspec_t supported_asymmetric_keyspec_ec[] = {EH_EC_P224, EH_EC_P256, EH_EC_P256K, EH_EC_P384, EH_EC_P521};

size_t supported_asymmetric_keyspec_ec_num = sizeof(supported_asymmetric_keyspec_ec) / sizeof(supported_asymmetric_keyspec_ec[0]);

ehsm_keyspec_t supported_asymmetric_keyspec_sm2[] = {EH_SM2};

size_t supported_asymmetric_keyspec_sm2_num = sizeof(supported_asymmetric_keyspec_sm2) / sizeof(supported_asymmetric_keyspec_sm2[0]);

ehsm_digest_mode_t supported_digest_mode[] = {EH_SHA_224, EH_SHA_256, EH_SHA_384, EH_SHA_512};

size_t supported_digest_mode_num = sizeof(supported_digest_mode) / sizeof(supported_digest_mode[0]);

ehsm_digest_mode_t supported_sm2_digest_mode[] = {EH_SM3};

size_t supported_sm2_digest_mode_num = sizeof(supported_sm2_digest_mode) / sizeof(supported_sm2_digest_mode[0]);

static bool _createkey(ehsm_keyblob_t *&cmk)
{
    ehsm_keyblob_t cmk_tmp = {};
    cmk_tmp.metadata.origin = EH_INTERNAL_KEY;
    cmk_tmp.metadata.keyspec = cmk->metadata.keyspec;
    cmk_tmp.metadata.keyusage = cmk->metadata.keyusage;
    cmk_tmp.keybloblen = 0;
    ehsm_status_t ret = CreateKey(&cmk_tmp);
    if (ret != EH_OK)
    {
        log_e("first createkey failed with keyspec code %d failed(%d).\n", cmk_tmp.metadata.keyspec, ret);
        return false;
    }

    cmk = (ehsm_keyblob_t *)malloc(APPEND_SIZE_TO_KEYBLOB_T(cmk_tmp.keybloblen));
    if (cmk == NULL)
    {
        log_e("malloc failed.\n");
        return false;
    }
    cmk->keybloblen = cmk_tmp.keybloblen;
    cmk->metadata = cmk_tmp.metadata;

    ret = CreateKey(cmk);
    if (ret != EH_OK)
    {
        log_e("Createkey with keyspec code %d failed.\n", cmk->metadata.keyspec);
        return false;
    }
    return true;
}

static bool _encrypt(ehsm_keyblob_t *cmk, ehsm_data_t *plaintext, ehsm_data_t *aad, ehsm_data_t *&ciphertext)
{
    ehsm_data_t ciphertext_tmp = {0};

    ehsm_status_t ret = Encrypt(cmk, plaintext, aad, &ciphertext_tmp);
    if (ret != EH_OK)
    {
        log_e("first encrypt failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    ciphertext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(ciphertext_tmp.datalen));
    if (ciphertext == NULL)
    {
        log_e("out of memory malloc failed.\n");
        return false;
    }
    ciphertext->datalen = ciphertext_tmp.datalen;

    ret = Encrypt(cmk, plaintext, aad, ciphertext);
    if (ret != EH_OK)
    {
        log_e("encrypt failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    return true;
}

static bool _decrypt(ehsm_keyblob_t *cmk, ehsm_data_t *ciphertext, ehsm_data_t *aad, ehsm_data_t *&plaintext)
{
    ehsm_data_t plaintext_tmp = {0};

    ehsm_status_t ret = Decrypt(cmk, ciphertext, aad, &plaintext_tmp);
    if (ret != EH_OK)
    {
        log_e("first encrypt failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_tmp.datalen));
    if (plaintext == NULL)
    {
        log_e("out of memory malloc failed.\n");
        return false;
    }
    plaintext->datalen = plaintext_tmp.datalen;

    ret = Decrypt(cmk, ciphertext, aad, plaintext);
    if (ret != EH_OK)
    {
        log_e("encrypt failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    return true;
}

static bool _asymmetric_encrypt(ehsm_keyblob_t *cmk, ehsm_data_t *plaintext, ehsm_data_t *&ciphertext)
{
    ehsm_data_t ciphertext_tmp = {0};

    ehsm_status_t ret = AsymmetricEncrypt(cmk, EH_RSA_PKCS1, plaintext, &ciphertext_tmp);
    if (ret != EH_OK)
    {
        log_e("first asymmetric encrypt failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    ciphertext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(ciphertext_tmp.datalen));
    if (ciphertext == NULL)
    {
        log_e("out of memory malloc failed.\n");
        return false;
    }
    ciphertext->datalen = ciphertext_tmp.datalen;

    ret = AsymmetricEncrypt(cmk, EH_RSA_PKCS1, plaintext, ciphertext);
    if (ret != EH_OK)
    {
        log_e("asymmetric encrypt failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    return true;
}

static bool _asymmetric_decrypt(ehsm_keyblob_t *cmk, ehsm_data_t *ciphertext, ehsm_data_t *&plaintext)
{
    ehsm_data_t plaintext_tmp = {0};

    ehsm_status_t ret = AsymmetricDecrypt(cmk, EH_RSA_PKCS1, ciphertext, &plaintext_tmp);
    if (ret != EH_OK)
    {
        log_e("first asymmetric decrypt failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    plaintext = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_tmp.datalen));
    if (plaintext == NULL)
    {
        log_e("out of memory malloc failed.\n");
        return false;
    }
    plaintext->datalen = plaintext_tmp.datalen;

    ret = AsymmetricDecrypt(cmk, EH_RSA_PKCS1, ciphertext, plaintext);
    if (ret != EH_OK)
    {
        log_e("asymmetric decrypt failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    return true;
}

static bool _sign(ehsm_keyblob_t *cmk, ehsm_digest_mode_t digest_mode, ehsm_padding_mode_t padding_mode, ehsm_message_type_t message_type, ehsm_data_t *message, ehsm_data_t *&signature)
{
    ehsm_data_t signature_tmp = {0};
    ehsm_status_t ret = Sign(cmk, digest_mode, padding_mode, message_type, message, &signature_tmp);
    if (ret != EH_OK)
    {
        log_e("first sign failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    signature = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(signature_tmp.datalen));
    if (signature == NULL)
    {
        log_e("out of memory malloc failed.\n");
        return false;
    }
    signature->datalen = signature_tmp.datalen;
    ret = Sign(cmk, digest_mode, padding_mode, message_type, message, signature);
    if (ret != EH_OK)
    {
        log_e("sign failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    return true;
}

static bool _verify(ehsm_keyblob_t *cmk, ehsm_digest_mode_t digest_mode, ehsm_padding_mode_t padding_mode, ehsm_message_type_t message_type, ehsm_data_t *message, ehsm_data_t *signature, bool *result)
{
    ehsm_status_t ret = Verify(cmk, digest_mode, padding_mode, message_type, message, signature, result);
    if (ret != EH_OK)
    {
        log_e("verify failed with keyspec code %d.\n", cmk->metadata.keyspec);
        return false;
    }
    return true;
}

void test_perf_create_aesgcm_key()
{
    // create aesgcm key
    for (int i = 0; i < supported_symmetric_keyspec_aesgcm_num; i++)
    {
        bool status = true;
        auto begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < AESGCM_CREATEKEY_PERFNUM; j++)
        {
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                log_e("out of memory\n");
                status = false;
                break;
            }
            cmk->metadata.keyspec = supported_symmetric_keyspec_aesgcm[i];
            cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
            if (!_createkey(cmk))
            {
                log_e("createkey failed\n");
                status = false;
                SAFE_FREE(cmk);
                break;
            }
            SAFE_FREE(cmk);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of CreateKey keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_symmetric_keyspec_aesgcm[i], AESGCM_CREATEKEY_PERFNUM, elapsed.count() * 1e-9);
        }
    }
}

void test_perf_create_sm4_key()
{
    // create sm4 key
    for (int i = 0; i < supported_symmetric_keyspec_sm4_num; i++)
    {
        bool status = true;
        auto begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < SM4_CREATEKEY_PERFNUM; j++)
        {
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                log_e("out of memory\n");
                status = false;
                break;
            }
            cmk->metadata.keyspec = supported_symmetric_keyspec_sm4[i];
            cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
            if (!_createkey(cmk))
            {
                log_e("createkey failed\n");
                status = false;
                SAFE_FREE(cmk);
                break;
            }
            SAFE_FREE(cmk);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of CreateKey keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_symmetric_keyspec_sm4[i], SM4_CREATEKEY_PERFNUM, elapsed.count() * 1e-9);
        }
    }
}

void test_perf_create_rsa_key()
{
    // create rsa key
    for (int i = 0; i < supported_asymmetric_keyspec_rsa_num; i++)
    {
        bool status = true;
        auto begin = std::chrono::high_resolution_clock::now();
        for (int k = 0; k < RSA_CREATEKEY_PERFNUM; k++)
        {
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                log_e("out of memory\n");
                status = false;
                break;
            }
            cmk->metadata.keyspec = supported_asymmetric_keyspec_rsa[i];
            cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
            if (!_createkey(cmk))
            {
                log_e("createkey failed\n");
                status = false;
                SAFE_FREE(cmk);
                break;
            }
            SAFE_FREE(cmk);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of CreateKey keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_rsa[i], RSA_CREATEKEY_PERFNUM, elapsed.count() * 1e-9);
        }
    }
}

void test_perf_create_ec_key()
{
    // create ec key
    for (int i = 0; i < supported_asymmetric_keyspec_ec_num; i++)
    {
        bool status = true;
        auto begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < EC_CREATEKEY_PERFNUM; j++)
        {
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                log_e("out of memory\n");
                status = false;
                break;
            }
            cmk->metadata.keyspec = supported_asymmetric_keyspec_ec[i];
            cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
            if (!_createkey(cmk))
            {
                log_e("createkey failed\n");
                status = false;
                SAFE_FREE(cmk);
                break;
            }
            SAFE_FREE(cmk);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of CreateKey keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_ec[i], EC_CREATEKEY_PERFNUM, elapsed.count() * 1e-9);
        }
    }
}

void test_perf_create_sm2_key()
{
    // create sm2 key
    for (int i = 0; i < supported_asymmetric_keyspec_sm2_num; i++)
    {
        bool status = true;
        auto begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < SM2_CREATEKEY_PERFNUM; j++)
        {
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                log_e("out of memory\n");
                status = false;
                break;
            }
            cmk->metadata.keyspec = supported_asymmetric_keyspec_sm2[i];
            cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
            if (!_createkey(cmk))
            {
                log_e("createkey failed\n");
                status = false;
                SAFE_FREE(cmk);
                break;
            }
            SAFE_FREE(cmk);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of CreateKey keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_sm2[i], SM2_CREATEKEY_PERFNUM, elapsed.count() * 1e-9);
        }
    }
}

void test_perf_rsa_encrytion_decryption()
{

    std::string plaintext_str = "helloworld";
    size_t plaintext_size = plaintext_str.length();
    // rsa encryption decryption
    for (int i = 0; i < supported_asymmetric_keyspec_rsa_num; i++)
    {
        // create key
        bool status = true;
        ehsm_data_t *ciphertext = NULL;
        ehsm_data_t *plaintext_in = NULL;
        ehsm_data_t *plaintext_out = NULL;
        auto begin = std::chrono::high_resolution_clock::now();
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
        if (cmk == NULL)
        {
            log_e("out of memory\n");
            status = false;
            goto out;
        }
        cmk->metadata.keyspec = supported_asymmetric_keyspec_rsa[i];
        cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;

        if (!_createkey(cmk))
        {
            log_e("createkey failed\n");
            status = false;
            goto out;
        }

        // encryption and decryption
        // encryption
        begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < RSA_ENCRYPT_PERFNUM; j++)
        {
            plaintext_in = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_size));
            if (plaintext_in == NULL)
            {
                log_e("out of memory malloc failed.\n");
                status = false;
                goto out;
            }
            plaintext_in->datalen = plaintext_size;
            memcpy_s(plaintext_in->data, plaintext_size, (uint8_t *)plaintext_str.data(), plaintext_size);

            if (!_asymmetric_encrypt(cmk, plaintext_in, ciphertext))
            {
                log_e("asymmetric encrypt failed with keyspec code %d in time %d.\n", supported_asymmetric_keyspec_rsa[i], j);
                status = false;
                goto out;
            }
            SAFE_FREE(plaintext_in);
            if (j < RSA_ENCRYPT_PERFNUM - 1)
            {
                SAFE_FREE(ciphertext);
            }
        }
        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of asymmetric encryption keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_rsa[i], RSA_ENCRYPT_PERFNUM, elapsed.count() * 1e-9);
        }

        // decryption
        begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < RSA_DECRYPT_PERFNUM; j++)
        {
            if (!_asymmetric_decrypt(cmk, ciphertext, plaintext_out))
            {
                log_e("asymmetric decrypt failed with keyspec code %d in time %d.\n", supported_asymmetric_keyspec_rsa[i], j);
                status = false;
                goto out;
            }
            SAFE_FREE(plaintext_out);
        }
        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of asymmetric decryption keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_rsa[i], RSA_DECRYPT_PERFNUM, elapsed.count() * 1e-9);
        }
    out:
        SAFE_FREE(cmk);
        SAFE_FREE(plaintext_in);
        SAFE_FREE(plaintext_out);
        SAFE_FREE(ciphertext);
    }
}

void test_perf_sm2_encryption_decryption()
{
    std::string plaintext_str = "helloworld";
    size_t plaintext_size = plaintext_str.length();

    // sm2 encryption decryption
    bool status = true;
    ehsm_data_t *ciphertext = NULL;
    ehsm_data_t *plaintext_in = NULL;
    ehsm_data_t *plaintext_out = NULL;
    ehsm_keyblob_t *cmk = NULL;
    auto begin = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    for (int i = 0; i < supported_asymmetric_keyspec_sm2_num; i++)
    {
        // create key
        cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
        if (cmk == NULL)
        {
            log_e("out of memory\n");
            status = false;
            goto out;
        }
        cmk->metadata.keyspec = supported_asymmetric_keyspec_sm2[i];
        cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
        if (!_createkey(cmk))
        {
            log_e("createkey failed\n");
            status = false;
            goto out;
        }

        // encryption and decryption
        // encryption
        begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < SM2_ENCRYPT_DECRYPT_PERFNUM; j++)
        {
            plaintext_in = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_size));
            if (plaintext_in == NULL)
            {
                log_e("out of memory malloc failed.\n");
                status = false;
                goto out;
            }
            plaintext_in->datalen = plaintext_size;
            memcpy_s(plaintext_in->data, plaintext_size, (uint8_t *)plaintext_str.data(), plaintext_size);

            if (!_asymmetric_encrypt(cmk, plaintext_in, ciphertext))
            {
                log_e("asymmetric encrypt failed with keyspec code %d in time %d.\n", supported_asymmetric_keyspec_sm2[i], j);
                status = false;
                goto out;
            }
            SAFE_FREE(plaintext_in);
            if (j < SM2_ENCRYPT_DECRYPT_PERFNUM - 1)
            {
                SAFE_FREE(ciphertext);
            }
        }
        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of asymmetric encryption keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_sm2[i], SM2_ENCRYPT_DECRYPT_PERFNUM, elapsed.count() * 1e-9);
        }

        // decryption
        begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < SM2_ENCRYPT_DECRYPT_PERFNUM; j++)
        {
            if (!_asymmetric_decrypt(cmk, ciphertext, plaintext_out))
            {
                log_e("asymmetric decrypt failed with keyspec code %d in time %d.\n", supported_asymmetric_keyspec_sm2[i], j);
                status = false;
                goto out;
            }
            SAFE_FREE(plaintext_out);
        }
        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of asymmetric decryption keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_sm2[i], SM2_ENCRYPT_DECRYPT_PERFNUM, elapsed.count() * 1e-9);
        }
    out:
        SAFE_FREE(cmk);
        SAFE_FREE(plaintext_in);
        SAFE_FREE(plaintext_out);
        SAFE_FREE(ciphertext);
    }
}

void test_perf_aesgcm_encryption_decryption()
{
    std::string plaintext_str = "helloworld";
    size_t plaintext_size = plaintext_str.length();
    std::string aad_str = "challenge";
    size_t aad_size = aad_str.length();

    // aesgcm encryption decryption
    for (int i = 0; i < supported_symmetric_keyspec_aesgcm_num; i++)
    {
        // create key
        bool status = true;
        ehsm_data_t *aad = NULL;
        ehsm_data_t *plaintext_in = NULL;
        ehsm_data_t *plaintext_out = NULL;
        ehsm_data_t *ciphertext = NULL;
        auto begin = std::chrono::high_resolution_clock::now();
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
        if (cmk == NULL)
        {
            log_e("out of memory\n");
            status = false;
            goto out;
        }
        cmk->metadata.keyspec = supported_symmetric_keyspec_aesgcm[i];
        cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
        if (!_createkey(cmk))
        {
            log_e("createkey failed\n");
            status = false;
            goto out;
        }

        // encryption and decryption
        // encryption
        begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < AESGCM_ENCRYPT_DECRYPT_PERFNUM; j++)
        {
            plaintext_in = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_size));
            aad = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(aad_size));
            if (plaintext_in == NULL || aad == NULL)
            {
                log_e("out of memory malloc failed.\n");
                status = false;
                goto out;
            }
            plaintext_in->datalen = plaintext_size;
            aad->datalen = aad_size;
            memcpy_s(plaintext_in->data, plaintext_size, (uint8_t *)plaintext_str.data(), plaintext_size);
            memcpy_s(aad->data, aad_size, (uint8_t *)aad_str.data(), aad_size);

            if (!_encrypt(cmk, plaintext_in, aad, ciphertext))
            {
                log_e("encrypt failed with keyspec code %d in time %d.\n", supported_symmetric_keyspec_aesgcm[i], j);
                status = false;
                goto out;
            }
            SAFE_FREE(aad);
            SAFE_FREE(plaintext_in);
            if (j < AESGCM_ENCRYPT_DECRYPT_PERFNUM - 1)
            {
                SAFE_FREE(ciphertext);
            }
        }
        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of encryption keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_symmetric_keyspec_aesgcm[i], AESGCM_ENCRYPT_DECRYPT_PERFNUM, elapsed.count() * 1e-9);
        }

        // decryption
        begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < AESGCM_ENCRYPT_DECRYPT_PERFNUM; j++)
        {
            aad = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(aad_size));
            if (aad == NULL)
            {
                log_e("out of memory malloc failed.\n");
                status = false;
                goto out;
            }
            aad->datalen = aad_size;
            memcpy_s(aad->data, aad_size, (uint8_t *)aad_str.data(), aad_size);

            if (!_decrypt(cmk, ciphertext, aad, plaintext_out))
            {
                log_e("encrypt failed with keyspec code %d in time %d.\n", supported_symmetric_keyspec_aesgcm[i], j);
                status = false;
                goto out;
            }
            SAFE_FREE(aad);
            SAFE_FREE(plaintext_out);
        }
        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of decryption keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_symmetric_keyspec_aesgcm[i], AESGCM_ENCRYPT_DECRYPT_PERFNUM, elapsed.count() * 1e-9);
        }
    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad);
        SAFE_FREE(plaintext_in);
        SAFE_FREE(plaintext_out);
        SAFE_FREE(ciphertext);
    }
}

void test_perf_sm4_encryption_decryption()
{
    std::string plaintext_str = "helloworld";
    size_t plaintext_size = plaintext_str.length();
    std::string aad_str = "challenge";
    size_t aad_size = aad_str.length();

    // sm4 encryption decryption
    for (int i = 0; i < supported_symmetric_keyspec_sm4_num; i++)
    {
        // create key
        bool status = true;
        ehsm_data_t *aad = NULL;
        ehsm_data_t *plaintext_in = NULL;
        ehsm_data_t *plaintext_out = NULL;
        ehsm_data_t *ciphertext = NULL;
        auto begin = std::chrono::high_resolution_clock::now();
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
        if (cmk == NULL)
        {
            log_e("out of memory\n");
            status = false;
            goto out;
        }
        cmk->metadata.keyspec = supported_symmetric_keyspec_sm4[i];
        cmk->metadata.keyusage = EH_KEYUSAGE_ENCRYPT_DECRYPT;
        if (!_createkey(cmk))
        {
            log_e("createkey failed\n");
            status = false;
            goto out;
        }

        // encryption and decryption
        // encryption
        begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < SM4_ENCRYPT_DECRYPT_PERFNUM; j++)
        {
            plaintext_in = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_size));
            aad = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(aad_size));
            if (plaintext_in == NULL || aad == NULL)
            {
                log_e("out of memory malloc failed.\n");
                status = false;
                goto out;
            }
            plaintext_in->datalen = plaintext_size;
            aad->datalen = aad_size;
            memcpy_s(plaintext_in->data, plaintext_size, (uint8_t *)plaintext_str.data(), plaintext_size);
            memcpy_s(aad->data, aad_size, (uint8_t *)aad_str.data(), aad_size);

            if (!_encrypt(cmk, plaintext_in, aad, ciphertext))
            {
                log_e("encrypt failed with keyspec code %d in time %d.\n", supported_symmetric_keyspec_sm4[i], j);
                status = false;
                goto out;
            }
            SAFE_FREE(aad);
            SAFE_FREE(plaintext_in);
            if (j < SM4_ENCRYPT_DECRYPT_PERFNUM - 1)
            {
                SAFE_FREE(ciphertext);
            }
        }
        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of encryption keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_symmetric_keyspec_sm4[i], SM4_ENCRYPT_DECRYPT_PERFNUM, elapsed.count() * 1e-9);
        }

        // decryption
        begin = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < SM4_ENCRYPT_DECRYPT_PERFNUM; j++)
        {
            aad = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(aad_size));
            if (aad == NULL)
            {
                log_e("out of memory malloc failed.\n");
                status = false;
                goto out;
            }
            aad->datalen = aad_size;
            memcpy_s(aad->data, aad_size, (uint8_t *)aad_str.data(), aad_size);

            if (!_decrypt(cmk, ciphertext, aad, plaintext_out))
            {
                log_e("encrypt failed with keyspec code %d in time %d.\n", supported_symmetric_keyspec_sm4[i], j);
                status = false;
                goto out;
            }
            SAFE_FREE(aad);
            SAFE_FREE(plaintext_out);
        }
        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        if (status)
        {
            log_i("Time measured of decryption keyspec code %d with Repeat NUM(%d): %.6f seconds.\n", supported_symmetric_keyspec_sm4[i], SM4_ENCRYPT_DECRYPT_PERFNUM, elapsed.count() * 1e-9);
        }
    out:
        SAFE_FREE(cmk);
        SAFE_FREE(aad);
        SAFE_FREE(plaintext_in);
        SAFE_FREE(plaintext_out);
        SAFE_FREE(ciphertext);
    }
}

void test_perf_rsa_sign_verify()
{
    std::string data2sign_str = "SIGN";
    size_t data2sign_size = data2sign_str.length();

    // rsa
    for (int i = 0; i < supported_asymmetric_keyspec_rsa_num; i++)
    {
        for (int j = 0; j < supported_digest_mode_num; j++)
        {
            bool status = true;
            bool verify_result = false;
            ehsm_data_t *signature = NULL;
            ehsm_data_t *data2sign = NULL;
            auto begin = std::chrono::high_resolution_clock::now();
            auto end = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

            // create key
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                log_e("out of memory\n");
                status = false;
                goto out;
            }
            cmk->metadata.keyspec = supported_asymmetric_keyspec_rsa[i];
            cmk->metadata.keyusage = EH_KEYUSAGE_SIGN_VERIFY;
            if (!_createkey(cmk))
            {
                log_e("createkey failed\n");
                status = false;
                goto out;
            }
            begin = std::chrono::high_resolution_clock::now();
            for (int k = 0; k < RSA_SIGN_VERIFY_PERFNUM; k++)
            {
                data2sign = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(data2sign_size));
                if (data2sign == NULL)
                {
                    log_e("out of memory malloc failed.\n");
                    status = false;
                    goto out;
                }
                data2sign->datalen = data2sign_size;
                memcpy_s(data2sign->data, data2sign_size, (uint8_t *)data2sign_str.data(), data2sign_size);

                if (!_sign(cmk, supported_digest_mode[j], EH_RSA_PKCS1, EH_RAW, data2sign, signature))
                {
                    log_e("signed failed with keyspec code %d ,digest mode code %d in time %d.\n", supported_asymmetric_keyspec_rsa[i], supported_digest_mode[j], k);
                    status = false;
                    goto out;
                }
                SAFE_FREE(data2sign);
                if (k < RSA_SIGN_VERIFY_PERFNUM - 1)
                {
                    SAFE_FREE(signature);
                }
            }
            end = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
            if (status)
            {
                log_i("Time measured of sign keyspec code %d, digest mode code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_rsa[i], supported_digest_mode[j], RSA_SIGN_VERIFY_PERFNUM, elapsed.count() * 1e-9);
            }

            // verify
            for (int k = 0; k < RSA_SIGN_VERIFY_PERFNUM; k++)
            {
                data2sign = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(data2sign_size));
                if (data2sign == NULL)
                {
                    log_e("out of memory malloc failed.\n");
                    status = false;
                    goto out;
                }
                data2sign->datalen = data2sign_size;
                memcpy_s(data2sign->data, data2sign_size, (uint8_t *)data2sign_str.data(), data2sign_size);
                if (!_verify(cmk, supported_digest_mode[j], EH_RSA_PKCS1, EH_RAW, data2sign, signature, &verify_result))
                {
                    log_e("verify failed with keyspec code %d digest mode code %d in time %d.\n", supported_asymmetric_keyspec_rsa[i], supported_digest_mode[j], k);
                    status = false;
                    goto out;
                }
                SAFE_FREE(data2sign);
            }
            end = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
            if (status)
            {
                log_i("Time measured of verify keyspec code %d digest mode code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_rsa[i], supported_digest_mode[j], RSA_SIGN_VERIFY_PERFNUM, elapsed.count() * 1e-9);
            }
        out:
            SAFE_FREE(cmk);
            SAFE_FREE(data2sign);
            SAFE_FREE(signature);
        }
    }
}

void test_perf_ec_sign_verify()
{
    std::string data2sign_str = "SIGN";
    size_t data2sign_size = data2sign_str.length();
    // ec
    for (int i = 0; i < supported_asymmetric_keyspec_ec_num; i++)
    {
        for (int j = 0; j < supported_digest_mode_num; j++)
        {
            bool status = true;
            bool verify_result = false;
            ehsm_data_t *signature = NULL;
            ehsm_data_t *data2sign = NULL;
            auto begin = std::chrono::high_resolution_clock::now();
            auto end = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
            // create key
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                log_e("out of memory\n");
                status = false;
                goto out;
            }
            cmk->metadata.keyspec = supported_asymmetric_keyspec_ec[i];
            cmk->metadata.keyusage = EH_KEYUSAGE_SIGN_VERIFY;
            if (!_createkey(cmk))
            {
                log_e("createkey failed\n");
                status = false;
                goto out;
            }
            begin = std::chrono::high_resolution_clock::now();
            for (int k = 0; k < EC_SIGN_PERFNUM; k++)
            {
                data2sign = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(data2sign_size));
                if (data2sign == NULL)
                {
                    log_e("out of memory malloc failed.\n");
                    status = false;
                    goto out;
                }
                data2sign->datalen = data2sign_size;
                memcpy_s(data2sign->data, data2sign_size, (uint8_t *)data2sign_str.data(), data2sign_size);

                if (!_sign(cmk, supported_digest_mode[j], EH_PAD_NONE, EH_RAW, data2sign, signature))
                {
                    log_e("signed failed with keyspec code %d digest mode code %d in time %d.\n", supported_asymmetric_keyspec_ec[i], supported_digest_mode[j], k);
                    status = false;
                    goto out;
                }
                SAFE_FREE(data2sign);
                if (k < EC_SIGN_PERFNUM - 1)
                {
                    SAFE_FREE(signature);
                }
            }
            end = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
            if (status)
            {
                log_i("Time measured of sign keyspec code %d digest mode code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_ec[i], supported_digest_mode[j], EC_SIGN_PERFNUM, elapsed.count() * 1e-9);
            }

            // verify
            for (int k = 0; k < EC_VERIFY_PERFNUM; k++)
            {
                data2sign = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(data2sign_size));
                if (data2sign == NULL)
                {
                    log_e("out of memory malloc failed.\n");
                    status = false;
                    goto out;
                }
                data2sign->datalen = data2sign_size;
                memcpy_s(data2sign->data, data2sign_size, (uint8_t *)data2sign_str.data(), data2sign_size);
                if (!_verify(cmk, supported_digest_mode[j], EH_PAD_NONE, EH_RAW, data2sign, signature, &verify_result))
                {
                    log_e("verify failed with keyspec code %d  digest mode code %d in time %d.\n", supported_asymmetric_keyspec_ec[i], supported_digest_mode[j], k);
                    status = false;
                    goto out;
                }
                SAFE_FREE(data2sign);
            }
            end = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
            if (status)
            {
                log_i("Time measured of verify keyspec code %d digest mode code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_ec[i], supported_digest_mode[j], EC_VERIFY_PERFNUM, elapsed.count() * 1e-9);
            }
        out:
            SAFE_FREE(cmk);
            SAFE_FREE(signature);
            SAFE_FREE(data2sign);
        }
    }
}

void test_perf_sm2_sign_verify()
{
    std::string data2sign_str = "SIGN";
    size_t data2sign_size = data2sign_str.length();
    // sm2
    for (int i = 0; i < supported_asymmetric_keyspec_sm2_num; i++)
    {
        for (int j = 0; j < supported_sm2_digest_mode_num; j++)
        {
            bool status = true;
            bool verify_result = false;
            ehsm_data_t *signature = NULL;
            ehsm_data_t *data2sign = NULL;
            auto begin = std::chrono::high_resolution_clock::now();
            auto end = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

            // create key
            ehsm_keyblob_t *cmk = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
            if (cmk == NULL)
            {
                log_e("out of memory\n");
                goto out;
            }
            cmk->metadata.keyspec = supported_asymmetric_keyspec_sm2[i];
            cmk->metadata.keyusage = EH_KEYUSAGE_SIGN_VERIFY;
            if (!_createkey(cmk))
            {
                log_e("createkey failed\n");
                status = false;
                goto out;
            }
            begin = std::chrono::high_resolution_clock::now();
            for (int k = 0; k < SM2_SIGN_VERIFY_PERFNUM; k++)
            {
                data2sign = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(data2sign_size));
                if (data2sign == NULL)
                {
                    log_e("out of memory malloc failed.\n");
                    status = false;
                    goto out;
                }
                data2sign->datalen = data2sign_size;
                memcpy_s(data2sign->data, data2sign_size, (uint8_t *)data2sign_str.data(), data2sign_size);

                if (!_sign(cmk, supported_sm2_digest_mode[j], EH_PAD_NONE, EH_RAW, data2sign, signature))
                {
                    log_e("signed failed with keyspec code %d digest mode code %d in time %d.\n", supported_asymmetric_keyspec_sm2[i], supported_sm2_digest_mode[j], k);
                    status = false;
                    goto out;
                }
                SAFE_FREE(data2sign);
                if (k < SM2_SIGN_VERIFY_PERFNUM - 1)
                {
                    SAFE_FREE(signature);
                }
            }
            end = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
            if (status)
            {
                log_i("Time measured of sign keyspec code %d digest mode code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_sm2[i], supported_sm2_digest_mode[j], SM2_SIGN_VERIFY_PERFNUM, elapsed.count() * 1e-9);
            }

            // verify
            for (int k = 0; k < SM2_SIGN_VERIFY_PERFNUM; k++)
            {
                data2sign = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(data2sign_size));
                if (data2sign == NULL)
                {
                    log_e("out of memory malloc failed.\n");
                    status = false;
                    goto out;
                }
                data2sign->datalen = data2sign_size;
                memcpy_s(data2sign->data, data2sign_size, (uint8_t *)data2sign_str.data(), data2sign_size);
                if (!_verify(cmk, supported_sm2_digest_mode[j], EH_PAD_NONE, EH_RAW, data2sign, signature, &verify_result))
                {
                    log_e("verify failed with keyspec code %d digest mode code %d in time %d.\n", supported_asymmetric_keyspec_sm2[i], supported_sm2_digest_mode[j], k);
                    status = false;
                    goto out;
                }
                SAFE_FREE(data2sign);
            }
            end = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
            if (status)
            {
                log_i("Time measured of verify keyspec code %d digest mode code %d with Repeat NUM(%d): %.6f seconds.\n", supported_asymmetric_keyspec_sm2[i], supported_sm2_digest_mode[j], SM2_SIGN_VERIFY_PERFNUM, elapsed.count() * 1e-9);
            }
        out:
            SAFE_FREE(cmk);
            SAFE_FREE(signature);
            SAFE_FREE(data2sign);
        }
    }
}

// void *test_createkey(void *threadid)
// {
//     RetJsonObj retJsonObj;
//     JsonObj param_json;
//     JsonObj payload_json;
//     char *returnJsonChar = nullptr;
//     long tid = (long)threadid;

//     for (int i = 0; i < PERF_NUM; i++)
//     {
//         payload_json.addData_uint32("keyspec", EH_AES_GCM_256);
//         payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//         param_json.addData_uint32("action", EH_CREATE_KEY);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);

//         if (retJsonObj.getCode() != 200)
//         {
//             log_e("Createkey with aes-128 failed in time(%d)\n", i);
//             SAFE_FREE(returnJsonChar);
//             break;
//         }
//         SAFE_FREE(returnJsonChar);
//         log_i("Thread[%ld], CreateKey(AES-128) succeed in time[%d]\n", tid, i);
//     }

//     pthread_exit(NULL);
// }

// void test_parallel_createkey()
// {
//     void *status;
//     pthread_t threads[NUM_THREADS];
//     int rc;
//     int i;
//     for (i = 0; i < NUM_THREADS; i++)
//     {
//         log_i("creating thread [%d]\n", i);
//         rc = pthread_create(&threads[i], NULL, test_createkey, (void *)i);
//         if (rc)
//         {
//             log_e("Error(%d):unable to create thread\n", rc);
//             exit(-1);
//         }
//     }

//     for (i = 0; i < NUM_THREADS; i++)
//     {
//         rc = pthread_join(threads[i], &status);
//         if (rc)
//         {
//             log_i("Error(%d) to join with thread[%d]\n", rc, i);
//             exit(-1);
//         }
//         log_i("Main: completed thread[%d]\n", i);
//     }
//     pthread_exit(NULL);
// }

// void *test_encrypt(void *threadid)
// {
//     long tid = (long)threadid;
//     char *returnJsonChar = nullptr;
//     char plaintext[32] = "helloworld";
//     char aad[] = "challenge";

//     log_i("Thread[%ld]. plaintext is %s\n", tid, plaintext);

//     char *cmk_base64 = nullptr;
//     char *plaintext_base64 = nullptr;
//     std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext, sizeof(plaintext) / sizeof(plaintext[0]));
//     std::string input_aad_base64 = base64_encode((const uint8_t *)aad, sizeof(aad) / sizeof(aad[0]));

//     RetJsonObj retJsonObj;
//     JsonObj param_json;
//     JsonObj payload_json;
//     payload_json.addData_uint32("keyspec", EH_AES_GCM_256);
//     payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
//     param_json.addData_uint32("action", EH_CREATE_KEY);
//     param_json.addData_JsonValue("payload", payload_json.getJson());

//     if (retJsonObj.getCode() != 200)
//     {
//         log_i("Thread[%ld], Createkey with aes-gcm-128 failed, error message: %s \n", tid, retJsonObj.getMessage().c_str());
//         goto cleanup;
//     }
//     log_i("Thread[%ld], FFI_CreateKey Json = %s\n", tid, returnJsonChar);
//     cmk_base64 = retJsonObj.readData_cstr("cmk");

//     for (int i = 0; i < PERF_NUM; i++)
//     {
//         payload_json.clear();
//         payload_json.addData_string("cmk", cmk_base64);
//         payload_json.addData_string("plaintext", input_plaintext_base64);
//         payload_json.addData_string("aad", input_aad_base64);

//         param_json.addData_uint32("action", EH_ENCRYPT);
//         param_json.addData_JsonValue("payload", payload_json.getJson());

//         returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
//         retJsonObj.parse(returnJsonChar);

//         if (retJsonObj.getCode() != 200)
//         {
//             log_e("Thread[%ld] with time[%d], failed to Encrypt the plaittext data, error message: %s \n", tid, i, retJsonObj.getMessage().c_str());
//             goto cleanup;
//         }

//         log_e("Thread[%ld] with time[%d], FFI_Encrypt json = %s\n", tid, i, returnJsonChar);

//         SAFE_FREE(returnJsonChar);
//     }

// cleanup:
//     SAFE_FREE(plaintext_base64);
//     SAFE_FREE(cmk_base64);
//     SAFE_FREE(returnJsonChar);

//     pthread_exit(NULL);
// }

// void test_parallel_encrypt()
// {
//     void *status;
//     pthread_t threads[NUM_THREADS];
//     int rc;
//     int i;
//     for (i = 0; i < NUM_THREADS; i++)
//     {
//         log_e("creating thread [%d]\n", i);
//         rc = pthread_create(&threads[i], NULL, test_encrypt, (void *)i);
//         if (rc)
//         {
//             log_e("Error(%d):unable to create thread\n", rc);
//             exit(-1);
//         }
//     }

//     for (i = 0; i < NUM_THREADS; i++)
//     {
//         rc = pthread_join(threads[i], &status);
//         if (rc)
//         {
//             log_e("Error(%d) to join with thread[%d]\n", rc, i);
//             exit(-1);
//         }
//         log_i("Main: completed thread[%d]\n", i);
//     }
//     pthread_exit(NULL);
// }

void test_perf_create_symmetric_key()
{
    test_perf_create_aesgcm_key();
    test_perf_create_sm4_key();
}

void test_perf_create_asymmetric_key()
{
    test_perf_create_rsa_key();
    test_perf_create_ec_key();
    test_perf_create_sm2_key();
}

void test_perf_symmetric_encryption_decryption()
{
    test_perf_aesgcm_encryption_decryption();
    test_perf_sm4_encryption_decryption();
}

void test_perf_asymmetric_encryption_decryption()
{
    test_perf_rsa_encrytion_decryption();
    test_perf_sm2_encryption_decryption();
}

void test_perf_sign_verify()
{
    test_perf_rsa_sign_verify();
    test_perf_ec_sign_verify();
    test_perf_sm2_sign_verify();
}

void performance_test()
{
    test_perf_create_symmetric_key();

    test_perf_create_asymmetric_key();

    test_perf_symmetric_encryption_decryption();

    test_perf_asymmetric_encryption_decryption();

    test_perf_sign_verify();
}