/*
 * Copyright (C) 2020-2021 Intel Corporation
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

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sgx_error.h>
#include <sgx_eid.h>
#include <sgx_urts.h>

#include "enclave_hsm_u.h"
#include "ehsm_provider.h"
#include "sgx_ukey_exchange.h"
#include "sgx_dcap_ql_wrapper.h"


void ocall_print_string(const char *str)
{
    printf("%s", str);
}

namespace EHsmProvider
{

sgx_ra_context_t g_context = INT_MAX;

sgx_enclave_id_t g_enclave_id;

static ehsm_status_t SetupSecureChannel(sgx_enclave_id_t eid)
{
    uint32_t sgxStatus;
    sgx_status_t ret;

    // create ECDH session using initiator enclave, it would create ECDH session with responder enclave running in another process
    ret = enclave_la_create_session(eid, &sgxStatus);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS) {
        printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", ret, sgxStatus);
        return EH_LA_SETUP_ERROR;
    }
    printf("succeed to establish secure channel.\n");

    // Test message exchange between initiator enclave and responder enclave running in another process
    ret = enclave_la_message_exchange(eid, &sgxStatus);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS) {
        printf("test_message_exchange Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", ret, sgxStatus);
        return EH_LA_EXCHANGE_MSG_ERROR;
    }
    printf("Succeed to exchange secure message...\n");

    // close ECDH session
    ret = enclave_la_close_session(eid, &sgxStatus);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS) {
        printf("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", ret, sgxStatus);
        return EH_LA_CLOSE_ERROR;
    }
    printf("Succeed to close Session...\n");

    return EH_OK;
}

ehsm_status_t Initialize()
{
    ehsm_status_t rc = EH_OK;
    sgx_status_t sgxStatus;
    sgx_status_t ret;

    ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                             SGX_DEBUG_FLAG,
                             NULL,
                             NULL,
                             &g_enclave_id, NULL);
    if(ret != SGX_SUCCESS) {
        printf("failed(%d) to create enclave.\n", ret);
        return EH_DEVICE_ERROR;
    }

    rc = SetupSecureChannel(g_enclave_id);
    if (rc != EH_OK) {
#if EHSM_DEFAULT_DOMAIN_KEY_FALLBACK
        printf("failed(%d) to setup secure channel, but continue to use the default domainkey...\n", rc);
        return EH_OK;
#endif
        printf("failed(%d) to setup secure channel\n", rc);
        sgx_destroy_enclave(g_enclave_id);
    }

    return rc;
}

void Finalize()
{
    sgx_destroy_enclave(g_enclave_id);
}
ehsm_status_t CreateKey(ehsm_keyblob_t *cmk)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY) {
        return EH_ARGUMENTS_BAD;
    }

    switch (cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
            if (cmk->keybloblen == 0) {
                ret = enclave_create_aes_key(g_enclave_id,
                                         &sgxStatus,
                                         NULL,
                                         0,
                                         &(cmk->keybloblen));
            } else {
                ret = enclave_create_aes_key(g_enclave_id,
                                         &sgxStatus,
                                         cmk->keyblob,
                                         cmk->keybloblen,
                                         NULL);
            }
            break;
        case EH_RSA_3072:
            if (cmk->keybloblen == 0)
                ret  = enclave_create_rsa_key(g_enclave_id,
                                         &sgxStatus,
                                         NULL,
                                         0,
                                         &(cmk->keybloblen));
            else
                ret  = enclave_create_rsa_key(g_enclave_id,
                                         &sgxStatus,
                                         cmk->keyblob,
                                         cmk->keybloblen,
                                         NULL);
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t Encrypt(ehsm_keyblob_t *cmk,
            ehsm_data_t *plaintext,
            ehsm_data_t *aad,
            ehsm_data_t *ciphertext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || plaintext == NULL || ciphertext == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_SM4) {
        return EH_KEYSPEC_INVALID;
    }

    /* only support to directly encrypt data of less than 6 KB */
    if (plaintext->data == NULL || plaintext->datalen == 0 ||
        plaintext->datalen > EH_ENCRYPT_MAX_SIZE) {
        return EH_ARGUMENTS_BAD;
    }

    switch(cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
            /* calculate the ciphertext length */
            if (ciphertext->datalen == 0) {
                ciphertext->datalen = plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE;
                return EH_OK;
            }
            /* check if the datalen is valid */
            if (ciphertext->data == NULL ||
                ciphertext->datalen != plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
                return EH_ARGUMENTS_BAD;

            if ((0 != aad->datalen) && (NULL == aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            if ((0 == aad->datalen) && (NULL != aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            ret = enclave_aes_encrypt(g_enclave_id,
                                  &sgxStatus,
                                  aad->data,
                                  aad->datalen,
                                  cmk->keyblob,
                                  cmk->keybloblen,
                                  plaintext->data,
                                  plaintext->datalen,
                                  ciphertext->data,
                                  ciphertext->datalen);
            break;
        case EH_SM4:
            //TODO
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t AsymmetricEncrypt(ehsm_keyblob_t *cmk,
        ehsm_data_t *plaintext,
        ehsm_data_t *ciphertext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || plaintext == NULL || ciphertext == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* this api only support for asymmetric keys */
    if (cmk->metadata.keyspec != EH_RSA_2048 &&
        cmk->metadata.keyspec != EH_RSA_3072 &&
        cmk->metadata.keyspec != EH_EC_P256 &&
        cmk->metadata.keyspec != EH_EC_P512 &&
        cmk->metadata.keyspec != EH_EC_SM2) {
        return EH_KEYSPEC_INVALID;
    }

    if (plaintext->data == NULL || plaintext->datalen == 0)
        return EH_ARGUMENTS_BAD;

    switch(cmk->metadata.keyspec) {
        case EH_RSA_2048:
            //TODO
            break;
        case EH_RSA_3072:
            if(plaintext->datalen > RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE) {
                printf("Error data len(%d) for rsa encryption, max is 318.\n", plaintext->datalen);
                return EH_ARGUMENTS_BAD;
            }
            /* calculate the ciphertext length  */
            if (ciphertext->datalen == 0) {
                ciphertext->datalen = RSA_OAEP_3072_CIPHER_LENGTH;
                return EH_OK;
            }
            /* check if the datalen is valid */
            if (ciphertext->data == NULL || ciphertext->datalen != RSA_OAEP_3072_CIPHER_LENGTH)
                return EH_ARGUMENTS_BAD;
            ret = enclave_rsa_encrypt(g_enclave_id,
                                  &sgxStatus,
                                  cmk->keyblob,
                                  cmk->keybloblen,
                                  plaintext->data,
                                  plaintext->datalen,
                                  ciphertext->data,
                                  ciphertext->datalen);
            break;
        case EH_EC_P256:
            //TODO
            break;
        case EH_EC_P512:
            //TODO
            break;
        case EH_EC_SM2:
            //TODO
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t Decrypt(ehsm_keyblob_t *cmk,
            ehsm_data_t *ciphertext,
            ehsm_data_t *aad,
            ehsm_data_t *plaintext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || plaintext == NULL || ciphertext == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_SM4) {
        return EH_KEYSPEC_INVALID;
    }

    if (ciphertext->data == NULL || ciphertext->datalen == 0) {
        return EH_ARGUMENTS_BAD;
    }

    switch(cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
            /* calculate the ciphertext length */
            if (plaintext->datalen == 0) {
                plaintext->datalen = ciphertext->datalen - EH_AES_GCM_IV_SIZE - EH_AES_GCM_MAC_SIZE;
                return EH_OK;
            }
            /* check if the datalen is valid */
            if (plaintext->data == NULL ||
                plaintext->datalen != ciphertext->datalen - EH_AES_GCM_IV_SIZE - EH_AES_GCM_MAC_SIZE)
                return EH_ARGUMENTS_BAD;

            if ((0 != aad->datalen) && (NULL == aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            if ((0 == aad->datalen) && (NULL != aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            ret = enclave_aes_decrypt(g_enclave_id,
                                  &sgxStatus,
                                  aad->data,
                                  aad->datalen,
                                  cmk->keyblob,
                                  cmk->keybloblen,
                                  ciphertext->data,
                                  ciphertext->datalen,
                                  plaintext->data,
                                  plaintext->datalen);
            break;
        case EH_SM4:
            //TODO
            break;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t AsymmetricDecrypt(ehsm_keyblob_t *cmk,
            ehsm_data_t *ciphertext,
            ehsm_data_t *plaintext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || plaintext == NULL || ciphertext == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* this api only support for asymmetric keys */
    if (cmk->metadata.keyspec != EH_RSA_2048 &&
        cmk->metadata.keyspec != EH_RSA_3072 &&
        cmk->metadata.keyspec != EH_EC_P256 &&
        cmk->metadata.keyspec != EH_EC_P512 &&
        cmk->metadata.keyspec != EH_EC_SM2) {
        return EH_KEYSPEC_INVALID;
    }

    switch(cmk->metadata.keyspec) {
        case EH_RSA_2048:
            //TODO
            return EH_OK;
        case EH_RSA_3072:
            if (ciphertext->data == NULL || ciphertext->datalen == 0 ||
                ciphertext->datalen > RSA_OAEP_3072_CIPHER_LENGTH) {
                return EH_ARGUMENTS_BAD;
            }
            /* calculate the ciphertext length */
            if (plaintext->datalen == 0) {
                ret = enclave_rsa_decrypt(g_enclave_id,
                                  &sgxStatus,
                                  cmk->keyblob,
                                  cmk->keybloblen,
                                  ciphertext->data,
                                  ciphertext->datalen,
                                  NULL, 0,
                                  &(plaintext->datalen));
                return EH_OK;
            }
            /* check if the datalen is valid */
            if (plaintext->data == NULL || plaintext->datalen == 0)
                return EH_ARGUMENTS_BAD;
            ret = enclave_rsa_decrypt(g_enclave_id,
                                  &sgxStatus,
                                  cmk->keyblob,
                                  cmk->keybloblen,
                                  ciphertext->data,
                                  ciphertext->datalen,
                                  plaintext->data,
                                  plaintext->datalen,
                                  NULL);
        case EH_EC_P256:
            //TODO
            return EH_OK;
        case EH_EC_P512:
            //TODO
            return EH_OK;
        case EH_EC_SM2:
            //TODO
            return EH_OK;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t Sign(ehsm_keyblob_t *cmk,
           ehsm_data_t *digest,
           ehsm_data_t *signature)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || digest == NULL || signature == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* this api only support for asymmetric keys */
    if (cmk->metadata.keyspec != EH_RSA_2048 &&
        cmk->metadata.keyspec != EH_RSA_3072 &&
        cmk->metadata.keyspec != EH_EC_P256 &&
        cmk->metadata.keyspec != EH_EC_P512 &&
        cmk->metadata.keyspec != EH_EC_SM2) {
        return EH_KEYSPEC_INVALID;
    }

    switch(cmk->metadata.keyspec) {
        case EH_RSA_2048:
            //TODO
            return EH_OK;
        case EH_RSA_3072:
            if (digest->datalen > RSA_OAEP_3072_DIGEST_SIZE) {
                printf("rsa 3072 sign requires a <=256B digest.\n");
                return EH_ARGUMENTS_BAD;
            }

            /* calculate the signature length */
            if (signature->datalen == 0) {
                signature->datalen = RSA_OAEP_3072_SIGNATURE_SIZE;
                return EH_OK;
            }
            /* check if the datalen is valid */
            if (signature->data == NULL || signature->datalen != RSA_OAEP_3072_SIGNATURE_SIZE)
                return EH_ARGUMENTS_BAD;

            ret = enclave_rsa_sign(g_enclave_id,
                               &sgxStatus,
                               cmk->keyblob,
                               cmk->keybloblen,
                               digest->data,
                               digest->datalen,
                               signature->data,
                               signature->datalen);
        case EH_EC_P256:
            //TODO
            return EH_OK;
        case EH_EC_P512:
            //TODO
            return EH_OK;
        case EH_EC_SM2:
            //TODO
            return EH_OK;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t Verify(ehsm_keyblob_t *cmk,
                 ehsm_data_t *digest,
                 ehsm_data_t *signature,
                 bool* result)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || digest == NULL || signature == NULL || result == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* this api only support for asymmetric keys */
    if (cmk->metadata.keyspec != EH_RSA_2048 &&
        cmk->metadata.keyspec != EH_RSA_3072 &&
        cmk->metadata.keyspec != EH_EC_P256 &&
        cmk->metadata.keyspec != EH_EC_P512 &&
        cmk->metadata.keyspec != EH_EC_SM2) {
        return EH_KEYSPEC_INVALID;
    }

    switch(cmk->metadata.keyspec) {
        case EH_RSA_2048:
            //TODO
            return EH_OK;
        case EH_RSA_3072:
            if (signature->data == NULL || signature->datalen != RSA_OAEP_3072_SIGNATURE_SIZE)
                return EH_ARGUMENTS_BAD;
            if (digest->data == NULL || digest->datalen > RSA_OAEP_3072_DIGEST_SIZE)
                return EH_ARGUMENTS_BAD;
            ret = enclave_rsa_verify(g_enclave_id,
                                 &sgxStatus,
                                 cmk->keyblob,
                                 cmk->keybloblen,
                                 digest->data,
                                 digest->datalen,
                                 signature->data,
                                 signature->datalen,
                                 result);

            break;
        case EH_EC_P256:
            //TODO
            return EH_OK;
        case EH_EC_P512:
            //TODO
            return EH_OK;
        case EH_EC_SM2:
            //TODO
            return EH_OK;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t GenerateDataKey(ehsm_keyblob_t *cmk,
            ehsm_data_t *aad,
            ehsm_data_t *plaintext,
            ehsm_data_t *ciphertext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || plaintext == NULL || ciphertext == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_SM4) {
        return EH_KEYSPEC_INVALID;
    }

    /* the datakey length should be 1~1024 and the data buffer should not be NULL */
    if (plaintext->data == NULL ||
        plaintext->datalen == 0 ||
        plaintext->datalen > EH_DATA_KEY_MAX_SIZE) {
        return EH_ARGUMENTS_BAD;
    }

    switch(cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
            /* calculate the ciphertext length */
            if (ciphertext->datalen == 0) {
                ciphertext->datalen = plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE;
                return EH_OK;
            }
            /* check if the datalen is valid */
            if (ciphertext->data == NULL ||
                ciphertext->datalen != plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE) {
                return EH_ARGUMENTS_BAD;
            }

            if ((0 != aad->datalen) && (NULL == aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            if ((0 == aad->datalen) && (NULL != aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            ret = enclave_generate_datakey(g_enclave_id,
                                   &sgxStatus,
                                   cmk->metadata.keyspec,
                                   cmk->keyblob,
                                   cmk->keybloblen,
                                   aad->data,
                                   aad->datalen,
                                   plaintext->data,
                                   plaintext->datalen,
                                   ciphertext->data,
                                   ciphertext->datalen);
            break;
        case EH_SM4:
            //TODO
            return EH_OK;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t GenerateDataKeyWithoutPlaintext(ehsm_keyblob_t *cmk,
        ehsm_data_t *aad,
        ehsm_data_t *plaintext,
        ehsm_data_t *ciphertext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || plaintext == NULL || ciphertext == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* this api only support for symmetric keys */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_SM4) {
        return EH_KEYSPEC_INVALID;
    }

    /* the datakey length should be 1~1024 and the data buffer should be NULL */
    if (plaintext->data != NULL ||
        plaintext->datalen == 0 ||
        plaintext->datalen > EH_DATA_KEY_MAX_SIZE) {
        return EH_ARGUMENTS_BAD;
    }

    switch(cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
            /* calculate the ciphertext length */
            if (ciphertext->datalen == 0) {
                ciphertext->datalen = plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE;
                return EH_OK;
            }
            /* check if the datalen is valid */
            if (ciphertext->data == NULL ||
                ciphertext->datalen != plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE)
                return EH_ARGUMENTS_BAD;

            if ((0 != aad->datalen) && (NULL == aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            if ((0 == aad->datalen) && (NULL != aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            ret = enclave_generate_datakey(g_enclave_id,
                                   &sgxStatus,
                                   cmk->metadata.keyspec,
                                   cmk->keyblob,
                                   cmk->keybloblen,
                                   aad->data,
                                   aad->datalen,
                                   NULL,
                                   plaintext->datalen,
                                   ciphertext->data,
                                   ciphertext->datalen);
            break;
        case EH_SM4:
            //TODO
            return EH_OK;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;

}

ehsm_status_t ExportDataKey(ehsm_keyblob_t *cmk,
            ehsm_keyblob_t *ukey,
            ehsm_data_t *aad,
            ehsm_data_t *olddatakey,
            ehsm_data_t *newdatakey)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL || cmk->metadata.origin != EH_INTERNAL_KEY
        || ukey == NULL || olddatakey == NULL || newdatakey == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    /* cmk should be symmetric key and the ukey should be an asymmetric key */
    if (cmk->metadata.keyspec != EH_AES_GCM_128 &&
        cmk->metadata.keyspec != EH_SM4 &&
        ukey->metadata.keyspec != EH_RSA_2048 &&
        ukey->metadata.keyspec != EH_RSA_3072 &&
        ukey->metadata.keyspec != EH_EC_P256 &&
        ukey->metadata.keyspec != EH_EC_P512 &&
        ukey->metadata.keyspec != EH_EC_SM2) {
        return EH_KEYSPEC_INVALID;
    }

    if (olddatakey->data == NULL ||
        olddatakey->datalen >1024 || olddatakey->datalen == 0)
        return EH_ARGUMENTS_BAD;

    switch(ukey->metadata.keyspec) {
        case EH_RSA_2048:
            //TODO
            return EH_OK;
        case EH_RSA_3072:
            if(olddatakey->datalen > RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE) {
                return EH_ARGUMENTS_BAD;
            }
            /* calculate the newdatakey length */
            if (newdatakey->datalen == 0) {
                newdatakey->datalen = RSA_OAEP_3072_CIPHER_LENGTH;
                return EH_OK;
            }
            /* check if the datalen is valid */
            if (newdatakey->data == NULL ||
                newdatakey->datalen != RSA_OAEP_3072_CIPHER_LENGTH){
                return EH_ARGUMENTS_BAD;
            }

            if ((0 != aad->datalen) && (NULL == aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            if ((0 == aad->datalen) && (NULL != aad->data)) {
                return EH_ARGUMENTS_BAD;
            }

            ret = enclave_export_datakey(g_enclave_id,
                           &sgxStatus,
                           cmk->metadata.keyspec,
                           cmk->keyblob,
                           cmk->keybloblen,
                           aad->data,
                           aad->datalen,
                           olddatakey->data,
                           olddatakey->datalen,
                           ukey->metadata.keyspec,
                           ukey->keyblob,
                           ukey->keybloblen,
                           newdatakey->data,
                           newdatakey->datalen);
            break;
        case EH_EC_P256:
            //TODO
            return EH_OK;
        case EH_EC_P512:
            //TODO
            return EH_OK;
        case EH_EC_SM2:
            //TODO
            return EH_OK;
        default:
            return EH_KEYSPEC_INVALID;
    }

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t generate_apikey(ehsm_data_t *apikey)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // create apikey
    if (apikey == NULL || apikey->datalen != EH_API_KEY_SIZE) {
        return EH_ARGUMENTS_BAD;
    }
    ret = enclave_generate_apikey(g_enclave_id,
                            &sgxStatus,
                            apikey->data,
                            apikey->datalen);
    
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS){
        printf("error: generate apikey faild (%d)(%d).\n", ret, sgxStatus);
        return EH_FUNCTION_FAILED;
    }
    else
    {
        return EH_OK;
    }
}

ehsm_status_t ra_get_msg1(sgx_ra_msg1_t *msg1)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (msg1 == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    //initialize the ra session
    sgx_status_t sgxStatus = SGX_SUCCESS;
    int enclave_lost_retry_time = 1;
    do {
        ret = enclave_init_ra(g_enclave_id, &sgxStatus, false, &g_context);
        //Ideally, this check would be around the full attestation flow.
    } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

    if(SGX_SUCCESS != ret || sgxStatus){
        printf("Error, call enclave_init_ra fail [%s].\n", __FUNCTION__);
       return EH_FUNCTION_FAILED;
    }
    printf("Call enclave_init_ra success.\n");

    //get the msg1 from core-enclave 
    sgx_att_key_id_t selected_key_id = {0};
    ret = sgx_ra_get_msg1_ex(&selected_key_id, g_context, g_enclave_id, sgx_ra_get_ga, msg1);
    if(SGX_SUCCESS != ret) {
        printf("Error, call sgx_ra_get_msg1_ex failed(%#x)\n", ret);
        return EH_FUNCTION_FAILED;
    }
    return EH_OK;
}

}
