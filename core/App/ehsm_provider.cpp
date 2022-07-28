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
#include <uuid/uuid.h>
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

#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"

#include "log_utils.h"

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
        case EH_AES_GCM_256:
            if (cmk->keybloblen == 0) {
                ret = enclave_create_aes_key(g_enclave_id,
                                             &sgxStatus,
                                             NULL,
                                             0,
                                             &(cmk->keybloblen),
                                             (ehsm_keyspec_t)cmk->metadata.keyspec);
            } else {
                ret = enclave_create_aes_key(g_enclave_id,
                                             &sgxStatus,
                                             cmk->keyblob,
                                             cmk->keybloblen,
                                             NULL,
                                             (ehsm_keyspec_t)cmk->metadata.keyspec);
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
        cmk->metadata.keyspec != EH_AES_GCM_256 &&
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
        case EH_AES_GCM_256:
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
                                      ciphertext->datalen,
                                      (ehsm_keyspec_t)cmk->metadata.keyspec);
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
        cmk->metadata.keyspec != EH_AES_GCM_256 &&
        cmk->metadata.keyspec != EH_SM4) {
        return EH_KEYSPEC_INVALID;
    }

    if (ciphertext->data == NULL || ciphertext->datalen == 0) {
        return EH_ARGUMENTS_BAD;
    }

    switch(cmk->metadata.keyspec) {
        case EH_AES_GCM_128:
        case EH_AES_GCM_256:
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
                                      plaintext->datalen,
                                      (ehsm_keyspec_t)cmk->metadata.keyspec);
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

ehsm_status_t Enroll(ehsm_data_t *appid, ehsm_data_t *apikey)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (appid == NULL || appid->datalen != UUID_STR_LEN) {
        return EH_ARGUMENTS_BAD;
    }

    if (apikey == NULL || apikey->datalen != EH_API_KEY_SIZE) {
        return EH_ARGUMENTS_BAD;
    }

    // create appid
    uuid_t uu;
    uuid_generate(uu);
    uuid_unparse(uu, (char*)appid->data);

    ret = enclave_get_apikey(g_enclave_id,
                            &sgxStatus,
                            apikey->data,
                            apikey->datalen);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t generate_apikey(ehsm_data_t *apikey, ehsm_data_t *cipherapikey)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (apikey == NULL || apikey->datalen > EH_API_KEY_SIZE) {
        return EH_ARGUMENTS_BAD;
    }
    if (cipherapikey == NULL || cipherapikey->datalen < EH_API_KEY_SIZE + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE) {
        return EH_ARGUMENTS_BAD;
    }

    ret = enclave_generate_apikey(g_enclave_id,
                            &sgxStatus,
                            g_context,
                            apikey->data,
                            apikey->datalen,
                            cipherapikey->data,
                            cipherapikey->datalen);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS){
        printf("error: generate apikey faild (%d)(%d).\n", ret, sgxStatus);
        return EH_FUNCTION_FAILED;
    }
    else
    {
        return EH_OK;
    }
}

ehsm_status_t GenerateQuote(ehsm_data_t *quote)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t dcap_ret = SGX_QL_SUCCESS;

    uint32_t quote_size = 0;
    sgx_target_info_t qe_target_info;
    sgx_report_t app_report;

    if (quote == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    dcap_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != dcap_ret) {
        log_e("Error in sgx_qe_get_target_info. 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }
    log_d("sgx_qe_get_target_info successfully returned\n");

    dcap_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != dcap_ret) {
        log_e("Error in sgx_qe_get_quote_size. 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }
    log_d("sgx_qe_get_quote_size successfully returned\n");

    if (quote->datalen == 0) {
        quote->datalen = quote_size;
        return EH_OK;
    }

    if (quote->data == NULL || quote->datalen != quote_size) {
        return EH_ARGUMENTS_BAD;
    }

    ret = enclave_create_report(g_enclave_id,
                    &sgxStatus,
                    &qe_target_info,
                    &app_report);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS){
        log_e("Error in enclave_create_report (%d)(%d).\n", ret, sgxStatus);
        return EH_FUNCTION_FAILED;
    }
    log_d("enclave_create_report successfully returned\n");

    memset(quote->data, 0, quote_size);

    // Get the Quote
    dcap_ret = sgx_qe_get_quote(&app_report,
                            quote->datalen,
                            quote->data);
    if (SGX_QL_SUCCESS != dcap_ret) {
        log_e( "Error in sgx_qe_get_quote. 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }
    log_d("sgx_qe_get_quote successfully returned\n");

    return EH_OK;
}

ehsm_status_t VerifyQuote(ehsm_data_t *quote,
            sgx_ql_qv_result_t *result)
{
    ehsm_status_t rc = EH_OK;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;

    uint32_t collateral_expiration_status = 1;

    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;

    // Threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
    // e.g. You can get latest QvE ISVSVN in QvE Identity JSON file from
    // https://api.trustedservices.intel.com/sgx/certification/v2/qve/identity
    // Make sure you are using trusted & latest QvE ISV SVN as threshold
    sgx_isv_svn_t qve_isvsvn_threshold = 5;

    sgx_ql_qe_report_info_t qve_report_info;
    uint8_t nonce[16] = {0};

    if (quote == NULL || quote->data == NULL) {
        return EH_ARGUMENTS_BAD;
    }

    ret = enclave_get_rand(g_enclave_id,
                    &sgxStatus,
                    nonce, sizeof(nonce));
    if (ret != SGX_SUCCESS) {
        return EH_FUNCTION_FAILED;
    }

    //set nonce
    memcpy(qve_report_info.nonce.rand, nonce, sizeof(nonce));

    ret = enclave_get_target_info(g_enclave_id,
                            &sgxStatus,
                            &qve_report_info.app_enclave_target_info);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS) {
        log_e("Error in sgx_get_target_info (%d)(%d).\n", ret, sgxStatus);
        return EH_FUNCTION_FAILED;
    }

    log_d("get target info successfully returned.\n");

    //call DCAP quote verify library to set QvE loading policy
    dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    if (dcap_ret != SGX_QL_SUCCESS) {
        log_e("Error in sgx_qv_set_enclave_load_policy failed: 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }

    log_d("sgx_qv_set_enclave_load_policy successfully returned.\n");

    //call DCAP quote verify library to get supplemental data size
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret != SGX_QL_SUCCESS) {
        log_e("Error in sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }

    log_d("sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
    p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    if (p_supplemental_data == NULL) {
        rc = EH_DEVICE_MEMORY;
        goto out;
    }

    //set current time. This is only for sample use, please use trusted time in product.
    current_time = time(NULL);

    //call DCAP quote verify library for quote verification with Intel QvE.
    dcap_ret = sgx_qv_verify_quote(
                                quote->data,
                                quote->datalen,
                                NULL,
                                current_time,
                                &collateral_expiration_status,
                                &quote_verification_result,
                                &qve_report_info,
                                supplemental_data_size,
                                p_supplemental_data);
    if (dcap_ret != SGX_QL_SUCCESS) {
        log_e("Error in sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
        rc = EH_FUNCTION_FAILED;
        goto out;
    }

    log_d("sgx_qv_verify_quote successfully returned\n");

    //call sgx_dcap_tvl API in SampleISVEnclave to verify QvE's report and identity
    ret = sgx_tvl_verify_qve_report_and_identity(g_enclave_id,
                                                &dcap_ret,
                                                quote->data,
                                                quote->datalen,
                                                &qve_report_info,
                                                current_time,
                                                collateral_expiration_status,
                                                quote_verification_result,
                                                p_supplemental_data,
                                                supplemental_data_size,
                                                qve_isvsvn_threshold);
    if (ret != SGX_SUCCESS || dcap_ret != SGX_QL_SUCCESS) {
        log_e("Error in Verify QvE report and identity failed. 0x%04x\n", dcap_ret);
        rc = EH_FUNCTION_FAILED;
        goto out;
    }

    log_d("Verify QvE report and identity successfully returned.\n");

    //check verification result
    switch (quote_verification_result)
    {
        case SGX_QL_QV_RESULT_OK:
            //check verification collateral expiration status
            //this value should be considered in your own attestation/verification policy
            if (collateral_expiration_status == 0) {
                printf("\tInfo: App: Verification completed successfully.\n");
            }
            else {
                printf("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.\n");
            }

            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            printf("\tWarning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            printf("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
            break;
    }

out:
    *result = quote_verification_result;

    SAFE_FREE(p_supplemental_data);
    return rc;
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

    //get the msg1 from core-enclave 
    sgx_att_key_id_t selected_key_id = {0};
    ret = sgx_ra_get_msg1_ex(&selected_key_id, g_context, g_enclave_id, sgx_ra_get_ga, msg1);
    if(SGX_SUCCESS != ret) {
        printf("Error, call sgx_ra_get_msg1_ex failed(%#x)\n", ret);
        return EH_FUNCTION_FAILED;
    }
    return EH_OK;
}

ehsm_status_t ra_get_msg3(sgx_ra_msg2_t *p_msg2, uint32_t msg2_size, sgx_ra_msg3_t **pp_msg3, uint32_t pp_msg3_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int enclave_lost_retry_time = 1;
    
    if (p_msg2 == nullptr || !msg2_size || pp_msg3 == NULL || !pp_msg3_size) {
        return EH_ARGUMENTS_BAD;
    }
    /* Call lib key_u(t)exchange(sgx_ra_proc_msg2_ex) to process the MSG2 and retrieve MSG3 back. */
    // p_msg2 = (sgx_ra_msg2_t*)((uint8_t*)msg2_full + sizeof(ra_ehsm_response_header_t));
    //process the msg2 and get the msg3 from core-enclave
    sgx_att_key_id_t selected_key_id = {0};
    
    uint32_t p_msg3_size = 0;
    sgx_ra_msg3_t *p_msg3 = NULL;
    p_msg3 = (sgx_ra_msg3_t *)malloc(pp_msg3_size);
    if(!p_msg3)
    {
        return EH_FUNCTION_FAILED;
    }
    do
    {
        ret = sgx_ra_proc_msg2_ex(&selected_key_id,
                           g_context,
                           g_enclave_id,
                           sgx_ra_proc_msg2_trusted,
                           sgx_ra_get_msg3_trusted,
                           p_msg2,
                           msg2_size,
                           &p_msg3,
                           &p_msg3_size);
    } while (SGX_ERROR_BUSY == ret && enclave_lost_retry_time--);

    if(!p_msg3)
    {
        printf("Error, call sgx_ra_proc_msg2_ex failed(0x%#x) p_msg3 = 0x%p\n", ret, p_msg3);
        return EH_FUNCTION_FAILED;
    }
    if(SGX_SUCCESS != (sgx_status_t)ret)
    {
        printf("Error, call sgx_ra_proc_msg2_ex failed(0x%#x)\n", ret);
        return EH_FUNCTION_FAILED;
    }

    *pp_msg3 = p_msg3;

    return EH_OK;
}

ehsm_status_t verify_att_result_msg(sample_ra_att_result_msg_t *p_att_result_msg)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    if (p_att_result_msg == NULL) {
        return EH_ARGUMENTS_BAD;
    }
    
    /*
    * Check the MAC using MK on the attestation result message.
    * The format of the attestation result message is specific(sample_ra_att_result_msg_t).
    */
    ret = enclave_verify_att_result_mac(g_enclave_id,
            &sgxStatus,
            g_context,
            (uint8_t*)&p_att_result_msg->platform_info_blob,
            sizeof(ias_platform_info_blob_t),
            (uint8_t*)&p_att_result_msg->mac,
            sizeof(sgx_mac_t));
    if((SGX_SUCCESS != ret) || (SGX_SUCCESS != sgxStatus)) {
        printf("Error: Attestation result MSG's MK based cmac check failed\n");
        return EH_FUNCTION_FAILED;
    }
    return EH_OK; 
}

}
