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
#include <iostream>
#include <fstream>
#include <sys/stat.h>

#include "enclave_hsm_u.h"
#include "ehsm_provider.h"
#include "sgx_ukey_exchange.h"
#include "sgx_dcap_ql_wrapper.h"

#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"

#include "auto_version.h"
#include "ulog_utils.h"
#include "json_utils.h"
#include "ffi_operation.h"

#include "openssl/rsa.h"
#include "openssl/evp.h"

using namespace std;

#define DKEY_FILE_NAME (std::string(EHSM_LOCAL_DATA_FOLDER) + "single_test_dkey.bin").c_str()

void ocall_print_string(uint32_t log_level, const char *str, const char *filename, uint32_t line)
{
    switch (log_level)
    {
    case LOG_INFO:
    case LOG_DEBUG:
    case LOG_ERROR:
    case LOG_WARN:
        log_c(log_level, str, filename, line);
        break;
    default:
        log_c(LOG_ERROR, "log system error in ocall print.\n", filename, line);
        break;
    }
}

errno_t memcpy_s(
    void *dest,
    size_t numberOfElements,
    const void *src,
    size_t count)
{
    if (numberOfElements < count)
        return -1;
    memcpy(dest, src, count);
    return 0;
}

sgx_ra_context_t g_context = INT_MAX;

sgx_enclave_id_t g_enclave_id;

static ehsm_status_t SetupSecureChannel(sgx_enclave_id_t eid)
{
    uint32_t sgxStatus;
    sgx_status_t ret;

    // create ECDH session using initiator enclave, it would create ECDH session with responder enclave running in another process
    ret = enclave_la_create_session(eid, &sgxStatus);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
    {
        log_e("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", ret, sgxStatus);
        return EH_LA_SETUP_ERROR;
    }
    log_i("succeed to establish secure channel.\n");

    // Test message exchange between initiator enclave and responder enclave running in another process
    ret = enclave_la_message_exchange(eid, &sgxStatus);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
    {
        log_e("test_message_exchange Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", ret, sgxStatus);
        return EH_LA_EXCHANGE_MSG_ERROR;
    }
    log_i("Succeed to exchange secure message...\n");

    // close ECDH session
    ret = enclave_la_close_session(eid, &sgxStatus);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
    {
        log_e("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", ret, sgxStatus);
        return EH_LA_CLOSE_ERROR;
    }
    log_i("Succeed to close Session...\n");

    return EH_OK;
}

static bool validate_params(const ehsm_keyblob_t *data, size_t max_size, bool required = true)
{
    if (required)
    {
        if (data != NULL && data->keybloblen <= max_size)
            return true;

        return false;
    }
    else
    {
        if (data != NULL && data->keybloblen > max_size)
            return false;

        return true;
    }
}

static bool validate_params(const ehsm_data_t *data, size_t max_size, bool required = true)
{
    if (required)
    {
        if (data != NULL && data->datalen > 0 && data->datalen <= max_size)
            return true;

        return false;
    }
    else
    {
        if (data != NULL && data->datalen > max_size)
            return false;

        return true;
    }
}

static bool validate_params(const char *data, size_t max_size, bool required = true)
{
    if (required)
    {
        if (data != NULL && strlen(data) > 0 && strlen(data) <= max_size)
            return true;

        return false;
    }
    else
    {
        if (data != NULL && strlen(data) > max_size)
            return false;

        return true;
    }
}

/**
 * @brief The unique ffi entry for the ehsm provider libaray.
 *
 * @param reqJson the request parameters in the form of JSON string
 * [string] json string
    {
        action: int
        payload: {
            [additional parameter]
        }
    }
 *
 * @param respJson response in json string
    {
        code: int,
        message: string,
        result: {
            xxx : xxx
        }
    }
 */
uint32_t EHSM_FFI_CALL(const char *reqJson, char *respJson)
{
    ehsm_status_t ret = EH_OK;
    RetJsonObj retJsonObj;
    uint32_t action = -1;
    JsonObj payloadJson;
    if (respJson == NULL)
    {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Argument bad.");
        retJsonObj.toChar(respJson);
        return EH_ARGUMENTS_BAD;
    }
    if (!validate_params(reqJson, EH_PAYLOAD_MAX_SIZE))
    {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Argument bad.");
        retJsonObj.toChar(respJson);
        return EH_ARGUMENTS_BAD;
    }
    // parse reqJson into reqJsonObj
    JsonObj reqJsonObj;
    if (!reqJsonObj.parse(reqJson))
    {
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("Server exception.");
        retJsonObj.toChar(respJson);
        return EH_ARGUMENTS_BAD;
    }

    action = reqJsonObj.readData_uint32("action");
    payloadJson.setJson(reqJsonObj.readData_JsonValue("payload"));
    switch (action)
    {
    case EH_INITIALIZE:
        ffi_initialize(payloadJson, respJson);
        break;
    case EH_FINALIZE:
        ffi_finalize(respJson);
        break;
    case EH_CREATE_KEY:
        ffi_createKey(payloadJson, respJson);
        break;
    case EH_ENCRYPT:
        ffi_encrypt(payloadJson, respJson);
        break;
    case EH_DECRYPT:
        ffi_decrypt(payloadJson, respJson);
        break;
    case EH_ASYMMETRIC_ENCRYPT:
        ffi_asymmetricEncrypt(payloadJson, respJson);
        break;
    case EH_ASYMMETRIC_DECRYPT:
        ffi_asymmetricDecrypt(payloadJson, respJson);
        break;
    case EH_SIGN:
        ffi_sign(payloadJson, respJson);
        break;
    case EH_VERIFY:
        ffi_verify(payloadJson, respJson);
        break;
    case EH_GENERATE_DATAKEY:
        ffi_generateDataKey(payloadJson, respJson);
        break;
    case EH_GENERATE_DATAKEY_WITHOUT_PLAINTEXT:
        ffi_generateDataKeyWithoutPlaintext(payloadJson, respJson);
        break;
    case EH_EXPORT_DATAKEY:
        ffi_exportDataKey(payloadJson, respJson);
        break;
    case EH_GET_PUBLIC_KEY:
        ffi_getPublicKey(payloadJson, respJson);
        break;
    case EH_GET_VERSION:
        ffi_getVersion(respJson);
        break;
    case EH_ENROLL:
        ffi_enroll(respJson);
        break;
    case EH_GENERATE_QUOTE:
        ffi_generateQuote(payloadJson, respJson);
        break;
    case EH_VERIFY_QUOTE:
        ffi_verifyQuote(payloadJson, respJson);
        break;
    case EH_GEN_HMAC:
        ffi_generateHmac(payloadJson, respJson);
        break;
    case EH_GEN_TOKEN_HMAC:
        ffi_generateTokenHmac(payloadJson, respJson);
        break;
    case EH_IMPORT_KEY_MATERIAL:
        ffi_importKeyMaterial(payloadJson, respJson);
        break;
    case EH_GET_PARAMETERS_FOR_IMPORT:
        ffi_getParametersForImport(payloadJson, respJson);
        break;
    default:
        RetJsonObj retJsonObj;
        retJsonObj.setCode(retJsonObj.CODE_FAILED);
        retJsonObj.setMessage("action not find.");
        retJsonObj.toChar(respJson);
        break;
    }
    return ret;
}

static inline bool file_exists(const std::string &name)
{
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

int ocall_read_domain_key(uint8_t *cipher_dk, uint32_t cipher_dk_len)
{
    if (!file_exists(DKEY_FILE_NAME))
    {
        log_d("ocall_read_domain_key file does not exist.\n");
        return -2;
    }

    fstream file;
    file.open(DKEY_FILE_NAME, ios::in | ios::binary);
    if (!file)
    {
        log_d("Failed to open file...\n");
        return -1;
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);
    if (size != cipher_dk_len)
    {
        log_d("mismatched length: %ld:%d.\n", size, cipher_dk_len);
        return -1;
    }

    uint8_t tmp[size] = {0};
    if (file.read((char *)&tmp, size))
    {
        memcpy(cipher_dk, tmp, cipher_dk_len);
    }
    else
    {
        log_d("Failed to read data from file...\n");
        return -1;
    }

    file.close();

    return 0;
}

int ocall_store_domain_key(uint8_t *cipher_dk, uint32_t cipher_dk_len)
{
    uint8_t tmp[cipher_dk_len];
    memcpy(tmp, cipher_dk, cipher_dk_len);

    fstream file;
    file.open(DKEY_FILE_NAME, ios::out | ios::binary | ios::trunc);
    if (!file)
    {
        log_d("Failed to create file...\n");
        return -1;
    }

    file.write((char *)&tmp, cipher_dk_len);
    file.close();

    return 0;
}

ehsm_status_t Initialize(bool run_on_cluter)
{
    if (access(EHSM_RUNTIME_FOLDER, F_OK) != 0)
    {
        if (mkdir(EHSM_RUNTIME_FOLDER, 0755) != 0)
        {
            return EH_FUNCTION_FAILED;
        }
    }
    if (access(EHSM_LOCAL_DATA_FOLDER, F_OK) != 0)
    {
        if (mkdir(EHSM_LOCAL_DATA_FOLDER, 0755) != 0)
        {
            return EH_FUNCTION_FAILED;
        }
    }
    if (access(EHSM_LOGS_FOLDER, F_OK) != 0)
    {
        if (mkdir(EHSM_LOGS_FOLDER, 0755) != 0)
        {
            return EH_FUNCTION_FAILED;
        }
    }
    if (initLogger("core.log") < 0)
        return EH_FUNCTION_FAILED;

    log_i("Service name:\t\teHSM-KMS service %s", EHSM_VERSION);
    log_i("Service built:\t\t%s", EHSM_DATE);
    log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);
    log_i("Runtime folder:\t%s", EHSM_RUNTIME_FOLDER);
    log_i("Local data folder:\t%s", EHSM_LOCAL_DATA_FOLDER);
    log_i("Logs folder:\t%s", EHSM_LOGS_FOLDER);

    ehsm_status_t rc = EH_OK;
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                             SGX_DEBUG_FLAG,
                             NULL,
                             NULL,
                             &g_enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        log_e("failed(%d) to create enclave.\n", ret);
        return EH_DEVICE_ERROR;
    }

    if (run_on_cluter)
    {
        rc = SetupSecureChannel(g_enclave_id);
        if (rc != EH_OK)
        {
            log_e("failed(%d) to setup secure channel\n", rc);
            sgx_destroy_enclave(g_enclave_id);
            return EH_DEVICE_ERROR;
        }
    }
    else
    {
        ret = enclave_get_domain_key_from_local(g_enclave_id, &sgxStatus);
        if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        {
            log_e("failed(%d) to get domain key.\n", ret);
            return EH_DEVICE_ERROR;
        }
    }

#ifdef ENABLE_SELF_TEST
    ret = enclave_self_test(g_enclave_id, &sgxStatus);

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
    {
        return EH_FUNCTION_FAILED;
    }

    log_i("self test pass\n");
#endif

    return rc;
}

ehsm_status_t Finalize()
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    logger_shutDown();

    sgxStatus = sgx_destroy_enclave(g_enclave_id);

    if (sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t CreateKey(ehsm_keyblob_t *cmk)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_create_key(g_enclave_id, &sgxStatus, cmk, APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t GetPublicKey(ehsm_keyblob_t *cmk,
                           ehsm_data_t *pubkey)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* only support to directly encrypt data of less than 6 KB */
    if (!validate_params(cmk, EH_CMK_MAX_SIZE))
        return EH_ARGUMENTS_BAD;

    if (pubkey == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_get_public_key(g_enclave_id,
                                 &sgxStatus,
                                 cmk,
                                 APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                 pubkey,
                                 APPEND_SIZE_TO_DATA_T(pubkey->datalen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t ImportKeyMaterial(ehsm_keyblob_t *cmk, ehsm_padding_mode_t padding_mode, ehsm_data_t *key_material)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* only support to directly encrypt data of less than 6 KB */
    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(key_material, EH_CIPHERTEXT_MAX_SIZE))
        return EH_ARGUMENTS_BAD;

    ret = enclave_import_key_material(g_enclave_id,
                                      &sgxStatus,
                                      cmk,
                                      APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                      padding_mode,
                                      key_material,
                                      APPEND_SIZE_TO_DATA_T(key_material->datalen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t GetParametersForImport(ehsm_keyblob_t *cmk, ehsm_keyspec_t keyspec, ehsm_data_t *pubkey)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (!validate_params(cmk, EH_CMK_MAX_SIZE))
        return EH_ARGUMENTS_BAD;

    if (pubkey == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_get_parameters_for_import(g_enclave_id,
                                            &sgxStatus,
                                            cmk,
                                            APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                            keyspec,
                                            pubkey,
                                            APPEND_SIZE_TO_DATA_T(pubkey->datalen));

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

    /* only support to directly encrypt data of less than 6 KB */
    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(plaintext, EH_PLAINTEXT_MAX_SIZE) ||
        !validate_params(aad, EH_AAD_MAX_SIZE, false))
        return EH_ARGUMENTS_BAD;

    if (ciphertext == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_encrypt(g_enclave_id,
                          &sgxStatus,
                          cmk,
                          APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                          aad,
                          APPEND_SIZE_TO_DATA_T(aad->datalen),
                          plaintext,
                          APPEND_SIZE_TO_DATA_T(plaintext->datalen),
                          ciphertext,
                          APPEND_SIZE_TO_DATA_T(ciphertext->datalen));

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

    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(aad, EH_AAD_MAX_SIZE, false) ||
        !validate_params(ciphertext, EH_PLAINTEXT_MAX_SIZE + EH_AAD_MAX_SIZE))
        return EH_ARGUMENTS_BAD;

    if (plaintext == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_decrypt(g_enclave_id,
                          &sgxStatus,
                          cmk,
                          APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                          aad,
                          APPEND_SIZE_TO_DATA_T(aad->datalen),
                          ciphertext,
                          APPEND_SIZE_TO_DATA_T(ciphertext->datalen),
                          plaintext,
                          APPEND_SIZE_TO_DATA_T(plaintext->datalen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t AsymmetricEncrypt(ehsm_keyblob_t *cmk,
                                ehsm_padding_mode_t padding_mode,
                                ehsm_data_t *plaintext,
                                ehsm_data_t *ciphertext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(plaintext, EH_PLAINTEXT_MAX_SIZE))
        return EH_ARGUMENTS_BAD;

    if (ciphertext == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_asymmetric_encrypt(g_enclave_id,
                                     &sgxStatus,
                                     cmk,
                                     APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                     padding_mode,
                                     plaintext,
                                     APPEND_SIZE_TO_DATA_T(plaintext->datalen),
                                     ciphertext,
                                     APPEND_SIZE_TO_DATA_T(ciphertext->datalen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t AsymmetricDecrypt(ehsm_keyblob_t *cmk,
                                ehsm_padding_mode_t padding_mode,
                                ehsm_data_t *ciphertext,
                                ehsm_data_t *plaintext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(ciphertext, EH_CIPHERTEXT_MAX_SIZE))
        return EH_ARGUMENTS_BAD;

    if (plaintext == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_asymmetric_decrypt(g_enclave_id,
                                     &sgxStatus,
                                     cmk,
                                     APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                     padding_mode,
                                     ciphertext,
                                     APPEND_SIZE_TO_DATA_T(ciphertext->datalen),
                                     plaintext,
                                     APPEND_SIZE_TO_DATA_T(plaintext->datalen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

/**
 * @brief Sign the message and store it in signature
 *
 * @param cmk storage the key metadata and keyblob
 * @param digest message to be signed
 * @param signature generated signature
 * @return ehsm_status_t
 */
ehsm_status_t Sign(ehsm_keyblob_t *cmk,
                   ehsm_digest_mode_t digest_mode,
                   ehsm_padding_mode_t padding_mode,
                   ehsm_message_type_t message_type,
                   ehsm_data_t *message,
                   ehsm_data_t *signature)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(message, MAX_SIGN_DATA_SIZE))
        return EH_ARGUMENTS_BAD;

    if (signature == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_sign(g_enclave_id,
                       &sgxStatus,
                       cmk,
                       APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                       digest_mode,
                       padding_mode,
                       message_type,
                       message,
                       APPEND_SIZE_TO_DATA_T(message->datalen),
                       signature,
                       APPEND_SIZE_TO_DATA_T(signature->datalen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

/**
 * @brief verify the signature is correct
 *
 * @param cmk storage the key metadata and keyblob
 * @param digest message for signature
 * @param signature generated signature
 * @param result Signature match result
 * @return ehsm_status_t
 */
ehsm_status_t Verify(ehsm_keyblob_t *cmk,
                     ehsm_digest_mode_t digest_mode,
                     ehsm_padding_mode_t padding_mode,
                     ehsm_message_type_t message_type,
                     ehsm_data_t *message,
                     ehsm_data_t *signature,
                     bool *result)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // TODO : update size check for digest length
    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(message, MAX_SIGN_DATA_SIZE) ||
        !validate_params(signature, MAX_SIGNATURE_SIZE))
        return EH_ARGUMENTS_BAD;

    ret = enclave_verify(g_enclave_id,
                         &sgxStatus,
                         cmk,
                         APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                         digest_mode,
                         padding_mode,
                         message_type,
                         message,
                         APPEND_SIZE_TO_DATA_T(message->datalen),
                         signature,
                         APPEND_SIZE_TO_DATA_T(signature->datalen),
                         result);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

/**
 * @brief verify the signature is correct
 *
 * @param cmk storage the key metadata and keyblob
 * @param aad additional data
 * @param plaintext data to be encrypted
 * @param ciphertext information of ciphertext
 * @return ehsm_status_t
 */
ehsm_status_t GenerateDataKey(ehsm_keyblob_t *cmk,
                              ehsm_data_t *aad,
                              ehsm_data_t *plaintext,
                              ehsm_data_t *ciphertext)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(aad, EH_AAD_MAX_SIZE, false))
        return EH_ARGUMENTS_BAD;

    if (plaintext == NULL || ciphertext == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_generate_datakey(g_enclave_id,
                                   &sgxStatus,
                                   cmk,
                                   APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                   aad,
                                   APPEND_SIZE_TO_DATA_T(aad->datalen),
                                   plaintext,
                                   APPEND_SIZE_TO_DATA_T(plaintext->datalen),
                                   ciphertext,
                                   APPEND_SIZE_TO_DATA_T(ciphertext->datalen));
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

    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(aad, EH_AAD_MAX_SIZE, false))
        return EH_ARGUMENTS_BAD;

    if (plaintext == NULL || ciphertext == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_generate_datakey(g_enclave_id,
                                   &sgxStatus,
                                   cmk,
                                   APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                   aad,
                                   APPEND_SIZE_TO_DATA_T(aad->datalen),
                                   plaintext,
                                   APPEND_SIZE_TO_DATA_T(plaintext->datalen),
                                   ciphertext,
                                   APPEND_SIZE_TO_DATA_T(ciphertext->datalen));
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

/**
 * @brief decrypt data key using cmk then use ukey encrypt it
 *
 * @param cmk symmetric key
 * @param ukey asymmetric key
 * @param aad extra data to ensure data integrity
 * @param olddatakey cmk wrapped data key
 * @param newdatakey ukey wrapped data key
 * @return ehsm_status_t
 */
ehsm_status_t ExportDataKey(ehsm_keyblob_t *cmk,
                            ehsm_keyblob_t *ukey,
                            ehsm_data_t *aad,
                            ehsm_data_t *olddatakey,
                            ehsm_data_t *newdatakey)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (!validate_params(cmk, EH_CMK_MAX_SIZE) ||
        !validate_params(ukey, EH_CMK_MAX_SIZE) ||
        !validate_params(aad, EH_AAD_MAX_SIZE, false) ||
        !validate_params(olddatakey, EH_DATA_KEY_MAX_SIZE + EH_AAD_MAX_SIZE))
        return EH_ARGUMENTS_BAD;

    if (newdatakey == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_export_datakey(g_enclave_id,
                                 &sgxStatus,
                                 cmk,
                                 APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                 aad,
                                 APPEND_SIZE_TO_DATA_T(aad->datalen),
                                 olddatakey,
                                 APPEND_SIZE_TO_DATA_T(olddatakey->datalen),
                                 ukey,
                                 APPEND_SIZE_TO_KEYBLOB_T(ukey->keybloblen),
                                 newdatakey,
                                 APPEND_SIZE_TO_DATA_T(newdatakey->datalen));
out:
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t Enroll(ehsm_data_t *appid, ehsm_data_t *apikey)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (appid == NULL || appid->datalen != UUID_STR_LEN)
        return EH_ARGUMENTS_BAD;

    if (apikey == NULL || apikey->datalen != EH_API_KEY_SIZE)
        return EH_ARGUMENTS_BAD;

    // create appid
    uuid_t uu;
    uuid_generate(uu);
    uuid_unparse(uu, (char *)appid->data);

    ret = enclave_get_apikey(g_enclave_id,
                             &sgxStatus,
                             apikey->data,
                             apikey->datalen);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t GenerateQuote(ehsm_data_t *quote)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t dcap_ret = SGX_QL_SUCCESS;

    uint32_t quote_size = 0;
    sgx_target_info_t qe_target_info;
    sgx_report_t app_report;

    if (quote == NULL)
        return EH_ARGUMENTS_BAD;

    dcap_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != dcap_ret)
    {
        log_e("Error in sgx_qe_get_target_info. 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }
    log_d("sgx_qe_get_target_info successfully returned\n");

    dcap_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != dcap_ret)
    {
        log_e("Error in sgx_qe_get_quote_size. 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }
    log_d("sgx_qe_get_quote_size successfully returned\n");

    if (quote->datalen == 0)
    {
        quote->datalen = quote_size;
        return EH_OK;
    }

    if (quote->datalen != quote_size)
        return EH_ARGUMENTS_BAD;

    ret = enclave_create_report(g_enclave_id,
                                &sgxStatus,
                                &qe_target_info,
                                &app_report);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
    {
        log_e("Error in enclave_create_report (%d)(%d).\n", ret, sgxStatus);
        return EH_FUNCTION_FAILED;
    }
    log_d("enclave_create_report successfully returned\n");

    memset(quote->data, 0, quote_size);

    // Get the Quote
    dcap_ret = sgx_qe_get_quote(&app_report,
                                quote->datalen,
                                quote->data);
    if (SGX_QL_SUCCESS != dcap_ret)
    {
        log_e("Error in sgx_qe_get_quote. 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }
    log_d("sgx_qe_get_quote successfully returned\n");

    return EH_OK;
}

ehsm_status_t VerifyQuote(ehsm_data_t *quote,
                          const char *mr_signer,
                          const char *mr_enclave,
                          int *result)
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

    if (quote == NULL)
        return EH_ARGUMENTS_BAD;

    ret = enclave_get_rand(g_enclave_id,
                           &sgxStatus,
                           nonce, sizeof(nonce));
    if (ret != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;

    // set nonce
    memcpy(qve_report_info.nonce.rand, nonce, sizeof(nonce));

    ret = enclave_get_target_info(g_enclave_id,
                                  &sgxStatus,
                                  &qve_report_info.app_enclave_target_info);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
    {
        log_e("Error in sgx_get_target_info (%d)(%d).\n", ret, sgxStatus);
        return EH_FUNCTION_FAILED;
    }

    log_d("get target info successfully returned.\n");

    // call DCAP quote verify library to set QvE loading policy
    dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    if (dcap_ret != SGX_QL_SUCCESS)
    {
        log_e("Error in sgx_qv_set_enclave_load_policy failed: 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }

    log_d("sgx_qv_set_enclave_load_policy successfully returned.\n");

    // call DCAP quote verify library to get supplemental data size
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret != SGX_QL_SUCCESS)
    {
        log_e("Error in sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);
        return EH_FUNCTION_FAILED;
    }

    log_d("sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
    p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
    if (p_supplemental_data == NULL)
    {
        rc = EH_DEVICE_MEMORY;
        goto out;
    }

    // set current time. This is only for sample use, please use trusted time in product.
    current_time = time(NULL);
    // check mr_signer and mr_enclave
    if ((mr_signer != NULL && strncmp(mr_signer, " ", strlen(mr_signer)) != 0) ||
        (mr_enclave != NULL && strncmp(mr_enclave, " ", strlen(mr_enclave)) != 0))
    {
        ret = enclave_verify_quote_policy(g_enclave_id,
                                          &sgxStatus,
                                          quote->data,
                                          quote->datalen,
                                          mr_signer,
                                          strlen(mr_signer),
                                          mr_enclave,
                                          strlen(mr_enclave));
        if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        {
            rc = EH_DEVICE_MEMORY;
            goto out;
        }
    }

    // call DCAP quote verify library for quote verification with Intel QvE.
    dcap_ret = sgx_qv_verify_quote(quote->data,
                                   quote->datalen,
                                   NULL,
                                   current_time,
                                   &collateral_expiration_status,
                                   &quote_verification_result,
                                   &qve_report_info,
                                   supplemental_data_size,
                                   p_supplemental_data);
    if (dcap_ret != SGX_QL_SUCCESS)
    {
        log_e("Error in sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
        rc = EH_FUNCTION_FAILED;
        goto out;
    }

    log_d("sgx_qv_verify_quote successfully returned\n");

    // call sgx_dcap_tvl API in SampleISVEnclave to verify QvE's report and identity
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
    if (ret != SGX_SUCCESS || dcap_ret != SGX_QL_SUCCESS)
    {
        log_e("Error in Verify QvE report and identity failed. 0x%04x\n", dcap_ret);
        rc = EH_FUNCTION_FAILED;
        goto out;
    }

    log_d("Verify QvE report and identity successfully returned.\n");

    // check verification result
    switch (quote_verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
        // check verification collateral expiration status
        // this value should be considered in your own attestation/verification policy
        if (collateral_expiration_status == 0)
            log_i("\tInfo: App: Verification completed successfully.\n");
        else
            log_w("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.\n");

        break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        log_w("\tWarning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        log_e("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
        break;
    }

out:
    *result = quote_verification_result;
    SAFE_FREE(p_supplemental_data);
    return rc;
}

ehsm_status_t GenerateHmac(ehsm_keyblob_t *cmk, ehsm_data_t *apikey, ehsm_data_t *payload, ehsm_data_t *hmac)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL)
        return EH_ARGUMENTS_BAD;

    if (apikey == NULL || apikey->datalen > EH_CIPHERTEXT_MAX_SIZE)
        return EH_ARGUMENTS_BAD;

    if (payload == NULL || payload->datalen > EH_PAYLOAD_MAX_SIZE)
        return EH_ARGUMENTS_BAD;
    
    if (hmac == NULL || hmac->datalen != EH_HMAC_SHA256_SIZE)
        return EH_ARGUMENTS_BAD;

    ret = enclave_generate_hmac(g_enclave_id, &sgxStatus,
                                cmk, APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen),
                                apikey, APPEND_SIZE_TO_DATA_T(apikey->datalen),
                                payload, APPEND_SIZE_TO_DATA_T(payload->datalen),
                                hmac, APPEND_SIZE_TO_DATA_T(hmac->datalen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}

ehsm_status_t GenerateTokenHmac(ehsm_keyblob_t *sessionkey, ehsm_data_t *import_token, ehsm_data_t *hmac)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (sessionkey == NULL)
        return EH_ARGUMENTS_BAD;

    if (import_token == NULL || import_token->datalen > EH_PAYLOAD_MAX_SIZE)
        return EH_ARGUMENTS_BAD;

    if (hmac == NULL || hmac->datalen != EH_HMAC_SHA256_SIZE)
        return EH_ARGUMENTS_BAD;
    // At present, this interface is only compatible with BYOK function.
    // The parameters of session key are set in function  ffi_getParametersForImpor.
    ret = enclave_generate_token_hmac(g_enclave_id, &sgxStatus,
                                      sessionkey, APPEND_SIZE_TO_KEYBLOB_T(sessionkey->keybloblen),
                                      import_token, APPEND_SIZE_TO_DATA_T(import_token->datalen),
                                      hmac, APPEND_SIZE_TO_DATA_T(hmac->datalen));

    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
        return EH_FUNCTION_FAILED;
    else
        return EH_OK;
}