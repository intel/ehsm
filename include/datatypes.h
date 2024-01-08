/*
 * Copyright (C) 2011-2023 Intel Corporation. All rights reserved.
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

#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"
#include "sgx_tseal.h"

#include <stdio.h>
#include <stdbool.h>

#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"

#ifndef DATATYPES_H_
#define DATATYPES_H_

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#define SAFE_MEMSET(ptr, length1, value, length2)     {if (NULL != (ptr)) {memset_s(ptr, length1, 0, length2);}}
#define APPEND_SIZE_TO_KEYBLOB_T(x)    (sizeof(ehsm_keyblob_t) + x*sizeof(uint8_t))
#define APPEND_SIZE_TO_DATA_T(x)    (sizeof(ehsm_data_t) + x*sizeof(uint8_t))
#define SM2_DEFAULT_USERID      "1234567812345678" 
#define SM2_DEFAULT_USERID_LEN      sizeof(SM2_DEFAULT_USERID) - 1

#define _T(x) x

#define UNUSED(val) (void)(val)

#ifndef INT_MAX
#define INT_MAX     0x7fffffff
#endif

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif

#define NONCE_SIZE         16
#define MAC_SIZE           16
#define MAC_KEY_SIZE       16

#define EH_API_KEY_SIZE    32
#define UUID_STR_LEN	   37

#define EH_HMAC_SHA256_SIZE 32

#define EH_AES_GCM_256_SIZE 80 // 80: 32 + sizeof(sgx_aes_gcm_data_ex_t)

#define TAG_SIZE           16
#define IV_SIZE            12

#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

#define RSA_OAEP_4096_SIGNATURE_SIZE      512
#define RSA_OAEP_3072_SIGNATURE_SIZE      384
#define RSA_OAEP_2048_SIGNATURE_SIZE      256

/* The maximum length of ec is obtained by ecdsa_size() */
#define EC_P224_SIGNATURE_MAX_SIZE        66
#define EC_P256_SIGNATURE_MAX_SIZE        72
#define EC_P384_SIGNATURE_MAX_SIZE        104
#define EC_P521_SIGNATURE_MAX_SIZE        141
#define EC_SM2_SIGNATURE_MAX_SIZE         72

#define MAX_SIGN_DATA_SIZE         (6*1024)
#define MAX_SIGNATURE_SIZE                512

#define EH_AES_GCM_IV_SIZE  12
#define EH_AES_GCM_MAC_SIZE 16
#define SGX_SM4_IV_SIZE     16

#define SM2PKE_MAX_ENCRYPTION_SIZE              6047
#define EH_ENCRYPT_MAX_SIZE                    (6*1024)
#define EH_DATA_KEY_MAX_SIZE                    (6*1024)

#define MESSAGE_EXCHANGE 0x0

#define MESSAGE_EXCHANGE_CMD_DK 0x1

#define ENCLAVE_TO_ENCLAVE_CALL 0x1

#define EH_CMK_MAX_SIZE (8*1024)
#define EH_AAD_MAX_SIZE (8*1024)
#define EH_PLAINTEXT_MAX_SIZE (6*1024)
#define EH_CIPHERTEXT_MAX_SIZE (6*1024)
#define EH_PAYLOAD_MAX_SIZE (12*1024)
#define EH_QUOTE_MAX_SIZE (8*1024)

#define SGX_DOMAIN_KEY_SIZE     32

#define RSA_2048_KEY_BITS   2048
#define RSA_3072_KEY_BITS   3072
#define RSA_4096_KEY_BITS   4096

typedef uint8_t dh_nonce[NONCE_SIZE];
typedef uint8_t cmac_128[MAC_SIZE];

typedef uint8_t sgx_aes_gcm_256bit_key_t[SGX_DOMAIN_KEY_SIZE];

typedef enum {
    EH_OK                           = 0,
    EH_KEYSPEC_INVALID              = -1,
    EH_DEVICE_MEMORY                = -2,
    EH_DEVICE_ERROR                 = -3,
    EH_GENERAL_ERROR                = -4,
    EH_FUNCTION_FAILED              = -5,
    EH_ARGUMENTS_BAD                = -6,
    EH_LA_SETUP_ERROR               = -7,
    EH_LA_EXCHANGE_MSG_ERROR        = -8,
    EH_LA_CLOSE_ERROR               = -9,
} ehsm_status_t;

//sgx-ssl framework
typedef enum  {
    EH_INTERNAL_KEY = 1,
    EH_EXTERNAL_KEY,
} ehsm_keyorigin_t;

typedef enum {
    EH_KEYUSAGE_ENCRYPT_DECRYPT = 1,
    EH_KEYUSAGE_SIGN_VERIFY,
} ehsm_keyusage_t;

typedef enum {
    EH_AES_GCM_128 = 1,
    EH_AES_GCM_192 = 2,
    EH_AES_GCM_256 = 3,
    EH_RSA_2048 = 10,
    EH_RSA_3072 = 11,
    EH_RSA_4096 = 12,
    EH_EC_P224 = 20,
    EH_EC_P256 = 21,
    EH_EC_P256K = 22,
    EH_EC_P384 = 23,
    EH_EC_P521 = 24,
    EH_SM2 = 30,
    EH_SM4_CTR = 31,
    EH_SM4_CBC= 32,
    EH_HMAC = 40
} ehsm_keyspec_t;

// use in sign/verify
typedef enum {
    EH_RAW = 1,
    EH_DIGEST = 2,
} ehsm_message_type_t;

typedef enum {
    EH_SHA_224 = 1,
    EH_SHA_256 = 2,
    EH_SHA_384 = 3,
    EH_SHA_512 = 4,
    EH_SM3 = 5 // only use for sm2 keypair
} ehsm_digest_mode_t;

typedef enum {
    EH_PAD_NONE = 0,
    EH_RSA_PKCS1 = 1,
    EH_RSA_PKCS1_PSS = 2, // only use for RSA sign/verify
    EH_RSA_PKCS1_OAEP = 3, // only use for RSA encrypt/decrypt
} ehsm_padding_mode_t;

#pragma pack(push,1)

typedef struct {
    uint32_t    datalen;
    uint8_t     data[0];
} ehsm_data_t;

typedef struct {
    ehsm_keyspec_t        keyspec;
    ehsm_keyorigin_t      origin;
    ehsm_keyusage_t       keyusage;

    uint32_t              apiversion;
    uint8_t               descrption[16];
    uint8_t               createdate[8];
} ehsm_keymetadata_t;

typedef struct {
    ehsm_keymetadata_t  metadata;
    uint32_t            keybloblen;
    uint8_t             keyblob[0];
} ehsm_keyblob_t;

typedef enum {
    LOG_DEBUG = 10000,
    LOG_INFO = 20000,
    LOG_WARN = 30000,
    LOG_ERROR = 40000
} log_type;

//Format of the AES-GCM message being exchanged between the source and the destination enclaves
typedef struct _secure_message_t
{
    uint32_t session_id; //Session ID identifyting the session to which the message belongs
    sgx_aes_gcm_data_t message_aes_gcm_data;
} secure_message_t;

//Format of the input function parameter structure
typedef struct _ms_in_msg_exchange_t {
    uint32_t msg_type; //Type of Call E2E or general message exchange
    uint32_t target_fn_id; //Function Id to be called in Destination. Is valid only when msg_type=ENCLAVE_TO_ENCLAVE_CALL
    uint32_t inparam_buff_len; //Length of the serialized input parameters
    uint8_t inparam_buff[1]; //Serialized input parameters
} ms_in_msg_exchange_t;

//Format of the return value and output function parameter structure
typedef struct _ms_out_msg_exchange_t {
    uint32_t retval_len; //Length of the return value
    uint32_t ret_outparam_buff_len; //Length of the serialized return value and output parameters
    uint8_t ret_outparam_buff[1]; //Serialized return value and output parameters
} ms_out_msg_exchange_t;

//Session Tracker to generate session ids
typedef struct _session_id_tracker_t
{
    uint32_t          session_id;
} session_id_tracker_t;

#pragma pack(pop)

#endif