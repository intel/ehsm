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

#include "log_utils.h"
#include "sgx_tseal.h"

#include <stdio.h>
#include <stdbool.h>

#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"

#ifndef DATATYPES_H_
#define DATATYPES_H_

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#define SIZE_OF_KEYBLOB_T(x)    (sizeof(ehsm_keyblob_t) + x*sizeof(uint8_t))
#define SIZE_OF_DATA_T(x)    (sizeof(ehsm_data_t) + x*sizeof(uint8_t))

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

#define TAG_SIZE           16
#define IV_SIZE            12

#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

#define SGX_DOMAIN_KEY_SIZE     16

#define RSA_OAEP_2048_CIPHER_LENGTH       256
#define RSA_OAEP_3072_CIPHER_LENGTH       384
#define RSA_OAEP_4096_CIPHER_LENGTH       512

#define RSA_OAEP_4096_SIGNATURE_SIZE      512
#define RSA_OAEP_3072_SIGNATURE_SIZE      384
#define RSA_OAEP_2048_SIGNATURE_SIZE      256

#define EC_P256_SIGNATURE_MAX_SIZE        72
#define EC_SM2_SIGNATURE_MAX_SIZE         72

#define EC_APPID_SIZE                     37

#define RSA_OAEP_4096_DIGEST_SIZE         264
#define EC_MAX_DIGEST_SIZE                264

#define RSA_PKCS1_OAEP_PADDING_SIZE       41
#define RSA_PKCS1_PADDING_SIZE            11

#define EH_AES_GCM_IV_SIZE  12
#define EH_AES_GCM_MAC_SIZE 16
#define SGX_SM4_IV_SIZE     16

#define SM2PKE_MAX_ENCRYPTION_SIZE              6047
#define EH_ENCRYPT_MAX_SIZE                    (6*1024)
#define EH_DATA_KEY_MAX_SIZE                    1024

#define MESSAGE_EXCHANGE 0x0

#define MESSAGE_EXCHANGE_CMD_DK 0x1

#define ENCLAVE_TO_ENCLAVE_CALL 0x1

#define EH_CMK_MAX_SIZE (8*1024)
#define EH_AAD_MAX_SIZE (8*1024)
#define EH_QUOTE_MAX_SIZE (8*1024)

#define SGX_DOMAIN_KEY_SIZE     16

#define RSA_2048_KEY_BITS   2048
#define RSA_3072_KEY_BITS   3072
#define RSA_4096_KEY_BITS   4096

#define RSA_2048_PUBLIC_KEY_PEM_SIZE    426
#define RSA_2048_PRIVATE_KEY_PEM_SIZE    1679

#define RSA_3072_PUBLIC_KEY_PEM_SIZE    625
#define RSA_3072_PRIVATE_KEY_PEM_SIZE    2484

#define RSA_4096_PUBLIC_KEY_PEM_SIZE    775
#define RSA_4096_PRIVATE_KEY_PEM_SIZE    3247

#define ECC_PUBLIC_KEY_PEM_SIZE     178
#define ECC_PRIVATE_KEY_PEM_SIZE    227
#define ECC_MAX_PLAINTEXT_SIZE      256

typedef uint8_t dh_nonce[NONCE_SIZE];
typedef uint8_t cmac_128[MAC_SIZE];

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
    EH_INTERNAL_KEY,
    EXTERNAL_KEY,
} ehsm_keyorigin_t;

typedef enum {
    ENCRYPT_DECRYPT = 0,
    SIGN_VERIFY = 1,
} ehsm_keypurpose_t;

typedef enum {
    EH_AES_GCM_128 = 0,
    EH_AES_GCM_192,
    EH_AES_GCM_256,
    EH_RSA_2048,
    EH_RSA_3072,
    EH_RSA_4096,
    EH_EC_P224,
    EH_EC_P256,
    EH_EC_P384,
    EH_EC_P512,
    EH_HMAC,
    EH_SM2,
    EH_SM4,
    INVALID_VALUE
} ehsm_keyspec_t;

typedef enum {
    EH_NONE = 0,
    EH_SHA_2_224,
    EH_SHA_2_256,
    EH_SHA_2_384,
    EH_SHA_2_512,
    EH_SM3
} ehsm_digest_mode_t;

typedef enum {
    EH_PAD_RSA_PKCS1 = 1,      
    EH_PAD_RSA_SSLV23,      
    EH_PAD_RSA_NO,          
    EH_PAD_RSA_PKCS1_OAEP,  
    EH_PAD_RSA_X931,
    EH_PAD_RSA_PKCS1_PSS       
} ehsm_padding_mode_t;

typedef enum {
    FIPS_APPROVAL = 0,
    FIPS_NOT_APPROVAL
} ehsm_fips_mode_t;

#pragma pack(push,1)

typedef struct {
    uint32_t    datalen;
    uint8_t     data[0];
} ehsm_data_t;

typedef struct {
    ehsm_keyspec_t        keyspec;
    ehsm_digest_mode_t    digest_mode;
    ehsm_padding_mode_t   padding_mode;
    ehsm_keyorigin_t      origin;
    ehsm_keypurpose_t     purpose;
    ehsm_fips_mode_t      fips_mode;

    uint32_t              apiversion;
    uint8_t               descrption[16];
    uint8_t               createdate[8];
} ehsm_keymetadata_t;

typedef struct {
    ehsm_keymetadata_t  metadata;
    uint32_t            keybloblen;
    uint8_t             keyblob[0];
} ehsm_keyblob_t;


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