/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

#ifndef DATATYPES_H_
#define DATATYPES_H_

#define NONCE_SIZE         16
#define MAC_SIZE           16
#define MAC_KEY_SIZE       16

#define EH_API_KEY_SIZE     32
#define UUID_STR_LEN	   37

#define TAG_SIZE        16
#define IV_SIZE            12

#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

#define SGX_DOMAIN_KEY_SIZE     16

#define MESSAGE_EXCHANGE 0x0

#define MESSAGE_EXCHANGE_CMD_DK 0x1

#define ENCLAVE_TO_ENCLAVE_CALL 0x1

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}

#define _T(x) x

#define UNUSED(val) (void)(val)

#ifndef INT_MAX
#define INT_MAX     0x7fffffff
#endif

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif

typedef uint8_t dh_nonce[NONCE_SIZE];
typedef uint8_t cmac_128[MAC_SIZE];

#pragma pack(push, 1)

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

typedef struct _aes_gcm_data_ex_t
{
    uint32_t  ciphertext_size;
    uint32_t  aad_size;
    uint8_t   reserve1[8];
    uint8_t   iv[SGX_AESGCM_IV_SIZE];
    uint8_t   reserve2[4];
    uint8_t   mac[SGX_AESGCM_MAC_SIZE];
    uint8_t   payload[];   /* ciphertext + aad */
} sgx_aes_gcm_data_ex_t;

//sgx-ssl framework

typedef struct {
    uint32_t keyspec;
    uint32_t digest_mode;
    uint32_t padding_mode;
    uint32_t origin;
    uint32_t purpose;

    uint32_t apiversion;
    uint8_t  descrption[16];
    uint8_t  createdate[8];
} ehsm_keymetadata_t;

typedef struct {
    ehsm_keymetadata_t  metadata;
    uint32_t            keybloblen;
    uint8_t             *keyblob;
} ehsm_keyblob_t;

//aes
typedef struct
{
    uint32_t    ciphertext_size;
    uint32_t    aad_size;
    uint8_t     iv[SGX_AESGCM_IV_SIZE];
    uint8_t     mac[SGX_AESGCM_MAC_SIZE];
    uint8_t     payload[];   /* ciphertext + aad */
} aes_gcm_key_data_t;

//rsa
typedef struct
{
    char* rsa_private_key;
    char* rsa_public_key;
} rsa_key_data_t;

//ec:
typedef struct 
{
    char* ec_private_key;
    char* ec_public_key;
    char* ec_parameters;
} ec_key_data_t;

//hmac
typedef struct
{
    //temporary
} hmac_key_data_t;

//sm2
typedef struct
{
    //temporary
} sm2_key_data_t;

//sm4
typedef struct 
{
    uint32_t    ciphertext_size;
    uint32_t    aad_size;
    uint8_t     iv[SGX_AESGCM_IV_SIZE];
    uint8_t     mac[SGX_AESGCM_MAC_SIZE];
    uint8_t     payload[];   /* ciphertext + aad */
} sm4_key_data_t;

typedef enum {
    EH_AES_GCM_128 = 0,
    EH_AES_GCM_192,
    EH_AES_GCM_256,
    EH_RSA_2048,
    EH_RSA_3072,
    EH_EC_P224,
    EH_EC_P256,
    EH_EC_P384,
    EH_EC_P512,
    EH_EC_SM2,
    EH_HMAC,
    EH_SM3, 
    EH_SM4 
} ehsm_keyspec_t;

typedef enum {
    EH_RSA_PKCS1v2_OAEP = 0,
    EH_RSA_PKCS1_v1_5,
    EH_RSA_PKCS1v2_PSS,
    EH_PKCS1_v1_5
} ehsm_padding_mode_t;

typedef enum {
    EH_NONE = 0,
    EH_MD5,
    EH_SHA1,
    EH_SHA_2_224,
    EH_SHA_2_256,
    EH_SHA_2_384,
    EH_SHA_2_512
} ehsm_digest_mode_t;

#pragma pack(pop)

#endif
