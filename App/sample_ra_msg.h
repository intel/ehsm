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

#ifndef _REMOTE_ATTESTATION_RESULT_H_
#define _REMOTE_ATTESTATION_RESULT_H_

#include <stdint.h>

#include "sgx_quote.h"
#include "sgx_qve_header.h"
#include "sgx_ql_quote.h"
#include "sgx_key_exchange.h"

#ifdef  __cplusplus
extern "C" {
#endif


typedef enum _ra_msg_type_t
{
     TYPE_RA_MSG0 = 0,
     TYPE_RA_MSG1,
     TYPE_RA_MSG2,
     TYPE_RA_MSG3,
     TYPE_RA_ATT_RESULT,
     TYPE_RA_RETRIEVE_DK,
}ra_msg_type_t;


#define SAMPLE_SP_TAG_SIZE          16
#define ISVSVN_SIZE 2
#define PSDA_SVN_SIZE 4
#define GID_SIZE 4
#define PSVN_SIZE 18

#define SGX_DOMAIN_KEY_SIZE     16

#pragma pack(push,1)

typedef struct sp_aes_gcm_data_t {
    uint32_t        payload_size;       /*  0: Size of the payload which is*/
                                        /*     encrypted*/
    uint8_t         reserved[12];       /*  4: Reserved bits*/
    uint8_t         payload_tag[SAMPLE_SP_TAG_SIZE];
                                        /* 16: AES-GMAC of the plain text,*/
                                        /*     payload, and the sizes*/
    uint8_t         payload[];          /* 32: Ciphertext of the payload*/
                                        /*     followed by the plain text*/
} sp_aes_gcm_data_t;

typedef struct ias_platform_info_blob_t
{
    sgx_quote_nonce_t nonce;
    sgx_ql_qv_result_t quote_verification_result;
    sgx_ql_qe_report_info_t qve_report_info;
} ias_platform_info_blob_t;


typedef struct sample_ra_att_result_msg_t {
    ias_platform_info_blob_t    platform_info_blob;
    sgx_mac_t                mac;    /* mac_smk(attestation_status)*/
    sp_aes_gcm_data_t           secret;
} sample_ra_att_result_msg_t;

typedef struct sample_key_blob_t {
    uint32_t        blob_size;
    uint8_t         blob[];
} sample_key_blob_t;

typedef struct _ra_samp_request_header_t{
    uint8_t  type;     /* set to one of ra_msg_type_t*/
    uint32_t size;     /*size of request body*/
    uint8_t  align[3];
    uint8_t body[];
} ra_samp_request_header_t;

typedef struct _ra_samp_response_header_t{
    uint8_t  type;      /* set to one of ra_msg_type_t*/
    uint8_t  status[2];
    uint32_t size;      /*size of the response body*/
    uint8_t  align[1];
    uint8_t  body[];
} ra_samp_response_header_t;

#pragma pack(pop)

#ifdef  __cplusplus
}
#endif

#endif
