/*
 * Copyright (C) 2021-2022 Intel Corporation
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

#ifndef _ENROLL_MARSHAL_H_
#define _ENROLL_MARSHAL_H_

#include "sample_ra_msg.h"
#include "json_utils.h"

typedef enum
{
    ENL_OK = 0,
    ENL_CONFIG_INVALID = -1,
    ENL_POST_EXCEPTION = -2,
    ENL_NAPI_EXCEPTION = -3,
    ENL_CHALLENGE_NO_COMPARE = -4,
    ENL_INTERNAL_ERROR = -5,
    ENL_ERROR_INVALID_PARAMETER = -6,
    ENL_ERROR_VERIFY_NONCE_FAILED = -7,
    ENL_ERROR_DECRYPT_APIKEY_FAILED = -8,
    ENL_DEVICE_MEMORY_FAILED = -9
} enroll_status_t;

/*
 * process eHSM-KMS return msg1 json
 */
enroll_status_t unmarshal_ga_from_json(RetJsonObj retJsonObj_msg1, sample_ec_pub_t *g_a);

/*
 * process will be send to eHSM-KMS msg2 json
 *  p_msg2 : json
 *      {
 *          "g_b" : Json::Value
 *              {
 *                  gx : array(int),
 *                  gy : array(int)
 *              },
 *          "spid" : Json::Value
 *              {
 *                  id : array(int),
 *              },
 *          "quote_type" : int,
 *          "kdf_id" : int,
 *          "sign_gb_ga" : Json::Value
 *              {
 *                  x : array(int),
 *                  y : array(int)
 *              },
 *          "mac" : array(int),
 *          "sig_rl_size" : int,
 *          "sig_rl" : array(int)
 *      }
 */
enroll_status_t marshal_msg2_to_json(sample_ra_msg2_t *tp_msg2, std::string *p_msg2);

/*
 * process eHSM-KMS return msg3 json
 */
enroll_status_t unmarshal_msg3_from_json(RetJsonObj retJsonObj_msg3, sample_ra_msg3_t *p_msg3);

/*
 * process will be send to eHSM-KMS att_result_msg json
 *  p_att_result_msg : json
 *      {
 *          "mac": array(int),
 *          "platform_info_blob": {
 *              "nonce": {
 *                  "rand": array(int)
 *              },
 *              "quote_verification_result" : int,
 *              "qve_report_info": {
 *                  "app_enclave_target_info": {
 *                      "attributes": {
 *                          "flags": uint64(string),
 *                          "xfrm": uint64(string)
 *                      },
 *                      "config_id": array(int),
 *                      "config_svn": int,
 *                      "misc_select": int,
 *                      "mr_enclave": {
 *                          "m": array(int),
 *                      },
 *                      "reserved1": array(int),
 *                      "reserved2": array(int),
 *                      "reserved3": array(int)
 *                  },
 *                  "nonce": {
 *                      "rand": array(int)
 *                  },
 *                  "qe_report": {
 *                      "body": {
 *                          "attributes": {
 *                              "flags": uint64(string),
 *                              "xfrm": uint64(string)
 *                          },
 *                          "config_id": array(int),
 *                          "config_svn": int,
 *                          "cpu_svn": {
 *                              "svn": array(int)
 *                          },
 *                          "isv_ext_prod_id": array(int),
 *                          "isv_family_id": array(int),
 *                          "isv_prod_id": int,
 *                          "isv_svn": int,
 *                          "misc_select": int,
 *                          "mr_enclave": {
 *                              "m": array(int)
 *                          },
 *                          "mr_signer": {
 *                              "m": array(int)
 *                          },
 *                          "report_data": {
 *                              "d": array(int)
 *                          },
 *                          "reserved1": array(int),
 *                          "reserved2": array(int),
 *                          "reserved3": array(int),
 *                          "reserved4": array(int)
 *                      },
 *                      "key_id": {
 *                          "id": array(int)
 *                      },
 *                      "mac": array(int)
 *                  }
 *              }
 *          },
 *          "quote_type": int,
 *          "secret": {
 *              "payload": array(int),
 *              "payload_size": int,
 *              "payload_tag": array(int),
 *              "reserved": array(int)
 *          }
 *      }
 */
enroll_status_t ra_proc_att_result_msg(sample_ra_att_result_msg_t *tp_att_result_msg, std::string *p_att_result_msg);

#endif