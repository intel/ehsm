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

#include "enroll_marshal.h"

/*
 * process eHSM-KMS return msg1 json
 */
enroll_status_t unmarshal_ga_from_json(RetJsonObj retJsonObj_msg1, sample_ec_pub_t *g_a)
{
    if (g_a == NULL)
    {
        return ENL_ERROR_INVALID_PARAMETER;
    }

    // parse g_a
    std::string json_key;
    json_key.clear();
    json_key = json_key + "g_a" + LAYERED_CHARACTER + "gx";
    retJsonObj_msg1.readData_uint8Array(json_key, g_a->gx);
    json_key.clear();
    json_key = json_key + "g_a" + LAYERED_CHARACTER + "gy";
    retJsonObj_msg1.readData_uint8Array(json_key, g_a->gy);

    return ENL_OK;
}

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
enroll_status_t marshal_msg2_to_json(sample_ra_msg2_t *tp_msg2, std::string *p_msg2)
{
    JsonObj msg2_json;
    if (tp_msg2 == NULL || p_msg2 == NULL)
    {
        return ENL_ERROR_INVALID_PARAMETER;
    }

    std::string json_key;
    // g_b
    json_key.clear();
    json_key = json_key + "g_b" + LAYERED_CHARACTER + "gx";
    msg2_json.addData_uint8Array(json_key, tp_msg2->g_b.gx, SAMPLE_ECP_KEY_SIZE);
    json_key.clear();
    json_key = json_key + "g_b" + LAYERED_CHARACTER + "gy";
    msg2_json.addData_uint8Array(json_key, tp_msg2->g_b.gy, SAMPLE_ECP_KEY_SIZE);

    // spid
    json_key.clear();
    json_key = json_key + "spid" + LAYERED_CHARACTER + "id";
    msg2_json.addData_uint8Array(json_key, tp_msg2->spid.id, 16);

    // quote_type
    msg2_json.addData_uint16("quote_type", tp_msg2->quote_type);
    // kdf_id
    msg2_json.addData_uint16("kdf_id", tp_msg2->kdf_id);

    // sign_gb_ga
    json_key.clear();
    json_key = json_key + "sign_gb_ga" + LAYERED_CHARACTER + "x";
    msg2_json.addData_uint32Array(json_key, tp_msg2->sign_gb_ga.x, SAMPLE_NISTP256_KEY_SIZE);
    json_key.clear();
    json_key = json_key + "sign_gb_ga" + LAYERED_CHARACTER + "y";
    msg2_json.addData_uint32Array(json_key, tp_msg2->sign_gb_ga.y, SAMPLE_NISTP256_KEY_SIZE);

    // mac
    msg2_json.addData_uint8Array("mac", tp_msg2->mac, SAMPLE_MAC_SIZE);

    // sig_rl_size
    msg2_json.addData_uint32("sig_rl_size", tp_msg2->sig_rl_size);

    // sig_rl
    msg2_json.addData_uint8Array("sig_rl", tp_msg2->sig_rl, tp_msg2->sig_rl_size);

    // setting return msg2 json string.
    *p_msg2 = msg2_json.toString();

    return ENL_OK;
}

/*
 * process eHSM-KMS return msg3 json
 */
enroll_status_t unmarshal_msg3_from_json(RetJsonObj retJsonObj_msg3, sample_ra_msg3_t *p_msg3)
{
    if (p_msg3 == NULL)
    {
        return ENL_ERROR_INVALID_PARAMETER;
    }

    std::string json_key;
    // mac
    retJsonObj_msg3.readData_uint8Array("mac", p_msg3->mac);

    // g_a
    json_key.clear();
    json_key = json_key + "g_a" + LAYERED_CHARACTER + "gx";
    retJsonObj_msg3.readData_uint8Array(json_key, p_msg3->g_a.gx);
    json_key.clear();
    json_key = json_key + "g_a" + LAYERED_CHARACTER + "gy";
    retJsonObj_msg3.readData_uint8Array(json_key, p_msg3->g_a.gy);

    // ps_sec_prop
    json_key.clear();
    json_key = json_key + "ps_sec_prop" + LAYERED_CHARACTER + "sgx_ps_sec_prop_desc";
    retJsonObj_msg3.readData_uint8Array(json_key, p_msg3->ps_sec_prop.sample_ps_sec_prop_desc);

    // quote
    retJsonObj_msg3.readData_uint8Array("quote", p_msg3->quote);

    return ENL_OK;
}

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
enroll_status_t ra_proc_att_result_msg(sample_ra_att_result_msg_t *tp_att_result_msg, std::string *p_att_result_msg)
{
    enroll_status_t ret = ENL_OK;
    if (tp_att_result_msg == NULL || p_att_result_msg == NULL)
    {
        return ENL_ERROR_INVALID_PARAMETER;
    }

    JsonObj att_result_msg_json;
    std::string json_key;

    // platform_info_blob
    {
        std::string base_level_1;
        base_level_1 = base_level_1 + "platform_info_blob" + LAYERED_CHARACTER;
        // platform_info_blob &-> nonce
        {
            json_key.clear();
            json_key = base_level_1 + "nonce" + LAYERED_CHARACTER + "rand";
            att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.nonce.rand, 16);
        }
        // platform_info_blob &-> quote_verification_result
        {
            json_key.clear();
            json_key = base_level_1 + "quote_verification_result";
            att_result_msg_json.addData_uint32(json_key, tp_att_result_msg->platform_info_blob.quote_verification_result);
        }
        // platform_info_blob &-> qve_report_info
        {
            std::string base_level_2 = base_level_1 + "qve_report_info" + LAYERED_CHARACTER;
            // platform_info_blob &-> qve_report_info &-> nonce
            {
                json_key.clear();
                json_key = base_level_2 + "nonce" + LAYERED_CHARACTER + "rand";
                att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.nonce.rand, 16);
            }
            // platform_info_blob &-> qve_report_info &-> app_enclave_target_info
            {
                std::string base_level_3 = base_level_2 + "app_enclave_target_info" + LAYERED_CHARACTER;
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> mr_enclave
                json_key.clear();
                json_key = base_level_3 + "mr_enclave" + LAYERED_CHARACTER + "m";
                att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.mr_enclave.m, SGX_HASH_SIZE);
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> attributes
                json_key.clear();
                json_key = base_level_3 + "attributes" + LAYERED_CHARACTER + "flags";
                att_result_msg_json.addData_uint64(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.attributes.flags);
                json_key.clear();
                json_key = base_level_3 + "attributes" + LAYERED_CHARACTER + "xfrm";
                att_result_msg_json.addData_uint64(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.attributes.xfrm);
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> reserved1
                json_key.clear();
                json_key = base_level_3 + "reserved1";
                att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.reserved1, SGX_TARGET_INFO_RESERVED1_BYTES);
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> config_svn
                json_key.clear();
                json_key = base_level_3 + "config_svn";
                att_result_msg_json.addData_uint16(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.config_svn);
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> misc_select
                json_key.clear();
                json_key = base_level_3 + "misc_select";
                att_result_msg_json.addData_uint32(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.misc_select);
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> reserved2
                json_key.clear();
                json_key = base_level_3 + "reserved2";
                att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.reserved2, SGX_TARGET_INFO_RESERVED2_BYTES);
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> config_id
                json_key.clear();
                json_key = base_level_3 + "config_id";
                att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.config_id, SGX_CONFIGID_SIZE);
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> reserved3
                json_key.clear();
                json_key = base_level_3 + "reserved3";
                att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.reserved3, SGX_TARGET_INFO_RESERVED3_BYTES);
            }
            // platform_info_blob &-> qve_report_info &-> qe_report
            {
                std::string base_level_3 = base_level_2 + "qe_report" + LAYERED_CHARACTER;
                // platform_info_blob &-> qve_report_info &-> qe_report &-> body
                {
                    std::string base_level_4 = base_level_3 + "body" + LAYERED_CHARACTER;
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> cpu_svn
                    json_key.clear();
                    json_key = base_level_4 + "cpu_svn" + LAYERED_CHARACTER + "svn";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.cpu_svn.svn, SGX_CPUSVN_SIZE);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> misc_select
                    json_key.clear();
                    json_key = base_level_4 + "misc_select";
                    att_result_msg_json.addData_uint32(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.misc_select);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> reserved1
                    json_key.clear();
                    json_key = base_level_4 + "reserved1";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.reserved1, SGX_REPORT_BODY_RESERVED1_BYTES);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> isv_ext_prod_id
                    json_key.clear();
                    json_key = base_level_4 + "isv_ext_prod_id";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.isv_ext_prod_id, SGX_ISVEXT_PROD_ID_SIZE);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> attributes
                    json_key.clear();
                    json_key = base_level_4 + "attributes" + LAYERED_CHARACTER + "flags";
                    att_result_msg_json.addData_uint64(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.attributes.flags);
                    json_key.clear();
                    json_key = base_level_4 + "attributes" + LAYERED_CHARACTER + "xfrm";
                    att_result_msg_json.addData_uint64(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.attributes.xfrm);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> mr_enclave
                    json_key.clear();
                    json_key = base_level_4 + "mr_enclave" + LAYERED_CHARACTER + "m";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.mr_enclave.m, SGX_HASH_SIZE);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> reserved2
                    json_key.clear();
                    json_key = base_level_4 + "reserved2";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.reserved2, SGX_REPORT_BODY_RESERVED2_BYTES);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> mr_signer
                    json_key.clear();
                    json_key = base_level_4 + "mr_signer" + LAYERED_CHARACTER + "m";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.mr_signer.m, SGX_HASH_SIZE);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> reserved3
                    json_key.clear();
                    json_key = base_level_4 + "reserved3";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.reserved3, SGX_REPORT_BODY_RESERVED3_BYTES);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> config_id
                    json_key.clear();
                    json_key = base_level_4 + "config_id";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.config_id, SGX_CONFIGID_SIZE);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> isv_prod_id
                    json_key.clear();
                    json_key = base_level_4 + "isv_prod_id";
                    att_result_msg_json.addData_uint16(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.isv_prod_id);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> isv_svn
                    json_key.clear();
                    json_key = base_level_4 + "isv_svn";
                    att_result_msg_json.addData_uint16(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.isv_svn);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> config_svn
                    json_key.clear();
                    json_key = base_level_4 + "config_svn";
                    att_result_msg_json.addData_uint16(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.config_svn);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> reserved4
                    json_key.clear();
                    json_key = base_level_4 + "reserved4";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.reserved4, SGX_REPORT_BODY_RESERVED4_BYTES);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> isv_family_id
                    json_key.clear();
                    json_key = base_level_4 + "isv_family_id";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.isv_family_id, SGX_ISV_FAMILY_ID_SIZE);
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> report_data
                    json_key.clear();
                    json_key = base_level_4 + "report_data" + LAYERED_CHARACTER + "d";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.report_data.d, SGX_REPORT_DATA_SIZE);
                }
                // platform_info_blob &-> qve_report_info &-> qe_report &-> key_id
                {
                    json_key.clear();
                    json_key = base_level_3 + "key_id" + LAYERED_CHARACTER + "id";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.key_id.id, SGX_KEYID_SIZE);
                }
                // platform_info_blob &-> qve_report_info &-> qe_report &-> mac
                {
                    json_key.clear();
                    json_key = base_level_3 + "mac";
                    att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->platform_info_blob.qve_report_info.qe_report.mac, SGX_MAC_SIZE);
                }
            }
        }
    }
    // mac
    {
        json_key.clear();
        json_key = "mac";
        att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->mac, SAMPLE_MAC_SIZE);
    }
    // secret
    {
        std::string base_level_1;
        base_level_1 = base_level_1 + "secret" + LAYERED_CHARACTER;
        // secret &-> payload_size
        json_key.clear();
        json_key = base_level_1 + "payload_size";
        att_result_msg_json.addData_uint32(json_key, tp_att_result_msg->secret.payload_size);
        // secret &-> reserved
        json_key.clear();
        json_key = base_level_1 + "reserved";
        att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->secret.reserved, 12);
        // secret &-> payload_tag
        json_key.clear();
        json_key = base_level_1 + "payload_tag";
        att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->secret.payload_tag, SAMPLE_SP_TAG_SIZE);
        // secret &-> payload
        json_key.clear();
        json_key = base_level_1 + "payload";
        att_result_msg_json.addData_uint8Array(json_key, tp_att_result_msg->secret.payload, tp_att_result_msg->secret.payload_size);
    }

    *p_att_result_msg = att_result_msg_json.toString();

    return ret;
}