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

#include "ehsm_marshal.h"

/*
 * process receive msg2 json string to sgx_ra_msg2_t
 *  @param ra_msg2 : receive msg2 json string
 *  @param req_msg2 : return sgx_ra_msg2_t
 *  @param msg2_size : return sgx_ra_msg2_t real size
 */
ehsm_status_t unmarshal_msg2_from_json(std::string ra_msg2, sgx_ra_msg2_t *req_msg2, uint32_t *msg2_size)
{
    if (ra_msg2.empty() || req_msg2 == NULL || msg2_size == NULL)
    {
        return EH_ARGUMENTS_BAD;
    }

    JsonObj msg2_json;

    if (msg2_json.parse(ra_msg2))
    {
        std::string json_key;
        // g_b
        json_key.clear();
        json_key = json_key + "g_b" + LAYERED_CHARACTER + "gx";
        msg2_json.readData_uint8Array(json_key, req_msg2->g_b.gx);
        json_key.clear();
        json_key = json_key + "g_b" + LAYERED_CHARACTER + "gy";
        msg2_json.readData_uint8Array(json_key, req_msg2->g_b.gy);

        // spid
        json_key.clear();
        json_key = json_key + "spid" + LAYERED_CHARACTER + "id";
        msg2_json.readData_uint8Array(json_key, req_msg2->spid.id);

        // quote_type
        req_msg2->quote_type = msg2_json.readData_uint16("quote_type");

        // kdf_id
        req_msg2->kdf_id = msg2_json.readData_uint16("kdf_id");

        // // sign_gb_ga
        json_key.clear();
        json_key = json_key + "sign_gb_ga" + LAYERED_CHARACTER + "x";
        msg2_json.readData_uint32Array(json_key, req_msg2->sign_gb_ga.x);
        json_key.clear();
        json_key = json_key + "sign_gb_ga" + LAYERED_CHARACTER + "y";
        msg2_json.readData_uint32Array(json_key, req_msg2->sign_gb_ga.y);

        // mac
        msg2_json.readData_uint8Array("mac", req_msg2->mac);

        // sig_rl_size
        req_msg2->sig_rl_size = msg2_json.readData_uint32("sig_rl_size");

        // sig_rl
        msg2_json.readData_uint8Array("sig_rl", req_msg2->sig_rl);

        // setting return msg2_size
        *msg2_size = sizeof(sgx_ra_msg2_t) + req_msg2->sig_rl_size;
    }
    else
    {
        return EH_ARGUMENTS_BAD;
    }
    return EH_OK;
}

/*
 * process will be return to Enroll APP msg3 json
 *  @param p_msg3 : will be parse sgx_ra_msg3_t
 *  @param quote_size : quote size
 *  @param retJsonObj : return msg3 json object
 *  retJsonObj : RetJsonObj
 *      {
 *          "mac" : array(int),
 *          "g_a" : Json::Value
 *              {
 *                  gx : array(int),
 *                  gy : array(int)
 *              },
 *          "ps_sec_prop" : Json::Value
 *              {
 *                  sgx_ps_sec_prop_desc : array(int)
 *              },
 *          "quote_size" : int,
 *          "quote" : array(int)
 *      }
 */
ehsm_status_t marshal_msg3_to_json(sgx_ra_msg3_t *p_msg3, RetJsonObj *retJsonObj, uint32_t quote_size)
{
    ehsm_status_t ret = EH_OK;

    if (p_msg3 == NULL || retJsonObj == NULL)
    {
        return EH_ARGUMENTS_BAD;
    }

    JsonObj msg3_json;

    std::string json_key; // json key use for string connect
    // mac
    msg3_json.addData_uint8Array("mac", p_msg3->mac, SGX_MAC_SIZE);

    // g_a
    json_key.clear();
    json_key = json_key + "g_a" + LAYERED_CHARACTER + "gx";
    msg3_json.addData_uint8Array(json_key, p_msg3->g_a.gx, SGX_ECP256_KEY_SIZE);
    json_key.clear();
    json_key = json_key + "g_a" + LAYERED_CHARACTER + "gy";
    msg3_json.addData_uint8Array(json_key, p_msg3->g_a.gy, SGX_ECP256_KEY_SIZE);

    // ps_sec_prop
    json_key.clear();
    json_key = json_key + "ps_sec_prop" + LAYERED_CHARACTER + "sgx_ps_sec_prop_desc";
    msg3_json.addData_uint8Array(json_key, p_msg3->ps_sec_prop.sgx_ps_sec_prop_desc, 256);

    // quote_size
    msg3_json.addData_uint32("quote_size", quote_size);

    // quote
    msg3_json.addData_uint8Array("quote", p_msg3->quote, quote_size);

    // setting return msg3_json
    retJsonObj->setResult(msg3_json);

    return ret;
}

/*
 * process receive att_result_msg json
 *  @param ra_att_result_msg : receive att_result_msg json string
 *  @param req_att_result_msg : return sample_ra_att_result_msg_t
 */
ehsm_status_t unmarshal_att_result_msg_from_json(std::string ra_att_result_msg, sample_ra_att_result_msg_t *req_att_result_msg)
{
    if (ra_att_result_msg.empty() || req_att_result_msg == NULL)
    {
        return EH_ARGUMENTS_BAD;
    }

    JsonObj att_result_msg_json;

    if (att_result_msg_json.parse(ra_att_result_msg))
    {
        std::string json_key;
        // platform_info_blob
        {
            std::string base_level_1;
            base_level_1 = base_level_1 + "platform_info_blob" + LAYERED_CHARACTER;
            // platform_info_blob &-> nonce
            {
                json_key.clear();
                json_key = base_level_1 + "nonce" + LAYERED_CHARACTER + "rand";
                att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.nonce.rand);
            }
            // platform_info_blob &-> quote_verification_result
            {
                json_key.clear();
                json_key = base_level_1 + "quote_verification_result";
                req_att_result_msg->platform_info_blob.quote_verification_result = (sgx_ql_qv_result_t)att_result_msg_json.readData_uint32(json_key);
            }
            // platform_info_blob &-> qve_report_info
            {
                std::string base_level_2 = base_level_1 + "qve_report_info" + LAYERED_CHARACTER;
                // platform_info_blob &-> qve_report_info &-> nonce
                {
                    json_key.clear();
                    json_key = base_level_2 + "nonce" + LAYERED_CHARACTER + "rand";
                    att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.nonce.rand);
                }
                // platform_info_blob &-> qve_report_info &-> app_enclave_target_info
                {
                    std::string base_level_3 = base_level_2 + "app_enclave_target_info" + LAYERED_CHARACTER;
                    // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> mr_enclave
                    json_key.clear();
                    json_key = base_level_3 + "mr_enclave" + LAYERED_CHARACTER + "m";
                    att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.mr_enclave.m);
                    // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> attributes
                    json_key.clear();
                    json_key = base_level_3 + "attributes" + LAYERED_CHARACTER + "flags";
                    req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.attributes.flags = att_result_msg_json.readData_uint64(json_key);
                    json_key.clear();
                    json_key = base_level_3 + "attributes" + LAYERED_CHARACTER + "xfrm";
                    req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.attributes.xfrm = att_result_msg_json.readData_uint64(json_key);
                    // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> reserved1
                    json_key.clear();
                    json_key = base_level_3 + "reserved1";
                    att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.reserved1);
                    // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> config_svn
                    json_key.clear();
                    json_key = base_level_3 + "config_svn";
                    req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.config_svn = att_result_msg_json.readData_uint16(json_key);
                    // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> misc_select
                    json_key.clear();
                    json_key = base_level_3 + "misc_select";
                    req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.misc_select = att_result_msg_json.readData_uint32(json_key);
                    // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> reserved2
                    json_key.clear();
                    json_key = base_level_3 + "reserved2";
                    att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.reserved2);
                    // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> config_id
                    json_key.clear();
                    json_key = base_level_3 + "config_id";
                    att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.config_id);
                    // platform_info_blob &-> qve_report_info &-> app_enclave_target_info &-> reserved3
                    json_key.clear();
                    json_key = base_level_3 + "reserved3";
                    att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.app_enclave_target_info.reserved3);
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
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.cpu_svn.svn);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> misc_select
                        json_key.clear();
                        json_key = base_level_4 + "misc_select";
                        req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.misc_select = att_result_msg_json.readData_uint32(json_key);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> reserved1
                        json_key.clear();
                        json_key = base_level_4 + "reserved1";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.reserved1);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> isv_ext_prod_id
                        json_key.clear();
                        json_key = base_level_4 + "isv_ext_prod_id";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.isv_ext_prod_id);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> attributes
                        json_key.clear();
                        json_key = base_level_4 + "attributes" + LAYERED_CHARACTER + "flags";
                        req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.attributes.flags = att_result_msg_json.readData_uint64(json_key);
                        json_key.clear();
                        json_key = base_level_4 + "attributes" + LAYERED_CHARACTER + "xfrm";
                        req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.attributes.xfrm = att_result_msg_json.readData_uint64(json_key);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> mr_enclave
                        json_key.clear();
                        json_key = base_level_4 + "mr_enclave" + LAYERED_CHARACTER + "m";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.mr_enclave.m);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> reserved2
                        json_key.clear();
                        json_key = base_level_4 + "reserved2";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.reserved2);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> mr_signer
                        json_key.clear();
                        json_key = base_level_4 + "mr_signer" + LAYERED_CHARACTER + "m";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.mr_signer.m);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> reserved3
                        json_key.clear();
                        json_key = base_level_4 + "reserved3";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.reserved3);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> config_id
                        json_key.clear();
                        json_key = base_level_4 + "config_id";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.config_id);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> isv_prod_id
                        json_key.clear();
                        json_key = base_level_4 + "isv_prod_id";
                        req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.isv_prod_id = att_result_msg_json.readData_uint16(json_key);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> isv_svn
                        json_key.clear();
                        json_key = base_level_4 + "isv_svn";
                        req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.isv_svn = att_result_msg_json.readData_uint16(json_key);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> config_svn
                        json_key.clear();
                        json_key = base_level_4 + "config_svn";
                        req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.config_svn = att_result_msg_json.readData_uint16(json_key);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> reserved4
                        json_key.clear();
                        json_key = base_level_4 + "reserved4";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.reserved4);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> isv_family_id
                        json_key.clear();
                        json_key = base_level_4 + "isv_family_id";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.isv_family_id);
                        // platform_info_blob &-> qve_report_info &-> qe_report &-> body &-> report_data
                        json_key.clear();
                        json_key = base_level_4 + "report_data" + LAYERED_CHARACTER + "d";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.body.report_data.d);
                    }
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> key_id
                    {
                        json_key.clear();
                        json_key = base_level_3 + "key_id" + LAYERED_CHARACTER + "id";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.key_id.id);
                    }
                    // platform_info_blob &-> qve_report_info &-> qe_report &-> mac
                    {
                        json_key.clear();
                        json_key = base_level_3 + "mac";
                        att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->platform_info_blob.qve_report_info.qe_report.mac);
                    }
                }
            }
        }
        // mac
        {
            json_key.clear();
            json_key = "mac";
            att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->mac);
        }
        // secret
        {
            std::string base_level_1;
            base_level_1 = base_level_1 + "secret" + LAYERED_CHARACTER;
            // secret &-> payload_size
            json_key.clear();
            json_key = base_level_1 + "payload_size";
            req_att_result_msg->secret.payload_size = att_result_msg_json.readData_uint32(json_key);
            // secret &-> reserved
            json_key.clear();
            json_key = base_level_1 + "reserved";
            att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->secret.reserved);
            // secret &-> payload_tag
            json_key.clear();
            json_key = base_level_1 + "payload_tag";
            att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->secret.payload_tag);
            // secret &-> payload
            json_key.clear();
            json_key = base_level_1 + "payload";
            att_result_msg_json.readData_uint8Array(json_key, req_att_result_msg->secret.payload);
        }
    }
    else
    {
        return EH_ARGUMENTS_BAD;
    }
    return EH_OK;
}
