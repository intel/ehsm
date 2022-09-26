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
#include "datatypes.h"
#include "base64.h"
#include "string.h"
#include "ehsm_provider.h"

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

/**
 * @brief set sigle data to json
 * @param data data
 * @param retJsonObj json
 * @param key the key of json data
 */
ehsm_status_t marshal_single_data_to_json(void *data, RetJsonObj &retJsonObj, std::string key)
{
    if (data == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    std::string data_base64;
    uint32_t data_size = 0;
    if (key == "cmk")
    {
        data_size = APPEND_SIZE_TO_KEYBLOB_T(((ehsm_keyblob_t *)data)->keybloblen);
        data_base64 = base64_encode((uint8_t *)data, data_size);
    }
    else
    {
        data_size = ((ehsm_data_t *)data)->datalen;
        data_base64 = base64_encode((uint8_t *)((ehsm_data_t *)data)->data, data_size);
    }
    if (data_base64.size() > 0)
    {
        retJsonObj.addData_string(key, data_base64);
    }
    return EH_OK;
}

ehsm_status_t marshal_multi_data_to_json(void *data1, void *data2, std::string key1,
                                         std::string key2, RetJsonObj &retJsonObj)
{
    ehsm_status_t ret = EH_OK;
    if (data1 == NULL || data2 == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    ret = marshal_single_data_to_json(data1, retJsonObj, key1);
    if (ret != EH_OK)
    {
        return ret;
    }
    ret = marshal_single_data_to_json(data2, retJsonObj, key2);

    return ret;
}

/**
 *  @brief get creatkey data from json
 *  @param payloadJson json data
 *  @param cmk creatkey data
 */
ehsm_status_t unmarshal_creatkey_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk)
{
    (*cmk) = (ehsm_keyblob_t *)malloc(sizeof(ehsm_keyblob_t));
    if ((*cmk) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }

    // storage common key properties into metadata of cmk
    if (payloadJson.getJson().isMember("keyspec"))
        (*cmk)->metadata.keyspec = (ehsm_keyspec_t)payloadJson.readData_uint32("keyspec");
    if (payloadJson.getJson().isMember("origin"))
        (*cmk)->metadata.origin = (ehsm_keyorigin_t)payloadJson.readData_uint32("origin");
    if (payloadJson.getJson().isMember("purpose"))
        (*cmk)->metadata.purpose = (ehsm_keypurpose_t)payloadJson.readData_uint32("purpose");
    if (payloadJson.getJson().isMember("padding_mode"))
        (*cmk)->metadata.padding_mode = (ehsm_padding_mode_t)payloadJson.readData_uint32("padding_mode");
    if (payloadJson.getJson().isMember("digest_mode"))
        (*cmk)->metadata.digest_mode = (ehsm_digest_mode_t)payloadJson.readData_uint32("digest_mode");
    (*cmk)->keybloblen = 0;

    if ((*cmk)->metadata.padding_mode == EH_PAD_RSA_NO)
    {
        return EH_KEYSPEC_INVALID;
    }

    return EH_OK;
}

/**
 * @brief get encrypt data from json
 * @param payloadJson json data
 * @param cmk encrypt data
 * @param plaint_data the plaintext
 * @param aad_data the additional data
 * @param cipher_data encrypted data
 */
ehsm_status_t unmarshal_encrypt_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                               ehsm_data_t **plaint_data, ehsm_data_t **aad_data,
                                               ehsm_data_t **cipher_data)
{
    std::string cmk_base64;
    std::string plaintext_base64;
    std::string aad_base64;
    if (payloadJson.getJson().isMember("cmk"))
        cmk_base64 = payloadJson.readData_string("cmk");
    if (payloadJson.getJson().isMember("plaintext"))
        plaintext_base64 = payloadJson.readData_string("plaintext");
    if (payloadJson.getJson().isMember("aad"))
        aad_base64 = payloadJson.readData_string("aad");

    if (cmk_base64.size() == 0 || plaintext_base64.size() == 0)
    {
        return EH_KEYSPEC_INVALID;
    }

    if (aad_base64.size() == 0)
    {
        aad_base64 = "";
    }

    std::string cmk_str = base64_decode(cmk_base64);
    std::string plaintext_str = base64_decode(plaintext_base64);
    std::string aad_str = base64_decode(aad_base64);
    int cmk_size = cmk_str.size();
    int plaintext_size = plaintext_str.size();
    int aad_datalen = aad_str.size();

    if (cmk_size == 0 || cmk_size > EH_CMK_MAX_SIZE)
    {
        return EH_KEYSPEC_INVALID;
    }
    if (plaintext_size == 0 || plaintext_size > EH_ENCRYPT_MAX_SIZE)
    {
        return EH_KEYSPEC_INVALID;
    }
    if (aad_datalen > EH_AAD_MAX_SIZE)
    {
        return EH_KEYSPEC_INVALID;
    }

    (*plaint_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_size));
    if ((*plaint_data) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }

    (*aad_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(aad_datalen));
    if ((*aad_data) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }

    (*cmk) = (ehsm_keyblob_t *)malloc(cmk_size);
    if ((*cmk) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    (*cipher_data) = (ehsm_data_t *)malloc(sizeof(ehsm_data_t));
    if ((*cipher_data) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }

    (*plaint_data)->datalen = plaintext_size;
    memcpy_s((*plaint_data)->data, plaintext_size, (uint8_t *)plaintext_str.data(), plaintext_size);

    (*aad_data)->datalen = aad_datalen;
    if (aad_datalen > 0)
    {
        memcpy_s((*aad_data)->data, aad_datalen, (uint8_t *)aad_str.data(), aad_datalen);
    }
    memcpy_s((*cmk), cmk_size, (ehsm_keyblob_t *)cmk_str.data(), cmk_size);
    (*cipher_data)->datalen = 0;

    return EH_OK;
}

/**
 * @brief get decrypt data from json
 * @param payloadJson json data
 * @param cmk key infomation
 * @param plaint_data decrypted data
 * @param aad_data the additional data
 * @param cipher_data ciphertext data
 */
ehsm_status_t unmarshal_decrypt_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                               ehsm_data_t **plaint_data, ehsm_data_t **aad_data,
                                               ehsm_data_t **cipher_data)
{

    std::string cmk_base64;
    std::string ciphertext_base64;
    std::string aad_base64;
    if (payloadJson.getJson().isMember("cmk"))
        cmk_base64 = payloadJson.readData_string("cmk");
    if (payloadJson.getJson().isMember("ciphertext"))
        ciphertext_base64 = payloadJson.readData_string("ciphertext");
    if (payloadJson.getJson().isMember("aad"))
        aad_base64 = payloadJson.readData_string("aad");

    if (cmk_base64.size() == 0 || ciphertext_base64.size() == 0)
    {
        printf("paramter invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (aad_base64.size() == 0)
    {
        aad_base64 = "";
    }

    std::string cmk_str = base64_decode(cmk_base64);
    std::string ciphertext_str = base64_decode(ciphertext_base64);
    std::string aad_str = base64_decode(aad_base64);
    int cmk_size = cmk_str.size();
    int ciphertext_size = ciphertext_str.size();
    int aad_datalen = aad_str.size();

    if (cmk_size == 0 || cmk_size > EH_CMK_MAX_SIZE)
    {
        printf("The cmk's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (ciphertext_size == 0 || ciphertext_size > EH_ENCRYPT_MAX_SIZE + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)
    {
        printf("The ciphertext's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (aad_datalen > EH_AAD_MAX_SIZE)
    {
        printf("The aad's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    (*plaint_data) = (ehsm_data_t *)malloc(sizeof(ehsm_data_t));
    if ((*plaint_data) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }

    (*aad_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(aad_datalen));
    if ((*aad_data) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }

    (*cmk) = (ehsm_keyblob_t *)malloc(cmk_size);
    if ((*cmk) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    (*cipher_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(ciphertext_size));
    if ((*cipher_data) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    (*cipher_data)->datalen = ciphertext_size;
    memcpy_s((*cipher_data)->data, ciphertext_size, (uint8_t *)ciphertext_str.data(), ciphertext_size);

    (*aad_data)->datalen = aad_datalen;
    if (aad_datalen > 0)
    {
        memcpy_s((*aad_data)->data, aad_datalen, (uint8_t *)aad_str.data(), aad_datalen);
    }
    memcpy_s((*cmk), cmk_size, (ehsm_keyblob_t *)cmk_str.data(), cmk_size);

    (*plaint_data)->datalen = 0;

    return EH_OK;
}

/**
 * @brief get asymmetric encrypt data from json
 * @param payloadJson json data
 * @param cmk key infomation
 * @param plaint_data plaintext data
 * @param cipher_data encrypted data
 */
ehsm_status_t unmarshal_asymmetric_encrypt_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                                          ehsm_data_t **plaint_data, ehsm_data_t **cipher_data)
{
    std::string cmk_base64;
    std::string plaintext_base64;

    if (payloadJson.getJson().isMember("cmk"))
        cmk_base64 = payloadJson.readData_string("cmk");
    if (payloadJson.getJson().isMember("plaintext"))
        plaintext_base64 = payloadJson.readData_string("plaintext");

    if (cmk_base64.empty() || plaintext_base64.empty())
    {
        printf("paramter invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    std::string cmk_str = base64_decode(cmk_base64);
    std::string plaintext_str = base64_decode(plaintext_base64);

    int cmk_size = cmk_str.size();
    int plaintext_size = plaintext_str.size();
    int plaintext_maxLen = 0;

    if (cmk_size == 0 || cmk_size > EH_CMK_MAX_SIZE)
    {
        printf("The cmk's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    (*cmk) = (ehsm_keyblob_t *)malloc(cmk_size);
    memcpy((*cmk), (uint8_t *)cmk_str.data(), cmk_size);

    switch ((*cmk)->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
    case EH_SM2:
        plaintext_maxLen = get_asymmetric_max_encrypt_plaintext_size((*cmk)->metadata.keyspec, (*cmk)->metadata.padding_mode);
        break;
    default:
        printf("The cmk's keyspec is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    if (plaintext_size == 0 || plaintext_size > plaintext_maxLen)
    {
        printf("The plaintext's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    if (!((*plaint_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(plaintext_size))))
    {
        return EH_KEYSPEC_INVALID;
    }
    (*plaint_data)->datalen = plaintext_size;
    memcpy((*plaint_data)->data, (uint8_t *)plaintext_str.data(), plaintext_size);

    if (!((*cipher_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0))))
    {
        return EH_KEYSPEC_INVALID;
    }
    (*cipher_data)->datalen = 0;

    return EH_OK;
}

/**
 * @brief get decrypt data from json
 * @param payloadJson json data
 * @param cmk key infomation
 * @param plaint_data decrypted data
 * @param cipher_data ciphertext data
 */
ehsm_status_t unmarshal_asymmetric_decrypt_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                                          ehsm_data_t **plaint_data, ehsm_data_t **cipher_data)
{
    std::string cmk_base64;
    std::string ciphertext_base64;

    if (payloadJson.getJson().isMember("cmk"))
        cmk_base64 = payloadJson.readData_string("cmk");
    if (payloadJson.getJson().isMember("ciphertext"))
        ciphertext_base64 = payloadJson.readData_string("ciphertext");

    if (cmk_base64.empty() || ciphertext_base64.empty())
    {
        printf("paramter invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    uint32_t ciphertext_maxLen;

    std::string cmk_str = base64_decode(cmk_base64);
    std::string ciphertext_str = base64_decode(ciphertext_base64);
    int cmk_size = cmk_str.size();
    int ciphertext_size = ciphertext_str.size();

    if (cmk_size == 0 || cmk_size > EH_CMK_MAX_SIZE)
    {
        printf("The cmk's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (!((*cmk) = (ehsm_keyblob_t *)malloc(cmk_size)))
    {
        return EH_KEYSPEC_INVALID;
    }
    memcpy((*cmk), (const uint8_t *)cmk_str.data(), cmk_size);

    if (!((*cipher_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(ciphertext_size))))
    {
        return EH_KEYSPEC_INVALID;
    }
    (*cipher_data)->datalen = ciphertext_size;
    memcpy((*cipher_data)->data, (uint8_t *)ciphertext_str.data(), ciphertext_size);

    if (!((*plaint_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0))))
    {
        return EH_KEYSPEC_INVALID;
    }
    (*plaint_data)->datalen = 0;

    return EH_OK;
}

ehsm_status_t unmarshal_generatedata_key_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                                        ehsm_data_t **aad_data, ehsm_data_t **plaint_datakey,
                                                        ehsm_data_t **cipher_datakey)
{
    std::string cmk_base64;
    std::string aad_base64;
    uint32_t keylen = 0;

    if (payloadJson.getJson().isMember("cmk"))
        cmk_base64 = payloadJson.readData_string("cmk");
    if (payloadJson.getJson().isMember("aad"))
        aad_base64 = payloadJson.readData_string("aad");
    if (payloadJson.getJson().isMember("keylen"))
        keylen = payloadJson.readData_uint32("keylen");

    if (cmk_base64.size() == 0)
    {
        printf("paramter invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (aad_base64.size() == 0)
    {
        aad_base64 = "";
    }

    std::string cmk_str = base64_decode(cmk_base64);
    std::string aad_str = base64_decode(aad_base64);
    int cmk_size = cmk_str.size();
    int aad_datalen = aad_str.size();

    if (cmk_size == 0 || cmk_size > EH_CMK_MAX_SIZE)
    {
        printf("The cmk's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (keylen == 0 || keylen > EH_DATA_KEY_MAX_SIZE)
    {
        printf("The keylen's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (aad_datalen > EH_AAD_MAX_SIZE)
    {
        printf("The aad's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    (*cmk) = (ehsm_keyblob_t *)malloc(cmk_size);
    if ((*cmk) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    memcpy((*cmk), (uint8_t *)cmk_str.data(), cmk_size);

    (*aad_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(aad_datalen));
    if ((*aad_data) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    (*aad_data)->datalen = aad_datalen;
    if (aad_datalen > 0)
    {
        memcpy((*aad_data)->data, (uint8_t *)aad_str.data(), aad_datalen);
    }
    (*plaint_datakey) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(keylen));
    if ((*plaint_datakey) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    (*plaint_datakey)->datalen = keylen;
    // memcpy((*plaint_datakey)->data, (uint8_t *)plaintext_base64.data(), keylen);

    if (!((*cipher_datakey) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0))))
    {
        return EH_KEYSPEC_INVALID;
    }

    (*cipher_datakey)->datalen = 0;

    return EH_OK;
}

ehsm_status_t unmarshal_exportdata_key_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                                      ehsm_data_t **aad, ehsm_data_t **olddatakey,
                                                      ehsm_keyblob_t **ukey, ehsm_data_t **newdatakey)
{
    std::string cmk_base64;
    std::string aad_base64;
    std::string ukey_base64;
    std::string olddatakey_base64;

    if (payloadJson.getJson().isMember("cmk"))
        cmk_base64 = payloadJson.readData_string("cmk");
    if (payloadJson.getJson().isMember("aad"))
        aad_base64 = payloadJson.readData_string("aad");
    if (payloadJson.getJson().isMember("olddatakey"))
        olddatakey_base64 = payloadJson.readData_string("olddatakey");
    if (payloadJson.getJson().isMember("ukey"))
        ukey_base64 = payloadJson.readData_string("ukey");

    if (cmk_base64.size() == 0 || ukey_base64.size() == 0 || olddatakey_base64.size() == 0)
    {
        if (cmk_base64.size() == 0)
        {
            printf("Paramter cmk invalid.\n");
        }
        else if (ukey_base64.size() == 0)
        {
            printf("Paramter ukey invalid.\n");
        }
        else
        {
            printf("Paramter olddatakey invalid.\n");
        }
        return EH_KEYSPEC_INVALID;
    }
    if (aad_base64.size() == 0)
    {
        aad_base64 = "";
    }

    std::string cmk_str = base64_decode(cmk_base64);
    std::string ukey_str = base64_decode(ukey_base64);
    std::string aad_str = base64_decode(aad_base64);
    std::string olddatakey_str = base64_decode(olddatakey_base64);

    // string2ehsm_keyblob_t and string2ehsm_data_t
    int cmk_size = cmk_str.size();
    int ukey_size = ukey_str.size();
    int aad_datalen = aad_str.size();
    int olddatakey_datalen = olddatakey_str.size();

    if (cmk_size == 0 || cmk_size > EH_CMK_MAX_SIZE)
    {
        printf("The cmk's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    if (ukey_size == 0 || ukey_size > EH_CMK_MAX_SIZE)
    {
        printf("The ukey's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (aad_datalen > EH_AAD_MAX_SIZE)
    {
        printf("The aad's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    if (olddatakey_datalen == 0 || olddatakey_datalen > EH_DATA_KEY_MAX_SIZE)
    {
        printf("The olddatakey's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    (*cmk) = (ehsm_keyblob_t *)malloc(cmk_size);
    if ((*cmk) == NULL)
    {
        printf("cmk malloc exception.\n");
        return EH_KEYSPEC_INVALID;
    }
    else
    {
        memcpy_s((*cmk), cmk_size, (uint8_t *)cmk_str.data(), cmk_size);
        if (APPEND_SIZE_TO_KEYBLOB_T((*cmk)->keybloblen) != cmk_size)
        {
            printf("cmk parse exception.\n");
            return EH_KEYSPEC_INVALID;
        }
    }
    (*ukey) = (ehsm_keyblob_t *)malloc(ukey_size);
    if ((*ukey) == NULL)
    {
        printf("ukey malloc exception.\n");
        return EH_KEYSPEC_INVALID;
    }
    else
    {
        memcpy_s((*ukey), ukey_size, (uint8_t *)ukey_str.data(), ukey_size);
        if (APPEND_SIZE_TO_KEYBLOB_T((*ukey)->keybloblen) != ukey_size)
        {
            printf("ukey parse exception.\n");
            return EH_KEYSPEC_INVALID;
        }
    }

    if (aad_datalen != 0)
    {
        (*aad) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(aad_datalen));
        if ((*aad) == NULL)
        {
            return EH_KEYSPEC_INVALID;
        }
        else
        {
            (*aad)->datalen = aad_datalen;
            memcpy_s((*aad)->data, aad_datalen, (uint8_t *)aad_str.data(), aad_datalen);
        }
    }
    else if (aad_datalen == 0)
    {
        (*aad)->datalen = aad_datalen;
    }
    (*olddatakey) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(olddatakey_datalen));
    if ((*olddatakey) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }

    (*olddatakey)->datalen = olddatakey_datalen;
    memcpy_s((*olddatakey)->data, olddatakey_datalen, (uint8_t *)olddatakey_str.data(), olddatakey_datalen);

    (*newdatakey) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));
    if ((*newdatakey) == NULL)
    {
        return EH_KEYSPEC_INVALID;
    }
    else
    {
        (*newdatakey)->datalen = 0;
    }

    return EH_OK;
}

ehsm_status_t unmarshal_sign_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                            ehsm_data_t **digest_data,
                                            ehsm_data_t **signature)
{
    std::string cmk_base64;
    std::string digest_base64;

    if (payloadJson.getJson().isMember("cmk"))
        cmk_base64 = payloadJson.readData_string("cmk");
    if (payloadJson.getJson().isMember("digest"))
        digest_base64 = payloadJson.readData_string("digest");

    if (cmk_base64.size() == 0 || digest_base64.size() == 0)
    {
        printf("paramter invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    std::string cmk_str = base64_decode(cmk_base64);
    std::string digest_str = base64_decode(digest_base64);
    std::string signature_base64;
    int cmk_size = cmk_str.size();
    int digest_size = digest_str.size();

    if (cmk_size == 0 || cmk_size > EH_CMK_MAX_SIZE)
    {
        printf("The cmk's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (digest_size == 0 || digest_size > RSA_OAEP_4096_DIGEST_SIZE)
    {
        printf("The digest's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    (*cmk) = (ehsm_keyblob_t *)malloc(cmk_size);
    memcpy((*cmk), (const uint8_t *)cmk_str.data(), cmk_size);
    if ((*cmk) == NULL)
    {
        printf("Server exception.\n");
        return EH_KEYSPEC_INVALID;
    }
    (*digest_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(digest_size));
    (*digest_data)->datalen = digest_size;
    memcpy((*digest_data)->data, (uint8_t *)digest_str.data(), digest_size);
    if ((*digest_data) == NULL)
    {
        printf("Server exception.\n");
        return EH_KEYSPEC_INVALID;
    }
    (*signature) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(0));

    // get signature datalen
    (*signature)->datalen = 0;

    return EH_OK;
}

ehsm_status_t unmarshal_verify_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                              ehsm_data_t **digest_data,
                                              ehsm_data_t **signature_data)
{
    std::string cmk_base64;
    std::string digest_base64;
    std::string signature_base64;

    if (payloadJson.getJson().isMember("cmk"))
        cmk_base64 = payloadJson.readData_string("cmk");
    if (payloadJson.getJson().isMember("digest"))
        digest_base64 = payloadJson.readData_string("digest");
    if (payloadJson.getJson().isMember("signature"))
        signature_base64 = payloadJson.readData_string("signature");

    if (cmk_base64.size() == 0 || digest_base64.size() == 0 || signature_base64.size() == 0)
    {
        printf("paramter invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    std::string cmk_str = base64_decode(cmk_base64);
    std::string signature_str = base64_decode(signature_base64);
    std::string digest_str = base64_decode(digest_base64);
    int cmk_size = cmk_str.size();
    int digest_size = digest_str.size();
    int signature_size = signature_str.size();

    if (cmk_size == 0 || cmk_size > EH_CMK_MAX_SIZE)
    {
        printf("The cmk's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (digest_size == 0 || digest_size > RSA_OAEP_4096_DIGEST_SIZE)
    {
        printf("The digest's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }
    if (signature_size == 0 || signature_size > RSA_OAEP_4096_SIGNATURE_SIZE)
    {
        printf("The signature's length is invalid.\n");
        return EH_KEYSPEC_INVALID;
    }

    (*cmk) = (ehsm_keyblob_t *)malloc(cmk_size);
    memcpy((*cmk), (const uint8_t *)cmk_str.data(), cmk_size);
    if ((*cmk) == NULL)
    {
        printf("Server exception.\n");
        return EH_KEYSPEC_INVALID;
    }
    (*digest_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(digest_size));
    (*digest_data)->datalen = digest_size;
    memcpy((*digest_data)->data, (uint8_t *)digest_str.data(), digest_size);
    if ((*digest_data) == NULL)
    {
        printf("Server exception.\n");
        return EH_KEYSPEC_INVALID;
    }
    (*signature_data) = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(signature_size));
    (*signature_data)->datalen = signature_size;
    memcpy((*signature_data)->data, (uint8_t *)signature_str.data(), signature_size);
    if ((*signature_data) == NULL)
    {
        printf("Server exception.\n");
        return EH_KEYSPEC_INVALID;
    }
    return EH_OK;
}