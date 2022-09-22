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

#ifndef _EHSM_MARSHAL_H_
#define _EHSM_MARSHAL_H_

#include "serialize.h"
#include "sample_ra_msg.h"
#include "json_utils.h"

#include <string>

/*
 * process receive msg2 json string to sgx_ra_msg2_t
 *  @param ra_msg2 : receive msg2 json string
 *  @param req_msg2 : return sgx_ra_msg2_t
 *  @param msg2_size : return sgx_ra_msg2_t real size
 */
ehsm_status_t unmarshal_msg2_from_json(std::string ra_msg2, sgx_ra_msg2_t *req_msg2, uint32_t *msg2_size);

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
ehsm_status_t marshal_msg3_to_json(sgx_ra_msg3_t *p_msg3, RetJsonObj *retJsonObj, uint32_t quote_size);

/*
 * process receive att_result_msg json
 *  @param ra_att_result_msg : receive att_result_msg json string
 *  @param req_att_result_msg : return sample_ra_att_result_msg_t
 */
ehsm_status_t unmarshal_att_result_msg_from_json(std::string ra_att_result_msg, sample_ra_att_result_msg_t *req_att_result_msg);

ehsm_status_t unmarshal_creatkey_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk);

ehsm_status_t marshal_single_data_to_json(void *data, RetJsonObj &retJsonObj, std::string key);

ehsm_status_t marshal_multi_data_to_json(void *data1, void *data2, std::string key1,
                                         std::string key2, RetJsonObj &retJsonObj);

ehsm_status_t unmarshal_encrypt_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                               ehsm_data_t **plaint_data, ehsm_data_t **aad_data,
                                               ehsm_data_t **cipher_data);

ehsm_status_t unmarshal_decrypt_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                               ehsm_data_t **plaint_data, ehsm_data_t **aad_data,
                                               ehsm_data_t **cipher_data);

ehsm_status_t unmarshal_asymmetric_encrypt_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                                          ehsm_data_t **plaint_data, ehsm_data_t **cipher_data);

ehsm_status_t unmarshal_asymmetric_decrypt_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                                          ehsm_data_t **plaint_data, ehsm_data_t **cipher_data);

ehsm_status_t unmarshal_generatedata_key_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                                        ehsm_data_t **aad_data, ehsm_data_t **plaint_datakey,
                                                        ehsm_data_t **cipher_datakey);

ehsm_status_t unmarshal_exportdata_key_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                                      ehsm_data_t **aad_data, ehsm_data_t **olddatakey,
                                                      ehsm_keyblob_t **ukey, ehsm_data_t **newdatakey);

ehsm_status_t unmarshal_sign_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                            ehsm_data_t **digest_data,
                                            ehsm_data_t **signature);

ehsm_status_t unmarshal_verify_data_from_json(JsonObj payloadJson, ehsm_keyblob_t **cmk,
                                              ehsm_data_t **digest_data,
                                              ehsm_data_t **signature_data);

#endif