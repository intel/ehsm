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


#include "sgx_trts.h"
#include "sgx_utils.h"
//#include "EnclaveMessageExchange.h"
#include "sgx_eid.h"
#include "error_codes.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "elog_utils.h"
#include <map>

#include "sgx_dh.h"

#include "enclave_la.h"
#include "marshal.h"

#include "sgx_tcrypto.h"

void log_printf(uint32_t log_level, const char* filename, uint32_t line, const char *fmt, ...);

#define MAX_SESSION_COUNT  16

//number of open sessions
uint32_t g_session_count = 0;

//Array of open session ids
session_id_tracker_t *g_session_id_tracker[MAX_SESSION_COUNT];

extern uint8_t g_domain_key[SGX_DOMAIN_KEY_SIZE];

//Map between the session id and the session information associated with that particular session
std::map<uint32_t, dh_session_t>g_dest_session_info_map;

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

#define UNUSED(val) (void)(val)


// this is expected initiator's MRSIGNER for demonstration purpose 
sgx_measurement_t g_initiator_mrsigner = {
        {
                0xc3, 0x04, 0x46, 0xb4, 0xbe, 0x9b, 0xaf, 0x0f, 0x69, 0x72, 0x84, 0x23, 0xea, 0x61, 0x3e, 0xf8,
                0x1a, 0x63, 0xe7, 0x2a, 0xcf, 0x74, 0x39, 0xfa, 0x05, 0x49, 0x00, 0x1f, 0xd5, 0x48, 0x28, 0x35
        }
};

/* Function Description:
 *   this is to verify peer enclave's identity
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable that it should be INITIALIZED and without DEBUG attribute (except the project is built with DEBUG option)
 * */
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
        return INVALID_PARAMETER_ERROR;
   
    // check peer enclave's MRSIGNER
    if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_initiator_mrsigner, sizeof(sgx_measurement_t)))
        return ENCLAVE_TRUST_ERROR;

    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        return ENCLAVE_TRUST_ERROR;

    // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
    if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
        return ENCLAVE_TRUST_ERROR;
#endif
    
    return SUCCESS;
}


/* Function Description: Operates on the input secret and generates the output secret */
uint32_t get_message_exchange_response(uint32_t cmd_id, uint8_t** out, uint32_t* out_size)
{


    switch(cmd_id) {
        case MESSAGE_EXCHANGE_CMD_DK:
            log_d("Receive cmd: MESSAGE_EXCHANGE_CMD_DK.\n");
            uint8_t *tmp_data;

            tmp_data = (uint8_t*)malloc(SGX_DOMAIN_KEY_SIZE);
            if (!tmp_data)
                return MALLOC_ERROR;


            memcpy(tmp_data, g_domain_key, SGX_DOMAIN_KEY_SIZE);
            *out_size = SGX_DOMAIN_KEY_SIZE;
            *out = tmp_data;
            break;
        default:
            break;
    }

    return 0;
}

/* Function Description: Generates the response from the request message 
 * Parameter Descriptin:
 * [input] decrtyped_data: pointer to decrypted data
 * [output] resp_buffer: pointer to response message, which is allocated in this function 
 * [output] resp_length: this is response length */
extern "C" uint32_t message_exchange_response_generator(uint8_t* decrypted_data,
                                              uint8_t** resp_buffer,
                                               uint32_t* resp_length)
{
    ms_in_msg_exchange_t *ms;

    uint32_t cmd_id;
    uint8_t* out = NULL;
    uint32_t out_size = 0;
    
    if(!decrypted_data || !resp_length)
        return INVALID_PARAMETER_ERROR;
    
    ms = (ms_in_msg_exchange_t *)decrypted_data;

    if(umarshal_message_exchange_request(&cmd_id,ms) != SUCCESS)
        return ATTESTATION_ERROR;

    get_message_exchange_response(cmd_id, &out, &out_size);
    if(!out || !out_size) {
        return INVALID_PARAMETER;
    }

    if(marshal_message_exchange_response(resp_buffer, resp_length, out, out_size) != SUCCESS)
        return MALLOC_ERROR;

    SAFE_FREE(out);
    return SUCCESS;
}


//Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    if(!session_id)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //if the session structure is untintialized, set that as the next session ID
    for (int i = 0; i < MAX_SESSION_COUNT; i++)
    {
        if (g_session_id_tracker[i] == NULL)
        {
            *session_id = i;
            return status;
        }
    }

    status = NO_AVAILABLE_SESSION_ERROR;

    return status;

}

//Create a session with the destination enclave

//Handle the request from Source Enclave for a session
extern "C" ATTESTATION_STATUS enclave_la_session_request(sgx_dh_msg1_t *dh_msg1,
                          uint32_t *session_id )
{
    // initialize all members manually to avoid 
    // "no missing initializer for member" warning
    dh_session_t session_info = {
        .session_id = 0,
        .status = 0,
        .in_progress = {0},
    };
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;

    if(!session_id || !dh_msg1)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return status;
    }

    //get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(session_id)) != SUCCESS)
        return status; //no more sessions available

    //Allocate memory for the session id tracker
    g_session_id_tracker[*session_id] = (session_id_tracker_t *)malloc(sizeof(session_id_tracker_t));
    if(!g_session_id_tracker[*session_id])
    {
        return MALLOC_ERROR;
    }

    memset(g_session_id_tracker[*session_id], 0, sizeof(session_id_tracker_t));
    g_session_id_tracker[*session_id]->session_id = *session_id;
    session_info.status = IN_PROGRESS;

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(g_session_id_tracker[*session_id]);
        return status;
    }
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    //Store the session information under the correspoding source enlave id key
    g_dest_session_info_map.insert(std::pair<uint32_t, dh_session_t>(*session_id, session_info));

    return status;
}

//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
extern "C" ATTESTATION_STATUS enclave_la_exchange_report(sgx_dh_msg2_t *dh_msg2,
                          sgx_dh_msg3_t *dh_msg3,
                          uint32_t session_id)
{

    sgx_key_128bit_t dh_aek;   // Session key
    dh_session_t *session_info;
    ATTESTATION_STATUS status = SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t initiator_identity;

    if(!dh_msg2 || !dh_msg3)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    do
    {
        //Retreive the session information for the corresponding source enclave id
        std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
        if(it != g_dest_session_info_map.end())
        {
            session_info = &it->second;
        }
        else
        {
            status = INVALID_SESSION;
            break;
        }

        if(session_info->status != IN_PROGRESS)
        {
            status = INVALID_SESSION;
            break;
        }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        dh_msg3->msg3_body.additional_prop_length = 0;
        //Process message 2 from source enclave and obtain message 3
        sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2,
                                                       dh_msg3,
                                                       &sgx_dh_session,
                                                       &dh_aek,
                                                       &initiator_identity);
        if(SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }

        //Verify source enclave's trust
          if(verify_peer_enclave_trust(&initiator_identity) != SUCCESS)
        {
            return INVALID_SESSION;
        }

        //save the session ID, status and initialize the session nonce
        session_info->session_id = session_id;
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
        g_session_count++;
    }while(0);

    if(status != SUCCESS)
    {
        enclave_la_end_session(session_id);
    }

    return status;
}

//Process the request from the Source enclave and send the response message back to the Source enclave
extern "C" ATTESTATION_STATUS enclave_la_generate_response(secure_message_t* req_message,
                                     uint32_t req_message_size,
                                     uint32_t max_payload_size,
                                     secure_message_t* resp_message,
                                     uint32_t resp_message_size,
                				     uint32_t session_id)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    ms_in_msg_exchange_t * ms;
    uint32_t resp_data_length;
    uint32_t resp_message_calc_size;
    uint8_t* resp_data;
    uint8_t l_tag[TAG_SIZE];
    uint32_t header_size, expected_payload_size;
    dh_session_t *session_info;
    secure_message_t* temp_resp_message;
    uint32_t ret;
    sgx_status_t status;

    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!req_message || !resp_message)
    {
        return INVALID_PARAMETER_ERROR;
    }

    //Get the session information from the map corresponding to the source enclave id
    std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if(it != g_dest_session_info_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        return INVALID_SESSION;
    }

    if(session_info->status != ACTIVE)
    {
        return INVALID_SESSION;
    }

    //Set the decrypted data length to the payload size obtained from the message
    decrypted_data_length = req_message->message_aes_gcm_data.payload_size;

    header_size = sizeof(secure_message_t);
    expected_payload_size = req_message_size - header_size;

    //Verify the size of the payload
    if(expected_payload_size != decrypted_data_length)
        return INVALID_PARAMETER_ERROR;

    memset(&l_tag, 0, 16);
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data)
    {
            return MALLOC_ERROR;
    }

    memset(decrypted_data, 0, decrypted_data_length);

    //Decrypt the request message payload from source enclave
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, req_message->message_aes_gcm_data.payload,
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), &(req_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length,
                &req_message->message_aes_gcm_data.payload_tag);

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(decrypted_data);
        return status;
    }

    //Casting the decrypted data to the marshaling structure type to obtain type of request (generic message exchange/enclave to enclave call)
    ms = (ms_in_msg_exchange_t *)decrypted_data;

    // Verify if the nonce obtained in the request is equal to the session nonce
    if(*((uint32_t*)req_message->message_aes_gcm_data.reserved) != session_info->active.counter || *((uint32_t*)req_message->message_aes_gcm_data.reserved) > ((uint32_t)-2))
    {
        SAFE_FREE(decrypted_data);
        return INVALID_PARAMETER_ERROR;
    }

    if(ms->msg_type == MESSAGE_EXCHANGE)
    {
        //Call the generic secret response generator for message exchange
        ret = message_exchange_response_generator((uint8_t*)decrypted_data, &resp_data, &resp_data_length);
        if(ret !=0)
        {
            SAFE_FREE(decrypted_data);
            SAFE_FREE(resp_data);
            return INVALID_SESSION;
        }
    }
    else
    {
        SAFE_FREE(decrypted_data);
        return INVALID_REQUEST_TYPE_ERROR;
    }


    if(resp_data_length > max_payload_size)
    {
        SAFE_FREE(resp_data);
        SAFE_FREE(decrypted_data);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    resp_message_calc_size = sizeof(secure_message_t)+ resp_data_length;

    if(resp_message_calc_size > resp_message_size)
    {
        SAFE_FREE(resp_data);
        SAFE_FREE(decrypted_data);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    //Code to build the response back to the Source Enclave
    temp_resp_message = (secure_message_t*)malloc(resp_message_calc_size);
    if(!temp_resp_message)
    {
            SAFE_FREE(resp_data);
            SAFE_FREE(decrypted_data);
            return MALLOC_ERROR;
    }

    memset(temp_resp_message,0,sizeof(secure_message_t)+ resp_data_length);
    const uint32_t data2encrypt_length = (uint32_t)resp_data_length;
    temp_resp_message->session_id = session_info->session_id;
    temp_resp_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    //Increment the Session Nonce (Replay Protection)
    session_info->active.counter = session_info->active.counter + 1;

    //Set the response nonce as the session nonce
    memcpy(&temp_resp_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));

    //Prepare the response message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)resp_data, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.reserved)),
                sizeof(temp_resp_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                &(temp_resp_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(resp_data);
        SAFE_FREE(decrypted_data);
        SAFE_FREE(temp_resp_message);
        return status;
    }

    memset(resp_message, 0, sizeof(secure_message_t)+ resp_data_length);
    memcpy(resp_message, temp_resp_message, sizeof(secure_message_t)+ resp_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(resp_data);
    SAFE_FREE(temp_resp_message);

    return SUCCESS;
}


//Respond to the request from the Source Enclave to close the session
extern "C" ATTESTATION_STATUS enclave_la_end_session(uint32_t session_id)
{
    ATTESTATION_STATUS status = SUCCESS;
    int i;
    dh_session_t session_info;
    //uint32_t session_id;

    //Get the session information from the map corresponding to the source enclave id
    std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if(it != g_dest_session_info_map.end())
    {
        session_info = it->second;
    }
    else
    {
        return INVALID_SESSION;
    }

    //session_id = session_info.session_id;
    //Erase the session information for the current session
    g_dest_session_info_map.erase(session_id);

    //Update the session id tracker
    if (g_session_count > 0)
    {
        //check if session exists
        for (i=1; i <= MAX_SESSION_COUNT; i++)
        {
            if(g_session_id_tracker[i-1] != NULL && g_session_id_tracker[i-1]->session_id == session_id)
            {
                memset(g_session_id_tracker[i-1], 0, sizeof(session_id_tracker_t));
                SAFE_FREE(g_session_id_tracker[i-1]);
                g_session_count--;
                break;
            }
        }
    }

    return status;

}
