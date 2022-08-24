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

#ifndef _MARSHAL_H__
#define _MARSHAL_H__
#include "stdint.h"
#include "datatypes.h"

typedef struct _param_struct_t
{
    uint32_t var1;
    uint32_t var2;
}param_struct_t;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t marshal_input_parameters_e3_foo1(uint32_t target_fn_id, uint32_t msg_type, param_struct_t *p_struct_var, uint8_t** marshalled_buff, uint32_t* marshalled_buff_len);
uint32_t unmarshal_retval_and_output_parameters_e3_foo1(uint8_t* out_buff, param_struct_t *p_struct_var, uint8_t** retval);
uint32_t unmarshal_input_parameters_e2_foo1(uint32_t* var1, uint32_t* var2, ms_in_msg_exchange_t* ms);
uint32_t marshal_retval_and_output_parameters_e2_foo1(uint8_t** resp_buffer, uint32_t* resp_length, uint32_t retval);
uint32_t marshal_message_exchange_request(uint32_t target_fn_id, uint32_t msg_type, uint32_t secret_data, uint8_t** marshalled_buff, uint32_t* marshalled_buff_len);
uint32_t umarshal_message_exchange_request(uint32_t* inp_secret_data, ms_in_msg_exchange_t* ms);
uint32_t marshal_message_exchange_response(uint8_t** resp_buffer, uint32_t* resp_length, uint8_t* out, uint32_t out_size);
uint32_t umarshal_message_exchange_response(uint8_t* out_buff, uint8_t** secret, uint32_t* secret_len);


#ifdef __cplusplus
 }
#endif
#endif

