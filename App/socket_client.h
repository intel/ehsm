/*
* Copyright (C) 2020-2021 Intel Corporation
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

#ifndef SOCKET_CLIENT_H
#define SOCKET_CLIENT_H

#include <cstdint>
#include <vector>
#include <memory>

#include "sample_ra_msg.h"

using namespace std;

namespace socket_client {

const char deploy_ip_addr[] = "10.239.158.138";
const uint32_t deploy_port = 8888;
const uint32_t provisioning_port = 8887;

#define ENCLAVE_PATH "enclave.signed.so"

#define _T(x) x

#ifndef INT_MAX
#define INT_MAX     0x7fffffff 
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif
errno_t memcpy_s(void *dest,
        size_t numberOfElements,
        const void *src,
        size_t count);

/* Opens a connection to the socket server */
void Connect();

/* Closes the connection to socket server */
void DisConnect();

/* Check the status of the connection */
bool IsConnected();

void Initialize();

/* Send and Recv msg to/from socket server */
int SendAndRecvMsg(const ra_samp_request_header_t *req,
                        ra_samp_response_header_t **p_resp);

int RetreiveDomainKey(const ra_samp_request_header_t *req,
                    ra_samp_response_header_t **p_resp);

}

#endif

