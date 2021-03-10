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

using namespace std;

namespace socket_client {

const uint32_t SOCKET_RECV_BUF_SIZE = 2 * 4096;
const uint32_t SOCKET_SEND_BUF_SIZE = 4096;

const char server_ip_addr[] = "127.0.0.1";
const uint32_t server_port = 8888;


typedef struct socket_ipc_msg {
    uint32_t cmd;
    uint8_t payload[0];
} socket_ipc_msg_t;

/* Enum for all possible message types between the ISV app and
 * the ISV SP. Requests and responses in the remote attestation
 * sample.
 */
typedef enum _ra_msg_type_t
{
     TYPE_RA_MSG0 = 0,
     TYPE_RA_MSG1,
     TYPE_RA_MSG2,
     TYPE_RA_MSG3,
     TYPE_RA_ATT_RESULT,
}ra_msg_type_t;

/* Enum for all possible message types between the SP and IAS.
 * Network communication is not simulated in the remote
 * attestation sample.  Currently these aren't used.
 */
typedef enum _ias_msg_type_t
{
     TYPE_IAS_ENROLL,
     TYPE_IAS_GET_SIGRL,
     TYPE_IAS_SIGRL,
     TYPE_IAS_ATT_EVIDENCE,
     TYPE_IAS_ATT_RESULT,
}ias_msg_type_t;

#pragma pack(1)

typedef struct _ra_samp_request_header_t{
    uint8_t  type;     /* set to one of ra_msg_type_t*/
    uint32_t size;     /*size of request body*/
    uint8_t  align[3];
    uint8_t body[];
}ra_samp_request_header_t;

typedef struct _ra_samp_response_header_t{
    uint8_t  type;      /* set to one of ra_msg_type_t*/
    uint8_t  status[2];
    uint32_t size;      /*size of the response body*/
    uint8_t  align[1];
    uint8_t  body[];
}ra_samp_response_header_t;

#pragma pack()

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif
errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src,
                 size_t count);

class SocketClient {
public:
    SocketClient() = default;
    ~SocketClient();

    /* Opens a connection to the socket server */
    void Open();

    /* Closes the connection to socket server */
    void Close();

    /* Check the status of the connection */
    bool IsOpen();

    /* Send and Recv msg to/from socket server */
    int SendAndRecvMsg(    const ra_samp_request_header_t *req,
                            ra_samp_response_header_t **p_resp);

    void FreeRespBuf(ra_samp_response_header_t *resp);
private:
    int32_t _sockFd = -1;
};

}

#endif

