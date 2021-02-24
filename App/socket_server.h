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

#ifndef SOCKET_SERVER_H
#define SOCKET_SERVER_H

#include <cstdint>
#include <vector>
#include <memory>

using namespace std;


namespace socket_server {

const uint32_t SOCKET_RECV_BUF_SIZE = 2 * 4096;
const uint32_t SOCKET_SEND_BUF_SIZE = 4096;

const uint32_t server_port = 8888;

// Commands
enum socket_ipc_command {
    KMS_RETRIEVE_DOMAINKEY = 0,
    KMS_SETUP_TRTUST_CHNNEL = 1,
};

typedef struct socket_ipc_msg {
    uint32_t cmd;
    uint8_t payload[0];
} socket_ipc_msg_t;


class SocketServer {
public:
    SocketServer() = default;
    ~SocketServer() = default;
    /* initialize the socket handle */
    void Initialize();

};

}

#endif

