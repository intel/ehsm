/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <error.h>
#include <socket_client.h>


using namespace std;

namespace socket_client {

static bool SendAll(int32_t sock, const void *data, int32_t data_size)
{
    const char *data_ptr = (const char*) data;
    int32_t bytes_sent;

    while (data_size > 0)
    {
        bytes_sent = send(sock, data_ptr, data_size, 0);
        if (bytes_sent < 1)
            return false;

        data_ptr += bytes_sent;
        data_size -= bytes_sent;
    }

    return true;
}

static bool RecvAll(int32_t sock, void *data, int32_t data_size)
{
    char *data_ptr = (char*) data;
    int32_t bytes_recv;

    while (data_size > 0)
    {
        bytes_recv = recv(sock, data_ptr, data_size, 0);
        if (bytes_recv == 0) {
            fprintf(stderr, "the server side may closed...\n");
            return true;
        }
        if (bytes_recv < 0) {
            fprintf(stderr, "failed to read data\n");
            return false;
        }

        data_ptr += bytes_recv;
        data_size -= bytes_recv;
    }

    return true;
}

errno_t memcpy_s(
    void *dest,
    size_t numberOfElements,
    const void *src,
    size_t count)
{
    if(numberOfElements<count)
        return -1;
    memcpy(dest, src, count);
    return 0;
}

SocketClient::~SocketClient() {
    Close();
}


void SocketClient::FreeRespBuf(ra_samp_response_header_t *resp)
{
    if(resp!=NULL)
    {
        free(resp);
    }
}

int32_t SocketClient::SendAndRecvMsg(  const ra_samp_request_header_t *p_req,
    ra_samp_response_header_t **p_resp)
{
    ra_samp_response_header_t* out_msg;
    int req_size, resp_size = 0;
    int32_t err = NO_ERROR;

    if((NULL == p_req) ||
        (NULL == p_resp))
    {
        return -1;
    }

    /* Send a message to server */
    req_size = sizeof(ra_samp_request_header_t)+p_req->size;

    if (!SendAll(_sockFd, &req_size, sizeof(req_size))) {
        fprintf(stderr, "send req_size failed\n");
        err = ERR_GENERIC;
        goto out;
    }
    if (!SendAll(_sockFd, p_req, req_size)) {
        fprintf(stderr, "send req buffer failed\n");
        err = ERR_GENERIC;
        goto out;
    }

    /* Receive a message from server */
    if (!RecvAll(_sockFd, &resp_size, sizeof(resp_size))) {
        fprintf(stderr, "failed to get the resp size\n");
        err = ERR_GENERIC;
        goto out;
    }

    if (resp_size <= 0) {
        fprintf(stderr, "no msg need to read\n");
        err = ERR_GENERIC;
        goto out;
    }
    out_msg = (ra_samp_response_header_t *)malloc(resp_size);
    if (!out_msg) {
        fprintf(stderr, "allocate out_msg failed\n");
        err = ERR_NO_MEMORY;
        goto out;
    }
    if (!RecvAll(_sockFd, out_msg, resp_size)) {
        fprintf(stderr, "failed to get the data\n");
        err = ERR_GENERIC;
        goto out;
    }

    *p_resp = out_msg;
out:
    return err;
}

void SocketClient::Open() {
    int32_t retry_count = 360;
    struct sockaddr_in serAddr;
    int32_t sockFd = -1;

    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockFd < 0) {
        fprintf(stderr, "Create socket failed\n");
        exit(1);
    }
    bzero(&serAddr, sizeof(serAddr));
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(server_port);
    serAddr.sin_addr.s_addr = inet_addr(server_ip_addr);

    do {
        if(connect(sockFd, (struct sockaddr*)&serAddr, sizeof(serAddr)) >= 0) {
            fprintf(stderr, "Connect socket server suucess!\n");
            break;
        }
        else if (retry_count > 0) {
            fprintf(stderr, "Connect socket server failed, sleep 0.5s and try again...\n");
            usleep(500000); // 0.5 s
        }
        else {
            fprintf(stderr, "Fail to connect socket server.\n");
            return;
        }
    } while (retry_count-- > 0);

    _sockFd = sockFd;
}

void SocketClient::Close() {
    close(_sockFd);
}

bool SocketClient::IsOpen()  {
    if (_sockFd > 0)
        return true;
    else
        return false;
}

} // namespace keymaster

