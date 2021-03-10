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

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<errno.h>
#include<pthread.h>

#include<error.h>
#include<socket_server.h>

namespace socket_server {

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

static char* hexToCharIP(struct in_addr addrIP)
{
    char* ip;
    unsigned int intIP;
    memcpy(&intIP, &addrIP,sizeof(unsigned int));
    int a = (intIP >> 24) & 0xFF;
    int b = (intIP >> 16) & 0xFF;
    int c = (intIP >> 8) & 0xFF;
    int d = intIP & 0xFF;
    if((ip = (char*)malloc(16*sizeof(char))) == NULL) {
        return NULL;
    }
    sprintf(ip, "%d.%d.%d.%d", d,c,b,a);
    return ip;
}

static bool RecvAll(int32_t sock, void *data, int32_t data_size)
{
    char *data_ptr = (char*) data;
    int32_t bytes_recv;

    while (data_size > 0)
    {
        bytes_recv = recv(sock, data_ptr, data_size, 0);
        if (bytes_recv == 0) {
            return true;
        }
        if (bytes_recv < 0) {
            printf("failed to read data\n");
            return false;
        }

        data_ptr += bytes_recv;
        data_size -= bytes_recv;
    }

    return true;
}

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

static int32_t SendResponse(int32_t sockfd,
                ra_samp_response_header_t *resp) {
    uint32_t resp_size;
    uint32_t ret = NO_ERROR;

    resp_size = resp->size + sizeof(ra_samp_response_header_t);

    if (!SendAll(sockfd, &resp_size, sizeof(resp_size))) {
        printf("send resp_size failed\n");
        ret = ERR_IO;
        goto out;
    }
    if (!SendAll(sockfd, resp, resp_size)) {
        printf("send out_msg failed\n");
        ret = ERR_IO;
        goto out;
    }

    printf("send response success with msg type(%d)\n", resp->type);
out:
    if (resp) {
        free(resp);
        resp = nullptr;
    }

    return ret;
}

int sp_ra_proc_msg0_req(const sample_ra_msg0_t *p_msg0,
    uint32_t msg0_size,
    ra_samp_response_header_t **pp_msg0_resp) {
    ra_samp_response_header_t * p_msg0_resp_full;

    printf("msg0_size=%d\n", msg0_size);
    char *body = (char*)p_msg0;
    for (int i=0; i<msg0_size; i++){
        printf("%c", body[i]);
    }
    printf("\n");

    char *testMsg="welcome!";
    p_msg0_resp_full = (ra_samp_response_header_t *)malloc(
        sizeof(ra_samp_response_header_t)
        +strlen(testMsg));
    if (!p_msg0_resp_full) {
        printf("failed to allocate memory\n");
        return ERR_NO_MEMORY;
    }

    p_msg0_resp_full->type = TYPE_RA_MSG0;
    p_msg0_resp_full->size = strlen(testMsg)+1;
    p_msg0_resp_full->status[0] = 0;
    p_msg0_resp_full->status[1] = 0;
    memcpy_s(p_msg0_resp_full->body, p_msg0_resp_full->size, testMsg, p_msg0_resp_full->size);

    *pp_msg0_resp = p_msg0_resp_full;
    return 0;
}

int sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg0,
    uint32_t msg1_size,
    ra_samp_response_header_t **pp_msg0_resp) {
    printf("TODO: sp_ra_proc_msg1_req\n");
    return 0;
}

int sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg0,
    uint32_t msg3_size,
    ra_samp_response_header_t **pp_msg0_resp) {
    printf("TODO: sp_ra_proc_msg3_req\n");
    return 0;
}

int32_t SocketDispatchCmd(
                    ra_samp_request_header_t *req,
                    ra_samp_response_header_t **p_resp) {
    printf("receive the msg type(%d) from client.\n", req->type);
    int32_t ret;

    switch (req->type) {
    case TYPE_RA_MSG0:
        printf("Dispatching TYPE_RA_MSG0, body size: %d\n", req->size);
        ret = sp_ra_proc_msg0_req((const sample_ra_msg0_t*)((size_t)req
            + sizeof(ra_samp_request_header_t)),
            req->size,
            p_resp);
        if (0 != ret) {
            printf("call sp_ra_proc_msg1_req fail\n");
        }
        break;
    case TYPE_RA_MSG1:
        printf("Dispatching TYPE_RA_MSG1, body size: %d\n", req->size);
        ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((size_t)req
            + sizeof(ra_samp_request_header_t)),
            req->size,
            p_resp);
        if (0 != ret) {
            printf("call sp_ra_proc_msg1_req fail\n");
        }
        break;
    case TYPE_RA_MSG3:
        printf("Dispatching TYPE_RA_MSG3, body size: %d\n", req->size);
        ret = sp_ra_proc_msg3_req((const sample_ra_msg3_t*)((size_t)req
            + sizeof(ra_samp_request_header_t)),
            req->size,
            p_resp);
        if (0 != ret) {
            printf("call sp_ra_proc_msg1_req fail\n");
        }
        break;
    case TYPE_RA_ATT_RESULT:
        printf("Dispatching TYPE_RA_ATT_RESULT, body size: %d\n", req->size);
        return 0;

    default:
        printf("Cannot dispatch unknown msg type %d\n", req->type);
        return ERR_NOT_IMPLEMENTED;
    } 

    return ret;
}

/*
* This will handle connection for each socket client
*/
static void* SocketMsgHandler(void *sock_addr)
{
    ra_samp_request_header_t *req;
    ra_samp_response_header_t *resp;
    uint32_t req_size, resp_size;

    int32_t sockfd = *(int32_t*)sock_addr;
    int32_t ret;

    /* Receive a message from client */
    while (true) {
        req_size = 0;
        if (!RecvAll(sockfd, &req_size, sizeof(req_size))) {
            printf("failed to get req_size\n");
            break;
        }
        if (req_size <= 0) //no msg need to read
            break;

        req = (ra_samp_request_header_t *)malloc(req_size);
        if (!req) {
            printf("failed to allocate req buffer\n");
            break;
        }
        memset(req, 0, req_size);
        if (!RecvAll(sockfd, req, req_size)) {
            printf("failed to get req data\n");
            break;
        }

        ret = SocketDispatchCmd(req,&resp);
        if (ret < 0) {
            printf("failed(%d) to handle msg type(%d)\n", ret, req->type);
            resp->status[0] = SP_INTERNAL_ERROR;
            break;
        }

        SendResponse(sockfd, resp);

        SAFE_FREE(req);
        SAFE_FREE(resp);
    }

    SAFE_FREE(req);

    return 0;
}


void SocketServer::Initialize() {
    struct sockaddr_in serAddr, cliAddr;
    int32_t listenfd, connfd;
    socklen_t cliAddr_len;

    /* Create socket */
    listenfd = socket(AF_INET, SOCK_STREAM , 0);
    if (listenfd == -1) {
        printf("Could not create socket\n");
        return;
    }

    /* Prepare the sockaddr_in structure */
    serAddr.sin_family = AF_INET;
    serAddr.sin_addr.s_addr = INADDR_ANY;
    serAddr.sin_port = htons(server_port);

    /* Bind the server socket */
    if (bind(listenfd,(struct sockaddr *)&serAddr , sizeof(serAddr)) < 0) {
        printf("bind failed\n");
        return;
    }

    /* Listen */
    listen(listenfd , 1024);

    printf("Waiting for incoming connections...\n");
    cliAddr_len = sizeof(cliAddr);
    while (true) {
        /* Accept and incoming connection */
        connfd = accept(listenfd, (struct sockaddr *)&cliAddr, &cliAddr_len);
        if(connfd < 0) {
            printf("accept error\n");
            break;
        }

        char *ipaddr = hexToCharIP(cliAddr.sin_addr);
        if (ipaddr)
            printf("New Client(%d) connected! IP=%s\n", connfd, ipaddr);

        pthread_t sniffer_thread;
        if (pthread_create(&sniffer_thread, NULL, SocketMsgHandler, (void *)&connfd) < 0) {
            printf("could not create thread\n");
            break;
        }

        /* Join the thread
        * can't block here, since the main thread need to accept the other connections.
        */
        //pthread_join(sniffer_thread , NULL);
    }

    close(listenfd);

}


}
