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
            printf("client may closed...\n");
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
                uint32_t cmd,
                uint8_t* out_buf,
                uint32_t out_buf_size) {
    socket_ipc_msg_t *out_msg = NULL;
    uint32_t out_msg_size;
    uint32_t ret = NO_ERROR;

    out_msg_size = out_buf_size + sizeof(socket_ipc_msg_t);
    out_msg = (socket_ipc_msg_t *)malloc(out_msg_size);
    if (!out_msg) {
        printf("failed to allocate msg\n");
        return ERR_NO_MEMORY;
    }
    memset(out_msg, 0, out_msg_size);

    out_msg->cmd = cmd;
    memcpy(out_msg->payload, out_buf, out_buf_size);

    if (!SendAll(sockfd, &out_msg_size, sizeof(out_msg_size))) {
        printf("send out_msg_size failed\n");
        ret = ERR_IO;
        goto out;
    }
    if (!SendAll(sockfd, out_msg, out_msg_size)) {
        printf("send out_msg failed\n");
        ret = ERR_IO;
        goto out;
    }

    printf("send response success, cmd(%d)\n", cmd);
out:
    if (out_msg) {
        free(out_msg);
        out_msg = NULL;
    }

    return ret;
}

static int32_t SendErrorResponse(int32_t sockfd,
                                uint32_t cmd,
                                int32_t err) {
    return SendResponse(sockfd, cmd, reinterpret_cast<uint8_t*>(&err),
                         sizeof(err));
}

static int32_t SocketDispatchCmd(
                        socket_ipc_msg_t *msg,
                        uint32_t payload_size,
                        unique_ptr<uint8_t[]>* out,
                        uint32_t* out_size) {
    printf("receive the cmd(%d) from client.", msg->cmd);

    switch (msg->cmd) {
    case KMS_RETRIEVE_DOMAINKEY:
        printf("Dispatching RETRIEVE_DOMAINKEY, size: %d", payload_size);
        return 0;

    case KMS_SETUP_TRTUST_CHNNEL:
        printf("Dispatching SETUP_TRTUST_CHNNEL, size: %d", payload_size);
        return 0;

    default:
        printf("Cannot dispatch unknown command %d", msg->cmd);
        return ERR_NOT_IMPLEMENTED;
    }
}


/*
* This will handle connection for each socket client
*/
static void* SocketMsgHandler(void *sock_addr)
{
    socket_ipc_msg_t *in_msg=NULL;
    uint32_t in_msg_size;
    int32_t sockfd = *(int32_t*)sock_addr;
    int32_t ret;

    /* Receive a message from client */
    while (true) {
        in_msg_size = 0;
        if (!RecvAll(sockfd, &in_msg_size, sizeof(in_msg_size))) {
            printf("failed to get in_msg_size\n");
            break;
        }
        if (in_msg_size <= 0) //no msg need to read
            break;

        in_msg = (socket_ipc_msg_t *)malloc(in_msg_size);
        if (!in_msg) {
            printf("failed to allocate in_msg\n");
            break;
        }
        memset(in_msg, 0, in_msg_size);
        if (!RecvAll(sockfd, in_msg, in_msg_size)) {
            printf("failed to get in_msg\n");
            break;
        }

        unique_ptr<uint8_t[]> out_buf;
        uint32_t out_buf_size = 0;
        ret = SocketDispatchCmd(in_msg,
                in_msg_size-sizeof(socket_ipc_msg_t),
                &out_buf,
                &out_buf_size);
        if (ret < 0) {
            printf("failed(%d) to handle msg cmd(%d)\n", ret, in_msg->cmd);
            SendErrorResponse(sockfd, in_msg->cmd, ret);
            break;
        }

        SendResponse(sockfd, in_msg->cmd, out_buf.get(), out_buf_size);

        if (in_msg) {
            free(in_msg);
            in_msg = NULL;
        }
    }

    if (in_msg) {
        free(in_msg);
        in_msg = NULL;
    }

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
