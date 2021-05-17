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

#include <memory>
#include <error.h>
#include <limits.h>
#include <unistd.h>

#include <enclave_u.h>

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"


using namespace std;

static bool g_securechannel_ready = false;

static int32_t g_deploy_sock = -1;

sgx_enclave_id_t g_enclave_id;

namespace socket_client {


// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
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

static int32_t SendResponse(int32_t sockfd,
                ra_samp_response_header_t *resp) {
    uint32_t resp_size;
    uint32_t ret = NO_ERROR;

printf("YYY--resp->size=%d\n", resp->size);
    resp_size = resp->size + sizeof(ra_samp_response_header_t);

    if (!SendAll(sockfd, &resp_size, sizeof(resp_size))) {
        printf("send resp_size failed\n");
        return ERR_IO;
    }
    if (!SendAll(sockfd, resp, resp_size)) {
        printf("send out_msg failed\n");
        return ERR_IO;
    }

    printf("send response success with msg type(%d)\n", resp->type);

    return ret;
}

static int32_t SendErrResponse(int32_t sockfd, int8_t type, int8_t err) {
    ra_samp_response_header_t  p_err_resp_full = {0};

    p_err_resp_full.type = type;
    p_err_resp_full.status[0] = err;
    p_err_resp_full.status[1] = err;
    return SendResponse(sockfd, &p_err_resp_full);
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

int32_t SocketDispatchCmd(
                    ra_samp_request_header_t *req,
                    ra_samp_response_header_t **p_resp) {
    printf("receive the msg type(%d) from client.\n", req->type);
    int32_t ret;

    switch (req->type) {
    case TYPE_RA_RETRIEVE_DK:
        printf("Dispatching TYPE_RA_RETRIEVE_DK, body size: %d\n", req->size);
        return RetreiveDomainKey(req, p_resp);

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
    uint32_t req_size;

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
            SendErrResponse(sockfd, req->type, ret);
            continue;
        }

        SendResponse(sockfd, resp);

        SAFE_FREE(req);
        SAFE_FREE(resp);
    }

    SAFE_FREE(req);

    return 0;
}

int32_t SendAndRecvMsg(
    const ra_samp_request_header_t *p_req,
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

    if (!SendAll(g_deploy_sock, &req_size, sizeof(req_size))) {
        fprintf(stderr, "send req_size failed\n");
        err = ERR_GENERIC;
        goto out;
    }
    if (!SendAll(g_deploy_sock, p_req, req_size)) {
        fprintf(stderr, "send req buffer failed\n");
        err = ERR_GENERIC;
        goto out;
    }

    /* Receive a message from server */
    if (!RecvAll(g_deploy_sock, &resp_size, sizeof(resp_size))) {
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
    if (!RecvAll(g_deploy_sock, out_msg, resp_size)) {
        fprintf(stderr, "failed to get the data\n");
        err = ERR_GENERIC;
        goto out;
    }

    *p_resp = out_msg;
out:
    return err;
}


static int RaSetupSecureChannel() {
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    ra_samp_request_header_t* p_msg3_full = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;

    sample_ra_att_result_msg_t *p_att_result_msg_body = NULL;
    sgx_ra_msg2_t* p_msg2_body = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;

    uint32_t msg3_size = 0;
    int busy_retry_time = 4;
    int enclave_lost_retry_time = 1;
    sgx_ra_context_t context = INT_MAX;
    sgx_status_t status = SGX_SUCCESS;
    int ret = 0;
    FILE* OUTPUT = stdout;

    sgx_att_key_id_t selected_key_id = {0}; //acutally not used in our case
    
    do {
        ret = enclave_init_ra(g_enclave_id,
                          &status,
                          false,
                          &context);
     //Ideally, this check would be around the full attestation flow.
    } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

    if(SGX_SUCCESS != ret || status) {
        ret = -1;
        fprintf(OUTPUT, "Error, call enclave_init_ra failed.\n");
        goto CLEANUP;
    }

    /* Allocate MSG1 buf to call libukey_exchange API to retrieve MSG1 */
    p_msg1_full = (ra_samp_request_header_t*)
                 malloc(sizeof(ra_samp_request_header_t)
                        + sizeof(sgx_ra_msg1_t));
    if(NULL == p_msg1_full) {
        ret = -1;
        goto CLEANUP;
    }
    p_msg1_full->type = TYPE_RA_MSG1;
    p_msg1_full->size = sizeof(sgx_ra_msg1_t);

    do
    {
        ret = sgx_ra_get_msg1_ex(&selected_key_id, context, g_enclave_id, sgx_ra_get_ga,
                             (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
                             + sizeof(ra_samp_request_header_t)));
        //sleep(3); // Wait 3s between retries
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    if(SGX_SUCCESS != ret) {
        fprintf(OUTPUT, "Error, call sgx_ra_get_msg1_ex failed(%#x)\n", ret);
        ret = -1;
        goto CLEANUP;
    }
    fprintf(OUTPUT, "Call sgx_ra_get_msg1_ex success, the MSG1 body generated.\n");

    fprintf(OUTPUT, "Sending MSG1 to remote attestation service provider, and expecting MSG2 back...\n");
    SendAndRecvMsg(p_msg1_full, &p_msg2_full);
    if(!p_msg2_full) {
        fprintf(OUTPUT, "Error,sending MSG1 failed.\n");
        ret = -1;
        goto CLEANUP;
    }

    /* Successfully sent MSG1 and received a MSG2 back. */
    if(TYPE_RA_MSG2 != p_msg2_full->type) {
        fprintf(OUTPUT, "Error, MSG2's type is not matched!\n");
        ret = -1;
        goto CLEANUP;
    }

    //PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full, (uint32_t)sizeof(ra_samp_response_header_t) + p_msg2_full->size);
    fprintf(OUTPUT, "MSG2 recieved success!\n");

    /* Call lib key_u(t)exchange(sgx_ra_proc_msg2_ex) to process the MSG2 and retrieve MSG3 back. */
    p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full + sizeof(ra_samp_response_header_t));

    busy_retry_time = 2;
    do
    {
        ret = sgx_ra_proc_msg2_ex(&selected_key_id,
                           context,
                           g_enclave_id,
                           sgx_ra_proc_msg2_trusted,
                           sgx_ra_get_msg3_trusted,
                           p_msg2_body,
                           p_msg2_full->size,
                           &p_msg3,
                           &msg3_size);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    if(!p_msg3 || (SGX_SUCCESS != (sgx_status_t)ret)) {
        fprintf(OUTPUT, "Error(%d), call sgx_ra_proc_msg2_ex failed, p_msg3 = 0x%p.", ret, p_msg3);
        goto CLEANUP;
    }
    fprintf(OUTPUT, "Call sgx_ra_proc_msg2_ex success.\n");

    //PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

    p_msg3_full = (ra_samp_request_header_t*)malloc(sizeof(ra_samp_request_header_t) + msg3_size);
    if(NULL == p_msg3_full) {
        ret = -1;
        goto CLEANUP;
    }
    p_msg3_full->type = TYPE_RA_MSG3;
    p_msg3_full->size = msg3_size;
    if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size)) {
        fprintf(OUTPUT,"Error: memcpy failed\n.");
        ret = -1;
        goto CLEANUP;
    }

    // The ISV application sends msg3 to the SP to get the attestation
    // result message, attestation result message needs to be freed when
    // no longer needed. The ISV service provider decides whether to use
    // linkable or unlinkable signatures. The format of the attestation
    // result is up to the service provider. This format is used for
    // demonstration.  Note that the attestation result message makes use
    // of both the MK for the MAC and the SK for the secret. These keys are
    // established from the SIGMA secure channel binding.
    fprintf(OUTPUT, "Sending MSG3 to remote attestation service provider,"
                        "expecting attestation result msg back...\n");
    SendAndRecvMsg(p_msg3_full, &p_att_result_msg_full);
    if(ret || !p_att_result_msg_full) {
        ret = -1;
        fprintf(OUTPUT, "Error, sending MSG3 failed\n.");
        goto CLEANUP;
    }


    p_att_result_msg_body = (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                           + sizeof(ra_samp_response_header_t));
    if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type) {
        ret = -1;
        fprintf(OUTPUT, "Error, the attestaion MSG's type is not matched!\n");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "Attestation result MSG recieved success!\n");
    //PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body, p_att_result_msg_full->size);

    /*
    * Check the MAC using MK on the attestation result message.
    * The format of the attestation result message is specific(sample_ra_att_result_msg_t).
    */
    ret = enclave_verify_att_result_mac(g_enclave_id,
            &status,
            context,
            (uint8_t*)&p_att_result_msg_body->platform_info_blob,
            sizeof(ias_platform_info_blob_t),
            (uint8_t*)&p_att_result_msg_body->mac,
            sizeof(sgx_mac_t));
    if((SGX_SUCCESS != ret) ||
       (SGX_SUCCESS != status)) {
        ret = -1;
        fprintf(OUTPUT, "Error: Attestation result MSG's MK based cmac check failed\n");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "Verify attestation result is succeed!\n");

    ret = enclave_store_domainkey(g_enclave_id,
                          &status,
                          context,
                          p_att_result_msg_body->secret.payload,
                          p_att_result_msg_body->secret.payload_size,
                          p_att_result_msg_body->secret.payload_tag);
    if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status)) {
        fprintf(OUTPUT, "Error(%d), decrypt secret using SK based on AES-GCM failed.\n", ret);
        ret = -1;
        goto CLEANUP;
    }

    fprintf(OUTPUT, "Successfully received the DomainKey from deploy server.");
CLEANUP:
    // Clean-up
    // Need to close the RA key state.
    if(INT_MAX != context) {
        int ret_save = ret;
        ret = enclave_ra_close(g_enclave_id, &status, context);
        if(SGX_SUCCESS != ret || status) {
            fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%#x].\n",ret);
        }
        else {
            // enclave_ra_close was successful, let's restore the value that
            // led us to this point in the code.
            ret = ret_save;
        }
        fprintf(OUTPUT, "\nCall enclave_ra_close success.\n");
    }

    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg2_full);
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_att_result_msg_full);

    return ret;
}


int RetreiveDomainKey(const ra_samp_request_header_t *req,
                ra_samp_response_header_t **p_resp) {
    ra_samp_response_header_t* p_resp_full = NULL;
    sample_key_blob_t *p_dk = NULL;

    int ret = 0;
    sgx_status_t status = SGX_SUCCESS;

    uint32_t blob_size = 0;
    uint32_t resp_size = 0;

    if(!req || !p_resp) {
        return -1;
    }

    if (!g_securechannel_ready) {
        /* setup the remote secure channel */
        ret = RaSetupSecureChannel();
        if (ret != SGX_SUCCESS) {
            printf("failed(%d) to setup the secure channel.\n", ret);
            goto out;
        }
        g_securechannel_ready = true;
    }

    ret = enclave_get_domainkey(g_enclave_id, &status,
                NULL,
                0,
                &(blob_size));
    if(SGX_SUCCESS != ret || status) {
        printf("failed(%d) to get the blob size\n", ret);
        ret = -1;
        goto out;
    }

    resp_size = sizeof(ra_samp_response_header_t) + sizeof(sample_key_blob_t) + blob_size;
    p_resp_full = (ra_samp_response_header_t*)malloc(resp_size);
    if (!p_resp_full) {
        ret = -1;
        goto out;
    }

    memset(p_resp_full, 0, resp_size);
    /* initialize the resp buffer */
    p_resp_full->type = TYPE_RA_RETRIEVE_DK;
    p_resp_full->size = sizeof(sample_key_blob_t) + blob_size;
    p_resp_full->status[0] = 0;
    p_resp_full->status[1] = 0;
    p_dk = (sample_key_blob_t *)p_resp_full->body;
    p_dk->blob_size = blob_size;
    printf("YYY--p_resp_full->size=%d\n", p_resp_full->size);

    ret = enclave_get_domainkey(g_enclave_id, &status,
                p_dk->blob,
                p_dk->blob_size,
                NULL);
    if(SGX_SUCCESS != ret || status) {
        printf("failed(%d) to get the domainkey, status=%d\n", ret, status);
        ret = -1;
        goto out;
    }

out:
    if(ret) {
        *p_resp = NULL;
        SAFE_FREE(p_resp_full);
    }
    else {
        *p_resp = p_resp_full;
    }

    return ret;
}


void Connect() {
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
    serAddr.sin_port = htons(deploy_port);
    serAddr.sin_addr.s_addr = inet_addr(deploy_ip_addr);

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

    g_deploy_sock = sockFd;
}

void DisConnect() {
    close(g_deploy_sock);
}

bool IsConnected()  {
    if (g_deploy_sock > 0)
        return true;
    else
        return false;
}

void Initialize() {
    struct sockaddr_in serAddr, cliAddr;
    int32_t listenfd, connfd;
    socklen_t cliAddr_len;
    int ret = 0;

    /* Create socket */
    listenfd = socket(AF_INET, SOCK_STREAM , 0);
    if (listenfd == -1) {
        printf("Could not create socket\n");
        return;
    }

    /* Prepare the sockaddr_in structure */
    serAddr.sin_family = AF_INET;
    serAddr.sin_addr.s_addr = INADDR_ANY;
    serAddr.sin_port = htons(provisioning_port);

    /* Bind the server socket */
    if ((ret = bind(listenfd,(struct sockaddr *)&serAddr , sizeof(serAddr))) < 0) {
        printf("bind failed(%d)\n", ret);
        return;
    }

    /* Listen */
    listen(listenfd , 1024);

    printf("Provisioning service is waiting for incoming connections...\n");
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

