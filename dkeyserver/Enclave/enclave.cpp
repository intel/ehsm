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

#include "enclave_t.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "elog_utils.h"

#include <string>
#include <stdio.h>
#include <stdbool.h>
#include <mbusafecrt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <mutex>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "openssl/sha.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "byteswap.h"
#include "openssl_utility.h"
#include "datatypes.h"
#include "domainkey_factory.h"

#define ROLE_WORKER "worker"
#define ROLE_ROOT "root"

std::string g_server_name;
uint16_t g_server_port;
std::string g_server_role;

SSL *g_ssl_session = nullptr;
int g_socket_fd = -1;

dkey_server_domainkey g_domainkey;

uint64_t g_nextRotationTime = 0;
int g_period = -1;

size_t g_password = 0;
bool g_ready_flag = false;

typedef struct g_sessionPoolStruct
{
    SSL *ssl_session;
    int errorCnt;
} g_sessionPoolStruct;

g_sessionPoolStruct g_client_session[CONCURRENT_MAX] = {{NULL, 0}};

typedef struct SocketMsgHandlerParam
{
    int socket_fd;
    SSL_CTX *ssl_server_ctx;
    SSL *ssl_session;
    uint8_t *domainkey;
} SocketMsgHandlerParam;

void log_printf(uint32_t log_level, const char *filename, uint32_t line, const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(log_level, buf, filename, line);
}

int update_couch_db(int db_type, int key_type)
{
    int db_size;
    ocall_load_couchdb(&db_size, db_type);
    log_i("db_size=%d", db_size);

    for (int i = 0; i < db_size; i++)
    {
        int ret;

        uint32_t dk_cipher_len = sgx_calc_sealed_data_size(0, SGX_DOMAIN_KEY_SIZE);
        uint8_t dk_cipher[dk_cipher_len] = {0};

        ocall_update_CMK(&ret, dk_cipher, dk_cipher_len, g_domainkey.dk_hash, DOMAINKEY_HASH_SIZE, key_type);
        if (ret == -1)
            return -1;
    }
    return 0;
}

void t_time(time_t *current_t)
{
    ocall_get_current_time((uint64_t *)current_t);
}

void t_sleep(int second)
{
    ocall_sleep(second);
}

uint32_t htonl(uint32_t n)
{
    union
    {
        int i;
        char c;
    } u = {1};
    return u.c ? bswap_32(n) : n;
}

uint16_t htons(uint16_t n)
{
    union
    {
        int i;
        char c;
    } u = {1};
    return u.c ? bswap_16(n) : n;
}

/* support socket APIs inside enclave */
/* for socket APIs, refer to https://en.wikipedia.org/wiki/Berkeley_sockets */

int socket(int domain, int type, int protocol)
{
    int ret = -1;

    if (ocall_socket(&ret, domain, type, protocol) == SGX_SUCCESS)
        return ret;

    return -1;
}

int bind(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{
    int ret = -1;

    if (ocall_bind(&ret, sockfd, servaddr, addrlen) == SGX_SUCCESS)
        return ret;

    return -1;
}

int listen(int sockfd, int backlog)
{
    int ret = -1;

    if (ocall_listen(&ret, sockfd, backlog) == SGX_SUCCESS)
        return ret;

    return -1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int ret = -1;
    socklen_t addrlen_in = 0;

    if ((addr && !addrlen) || (addrlen && !addr))
    {
        return -1;
    }

    if (addr && addrlen)
    {
        addrlen_in = *addrlen;
    }

    if (ocall_accept(&ret, sockfd, addr, addrlen_in, addrlen) == SGX_SUCCESS)
        return ret;

    return -1;
}

int setsockopt(
    int fd,
    int level,
    int optname,
    const void *optval,
    socklen_t optlen)
{
    int ret = -1;

    // errno = 0;

    if (!optval || !optlen)
    {
        //   errno = EINVAL;
        return -1;
    }

    if (ocall_setsockopt(&ret, fd, level, optname, optval, optlen) != SGX_SUCCESS)
    {
        //  errno = EINVAL;
        return -1;
    }

    return ret;
}

int create_listener_socket(int port, int &server_socket)
{
    int ret = -1;
    const int reuse = 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        log_d(TLS_SERVER "socket creation failed\n");
        goto exit;
    }

    if (setsockopt(
            server_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void *)&reuse,
            sizeof(reuse)) < 0)
    {
        log_d(TLS_SERVER "setsocket failed \n");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        log_d(TLS_SERVER "Unable to bind socket to the port\n");
        goto exit;
    }

    if (listen(server_socket, CLIENT_MAX_NUM) < 0)
    {
        log_d(TLS_SERVER "Unable to open socket for listening\n");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

std::mutex mtx;

static bool RecvAll(SSL *ssl_session, void *data, int32_t data_size)
{
    char *data_ptr = (char *)data;
    int32_t bytes_recv;
    int error = 0;

    while (true)
    {
        // mtx.lock();

        bytes_recv = SSL_read(ssl_session, data_ptr, data_size);

        // log_i("bytes_recv=%d\n", bytes_recv);
        // mtx.unlock();

        if (bytes_recv <= 0)
        {
            error = SSL_get_error(ssl_session, bytes_recv);
            if (error == SSL_ERROR_WANT_READ)
            {
                log_i("SSL_ERROR_WANT_READ");
                continue;
            }

            // log_d(TLS_SERVER "Failed! SSL_read returned error=%d\n", error);
            return false;
        }

        // t_sleep(1);
        // log_d(TLS_SERVER "%d bytes recv\n", bytes_recv);
        return true;
    }

    return true;
}

static bool SendAll(SSL *ssl_session, const void *data, int32_t data_size)
{
    // mtx.lock();

    const char *data_ptr = (const char *)data;
    int32_t bytes_sent;
    int error = 0;

    while (true)
    {
        bytes_sent = SSL_write(ssl_session, data_ptr, data_size);

        if (bytes_sent <= 0)
        {
            error = SSL_get_error(ssl_session, bytes_sent);
            if (error == SSL_ERROR_WANT_WRITE)
            {
                continue;
            }
            else
            {
                // mtx.unlock();

                return false;
            }
        }
        else
        {
            break;
        }
    }

    // mtx.unlock();

    return true;
}

int SocketDispatchCmd(_request_header_t *req, SSL *ssl_session)
{
    //parse the command sent by the client
    int bytes_written = 0;
    _response_header_t *server_res = NULL;

    if (req->password != g_password && req->cmd != GET_DOMAINKEY && g_password != 0)
    {
        if (!SendAll(ssl_session, PASSWORD_WRONG, PASSWORD_WRONG_SIZE))
        {
            log_d("failed to send PASSWORD_WRONG datas\n");
        }
        return -1;
    }

    switch (req->cmd)
    {
    case GET_DOMAINKEY:
    {
        //send domainkey to the client
        log_d(TLS_SERVER "<---- Write domainkey to client:\n");

        server_res = (_response_header_t *)malloc(sizeof(_response_header_t));
        memcpy_s(server_res->domainKey, SGX_DOMAIN_KEY_SIZE, g_domainkey.domainkey, SGX_DOMAIN_KEY_SIZE);
        server_res->type = MSG_DOMAINKEY;

        if (!SendAll(ssl_session, server_res, sizeof(_response_header_t)))
        {
            log_d("failed to send domainkey data\n");
            SAFE_FREE(server_res);
            return -1;
        }
        SAFE_FREE(server_res);
        return 0;
    }
    case STOP_AUTO_ROTATION:
    {
        g_period = -1;
        g_nextRotationTime = g_period;
        if (!SendAll(ssl_session, STOP_AUTO_ROTATION_MSG, STOP_AUTO_ROTATION_MSG_SIZE))
        {
            log_d("failed to send STOP_AUTO_ROTATION_MSG datas\n");
            return -1;
        }
        return 0;
    }
    case START_ROTATION:
    {
        log_i("START_ROTATION!");
        t_time((time_t *)&g_nextRotationTime);
        if (!SendAll(ssl_session, START_ROTATION_MSG, START_ROTATION_MSG_SIZE))
        {
            log_d("failed to send START_ROTATION_MSG datas\n");
            return -1;
        }
        return 0;
    }
    case SET_PERIOD:
    {
        std::string set_period_msg;
        uint32_t set_period_msg_size = 0;
        if (req->period <= 30 || req->period >= 365)
        {
            log_d("the period must greater than 30 days and less than 365 days");
            set_period_msg = SET_PERIOD_FAILED_MSG;
            set_period_msg_size = SET_PERIOD_FAILED_MSG_SIZE;
        }
        else
        {
            g_period = req->period;
            g_nextRotationTime = g_period * 24 * 60 * 60 + g_domainkey.createTime;
            set_period_msg = SET_PERIOD_SUCCESS_MSG;
            set_period_msg_size = SET_PERIOD_SUCCESS_MSG_SIZE;
        }
        if (!SendAll(ssl_session, set_period_msg.c_str(), set_period_msg_size))
        {
            log_d("failed to send SET_PERIOD_MSG datas\n");
            return -1;
        }
        return 0;
    }
    case GET_PERIOD:
    {
        std::string get_period_msg = "The period time is " + std::to_string(g_period) + " days.";
        if (!SendAll(ssl_session, get_period_msg.c_str(), get_period_msg.size() + 1))
        {
            log_d("failed to send get_period_msg datas\n");
            return -1;
        }
        return 0;
    }
    case GET_NEXT_ROTATION_DATETIME:
    {
        std::string get_next_rotation_datetime_msg = "The next retation time is " +
                                                     std::to_string(g_nextRotationTime) + ".";
        if (!SendAll(ssl_session, get_next_rotation_datetime_msg.c_str(), get_next_rotation_datetime_msg.size() + 1))
        {
            log_d("failed to send get_next_rotation_datetime_msg datas\n");
            return -1;
        }
        return 0;
    }
    case UPDATE_CMK:
    {
        uint32_t dk_cipher_len = sgx_calc_sealed_data_size(0, SGX_DOMAIN_KEY_SIZE);
        uint8_t dk_cipher[dk_cipher_len] = {0};
        std::string update_cmk_msg;

        int ret;
        ret = update_couch_db(CMK_INFO, KEYBLOB);
        if (ret == -1)
        {
            update_cmk_msg = "Update CMK failed";
        }

        ret = update_couch_db(USER_INFO, CMK);
        if (ret == -1)
        {
            update_cmk_msg = "Update CMK failed";
        }

        ret = update_couch_db(USER_INFO, SM_DEFAULT_CMK);
        if (ret == -1)
        {
            update_cmk_msg = "Update CMK failed";
        }

        if (ret == 1)
        {
            update_cmk_msg = "Update CMK done";
            log_i("UPDATE_CMK ok");
        }

        if (!SendAll(ssl_session, update_cmk_msg.c_str(), strlen(update_cmk_msg.c_str()) + 1))
            log_e("failed to send update_cmk_msg datas\n");
    }
    default:
        return -1;
    }
}

static void *Server_heart(void *args)
{
    (void)args;
    log_d("in Server_heart");

    int bytes_written = 0;
    int test_error = 0;

    _response_header_t *server_res = NULL;
    server_res = (_response_header_t *)malloc(sizeof(_response_header_t));
    server_res->type = MSG_HEARTBEAT;
    //session in the pool is connected every 10 seconds.
    //If a session connection fails for three times, the session is deleted
    while (true)
    {
        t_sleep(10);
        for (int i = 0; i < CONCURRENT_MAX; i++)
        {
            if (g_client_session[i].ssl_session != NULL)
            {
                if (g_client_session[i].errorCnt < MAX_RECONNECT)
                {
                    log_i("Server->client heart start index = %d", i);
                    int r = SendAll(g_client_session[i].ssl_session, server_res, sizeof(_response_header_t));
                    if (!r)
                        g_client_session[i].errorCnt++;
                    else
                        g_client_session[i].errorCnt = 0;
                    continue;
                }

                int client_fd = SSL_get_fd(g_client_session[i].ssl_session);
                if (client_fd > 0)
                {
                    int closeRet;
                    ocall_close(&closeRet, client_fd);
                }

                SSL_shutdown(g_client_session[i].ssl_session);
                SSL_free(g_client_session[i].ssl_session);

                g_client_session[i].ssl_session = nullptr;
                g_client_session[i].errorCnt = 0;

                log_i("remove session index=%d", i);
            }
        }
    }
}

static void *SocketMsgHandler(void *arg)
{
    if (arg == NULL)
    {
        log_d(TLS_SERVER
              "arg cannot be obtained\n");
        return ((void *)0);
    }

    int index = -1;
    _request_header_t *client_req = NULL;
    client_req = (_request_header_t *)malloc(sizeof(_request_header_t));

    // add new connection to connection pool if it's not full
    for (int i = 0; i < CONCURRENT_MAX; i++)
    {
        if (g_client_session[i].ssl_session == NULL)
        {
            index = i;
            log_i("create session index=%d", index);
            break;
        }
    }
    if (index < 0)
    {
        log_d(TLS_SERVER "The connection pool was full.\n");
        return ((void *)0);
    }

    SocketMsgHandlerParam handler_ctx = *(SocketMsgHandlerParam *)arg;
    int test_error = 1;

    // create a new SSL structure for a connection
    if ((g_client_session[index].ssl_session = SSL_new(handler_ctx.ssl_server_ctx)) == nullptr)
    {
        log_d(TLS_SERVER
              "Unable to create a new SSL connection state object\n");
        goto exit;
    }

    if (SSL_set_fd(g_client_session[index].ssl_session, handler_ctx.socket_fd) != 1)
    {
        log_d(TLS_SERVER
              "SSL set fd failed\n");
        goto exit;
    }

    // wait for a TLS/SSL client to initiate a TLS/SSL handshake
    log_i(TLS_SERVER "initiating a passive connect SSL_accept\n");
    test_error = SSL_accept(g_client_session[index].ssl_session);
    if (test_error <= 0)
    {
        log_d(TLS_SERVER " SSL handshake failed, error(%d)(%d)\n",
              test_error, SSL_get_error(g_client_session[index].ssl_session, test_error));
        goto exit;
    }

    //Receive messages from the client
    while (true)
    {
        if (g_client_session[index].ssl_session == NULL)
            continue;

        // log_d(TLS_SERVER "<---- Read cmd from client:\n");

        memset(client_req, 0, sizeof(client_req));

        if (!RecvAll(g_client_session[index].ssl_session, client_req, sizeof(_request_header_t)))
        {
            // log_d("failed to get res data\n");
            t_sleep(1);
            continue;
        }

        // log_i("\ntype=%d\n", client_req->cmd);

        test_error = SocketDispatchCmd(client_req, g_client_session[index].ssl_session);
        // t_sleep(20);
        if (test_error < 0)
        {
            // log_d("parse cmd failed\n");
        }
    }

exit:
    if (client_req)
        SAFE_FREE(client_req);
    return ((void *)0);
}

int handle_communication_until_done(
    int &server_socket_fd,
    int &client_socket_fd,
    SSL_CTX *&ssl_server_ctx)
{
    int ret = -1;
    // waiting_for_connection_request:
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    pthread_t heart_thread;
    
    //start the server heartbeat thread
    if (pthread_create(&heart_thread, NULL, Server_heart, NULL) < 0)
    {
        log_d("could not create thread\n");
        goto exit;
    }

    // reset ssl_session and client_socket_fd to prepare for the new TLS
    // connection

    log_i(TLS_SERVER " waiting for client connection\n");

waiting_for_connection_request:

    client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&addr, &len);
    
    if (g_ready_flag == false)
    {
        if (client_socket_fd != -1)
        {
            int closeRet;
            ocall_close(&closeRet, client_socket_fd);
        }
        goto waiting_for_connection_request;
    }

    if (client_socket_fd < 0)
    {
        log_d(TLS_SERVER "Unable to accept the client request\n");
        goto exit;
    }

    SocketMsgHandlerParam param;
    param.socket_fd = client_socket_fd;
    param.ssl_server_ctx = ssl_server_ctx;

    pthread_t sniffer_thread;
    //start the thread that receive and parse command
    if (pthread_create(&sniffer_thread, NULL, SocketMsgHandler, (void *)&param) < 0)
    {
        log_d("could not create thread\n");
        goto exit;
    }

    goto waiting_for_connection_request;
exit:
    return ret;
}

static unsigned long inet_addr(const char *str)
{
    unsigned long lHost = 0;
    char *pLong = (char *)&lHost;
    char *p = (char *)str;
    while (p)
    {
        *pLong++ = atoi(p);
        p = strchr(p, '.');
        if (p)
            ++p;
    }
    return lHost;
}

int connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{
    int ret = -1;

    if (ocall_connect(&ret, sockfd, servaddr, addrlen) == SGX_SUCCESS)
        return ret;

    return -1;
}

int create_socket(const char *server_name, uint16_t server_port)
{
    int sockfd = -1;
    struct sockaddr_in dest_sock;
    int ret = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        log_e(TLS_SERVER "Error: Cannot create socket %d.\n", errno);
        goto out;
    }

    dest_sock.sin_family = AF_INET;
    dest_sock.sin_port = htons(server_port);
    dest_sock.sin_addr.s_addr = inet_addr(server_name);
    bzero(&(dest_sock.sin_zero), sizeof(dest_sock.sin_zero));

    if (connect(
            sockfd, (sockaddr *)&dest_sock,
            sizeof(struct sockaddr)) == -1)
    {
        log_e(
            TLS_SERVER "failed to connect to target server %d:%d (errno=%d)\n",
            server_name,
            server_port,
            errno);
        ocall_close(&ret, sockfd);
        if (ret != 0)
            log_e(TLS_SERVER "OCALL: error closing socket\n");
        sockfd = -1;
        goto out;
    }
    log_d(TLS_SERVER "connected to target server %s:%d\n", server_name, server_port);

out:
    return sockfd;
}

sgx_status_t store_domain_key(uint8_t *domain_key)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t dk_cipher_len = sgx_calc_sealed_data_size(0, SGX_DOMAIN_KEY_SIZE);
    uint8_t dk_cipher[dk_cipher_len] = {0};
    time_t current_time;
    int retstatus;

    SHA256(domain_key, SGX_DOMAIN_KEY_SIZE, g_domainkey.dk_hash);

    ret = sgx_seal_data(0, NULL, SGX_DOMAIN_KEY_SIZE, domain_key, dk_cipher_len, (sgx_sealed_data_t *)dk_cipher);
    if (ret != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    ret = ocall_store_domain_key(&retstatus, dk_cipher, dk_cipher_len, g_domainkey.dk_hash, DOMAINKEY_HASH_SIZE);
    if (ret != SGX_SUCCESS || retstatus != 0)
        return SGX_ERROR_UNEXPECTED;

    t_time((time_t *)&g_domainkey.createTime);

    return ret;
}

int generate_ssl_session()
{
    SSL_CTX *ssl_client_ctx = nullptr;
    X509 *cert = nullptr;
    EVP_PKEY *pkey = nullptr;
    SSL_CONF_CTX *ssl_confctx = SSL_CONF_CTX_new();
    int ret = -1;

    if ((ssl_client_ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
    {
        log_e(TLS_SERVER "Unable to create a new SSL context\n");
        goto out;
    }

    if (initalize_ssl_context(ssl_confctx, ssl_client_ctx) != SGX_SUCCESS)
    {
        log_e(TLS_SERVER "Unable to create a initialize SSL context\n ");
        goto out;
    }

    // specify the verify_callback for verification
    SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, &verify_callback);
    log_d(TLS_SERVER "Load cert and key\n");
    if (load_tls_certificates_and_keys(ssl_client_ctx, cert, pkey) != 0)
    {
        log_e(TLS_SERVER "Unable to load certificate and private key on the client\n");
        goto out;
    }

    if ((g_ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
    {
        log_d(TLS_SERVER "Unable to create a new SSL connection state object\n");
        goto out;
    }

    ret = 0;

out:
    if (cert)
        X509_free(cert);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (ssl_client_ctx)
        SSL_CTX_free(ssl_client_ctx);

    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);

    return ret;
}

//send the getdomainkey command to the server
static int req_domainkey(SSL *ssl_session)
{
    if (ssl_session == NULL)
        return -1;

    _request_header_t *client_req = NULL;

    log_d(TLS_SERVER "-----> Write getdomainkey cmd to server:\n");

    client_req = (_request_header_t *)malloc(sizeof(_request_header_t));
    client_req->cmd = GET_DOMAINKEY;

    if (!SendAll(ssl_session, client_req, sizeof(_request_header_t)))
    {
        log_d("failed to send req data\n");
        SAFE_FREE(client_req);
        return -1;
    }

    SAFE_FREE(client_req);
    return 0;
}

static int connect_target_server(const char *target_server_name,
                                 uint16_t target_server_port)
{
    int error = 0;
    int ret = SGX_ERROR_UNEXPECTED;

    if (generate_ssl_session() < 0)
    {
        log_d(TLS_SERVER "generate ssl session in get_domainkey_from_target failed\n");
        goto out;
    }

    log_d(TLS_SERVER "New ssl connection getting created\n");
    g_socket_fd = create_socket(target_server_name, target_server_port);

    if (g_socket_fd == -1)
    {
        log_e(
            TLS_SERVER "Create a socket and initiate a TCP connect to target server: %s:%d "
                       "(errno=%d)\n",
            target_server_name,
            target_server_port,
            errno);
        goto out;
    }

    // set up ssl socket and initiate TLS connection with TLS target server
    if (SSL_set_fd(g_ssl_session, g_socket_fd) != 1)
    {
        log_e(TLS_SERVER "Ssl set fd error.\n");
        goto out;
    }

    if ((error = SSL_connect(g_ssl_session)) != 1)
    {
        log_e(TLS_SERVER "Error: Could not establish a TLS session ret2=%d "
                         "SSL_get_error()=%d\n",
              error,
              SSL_get_error(g_ssl_session, error));
        goto out;
    }

    log_d(TLS_SERVER "successfully established TLS channel:%s\n",
          SSL_get_version(g_ssl_session));

    ret = SGX_SUCCESS;
out:
    if (ret != SGX_SUCCESS)
        g_ready_flag = false;
    log_i("ready flag change to %s\n", g_ready_flag == true ? "true" : "false");
    return ret;
}

static void *ClientSocketMsgHandler(void *args)
{
    (void)args;

    _response_header_t *server_res = NULL;
    server_res = (_response_header_t *)malloc(sizeof(_response_header_t));

    while (true)
    {
        if (g_ssl_session == nullptr || g_socket_fd == -1)
        {
            t_sleep(1);
            continue;
        }

        memset(server_res, 0, sizeof(_response_header_t));
        //receives messages from the server
        if (!RecvAll(g_ssl_session, server_res, sizeof(_response_header_t)))
        {
            log_d("failed to get res data\n");

            continue;
        }

        log_i("server_res->type=%d\n", server_res->type);

        switch (server_res->type)
        {
        case MSG_DOMAINKEY:
            log_i("in msg_domainkey type");
            memcpy_s(g_domainkey.domainkey, SGX_DOMAIN_KEY_SIZE, server_res->domainKey, SGX_DOMAIN_KEY_SIZE);

            for (unsigned long int i = 0; i < SGX_DOMAIN_KEY_SIZE; i++)
            {
                log_d("new domain_key from root[%u]=%2u\n", i, g_domainkey.domainkey[i]);
            }
            
            if (store_domain_key(g_domainkey.domainkey) != SGX_SUCCESS)
            {
                log_d("store_domain_key failed\n");
                continue;
            }

            log_d(TLS_SERVER "new domainkey received succeed:\n");

            memset(server_res, 0, sizeof(_response_header_t));
            server_res->type = MSG_ROTATE_END;

            g_ready_flag = true;
            log_i("ready flag change to %s\n", g_ready_flag == true ? "true" : "false");

            //Send MSG_ROTATE_END to all connected clients
            for (int i = 0; i < CONCURRENT_MAX; i++)
            {
                if (g_client_session[i].ssl_session != NULL)
                {
                    if (!SendAll(g_client_session[i].ssl_session,
                                 server_res,
                                 sizeof(_response_header_t)))
                    {
                        log_d("failed to send ROTATION_START datas\n");
                        continue;
                    }
                }
            }
            break;

        case MSG_ROTATE_START:
            g_ready_flag = false;
            log_i("ready flag change to %s\n", g_ready_flag == true ? "true" : "false");
            
            //Send MSG_ROTATE_START to all connected clients
            for (int i = 0; i < CONCURRENT_MAX; i++)
            {
                if (g_client_session[i].ssl_session != NULL)
                {
                    if (!SendAll(g_client_session[i].ssl_session,
                                 server_res,
                                 sizeof(_response_header_t)))
                    {
                        log_d("failed to send ROTATION_START datas\n");
                        continue;
                    }
                }
            }
            break;

        case MSG_ROTATE_END:
            if (req_domainkey(g_ssl_session) < 0)
            {
                log_d("send get_domainkey cmd failed\n");
            }

            break;

        default:
            break;
        }

        //root server only needs to get the domainkey once
        if (strncmp(g_server_role.c_str(), ROLE_ROOT, strlen(g_server_role.c_str())) == 0 &&
            server_res->type == MSG_DOMAINKEY)
        {
            if (g_socket_fd != -1)
            {
                int closeRet;
                ocall_close(&closeRet, g_socket_fd);
            }

            if (g_ssl_session)
            {
                SSL_shutdown(g_ssl_session);
                SSL_free(g_ssl_session);
            }
            break;
        }
    }

    SAFE_FREE(server_res);

    return ((void *)0);
}

static void *Client_Heart(void *args)
{
    (void)args;

    int len = 0;
    int error = 0;
    int bytes_written = 0;
    int numberOfErrors = 0;

    _response_header_t *server_res = NULL;
    server_res = (_response_header_t *)malloc(sizeof(_response_header_t));
    server_res->type = MSG_HEARTBEAT;

    //reconnect after three failures
    while (true)
    {
        if (g_ssl_session == nullptr || g_socket_fd == -1)
        {
            t_sleep(1);
            continue;
        }

        while (numberOfErrors <= MAX_RECONNECT)
        {
            log_i("client->server heart start");
            if (!SendAll(g_ssl_session, server_res, sizeof(_response_header_t)))
                numberOfErrors++;
            else
                numberOfErrors = 0;
            log_i("client->server heart end");
            t_sleep(10);
        }
        while (true)
        {
            // Empty g_socket_fd and g_ssl_session
            if (g_socket_fd != -1)
            {
                int closeRet;
                ocall_close(&closeRet, g_socket_fd);
                if (closeRet != 0)
                {
                    log_d(TLS_CLIENT "OCALL: error close socket\n");
                    continue;
                }
            }
            if (g_ssl_session)
            {
                SSL_shutdown(g_ssl_session);
                SSL_free(g_ssl_session);
            }
            // Reconnect to the target server
            if (connect_target_server(g_server_name.c_str(), g_server_port) < 0)
            {
                log_d(TLS_SERVER "connect to target failed\n");
                continue;
            }
            numberOfErrors = 0;
            if (req_domainkey(g_ssl_session) < 0)
            {
                log_d("send get_domainkey cmd failed\n");
                continue;
            }
            break;
        }
    }
    return ((void *)0);
}

sgx_status_t get_domainkey_from_target(const char *target_server_name,
                                       uint16_t target_server_port)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (target_server_name[0] == '\0')
        return ret;

    pthread_t sniffer_thread;
    pthread_t heart_thread;

    _response_header_t *server_res = NULL;

    if (connect_target_server(target_server_name, target_server_port) < 0)
    {
        log_d(TLS_SERVER "connect to target failed\n");
        goto out;
    }

    //  start heart thread
    if (strncmp(g_server_role.c_str(), ROLE_WORKER, strlen(g_server_role.c_str())) == 0)
    {
        log_d("create Client_Heart thread\n");
        if (pthread_create(&heart_thread, NULL, Client_Heart, NULL) < 0)
        {
            log_d("could not create Client_Heart thread\n");
            goto out;
        }
    }

    // start the communication
    // Read the HTTP response from target server
    if (pthread_create(&sniffer_thread, NULL, ClientSocketMsgHandler, NULL) < 0)
    {
        log_d("could not create sniffer thread\n");
        goto out;
    }

    // Write an GET request to the target server
    if (req_domainkey(g_ssl_session) < 0)
    {
        log_d("send get_domainkey cmd failed\n");
        goto out;
    }

    ret = SGX_SUCCESS;

out:
    log_d(TLS_SERVER "get domain key from target server %s\n", (ret == SGX_SUCCESS) ? "success" : "failed");
    return ret;
}

sgx_status_t create_new_domainkey(uint8_t *domainkey)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_read_rand(domainkey, SGX_DOMAIN_KEY_SIZE);
    if (ret != SGX_SUCCESS)
        return ret;

    log_i("start store domain key to disk");
    ret = store_domain_key(domainkey);
    if (ret != SGX_SUCCESS)
        return ret;

    return ret;
}

sgx_status_t get_domainkey_from_local(uint8_t *domain_key)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t dk_cipher_len = sgx_calc_sealed_data_size(0, SGX_DOMAIN_KEY_SIZE);

    if (dk_cipher_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    int retstatus;
    uint8_t dk_cipher[dk_cipher_len] = {0};
    uint8_t tmp[SGX_DOMAIN_KEY_SIZE] = {0};

    ret = ocall_read_domain_key(&retstatus,
                                dk_cipher,
                                dk_cipher_len,
                                &g_domainkey.createTime,
                                g_domainkey.dk_hash,
                                DOMAINKEY_HASH_SIZE);
    if (ret != SGX_SUCCESS)
        return ret;

    if (retstatus == 0)
    {
        uint32_t dk_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)dk_cipher);

        ret = sgx_unseal_data((const sgx_sealed_data_t *)dk_cipher, NULL, 0, tmp, &dk_len);
        if (ret != SGX_SUCCESS)
            return ret;
    }
    // -2: dk file does not exist.
    else if (retstatus == -2)
    {
        log_d("enclave file does not exist.\n");

        ret = create_new_domainkey(tmp);
        if (ret != SGX_SUCCESS)
            return ret;
    }
    else
        return SGX_ERROR_UNEXPECTED;

    memcpy_s(domain_key, SGX_DOMAIN_KEY_SIZE, tmp, SGX_DOMAIN_KEY_SIZE);
    memset_s(tmp, SGX_DOMAIN_KEY_SIZE, 0, SGX_DOMAIN_KEY_SIZE);
    g_ready_flag = true;
    log_i("ready flag change to %s\n", g_ready_flag == true ? "true" : "false");

    return ret;
}

sgx_status_t sgx_get_domainkey(const char *target_server_name,
                               uint16_t target_server_port)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int errorNumber = 0;

    log_i("start get domain key from target server. \n");
    ret = get_domainkey_from_target(target_server_name, target_server_port);
    if (strncmp(g_server_role.c_str(), ROLE_WORKER, strlen(g_server_role.c_str())) == 0 && ret != SGX_SUCCESS)
    {
        log_e("worker get domain key from target failed. \n");
        return ret;
    }

    t_sleep(10);
    if (g_ready_flag == false && strncmp(g_server_role.c_str(), ROLE_ROOT, strlen(g_server_role.c_str())) == 0)
    {
        log_i("start get domain key from disk\n");
        ret = get_domainkey_from_local(g_domainkey.domainkey);
    }

    return ret;
}

int ecall_reencrypt_cmk(uint8_t *cipher_dk,
                        uint32_t cipher_dk_len,
                        ehsm_keyblob_t *cmk,
                        size_t cmk_size)
{
    uint8_t *key = NULL;
    uint8_t tmp[SGX_DOMAIN_KEY_SIZE] = {0};
    uint32_t keyblob_size = 0;
    int ret = SGX_ERROR_UNEXPECTED;

    uint32_t dk_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)cipher_dk);
    if (sgx_unseal_data((const sgx_sealed_data_t *)cipher_dk, NULL, 0, tmp, &dk_len) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    uint32_t key_size = ehsm_get_gcm_ciphertext_size((sgx_aes_gcm_data_ex_t *)cmk->keyblob);
    keyblob_size = key_size;
    log_i("keyblob_size=%d", key_size);

    SHA256(g_domainkey.domainkey, SGX_DOMAIN_KEY_SIZE, cmk->metadata.dk_hashcode);

    key = (uint8_t *)malloc(keyblob_size);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    //Decrypt keyblob with the domainkey
    if (SGX_SUCCESS != ehsm_parse_keyblob(key, (sgx_aes_gcm_data_ex_t *)cmk->keyblob, tmp))
    {
        log_d("ehsm_parse_keyblob failed\n");
        goto out;
    }
    //Encrypt keyblob with the latest cmk
    if (SGX_SUCCESS != ehsm_create_keyblob(key, keyblob_size, (sgx_aes_gcm_data_ex_t *)cmk->keyblob, g_domainkey.domainkey))
    {
        log_d("ehsm_create_keyblob failed\n");
        goto out;
    }
    ret = SGX_SUCCESS;

out:
    if (key)
    {
        memset_s(key, keyblob_size, 0, keyblob_size);
        free(key);
    }

    return ret;
}

static void *rotationTimerListener(void *arg)
{
    log_i("rotation thread start.");
    log_i("g_nextRotationTime %d.", g_nextRotationTime);
    time_t current_time;
    int bytes_written;
    int test_error;
    int failed_number;
    uint32_t dk_cipher_len = sgx_calc_sealed_data_size(0, SGX_DOMAIN_KEY_SIZE);
    uint8_t dk_cipher[dk_cipher_len] = {0};
    int ret;
    _response_header_t *server_req = (_response_header_t *)malloc(sizeof(_response_header_t));

    while (true)
    {
        t_time(&current_time);
        // TODO : g_nextRotationTime always > 0
        if (current_time >= g_nextRotationTime && g_nextRotationTime > 0)
        {
            g_ready_flag = false;
            log_i("ready flag change to %s\n", g_ready_flag == true ? "true" : "false");
            server_req->type = MSG_ROTATE_START;
            //
            for (int i = 0; i < CONCURRENT_MAX; i++)
            {
                if (g_client_session[i].ssl_session != NULL)
                {
                    if (!SendAll(g_client_session[i].ssl_session,
                                 server_req,
                                 sizeof(_response_header_t)))
                    {
                        log_d("failed to send ROTATION_START datas");
                        continue;
                    }
                    else
                    {
                        log_i("send to fd=%d", SSL_get_fd(g_client_session[i].ssl_session));
                    }
                }
            }
            log_i("server sleep 60s for client change flag.");
            t_sleep(60);
            log_i("rotation start.");
            //Generate a new domainkey
            uint8_t new_domainkey[SGX_DOMAIN_KEY_SIZE] = {0};
            if (create_new_domainkey(new_domainkey) != SGX_SUCCESS)
                continue;

            memcpy_s(g_domainkey.domainkey, SGX_DOMAIN_KEY_SIZE, new_domainkey, SGX_DOMAIN_KEY_SIZE);

            int ret;

            ret = update_couch_db(CMK_INFO, KEYBLOB);
            if (ret == -1)
            {
                log_i("goto out");
                goto out;
            }

            ret = update_couch_db(USER_INFO, CMK);
            if (ret == -1)
            {
                log_i("goto out");
                goto out;
            }

            ret = update_couch_db(USER_INFO, SM_DEFAULT_CMK);
            if (ret == -1)
            {
                log_i("goto out");
                goto out;
            }

            log_i("UPDATE_CMK ok");
            server_req->type = MSG_ROTATE_END;
            g_ready_flag = true;
            log_i("ready flag change to %s\n", g_ready_flag == true ? "true" : "false");

            for (int i = 0; i < CONCURRENT_MAX; i++)
            {
                if (g_client_session[i].ssl_session != NULL)
                {
                    if (!SendAll(g_client_session[i].ssl_session,
                                 server_req,
                                 sizeof(_response_header_t)))
                    {
                        log_d("failed to send ROTATION_END datas\n");
                        continue;
                    }
                }
            }

        out:
            // always
            if (g_period == -1)
                g_nextRotationTime = -1;
            else
                g_nextRotationTime = g_domainkey.createTime + g_period * 24 * 60 * 60;
        }
        t_sleep(5);
    }
    log_i("rotation thread end.");
}

int sgx_set_up_tls_server(char *server_port,
                          const char *server_role,
                          const char *target_server_name,
                          uint16_t target_server_port,
                          size_t root_password,
                          int root_period)
{
    int ret = -1;
    int server_socket_fd;
    int client_socket_fd = -1;
    unsigned int server_port_number;
    int retval = 0;

    X509 *certificate = nullptr;
    EVP_PKEY *pkey = nullptr;
    SSL_CONF_CTX *ssl_confctx = SSL_CONF_CTX_new();
    SSL_CTX *ssl_server_ctx = nullptr;
    pthread_t sniffer_thread;

    if (root_period >= 0)
    {
        log_d("set period to %dd\n", root_period);
        g_period = root_period;
    }

    g_password = root_password;
    g_server_role = server_role;
    g_server_name = target_server_name;
    g_server_port = target_server_port;

    if (server_port == NULL)
    {
        log_e(TLS_SERVER "Failed to get server_port\n");
        goto exit;
    }

    if ((ssl_server_ctx = SSL_CTX_new(TLS_server_method())) == nullptr)
    {
        log_e(TLS_SERVER "unable to create a new SSL context\n");
        goto exit;
    }

    if (SSL_CTX_set_cipher_list(ssl_server_ctx, "TLS_AES_256_GCM_SHA384") != SGX_SUCCESS)
    {
        log_e(TLS_SERVER "unable to create SSL_CTX_set_cipher_list\n ");
        goto exit;
    }

    if (initalize_ssl_context(ssl_confctx, ssl_server_ctx) != SGX_SUCCESS)
    {
        log_e(TLS_SERVER "unable to create a initialize SSL context\n ");
        goto exit;
    }
    SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, &verify_callback);

    if (load_tls_certificates_and_keys(ssl_server_ctx, certificate, pkey) != 0)
    {
        log_e(TLS_SERVER
              " unable to load certificate and private key on the server\n ");
        goto exit;
    }

    // get domainkey
    if (sgx_get_domainkey(target_server_name, target_server_port) != SGX_SUCCESS)
    {
        log_e("Failed to get domain key.\n");
        goto exit;
    }
    // update dkeyserver status
    if (ocall_set_dkeyserver_done(&retval) != SGX_SUCCESS)
    {
        log_e("OCALL status failed .\n");
        goto exit;
    }
    if (retval != 0)
    {
        log_e("Dkeyserver service setting isready status failed .\n");
        goto exit;
    }

    //root server start a rotation time listener thread
    if (strncmp(g_server_role.c_str(), ROLE_ROOT, strlen(g_server_role.c_str())) == 0)
    {
        if (g_period < 0)
            g_nextRotationTime = g_period;
        else
            g_nextRotationTime = g_domainkey.createTime + root_period * 24 * 60 * 60;
        pthread_create(&sniffer_thread, NULL, rotationTimerListener, NULL);
    }

    server_port_number = (unsigned int)atoi(server_port); // convert to char* to int
    if (create_listener_socket(server_port_number, server_socket_fd) != 0)
    {
        log_e(TLS_SERVER "unable to create listener socket on the server\n ");
        goto exit;
    }

    // handle communication
    ret = handle_communication_until_done(
        server_socket_fd,
        client_socket_fd,
        ssl_server_ctx);
    if (ret != 0)
    {
        log_e(TLS_SERVER "server communication error %d\n", ret);
        goto exit;
    }

exit:
    if (ssl_server_ctx)
        SSL_CTX_free(ssl_server_ctx);
    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);
    if (certificate)
        X509_free(certificate);
    if (pkey)
        EVP_PKEY_free(pkey);
    return ret;
}
