/**
 *
 * MIT License
 *
 * Copyright (c) Open Enclave SDK contributors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 *
 */

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <string>
#include <stdarg.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <byteswap.h>

#include "openssl_utility.h"
#include "enclave_t.h"
#include "elog_utils.h"
#include "datatypes.h"

#define RECONNECT_TIMES 3

#define ROTATE_START true

#define ROTATE_END false

uint8_t g_domain_key[SGX_DOMAIN_KEY_SIZE] = {0};

SSL *g_ssl_session = nullptr;

std::string g_server_name;

uint16_t g_server_port = 0;

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

void log_printf(uint32_t log_level, const char* filename, uint32_t line, const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(log_level, buf, filename, line);
}

void t_time(time_t *current_t)
{
    ocall_get_current_time((uint64_t *)current_t);
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

// support socket APIs inside enclave
// for socket APIs, refer to https://en.wikipedia.org/wiki/Berkeley_sockets
int socket(int domain, int type, int protocol)
{
    int ret = -1;

    if (ocall_socket(&ret, domain, type, protocol) == SGX_SUCCESS)
        return ret;

    return -1;
}

int connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{
    int ret = -1;

    if (ocall_connect(&ret, sockfd, servaddr, addrlen) == SGX_SUCCESS)
        return ret;

    return -1;
}

unsigned long inet_addr2(const char *str)
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

// create a socket and connect to the server_name:server_port
int create_socket(const char *server_name, uint16_t server_port)
{
    int sockfd = -1;
    struct sockaddr_in dest_sock;
    int res = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        log_d(TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
        goto done;
    }

    dest_sock.sin_family = AF_INET;
    dest_sock.sin_port = htons(server_port);
    dest_sock.sin_addr.s_addr = inet_addr2(server_name);
    bzero(&(dest_sock.sin_zero), sizeof(dest_sock.sin_zero));

    if (connect(
            sockfd, (sockaddr *)&dest_sock,
            sizeof(struct sockaddr)) == -1)
    {
        log_d(
            TLS_CLIENT "failed to connect to %d:%d (errno=%d)\n",
            server_port,
            server_port,
            errno);
        ocall_close(&res, sockfd);
        if (res != 0)
            log_d(TLS_CLIENT "OCALL: error closing socket\n");
        sockfd = -1;
        goto done;
    }
    log_d(TLS_CLIENT "connected to %s:%d\n", server_name, server_port);

done:
    return sockfd;
}

// send msg to g_ssl_session
static bool SendAll(const void *data, int32_t data_size)
{
    const char *data_ptr = (const char *)data;
    int32_t bytes_sent;
    int error = 0;

    while ((bytes_sent = SSL_write(g_ssl_session, data_ptr, data_size)) <= 0)
    {
        error = SSL_get_error(g_ssl_session, bytes_sent);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        log_d(TLS_SERVER "Failed! SSL_write returned %d\n", error);
        return false;
    }
    log_d(TLS_SERVER "%d bytes sent\n", bytes_sent);
    return true;
}


// receive msg from g_ssl_session
static bool RecvAll(void *data, int32_t data_size)
{
    char *data_ptr = (char *)data;
    int32_t bytes_recv;
    int error = 0;

    while (true)
    {
        bytes_recv = SSL_read(g_ssl_session, data_ptr, data_size);
        if (bytes_recv <= 0)
        {
            error = SSL_get_error(g_ssl_session, bytes_recv);
            if (error == SSL_ERROR_WANT_READ)
                continue;
            log_d(TLS_SERVER "Failed! SSL_read returned error=%d\n", error);
            return false;
        }
        log_d(TLS_SERVER "%d bytes recv\n", bytes_recv);
        return true;
    }
    return true;
}

// send get domainkey request to dkeyserver worker
int SendGetDomainkeyReq()
{
    int ret = 1;

    _request_header_t *req = nullptr;
    _response_header_t *resp = nullptr;

    log_d(TLS_CLIENT "-----> Write getdomainkey cmd to server:\n");

    req = (_request_header_t *)malloc(sizeof(_request_header_t));
    resp = (_response_header_t *)malloc(sizeof(_response_header_t));

    if (req == nullptr || resp == nullptr)
    {
        log_d(TLS_CLIENT "getDomainkey malloc failed\n");
        goto out;
    }
    req->cmd = GET_DOMAINKEY;

    if (!SendAll(req, sizeof(_request_header_t)))
    {
        goto out;
    }
    ret = 0;

out:
    SAFE_FREE(req);
    return ret;
}

// set up tls channel with g_ssl_session and send get domainkey request to dkeyserver worker
int enclave_connect_and_get_domainkey()
{
    int ret = -1;

    SSL_CTX *ssl_client_ctx = nullptr;
    SSL *ssl_session = nullptr;

    X509 *cert = nullptr;
    EVP_PKEY *pkey = nullptr;
    SSL_CONF_CTX *ssl_confctx = SSL_CONF_CTX_new();

    int client_socket = -1;
    int error = 0;

    log_d("\nStarting" TLS_CLIENT "\n\n\n");

    if ((ssl_client_ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
    {
        log_d(TLS_CLIENT "unable to create a new SSL context\n");
        goto done;
    }

    if (SSL_CTX_set_cipher_list(ssl_client_ctx, "TLS_AES_256_GCM_SHA384") != SGX_SUCCESS)
    {
        log_d(TLS_CLIENT "unable to create SSL_CTX_set_cipher_list\n ");
        goto done;
    }

    if (initalize_ssl_context(ssl_confctx, ssl_client_ctx) != SGX_SUCCESS)
    {
        log_d(TLS_CLIENT "unable to create a initialize SSL context\n ");
        goto done;
    }

    // specify the verify_callback for custom verification
    SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, &verify_callback);
    log_d(TLS_CLIENT "load cert and key\n");
    if (load_tls_certificates_and_keys(ssl_client_ctx, cert, pkey) != 0)
    {
        log_d(TLS_CLIENT
              " unable to load certificate and private key on the client\n");
        goto done;
    }

    if ((g_ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
    {
        log_d(TLS_CLIENT
              "Unable to create a new SSL connection state object\n");
        goto done;
    }

    log_d(TLS_CLIENT "new ssl connection getting created\n");
    client_socket = create_socket(g_server_name.c_str(), g_server_port);
    if (client_socket == -1)
    {
        log_d(
            TLS_CLIENT
            "create a socket and initiate a TCP connect to server: %s:%d "
            "(errno=%d)\n",
            g_server_name,
            g_server_port,
            errno);
        goto done;
    }

    // set up ssl socket and initiate TLS connection with TLS server
    if (SSL_set_fd(g_ssl_session, client_socket) != 1)
    {
        log_d(TLS_CLIENT "ssl set fd error.\n");
    }
    else
    {
        log_d(TLS_CLIENT "ssl set fd succeed.\n");
    }

    if ((error = SSL_connect(g_ssl_session)) != 1)
    {
        log_d(
            TLS_CLIENT "Error: Could not establish a TLS session ret2=%d "
                       "SSL_get_error()=%d\n",
            error,
            SSL_get_error(g_ssl_session, error));
        goto done;
    }
    log_d(
        TLS_CLIENT "successfully established TLS channel:%s\n",
        SSL_get_version(g_ssl_session));

    if ((error = SendGetDomainkeyReq()) != 0)
    {
        log_d(TLS_CLIENT "Failed: get domainkey (ret=%d)\n", error);
        goto done;
    }

    // Free the structures we don't need anymore
    ret = 0;
done:

    if (cert)
        X509_free(cert);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (ssl_client_ctx)
        SSL_CTX_free(ssl_client_ctx);

    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);
    if (ret == -1)
    {
        SSL_shutdown(g_ssl_session);
        if (g_ssl_session)
            SSL_free(g_ssl_session);
    }
    return ret;
}

// send heartbeat to dkeyserver worker if connection lost then reconnect and get new domainkey
static void *HeartbeatToServerHandler(void *arg)
{
    int numberOfErrors = 0;
    int res = -1;
    bool is_ready = false;
    _response_header_t *heart_beat = nullptr;
    heart_beat = (_response_header_t *)malloc(sizeof(_response_header_t));

    if (heart_beat == nullptr)
    {
        log_d(TLS_CLIENT "HeartbeatToServer malloc failed\n");
        goto out;
    }
    heart_beat->type = MSG_HEARTBEAT;

    while (true)
    {
        if (g_ssl_session != nullptr)
        {
            while (numberOfErrors < RECONNECT_TIMES)
            {
                
                if (!SendAll(heart_beat, sizeof(_response_header_t)))
                {
                    numberOfErrors++;
                }
                else
                {
                    numberOfErrors = 0;
                }
                ocall_sleep(5); // sleep 5s.
            }
            // send failed reach max time then reconnect
            if (g_ssl_session)
            {
                SSL_shutdown(g_ssl_session);
                SSL_free(g_ssl_session);
                ocall_close(&res, SSL_get_fd(g_ssl_session));
                g_ssl_session = nullptr;
            }
            if (0 != enclave_connect_and_get_domainkey())
            {
                log_d(TLS_CLIENT "Failed: reconnect_with_server\n");
                ocall_update_is_ready(&is_ready);
            }
            numberOfErrors = 0;
        }
    }
out:
    SAFE_FREE(heart_beat);
    pthread_exit((void *)-1);
}

int UpdateRotateFlag(bool rotate_flag)
{
    int ret = 0;
    if (ocall_update_rotate_flag(&rotate_flag) != SGX_SUCCESS)
    {
        ret = 1;
        log_e("OCALL status failed.\n");
    }
    return ret;
}

static void *RecvMsgHandler(void *args)
{
    int ret = 1;
    _response_header_t *recv_msg = nullptr;
    recv_msg = (_response_header_t *)malloc(sizeof(_response_header_t));
    if (recv_msg == nullptr)
    {
        log_d(TLS_CLIENT "getDomainkey malloc failed\n");
    }

    while (true)
    {
        if (g_ssl_session == nullptr)
        {
            continue;
        }

        memset(recv_msg, 0, sizeof(_response_header_t));
        RecvAll(recv_msg, sizeof(_response_header_t));

        switch (recv_msg->type)
        {
        case MSG_ROTATE_START:
        {
            if (UpdateRotateFlag(ROTATE_START))
            {
                log_d(TLS_CLIENT "Failed: update rotate flag\n");
                ret = -1;
                goto done;
            }
        }
        break;
        case MSG_ROTATE_END:
        {
            if ((ret = SendGetDomainkeyReq()) != 0)
            {
                log_d(TLS_CLIENT "Failed: get send get domainkey req\n");
                goto done;
            }
        }
        break;
        case MSG_DOMAINKEY:
        {
            ret = 0;
            memcpy(g_domain_key, recv_msg->domainKey, SGX_DOMAIN_KEY_SIZE);
            log_i("Successfully received the DomainKey from deploy server.\n");
            for (unsigned long int i = 0; i < SGX_DOMAIN_KEY_SIZE; i++)
            {
                log_d("domain_key[%u]=%2u\n", i, g_domain_key[i]);
            }
            int retval = 0;
            if (UpdateRotateFlag(ROTATE_END))
            {
                log_d(TLS_CLIENT "Failed: update rotate flag\n");
                ret = -1;
                goto done;
            }
        }
        break;
        default:
            break;
        }
    }
done:
    SAFE_FREE(recv_msg);
    pthread_exit((void *)-1);
}

int enclave_launch_tls_client(const char *server_name, uint16_t server_port)
{
    log_d(TLS_CLIENT " called launch tls client\n");

    int ret = -1;
    if (server_name == nullptr)
    {
        log_d(TLS_CLIENT "Failed: null server_name");
        goto done;
    }

    g_server_name = server_name;
    g_server_port = server_port;
    if (0 != enclave_connect_and_get_domainkey())
    {
        log_d(TLS_CLIENT "Failed: reconnect_with_server\n");
        goto done;
    }

    pthread_t heartbeat_to_server_thread, recvmsg_thread;
    if (pthread_create(&heartbeat_to_server_thread, NULL, HeartbeatToServerHandler, NULL) < 0)
    {
        log_d("could not create thread\n");
        goto done;
    }

    if (pthread_create(&recvmsg_thread, NULL, RecvMsgHandler, NULL) < 0)
    {
        log_d("could not create thread\n");
        goto done;
    }

    // Free the structures we don't need anymore
    ret = 0;
done:
    log_d(TLS_CLIENT " %s\n", (ret == 0) ? "success" : "failed");
    return ret;
}
