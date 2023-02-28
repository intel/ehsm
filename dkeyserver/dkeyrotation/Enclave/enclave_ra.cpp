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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <byteswap.h>

#include "sgx_trts.h"
#include "openssl_utility.h"
#include "enclave_t.h"
#include "datatypes.h"

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

void log_printf(uint32_t log_level, const char *filename, uint32_t line, const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_printf(buf);
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_printf(buf);
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

// This routine conducts a simple HTTP request/response communication with server
static int communicate_with_server(SSL *ssl, uint32_t key, const char *action)
{
    unsigned char buf[200] = {0};
    int ret = 1;
    int error = 0;
    int bytes_written = 0;
    int bytes_read = 0;

    _response_header_t *heart_msg = NULL;
    heart_msg = (_response_header_t *)malloc(sizeof(_response_header_t));

    _request_header_t *send_msg = (_request_header_t *)malloc(sizeof(_request_header_t));
    if (send_msg == NULL)
    {
        return -1;
    }

    send_msg->password = key;

    if (!strcasecmp(action, "start_rotation"))
    {
        send_msg->cmd = START_ROTATION;
    }
    else if (!strcasecmp(action, "stop_auto_rotation"))
    {
        send_msg->cmd = STOP_AUTO_ROTATION;
    }
    else if (!strcasecmp(action, "set_period"))
    {
        send_msg->cmd = SET_PERIOD;
    }
    else if (!strcasecmp(action, "get_period"))
    {
        send_msg->cmd = GET_PERIOD;
    }
    else if (!strcasecmp(action, "get_next_rotation_time"))
    {
        send_msg->cmd = GET_NEXT_ROTATION_DATETIME;
    }
    else if (!strcasecmp(action, "update_cmk"))
    {
        send_msg->cmd = UPDATE_CMK;
    }
    else
    {
        return -1;
    }

    // Write an GET request to the server
    int len = sizeof(_request_header_t);

    log_i("rotation = %d\n", SSL_get_fd(ssl));

    while ((bytes_written = SSL_write(ssl, (char *)send_msg, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        ret = bytes_written;
        goto done;
    }

    // Read the HTTP response from server
    while (1)
    {
        memset(buf, 0, 200);

        bytes_read = SSL_read(ssl, buf, sizeof(buf) - 1);
        log_i("bytes_read=%d\n", bytes_read);

        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;
            ret = bytes_read;
            break;
        }
        else
        {
            memcpy(heart_msg, buf, sizeof(_response_header_t));

            if (heart_msg->type == MSG_HEARTBEAT)
            {
                printf("this is a heart message");
                continue;
            }

            printf("========================================\n");
            printf("res msg: %s\n", buf);
            printf("========================================\n");
        }

        ret = 0;

        break;
    }
done:

    // ocall_sleep(10);
    return ret;
}

// create a socket and connect to the server_name:server_port
int create_socket(const char *server_name, uint16_t server_port)
{
    int sockfd = -1;
    struct sockaddr_in dest_sock;
    int res = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
        goto done;

    dest_sock.sin_family = AF_INET;
    dest_sock.sin_port = htons(server_port);
    dest_sock.sin_addr.s_addr = inet_addr2(server_name);
    bzero(&(dest_sock.sin_zero), sizeof(dest_sock.sin_zero));

    if (connect(
            sockfd, (sockaddr *)&dest_sock,
            sizeof(struct sockaddr)) == -1)
    {
        ocall_close(&res, sockfd);
        sockfd = -1;
        goto done;
    }

done:
    return sockfd;
}

int enclave_launch_tls_client(const char *server_name, uint16_t server_port, uint32_t key, const char *action)
{
    int ret = -1;

    SSL_CTX *ssl_client_ctx = nullptr;
    SSL *ssl_session = nullptr;

    X509 *cert = nullptr;
    EVP_PKEY *pkey = nullptr;
    SSL_CONF_CTX *ssl_confctx = SSL_CONF_CTX_new();

    int client_socket = -1;
    int error = 0;
    if (server_name == NULL)
        goto done;

    if ((ssl_client_ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
        goto done;

    if (SSL_CTX_set_cipher_list(ssl_client_ctx, "TLS_AES_256_GCM_SHA384") != SGX_SUCCESS)
        goto done;

    if (initalize_ssl_context(ssl_confctx, ssl_client_ctx) != SGX_SUCCESS)
        goto done;

    // specify the verify_callback for custom verification
    SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, &verify_callback);
    if (load_tls_certificates_and_keys(ssl_client_ctx, cert, pkey) != 0)
        goto done;

    if ((ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
        goto done;

    client_socket = create_socket(server_name, server_port);
    if (client_socket == -1)
        goto done;

    // set up ssl socket and initiate TLS connection with TLS server
    SSL_set_fd(ssl_session, client_socket);

    if ((error = SSL_connect(ssl_session)) != 1)
        goto done;

    // start the client server communication
    if ((error = communicate_with_server(ssl_session, key, action)) != 0)
        goto done;

    // Free the structures we don't need anymore

    ret = 0;
done:

    if (client_socket != -1)
    {
        int closeRet;
        ocall_close(&closeRet, client_socket);
        if (closeRet != 0)
            ret = -1;
    }

    if (ssl_session)
    {
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
    }

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
