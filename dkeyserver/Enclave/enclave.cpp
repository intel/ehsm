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
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "byteswap.h"
#include "openssl_utility.h"
#include "datatypes.h"

#define CLIENT_MAX_NUM 20
#define ROLE_WORKER "worker"
#define ROLE_ROOT "root"

typedef struct SocketMsgHandlerParam
{
    int client_socket_fd;
    SSL_CTX *ssl_server_ctx;
    SSL *ssl_session;
    uint8_t *domainkey;
} SocketMsgHandlerParam;

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

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

static void *SocketMsgHandler(void *arg)
{
    if (arg == NULL)
    {
        log_d(TLS_SERVER
              "arg cannot be obtained\n");
        return ((void *)0);
    }
    SSL *ssl_session = nullptr;
    SocketMsgHandlerParam handler_ctx = *(SocketMsgHandlerParam *)arg;
    int test_error = 1;
    int ret = -1;
    // create a new SSL structure for a connection
    if ((ssl_session = SSL_new(handler_ctx.ssl_server_ctx)) == nullptr)
    {
        log_d(TLS_SERVER
              "Unable to create a new SSL connection state object\n");
        goto exit;
    }

    if (SSL_set_fd(ssl_session, handler_ctx.client_socket_fd) != 1)
    {
        log_d(TLS_SERVER
              "SSL set fd failed\n");
        goto exit;
    }

    // wait for a TLS/SSL client to initiate a TLS/SSL handshake
    log_i(TLS_SERVER "initiating a passive connect SSL_accept\n");
    test_error = SSL_accept(ssl_session);
    if (test_error <= 0)
    {
        log_d(TLS_SERVER " SSL handshake failed, error(%d)(%d)\n",
              test_error, SSL_get_error(ssl_session, test_error));
        goto exit;
    }

    log_d(TLS_SERVER "<---- Read from client:\n");
    if (read_from_session_peer(
            ssl_session, CLIENT_PAYLOAD, CLIENT_PAYLOAD_SIZE) != 0)
    {
        log_d(TLS_SERVER " Read from client failed\n");
        goto exit;
    }

    for (int i = 0; i < SGX_DOMAIN_KEY_SIZE; i++)
    {
        log_d("domain_key[%d]=%2u", i, handler_ctx.domainkey[i]);
    }

    log_d(TLS_SERVER "<---- Write to client:\n");
    if (write_to_session_peer(
            ssl_session, handler_ctx.domainkey, SGX_DOMAIN_KEY_SIZE) != 0)
    {
        log_d(TLS_SERVER " Write to client failed\n");
        goto exit;
    }
    if (handler_ctx.client_socket_fd > 0)
    {
        ocall_close(&ret, handler_ctx.client_socket_fd);
        if (ret != 0)
        {
            log_d(TLS_SERVER "OCALL: error closing client socket before starting a new TLS session.\n");
            goto exit;
        }
    }
exit:
    SSL_free(ssl_session);
    log_i("write domainkey to clent success\n");
    return ((void *)0);
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

int handle_communication_until_done(
    int &server_socket_fd,
    int &client_socket_fd,
    SSL_CTX *&ssl_server_ctx,
    uint8_t *domainkey)
{
    int ret = -1;
    // waiting_for_connection_request:
    struct sockaddr_in addr;
    uint len = sizeof(addr);

    // reset ssl_session and client_socket_fd to prepare for the new TLS
    // connection

    log_i(TLS_SERVER " waiting for client connection\n");

waiting_for_connection_request:

    client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&addr, &len);

    if (client_socket_fd < 0)
    {
        log_d(TLS_SERVER "Unable to accept the client request\n");
        goto exit;
    }

    SocketMsgHandlerParam param;
    param.client_socket_fd = client_socket_fd;
    param.ssl_server_ctx = ssl_server_ctx;
    param.domainkey = domainkey;

    pthread_t sniffer_thread;
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
            TLS_SERVER "failed to connect to target server %s:%d (errno=%d)\n",
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

sgx_status_t get_domainkey_from_target(uint8_t *domain_key,
                                       const char *target_server_name,
                                       uint16_t target_server_port)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (target_server_name[0] == '\0')
        return ret;

    SSL_CTX *ssl_client_ctx = nullptr;
    SSL *ssl_session = nullptr;

    X509 *cert = nullptr;
    EVP_PKEY *pkey = nullptr;
    SSL_CONF_CTX *ssl_confctx = SSL_CONF_CTX_new();

    int client_socket = -1;
    int error = 0;
    unsigned char buf[200];
    int len = 0;
    int bytes_written = 0;
    int bytes_read = 0;

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

    if ((ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
    {
        log_e(TLS_SERVER "Unable to create a new SSL connection state object\n");
        goto out;
    }

    log_d(TLS_SERVER "New ssl connection getting created\n");
    client_socket = create_socket(target_server_name, target_server_port);
    if (client_socket == -1)
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
    if (SSL_set_fd(ssl_session, client_socket) != 1)
    {
        log_e(TLS_SERVER "Ssl set fd error.\n");
        goto out;
    }

    if ((error = SSL_connect(ssl_session)) != 1)
    {
        log_e(TLS_SERVER "Error: Could not establish a TLS session ret2=%d "
                         "SSL_get_error()=%d\n",
              error,
              SSL_get_error(ssl_session, error));
        goto out;
    }
    log_d(TLS_SERVER "successfully established TLS channel:%s\n",
          SSL_get_version(ssl_session));

    // start the communication
    // Write an GET request to the target server
    log_d(TLS_SERVER "-----> Write to server:\n");
    len = snprintf((char *)buf, sizeof(buf) - 1, CLIENT_PAYLOAD);

    while ((bytes_written = SSL_write(ssl_session, buf, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        log_e(TLS_SERVER "Failed! SSL_write returned %d\n", error);
        goto out;
    }

    log_d(TLS_SERVER "%d bytes written\n", bytes_written);

    // Read the HTTP response from target server
    log_d(TLS_SERVER "<---- Read from server:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset_s(buf, sizeof(buf), 0, sizeof(buf));
        bytes_read = SSL_read(ssl_session, buf, (size_t)len);

        if (bytes_read <= 0)
        {
            error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            log_e(TLS_SERVER "Failed! SSL_read returned error=%d\n", error);
            goto out;
        }

        log_d(TLS_SERVER " %d bytes read\n", bytes_read);

        if (bytes_read != SGX_DOMAIN_KEY_SIZE)
        {
            log_e(
                TLS_SERVER "ERROR: expected reading %ul bytes but only "
                           "received %d bytes\n",
                SGX_DOMAIN_KEY_SIZE,
                bytes_read);
            goto out;
        }
        else
        {
            memcpy_s(domain_key, SGX_DOMAIN_KEY_SIZE, buf, SGX_DOMAIN_KEY_SIZE);
            memset_s(buf, SGX_DOMAIN_KEY_SIZE, 0, SGX_DOMAIN_KEY_SIZE);
            log_i(TLS_SERVER "domainkey received succeed:\n");
            break;
        }
    } while (1);

    for (int i = 0; i < SGX_DOMAIN_KEY_SIZE; i++)
    {
        log_d("domain_key[%d]=%2u", i, domain_key[i]);
    }

    ret = SGX_SUCCESS;

out:

    if (client_socket != -1)
    {
        int closeRet;
        ocall_close(&closeRet, client_socket);
        if (closeRet != 0)
        {
            log_e(TLS_CLIENT "OCALL: error close socket\n");
            ret = SGX_ERROR_UNEXPECTED;
        }
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

    log_i(TLS_SERVER "get domain key from target server %s\n", (ret == SGX_SUCCESS) ? "success" : "failed");
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

    ret = ocall_read_domain_key(&retstatus, dk_cipher, dk_cipher_len);
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
        ret = sgx_read_rand(tmp, SGX_DOMAIN_KEY_SIZE);
        if (ret != SGX_SUCCESS)
            return ret;
    }
    else
        return SGX_ERROR_UNEXPECTED;

    if (memcpy_s(domain_key, SGX_DOMAIN_KEY_SIZE, tmp, SGX_DOMAIN_KEY_SIZE))
        return SGX_ERROR_UNEXPECTED;
    if (memset_s(tmp, SGX_DOMAIN_KEY_SIZE, 0, SGX_DOMAIN_KEY_SIZE))
        return SGX_ERROR_UNEXPECTED;

    return ret;
}

sgx_status_t store_domain_key(uint8_t *domain_key)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t dk_cipher_len = sgx_calc_sealed_data_size(0, SGX_DOMAIN_KEY_SIZE);
    uint8_t dk_cipher[dk_cipher_len] = {0};
    int retstatus;

    ret = sgx_seal_data(0, NULL, SGX_DOMAIN_KEY_SIZE, domain_key, dk_cipher_len, (sgx_sealed_data_t *)dk_cipher);
    if (ret != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    ret = ocall_store_domain_key(&retstatus, dk_cipher, dk_cipher_len);
    if (ret != SGX_SUCCESS || retstatus != 0)
        return SGX_ERROR_UNEXPECTED;

    return ret;
}

sgx_status_t sgx_get_domainkey(uint8_t *domain_key,
                               const char *server_role,
                               const char *target_server_name,
                               uint16_t target_server_port)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    if (domain_key == NULL)
    {
        log_e("domain key is null. \n");
        return ret;
    }

    log_i("start get domain key from target server. \n");
    ret = get_domainkey_from_target(domain_key, target_server_name, target_server_port);
    if (strncmp(server_role, ROLE_WORKER, strlen(server_role)) == 0 && ret != SGX_SUCCESS)
    {
        log_i("worker get domain key from target failed. \n");
        return ret;
    }

    if (strncmp(server_role, ROLE_ROOT, strlen(server_role)) == 0 && ret != SGX_SUCCESS)
    {
        log_i("start get domain key from disk\n");
        ret = get_domainkey_from_local(domain_key);
    }

    if (ret == SGX_SUCCESS)
    {
        log_i("start store domain key to disk\n");
        ret = store_domain_key(domain_key);
    }

    return ret;
}

int sgx_set_up_tls_server(char *server_port,
                          const char *server_role,
                          const char *target_server_name,
                          uint16_t target_server_port)
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
    uint8_t domain_key[SGX_DOMAIN_KEY_SIZE];

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
    if (sgx_get_domainkey(domain_key,
                          server_role,
                          target_server_name,
                          target_server_port) != SGX_SUCCESS)
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

    server_port_number = (unsigned int)atoi(server_port); // convert to char* to int
    if (create_listener_socket(server_port_number, server_socket_fd) != 0)
    {
        log_e(TLS_SERVER " unable to create listener socket on the server\n ");
        goto exit;
    }

    // handle communication
    ret = handle_communication_until_done(
        server_socket_fd,
        client_socket_fd,
        ssl_server_ctx,
        domain_key);
    if (ret != 0)
    {
        log_e(TLS_SERVER "server communication error %d\n", ret);
        goto exit;
    }

exit:
    int closeRet;
    ocall_close(&closeRet, client_socket_fd); // close the socket connections
    if (closeRet != 0)
    {
        log_e(TLS_SERVER "OCALL: error closing client socket\n");
        ret = -1;
    }
    ocall_close(&closeRet, server_socket_fd);
    if (closeRet != 0)
    {
        log_e(TLS_SERVER "OCALL: error closing server socket\n");
        ret = -1;
    }
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
