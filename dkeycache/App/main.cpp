#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string>
#include <unistd.h>

#include <enclave_u.h>
#include <getopt.h>
#include "ulog_utils.h"

// Need to create enclave and do ecall.
#include "sgx_urts.h"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fifo_def.h"
#include "datatypes.h"

#include "la_task.h"
#include "la_server.h"
#include "auto_version.h"

#define __STDC_FORMAT_MACROS
#define ENCLAVE_PATH "libenclave-ehsm-dkeycache.signed.so"
#include <inttypes.h>

using namespace std;

sgx_enclave_id_t g_enclave_id;

void ocall_print_string(uint32_t log_level, const char *str, const char *filename, uint32_t line)
{
    switch (log_level)
    {
    case LOG_INFO:
    case LOG_DEBUG:
    case LOG_ERROR:
    case LOG_WARN:
        log_c(log_level, str, filename, line);
        break;
    default:
        log_c(LOG_ERROR, "log system error in ocall print.\n", filename, line);
        break;
    }
}

int ocall_close(int fd)
{
    return close(fd);
}

void ocall_get_current_time(uint64_t *p_current_time)
{
    time_t rawtime;
    time(&rawtime);

    if (!p_current_time)
        return;
    *p_current_time = (uint64_t)rawtime;
}

/* ocalls to use socket APIs , call socket syscalls */

int ocall_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int ocall_connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{
    int32_t retry_count = 10;
    do
    {
        int ret = connect(sockfd, servaddr, addrlen);
        if (ret >= 0)
            return ret;

        log_i("Failed to Connect dkeyserver, sleep 0.5s and try again...\n");
        usleep(500000); // 0.5s
    } while (retry_count-- > 0);

    log_e("Failed to connect dkeyserver.\n");
    return -1;
}

int ocall_set_dkeycache_done()
{
    return (system("touch /tmp/dkeycache_isready.status"));
}

LaTask *g_la_task = NULL;
LaServer *g_la_server = NULL;

void signal_handler(int sig)
{
    switch (sig)
    {
    case SIGINT:
    case SIGTERM:
    {
        if (g_la_server)
            g_la_server->shutDown();
    }
    break;
    default:
        break;
    }

    exit(1);
}

void cleanup()
{
    if (g_la_task != NULL)
        delete g_la_task;
    if (g_la_server != NULL)
        delete g_la_server;
}

static void show_usage_and_exit(int code)
{
    log_i("\nusage: ehsm-dkeycache -i 127.0.0.1 -p 8888\n\n");
    exit(code);
}
static void parse_args(int argc, char *argv[],
                       string &deploy_ip_addr,
                       uint16_t *deploy_port)
{
    int opt;
    int oidx = 0;
    static const char *_sopts = "i:p:";
    static const struct option _lopts[] = {{"ip", required_argument, NULL, 'i'},
                                       {"port", required_argument, NULL, 'p'},
                                       {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, _sopts, _lopts, &oidx)) != -1)
    {
        switch (opt)
        {
        case 'i':
            deploy_ip_addr = strdup(optarg);
            break;
        case 'p':
            try
            {
                *deploy_port = std::stoi(strdup(optarg));
            }
            catch (...)
            {
                log_e("[-p %s] port must be a number.", optarg);
            }
            break;
        default:
            log_e("unrecognized option (%c):\n", opt);
            show_usage_and_exit(EXIT_FAILURE);
        }
    }
    if (deploy_ip_addr.empty() || *deploy_port == 0)
    {
        log_e("error: missing required argument(s)\n");
        show_usage_and_exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    // mkdir RUNTIME_FOLDER
    if (access(EHSM_RUNTIME_FOLDER, F_OK) != 0)
    {
        printf("Initializing runtime folder [path: %s].\n", EHSM_RUNTIME_FOLDER);
        if (mkdir(EHSM_RUNTIME_FOLDER, 0755) != 0)
        {
            printf("Create runtime folder failed!\n");
            return -1;
        }
    }
    if (initLogger("dkeycache.log") < 0)
        return -1;
    log_i("Service name:\t\tDomainKey Caching Service %s", EHSM_VERSION);
    log_i("Service built:\t\t%s", EHSM_DATE);
    log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);

    string deploy_ip_addr;
    uint16_t deploy_port = 0;

    // process argv
    parse_args(argc, argv, deploy_ip_addr, &deploy_port);

    log_i("Runtime folder:\t\t%s", EHSM_RUNTIME_FOLDER);
    log_i("DomainKey Server IP:\t\t%s", deploy_ip_addr.c_str());
    log_i("DomainKey Server port:\t%d", deploy_port);

    int ret = 0;
    int retval = -1;

    ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                             SGX_DEBUG_FLAG,
                             NULL,
                             NULL,
                             &g_enclave_id, NULL);
    if (SGX_SUCCESS != ret)
    {
        log_e("failed(%d) to create enclave.\n", ret);
        return -1;
    }

    // Connect to the dkeyserver and retrieve the domain key via the remote secure channel
    log_i("Host: launch TLS client to initiate TLS connection\n");
    ret = enclave_launch_tls_client(g_enclave_id, &retval, deploy_ip_addr.c_str(), deploy_port);
    if (SGX_SUCCESS != ret || retval != 0)
    {
        log_e("failed to initialize the dkeycache service.\n");
        goto out;
    }

    // create server instance, it would listen on sockets and proceeds client's requests
    g_la_task = new (std::nothrow) LaTask;
    g_la_server = new (std::nothrow) LaServer(g_la_task);

    if (!g_la_task || !g_la_server)
        goto out;

    atexit(cleanup);

    // register signal handler so to respond to user interception
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    g_la_task->start();

    if (g_la_server->init() != 0)
    {
        log_e("fail to init dkeycache service!\n");
    }
    else
    {
        log_i("dkeycache service is ON...\n");
        // printf("Press Ctrl+C to exit...\n");
        g_la_server->doWork();
    }
out:
    logger_shutDown();

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}
