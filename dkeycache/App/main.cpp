#include <stdint.h>
#include <stdio.h>
#include <signal.h>

#include <enclave_u.h>
#include <getopt.h>
#include "log_utils.h"

// Need to create enclave and do ecall.
#include "sgx_urts.h"

#include "ra_client.h"

#include "fifo_def.h"
#include "datatypes.h"

#include "la_task.h"
#include "la_server.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

using namespace std;
using namespace ra_client;

extern sgx_enclave_id_t g_enclave_id;

void ocall_print_string(const char *str)
{
     printf("Enclave: %s", str);
}

LaTask * g_la_task = NULL;
LaServer * g_la_server = NULL;

std::string deploy_ip_addr;
uint32_t deploy_port = 0;
static const char* _sopts = "i:p:";
static const struct option _lopts[] = {{"ip", required_argument, NULL, 'i'},
                                       {"port", required_argument, NULL, 'p'},
                                       {0, 0, 0, 0}};

void signal_handler(int sig)
{
    switch(sig)
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
    if(g_la_task != NULL)
        delete g_la_task;
    if(g_la_server != NULL)
        delete g_la_server;
}

static void show_usage_and_exit(int code) {
    printf("\nusage: ehsm-dkeycache -i 127.0.0.1 -p 8888\n\n");
    exit(code);
}
static void parse_args(int argc, char* argv[]) {
    int opt;
    int oidx = 0;
    while ((opt = getopt_long(argc, argv, _sopts, _lopts, &oidx)) != -1) {
        switch (opt) {
            case 'i':
                deploy_ip_addr = strdup(optarg);
                break;
            case 'p':
                try {
                    deploy_port = std::stoi(strdup(optarg));
                }
                catch (...) {
                    log_e("[-p %s] port must be a number.", optarg);
                }
                break;
            default:
                log_e("unrecognized option (%c):\n", opt);
                show_usage_and_exit(EXIT_FAILURE);
        }
    }
    if (deploy_ip_addr.empty() || deploy_port == 0) {
        printf("error: missing required argument(s)\n");
        show_usage_and_exit(EXIT_FAILURE);
    }
    log_i("starting dkeycache");
    log_i("host: %s", deploy_ip_addr.c_str());
    log_i("port: %d", deploy_port);
}

int main(int argc, char* argv[])
{
    // process argv
    parse_args(argc, argv);

    int ret = 0;

    ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                                 SGX_DEBUG_FLAG,
                                 NULL,
                                 NULL,
                                 &g_enclave_id, NULL);
    if(SGX_SUCCESS != ret) {
        printf("failed(%d) to create enclave.\n", ret);
        return -1;
    }

    // Connect to the dkeyserver and retrieve the domain key via the remote secure channel
    ret = Initialize(deploy_ip_addr, deploy_port);
    if (ret != 0) {
        printf("failed to initialize the dkeycache service.\n");
        sgx_destroy_enclave(g_enclave_id);
    }

    // create server instance, it would listen on sockets and proceeds client's requests
    g_la_task = new (std::nothrow) LaTask;
    g_la_server = new (std::nothrow) LaServer(g_la_task);

    if (!g_la_task || !g_la_server)
         return -1;

    atexit(cleanup);

    // register signal handler so to respond to user interception
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    g_la_task->start();

    if (g_la_server->init() != 0)
    {
         printf("fail to init dkeycache service!\n");
    }else
    {
         printf("dkeycache service is ON...\n");
         //printf("Press Ctrl+C to exit...\n");
         g_la_server->doWork();
    }


    sgx_destroy_enclave(g_enclave_id);

    return 0;
}

