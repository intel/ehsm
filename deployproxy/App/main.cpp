#include <stdint.h>
#include <stdio.h>
#include <signal.h>

#include <enclave_u.h>

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


#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

LaTask * g_la_task = NULL;
LaServer * g_la_server = NULL;

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

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

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

    /* Connect to the deploy service*/
    if(!IsConnected()) {
        printf("try to connect to the socket server.\n");
        Connect();
    }

    /* Initialize a socket server and wait for the connecttion */
    //Initialize();

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
         printf("fail to init server\n");
    }else
    {
         printf("Server is ON...\n");
         printf("Press Ctrl+C to exit...\n");
         g_la_server->doWork();
    }

    /* close the socket connection */
    //DisConnect();

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}

