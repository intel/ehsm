#include <stdint.h>
#include <stdio.h>

#include <enclave_u.h>

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

#include "socket_client.h"

using namespace std;
using namespace socket_client;

extern sgx_enclave_id_t g_enclave_id;

void ocall_print_string(const char *str)
{
     printf("Enclave: %s", str);
}

int main(int argc, char* argv[])
{
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
    Initialize();

    /* close the socket connection */
    DisConnect();

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}

