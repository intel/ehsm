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

    SocketClient *sc = new SocketClient();
    if(!sc) {
        printf("failed to initialize the socket client.\n");
        return -1;
    }

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
    if(!sc->IsOpen()) {
        printf("try to connect to the socket server.\n");
        sc->Open();
    }

    /* Initialize the socket server and wait the core service to connect */
    sc->Initialize();

    /* close the socket connection with deplopy service */
    sc->Close();

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}

