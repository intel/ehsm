#include <enclave_u.h>

#include <stdio.h>
#include <memory>
#include <string.h>
#include <error.h>
#include <socket_client.h>

using namespace std;
using namespace socket_client;

void ocall_print_string(const char *str)
{
     printf("%s", str);
}


int main(int argc, char* argv[])
{   
    int ret = 0;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;

    
    SocketClient *sc = new SocketClient();
    if(!sc) {
        printf("failed to initialize the socket client\n");
        return ERR_GENERIC;
    }

    if(!sc->IsOpen()) {
        printf("try to connect to the socket server\n");
        sc->Open();
    }

    char *testmsg = "helloworld!";

    /* construct the MSG0 */
    p_msg0_full = (ra_samp_request_header_t *)
            malloc(sizeof(ra_samp_request_header_t)
            +strlen(testmsg));
    if (!p_msg0_full) {
        printf("failed to allocate memory\n");
        return -1;
    }

    p_msg0_full->size = strlen(testmsg)+1;
    p_msg0_full->type = TYPE_RA_MSG0;

    memcpy_s(p_msg0_full->body, p_msg0_full->size, testmsg, p_msg0_full->size);

    sc->SendAndRecvMsg(p_msg0_full, &p_msg0_resp_full);

    char *rsp_body = (char *)p_msg0_resp_full+sizeof(ra_samp_response_header_t);
    for(uint32_t i=0; i<p_msg0_resp_full->size; i++) {
        printf("%c", rsp_body[i]);
    }
    printf("\n");

    sc->FreeRespBuf(p_msg0_resp_full);
    return ret;
}


