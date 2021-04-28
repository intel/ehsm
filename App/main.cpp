#include <stdio.h>
#include <enclave_u.h>

#include <socket_server.h>

using namespace std;
using namespace socket_server;

void ocall_print_string(const char *str)
{
     printf("%s", str);
}


int main(int argc, char* argv[]) {
    printf("initialize socket server\n");
    SocketServer *ss = new SocketServer();
    if (!ss) {
        printf("failed to initialze the socket server\n");
        return -1;
    }

    ss->Initialize();
    return 0;
}

