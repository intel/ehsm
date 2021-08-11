#include <stdio.h>
#include <enclave_u.h>

#include <socket_server.h>

using namespace std;
using namespace socket_server;

void ocall_print_string(const char *str)
{
     printf("%s", str);
}


int main() {
    Initialize();

    return 0;
}

