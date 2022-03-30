#include <stdio.h>
#include <enclave_u.h>

#include <socket_server.h>
#include "auto_version.h"
#include "log_utils.h"

using namespace std;
using namespace socket_server;

void ocall_print_string(const char *str)
{
     printf("%s", str);
}


int main() {

    log_i("Service name:\t\tDomainKey Provisioning Service %s", EHSM_VERSION);
    log_i("Service built:\t\t%s", EHSM_DATE);
    log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);

    Initialize();

    return 0;
}

