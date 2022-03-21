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

	log_i("Server version name:\teHSM-KMS DomainKey Server %s", VERSION);
	log_i("Server built:\t\t%s", DATE);

    Initialize();

    return 0;
}

