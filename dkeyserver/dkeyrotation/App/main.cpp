#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string>
#include <unistd.h>
#include <iostream>

#include <enclave_u.h>
#include <getopt.h>

// Need to create enclave and do ecall.
#include "sgx_urts.h"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fifo_def.h"
#include "datatypes.h"
#include "json_utils.h"

#include "auto_version.h"

#define __STDC_FORMAT_MACROS
#define ENCLAVE_PATH "libenclave-ehsm-dkeyrotation.signed.so"
#include <inttypes.h>

using namespace std;

sgx_enclave_id_t g_enclave_id;

int ocall_close(int fd)
{
    return close(fd);
}

void ocall_printf(const char *str)
{
    printf("%s", str);
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
    int32_t retry_count = 60;
    do
    {
        int ret = connect(sockfd, servaddr, addrlen);
        if (ret >= 0)
            return ret;

        printf("Failed to Connect dkeyserver, sleep 0.5s and try again...\n");
        usleep(500000); // 0.5s
    } while (retry_count-- > 0);

    printf("Failed to connect dkeyserver.\n");
    return -1;
}

std::string deploy_ip_addr;
uint32_t key;
std::string action;
uint16_t deploy_port = 0;
static const char *_sopts = "i:p:k:a:";
static const struct option _lopts[] = {{"ip", required_argument, NULL, 'i'},
                                       {"port", required_argument, NULL, 'p'},
                                       {"key", required_argument, NULL, 'k'},
                                       {"action", required_argument, NULL, 'a'},
                                       {0, 0, 0, 0}};

static void show_usage_and_exit(int code)
{
    printf("Required parameters:\n"
           " -i     ip\n"
           " -p     port\n"
           " -k     key\n"
           " -a     action:\n"
           "        start_rotation, stop_auto_rotation, set_period\n"
           "        get_period, get_next_rotation_time, update_cmk\n");
    exit(code);
}

void ocall_sleep(int sec)
{
    sleep(sec);
}

static void parse_args(int argc, char *argv[])
{
    int opt;
    int oidx = 0;
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
                deploy_port = std::stoi(strdup(optarg));
            }
            catch (...)
            {
                printf("[-p %s] port must be a number.", optarg);
            }
            break;
        case 'k':
            key = std::stoi(strdup(optarg));
            break;
        case 'a':
            action = strdup(optarg);
            break;
        default:
            show_usage_and_exit(EXIT_FAILURE);
        }
    }
    if (deploy_ip_addr.empty() || deploy_port == 0)
        show_usage_and_exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    // process argv
    parse_args(argc, argv);

    int ret = 0;

    ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                             SGX_DEBUG_FLAG,
                             NULL,
                             NULL,
                             &g_enclave_id, NULL);
    if (SGX_SUCCESS != ret)
    {
        printf("failed to create enclave.\n");
        return -1;
    }

    // Connect to the dkeyserver and retrieve the domain key via the remote secure channel
    ret = enclave_launch_tls_client(g_enclave_id, &ret, deploy_ip_addr.c_str(), deploy_port,
                                    key, action.c_str());

    if (ret != 0)
        sgx_destroy_enclave(g_enclave_id);

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}
