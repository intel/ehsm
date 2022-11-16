#include <stdio.h>
#include <enclave_u.h>
#include "sgx_urts.h"

#include "auto_version.h"
#include "log_utils.h"
#include "enclave_u.h"
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <getopt.h>

#define ENCLAVE_PATH "libenclave-ehsm-dkeyserver.signed.so"
#define FILE_NAME "/etc/dkey.bin"
#define ROLE_WORKER "worker"
#define ROLE_ROOT "root"
char s_port[] = "8888";

sgx_enclave_id_t g_enclave_id;

using namespace std;

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

int ocall_close(int fd)
{
    return close(fd);
}

void ocall_get_current_time(uint64_t *p_current_time)
{
    time_t rawtime;
    time(&rawtime);

    if (!p_current_time)
        return;
    *p_current_time = (uint64_t)rawtime;
}

int ocall_set_dkeyserver_done()
{
    return (system("touch /tmp/dkeyserver_isready.status"));
}

static inline bool file_exists(const std::string &name)
{
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

int ocall_read_domain_key(uint8_t *cipher_dk, uint32_t cipher_dk_len)
{
    if (!file_exists(FILE_NAME))
    {
        printf("ocall_read_domain_key file does not exist.\n");
        return -2;
    }

    fstream file;
    file.open(FILE_NAME, ios::in | ios::binary);
    if (!file)
    {
        printf("Failed to open file...\n");
        return -1;
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);
    if (size != cipher_dk_len)
    {
        printf("mismatched length: %ld:%d.\n", size, cipher_dk_len);
        return -1;
    }

    uint8_t tmp[size] = {0};
    if (file.read((char *)&tmp, size))
    {
        memcpy(cipher_dk, tmp, cipher_dk_len);
    }
    else
    {
        printf("Failed to read data from file...\n");
        return -1;
    }

    file.close();

    return 0;
}

int ocall_store_domain_key(uint8_t *cipher_dk, uint32_t cipher_dk_len)
{
    uint8_t tmp[cipher_dk_len];
    memcpy(tmp, cipher_dk, cipher_dk_len);

    fstream file;
    file.open(FILE_NAME, ios::out | ios::binary | ios::trunc);
    if (!file)
    {
        printf("Failed to create file...\n");
        return -1;
    }

    file.write((char *)&tmp, cipher_dk_len);
    file.close();

    return 0;
}

/* ocalls to use socket APIs , call socket syscalls */

int ocall_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int ocall_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    return bind(fd, addr, len);
}

int ocall_listen(int fd, int n)
{
    return listen(fd, n);
}

int ocall_accept(int fd,
                 struct sockaddr *addr,
                 socklen_t addrlen_in,
                 socklen_t *addrlen_out)
{
    int ret = -1;

    if ((ret = accept(fd, addr, &addrlen_in)) != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }
    return ret;
}

int ocall_setsockopt(int sockfd,
                     int level,
                     int optname,
                     const void *optval,
                     socklen_t optlen)
{
    return setsockopt(sockfd, level, optname, optval, optlen);
}

int ocall_connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{
    int32_t retry_count = 60;
    do
    {
        int ret = connect(sockfd, servaddr, addrlen);
        if (ret >= 0)
            return ret;

        log_i("Failed to connect target server, sleep 0.5s and try again...\n");
        usleep(500000); // 0.5s
    } while (retry_count-- > 0);

    log_e("Failed to connect target server.\n");
    return -1;
}

void print_usage(int code)
{
    printf ("Usage: ehsm-dkeyserver "\
            BLUE "-r" NONE " [ server role ] "\
            BLUE "-i" NONE " [ target server ip ] "\
            BLUE "-p" NONE " [target server port]\n");
    printf (BLUE "-h" NONE"    Print usage information and quit.\n"
            BLUE "-r" NONE"    Set the role of this machine as root or worker in server cluster.\n"
            BLUE "-i" NONE"    Set the ip address of target server.\n"
            BLUE "-p" NONE"    Set the port of target server.\n");
    exit(code);
}

static void parse_args(int argc,
                       char *argv[],
                       string& server_role,
                       string& target_ip_addr,
                       uint16_t *target_port)
{
    int opt;
    int oidx = 0;
    static const char *_sopts = "r:i:p:h";
    static const struct option _lopts[] = {{"role", required_argument, NULL, 'r'},
                                           {"ip", optional_argument, NULL, 'i'},
                                           {"port", optional_argument, NULL, 'p'},
                                           {"help", no_argument, NULL, 'h'},
                                           {0, 0, 0, 0}};
    while ((opt = getopt_long(argc, argv, _sopts, _lopts, &oidx)) != -1)
    {
        switch (opt)
        {
        case 'r':
            server_role = strdup(optarg);
            if (server_role != ROLE_ROOT && server_role != ROLE_WORKER)
            {
                log_e("please set server role with -r by 'worker' or 'root'.\n");
                print_usage(EXIT_FAILURE);
            }
            break;
        case 'i':
            target_ip_addr = strdup(optarg);
            break;
        case 'p':
            try
            {
                *target_port = std::stoi(strdup(optarg));
            }
            catch (...)
            {
                log_e("[-p %s] port must be a number.", optarg);
            }
            break;
	case 'h':
            print_usage(EXIT_SUCCESS);
            break;
        default:
            log_e("unrecognized option (%c):\n", opt);
	    print_usage(EXIT_FAILURE);
        }
    }
}

int validate_parameter(string server_role,
                       string target_ip_addr,
                       uint16_t target_port)
{
    if (server_role[0] == '\0')
    {
        log_e("please set server role with -r by 'worker' or 'root'.\n");
        return -1;
    }
    if (target_ip_addr[0] == '\0' &&
        target_port == 0 &&
        server_role == ROLE_WORKER)
    {
        log_e("please set a correct target server for worker node.\n");
        return -1;
    }
    if (target_ip_addr[0] == '\0' && target_port != 0)
    {
        log_e("please set correct target server ip and port.\n");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) 
{
    log_i("Service name:\t\tDomainKey Provisioning Service %s", EHSM_VERSION);
    log_i("Service built:\t\t%s", EHSM_DATE);
    log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);
    string server_role;
    string target_ip_addr;
    uint16_t target_port = 0;

    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    parse_args(argc,
               argv,
               server_role,
               target_ip_addr,
               &target_port);

    int ret = validate_parameter(server_role, target_ip_addr, target_port);
    if (ret != 0)
    {
        printf ("Usage: ehsm-dkeyserver "\
                BLUE "-r" NONE " [server role] "\
                BLUE "-i" NONE " [target server ip] "\
                BLUE "-p" NONE " [target server port]\n");
        return -1;
    }
    
    ret = sgx_create_enclave(ENCLAVE_PATH,
                             SGX_DEBUG_FLAG,
                             NULL, NULL,
                             &g_enclave_id, NULL);
    if (SGX_SUCCESS != ret)
    {
        log_e("failed(%d) to create enclave.\n", ret);
        return -1;
    }

    ret = sgx_set_up_tls_server(g_enclave_id,
                                &ret,
                                s_port,
                                server_role.c_str(),
                                target_ip_addr.c_str(),
                                target_port);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
    {
        log_d("Host: setup_tls_server failed\n");
    }

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}
