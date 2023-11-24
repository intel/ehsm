#include <stdio.h>
#include <enclave_u.h>
#include "sgx_urts.h"

#include "auto_version.h"
#include "ulog_utils.h"
#include "enclave_u.h"
#include "datatypes.h"
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

#include <arpa/inet.h>

#define ENCLAVE_PATH "libenclave-ehsm-dkeyserver.signed.so"
#define ROLE_WORKER "worker"
#define ROLE_ROOT "root"
char s_port[] = "8888";
#define FILE_NAME (std::string(EHSM_LOCAL_DATA_FOLDER) + "dkey.bin").c_str()

sgx_enclave_id_t g_enclave_id;

using namespace std;

void ocall_print_string(uint32_t log_level, const char *str, const char *filename, uint32_t line)
{
    switch (log_level) 
    {
        case LOG_INFO:
        case LOG_DEBUG:
        case LOG_ERROR:
        case LOG_WARN:
            log_c(log_level, str, filename, line);
            break;
        default:
            log_c(LOG_ERROR, "log system error in ocall print.\n", filename, line);
            break;
    }
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
        log_e("ocall_read_domain_key file does not exist.\n");
        return -2;
    }

    fstream file;
    file.open(FILE_NAME, ios::in | ios::binary);
    if (!file)
    {
        log_e("Failed to open file...\n");
        return -1;
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);
    if (size != cipher_dk_len)
    {
        log_e("mismatched length: %ld:%d.\n", size, cipher_dk_len);
        return -1;
    }

    uint8_t tmp[size] = {0};
    if (file.read((char *)&tmp, size))
    {
        memcpy(cipher_dk, tmp, cipher_dk_len);
    }
    else
    {
        log_e("Failed to read data from file...\n");
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
        log_e("Failed to create file...\n");
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
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    log_d("New Client(%d) connected! IP=%s", fd, inet_ntoa(addr_in->sin_addr));
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
    int32_t retry_count = 10;
    do
    {
        int ret = connect(sockfd, servaddr, addrlen);
        if (ret >= 0)
            return ret;

        log_e("Failed to connect target server, sleep 0.5s and try again...\n");
        usleep(500000); // 0.5s
    } while (retry_count-- > 0);

    log_e("Failed to connect target server.\n");
    return -1;
}

void print_usage(int code)
{
    log_i("Usage: ehsm-dkeyserver "
          "-r [ server role ] "
          "-i [ target server ip ] "
          "-u [ target server url ] "
          "-p [target server port]\n");
    log_i("-h    Print usage information and quit.\n"
          "-r    Set the role of this machine as root or worker in server cluster.\n"
          "-i    Set the ip address of target server.\n"
          "-u    Set the url of target server.\n"
          "-p    Set the port of target server.\n");
    exit(code);
}

static void parse_args(int argc,
                       char *argv[],
                       string &server_role,
                       string &target_ip_addr,
                       uint16_t *target_port)
{
    int opt;
    int oidx = 0;
    string host;
    struct hostent *hptr;
    static const char *_sopts = "r:i:u:p:h";
    static const struct option _lopts[] = {{"role", required_argument, NULL, 'r'},
                                           {"ip", optional_argument, NULL, 'i'},
                                           {"url", optional_argument, NULL, 'u'},
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
        case 'u':
            host = strdup(optarg);
            hptr = gethostbyname(host.c_str());
            if (hptr == NULL || hptr->h_addr == NULL)
            {
                log_e("can't parse hostname [%s].", host.c_str());
            }
            else
            {
                target_ip_addr = inet_ntoa(*(struct in_addr *)hptr->h_addr_list[0]);
            }
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
    if (access(EHSM_RUNTIME_FOLDER, F_OK) != 0)
    {
        printf("Initializing runtime folder [path: %s].\n", EHSM_RUNTIME_FOLDER);
        if (mkdir(EHSM_RUNTIME_FOLDER, 0755) != 0)
        {
            printf("Create runtime folder failed!\n");
            return -1;
        }
    }
    if (access(EHSM_LOCAL_DATA_FOLDER, F_OK) != 0)
    {
        printf("Initializing local data folder [path: %s].\n", EHSM_LOCAL_DATA_FOLDER);
        if (mkdir(EHSM_LOCAL_DATA_FOLDER, 0755) != 0)
        {
            printf("Create local data folder failed!\n");
            return -1;
        }
    }
    if (access(EHSM_LOGS_FOLDER, F_OK) != 0)
    {
        printf("Initializing log folder [path: %s].\n", EHSM_LOGS_FOLDER);
        if (mkdir(EHSM_LOGS_FOLDER, 0755) != 0)
        {
            printf("Create log folder failed!\n");
            return -1;
        }
    }
    if (initLogger("dkeyserver.log") < 0)
        return -1;
    log_i("Service name:\t\tDomainKey Provisioning Service %s", EHSM_VERSION);
    log_i("Service built:\t\t%s", EHSM_DATE);
    log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);
    log_i("Runtime folder:\t%s", EHSM_RUNTIME_FOLDER);
    log_i("Local data folder:\t%s", EHSM_LOCAL_DATA_FOLDER);
    log_i("Log folder:\t%s", EHSM_LOGS_FOLDER);
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
        log_i("Usage: ehsm-dkeyserver "
              "-r [server role] "
              "-i [target server ip] "
              "-u [target server url] "
              "-p [target server port]\n");
        return -1;
    }

    if (target_ip_addr[0] == '\0')
    {
        log_i("Target Server:\tNULL");
    }
    else
    {
        log_i("Target Server:\t%s:%d", target_ip_addr.c_str(), target_port);
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

    logger_shutDown();

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}
