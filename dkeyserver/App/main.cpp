#include <stdio.h>
#include <enclave_u.h>
#include "sgx_urts.h"

#include <socket_server.h>
#include "auto_version.h"
#include "log_utils.h"
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <getopt.h>
#include "ra_getkey.h"

#define ENCLAVE_PATH "libenclave-ehsm-dkeyserver.signed.so"
#define FILE_NAME "/etc/dkey.bin"

extern sgx_enclave_id_t g_enclave_id;

using namespace std;
using namespace socket_server;
using namespace ra_getkey;

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

static inline bool file_exists(const std::string& name) {
    struct stat buffer;
    return (stat (name.c_str(), &buffer) == 0);
}

int ocall_read_domain_key(uint8_t* cipher_dk, uint32_t cipher_dk_len)
{
    if (!file_exists(FILE_NAME)) {
        printf("ocall_read_domain_key file does not exist.\n");
        return -2;
    }

    fstream file;
    file.open(FILE_NAME, ios::in|ios::binary);
    if (!file){
        printf("Failed to open file...\n");
        return -1;
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);
    if (size != cipher_dk_len) {
        printf("mismatched length: %ld:%d.\n", size, cipher_dk_len);
        return -1;
    }

    uint8_t tmp[size] = {0};
    if (file.read((char*)&tmp, size)) {
        memcpy(cipher_dk, tmp, cipher_dk_len);
    }
    else {
        printf("Failed to read data from file...\n");
        return -1;
    }

    file.close();

    return 0;
}

int ocall_store_domain_key(uint8_t* cipher_dk, uint32_t cipher_dk_len)
{
    uint8_t tmp[cipher_dk_len];
    memcpy(tmp, cipher_dk, cipher_dk_len);

    if (file_exists(FILE_NAME)) {
        printf("file already exist, substitute by new file\n");
    }

    fstream file;
    file.open(FILE_NAME, ios::out|ios::binary|ios::trunc);
    if (!file) {
        printf("Failed to create file...\n");
        return -1;
    }

    file.write((char*)&tmp, cipher_dk_len);
    file.close();

    return 0;
}

std::string deploy_ip_addr;
uint32_t deploy_port = 0;
static const char* _sopts = "i:p:";
static const struct option _lopts[] = {{"ip", required_argument, NULL, 'i'},
                                       {"port", required_argument, NULL, 'p'},
                                       {0, 0, 0, 0}};

static void show_usage_and_exit(int code) {
    printf("\nusage: ehsm-dkeyserver -i [ActiveServer ip] -p [port]\n\n");
    exit(code);
}
static void parse_args(int argc, char* argv[]) {
    int opt;
    int oidx = 0;
    while ((opt = getopt_long(argc, argv, _sopts, _lopts, &oidx)) != -1) {
        switch (opt) {
            case 'i':
                deploy_ip_addr = optarg;
                break;
            case 'p':
                try {
                    deploy_port = std::stoi(optarg);
                }
                catch (...) {
                    log_e("port must be a number.");
                }
                break;
            default:
                log_e("unrecognized option (%c):\n", opt);
                show_usage_and_exit(EXIT_FAILURE);
        }
    }
    if (deploy_ip_addr.empty() || deploy_port == 0) {
        printf("error: missing required argument(s)\n");
        show_usage_and_exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {

    log_i("Service name:\t\tDomainKey Provisioning Service %s", EHSM_VERSION);
    log_i("Service built:\t\t%s", EHSM_DATE);
    log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);

    int ret = sgx_create_enclave(ENCLAVE_PATH,
                                 SGX_DEBUG_FLAG,
                                 NULL, NULL,
                                 &g_enclave_id, NULL);
    if (SGX_SUCCESS != ret) {
        log_e("failed(%d) to create enclave.\n", ret);
        return -1;
    }

    if (argc > 1) {
        // process argv
        parse_args(argc, argv);
        log_i("DomainKey Server IP:\t\t%s", deploy_ip_addr.c_str());
        log_i("DomainKey Server port:\t%d", deploy_port);
        ret = Initialize_ra(deploy_ip_addr, deploy_port);
        if (ret != 0) {
            sgx_destroy_enclave(g_enclave_id);
            return -1;
        }
    }

    Initialize();

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}
