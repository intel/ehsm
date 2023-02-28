#include <stdio.h>
#include <enclave_u.h>
#include "sgx_urts.h"
#include <sgx_uswitchless.h>

#include "auto_version.h"
#include "ulog_utils.h"
#include "enclave_u.h"
#include "datatypes.h"
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <getopt.h>
#include <typeinfo>
#include <arpa/inet.h>
#include <signal.h>
#include <thread>

#include "base64.h"
#include "couchdb_curl.h"
#include "datatypes.h"
#include "json_utils.h"

#define ENCLAVE_PATH "libenclave-ehsm-dkeyserver.signed.so"
#define ROLE_WORKER "worker"
#define ROLE_ROOT "root"
#define CMK_DB "cmk:"
#define USER_INFO_DB "user_info:"
char s_port[] = "8888";
#define FILE_NAME (std::string(RUNTIME_FOLDER) + "dkey.bin").c_str()

#define CMK_INFO 0
#define USER_INFO 1

#define KEYBLOB 0
#define CMK 1
#define SM_DEFAULT_CMK 2

sgx_enclave_id_t g_enclave_id = 0;
std::string g_couchdb_url;

using namespace std;

errno_t memcpy_s(
    void *dest,
    size_t numberOfElements,
    const void *src,
    size_t count)
{
    if (numberOfElements < count)
        return -1;
    memcpy(dest, src, count);
    return 0;
}

int ocall_select(int fd)
{
    fd_set server_fd_set;
    FD_ZERO(&server_fd_set);
    FD_SET(fd, &server_fd_set);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 5000;

    int ret = select(fd + 1, &server_fd_set, NULL, NULL, &tv);
    if (ret > 0)
    {
        if (FD_ISSET(fd, &server_fd_set))
        {
            log_d("%d\n", ret);
            return 1;
        }
    }

    sleep(1);

    return 0;
}

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

void ocall_sleep(int second)
{
    sleep(second);
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

int ocall_read_domain_key(uint8_t *cipher_dk,
                          uint32_t cipher_dk_len,
                          uint64_t *create_time,
                          uint8_t *dk_hash,
                          uint32_t dk_hash_size)
{
    if (!file_exists(FILE_NAME))
    {
        log_e("ocall_read_domain_key: file does not exist.\n");
        return -2;
    }

    fstream file;
    JsonReader reader;
    JsonValue value;
    uint64_t temp_time = 0;

    file.open(FILE_NAME, ios::in | ios::binary);
    if (!file)
    {
        log_e("ocall_read_domain_key: failed to open file\n");
        return -1;
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);

    uint8_t tmp_buf[size] = {0};
    
    //Get the latest domainkey json in buf
    if (file.read((char *)&tmp_buf, size))
    {
        if (!reader.parse((char *)tmp_buf, value))
            return -1;

        JsonValue::Members mem = value.getMemberNames();

        JsonObj latest_domainkey_json;
        latest_domainkey_json.addData_uint64("createDate", 0);

        for (auto iter = mem.begin(); iter != mem.end(); iter++)
        {
            for (auto iter = mem.begin(); iter != mem.end(); iter++)
            {
                if (value[*iter].type() == Json::objectValue)
                {
                    JsonObj temp;
                    temp.setJson(value[*iter]);
                    uint64_t time = temp.readData_uint64("createDate");
                    if (time > latest_domainkey_json.readData_uint64("createDate"))
                    {
                        latest_domainkey_json = temp;
                    }
                }
            }
        }
        //get the domainkey ciper, createdate and dk_hash in json
        *create_time = latest_domainkey_json.readData_uint64("createDate");
        memcpy(dk_hash,
               base64_decode(latest_domainkey_json.readData_string("dk_hashcode").c_str()).c_str(),
               32);

        log_i("base64 hash=%s", latest_domainkey_json.readData_string("dk_hashcode").c_str());
        log_i("createDate=%d", latest_domainkey_json.readData_uint64("createDate"));

        latest_domainkey_json.readData_uint8Array("dkey", cipher_dk);
    }
    else
    {
        log_e("ocall_read_domain_key: Failed to read data from file...\n");
        return -1;
    }

    file.close();

    return 0;
}

int ocall_store_domain_key(uint8_t *cipher_dk,
                           uint32_t cipher_dk_len,
                           uint8_t *dk_hash,
                           uint32_t dk_hash_size)
{
    fstream file;

    string dk_hash_base64 = base64_encode(dk_hash, dk_hash_size);

    if (!file_exists(FILE_NAME))
    {
        log_d("domain key file does not exist.\n");
        file.open(FILE_NAME, ios::out | ios::binary | ios::trunc);
        if (!file)
        {
            log_e("Failed to create file...\n");
            return -1;
        }
        file.write("{}", 3);
        file.close();
    }
    uint8_t tmp[cipher_dk_len];
    JsonObj domainkey_json;
    JsonObj storeJson;
    time_t createdate;

    time(&createdate);
    memcpy(tmp, cipher_dk, cipher_dk_len);

    file.open(FILE_NAME, ios::in | ios::binary);
    if (!file)
    {
        log_e("store_domain_key: Failed to open file...\n");
        return -1;
    }
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);
    char tmp_buf[size + 1] = {0};

    if (file.read(tmp_buf, size))
        storeJson.parse(tmp_buf);
    else
    {
        log_e("store_domain_key: Failed to read data from file...\n");
        return -1;
    }
    file.close();

    /*store json format:
    {
    "PHr4qY1m4afiJFgHoiRC4+Y2SP7oImkRqmBDFwA1LTk=":
    {createDate":"1673835139",
    "dk_hashcode":"PHr4qY1m4afiJFgHoiRC4+Y2SP7oImkRqmBDFwA1LTk=",
    "dkey":[4,0,2,0,0,0,0,0,5,8,8,9,255,255,0,0,0,0,0,1]}
    {
    "PHr4qY1m4afiJFgHoiRC4+Y2SP7oImkRqmBDFwA1LTk=":
    {createDate":"1673835139",
    "dk_hashcode":"PHr4qY1m4afiJFgHoiRC4+Y2SP7oImkRqmBDFwA1LTk=",
    "dkey":[4,0,2,0,0,0,0,0,5,8,8,9,255,255,0,0,0,0,0,1]}
    }
    */
    if (!storeJson.hasOwnProperty(dk_hash_base64))
    {
        domainkey_json.addData_uint8Array("dkey", tmp, cipher_dk_len);
        domainkey_json.addData_uint64("createDate", (uint64_t)createdate);
        domainkey_json.addData_string("dk_hashcode", dk_hash_base64);

        storeJson.addData_JsonValue(dk_hash_base64, domainkey_json.getJson());
        // log_d("storeJson=> %s", storeJson.toString().c_str());

        file.open(FILE_NAME, ios::out | ios::binary | ios::trunc);
        file.write(storeJson.toString().c_str(), strlen(storeJson.toString().c_str()));
        file.close();
    }

    log_i("new dkey base64 hash=%s", dk_hash_base64.c_str());
    log_i("new dkey createDate=%d", createdate);

    return 0;
}

/* ocalls to use socket APIs , call socket syscalls */

int ocall_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int ocall_send(int fd, const char *msg, uint32_t msg_size, int flag)
{
    return send(fd, msg, msg_size, flag);
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

std::vector<JsonObj> couchdb_data;

int ocall_load_couchdb(int db_type)
{
    int db_size;
    couchdb_data.clear();

    switch (db_type)
    {
    case CMK_INFO:
        db_size = couchdb_get(couchdb_data, CMK_DB, g_couchdb_url);
        break;
    case USER_INFO:
        db_size = couchdb_get(couchdb_data, USER_INFO_DB, g_couchdb_url);
        break;
    default:
        return 0;
    }

    if (db_size == 0)
    {
        log_d("no cmkdb data\n");
        return 0;
    }
    return db_size;
}

int update_CMK_by_dbName(std::string dbName,
                         std::string keyName,
                         uint8_t *cipher_cmk_dk,
                         uint32_t cipher_cmk_dk_len,
                         uint8_t *dk_hash)
{
    int error = 0;
    int ret;
    fstream file;
    JsonObj dkey_storeJson;
    JsonObj domainkeyJson;
    string cmk_dk_hash_base64;

    std::string cmk_str;
    string new_cmk;
    size_t cmk_size = 0;
    size_t new_cmk_size = 0;
    string new_dk_hash_base64 = base64_encode(dk_hash, 32);
    ehsm_keyblob_t *cmk = NULL;

    //read the local domainkey file
    file.open(FILE_NAME, ios::in | ios::binary);
    if (!file)
    {
        log_e("update_CMK_by_dbName: Failed to open file...\n");
        return -1;
    }
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);
    char tmp_buf[size] = {0};

    if (file.read(tmp_buf, size))
        dkey_storeJson.parse(tmp_buf);
    else
    {
        log_e("update_CMK_by_dbName: Failed to read data from file...\n");
        return -1;
    }
    file.close();

    auto iter = couchdb_data.at(0);
    log_i("iter0=%s", iter.toString().c_str());

    if (iter.hasOwnProperty("error"))
    {
        log_e("iter:\n%s", iter.toString().c_str());
        goto out;
    }
    //decode cmk from couchdb
    cmk_str = base64_decode(iter.readData_string(keyName));
    cmk_size = cmk_str.size();
    cmk = (ehsm_keyblob_t *)malloc(cmk_size);
    if (cmk == NULL)
    {
        log_e("cmk = NULL");
        goto out;
    }
    memcpy(cmk, (uint8_t *)cmk_str.data(), cmk_size);
    cmk_dk_hash_base64 = base64_encode(cmk->metadata.dk_hashcode, 32);
    //if dk_hash is the same, it is the latest version of domainkey and there is no need to re-encrypt cmk
    if (strncmp(cmk_dk_hash_base64.c_str(), new_dk_hash_base64.c_str(), new_dk_hash_base64.size()) == 0)
    {
        SAFE_FREE(cmk);
        log_i("this cmk has been updated");
        couchdb_data.erase(couchdb_data.begin());
        return 0;
    }
    //get the ciphertext of the domainkey used to encrypt the cmk
    domainkeyJson.setJson(dkey_storeJson.readData_JsonValue(cmk_dk_hash_base64));
    domainkeyJson.readData_uint8Array("dkey", cipher_cmk_dk);
    log_i("ecall_reencrypt_cmk in");
    error = ecall_reencrypt_cmk(g_enclave_id, &ret, cipher_cmk_dk, cipher_cmk_dk_len, cmk, APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen));
    if (ret != SGX_SUCCESS || error != SGX_SUCCESS)
    {
        SAFE_FREE(cmk);
        log_e("store new domain key failed (%d)(%d)", error, ret);
        goto out;
    }
    log_i("ecall_reencrypt_cmk out");
    // sleep(1);

    new_cmk_size = APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen);
    new_cmk = base64_encode((uint8_t *)cmk, new_cmk_size);
    
    if (new_cmk.size() > 0)
    {
        iter.addData_string(keyName, new_cmk);
        SAFE_FREE(cmk);
    }
    else
    {
        SAFE_FREE(cmk);
        goto out;
    }
    if (couchdb_put(iter, g_couchdb_url) < 0)
    {
        goto out;
    }
    //delete the processed data from the vector
    couchdb_data.erase(couchdb_data.begin());
    return 0;
out:
    couchdb_data.erase(couchdb_data.begin());
    return -1;
}

int ocall_update_CMK(uint8_t *cipher_dk,
                     uint32_t cipher_dk_len,
                     uint8_t *dk_hash,
                     uint32_t dk_hash_size,
                     int key_type)
{
    int ret = 0;

    std::string key;
    std::string db;
    switch (key_type)
    {
    case KEYBLOB:
        key = "keyBlob";
        db = CMK_DB;
        break;
    case CMK:
        key = "cmk";
        db = USER_INFO_DB;
        break;
    case SM_DEFAULT_CMK:
        key = "sm_default_cmk";
        db = USER_INFO_DB;
        break;
    default:
        return -1;
    }
    // update cmk_db data
    ret = update_CMK_by_dbName(db, key, cipher_dk, cipher_dk_len, dk_hash);
    if (ret == -1)
        return -1;

    return ret;
}

void print_usage(int code)
{
    log_i("Usage: ehsm-dkeyserver "
          "-r [ server role ] "
          "-w [ password ] "
          "-t [ period ] "
          "-u [ couchdb_url ] "
          "-i [ target server ip ] "
          "-p [target server port]\n");
    log_i("-h    Print usage information and quit.\n"
          "-r    Set the role of this machine as root or worker in server cluster.\n"
          "-i    Set the ip address of target server.\n"
          "-w    Set the password of root server.\n"
          "-u    Set the url to connect to couchdb, if you want use roration dk function, you must set couchdb_url. eg:http:// + user + : + password + @ + ip + : + port\n"
          "-P    Set the period of root server.\n");
    exit(code);
}

static void parse_args(int argc,
                       char *argv[],
                       string &server_role,
                       string &target_ip_addr,
                       string &couchdb_url,
                       uint16_t *target_port,
                       size_t *password,
                       int *period)
{
    int opt;
    int oidx = 0;
    static const char *_sopts = "r:i:p:h:w:P:u:";
    static const struct option _lopts[] = {{"role", required_argument, NULL, 'r'},
                                           {"ip", optional_argument, NULL, 'i'},
                                           {"port", optional_argument, NULL, 'p'},
                                           {"password", optional_argument, NULL, 'w'},
                                           {"period", optional_argument, NULL, 'P'},
                                           {"help", no_argument, NULL, 'h'},
                                           {"couchdb_url", optional_argument, NULL, 'u'},
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
            couchdb_url = strdup(optarg);
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
        case 'w':
            try
            {
                *password = std::stoi(strdup(optarg));
            }
            catch (...)
            {
                log_e("[-w %s] password must be a number.", optarg);
            }
            break;
        case 'P':
            try
            {
                *period = std::stoi(strdup(optarg));
                if (*period <= 30 || *period >= 365)
                {
                    log_e("the period must greater than 30 days and less than 365 days.");
                    print_usage(EXIT_FAILURE);
                }
            }
            catch (...)
            {
                log_e("[-t %s] period time must be a number.", optarg);
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
                       string couchdb_url,
                       uint16_t target_port,
                       size_t password,
                       int period)
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
    if (server_role == ROLE_WORKER && password != 0 && period != -1)
    {
        log_e("worker server cannot set password and period\n");
        return -1;
    }
    if (server_role == ROLE_ROOT && couchdb_url[0] == '\0')
    {
        log_e("root server must set couchdb_url\n");
        return -1;
    }
    return 0;
}

int initialize_enclave(const sgx_uswitchless_config_t *us_config)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    const void *enclave_ex_p[32] = {0};

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void *)us_config;

    ret = sgx_create_enclave_ex(ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &g_enclave_id, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS)
    {
        // print_error_message(ret);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (access(RUNTIME_FOLDER, F_OK) != 0)
    {
        printf("Initializing runtime folder [path: %s].\n", RUNTIME_FOLDER);
        if (mkdir(RUNTIME_FOLDER, 0755) != 0)
        {
            printf("Create runtime folder failed!\n");
            return -1;
        }
    }

    if (initLogger("dkeyserver.log") < 0)
        return -1;
    log_i("Service name:\t\tDomainKey Provisioning Service %s", EHSM_VERSION);
    log_i("Service built:\t\t%s", EHSM_DATE);
    log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);
    log_i("Runtime folder:\t%s", RUNTIME_FOLDER);

    signal(SIGPIPE, SIG_IGN);

    string server_role;
    string target_ip_addr;
    string couchdb_url;
    uint16_t target_port = 0;
    size_t root_password = 0;
    int root_period = -1;

    parse_args(argc,
               argv,
               server_role,
               target_ip_addr,
               couchdb_url,
               &target_port,
               &root_password,
               &root_period);

    int ret = validate_parameter(server_role,
                                 target_ip_addr,
                                 couchdb_url,
                                 target_port,
                                 root_password,
                                 root_period);
    if (ret != 0)
    {
        log_i("Usage: ehsm-dkeyserver "
              "-r [server role] "
              "-i [target server ip] "
              "-w [set root password] "
              "-P [set period, eg:40(days)] "
              "-u [set couchdb_url eg:http:// + user + : + password + @ + ip + : + port] "
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

    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
    us_config.num_uworkers = 2;
    us_config.num_tworkers = 2;

    /* Initialize the enclave */
    if (initialize_enclave(&us_config) < 0)
    {
        printf("Error: enclave initialization failed\n");
        return -1;
    }

    g_couchdb_url = couchdb_url;

    int sgxStatus = -1;
    ret = sgx_set_up_tls_server(g_enclave_id,
                                &sgxStatus,
                                s_port,
                                server_role.c_str(),
                                target_ip_addr.c_str(),
                                target_port,
                                root_password,
                                root_period);
    if (ret != SGX_SUCCESS || sgxStatus != SGX_SUCCESS)
    {
        log_d("Host: setup_tls_server failed(%d)(%d)\n", ret, sgxStatus);
    }

    logger_shutDown();

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}
