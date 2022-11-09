/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <ra_getkey.h>
#include "ra_common.h"
#include "log_utils.h"

using namespace std;

sgx_enclave_id_t g_enclave_id;

int32_t ra_getkey(std::string deploy_ip_addr, uint32_t deploy_port) {
    log_i("Applying for a DomainKey from eHSM-KMS domainKey server.");
    int32_t ret = -1;
    int32_t retry_count = 5;
    struct sockaddr_in serAddr;
    int32_t sockfd = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        printf("Create socket failed\n");
        exit(1);
    }
    bzero(&serAddr, sizeof(serAddr));
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(deploy_port);
    serAddr.sin_addr.s_addr = inet_addr(deploy_ip_addr.c_str());

    do {
        if(connect(sockfd, (struct sockaddr*)&serAddr, sizeof(serAddr)) >= 0) {
            break;
        }
        else if (retry_count > 0) {
            log_w("Failed to Connect dkeyserver, sleep 0.5s and try again...\n");
            usleep(500000); // 0.5 s
        }
        else {
            log_e("Failed to connect dkeyserver\n");
            goto out;
        }
    } while (retry_count-- > 0);

    /* retrieve the domain key from dkeyserver via remote secure channel */
    ret = RetreiveDomainKey(sockfd);
    if (ret != 0) {
        log_e("Failed(%d) to setup the secure channel.\n", ret);
        goto out;
    }
    
    log_i("Successfully received the DomainKey from deploy server.");

out:
    close(sockfd);
    return ret;
}
