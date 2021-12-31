/*
 * Copyright (C) 2021-2022 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <cstdint>
#include "base64.h"

int main(int argc, char* argv[])
{
    int ret = -1;

    // start the enroll session, kms-server authenticate the enroll_app's identity.
    initial_enroll_session();

    //construct the msg0 and send to kms-server.
    req_data=payload(msg0 : "challenge")
    resp_data = requests.post(url=base_url + "RA_HANDSHAKE_MSG0", data=json.dumps(req_data), headers=headers)

    resp_data = payload(msg1: "base64(ga || challenge)");

    //verify the challenge;

    //store the ga into the database

    //compute its ec-dh keys

    //derive the sub keys (SMK, MK, VK, SK) and store them into database

    //construct the msg2 = (gb || SIGtmp-pri(gb, ga) || CMAC-SMK(gb|| SIGtmp-pri(gb, ga))) send request to kms-server
    req_data=payload(msg2 : "(gb || SIGtmp-pri(gb, ga) || CMAC-SMK(gb|| SIG-tmp-pri(gb, ga)))")
    resp_data = requests.post(url=base_url + "RA_HANDSHAKE_MSG2", data=json.dumps(req_data), headers=headers)

    resp_data = payload(msg3: "base64(ga || QUOTE(SHA256(ga|gb|VK))  || CMAC-SMK(ga || QUOTE(SHA256(ga|gb|VK))))");

    //verify msg3

    //construct the msg4 and send request to kms-server
    req_data=payload(msg4 : "(nonce||attResult||qve_report_info || CMAC-MK(nonce||attResult||qve_report_info ))");
    resp_data = requests.post(url=base_url + "RA_HANDSHAKE_MSG2", data=json.dumps(req_data), headers=headers)

    resp_data = payload(msg5: "base64(nonce || (APPID || APIKey)SK)");

    //verify msg5 and get the cleartext of appid and apikey.
    appi+apikey;

    finalize_enroll_session();

    return ret;
}