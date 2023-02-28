/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#define CONCURRENT_MAX 50
#define MAX_RECONNECT 3
#define CLIENT_MAX_NUM 20
#define TLS_CLIENT "TLS client: "
#define TLS_SERVER "TLS server: "

#define CLIENT_PAYLOAD           "GET / HTTP/1.0\r\n\r\n"
#define PASSWORD_WRONG           "The password is wrong!"
#define START_ROTATION_MSG       "Domian key rotation start!"
#define SET_PERIOD_SUCCESS_MSG   "Update period success!"
#define SET_PERIOD_FAILED_MSG    "Update period failed, the period must greater than 30 days and less than 365 days!"
#define STOP_AUTO_ROTATION_MSG   "Stop auto rotation success!"

#define CLIENT_PAYLOAD_SIZE          sizeof(CLIENT_PAYLOAD)
#define PASSWORD_WRONG_SIZE          sizeof(PASSWORD_WRONG)
#define START_ROTATION_MSG_SIZE      sizeof(START_ROTATION_MSG)
#define SET_PERIOD_SUCCESS_MSG_SIZE  sizeof(SET_PERIOD_SUCCESS_MSG)
#define SET_PERIOD_FAILED_MSG_SIZE   sizeof(SET_PERIOD_FAILED_MSG)
#define STOP_AUTO_ROTATION_MSG_SIZE  sizeof(STOP_AUTO_ROTATION_MSG)

#define CMK_INFO 0
#define USER_INFO 1
#define KEYBLOB 0
#define CMK 1
#define SM_DEFAULT_CMK 2

#include "sgx_ttls.h"
#include "elog_utils.h"

#define GETCURRTIME t_time
#define VERIFY_CALLBACK tee_verify_certificate_with_evidence
#define FREE_SUPDATA tee_free_supplemental_data
