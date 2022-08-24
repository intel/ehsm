/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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


#include "CacheController_test.h"
#include "CacheController.h"
#include "error.h"
#include "rand.h"
#include <cstring>
#include <string>
#include <pthread.h>
#include "log_utils.h"

void print_uint8_array(uint8_t *p, int size, const char *prefix){
    for(int i=0; i<size; ++i){
        if(i == 0){
            printf("%s", prefix);
        }
        printf("[%x], ", p[i]);
        if(i != 0 && (i+1)%8 == 0){
            printf("\n%s",prefix );
        }
    }
    printf("\n");
}

void print_sp_db(sp_db_item_t *p_sp_db){
    printf("/******************* sp_db *******************\n");
    printf("sessionId: %s\n",p_sp_db->session_id);
    print_uint8_array(p_sp_db->session_id, SESSION_ID_SIZE, "\t");
    printf("expired_time: %ld\n",p_sp_db->expired_time);

    printf("g_a : \n");
    printf("  g_a->gx:\n");
    print_uint8_array(p_sp_db->g_a.gx, SAMPLE_ECP_KEY_SIZE, "\t");
    printf("  g_a->gy:\n");
    print_uint8_array(p_sp_db->g_a.gy, SAMPLE_ECP_KEY_SIZE, "\t");

    printf("g_b : \n");
    printf("\tg_b->gx:\n");
    print_uint8_array(p_sp_db->g_b.gx, SAMPLE_ECP_KEY_SIZE, "\t");
    printf("\tg_b->gy:\n");
    print_uint8_array(p_sp_db->g_b.gy, SAMPLE_ECP_KEY_SIZE, "\t");

    printf("vk_key : \n");
    print_uint8_array(p_sp_db->vk_key, 16, "\t");
    printf("mk_key : \n");
    print_uint8_array(p_sp_db->mk_key, 16, "\t");
    printf("sk_key : \n");
    print_uint8_array(p_sp_db->sk_key, 16, "\t");
    printf("smk_key : \n");
    print_uint8_array(p_sp_db->smk_key, SAMPLE_ECP_KEY_SIZE, "\t");

    printf("b : \n");
    print_uint8_array(p_sp_db->b.r, 16, "\t");
    printf("ps_sec_prop : \n");
    print_uint8_array(p_sp_db->ps_sec_prop.sample_ps_sec_prop_desc, 256, "\t");

    printf("**************************************/\n");
}

void *test_Lifecycle(void *p_thread_index) {
    long thread_index = (long) (p_thread_index);
    log_d("[Thread %ld] start test_Lifecycle", thread_index);

    int ret;

    // create a new session
    sesion_id_t session_id;

    ret = db_initialize(session_id);
    if (ret != NO_ERROR) {
        log_d("[Thread %ld] db_initialize failed", thread_index);
        return 0;
    }
    std::string session_id_str((char *) session_id, SESSION_ID_SIZE);
    log_d("[Thread %ld] back sessionid ==> %s", thread_index, session_id_str.c_str());


    // load the session's sp_db.
    sp_db_item_t *p_sp_db;
    ret = get_session_db(session_id, &p_sp_db);
    if (ret != NO_ERROR || p_sp_db == NULL) {
        std::string t((char *) session_id, SESSION_ID_SIZE);
        log_e("[Thread %ld] Can't find sp_db by sessionId[%s].", thread_index, t.c_str());
        return 0;
    }
    std::string sp_db_session_id_str((char *) p_sp_db->session_id, SESSION_ID_SIZE);
    log_d("[Thread %ld] p_sp_db sessionid ==> %s", thread_index, sp_db_session_id_str.c_str());

    ret = db_finalize(session_id);
    if (ret != NO_ERROR) {
        log_d("[Thread %ld] db_finalize failed", thread_index);
        return 0;
    }
    log_d("[Thread %ld] db_finalize success.", thread_index);

    log_d("[Thread %ld] end test_Lifecycle", thread_index);
}

void test_CacheController() {
    test_Lifecycle(0);
}

void test_CacheController_thread() {
    for (int i = 0; i < 17; ++i) {
        pthread_t thread1;
        int ret_thrd1 = pthread_create(&thread1, NULL, test_Lifecycle, (void *) i);

        // create thread success return 0 failed return thread number
        if (ret_thrd1 != 0) {
            log_d("Thread %d create failed", i);
        } else {
            log_d("Thread %d create success", i);
        }
    }

}
