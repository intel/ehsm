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

#ifndef EHSM_CACHECONTROLLER_H
#define EHSM_CACHECONTROLLER_H

#include "sample_ra_msg.h"

#define CACHE_MAX_SESSION_NUM  16   // max sessionId number of cache
#define CACHE_DEAMON_SLEEP_TIME  60 * 5   // 5 minutes
#define CACHE_SP_DB_EXPIRED_TIME  60 * 5   // 5 minutes

/**
 * create a new sessionId and initialize a sp_db for this sessionId.Then return the sessonId
 * @param session_id_size
 * @return session_id
 */
int32_t db_initialize(sesion_id_t session_id);

/**
 * Destroy sp_db of sessionId and remove the sessionId from cache.
 * @param session_id
 * @return
 */
int32_t db_finalize(const sesion_id_t session_id);


/**
 * get a sp_db by sessionId.
 * @param session_id
 * @return p_sp_db
 */
int32_t get_session_db(const sesion_id_t session_id, sp_db_item_t **p_sp_db);

#endif //EHSM_CACHECONTROLLER_H
