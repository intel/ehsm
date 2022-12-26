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

#ifndef _ULOG_UTILS_H
#define _ULOG_UTILS_H

#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>
#define IS_DEBUG false
#define MAX_LOG_BUF 1024

using namespace log4cplus;
using namespace log4cplus::helpers;

extern Logger logger;
extern void do_logger(LogLevel logLevel,
                      const char *filename,
                      int line,
                      int bufSize,
                      const char *pFormat, ...);

#define log_d(pFormat, ...) do_logger(log4cplus::DEBUG_LOG_LEVEL, \
                                      __FILE__,                   \
                                      __LINE__,                   \
                                      MAX_LOG_BUF,                \
                                      pFormat,                    \
                                      ##__VA_ARGS__)
#define log_i(pFormat, ...) do_logger(log4cplus::INFO_LOG_LEVEL, \
                                      __FILE__,                  \
                                      __LINE__,                  \
                                      MAX_LOG_BUF,               \
                                      pFormat,                   \
                                      ##__VA_ARGS__)
#define log_e(pFormat, ...) do_logger(log4cplus::ERROR_LOG_LEVEL, \
                                      __FILE__,                   \
                                      __LINE__,                   \
                                      MAX_LOG_BUF,                \
                                      pFormat,                    \
                                      ##__VA_ARGS__)
#define log_w(pFormat, ...) do_logger(log4cplus::WARN_LOG_LEVEL, \
                                      __FILE__,                  \
                                      __LINE__,                  \
                                      MAX_LOG_BUF,               \
                                      pFormat,                   \
                                      ##__VA_ARGS__)
#define log_c(log_level, pFormat, filename, line, ...) do_logger(log_level,   \
                                                                 filename,    \
                                                                 line,        \
                                                                 MAX_LOG_BUF, \
                                                                 pFormat,     \
                                                                 ##__VA_ARGS__)

int initLogger(const char *logs_filename);

void logger_shutDown();

#endif