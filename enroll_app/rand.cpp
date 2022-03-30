/*
* Copyright (C) 2020-2021 Intel Corporation
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
#include "rand.h"
#include "ecp.h"

uint32_t g_drng_feature = 0;

static void __cpuid(uint64_t cpu_info[4], uint64_t leaf, uint64_t subleaf)
{
    __asm__ __volatile__ (
        "cpuid;"
        : "=a" (cpu_info[0]),
        "=b" (cpu_info[1]),
        "=c" (cpu_info[2]),
        "=d" (cpu_info[3])
        : "a" (leaf), "c" (subleaf)
        : "cc"
    );
}

void get_drng_support(void)
{
    uint64_t info[4];

    __cpuid(info, 1, 0);
    if ((info[2] & 0x40000000) == 0x40000000) {
        g_drng_feature |= DRNG_HAS_RDRAND;
    }

    __cpuid(info, 7, 0);
    if ((info[1] & 0x40000) == 0x40000) {
        g_drng_feature |= DRNG_HAS_RDSEED;
    }
}

static int rdseed32(uint32_t *out)
{
    uint8_t ret;
    int i;

    for (i = 0; i < DRNG_MAX_TRIES; i++) {
        __asm__ __volatile__ (
            "RDSEED %0;"
            "setc %1;"
            : "=r"(*out), "=qm"(ret)
            );

        if (ret)
            return 0;
    }

    return -1;
}

static int rdrand32(uint32_t *out)
{
    uint8_t ret;
    int i;

    for (i = 0; i < DRNG_MAX_TRIES; i++) {
        __asm__ __volatile__ (
        "RDRAND %0;"
        "setc %1;"
        : "=r"(*out), "=qm"(ret)
        );

        if (ret)
            return 0;
    }

    return -1;
}

static int drng_rand32(uint32_t *out)
{
    int rc = -1;

    if (g_drng_feature & DRNG_HAS_RDSEED) {
        rc = rdseed32(out);
        if (0 == rc)
            return rc;
    }

    if (g_drng_feature & DRNG_HAS_RDRAND) {
        rc = rdrand32(out);
        if (0 != rc)
            printf("failed with rdrand32\n");
    }

    return rc;
}

int get_random(uint8_t *buf, size_t len)
{
    uint32_t i;

    if (len % 4) {
        printf("the len isn't multiple of 4bytes\n");
        return -1;
    }

    for (i = 0; i < len; i += 4) {
        uint32_t tmp_buf = 0;
        if (0 != drng_rand32(&tmp_buf)) {
            printf("failed with rdrng_rand32:%d.\n", i);
            return -1;
        }

    if (0 != memcpy_s(buf + i, sizeof(tmp_buf), &tmp_buf, sizeof(tmp_buf)))
        return -1;
    }

    return 0;
}

