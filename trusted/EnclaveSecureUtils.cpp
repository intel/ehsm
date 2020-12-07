/*
 * Copyright (C) 2019-2020 Intel Corporation
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
#include "EnclaveHsm.h"
#include "EnclaveSecureUtils.h"

#include <sgx_trts.h>

bool validate_user_check_ptr(const void* ptr, const size_t length)
{
    if (!ptr || !sgx_is_outside_enclave(ptr, length))
    {
        return false;
    }

    return true;
}

bool validate_user_check_mechanism_ptr(const EH_MECHANISM_PTR pMechanism, const EH_ULONG ulCount)
{
    if (!pMechanism || !sgx_is_outside_enclave(pMechanism, sizeof(EH_MECHANISM) * ulCount))
    {
        return false;
    }

    // extra check to make sure the members are also within the boundary
    for (EH_ULONG i = 0; i < ulCount; ++i)
	{
		if (pMechanism[i].pParameter)
        {
            if (!validate_user_check_ptr(pMechanism[i].pParameter, pMechanism[i].ulParameterLen))
            {
                return false;
            }
        }
    }

    return true;
}

bool is_outside_enclave(const void* ptr, const size_t length)
{
    if (!sgx_is_outside_enclave(ptr, length))
    {
        return false;
    }

    return true;
}

bool is_inside_enclave(const void* ptr, const size_t length)
{
    if (!ptr || !sgx_is_within_enclave(ptr, length))
    {
        return false;
    }

    return true;
}
