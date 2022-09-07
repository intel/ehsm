/*
 * Copyright (C) 2020-2022 Intel Corporation
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

#include "enclave_hsm_t.h"
#include "log_utils.h"
#include "sgx_tseal.h"

#include <string>
#include <stdio.h>
#include <stdbool.h>
#include <mbusafecrt.h>

#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"

#include "datatypes.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/err.h"

#include "key_operation.h"
#include "key_factory.h"

using namespace std;

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

sgx_status_t ehsm_aes_gcm_encrypt(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_aes_gcm_derypt(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_sm4_encrypt(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_sm4_decrypt(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_asymmetric_encrypt(const ehsm_keyblob_t *cmk, ehsm_data_t *plaintext, ehsm_data_t *ciphertext)
{
    sgx_status_t ret;
            
    uint8_t* rsa_keypair = NULL;
    uint8_t* rsa_public_key = NULL;
    BIO *bio = NULL;

    RSA* rsa_pubkey = NULL;

    do {
        // load rsa public key
        //
        rsa_keypair = (uint8_t*)malloc(cmk->keybloblen);

        ret = ehsm_parse_keyblob(cmk->keybloblen, rsa_keypair,
                                (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
        if (ret != SGX_SUCCESS)
            break;

        bio = BIO_new_mem_buf(rsa_keypair, -1); // use -1 to auto compute length
        if (bio == NULL) {
            printf("failed to load rsa key pem\n");
            break;
        }
        PEM_read_bio_RSA_PUBKEY(bio, &rsa_pubkey, NULL, NULL);
        if (rsa_pubkey == NULL) {
            printf("failed to load rsa key\n");
            break;
        }
        RSA_public_encrypt(plaintext->datalen, plaintext->data, ciphertext->data, rsa_pubkey, cmk->metadata.padding_mode);
    } while(0);

    BIO_free(bio);
    SAFE_FREE(rsa_keypair);
    SAFE_FREE(rsa_public_key);

    return ret;
}

sgx_status_t ehsm_rsa_decrypt(const ehsm_keyblob_t *cmk, ehsm_data_t *ciphertext, ehsm_data_t *plaintext)
{
    sgx_status_t ret;

    uint8_t* rsa_keypair = NULL;
    BIO *bio = NULL;
    RSA* rsa_prikey = NULL;

    do {
        // load private key
        //
        rsa_keypair = (uint8_t*)malloc(cmk->keybloblen);
        ret = ehsm_parse_keyblob(cmk->keybloblen, rsa_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
        if (ret != SGX_SUCCESS)
            break;

        bio = BIO_new_mem_buf(rsa_keypair, -1); // use -1 to auto compute length
        if (bio == NULL) {
            printf("failed to load rsa key pem\n");
            break;
        }

        PEM_read_bio_RSAPrivateKey(bio, &rsa_prikey, NULL, NULL);
        if (rsa_prikey == NULL) {
            printf("failed to load rsa key\n");
            break;
        }

        if (plaintext->datalen == 0) {
            uint8_t* temp_plaintext = (uint8_t*)malloc(RSA_size(rsa_prikey));
            plaintext->datalen = RSA_private_decrypt(ciphertext->datalen, ciphertext->data, temp_plaintext, rsa_prikey, cmk->metadata.padding_mode);
            return SGX_SUCCESS;
        }

        RSA_private_decrypt(ciphertext->datalen, ciphertext->data, plaintext->data, rsa_prikey, 4);
        
    } while(0);

    BIO_free(bio);
    SAFE_FREE(rsa_keypair);

    return ret;
}

sgx_status_t ehsm_rsa_sign(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_rsa_verify(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_ec_encrypt(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_ec_decrypt(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_ec_sign(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_ec_verify(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_sm2_sign(const ehsm_keyblob_t *cmk)
{

}

sgx_status_t ehsm_sm2_verify(const ehsm_keyblob_t *cmk)
{
    
}

sgx_status_t ehsm_aes_gcm_generate_datakey(const ehsm_keyblob_t *cmk)
{
    
}

sgx_status_t ehsm_sm4_generate_datakey(const ehsm_keyblob_t *cmk)
{
    
}