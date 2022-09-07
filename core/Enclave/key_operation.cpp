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
    EVP_PKEY *keypair = NULL;
    EVP_PKEY_CTX *ectx = NULL;

    RSA* rsa_pubkey = NULL;

    do {
        // load rsa public key
        //
        rsa_keypair = (uint8_t*)malloc(cmk->keybloblen);

        ret = ehsm_parse_keyblob(cmk->keybloblen, rsa_keypair,
                                (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
        if (ret != SGX_SUCCESS)
            break;

        bio = BIO_new_mem_buf(rsa_keypair, 625); // use -1 to auto compute length
        if (bio == NULL) {
            printf("failed to load rsa key pem\n");
            break;
        }
        // PEM_read_bio_RSA_PUBKEY(bio, &rsa_pubkey, NULL, NULL);
        // if (rsa_pubkey == NULL) {
        //     printf("failed to load rsa key1\n");
        //     break;
        // }
        // RSA_public_encrypt(plaintext->datalen, plaintext->data, ciphertext->data, rsa_pubkey, 4);

        
        PEM_read_bio_PUBKEY(bio, &keypair, NULL, NULL);
        if (keypair == NULL) {
            printf("failed to load rsa key2\n");
            break;
        }

        ectx = EVP_PKEY_CTX_new(keypair, NULL);
        if ((ectx == NULL) || (EVP_PKEY_encrypt_init(ectx) < 1))
        {
            break;
        }

        //set the RSA padding mode, init it to use SHA256
        //
        EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(ectx, EVP_sha256());
        
        // make encryption
        //
        if (!EVP_PKEY_encrypt(ectx, ciphertext->data, (size_t*)&ciphertext->datalen, plaintext->data, plaintext->datalen))
            ret = SGX_ERROR_UNEXPECTED;
        else
            ret = SGX_SUCCESS;

        printf("ciphertext->data=%s\n", ciphertext->data[2]);
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
    uint8_t* rsa_private_key = NULL;
    uint32_t private_key_size;
    uint32_t public_key_size;
    BIO *bio = NULL;

    EVP_PKEY *keypair = NULL;
    EVP_PKEY_CTX *dctx = NULL;

    

    do {
        // load private key
        //
        rsa_keypair = (uint8_t*)malloc(cmk->keybloblen);
        ret = ehsm_parse_keyblob(cmk->keybloblen, rsa_keypair,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);
        if (ret != SGX_SUCCESS)
            break;

        bio = BIO_new_mem_buf(rsa_keypair+625, 2484); // use -1 to auto compute length
        if (bio == NULL) {
            printf("failed to load rsa key pem\n");
            break;
        }

        PEM_read_bio_PrivateKey(bio, &keypair, NULL, NULL);
        if (keypair == NULL) {
            printf("failed to load rsa key\n");
            break;
        }

        dctx = EVP_PKEY_CTX_new(keypair, NULL);
        if ((dctx == NULL) || (EVP_PKEY_decrypt_init(dctx) < 1))
        {
            break;
        }

        EVP_PKEY_CTX_set_rsa_padding(dctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(dctx, EVP_sha256());

        // make decryption and compute plaintext length
        //
        if (plaintext->datalen == 0) {
            EVP_PKEY_decrypt(dctx, NULL, (size_t*)&plaintext->datalen, ciphertext->data, ciphertext->datalen);
            return SGX_SUCCESS;
        }

        EVP_PKEY_decrypt(dctx, plaintext->data, (size_t*)&plaintext->datalen, ciphertext->data, ciphertext->datalen);
        
    } while(0);

    BIO_free(bio);
    SAFE_FREE(rsa_keypair);
    SAFE_FREE(rsa_private_key);

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