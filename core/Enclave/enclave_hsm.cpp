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

#include "enclave_hsm_t.h"

#include "datatypes.h"
#include "key_factory.h"
#include "key_operation.h"

using namespace std;

sgx_aes_gcm_256bit_key_t g_domain_key = {0};

static uint32_t get_asymmetric_max_encrypt_plaintext_size(ehsm_keyspec_t keyspec, ehsm_padding_mode_t padding_mode)
{
    uint32_t padding_size;
    switch (padding_mode)
    {
    case EH_RSA_PKCS1:
        padding_size = 11;
        break;
    case EH_RSA_PKCS1_OAEP:
        // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/rsa/rsa_oaep.c#L66
        padding_size = 42;
        break;
    default:
        padding_size = 0;
        break;
    }
    switch (keyspec)
    {
    case EH_RSA_2048:
        return 256 - padding_size;
    case EH_RSA_3072:
        return 384 - padding_size;
    case EH_RSA_4096:
        return 512 - padding_size;
    case EH_SM2:
        // https://github.com/guanzhi/GmSSL/blob/v3.0.0/include/gmssl/sm2.h#L345
        return 255;
    default:
        return 0;
    }
}

static size_t get_signature_length(ehsm_keyspec_t keyspec)
{
    switch (keyspec)
    {
    case EH_RSA_2048:
        return RSA_OAEP_2048_SIGNATURE_SIZE;
    case EH_RSA_3072:
        return RSA_OAEP_3072_SIGNATURE_SIZE;
    case EH_RSA_4096:
        return RSA_OAEP_4096_SIGNATURE_SIZE;
    case EH_EC_P256:
    case EH_EC_P256K:
        return EC_P256_SIGNATURE_MAX_SIZE;
    case EH_EC_P224:
        return EC_P224_SIGNATURE_MAX_SIZE;
    case EH_EC_P384:
        return EC_P384_SIGNATURE_MAX_SIZE;
    case EH_EC_P521:
        return EC_P521_SIGNATURE_MAX_SIZE;
    case EH_SM2:
        return EC_SM2_SIGNATURE_MAX_SIZE;
    default:
        return -1;
    }
}

static sgx_status_t check_import_key_length(int keylen, ehsm_keyspec_t keyspec)
{
    sgx_status_t ret = SGX_SUCCESS;
    switch (keyspec)
    {
    case EH_SM4_CTR:
    case EH_SM4_CBC:
    case EH_AES_GCM_128:
        if (keylen != 16)
            ret = SGX_ERROR_UNEXPECTED;
        break;
    case EH_AES_GCM_192:
        if (keylen != 24)
            ret = SGX_ERROR_UNEXPECTED;
        break;
    case EH_AES_GCM_256:
        if (keylen != 32)
            ret = SGX_ERROR_UNEXPECTED;
        break;
    default:
        ret = SGX_ERROR_UNEXPECTED;
    }
    return ret;
}

sgx_status_t enclave_get_domain_key_from_local()
{
    log_i("start get domain key from local.");
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t dk_cipher_len = sgx_calc_sealed_data_size(0, SGX_DOMAIN_KEY_SIZE);

    if (dk_cipher_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;

    int retstatus;
    uint8_t dk_cipher[dk_cipher_len] = {0};
    uint8_t tmp[SGX_DOMAIN_KEY_SIZE] = {0};

    ret = ocall_read_domain_key(&retstatus, dk_cipher, dk_cipher_len);
    if (ret != SGX_SUCCESS)
    {
        log_e("failed read domain key\n");
        return ret;
    }

    if (retstatus == 0)
    {
        uint32_t dk_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)dk_cipher);

        ret = sgx_unseal_data((const sgx_sealed_data_t *)dk_cipher, NULL, 0, tmp, &dk_len);
        if (ret != SGX_SUCCESS)
        {
            log_e("failed in sgx_unseal_data\n");
            return ret;
        }
        log_i("get domain key from disk.");
    }
    // -2: dk file does not exist.
    else if (retstatus == -2)
    {
        log_i("domain key file does not exist.\n");
        ret = sgx_read_rand(tmp, SGX_DOMAIN_KEY_SIZE);
        if (ret != SGX_SUCCESS)
        {
            return ret;
        }

        ret = sgx_seal_data(0, NULL, SGX_DOMAIN_KEY_SIZE, tmp, dk_cipher_len, (sgx_sealed_data_t *)dk_cipher);
        if (ret != SGX_SUCCESS)
            return SGX_ERROR_UNEXPECTED;

        ret = ocall_store_domain_key(&retstatus, dk_cipher, dk_cipher_len);
        if (ret != SGX_SUCCESS || retstatus != 0)
            return SGX_ERROR_UNEXPECTED;
        log_i("create a new domain key and store it to disk.\n");
    }
    else
        return SGX_ERROR_UNEXPECTED;

    memcpy_s(g_domain_key, SGX_DOMAIN_KEY_SIZE, tmp, SGX_DOMAIN_KEY_SIZE);
    memset_s(tmp, SGX_DOMAIN_KEY_SIZE, 0, SGX_DOMAIN_KEY_SIZE);

    return ret;
}

sgx_status_t enclave_create_key(ehsm_keyblob_t *cmk, size_t cmk_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        (cmk->metadata.origin != EH_EXTERNAL_KEY && cmk->metadata.origin != EH_INTERNAL_KEY) ||
        (cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT && cmk->metadata.keyusage != EH_KEYUSAGE_SIGN_VERIFY))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // For external keys, keyblob is empty when first created.
    if (cmk->metadata.origin == EH_EXTERNAL_KEY)
    {
        cmk->keybloblen = 0;
        return SGX_SUCCESS;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        ret = ehsm_create_aes_key(cmk);
        break;
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_create_rsa_key(cmk);
        break;
    case EH_EC_P224:
    case EH_EC_P256:
    case EH_EC_P256K:
    case EH_EC_P384:
    case EH_EC_P521:
        ret = ehsm_create_ecc_key(cmk);
        break;
    case EH_SM2:
        ret = ehsm_create_sm2_key(cmk);
        break;
    case EH_SM4_CTR:
    case EH_SM4_CBC:
        ret = ehsm_create_sm4_key(cmk);
        break;
    default:
        ret = SGX_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

sgx_status_t enclave_get_parameters_for_import(ehsm_keyblob_t *cmk, size_t cmk_size,
                                               ehsm_keyspec_t keyspec,
                                               ehsm_data_t *pubkey, size_t pubkey_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->metadata.origin != EH_EXTERNAL_KEY ||
        pubkey_size != APPEND_SIZE_TO_DATA_T(pubkey->datalen) ||
        (cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT && cmk->metadata.keyusage != EH_KEYUSAGE_SIGN_VERIFY))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = ehsm_calc_keyblob_size(keyspec, cmk->keybloblen);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }

    ret = ehsm_create_rsa_key_for_BYOK(cmk, pubkey, keyspec);

    return ret;
}

sgx_status_t enclave_import_key_material(ehsm_keyblob_t *cmk, size_t cmk_size,
                                         ehsm_padding_mode_t padding_mode,
                                         ehsm_data_t *key_material, size_t key_material_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->metadata.origin != EH_EXTERNAL_KEY ||
        key_material_size != APPEND_SIZE_TO_DATA_T(key_material->datalen) ||
        (cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT && cmk->metadata.keyusage != EH_KEYUSAGE_SIGN_VERIFY))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ehsm_data_t import_key_tmp = {0};

    ret = ehsm_rsa_decrypt(cmk, padding_mode, key_material, &import_key_tmp);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }

    ehsm_data_t *import_key = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(import_key_tmp.datalen));
    import_key->datalen = import_key_tmp.datalen;

    ret = ehsm_rsa_decrypt(cmk, padding_mode, key_material, import_key);
    if (ret != SGX_SUCCESS)
        goto out;

    ret = check_import_key_length(import_key->datalen, cmk->metadata.keyspec);
    if (ret != SGX_SUCCESS)
        goto out;

    memset_s(cmk->keyblob, cmk->keybloblen, 0, cmk->keybloblen);

    ret = ehsm_create_keyblob(import_key->data,
                              import_key->datalen,
                              (sgx_aes_gcm_data_ex_t *)cmk->keyblob);

    cmk->keybloblen = import_key->datalen + sizeof(sgx_aes_gcm_data_ex_t);

    if (ret != SGX_SUCCESS)
        goto out;

out:
    SAFE_MEMSET(import_key->data, import_key->datalen, 0, import_key->datalen);
    SAFE_FREE(import_key);
    return ret;
}

sgx_status_t enclave_get_public_key(ehsm_keyblob_t *cmk, size_t cmk_size,
                                    ehsm_data_t *pubkey, size_t pubkey_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        cmk->metadata.origin != EH_INTERNAL_KEY ||
        (cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT && cmk->metadata.keyusage != EH_KEYUSAGE_SIGN_VERIFY))
        return SGX_ERROR_INVALID_PARAMETER;

    if (cmk->metadata.keyspec != EH_SM2 &&
        cmk->metadata.keyspec != EH_EC_P224 &&
        cmk->metadata.keyspec != EH_EC_P256 &&
        cmk->metadata.keyspec != EH_EC_P256K &&
        cmk->metadata.keyspec != EH_EC_P384 &&
        cmk->metadata.keyspec != EH_EC_P521 &&
        cmk->metadata.keyspec != EH_RSA_2048 &&
        cmk->metadata.keyspec != EH_RSA_3072 &&
        cmk->metadata.keyspec != EH_RSA_4096)
        return SGX_ERROR_INVALID_PARAMETER;

    if (pubkey != NULL && pubkey_size != APPEND_SIZE_TO_DATA_T(pubkey->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (pubkey == NULL && pubkey_size != 0)
        return SGX_ERROR_INVALID_PARAMETER;

    if (pubkey == NULL ||
        pubkey_size != APPEND_SIZE_TO_DATA_T(pubkey->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    ret = ehsm_get_public_key(cmk, pubkey);

    return ret;
}

sgx_status_t enclave_encrypt(ehsm_keyblob_t *cmk, size_t cmk_size,
                             ehsm_data_t *aad, size_t aad_size,
                             ehsm_data_t *plaintext, size_t plaintext_size,
                             ehsm_data_t *ciphertext, size_t ciphertext_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        (cmk->metadata.origin != EH_INTERNAL_KEY && cmk->metadata.origin != EH_EXTERNAL_KEY) ||
        cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return SGX_ERROR_INVALID_PARAMETER;

    if (aad != NULL && aad_size != APPEND_SIZE_TO_DATA_T(aad->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (aad == NULL && aad_size != 0)
        return SGX_ERROR_INVALID_PARAMETER;

    /* only support to directly encrypt data of less than 6 KB */
    if (plaintext == NULL ||
        plaintext_size != APPEND_SIZE_TO_DATA_T(plaintext->datalen) ||
        plaintext->datalen == 0 ||
        plaintext->datalen > EH_ENCRYPT_MAX_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    if (ciphertext == NULL ||
        ciphertext_size != APPEND_SIZE_TO_DATA_T(ciphertext->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        ret = ehsm_aes_gcm_encrypt(aad, cmk, plaintext, ciphertext);
        break;
    case EH_SM4_CTR:
        ret = ehsm_sm4_ctr_encrypt(cmk, plaintext, ciphertext);
        break;
    case EH_SM4_CBC:
        ret = ehsm_sm4_cbc_encrypt(cmk, plaintext, ciphertext);
        break;
    default:
        return SGX_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

sgx_status_t enclave_decrypt(ehsm_keyblob_t *cmk, size_t cmk_size,
                             ehsm_data_t *aad, size_t aad_size,
                             ehsm_data_t *ciphertext, size_t ciphertext_size,
                             ehsm_data_t *plaintext, size_t plaintext_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        (cmk->metadata.origin != EH_INTERNAL_KEY && cmk->metadata.origin != EH_EXTERNAL_KEY) ||
        cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return SGX_ERROR_INVALID_PARAMETER;

    if (aad != NULL && aad_size != APPEND_SIZE_TO_DATA_T(aad->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (aad == NULL && aad_size != 0)
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext == NULL ||
        plaintext_size != APPEND_SIZE_TO_DATA_T(plaintext->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (ciphertext == NULL ||
        ciphertext_size != APPEND_SIZE_TO_DATA_T(ciphertext->datalen) ||
        ciphertext->datalen == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        ret = ehsm_aes_gcm_decrypt(aad, cmk, ciphertext, plaintext);
        break;
    case EH_SM4_CTR:
        ret = ehsm_sm4_ctr_decrypt(cmk, ciphertext, plaintext);
        break;
    case EH_SM4_CBC:
        ret = ehsm_sm4_cbc_decrypt(cmk, ciphertext, plaintext);
        break;
    default:
        return SGX_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

sgx_status_t enclave_asymmetric_encrypt(const ehsm_keyblob_t *cmk, size_t cmk_size,
                                        ehsm_padding_mode_t padding_mode,
                                        ehsm_data_t *plaintext, size_t plaintext_size,
                                        ehsm_data_t *ciphertext, size_t ciphertext_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        cmk->metadata.origin != EH_INTERNAL_KEY ||
        cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext == NULL ||
        plaintext_size != APPEND_SIZE_TO_DATA_T(plaintext->datalen) ||
        plaintext->datalen == 0 ||
        /* Verify the maximum plaintext length supported by different keyspac */
        plaintext->datalen > get_asymmetric_max_encrypt_plaintext_size(cmk->metadata.keyspec, padding_mode))
        return SGX_ERROR_INVALID_PARAMETER;

    if (ciphertext == NULL ||
        ciphertext_size != APPEND_SIZE_TO_DATA_T(ciphertext->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_rsa_encrypt(cmk, padding_mode, plaintext, ciphertext);
        break;
    case EH_SM2:
        ret = ehsm_sm2_encrypt(cmk, plaintext, ciphertext);
        break;
    default:
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return ret;
}

sgx_status_t enclave_asymmetric_decrypt(const ehsm_keyblob_t *cmk, size_t cmk_size,
                                        ehsm_padding_mode_t padding_mode,
                                        ehsm_data_t *ciphertext, uint32_t ciphertext_size,
                                        ehsm_data_t *plaintext, uint32_t plaintext_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        cmk->metadata.origin != EH_INTERNAL_KEY ||
        cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext == NULL ||
        plaintext_size != APPEND_SIZE_TO_DATA_T(plaintext->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (ciphertext == NULL ||
        ciphertext_size != APPEND_SIZE_TO_DATA_T(ciphertext->datalen) ||
        ciphertext->datalen == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_rsa_decrypt(cmk, padding_mode, ciphertext, plaintext);
        break;
    case EH_SM2:
        ret = ehsm_sm2_decrypt(cmk, ciphertext, plaintext);
        break;
    default:
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return ret;
}

/**
 * @brief Sign the message and store it in signature
 *
 * @param cmk storage the key metadata and keyblob
 * @param cmk_size size of input cmk
 * @param message message to be signed
 * @param message_size size of input message
 * @param signature generated signature
 * @param signature_size size of input signature
 * @return ehsm_status_t
 */
sgx_status_t enclave_sign(const ehsm_keyblob_t *cmk, size_t cmk_size,
                          ehsm_digest_mode_t digest_mode,
                          ehsm_padding_mode_t padding_mode,
                          ehsm_message_type_t message_type,
                          const ehsm_data_t *message, size_t message_size,
                          ehsm_data_t *signature, size_t signature_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // check cmk_blob and cmk_blob_size
    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        cmk->metadata.origin != EH_INTERNAL_KEY ||
        cmk->metadata.keyusage != EH_KEYUSAGE_SIGN_VERIFY)
        return SGX_ERROR_INVALID_PARAMETER;

    if (signature == NULL ||
        signature_size != APPEND_SIZE_TO_DATA_T(signature->datalen))
    {
        log_d("ecall sign signture or signature_size wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // Set signature data length
    if (signature->datalen == 0)
    {
        signature->datalen = get_signature_length(cmk->metadata.keyspec);
        return SGX_SUCCESS;
    }
    if (signature->datalen == -1 ||
        signature->datalen != get_signature_length(cmk->metadata.keyspec))
    {
        log_d("ecall sign cant get signature length or ecall sign signature length error.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (message == NULL ||
        message_size != APPEND_SIZE_TO_DATA_T(message->datalen) ||
        message->datalen == 0)
    {
        log_d("ecall sign data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = ehsm_rsa_sign(cmk,
                            digest_mode,
                            padding_mode,
                            message_type,
                            message,
                            signature);
        break;
    case EH_EC_P224:
    case EH_EC_P256:
    case EH_EC_P256K:
    case EH_EC_P384:
    case EH_EC_P521:
        ret = ehsm_ecc_sign(cmk,
                            digest_mode,
                            message_type,
                            message,
                            signature);
        break;
    case EH_SM2:
        ret = ehsm_sm2_sign(cmk,
                            digest_mode,
                            message_type,
                            message,
                            signature);
        break;
    default:
        log_d("ecall sign unsupport keyspec.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

/**
 * @brief verify the signature is correct
 *
 * @param cmk storage the key metadata and keyblob
 * @param cmk_size size of input cmk
 * @param message message for signature
 * @param message_size size of input message
 * @param signature generated signature
 * @param signature_size size of input signature
 * @param result Signature match result
 * @return ehsm_status_t
 */
sgx_status_t enclave_verify(const ehsm_keyblob_t *cmk, size_t cmk_size,
                            ehsm_digest_mode_t digest_mode,
                            ehsm_padding_mode_t padding_mode,
                            ehsm_message_type_t message_type,
                            const ehsm_data_t *message, size_t message_size,
                            const ehsm_data_t *signature, size_t signature_size,
                            bool *result)
{
    // TODO : make default padding mode for ECC/SM2
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        cmk->metadata.origin != EH_INTERNAL_KEY ||
        cmk->metadata.keyusage != EH_KEYUSAGE_SIGN_VERIFY)
        return SGX_ERROR_INVALID_PARAMETER;

    if (signature == NULL ||
        signature_size != APPEND_SIZE_TO_DATA_T(signature->datalen) ||
        signature->datalen <= 0)
    {
        log_d("ecall verify signture or signature_size wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (message == NULL ||
        message_size != APPEND_SIZE_TO_DATA_T(message->datalen) ||
        message->datalen == 0)
    {
        log_d("ecall verify data or data len is wrong.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (result == NULL)
    {
        log_d("ecall verify result is NULL.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        if (signature->datalen != get_signature_length(cmk->metadata.keyspec))
        {
            log_d("ecall verify cant get signature length or ecall sign signature length error.\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        ret = ehsm_rsa_verify(cmk,
                              digest_mode,
                              padding_mode,
                              message_type,
                              message,
                              signature,
                              result);
        break;
    case EH_EC_P224:
    case EH_EC_P256:
    case EH_EC_P256K:
    case EH_EC_P384:
    case EH_EC_P521:
        // not check ecc & sm2 signateure len because the len will be change after sign
        // refence https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying#Signing
        ret = ehsm_ecc_verify(cmk,
                              digest_mode,
                              message_type,
                              message,
                              signature,
                              result);
        break;
    case EH_SM2:
        ret = ehsm_sm2_verify(cmk,
                              digest_mode,
                              message_type,
                              message,
                              signature,
                              result);
        break;
    default:
        log_d("ecall verify unsupport keyspec.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

/**
 * @brief verify the signature is correct
 *
 * @param cmk storage the key metadata and keyblob
 * @param cmk_size size of input cmk
 * @param aad additional data
 * @param aad_size size of additional data
 * @param plaintext data to be encrypted
 * @param plaintext_size size of data to be encrypted
 * @param ciphertext information of ciphertext
 * @param ciphertext_size size of ciphertext
 * @return ehsm_status_t
 */
sgx_status_t enclave_generate_datakey(ehsm_keyblob_t *cmk, size_t cmk_size,
                                      ehsm_data_t *aad, size_t aad_size,
                                      ehsm_data_t *plaintext, size_t plaintext_size,
                                      ehsm_data_t *ciphertext, size_t ciphertext_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        cmk->metadata.origin != EH_INTERNAL_KEY ||
        cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return SGX_ERROR_INVALID_PARAMETER;

    if (plaintext == NULL ||
        plaintext_size != APPEND_SIZE_TO_DATA_T(plaintext->datalen) ||
        plaintext->datalen > 1024 ||
        plaintext->datalen == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    if (aad != NULL && aad_size != APPEND_SIZE_TO_DATA_T(aad->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (aad == NULL && aad_size != 0)
        return SGX_ERROR_INVALID_PARAMETER;

    if (ciphertext == NULL ||
        ciphertext_size != APPEND_SIZE_TO_DATA_T(ciphertext->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (ciphertext->datalen == 0)
    {
        switch (cmk->metadata.keyspec)
        {
        case EH_AES_GCM_128:
        case EH_AES_GCM_192:
        case EH_AES_GCM_256:
            ciphertext->datalen = plaintext->datalen + EH_AES_GCM_IV_SIZE + EH_AES_GCM_MAC_SIZE;
            return SGX_SUCCESS;
        case EH_SM4_CBC:
            ciphertext->datalen = (plaintext->datalen / 16 + 1) * 16 + SGX_SM4_IV_SIZE;
            return SGX_SUCCESS;
        case EH_SM4_CTR:
            ciphertext->datalen = plaintext->datalen + SGX_SM4_IV_SIZE;
            return SGX_SUCCESS;
        default:
            return SGX_ERROR_INVALID_PARAMETER;
        }
    }

    uint8_t *temp_datakey = NULL;

    temp_datakey = (uint8_t *)malloc(plaintext->datalen);
    if (temp_datakey == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    if (sgx_read_rand(temp_datakey, plaintext->datalen) != SGX_SUCCESS)
    {
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    if (memcpy_s(plaintext->data, plaintext->datalen, temp_datakey, plaintext->datalen))
    {
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        ret = ehsm_aes_gcm_encrypt(aad,
                                   cmk,
                                   plaintext,
                                   ciphertext);
        break;
    case EH_SM4_CBC:
        ret = ehsm_sm4_cbc_encrypt(cmk,
                                   plaintext,
                                   ciphertext);
        break;
    case EH_SM4_CTR:
        ret = ehsm_sm4_ctr_encrypt(cmk,
                                   plaintext,
                                   ciphertext);
        break;
    default:
        break;
    }

out:
    memset_s(temp_datakey, plaintext->datalen, 0, plaintext->datalen);
    free(temp_datakey);
    return ret;
}

sgx_status_t enclave_export_datakey(ehsm_keyblob_t *cmk, size_t cmk_size,
                                    ehsm_data_t *aad, size_t aad_size,
                                    ehsm_data_t *olddatakey, size_t olddatakey_size,
                                    ehsm_keyblob_t *ukey, size_t ukey_size,
                                    ehsm_data_t *newdatakey, size_t newdatakey_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        cmk->metadata.origin != EH_INTERNAL_KEY ||
        cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return SGX_ERROR_INVALID_PARAMETER;

    if (aad != NULL && aad_size != APPEND_SIZE_TO_DATA_T(aad->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (aad == NULL && aad_size != 0)
        return SGX_ERROR_INVALID_PARAMETER;

    if (olddatakey == NULL ||
        olddatakey_size != APPEND_SIZE_TO_DATA_T(olddatakey->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (ukey == NULL ||
        ukey_size != APPEND_SIZE_TO_KEYBLOB_T(ukey->keybloblen) ||
        ukey->keyblob == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    if (newdatakey == NULL ||
        newdatakey_size != APPEND_SIZE_TO_DATA_T(newdatakey->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    ehsm_data_t *tmp_datakey = NULL;
    size_t tmp_datakey_size = 0;

    // datakey plaintext
    // to calc the plaintext len
    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
        tmp_datakey_size = olddatakey->datalen - EH_AES_GCM_IV_SIZE - EH_AES_GCM_MAC_SIZE;
        break;
    case EH_SM4_CBC:
    case EH_SM4_CTR:
        tmp_datakey_size = olddatakey->datalen - SGX_SM4_IV_SIZE;
        break;
    default:
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }

    tmp_datakey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(tmp_datakey_size));
    if (tmp_datakey == NULL)
    {
        tmp_datakey_size = 0;
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    tmp_datakey->datalen = tmp_datakey_size;
    tmp_datakey_size = APPEND_SIZE_TO_DATA_T(tmp_datakey_size);
    // decrypt olddatakey using cmk
    switch (cmk->metadata.keyspec)
    {
    case EH_AES_GCM_128:
    case EH_AES_GCM_192:
    case EH_AES_GCM_256:
    case EH_SM4_CTR:
        ret = enclave_decrypt(cmk, cmk_size, aad, aad_size, olddatakey, olddatakey_size, tmp_datakey, tmp_datakey_size);
        break;
    case EH_SM4_CBC:
        ret = enclave_decrypt(cmk, cmk_size, aad, aad_size, olddatakey, olddatakey_size, tmp_datakey, tmp_datakey_size);
        tmp_datakey_size = APPEND_SIZE_TO_DATA_T(tmp_datakey->datalen);
        break;
    default:
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    // check enclave_decrypt status
    if (ret != SGX_SUCCESS)
        goto out;

    // calc length
    // encrypt datakey using ukey
    // or just ret = enclave_asymmetric_encrypt(ukey, ukey_size, tmp_datakey, tmp_datakey_size, newdatakey, newdatakey_size);
    switch (ukey->metadata.keyspec)
    {
    case EH_RSA_2048:
    case EH_RSA_3072:
    case EH_RSA_4096:
        ret = enclave_asymmetric_encrypt(ukey, ukey_size, EH_RSA_PKCS1_OAEP, tmp_datakey, tmp_datakey_size, newdatakey, newdatakey_size);
        break;
    case EH_SM2:
        ret = enclave_asymmetric_encrypt(ukey, ukey_size, EH_PAD_NONE, tmp_datakey, tmp_datakey_size, newdatakey, newdatakey_size);
        break;
    default:
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto out;
    }
    if (ret != SGX_SUCCESS)
        goto out;

out:
    SAFE_MEMSET(tmp_datakey, tmp_datakey_size, 0, tmp_datakey_size);
    SAFE_FREE(tmp_datakey);
    return ret;
}

sgx_status_t enclave_get_target_info(sgx_target_info_t *target_info)
{
    return sgx_self_target(target_info);
}

sgx_status_t enclave_create_report(const sgx_target_info_t *p_qe3_target, sgx_report_t *p_report)
{
    sgx_status_t ret = SGX_SUCCESS;

    sgx_report_data_t report_data = {0};

    // Generate the report for the app_enclave
    ret = sgx_create_report(p_qe3_target, &report_data, p_report);

    return ret;
}

sgx_status_t enclave_get_rand(uint8_t *data, uint32_t datalen)
{
    if (data == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    return sgx_read_rand(data, datalen);
}

sgx_status_t enclave_get_apikey(uint8_t *apikey, uint32_t keylen)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (apikey == NULL || keylen != EH_API_KEY_SIZE)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate apikey
    std::string psw_chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
    uint8_t temp[keylen];
    ret = sgx_read_rand(temp, keylen);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }
    memset_s(apikey, keylen, 0, keylen);
    for (int i = 0; i < keylen; i++)
    {
        apikey[i] = psw_chars[temp[i] % psw_chars.length()];
    }

    memset_s(temp, keylen, 0, keylen);
    return ret;
}

/*
 *  @brief check mr_signer and mr_enclave
 *  @param quote quote data
 *  @param quote_size the length of quote
 *  @param mr_signer_good the mr_signer
 *  @param mr_signer_good_size the length of mr_signer_good
 *  @param mr_enclave_good the mr_enclave
 *  @param mr_enclave_good_size the length of mr_enclave_good
 *  @return SGX_ERROR_INVALID_PARAMETER paramater is incorrect
 *  @return SGX_ERROR_UNEXPECTED mr_signer or mr_enclave is invalid
 */
sgx_status_t enclave_verify_quote_policy(uint8_t *quote, uint32_t quote_size,
                                         const char *mr_signer_good, uint32_t mr_signer_good_size,
                                         const char *mr_enclave_good, uint32_t mr_enclave_good_size)
{
    if (quote == NULL || mr_signer_good == NULL || mr_enclave_good == NULL)
    {
        log_d("quote or mr_signer_good or mr_enclave_good is null");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    string mr_signer_str;
    string mr_enclave_str;
    char mr_signer_temp[3] = {0};
    char mr_enclave_temp[3] = {0};
    sgx_quote3_t *p_sgx_quote = (sgx_quote3_t *)quote;
    for (int i = 0; i < SGX_HASH_SIZE; i++)
    {
        snprintf(mr_signer_temp, sizeof(mr_signer_temp), "%02x", p_sgx_quote->report_body.mr_signer.m[i]);
        snprintf(mr_enclave_temp, sizeof(mr_enclave_temp), "%02x", p_sgx_quote->report_body.mr_enclave.m[i]);
        mr_signer_str += mr_signer_temp;
        mr_enclave_str += mr_enclave_temp;
    }
    if ((mr_signer_str.size() != mr_signer_good_size) ||
        (mr_enclave_str.size() != mr_enclave_good_size))
    {
        log_d("mr_signer_str length is not same with mr_signer_good_size or\
                mr_enclave_str length is not same with mr_enclave_good_size!\n");
        return SGX_ERROR_UNEXPECTED;
    }
    if (strncmp(mr_signer_good, mr_signer_str.c_str(), mr_signer_str.size()) != 0 ||
        strncmp(mr_enclave_good, mr_enclave_str.c_str(), mr_enclave_str.size()) != 0)
    {
        log_d("mr_signer or mr_enclave is invalid!\n");
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

/**
 * @brief Generate HMAC with given cmk, apikey and payload
 * @param cmk the cmk for apikey decryption
 * @param apikey the encrypted apikey
 * @param payload the payload of HMAC
 * @param hmac the output of the function
 */
sgx_status_t enclave_generate_hmac(ehsm_keyblob_t *cmk, uint32_t cmk_size,
                                   ehsm_data_t *apikey, uint32_t apikey_size,
                                   ehsm_data_t *payload, uint32_t payload_size,
                                   ehsm_data_t *hmac, uint32_t hmac_size)
{
    if (cmk == NULL ||
        cmk_size != APPEND_SIZE_TO_KEYBLOB_T(cmk->keybloblen) ||
        cmk->keybloblen == 0 ||
        cmk->metadata.origin != EH_INTERNAL_KEY ||
        cmk->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return SGX_ERROR_INVALID_PARAMETER;

    if (apikey == NULL ||
        apikey_size != APPEND_SIZE_TO_DATA_T(apikey->datalen))
        return SGX_ERROR_INVALID_PARAMETER;

    if (payload == NULL ||
        payload_size != APPEND_SIZE_TO_DATA_T(payload->datalen) ||
        payload->datalen == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    if (hmac == NULL ||
        hmac_size != APPEND_SIZE_TO_DATA_T(hmac->datalen) ||
        hmac->datalen != EH_HMAC_SHA256_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ehsm_data_t *rawApiKey = NULL;

    // create space for storing raw apikey
    rawApiKey = (ehsm_data_t *)malloc(APPEND_SIZE_TO_DATA_T(EH_API_KEY_SIZE));
    if (rawApiKey == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }
    rawApiKey->datalen = EH_API_KEY_SIZE;

    // 1. Decrypt the apikey
    // aad is empty, thus NULL is passed as `aad` and 0 is passed as `aad_size`
    ret = enclave_decrypt(cmk, cmk_size, NULL, 0, apikey, apikey_size, rawApiKey, APPEND_SIZE_TO_DATA_T(rawApiKey->datalen));
    if (ret != SGX_SUCCESS)
    {
        log_w("apikey decrypt failed");
        goto out;
    }

    // 2. Generate HMAC
    ret = sgx_hmac_sha256_msg(payload->data, payload->datalen, rawApiKey->data, rawApiKey->datalen, hmac->data, hmac->datalen);

out:
    // clear sensitive info
    if (rawApiKey)
    {
        memset_s(rawApiKey, APPEND_SIZE_TO_DATA_T(rawApiKey->datalen), 0, APPEND_SIZE_TO_DATA_T(rawApiKey->datalen));
    }
    // free allocations
    SAFE_FREE(rawApiKey);
    return ret;
}

// Currently only used for BYOK.
sgx_status_t enclave_generate_token_hmac(ehsm_keyblob_t *sessionkey, uint32_t sessionkey_size,
                                         ehsm_data_t *import_token, uint32_t import_token_size,
                                         ehsm_data_t *hmac, uint32_t hmac_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    if (sessionkey == NULL ||
        sessionkey_size != APPEND_SIZE_TO_KEYBLOB_T(sessionkey->keybloblen) ||
        sessionkey->keybloblen == 0 ||
        sessionkey->metadata.origin != EH_INTERNAL_KEY ||
        sessionkey->metadata.keyusage != EH_KEYUSAGE_ENCRYPT_DECRYPT)
        return SGX_ERROR_INVALID_PARAMETER;

    if (import_token == NULL ||
        import_token_size != APPEND_SIZE_TO_DATA_T(import_token->datalen) ||
        import_token->datalen == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    if (hmac == NULL ||
        hmac_size != APPEND_SIZE_TO_DATA_T(hmac->datalen) ||
        hmac->datalen != EH_HMAC_SHA256_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;
    
    uint32_t keysize = 0;
    if (!ehsm_get_symmetric_key_size(sessionkey->metadata.keyspec, keysize))
        return SGX_ERROR_UNEXPECTED;

    uint8_t *key = (uint8_t *)malloc(keysize);
    if (key == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    ret = ehsm_parse_keyblob(key,
                             (sgx_aes_gcm_data_ex_t *)sessionkey->keyblob);
    if (ret != SGX_SUCCESS)
        goto out;

    ret = sgx_hmac_sha256_msg(import_token->data,
                              import_token->datalen,
                              key,
                              keysize,
                              hmac->data,
                              hmac->datalen);

    if (ret != SGX_SUCCESS)
        goto out;

out:
    SAFE_MEMSET(key, keysize, 0, keysize);
    SAFE_FREE(key);
    return ret;
}