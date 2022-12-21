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

#include "enroll_msg.h"

#include <sys/time.h>

#include "ulog_utils.h"
#include "ecp.h"
#include "sample_ra_msg.h"
#include "sample_libcrypto.h"

#include "sgx_quote_3.h"
#include "sgx_urts.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "rand.h"

std::string g_challenge;
sgx_quote_nonce_t g_nonce;
static sp_db_item_t g_sp_db;
static sample_spid_t g_spid;

// This is the private EC key of SP, the corresponding public EC key is
// hard coded in isv_enclave. It is based on NIST P-256 curve.
static const sample_ec256_private_t g_sp_priv_key = {
    {0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
     0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
     0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
     0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01}};

enroll_status_t ra_get_msg0(std::string *p_msg0)
{
    Json::Value msg0_json;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    g_challenge = std::to_string(tv.tv_sec) + std::to_string(tv.tv_usec);
    msg0_json["challenge"] = g_challenge;
    *p_msg0 = msg0_json.toStyledString();
    return ENL_OK;
}

// Verify message 1 g_a then generate and return message 2 to isv.
enroll_status_t sp_ra_proc_msg1_req(const sample_ec_pub_t *g_a,
                                    uint32_t ga_size,
                                    sample_ra_msg2_t **pp_msg2)
{
    enroll_status_t ret = ENL_OK;
    sample_ecc_state_handle_t ecc_state = NULL;
    sample_status_t sample_ret = SAMPLE_SUCCESS;
    bool derive_ret = false;
    sample_ra_msg2_t *p_msg2;

    if (!g_a || !pp_msg2 || (ga_size != sizeof(sample_ec_pub_t)))
    {
        return ENL_ERROR_INVALID_PARAMETER;
    }
    do
    {
        // Get the sig_rl from attestation server using GID.
        // GID is Base-16 encoded of EPID GID in little-endian format.
        // In the product, the SP and attestation server uses an established channel for
        // communication.
        uint8_t *sig_rl = NULL;
        uint32_t sig_rl_size = 0;

        // clear the g_sp_db database when the attesation session begins.
        memset(&g_sp_db, 0, sizeof(sp_db_item_t));

        // Need to save the client's public ECDH key to local storage
        if (memcpy_s(&g_sp_db.g_a, sizeof(g_sp_db.g_a), g_a, ga_size))
        {
            log_e("cannot do memcpy.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        // Generate the Service providers ECDH key pair.
        sample_ret = sample_ecc256_open_context(&ecc_state);
        if (SAMPLE_SUCCESS != sample_ret)
        {
            log_e("cannot get ECC context.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        sample_ec256_public_t pub_key = {{0}, {0}};
        sample_ec256_private_t priv_key = {{0}};
        sample_ret = sample_ecc256_create_key_pair(&priv_key, &pub_key,
                                                   ecc_state);
        if (SAMPLE_SUCCESS != sample_ret)
        {
            log_e("cannot generate key pair.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        // Need to save the SP ECDH key pair to local storage.
        if (memcpy_s(&g_sp_db.b, sizeof(g_sp_db.b), &priv_key, sizeof(priv_key)) != 0)
        {
            log_e("cannot do memcpy.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        if (memcpy_s(&g_sp_db.g_b, sizeof(g_sp_db.g_b), &pub_key, sizeof(pub_key)) != 0)
        {
            log_e("cannot do memcpy.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        // Generate the client/SP shared secret
        sample_ec_dh_shared_t dh_key = {{0}};
        sample_ret = sample_ecc256_compute_shared_dhkey(&priv_key,
                                                        (sample_ec256_public_t *)g_a,
                                                        (sample_ec256_dh_shared_t *)&dh_key,
                                                        ecc_state);
        if (SAMPLE_SUCCESS != sample_ret)
        {
            log_e("compute share key fail");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

#ifdef SUPPLIED_KEY_DERIVATION

        // smk is only needed for msg2 generation.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SMK_SK,
                                &g_sp_db.smk_key, &g_sp_db.sk_key);
        if (derive_ret != true)
        {
            log_e("derive key fail.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        // The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_MK_VK,
                                &g_sp_db.mk_key, &g_sp_db.vk_key);
        if (derive_ret != true)
        {
            log_e("derive key fail.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }
#else
        // smk is only needed for msg2 generation.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SMK,
                                &g_sp_db.smk_key);
        if (derive_ret != true)
        {
            log_e("derive key fail.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        // The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_MK,
                                &g_sp_db.mk_key);
        if (derive_ret != true)
        {
            log_e("derive key fail.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SK,
                                &g_sp_db.sk_key);
        if (derive_ret != true)
        {
            log_e("derive key fail.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_VK,
                                &g_sp_db.vk_key);
        if (derive_ret != true)
        {
            log_e("derive key fail.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }
#endif
        uint32_t msg2_size = (uint32_t)sizeof(sample_ra_msg2_t) + sig_rl_size;

        p_msg2 = (sample_ra_msg2_t *)malloc(msg2_size);
        if (!p_msg2)
        {
            log_e("out of memory.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }
        memset(p_msg2, 0, msg2_size);

        // Assemble MSG2
        if (memcpy_s(&p_msg2->g_b, sizeof(p_msg2->g_b), &g_sp_db.g_b,
                     sizeof(g_sp_db.g_b)) ||
            memcpy_s(&p_msg2->spid, sizeof(sample_spid_t),
                     &g_spid, sizeof(g_spid)))
        {
            log_e("memcpy failed.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        // The service provider is responsible for selecting the proper EPID
        // signature type and to understand the implications of the choice!
        p_msg2->quote_type = SAMPLE_QUOTE_LINKABLE_SIGNATURE;

#ifdef SUPPLIED_KEY_DERIVATION
// isv defined key derivation function id
#define ISV_KDF_ID 2
        p_msg2->kdf_id = ISV_KDF_ID;
#else
        p_msg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;
#endif
        // Create gb_ga
        sample_ec_pub_t gb_ga[2];
        if (memcpy_s(&gb_ga[0], sizeof(gb_ga[0]), &g_sp_db.g_b,
                     sizeof(g_sp_db.g_b)) ||
            memcpy_s(&gb_ga[1], sizeof(gb_ga[1]), &g_sp_db.g_a,
                     sizeof(g_sp_db.g_a)))
        {
            log_e("memcpy failed.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        // Sign gb_ga
        sample_ret = sample_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga),
                                       (sample_ec256_private_t *)&g_sp_priv_key,
                                       (sample_ec256_signature_t *)&p_msg2->sign_gb_ga,
                                       ecc_state);
        if (SAMPLE_SUCCESS != sample_ret)
        {
            log_e("sign ga_gb fail.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        // Generate the CMACsmk for gb||SPID||TYPE||KDF_ID||Sigsp(gb,ga)
        uint8_t mac[SAMPLE_EC_MAC_SIZE] = {0};
        uint32_t cmac_size = offsetof(sample_ra_msg2_t, mac);
        sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.smk_key,
                                                 (uint8_t *)&p_msg2->g_b, cmac_size, &mac);
        if (SAMPLE_SUCCESS != sample_ret)
        {
            log_e("cmac fail.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        if (memcpy_s(&p_msg2->mac, sizeof(p_msg2->mac), mac, sizeof(mac)))
        {
            log_e("memcpy failed.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }

        if (memcpy_s(&p_msg2->sig_rl[0], sig_rl_size, sig_rl, sig_rl_size))
        {
            log_e("memcpy failed.");
            ret = ENL_INTERNAL_ERROR;
            break;
        }
        p_msg2->sig_rl_size = sig_rl_size;

    } while (0);

    if (ret)
    {
        *pp_msg2 = NULL;
        SAFE_FREE(p_msg2);
    }
    else
    {
        // Freed by the network simulator in ra_free_network_response_buffer
        *pp_msg2 = p_msg2;
    }

    if (ecc_state)
    {
        sample_ecc256_close_context(ecc_state);
    }

    return ret;
}

// Process remote attestation message 3
int sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg3,
                        uint32_t msg3_size,
                        sample_ra_att_result_msg_t **pp_att_result_msg)
{
    int ret = 0;
    sample_status_t sample_ret = SAMPLE_SUCCESS;
    const uint8_t *p_msg3_cmaced = NULL;
    const sgx_quote3_t *p_quote = NULL;
    sample_sha_state_handle_t sha_handle = NULL;
    sample_report_data_t report_data = {0};
    sample_ra_att_result_msg_t *p_att_result_msg = NULL;

    sgx_ql_auth_data_t *p_auth_data;
    sgx_ql_ecdsa_sig_data_t *p_sig_data;
    sgx_ql_certification_data_t *p_cert_data;

    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;

    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    uint32_t collateral_expiration_status = 1;

    sgx_ql_qe_report_info_t qve_report_info;
    unsigned char rand_nonce[16] = "59jslk201fgjmm;";

    uint8_t *domain_key = NULL;

    uint32_t quote_size = 0;

    if ((!p_msg3) || (msg3_size < sizeof(sample_ra_msg3_t)) || (!pp_att_result_msg))
    {
        return SP_INTERNAL_ERROR;
    }

    do
    {
        // Compare g_a in message 3 with local g_a.
        ret = memcmp(&g_sp_db.g_a, &p_msg3->g_a, sizeof(sample_ec_pub_t));
        if (ret)
        {
            fprintf(stderr, "\nError, g_a is not same [%s].", __FUNCTION__);
            ret = SP_PROTOCOL_ERROR;
            break;
        }
        // Make sure that msg3_size is bigger than sample_mac_t.
        uint32_t mac_size = msg3_size - (uint32_t)sizeof(sample_mac_t);
        p_msg3_cmaced = reinterpret_cast<const uint8_t *>(p_msg3);
        p_msg3_cmaced += sizeof(sample_mac_t);

        // Verify the message mac using SMK
        sample_cmac_128bit_tag_t mac = {0};
        sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.smk_key,
                                                 p_msg3_cmaced,
                                                 mac_size,
                                                 &mac);
        if (SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // In real implementation, should use a time safe version of memcmp here,
        // in order to avoid side channel attack.
        ret = memcmp(&p_msg3->mac, mac, sizeof(mac));
        if (ret)
        {
            fprintf(stderr, "\nError, verify cmac fail [%s].", __FUNCTION__);
            ret = SP_INTEGRITY_FAILED;
            break;
        }

        if (memcpy_s(&g_sp_db.ps_sec_prop, sizeof(g_sp_db.ps_sec_prop),
                     &p_msg3->ps_sec_prop, sizeof(p_msg3->ps_sec_prop)))
        {
            fprintf(stderr, "\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // p_quote = (const sample_quote_t*)p_msg3->quote;
        p_quote = (sgx_quote3_t *)p_msg3->quote;
        quote_size = msg3_size - (uint32_t)sizeof(sample_mac_t) - (uint32_t)sizeof(sample_ec_pub_t) - (uint32_t)sizeof(sample_ps_sec_prop_desc_t);
        p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
        p_auth_data = (sgx_ql_auth_data_t *)p_sig_data->auth_certification_data;
        p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

        // log_i("cert_key_type = 0x%x\n", p_cert_data->cert_key_type);

        // Check the quote version if needed. Only check the Quote.version field if the enclave
        // identity fields have changed or the size of the quote has changed.  The version may
        // change without affecting the legacy fields or size of the quote structure.
        // if(p_quote->version < ACCEPTED_QUOTE_VERSION)
        //{
        //    fprintf(stderr,"\nError, quote version is too old.", __FUNCTION__);
        //    ret = SP_QUOTE_VERSION_ERROR;
        //    break;
        //}

        // Verify the report_data in the Quote matches the expected value.
        // The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
        // The second 32 bytes of report_data are set to zero.
        sample_ret = sample_sha256_init(&sha_handle);
        if (sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr, "\nError, init hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.g_a),
                                          sizeof(g_sp_db.g_a), sha_handle);
        if (sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr, "\nError, udpate hash failed in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.g_b),
                                          sizeof(g_sp_db.g_b), sha_handle);
        if (sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr, "\nError, udpate hash failed in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.vk_key),
                                          sizeof(g_sp_db.vk_key), sha_handle);
        if (sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr, "\nError, udpate hash failed in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        sample_ret = sample_sha256_get_hash(sha_handle,
                                            (sample_sha256_hash_t *)&report_data);
        if (sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr, "\nError, Get hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        ret = memcmp((uint8_t *)&report_data,
                     &(p_quote->report_body.report_data),
                     sizeof(report_data));
        if (ret)
        {
            fprintf(stderr, "\nError, verify hash fail [%s].", __FUNCTION__);
            ret = SP_INTEGRITY_FAILED;
            break;
        }

        // call DCAP quote verify library to get supplemental data size
        dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
        if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t))
        {
            // log_i("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
            p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
        }
        else
        {
            log_e("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);
            supplemental_data_size = 0;
        }

        // set current time. This is only for sample purposes, in production mode a trusted time should be used.
        current_time = time(NULL);
        // set nonce
        get_drng_support();
        if (0 != get_random(rand_nonce, sizeof(rand_nonce)))
        {
            fprintf(stderr, "\nfailed to get random.\n");
            ret = SP_INTERNAL_ERROR;
            break;
        }

        memcpy(qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));
#if 0
        // Trusted quote verification
        if (use_qve) {
            //set nonce
            //
            memcpy(qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

            //get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
            //
            sgx_ret = sgx_create_enclave(SAMPLE_ISV_ENCLAVE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
            if (sgx_ret != SGX_SUCCESS) {
                log_e("\tError: Can't load SampleISVEnclave. 0x%04x\n", sgx_ret);
                return -1;
            }
            sgx_status_t get_target_info_ret;
            sgx_ret = ecall_get_target_info(eid, &get_target_info_ret, &qve_report_info.app_enclave_target_info);
            if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS) {
                log_e("\tError in sgx_get_target_info. 0x%04x\n", get_target_info_ret);
            }
            else {
                log_i("\tInfo: get target info successfully returned.\n");
            }

            //call DCAP quote verify library to set QvE loading policy
            //
            dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
            if (dcap_ret == SGX_QL_SUCCESS) {
                log_i("\tInfo: sgx_qv_set_enclave_load_policy successfully returned.\n");
            }
            else {
                log_e("\tError: sgx_qv_set_enclave_load_policy failed: 0x%04x\n", dcap_ret);
            }


            //call DCAP quote verify library to get supplemental data size
            //
            dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
            if (dcap_ret == SGX_QL_SUCCESS) {
                log_i("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
                p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
            }
            else {
                log_e("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);
                supplemental_data_size = 0;
            }

            //set current time. This is only for sample purposes, in production mode a trusted time should be used.
            //
            current_time = time(NULL);


            //call DCAP quote verify library for quote verification
            //here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
            //if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
            //if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
            dcap_ret = sgx_qv_verify_quote(
                quote.data(), (uint32_t)quote.size(),
                NULL,
                current_time,
                &collateral_expiration_status,
                &quote_verification_result,
                &qve_report_info,
                supplemental_data_size,
                p_supplemental_data);
            if (dcap_ret == SGX_QL_SUCCESS) {
                log_i("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
            }
            else {
                log_e("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
            }


            // Threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
            // e.g. You can get latest QvE ISVSVN in QvE Identity JSON file from
            // https://api.trustedservices.intel.com/sgx/certification/v2/qve/identity
            // Make sure you are using trusted & latest QvE ISV SVN as threshold
            //
            sgx_isv_svn_t qve_isvsvn_threshold = 3;

            //call sgx_dcap_tvl API in SampleISVEnclave to verify QvE's report and identity
            //
            sgx_ret = sgx_tvl_verify_qve_report_and_identity(eid,
                &verify_qveid_ret,
                quote.data(),
                (uint32_t) quote.size(),
                &qve_report_info,
                current_time,
                collateral_expiration_status,
                quote_verification_result,
                p_supplemental_data,
                supplemental_data_size,
                qve_isvsvn_threshold);

            if (sgx_ret != SGX_SUCCESS || verify_qveid_ret != SGX_QL_SUCCESS) {
                log_e("\tError: Ecall: Verify QvE report and identity failed. 0x%04x\n", verify_qveid_ret);
            }
            else {
                log_i("\tInfo: Ecall: Verify QvE report and identity successfully returned.\n");
            }

            //check verification result
            //
            switch (quote_verification_result)
            {
            case SGX_QL_QV_RESULT_OK:
                log_i("\tInfo: App: Verification completed successfully.\n");
                ret = 0;
                break;
            case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            case SGX_QL_QV_RESULT_OUT_OF_DATE:
            case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
                log_w("\tWarning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
                ret = 1;
                break;
            case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            case SGX_QL_QV_RESULT_REVOKED:
            case SGX_QL_QV_RESULT_UNSPECIFIED:
            default:
                log_e("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
                ret = -1;
                break;
            }
        }
#endif
        // call DCAP quote verify library for quote verification
        // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
        // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        dcap_ret = sgx_qv_verify_quote(
            (uint8_t *)p_quote, quote_size,
            NULL,
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            NULL,
            supplemental_data_size,
            p_supplemental_data);
        if (dcap_ret == SGX_QL_SUCCESS)
        {
            // log_i("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
        }
        else
        {
            log_e("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
            ret = -1;
            break;
        }

        // log_i("\tInfo: App: Verification quote_verification_result=%#x\n", quote_verification_result);

        // check verification result
        if ((quote_verification_result != SGX_QL_QV_RESULT_OK) &&
            (quote_verification_result != SGX_QL_QV_RESULT_OUT_OF_DATE))
        {
            log_i("verify result is not expected (%#x)\n", quote_verification_result);
            ret = -1;
            break;
        }

        domain_key = (uint8_t *)malloc(SGX_DOMAIN_KEY_SIZE);
        if (!domain_key)
        {
            ret = SP_INTERNAL_ERROR;
            break;
        }
        /*TODO: current initialize the domain key as 1*SGX_DOMAIN_KEY_SIZE
         * need to generate the real domain_key from the HSM in the real product
         */
        memset(domain_key, 1, SGX_DOMAIN_KEY_SIZE);

        // Respond the client with the results of the attestation.
        uint32_t att_result_msg_size = sizeof(sample_ra_att_result_msg_t) + SGX_DOMAIN_KEY_SIZE;
        p_att_result_msg = (sample_ra_att_result_msg_t *)malloc(att_result_msg_size);
        if (!p_att_result_msg)
        {
            fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        memset(p_att_result_msg, 0, att_result_msg_size);

        memcpy_s(p_att_result_msg->platform_info_blob.nonce.rand, sizeof(rand_nonce), rand_nonce, sizeof(rand_nonce));
        memcpy_s(&(p_att_result_msg->platform_info_blob.quote_verification_result), sizeof(sgx_ql_qv_result_t), &quote_verification_result, sizeof(sgx_ql_qv_result_t));
        memcpy_s(&(p_att_result_msg->platform_info_blob.qve_report_info), sizeof(sgx_ql_qe_report_info_t), &qve_report_info, sizeof(sgx_ql_qe_report_info_t));
        // Generate mac based on the mk key.
        mac_size = sizeof(ias_platform_info_blob_t);
        sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.mk_key,
                                                 (const uint8_t *)&p_att_result_msg->platform_info_blob,
                                                 mac_size,
                                                 &p_att_result_msg->mac);
        if (SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, cmac platform_info fail in [%s].\n", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate shared secret and encrypt it with SK, if attestation passed.
        uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};
        p_att_result_msg->secret.payload_size = SGX_DOMAIN_KEY_SIZE;

        ret = sample_rijndael128GCM_encrypt(&g_sp_db.sk_key,
                                            domain_key,
                                            p_att_result_msg->secret.payload_size,
                                            p_att_result_msg->secret.payload,
                                            &aes_gcm_iv[0],
                                            SAMPLE_SP_IV_SIZE,
                                            NULL,
                                            0,
                                            &p_att_result_msg->secret.payload_tag);

    } while (0);

    if (ret)
    {
        *pp_att_result_msg = NULL;
        SAFE_FREE(p_att_result_msg);
    }
    else
    {
        *pp_att_result_msg = p_att_result_msg;
    }

    SAFE_FREE(domain_key);
    return ret;
}

enroll_status_t ra_proc_msg1_get_msg2(RetJsonObj retJsonObj_msg1, std::string *p_msg2)
{
    enroll_status_t ret = ENL_OK;
    sample_ec_pub_t *g_a;
    sample_ra_msg2_t *tp_msg2;

    memset(&g_a, 0, sizeof(g_a));
    memset(&tp_msg2, 0, sizeof(tp_msg2));

    // Verify challenge
    std::string challenge_response = retJsonObj_msg1.readData_string("challenge");

    // compare challenge
    if (g_challenge.compare(challenge_response) != 0)
    {
        return ENL_CHALLENGE_NO_COMPARE;
        log_e("challenge compare failed(%d).", ret);
        goto OUT;
    }
    log_d("ra_proc_msg1_get_msg2 challenge compare success.");

    // process g_a
    g_a = (sample_ec_pub_t *)malloc(sizeof(sample_ec_pub_t));
    if (g_a == NULL)
    {
        ret = ENL_INTERNAL_ERROR;
        log_e("malloc failed.");
        goto OUT;
    }
    ret = unmarshal_ga_from_json(retJsonObj_msg1, g_a);
    if (ret != ENL_OK)
    {
        log_e("unmarshal_ga_from_json failed(%d).", ret);
        goto OUT;
    }

    // create msg2
    ret = sp_ra_proc_msg1_req(g_a, sizeof(sample_ec_pub_t), &tp_msg2);
    if (ret != ENL_OK || !tp_msg2)
    {
        log_e("build msg2 failed(%d).", ret);
        goto OUT;
    }

    ret = marshal_msg2_to_json(tp_msg2, p_msg2);
    if (ret != ENL_OK)
    {
        log_e("marshal_msg2_to_json failed(%d).", ret);
        goto OUT;
    }

OUT:
    SAFE_FREE(g_a);
    SAFE_FREE(tp_msg2);
    return ret;
}

enroll_status_t ra_proc_msg3_get_att_result_msg(RetJsonObj retJsonObj_msg3, std::string *p_att_result_msg)
{
    enroll_status_t ret = ENL_OK;

    sample_ra_msg3_t *p_msg3;
    uint32_t quote_size = 0;
    uint32_t msg3_size = 0;

    sample_ra_att_result_msg_t *tp_att_result_msg;

    if (p_att_result_msg == NULL)
    {
        ret = ENL_ERROR_INVALID_PARAMETER;
        goto OUT;
    }

    memset(&p_msg3, 0, sizeof(p_msg3));

    // process p_msg3
    quote_size = retJsonObj_msg3.readData_uint32("quote_size");
    msg3_size = static_cast<uint32_t>(sizeof(sample_ra_msg3_t)) + quote_size;
    p_msg3 = (sample_ra_msg3_t *)malloc(msg3_size);
    if (p_msg3 == NULL)
    {
        ret = ENL_INTERNAL_ERROR;
        log_e("malloc failed.");
        goto OUT;
    }
    ret = unmarshal_msg3_from_json(retJsonObj_msg3, p_msg3);
    if (ret != ENL_OK)
    {
        log_e("unmarshal_msg3_from_json failed(%d).", ret);
        goto OUT;
    }

    // create att_result_msg
    ret = (enroll_status_t)sp_ra_proc_msg3_req(p_msg3, msg3_size, &tp_att_result_msg);
    if (ret != ENL_OK || !tp_att_result_msg)
    {
        log_e("build att_result_msg failed(%d).", ret);
        goto OUT;
    }

    // save g_nonce
    g_nonce = tp_att_result_msg->platform_info_blob.nonce;

    ret = ra_proc_att_result_msg(tp_att_result_msg, p_att_result_msg);
    if (ret != ENL_OK)
    {
        log_e("ra_proc_att_result_msg failed(%d).", ret);
        goto OUT;
    }
OUT:
    SAFE_FREE(p_msg3);
    return ret;
}

enroll_status_t ra_proc_apikey_result_msg_get_apikey(RetJsonObj retJsonObj_apikey_result_msg, uint8_t *apikey)
{
    // check nonce
    sgx_quote_nonce_t nonce;
    enroll_status_t enroll_ret = ENL_OK;
    uint8_t *iv = nullptr;
    uint8_t *mac = nullptr;
    uint32_t ret = 0;
    uint8_t cipherapikey[EH_API_KEY_SIZE + SAMPLE_SP_IV_SIZE + SAMPLE_AESGCM_MAC_SIZE] = {0};
    int nonce_size;
    if (apikey == NULL)
    {
        ret = ENL_ERROR_VERIFY_NONCE_FAILED;
        goto OUT;
    }
    retJsonObj_apikey_result_msg.readData_uint8Array("nonce", nonce.rand);
    nonce_size = sizeof(g_nonce.rand) / sizeof(g_nonce.rand[0]);
    if (nonce_size != sizeof(nonce.rand) / sizeof(nonce.rand[0]))
    {
        enroll_ret = ENL_ERROR_VERIFY_NONCE_FAILED;
        goto OUT;
    }
    for (int i = 0; i < nonce_size; i++)
    {
        if (g_nonce.rand[i] != nonce.rand[i])
        {
            enroll_ret = ENL_ERROR_VERIFY_NONCE_FAILED;
            goto OUT;
        }
    }

    // get apikey
    retJsonObj_apikey_result_msg.readData_uint8Array("cipherapikey", cipherapikey);
    iv = (uint8_t *)(cipherapikey + EH_API_KEY_SIZE);
    mac = (uint8_t *)(cipherapikey + EH_API_KEY_SIZE + SAMPLE_SP_IV_SIZE);
    ret = sample_rijndael128GCM_decrypt(&g_sp_db.sk_key,
                                        cipherapikey,
                                        EH_API_KEY_SIZE, apikey,
                                        iv, SAMPLE_SP_IV_SIZE,
                                        NULL, 0,
                                        reinterpret_cast<uint8_t(*)[SAMPLE_AESGCM_MAC_SIZE]>(mac));
    if (ret)
    {
        enroll_ret = ENL_ERROR_DECRYPT_APIKEY_FAILED;
        goto OUT;
    }
OUT:
    // clear the g_sp_db database after the attesation session finished.
    explicit_bzero(&g_sp_db, sizeof(sp_db_item_t));
    return enroll_ret;
}
