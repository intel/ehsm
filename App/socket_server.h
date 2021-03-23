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

#ifndef _SOCKET_SERVER_H_
#define _SOCKET_SERVER_H_

#include <cstdint>
#include <vector>
#include <memory>

#include "ecp.h"

using namespace std;


namespace socket_server {

const uint32_t SOCKET_RECV_BUF_SIZE = 2 * 4096;
const uint32_t SOCKET_SEND_BUF_SIZE = 4096;

const uint32_t server_port = 8888;

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif


typedef enum {
    IAS_QUOTE_OK,
    IAS_QUOTE_SIGNATURE_INVALID,
    IAS_QUOTE_GROUP_REVOKED,
    IAS_QUOTE_SIGNATURE_REVOKED,
    IAS_QUOTE_KEY_REVOKED,
    IAS_QUOTE_SIGRL_VERSION_MISMATCH,
    IAS_QUOTE_GROUP_OUT_OF_DATE,
} ias_quote_status_t;

// These status should align with the definition in IAS API spec(rev 0.6)
typedef enum {
    IAS_PSE_OK,
    IAS_PSE_DESC_TYPE_NOT_SUPPORTED,
    IAS_PSE_ISVSVN_OUT_OF_DATE,
    IAS_PSE_MISCSELECT_INVALID,
    IAS_PSE_ATTRIBUTES_INVALID,
    IAS_PSE_MRSIGNER_INVALID,
    IAS_PS_HW_GID_REVOKED,
    IAS_PS_HW_PRIVKEY_RLVER_MISMATCH,
    IAS_PS_HW_SIG_RLVER_MISMATCH,
    IAS_PS_HW_CA_ID_INVALID,
    IAS_PS_HW_SEC_INFO_INVALID,
    IAS_PS_HW_PSDA_SVN_OUT_OF_DATE,
} ias_pse_status_t;

// Revocation Reasons from RFC5280
typedef enum {
    IAS_REVOC_REASON_NONE,
    IAS_REVOC_REASON_KEY_COMPROMISE,
    IAS_REVOC_REASON_CA_COMPROMISED,
    IAS_REVOC_REASON_SUPERCEDED,
    IAS_REVOC_REASON_CESSATION_OF_OPERATION,
    IAS_REVOC_REASON_CERTIFICATE_HOLD,
    IAS_REVOC_REASON_PRIVILEGE_WITHDRAWN,
    IAS_REVOC_REASON_AA_COMPROMISE,
} ias_revoc_reason_t;

// These status should align with the definition in IAS API spec(rev 0.6)
#define IAS_EPID_GROUP_STATUS_REVOKED_BIT_POS           0x00
#define IAS_EPID_GROUP_STATUS_REKEY_AVAILABLE_BIT_POS   0x01

#define IAS_TCB_EVAL_STATUS_CPUSVN_OUT_OF_DATE_BIT_POS  0x00
#define IAS_TCB_EVAL_STATUS_ISVSVN_OUT_OF_DATE_BIT_POS  0x01

#define IAS_PSE_EVAL_STATUS_ISVSVN_OUT_OF_DATE_BIT_POS  0x00
#define IAS_PSE_EVAL_STATUS_EPID_GROUP_REVOKED_BIT_POS  0x01
#define IAS_PSE_EVAL_STATUS_PSDASVN_OUT_OF_DATE_BIT_POS 0x02
#define IAS_PSE_EVAL_STATUS_SIGRL_OUT_OF_DATE_BIT_POS   0x03
#define IAS_PSE_EVAL_STATUS_PRIVRL_OUT_OF_DATE_BIT_POS  0x04

// These status should align with the definition in IAS API spec(rev 0.6)
#define ISVSVN_SIZE         2
#define PSDA_SVN_SIZE       4
#define GID_SIZE            4
#define PSVN_SIZE           18

#define SAMPLE_HASH_SIZE    32  // SHA256
#define SAMPLE_MAC_SIZE     16  // Message Authentication Code
                                // - 16 bytes

#define SAMPLE_REPORT_DATA_SIZE         64

typedef uint8_t             sample_measurement_t[SAMPLE_HASH_SIZE];
typedef uint8_t             sample_mac_t[SAMPLE_MAC_SIZE];
typedef uint8_t             sample_report_data_t[SAMPLE_REPORT_DATA_SIZE];
typedef uint16_t            sample_prod_id_t;

#define SAMPLE_CPUSVN_SIZE  16

typedef uint8_t             sample_cpu_svn_t[SAMPLE_CPUSVN_SIZE];
typedef uint16_t            sample_isv_svn_t;

typedef struct sample_attributes_t
{
    uint64_t                flags;
    uint64_t                xfrm;
} sample_attributes_t;

typedef struct sample_report_body_t {
    sample_cpu_svn_t        cpu_svn;        // (  0) Security Version of the CPU
    uint8_t                 reserved1[32];  // ( 16)
    sample_attributes_t     attributes;     // ( 48) Any special Capabilities
                                            //       the Enclave possess
    sample_measurement_t    mr_enclave;     // ( 64) The value of the enclave's
                                            //       ENCLAVE measurement
    uint8_t                 reserved2[32];  // ( 96)
    sample_measurement_t    mr_signer;      // (128) The value of the enclave's
                                            //       SIGNER measurement
    uint8_t                 reserved3[32];  // (160)
    sample_measurement_t    mr_reserved1;   // (192)
    sample_measurement_t    mr_reserved2;   // (224)
    sample_prod_id_t        isv_prod_id;    // (256) Product ID of the Enclave
    sample_isv_svn_t        isv_svn;        // (258) Security Version of the
                                            //       Enclave
    uint8_t                 reserved4[60];  // (260)
    sample_report_data_t    report_data;    // (320) Data provided by the user
} sample_report_body_t;

#pragma pack(push, 1)


// This is a context data structure used in SP side
// @TODO: Modify at production to use the values specified by the Production
// IAS API
typedef struct _ias_att_report_t
{
    uint32_t                id;
    ias_quote_status_t      status;
    uint32_t                revocation_reason;
    ias_platform_info_blob_t    info_blob;
    ias_pse_status_t        pse_status;
    uint32_t                policy_report_size;

    uint8_t                 policy_report[];// IAS_Q: Why does it specify a
                                            // list of reports?


} ias_att_report_t;

typedef uint8_t sample_epid_group_id_t[4];


typedef struct sample_basename_t
{
    uint8_t                 name[32];
} sample_basename_t;


typedef struct sample_quote_nonce_t
{
    uint8_t                 rand[16];
} sample_quote_nonce_t;

#define SAMPLE_QUOTE_UNLINKABLE_SIGNATURE 0
#define SAMPLE_QUOTE_LINKABLE_SIGNATURE   1

typedef struct sample_quote_t {
    uint16_t                version;        // 0
    uint16_t                sign_type;      // 2
    sample_epid_group_id_t  epid_group_id;  // 4
    sample_isv_svn_t        qe_svn;         // 8
    uint8_t                 reserved[6];    // 10
    sample_basename_t       basename;       // 16
    sample_report_body_t    report_body;    // 48
    uint32_t                signature_len;  // 432
    uint8_t                 signature[];    // 436
} sample_quote_t;

#pragma pack(pop)



/* Enum for all possible message types between the ISV app and
 * the ISV SP. Requests and responses in the remote attestation
 * sample.
 */
typedef enum _ra_msg_type_t
{
     TYPE_RA_MSG0,
     TYPE_RA_MSG1,
     TYPE_RA_MSG2,
     TYPE_RA_MSG3,
     TYPE_RA_ATT_RESULT,
}ra_msg_type_t;

/* Enum for all possible message types between the SP and IAS.
 * Network communication is not simulated in the remote
 * attestation sample.  Currently these aren't used.
 */
typedef enum _ias_msg_type_t
{
     TYPE_IAS_ENROLL,
     TYPE_IAS_GET_SIGRL,
     TYPE_IAS_SIGRL,
     TYPE_IAS_ATT_EVIDENCE,
     TYPE_IAS_ATT_RESULT,
}ias_msg_type_t;

#pragma pack(1)

typedef struct _ra_samp_request_header_t{
    uint8_t  type;     /* set to one of ra_msg_type_t*/
    uint32_t size;     /*size of request body*/
    uint8_t  align[3];
    uint8_t body[];
}ra_samp_request_header_t;

typedef struct _ra_samp_response_header_t{
    uint8_t  type;      /* set to one of ra_msg_type_t*/
    uint8_t  status[2];
    uint32_t size;      /*size of the response body*/
    uint8_t  align[1];
    uint8_t  body[];
}ra_samp_response_header_t;

#pragma pack()

typedef enum {
    SP_OK,
    SP_UNSUPPORTED_EXTENDED_EPID_GROUP,
    SP_INTEGRITY_FAILED,
    SP_QUOTE_VERIFICATION_FAILED,
    SP_IAS_FAILED,
    SP_INTERNAL_ERROR,
    SP_PROTOCOL_ERROR,
    SP_QUOTE_VERSION_ERROR,
} sp_ra_msg_status_t;

#pragma pack(push,1)

#define SAMPLE_SP_TAG_SIZE       16
#define SAMPLE_SP_IV_SIZE        12

#ifndef SAMPLE_FEBITSIZE
    #define SAMPLE_FEBITSIZE                    256
#endif

#define SAMPLE_ECP_KEY_SIZE                     (SAMPLE_FEBITSIZE/8)

#define SAMPLE_HASH_SIZE    32  // SHA256
#define SAMPLE_MAC_SIZE     16  // Message Authentication Code
                                // - 16 bytes

/*Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion*/
const uint16_t SAMPLE_AES_CMAC_KDF_ID = 0x0001;


#pragma pack(pop)

typedef uint32_t                sample_ra_context_t;

typedef uint8_t                 sample_key_128bit_t[16];

typedef sample_key_128bit_t     sample_ra_key_128_t;

typedef struct sample_ec_pub_t
{
    uint8_t gx[SAMPLE_ECP_KEY_SIZE];
    uint8_t gy[SAMPLE_ECP_KEY_SIZE];
} sample_ec_pub_t;

typedef uint8_t sample_epid_group_id_t[4];

typedef struct sample_spid_t
{
    uint8_t                 id[16];
} sample_spid_t;

typedef struct sample_ra_msg0_t
{
    uint32_t                    extended_epid_group_id;
} sample_ra_msg0_t;

typedef struct sample_ra_msg1_t
{
    sample_ec_pub_t             g_a;        /* the Endian-ness of Ga is
                                                 Little-Endian*/
    sample_epid_group_id_t      gid;        /* the Endian-ness of GID is
                                                 Little-Endian*/
} sample_ra_msg1_t;

#define SAMPLE_NISTP256_KEY_SIZE    (SAMPLE_FEBITSIZE/ 8 /sizeof(uint32_t))

typedef struct sample_ec_sign256_t
{
    uint32_t x[SAMPLE_NISTP256_KEY_SIZE];
    uint32_t y[SAMPLE_NISTP256_KEY_SIZE];
} sample_ec_sign256_t;

typedef uint8_t             sample_mac_t[SAMPLE_MAC_SIZE];

typedef struct sample_ra_msg2_t
{
    sample_ec_pub_t             g_b;        /* the Endian-ness of Gb is
                                                  Little-Endian*/
    sample_spid_t               spid;       /* In little endian*/
    uint16_t                    quote_type; /* unlinkable Quote(0) or linkable Quote(0) in little endian*/
    uint16_t                    kdf_id;     /* key derivation function id in little endian.
                                             0x0001 for AES-CMAC Entropy Extraction and Key Derivation */
    sample_ec_sign256_t         sign_gb_ga; /* In little endian*/
    sample_mac_t                mac;        /* mac_smk(g_b||spid||quote_type||
                                                       sign_gb_ga)*/
    uint32_t                    sig_rl_size;
    uint8_t                     sig_rl[];
} sample_ra_msg2_t;

/*fixed length to align with internal structure*/
typedef struct sample_ps_sec_prop_desc_t
{
    uint8_t  sample_ps_sec_prop_desc[256];
} sample_ps_sec_prop_desc_t;

typedef struct sample_ra_msg3_t
{
    sample_mac_t                mac;           /* mac_smk(g_a||ps_sec_prop||quote)*/
    sample_ec_pub_t             g_a;           /* the Endian-ness of Ga is*/
                                               /*  Little-Endian*/
    sample_ps_sec_prop_desc_t   ps_sec_prop;
    uint8_t                     quote[];
} sample_ra_msg3_t;


/*
int sp_ra_proc_msg0_req(const sample_ra_msg0_t *p_msg0,
    uint32_t msg0_size, ra_samp_response_header_t **pp_msg0_resp);

int sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg1,
						uint32_t msg1_size,
						ra_samp_response_header_t **pp_msg2);

int sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg3,
                        uint32_t msg3_size,
                        ra_samp_response_header_t **pp_att_result_msg);

int sp_ra_free_msg2(sample_ra_msg2_t *p_msg2);

int32_t SocketDispatchCmd(
                        ra_samp_request_header_t *req,
                        ra_samp_response_header_t **p_resp);
*/
class SocketServer {
public:
    SocketServer() = default;
    ~SocketServer() = default;
    /* initialize the socket handle */
    void Initialize();

};

}

#endif

