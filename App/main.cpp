#include <stdint.h>
#include <stdio.h>
#include <memory>
#include <string.h>
#include <error.h>

#include <limits.h>
#include <unistd.h>

#include <enclave_u.h>

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"

#include <socket_client.h>

using namespace std;
using namespace socket_client;

void ocall_print_string(const char *str)
{
     printf("Enclave: %s", str);
}


// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
}


#define _T(x) x

int main(int argc, char* argv[])
{   
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    ra_samp_request_header_t* p_msg3_full = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;

    sample_ra_att_result_msg_t *p_att_result_msg_body = NULL;
    sgx_ra_msg2_t* p_msg2_body = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;

    uint32_t msg3_size = 0;
    sgx_enclave_id_t enclave_id = 0;
    int busy_retry_time = 4;
    int enclave_lost_retry_time = 1;
    sgx_ra_context_t context = INT_MAX;
    sgx_status_t status = SGX_SUCCESS;
    int ret = 0;
    FILE* OUTPUT = stdout;

    sgx_att_key_id_t selected_key_id = {0}; //acutally not used in our case


    /* Connect to ther TCP-Server */
    SocketClient *sc = new SocketClient();
    if(!sc) {
        fprintf(OUTPUT, "Failed to initialize the socket client.\n");
        return ERR_GENERIC;
    }

    if(!sc->IsOpen()) {
        fprintf(OUTPUT, "Try to connect to the socket server.\n");
        sc->Open();
    }
 
    /* Creates the provisioning enclave. */
    do {
        ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                             SGX_DEBUG_FLAG,
                             NULL,
                             NULL,
                             &enclave_id, NULL);
        if(SGX_SUCCESS != ret) {
            fprintf(OUTPUT, "Error, call sgx_create_enclave failed(%d).\n", ret);
            goto CLEANUP;
        }
        fprintf(OUTPUT, "Call sgx_create_enclave success.\n");


        ret = enclave_init_ra(enclave_id,
                          &status,
                          false,
                          &context);
        //Ideally, this check would be around the full attestation flow.
    } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

    if(SGX_SUCCESS != ret || status) {
        ret = -1;
        fprintf(OUTPUT, "Error, call enclave_init_ra failed.\n");
        goto CLEANUP;
    }
    fprintf(OUTPUT, "Call enclave_init_ra success.\n");

    /* Allocate MSG1 buf to call libukey_exchange API to retrieve MSG1 */
    p_msg1_full = (ra_samp_request_header_t*)
                 malloc(sizeof(ra_samp_request_header_t)
                        + sizeof(sgx_ra_msg1_t));
    if(NULL == p_msg1_full) {
        ret = -1;
        goto CLEANUP;
    }
    p_msg1_full->type = TYPE_RA_MSG1;
    p_msg1_full->size = sizeof(sgx_ra_msg1_t);

    do
    {
        ret = sgx_ra_get_msg1_ex(&selected_key_id, context, enclave_id, sgx_ra_get_ga,
                             (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
                             + sizeof(ra_samp_request_header_t)));
        //sleep(3); // Wait 3s between retries
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    if(SGX_SUCCESS != ret) {
        fprintf(OUTPUT, "Error, call sgx_ra_get_msg1_ex failed(%#x)\n", ret);
        ret = -1;
        goto CLEANUP;
    }
    fprintf(OUTPUT, "Call sgx_ra_get_msg1_ex success, the MSG1 body generated.\n");

    //PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);

    fprintf(OUTPUT, "Sending MSG1 to remote attestation service provider, and expecting MSG2 back...\n");
    sc->SendAndRecvMsg(p_msg1_full, &p_msg2_full);
    if(!p_msg2_full) {
        fprintf(OUTPUT, "Error,sending MSG1 failed.\n");
        ret = -1;
        goto CLEANUP;
    }

    /* Successfully sent MSG1 and received a MSG2 back. */
    if(TYPE_RA_MSG2 != p_msg2_full->type) {
        fprintf(OUTPUT, "Error, MSG2's type is not matched!\n");
        ret = -1;
        goto CLEANUP;
    }

    //PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full, (uint32_t)sizeof(ra_samp_response_header_t) + p_msg2_full->size);
    fprintf(OUTPUT, "MSG2 recieved success!\n");

    /* Call lib key_u(t)exchange(sgx_ra_proc_msg2_ex) to process the MSG2 and retrieve MSG3 back. */
    p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full + sizeof(ra_samp_response_header_t));

    busy_retry_time = 2;
    do
    {
        ret = sgx_ra_proc_msg2_ex(&selected_key_id,
                           context,
                           enclave_id,
                           sgx_ra_proc_msg2_trusted,
                           sgx_ra_get_msg3_trusted,
                           p_msg2_body,
                           p_msg2_full->size,
                           &p_msg3,
                           &msg3_size);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    if(!p_msg3 || (SGX_SUCCESS != (sgx_status_t)ret)) {
        fprintf(OUTPUT, "Error(%d), call sgx_ra_proc_msg2_ex failed, p_msg3 = 0x%p.", ret, p_msg3);
        goto CLEANUP;
    }
    fprintf(OUTPUT, "Call sgx_ra_proc_msg2_ex success.\n");

    //PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

    p_msg3_full = (ra_samp_request_header_t*)malloc(sizeof(ra_samp_request_header_t) + msg3_size);
    if(NULL == p_msg3_full) {
        ret = -1;
        goto CLEANUP;
    }
    p_msg3_full->type = TYPE_RA_MSG3;
    p_msg3_full->size = msg3_size;
    if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size)) {
        fprintf(OUTPUT,"Error: memcpy failed\n.");
        ret = -1;
        goto CLEANUP;
    }

    // The ISV application sends msg3 to the SP to get the attestation
    // result message, attestation result message needs to be freed when
    // no longer needed. The ISV service provider decides whether to use
    // linkable or unlinkable signatures. The format of the attestation
    // result is up to the service provider. This format is used for
    // demonstration.  Note that the attestation result message makes use
    // of both the MK for the MAC and the SK for the secret. These keys are
    // established from the SIGMA secure channel binding.
    fprintf(OUTPUT, "Sending MSG3 to remote attestation service provider,"
                        "expecting attestation result msg back...\n");
    sc->SendAndRecvMsg(p_msg3_full, &p_att_result_msg_full);
    if(ret || !p_att_result_msg_full) {
        ret = -1;
        fprintf(OUTPUT, "Error, sending MSG3 failed\n.");
        goto CLEANUP;
    }


    p_att_result_msg_body = (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                           + sizeof(ra_samp_response_header_t));
    if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type) {
        ret = -1;
        fprintf(OUTPUT, "Error, the attestaion MSG's type is not matched!\n");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "Attestation result MSG recieved success!\n");
    //PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body, p_att_result_msg_full->size);

    /*
    * Check the MAC using MK on the attestation result message.
    * The format of the attestation result message is specific(sample_ra_att_result_msg_t).
    */
    ret = verify_att_result_mac(enclave_id,
            &status,
            context,
            (uint8_t*)&p_att_result_msg_body->platform_info_blob,
            sizeof(ias_platform_info_blob_t),
            (uint8_t*)&p_att_result_msg_body->mac,
            sizeof(sgx_mac_t));
    if((SGX_SUCCESS != ret) ||
       (SGX_SUCCESS != status)) {
        ret = -1;
        fprintf(OUTPUT, "Error: Attestation result MSG's MK based cmac check failed\n");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "Verify attestation result is succeed!\n");

    ret = put_secret_data(enclave_id,
                          &status,
                          context,
                          p_att_result_msg_body->secret.payload,
                          p_att_result_msg_body->secret.payload_size,
                          p_att_result_msg_body->secret.payload_tag);
    if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status)) {
        fprintf(OUTPUT, "Error(%d), decrypt secret using SK based on AES-GCM failed.\n", ret);
        ret = -1;
        goto CLEANUP;
    }

    fprintf(OUTPUT, "Secret successfully received from server.");
CLEANUP:
    // Clean-up
    // Need to close the RA key state.
    if(INT_MAX != context) {
        int ret_save = ret;
        ret = enclave_ra_close(enclave_id, &status, context);
        if(SGX_SUCCESS != ret || status) {
            fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%#x].\n",ret);
        }
        else {
            // enclave_ra_close was successful, let's restore the value that
            // led us to this point in the code.
            ret = ret_save;
        }
        fprintf(OUTPUT, "\nCall enclave_ra_close success.\n");
    }

    sgx_destroy_enclave(enclave_id);

    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg2_full);
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_att_result_msg_full);

    return ret;
}

