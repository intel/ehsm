#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_ttls.h"
#include "sgx_key_exchange.h"
#include "sgx_quote.h"
#include "sgx_trts.h"
#include "stdbool.h"
#include "datatypes.h"
#include "dh_session_protocol.h"
#include "sys/socket.h"
#include "sys/select.h"
#include "netdb.h"
#include "poll.h"
#include "sgx_report.h"
#include "sgx_qve_header.h"
#include "sgx_ql_lib_common.h"
#include "sgx_ql_quote.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int enclave_launch_tls_client(const char* server_name, uint16_t server_port, uint32_t key, const char* action);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_printf(const char* str);
sgx_status_t SGX_CDECL ocall_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_sleep(int sec);
sgx_status_t SGX_CDECL ocall_get_current_time(uint64_t* p_current_time);
sgx_status_t SGX_CDECL ocall_socket(int* retval, int domain, int type, int protocol);
sgx_status_t SGX_CDECL ocall_connect(int* retval, int fd, const struct sockaddr* addr, socklen_t len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL u_sgxssl_write(size_t* retval, int fd, const void* buf, size_t n);
sgx_status_t SGX_CDECL u_sgxssl_read(size_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL u_sgxssl_close(int* retval, int fd);
sgx_status_t SGX_CDECL sgx_tls_get_qe_target_info_ocall(quote3_error_t* retval, sgx_target_info_t* p_target_info, size_t target_info_size);
sgx_status_t SGX_CDECL sgx_tls_get_quote_size_ocall(quote3_error_t* retval, uint32_t* p_quote_size);
sgx_status_t SGX_CDECL sgx_tls_get_quote_ocall(quote3_error_t* retval, sgx_report_t* p_report, size_t report_size, uint8_t* p_quote, uint32_t quote_size);
sgx_status_t SGX_CDECL sgx_tls_get_supplemental_data_size_ocall(quote3_error_t* retval, uint32_t* p_supplemental_data_size);
sgx_status_t SGX_CDECL sgx_tls_verify_quote_ocall(quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, time_t expiration_check_date, sgx_ql_qv_result_t* p_quote_verification_result, sgx_ql_qe_report_info_t* p_qve_report_info, size_t qve_report_info_size, uint8_t* p_supplemental_data, uint32_t supplemental_data_size);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
