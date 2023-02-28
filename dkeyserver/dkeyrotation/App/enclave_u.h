#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

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

#ifndef OCALL_PRINTF_DEFINED__
#define OCALL_PRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_printf, (const char* str));
#endif
#ifndef OCALL_CLOSE_DEFINED__
#define OCALL_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd));
#endif
#ifndef OCALL_SLEEP_DEFINED__
#define OCALL_SLEEP_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sleep, (int sec));
#endif
#ifndef OCALL_GET_CURRENT_TIME_DEFINED__
#define OCALL_GET_CURRENT_TIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_current_time, (uint64_t* p_current_time));
#endif
#ifndef OCALL_SOCKET_DEFINED__
#define OCALL_SOCKET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_socket, (int domain, int type, int protocol));
#endif
#ifndef OCALL_CONNECT_DEFINED__
#define OCALL_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_connect, (int fd, const struct sockaddr* addr, socklen_t len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef U_SGXSSL_WRITE_DEFINED__
#define U_SGXSSL_WRITE_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_write, (int fd, const void* buf, size_t n));
#endif
#ifndef U_SGXSSL_READ_DEFINED__
#define U_SGXSSL_READ_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_read, (int fd, void* buf, size_t count));
#endif
#ifndef U_SGXSSL_CLOSE_DEFINED__
#define U_SGXSSL_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_close, (int fd));
#endif
#ifndef SGX_TLS_GET_QE_TARGET_INFO_OCALL_DEFINED__
#define SGX_TLS_GET_QE_TARGET_INFO_OCALL_DEFINED__
quote3_error_t SGX_UBRIDGE(SGX_NOCONVENTION, sgx_tls_get_qe_target_info_ocall, (sgx_target_info_t* p_target_info, size_t target_info_size));
#endif
#ifndef SGX_TLS_GET_QUOTE_SIZE_OCALL_DEFINED__
#define SGX_TLS_GET_QUOTE_SIZE_OCALL_DEFINED__
quote3_error_t SGX_UBRIDGE(SGX_NOCONVENTION, sgx_tls_get_quote_size_ocall, (uint32_t* p_quote_size));
#endif
#ifndef SGX_TLS_GET_QUOTE_OCALL_DEFINED__
#define SGX_TLS_GET_QUOTE_OCALL_DEFINED__
quote3_error_t SGX_UBRIDGE(SGX_NOCONVENTION, sgx_tls_get_quote_ocall, (sgx_report_t* p_report, size_t report_size, uint8_t* p_quote, uint32_t quote_size));
#endif
#ifndef SGX_TLS_GET_SUPPLEMENTAL_DATA_SIZE_OCALL_DEFINED__
#define SGX_TLS_GET_SUPPLEMENTAL_DATA_SIZE_OCALL_DEFINED__
quote3_error_t SGX_UBRIDGE(SGX_NOCONVENTION, sgx_tls_get_supplemental_data_size_ocall, (uint32_t* p_supplemental_data_size));
#endif
#ifndef SGX_TLS_VERIFY_QUOTE_OCALL_DEFINED__
#define SGX_TLS_VERIFY_QUOTE_OCALL_DEFINED__
quote3_error_t SGX_UBRIDGE(SGX_NOCONVENTION, sgx_tls_verify_quote_ocall, (const uint8_t* p_quote, uint32_t quote_size, time_t expiration_check_date, sgx_ql_qv_result_t* p_quote_verification_result, sgx_ql_qe_report_info_t* p_qve_report_info, size_t qve_report_info_size, uint8_t* p_supplemental_data, uint32_t supplemental_data_size));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif

sgx_status_t enclave_launch_tls_client(sgx_enclave_id_t eid, int* retval, const char* server_name, uint16_t server_port, uint32_t key, const char* action);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
