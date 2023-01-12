#include "enclave_u.h"
#include <errno.h>

typedef struct ms_enclave_launch_tls_client_t {
	int ms_retval;
	const char* ms_server_name;
	size_t ms_server_name_len;
	uint16_t ms_server_port;
	uint32_t ms_key;
	const char* ms_action;
	size_t ms_action_len;
} ms_enclave_launch_tls_client_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_printf_t {
	const char* ms_str;
} ms_ocall_printf_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_sleep_t {
	int ms_sec;
} ms_ocall_sleep_t;

typedef struct ms_ocall_get_current_time_t {
	uint64_t* ms_p_current_time;
} ms_ocall_get_current_time_t;

typedef struct ms_ocall_socket_t {
	int ms_retval;
	int ocall_errno;
	int ms_domain;
	int ms_type;
	int ms_protocol;
} ms_ocall_socket_t;

typedef struct ms_ocall_connect_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	const struct sockaddr* ms_addr;
	socklen_t ms_len;
} ms_ocall_connect_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_u_sgxssl_write_t {
	size_t ms_retval;
	int ms_fd;
	const void* ms_buf;
	size_t ms_n;
} ms_u_sgxssl_write_t;

typedef struct ms_u_sgxssl_read_t {
	size_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_u_sgxssl_read_t;

typedef struct ms_u_sgxssl_close_t {
	int ms_retval;
	int ms_fd;
} ms_u_sgxssl_close_t;

typedef struct ms_sgx_tls_get_qe_target_info_ocall_t {
	quote3_error_t ms_retval;
	sgx_target_info_t* ms_p_target_info;
	size_t ms_target_info_size;
} ms_sgx_tls_get_qe_target_info_ocall_t;

typedef struct ms_sgx_tls_get_quote_size_ocall_t {
	quote3_error_t ms_retval;
	uint32_t* ms_p_quote_size;
} ms_sgx_tls_get_quote_size_ocall_t;

typedef struct ms_sgx_tls_get_quote_ocall_t {
	quote3_error_t ms_retval;
	sgx_report_t* ms_p_report;
	size_t ms_report_size;
	uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
} ms_sgx_tls_get_quote_ocall_t;

typedef struct ms_sgx_tls_get_supplemental_data_size_ocall_t {
	quote3_error_t ms_retval;
	uint32_t* ms_p_supplemental_data_size;
} ms_sgx_tls_get_supplemental_data_size_ocall_t;

typedef struct ms_sgx_tls_verify_quote_ocall_t {
	quote3_error_t ms_retval;
	const uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
	time_t ms_expiration_check_date;
	sgx_ql_qv_result_t* ms_p_quote_verification_result;
	sgx_ql_qe_report_info_t* ms_p_qve_report_info;
	size_t ms_qve_report_info_size;
	uint8_t* ms_p_supplemental_data;
	uint32_t ms_supplemental_data_size;
} ms_sgx_tls_verify_quote_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL enclave_ocall_printf(void* pms)
{
	ms_ocall_printf_t* ms = SGX_CAST(ms_ocall_printf_t*, pms);
	ocall_printf(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ocall_sleep(ms->ms_sec);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_get_current_time(void* pms)
{
	ms_ocall_get_current_time_t* ms = SGX_CAST(ms_ocall_get_current_time_t*, pms);
	ocall_get_current_time(ms->ms_p_current_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_socket(void* pms)
{
	ms_ocall_socket_t* ms = SGX_CAST(ms_ocall_socket_t*, pms);
	ms->ms_retval = ocall_socket(ms->ms_domain, ms->ms_type, ms->ms_protocol);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_connect(void* pms)
{
	ms_ocall_connect_t* ms = SGX_CAST(ms_ocall_connect_t*, pms);
	ms->ms_retval = ocall_connect(ms->ms_fd, ms->ms_addr, ms->ms_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_u_sgxssl_write(void* pms)
{
	ms_u_sgxssl_write_t* ms = SGX_CAST(ms_u_sgxssl_write_t*, pms);
	ms->ms_retval = u_sgxssl_write(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_u_sgxssl_read(void* pms)
{
	ms_u_sgxssl_read_t* ms = SGX_CAST(ms_u_sgxssl_read_t*, pms);
	ms->ms_retval = u_sgxssl_read(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_u_sgxssl_close(void* pms)
{
	ms_u_sgxssl_close_t* ms = SGX_CAST(ms_u_sgxssl_close_t*, pms);
	ms->ms_retval = u_sgxssl_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_tls_get_qe_target_info_ocall(void* pms)
{
	ms_sgx_tls_get_qe_target_info_ocall_t* ms = SGX_CAST(ms_sgx_tls_get_qe_target_info_ocall_t*, pms);
	ms->ms_retval = sgx_tls_get_qe_target_info_ocall(ms->ms_p_target_info, ms->ms_target_info_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_tls_get_quote_size_ocall(void* pms)
{
	ms_sgx_tls_get_quote_size_ocall_t* ms = SGX_CAST(ms_sgx_tls_get_quote_size_ocall_t*, pms);
	ms->ms_retval = sgx_tls_get_quote_size_ocall(ms->ms_p_quote_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_tls_get_quote_ocall(void* pms)
{
	ms_sgx_tls_get_quote_ocall_t* ms = SGX_CAST(ms_sgx_tls_get_quote_ocall_t*, pms);
	ms->ms_retval = sgx_tls_get_quote_ocall(ms->ms_p_report, ms->ms_report_size, ms->ms_p_quote, ms->ms_quote_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_tls_get_supplemental_data_size_ocall(void* pms)
{
	ms_sgx_tls_get_supplemental_data_size_ocall_t* ms = SGX_CAST(ms_sgx_tls_get_supplemental_data_size_ocall_t*, pms);
	ms->ms_retval = sgx_tls_get_supplemental_data_size_ocall(ms->ms_p_supplemental_data_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_tls_verify_quote_ocall(void* pms)
{
	ms_sgx_tls_verify_quote_ocall_t* ms = SGX_CAST(ms_sgx_tls_verify_quote_ocall_t*, pms);
	ms->ms_retval = sgx_tls_verify_quote_ocall(ms->ms_p_quote, ms->ms_quote_size, ms->ms_expiration_check_date, ms->ms_p_quote_verification_result, ms->ms_p_qve_report_info, ms->ms_qve_report_info_size, ms->ms_p_supplemental_data, ms->ms_supplemental_data_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[23];
} ocall_table_enclave = {
	23,
	{
		(void*)enclave_ocall_printf,
		(void*)enclave_ocall_close,
		(void*)enclave_ocall_sleep,
		(void*)enclave_ocall_get_current_time,
		(void*)enclave_ocall_socket,
		(void*)enclave_ocall_connect,
		(void*)enclave_sgx_oc_cpuidex,
		(void*)enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)enclave_u_sgxssl_ftime,
		(void*)enclave_u_sgxssl_write,
		(void*)enclave_u_sgxssl_read,
		(void*)enclave_u_sgxssl_close,
		(void*)enclave_sgx_tls_get_qe_target_info_ocall,
		(void*)enclave_sgx_tls_get_quote_size_ocall,
		(void*)enclave_sgx_tls_get_quote_ocall,
		(void*)enclave_sgx_tls_get_supplemental_data_size_ocall,
		(void*)enclave_sgx_tls_verify_quote_ocall,
		(void*)enclave_pthread_wait_timeout_ocall,
		(void*)enclave_pthread_create_ocall,
		(void*)enclave_pthread_wakeup_ocall,
	}
};
sgx_status_t enclave_launch_tls_client(sgx_enclave_id_t eid, int* retval, const char* server_name, uint16_t server_port, uint32_t key, const char* action)
{
	sgx_status_t status;
	ms_enclave_launch_tls_client_t ms;
	ms.ms_server_name = server_name;
	ms.ms_server_name_len = server_name ? strlen(server_name) + 1 : 0;
	ms.ms_server_port = server_port;
	ms.ms_key = key;
	ms.ms_action = action;
	ms.ms_action_len = action ? strlen(action) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

