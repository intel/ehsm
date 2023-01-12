#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_enclave_launch_tls_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_launch_tls_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_launch_tls_client_t* ms = SGX_CAST(ms_enclave_launch_tls_client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_server_name = ms->ms_server_name;
	size_t _len_server_name = ms->ms_server_name_len ;
	char* _in_server_name = NULL;
	const char* _tmp_action = ms->ms_action;
	size_t _len_action = ms->ms_action_len ;
	char* _in_action = NULL;

	CHECK_UNIQUE_POINTER(_tmp_server_name, _len_server_name);
	CHECK_UNIQUE_POINTER(_tmp_action, _len_action);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_server_name != NULL && _len_server_name != 0) {
		_in_server_name = (char*)malloc(_len_server_name);
		if (_in_server_name == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_server_name, _len_server_name, _tmp_server_name, _len_server_name)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_server_name[_len_server_name - 1] = '\0';
		if (_len_server_name != strlen(_in_server_name) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_action != NULL && _len_action != 0) {
		_in_action = (char*)malloc(_len_action);
		if (_in_action == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_action, _len_action, _tmp_action, _len_action)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_action[_len_action - 1] = '\0';
		if (_len_action != strlen(_in_action) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = enclave_launch_tls_client((const char*)_in_server_name, ms->ms_server_port, ms->ms_key, (const char*)_in_action);

err:
	if (_in_server_name) free(_in_server_name);
	if (_in_action) free(_in_action);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}

	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
	if (_in_g_a) {
		if (memcpy_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}

	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_enclave_launch_tls_client, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[23][4];
} g_dyn_entry_table = {
	23,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_printf(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_printf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_printf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_printf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_printf_t));
	ocalloc_size -= sizeof(ms_ocall_printf_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_t));
	ocalloc_size -= sizeof(ms_ocall_close_t);

	ms->ms_fd = fd;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sleep(int sec)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sleep_t));
	ocalloc_size -= sizeof(ms_ocall_sleep_t);

	ms->ms_sec = sec;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_current_time(uint64_t* p_current_time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_current_time = sizeof(uint64_t);

	ms_ocall_get_current_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_current_time_t);
	void *__tmp = NULL;

	void *__tmp_p_current_time = NULL;

	CHECK_ENCLAVE_POINTER(p_current_time, _len_p_current_time);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_current_time != NULL) ? _len_p_current_time : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_current_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_current_time_t));
	ocalloc_size -= sizeof(ms_ocall_get_current_time_t);

	if (p_current_time != NULL) {
		ms->ms_p_current_time = (uint64_t*)__tmp;
		__tmp_p_current_time = __tmp;
		if (_len_p_current_time % sizeof(*p_current_time) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_p_current_time, 0, _len_p_current_time);
		__tmp = (void *)((size_t)__tmp + _len_p_current_time);
		ocalloc_size -= _len_p_current_time;
	} else {
		ms->ms_p_current_time = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (p_current_time) {
			if (memcpy_s((void*)p_current_time, _len_p_current_time, __tmp_p_current_time, _len_p_current_time)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_socket(int* retval, int domain, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_socket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_socket_t));
	ocalloc_size -= sizeof(ms_ocall_socket_t);

	ms->ms_domain = domain;
	ms->ms_type = type;
	ms->ms_protocol = protocol;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_connect(int* retval, int fd, const struct sockaddr* addr, socklen_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = len;

	ms_ocall_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_connect_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_connect_t));
	ocalloc_size -= sizeof(ms_ocall_connect_t);

	ms->ms_fd = fd;
	if (addr != NULL) {
		ms->ms_addr = (const struct sockaddr*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_write(size_t* retval, int fd, const void* buf, size_t n)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_u_sgxssl_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_write_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_write_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_write_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_n = n;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_read(size_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_u_sgxssl_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_read_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_read_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxssl_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_close_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_close_t);

	ms->ms_fd = fd;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_get_qe_target_info_ocall(quote3_error_t* retval, sgx_target_info_t* p_target_info, size_t target_info_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_target_info = target_info_size;

	ms_sgx_tls_get_qe_target_info_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_get_qe_target_info_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_target_info = NULL;

	CHECK_ENCLAVE_POINTER(p_target_info, _len_p_target_info);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_target_info != NULL) ? _len_p_target_info : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_get_qe_target_info_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_get_qe_target_info_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_get_qe_target_info_ocall_t);

	if (p_target_info != NULL) {
		ms->ms_p_target_info = (sgx_target_info_t*)__tmp;
		__tmp_p_target_info = __tmp;
		memset(__tmp_p_target_info, 0, _len_p_target_info);
		__tmp = (void *)((size_t)__tmp + _len_p_target_info);
		ocalloc_size -= _len_p_target_info;
	} else {
		ms->ms_p_target_info = NULL;
	}
	
	ms->ms_target_info_size = target_info_size;
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (p_target_info) {
			if (memcpy_s((void*)p_target_info, _len_p_target_info, __tmp_p_target_info, _len_p_target_info)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_get_quote_size_ocall(quote3_error_t* retval, uint32_t* p_quote_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_quote_size = sizeof(uint32_t);

	ms_sgx_tls_get_quote_size_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_get_quote_size_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_quote_size = NULL;

	CHECK_ENCLAVE_POINTER(p_quote_size, _len_p_quote_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_quote_size != NULL) ? _len_p_quote_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_get_quote_size_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_get_quote_size_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_get_quote_size_ocall_t);

	if (p_quote_size != NULL) {
		ms->ms_p_quote_size = (uint32_t*)__tmp;
		__tmp_p_quote_size = __tmp;
		if (_len_p_quote_size % sizeof(*p_quote_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_p_quote_size, 0, _len_p_quote_size);
		__tmp = (void *)((size_t)__tmp + _len_p_quote_size);
		ocalloc_size -= _len_p_quote_size;
	} else {
		ms->ms_p_quote_size = NULL;
	}
	
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (p_quote_size) {
			if (memcpy_s((void*)p_quote_size, _len_p_quote_size, __tmp_p_quote_size, _len_p_quote_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_get_quote_ocall(quote3_error_t* retval, sgx_report_t* p_report, size_t report_size, uint8_t* p_quote, uint32_t quote_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_report = report_size;
	size_t _len_p_quote = quote_size;

	ms_sgx_tls_get_quote_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_get_quote_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_quote = NULL;

	CHECK_ENCLAVE_POINTER(p_report, _len_p_report);
	CHECK_ENCLAVE_POINTER(p_quote, _len_p_quote);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_report != NULL) ? _len_p_report : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_quote != NULL) ? _len_p_quote : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_get_quote_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_get_quote_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_get_quote_ocall_t);

	if (p_report != NULL) {
		ms->ms_p_report = (sgx_report_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, p_report, _len_p_report)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_report);
		ocalloc_size -= _len_p_report;
	} else {
		ms->ms_p_report = NULL;
	}
	
	ms->ms_report_size = report_size;
	if (p_quote != NULL) {
		ms->ms_p_quote = (uint8_t*)__tmp;
		__tmp_p_quote = __tmp;
		if (_len_p_quote % sizeof(*p_quote) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_p_quote, 0, _len_p_quote);
		__tmp = (void *)((size_t)__tmp + _len_p_quote);
		ocalloc_size -= _len_p_quote;
	} else {
		ms->ms_p_quote = NULL;
	}
	
	ms->ms_quote_size = quote_size;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (p_quote) {
			if (memcpy_s((void*)p_quote, _len_p_quote, __tmp_p_quote, _len_p_quote)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_get_supplemental_data_size_ocall(quote3_error_t* retval, uint32_t* p_supplemental_data_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_supplemental_data_size = sizeof(uint32_t);

	ms_sgx_tls_get_supplemental_data_size_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_get_supplemental_data_size_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_supplemental_data_size = NULL;

	CHECK_ENCLAVE_POINTER(p_supplemental_data_size, _len_p_supplemental_data_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_supplemental_data_size != NULL) ? _len_p_supplemental_data_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_get_supplemental_data_size_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_get_supplemental_data_size_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_get_supplemental_data_size_ocall_t);

	if (p_supplemental_data_size != NULL) {
		ms->ms_p_supplemental_data_size = (uint32_t*)__tmp;
		__tmp_p_supplemental_data_size = __tmp;
		if (_len_p_supplemental_data_size % sizeof(*p_supplemental_data_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_p_supplemental_data_size, 0, _len_p_supplemental_data_size);
		__tmp = (void *)((size_t)__tmp + _len_p_supplemental_data_size);
		ocalloc_size -= _len_p_supplemental_data_size;
	} else {
		ms->ms_p_supplemental_data_size = NULL;
	}
	
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (p_supplemental_data_size) {
			if (memcpy_s((void*)p_supplemental_data_size, _len_p_supplemental_data_size, __tmp_p_supplemental_data_size, _len_p_supplemental_data_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_verify_quote_ocall(quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, time_t expiration_check_date, sgx_ql_qv_result_t* p_quote_verification_result, sgx_ql_qe_report_info_t* p_qve_report_info, size_t qve_report_info_size, uint8_t* p_supplemental_data, uint32_t supplemental_data_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_quote = quote_size;
	size_t _len_p_quote_verification_result = sizeof(sgx_ql_qv_result_t);
	size_t _len_p_qve_report_info = qve_report_info_size;
	size_t _len_p_supplemental_data = supplemental_data_size;

	ms_sgx_tls_verify_quote_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_verify_quote_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_quote_verification_result = NULL;
	void *__tmp_p_qve_report_info = NULL;
	void *__tmp_p_supplemental_data = NULL;

	CHECK_ENCLAVE_POINTER(p_quote, _len_p_quote);
	CHECK_ENCLAVE_POINTER(p_quote_verification_result, _len_p_quote_verification_result);
	CHECK_ENCLAVE_POINTER(p_qve_report_info, _len_p_qve_report_info);
	CHECK_ENCLAVE_POINTER(p_supplemental_data, _len_p_supplemental_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_quote != NULL) ? _len_p_quote : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_quote_verification_result != NULL) ? _len_p_quote_verification_result : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_qve_report_info != NULL) ? _len_p_qve_report_info : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_supplemental_data != NULL) ? _len_p_supplemental_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_verify_quote_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_verify_quote_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_verify_quote_ocall_t);

	if (p_quote != NULL) {
		ms->ms_p_quote = (const uint8_t*)__tmp;
		if (_len_p_quote % sizeof(*p_quote) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, p_quote, _len_p_quote)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_quote);
		ocalloc_size -= _len_p_quote;
	} else {
		ms->ms_p_quote = NULL;
	}
	
	ms->ms_quote_size = quote_size;
	ms->ms_expiration_check_date = expiration_check_date;
	if (p_quote_verification_result != NULL) {
		ms->ms_p_quote_verification_result = (sgx_ql_qv_result_t*)__tmp;
		__tmp_p_quote_verification_result = __tmp;
		memset(__tmp_p_quote_verification_result, 0, _len_p_quote_verification_result);
		__tmp = (void *)((size_t)__tmp + _len_p_quote_verification_result);
		ocalloc_size -= _len_p_quote_verification_result;
	} else {
		ms->ms_p_quote_verification_result = NULL;
	}
	
	if (p_qve_report_info != NULL) {
		ms->ms_p_qve_report_info = (sgx_ql_qe_report_info_t*)__tmp;
		__tmp_p_qve_report_info = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, p_qve_report_info, _len_p_qve_report_info)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_qve_report_info);
		ocalloc_size -= _len_p_qve_report_info;
	} else {
		ms->ms_p_qve_report_info = NULL;
	}
	
	ms->ms_qve_report_info_size = qve_report_info_size;
	if (p_supplemental_data != NULL) {
		ms->ms_p_supplemental_data = (uint8_t*)__tmp;
		__tmp_p_supplemental_data = __tmp;
		if (_len_p_supplemental_data % sizeof(*p_supplemental_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_p_supplemental_data, 0, _len_p_supplemental_data);
		__tmp = (void *)((size_t)__tmp + _len_p_supplemental_data);
		ocalloc_size -= _len_p_supplemental_data;
	} else {
		ms->ms_p_supplemental_data = NULL;
	}
	
	ms->ms_supplemental_data_size = supplemental_data_size;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (p_quote_verification_result) {
			if (memcpy_s((void*)p_quote_verification_result, _len_p_quote_verification_result, __tmp_p_quote_verification_result, _len_p_quote_verification_result)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_qve_report_info) {
			if (memcpy_s((void*)p_qve_report_info, _len_p_qve_report_info, __tmp_p_qve_report_info, _len_p_qve_report_info)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_supplemental_data) {
			if (memcpy_s((void*)p_supplemental_data, _len_p_supplemental_data, __tmp_p_supplemental_data, _len_p_supplemental_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_timeout = timeout;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

