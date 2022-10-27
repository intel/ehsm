#include "sgx_error.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/ec.h"
#include "openssl/evp.h"

#include "datatypes.h"
#include "key_operation.h"

#include <vector>
#include <map>

using namespace std;

#define VECTOR_LENGTH(x) (uint32_t)(test_vector[x].length()) / 2
#define SELF_TEST_NUM 24

sgx_status_t ehsm_self_test();