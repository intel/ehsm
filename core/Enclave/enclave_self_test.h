#include "sgx_error.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/ec.h"
#include "openssl/evp.h"

#include "datatypes.h"
#include <vector>
#include <map>

using namespace std;

#define VECTOR_LENGTH(x) (test_vector[x].length()) / 2

#define CHECK_EQUAL(x)                                     \
    for (int i = 0; i < sizeof(x) / sizeof(x[0]) - 1; i++) \
        if (x[i] != _##x[i])                               \
            return false;

sgx_status_t ehsm_self_test();