#include <datatypes.h>
#include <memory>
#include <map>
#include <string>
#include <vector>
#include <openssl_operation.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include "enclave_hsm_t.h"
#include "key_operation.h"

using namespace std;

#define GET_PARAMETER(x) \
    auto x = get_parameter(#x, test_vector);

#define TEST_COMPARE(x) (memcmp(&*x, _##x, VECTOR_LENGTH(#x)) == 0)

#define VECTOR_LENGTH(x) (uint32_t)(test_vector[x].length()) / 2

typedef vector<map<string, string>> EHSM_TEST_VECTOR;

void Str2Hex(const char *in, uint8_t *out, int nLen);

shared_ptr<uint8_t> get_parameter(string key_name, map<string, string> test_vector);

const EVP_MD *getDigestMode(int digestMode);