#include "sgx_error.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/ec.h"
#include "openssl/evp.h"

#include "datatypes.h"
#include "openssl_operation.h"
#include "key_operation.h"

#include <vector>
#include <map>

using namespace std;

#define VECTOR_LENGTH(x) (uint32_t)(test_vector[x].length()) / 2

bool aes_gcm_crypto_test();
bool sm4_crypto_test();
bool rsa_crypto_test();
bool rsa_sign_verify_test();
bool ecc_sign_verify_test();
bool sm2_sign_verify_test();
bool sm2_crypto_test();