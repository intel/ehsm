#include <enclave_self_test.h>

void Str2Hex(const char *in, uint8_t *out, int nLen)
{
    char h1, h2;
    char s1, s2;
    int i;

    for (i = 0; i < nLen; i++)
    {
        h1 = in[2 * i];
        h2 = in[2 * i + 1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9)
            s1 -= 7;
        s2 = toupper(h2) - 0x30;
        if (s2 > 9)
            s2 -= 7;

        out[i] = s1 * 16 + s2;
    }
}

shared_ptr<uint8_t> get_parameter(string key_name, map<string, string> test_vector)
{
    string target = test_vector[key_name];
    int len = strlen(target.c_str()) / 2;

    shared_ptr<uint8_t> value(new uint8_t[len]);
    Str2Hex(target.c_str(), &*value, len);

    return value;
}

const EVP_MD *getDigestMode(int digestMode)
{
    switch (digestMode)
    {
    case 224:
        return EVP_sha224();
    case 256:
        return EVP_sha256();
    case 384:
        return EVP_sha384();
    case 512:
        return EVP_sha512();
    case 3:
        return EVP_sm3();
    default:
        return NULL;
    }
}

extern sgx_status_t aes_gcm_crypto_test();
extern sgx_status_t rsa_crypto_test();
extern sgx_status_t rsa_sign_verify_test();
extern sgx_status_t ecc_sign_verify_test();
extern sgx_status_t sm2_crypto_test();
extern sgx_status_t sm2_sign_verify_test();
extern sgx_status_t sm4_crypto_test();

sgx_status_t enclave_self_test()
{
    if (
        aes_gcm_crypto_test() &
        sm4_crypto_test() &
        rsa_crypto_test() &
        rsa_sign_verify_test() &
        // ecc_sign_verify_test() &
        // sm2_sign_verify_test() &
        sm2_crypto_test()
        )
    {
        return SGX_SUCCESS;
    }

    return SGX_ERROR_INVALID_FUNCTION;
}