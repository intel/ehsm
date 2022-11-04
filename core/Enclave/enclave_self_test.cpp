#include "enclave_self_test.h"
#include <string.h>
#include <vector>
#include <map>
#include "datatypes.h"
#include "self_test_vector.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/bn.h"

using namespace std;

#define GET_PARAMETER(x) \
    uint8_t *x = (uint8_t *)get_parameter(#x, test_vector);

#define TEST_COMPARE(x) (memcmp(x, _##x, VECTOR_LENGTH(#x)) == 0)

// TODO : add test vector for sm2 crypto
// TODO : add test vector for sm2 sign/verify

/**
 * @brief make string to hex array, string length needs to be a even number
 *
 * @param str "a0b23d" will change to "/xa0/xb2/x3d"
 * @param buf buffer for saving the result
 * @param len str length / 2
 */
static void Str2Hex(const char *pbSrc, unsigned char *pbDest, int nLen)
{
    char h1, h2;
    char s1, s2;
    int i;

    for (i = 0; i < nLen; i++)
    {
        h1 = pbSrc[2 * i];
        h2 = pbSrc[2 * i + 1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9)
            s1 -= 7;
        s2 = toupper(h2) - 0x30;
        if (s2 > 9)
            s2 -= 7;

        pbDest[i] = s1 * 16 + s2;
    }
}

static void *get_parameter(string key_name, map<string, string> test_vector)
{
    string target = test_vector[key_name];
    int len = strlen(target.c_str()) / 2;
    uint8_t *value = (uint8_t *)malloc(len);
    Str2Hex(target.c_str(), value, len);
    return value;
}

static const EVP_CIPHER *get_block_mode(uint32_t key_length)
{
    switch (key_length)
    {
    case 16:
        return EVP_aes_128_gcm();
    case 24:
        return EVP_aes_192_gcm();
    case 32:
        return EVP_aes_256_gcm();
    default:
        return EVP_aes_256_gcm(); // return 256 block mode for unexpected key length
    }
}

static const EVP_MD *get_digestmode(int digestMode)
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

static ehsm_padding_mode_t get_paddingmode(int paddingmode)
{
    switch (paddingmode)
    {
    /* 1 means paddingmode PKCS#1 Ver 1.5, 2 means paddingmode PKCS#1 RSASSA-PSS */
    case 1:
        return EH_PAD_RSA_PKCS1;
    case 2:
        return EH_PAD_RSA_PKCS1_PSS;
    case 3:
        return EH_PAD_RSA_PKCS1_OAEP;
    default:
        return EH_PADDING_NONE;
    }
}

static void RSA_create_key(RSA *key, const char *n, const char *e, const char *d)

{
    BIGNUM *modulus = BN_new();
    BIGNUM *publicExponent = BN_new();
    BIGNUM *privateExponent = BN_new();

    BN_hex2bn(&modulus, n);
    BN_hex2bn(&publicExponent, e);
    BN_hex2bn(&privateExponent, d);

    RSA_set0_key(key,
                 modulus,
                 publicExponent,
                 privateExponent);
}

static bool aes_gcm_encrypt(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t _ciphertext[VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("aad")] = {0};
    uint8_t _tag[VECTOR_LENGTH("tag")] = {0};
    (void)aes_gcm_encrypt(key, _ciphertext, get_block_mode(VECTOR_LENGTH("key")), plaintext, VECTOR_LENGTH("plaintext"),
                          aad, VECTOR_LENGTH("aad"), iv, VECTOR_LENGTH("iv"), _tag, VECTOR_LENGTH("tag"));

    return (TEST_COMPARE(ciphertext) && TEST_COMPARE(tag));
}

static bool aes_gcm_decrypt(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t _plaintext[VECTOR_LENGTH("plaintext")] = {0};
    (void)aes_gcm_decrypt(key, _plaintext, get_block_mode(VECTOR_LENGTH("key")), ciphertext, VECTOR_LENGTH("ciphertext"),
                          aad, VECTOR_LENGTH("aad"), iv, VECTOR_LENGTH("iv"), tag, VECTOR_LENGTH("tag"));

    return TEST_COMPARE(plaintext);
}

static bool sm4_ctr_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t _ciphertext[VECTOR_LENGTH("plaintext")] = {0};
    (void)sm4_ctr_encrypt(key, _ciphertext, plaintext, VECTOR_LENGTH("plaintext"), iv);

    return TEST_COMPARE(ciphertext);
}

static bool sm4_ctr_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t _plaintext[VECTOR_LENGTH("plaintext")] = {0};
    (void)sm4_ctr_decrypt(key, _plaintext, ciphertext, VECTOR_LENGTH("plaintext"), iv);

    return TEST_COMPARE(plaintext);
}

static bool sm4_cbc_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t _ciphertext[VECTOR_LENGTH("plaintext")] = {0};
    (void)sm4_cbc_encrypt(key, _ciphertext, plaintext, VECTOR_LENGTH("plaintext"), iv);

    return TEST_COMPARE(ciphertext);
}

static bool sm4_cbc_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t _plaintext[VECTOR_LENGTH("plaintext")] = {0};
    (void)sm4_cbc_decrypt(key, _plaintext, ciphertext, VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("iv"), iv);

    return TEST_COMPARE(plaintext);
}

static bool rsa_crypto(map<string, string> test_vector)
{
    GET_PARAMETER(n);
    GET_PARAMETER(e);
    GET_PARAMETER(d);
    GET_PARAMETER(p);
    GET_PARAMETER(q);
    GET_PARAMETER(dmp1);
    GET_PARAMETER(dmq1);
    GET_PARAMETER(iqmp);

    GET_PARAMETER(plaintext);
    GET_PARAMETER(ciphertext);

    RSA *key = RSA_new();

    RSA_set0_key(key,
                 BN_bin2bn(n, VECTOR_LENGTH("n"), NULL),
                 BN_bin2bn(e, VECTOR_LENGTH("e"), NULL),
                 BN_bin2bn(d, VECTOR_LENGTH("d"), NULL));
    RSA_set0_factors(key,
                     BN_bin2bn(p, VECTOR_LENGTH("p"), NULL),
                     BN_bin2bn(q, VECTOR_LENGTH("q"), NULL));
    RSA_set0_crt_params(key,
                        BN_bin2bn(dmp1, VECTOR_LENGTH("dmp1"), NULL),
                        BN_bin2bn(dmq1, VECTOR_LENGTH("dmq1"), NULL),
                        BN_bin2bn(iqmp, VECTOR_LENGTH("iqmp"), NULL));

    uint8_t _plaintext[VECTOR_LENGTH("plaintext")] ={0};

    RSA_private_decrypt(RSA_size(key), ciphertext, _plaintext, key, 1);

    return TEST_COMPARE(plaintext);
}

static sgx_status_t aes_gcm_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;
    for (auto test_vector : aes_gcm_crypto_test_vectors)
    {
        if (!aes_gcm_encrypt(test_vector))
        {
            printf("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!aes_gcm_decrypt(test_vector))
        {
            printf("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != aes_gcm_crypto_test_vectors.size() + 1)
    {
        return SGX_ERROR_INVALID_FUNCTION;
    }

    ret = SGX_SUCCESS;

    return ret;
}

static sgx_status_t sm4_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;

    for (auto test_vector : sm4_ctr_crypto_test_vectors)
    {
        if (!sm4_ctr_encryption(test_vector))
        {
            printf("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!sm4_ctr_decryption(test_vector))
        {
            printf("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }
    for (auto test_vector : sm4_cbc_crypto_test_vectors)
    {
        if (!sm4_cbc_encryption(test_vector))
        {
            printf("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!sm4_cbc_decryption(test_vector))
        {
            printf("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != sm4_ctr_crypto_test_vectors.size() + sm4_cbc_crypto_test_vectors.size() + 1)
    {
        return SGX_ERROR_INVALID_FUNCTION;
    }

    ret = SGX_SUCCESS;

    return ret;
}

static sgx_status_t rsa_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;

    for (auto test_vector : rsa_crypto_test_vectors)
    {
        if (!rsa_crypto(test_vector))
        {
            printf("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != rsa_crypto_test_vectors.size() + 1)
    {
        return SGX_ERROR_INVALID_FUNCTION;
    }

    ret = SGX_SUCCESS;

    return ret;
}

static bool rsa_sign_verify(map<string, string> test_vector)
{
    GET_PARAMETER(n);
    GET_PARAMETER(e);
    GET_PARAMETER(d);
    GET_PARAMETER(msg);
    GET_PARAMETER(S);
    bool result = false;
    int digestmode = atoi((test_vector["digestmode"]).c_str());
    int paddingmode = atoi((test_vector["paddingmode"]).c_str());

    RSA *key = RSA_new();

    RSA_create_key(key, test_vector["n"].c_str(), test_vector["e"].c_str(), test_vector["d"].c_str());

    uint8_t *_S = (uint8_t *)malloc((uint32_t)RSA_size(key));

    (void)rsa_sign(key, get_digestmode(digestmode), get_paddingmode(paddingmode), msg, VECTOR_LENGTH("msg"),
                   _S, (uint32_t)RSA_size(key));

    TEST_COMPARE(S);

    (void)rsa_verify(key, get_digestmode(digestmode), get_paddingmode(paddingmode), msg, VECTOR_LENGTH("msg"),
                     S, VECTOR_LENGTH("S"), &result);

    free(_S);
    RSA_free(key);

    if (result == false)
    {
        log_d(" Signature error\n");
        return false;
    }

    return true;
}

static sgx_status_t rsa_sign_verify_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;
    for (auto test_vector : rsa_sign_verify_test_vectors)
    {
        if (!rsa_sign_verify(test_vector))
        {
            printf("fail at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != rsa_sign_verify_test_vectors.size() + 1)
    {
        return SGX_ERROR_INVALID_FUNCTION;
    }

    ret = SGX_SUCCESS;

    return ret;
}

static bool ecc_sign_verify(map<string, string> test_vector)
{
    EC_KEY *ec_key = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    uint32_t ecdsa_signiture_max_size = 0;
    uint8_t *_signature = NULL;
    uint8_t *signature = NULL;
    uint8_t *tmp = NULL;
    uint32_t sig_len = 0;
    GET_PARAMETER(Qx);
    GET_PARAMETER(Qy);
    GET_PARAMETER(R);
    GET_PARAMETER(S);
    GET_PARAMETER(d);
    int digestmode = atoi((test_vector["digestmode"]).c_str());
    GET_PARAMETER(Msg);
    bool ret = false;
    bool result = false;

    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL)
    {
        goto out;
    }
    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL)
    {
        goto out;
    }

    if (EC_KEY_set_private_key(ec_key, BN_bin2bn(d, VECTOR_LENGTH("d"), NULL)) != 1)
    {
        log_d("EC_KEY_set_private_key failed.\n");
        goto out;
    }
    if (EC_KEY_set_public_key_affine_coordinates(ec_key, BN_bin2bn(Qx, VECTOR_LENGTH("Qx"), NULL), BN_bin2bn(Qy, VECTOR_LENGTH("Qy"), NULL)) != 1)
    {
        log_d("EC_KEY_set_public_key_affine_coordinates failed.\n");
        goto out;
    }
    ecdsa_signiture_max_size = ECDSA_size(ec_key);
    {
        if (ecdsa_signiture_max_size != 72)
        {
            log_d("ec key error\n");
            goto out;
        }
    }
    signature = (uint8_t *)malloc(ecdsa_signiture_max_size);

    // Concatenate R and S into signature in uint8_t*
    if (ECDSA_SIG_set0(ecdsa_sig, BN_bin2bn(R, VECTOR_LENGTH("R"), NULL), BN_bin2bn(S, VECTOR_LENGTH("S"), NULL)) != 1)
    {
        log_d("ECDSA_SIG_set0 failed.\n");
        goto out;
    }
    tmp = signature;
    sig_len = i2d_ECDSA_SIG(ecdsa_sig, &tmp);
    if (sig_len == 0)
    {
        log_d("i2d_ECDSA_SIG failed\n");
        goto out;
    }

    if (ecc_verify(ec_key, get_digestmode(digestmode), Msg, VECTOR_LENGTH("Msg"),
                   signature, sig_len, &result) != SGX_SUCCESS)
    {
        log_d("ecc_verify failed\n");
        goto out;
    }

    if (result == false)
    {
        log_d(" Signature error\n");
        goto out;
    }

    ret = true;
out:
    if (ec_key)
        EC_KEY_free(ec_key);
    if (ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);

    memset_s(signature, ecdsa_signiture_max_size, 0, ecdsa_signiture_max_size);
    SAFE_FREE(signature);

    return ret;
}

static sgx_status_t ecc_sign_verify_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;
    for (auto test_vector : ecc_sign_verify_test_vectors)
    {
        if (!ecc_sign_verify(test_vector))
        {
            printf("fail at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != ecc_sign_verify_test_vectors.size() + 1)
    {
        return SGX_ERROR_INVALID_FUNCTION;
    }

    ret = SGX_SUCCESS;

    return ret;
}

sgx_status_t ehsm_self_test()
{
    sgx_status_t ret;
    ret = aes_gcm_crypto_test();
    ret = sm4_crypto_test();
    ret = rsa_crypto_test();
    ret = rsa_sign_verify_test();
    ret = ecc_sign_verify_test();

    return ret;
}
