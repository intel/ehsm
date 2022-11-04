#include "enclave_self_test.h"
#include <string.h>
#include <vector>
#include <map>
#include "datatypes.h"
#include "self_test_vector.h"

using namespace std;

#define GET_PARAMETER(x) \
    uint8_t *x = (uint8_t *)get_parameter(#x, test_vector);

#define CHECK_EQUAL(x)                              \
    if (VECTOR_LENGTH(#x) > 0)                      \
        for (int i = 0; i < VECTOR_LENGTH(#x); i++) \
            if (x[i] != _##x[i])                    \
                return false;

// TODO : add test vector for sm4 crypto
// TODO : add test vector for rsa crypto
// TODO : add test vector for rsa sign/verify
// TODO : add test vector for ec sign/verify
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

static bool aes_gcm_encrypt(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("aad"));
    uint8_t *_tag = (uint8_t *)malloc(VECTOR_LENGTH("tag"));
    (void)aes_gcm_encrypt(key, _ciphertext, get_block_mode(VECTOR_LENGTH("key")), plaintext, VECTOR_LENGTH("plaintext"),
                          aad, VECTOR_LENGTH("aad"), iv, VECTOR_LENGTH("iv"), _tag, VECTOR_LENGTH("tag"));

    CHECK_EQUAL(ciphertext);
    CHECK_EQUAL(tag);

    free(_ciphertext);
    free(_tag);

    return true;
}

static bool aes_gcm_decrypt(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)aes_gcm_decrypt(key, _plaintext, get_block_mode(VECTOR_LENGTH("key")), ciphertext, VECTOR_LENGTH("ciphertext"),
                          aad, VECTOR_LENGTH("aad"), iv, VECTOR_LENGTH("iv"), tag, VECTOR_LENGTH("tag"));

    CHECK_EQUAL(plaintext);

    free(_plaintext);

    return true;
}

static bool sm4_ctr_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)sm4_ctr_encrypt(key, _ciphertext, plaintext, VECTOR_LENGTH("plaintext"), iv);

    CHECK_EQUAL(ciphertext);

    free(_ciphertext);

    return true;
}

static bool sm4_ctr_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)sm4_ctr_decrypt(key, _plaintext, ciphertext, VECTOR_LENGTH("plaintext"), iv);

    CHECK_EQUAL(plaintext);

    free(_plaintext);

    return true;
}

static bool sm4_cbc_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t *_ciphertext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)sm4_cbc_encrypt(key, _ciphertext, plaintext, VECTOR_LENGTH("plaintext"), iv);

    CHECK_EQUAL(ciphertext);

    free(_ciphertext);

    return true;
}

static bool sm4_cbc_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);

    uint8_t *_plaintext = (uint8_t *)malloc(VECTOR_LENGTH("plaintext"));
    (void)sm4_cbc_decrypt(key, _plaintext, ciphertext, VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("iv"), iv);

    CHECK_EQUAL(plaintext);

    free(_plaintext);

    return true;
}

static bool sm4_cbc_crypto(map<string, string> test_vector)
{

    return true;
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

static EC_GROUP *create_EC_group(const char *p_hex, const char *a_hex,
                                 const char *b_hex, const char *x_hex,
                                 const char *y_hex, const char *order_hex,
                                 const char *cof_hex)
{
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *g_x = NULL;
    BIGNUM *g_y = NULL;
    BIGNUM *order = NULL;
    BIGNUM *cof = NULL;
    EC_POINT *generator = NULL;
    EC_GROUP *group = NULL;
    int ok = 0;
    if (!BN_hex2bn(&p, p_hex) || !BN_hex2bn(&a, a_hex) || !BN_hex2bn(&b, b_hex))
        goto done;
    group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    generator = EC_POINT_new(group);
    if (!BN_hex2bn(&g_x, x_hex) || !BN_hex2bn(&g_y, y_hex) || !EC_POINT_set_affine_coordinates(group, generator, g_x, g_y, NULL))
        goto done;

    if (!BN_hex2bn(&order, order_hex) || !BN_hex2bn(&cof, cof_hex) || !EC_GROUP_set_generator(group, generator, order, cof))
        goto done;
    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok)
    {
        EC_GROUP_free(group);
        group = NULL;
    }
    return group;
}
static bool sm2_sign_test(map<string, string> test_vector)
{
    // TODO: Signature generation is affected by random values.
    return true;
}
static bool sm2_verify_test(map<string, string> test_vector)
{
    EC_KEY *ec_key = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    uint32_t ecdsa_signiture_max_size = 0;
    uint8_t *signature = NULL;
    uint8_t *tmp_sig_ptr = NULL;
    uint32_t sig_len = 0;
    EC_POINT *pt = NULL;
    EC_GROUP *ec_group = NULL;
    bool ret = false;
    bool result = false;
    GET_PARAMETER(R);
    GET_PARAMETER(S);
    GET_PARAMETER(Priv);

    ec_key = EC_KEY_new();
    if (ec_key == NULL)
    {
        printf("EC_KEY_new failed.\n");
        goto out;
    }
    ec_group = create_EC_group(test_vector["P"].c_str(),
                               test_vector["A"].c_str(),
                               test_vector["B"].c_str(),
                               test_vector["X"].c_str(),
                               test_vector["Y"].c_str(),
                               test_vector["Order"].c_str(),
                               test_vector["Cof"].c_str());
    if (ec_group == NULL)
    {
        printf("create_EC_group failed.\n");
        goto out;
    }
    if (!EC_KEY_set_group(ec_key, ec_group))
    {
        printf("EC_KEY_set_group failed.\n");
        goto out;
    }

    if (!EC_KEY_set_private_key(ec_key, BN_bin2bn(Priv, VECTOR_LENGTH("Priv"), NULL)))
    {
        printf("EC_KEY_set_private_key failed.\n");
        goto out;
    }
    pt = EC_POINT_new(ec_group);
    if (pt == NULL)
    {
        printf("EC_POINT_new failed.\n");
        goto out;
    }
    if (!EC_POINT_mul(ec_group, pt, BN_bin2bn(Priv, VECTOR_LENGTH("Priv"), NULL), NULL, NULL, NULL))
    {
        printf("EC_POINT_mul failed.\n");
        goto out;
    }
    if (!EC_KEY_set_public_key(ec_key, pt))
    {
        printf("EC_KEY_set_public_key failed.\n");
        goto out;
    }
    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL)
    {
        printf("ECDSA_SIG_new failed.\n");
        goto out;
    }
    ecdsa_signiture_max_size = ECDSA_size(ec_key);
    if (ecdsa_signiture_max_size != 72)
    {
        printf("ec key error\n");
        goto out;
    }
    signature = (uint8_t *)malloc(ecdsa_signiture_max_size);
    if (signature == NULL)
    {
        printf("signature malloc failed.\n");
        goto out;
    }
    if (ECDSA_SIG_set0(ecdsa_sig, BN_bin2bn(R, VECTOR_LENGTH("R"), NULL), BN_bin2bn(S, VECTOR_LENGTH("S"), NULL)) != 1)
    {
        printf("ECDSA_SIG_set0 failed.\n");
        goto out;
    }
    tmp_sig_ptr = signature;
    sig_len = i2d_ECDSA_SIG(ecdsa_sig, &tmp_sig_ptr);
    if (sig_len <= 0)
    {
        printf("i2d_ECDSA_SIG failed\n");
        goto out;
    }
    if (sm2_verify(ec_key, EVP_sm3(), (const uint8_t *)test_vector["Msg"].c_str(), strlen(test_vector["Msg"].c_str()),
                   signature, sig_len, &result, (const uint8_t *)(test_vector["UserID"].c_str()), strlen(test_vector["UserID"].c_str())) != SGX_SUCCESS)
    {
        printf("sm2_verify failed\n");
        goto out;
    }
    if (result == false)
    {
        printf(" Signature error\n");
        goto out;
    }
    printf("sm2 signature verify success.\n");
    ret = true;
out:
    if (signature)
        free(signature);
    if (ec_key)
        EC_KEY_free(ec_key);
    if (pt)
        EC_POINT_free(pt);
    if (ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);
    if (ec_group)
        EC_GROUP_free(ec_group);
    return ret;
}
static sgx_status_t sm2_sign_verify_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;
    for (auto test_vector : sm2_sign_verify_test_vectors)
    {
        if (!sm2_verify_test(test_vector))
        {
            printf("fail at %s case %d\n", __FUNCTION__, index);
        }
        index++;
    }

    if (index != sm2_sign_verify_test_vectors.size() + 1)
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
    ret = sm2_sign_verify_test();

    return ret;
}
