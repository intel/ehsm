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

#include "enclave_hsm_t.h"

using namespace std;

#define GET_PARAMETER(x) \
    uint8_t *x = (uint8_t *)get_parameter(#x, test_vector);

#define TEST_COMPARE(x) (memcmp(x, _##x, VECTOR_LENGTH(#x)) == 0)

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

static int getCurve(int curve)
{
    switch (curve)
    {
    case 224:
        return NID_secp224r1;
    case 256:
        return NID_secp256k1;
    case 384:
        return NID_secp384r1;
    case 521:
        return NID_secp521r1;
    default:
        return 0;
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

    uint8_t _plaintext[VECTOR_LENGTH("plaintext")] = {0};

    RSA_private_decrypt(RSA_size(key), ciphertext, _plaintext, key, 4);

    return TEST_COMPARE(plaintext);
}

bool aes_gcm_crypto_test()
{
    int index = 1;
    for (auto test_vector : aes_gcm_crypto_test_vectors)
    {
        if (!aes_gcm_encrypt(test_vector))
        {
            log_d("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!aes_gcm_decrypt(test_vector))
        {
            log_d("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != aes_gcm_crypto_test_vectors.size() + 1)
    {
        return 0;
    }

    return 1;
}

bool sm4_crypto_test()
{
    int index = 1;

    for (auto test_vector : sm4_ctr_crypto_test_vectors)
    {
        if (!sm4_ctr_encryption(test_vector))
        {
            log_d("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!sm4_ctr_decryption(test_vector))
        {
            log_d("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }
    for (auto test_vector : sm4_cbc_crypto_test_vectors)
    {
        if (!sm4_cbc_encryption(test_vector))
        {
            log_d("fail encrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        if (!sm4_cbc_decryption(test_vector))
        {
            log_d("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != sm4_ctr_crypto_test_vectors.size() + sm4_cbc_crypto_test_vectors.size() + 1)
    {
        return 0;
    }

    return 1;
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
        log_d("EC_KEY_new failed.\n");
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
        log_d("create_EC_group failed.\n");
        goto out;
    }
    if (!EC_KEY_set_group(ec_key, ec_group))
    {
        log_d("EC_KEY_set_group failed.\n");
        goto out;
    }

    if (!EC_KEY_set_private_key(ec_key, BN_bin2bn(Priv, VECTOR_LENGTH("Priv"), NULL)))
    {
        log_d("EC_KEY_set_private_key failed.\n");
        goto out;
    }
    pt = EC_POINT_new(ec_group);
    if (pt == NULL)
    {
        log_d("EC_POINT_new failed.\n");
        goto out;
    }
    if (!EC_POINT_mul(ec_group, pt, BN_bin2bn(Priv, VECTOR_LENGTH("Priv"), NULL), NULL, NULL, NULL))
    {
        log_d("EC_POINT_mul failed.\n");
        goto out;
    }
    if (!EC_KEY_set_public_key(ec_key, pt))
    {
        log_d("EC_KEY_set_public_key failed.\n");
        goto out;
    }
    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL)
    {
        log_d("ECDSA_SIG_new failed.\n");
        goto out;
    }
    ecdsa_signiture_max_size = ECDSA_size(ec_key);
    if (ecdsa_signiture_max_size != 72)
    {
        log_d("ec key error\n");
        goto out;
    }
    signature = (uint8_t *)malloc(ecdsa_signiture_max_size);
    if (signature == NULL)
    {
        log_d("signature malloc failed.\n");
        goto out;
    }
    if (ECDSA_SIG_set0(ecdsa_sig, BN_bin2bn(R, VECTOR_LENGTH("R"), NULL), BN_bin2bn(S, VECTOR_LENGTH("S"), NULL)) != 1)
    {
        log_d("ECDSA_SIG_set0 failed.\n");
        goto out;
    }
    tmp_sig_ptr = signature;
    sig_len = i2d_ECDSA_SIG(ecdsa_sig, &tmp_sig_ptr);
    if (sig_len <= 0)
    {
        log_d("i2d_ECDSA_SIG failed\n");
        goto out;
    }
    if (sm2_verify(ec_key, EVP_sm3(), (const uint8_t *)test_vector["Msg"].c_str(), strlen(test_vector["Msg"].c_str()),
                   signature, sig_len, &result, (const uint8_t *)(test_vector["UserID"].c_str()), strlen(test_vector["UserID"].c_str())) != SGX_SUCCESS)
    {
        log_d("sm2_verify failed\n");
        goto out;
    }
    if (result == false)
    {
        log_d(" Signature error\n");
        goto out;
    }
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
bool sm2_sign_verify_test()
{
    int index = 1;
    for (auto test_vector : sm2_sign_verify_test_vectors)
    {
        if (!sm2_verify_test(test_vector))
        {
            log_d("fail at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }
    if (index != sm2_sign_verify_test_vectors.size() + 1)
    {
        return 0;
    }

    return 1;
}
bool rsa_crypto_test()
{
    int index = 1;

    for (auto test_vector : rsa_crypto_test_vectors)
    {
        if (!rsa_crypto(test_vector))
        {
            log_d("fail decrypt at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != rsa_crypto_test_vectors.size() + 1)
    {
        return 0;
    }

    return 1;
}

static bool rsa_sign_verify(map<string, string> test_vector)
{
    GET_PARAMETER(n);
    GET_PARAMETER(e);
    GET_PARAMETER(d);
    GET_PARAMETER(msg);
    GET_PARAMETER(S);
    bool result = false;
    int saltlen = -1;
    int digestmode = atoi((test_vector["digestmode"]).c_str());
    int paddingmode = atoi((test_vector["paddingmode"]).c_str());

    RSA *key = RSA_new();

    RSA_create_key(key, test_vector["n"].c_str(), test_vector["e"].c_str(), test_vector["d"].c_str());

    uint8_t *_S = (uint8_t *)malloc((uint32_t)RSA_size(key));

    (void)rsa_sign(key, get_digestmode(digestmode), get_paddingmode(paddingmode), msg, VECTOR_LENGTH("msg"),
                   _S, (uint32_t)RSA_size(key));

    TEST_COMPARE(S);

    (void)rsa_verify(key, get_digestmode(digestmode), get_paddingmode(paddingmode), msg, VECTOR_LENGTH("msg"),
                     S, VECTOR_LENGTH("S"), &result, saltlen);

    free(_S);
    RSA_free(key);

    if (result == false)
    {
        log_d(" Signature error\n");
        return false;
    }

    return true;
}

static bool rsa_PSS_sign_verify(map<string, string> test_vector)
{
    /* TODO : rsa PSS padding mode sign self test was not done */
    GET_PARAMETER(n);
    GET_PARAMETER(e);
    GET_PARAMETER(msg);
    GET_PARAMETER(S);
    bool result = false;
    int saltlen = 0;
    int digestmode = atoi((test_vector["digestmode"]).c_str());
    int paddingmode = atoi((test_vector["paddingmode"]).c_str());

    RSA *key = RSA_new();

    BIGNUM *modulus = BN_new();
    BIGNUM *publicExponent = BN_new();

    BN_hex2bn(&modulus, test_vector["n"].c_str());
    BN_hex2bn(&publicExponent, test_vector["e"].c_str());

    RSA_set0_key(key,
                 modulus,
                 publicExponent,
                 NULL);

    (void)rsa_verify(key, get_digestmode(digestmode), get_paddingmode(paddingmode), msg, VECTOR_LENGTH("msg"),
                     S, VECTOR_LENGTH("S"), &result, saltlen);

    RSA_free(key);

    if (result == false)
    {
        log_d(" Signature error\n");
        return false;
    }

    return true;
}

bool rsa_sign_verify_test()
{
    int index = 1;
    for (auto test_vector : rsa_sign_verify_test_vectors)
    {
        if (!rsa_sign_verify(test_vector))
        {
            log_d("fail at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }
    for (auto test_vector : rsa_PSS_sign_verify_test_vectors)
    {
        if (!rsa_PSS_sign_verify(test_vector))
        {
            log_d("fail at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != (rsa_sign_verify_test_vectors.size() + rsa_PSS_sign_verify_test_vectors.size() + 1))
    {
        return 0;
    }

    return 1;
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
    BIGNUM *Qx = BN_new();
    BIGNUM *Qy = BN_new();
    BIGNUM *R = BN_new();
    BIGNUM *S = BN_new();

    int digestmode = atoi((test_vector["digestmode"]).c_str());
    int curve = atoi((test_vector["curve"]).c_str());
    GET_PARAMETER(Msg);
    bool ret = false;
    bool result = false;

    ec_key = EC_KEY_new_by_curve_name(getCurve(curve));
    if (ec_key == NULL)
    {
        goto out;
    }
    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL)
    {
        goto out;
    }
    BN_hex2bn(&Qx, (test_vector["Qx"]).c_str());
    BN_hex2bn(&Qy, (test_vector["Qy"]).c_str());
    BN_hex2bn(&R, (test_vector["R"]).c_str());
    BN_hex2bn(&S, (test_vector["S"]).c_str());

    /* TODO : ec sign self test was not done */
    if (EC_KEY_set_public_key_affine_coordinates(ec_key, Qx, Qy) != 1)
    {
        log_d("EC_KEY_set_public_key_affine_coordinates failed.\n");
        goto out;
    }
    ecdsa_signiture_max_size = ECDSA_size(ec_key);
    {
        if (ecdsa_signiture_max_size <= 0 )
        {
            log_d("ec key error\n");
            goto out;
        }
    }
    signature = (uint8_t *)malloc(ecdsa_signiture_max_size);

    // Concatenate R and S into signature in uint8_t*
    if (ECDSA_SIG_set0(ecdsa_sig, R, S) != 1)
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

bool ecc_sign_verify_test()
{
    int index = 1;
    for (auto test_vector : ecc_sign_verify_test_vectors)
    {
        if (!ecc_sign_verify(test_vector))
        {
            log_d("fail at %s case %d\n", __FUNCTION__, index);
            continue;
        }
        index++;
    }

    if (index != ecc_sign_verify_test_vectors.size() + 1)
    {
        return 0;
    }

    return 1;
}

bool sm2_crypto_test()
{
    int index = 1;
    size_t length = 128;
    for (int i = 0; i < index; i++)
    {
        // create key
        EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
        EC_KEY *ec_key = EC_KEY_new();
        EC_KEY_set_group(ec_key, ec_group);
        EC_KEY_generate_key(ec_key);
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_EC_PUBKEY(bio, ec_key);
        PEM_write_bio_ECPrivateKey(bio, ec_key, NULL, NULL, 0, NULL, NULL);

        // encryption
        uint8_t plaintext[length];
        sgx_read_rand(plaintext, length);
        EVP_PKEY *pkey1 = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        EVP_PKEY_set_alias_type(pkey1, EVP_PKEY_SM2);
        EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey1, NULL);
        EVP_PKEY_encrypt_init(ectx);
        size_t cipher_len;
        EVP_PKEY_encrypt(ectx, NULL, &cipher_len, plaintext, length);
        uint8_t ciphertext[cipher_len] = {0};
        EVP_PKEY_encrypt(ectx, ciphertext, &cipher_len, plaintext, length);

        // decryption
        uint8_t _plaintext[length] = {0};
        EVP_PKEY *pkey2 = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        EVP_PKEY_set_alias_type(pkey2, EVP_PKEY_SM2);
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(pkey2, NULL);
        EVP_PKEY_decrypt_init(dctx);
        if (EVP_PKEY_decrypt(dctx, _plaintext, &length, ciphertext, cipher_len) <= 0)
            return 0;
        if (memcmp(plaintext, _plaintext, length) != 0)
            return 0;
    }
    return 1;
}

sgx_status_t ehsm_self_test()
{
    if (aes_gcm_crypto_test() &
        sm4_crypto_test() &
        rsa_crypto_test() &
        rsa_sign_verify_test() &
        ecc_sign_verify_test() &
        sm2_sign_verify_test() &
        sm2_crypto_test())
    {
        return SGX_SUCCESS;
    }

    return SGX_ERROR_INVALID_FUNCTION;
}
