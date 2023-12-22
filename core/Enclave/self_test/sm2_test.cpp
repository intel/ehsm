#include "enclave_self_test.h"

using namespace std;

// In current sm2_sign(), userid will be concatenated with Msg and then make digest.
// The test vector can't pass in current method.
EHSM_TEST_VECTOR sm2_sign_verify_test_vectors = {
    {// Case 1 sm2 verify, sm3 digest. From draft-shen-sm2-ecdsa-02
     {"P", "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"},
     {"A", "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"},
     {"B", "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"},
     {"X", "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"},
     {"Y", "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"},
     {"Order", "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"},
     {"Cof", "1"},
     {"Msg", "message digest"},
     {"UserID", "ALICE123@YAHOO.COM"},
     {"Priv", "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263"},
     {"R", "40f1ec59f793d9f49e09dcef49130d4194f79fb1eed2caa55bacdb49c4e755d1"},
     {"S", "6fc6dac32c5d5cf10c77dfb20f7c2eb667a457872fb09ec56327a67ec7deebe7"}},
    {// Case 2 sm2 verify, sm3 digest. From Annex A in both GM/T0003.5-2012 and GB/T 32918.5-2016
     {"P", "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"},
     {"A", "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc"},
     {"B", "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93"},
     {"X", "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"},
     {"Y", "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"},
     {"Order", "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"},
     {"Cof", "1"},
     {"Msg", "message digest"},
     {"UserID", "1234567812345678"},
     {"Priv", "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"},
     {"R", "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"},
     {"S", "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"}}};

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

    if (!BN_hex2bn(&p, p_hex) ||
        !BN_hex2bn(&a, a_hex) ||
        !BN_hex2bn(&b, b_hex))
        goto done;

    group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    generator = EC_POINT_new(group);
    if (!BN_hex2bn(&g_x, x_hex) ||
        !BN_hex2bn(&g_y, y_hex) ||
        !EC_POINT_set_affine_coordinates(group, generator, g_x, g_y, NULL))
        goto done;

    if (!BN_hex2bn(&order, order_hex) ||
        !BN_hex2bn(&cof, cof_hex) ||
        !EC_GROUP_set_generator(group, generator, order, cof))
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

static bool sm2_verify_test(map<string, string> test_vector)
{
    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    uint8_t *signature = NULL;
    uint32_t sig_len = 0;

    EC_POINT *pt = NULL;
    EC_GROUP *ec_group = NULL;

    bool ret = false;
    bool result = false;

    GET_PARAMETER(R);
    GET_PARAMETER(S);
    GET_PARAMETER(Priv);
    ec_group = create_EC_group(test_vector["P"].c_str(),
                               test_vector["A"].c_str(),
                               test_vector["B"].c_str(),
                               test_vector["X"].c_str(),
                               test_vector["Y"].c_str(),
                               test_vector["Order"].c_str(),
                               test_vector["Cof"].c_str());

    if (ec_group == NULL)
    {
        log_e("create_EC_group failed.\n");
    }

    EC_POINT *pub = EC_POINT_new(ec_group);
    unsigned char *pbuf = NULL;
    size_t pub_out_len = EC_POINT_point2buf(ec_group, pub, POINT_CONVERSION_UNCOMPRESSED, &pbuf, NULL);

    OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME /*"group"*/,
                                    "SM2", 0);
    OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY /*"pub"*/,
                                     pbuf, pub_out_len);
    OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PRIV_KEY /*"Priv"*/,
                                     &*Priv, VECTOR_LENGTH("Priv"));
    params = OSSL_PARAM_BLD_to_param(param_bld);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_params(ctx, params);
    EVP_PKEY_generate(ctx, &pkey);
    if (pkey)
    {
        log_e("pkey");
    }

    signature = (uint8_t *)malloc(72);

    if (sm2_sign(
            pkey,
            EVP_sm3(),
            EH_RAW,
            (const uint8_t *)test_vector["Msg"].c_str(),
            strlen(test_vector["Msg"].c_str()),
            signature,
            &sig_len,
            (const uint8_t *)(test_vector["UserID"].c_str()),
            strlen(test_vector["UserID"].c_str())) != SGX_SUCCESS)
    {
        log_e("sm2_sign failed\n");
        goto out;
    }

    if (sm2_verify(pkey,
                   EVP_sm3(),
                   EH_RAW,
                   (const uint8_t *)test_vector["Msg"].c_str(),
                   strlen(test_vector["Msg"].c_str()),
                   signature,
                   sig_len,
                   &result,
                   (const uint8_t *)(test_vector["UserID"].c_str()),
                   strlen(test_vector["UserID"].c_str())) != SGX_SUCCESS)
    {
        log_e("sm2_verify failed\n");
        goto out;
    }

    if (result == false)
    {
        log_e("Signature error\n");
        goto out;
    }
    ret = true;

out:
    if (signature)
        free(signature);
    if (pt)
        EC_POINT_free(pt);
    if (ec_group)
        EC_GROUP_free(ec_group);
    return ret;
}

/***
 * setup1. load key pair
 * setup2. verify msg
 * setup3. compare result
 */
bool sm2_sign_verify_test()
{
    log_i("%s start", __func__);
    int index = 1;
    for (auto &test_vector : sm2_sign_verify_test_vectors)
    {
        if (!sm2_verify_test(test_vector))
        {
            log_e("self test failed");
            for (auto &item : test_vector)
                log_e("[%s]: [%s]", item.first.c_str(), item.second.c_str());
            continue;
        }

        index++;
    }

    if (index != sm2_sign_verify_test_vectors.size() + 1)
    {
        return false;
    }
    log_i("%s end", __func__);
    return true;
}

/***
 * setup1. generate random plaintext
 * setup2. encrypt plaintext
 * setup3. decrypt ciphertext
 * setup3. compare result
 */
bool sm2_crypto_test()
{
    log_i("%s start", __func__);
    int count = 10;

    for (int i = 0; i < count; i++)
    {
        uint16_t rand_len = 0;
        sgx_read_rand((uint8_t *)&rand_len, sizeof(rand_len));
        size_t length = rand_len % 1024 + 1;

        // create key
        EVP_PKEY *pkey = NULL;
        EVP_PKEY_CTX *pkctx = NULL;
        pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
        EVP_PKEY_keygen_init(pkctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, NID_sm2);
        EVP_PKEY_keygen(pkctx, &pkey);
        pkctx = EVP_PKEY_CTX_new(pkey, NULL);

        // encryption
        uint8_t plaintext[length] = {0};
        sgx_read_rand(plaintext, length);
        EVP_PKEY_encrypt_init(pkctx);
        size_t cipher_len;
        EVP_PKEY_encrypt(pkctx, NULL, &cipher_len, plaintext, length);
        uint8_t ciphertext[cipher_len] = {0};
        EVP_PKEY_encrypt(pkctx, ciphertext, &cipher_len, plaintext, length);

        // decryption
        uint8_t _plaintext[length] = {0};
        EVP_PKEY_decrypt_init(pkctx);
        EVP_PKEY_decrypt(pkctx, _plaintext, &length, ciphertext, cipher_len);

        if (memcmp(plaintext, _plaintext, length) != 0)
        {
            log_e("self test failed");
            log_e("[plaintext(%lu)]:", length);
            for (auto &item : plaintext)
                log_i("%02x", item);
            log_i("\n");

            return false;
        }

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pkctx);
    }

    log_i("%s end", __func__);
    return true;
}
