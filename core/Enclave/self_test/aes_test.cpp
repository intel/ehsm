#include "enclave_self_test.h"

using namespace std;

EHSM_TEST_VECTOR aes_gcm_crypto_test_vectors = {
    {// case1
     {"key", "cdb850da94d3b56563897c5961ef3ad8"},
     {"plaintext", "c16837cb486c04bd30dcae4bcd0bc098"},
     {"aad", "de33e6d20c14796484293dff48caffc784367f4bd7b957512ec026c0abc4a39217af0db35be154c45833b97a0b6454df"},
     {"iv", "841587b7174fb38fb7b3626e"},
     {"ciphertext", "f41a9ba9ff296ebdbe3fdd8b1c27dcdb"},
     {"tag", "506cc2136c15238b0f24f61b520fb5e6"}},
    {// case2
     {"key", "3be1d5fe92f786d0eee2d830e3507c22"},
     {"plaintext", "d2e398f74ce4c02f36c65507ac"},
     {"aad", "48bd18b8aeb88d3e90786bf17ef7d7e23362d5cddb9d2d5d2aeedfd637d88973ad1bb80ee0e27b3cb460adb68b767fc354574fa17cabcff7326fc9f1693344c68ed242517687ca204b11d800c3f4e60265b82d99e43d021b5d6b"},
     {"iv", "00cabd0cc8b34bf45d3dd403"},
     {"ciphertext", "bc628d92c7961ce62a7d78c60a"},
     {"tag", "080828887ee53e27"}},
    {// case3
     {"key", "8adf79d97bf600f2661a388f5e983f34"},
     {"plaintext", "c8e23a6c8b256856439c3e9c01383812e3842f2c93bb4cea965fda454f285cfb1547b6b26114bbf9289e1c184c526faba5dcec"},
     {"aad", "77b341f83c71d048d9a422d70fb635e3d2dc14b03cc089917540cfd84cced9a0bd3a200af36a97c205380e7f0483d058"},
     {"iv", "5308ed747cd7f02283a57797"},
     {"ciphertext", "e2e99c720427c27c0e2075fc9a57453d8c5de7f9e9d66694418026da8f598c1aa8815748c547fea937194df16743aec3d940c6"},
     {"tag", "46018aac9a5ec9dc05029d0c663c"}},
    {// case4
     {"key", "37495abb9133deb3fed1c29c713364bd"},
     {"plaintext", "f49ba75fa91bc00d25928939247a24b9"},
     {"aad", "3baf6b9ea623a4d881a984c3e6dfeb9ffe6d4fe66d37ef577832b52e0892fac415a2695dd04e5dc5328f60945e8ae93c63bdf60469b634f1ca75593abc87e69c2d0670643319581bcbe7b72e75a7ec1a8eb4b8916eb0d2f1cf88"},
     {"iv", "23"},
     {"ciphertext", "f686b17fc839c247690121f507a35bf8"},
     {"tag", "30c931d79cc25b58c151858ba392"}},
    {// case5
     {"key", "5f41d52b894f659077b23f8609cbaaa94eeeb95258d3f14c"},
     {"plaintext", "86c0139ebfbc9b39ca0c66b65c826c4e"},
     {"aad", ""},
     {"iv", "f559a8c732c634229619809b"},
     {"ciphertext", "2f4f84b828008b4594aa41692c60f9ad"},
     {"tag", "4f37c23f"}},
    {// case6
     {"key", "0419d280a95ede28bbcd196461c15f4cd096ae3d1340221a"},
     {"plaintext", "a2fe17cffc1aad1510c05aa3cc0d0053"},
     {"aad", ""},
     {"iv", "a1ad9a56f8162f63d936bb2f"},
     {"ciphertext", "5282d40702e6f4fcc55c18f86c862c97"},
     {"tag", "cef414ea"}},
    {// case7
     {"key", "65cddc40db54aea9a182f2263ee37e59c85fcecc94e8c945"},
     {"plaintext", "210c971b62963be27d48633e07c92af0"},
     {"aad", "980552058a183a98feed8b36e022b3a4bcb18b1c706101c8eb87eaa01586ac4e6d70d4a8f69b6e96569ef7a6d9b1d3c0"},
     {"iv", "650d7dc44b7f90267ed3c2ab"},
     {"ciphertext", "d4a04a08b4de73f94567f1051e6ef433"},
     {"tag", "a733d2bc98d4a1bc"}},
    {// case8
     {"key", "5945afe17dd686a6eb743188eabd42086c17c2a01a09bc77"},
     {"plaintext", "c1cceb90b0d5738dde4c827080bd906b"},
     {"aad", "f7d06a6a0488c1a78cfdbe2eefd6ee334a0f720cfc8678fcdb08eaabc3c2f743b4c8bd3ea2bcb35ca5f07bddb50e8ee8"},
     {"iv", "c19870a10452660b2ca1d5d3"},
     {"ciphertext", "e3b24b178090ae25040d499d97196840"},
     {"tag", "c81e535a37aea434"}},
    {// case9
     {"key", "c2235e29f4189d5ecaf4ec8078bd8f9d2a1659d6a27de8b116c0137ef7fa07d2"},
     {"plaintext", "50d46abd8d2e16d8ba1f4564766f871b"},
     {"aad", ""},
     {"iv", "e1374f54756eb19a7bd6d4bc"},
     {"ciphertext", "34298441c5b7355115addec0640cad79"},
     {"tag", "e0c66a1482990e95"}},
    {// case10
     {"key", "0cc76e053172c41c1e16bf6f1b64f05d8b28a3fe0923214a616e7398be384140"},
     {"plaintext", "69563e3cd5c24cff9376a387bab2994a"},
     {"aad", "ad0feb101d76201182d7eb4f96034cf59b57998b"},
     {"iv", "ce9a1cfbbd75fe666478741c"},
     {"ciphertext", "f2c2ad8d0b0fc03ec87ecad12420e2f3"},
     {"tag", "fbd22101464e1b3af51232a8"}},
    {// case11
     {"key", "5c9d723f652adf2161eb423c7fc06bb6833c1082b6f474303be85f047c83364d"},
     {"plaintext", "a33d2690edc76cd5d8ad87405c1a0445"},
     {"aad", "72c964b6dcb58adee3676646803ff1d0bf4dc2a0"},
     {"iv", "b8d8e234883fcea64406a769"},
     {"ciphertext", "c80bf1927e0a0ce88ff02b73f1723164"},
     {"tag", "4ed4776c18a245a537e7f6d4"}},
    {// case12
     {"key", "30ae230207257fc66b0ac8e8dde274eee2b65a5094ed59a861f29aa48ca52301"},
     {"plaintext", "9155b54f7e22ba99ded2d01a9910af08"},
     {"aad", "a72ad911cbda40a1a16295715cf7c088375e1616"},
     {"iv", "3afbce7bb80c70b8367f981a"},
     {"ciphertext", "3bf3507dfbedeacaf1a0510632e81be0"},
     {"tag", "775d84dfd9502aa48a13c827"}}};

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
        return NULL;
    }
}

static bool aes_gcm_encryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t _ciphertext[VECTOR_LENGTH("plaintext") + VECTOR_LENGTH("aad")] = {0};
    uint8_t _tag[VECTOR_LENGTH("tag")] = {0};
    (void)aes_gcm_encrypt(&*key,
                          _ciphertext,
                          get_block_mode(VECTOR_LENGTH("key")),
                          &*plaintext,
                          VECTOR_LENGTH("plaintext"),
                          &*aad,
                          VECTOR_LENGTH("aad"),
                          &*iv,
                          VECTOR_LENGTH("iv"),
                          _tag,
                          VECTOR_LENGTH("tag"));

    return (TEST_COMPARE(ciphertext) && TEST_COMPARE(tag));
}

static bool aes_gcm_decryption(map<string, string> test_vector)
{
    GET_PARAMETER(key);
    GET_PARAMETER(plaintext);
    GET_PARAMETER(aad);
    GET_PARAMETER(iv);
    GET_PARAMETER(ciphertext);
    GET_PARAMETER(tag);

    uint8_t _plaintext[VECTOR_LENGTH("plaintext")] = {0};
    (void)aes_gcm_decrypt(&*key,
                          _plaintext,
                          get_block_mode(VECTOR_LENGTH("key")),
                          &*ciphertext,
                          VECTOR_LENGTH("ciphertext"),
                          &*aad,
                          VECTOR_LENGTH("aad"),
                          &*iv,
                          VECTOR_LENGTH("iv"),
                          &*tag,
                          VECTOR_LENGTH("tag"));

    return TEST_COMPARE(plaintext);
}

/***
 * setup1. load key, iv, aad
 * setup2. decrypt ciphertext or encrypt plaintext
 * setup3. compare mac and crypto result
 */
bool aes_gcm_crypto_test()
{
    log_i("%s start", __func__);
    int index = 1;
    for (auto &test_vector : aes_gcm_crypto_test_vectors)
    {
        if (!aes_gcm_encryption(test_vector))
        {
            log_e("self test failed");
            for (auto &item : test_vector)
                log_e("[%s]: [%s]", item.first.c_str(), item.second.c_str());
            continue;
        }

        if (!aes_gcm_decryption(test_vector))
        {
            log_e("self test failed");
            for (auto &item : test_vector)
                log_e("[%s]: [%s]", item.first.c_str(), item.second.c_str());
            continue;
        }

        index++;
    }

    if (index != aes_gcm_crypto_test_vectors.size() + 1)
    {
        return false;
    }
    log_i("%s end", __func__);
    return true;
}