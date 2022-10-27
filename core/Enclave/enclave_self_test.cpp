#include "enclave_self_test.h"
#include <string.h>
#include <vector>
#include <map>
#include "datatypes.h"

using namespace std;

#define GET_PARAMETER(x) \
    uint8_t *x = (uint8_t *)get_parameter(#x, test_vector);

#define CHECK_EQUAL(x)                              \
    if (VECTOR_LENGTH(#x) > 0)                      \
        for (int i = 0; i < VECTOR_LENGTH(#x); i++) \
            if (x[i] != _##x[i])                    \
                return false;

// TODO : add test vector for aes_gcm 192/256
// TODO : add test vector for sm4 crypto
// TODO : add test vector for rsa crypto
// TODO : add test vector for rsa sign/verify
// TODO : add test vector for ec sign/verify
// TODO : add test vector for sm2 crypto
// TODO : add test vector for sm2 sign/verify

EHSM_TEST_VECTOR aes_gcm_encryption_test_vectors = {
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

EHSM_TEST_VECTOR aes_gcm_decryption_test_vectors = {
    {// case1
     {"key", "7ecf54b1d2d81b6ede2cd574d217d5c9"},
     {"plaintext", "c45dc86e1ffc3bc1013d4847b4dceb28"},
     {"aad", "0e65219827f0acf8b6b0e75f9397f711d0af4b21"},
     {"iv", "c335ee604c9055de42b2a672"},
     {"ciphertext", "fbf1dc7e4645a85ce2cb21b4b52697f6"},
     {"tag", "1d6c7302bfa6451fe096289629a68049"}},
    {// case2
     {"key", "4f64f175ff74efbdf887a53d8d125896"},
     {"plaintext", "9dd4c24c799e62db4481f1d2d3"},
     {"aad", "2f3da0238114f702872505d8e124190ebd0fba662ac3336bfac5611828426ed4f3fcaedf71a2707822cb197d4fbcd07f5dee436e9bc7a4e39a3975b782fe828b0df4ecb8c2971747cc666f00a277600d6b54d4194f17d2183afe"},
     {"iv", "d7e20930f58d330c305b345f"},
     {"ciphertext", "945b94e983082adf44eaa43d15"},
     {"tag", "50eaeb33e26053695397380f"}},
    {// case3
     {"key", "1481a94d1393618b51a584163107d5e6"},
     {"plaintext", "373a279d6be930def28036a3a0c3600e"},
     {"aad", "6b777358964cd16db2b3948f77879956e4c8b210"},
     {"iv", "7b"},
     {"ciphertext", "54f268ad389a587a5eea1d8ae63377d4"},
     {"tag", "56efc3150e9d6b2c7163a2f714"}},
    {// case4
     {"key", "0f4c1527ff9bd39abb2de18ef2d3a16b"},
     {"plaintext", "befff8af8ce85cda6c3eca58d0"},
     {"aad", "639e5c552d5cdabc8c4fb30f639700c9"},
     {"iv", "61d5487b89baf62d547810dd426519de60aea8723dbed676d6ae87e77aae98ae24dc142da333a8a99aeb710b30d8b410d6d3c63034667565238f311c8abccc5a32f1a7bcfaf4b7474b7ccc24b884f7a472964d0de4dc89a1d4f05ad5ca087cbc5cfaddb9a5f455aeae2fa2f90db3fbb44d6dcea4e43b89335e80e2ed4430b233"},
     {"ciphertext", "d38d5a188e9cf41410ada1ca07"},
     {"tag", "eeafd45fa3247203ac12c360"}},
    {// case5
     {"key", "b7da49aa29ee83c62015c484bb21b39b0091c0038627d556"},
     {"plaintext", ""},
     {"aad", "b463c36bb490167ed97adb195cfc0571e62c5262b4bae7217a01a76e0eb8afdc41909266261a1f6b81c58f5bbd58018d"},
     {"iv", "c501b0171dc20795edb3118a"},
     {"ciphertext", ""},
     {"tag", "60d1e373"}},
    {// case6
     {"key", "0a3362767b0a2d4274431c791a6402e372fa187e3fb9a1bf"},
     {"plaintext", "69c3844d67571ecb2147af343dfb197f"},
     {"aad", "ab65ba4fa7121b2def3bff5b7055eec67ccd46a98b64b5f410c7f969929eee532554930a8a69746d578196274747059d"},
     {"iv", "11d0d4b24dab9e2ac8498101"},
     {"ciphertext", "f3c6d2fdce453b9bca6cef821dac4aa1"},
     {"tag", "28bfbd91033d701ddf26fb380f"}},
    {// case7
     {"key", "abec38916c4317ff943f92a9463b21765e3d15549bfce719"},
     {"plaintext", "63f311396d21c65eeaeeae0233"},
     {"aad", "f055c743968923acb9d2e46b56fcbc70bd8cdc7b"},
     {"iv", "5da5498b2a7c92e7046c10b6"},
     {"ciphertext", "aebf3bdfe01f123b4cd2349dea"},
     {"tag", "9f81e1704cb3780120b755ac27a25d"}},
    {// case8
     {"key", "93c95365302adcaa3ff157c89cb5e90c1ce48c80380a4fec"},
     {"plaintext", "742bbbab27604176411603991a"},
     {"aad", "886db9b14534eb3e367c7bbc6ec12bedb5dc9004"},
     {"iv", "5f33aa557eadc254279de908"},
     {"ciphertext", "5d75e637f6f18c6394bf9d59b7"},
     {"tag", "dacee56765fea6340bb891efc49cf7"}},
    {// case9
     {"key", "afc95accdab4c77a321f5d9fd9b01fd629002f1619d6700ce589132455628ac1"},
     {"plaintext", "abada3fe5365fda82a13d29cb5"},
     {"aad", "7b902b0ef659903d0df5bd89bedbfc37"},
     {"iv", "691308f13fa8e358c97b6efd"},
     {"ciphertext", "4934204c966283844b7087362f"},
     {"tag", "b127cf8d"}},
    {// case10
     {"key", "be0b8a300ac50b9c21dbebb5d79771c1eab317c92b194d3db16504b20954d25c"},
     {"plaintext", "c895b909f2747697e298ba7886"},
     {"aad", "307b64495c29a299211a3d0759236c0e"},
     {"iv", "713026160b1b92147a322570"},
     {"ciphertext", "5a2d006c4e556327fd642b8120"},
     {"tag", "e0fdb988"}},
    {// case11
     {"key", "6b879203e1a23c90bc4b92e4ee42001f8466b0a168a3b09df9b644182d8242ab"},
     {"plaintext", "d167388250a59485b3dde40200"},
     {"aad", "b21100419dc0a8ea58ef372e5f07e841b2ee5568"},
     {"iv", "3e05199e1d56ca0b120694c8"},
     {"ciphertext", "ef4cd1b06520043c369f832448"},
     {"tag", "0ac846204a3a5299cef82d7a9b1748a8"}},
    {// case12
     {"key", "caf5452d9a3f19fe99f4e56f29bb93bbb60ed4439625a4d76079e7c0424f9843"},
     {"plaintext", "066b2d8d51ffecd9eee2d40b5e"},
     {"aad", "835ffbd8aa40ec691f4c8a5dc2dbed53ed241d1b"},
     {"iv", "b8d4baacc01c8d159db33976"},
     {"ciphertext", "bc59e06dbc2af9a2f8146e1db9"},
     {"tag", "cdc601beb551090fb12f5d4cb5682353"}}};

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

    return true;
}

static sgx_status_t aes_gcm_crypto_test()
{
    sgx_status_t ret = SGX_ERROR_INVALID_FUNCTION;
    int index = 1;
    for (auto test_vector : aes_gcm_encryption_test_vectors)
    {
        if (!aes_gcm_encrypt(test_vector))
        {
            printf("fail at %s case %d\n", __FUNCTION__, index);
        }
        index++;
    }
    for (auto test_vector : aes_gcm_decryption_test_vectors)
    {
        if (!aes_gcm_decrypt(test_vector))
        {
            printf("fail at %s case %d\n", __FUNCTION__, index);
        }
        index++;
    }

    if (index != SELF_TEST_NUM + 1)
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

    return ret;
}
