#include <map>
#include <string>
#include <vector>

using namespace std;

typedef vector<map<string, string>> EHSM_TEST_VECTOR;

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

EHSM_TEST_VECTOR sm4_ctr_crypto_test_vectors = {
    {// case1
     {"key", "0123456789abcdeffedcba9876543210"},
     {"plaintext", "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"},
     {"iv", "000102030405060708090a0b0c0d0e0f"},
     {"ciphertext", "ac3236cb970cc20791364c395a1342d1a3cbc1878c6f30cd074cce385cdd70c7f234bc0e24c11980fd1286310ce37b926e02fcd0faa0baf38b2933851d824514"}},
    {// case2
     {"key", "fedcba98765432100123456789abcdef"},
     {"plaintext", "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"},
     {"iv", "000102030405060708090a0b0c0d0e0f"},
     {"ciphertext", "5dcccd25b95ab07417a08512ee160e2f8f661521cbbab44cc87138445bc29e5c0ae0297205d62704173b21239b887f6c8cb5b800917a2488284bde9e16ea2906"}}};

EHSM_TEST_VECTOR sm4_cbc_crypto_test_vectors = {
    {// case1
     {"key", "0123456789abcdeffedcba9876543210"},
     {"plaintext", "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb"},
     {"iv", "000102030405060708090a0b0c0d0e0f"},
     {"ciphertext", "78ebb11cc40b0a48312aaeb2040244cb4cb7016951909226979b0d15dc6a8f6d"}},
    {// case2
     {"key", "fedcba98765432100123456789abcdef"},
     {"plaintext", "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb"},
     {"iv", "000102030405060708090a0b0c0d0e0f"},
     {"ciphertext", "0d3a6ddc2d21c698857215587b7bb59a91f2c147911a4144665e1fa1d40bae38"}}};

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