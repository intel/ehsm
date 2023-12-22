#include "enclave_self_test.h"
#if 0
using namespace std;

/**
 * @param Msg message that requires a signature
 * @param Qx Parameter used to generate the public key
 * @param Qy Parameter used to generate the public key
 * @param R Parameter used to concatenate signature
 * @param S Parameter used to concatenate signature
 * @param d Parameter used to generate the private key
 * @param curve EC_key's curve
 * @param digestmode Digest mode to use
 */
EHSM_TEST_VECTOR ecc_sign_verify_test_vectors = {

    {// case 1 k-256,SHA-224
     {"Msg", "66a2513d7b6045e56679b032cad45fb182289ca76a88c06d78c85f3dd3804590205b73a784249a0a0c8bf2f22145d105219b480d74607c02b8a6b6b459259e4fdfe2bdb4ab2238017535291d7ac1abda66c4f6dcea9e5d0bf05a9306f333b00e56342f755340211ac294ac21a7c2b26712b879951b2e23f6487e4d39899fe374"},
     {"Qx", "c3586fe88ffd9881d8e5690885b8b82915e6debeb685525eba7526936ea21005"},
     {"Qy", "de692fb876537285e9dc78a9bf80f4a2620d9bcc5ea4f29303d88056e7e0621e"},
     {"R", "bd3ae27569503a04c90c988979175e1714eeeeb5b2c2258507cfca704ce56697"},
     {"d", "8e8544a10b695e43af6a07148a1c307d65103b801f9842d7c32c9607d61ccf06"},
     {"S", "d4a5e666bdec26723ecbe6ef8d343b9f514300cbe255e00bfc7bf4928b6d3c5d"},
     {"curve", "256"},
     {"digestmode", "224"}},
    {// case 2 k-256,SHA-224
     {"Msg", "fd0b53d49384e2372d3b8554d895a2a4a908a475e514039f9f731579b49f6cc9d193660a069cba58b18f0a7238fe8491451bede0428911e829972a85393101a80c3aee16ae81ba1e55e819a39d7ef008b6921507170c40c51b5047f1daf72f3d982668e6359f2c44ced13900f1f1b765003a5bade1e02be26ab83c0f68ec45d1"},
     {"Qx", "bfde573e9ea0dce3dbc704c02ddfe9ce202da343c94b44664fd50d6722393925"},
     {"Qy", "cd788f8e52d76c5da2f6a628bf97ef39a87a96d057ffede1862dc52480cf01ac"},
     {"d", "9bbc1fc5fa06b03f0d1865a1813a06ae30ce515be1aed6083c2e03434697dbdf"},
     {"R", "41ad9b9b79fe9880feb2cf16514390ae1e5c8c2ca3eec682765a90f8b93ce0ca"},
     {"S", "3595fa09f358fa1aa8d52defd0de89dc5a828732c28a375dc49528defcf113a2"},
     {"curve", "256"},
     {"digestmode", "224"}},
    {// case 3 k-256,SHA-256
     {"Msg", "5c868fedb8026979ebd26f1ba07c27eedf4ff6d10443505a96ecaf21ba8c4f0937b3cd23ffdc3dd429d4cd1905fb8dbcceeff1350020e18b58d2ba70887baa3a9b783ad30d3fbf210331cdd7df8d77defa398cdacdfc2e359c7ba4cae46bb74401deb417f8b912a1aa966aeeba9c39c7dd22479ae2b30719dca2f2206c5eb4b7"},
     {"Qx", "131ca4e5811267fa90fc631d6298c2d7a4ecccc45cc60d378e0660b61f82fe8d"},
     {"Qy", "cf5acf8ed3e0bbf735308cc415604bd34ab8f7fc8b4a22741117a7fbc72a7949"},
     {"d", "42202a98374f6dca439c0af88140e41f8eced3062682ec7f9fc8ac9ea83c7cb2"},
     {"R", "d89f9586070230bb03e625cca18c89bb3117cd472ff6ee2a50809f0e89039309"},
     {"S", "45972842e92e3a41abeea1089d812eb5343ca8f075ac9c66e13f3db287048638"},
     {"curve", "256"},
     {"digestmode", "256"}},
    {// case 4 k-256,SHA-256
     {"Msg", "17cd4a74d724d55355b6fb2b0759ca095298e3fd1856b87ca1cb2df5409058022736d21be071d820b16dfc441be97fbcea5df787edc886e759475469e2128b22f26b82ca993be6695ab190e673285d561d3b6d42fcc1edd6d12db12dcda0823e9d6079e7bc5ff54cd452dad308d52a15ce9c7edd6ef3dad6a27becd8e001e80f"},
     {"Qx", "54ed69e1bbde38e60c7fb764479e0c2db60f2b853a537818c48d03c524e5245e"},
     {"Qy", "5099022ebd231b34098761351e9fabe15c84ad44710a1a66ed57174eb021cfd1"},
     {"d", "d89996aada18436e87a5feaccf3fece96977cde0b89d44aedd914ee76e94da1c"},
     {"R", "40927e35b7b847a198e130312d5d9264325895892d4a9c262c323ecf500a5759"},
     {"S", "b2a9f6e8660e5bc6eb78a81b76c1eb9c56d8d6860eaabfe9cb58a3587594cdfe"},
     {"curve", "256"},
     {"digestmode", "256"}},
    {// case 5 k-256,SHA-384
     {"Msg", "d68f654acefe2db8103663dffea796579c48cb0f7d74b281621528696a7bb40fdcc9f99ae1155f317e274ef8eab53f1c3c180db019abf38dfa037e70c1a90a154dbd887c66f20fbc8797c6811fb9a36926fc460b50777e79a4ce8265d5083375c44fb21900ba5516e5537f46766a31e19884d824c9e339947179e5c011307bad"},
     {"Qx", "58ac983601b7b87eda2afdbe72643d036e12673e0badc67ff44380a7bec59f14"},
     {"Qy", "34ebd172659000d2fffc63b7bc7eb6ac43d3f4b6995fe1151c458651e3539328"},
     {"d", "292efd39a4e53efb580ba4ba3e5bb47d6e7463cddab04335aa061d554c74bcc8"},
     {"R", "9ae57e4e4eca88939152ee38a07860ae03cff51d84708eeceabc70d615b7d31b"},
     {"S", "808cddd65562c77c81a1c8d45e229f53edf19864069f8d62c3c3fa1f8c8c3c66"},
     {"curve", "256"},
     {"digestmode", "384"}},
    {// case 6 k-256,SHA-384
     {"Msg", "46b0de23fa820910d5854c6e49bc788bedb2a79f50031ff02b89e12f356089f11864cab92094968cb7663f119ba70c4d1631cb3355958bee7c4064d75967fd22797d1f534196ef0bd99fac3c73382bf7a7c550a8f8460a93e7bf30a60d974cea49af280738f150eff1c5bf9c6805c9b057de5330c471c8f16824d491c88bcba4"},
     {"Qx", "ac9369648d379af84e90e233696c4708423af95890ce41226e49a524ddfbed83"},
     {"Qy", "1b7f0c6bc6a2c65aa3a66dba5722c26d362a2a8a445a70e4e0e9c08851e3daa5"},
     {"d", "634ccc8392372f66e9086c540f868a9ce93d5452aa1e0e1a5448ed15f4252c85"},
     {"R", "c7700bcd35c0f82ca14c1c3d5a3b3b444a187593ebafcd5ec401f8a49b024553"},
     {"S", "3dbd18cf865697dfa6733dd0676063b769a1fd94f2d2a3b92e2680d4291c6128"},
     {"curve", "256"},
     {"digestmode", "384"}},
    {// case 7 k-256,SHA-512
     {"Msg", "975ac93690f0f7b9fea8fbd2d8f13fbdfa59e196cbc27795c0a28c7d1bb0636f7f630eca630ef89e901451a17335d9ca2b10b42947e9add0aa0b3e00ab7a4eb64c3c9fdca43ae7ff515ce09e08ba7b0bfed5bde17c4e0f4c84f9037d1da1cd50c546c29aafe79651d2e6a8e956695255d463772bc50dc8c12be8c8a5a7ea5a8a"},
     {"Qx", "55dffb031040816b472348ffc77f0359c2dd5791bdb6925d0c95792b67454a75"},
     {"Qy", "ccb56932797a4c72eae2eba99010ce477c26ba0f65a9f3de484a95f7e8aa6218"},
     {"d", "fc280d9b8f1e9e51566ea4813f48535fdcc84fe988789bc991dd5aea42282f39"},
     {"R", "2a82d76047c17cdc9ca7b467304e3eea8294446d948c6d0c44bf23b9167c17d7"},
     {"S", "7aecd4ca2262f8f09b334d21b55835f882810a05ef52d4f6507c36eba72cbfb9"},
     {"curve", "256"},
     {"digestmode", "512"}},
    {// case 8 k-256,SHA-512
     {"Msg", "5b8a6a9c878e401fbb13066324d040b4cd21466d334248a9537c22cee41d9307b6000820e1ed44678c9401dbf722caaa62c453afc4e970cb772b688c436f1397c61f402ddd359e8e40551d43ae26d90a996bf7a0aae0878149f21e07f0e8f25ceb88cf5f2dbb9197c6420129e973caecdad9b7fd9974556db402310ea0871149"},
     {"Qx", "c8921271d9380dc4d580bf1a34913e965865310107c4501944ff6b8ec4848a49"},
     {"Qy", "583e75db8c93fa90044ab456f127d0043d31cfd0adcb34c52b733fbb00f6f629"},
     {"d", "5246fe281b4aceb74b66fb48dcf1489971e6b98ad242b92b5e2042829cbe359c"},
     {"R", "91c38ee963e0dd72bd688be55a17cfa66c94e66a3bf92f5dccdee2b6ba86ddfd"},
     {"S", "23b344220f12b9f80e0cc2b814e5af78ddcf7b767171f36fd2eb60a2eafabc47"},
     {"curve", "256"},
     {"digestmode", "512"}},
    {// case 9 k-384,SHA-224
     {"Msg", "39f0b25d4c15b09a0692b22fbacbb5f8aee184cb75887e2ebe0cd3be5d3815d29f9b587e10b3168c939054a89df11068e5c3fac21af742bf4c3e9512f5569674e7ad8b39042bcd73e4b7ce3e64fbea1c434ed01ad4ad8b5b569f6a0b9a1144f94097925672e59ba97bc4d33be2fa21b46c3dadbfb3a1f89afa199d4b44189938"},
     {"Qx", "00ea9d109dbaa3900461a9236453952b1f1c2a5aa12f6d500ac774acdff84ab7cb71a0f91bcd55aaa57cb8b4fbb3087d"},
     {"Qy", "0fc0e3116c9e94be583b02b21b1eb168d8facf3955279360cbcd86e04ee50751054cfaebcf542538ac113d56ccc38b3e"},
     {"d", "0af857beff08046f23b03c4299eda86490393bde88e4f74348886b200555276b93b37d4f6fdec17c0ea581a30c59c727"},
     {"R", "c36e5f0d3de71411e6e519f63e0f56cff432330a04fefef2993fdb56343e49f2f7db5fcab7728acc1e33d4692553c02e"},
     {"S", "0d4064399d58cd771ab9420d438757f5936c3808e97081e457bc862a0c905295dca60ee94f4537591c6c7d217453909b"},
     {"curve", "384"},
     {"digestmode", "224"}},
    {// case 10 k-384,SHA-224
     {"Msg", "e7d974c5dbd3bfb8a2fb92fdd782f997d04be79e9713944ce13c5eb6f75dfdec811b7ee4b3859114b07f263846ae13f795eec8f3cb5b7565baff68e0fdd5e09ba8b176d5a71cb03fbc5546e6937fba560acb4db24bd42de1851432b96e8ca4078313cb849bce29c9d805258601d67cd0259e255f3048682e8fdbdda3398c3e31"},
     {"Qx", "3db95ded500b2506b627270bac75688dd7d44f47029adeff99397ab4b6329a38dbb278a0fc58fe4914e6ae31721a6875"},
     {"Qy", "049288341553a9ac3dc2d9e18e7a92c43dd3c25ca866f0cb4c68127bef6b0e4ba85713d27d45c7d0dc57e5782a6bf733"},
     {"d", "54ba9c740535574cebc41ca5dc950629674ee94730353ac521aafd1c342d3f8ac52046ed804264e1440d7fe409c45c83"},
     {"R", "b2752aa7abc1e5a29421c9c76620bcc3049ecc97e6bc39fcca126f505a9a1bfae3bde89fb751a1aa7b66fa8db3891ef0"},
     {"S", "f1c69e6d818ca7ae3a477049b46420cebd910c0a9a477fd1a67a38d628d6edaac123aebfca67c53a5c80fe454dba7a9d"},
     {"curve", "384"},
     {"digestmode", "224"}},
    {// case 11 k-384,SHA-256
     {"Msg", "663b12ebf44b7ed3872b385477381f4b11adeb0aec9e0e2478776313d536376dc8fd5f3c715bb6ddf32c01ee1d6f8b731785732c0d8441df636d8145577e7b3138e43c32a61bc1242e0e73d62d624cdc924856076bdbbf1ec04ad4420732ef0c53d42479a08235fcfc4db4d869c4eb2828c73928cdc3e3758362d1b770809997"},
     {"Qx", "0400193b21f07cd059826e9453d3e96dd145041c97d49ff6b7047f86bb0b0439e909274cb9c282bfab88674c0765bc75"},
     {"Qy", "f70d89c52acbc70468d2c5ae75c76d7f69b76af62dcf95e99eba5dd11adf8f42ec9a425b0c5ec98e2f234a926b82a147"},
     {"d", "c602bc74a34592c311a6569661e0832c84f7207274676cc42a89f058162630184b52f0d99b855a7783c987476d7f9e6b"},
     {"R", "b11db00cdaf53286d4483f38cd02785948477ed7ebc2ad609054551da0ab0359978c61851788aa2ec3267946d440e878"},
     {"S", "16007873c5b0604ce68112a8fee973e8e2b6e3319c683a762ff5065a076512d7c98b27e74b7887671048ac027df8cbf2"},
     {"curve", "384"},
     {"digestmode", "256"}},
    {// case 12 k-384,SHA-256
     {"Msg", "45e47fccc5bd6801f237cdbeac8f66ebc75f8b71a6da556d2e002352bd85bf269b6bc7c928d7bb1b0422601e4dd80b29d5906f8fcac212fe0eaaf52eda552303259cbcbe532e60abd3d38d786a45e39a2875bce675800a3eaeb9e42983d9fd9031180abd9adccc9ba30c6c198b4202c4dd70f241e969a3c412724b9b595bc28a"},
     {"Qx", "c703835d723c85c643260379d8445b0c816fe9534351921e14a8e147fe140ec7b0c4d704f8dc66a232b2333b28f03dee"},
     {"Qy", "c5d0bb054053fd86c26f147c4966757aa04b00513a02d427b8d06c16055c607955efdc518d338abfe7927c195dc28588"},
     {"d", "d44d3108873977036c9b97e03f914cba2f5775b68c425d550995574081191da764acc50196f6d2508082a150af5cd41f"},
     {"R", "81de2810cde421997013513951a3d537c51a013110d6dbb29251410bcb5ba001a9686b8490f1e581e282fd2ed0974b22"},
     {"S", "9cab0bbaffe91c7677ec3dd1f17060211a3cc0be574cbca064aa8c4b66ba6e64f3d80e83da895042ca32d311c388d950"},
     {"curve", "384"},
     {"digestmode", "256"}},
    {// case 13 k-384,SHA-384
     {"Msg", "6af6652e92a17b7898e40b6776fabaf0d74cf88d8f0ebfa6088309cbe09fac472eeac2aa8ea96b8c12e993d14c93f8ef4e8b547afe7ae5e4f3973170b35deb3239898918c70c1056332c3f894cd643d2d9b93c2561aac069577bbab45803250a31cd62226cab94d8cba7261dce9fe88c210c212b54329d76a273522c8ba91ddf"},
     {"Qx", "44ffb2a3a95e12d87c72b5ea0a8a7cb89f56b3bd46342b2303608d7216301c21b5d2921d80b6628dc512ccb84e2fc278"},
     {"Qy", "e4c1002f1828abaec768cadcb7cf42fbf93b1709ccae6df5b134c41fae2b9a188bfbe1eccff0bd348517d7227f2071a6"},
     {"d", "b5f670e98d8befc46f6f51fb2997069550c2a52ebfb4e5e25dd905352d9ef89eed5c2ecd16521853aadb1b52b8c42ae6"},
     {"R", "b11db592e4ebc75b6472b879b1d8ce57452c615aef20f67a280f8bca9b11a30ad4ac9d69541258c7dd5d0b4ab8dd7d49"},
     {"S", "4eb51db8004e46d438359abf060a9444616cb46b4f99c9a05b53ba6df02e914c9c0b6cc3a9791d804d2e4c0984dab1cc"},
     {"curve", "384"},
     {"digestmode", "384"}},
    {// case 14 k-384,SHA-384
     {"Msg", "6b45d88037392e1371d9fd1cd174e9c1838d11c3d6133dc17e65fa0c485dcca9f52d41b60161246039e42ec784d49400bffdb51459f5de654091301a09378f93464d52118b48d44b30d781eb1dbed09da11fb4c818dbd442d161aba4b9edc79f05e4b7e401651395b53bd8b5bd3f2aaa6a00877fa9b45cadb8e648550b4c6cbe"},
     {"Qx", "c2b47944fb5de342d03285880177ca5f7d0f2fcad7678cce4229d6e1932fcac11bfc3c3e97d942a3c56bf34123013dbf"},
     {"Qy", "37257906a8223866eda0743c519616a76a758ae58aee81c5fd35fbf3a855b7754a36d4a0672df95d6c44a81cf7620c2d"},
     {"d", "201b432d8df14324182d6261db3e4b3f46a8284482d52e370da41e6cbdf45ec2952f5db7ccbce3bc29449f4fb080ac97"},
     {"R", "50835a9251bad008106177ef004b091a1e4235cd0da84fff54542b0ed755c1d6f251609d14ecf18f9e1ddfe69b946e32"},
     {"S", "0475f3d30c6463b646e8d3bf2455830314611cbde404be518b14464fdb195fdcc92eb222e61f426a4a592c00a6a89721"},
     {"curve", "384"},
     {"digestmode", "384"}},
    {// case 15 k-384,SHA-512
     {"Msg", "45db86829c363c80160659e3c5c7d7971abb1f6f0d495709bba908d7aa99c9df64b3408a51bd69aba8870e2aaff488ef138f3123cf94391d081f357e21906a4e2f311defe527c55e0231579957c51def507f835cceb466eb2593a509dcbee2f09e0dde6693b2bfe17697c9e86dd672f5797339cbe9ea8a7c6309b061eca7aef5"},
     {"Qx", "832cbb7061a719a316e73dbad348fa67cd17c33f40b9000a3d3b691a2a2cd821052566717c3ead01089b56086af1366f"},
     {"Qy", "1e15a048d1dce642d9ebcbfac7f92b1bcee90fd0240cc79abd29e32e0e655c4ee1fd34fb88178bba92aca100e7794ed0"},
     {"d", "0a3f45a28a355381a919372f60320d6610cfb69c3e318eb1607db3cadfc42b728b77a6a9e9e333de9183c58933daf60f"},
     {"R", "0db0cc9a2bda8dd7e565ad36f91b1c5756d78164dc8a72a5bee4b6bc45ea38c7a16b01d05b1893d4e06b62db24c30385"},
     {"S", "abd383edaeda7d0b8de1b54fcd3c28874fed62ab266f1f84c8ba796a7b54e5e0695fdb43ce7fe90ed00fa468d87bca64"},
     {"curve", "384"},
     {"digestmode", "512"}},
    {// case 16 k-384,SHA-512
     {"Msg", "4672fce0721d37c5be166bffa4b30d753bcf104b9b414db994b3ed33f36af4935ea59a0bb92db66448b3f57dad4fc67cef10ce141bf82c536be604b89a0bc0e8bca605b867880049d97142d30538fc543bd9d4fab7fdbe2f703815cdb6361beb66acff764bc275f910d1662445b07b92830db69a5994857f53657ed5ca282648"},
     {"Qx", "a2b24a5ad4a2e91f12199ed7699e3f297e27bf8b8ea8fbe7ed28366f3544cd8e680c238450f8a6422b40829d6647b25c"},
     {"Qy", "2732be0075536e6519f6a099b975a40f8e0de337fa4d48bd0762b43f41cab8deafdef9cfbb9973e457801e3bf9c93304"},
     {"d", "2e408c57921939f0e0fe2e80ce74a4fa4a1b4fa7ab070206298fe894d655be50e2583af9e45544b5d69c73dce8a2c8e7"},
     {"R", "be428a8de89a364a134719141ee8d776a3a8338f1132b07e01b28573d8eaf3b9008b63304c48821e53638b6141f9660b"},
     {"S", "866181dbef5c147d391bed6adcee408c339982c307adc718c2b9ab9e5642d8dedc36dd6402559a3ab614c99c1e56b529"},
     {"curve", "384"},
     {"digestmode", "512"}},
    {// case 17 k-521,SHA-224
     {"Msg", "58ec2b2ceb80207ff51b17688bd5850f9388ce0b4a4f7316f5af6f52cfc4dde4192b6dbd97b56f93d1e4073517ac6c6140429b5484e266d07127e28b8e613ddf65888cbd5242b2f0eee4d5754eb11f25dfa5c3f87c790de371856c882731a157083a00d8eae29a57884dbbfcd98922c12cf5d73066daabe3bf3f42cfbdb9d853"},
     {"Qx", "1a7596d38aac7868327ddc1ef5e8178cf052b7ebc512828e8a45955d85bef49494d15278198bbcc5454358c12a2af9a3874e7002e1a2f02fcb36ff3e3b4bc0c69e7"},
     {"Qy", "184902e515982bb225b8c84f245e61b327c08e94d41c07d0b4101a963e02fe52f6a9f33e8b1de2394e0cb74c40790b4e489b5500e6804cabed0fe8c192443d4027b"},
     {"d", "1d7bb864c5b5ecae019296cf9b5c63a166f5f1113942819b1933d889a96d12245777a99428f93de4fc9a18d709bf91889d7f8dddd522b4c364aeae13c983e9fae46"},
     {"R", "06b973a638bde22d8c1c0d804d94e40538526093705f92c0c4dac2c72e7db013a9c89ffc5b12a396886305ddf0cbaa7f10cdd4cd8866334c8abfc800e5cca365391"},
     {"S", "0b0a01eca07a3964dd27d9ba6f3750615ea36434979dc73e153cd8ed1dbcde2885ead5757ebcabba117a64fcff9b5085d848f107f0c9ecc83dfa2fa09ada3503028"},
     {"curve", "521"},
     {"digestmode", "224"}},
    {// case 18 k-521,SHA-224
     {"Msg", "7ba05797b5b67e1adfafb7fae20c0c0abe1543c94cee92d5021e1abc57720a6107999c70eacf3d4a79702cd4e6885fa1b7155398ac729d1ed6b45e51fe114c46caf444b20b406ad9cde6b9b2687aa645b46b51ab790b67047219e7290df1a797f35949aaf912a0a8556bb21018e7f70427c0fc018e461755378b981d0d9df3a9"},
     {"Qx", "18d40cc4573892b3e467d314c39c95615ee0510e3e4dbc9fa28f6cd1f73e7acde15ad7c8c5339df9a7774f8155130e7d1f8de9139ddd6dfe1841c1e64c38ea98243"},
     {"Qy", "17021782d33dc513716c83afe7ba5e7abef9cb25b31f483661115b8d6b5ae469aaf6f3d54baa3b658a9af9b6249fd4d5ea7a07cb8b600f1df72b81dac614cfc384a"},
     {"d", "135ea346852f837d10c1b2dfb8012ae8215801a7e85d4446dadd993c68d1e9206e1d8651b7ed763b95f707a52410eeef4f21ae9429828289eaea1fd9caadf826ace"},
     {"R", "183da7b8a9f9d5f08903359c1a2435b085fcf26a2ed09ab71357bb7634054acc569535e6fe81d28233e4703005fc4bf83ce794d9463d575795aa0f03398e854cefd"},
     {"S", "0b3621145b9866ab7809139795cc30cd0404127a7f0fafa793660491009f6c53724fdb0b1ffbf0fd51c131180b8a957fe66e76d2970247c024261c768dee9abbfb9"},
     {"curve", "521"},
     {"digestmode", "224"}},
    {// case 19 k-521,SHA-256
     {"Msg", "8ab8176b16278db54f84328ae0b75ef8f0cd18afdf40c04ad0927ed0f6d9e47470396c8e87cde7a9be2ffbfe6c9658c88b7de4d582111119c433b2e4a504493f0a1166e3a3ea0d7b93358f4a297d63f65a5e752f94e2ee7f49ebcc742fa3eb03a617d00c574245b77a20033854d82964b2949e2247637239ab00baf4d170d97c"},
     {"Qx", "07d042ca19408524e68b981f1419351e3b84736c77fe58fee7d11317df2e850d960c7dd10d10ba714c8a609d163502b79d682e8bbecd4f52591d2748533e45a867a"},
     {"Qy", "197ac6416111ccf987d290459ebc8ad9ec56e49059c992155539a36a626631f4a2d89164b985154f2dddc0281ee5b5178271f3a76a0914c3fcd1f97be8e8376efb3"},
     {"d", "1e8c05996b85e6f3f875712a09c1b40672b5e7a78d5852de01585c5fb990bf3812c3245534a714389ae9014d677a449efd658254e610da8e6cad33414b9d33e0d7a"},
     {"R", "09dd1f2a716843eedec7a6645ac834d4336e7b18e35701f06cae9d6b290d41491424735f3b57e829ad5de055eaeef1778f051c1ee152bf2131a081e53df2a567a8a"},
     {"S", "02148e8428d70a72bc9fa986c38c2c97deda0420f222f9dc99d32c0acba699dc7ba0a2b79ce5999ff61bd0b233c744a893bc105bca5c235423e531612da65d72e62"},
     {"curve", "521"},
     {"digestmode", "256"}},
    {// case 20 k-521,SHA-256
     {"Msg", "1c1b641d0511a0625a4b33e7639d7a057e27f3a7f818e67f593286c8a4c827bb1f3e4f399027e57f18a45403a310c785b50e5a03517c72b45ef8c242a57b162debf2e80c1cf6c7b90237aede5f4ab1fcaf8187be3beb524c223cc0ceff24429eb181a5eea364a748c713214880d976c2cd497fd65ab3854ad0d6c2c1913d3a06"},
     {"Qx", "0fb3868238ca840dbb36ecc6cf04f5f773ea0ab8e8b0fdcf779dc4039a8d7146a417504e953c0cb5e7f4e599cc2c168deda8b7f16084b5582f89f2ece4cae5167f7"},
     {"Qy", "1f90b5c15eeda48e747cf3ee8183166a49dbfac6161cbd09d29d40a6854f4c495e88a435892a920cdaad20d41985890b648badd4f0a858ffcbd9afdfc23134ede18"},
     {"d", "02c4e660609e99becd61c14d043e8b419a663010cc1d8f9469897d7d0a4f076a619a7214a2a9d07957b028f7d8539ba7430d0b9a7de08beeeae8452d7bb0eac669d"},
     {"R", "07aa70425697736b298233249f5d0cf25c99e640c9ff88035ef1804820e1bfe7d043755f02d7a079494f7fa6dc26740c4e6b7b430c63f29c67bbd3a5c88d2f0e8d1"},
     {"S", "0e0d42e4ff11cf5be37a9fda348514d5097a662f214687cbfb28ff42d635b13029871ca4f464bb1fbce02d5da4d5fb61b2a071844259fc863d136197bec3a61e7c7"},
     {"curve", "521"},
     {"digestmode", "256"}},
    {// case 21 k-521,SHA-384
     {"Msg", "dbc094402c5b559d53168c6f0c550d827499c6fb2186ae2db15b89b4e6f46220386d6f01bebde91b6ceb3ec7b4696e2cbfd14894dd0b7d656d23396ce920044f9ca514bf115cf98ecaa55b950a9e49365c2f3a05be5020e93db92c37437513044973e792af814d0ffad2c8ecc89ae4b35ccb19318f0b988a7d33ec5a4fe85dfe"},
     {"Qx", "13b4ab7bc1ddf7fd74ca6f75ac560c94169f435361e74eba1f8e759ac70ab3af138d8807aca3d8e73b5c2eb787f6dcca2718122bd94f08943a686b115d869d3f406"},
     {"Qy", "0f293c1d627b44e7954d0546270665888144a94d437679d074787959d0d944d8223b9d4b5d068b4fbbd1176a004b476810475cd2a200b83eccd226d08b444a71e71"},
     {"d", "095976d387d814e68aeb09abecdbf4228db7232cd3229569ade537f33e07ed0da0abdee84ab057c9a00049f45250e2719d1ecaccf91c0e6fcdd4016b75bdd98a950"},
     {"R", "02128f77df66d16a604ffcd1a515e039d49bf6b91a215b814b2a1c88d32039521fbd142f717817b838450229025670d99c1fd5ab18bd965f093cae7accff0675aae"},
     {"S", "008dc65a243700a84619dce14e44ea8557e36631db1a55de15865497dbfd66e76a7471f78e510c04e613ced332aa563432a1017da8b81c146059ccc7930153103a6"},
     {"curve", "521"},
     {"digestmode", "384"}},
    {// case 22 k-521,SHA-384
     {"Msg", "16001f4dcf9e76aa134b12b867f252735144e523e40fba9b4811b07448a24ef4ccf3e81fe9d7f8097ae1d216a51b6eefc83880885e5b14a5eeee025c4232319c4b8bce26807d1b386ad6a964deb3bdca30ee196cfdd717facfad5c77d9b1d05fdd96875e9675e85029ecbf4f94c524624746b7c42870c14a9a1454acf3354474"},
     {"Qx", "05055b9ad726ba8a48219b0ecbfffb89f8428de895b231f676705b7de9f2022d9ff4e0114ebb52dea342f9bf76b2fb060c020e29d92074ebb1fbfe5290a58c8bc10"},
     {"Qy", "0415af7f20a6e945315adbf757316bb486c80780a0a3a15b4b9609f126d7341053a2b726ab63cb46feee527b0bf532b32b477e5671aea23d9b3c3e604b9029954b5"},
     {"d", "1a300b8bf028449344d0e736145d9dd7c4075a783cb749e1ec7988d60440a07021a25a3de74ea5e3d7bd4ab774d8ad6163adae31877ef0b2bd50e26e9e4be8a7b66"},
     {"R", "104a78ce94f878822daaf00ee527fbdbf6cceb3cbb23a2caa485e4109466de8910252f92379ab292cac8d1eda164f880c0067696e733fc8588a27703a3e1f5b8f1f"},
     {"S", "1ffe23e8ab5a31668a81161a234ea14879771fe9866f8872eb6edb672e0fe91d2bb75c9767a2dfbac7c15c802211236b22ea41ecd055a0b8b311ffc4255f86d5c67"},
     {"curve", "521"},
     {"digestmode", "384"}},
    {// case 23 k-521,SHA-512
     {"Msg", "6e0f96d56505ffd2d005d5677dbf926345f0ff0a5da456bbcbcfdc2d33c8d878b0bc8511401c73168d161c23a88b04d7a9629a7a6fbcff241071b0d212248fcc2c94fa5c086909adb8f4b9772b4293b4acf5215ea2fc72f8cec57b5a13792d7859b6d40348fc3ba3f5e7062a19075a9edb713ddcd391aefc90f46bbd81e2557b"},
     {"Qx", "0c2d540a7557f4530de35bbd94da8a6defbff783f54a65292f8f76341c996cea38795805a1b97174a9147a8644282e0d7040a6f83423ef2a0453248156393a1782e"},
     {"Qy", "119f746c5df8cec24e4849ac1870d0d8594c799d2ceb6c3bdf891dfbd2242e7ea24d6aec3166214734acc4cbf4da8f71e2429c5c187b2b3a048527c861f58a9b97f"},
     {"d", "14787f95fb1057a2f3867b8407e54abb91740c097dac5024be92d5d65666bb16e4879f3d3904d6eab269cf5e7b632ab3c5f342108d1d4230c30165fba3a1bf1c66f"},
     {"R", "10ed3ab6d07a15dc3376494501c27ce5f78c8a2b30cc809d3f9c3bf1aef437e590ef66abae4e49065ead1af5f752ec145acfa98329f17bca9991a199579c41f9229"},
     {"S", "08c3457fe1f93d635bb52df9218bf3b49a7a345b8a8a988ac0a254340546752cddf02e6ce47eee58ea398fdc9130e55a4c09f5ae548c715f5bcd539f07a34034d78"},
     {"curve", "521"},
     {"digestmode", "512"}},
    {// case 24 k-521,SHA-512
     {"Msg", "9ecd500c60e701404922e58ab20cc002651fdee7cbc9336adda33e4c1088fab1964ecb7904dc6856865d6c8e15041ccf2d5ac302e99d346ff2f686531d25521678d4fd3f76bbf2c893d246cb4d7693792fe18172108146853103a51f824acc621cb7311d2463c3361ea707254f2b052bc22cb8012873dcbb95bf1a5cc53ab89f"},
     {"Qx", "061387fd6b95914e885f912edfbb5fb274655027f216c4091ca83e19336740fd81aedfe047f51b42bdf68161121013e0d55b117a14e4303f926c8debb77a7fdaad1"},
     {"Qy", "0e7d0c75c38626e895ca21526b9f9fdf84dcecb93f2b233390550d2b1463b7ee3f58df7346435ff0434199583c97c665a97f12f706f2357da4b40288def888e59e6"},
     {"d", "0f749d32704bc533ca82cef0acf103d8f4fba67f08d2678e515ed7db886267ffaf02fab0080dca2359b72f574ccc29a0f218c8655c0cccf9fee6c5e567aa14cb926"},
     {"R", "04de826ea704ad10bc0f7538af8a3843f284f55c8b946af9235af5af74f2b76e099e4bc72fd79d28a380f8d4b4c919ac290d248c37983ba05aea42e2dd79fdd33e8"},
     {"S", "087488c859a96fea266ea13bf6d114c429b163be97a57559086edb64aed4a18594b46fb9efc7fd25d8b2de8f09ca0587f54bd287299f47b2ff124aac566e8ee3b43"},
     {"curve", "521"},
     {"digestmode", "512"}},
    {// case 25 k-224,SHA-224
     {"Msg", "699325d6fc8fbbb4981a6ded3c3a54ad2e4e3db8a5669201912064c64e700c139248cdc19495df081c3fc60245b9f25fc9e301b845b3d703a694986e4641ae3c7e5a19e6d6edbf1d61e535f49a8fad5f4ac26397cfec682f161a5fcd32c5e780668b0181a91955157635536a22367308036e2070f544ad4fff3d5122c76fad5d"},
     {"Qx", "605495756e6e88f1d07ae5f98787af9b4da8a641d1a9492a12174eab"},
     {"Qy", "f5cc733b17decc806ef1df861a42505d0af9ef7c3df3959b8dfc6669"},
     {"R", "2fc2cff8cdd4866b1d74e45b07d333af46b7af0888049d0fdbc7b0d6"},
     {"d", "16797b5c0c7ed5461e2ff1b88e6eafa03c0f46bf072000dfc830d615"},
     {"S", "8d9cc4c8ea93e0fd9d6431b9a1fd99b88f281793396321b11dac41eb"},
     {"curve", "224"},
     {"digestmode", "224"}},
    {// case 26 k-224,SHA-224
     {"Msg", "7de42b44db0aa8bfdcdac9add227e8f0cc7ad1d94693beb5e1d325e5f3f85b3bd033fc25e9469a89733a65d1fa641f7e67d668e7c71d736233c4cba20eb83c368c506affe77946b5e2ec693798aecd7ff943cd8fab90affddf5ad5b8d1af332e6c5fe4a2df16837700b2781e08821d4fbdd8373517f5b19f9e63b89cfeeeef6f"},
     {"Qx", "fa21f85b99d3dc18c6d53351fbcb1e2d029c00fa7d1663a3dd94695e"},
     {"Qy", "e9e79578f8988b168edff1a8b34a5ed9598cc20acd1f0aed36715d88"},
     {"d", "cf020a1ff36c28511191482ed1e5259c60d383606c581948c3fbe2c5"},
     {"R", "45145f06b566ec9fd0fee1b6c6551a4535c7a3bbfc0fede45f4f5038"},
     {"S", "7302dff12545b069cf27df49b26e4781270585463656f2834917c3ca"},
     {"curve", "224"},
     {"digestmode", "224"}},
    {// case 27 k-224,SHA-256
     {"Msg", "74715fe10748a5b98b138f390f7ca9629c584c5d6ad268fc455c8de2e800b73fa1ea9aaee85de58baa2ce9ce68d822fc31842c6b153baef3a12bf6b4541f74af65430ae931a64c8b4950ad1c76b31aea8c229b3623390e233c112586aa5907bbe419841f54f0a7d6d19c003b91dc84bbb59b14ec477a1e9d194c137e21c75bbb"},
     {"Qx", "40a4ab1e6a9f84b4dedb81795e6a7124d1cfdfd7ec64c5d4b9e32666"},
     {"Qy", "83aa32a3c2fc068e62626f2dafce5d7f050e826e5c145cd2d13d1b27"},
     {"d", "f60b3a4d4e31c7005a3d2d0f91cb096d016a8ddb5ab10ecb2a549170"},
     {"R", "bf6c6daa89b21211ea2c9f45192d91603378d46b1a5057962dafaf12"},
     {"S", "cb6b237950e0f0369323055cd1f643528c7a64616f75b11c4ddd63c7"},
     {"curve", "224"},
     {"digestmode", "256"}},
    {// case 28 k-224,SHA-256
     {"Msg", "ef9dbd90ded96ad627a0a987ab90537a3e7acc1fdfa991088e9d999fd726e3ce1e1bd89a7df08d8c2bf51085254c89dc67bc21e8a1a93f33a38c18c0ce3880e958ac3e3dbe8aec49f981821c4ac6812dd29fab3a9ebe7fbd799fb50f12021b48d1d9abca8842547b3b99befa612cc8b4ca5f9412e0352e72ab1344a0ac2913db"},
     {"Qx", "8d642868e4d0f55ee62a2052e6b806b566d2ac79dbde7939fe725773"},
     {"Qy", "79505a57cd56904d2523b3e1281e9021167657d38aeb7d42fc8ec849"},
     {"d", "04ef5d2a45341e2ace9af8a6ebd25f6cde45453f55b7a724eb6c21f6"},
     {"R", "2fd7fcbb7832c97ce325301dd338b279a9e28b8933284d49c6eabcf6"},
     {"S", "550b2f1efc312805a6ed8f252e692d8ee19eaa5bcd5d0cda63a1a3f0"},
     {"curve", "224"},
     {"digestmode", "256"}},
    {// case 29 k-224,SHA-384
     {"Msg", "9164d633a553deccf3cbd2effccf1387fa3177cd28c95d94a7d1a3e159c5e5c027758cc26493301b2f4d141d8d07a5fe5fead987ce5f30abeafcb48c302afc6c2309f0e93d9b6818cbb6972d222cb7b01302dfe202ae83b89f53150ae4a0e2b8fc0fd1091f19b4ab2e6ab213ab322d04f2c5f57113bfad3c5675227237abf773"},
     {"Qx", "f5d5346f17898ea6bbdfff19c216a8757a5dc37b95315f5481628381"},
     {"Qy", "ae61fd172ac8b7a4f13870a932dece465834cbd4f50bbcfb802c824e"},
     {"d", "e2f86bf73ba9336fa023343060f038e9ad41e5fe868e9f80574619a3"},
     {"R", "535147c265af138eec50c7fb570bcc8d2e6f675597b0fcc034e536bc"},
     {"S", "743812c188a1dddf9fb34b90738f8b2e58760d6cd20ccceb1bb9c516"},
     {"curve", "224"},
     {"digestmode", "384"}},
    {// case 30 k-224,SHA-384
     {"Msg", "5d09d2b1d3fa6e12c10d8b26dc9aabc8dc02bd06e63ff33f8bb91ede4b8694592a69e4ed4cdf6820069e2b9c7803658949e877ffe23bf90bcf5ce1409c06c71d86885a94048b05ac0ec9db193e489a5a2bfa367caf6aa8ecdb032be366174343f6875d2fe1785e8d77334f5f469cec64998e08d3303e5c9a1923b34fdc105d65"},
     {"Qx", "61521a0cfb72be77ba33cb3b8e022743cd9130ff49e97093b71aa178"},
     {"Qy", "ce0819aedaf6fce639d0e593f8ab0147eeb6058f5f2b448231584ea9"},
     {"d", "efcfa50fad6fb2065f9a55f28c0c42fa24c809ccb19b6fc6d8ffb085"},
     {"R", "b37caaa71103752ac559f9eb4943324409ebfa8b585f684dcaa5c411"},
     {"S", "7c28e7619e2944ab4b7be022878c8052ebdf2cae5dff4f976c49686a"},
     {"curve", "224"},
     {"digestmode", "384"}},
    {// case 31 k-224,SHA-512
     {"Msg", "7522492bdb916a597b8121f3e5c273b1d2800ef8c1db4f7dcbae633b60d7da5193ba53a63d7a377b351897c3b24903ae1cd1994211b259be3e6ae2cbc8970e4957fdf782c7d1bc7a91c80c8ef65468d4ef35428f26e2940ae8b0bd9b8074236bf6c00d0ebe83f9ddb2ade0f835138d39f33b59f244e0037c171f1ba7045a96f5"},
     {"Qx", "ac635fe00e8b7a3c8ef5655bdfb7f83e8532e59c0cc0b6534d810ffa"},
     {"Qy", "1d067aebeba66e79b28ecfe59ac6fdf5e1970dc3a84499c9d90cd8e2"},
     {"d", "ba5374541c13597bded6880849184a593d69d3d4f0b1cb4d0919cbd6"},
     {"R", "f83d54945997584c923c09662c34cf9ad1e987da8bfd9be600e7a098"},
     {"S", "4ff2dba9dba992c98a095b1144a539310e1a570e20c88b7d0aa1955c"},
     {"curve", "224"},
     {"digestmode", "512"}},
    {// case 32 k-224,SHA-512
     {"Msg", "dd09ae6c982bb1440ca175a87766fefeacc49393ff797c446200662744f37a6e30c5d33ba70cbd8f12277fd6cc0704c17478bbab2a3047469e9618e3c340a9c8caaff5ce7c8a4d90ecae6a9b84b813419dec14460298e7521c9b7fdb7a2089328005bd51d57f92a1bcbeecd34aa40482b549e006bbf6c4ce66d34a22dda4e0e0"},
     {"Qx", "d656b73b131aa4c6336a57849ce0d3682b6ab2113d013711e8c29762"},
     {"Qy", "6328335ffc2029afbfe2a15cc5636978778c3f9dab84840b05f2e705"},
     {"d", "0905b40e6c29bfcbf55e04266f68f10ca8d3905001d68bb61a27749b"},
     {"R", "583af080e0ec7c1ba5a491a84889b7b7b11ccfe18927c7c219b11757"},
     {"S", "b23700035349df25d839f0973bef78a7515287de6c83707907074fa6"},
     {"curve", "224"},
     {"digestmode", "512"}},
};

static int get_curve(int curve)
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
        return NID_undef;
    }
}

static bool ecc_sign_verify(map<string, string> test_vector)
{
    /* TODO : ec sign self test was not done */
    EC_KEY *ec_key = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;

    uint32_t ecdsa_signature_max_size = 0;
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

    // Get the curve in the test vector and set it in ec_key
    ec_key = EC_KEY_new_by_curve_name(get_curve(curve));
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

    // Set the public key of ec_key through Qx and Qy
    if (EC_KEY_set_public_key_affine_coordinates(ec_key, Qx, Qy) != 1)
    {
        log_e("EC_KEY_set_public_key_affine_coordinates failed.\n");
        goto out;
    }
    ecdsa_signature_max_size = ECDSA_size(ec_key);
    {
        if (ecdsa_signature_max_size <= 0)
        {
            log_e("ec key error\n");
            goto out;
        }
    }
    signature = (uint8_t *)malloc(ecdsa_signature_max_size);

    // Concatenate R and S into signature in uint8_t*
    if (ECDSA_SIG_set0(ecdsa_sig, R, S) != 1)
    {
        log_e("ECDSA_SIG_set0 failed.\n");
        goto out;
    }

    tmp = signature;
    sig_len = i2d_ECDSA_SIG(ecdsa_sig, &tmp);
    if (sig_len == 0)
    {
        log_e("i2d_ECDSA_SIG failed\n");
        goto out;
    }

    // Verify the generated signature
    if (ecc_verify(ec_key,
                   getDigestMode(digestmode),
                   EH_RAW,
                   &*Msg,
                   VECTOR_LENGTH("Msg"),
                   signature,
                   sig_len,
                   &result) != SGX_SUCCESS)
    {
        log_e("ecc_verify failed\n");
        goto out;
    }

    if (result == false)
    {
        log_e("Signature error\n");
        goto out;
    }

    ret = true;
out:
    if (ec_key)
        EC_KEY_free(ec_key);
    if (ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);
    if (Qx)
        BN_free(Qx);
    if (Qy)
        BN_free(Qy);

    memset_s(signature, ecdsa_signature_max_size, 0, ecdsa_signature_max_size);
    SAFE_FREE(signature);

    return ret;
}

/***
 * setup1. load curve
 * setup2. load key pair
 * setup3. verify msg
 * setup4. compare result
 */
bool ecc_sign_verify_test()
{
    log_i("%s start", __func__);
    int index = 1;
    for (auto &test_vector : ecc_sign_verify_test_vectors)
    {
        if (!ecc_sign_verify(test_vector))
        {
            log_e("self test failed");
            for (auto &item : test_vector)
                log_e("[%s]: [%s]", item.first.c_str(), item.second.c_str());
            continue;
        }

        index++;
    }

    if (index != ecc_sign_verify_test_vectors.size() + 1)
    {
        return false;
    }
    log_i("%s end", __func__);
    return true;
}
#endif