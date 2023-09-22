from enum import Enum


class KeySpec(Enum):
    EH_AES_GCM_128 = "EH_AES_GCM_128"
    EH_AES_GCM_192 = "EH_AES_GCM_192"
    EH_AES_GCM_256 = "EH_AES_GCM_256"
    EH_RSA_2048 = "EH_RSA_2048"
    EH_RSA_3072 = "EH_RSA_3072"
    EH_RSA_4096 = "EH_RSA_4096"
    EH_EC_P224 = "EH_EC_P224"
    EH_EC_P256 = "EH_EC_P256"
    EH_EC_P256K = "EH_EC_P256K"
    EH_EC_P384 = "EH_EC_P384"
    EH_EC_P521 = "EH_EC_P521"
    EH_SM2 = "EH_SM2"
    EH_SM4_CTR = "EH_SM4_CTR"
    EH_SM4_CBC = "EH_SM4_CBC"
    EH_HMAC = "EH_HMAC"


class Origin(Enum):
    EH_INTERNAL_KEY = "EH_INTERNAL_KEY"
    EH_EXTERNAL_KEY = "EH_EXTERNAL_KEY"


class KeyUsage(Enum):
    EH_KEYUSAGE_ENCRYPT_DECRYPT = "EH_KEYUSAGE_ENCRYPT_DECRYPT"
    EH_KEYUSAGE_SIGN_VERIFY = "EH_KEYUSAGE_SIGN_VERIFY"


class PaddingMode(Enum):
    # padding modes for RSA
    EH_RSA_PKCS1 = "EH_RSA_PKCS1"
    EH_RSA_PKCS1_OAEP = "EH_RSA_PKCS1_OAEP"
    # for SM2
    EH_PAD_NONE = "EH_PAD_NONE"


class DigestMode(Enum):
    EH_SHA_224 = "EH_SHA_224"
    EH_SHA_256 = "EH_SHA_256"
    EH_SHA_384 = "EH_SHA_384"
    EH_SHA_512 = "EH_SHA_512"
    EH_SM3 = "EH_SM3"


class MessageType(Enum):
    EH_RAW = "EH_RAW"
    EH_DIGEST = "EH_DIGEST"
