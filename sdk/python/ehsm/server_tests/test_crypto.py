import pytest

from ehsm.api import Client
from ehsm.api.enums import (
    KeySpec,
    Origin,
    KeyUsage,
    PaddingMode,
    DigestMode,
    MessageType,
)
from ehsm.utils import str_to_base64, rsa_encrypt, generate_random_key_hex
from ehsm.server_tests.utils import random_str, assert_response_success


@pytest.mark.parametrize(
    "keyspec",
    [KeySpec.EH_RSA_2048, KeySpec.EH_RSA_3072, KeySpec.EH_RSA_4096, KeySpec.EH_SM2],
)
def test_asymm_encrypt_decrypt(client: Client, keyspec: KeySpec):
    # 1. create a key
    result = client.create_key(
        keyspec, Origin.EH_INTERNAL_KEY, KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT
    )
    assert_response_success(result.response)
    keyid = result.keyid
    # 2. test encrypt and decrypt
    origin_text = str_to_base64(random_str(100))
    enc_resp = client.asymm_encrypt(keyid, origin_text, PaddingMode.EH_RSA_PKCS1_OAEP)
    assert_response_success(enc_resp.response)
    ciphertext = enc_resp.ciphertext
    dec_resp = client.asymm_decrypt(keyid, ciphertext, PaddingMode.EH_RSA_PKCS1_OAEP)
    assert_response_success(dec_resp.response)
    plaintext = dec_resp.plaintext
    assert origin_text == plaintext


@pytest.mark.parametrize(
    "keyspec",
    [
        KeySpec.EH_RSA_2048,
        KeySpec.EH_RSA_3072,
        KeySpec.EH_RSA_4096,
        KeySpec.EH_SM2,
        KeySpec.EH_EC_P224,
        KeySpec.EH_EC_P256,
        KeySpec.EH_EC_P256K,
        KeySpec.EH_EC_P384,
        KeySpec.EH_EC_P521,
    ],
)
def test_get_public_key(client: Client, keyspec: KeySpec):
    # 1. create a key
    result = client.create_key(
        keyspec, Origin.EH_INTERNAL_KEY, KeyUsage.EH_KEYUSAGE_SIGN_VERIFY
    )
    assert_response_success(result.response)
    keyid = result.keyid
    # 2. try acquire the key from server
    result = client.get_public_key(keyid)
    assert_response_success(result.response)


@pytest.mark.parametrize(
    "keyspec, padding_mode, digest_mode",
    [
        (KeySpec.EH_RSA_2048, PaddingMode.EH_RSA_PKCS1, DigestMode.EH_SHA_256),
        (KeySpec.EH_RSA_3072, PaddingMode.EH_RSA_PKCS1, DigestMode.EH_SHA_256),
        (KeySpec.EH_RSA_4096, PaddingMode.EH_RSA_PKCS1, DigestMode.EH_SHA_256),
        (KeySpec.EH_SM2, PaddingMode.EH_PAD_NONE, DigestMode.EH_SM3),
        (KeySpec.EH_EC_P224, PaddingMode.EH_PAD_NONE, DigestMode.EH_SHA_256),
        (KeySpec.EH_EC_P256, PaddingMode.EH_PAD_NONE, DigestMode.EH_SHA_256),
        (KeySpec.EH_EC_P256K, PaddingMode.EH_PAD_NONE, DigestMode.EH_SHA_256),
        (KeySpec.EH_EC_P384, PaddingMode.EH_PAD_NONE, DigestMode.EH_SHA_256),
        (KeySpec.EH_EC_P521, PaddingMode.EH_PAD_NONE, DigestMode.EH_SHA_256),
    ],
)
def test_sign_verify(
    client: Client, keyspec: KeySpec, padding_mode: PaddingMode, digest_mode: DigestMode
):
    # 1. create key
    result = client.create_key(
        keyspec, Origin.EH_INTERNAL_KEY, KeyUsage.EH_KEYUSAGE_SIGN_VERIFY
    )
    assert_response_success(result.response)
    keyid = result.keyid
    # 2. test sign and verify
    message = str_to_base64(random_str(100))
    sign_result = client.sign(
        keyid=keyid,
        padding_mode=padding_mode,
        digest_mode=digest_mode,
        message_type=MessageType.EH_RAW,
        message=message,
    )
    assert_response_success(sign_result.response)
    sign = sign_result.signature
    verify_result = client.verify(
        keyid=keyid,
        padding_mode=PaddingMode.EH_RSA_PKCS1,
        digest_mode=digest_mode,
        message_type=MessageType.EH_RAW,
        message=message,
        signature=sign,
    )
    assert_response_success(verify_result.response)
    # assert the verification is success
    assert verify_result.result


@pytest.mark.parametrize(
    "keyspec",
    [
        KeySpec.EH_AES_GCM_128,
        KeySpec.EH_AES_GCM_192,
        KeySpec.EH_AES_GCM_256,
        KeySpec.EH_SM4_CBC,
        KeySpec.EH_SM4_CTR,
    ],
)
def test_symm_encrypt_decrypt(client: Client, keyspec: KeySpec):
    # 1. create a key
    result = client.create_key(
        keyspec, Origin.EH_INTERNAL_KEY, KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT
    )
    assert_response_success(result.response)
    keyid = result.keyid
    # 2. test encrypt and decrypt
    aad = str_to_base64(random_str(8))
    origin_text = str_to_base64(random_str(111))
    enc_result = client.encrypt(aad=aad, keyid=keyid, plaintext=origin_text)
    assert_response_success(enc_result.response)
    ciphertext = enc_result.ciphertext
    dec_result = client.decrypt(aad=aad, keyid=keyid, ciphertext=ciphertext)
    assert_response_success(dec_result.response)
    plaintext = dec_result.plaintext
    assert origin_text == plaintext


@pytest.mark.parametrize(
    "keyspec",
    [
        KeySpec.EH_AES_GCM_128,
        KeySpec.EH_AES_GCM_192,
        KeySpec.EH_AES_GCM_256,
        KeySpec.EH_SM4_CBC,
        KeySpec.EH_SM4_CTR,
    ],
)
def test_generate_data_key(client: Client, keyspec: KeySpec):
    KEYLEN = 16
    aad = str_to_base64(random_str(10))
    # 1. create data key
    result = client.create_key(
        keyspec, Origin.EH_INTERNAL_KEY, KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT
    )
    assert_response_success(result.response)
    keyid = result.keyid
    # 2. test creation of data key
    result = client.generate_data_key(aad=aad, keyid=keyid, keylen=KEYLEN)
    assert_response_success(result.response)
    ciphertext = result.ciphertext
    # 3. test decryption
    client.decrypt(aad=aad, keyid=keyid, ciphertext=ciphertext)


@pytest.mark.parametrize(
    "keyspec",
    [
        KeySpec.EH_AES_GCM_128,
        KeySpec.EH_AES_GCM_192,
        KeySpec.EH_AES_GCM_256,
        KeySpec.EH_SM4_CBC,
        KeySpec.EH_SM4_CTR,
    ],
)
def test_generate_data_key_without_plaintext(client: Client, keyspec: KeySpec):
    KEYLEN = 48
    aad = str_to_base64(random_str(10))
    # 1. create data key
    result = client.create_key(
        keyspec, Origin.EH_INTERNAL_KEY, KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT
    )
    assert_response_success(result.response)
    keyid = result.keyid
    # 2. test creation of data key
    result = client.generate_data_key_without_plaintext(
        aad=aad, keyid=keyid, keylen=KEYLEN
    )
    assert_response_success(result.response)
    ciphertext = result.ciphertext
    # 3. test decryption
    client.decrypt(aad=aad, keyid=keyid, ciphertext=ciphertext)


importKeyspec_values = [
    KeySpec.EH_AES_GCM_128,
    KeySpec.EH_AES_GCM_192,
    KeySpec.EH_AES_GCM_256,
    KeySpec.EH_SM4_CBC,
    KeySpec.EH_SM4_CTR,
]
cryptoKeyspec_values = [
    KeySpec.EH_RSA_2048,
    KeySpec.EH_RSA_3072,
    KeySpec.EH_RSA_4096,
]
padding_mode_values = [
    PaddingMode.EH_RSA_PKCS1,
    PaddingMode.EH_RSA_PKCS1_OAEP,
]


@pytest.mark.parametrize(
    "importKeyspec, cryptoKeyspec, padding_mode",
    [
        (importKeyspec, cryptoKeyspec, padding_mode)
        for importKeyspec in importKeyspec_values
        for cryptoKeyspec in cryptoKeyspec_values
        for padding_mode in padding_mode_values
    ],
)
def test_BYOK(
    client: Client,
    cryptoKeyspec: KeySpec,
    importKeyspec: KeySpec,
    padding_mode: PaddingMode,
):
    # 1. create data key
    result = client.create_key(
        importKeyspec, Origin.EH_EXTERNAL_KEY, KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT
    )
    assert_response_success(result.response)
    keyid = result.keyid
    # 2. get parameters for import
    result = client.get_parameters_for_import(keyid=keyid, keyspec=cryptoKeyspec)
    assert_response_success(result.response)
    pubkey = result.pubkey
    importToken = result.importToken
    # 3. encrypt import key
    aes_key = generate_random_key_hex(importKeyspec)
    key_material = rsa_encrypt(aes_key, pubkey, padding_mode)
    # 4. import key material
    result = client.import_key_material(
        keyid=keyid,
        key_material=key_material.decode("utf-8"),
        padding_mode=padding_mode,
        importToken=importToken,
    )
    assert_response_success(result.response)
    assert result.result
