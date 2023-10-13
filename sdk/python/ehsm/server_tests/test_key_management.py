from typing import Tuple, List, Optional
import random

from ehsm.api import Client
from ehsm.api.enums import KeySpec, Origin, KeyUsage
from ehsm.serializers.key_management import ListKeyItem
from ehsm.server_tests.utils import assert_response_success


def test_get_version(client: Client):
    resp = client.get_version()
    assert_response_success(resp)


def test_enroll(client: Client):
    appid, apikey = client.enroll()
    assert appid != ""
    assert apikey != ""


def create_random_keys(client: Client, k: int = 8):
    # list(Enum) gets all options from Enum
    keys: List[Tuple[KeySpec, Origin, KeyUsage]] = [
        (
            random.choice(
                [
                    KeySpec.EH_AES_GCM_128,
                    KeySpec.EH_AES_GCM_192,
                    KeySpec.EH_AES_GCM_256,
                    KeySpec.EH_EC_P224,
                    KeySpec.EH_EC_P256,
                    KeySpec.EH_EC_P256K,
                    KeySpec.EH_EC_P384,
                    KeySpec.EH_EC_P521,
                    KeySpec.EH_RSA_2048,
                    KeySpec.EH_RSA_3072,
                    KeySpec.EH_RSA_4096,
                ]
            ),
            Origin.EH_INTERNAL_KEY,  # external key is not supported yet
            KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,  # symm. key cannot be used for signing
        )
        for _ in range(k)
    ]
    key_ids = []
    for keyspec, origin, keyusage in keys:
        resp = client.create_key(keyspec=keyspec, origin=origin, keyusage=keyusage)
        assert_response_success(resp)
        key_ids.append(resp.result.keyid)
    return list(zip(key_ids, keys))


def test_list_key(client: Client):
    # 1. create keys randomly
    keys = create_random_keys(client, 10)
    validate_set = set()
    for keyid, (keyspec, _, _) in keys:
        validate_set.add((keyid, keyspec))
    # 2. get keys back
    resp = client.list_key()
    assert_response_success(resp)
    resp_keys = set([(k.keyid, k.keyspec) for k in resp.result.list])
    assert validate_set == resp_keys


def test_delete_all_key(client: Client):
    # 1. creat keys
    keys = create_random_keys(client, 10)
    assert len(keys) == 10
    # 2. delete all keys
    resp = client.delete_all_key()
    assert_response_success(resp)
    # 3. verify
    resp = client.list_key()
    assert_response_success(resp)
    assert len(resp.result.list) == 0


def test_enable_disable_key(client: Client):
    keyid, _ = create_random_keys(client, 1)[0]
    # disable it
    resp = client.disable_key(keyid)
    assert_response_success(resp)
    resp = client.list_key()
    assert_response_success(resp)
    key: Optional[ListKeyItem] = next(filter(lambda k: k.keyid == keyid, resp.result.list), None)
    assert key is not None
    assert key.keystate == 0
    # enable it
    resp = client.enable_key(keyid)
    assert_response_success(resp)
    resp = client.list_key()
    assert_response_success(resp)
    key: Optional[ListKeyItem] = next(filter(lambda k: k.keyid == keyid, resp.result.list), None)
    assert key is not None
    assert key.keystate == 1


def test_enable_enable_key(client: Client):
    """
    Enable a key twice should be valid
    """
    keyid, _ = create_random_keys(client, 1)[0]
    # enable it
    resp = client.enable_key(keyid)
    assert_response_success(resp)
    resp = client.list_key()
    assert_response_success(resp)
    key: Optional[ListKeyItem] = next(filter(lambda k: k.keyid == keyid, resp.result.list), None)
    assert key is not None
    assert key.keystate == 1
    # enable it again
    resp = client.enable_key(keyid)
    assert_response_success(resp)
    resp = client.list_key()
    assert_response_success(resp)
    key: Optional[ListKeyItem] = next(filter(lambda k: k.keyid == keyid, resp.result.list), None)
    assert key is not None
    assert key.keystate == 1


def test_disable_disable_key(client: Client):
    """
    Disable a key twice should be valid
    """
    keyid, _ = create_random_keys(client, 1)[0]
    # enable it
    resp = client.disable_key(keyid)
    assert_response_success(resp)
    resp = client.list_key()
    assert_response_success(resp)
    key: Optional[ListKeyItem] = next(filter(lambda k: k.keyid == keyid, resp.result.list), None)
    assert key is not None
    assert key.keystate == 0
    # enable it again
    resp = client.disable_key(keyid)
    assert_response_success(resp)
    resp = client.list_key()
    assert_response_success(resp)
    key: Optional[ListKeyItem] = next(filter(lambda k: k.keyid == keyid, resp.result.list), None)
    assert key is not None
    assert key.keystate == 0


def test_delete_key(client: Client):
    keyid, _ = create_random_keys(client, 1)[0]
    # before delete: should successfully acquire
    resp = client.list_key()
    assert_response_success(resp)
    key: Optional[ListKeyItem] = next(filter(lambda k: k.keyid == keyid, resp.result.list), None)
    assert key is not None
    # delete: should not be found
    resp = client.delete_key(keyid)
    assert_response_success(resp)
    resp = client.list_key()
    assert_response_success(resp)
    key: Optional[ListKeyItem] = next(filter(lambda k: k.keyid == keyid, resp.result.list), None)
    assert key is None
