from typing import Tuple, List, Optional
import pytest
import random
import time

from ehsm.api import Client
from ehsm.api.enums import KeySpec, Origin, KeyUsage
from ehsm.exceptions import InvalidParamException
from ehsm.serializers.key_management import ListKeyItem
from ehsm.server_tests.utils import assert_response_success, random_str


common_keyspec_list = [
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


def test_get_version(client: Client):
    result = client.get_version()
    assert_response_success(result.response)


def test_enroll(client: Client):
    appid, apikey = client.enroll()
    assert appid != ""
    assert apikey != ""


def create_random_keys(client: Client, k: int = 8):
    # list(Enum) gets all options from Enum
    keys: List[Tuple[KeySpec, Origin, KeyUsage]] = [
        (
            random.choice(common_keyspec_list),
            Origin.EH_INTERNAL_KEY,  # external key is not supported yet
            KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,  # symm. key cannot be used for signing
        )
        for _ in range(k)
    ]
    key_ids = []
    for keyspec, origin, keyusage in keys:
        result = client.create_key(keyspec=keyspec, origin=origin, keyusage=keyusage)
        assert_response_success(result.response)
        key_ids.append(result.keyid)
    return list(zip(key_ids, keys))


def test_list_key(client: Client):
    # 1. create keys randomly
    keys = create_random_keys(client, 10)
    validate_set = set()
    for keyid, (keyspec, _, _) in keys:
        validate_set.add((keyid, keyspec))
    # 2. get keys back
    result = client.list_key()
    assert_response_success(result.response)
    resp_keys = set([(k.keyid, k.keyspec) for k in result.list])
    assert validate_set == resp_keys


def test_delete_all_key(client: Client):
    # 1. creat keys
    keys = create_random_keys(client, 10)
    assert len(keys) == 10
    # 2. delete all keys
    result = client.delete_all_key()
    assert_response_success(result.response)
    # 3. verify
    result = client.list_key()
    assert_response_success(result.response)
    assert len(result.list) == 0


def test_enable_disable_key(client: Client):
    keyid, _ = create_random_keys(client, 1)[0]
    # disable it
    result = client.disable_key(keyid)
    assert_response_success(result.response)
    result = client.list_key()
    assert_response_success(result.response)
    key: Optional[ListKeyItem] = next(
        filter(lambda k: k.keyid == keyid, result.list), None
    )
    assert key is not None
    assert key.keystate == 0
    # enable it
    result = client.enable_key(keyid)
    assert_response_success(result.response)
    result = client.list_key()
    assert_response_success(result.response)
    key: Optional[ListKeyItem] = next(
        filter(lambda k: k.keyid == keyid, result.list), None
    )
    assert key is not None
    assert key.keystate == 1


def test_enable_enable_key(client: Client):
    """
    Enable a key twice should be valid
    """
    keyid, _ = create_random_keys(client, 1)[0]
    # enable it
    result = client.enable_key(keyid)
    assert_response_success(result.response)
    result = client.list_key()
    assert_response_success(result.response)
    key: Optional[ListKeyItem] = next(
        filter(lambda k: k.keyid == keyid, result.list), None
    )
    assert key is not None
    assert key.keystate == 1
    # enable it again
    result = client.enable_key(keyid)
    assert_response_success(result.response)
    result = client.list_key()
    assert_response_success(result.response)
    key: Optional[ListKeyItem] = next(
        filter(lambda k: k.keyid == keyid, result.list), None
    )
    assert key is not None
    assert key.keystate == 1


def test_disable_disable_key(client: Client):
    """
    Disable a key twice should be valid
    """
    keyid, _ = create_random_keys(client, 1)[0]
    # enable it
    result = client.disable_key(keyid)
    assert_response_success(result.response)
    result = client.list_key()
    assert_response_success(result.response)
    key: Optional[ListKeyItem] = next(
        filter(lambda k: k.keyid == keyid, result.list), None
    )
    assert key is not None
    assert key.keystate == 0
    # enable it again
    result = client.disable_key(keyid)
    assert_response_success(result.response)
    result = client.list_key()
    assert_response_success(result.response)
    key: Optional[ListKeyItem] = next(
        filter(lambda k: k.keyid == keyid, result.list), None
    )
    assert key is not None
    assert key.keystate == 0


def test_delete_key(client: Client):
    keyid, _ = create_random_keys(client, 1)[0]
    # before delete: should successfully acquire
    result = client.list_key()
    assert_response_success(result.response)
    key: Optional[ListKeyItem] = next(
        filter(lambda k: k.keyid == keyid, result.list), None
    )
    assert key is not None
    # delete: should not be found
    result = client.delete_key(keyid)
    assert_response_success(result.response)
    result = client.list_key()
    assert_response_success(result.response)
    key: Optional[ListKeyItem] = next(
        filter(lambda k: k.keyid == keyid, result.list), None
    )
    assert key is None


@pytest.mark.parametrize("keyspec", common_keyspec_list)
def test_create_key_with_invalid_appid(client: Client, keyspec: KeySpec):
    with pytest.raises(InvalidParamException):
        client.set_appid(random_str(20))
        client.create_key(
            keyspec=keyspec,
            origin=Origin.EH_INTERNAL_KEY,
            keyusage=KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,
        )


@pytest.mark.parametrize("keyspec", common_keyspec_list)
def test_create_key_with_invalid_apikey(client: Client, keyspec: KeySpec):
    with pytest.raises(InvalidParamException):
        client.set_apikey(random_str(100))
        client.create_key(
            keyspec=keyspec,
            origin=Origin.EH_INTERNAL_KEY,
            keyusage=KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,
        )


@pytest.mark.parametrize("keyspec", common_keyspec_list)
def test_create_key_with_future_timestamp(client: Client, keyspec: KeySpec):
    future_time = time.time() + 1320

    def mock_time(*args, **kwrags):
        return future_time

    mock = pytest.MonkeyPatch()
    mock.setattr(time, "time", mock_time)
    with mock.context() as m:
        with pytest.raises(InvalidParamException):
            client.create_key(
                keyspec=keyspec,
                origin=Origin.EH_INTERNAL_KEY,
                keyusage=KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,
            )
    mock.undo()


@pytest.mark.parametrize("keyspec", common_keyspec_list)
def test_create_key_with_past_timestamp(client: Client, keyspec: KeySpec):
    past_time = time.time() + 1320

    def mock_time(*args, **kwrags):
        return past_time

    mock = pytest.MonkeyPatch()
    mock.setattr(time, "time", mock_time)
    with mock.context() as m:
        with pytest.raises(InvalidParamException):
            client.create_key(
                keyspec=keyspec,
                origin=Origin.EH_INTERNAL_KEY,
                keyusage=KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,
            )
    mock.undo()


def test_create_key_with_invalid_keyspec(client: Client):
    keyspec = random_str(12)
    with pytest.raises(InvalidParamException):
        client.create_key(
            keyspec=keyspec,  # type: ignore
            origin=Origin.EH_INTERNAL_KEY,
            keyusage=KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,
        )


@pytest.mark.parametrize("keyspec", common_keyspec_list)
def test_create_key_with_invalid_origin(client: Client, keyspec: KeySpec):
    with pytest.raises(InvalidParamException):
        client.create_key(
            keyspec=keyspec,
            origin=random_str(12),  # type: ignore
            keyusage=KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,
        )


@pytest.mark.parametrize("keyspec", common_keyspec_list)
def test_create_key_with_duplicate_request(client: Client, keyspec: KeySpec):
    result = client.create_key(
        keyspec=keyspec,
        origin=Origin.EH_INTERNAL_KEY,
        keyusage=KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,
    )
    origin_request = result.raw_response.request
    resp = client._session._client.send(origin_request)
    # status code is correct with `code` field in response body equals to 400
    assert resp.status_code == 200
    data = resp.json()
    assert "code" in data
    assert data["code"] == 400
