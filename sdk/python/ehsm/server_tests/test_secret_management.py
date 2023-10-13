import pytest
import random

from ehsm.api import Client
from ehsm.api.enums import KeySpec, Origin, KeyUsage
from ehsm.server_tests.utils import random_str, assert_response_success


def random_secret():
    secret = random_str(150)
    secret_name = random_str(10)
    return secret, secret_name


def test_create_secret_without_key(client: Client):
    secret, secret_name = random_secret()
    resp = client.create_secret(
        secret_name=secret_name,
        secret_data=secret,
        encryption_key_id=None,
        rotation_interval=None,
    )
    assert_response_success(resp)
    # try get key value
    resp = client.get_secret_value(secret_name=secret_name, version_id=None)
    assert_response_success(resp)
    assert resp.result.secret_name == secret_name
    assert resp.result.secret_data == secret
    assert resp.result.version_id == 1


@pytest.mark.parametrize(
    "keyspec",
    (
        KeySpec.EH_AES_GCM_128,
        KeySpec.EH_AES_GCM_192,
        KeySpec.EH_AES_GCM_256,
    ),
)
def test_create_secret_with_key(client: Client, keyspec: KeySpec):
    key_resp = client.create_key(
        keyspec=keyspec,
        origin=Origin.EH_INTERNAL_KEY,
        keyusage=KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT,
    )
    assert_response_success(key_resp)
    keyid = key_resp.result.keyid
    # create key
    secret, secret_name = random_secret()
    resp = client.create_secret(
        secret_name=secret_name,
        secret_data=secret,
        encryption_key_id=keyid,
        rotation_interval=None,
    )
    assert_response_success(resp)
    # try get key value
    resp = client.get_secret_value(secret_name=secret_name, version_id=None)
    assert_response_success(resp)
    assert resp.result.secret_name == secret_name
    assert resp.result.secret_data == secret
    assert resp.result.version_id == 1


def test_secret_versioning(client: Client):
    secret, secret_name = random_secret()
    resp = client.create_secret(secret_name=secret_name, secret_data=secret)
    assert_response_success(resp)
    # a list stores different version of secret
    K = 10
    secret_versions = [secret]
    # create K versions
    for _ in range(K):
        secret = random_str(150)
        secret_versions.append(secret)
        resp = client.put_secret_value(secret_name=secret_name, secret_data=secret)
        assert_response_success(resp)
    # list versions
    resp = client.list_secret_version_ids(secret_name=secret_name)
    assert_response_success(resp)
    assert resp.result.total_count == K + 1  # add the version when created
    resp_versions = set([v.version_id for v in resp.result.version_ids])
    # version counts from 1
    assert resp_versions == set([i + 1 for i in range(K + 1)])
    # access the versions randomly
    access_seq = list(range(K + 1))
    random.shuffle(access_seq)
    for i in access_seq:
        resp = client.get_secret_value(secret_name=secret_name, version_id=i + 1)
        assert_response_success(resp)
        assert resp.result.version_id == i + 1
        assert resp.result.secret_name == secret_name
        assert resp.result.secret_data == secret_versions[i]
    # access the latest version
    resp = client.get_secret_value(secret_name=secret_name)
    assert_response_success(resp)
    assert resp.result.version_id == K + 1
    assert resp.result.secret_name == secret_name
    assert resp.result.secret_data == secret_versions[-1]


def tset_delete_restore_secret(client: Client):
    # create the key
    secret, secret_name = random_secret()
    resp = client.create_secret(secret_name=secret_name, secret_data=secret)
    assert_response_success(resp)
    # delete the key
    resp = client.delete_secret(secret_name=secret_name, recovery_period=None, force_delete=False)
    assert_response_success(resp)
    resp = client.get_secret_value(secret_name=secret_name)
    assert_response_success(resp)
    assert resp.result.secret_data is None
    # restore the key
    resp = client.restore_secret(secret_name=secret_name)
    resp = client.get_secret_value(secret_name=secret_name)
    assert_response_success(resp)
    assert resp.result.secret_data == secret
    

def test_describe_secret(client: Client):
    # create the key
    secret, secret_name = random_secret()
    desc = random_str(100)
    resp = client.create_secret(secret_name=secret_name, secret_data=secret, description=desc)
    assert_response_success(resp)
    resp = client.list_secrets(secret_name=secret_name)
    assert_response_success(resp)
    assert resp.result.total_count == 1
    assert resp.result.secret_list[0].description == desc
    # update desc
    new_desc = random_str(111)
    resp = client.update_secret_description(secret_name=secret_name, description=new_desc)
    assert_response_success(resp)
    resp = client.list_secrets(secret_name=secret_name)
    assert_response_success(resp)
    assert resp.result.total_count == 1
    assert resp.result.secret_list[0].description == new_desc 
    

def test_list_secrets(client: Client):
    # K = random.randint(10, 20)
    K = 1
    # create K keys
    secrets = [random_secret() for _ in range(K)]
    for secret, secret_name in secrets:
        resp = client.create_secret(secret_name=secret_name, secret_data=secret)
        assert_response_success(resp)
    # verify list_secrets func
    resp = client.list_secrets()
    assert_response_success(resp)
    assert resp.result.total_count == K
    names = set([s.secret_name for s in resp.result.secret_list])
    assert names == set([secret_name for secret, secret_name in secrets])
