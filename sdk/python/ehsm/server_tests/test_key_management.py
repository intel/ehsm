from ehsm.api import Client

from .base import assert_response_success


def test_get_version(client: Client):
    resp = client.get_version()
    assert_response_success(resp)


def test_enroll(client: Client):
    appid, apikey = client.enroll()
    assert appid != ""
    assert apikey != ""


def test_list_key(client: Client):
    resp = client.list_key()
    assert_response_success(resp)
