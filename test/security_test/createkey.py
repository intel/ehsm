import requests
import json
import argparse
import base64
import time
import random
import hmac
from hashlib import sha256
from collections import OrderedDict
import urllib.parse
import pytest
from conftest import test_url


headers = {"Content-Type":"application/json"}
#  Max timestamp diff is 10 mins set in eHSM
#  Thus the nonce is set to twice timestamp diff
#  MAX_TIME_STAMP_DIFF = 10 * 60 * 1000
#  NONCE_CACHE_TIME = MAX_TIME_STAMP_DIFF * 2
NONCE_CACHE_TIME_MINS = 20


def init_params(appid, apikey, timestamp_id, keyspec, origin, sign=None):
    payload = OrderedDict()
    payload["keyspec"] = keyspec
    payload["origin"] = origin
    params = OrderedDict()
    params["appid"] = appid
    params["payload"] = urllib.parse.unquote(urllib.parse.urlencode(payload))
    if timestamp_id in [0, 1, 2]:
        params["timestamp"] = str(int((time.time()-540+(int(timestamp_id)*540)) * 1000))
    else:
        params["timestamp"] = timestamp_id
    #params["timestamp"] = str(int((time.time()) * 1000))

    sign_string = urllib.parse.unquote(urllib.parse.urlencode(params))
    sign = str(base64.b64encode(hmac.new(apikey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8').upper()

    params["payload"] = payload
    params["sign"] = sign
    return params

def init_params_with_invalid_sign(appid, apikey, timestamp_id, keyspec, origin, sign=None):
    payload = OrderedDict()
    payload["keyspec"] = keyspec
    payload["origin"] = origin
    params = OrderedDict()
    params["appid"] = appid
    params["payload"] = urllib.parse.unquote(urllib.parse.urlencode(payload))
    params["timestamp"] = timestamp_id
    #params["timestamp"] = str(int((time.time()) * 1000))

    sign_string = urllib.parse.unquote(urllib.parse.urlencode(params))
    sign = str(base64.b64encode(hmac.new(apikey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8').upper()

    params["timestamp"] = str(int(timestamp_id)+1)
    params["payload"] = payload
    params["sign"] = sign
    return params


@pytest.fixture(params=["ee5ea32c-451e-4c75-9432-bfcf92ab1345"])
def appid_params(request):
    return request.param

@pytest.fixture(params=["123", "000", "aaaaaa", "`~!@#$%^&*()_+=-[]|}{\\;\'\":,./?> <", "!=1 or", "12.13", "e2014b79-ad08-49c4-897d-cbf39a2cdcce; sleep(5000000)", "", "<script>alert(\"1111111\");</script>"])
def invalid_appid_params(request):
    return request.param


@pytest.fixture(params=["ApzbK8MV2edYD0R257CFwSvX091hyD9n"])
def apikey_params(request):
    return request.param

@pytest.fixture(params=["123", "000", "aaaaaa", "`~!@#$%^&*()_+=-[]|}{\\;\'\":,./?> <", "!=1 or", "12.13", "", "<script>alert(\"1111111\");</script>"])
def invalid_apikey_params(request):
    return request.param


@pytest.fixture(params=[0, 1, 2])
def timestamp_id_params(request):
    return request.param

@pytest.fixture(params=[str(int(time.time() * 1000)), str(int((time.time()+540) * 1000)), str(int((time.time()-540) * 1000))])
def timestamp_params(request):
    return request.param

@pytest.fixture(params=["123", "000", "aaaaaa", "`~!@#$%^&*()_+=-[]|}{\\;\'\":,./?> <", "!=1 or", "12.13", "<script>alert(\"1111111\");</script>", str(int((time.time()+1320) * 1000)), str(int((time.time()-1320) * 1000))])
def invalid_timestamp_params(request):
    return request.param


@pytest.fixture(params=["EH_AES_GCM_128", "EH_RSA_3072"])
def keyspec_params(request):
    return request.param

@pytest.fixture(params=["", "EH_AES_GCM_256", "abc", "128", "EH_AES_GCM_1", "`~!@#$%^&*()_+=-[]|}{\\;\'\":,./?> <", "<script>alert(\"1111111\");</script>"])
def invalid_keyspec_params(request):
    return request.param


@pytest.fixture(params=["EH_INTERNAL_KEY"])
def origin_params(request):
    return request.param

@pytest.fixture(params=["", "aaa", "123", "EH_INTERNAL_KEY2", "`~!@#$%^&*()_+=-[]|}{\\;\'\":,./?> <", "<script>alert(\"1111111\");</script>"])
def invalid_origin_params(request):
    return request.param


def test_createkey_normally(test_url, appid_params, apikey_params, timestamp_id_params, keyspec_params, origin_params):
    print("test creatkey using legal params")

    params = init_params(appid_params, apikey_params, timestamp_id_params, keyspec_params, origin_params)

    resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    print(resp.text)
    resp_json = json.loads(resp.text)
    assert 200 == resp_json["code"]


def test_createkey_with_invalid_appid(test_url, invalid_appid_params, apikey_params, timestamp_id_params, keyspec_params, origin_params):
    params = init_params(invalid_appid_params, apikey_params, timestamp_id_params, keyspec_params, origin_params)
    resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    print(resp.text)
    resp_json = json.loads(resp.text)
    assert 200 != resp_json["code"]


def test_createkey_with_invalid_apikey(test_url, appid_params, invalid_apikey_params, timestamp_id_params, keyspec_params, origin_params):
    params = init_params(appid_params, invalid_apikey_params, timestamp_id_params, keyspec_params, origin_params)
    resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    print(resp.text)
    resp_json = json.loads(resp.text)
    assert 200 != resp_json["code"]


def test_createkey_with_invalid_timestamp(test_url, appid_params, apikey_params, invalid_timestamp_params, keyspec_params, origin_params):
    params = init_params(appid_params, apikey_params, invalid_timestamp_params, keyspec_params, origin_params)
    resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    print(resp.text)
    resp_json = json.loads(resp.text)
    assert 200 != resp_json["code"]

def test_createkey_with_invalid_keyspec(test_url, appid_params, apikey_params, timestamp_id_params, invalid_keyspec_params, origin_params):
    params = init_params(appid_params, apikey_params, timestamp_id_params, invalid_keyspec_params, origin_params)
    resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    print(resp.text)
    resp_json = json.loads(resp.text)
    assert 200 != resp_json["code"]

def test_createkey_with_invalid_origin(test_url, appid_params, apikey_params, timestamp_id_params, keyspec_params, invalid_origin_params):
    params = init_params(appid_params, apikey_params, timestamp_id_params, keyspec_params, invalid_origin_params)
    resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    print(resp.text)
    resp_json = json.loads(resp.text)
    assert 200 != resp_json["code"]


def test_duplicated_request(test_url, appid_params, apikey_params, timestamp_params, keyspec_params, origin_params):
    params = init_params(appid_params, apikey_params, timestamp_params, keyspec_params, origin_params)
    tempresp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    print(tempresp.text, timestamp_params)
    print(resp.text, timestamp_params)
    resp_json = json.loads(resp.text)
    assert 200 != resp_json["code"]

def test_wrong_sign_request(test_url, appid_params, apikey_params, timestamp_params, keyspec_params, origin_params):
    params = init_params_with_invalid_sign(appid_params, apikey_params, timestamp_params, timestamp_params, keyspec_params, origin_params)
    resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    print(resp.text, timestamp_params)
    resp_json = json.loads(resp.text)
    assert 200 != resp_json["code"]

#  Test timestamp cache whether available within 20 mins (NONCE_CACHE_TIME)
def test_replay_attack_for_createkey_api(test_url, appid_params, apikey_params, origin_params):
    timestamp = str(int((time.time()+599) * 1000))
    params = init_params(appid_params, apikey_params, timestamp, "EH_AES_GCM_128", origin_params)
    tempresp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
    resp_json = json.loads(tempresp.text)
    for i in range (0, NONCE_CACHE_TIME_MINS):
        time.sleep(60)
        resp = requests.post(url=test_url + "/ehsm?Action=CreateKey", data=json.dumps(params), headers=headers, verify=_utils_.use_secure_cert)
        print(tempresp.text, timestamp)
        print(resp.text, timestamp)
        resp_json = json.loads(resp.text)
        if 200 == resp_json["code"]:
            assert 200 != resp_json["code"]
            break
    assert 200 != resp_json["code"]


if __name__ == "__main__":
    pytest.main(["-s","createkey.py"])


