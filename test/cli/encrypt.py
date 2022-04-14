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

import _utils_

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    parser.add_argument('--keyid', type=str, help='the keyid of symmetric cmk', required=True)
    parser.add_argument('--data', type=str, help='the plaintext data that to be encrypted', required=True)
    parser.add_argument('--aad', type=str, help='the aad data that user want to provide, could be null')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.data, args.aad

def encrypt(base_url, keyid, data, aad):
    print('encrypt data with a symmetric cmk')

    payload = OrderedDict()
    if aad is not None:
        payload["aad"] = aad
    payload["keyid"] = keyid
    payload["plaintext"] = data
    params = _utils_.init_params(payload)
    print('encrypt req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "Encrypt", data=json.dumps(params), headers=_utils_.headers)
    if(_utils_.check_result(resp, 'Encrypt') == False):
        return

    print('encrypt resp:\n%s\n' %(resp.text))
    return json.loads(resp.text)['result']['ciphertext']

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, data, aad = get_args()

    encrypt(base_url, keyid, data, aad)

