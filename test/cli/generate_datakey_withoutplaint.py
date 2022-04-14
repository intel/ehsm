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
    parser.add_argument('--keyid', type=str, help='the keyid of symmetric cmk that want to use', required=True)
    parser.add_argument('--len', type=int, help='the length(1~1024) of datakey that want to generate', required=True)
    parser.add_argument('--aad', type=str, help='the aad data that want to provide, could be null')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.len, args.aad

def generate_datakey_withoutplaint(base_url, keyid, len, aad):
    print('generate_datakey_withoutplaint with len (%d) wraped by a symmetric cmk' %(len))

    payload = OrderedDict()
    if aad is not None:
        payload["aad"] = aad
    payload["keyid"] = keyid
    payload["keylen"] = len
    params = _utils_.init_params(payload)
    print('generate_datakey_withoutplaint req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "GenerateDataKeyWithoutPlaintext", data=json.dumps(params), headers=_utils_.headers)
    if(_utils_.check_result(resp, 'GenerateDataKeyWithoutPlaintext') == False):
        return

    print('generate_datakey_withoutplaint resp:\n%s\n' %(resp.text))
    return json.loads(resp.text)['result']['ciphertext']

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, len, aad = get_args()

    generate_datakey_withoutplaint(base_url, keyid, len, aad)

