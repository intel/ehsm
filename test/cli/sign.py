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
    parser.add_argument('--keyid', type=str, help='the keyid of asymmetric cmk', required=True)
    parser.add_argument('--digest', type=str, help='the digest data to be signed', required=True)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.digest

def sign(base_url, keyid, digest):
    print('sign data with an asymmetric cmk')

    payload = OrderedDict()
    payload["digest"] = digest
    payload["keyid"] = keyid
    params = _utils_.init_params(payload)
    print('sign req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "Sign", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'Sign') == False):
        return
    print('sign resp:\n%s\n' %(resp.text))
    return json.loads(resp.text)['result']['signature']

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, digest = get_args()

    sign(base_url, keyid, digest)

