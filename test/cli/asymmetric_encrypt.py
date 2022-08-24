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
    parser.add_argument('--keyid', type=str, help='the keyid of the asymmetric cmk', required=True)
    parser.add_argument('--data', type=str, help='the plaintext data to be encrypted', required=True)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.data

def asymmetric_encrypt(base_url, keyid, data):
    print('encrypt data with an asymmetric cmk')

    payload = OrderedDict()
    payload["keyid"] = keyid
    payload["plaintext"] = data
    params = _utils_.init_params(payload)
    print('asymmetric_encrypt req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "AsymmetricEncrypt", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'AsymmetricEncrypt') == False):
        return

    print('asymmetric_encrypt resp:\n%s\n' %(resp.text))
    return json.loads(resp.text)['result']['ciphertext']

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, data = get_args()

    asymmetric_encrypt(base_url, keyid, data)

