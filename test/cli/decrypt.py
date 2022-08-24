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
    parser.add_argument('--data', type=str, help='the ciphertext data that to be decrypted', required=True)
    parser.add_argument('--aad', type=str, help='the aad data that want to provide, could be null')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.data, args.aad

def decrypt(base_url, keyid, data, aad):
    print('encrypt data with a symmetric cmk')

    payload = OrderedDict()
    if aad is not None:
        payload["aad"] = aad
    payload["ciphertext"] = data
    payload["keyid"] = keyid
    params = _utils_.init_params(payload)
    print('decrypt req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "Decrypt", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'Decrypt') == False):
        return

    print('decrypt resp:\n%s\n' %(resp.text))
    try:
        plaintext = str(base64.b64decode(json.loads(resp.text)['result']['plaintext']), 'utf-8')
    except:
        plaintext = base64.b64decode(json.loads(resp.text)['result']['plaintext'])
    print('decrypt plaintext:\n%s\n' %(plaintext))
    return plaintext

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, data, aad = get_args()

    decrypt(base_url, keyid, data, aad)

