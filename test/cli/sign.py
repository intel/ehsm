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
    parser.add_argument('--message', type=str, help='the message data to be signed', required=True)
    parser.add_argument('--message_type', type=str, help='the message type: raw or digest', required=True)
    parser.add_argument('--padding_mode', type=str, help='the padding_mode for RSA sign/verify')
    parser.add_argument('--digest_mode', type=str, help='the digest_mode for sign/verify', required=True)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.message, args.message_type, args.padding_mode, args.digest_mode

def sign(base_url, keyid, message, message_type, padding_mode, digest_mode):
    print('sign data with an asymmetric cmk')

    payload = OrderedDict()
    payload["message"] = message
    payload["message_type"] = message_type
    if padding_mode is not None:
        payload["padding_mode"] = padding_mode
    payload["digest_mode"] = digest_mode
    payload["keyid"] = keyid
    params = _utils_.init_params(payload)
    print('sign req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "Sign", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    print('sign resp:\n%s\n' %(resp.text))
    if(_utils_.check_result(resp, 'Sign') == False):
        return
    print('sign resp:\n%s\n' %(resp.text))
    return json.loads(resp.text)['result']['signature']

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, message, message_type, padding_mode, digest_mode = get_args()

    sign(base_url, keyid, message, message_type, padding_mode, digest_mode)

