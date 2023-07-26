from signal import sigwaitinfo
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
    parser.add_argument('--message', type=str, help='the digest data', required=True)
    parser.add_argument('--sig', type=str, help='the signature of the digest to be verified', required=True)
    parser.add_argument('--message_type', type=str, help='the message type: raw or digest', required=True)
    parser.add_argument('--digest_mode', type=str, help='the digest_mode for sign/verify', required=True)
    parser.add_argument('--padding_mode', type=str, help='the digest_mode for RSA sign/verify')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.digest, args.sig, args.message_type, args.digest_mode, args.padding_mode 

def verify(base_url, keyid, message, sig, message_type, padding_mode, digest_mode):
    print('verify data with an signature')

    payload = OrderedDict()
    payload["message"] = message
    payload["keyid"] = keyid
    payload["signature"] = sig
    payload["message_type"] = message_type
    payload["digest_mode"] = digest_mode
    if padding_mode is not None:
        payload["padding_mode"] = padding_mode
    params = _utils_.init_params(payload)
    print('verify req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "Verify", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'Verify') == False):
        return
    print('verify resp:\n%s\n' %(resp.text))

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, message, sig, message_type, digest_mode, padding_mode = get_args()

    verify(base_url, keyid, message, message_type, padding_mode, digest_mode)

