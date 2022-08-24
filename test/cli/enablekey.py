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
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.keyid

def enablekey(base_url, keyid):
    print('enable key with keyid %s' %(keyid))

    payload = OrderedDict()
    payload["keyid"] = keyid
    params = _utils_.init_params(payload)
    print('enablekey req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "EnableKey", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'EnableKey') == False):
        return

    print('enablekey resp:\n%s\n' %(resp.text))

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid = get_args()

    enablekey(base_url, keyid)

