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

supported_keyspec = ["EH_AES_GCM_128", "EH_RSA_3072"]

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    parser.add_argument('--keyspec', type=str, help='the keyspec [EH_AES_GCM_128, EH_RSA_3072]', required=True)
    parser.add_argument('--origin', type=str, help='the key origin [default is: EH_INTERNAL_KEY]')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.keyspec, args.origin

def createkey(base_url, keyspec, origin):
    print('generate key with keyspec %s' %(keyspec))

    payload = OrderedDict()
    payload["keyspec"] = keyspec
    payload["origin"] = origin
    params = _utils_.init_params(payload)
    print('createkey req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=_utils_.headers)
    if(_utils_.check_result(resp, 'CreateKey') == False):
        return

    print('createkey resp:\n%s\n' %(resp.text))

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyspec, origin = get_args()

    if origin != "EH_INTERNAL_KEY":
        origin = "EH_INTERNAL_KEY"

    if keyspec in supported_keyspec:
        createkey(base_url, keyspec, origin)
    else:
        print('current version do not support this keyspec: %s' %(keyspec))

