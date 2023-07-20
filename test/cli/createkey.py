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

supported_keyspec = ["EH_AES_GCM_128", "EH_AES_GCM_192", "EH_AES_GCM_256", "EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096", "EH_RSA_3072", "EH_EC_P256", "EH_EC_P256K", "EH_SM2", "EH_SM4"]

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    parser.add_argument('--keyspec', type=str, help='supported keyspec [EH_AES_GCM_128", "EH_AES_GCM_192", "EH_AES_GCM_256", "EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096", "EH_RSA_3072", "EH_EC_P256", "EH_EC_P256K", "EH_SM2", "EH_SM4]', required=True)
    parser.add_argument('--origin', type=str, help='the key origin [EH_EXTERNAL_KEY or EH_INTERNAL_KEY]', required=True)
    parser.add_argument('--purpose', type=str, help='the key purpose')
    parser.add_argument('--padding_mode', type=str, help='the key padding_mode')
    parser.add_argument('--digest_mode', type=str, help='the key digest_mode')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.keyspec, args.origin, args.purpose, args.padding_mode, args.digest_mode

def createkey(base_url, keyspec, origin, purpose = None, padding_mode = None, digest_mode = None):
    print('generate key with keyspec %s' %(keyspec))

    payload = OrderedDict()
    if digest_mode != None:
        payload["digest_mode"] = digest_mode
    payload["keyspec"] = keyspec
    payload["origin"] = origin
    if padding_mode != None:
        payload["padding_mode"] = padding_mode
    if purpose != None:
        payload["purpose"] = purpose
    params = _utils_.init_params(payload)
    print('createkey req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'CreateKey') == False):
        return

    print('createkey resp:\n%s\n' %(resp.text))
    return json.loads(resp.text)['result']['keyid']

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyspec, origin, purpose, padding_mode, digest_mode = get_args()

    if origin != "EH_INTERNAL_KEY":
        origin = "EH_INTERNAL_KEY"

    if keyspec in supported_keyspec:
        createkey(base_url, keyspec, origin, purpose, padding_mode, digest_mode)
    else:
        print('current version do not support this keyspec: %s' %(keyspec))

