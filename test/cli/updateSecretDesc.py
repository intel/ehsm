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
    parser.add_argument('--secretName', type=str, help='the name of the secret', required=True)
    parser.add_argument('--description', type=str, help='the description of the secret')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.secretName, args.description

def updateSecretDesc(base_url, secretName, description = None):
    print('update secret description')
    
    payload = OrderedDict()
    if description != None:
        payload["description"] = description
    payload["secretName"] = secretName
    params = _utils_.init_params(payload)
    print('update Secret req:\n%s\n' %(params))
    
    resp = requests.post(url=base_url + "UpdateSecretDesc", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'UpdateSecretDesc') == False):
        return
    print('updateSecretDesc resp:\n%s\n' %(resp.text))


if __name__ == "__main__":
    headers = _utils_.headers

    base_url, secretName, description = get_args()

    updateSecretDesc(base_url, secretName, description)