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
    parser.add_argument('--secretName', type=str, help='the name of the secret', required=False)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.secretName

def listSecrets(base_url, secretName=None):
    payload = OrderedDict()
    if secretName != None:
        payload["secretName"] = secretName
        params = _utils_.init_params(payload)
    else:
        params = _utils_.init_params()
    print('listSecrets req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "ListSecrets", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'ListSecrets') == False):
        return

    print('listSecrets resp:\n%s\n' %(resp.text))
    totalCount = json.loads(resp.text)['result']['totalCount']
    return totalCount

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, secretName = get_args()

    listSecrets(base_url, secretName)