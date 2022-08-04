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
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.secretName

def describeSecret(base_url, secretName):
    payload = OrderedDict()
    payload["secretName"] = secretName
    params = _utils_.init_params(payload)
    print('describeSecret req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "DescribeSecret", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'DescribeSecret') == False):
        return

    print('describeSecret resp:\n%s\n' %(resp.text))
    if ('secretName' in json.loads(resp.text)['result']):
        secretName = json.loads(resp.text)['result']['secretName']
    return secretName

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, secretName = get_args()

    describeSecret(base_url, secretName)

