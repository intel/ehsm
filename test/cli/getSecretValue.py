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
    parser.add_argument('--versionId', type=int, help='the verdionId of the secret', required=False)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.secretName, args.versionId

def getSecretValue(base_url, secretName, versionId = None):
    payload = OrderedDict()
    payload["secretName"] = secretName
    if versionId != None:
        payload["versionId"] = versionId
    params = _utils_.init_params(payload)
    print('getSecretValue req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "GetSecretValue", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'GetSecretValue') == False):
        return

    print('GetSecretValue resp:\n%s\n' %(resp.text))
    if ('secretData' in json.loads(resp.text)['result']):
        secretData = json.loads(resp.text)['result']['secretData']
    return secretData

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, secretName, versionId = get_args()
    
    getSecretValue(base_url, secretName, versionId)

