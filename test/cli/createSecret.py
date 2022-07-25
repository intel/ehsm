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
    parser.add_argument('--secretData', type=str, help='the value of the secret to be created', required=True)
    parser.add_argument('--secretName', type=str, help='the name of the secret', required=True)
    parser.add_argument('--encryptionKeyId', type=str, help='The ID of the CMK that is used to encrypt the secret value')
    parser.add_argument('--description', type=str, help='the description of the secret')
    parser.add_argument('--rotationInterval', type=str, help='Automatic rotation interval')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.secretData, args.secretName, args.encryptionKeyId, args.description, args.rotationInterval

def createSecret(base_url, secretData, secretName, encryptionKeyId, description, rotationInterval):
    print('create secret')
    
    payload = OrderedDict()
    payload["description"] = description
    if encryptionKeyId != None:
        payload["encryptionKeyId"] = encryptionKeyId
    payload["rotationInterval"] = rotationInterval
    payload["secretData"] = secretData
    payload["secretName"] = secretName
    params = _utils_.init_params(payload)
    print('create secret req:\n%s\n' %(params))
    
    resp = requests.post(url=base_url + "CreateSecret", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'CreateSecret') == False):
        return
    print('createSecret resp:\n%s\n' %(resp.text))


if __name__ == "__main__":
    headers = _utils_.headers

    base_url, secretData, secretName, encryptionKeyId, description, rotationInterval = get_args()

    createSecret(base_url, secretData, secretName, encryptionKeyId, description, rotationInterval)

