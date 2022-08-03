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
    parser.add_argument('--recoveryPeriod', type=str, help='Specifies the recovery period of the secret if you do not forcibly delete it')
    parser.add_argument('--forceDelete', type=str, help='Specifies whether to forcibly delete the secret')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.secretName, args.recoveryPeriod, args.forceDelete

def deleteSecret(base_url, secretName, recoveryPeriod = None, forceDelete = None):
    print('delete secret')
    
    payload = OrderedDict()
    if forceDelete != None:
        payload["forceDelete"] = forceDelete
    if recoveryPeriod != None:
        payload["recoveryPeriod"] = recoveryPeriod
    payload["secretName"] = secretName
    params = _utils_.init_params(payload)
    print('update Secret req:\n%s\n' %(params))
    
    resp = requests.post(url=base_url + "DeleteSecret", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'DeleteSecret') == False):
        return
    print('deleteSecret resp:\n%s\n' %(resp.text))


if __name__ == "__main__":
    headers = _utils_.headers

    base_url, secretName, recoveryPeriod, forceDelete = get_args()

    deleteSecret(base_url, secretName, recoveryPeriod, forceDelete)

