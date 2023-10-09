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

supported_keyspec = ["EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096", "EH_SM2"]

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    parser.add_argument('--keyid', type=str, help='the keyid of the asymmetric cmk', required=True)
    parser.add_argument('--keyspec', type=str, help='supported_keyspec = ["EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096", "EH_SM2"]', required=True)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.keyspec

def get_parameters_for_import(base_url, keyid, keyspec):
    print('get parameters for import key')

    payload = OrderedDict()
    payload["keyid"] = keyid
    payload["keyspec"] = keyspec
    params = _utils_.init_params(payload)
    print('get_parameters_for_import req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "GetParametersForImport", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'GetParametersForImport') == False):
        return
    
    print('get parameters for import key resp:\n%s\n' %(resp.text))
    return json.loads(resp.text)['result']['pubkey'] ,json.loads(resp.text)['result']['importToken']

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, keyspec = get_args()

    get_parameters_for_import(base_url, keyid, keyspec)

