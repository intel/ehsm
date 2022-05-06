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
    parser.add_argument('--keyid', type=str, help='the old keyid of symmetric cmk', required=True)
    parser.add_argument('--ukeyid', type=str, help='the new keyid of asymmetric cmk', required=True)
    parser.add_argument('--datakey', type=str, help='the ciphertext of datakey', required=True)
    parser.add_argument('--aad', type=str, help='the aad data that want to provide, could be null')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.ukeyid, args.datakey, args.aad

def export_datakey(base_url, keyid, ukeyid, datakey, aad):
    payload = OrderedDict()
    if aad is not None:
        payload["aad"] = aad
    payload["keyid"] = keyid
    payload["olddatakey_base"] = datakey
    payload["ukeyid"] = ukeyid
    params = _utils_.init_params(payload)
    print('export_datakey req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "ExportDataKey", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'ExportDataKey') == False):
        return

    print('export_datakey resp:\n%s\n' %(resp.text))

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, ukeyid, datakey, aad = get_args()

    export_datakey(base_url, keyid, ukeyid, datakey, aad)

