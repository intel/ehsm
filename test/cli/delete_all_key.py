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
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url

def delete_all_key(base_url):
    print('delete all key')

    params = _utils_.init_params()
    print('delete all key req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "DeleteAllKey", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'DeleteALLKey') == False):
        return

    print('delete all key resp:\n%s\n' %(resp.text))

if __name__ == "__main__":
    headers = _utils_.headers

    base_url = get_args()

    delete_all_key(base_url)

