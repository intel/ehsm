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

def listkey(base_url):
    print('list key')

    params = _utils_.init_params()
    print('list key req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "ListKey", data=json.dumps(params), headers=_utils_.headers)
    if(_utils_.check_result(resp, 'ListKey') == False):
        return

    print('listkey resp:\n%s\n' %(resp.text))

if __name__ == "__main__":
    headers = _utils_.headers

    base_url = get_args()

    listkey(base_url)

