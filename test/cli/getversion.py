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

def getversion(base_url):
    print('get version')


    resp = requests.get(url=base_url + "GetVersion", headers=_utils_.headers)
    if(_utils_.check_result(resp, 'GetVersion') == False):
        return

    print('getversion resp:\n%s\n' %(resp.text))

if __name__ == "__main__":
    headers = _utils_.headers

    base_url = get_args()

    getversion(base_url)

