import requests
import json
import argparse
import base64
import time
import random
import hmac
import re

from hashlib import sha256
from collections import OrderedDict
import urllib.parse

import _utils_



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url

def enroll(base_url):
    requrl = base_url + "Enroll"
    print(requrl)
    resp = requests.get(url=requrl, verify=_utils_.use_secure_cert, headers=_utils_.headers)
    if(_utils_.check_result(resp, 'Enroll') == False):
        return

    print('Enroll resp:\n%s\n' %(resp.text))


    with open('_utils_.py', 'r') as f:
        content = f.read()

    appid = json.loads(resp.text)['result']['appid']
    apikey = json.loads(resp.text)['result']['apikey']

    content = re.sub(r"appid='[^']+'", f"appid='{appid}'", content)
    content = re.sub(r"apikey='[^']+'", f"apikey='{apikey}'", content)

    with open('_utils_.py', 'w') as f:
        f.write(content)

    return appid, apikey

if __name__ == "__main__":
    headers = _utils_.headers

    base_url = get_args()

    enroll(base_url)

