import requests
import json
import argparse
import base64
import time
import random
import hmac
from hashlib import sha256
from collections import OrderedDict
import decrypt
import urllib.parse

import _utils_

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    parser.add_argument('--name', type=str, help='the name of the secret', required=True)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.name

def get_secret_value(base_url, name):
    with open('secret_DB', 'r') as f:
        for row in f.readlines():
            row = json.loads(row)
            if row['appid'] == _utils_.appid and row['name'] == name:
                break

    ciphersecret = row["ciphertext"]

    secret = decrypt.decrypt(base_url, row["cmkid"], ciphersecret, None)
    print(secret)

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, name = get_args()

    get_secret_value(base_url, name)

