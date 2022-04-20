import requests
import json
import argparse
import base64
import time
import random
import hmac
from hashlib import sha256
from collections import OrderedDict
import createkey, encrypt, decrypt
import urllib.parse

import _utils_


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    parser.add_argument('--name', type=str, help='the name of the secret', required=True)
    parser.add_argument('--data', type=str, help='the secret need to store')
    parser.add_argument('--version', type=str, help='the version of the secret')
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.name, args.data, args.version

def PutSecretValue(base_url, name, secret, version):

    with open('secret_DB', 'r') as f:
        for row in f.readlines():
            row = json.loads(row)
            if row['appid'] == _utils_.appid and row['name'] == name:
                break

    if row['name'] != name:
        print("not found this secret")
        return
    get_secret = decrypt.decrypt(base_url, row["cmkid"], row['ciphertext'], None)
    if get_secret != secret:
        print("secret not same")
        return
    if version == row["version"]:
        print("success")
        return

    key = row['cmkid']
    print('create secret with secret %s' %(secret))

    encodesecret = str(base64.b64encode(secret.encode("utf-8")), 'utf-8')
    ciphertext = encrypt.encrypt(base_url, key, encodesecret, None)

    f =open("secret_DB", 'r')
    secrets = f.readlines()

    f =open('secret_DB', 'w')
    for row in secrets:
        rowj  = json.loads(row)
        if rowj['appid'] == _utils_.appid and rowj['name'] == name:
            jsonfile = {"appid": _utils_.appid, 'name': name, 'cmkid': key, 'ciphertext': ciphertext, 'version': version}
            f.write(str(jsonfile).replace('\'', '\"'))
            f.write('\n')
            #f.write(row) #control whether old data still in DB
        else:
            f.write(row)

    print("put secret %s into DB" %(jsonfile))
    f.close()

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, name, secret, version = get_args()

    PutSecretValue(base_url, name, secret, version)

