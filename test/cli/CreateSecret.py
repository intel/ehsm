import requests
import json
import argparse
import base64
import time
import random
import hmac
from hashlib import sha256
from collections import OrderedDict
import createkey, encrypt
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

def CreateSecret(base_url, name, secret, version):
    key = createkey.createkey(base_url, "EH_AES_GCM_128", "EH_INTERNAL_KEY")
    print('create secret with secret %s' %(secret))

    encodesecret = str(base64.b64encode(secret.encode("utf-8")), 'utf-8')
    ciphertext = encrypt.encrypt(base_url, key, encodesecret, None)


    #payload = OrderedDict()
    #payload["name"] = name
    #params = _utils_.init_params(payload)
    #sign = params["sign"]
    #print(sign)
    #if signature != sign:
    #    return
    #print('createsecret req:\n%s\n' %(params))

    jsonfile = {"appid": _utils_.appid, 'name': name, 'cmkid': key, 'ciphertext': ciphertext, 'version': version}
    f = open("secret_DB", "a")
    
    json.dump(jsonfile, f)
    f.write("\n")
    print("write secret %s into DB" %(jsonfile))
    f.close()

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, name, secret, version = get_args()

    CreateSecret(base_url, name, secret, version)

