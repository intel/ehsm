import requests
import json
import argparse
import base64
import time
import random
import hmac
import os
from hashlib import sha256
from collections import OrderedDict
from cli import createkey, enroll, createSecret, getSecretValue
import urllib.parse
import _utils_
appid= ''
apikey= ''
keyid= ''

def get_appid_apikey(base_url):
    global appid
    global apikey
    appid, apikey = enroll.enroll(base_url)
    _utils_.init_appid_apikey(appid, apikey)

def test_secret_manager(base_url, headers):
    
    print('====================test_secret_manager start===========================')
    key1 = createkey.createkey(base_url, "EH_AES_GCM_128", "EH_INTERNAL_KEY")

    # createSecret with encryptionKeyId
    createSecret.createSecret(base_url, "secretData1", "secret001", key1, "mysecret", "30h")
    # createSecret use default CMK
    createSecret.createSecret(base_url, "secretData2", "secret002", None, "mysecret", "20d")

    # getSecretValue by current version
    secretData1 = getSecretValue.getSecretValue(base_url, "secret001")
    print('check getSecretValue result with %s: %s\n' %('secretData1', secretData1 == 'secretData1'))
    # getSecretValue by versionId
    secretData2 = getSecretValue.getSecretValue(base_url, "secret002", 1)
    print('check getSecretValue result with %s: %s\n' %('secretData2', secretData2 == 'secretData2'))

    print('====================test_secret_manager end===========================')

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server, e.g. http://1.2.3.4:9000', required=True)
    args = parser.parse_args()
    ip = args.url
    return ip
    
if __name__ == "__main__":
    headers = {"Content-Type":"application/json"}

    url = get_args()

    base_url = url + "/ehsm?Action="

    get_appid_apikey(base_url)
    
    test_secret_manager(base_url, headers)


    
