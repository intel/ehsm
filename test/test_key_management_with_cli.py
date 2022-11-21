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
from cli import delete_all_key, deletekey, disablekey, enablekey, enroll, listkey, createkey
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

def test_disableKey(base_url, headers):
    disablekey.disablekey(base_url, keyid)

def test_enableKey(base_url, headers):
    enablekey.enablekey(base_url, keyid)

def test_deleteKey(base_url, headers):
    deletekey.deletekey(base_url, keyid)

def test_deleteAllKey(base_url, headers):
    delete_all_key.delete_all_key(base_url)
    
def test_listKey(base_url, headers):
    createkey.createkey(base_url, "RSA_3072", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1_OAEP", None)
    keylist = listkey.listkey(base_url)

    global keyid 
    keyid = keylist[0]['keyid']

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
     
    test_listKey(base_url, headers)

    test_disableKey(base_url, headers)

    test_enableKey(base_url, headers)

    test_deleteKey(base_url, headers)

    test_deleteAllKey(base_url, headers)
    