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
from cli import createkey, enroll, createSecret, deletekey, updateSecretDesc, putSecretValue, listSecretVersionIds, listSecrets, describeSecret, deleteSecret, getSecretValue, restoreSecret
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

    # if two createSecret are success, listSecrets will be return totalCount_all == 2
    secretData1 = "secret Data1"
    secretData2 = "secretData2"
    createSecret.createSecret(base_url, "secret001", secretData1, key1, "mysecret", "30h")
    createSecret.createSecret(base_url, "secret002", secretData2, None, "mysecret", "20d")
    newSecretDesc = "myNewSecret"
    updateSecretDesc.updateSecretDesc(base_url, "secret001", newSecretDesc)

    # if putSecrectValue success, listSecretVersionIds will be return totalCount_version == 2
    putValue = "putSecret01"
    putSecretValue.putSecrectValue(base_url, "secret001", putValue)

    totalCount_version = listSecretVersionIds.listSecretVersionIds(base_url, "secret001")
    print('SecretManagerTest :: Check listSecretVersionIds result with %s: %s\n' %('totalCount', totalCount_version == 2))

    totalCount_all = listSecrets.listSecrets(base_url)
    print('SecretManagerTest :: Check listSecrets result with %s: %s\n' %('All', totalCount_all == 2))

    totalCount_one = listSecrets.listSecrets(base_url, "secret001")
    print('SecretManagerTest :: Check listSecrets result with %s: %s\n' %('One', totalCount_one == 1))

    describeSecret_description = describeSecret.describeSecret(base_url, "secret001")
    print('SecretManagerTest :: Check describeSecret result with %s: %s\n' %('description', describeSecret_description == newSecretDesc))

    # if deleteSecret success, getSecretValue will be return getSV_secretData2 == None
    deleteSecret.deleteSecret(base_url, "secret002", 10, "False")
    # getSecretValue by current version
    getSV_secretData1 = getSecretValue.getSecretValue(base_url, "secret001")
    print('SecretManagerTest :: Check getSecretValue result with %s: %s\n' %('putSecret01', getSV_secretData1 == putValue))
    # getSecretValue by versionId
    getSV_secretData3 = getSecretValue.getSecretValue(base_url, "secret001", 1)
    print('SecretManagerTest :: Check getSecretValue result with %s: %s\n' %('secretData1', getSV_secretData3 == secretData1))
    # getSecretValue by a delete secret
    getSV_secretData2 = getSecretValue.getSecretValue(base_url, "secret002")
    print('SecretManagerTest :: Check getSecretValue result with %s: %s\n' %('secretData2', getSV_secretData2 == None))

    restoreSecret.restoreSecret(base_url, 'secret002')
    getSV_secretData2 = getSecretValue.getSecretValue(base_url, "secret002")
    print('SecretManagerTest :: Check restoreSecret result with %s: %s\n' %('secretData2', getSV_secretData2 == secretData2))

    deleteSecret.deleteSecret(base_url, "secret001", None, "true")
    deleteSecret.deleteSecret(base_url, "secret002", None, "true")
    totalCount_all = listSecrets.listSecrets(base_url)
    print('SecretManagerTest :: Check deleteSecret result with %s: %s\n' %('All', totalCount_all == 0))

    # remove cmk
    deletekey.deletekey(base_url, key1)

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
