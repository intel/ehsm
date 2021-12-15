import requests
import json
import argparse
import base64
import time
import random
import hmac
from hashlib import sha256
import os
from collections import OrderedDict
import urllib.parse

appid = '202112101919'
appkey = '202112345678'

def test_params(payload):
    params = OrderedDict()

    params["appid"] = appid
    params["nonce"] = str(int.from_bytes(os.urandom(16), "big"))
    params["timestamp"] = int(time.time())

    query_string = urllib.parse.urlencode(params)
    query_string += '&app_key=' + appkey
    sign = str(base64.b64encode(hmac.new(appkey.encode('utf-8'), query_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8')

    params["sign"] = sign
    params["payload"] = payload
    return params

def test_RSA3072_encrypt_decrypt(base_url, headers):

    print('====================test_RSA3072_encrypt_decrypt start===========================')
    params=test_params({
            "keyspec":"EH_RSA_3072",
            "origin":"EH_INTERNAL_KEY"
        })
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test AsymmetricEncrypt("123456")
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "plaintext":"123456"
        })
    print('AsymmetricEncrypt req:\n%s\n' %(params))
    asymmetricEncrypt_resp = requests.post(url=base_url + "AsymmetricEncrypt", data=json.dumps(params), headers=headers)
    print('AsymmetricEncrypt resp:\n%s\n' %(asymmetricEncrypt_resp.text))

    # test AsymmetricDecrypt(ciphertext)
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "ciphertext_base64":json.loads(asymmetricEncrypt_resp.text)['result']['ciphertext_base64']
        })
    print('AsymmetricDecrypt req:\n%s\n' %(params))
    asymmetricDecrypt_res = requests.post(url=base_url + "AsymmetricDecrypt", data=json.dumps(params), headers=headers)
    print('AsymmetricDecrypt resp:\n%s\n' %(asymmetricDecrypt_res.text))
    plaintext = str(base64.b64decode(json.loads(asymmetricDecrypt_res.text)['result']['plaintext_base64']), 'utf-8')
    print('AsymmetricDecrypt plaintext:\n%s\n' %(plaintext))
    print('====================test_RSA3072_encrypt_decrypt end===========================')

def test_Stest_RSA3072_sign_verify(base_url, headers):
    print('====================test_Stest_RSA3072_sign_verify start===========================')
    params=test_params({
            "keyspec":"EH_RSA_3072",
            "origin":"EH_INTERNAL_KEY"
        })
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test Sign
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "digest":"test"
        })
    print('Sign req:\n%s\n' %(params))
    sign_resp = requests.post(url=base_url + "Sign", data=json.dumps(params), headers=headers)
    print('Sign resp:\n%s\n' %(sign_resp.text))

    # test Verify
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "digest":"test",
            "signature_base64":json.loads(sign_resp.text)['result']['signature_base64'],
        })
    print('Verify req:\n%s\n' %(params))
    verify_resp = requests.post(url=base_url + "Verify", data=json.dumps(params), headers=headers)
    print('Verify resp:\n%s\n' %(verify_resp.text))

    print('====================test_Stest_RSA3072_sign_verify end===========================')

def test_GenerateDataKeyWithoutPlaintext(base_url, headers):
    print('====================test_GenerateDataKeyWithoutPlaintext start===========================')
    params=test_params({
            "keyspec":"EH_AES_GCM_128",
            "origin":"EH_INTERNAL_KEY"
        })
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test GenerateDataKey
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "keylen": 16,
            "aad": "test",
        })
    print('GenerateDataKeyWithoutPlaintext req:\n%s\n' %(params))
    generateDataKeyWithoutPlaintext_resp = requests.post(url=base_url + "GenerateDataKeyWithoutPlaintext", data=json.dumps(params), headers=headers)
    print('GenerateDataKeyWithoutPlaintext resp:\n%s\n' %(generateDataKeyWithoutPlaintext_resp.text))

    # test Decrypt(cipher_datakey)
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "ciphertext":json.loads(generateDataKeyWithoutPlaintext_resp.text)['result']['ciphertext_base64'],
            "aad":"test",
        })
    print('Decrypt req:\n%s\n' %(params))
    decrypt_res = requests.post(url=base_url + "Decrypt", data=json.dumps(params), headers=headers)
    print('Decrypt resp:\n%s\n' %(decrypt_res.text))

    print('====================test_GenerateDataKeyWithoutPlaintext end===========================')

def test_GenerateDataKey(base_url, headers):
    print('====================test_GenerateDataKey start===========================')
    params=test_params({
            "keyspec":"EH_AES_GCM_128",
            "origin":"EH_INTERNAL_KEY"
        })
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test GenerateDataKey
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "keylen": 16,
            "aad": "test",
        })
    print('GenerateDataKey req:\n%s\n' %(params))
    generatedatakey_resp = requests.post(url=base_url + "GenerateDataKey", data=json.dumps(params), headers=headers)
    print('GenerateDataKey resp:\n%s\n' %(generatedatakey_resp.text))

    # test Decrypt(cipher_datakey)
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "ciphertext":json.loads(generatedatakey_resp.text)['result']['ciphertext_base64'],
            "aad":"test",
        })
    print('Decrypt req:\n%s\n' %(params))
    decrypt_res = requests.post(url=base_url + "Decrypt", data=json.dumps(params), headers=headers)
    print('Decrypt resp:\n%s\n' %(decrypt_res.text))

    print('====================test_GenerateDataKey end===========================')

def test_AES128(base_url, headers):

    print('====================test_AES128 start===========================')
    params=test_params({
            "keyspec":"EH_AES_GCM_128",
            "origin":"EH_INTERNAL_KEY"
        })
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test Encrypt("123456")
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "plaintext":"123456",
            "aad":"test"
        })
    print('Encrypt req:\n%s\n' %(params))
    encrypt_resp = requests.post(url=base_url + "Encrypt", data=json.dumps(params), headers=headers)
    print('Encrypt resp:\n%s\n' %(encrypt_resp.text))

    # test Decrypt(ciphertext)
    params=test_params({
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "ciphertext":json.loads(encrypt_resp.text)['result']['ciphertext_base64'],
            "aad":"test",
        })
    print('Decrypt req:\n%s\n' %(params))
    decrypt_res = requests.post(url=base_url + "Decrypt", data=json.dumps(params), headers=headers)
    print('Decrypt resp:\n%s\n' %(decrypt_res.text))
    plaintext = str(base64.b64decode(json.loads(decrypt_res.text)['result']['plaintext_base64']), 'utf-8')
    print('Decrypt plaintext:\n%s\n' %(plaintext))
    print('====================test_AES128 end===========================')

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip-adress', type=str, help='ip address of the ehsm_kms_server', required=True)
    parser.add_argument('-p', '--port', type=str, help='port of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    ip = args.ip_adress
    port = args.port
    return ip, port

if __name__ == "__main__":
    headers = {"Content-Type":"application/json"}

    ip,port = get_args()

    base_url = "http://" + ip + ":" + port + "/ehsm?Action="
    #print(base_url)

    test_AES128(base_url, headers)

    test_GenerateDataKey(base_url, headers)

    test_GenerateDataKeyWithoutPlaintext(base_url, headers)

    test_Stest_RSA3072_sign_verify(base_url, headers)

    test_RSA3072_encrypt_decrypt(base_url, headers)