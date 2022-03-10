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
appid= '468c507a-da1f-4127-9cd0-82f0e7ce247e'
apikey= 'Merh0HrKuc2e8ECt5qba5dhy0ykyp1Js'
keyid= ''

def test_disableKey(base_url, headers):
    payload = OrderedDict()
    payload["keyid"] = keyid
    params=test_params(payload)
    print('DisableKey req:\n%s\n' %(params))
    disableKey_resp = requests.post(url=base_url + "DisableKey", data=json.dumps(params), headers=headers)
    if(check_result(disableKey_resp, 'DisableKey', 'test_disableKey') == False):
        return
    print('DisableKey resp:\n%s\n' %(disableKey_resp.text))

def test_enableKey(base_url, headers):
    payload = OrderedDict()
    payload["keyid"] = keyid
    params=test_params(payload)
    print('EnableKey req:\n%s\n' %(params))
    enableKey_resp = requests.post(url=base_url + "EnableKey", data=json.dumps(params), headers=headers)
    if(check_result(enableKey_resp, 'EnableKey', 'test_enableKey') == False):
        return
    print('EnableKey resp:\n%s\n' %(enableKey_resp.text))

def test_deleteKey(base_url, headers):
    payload = OrderedDict()
    payload["keyid"] = keyid
    params=test_params(payload)
    print('DeleteKey req:\n%s\n' %(params))
    deleteKey_resp = requests.post(url=base_url + "DeleteKey", data=json.dumps(params), headers=headers)
    if(check_result(deleteKey_resp, 'DeleteKey', 'test_deleteKey') == False):
        return
    print('DeleteKey resp:\n%s\n' %(deleteKey_resp.text))

def test_deleteAllKey(base_url, headers):
    params=test_params(False)
    print('DeleteAllKey req:\n%s\n' %(params))
    deleteAllKey_resp = requests.post(url=base_url + "DeleteAllKey", data=json.dumps(params), headers=headers)
    if(check_result(deleteAllKey_resp, 'DeleteAllKey', 'test_deleteAllKey') == False):
        return
    print('DeleteAllKey resp:\n%s\n' %(deleteAllKey_resp.text))
    
def test_listKey(base_url, headers):
    params=test_params(False)
    print('ListKey req:\n%s\n' %(params))
    listKey_resp = requests.post(url=base_url + "ListKey", data=json.dumps(params), headers=headers)
    if(check_result(listKey_resp, 'ListKey', 'test_listKey') == False):
        return
    print('ListKey resp: \n%s\n' %(listKey_resp.text))

    global keyid 
    keyid = json.loads(listKey_resp.text)['result']['list'][0]['keyid']

def test_params(payload):
    params = OrderedDict()
    params["appid"] = appid
    if payload!=False:
        ord_payload = OrderedDict(sorted(payload.items(), key=lambda k: k[0]))
        params["payload"] = urllib.parse.unquote(urllib.parse.urlencode(ord_payload))
    params["timestamp"] = str(int(time.time() * 1000))
    sign_string = urllib.parse.unquote(urllib.parse.urlencode(params))
    print(sign_string.encode('utf-8'))
    print(apikey.encode('utf-8'))
    sign = str(base64.b64encode(hmac.new(apikey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8')
    if payload!=False:
        params["payload"] = payload
    params["sign"] = sign
    return params
    
def test_export_datakey(base_url, headers):
    print('====================test_export_datakey start===========================')
    payload = OrderedDict()
    payload["keyspec"] = "EH_AES_GCM_128"
    payload["origin"] = "EH_INTERNAL_KEY"
    params=test_params(payload)
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    if(check_result(create_resp, 'CreateKey', 'test_export_datakey') == False):
        return
    print('CreateKey resp(EH_AES_GCM_128):\n%s\n' %(create_resp.text))

    payload.clear()
    payload["keyspec"] = "EH_RSA_3072"
    payload["origin"] = "EH_INTERNAL_KEY"
    params=test_params(payload)
    print('CreateKey req:\n%s\n' %(params))
    create_ukey_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    if(check_result(create_ukey_resp, 'CreateKey', 'test_export_datakey') == False):
        return
    print('CreateKey resp(EH_RSA_3072):\n%s\n' %(create_ukey_resp.text))

    payload.clear()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    payload["keylen"] = 48
    params=test_params(payload)
    print('GenerateDataKeyWithoutPlaintext req:\n%s\n' %(params))
    generateDataKeyWithoutPlaintext_resp = requests.post(url=base_url + "GenerateDataKeyWithoutPlaintext", data=json.dumps(params), headers=headers)
    if(check_result(generateDataKeyWithoutPlaintext_resp, 'GenerateDataKeyWithoutPlaintext', 'test_export_datakey') == False):
        return
    print('GenerateDataKeyWithoutPlaintext resp:\n%s\n' %(generateDataKeyWithoutPlaintext_resp.text))

    # test ExportDataKey
    payload.clear()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    payload["olddatakey_base"] = json.loads(generateDataKeyWithoutPlaintext_resp.text)['result']['ciphertext']
    payload["ukeyid"] = json.loads(create_ukey_resp.text)['result']['keyid']
    params=test_params(payload)
    print('ExportDataKey req:\n%s\n' %(params))
    exportDataKey_resp = requests.post(url=base_url + "ExportDataKey", data=json.dumps(params), headers=headers)
    if(check_result(exportDataKey_resp, 'ExportDataKey', 'test_export_datakey') == False):
        return
    print('ExportDataKey resp:\n%s\n' %(exportDataKey_resp.text))

    print('====================test_export_datakey end===========================')

def test_RSA3072_encrypt_decrypt(base_url, headers):
    print('====================test_RSA3072_encrypt_decrypt start===========================')
    payload = OrderedDict()
    payload["keyspec"] = "EH_RSA_3072"
    payload["origin"] = "EH_INTERNAL_KEY"
    params=test_params(payload)
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    if(check_result(create_resp, 'CreateKey', 'test_RSA3072_encrypt_decrypt') == False):
        return
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test AsymmetricEncrypt("123456")
    payload.clear()
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    payload["plaintext"] = str(base64.b64encode("123456".encode("utf-8")),'utf-8')
    params=test_params(payload)
    print('AsymmetricEncrypt req:\n%s\n' %(params))
    asymmetricEncrypt_resp = requests.post(url=base_url + "AsymmetricEncrypt", data=json.dumps(params), headers=headers)
    if(check_result(asymmetricEncrypt_resp, 'AsymmetricEncrypt', 'test_RSA3072_encrypt_decrypt') == False):
        return
    print('AsymmetricEncrypt resp:\n%s\n' %(asymmetricEncrypt_resp.text))

    # test AsymmetricDecrypt(ciphertext)
    payload.clear()
    payload["ciphertext"] = json.loads(asymmetricEncrypt_resp.text)['result']['ciphertext']
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    params=test_params(payload)
    print('AsymmetricDecrypt req:\n%s\n' %(params))
    asymmetricDecrypt_resp = requests.post(url=base_url + "AsymmetricDecrypt", data=json.dumps(params), headers=headers)
    if(check_result(asymmetricDecrypt_resp, 'AsymmetricDecrypt', 'test_RSA3072_encrypt_decrypt') == False):
        return
    print('AsymmetricDecrypt resp:\n%s\n' %(asymmetricDecrypt_resp.text))

    plaintext = str(base64.b64decode(json.loads(asymmetricDecrypt_resp.text)['result']['plaintext']), 'utf-8').strip(b"\x00".decode())
    print('AsymmetricDecrypt plaintext:\n%s\n' %(plaintext))
    print('====================test_RSA3072_encrypt_decrypt end===========================')

def test_Stest_RSA3072_sign_verify(base_url, headers):
    print('====================test_Stest_RSA3072_sign_verify start===========================')
    payload = OrderedDict()
    payload["keyspec"] = "EH_RSA_3072"
    payload["origin"] = "EH_INTERNAL_KEY"
    params=test_params(payload)
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    if(check_result(create_resp, 'CreateKey', 'test_Stest_RSA3072_sign_verify') == False):
        return
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test Sign
    payload.clear()
    payload["digest"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    params=test_params(payload)
    print('Sign req:\n%s\n' %(params))
    sign_resp = requests.post(url=base_url + "Sign", data=json.dumps(params), headers=headers)
    if(check_result(sign_resp, 'Sign', 'test_Stest_RSA3072_sign_verify') == False):
        return
    print('Sign resp:\n%s\n' %(sign_resp.text))

    # test Verify
    payload.clear()
    payload["digest"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    payload["signature"] = json.loads(sign_resp.text)['result']['signature']
    params=test_params(payload)
    print('Verify req:\n%s\n' %(params))
    verify_resp = requests.post(url=base_url + "Verify", data=json.dumps(params), headers=headers)
    if(check_result(verify_resp, 'Verify', 'test_Stest_RSA3072_sign_verify') == False):
        return
    print('Verify resp:\n%s\n' %(verify_resp.text))

    print('====================test_Stest_RSA3072_sign_verify end===========================')

def test_GenerateDataKeyWithoutPlaintext(base_url, headers):
    print('====================test_GenerateDataKeyWithoutPlaintext start===========================')
    payload = OrderedDict()
    payload["keyspec"] = "EH_AES_GCM_128"
    payload["origin"] = "EH_INTERNAL_KEY"
    params=test_params(payload)
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    if(check_result(create_resp, 'CreateKey', 'test_GenerateDataKeyWithoutPlaintext') == False):
        return
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test GenerateDataKeyWithoutPlaintext
    payload.clear()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    payload["keylen"] = 48
    params=test_params(payload)
    print('GenerateDataKeyWithoutPlaintext req:\n%s\n' %(params))
    generateDataKeyWithoutPlaintext_resp = requests.post(url=base_url + "GenerateDataKeyWithoutPlaintext", data=json.dumps(params), headers=headers)
    if(check_result(generateDataKeyWithoutPlaintext_resp, 'GenerateDataKeyWithoutPlaintext', 'test_GenerateDataKeyWithoutPlaintext') == False):
        return
    print('GenerateDataKeyWithoutPlaintext resp:\n%s\n' %(generateDataKeyWithoutPlaintext_resp.text))

    # test Decrypt(cipher_datakey)
    payload.clear()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["ciphertext"] = json.loads(generateDataKeyWithoutPlaintext_resp.text)['result']['ciphertext']
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    params=test_params(payload)
    print('Decrypt req:\n%s\n' %(params))
    decrypt_resp = requests.post(url=base_url + "Decrypt", data=json.dumps(params), headers=headers)
    if(check_result(decrypt_resp, 'Decrypt', 'test_GenerateDataKeyWithoutPlaintext') == False):
        return
    print('Decrypt resp:\n%s\n' %(decrypt_resp.text))

    print('====================test_GenerateDataKeyWithoutPlaintext end===========================')

def test_GenerateDataKey(base_url, headers):
    print('====================test_GenerateDataKey start===========================')
    payload = OrderedDict()
    payload["keyspec"] = "EH_AES_GCM_128"
    payload["origin"] = "EH_INTERNAL_KEY"
    params=test_params(payload)
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    if(check_result(create_resp, 'CreateKey', 'test_GenerateDataKey') == False):
        return
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test GenerateDataKey
    payload.clear()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    payload["keylen"] = 16
    params=test_params(payload)
    print('GenerateDataKey req:\n%s\n' %(params))
    generatedatakey_resp = requests.post(url=base_url + "GenerateDataKey", data=json.dumps(params), headers=headers)
    if(check_result(generatedatakey_resp, 'GenerateDataKey', 'test_GenerateDataKey') == False):
        return
    print('GenerateDataKey resp:\n%s\n' %(generatedatakey_resp.text))

    # test Decrypt(cipher_datakey)
    payload.clear()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["ciphertext"] = json.loads(generatedatakey_resp.text)['result']['ciphertext']
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    params=test_params(payload)
    print('Decrypt req:\n%s\n' %(params))
    decrypt_resp = requests.post(url=base_url + "Decrypt", data=json.dumps(params), headers=headers)
    if(check_result(decrypt_resp, 'Decrypt', 'test_GenerateDataKey') == False):
        return
    print('Decrypt resp:\n%s\n' %(decrypt_resp.text))

    print('====================test_GenerateDataKey end===========================')

def test_AES128(base_url, headers):
    print('====================test_AES128 start===========================')
    payload = OrderedDict()
    payload["keyspec"] = "EH_AES_GCM_128"
    payload["origin"] = "EH_INTERNAL_KEY"
    params=test_params(payload)
    print('CreateKey req:\n%s\n' %(params))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    if(check_result(create_resp, 'CreateKey', 'test_AES128') == False):
        return
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test Encrypt("123456")
    payload.clear()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    payload["plaintext"] = str(base64.b64encode("123456".encode("utf-8")),'utf-8')
    params=test_params(payload)
    print('Encrypt req:\n%s\n' %(params))
    encrypt_resp = requests.post(url=base_url + "Encrypt", data=json.dumps(params), headers=headers)
    if(check_result(encrypt_resp, 'Encrypt', 'test_AES128') == False):
        return
    print('Encrypt resp:\n%s\n' %(encrypt_resp.text))

    # test Decrypt(ciphertext)
    payload.clear()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["ciphertext"] = json.loads(encrypt_resp.text)['result']['ciphertext']
    payload["keyid"] = json.loads(create_resp.text)['result']['keyid']
    params=test_params(payload)
    print('Decrypt req:\n%s\n' %(params))
    decrypt_resp = requests.post(url=base_url + "Decrypt", data=json.dumps(params), headers=headers)
    if(check_result(decrypt_resp, 'Decrypt', 'test_AES128') == False):
        return
    print('Decrypt resp:\n%s\n' %(decrypt_resp.text))
    
    plaintext = str(base64.b64decode(json.loads(decrypt_resp.text)['result']['plaintext']), 'utf-8')
    print('Decrypt plaintext:\n%s\n' %(plaintext))
    print('check Decrypt plaintext result with %s: %s\n' %('123456', plaintext == '123456'))

    print('====================test_AES128 end===========================')

# A hook function forst JSON load function that avoid
# bool type value changing from "true" to "True".It will be caused the sign verfiy error
def no_bool_convert(pairs):
  return {k: str(v).casefold() if isinstance(v, bool) else v for k, v in pairs}

def test_GenerateQuote_and_VerifyQuote(base_url, headers):
    print('====================test_GenerateQuote_and_VerifyQuote start===========================')
    payload = OrderedDict()
    payload["challenge"] = "challenge123456"
    params=test_params(payload)
    print('GenerateQuote req:\n%s\n' %(params))
    GenerateQuote_resp = requests.post(url=base_url + "GenerateQuote", data=json.dumps(params), headers=headers)
    if(check_result(GenerateQuote_resp, 'GenerateQuote', 'test_GenerateQuote_and_VerifyQuote') == False):
        return
    print('GenerateQuote resp:\n%s\n' %(GenerateQuote_resp.text))

    payload.clear()
    payload["quote"] = json.loads(GenerateQuote_resp.text)['result']['quote']
    payload["nonce"] = "nonce12345"
    params=test_params(payload)
    print('VerifyQuote req:\n%s\n' %(params))
    VerifyQuote_resp = requests.post(url=base_url + "VerifyQuote", data=json.dumps(params), headers=headers)
    if(check_result(VerifyQuote_resp, 'VerifyQuote', 'test_GenerateQuote_and_VerifyQuote') == False):
        return
    print('VerifyQuote resp:\n%s\n' %(VerifyQuote_resp.text))
    VerifyQuote_Result = json.loads(VerifyQuote_resp.text, object_pairs_hook=no_bool_convert)['result']
    hmac_sign = VerifyQuote_Result['sign']

    VerifyQuote_Result.pop('sign')
    ord_VerifyQuote_Result = OrderedDict(sorted(VerifyQuote_Result.items(), key=lambda k: k[0]))
    sign_string = urllib.parse.unquote(urllib.parse.urlencode(ord_VerifyQuote_Result))
    sign = str(base64.b64encode(hmac.new(apikey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8')
    print('check HMAC sign result with %s: %s\n' %(sign, hmac_sign == sign))

    print('====================test_GenerateQuote_and_VerifyQuote end===========================')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip-adress', type=str, help='ip address of the ehsm_kms_server', required=True)
    parser.add_argument('-p', '--port', type=str, help='port of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    ip = args.ip_adress
    port = args.port
    return ip, port
    
def check_result(res, action, test_name):
    res_json = json.loads(res.text)
    if(res_json['code'] == 200):
        print("%s successfully \n" %(action))
        return True
    else:
        print("%s failed, error message: %s \n" %(action, res_json["message"]))
        print('====================%s end===========================' %(test_name))
        return False
if __name__ == "__main__":
    headers = {"Content-Type":"application/json"}

    ip,port = get_args()

    base_url = "http://" + ip + ":" + port + "/ehsm?Action="

    test_AES128(base_url, headers)

    test_GenerateDataKey(base_url, headers)

    test_GenerateDataKeyWithoutPlaintext(base_url, headers)

    test_Stest_RSA3072_sign_verify(base_url, headers)

    test_RSA3072_encrypt_decrypt(base_url, headers)

    test_export_datakey(base_url, headers)

    test_listKey(base_url, headers)

    test_disableKey(base_url, headers)

    test_enableKey(base_url, headers)

    test_deleteKey(base_url, headers)

    test_deleteAllKey(base_url, headers)

    test_GenerateQuote_and_VerifyQuote(base_url, headers)
