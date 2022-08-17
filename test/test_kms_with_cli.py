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
from cli import createkey, asymmetric_decrypt, asymmetric_encrypt, decrypt, delete_all_key, deletekey, disablekey, enablekey, encrypt, export_datakey, generate_datakey, generate_datakey_withoutplaint, generate_quote, getversion, listkey, sign, verify, verify_quote, enroll, uploadQuotePolicy, getQuotePolicy
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
    keylist = listkey.listkey(base_url)

    global keyid 
    keyid = keylist[0]['keyid']

    
def test_export_datakey(base_url, headers):
    print('====================test_export_datakey start===========================')
    key1 = createkey.createkey(base_url, "EH_AES_GCM_128", "EH_INTERNAL_KEY")

    key2 = createkey.createkey(base_url, "EH_RSA_3072", "EH_INTERNAL_KEY")

    aad = str(base64.b64encode("test".encode("utf-8")),'utf-8')

    ciphertext = generate_datakey_withoutplaint.generate_datakey_withoutplaint(base_url, key1, 48, aad)

    # test ExportDataKey
    export_datakey.export_datakey(base_url, key1, key2, ciphertext, aad)

    print('====================test_export_datakey end===========================')

def test_RSA3072_encrypt_decrypt(base_url, headers):
    print('====================test_RSA3072_encrypt_decrypt start===========================')
    key = createkey.createkey(base_url, "EH_RSA_3072", "EH_INTERNAL_KEY")

    # test AsymmetricEncrypt("123456")
    ciphertext = asymmetric_encrypt.asymmetric_encrypt(base_url, key, str(base64.b64encode("123456".encode("utf-8")), 'utf-8'))

    # test AsymmetricDecrypt(ciphertext)
    resp_plaintext = asymmetric_decrypt.asymmetric_decrypt(base_url, key, ciphertext)

    plaintext = str(base64.b64decode(resp_plaintext), 'utf-8').strip(b"\x00".decode())
    print('AsymmetricDecrypt plaintext:\n%s\n' %(plaintext))
    print('====================test_RSA3072_encrypt_decrypt end===========================')

def test_Stest_RSA3072_sign_verify(base_url, headers):
    print('====================test_Stest_RSA3072_sign_verify start===========================')
    key = createkey.createkey(base_url, "EH_RSA_3072", "EH_INTERNAL_KEY")

    # test Sign
    signature = sign.sign(base_url, key, str(base64.b64encode("test".encode("utf-8")),'utf-8'))

    # test Verify
    verify.verify(base_url, key, str(base64.b64encode("test".encode("utf-8")),'utf-8'), signature)

    print('====================test_Stest_RSA3072_sign_verify end===========================')

def test_GenerateDataKeyWithoutPlaintext(base_url, headers):
    print('====================test_GenerateDataKeyWithoutPlaintext start===========================')
    key = createkey.createkey(base_url, "EH_AES_GCM_128", "EH_INTERNAL_KEY")

    # test GenerateDataKeyWithoutPlaintext
    aad = str(base64.b64encode("test".encode("utf-8")),'utf-8')

    ciphertext = generate_datakey_withoutplaint.generate_datakey_withoutplaint(base_url, key, 48, aad)

    # test Decrypt(cipher_datakey)
    decrypt.decrypt(base_url, key, ciphertext, aad)

    print('====================test_GenerateDataKeyWithoutPlaintext end===========================')

def test_GenerateDataKey(base_url, headers):
    print('====================test_GenerateDataKey start===========================')
    key = createkey.createkey(base_url, "EH_AES_GCM_128", "EH_INTERNAL_KEY")
    
    # test GenerateDataKey
    aad = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    ciphertext = generate_datakey.generate_datakey(base_url, key, 16, aad)

    # test Decrypt(cipher_datakey)
    decrypt.decrypt(base_url, key, ciphertext, aad)

    print('====================test_GenerateDataKey end===========================')

def test_AES128(base_url, headers):
    print('====================test_AES128 start===========================')
    key = createkey.createkey(base_url, "EH_AES_GCM_128", "EH_INTERNAL_KEY")

    # test Encrypt("123456")
    data = str(base64.b64encode("123456".encode("utf-8")),'utf-8')
    aad = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    ciphertext = encrypt.encrypt(base_url, key, data, aad)

    # test Decrypt(ciphertext)
    plaintext = decrypt.decrypt(base_url, key, ciphertext, aad)
    
    print('Decrypt plaintext:\n%s\n' %(plaintext))
    print('check Decrypt plaintext result with %s: %s\n' %('123456', plaintext == '123456'))

    print('====================test_AES128 end===========================')

# A hook function forst JSON load function that avoid
# bool type value changing from "true" to "True".It will be caused the sign verfiy error
def no_bool_convert(pairs):
  return {k: str(v).casefold() if isinstance(v, bool) else v for k, v in pairs}

def test_GenerateQuote_and_VerifyQuote(base_url, headers):
    print('====================test_GenerateQuote_and_VerifyQuote start===========================')
    # notice: these 2 values will be changed if our enclave has been updated. then the case may be failed.
    mr_enclave = '870c42c59bc74c7ad22869411709e4f78ac3c76add6693bb43296b03362e5038';
    mr_signer = 'c30446b4be9baf0f69728423ea613ef81a63e72acf7439fa0549001fd5482835';   

    policyId = uploadQuotePolicy.uploadQuotePolicy(base_url, mr_enclave, mr_signer)

    result_getQuotePlicy = getQuotePolicy.getQuotePolicy(base_url, policyId)
    if ('mr_enclave' in result_getQuotePlicy):
        print('check getQuotePolicy result with %s: %s' %('mr_enclave', mr_enclave == result_getQuotePlicy['mr_enclave']))
    else:
        print('check getQuotePolicy result with %s: %s' %('mr_enclave', False))
    if ('mr_signer' in result_getQuotePlicy):
        print('check getQuotePolicy result with %s: %s\n' %('mr_signer', mr_signer == result_getQuotePlicy['mr_signer']))
    else:
        print('check getQuotePolicy result with %s: %s\n' %('mr_signer', False))

    generate_quote.generate_quote_with_file(base_url, "a.txt")

    verify_quote.verify_quote_with_file(base_url, "a.txt", policyId)
    os.remove("a.txt")
    print('====================test_GenerateQuote_and_VerifyQuote end===========================')


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
    