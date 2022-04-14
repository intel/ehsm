import requests
import json
import argparse
import base64
import time
import random
import hmac
from hashlib import sha256
from collections import OrderedDict
from cli import createkey, asymmetric_decrypt, asymmetric_encrypt, decrypt, delete_all_key, deletekey, disablekey, enablekey, encrypt, export_datakey, generate_datakey, generate_datakey_withoutplaint, generate_quote, getversion, listkey, sign, verify, verify_quote
import urllib.parse
appid= '468c507a-da1f-4127-9cd0-82f0e7ce247e'
apikey= 'Merh0HrKuc2e8ECt5qba5dhy0ykyp1Js'
keyid= ''

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
    generate_quote.generate_quote_with_file(base_url, "a.txt")

    verify_quote.verify_quote_with_file(base_url, "a.txt")

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
    
