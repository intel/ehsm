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

def test_export_datakey(base_url, headers):
    print('====================test_export_datakey start===========================')
    key_GCM_128 = createkey.createkey(base_url, "AES_GCM_128", "EH_INTERNAL_KEY", None, None, None)
    key_GCM_192 = createkey.createkey(base_url, "AES_GCM_192", "EH_INTERNAL_KEY", None, None, None)
    key_GCM_256 = createkey.createkey(base_url, "AES_GCM_256", "EH_INTERNAL_KEY", None, None, None)
    key_SM4_ctr = createkey.createkey(base_url, "SM4_CTR", "EH_INTERNAL_KEY", None, None, None)
    key_SM4_cbc = createkey.createkey(base_url, "SM4_CBC", "EH_INTERNAL_KEY", None, None, None)

    key_RSA_3072 = createkey.createkey(base_url, "RSA_3072", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1_OAEP", None)
    key_RSA_4096 = createkey.createkey(base_url, "RSA_4096", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1_OAEP", None)
    key_RSA_2048 = createkey.createkey(base_url, "RSA_2048", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1", None)
    key_SM2 = createkey.createkey(base_url, "SM2", "EH_INTERNAL_KEY", None, None, None)
    symmetricKey = [key_GCM_128, key_GCM_192, key_GCM_256, key_SM4_ctr, key_SM4_cbc]
    asymmetricKey = [key_RSA_3072, key_RSA_4096, key_RSA_2048, key_SM2]
    aad = str(base64.b64encode("test".encode("utf-8")),'utf-8')

    for i in symmetricKey:
        ciphertext = generate_datakey_withoutplaint.generate_datakey_withoutplaint(base_url, i, 48, aad)
        for j in asymmetricKey:
            # test ExportDataKey
            export_datakey.export_datakey(base_url, i, j, ciphertext, aad)
            
    print('====================test_export_datakey end===========================')

def test_asymmetricKey_encrypt_decrypt(base_url, headers):
    print('====================test_asymmetricKey_encrypt_decrypt start===========================')
    key_RSA_3072 = createkey.createkey(base_url, "RSA_3072", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1_OAEP", None)
    key_RSA_4096 = createkey.createkey(base_url, "RSA_4096", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1_OAEP", None)
    key_RSA_2048 = createkey.createkey(base_url, "RSA_2048", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1", None)
    key_SM2 = createkey.createkey(base_url, "SM2", "EH_INTERNAL_KEY", None, None, None)
    asymmetricKey = [key_RSA_2048, key_RSA_3072, key_RSA_4096, key_SM2]

    for i in asymmetricKey:
        # test AsymmetricEncrypt("123456")
        print('%s encrypt' %i)
        ciphertext = asymmetric_encrypt.asymmetric_encrypt(base_url, i, str(base64.b64encode("123456".encode("utf-8")), 'utf-8'))

        # test AsymmetricDecrypt(ciphertext)
        asymmetric_decrypt.asymmetric_decrypt(base_url, i, ciphertext)

    print('====================test_asymmetricKey_encrypt_decrypt end===========================')

def test_Stest_sign_verify(base_url, headers):
    print('====================test_Stest_sign_verify start===========================')

    key_RSA_3072 = createkey.createkey(base_url, "RSA_3072", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1_PSS", "SHA_2_224")
    key_RSA_4096 = createkey.createkey(base_url, "RSA_4096", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1_PSS", "SHA_2_384")
    key_RSA_2048 = createkey.createkey(base_url, "RSA_2048", "EH_INTERNAL_KEY", None, "PAD_RSA_PKCS1", "SHA_2_512")
    key_EC_p256 = createkey.createkey(base_url, "EC_P256", "EH_INTERNAL_KEY", None, None, "SHA_2_256")
    asymmetricKey = [key_RSA_3072, key_RSA_4096, key_RSA_2048, key_EC_p256]
    
    for i in asymmetricKey:
        # test Sign
        signature = sign.sign(base_url, i, str(base64.b64encode("test".encode("utf-8")),'utf-8'), None)

        # test Verify
        verify.verify(base_url, i, str(base64.b64encode("test".encode("utf-8")),'utf-8'), signature, None)

    print('====================test_Stest_sign_verify end===========================')

def test_Stest_SM2_sign_verify(base_url, headers):
    print('====================test_Stest_SM2_sign_verify start===========================')
    key_SM2 = createkey.createkey(base_url, "SM2", "EH_INTERNAL_KEY", None, None, "SM3")
    userid = str(base64.b64encode(appid.encode("utf-8")),'utf-8')

    # test Sign
    signature = sign.sign(base_url, key_SM2, str(base64.b64encode("test".encode("utf-8")),'utf-8'), userid)

    # test Verify
    verify.verify(base_url, key_SM2, str(base64.b64encode("test".encode("utf-8")),'utf-8'), signature, userid)

    print('====================test_Stest_SM2_sign_verify end===========================')


def test_GenerateDataKeyWithoutPlaintext(base_url, headers):
    print('====================test_GenerateDataKeyWithoutPlaintext start===========================')
    key_GCM_128 = createkey.createkey(base_url, "AES_GCM_128", "EH_INTERNAL_KEY", None, None, None)
    key_GCM_192 = createkey.createkey(base_url, "AES_GCM_192", "EH_INTERNAL_KEY", None, None, None)
    key_GCM_256 = createkey.createkey(base_url, "AES_GCM_256", "EH_INTERNAL_KEY", None, None, None)
    key_SM4_ctr = createkey.createkey(base_url, "SM4_CTR", "EH_INTERNAL_KEY", None, None, None)
    key_SM4_cbc = createkey.createkey(base_url, "SM4_CBC", "EH_INTERNAL_KEY", None, None, None)
    symmetricKey = [key_GCM_128, key_GCM_192, key_GCM_256, key_SM4_ctr, key_SM4_cbc]

    # test GenerateDataKeyWithoutPlaintext
    aad = str(base64.b64encode("test".encode("utf-8")),'utf-8')

    for i in symmetricKey:
        
        ciphertext = generate_datakey_withoutplaint.generate_datakey_withoutplaint(base_url, i, 48, aad)

        # test Decrypt(cipher_datakey)
        decrypt.decrypt(base_url, i, ciphertext, aad)

    print('====================test_GenerateDataKeyWithoutPlaintext end===========================')

def test_GenerateDataKey(base_url, headers):
    print('====================test_GenerateDataKey start===========================')
    key_GCM_128 = createkey.createkey(base_url, "AES_GCM_128", "EH_INTERNAL_KEY", None, None, None)
    key_GCM_192 = createkey.createkey(base_url, "AES_GCM_192", "EH_INTERNAL_KEY", None, None, None)
    key_GCM_256 = createkey.createkey(base_url, "AES_GCM_256", "EH_INTERNAL_KEY", None, None, None)
    key_SM4_ctr = createkey.createkey(base_url, "SM4_CTR", "EH_INTERNAL_KEY", None, None, None)
    key_SM4_cbc = createkey.createkey(base_url, "SM4_CBC", "EH_INTERNAL_KEY", None, None, None)
    symmetricKey = [key_GCM_128, key_GCM_192, key_GCM_256, key_SM4_ctr, key_SM4_cbc]

    # test GenerateDataKeyWithoutPlaintext
    aad = str(base64.b64encode("test".encode("utf-8")),'utf-8')

    for i in symmetricKey:
    
        # test GenerateDataKey
        ciphertext = generate_datakey.generate_datakey(base_url, i, 16, None)

        # test Decrypt(cipher_datakey)
        decrypt.decrypt(base_url, i, ciphertext, None)

    print('====================test_GenerateDataKey end===========================')

def test_symmetricKey_encrypt_decrypt(base_url, headers):
    print('====================test_symmetricKey_encrypt_decrypt start===========================')
    key_GCM_128 = createkey.createkey(base_url, "AES_GCM_128", "EH_INTERNAL_KEY", None, None, None)
    key_GCM_192 = createkey.createkey(base_url, "AES_GCM_192", "EH_INTERNAL_KEY", None, None, None)
    key_GCM_256 = createkey.createkey(base_url, "AES_GCM_256", "EH_INTERNAL_KEY", None, None, None)
    key_SM4_ctr = createkey.createkey(base_url, "SM4_CTR", "EH_INTERNAL_KEY", None, None, None)
    key_SM4_cbc = createkey.createkey(base_url, "SM4_CBC", "EH_INTERNAL_KEY", None, None, None)
    symmetricKey = [key_GCM_128, key_GCM_192, key_GCM_256, key_SM4_ctr, key_SM4_cbc]

    aad = str(base64.b64encode("test".encode("utf-8")),'utf-8')

    for i in symmetricKey:
        
        # test Encrypt("gcm128")
        data = str(base64.b64encode("symmetricKeytest".encode("utf-8")),'utf-8')
        ciphertext = encrypt.encrypt(base_url, i, data, aad)

        # test Decrypt(ciphertext)
        decrypt.decrypt(base_url, i, ciphertext, aad)
    
    print('====================test_symmetricKey_encrypt_decrypt end===========================')

# A hook function forst JSON load function that avoid
# bool type value changing from "true" to "True".It will be caused the sign verfiy error
def no_bool_convert(pairs):
  return {k: str(v).casefold() if isinstance(v, bool) else v for k, v in pairs}

def test_GenerateQuote_and_VerifyQuote(base_url, headers):
    print('====================test_GenerateQuote_and_VerifyQuote start===========================')
    # notice: these 2 values will be changed if our enclave has been updated. then the case may be failed.
    # you can get mr_signer and mr_enclave through cmd: 
    # "/opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave libenclave-ehsm-core.signed.so -dumpfile out.log"
    mr_enclave = '59ac5a9f3f2c63846c3d469b38f31452760615f4562fc7723edafecaaf946807';
    mr_signer = 'c30446b4be9baf0f69728423ea613ef81a63e72acf7439fa0549001fd5482835';   

    policyId = uploadQuotePolicy.uploadQuotePolicy(base_url, mr_enclave, mr_signer)

    result_getQuotePolicy = getQuotePolicy.getQuotePolicy(base_url, policyId)
    if ('mr_enclave' in result_getQuotePolicy):
        print('check getQuotePolicy result with %s: %s' %('mr_enclave', mr_enclave == result_getQuotePolicy['mr_enclave']))
    else:
        print('check getQuotePolicy result with %s: %s' %('mr_enclave', False))
    if ('mr_signer' in result_getQuotePolicy):
        print('check getQuotePolicy result with %s: %s\n' %('mr_signer', mr_signer == result_getQuotePolicy['mr_signer']))
    else:
        print('check getQuotePolicy result with %s: %s\n' %('mr_signer', False))

    generate_quote.generate_quote_with_file(base_url, "a.txt")

    verify_quote.verify_quote_with_file(base_url, "a.txt")
    verify_quote.verify_quote_with_file_and_policyId(base_url, "a.txt", policyId)
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
    
    test_symmetricKey_encrypt_decrypt(base_url, headers)

    test_GenerateDataKey(base_url, headers)

    test_GenerateDataKeyWithoutPlaintext(base_url, headers)

    test_Stest_sign_verify(base_url, headers)

    test_Stest_SM2_sign_verify(base_url, headers)

    test_asymmetricKey_encrypt_decrypt(base_url, headers)

    test_export_datakey(base_url, headers)

    test_GenerateQuote_and_VerifyQuote(base_url, headers)
    