import argparse
import json
import base64

from cli import createkey
from cli import decrypt
from cli import encrypt

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    base_url = args.url + "/ehsm?Action="
    return base_url

def test_AES128(base_url):
    print('====================test_AES128 start===========================')

    keyspec = "EH_AES_GCM_128"
    origin = "EH_INTERNAL_KEY"
    data = "123456"
    aad = "test"
    creatkey_resp = createkey.createkey(base_url, keyspec, origin)

    if(creatkey_resp != False):
      keyid = json.loads(creatkey_resp)['result']['keyid']
      encrypt_resp = encrypt.encrypt(base_url, keyid, data, aad)

    if(encrypt_resp != False):
      ciphertext = json.loads(encrypt_resp)['result']['ciphertext_base64']
      decrypt_resp = decrypt.decrypt(base_url, keyid, ciphertext, aad)

    if(decrypt_resp != False):
      plaintext = str(base64.b64decode(json.loads(decrypt_resp)['result']['plaintext_base64']), 'utf-8')
      print('Decrypt plaintext:\n%s\n' %(plaintext))
      print('check Decrypt plaintext result with %s: %s\n' %(data, plaintext == data))
    
    print('====================test_AES128 end===========================')
if __name__ == "__main__":
    base_url= get_args()
   
    test_AES128(base_url)

