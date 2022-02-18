import argparse
import json

from cli import createkey
from cli import asymmetric_decrypt
from cli import asymmetric_encrypt

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    base_url = args.url + "/ehsm?Action="
    return base_url

def test_RSA3072_encrypt_decrypt(base_url):
    print('====================test_RSA3072_encrypt_decrypt start===========================')
    keyspec = "EH_RSA_3072"
    origin = "EH_INTERNAL_KEY"
    plaintext = '123456'
    creatkey_resp = createkey.createkey(base_url, keyspec, origin)

    if(creatkey_resp != False):
      keyid = json.loads(creatkey_resp)['result']['keyid']
      asymmetric_encrypt_resp = asymmetric_encrypt.asymmetric_encrypt(base_url, keyid, plaintext)

    if(asymmetric_encrypt_resp != False):
      ciphertext_base64 = json.loads(asymmetric_encrypt_resp)['result']['ciphertext_base64']
      asymmetric_decrypt.asymmetric_decrypt(base_url, keyid, ciphertext_base64,)
  
    print('====================test_RSA3072_encrypt_decrypt end===========================')
if __name__ == "__main__":
    base_url= get_args()
   
    test_RSA3072_encrypt_decrypt(base_url)
