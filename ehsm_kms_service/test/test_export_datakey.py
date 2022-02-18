import argparse
import json

from cli import createkey
from cli import export_datakey
from cli import generate_datakey_withoutplaint

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    base_url = args.url + "/ehsm?Action="
    return base_url

def test_RSA3072_encrypt_decrypt(base_url):
    print('====================test_RSA3072_encrypt_decrypt start===========================')
    keyspec_128 = "EH_AES_GCM_128"
    keyspec_3072 = "EH_RSA_3072"
    origin = "EH_INTERNAL_KEY"
    keylen = 48
    aad = "test"
    creatkey_128_resp = createkey.createkey(base_url, keyspec_128, origin)
    creatkey_3072_resp = createkey.createkey(base_url, keyspec_3072, origin)

    if(creatkey_128_resp != False and creatkey_3072_resp != False):
      keyid = json.loads(creatkey_128_resp)['result']['keyid']
      ukeyid = json.loads(creatkey_3072_resp)['result']['keyid']
      generate_datakey_withoutplaint_resp = generate_datakey_withoutplaint.generate_datakey_withoutplaint(base_url, keyid, keylen, aad)
    
    if(generate_datakey_withoutplaint_resp != False):
      olddatakey_base = json.loads(generate_datakey_withoutplaint_resp)['result']['ciphertext_base64']
      export_datakey.export_datakey(base_url, keyid, ukeyid, olddatakey_base, aad)
  
    print('====================test_RSA3072_encrypt_decrypt end===========================')
if __name__ == "__main__":
    base_url= get_args()
   
    test_RSA3072_encrypt_decrypt(base_url)
