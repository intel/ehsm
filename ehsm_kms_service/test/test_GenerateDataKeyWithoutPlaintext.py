import argparse
import json

from cli import createkey
from cli import decrypt
from cli import generate_datakey_withoutplaint

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    base_url = args.url + "/ehsm?Action="
    return base_url

def test_GenerateDataKeyWithoutPlaintext(base_url):
    print('====================test_GenerateDataKeyWithoutPlaintext start===========================')

    keyspec = "EH_AES_GCM_128"
    origin = "EH_INTERNAL_KEY"
    len = 48
    aad = "test"
    creatkey_resp = createkey.createkey(base_url, keyspec, origin)

    if(creatkey_resp != False):
      keyid = json.loads(creatkey_resp)['result']['keyid']
      generate_datakey_withoutplaint_resp = generate_datakey_withoutplaint.generate_datakey_withoutplaint(base_url, keyid, len, aad)

    if(generate_datakey_withoutplaint_resp != False):
      ciphertext = json.loads(generate_datakey_withoutplaint_resp)['result']['ciphertext_base64']
      decrypt.decrypt(base_url, keyid, ciphertext, aad)
  
    print('====================test_GenerateDataKeyWithoutPlaintext end===========================')
if __name__ == "__main__":
    base_url= get_args()
   
    test_GenerateDataKeyWithoutPlaintext(base_url)
