import argparse
import json

from cli import createkey
from cli import sign
from cli import verify

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    base_url = args.url + "/ehsm?Action="
    return base_url

def test_RSA3072_sign_verify(base_url):
    print('====================test_RSA3072_sign_verify start===========================')
    keyspec = "EH_RSA_3072"
    origin = "EH_INTERNAL_KEY"
    digest = '123'
    creatkey_resp = createkey.createkey(base_url, keyspec, origin)

    if(creatkey_resp != False):
      keyid = json.loads(creatkey_resp)['result']['keyid']
      sign_resp = sign.sign(base_url, keyid, digest)

    if(sign_resp != False):
      signature_base64 = json.loads(sign_resp)['result']['signature_base64']
      verify.verify(base_url, keyid, digest, signature_base64,)
  
    print('====================test_RSA3072_sign_verify end===========================')
if __name__ == "__main__":
    base_url= get_args()
   
    test_RSA3072_sign_verify(base_url)
