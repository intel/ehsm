import requests
import json
import argparse
from hashlib import sha256
from collections import OrderedDict

import _utils_

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    parser.add_argument('--keyid', type=str, help='the keyid of the asymmetric cmk', required=True)
    parser.add_argument('--keyspec', type=str, help='supported_keyspec = ["EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096", "EH_SM2"]', required=True)
    parser.add_argument('--padding_mode',type=str, help='the paddign mode for RSA encrypt', required=True)
    parser.add_argument('--key_material', type=str, help='the keymaterial data to be decrypted', required=True)
    parser.add_argument('--importToken', type=str, help='importToken', required=True)

    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.keyid, args.padding_mode, args.key_material

def import_key_material(base_url, keyid, padding_mode,key_material,importToken):
    print('import symmetric key material')
    
    payload = OrderedDict()
    payload["key_material"] = key_material
    payload["keyid"] = keyid
    payload["padding_mode"] = padding_mode
    payload["importToken"]= importToken
    params = _utils_.init_params(payload)
    print('import_key_material req:\n%s\n' %(params))

    resp = requests.post(url=base_url + "ImportKeyMaterial", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'ImportKeyMaterial') == False):
        return
    print('importkey resp:\n%s\n' %(resp.text))

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, keyid, padding_mode, key_material = get_args()

    import_key_material(base_url, keyid, padding_mode, key_material)
