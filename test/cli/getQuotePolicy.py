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

import _utils_


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, help='the address of the ehsm_kms_server', required=True)
    parser.add_argument('--policyId', type=str, help='the id of the quote policy.', required=True)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    print(base_url)
    return base_url, args.policyId

def getQuotePolicy(base_url, policyId):
    payload = OrderedDict()
    payload["policyId"] = policyId
    params = _utils_.init_params(payload)
    print('getQuotePolicy req:\n%s\n' %(params))
    
    resp = requests.post(url=base_url + "GetQuotePolicy", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'GetQuotePolicy') == False):
        return
    print('getQuotePolicy resp:\n%s\n' %(resp.text))

    result = json.loads(resp.text)['result']
    return result

if __name__ == "__main__":
    headers = _utils_.headers

    base_url, policyId = get_args()

    getQuotePolicy(base_url, policyId)

