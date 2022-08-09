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
    parser.add_argument('--quote', type=str, help='the quote want to verify', required=True)
    parser.add_argument('--policyId', type=str, help='the quote want to verify', required=True)
    args = parser.parse_args()

    base_url = args.url + "/ehsm?Action="
    return base_url, args.quote

def verify_quote(base_url, quote, policyId):
    payload = OrderedDict()

    f = open(quote_file, "r")

    payload["quote"] = quote
    payload["nonce"] = "nonce12345"
    payload["policyId"] = policyId
    params = _utils_.init_params(payload)
    print('verify_quote req:\n%s\n' %(params))
    resp = requests.post(url=base_url + "VerifyQuote", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'VerifyQuote') == False):
        return
    print('verify_quote resp:\n%s\n' %(resp.text))

    VerifyQuote_Result = json.loads(resp.text, object_pairs_hook=_utils_.no_bool_convert)['result']
    hmac_sign = VerifyQuote_Result['sign']

    VerifyQuote_Result.pop('sign')
    ord_VerifyQuote_Result = OrderedDict(sorted(VerifyQuote_Result.items(), key=lambda k: k[0]))
    sign_string = urllib.parse.unquote(urllib.parse.urlencode(ord_VerifyQuote_Result))
    sign = str(base64.b64encode(hmac.new(_utils_.apikey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8')
    print('check HMAC sign result with %s: %s\n' %(sign, hmac_sign == sign))

def verify_quote_with_file(base_url, quote_file, policyId):
    payload = OrderedDict()

    f = open(quote_file, "r")

    payload["quote"] = f.read()
    payload["nonce"] = "nonce12345"
    payload["policyId"] = policyId
    params = _utils_.init_params(payload)
    print('verify_quote req:\n%s\n' %(params))
    resp = requests.post(url=base_url + "VerifyQuote", data=json.dumps(params), headers=_utils_.headers, verify=_utils_.use_secure_cert)
    if(_utils_.check_result(resp, 'VerifyQuote') == False):
        return
    print('verify_quote resp:\n%s\n' %(resp.text))

    VerifyQuote_Result = json.loads(resp.text, object_pairs_hook=_utils_.no_bool_convert)['result']
    hmac_sign = VerifyQuote_Result['sign']

    VerifyQuote_Result.pop('sign')
    ord_VerifyQuote_Result = OrderedDict(sorted(VerifyQuote_Result.items(), key=lambda k: k[0]))
    sign_string = urllib.parse.unquote(urllib.parse.urlencode(ord_VerifyQuote_Result))
    sign = str(base64.b64encode(hmac.new(_utils_.apikey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8')
    print('check HMAC sign result with %s: %s\n' %(sign, hmac_sign == sign))


if __name__ == "__main__":
    headers = _utils_.headers

    base_url, quote, policyId = get_args()

    verify_quote_with_file(base_url, quote, policyId)

