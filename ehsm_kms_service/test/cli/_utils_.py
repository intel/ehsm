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

# Using a dummy appid and app key
appid='563173cf-f26d-4c74-82e1-a4105cf3fb48'
apikey = 'xXH5nmw4J0NaKwKEJiKcxuJ859u1cwrE'

headers = {"Content-Type":"application/json"}

def init_params(payload):
    params = OrderedDict()
    params["appid"] = appid
    if payload!=False:
        ord_payload = OrderedDict(sorted(payload.items(), key=lambda k: k[0]))
        params["payload"] = urllib.parse.unquote(urllib.parse.urlencode(ord_payload))
    params["timestamp"] = str(int(time.time() * 1000))
    sign_string = urllib.parse.unquote(urllib.parse.urlencode(params))
    #print(sign_string.encode('utf-8'))
    #print(apikey.encode('utf-8'))
    sign = str(base64.b64encode(hmac.new(apikey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8')
    if payload!=False:
        params["payload"] = payload
    params["sign"] = sign
    return params

# A hook function forst JSON load function that avoid
# bool type value changing from "true" to "True".It will be caused the sign verfiy error
def no_bool_convert(pairs):
  return {k: str(v).casefold() if isinstance(v, bool) else v for k, v in pairs}

def check_result(res, action):
    res_json = json.loads(res.text)
    if(res_json['code'] == 200):
        print("%s successfully \n" %(action))
        return True
    else:
        print("%s failed, error message: %s \n" %(action, res_json["message"]))
        return False
