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
appid='1644220551486'
appkey = '1644220551486'

headers = {"Content-Type":"application/json"}

def init_params(payload):
    params = OrderedDict()
    params["appid"] = appid
    params["payload"] = urllib.parse.unquote(urllib.parse.urlencode(payload))
    params["timestamp"] = str(int(time.time() * 1000))

    sign_string = urllib.parse.unquote(urllib.parse.urlencode(params))
    sign = str(base64.b64encode(hmac.new(appkey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8').upper()

    params["payload"] = payload
    params["sign"] = sign
    return params

def check_result(res, action):
    res_json = json.loads(res.text)
    if(res_json['code'] == 200):
        print("%s successfully \n" %(action))
        return True
    else:
        print("%s failed, error message: %s \n" %(action, res_json["message"]))
        return False