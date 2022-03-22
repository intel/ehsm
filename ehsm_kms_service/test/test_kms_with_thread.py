import requests
import json
import argparse
import base64
import _thread
import time
import datetime
import random
import hmac
import os
from hashlib import sha256
from collections import OrderedDict
import urllib.parse
appid= '25bca51e-8440-4c45-a276-9ab588a904ec'
apikey= 'yTLwLr9ZPeGv9nE9WBc7c0GWTJh6Kp7c'
keyid= ''

def test_params(payload):
    params = OrderedDict()
    params["appid"] = appid
    if payload!=False:
        ord_payload = OrderedDict(sorted(payload.items(), key=lambda k: k[0]))
        params["payload"] = urllib.parse.unquote(urllib.parse.urlencode(ord_payload))
    params["timestamp"] = str(int(time.time() * 1000) + int.from_bytes(os.urandom(2), byteorder='little'))
    sign_string = urllib.parse.unquote(urllib.parse.urlencode(params))
    sign = str(base64.b64encode(hmac.new(apikey.encode('utf-8'), sign_string.encode('utf-8'), digestmod=sha256).digest()),'utf-8')
    if payload!=False:
        params["payload"] = payload
    params["sign"] = sign
    return params
    
def test_thread(base_url, headers):
    payload = OrderedDict()
    payload["keyspec"] = "EH_AES_GCM_128"
    payload["origin"] = "EH_INTERNAL_KEY"
    params=test_params(payload)
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(params), headers=headers)
    if(check_result(create_resp, 'CreateKey', 'test_AES128') == False):
        return
    keyid = json.loads(create_resp.text)['result']['keyid']

    try:
        for i in range(1000):
            _thread.start_new_thread(thread_encrytp, ('Thread-{}'.format(i), base_url, headers, keyid,) )
            # thread_encrytp('Thread-{}'.format(i), base_url, headers, keyid )
    except:
        print ("Error: can't start thread.")
    while 1:
        pass


def thread_encrytp(threadName, base_url, headers, keyid):
    # test Encrypt("123456")
    start_format = 'start：{}'.format(datetime.datetime.now())
    t_s = time.time()
    millis_s = int(t_s * 1000)
    payload = OrderedDict()
    payload["aad"] = str(base64.b64encode("test".encode("utf-8")),'utf-8')
    payload["keyid"] = keyid
    payload["plaintext"] = str(base64.b64encode("123456".encode("utf-8")),'utf-8')
    params=test_params(payload)
    encrypt_resp = requests.post(url=base_url + "Encrypt", data=json.dumps(params), headers=headers)
    if(check_result(encrypt_resp, 'Encrypt', 'test_AES128') == False):
        return

    end_format = 'end: {}'.format(datetime.datetime.now())
    t_e = time.time()
    millis_e = int(t_e * 1000) 
    useTime = millis_e - millis_s
    print(threadName + '==>'+start_format+'\t'+end_format+'\tuse time：{}'.format(useTime))
    print(threadName + '==>\tEncrypt resp:\n%s\n' %(encrypt_resp.text))




# A hook function forst JSON load function that avoid
# bool type value changing from "true" to "True".It will be caused the sign verfiy error
def no_bool_convert(pairs):
  return {k: str(v).casefold() if isinstance(v, bool) else v for k, v in pairs}

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip-adress', type=str, help='ip address of the ehsm_kms_server', required=True)
    parser.add_argument('-p', '--port', type=str, help='port of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    ip = args.ip_adress
    port = args.port
    return ip, port
    
def check_result(res, action, test_name):
    res_json = json.loads(res.text)
    if(res_json['code'] == 200):
        return True
    else:
        return False
if __name__ == "__main__":
    headers = {"Content-Type":"application/json"}

    ip,port = get_args()

    base_url = "http://" + ip + ":" + port + "/ehsm?Action="

    test_thread(base_url, headers)

    
