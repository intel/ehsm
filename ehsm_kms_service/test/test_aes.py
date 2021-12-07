import requests 
import json

# Replace <port> with real port number
ehsm_srv_addr = "http://127.0.0.1"
port = "3000"

base_url = ehsm_srv_addr + ":" + port + "/ehsm?Action="

# todo: remove hardcoded parameters
# test CreateKey(AES)
data = {
    "appid":"t123",
    "nonce":"t123",
    "timestamp":"t123",
    "sign":"t123",
    "payload":{
        "keyspec":"EH_AES_GCM_128",
        "origin":"EH_INTERNAL_KEY"
    }
}
headers = {"Content-Type":"application/json"}
createKey_res = requests.post(url=base_url + "CreateKey", data=json.dumps(data), headers=headers) 
print('createKey result:%s' %(createKey_res.text)) 

# test Encrypt("123456")
Encrypt_p = {
    "appid":"t123",
    "nonce":"t123",
    "timestamp":"t123",
    "sign":"t123",
    "payload":{
        "cmk_base64":json.loads(createKey_res.text)['result']['cmk_base64'],
        "plaintext":"123456",
        "aad":"test"
    }
}
encrypt_res = requests.post(url=base_url + "Encrypt", data=json.dumps(Encrypt_p), headers=headers) 
print('encrypt result:%s' %(encrypt_res.text)) 

# test Decrypt(ciphertext)
Decrypt_p = {
    "appid":"t123",
    "nonce":"t123",
    "timestamp":"t123",
    "sign":"t123",
    "payload":{
        "cmk_base64":json.loads(createKey_res.text)['result']['cmk_base64'],
        "ciphertext":json.loads(encrypt_res.text)['result']['ciphertext_base64'],
        "aad":"test",
    }
}
decrypt_res = requests.post(url=base_url + "Decrypt", data=json.dumps(Decrypt_p), headers=headers) 
print('decrypt result:%s' %(decrypt_res.text)) 

# test GenerateDataKey
GenerateDataKey_p = {
    "appid":"t123",
    "nonce":"t123",
    "timestamp":"t123",
    "sign":"t123",
    "payload":{
        "cmk_base64":json.loads(createKey_res.text)['result']['cmk_base64'],
        "keylen": 16,
        "aad": "test",
    }
}
generateDataKey_res = requests.post(url=base_url + "GenerateDataKey", data=json.dumps(GenerateDataKey_p), headers=headers) 
print('generateDataKe result:', generateDataKey_res.text) 