import requests
import json
import argparse
import base64
def test_GenerateDataKey(base_url, headers):
    print('====================test_GenerateDataKey start===========================')
    create_req = {
        "appid":"t123",
        "nonce":"t123",
        "timestamp":"t123",
        "sign":"t123",
        "payload":{
            "keyspec":"EH_AES_GCM_128",
            "origin":"EH_INTERNAL_KEY"
        }
    }

    print('CreateKey req:\n%s\n' %(create_req))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(create_req), headers=headers)
    print('CreateKey resp:\n%s\n' %(create_resp.text))

        # test GenerateDataKey
    generatedatakey_req = {
        "appid":"t123",
        "nonce":"t123",
        "timestamp":"t123",
        "sign":"t123",
        "payload":{
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "keylen": 16,
            "aad": "test",
        }
    }
    print('GenerateDataKey req:\n%s\n' %(generatedatakey_req))
    generatedatakey_resp = requests.post(url=base_url + "GenerateDataKey", data=json.dumps(generatedatakey_req), headers=headers)
    print('GenerateDataKey resp:\n%s\n' %(generatedatakey_resp.text))

    # test Decrypt(cipher_datakey)
    decrypt_req = {
        "appid":"t123",
        "nonce":"t123",
        "timestamp":"t123",
        "sign":"t123",
        "payload":{
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "ciphertext":json.loads(generatedatakey_resp.text)['result']['ciphertext_base64'],
            "aad":"test",
        }
    }
    print('Decrypt req:\n%s\n' %(decrypt_req))
    decrypt_res = requests.post(url=base_url + "Decrypt", data=json.dumps(decrypt_req), headers=headers)
    print('Decrypt resp:\n%s\n' %(decrypt_res.text))

    print('====================test_GenerateDataKey end===========================')

def test_AES128(base_url, headers):

    print('====================test_AES128 start===========================')
    create_req = {
        "appid":"t123",
        "nonce":"t123",
        "timestamp":"t123",
        "sign":"t123",
        "payload":{
            "keyspec":"EH_AES_GCM_128",
            "origin":"EH_INTERNAL_KEY"
        }
    }

    print('CreateKey req:\n%s\n' %(create_req))
    create_resp = requests.post(url=base_url + "CreateKey", data=json.dumps(create_req), headers=headers)
    print('CreateKey resp:\n%s\n' %(create_resp.text))

    # test Encrypt("123456")
    encrypt_req = {
        "appid":"t123",
        "nonce":"t123",
        "timestamp":"t123",
        "sign":"t123",
        "payload":{
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "plaintext":"123456",
            "aad":"test"
        }
    }
    print('Encrypt req:\n%s\n' %(encrypt_req))
    encrypt_resp = requests.post(url=base_url + "Encrypt", data=json.dumps(encrypt_req), headers=headers)
    print('Encrypt resp:\n%s\n' %(encrypt_resp.text))

    # test Decrypt(ciphertext)
    decrypt_req = {
        "appid":"t123",
        "nonce":"t123",
        "timestamp":"t123",
        "sign":"t123",
        "payload":{
            "cmk_base64":json.loads(create_resp.text)['result']['cmk_base64'],
            "ciphertext":json.loads(encrypt_resp.text)['result']['ciphertext_base64'],
            "aad":"test",
        }
    }
    print('Decrypt req:\n%s\n' %(decrypt_req))
    decrypt_res = requests.post(url=base_url + "Decrypt", data=json.dumps(decrypt_req), headers=headers)
    print('Decrypt resp:\n%s\n' %(decrypt_res.text))
    plaintext = str(base64.b64decode(json.loads(decrypt_res.text)['result']['plaintext_base64']), 'utf-8')
    print('Decrypt plaintext:\n%s\n' %(plaintext))
    print('====================test_AES128 end===========================')

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip-adress', type=str, help='ip address of the ehsm_kms_server', required=True)
    parser.add_argument('-p', '--port', type=str, help='port of the ehsm_kms_server', required=True)
    args = parser.parse_args()
    ip = args.ip_adress
    port = args.port
    return ip, port

if __name__ == "__main__":
    headers = {"Content-Type":"application/json"}

    ip,port = get_args()

    base_url = "http://" + ip + ":" + port + "/ehsm?Action="
    #print(base_url)

    test_AES128(base_url, headers)

    test_GenerateDataKey(base_url, headers)