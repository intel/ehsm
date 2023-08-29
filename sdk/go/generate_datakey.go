package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
The same as GenerateDataKey, but it doesn’t return plaintext of generated DataKey.
Input:
keyid    	-- A unique id of the specified symmetric CMK.

aad_b64  	-- Some extra datas input by the user, which could help to to ensure data integrity,
			   and not be included in the cipherblobs. The aad stored in BASE64 string.

keylen   	-- Specifies the length of the plaintext, length is 0~1024 bytes.

Output:
ciphertext  -- The cipher text of the data key stores in BASE64 string.
*/
func (c *Client) GenerateDatakeyWithoutPlaintext(keyid, aad_b64 string, len int32) (string, error) {
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return "", fmt.Errorf("keyid is empty.")
	}
	if len > 0 && len <= 1024 {
		payload.Set("keylen", len)
	} else {
		return "", fmt.Errorf("len is false.")
	}
	if aad_b64 != "" && isBase64(aad_b64) {
		payload.Set("aad", aad_b64)
	} else {
		return "", fmt.Errorf("aad is empty.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "GenerateDataKeyWithoutPlaintext")
	if err != nil {
		return "", err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("result field is not a valid map")
	}

	ciphertext, ok := result["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("ciphertext field is not a valid string")
	}
	return ciphertext, nil
}

/*
Description:
Generates a random data key that is used to locally encrypt data.
the DataKey will be wrapped by the specified CMK(only support asymmetric keyspec),
and it will return the plaintext and ciphertext of the data key.

You can use the plaintext of the data key to locally encrypt your data
without using KMS and store the encrypted data together
with the ciphertext of the data key, then clear the plaintext data from memory as soon as possible.

when you want to obtain the plaintext of datakey again, you can call the Decrypt with the cmk to get the plaintext data.
Input:
keyid    	-- A unique id of the specified symmetric CMK.
aad_b64  	-- Some extra datas input by the user, which could help to to ensure data integrity,
			   and not be included in the cipherblobs. The aad stored in BASE64 string.

keylen   	-- Specifies the length of the plaintext, length is 0~1024 bytes.
Output:
ciphertext  -- The cipher text of the data key stores in BASE64 string.
*/
func (c *Client) GenerateDatakey(keyid, aad_b64 string, len int32) (string, error) {
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return "", fmt.Errorf("keyid is empty.")
	}

	if len > 0 && len <= 1024 {
		payload.Set("keylen", len)
	} else {
		return "", fmt.Errorf("len is false.")
	}

	if aad_b64 != "" && isBase64(aad_b64) {
		payload.Set("aad", aad_b64)
	} else {
		return "", fmt.Errorf("aad is false.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "GenerateDataKey")
	if err != nil {
		return "", err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("result field is not a valid map")
	}

	ciphertext, ok := result["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("ciphertext field is not a valid string")
	}
	return ciphertext, nil
}
