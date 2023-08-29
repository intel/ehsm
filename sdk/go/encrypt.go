package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
Encrypt an arbitrary set of bytes using the CMK.(only support symmetric types).
Input:
keyid      -- The keyid of the cmk you want to use which must be a symmetric key.

aad_b64    -- Some extra datas input by the user, which could help to to ensure data integrity,
			  and not be included in the cipherblobs. The aad stored in BASE64 string.

data_b64   -- The datas of the plaintext which in based64 encoding.

Output:
ciphertext -- The result in json object for the Ciphertext which in based64 encoding.
*/
func (c *Client) Encrypt(keyid, data_b64, aad_b64 string) (string, error) {
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return "", fmt.Errorf("keyid is empty.")
	}
	if data_b64 != "" && isBase64(data_b64) {
		payload.Set("plaintext", data_b64)
	} else {
		return "", fmt.Errorf("data is false.")
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
	resp, err := c.doPost(params, "Encrypt")
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
