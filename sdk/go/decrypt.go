package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
Decrypt an arbitrary set of bytes using the CMK.(only support symmetric types).
Input:
keyid     -- The keyid of the symmetric cmk which used to decryt the ciphertext.

aad_b64   -- Some extra datas input by the user, which could help to to ensure data integrity,
			 and not be included in the cipherblobs. The aad stored in BASE64 string.

data_b64  -- Ciphertext to be decrypted in BASE64 string.

Output:
plaintext -- Plain data after decrypt and stored in BASE64 string.
*/
func (c *Client) Decrypt(keyid, data_b64, aad_b64 string) (string, error) {
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return "", fmt.Errorf("keyid is empty.")
	}
	if data_b64 != "" && isBase64(data_b64) {
		payload.Set("ciphertext", data_b64)
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
	resp, err := c.doPost(params, "Decrypt")
	if err != nil {
		return "", err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("result field is not a valid map")
	}

	plaintext, ok := result["plaintext"].(string)
	if !ok {
		return "", fmt.Errorf("plaintext field is not a valid string")
	}
	return plaintext, nil
}
