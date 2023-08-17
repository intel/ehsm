package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
Encrypt an arbitrary set of bytes using the CMK.(only support asymmetric types).
Input:
keyid    		-- A unique keyid for asymmetric key.

plaintext 		-- The datas of the plaintext which in based64 encoding.

padding mode	-- Padding_mode is necessary when keyspec is RSA.
	-EH_RSA_PKCS1
	-EH_RSA_PKCS1_OAEP
	-EH_PAD_NONE

Output:
ciphertext 		-- The result in json object for the Ciphertext which in based64 encoding.
*/
func (c *Client) AsymmetricEncrypt(keyid, plaintext, padding_mode string) (string, error) {
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return "", fmt.Errorf("keyid is empty.")
	}
	if padding_mode != "" {
		payload.Set("padding_mode", padding_mode)
	} else {
		return "", fmt.Errorf("padding_mode is empty.")
	}
	if plaintext != "" && isBase64(plaintext) {
		payload.Set("plaintext", plaintext)
	} else {
		return "", fmt.Errorf("plaintext is false.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "AsymmetricEncrypt")
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
