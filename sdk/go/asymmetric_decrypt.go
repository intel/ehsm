package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
Decrypt an arbitrary set of bytes using the CMK.(only support asymmetric types).
Input:
keyid    		-- The keyid of the asymmetric cmk.

ciphertext 		-- The data of the ciphertext in BASE64 string.

padding mode	-- For RSA keys, it support EH_RSA_PKCS1 and EH_RSA_PKCS1_OAEP
				   for SM2, it should be EH_PAD_NONE.
				   Currently, ecc keypair does not support this function.
	-EH_RSA_PKCS1
	-EH_RSA_PKCS1_OAEP
	-EH_PAD_NONE

Output:
plaintext 		-- Plaint data after decrypt and stored in BASE64 string.
*/
func (c *Client) AsymmetricDecrypt(keyid, ciphertext, padding_mode string) (string, error) {
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
	if ciphertext != "" && isBase64(ciphertext) {
		payload.Set("ciphertext", ciphertext)
	} else {
		return "", fmt.Errorf("ciphertext is false.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "AsymmetricDecrypt")
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
