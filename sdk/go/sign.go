package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
Performs sign operation using the cmk(only support asymmetric keyspec).
Input:
keyid    		-- A unique keyid of asymmetric cmk.

padding mode	--padding_mode is necessary when keyspec is RSA.
	-EH_RSA_PKCS1(only support rsa keyspec)
	-EH_RSA_PKCS1_PSS(only support rsa keyspec)
	-EH_PAD_NONE(supprot ecc and sm2 keyspec)

digest mode		--If digest mode is not provided, the default digest mode will be used.
				  EH_SHA_SHA256 will be used for rsa and ecc, and EH_SM3 will be used for sm2.
				  If use sm2 keypair, digest mode must be EH_SM3.
	-EH_SHA_224
	-EH_SHA_256
	-EH_SHA_384
	-EH_SHA_512
	-EH_SM3

message type
	-EH_RAW(KMS will calculate the digest with digest mode for your message)
	-EH_DIGEST(users need to fill in a digest value calculated using the digest mode.)

message			--Input raw string for messgae type EH_RAW or digest string for messgae type EH_DIGEST.
Output:
signature -- The calculated signature value stores in BASE64 string.
*/
func (c *Client) Sign(keyid, padding_mode, digest_mode, message_type, message string) (string, error) {
	// make JSON for sign
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return "", fmt.Errorf("Please input keyid.")
	}
	if message != "" && isBase64(message) {
		payload.Set("message", message)
	} else {
		return "", fmt.Errorf("Message is false.")
	}
	if message_type != "" {
		payload.Set("message_type", message_type)
	} else {
		return "", fmt.Errorf("Please input message_type.")
	}
	if padding_mode != "" {
		payload.Set("padding_mode", padding_mode)
	} else {
		return "", fmt.Errorf("Please input padding_mode.")
	}
	if digest_mode != "" {
		payload.Set("digest_mode", digest_mode)
	} else {
		return "", fmt.Errorf("Please input digest_mode.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "Sign")

	if err != nil {
		return "", err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("result field is not a valid map")
	}

	signature, ok := result["signature"].(string)
	if !ok {
		return "", fmt.Errorf("signature field is not a valid string")
	}
	return signature, nil
}
