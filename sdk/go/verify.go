package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
Performs verify operation using the cmk(only support asymmetric keyspec).
Input:
keyid    		-- A unique keyid of asymmetric cmk.

padding mode	--padding_mode is necessary when keyspec is RSA.
	-EH_RSA_PKCS1(only support rsa keyspec)
	-EH_RSA_PKCS1_PSS(only support rsa keyspec)
	-EH_PAD_NONE(supprot ecc and sm2 keyspec)

digest mode		--If digest mode is not provided, the default digest mode will be used.
	-EH_SHA_224
	-EH_SHA_256
	-EH_SHA_384
	-EH_SHA_512
	-EH_SM3

message type
	-EH_RAW(KMS will calculate the digest with digest mode for your message)
	-EH_DIGEST(users need to fill in a digest value calculated using the digest mode.)

message			--Input raw string for messgae type EH_RAW or digest string for messgae type EH_DIGEST.

signature		--The calculated signature value stores in BASE64 string.

Output:
result  -- True or False: indicate whether the signature passed the verification.
*/
func (c *Client) Verify(keyid, padding_mode, digest_mode, message_type, message, signature string) (bool, error) {
	// make JSON for verify
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return false, fmt.Errorf("Please input keyid.")
	}
	if message != "" && isBase64(message) {
		payload.Set("message", message)
	} else {
		return false, fmt.Errorf("Message is false.")
	}
	if signature != "" && isBase64(signature) {
		payload.Set("signature", signature)
	} else {
		return false, fmt.Errorf("Signature is false.")
	}
	if message_type != "" {
		payload.Set("message_type", message_type)
	} else {
		return false, fmt.Errorf("Please input message_type.")
	}
	if padding_mode != "" {
		payload.Set("padding_mode", padding_mode)
	} else {
		return false, fmt.Errorf("Please input padding_mode.")
	}
	if digest_mode != "" {
		payload.Set("digest_mode", digest_mode)
	} else {
		return false, fmt.Errorf("Please input digest_mode.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "Verify")
	if err != nil {
		return false, err
	}
	resultString, ok := resp["result"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("result field is not a valid map")
	}

	result, ok := resultString["result"].(bool)
	if !ok {
		return false, fmt.Errorf("result field is not a valid bool")
	}
	return result, nil
}
