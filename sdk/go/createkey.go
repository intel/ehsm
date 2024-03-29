package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
Create a customer master key(CMK) for the user,
which can be a symmetric or an asymmetric key,
for the symmetric cmk mainly used to wrap the datakey,
also can be used to encrypted an arbitrary set of bytes data(<6KB).
And for the asymmetric cmk mainly used to sign/verify
or asymmetric encrypt/decrypt datas(not for the datakey.)
Input:
keyspec
	-EH_AES_GCM_128,
	-EH_AES_GCM_256,
	-EH_RSA_2048,
	-EH_RSA_3072,
	-EH_EC_P256,
	-EH_EC_P521,
	-EH_SM2,
	-EH_SM4_CBC,
	-EH_HMAC,

origin
	-EH_INTERNAL_KEY (generated from the eHSM inside)
	-EH_EXTERNAL_KEY (generated by the customer and want to import into the eHSM),

keyusage
	-EH_KEYUSAGE_ENCRYPT_DECRYPT
	-EH_KEYUSAGE_SIGN_VERIFY

Output:
keyid -- A uinque keyid of the cmk.
*/
func (c *Client) CreateKey(keyspec, origin, keyusage string) (string, error) {
	// make JSON for createkey
	payload := orderedmap.New()
	if keyspec != "" {
		payload.Set("keyspec", keyspec)
	} else {
		return "", fmt.Errorf("Please input keyspec.")
	}
	if origin != "" {
		payload.Set("origin", origin)
	} else {
		return "", fmt.Errorf("Please input origin.")
	}

	if keyusage != "" {
		payload.Set("keyusage", keyusage)
	} else {
		return "", fmt.Errorf("Please input keyusage.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "CreateKey")
	if err != nil {
		return "", err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("result field is not a valid map")
	}

	keyid, ok := result["keyid"].(string)
	if !ok {
		return "", fmt.Errorf("keyid field is not a valid string")
	}
	return keyid, nil
}
