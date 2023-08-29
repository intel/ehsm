package ehsm

import (
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
ehsm-core enclave will decrypt user-supplied ciphertextblob with specified CMK to get the plaintext of DataKey,
then use the user-supplied Public key to encrypt this DataKey(aka ExportedDataKey).
This ExportedDataKey (ciphertext) will be returned to caller.
Input:
keyid    	-- A unique id of the specified symmetric CMK.

ukeyid   	-- The unique keyid of the asymmetric CMK which used to export.

aad_64  	-- Some extra datas input by the user, which could help to to ensure data integrity.
                   The aad stored in BASE64 string.

datakey_64  -- The ciphertext of the datakey wrapped by the cmk in BASE64 string.

Output:
newdatakey  -- The ciphertext of the datakey wrapped by the ukey stores in BASE64 string.
*/
func (c *Client) ExportDatakey(keyid, ukeyid, datakey_64, aad_64 string) (string, error) {
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return "", fmt.Errorf("keyid is empty.")
	}

	if ukeyid != "" {
		payload.Set("ukeyid", ukeyid)
	} else {
		return "", fmt.Errorf("ukeyid is empty.")
	}
	if datakey_64 != "" && isBase64(datakey_64) {
		payload.Set("olddatakey_base", datakey_64)
	} else {
		return "", fmt.Errorf("datakey is false.")
	}

	if aad_64 != "" && isBase64(aad_64) {
		payload.Set("aad", aad_64)
	} else {
		return "", fmt.Errorf("aad is false.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "ExportDataKey")
	if err != nil {
		return "", err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("result field is not a valid map")
	}

	newdatakey, ok := result["newdatakey"].(string)
	if !ok {
		return "", fmt.Errorf("newdatakey field is not a valid string")
	}
	return newdatakey, nil
}
