package ehsm

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/iancoleman/orderedmap"
)

/*
Description:
Queries the parameters that are used to import key material for a customer master key (CMK).
Input:
keyid  -- The unique keyid of import CMK.
keyspec  -- The type of the public key that is used to encrypt key material.
Output:
pubkey  -- The public key that is used to encrypt key material.The public key is Base64-encoded.
import_token  -- The import_token is Base64-encoded string.
*/
func (c *Client) GetParametersForImport(keyid, keyspec string) (crypto.PublicKey, string, error) {
	payload := orderedmap.New()

	payload.Set("keyid", keyid)
	payload.Set("keyspec", keyspec)
	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "GetParametersForImport")
	if err != nil {
		return "", "", err
	}
	result, ok := resp["result"].(map[string]interface{})

	if !ok {
		return "", "", fmt.Errorf("result field is not a valid map")
	}
	pubkey, ok := result["pubkey"].(string)
	if !ok {
		return "", "", fmt.Errorf("pubkey field is not a valid string")
	}

	import_token, ok := result["importToken"].(string)
	if !ok {
		return "", "", fmt.Errorf("import_token field is not a valid string")
	}
	pemBytes := []byte(pubkey)
	derBytes, _ := pem.Decode(pemBytes)
	if derBytes == nil {
		return "", "", errors.New("PEM decoding failed")
	}
	switch derBytes.Type {
	case string(PublicKeyPEMType):
		pub_key, err := x509.ParsePKIXPublicKey(derBytes.Bytes)
		if err != nil {
			return "", "", err
		}
		return pub_key, import_token, nil
	case string(PKCS1PublicKeyPEMType):
		pub_key, err := x509.ParsePKCS1PublicKey(derBytes.Bytes)
		if err != nil {
			return "", "", err
		}
		return pub_key, import_token, nil
	default:
		return "", "", fmt.Errorf("unknown Public key PEM file type: %v. Are you passing the correct public key?",
			derBytes.Type)
	}

}

/*
Description:
Call the ImportKeyMaterial operation to import the key material.
Input:
keyid  -- The unique keyid of import CMK.
padding_mode  -- The padding mode that is used to encrypt key material.
key_material  -- The encrypted symmetric key.
import_token  -- The import_token is Base64-encoded string.
Output:
message  -- The description of result（success or failed）.
*/
func (c *Client) ImportKeyMaterial(keyid, padding_mode, key_material, import_token string) (bool, error) {

	payload := orderedmap.New()

	payload.Set("keyid", keyid)
	payload.Set("padding_mode", padding_mode)
	payload.Set("key_material", key_material)
	payload.Set("importToken", import_token)

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "ImportKeyMaterial")
	if err != nil {
		return false, err
	}
	resultString, ok := resp["result"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("import_token field is not a valid string")
	}
	result, ok := resultString["result"].(bool)
	if !ok {
		return false, fmt.Errorf("result field is not a valid bool")
	}

	return result, nil
}
