package ehsm

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/iancoleman/orderedmap"
)

type PEMType string

const (
	// PublicKeyPEMType is the string "PUBLIC KEY" to be used during PEM encoding and decoding
	PublicKeyPEMType PEMType = "PUBLIC KEY"
	// PKCS1PublicKeyPEMType is the string "RSA PUBLIC KEY" used to parse PKCS#1-encoded public keys
	PKCS1PublicKeyPEMType PEMType = "RSA PUBLIC KEY"
)

/*
Description:
Get public key from keypair.
Input:
keyid    -- A uinque keyid of the cmk.

Output:
pubkey  -- the data of the public key.
*/
func (c *Client) GetPublicKey(keyid string) (crypto.PublicKey, error) {
	// make JSON for getpubkey
	payload := orderedmap.New()
	if keyid != "" {
		payload.Set("keyid", keyid)
	} else {
		return nil, fmt.Errorf("Please input keyid.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "GetPublicKey")
	if err != nil {
		return nil, err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("result field is not a valid map")
	}

	pubkey, ok := result["pubkey"].(string)
	if !ok {
		return nil, fmt.Errorf("pubkey field is not a valid string")
	}
	// parse keyblob to crypto.x509
	// support EH_RSA_x and EH_EC_P256
	pemBytes := []byte(pubkey)
	derBytes, _ := pem.Decode(pemBytes)
	if derBytes == nil {
		return nil, errors.New("PEM decoding failed")
	}
	switch derBytes.Type {
	case string(PublicKeyPEMType):
		return x509.ParsePKIXPublicKey(derBytes.Bytes)
	case string(PKCS1PublicKeyPEMType):
		return x509.ParsePKCS1PublicKey(derBytes.Bytes)
	default:
		return nil, fmt.Errorf("unknown Public key PEM file type: %v. Are you passing the correct public key?",
			derBytes.Type)
	}
}
