package ehsm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/tjfoc/gmsm/sm3"
)

func TestECSignVerify(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyspec := []string{"EH_EC_P224", "EH_EC_P256", "EH_EC_P256K", "EH_EC_P384", "EH_EC_P521"}
	msg := "test for signature"
	msg_digest256 := sha256.Sum256([]byte(msg))
	for _, keyspec := range keyspec {
		keyid, err := client.CreateKey(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
		if err != nil {
			t.Error(err)
		}
		signature256_raw, err := client.Sign(keyid, "EH_PAD_NONE", "EH_SHA_256", "EH_RAW", base64.StdEncoding.EncodeToString([]byte(msg)))
		if err != nil {
			t.Error(err)
		}
		result256_raw, err := client.Verify(keyid, "EH_PAD_NONE", "EH_SHA_256", "EH_RAW", base64.StdEncoding.EncodeToString([]byte(msg)), signature256_raw)
		if result256_raw != true {
			t.Error(err)
		}
		signature256_digest, err := client.Sign(keyid, "EH_PAD_NONE", "EH_SHA_256", "EH_DIGEST", base64.StdEncoding.EncodeToString(msg_digest256[:]))
		if err != nil {
			t.Error(err)
		}
		result256_digest, err := client.Verify(keyid, "EH_PAD_NONE", "EH_SHA_256", "EH_DIGEST", base64.StdEncoding.EncodeToString(msg_digest256[:]), signature256_digest)
		if result256_digest != true {
			t.Error(err)
		}

	}
}

func TestRSASignVerify(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyspec := []string{"EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096"}
	msg := "test for signature"
	msg_digest256 := sha256.Sum256([]byte(msg))
	padding_mode := []string{"EH_RSA_PKCS1", "EH_RSA_PKCS1_PSS"}
	for _, keyspec := range keyspec {
		keyid, err := client.CreateKey(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
		if err != nil {
			t.Error(err)
		}
		for _, padding_mode := range padding_mode {
			signature256_raw, err := client.Sign(keyid, padding_mode, "EH_SHA_256", "EH_RAW", base64.StdEncoding.EncodeToString([]byte(msg)))
			if err != nil {
				t.Error(err)
			}
			result256_raw, err := client.Verify(keyid, padding_mode, "EH_SHA_256", "EH_RAW", base64.StdEncoding.EncodeToString([]byte(msg)), signature256_raw)
			if result256_raw != true {
				t.Error(err)
			}
			signature256_digest, err := client.Sign(keyid, padding_mode, "EH_SHA_256", "EH_DIGEST", base64.StdEncoding.EncodeToString(msg_digest256[:]))
			if err != nil {
				t.Error(err)
			}
			result256_digest, err := client.Verify(keyid, padding_mode, "EH_SHA_256", "EH_DIGEST", base64.StdEncoding.EncodeToString(msg_digest256[:]), signature256_digest)
			if result256_digest != true {
				t.Error(err)
			}
		}
	}
}

func TestSM2SignVerify(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyid, err := client.CreateKey("EH_SM2", "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
	if err != nil {
		t.Error(err)
	}
	msg := "test for signature"
	msg_digest := sm3.Sm3Sum([]byte(msg))
	signature_raw, err := client.Sign(keyid, "EH_PAD_NONE", "EH_SM3", "EH_RAW", base64.StdEncoding.EncodeToString([]byte(msg)))
	if err != nil {
		t.Error(err)
	}
	result_raw, err := client.Verify(keyid, "EH_PAD_NONE", "EH_SM3", "EH_RAW", base64.StdEncoding.EncodeToString([]byte(msg)), signature_raw)
	if result_raw != true {
		t.Error(err)
	}
	signature_digest, err := client.Sign(keyid, "EH_PAD_NONE", "EH_SM3", "EH_DIGEST", base64.StdEncoding.EncodeToString(msg_digest[:]))
	if err != nil {
		t.Error(err)
	}
	result_digest, err := client.Verify(keyid, "EH_PAD_NONE", "EH_SM3", "EH_DIGEST", base64.StdEncoding.EncodeToString(msg_digest[:]), signature_digest)
	if result_digest != true {
		t.Error(err)
	}

}

func TestRSAEncryptDecrypt(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	msg := "test for encrypt"
	keyspec := []string{"EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096"}
	padding_mode := []string{"EH_RSA_PKCS1", "EH_RSA_PKCS1_OAEP"}
	for _, keyspec := range keyspec {
		keyid, err := client.CreateKey(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
		if err != nil {
			t.Error(err)
		}
		for _, padding_mode := range padding_mode {
			ciphertext, err := client.AsymmetricEncrypt(keyid, base64.StdEncoding.EncodeToString([]byte(msg)), padding_mode)
			if err != nil {
				t.Error(err)
			}
			plaintext_b64, err := client.AsymmetricDecrypt(keyid, ciphertext, padding_mode)
			plaintext, _ := base64.StdEncoding.DecodeString(plaintext_b64)
			if err != nil || string(plaintext) != msg {
				t.Error(err)
			}
		}
	}
}

func TestSM2EncryptDecrypt(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyid, err := client.CreateKey("EH_SM2", "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
	if err != nil {
		t.Error(err)
	}
	msg := "test for encrypt"
	ciphertext, err := client.AsymmetricEncrypt(keyid, base64.StdEncoding.EncodeToString([]byte(msg)), "EH_PAD_NONE")
	if err != nil {
		t.Error(err)
	}
	plaintext_b64, err := client.AsymmetricDecrypt(keyid, ciphertext, "EH_PAD_NONE")
	plaintext, _ := base64.StdEncoding.DecodeString(plaintext_b64)
	if err != nil || string(plaintext) != msg {
		t.Error(err)
	}
}

func TestRSAInvalidPadding(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyid, err := client.CreateKey("EH_RSA_2048", "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
	if err != nil {
		t.Error(err)
	}
	msg := "test for encrypt"
	msg_digest256 := sha256.Sum256([]byte(msg))
	signature256_digest, err := client.Sign(keyid, "EH_PAD_NONE", "EH_SHA_256", "EH_DIGEST", base64.StdEncoding.EncodeToString(msg_digest256[:]))
	if signature256_digest != "" {
		t.Error("paddingmode mismatch test failed.")
	}
}

func TestInvalidKeyUsage(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyid, err := client.CreateKey("EH_RSA_2048", "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
	if err != nil {
		t.Error(err)
	}
	msg := "test for encrypt"
	ciphertext, err := client.AsymmetricEncrypt(keyid, base64.StdEncoding.EncodeToString([]byte(msg)), "EH_RSA_PKCS1")
	if ciphertext != "" {
		t.Error("keyusage mismatch test failed.")
	}
}

func TestImportKey(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyspec := []string{"EH_AES_GCM_128", "EH_AES_GCM_192", "EH_AES_GCM_256", "EH_SM4_CBC", "EH_SM4_CTR"}
	warpping_keyspec := []string{"EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096"}
	padding_mode := []string{"EH_RSA_PKCS1", "EH_RSA_PKCS1_OAEP"}
	for _, keyspec := range keyspec {
		for _, warpping_keyspec := range warpping_keyspec {
			for _, padding_mode := range padding_mode {
				keyid, err := client.CreateKey(keyspec, "EH_EXTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
				if err != nil {
					t.Error(err)
				}
				pubkey, importToken, err := client.GetParametersForImport(keyid, warpping_keyspec)
				if err != nil {
					t.Error(err)
				}
				key, err := generateRandomKey(keyspec)
				if err != nil {
					t.Error(err)
				}
				if _, err := rand.Read(key); err != nil {
					t.Error(err)
				}
				key_material, err := rsaEncrypt(pubkey, key, padding_mode)
				if err != nil {
					t.Error(err)
				}

				_, err = client.ImportKeyMaterial(keyid, padding_mode, base64.StdEncoding.EncodeToString(key_material), importToken)
				if err != nil {
					t.Error(err)
				}
				msg := "test for encrypt"
				aad := "aad"
				ciphertext, err := client.Encrypt(keyid, base64.StdEncoding.EncodeToString([]byte(msg)), base64.StdEncoding.EncodeToString([]byte(aad)))
				if err != nil {
					t.Error(err)
				}
				plaintext_b64, err := client.Decrypt(keyid, ciphertext, base64.StdEncoding.EncodeToString([]byte(aad)))
				if err != nil {
					t.Error(err)
				}
				plaintext, _ := base64.StdEncoding.DecodeString(plaintext_b64)
				if err != nil || string(plaintext) != msg {
					t.Error(err)
				}
			}
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyid, err := client.CreateKey("EH_AES_GCM_256", "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
	if err != nil {
		t.Error(err)
	}
	msg := "test for encrypt"
	aad := "aad"
	ciphertext, err := client.Encrypt(keyid, base64.StdEncoding.EncodeToString([]byte(msg)), base64.StdEncoding.EncodeToString([]byte(aad)))
	if err != nil {
		panic(err)
	}
	plaintext_b64, err := client.Decrypt(keyid, ciphertext, base64.StdEncoding.EncodeToString([]byte(aad)))
	if err != nil {
		panic(err)
	}
	plaintext, _ := base64.StdEncoding.DecodeString(plaintext_b64)
	if err != nil || string(plaintext) != msg {
		t.Error(err)
	}
}
