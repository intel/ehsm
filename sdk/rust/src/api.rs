use async_trait::async_trait;
use anyhow::Result;

#[async_trait]
pub trait KMS {
/*
Description:
Create a customer master key(CMK) for the user, 
which can be a symmetric or an asymmetric key, 
for the symmetric cmk mainly used to wrap the datakey, 
also can be used to encrypted an arbitrary set of bytes data(<6KB). 
And for the asymmetric cmk mainly used to sign/verify 
or asymmetric encrypt/decrypt datas(not for the datakey.)
Input:
keyspec -EH_AES_GCM_128,
        -EH_AES_GCM_256,
        -EH_RSA_2048,
        -EH_RSA_3072,
        -EH_EC_P256,
        -EH_EC_P521,
        -EH_SM2,
        -EH_SM4_CBC,
        -EH_HMAC,
origin  -EH_INTERNAL_KEY (generated from the eHSM inside)
        -EH_EXTERNAL_KEY (generated by the customer and want to import into the eHSM),  
keyusage -EH_KEYUSAGE_ENCRYPT_DECRYPT,
         -EH_KEYUSAGE_SIGN_VERIFY,
Output:
keyid  -- A uinque keyid of the cmk.
*/
    async fn create_key(
        &mut self,
        keyspec: &str,
        origin: &str,
        keyusage: &str) -> Result<String>;
/*
Description:
Get public key from keypair.
Input:
keyid  -- A uinque keyid of the cmk.
Output:
pubkey  -- the data of the public key.
*/
    async fn get_publickey(&mut self, keyid: &str) -> Result<String>;
/*
Description:
Performs sign operation using the cmk(only support asymmetric keyspec).
Input:
keyid  -- A unique keyid of asymmetric cmk.
message  -- Input raw string for messgae type EH_RAW or digest string for messgae type EH_DIGEST.
message_type
    -EH_RAW(KMS will calculate the digest with digest mode for your message)
    -EH_DIGEST(users need to fill in a digest value calculated using the digest mode.)

padding_mode  -- Padding_mode is necessary when keyspec is RSA.
    -EH_RSA_PKCS1(only support rsa keyspec)
    -EH_RSA_PKCS1_PSS(only support rsa keyspec)
    -EH_PAD_NONE(supprot ecc and sm2 keyspec)

digest_mode  -- If digest mode is not provided, the default digest mode will be used.
               EH_SHA_SHA256 will be used for rsa and ecc, and EH_SM3 will be used for sm2.
               If use sm2 keypair, digest mode must be EH_SM3.
    -EH_SHA_224
    -EH_SHA_256
    -EH_SHA_384
    -EH_SHA_512
    -EH_SM3

Output:
signature  -- The calculated signature value stores in BASE64 string.
*/
    async fn sign(&mut self, 
        keyid: &str, 
        padding_mode: &str, 
        digest_mode: &str,
        message_type: &str,
        message: &str) -> Result<String>;
/*
Description:
Performs verify operation using the cmk(only support asymmetric keyspec).
Input:
keyid    -- A unique keyid of asymmetric cmk.
signature -- The signature of the digest signed by the cmk in BASE64 string.
message         --Input raw string for messgae type EH_RAW or digest string for messgae type EH_DIGEST.
message_type
        -EH_RAW(KMS will calculate the digest with digest mode for your message)
        -EH_DIGEST(users need to fill in a digest value calculated using the digest mode.)

padding_mode    --padding_mode is necessary when keyspec is RSA.
        -EH_RSA_PKCS1(only support rsa keyspec)
        -EH_RSA_PKCS1_PSS(only support rsa keyspec)
        -EH_PAD_NONE(supprot ecc and sm2 keyspec)

digest_mode     --If digest mode is not provided, the default digest mode will be used.
                  EH_SHA_SHA256 will be used for rsa and ecc, and EH_SM3 will be used for sm2.
                  If use sm2 keypair, digest mode must be EH_SM3.
        -EH_SHA_224
        -EH_SHA_256
        -EH_SHA_384
        -EH_SHA_512
        -EH_SM3

Output:
result  -- True or False: indicate whether the signature passed the verification.
*/
    async fn verify(&mut self, 
        keyid: &str, 
        padding_mode: &str, 
        digest_mode: &str,
        message_type: &str,
        message: &str, 
        signature: &str) -> Result<bool>;
/*
Description:
Decrypt an arbitrary set of bytes using the CMK.(only support symmetric types).
Input:
keyid  -- The keyid of the symmetric cmk which used to decryt the ciphertext.
aad_b64  -- Some extra datas input by the user, which could help to to ensure data integrity, 
            and not be included in the cipherblobs. The aad stored in BASE64 string.
data_b64  -- Ciphertext to be decrypted in BASE64 string.
Output:
plaintext  -- Plain data after decrypt and stored in BASE64 string.
*/
    async fn decrypt(&mut self, _keyid: &str, data_b64: &str, aad_b64: Option<&str>) -> Result<String>;
/*
Description:
Encrypt an arbitrary set of bytes using the CMK.(only support symmetric types).
Input:
keyid  -- The keyid of the cmk you want to use which must be a symmetric key.
aad_b64  -- Some extra datas input by the user, which could help to to ensure data integrity, 
            and not be included in the cipherblobs. The aad stored in BASE64 string.
data_b64  -- The datas of the plaintext which in based64 encoding.
Output:
ciphertext  -- The result in json object for the Ciphertext which in based64 encoding.
*/
    async fn encrypt(&mut self, _keyid: &str, data_b64: &str, aad_b64: Option<&str>) -> Result<String>;
/*
Description:
The same as GenerateDataKey, but it doesn’t return plaintext of generated DataKey.
Input:
keyid  -- A unique id of the specified symmetric CMK.
aad_b64  -- Some extra datas input by the user, which could help to to ensure data integrity, 
            and not be included in the cipherblobs. The aad stored in BASE64 string.
keylen  -- Specifies the length of the plaintext, length is 0~1024 bytes.
Output:
ciphertext  -- The cipher text of the data key stores in BASE64 string.
*/
    async fn generate_datakey_without_plaintext(&mut self, _keyid: &str, _len: &i32, aad_b64: Option<&str>)-> Result<String>;
/*
Description:
Generates a random data key that is used to locally encrypt data. 
the DataKey will be wrapped by the specified CMK(only support asymmetric keyspec), 
and it will return the plaintext and ciphertext of the data key.

You can use the plaintext of the data key to locally encrypt your data 
without using KMS and store the encrypted data together 
with the ciphertext of the data key, then clear the plaintext data from memory as soon as possible.

when you want to obtain the plaintext of datakey again, you can call the Decrypt with the cmk to get the plaintext data.
Input:
keyid  -- A unique id of the specified symmetric CMK.
aad_b64  -- Some extra datas input by the user, which could help to to ensure data integrity, 
            and not be included in the cipherblobs. The aad stored in BASE64 string.
keylen  -- Specifies the length of the plaintext, length is 0~1024 bytes.
Output:
ciphertext  -- The cipher text of the data key stores in BASE64 string.
*/
    async fn generate_datakey(&mut self, _keyid: &str, _len: &i32, aad_b64: Option<&str>)-> Result<String>;
/*
Description:
Encrypt an arbitrary set of bytes using the CMK.(only support asymmetric types).
Input:
keyid  -- A unique keyid for asymmetric key.
data_b64  -- The datas of the plaintext which in based64 encoding.
padding mode  -- Padding_mode is necessary when keyspec is RSA.
    -EH_RSA_PKCS1
    -EH_RSA_PKCS1_OAEP
    -EH_PAD_NONE
Output:
ciphertext  -- The result in json object for the Ciphertext which in based64 encoding.
*/
    async fn asymmetric_encrypt(&mut self, _keyid: &str, data_b64: &str, padding_mode: &str)-> Result<String>;
/*
Description:
Decrypt an arbitrary set of bytes using the CMK.(only support asymmetric types).
Input:
keyid  -- The keyid of the asymmetric cmk.
data_b64  -- The data of the ciphertext in BASE64 string.
padding mode  -- Padding_mode is necessary when keyspec is RSA.
	-EH_RSA_PKCS1
	-EH_RSA_PKCS1_OAEP
	-EH_PAD_NONE
Output:
plaintext  -- Plaint data after decrypt and stored in BASE64 string.
*/  
    async fn asymmetric_decrypt(&mut self, _keyid: &str, data_b64: &str, padding_mode: &str)-> Result<String>;
/*
Description:
ehsm-core enclave will decrypt user-supplied ciphertextblob with specified CMK to get the plaintext of DataKey, 
then use the user-supplied Public key to encrypt this DataKey(aka ExportedDataKey). 
This ExportedDataKey (ciphertext) will be returned to caller.
Input:
keyid  -- A unique id of the specified symmetric CMK.
ukeyid  -- The unique keyid of the asymmetric CMK which used to export.
aad_b64  -- Some extra datas input by the user, which could help to to ensure data integrity. 
            The aad stored in BASE64 string.
datakey  -- The ciphertext of the datakey wrapped by the cmk in BASE64 string.
Output:
newdatakey  -- The ciphertext of the datakey wrapped by the ukey stores in BASE64 string.
*/
    async fn export_datakey(&mut self, _keyid: &str, _ukeyid: &str, _datakey: &str, aad_b64: Option<&str>)-> Result<String>;
}
#[async_trait]
pub trait Secret {
    async fn create_secret(
        &mut self,
        secret_name: &str,
        secret_data: &str,
        encryption_key_id: Option<&str>,
        description: Option<&str>,
        rotation_interval: Option<u32>) -> Result<String>;
}