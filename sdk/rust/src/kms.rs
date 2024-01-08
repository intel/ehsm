use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::api::KMS;
use crate::client::EHSMClient;

#[async_trait]
impl KMS for EHSMClient {
    async fn create_key(&mut self, keyspec: &str, origin: &str, keyusage: &str) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyspec.is_empty() {
            payload.insert("keyspec".to_owned(), Value::String(keyspec.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyspec is empty."));
        }
        if !origin.is_empty() {
            payload.insert("origin".to_owned(), Value::String(origin.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Origin is empty."));
        }
        if !keyusage.is_empty() {
            payload.insert("keyusage".to_owned(), Value::String(keyusage.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyusage is empty."));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "CreateKey")
            .await
            .unwrap();

        let keyid = resp_json["result"]["keyid"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing keyid"))?
            .to_owned();
        Ok(keyid)
    }

    async fn decrypt(
        &mut self,
        keyid: &str,
        data_b64: &str,
        aad_b64: Option<&str>,
    ) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if let Some(aad_b64) = aad_b64 {
            if crate::client::is_base64(aad_b64) {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            } else {
                return Err::<String, anyhow::Error>(anyhow::Error::msg(
                    "Aad should be base64 encode.",
                ));
            }
        }
        if !data_b64.is_empty() && crate::client::is_base64(data_b64) {
            payload.insert("ciphertext".to_owned(), Value::String(data_b64.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg(
                "Data should be base64 encoded and not empty.",
            ));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "Decrypt")
            .await
            .unwrap();

        let plaintext = resp_json["result"]["plaintext"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing plaintext"))?
            .to_owned();
        Ok(plaintext)
    }

    async fn encrypt(
        &mut self,
        keyid: &str,
        data_b64: &str,
        aad_b64: Option<&str>,
    ) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if let Some(aad_b64) = aad_b64 {
            if crate::client::is_base64(aad_b64) {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            } else {
                return Err::<String, anyhow::Error>(anyhow::Error::msg(
                    "Aad should be base64 encode.",
                ));
            }
        }
        if !data_b64.is_empty() && crate::client::is_base64(data_b64) {
            payload.insert("plaintext".to_owned(), Value::String(data_b64.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg(
                "Data should be base64 encoded and not empty.",
            ));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "Encrypt")
            .await
            .unwrap();

        let ciphertext = resp_json["result"]["ciphertext"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing ciphertext"))?
            .to_owned();

        Ok(ciphertext)
    }

    async fn get_publickey(&mut self, keyid: &str) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "GetPublicKey")
            .await
            .unwrap();
        let pubkey = resp_json["result"]["pubkey"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing pubkey"))?
            .to_owned();

        Ok(pubkey)
    }

    async fn sign(
        &mut self,
        keyid: &str,
        padding_mode: &str,
        digest_mode: &str,
        message_type: &str,
        message: &str,
    ) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();

        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if !padding_mode.is_empty() {
            payload.insert(
                "padding_mode".to_owned(),
                Value::String(padding_mode.to_owned()),
            );
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Padding_mode is empty."));
        }
        if !digest_mode.is_empty() {
            payload.insert(
                "digest_mode".to_owned(),
                Value::String(digest_mode.to_owned()),
            );
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Digest_mode is empty."));
        }
        if !message_type.is_empty() {
            payload.insert(
                "message_type".to_owned(),
                Value::String(message_type.to_owned()),
            );
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Message_type is empty."));
        }
        if !message.is_empty() && crate::client::is_base64(message) {
            payload.insert("message".to_owned(), Value::String(message.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg(
                "Message should be base64 encoded and not empty.",
            ));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "Sign")
            .await
            .unwrap();

        let signature = resp_json["result"]["signature"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing signature"))?
            .to_owned();

        Ok(signature)
    }

    async fn verify(
        &mut self,
        keyid: &str,
        padding_mode: &str,
        digest_mode: &str,
        message_type: &str,
        message: &str,
        signature: &str,
    ) -> Result<bool> {
        let mut payload: Map<String, Value> = Map::new();

        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if !padding_mode.is_empty() {
            payload.insert(
                "padding_mode".to_owned(),
                Value::String(padding_mode.to_owned()),
            );
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg("Padding_mode is empty."));
        }
        if !digest_mode.is_empty() {
            payload.insert(
                "digest_mode".to_owned(),
                Value::String(digest_mode.to_owned()),
            );
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg("Digest_mode is empty."));
        }
        if !message_type.is_empty() {
            payload.insert(
                "message_type".to_owned(),
                Value::String(message_type.to_owned()),
            );
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg("Message_type is empty."));
        }
        if !message.is_empty() && crate::client::is_base64(message) {
            payload.insert("message".to_owned(), Value::String(message.to_owned()));
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg(
                "Message should be base64 encoded and not empty.",
            ));
        }
        if !signature.is_empty() && crate::client::is_base64(signature) {
            payload.insert("signature".to_owned(), Value::String(signature.to_owned()));
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg(
                "Signature should be base64 encoded and not empty.",
            ));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);
        let resp_json = crate::client::do_post(body, &self.base_url, "Verify")
            .await
            .unwrap();

        let result = resp_json["result"]["result"]
            .as_bool()
            .ok_or_else(|| anyhow!("Verify false"))?;
        Ok(result)
    }

    async fn generate_datakey_without_plaintext(
        &mut self,
        keyid: &str,
        keylen: &i32,
        aad_b64: Option<&str>,
    ) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if let Some(aad_b64) = aad_b64 {
            if crate::client::is_base64(aad_b64) {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            } else {
                return Err::<String, anyhow::Error>(anyhow::Error::msg(
                    "Aad should be base64 encode.",
                ));
            }
        }
        if keylen > &0 && keylen <= &1024 {
            payload.insert("keylen".to_owned(), Value::Number(keylen.to_owned().into()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg(
                "Keylen should range from 0 to 1024.",
            ));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json =
            crate::client::do_post(body, &self.base_url, "GenerateDataKeyWithoutPlaintext")
                .await
                .unwrap();

        let datakey_cipher = resp_json["result"]["ciphertext"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing ciphertext"))?
            .to_owned();

        Ok(datakey_cipher)
    }

    async fn generate_datakey(
        &mut self,
        keyid: &str,
        keylen: &i32,
        aad_b64: Option<&str>,
    ) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if let Some(aad_b64) = aad_b64 {
            if crate::client::is_base64(aad_b64) {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            } else {
                return Err::<String, anyhow::Error>(anyhow::Error::msg(
                    "Aad should be base64 encode.",
                ));
            }
        }
        if keylen > &0 && keylen <= &1024 {
            payload.insert("keylen".to_owned(), Value::Number(keylen.to_owned().into()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg(
                "Keylen should range from 0 to 1024.",
            ));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "GenerateDataKey")
            .await
            .unwrap();

        let datakey_cipher = resp_json["result"]["ciphertext"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing ciphertext"))?
            .to_owned();

        Ok(datakey_cipher)
    }

    async fn asymmetric_encrypt(
        &mut self,
        keyid: &str,
        data_b64: &str,
        padding_mode: &str,
    ) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if !data_b64.is_empty() && crate::client::is_base64(data_b64) {
            payload.insert("plaintext".to_owned(), Value::String(data_b64.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg(
                "Data should be base64 encoded and not empty.",
            ));
        }
        if !padding_mode.is_empty() {
            payload.insert(
                "padding_mode".to_owned(),
                Value::String(padding_mode.to_owned()),
            );
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Padding_mode is empty."));
        }
        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "AsymmetricEncrypt")
            .await
            .unwrap();

        let ciphertext = resp_json["result"]["ciphertext"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing ciphertext"))?
            .to_owned();

        Ok(ciphertext)
    }

    async fn asymmetric_decrypt(
        &mut self,
        keyid: &str,
        data_b64: &str,
        padding_mode: &str,
    ) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if !padding_mode.is_empty() {
            payload.insert(
                "padding_mode".to_owned(),
                Value::String(padding_mode.to_owned()),
            );
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Padding_mode is empty."));
        }
        if !data_b64.is_empty() && crate::client::is_base64(data_b64) {
            payload.insert("ciphertext".to_owned(), Value::String(data_b64.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg(
                "Data should be base64 encoded and not empty.",
            ));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "AsymmetricDecrypt")
            .await
            .unwrap();

        let plaintext = resp_json["result"]["plaintext"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing plaintext"))?
            .to_owned();
        Ok(plaintext)
    }

    async fn export_datakey(
        &mut self,
        keyid: &str,
        ukeyid: &str,
        datakey: &str,
        aad_b64: Option<&str>,
    ) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if let Some(aad_b64) = aad_b64 {
            if crate::client::is_base64(aad_b64) {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            } else {
                return Err::<String, anyhow::Error>(anyhow::Error::msg(
                    "Aad should be base64 encode.",
                ));
            }
        }
        if !datakey.is_empty() && crate::client::is_base64(datakey) {
            payload.insert(
                "olddatakey_base".to_owned(),
                Value::String(datakey.to_owned()),
            );
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg(
                "Datakey should be base64 encoded and not empty.",
            ));
        }
        if !ukeyid.is_empty() {
            payload.insert("ukeyid".to_owned(), Value::String(ukeyid.to_owned()));
        } else {
            return Err::<String, anyhow::Error>(anyhow::Error::msg("Ukeyid is empty."));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "ExportDataKey")
            .await
            .unwrap();

        let datakey = resp_json["result"]["newdatakey"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing newdatakey"))?
            .to_owned();

        Ok(datakey)
    }

    async fn get_parameters_for_import(
        &mut self,
        keyid: &str,
        keyspec: &str,
    ) -> Result<(String, String)> {
        let mut payload: Map<String, Value> = Map::new();

        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<(String, String), anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if !keyspec.is_empty() {
            payload.insert("keyspec".to_owned(), Value::String(keyspec.to_owned()));
        } else {
            return Err::<(String, String), anyhow::Error>(anyhow::Error::msg("Keyspec is empty."));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "GetParametersForImport")
            .await
            .unwrap();
        let pubkey = resp_json["result"]["pubkey"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing pubkey"))?
            .to_owned();
        let import_token = resp_json["result"]["importToken"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing importToken"))?
            .to_owned();

        Ok((pubkey, import_token))
    }

    async fn import_key_material(
        &mut self,
        keyid: &str,
        padding_mode: &str,
        key_material: &str,
        import_token: &str,
    ) -> Result<bool> {
        let mut payload: Map<String, Value> = Map::new();

        if !keyid.is_empty() {
            payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg("Keyid is empty."));
        }
        if !padding_mode.is_empty() {
            payload.insert(
                "padding_mode".to_owned(),
                Value::String(padding_mode.to_owned()),
            );
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg("padding_mode is empty."));
        }
        if !key_material.is_empty() && crate::client::is_base64(key_material) {
            payload.insert(
                "key_material".to_owned(),
                Value::String(key_material.to_owned()),
            );
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg(
                "key_material should be base64 encoded and not empty.",
            ));
        }
        if !import_token.is_empty() && crate::client::is_base64(import_token) {
            payload.insert(
                "importToken".to_owned(),
                Value::String(import_token.to_owned()),
            );
        } else {
            return Err::<bool, anyhow::Error>(anyhow::Error::msg(
                "import_token should be base64 encoded and not empty.",
            ));
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "ImportKeyMaterial")
            .await
            .unwrap();

        let result = resp_json["result"]["result"]
            .as_bool()
            .ok_or_else(|| anyhow!("result is none"))?
            .to_owned();
        Ok(result)
    }
}
