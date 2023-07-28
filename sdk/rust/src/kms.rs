use async_trait::async_trait;
use anyhow::{Result, anyhow};
use serde_json::{Map, Value};

use crate::api::KMS;
use crate::client::EHSMClient;

#[async_trait]
impl KMS for EHSMClient {

    async fn create_key(
            &mut self,
            keyspec: &str,
            origin: &str,
            purpose: Option<&str>,
            padding_mode: Option<&str>,
            digest_mode: Option<&str>) -> Result<String> {
                
            let mut payload: Map<String, Value> = Map::new();

            if let Some(digest_mode) = digest_mode {
                payload.insert("digest_mode".to_owned(), Value::String(digest_mode.to_owned()));
            }
            payload.insert("keyspec".to_owned(), Value::String(keyspec.to_owned()));
            payload.insert("origin".to_owned(), Value::String(origin.to_owned()));
            if let Some(padding_mode) = padding_mode {
                payload.insert("padding_mode".to_owned(), Value::String(padding_mode.to_owned()));
            }
            if let Some(purpose) = purpose {
                payload.insert("purpose".to_owned(), Value::String(purpose.to_owned()));
            }

            let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

            let resp_json = crate::client::do_post(body, &self.base_url, "CreateKey")
                                .await.unwrap();
            
            let keyid = resp_json["result"]["keyid"]
                            .as_str()
                            .ok_or_else(|| anyhow!("Missing keyid"))?
                            .to_owned();
            Ok(keyid)
        }

    async fn decrypt(&mut self, _keyid: &str, data_b64: &str, aad_b64: Option<&str>) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        payload.insert("keyid".to_owned(), Value::String(_keyid.to_owned()));
        if crate::client::is_base64(aad_b64.unwrap()) && crate::client::is_base64(data_b64) {
            if let Some(aad_b64) = aad_b64 {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            }
            payload.insert("ciphertext".to_owned(), Value::String(data_b64.to_owned()));
        } else {
            println!("Please base64 encode the value");
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "Decrypt")
                                .await.unwrap();
        
        let plaintext = resp_json["result"]["plaintext"]
                        .as_str()
                        .ok_or_else(|| anyhow!("Missing plaintext"))?
                        .to_owned();
        Ok(plaintext)

    }

    async fn encrypt(&mut self, _keyid: &str, data_b64: &str, aad_b64: Option<&str>) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        payload.insert("keyid".to_owned(), Value::String(_keyid.to_owned()));
        if crate::client::is_base64(aad_b64.unwrap()) && crate::client::is_base64(data_b64) {
            if let Some(aad_b64) = aad_b64 {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            }
            payload.insert("plaintext".to_owned(), Value::String(data_b64.to_owned()));
        } else {
            println!("Please base64 encode the value");
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);
        
        let resp_json = crate::client::do_post(body, &self.base_url, "Encrypt")
                                .await.unwrap();

        let ciphertext = resp_json["result"]["ciphertext"]
                        .as_str()
                        .ok_or_else(|| anyhow!("Missing ciphertext"))?
                        .to_owned();
    
        Ok(ciphertext)

    }

    async fn get_publickey(&mut self, keyid: &str) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();

        payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "GetPublicKey")
                            .await.unwrap();    
       
        let pubkey = resp_json["result"]["pubkey"]
                        .as_str()
                        .ok_or_else(|| anyhow!("Missing pubkey"))?
                        .to_owned();
    
        Ok(pubkey)
    }

    async fn sign(&mut self, keyid: &str, digest: &str) -> Result<String> {
        let mut payload: Map<String, Value> = Map::new();

        payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        payload.insert("digest".to_owned(), Value::String(digest.to_owned()));

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);

        let resp_json = crate::client::do_post(body, &self.base_url, "Sign")
                                .await.unwrap();
        
        let signature = resp_json["result"]["signature"]
                        .as_str()
                        .ok_or_else(|| anyhow!("Missing signature"))?
                        .to_owned();
        
        Ok(signature)
    }

    async fn verify(&mut self, keyid: &str, digest: &str, signature: &str) -> Result<bool> {
        let mut payload: Map<String, Value> = Map::new();

        payload.insert("keyid".to_owned(), Value::String(keyid.to_owned()));
        payload.insert("digest".to_owned(), Value::String(digest.to_owned()));
        payload.insert("signature".to_owned(), Value::String(signature.to_owned()));

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);
        let resp_json = crate::client::do_post(body, &self.base_url, "Verify")
                                .await.unwrap();
        
        let result = resp_json["result"]["result"]  
                .as_bool()
                .ok_or_else(|| anyhow!("Verify false"))?;
        Ok(result)
    }

    async fn generate_datakey_without_plaintext(&mut self, _keyid: &str, _len: &i32, aad_b64: Option<&str>)-> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        payload.insert("keyid".to_owned(), Value::String(_keyid.to_owned()));
        if crate::client::is_base64(aad_b64.unwrap()) {
            if let Some(aad_b64) = aad_b64 {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            }
        } else {
            println!("Please base64 encode the value");
        }
        payload.insert("keylen".to_owned(), Value::Number(_len.to_owned().into()));

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);
        
        let resp_json = crate::client::do_post(body, &self.base_url, "GenerateDataKeyWithoutPlaintext")
                                .await.unwrap();

        let datakey_cipher = resp_json["result"]["ciphertext"]
                                .as_str()
                                .ok_or_else(|| anyhow!("Missing ciphertext"))?
                                .to_owned();
    
        Ok(datakey_cipher)
    }

    async fn generate_datakey(&mut self, _keyid: &str, _len: &i32, aad_b64: Option<&str>)-> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        payload.insert("keyid".to_owned(), Value::String(_keyid.to_owned()));
        if let Some(aad_b64) = aad_b64 {
            payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
        }
        payload.insert("keylen".to_owned(), Value::Number(_len.to_owned().into()));

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);
        
        let resp_json = crate::client::do_post(body, &self.base_url, "GenerateDataKey")
                                .await.unwrap();
        
        let datakey_cipher = resp_json["result"]["ciphertext"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing ciphertext"))?
                .to_owned();
    
        Ok(datakey_cipher)
    }

    async fn asymmetric_encrypt(&mut self, _keyid: &str, data_b64: &str)-> Result<String> {
        let mut payload: Map<String, Value> = Map::new();
        payload.insert("keyid".to_owned(), Value::String(_keyid.to_owned()));
        if crate::client::is_base64(data_b64) {
            payload.insert("plaintext".to_owned(), Value::String(data_b64.to_owned()));
        } else {
            println!("Please base64 encode the value");
        }
        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);
        
        let resp_json = crate::client::do_post(body, &self.base_url, "AsymmetricEncrypt")
                                .await.unwrap();
        
        let ciphertext = resp_json["result"]["ciphertext"]
                                    .as_str()
                                    .ok_or_else(|| anyhow!("Missing ciphertext"))?
                                    .to_owned();
    
        Ok(ciphertext)
    }
 
    async fn asymmetric_decrypt(&mut self, _keyid: &str, data_b64: &str)-> Result<String>{
        let mut payload: Map<String, Value> = Map::new();
        payload.insert("keyid".to_owned(), Value::String(_keyid.to_owned()));
        if crate::client::is_base64(data_b64) {
            payload.insert("ciphertext".to_owned(), Value::String(data_b64.to_owned()));
        } else {
            println!("Please base64 encode the value");
        }

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);
        
        let resp_json = crate::client::do_post(body, &self.base_url, "AsymmetricDecrypt")
                                .await.unwrap();
        
        let plaintext = resp_json["result"]["plaintext"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing plaintext"))?
                .to_owned();
        Ok(plaintext)
    }

    async fn export_datakey(&mut self, _keyid: &str, _ukeyid: &str, _datakey: &str, aad_b64: Option<&str>) -> Result<String>{
        let mut payload: Map<String, Value> = Map::new();
        payload.insert("keyid".to_owned(), Value::String(_keyid.to_owned()));
        if crate::client::is_base64(aad_b64.unwrap()) {
            if let Some(aad_b64) = aad_b64 {
                payload.insert("aad".to_owned(), Value::String(aad_b64.to_owned()));
            }
        } else {
            println!("Please base64 encode the value");
        }
        payload.insert("olddatakey_base".to_owned(), Value::String(_datakey.to_owned()));
        payload.insert("ukeyid".to_owned(), Value::String(_ukeyid.to_owned()));

        let body = crate::client::init_params(&payload, &self.appid, &self.apikey);
        
        let resp_json = crate::client::do_post(body, &self.base_url, "ExportDataKey")
                                .await.unwrap();
        
        let datakey = resp_json["result"]["newdatakey"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing newdatakey"))?
                .to_owned();

        Ok(datakey)
    }
}



