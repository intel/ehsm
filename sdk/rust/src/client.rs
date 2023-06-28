use async_trait::async_trait;
use anyhow::{Result, anyhow};
use hmac::{Hmac, NewMac, Mac};
use sha2::Sha256;
//use tokio;
// use std::collections::BTreeMap;
use serde_json::{json, Map, Value};
//use serde::{Serialize, Deserialize};
use reqwest::{ClientBuilder};

use crate::api::{KMS, Secret};

pub struct EHSMClient {
    pub base_url: String,
    pub appid: String,
    pub apikey: String,
}

fn gen_sign_string(params: &Map<String, Value>) -> String {
    let mut sign_string = String::new();

    for (key, value) in params {
        if key == "payload" {
            if let Value::Object(payload) = value {
                let nested_params = gen_sign_string(payload);
                sign_string.push_str(&format!("{}={}&", key, nested_params));
            }
        } else {
            sign_string.push_str(&format!("{}={}&", key, value));
        }
    }

    let sign_string = sign_string.trim_end_matches('&');

    sign_string.to_owned()
}

fn init_params(payload: &Map<String, Value>, appid: &str, apikey: &str) -> Value {
    let mut params: Map<String, Value> = Map::new();

    params.insert("appid".to_owned(), Value::String(appid.to_owned()));

    if !payload.is_empty() {
        params.insert("payload".to_owned(), Value::Object(payload.clone()));
    }

    params.insert("timestamp".to_owned(), Value::String(format!("{}", chrono::Utc::now().timestamp_millis())));

    let sign_string = gen_sign_string(&params).replace("\"", "");

    // println!("sign_string is {}", sign_string);

    let mut hmac = Hmac::<Sha256>::new_varkey(apikey.as_bytes()).expect("Invalid key");
    hmac.update(sign_string.as_bytes());
    let sign = base64::encode(hmac.finalize().into_bytes());

    params.insert("sign".to_owned(), Value::String(sign));

    json!(params)
}

#[async_trait]
impl KMS for EHSMClient {
    async fn create_key(
            &mut self,
            keyspec: &str,
            origin: &str,
            purpose: Option<&str>,
            padding_mode: Option<&str>,
            digest_mode: Option<&str>) -> Result<String> {
            println!("generate key with keyspec {}", keyspec);

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

            let body = init_params(&payload, &self.appid, &self.apikey);

            let client = ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .build()?;

            let resp = client
                .post(&format!("{}CreateKey", self.base_url))
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .await?;

            if !resp.status().is_success() {
                //return Err(Error::from(resp.status()));
                println!("send request failed!");
            }

            let resp_json: Value = serde_json::from_str(&resp.text().await?)?;
            let keyid = resp_json["result"]["keyid"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing keyid"))?
                    .to_owned();
        
            Ok(keyid)
        }

    async fn decrypt(&mut self, _keyid: &str, _data: &str, _aad: Option<&str>) -> Result<String>{
        Ok("Not Implemented".to_string())
    }

    async fn encrypt(&mut self, _keyid: &str, _data: &str, _aad: Option<&str>) -> Result<String>{
        Ok("Not Implemented".to_string())
    }
}

#[async_trait]
impl Secret for EHSMClient {

    #[warn(unused_variables)]
    async fn create_secret(
        &mut self,
        secret_name: &str,
        secret_data: &str,
        encryption_key_id: Option<&str>,
        description: Option<&str>,
        rotation_interval: Option<u32>) -> Result<String> {
            Ok("Not Implemented".to_string())
        }
}

impl EHSMClient {
    pub fn new(base_url: &str, appid: &str, apikey: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            appid: appid.to_string(),
            apikey: apikey.to_string(),
        }
    }
}
