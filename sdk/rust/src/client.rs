use hmac::{Hmac, NewMac, Mac};
use sha2::Sha256;
use serde_json::{json, Map, Value};
use reqwest::{ClientBuilder};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;

// Skip certificate validation
const SKIP_CERTS: bool = true;

pub struct EHSMClient {
    pub base_url: String,
    pub appid: String,
    pub apikey: String,
}

pub fn gen_sign_string(params: &Map<String, Value>) -> String {
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

pub fn init_params(payload: &Map<String, Value>, appid: &str, apikey: &str) -> Value {
    let mut params: Map<String, Value> = Map::new();
    
    let rng: u32 =rand::thread_rng().gen();

    params.insert("appid".to_owned(), Value::String(appid.to_owned()));
    params.insert("nonce".to_owned(), Value::String(rng.to_string().to_owned()));

    if !payload.is_empty() {
        params.insert("payload".to_owned(), Value::Object(payload.clone()));
    }

    params.insert("timestamp".to_owned(), Value::String(format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis())));

    let sign_string = gen_sign_string(&params).replace("\"", "");

    let mut hmac = Hmac::<Sha256>::new_varkey(apikey.as_bytes()).expect("Invalid key");
    hmac.update(sign_string.as_bytes());
    let sign = base64::encode(hmac.finalize().into_bytes());

    params.insert("sign".to_owned(), Value::String(sign));

    json!(params)
}

pub async fn do_post(body: Value, base_url: &str, action: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let client = ClientBuilder::new()
                .danger_accept_invalid_certs(SKIP_CERTS)
                .build()?;
    
    let resp = client
        .post(&format!("{}/ehsm?Action={}", base_url, action))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await?;
    if !resp.status().is_success() {
        println!("send request failed!");
    }
    let resp_json: Value = serde_json::from_str(&resp.text().await?)?;
    Ok(resp_json)
}

pub async fn do_get(base_url: &str, action: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let client = ClientBuilder::new()
                .danger_accept_invalid_certs(SKIP_CERTS)
                .build()?;

    let resp = client
                .get(&format!("{}/ehsm?Action={}", base_url, action))
                .header("Content-Type", "application/json")
                .body("")
                .send()
                .await?;      
    if !resp.status().is_success() {
        println!("send request failed!");
    }
    let resp_json: Value = serde_json::from_str(&resp.text().await?)?;
    Ok(resp_json)
}

pub fn is_base64(s: &str) -> bool {
	base64::decode_config(s, base64::STANDARD).is_ok()
}

impl EHSMClient {
    pub fn new() -> Self {
        Self {
            base_url: env::var("EHSM_ADDR").expect("Please export EHSM_ADDR."),
            appid: env::var("EHSM_APPID").expect("Please export EHSM_APPID."),
            apikey: env::var("EHSM_APIKEY").expect("Please export EHSM_APIKEY."),
        }
    }
/*
Description:
Obtain a valid access keypair (APPID and APIKey) which is MUST before request the public cryptographic APIs.

Notes: This operation only need to do once. After get the APPID and APIKey, user should be responsible for managing the keypair.
Output:
apikey  -- the API access key to the eHSM-KMS server.
appid   -- An uuid which represent the customer app.
*/
    pub async fn enroll() {
        let base_url = env::var("EHSM_ADDR").expect("Please export EHSM_ADDR.");
        let resp_json = crate::client::do_get(&base_url, "Enroll")
                                .await.unwrap();
        println!("enroll body: {}", resp_json);
    }
}

