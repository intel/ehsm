use tokio;
//use serde_json::{json, Map, Value};
//use serde::{Serialize, Deserialize};
//use reqwest::{Client, ClientBuilder, Result, Error};

use ehsm_client::{client::EHSMClient, api::KMS};

const APP_ID: &str = "011249a4-2f17-4380-8922-a90ff5dd3976";
const API_KEY: &str = "Zgeiig9SFvNy6vWRpSQMSFyrWUfEYnnG";
const BASE_URL: &str = "https://10.112.240.169:9002/ehsm?Action=";

#[tokio::main]
async fn main() {

    let mut client = EHSMClient::new(&BASE_URL.to_owned(), &APP_ID.to_owned(), &API_KEY.to_owned());
    println!("client.base_url: {}", client.base_url);

    let _result = client.create_key("EH_RSA_3072", "EH_INTERNAL_KEY", None, None, None).await;

    match _result {
        Ok(key) => {
            println!("key created: {}", key);
        }
        Err(err) => {
            eprintln!("Error creating key: {}", err);
        }
    }
}
