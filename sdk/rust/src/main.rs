use tokio;

use base64::{decode, encode};
use ehsm_client::{api::KMS, client::EHSMClient};

const PLAINT_TEXT: &str = "Intel test";

#[tokio::main]
async fn main() {
    let mut client = EHSMClient::new();

    let keyid = client
        .create_key(
            "EH_AES_GCM_128",
            "EH_INTERNAL_KEY",
            "EH_KEYUSAGE_ENCRYPT_DECRYPT",
        )
        .await
        .expect("fail to get keyid");
    let decodedata = &encode(PLAINT_TEXT).to_string()[..];
    let encrypt = client
        .encrypt(
            &keyid.to_owned(),
            &decodedata.to_owned(),
            Some(&encode("test").to_string()[..]),
        )
        .await
        .expect("fail to encrypt");
    let decrypt = client
        .decrypt(
            &keyid.to_owned(),
            &encrypt.to_owned(),
            Some(&encode("test").to_string()[..]),
        )
        .await;
    let decode = String::from_utf8(decode(decrypt.unwrap()).unwrap()[..].to_vec());
    match decode {
        Ok(key) => {
            println!("Decrypt : {:?}", key);
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}
