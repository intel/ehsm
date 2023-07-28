
#[cfg(test)]
mod tests {
    use base64::{encode, decode};
    use crate::{client::EHSMClient, api::KMS};

    const DIGEST: &str = "JVAPBOYcL7HFfJhtEwqL1lDoMZnUVwxYpCa6atFTH0E=";
    const PLAINT_TEXT: &str = "Intel test";

    #[tokio::test]
    async fn test_asymmetrickey_generate_key() {
        let mut client = EHSMClient::new();

        let keyspecs = vec!["EH_RSA_3072", "EH_RSA_4096", "EH_RSA_2048", "EH_SM2", "EH_EC_P224", "EH_EC_P256", "EH_EC_P384", "EH_EC_P521"];
        let padding_modes = vec![Some("EH_PAD_RSA_PKCS1_OAEP"), Some("EH_PAD_RSA_PKCS1"), None];
        let digest_modes = vec![Some("EH_SHA_2_224"), Some("EH_SHA_2_256"), Some("EH_SHA_2_384"), Some("EH_SHA_2_512")];
        for keyspec in keyspecs.iter() {
            for padding_mode in padding_modes.iter() {
                for digest_mode in digest_modes.iter() {
                    let keyid = client.create_key(keyspec, "EH_INTERNAL_KEY",None, *padding_mode, *digest_mode).await;
                    assert!(keyid.is_ok(), "ERROR GET KEYID: keyspec = {}, padding_mode = {}", keyspec, padding_mode.unwrap());
                }
            }
        }
    }

    #[tokio::test]
    async fn test_symmetrickey_generate_key() {
        let mut client = EHSMClient::new();

        let keyspecs = vec!["EH_AES_GCM_128", "EH_AES_GCM_192", "EH_AES_GCM_256", "EH_SM4_CTR", "EH_SM4_CBC"];
        for keyspec in keyspecs.iter() {
            let keyid = client.create_key(keyspec, "EH_INTERNAL_KEY",None, None, None).await;
            assert!(keyid.is_ok(), "ERROR GET KEYID: keyspec = {}", keyspec);
        }
    }

    #[tokio::test]
    async fn test_generate_key_err() {
        let mut client = EHSMClient::new();

        let result = client.create_key("EH_RSA_3071", "EH_INTERNAL_KEY", None, None, None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_publickey() {
        let mut client = EHSMClient::new();

        let keyid = client.create_key("EH_SM2", "EH_INTERNAL_KEY", None, None, None)
                            .await  
                            .expect("fail to get keyid");
        let pubkey = client.get_publickey(&keyid.to_owned()).await;

        assert!(pubkey.is_ok());
    }

    #[tokio::test]
    async fn test_symmetrickey_encrypt_decrypt() {
        let mut client = EHSMClient::new();
        
        let decodedata = &encode(PLAINT_TEXT).to_string()[..];
        let keyspecs = vec!["EH_AES_GCM_128", "EH_AES_GCM_192", "EH_AES_GCM_256", "EH_SM4_CTR"];
        for keyspec in keyspecs.iter() {
            let keyid = client.create_key(keyspec, "EH_INTERNAL_KEY",None, None, None)
                        .await
                        .expect("fail to get keyid");
            let encrypt = client.encrypt(&keyid.to_owned(), &decodedata.to_owned(), Some(&encode("test").to_string()[..]))
                        .await
                        .expect("fail to encrypt");
            let decrypt = client.decrypt(&keyid.to_owned(), &encrypt.to_owned(), Some(&encode("test").to_string()[..])).await;
            let decode = String::from_utf8(decode(decrypt.unwrap()).unwrap()[..].to_vec());
            assert_eq!(decode.expect("decode base64 fail."), PLAINT_TEXT); 
        }
    }

    #[tokio::test]
    async fn test_generate_datakey() {
        let mut client = EHSMClient::new();
        
        let keyspecs = vec!["EH_AES_GCM_128", "EH_AES_GCM_192", "EH_AES_GCM_256", "EH_SM4_CTR", "EH_SM4_CBC"];
        for keyspec in keyspecs.iter() {
            let keyid = client.create_key(keyspec, "EH_INTERNAL_KEY", None, None, None)
                            .await
                            .expect("fail to get keyid");
            let generate_datakey = client.generate_datakey(&keyid.to_owned(), &16, Some(&encode("test").to_string()[..])).await;
            let generate_datakey_without_plaintext = client.generate_datakey_without_plaintext(&keyid.to_owned(), &48, Some(&encode("test").to_string()[..])).await;
            
            assert!(generate_datakey.is_ok(), "ERROR get export_datakey: keyspec = {}", keyspec);
            assert!(generate_datakey_without_plaintext.is_ok(), "ERROR get generate_datakey_without_plaintext: keyspec = {}", keyspec);
        }
        
    }

    #[tokio::test]
    async fn test_export_datakey() {
        let mut client = EHSMClient::new();

        let keyspecs = vec!["EH_AES_GCM_128", "EH_AES_GCM_192", "EH_AES_GCM_256", "EH_SM4_CTR", "EH_SM4_CBC"];
        let rsa_keyspecs = vec!["EH_RSA_3072", "EH_RSA_4096", "EH_RSA_2048", "EH_SM2"];
        let padding_modes = vec![Some("EH_PAD_RSA_PKCS1_OAEP"), Some("EH_PAD_RSA_PKCS1")];

        for keyspec in keyspecs.iter() {
            let keyid = client.create_key(keyspec, "EH_INTERNAL_KEY", None, None, None)
                            .await
                            .expect("fail to get keyid");
            let ciphertext = client.generate_datakey_without_plaintext(&keyid.to_owned(), &48, Some(&encode("test").to_string()[..]))
                                .await
                                .unwrap();
            for rsa_keyspec in rsa_keyspecs.iter() {
                for padding_mode in padding_modes.iter() {
                    let ukeyid = client.create_key(rsa_keyspec, "EH_INTERNAL_KEY",None, *padding_mode, None)
                                    .await
                                    .unwrap();
                
                    let export_datakey = client.export_datakey(&keyid, &ukeyid, &ciphertext, Some(&encode("test").to_string()[..])).await;
                    assert!(export_datakey.is_ok(), "ERROR get export_datakey: keyspec = {}, ukeyspec = {}, padding_mode = {}", keyspec, rsa_keyspec, padding_mode.unwrap());
                }
            }
        }
    }

    #[tokio::test]
    async fn test_rsa_encrypt_decrypt() {
        let mut client = EHSMClient::new();

        let decodedata = &encode(PLAINT_TEXT).to_string()[..];

        let keyspecs = vec!["EH_RSA_3072", "EH_RSA_4096", "EH_RSA_2048"];
        let padding_modes = vec![Some("EH_PAD_RSA_PKCS1_OAEP"), Some("EH_PAD_RSA_PKCS1")];
        let digest_modes = vec![Some("EH_SHA_2_224"), Some("EH_SHA_2_256"), Some("EH_SHA_2_384"), Some("EH_SHA_2_512")];

        for keyspec in keyspecs.iter() {
            for padding_mode in padding_modes.iter() {
                for digest_mode in digest_modes.iter() {
                    let keyid = client.create_key(keyspec, "EH_INTERNAL_KEY",None, *padding_mode, *digest_mode)
                                .await
                                .unwrap();
                    let encrypt = client.asymmetric_encrypt(&keyid.to_owned(), &decodedata.to_owned())
                                    .await
                                    .expect("fail to encrypt"); 
                    let decrypt = client.asymmetric_decrypt(&keyid.to_owned(), &encrypt.to_owned()).await;
                    let decode = String::from_utf8(decode(decrypt.unwrap()).unwrap()[..].to_vec()).expect("decode base64 fail.");
                    assert_eq!(decode, PLAINT_TEXT);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_sm2_encrypt_decrypt() {
        let mut client = EHSMClient::new();

        let decodedata = &encode(PLAINT_TEXT).to_string()[..];

        let keyid = client.create_key("EH_SM2", "EH_INTERNAL_KEY",None, None, None)
                        .await
                        .unwrap();
        let encrypt = client.asymmetric_encrypt(&keyid.to_owned(), &decodedata.to_owned())
                        .await
                        .expect("fail to encrypt"); 
        let decrypt = client.asymmetric_decrypt(&keyid.to_owned(), &encrypt.to_owned()).await;
        let decode = String::from_utf8(decode(decrypt.unwrap()).unwrap()[..].to_vec()).expect("decode base64 fail.");
        assert_eq!(decode, PLAINT_TEXT);

    }

    #[tokio::test]
    async fn test_asymmetrickey_sign_verify() {
        let mut client = EHSMClient::new();

        let keyspecs = vec!["EH_RSA_3072", "EH_RSA_4096", "EH_RSA_2048", "EH_EC_P224", "EH_EC_P256", "EH_EC_P384", "EH_EC_P521"];
        let padding_modes = vec![Some("EH_PAD_RSA_PKCS1_PSS"), Some("EH_PAD_RSA_PKCS1")];
        let digest_modes = vec![Some("EH_SHA_2_224"), Some("EH_SHA_2_256"), Some("EH_SHA_2_384"), Some("EH_SHA_2_512")];

        for keyspec in keyspecs.iter() {
            for padding_mode in padding_modes.iter() {
                for digest_mode in digest_modes.iter() {
                    let keyid = client.create_key(keyspec, "EH_INTERNAL_KEY",None, *padding_mode, *digest_mode)
                                    .await
                                    .unwrap();
                    let signature = client.sign(&keyid.to_owned(), &DIGEST.to_owned())
                                    .await
                                    .expect("sign fail");
                    let verify = client.verify(&keyid.to_owned(), &DIGEST.to_owned(), &signature.to_owned()).await;
                    assert!(verify.is_ok(), "fail to verify: keyspec = {}, padding_mode = {}", keyspec, padding_mode.unwrap());
                }
            }
        }
    }

    #[tokio::test]
    async fn test_sm2_sign_verify() {
        let mut client = EHSMClient::new();

        let keyid = client.create_key("EH_SM2", "EH_INTERNAL_KEY",None, None, Some("EH_SM3"))
                        .await
                        .unwrap();
        let signature = client.sign(&keyid.to_owned(), &DIGEST.to_owned())
                        .await
                        .expect("sign fail");
        let verify = client.verify(&keyid.to_owned(), &DIGEST.to_owned(), &signature.to_owned()).await;
        assert!(verify.is_ok());     
    }
}