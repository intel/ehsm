#[cfg(test)]
mod tests {
    use crate::{api::KMS, client::EHSMClient};
    use base64;
    use base64::{decode, encode};
    use sha2::{Digest as Sha2Digest, Sha256};
    use sm3::{Digest as Sm3Digest, Sm3};

    #[tokio::test]
    async fn test_asymmetrickey_generate_key() {
        let mut client = EHSMClient::new();

        let keyspecs = vec![
            "EH_RSA_2048",
            "EH_RSA_3072",
            "EH_RSA_4096",
            "EH_SM2",
            "EH_EC_P224",
            "EH_EC_P256",
            "EH_EC_P256K",
            "EH_EC_P384",
            "EH_EC_P521",
        ];

        let keyusage = vec!["EH_KEYUSAGE_ENCRYPT_DECRYPT", "EH_KEYUSAGE_SIGN_VERIFY"];

        for keyspec in keyspecs.iter() {
            for keyusage in keyusage.iter() {
                let keyid = client
                    .create_key(keyspec, "EH_INTERNAL_KEY", keyusage)
                    .await;
                assert!(
                    keyid.is_ok(),
                    "ERROR GET KEYID: keyspec = {}, keyusage = {}",
                    keyspec,
                    keyusage
                );
            }
        }
    }

    #[tokio::test]
    async fn test_symmetrickey_generate_key() {
        let mut client = EHSMClient::new();

        let keyspecs = vec![
            "EH_AES_GCM_128",
            "EH_AES_GCM_192",
            "EH_AES_GCM_256",
            "EH_SM4_CTR",
            "EH_SM4_CBC",
        ];

        for keyspec in keyspecs.iter() {
            let keyid = client
                .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
                .await;

            assert!(keyid.is_ok(), "ERROR GET KEYID: keyspec = {}", keyspec);
        }
    }

    #[tokio::test]
    async fn test_generate_key_invaild_keyusage() {
        let mut client = EHSMClient::new();

        let result = client
            .create_key(
                "EH_AES_GCM_128",
                "EH_INTERNAL_KEY",
                "EH_KEYUSAGE_SIGN_VERIFY",
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_generate_key_invaild_keyspec() {
        let mut client = EHSMClient::new();

        let result = client
            .create_key(
                "EH_RSA_3071",
                "EH_INTERNAL_KEY",
                "EH_KEYUSAGE_ENCRYPT_DECRYPT",
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_publickey() {
        let mut client = EHSMClient::new();

        let keyspecs = vec![
            "EH_RSA_2048",
            "EH_RSA_3072",
            "EH_RSA_4096",
            "EH_SM2",
            "EH_EC_P224",
            "EH_EC_P256",
            "EH_EC_P256K",
            "EH_EC_P384",
            "EH_EC_P521",
        ];
        let keyusage = vec!["EH_KEYUSAGE_SIGN_VERIFY", "EH_KEYUSAGE_ENCRYPT_DECRYPT"];

        for keyspec in keyspecs.iter() {
            for keyusage in keyusage.iter() {
                let keyid = client
                    .create_key(keyspec, "EH_INTERNAL_KEY", keyusage)
                    .await
                    .expect("fail to get keyid");

                let pubkey = client.get_publickey(&keyid.to_owned()).await;

                assert!(pubkey.is_ok());
            }
        }
    }

    #[tokio::test]
    async fn test_symmetrickey_encrypt_decrypt() {
        let mut client = EHSMClient::new();

        let msg = "unit test";
        let aad = "aad";

        let keyspecs = vec![
            "EH_AES_GCM_128",
            "EH_AES_GCM_192",
            "EH_AES_GCM_256",
            "EH_SM4_CTR",
        ];

        for keyspec in keyspecs.iter() {
            let keyid = client
                .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
                .await
                .expect("fail to get keyid");

            let ciphertext = client
                .encrypt(
                    &keyid.to_owned(),
                    &encode(msg).to_string()[..].to_owned(),
                    Some(&encode(aad).to_string()[..]),
                )
                .await
                .expect("fail to encrypt");

            let plaintext_b64 = client
                .decrypt(
                    &keyid.to_owned(),
                    &ciphertext.to_owned(),
                    Some(&encode(aad).to_string()[..]),
                )
                .await;
            let plaintext = String::from_utf8(decode(plaintext_b64.unwrap()).unwrap()[..].to_vec());

            assert_eq!(plaintext.expect("decode base64 fail."), msg);
        }
    }

    #[tokio::test]
    async fn test_generate_datakey() {
        let mut client = EHSMClient::new();

        let aad = "aad";

        let keyspecs = vec![
            "EH_AES_GCM_128",
            "EH_AES_GCM_192",
            "EH_AES_GCM_256",
            "EH_SM4_CTR",
            "EH_SM4_CBC",
        ];

        for keyspec in keyspecs.iter() {
            let keyid = client
                .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
                .await
                .expect("fail to get keyid");

            let generate_datakey = client
                .generate_datakey(&keyid.to_owned(), &16, Some(&encode(aad).to_string()[..]))
                .await;

            assert!(
                generate_datakey.is_ok(),
                "ERROR get export_datakey: keyspec = {}",
                keyspec
            );
        }
    }

    #[tokio::test]
    async fn test_generate_datakey_without_plaintext() {
        let mut client = EHSMClient::new();

        let aad = "aad";

        let keyspecs = vec![
            "EH_AES_GCM_128",
            "EH_AES_GCM_192",
            "EH_AES_GCM_256",
            "EH_SM4_CTR",
            "EH_SM4_CBC",
        ];

        for keyspec in keyspecs.iter() {
            let keyid = client
                .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
                .await
                .expect("fail to get keyid");

            let generate_datakey_without_plaintext = client
                .generate_datakey_without_plaintext(
                    &keyid.to_owned(),
                    &48,
                    Some(&encode(aad).to_string()[..]),
                )
                .await;

            assert!(
                generate_datakey_without_plaintext.is_ok(),
                "ERROR get generate_datakey_without_plaintext: keyspec = {}",
                keyspec
            );
        }
    }

    #[tokio::test]
    async fn test_export_datakey() {
        let mut client = EHSMClient::new();

        let aad = "aad";

        let keyspecs = vec![
            "EH_AES_GCM_128",
            "EH_AES_GCM_192",
            "EH_AES_GCM_256",
            "EH_SM4_CTR",
            "EH_SM4_CBC",
        ];
        let rsa_keyspecs = vec!["EH_RSA_3072", "EH_RSA_4096", "EH_RSA_2048", "EH_SM2"];

        for keyspec in keyspecs.iter() {
            let keyid = client
                .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
                .await
                .expect("fail to get keyid");
            let ciphertext = client
                .generate_datakey_without_plaintext(
                    &keyid.to_owned(),
                    &48,
                    Some(&encode(aad).to_string()[..]),
                )
                .await
                .unwrap();

            for rsa_keyspec in rsa_keyspecs.iter() {
                let ukeyid = client
                    .create_key(
                        rsa_keyspec,
                        "EH_INTERNAL_KEY",
                        "EH_KEYUSAGE_ENCRYPT_DECRYPT",
                    )
                    .await
                    .unwrap();

                let export_datakey = client
                    .export_datakey(
                        &keyid,
                        &ukeyid,
                        &ciphertext,
                        Some(&encode(aad).to_string()[..]),
                    )
                    .await;

                assert!(
                    export_datakey.is_ok(),
                    "ERROR get export_datakey: keyspec = {}, ukeyspec = {}",
                    keyspec,
                    rsa_keyspec
                );
            }
        }
    }

    #[tokio::test]
    async fn test_rsa_encrypt_decrypt() {
        let mut client = EHSMClient::new();

        let msg = "unit test";

        let keyspecs = vec!["EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096"];
        let padding_modes = vec!["EH_RSA_PKCS1", "EH_RSA_PKCS1_OAEP"];

        for keyspec in keyspecs.iter() {
            for padding_mode in padding_modes.iter() {
                let keyid = client
                    .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
                    .await
                    .unwrap();

                let ciphertext = client
                    .asymmetric_encrypt(
                        &keyid.to_owned(),
                        &encode(msg).to_string()[..].to_owned(),
                        padding_mode,
                    )
                    .await
                    .expect("fail to encrypt");

                let plaintext_b64 = client
                    .asymmetric_decrypt(&keyid.to_owned(), &ciphertext.to_owned(), padding_mode)
                    .await;
                let plaintext =
                    String::from_utf8(decode(plaintext_b64.unwrap()).unwrap()[..].to_vec())
                        .expect("decode base64 fail.");

                assert_eq!(plaintext, msg);
            }
        }
    }

    #[tokio::test]
    async fn test_sm2_encrypt_decrypt() {
        let mut client = EHSMClient::new();

        let msg = "unit test";

        let keyid = client
            .create_key("EH_SM2", "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
            .await
            .unwrap();

        let ciphertext = client
            .asymmetric_encrypt(
                &keyid.to_owned(),
                &encode(msg).to_string()[..].to_owned(),
                "EH_PAD_NONE",
            )
            .await
            .expect("fail to encrypt");

        let plaintext_b64 = client
            .asymmetric_decrypt(&keyid.to_owned(), &ciphertext.to_owned(), "EH_PAD_NONE")
            .await;
        let plaintext = String::from_utf8(decode(plaintext_b64.unwrap()).unwrap()[..].to_vec())
            .expect("decode base64 fail.");

        assert_eq!(plaintext, msg);
    }

    #[tokio::test]
    async fn test_rsa_sign_verify_raw() {
        let mut client = EHSMClient::new();

        let keyspecs = vec!["EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096"];
        let padding_modes = vec!["EH_RSA_PKCS1", "EH_RSA_PKCS1_PSS"];

        let msg = "unit test";

        for keyspec in keyspecs.iter() {
            for padding_mode in padding_modes.iter() {
                let keyid = client
                    .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
                    .await
                    .unwrap();

                let signature_raw = client
                    .sign(
                        &keyid.to_owned(),
                        padding_mode,
                        "EH_SHA_256",
                        "EH_RAW",
                        &encode(msg).to_string()[..],
                    )
                    .await
                    .expect("sign fail");

                let verify_raw = client
                    .verify(
                        &keyid.to_owned(),
                        padding_mode,
                        "EH_SHA_256",
                        "EH_RAW",
                        &encode(msg).to_string()[..],
                        &signature_raw.to_owned(),
                    )
                    .await;

                assert!(
                    verify_raw.is_ok(),
                    "fail to verify_raw: keyspec = {}, padding_mode = {}",
                    keyspec,
                    padding_mode
                );
            }
        }
    }

    #[tokio::test]
    async fn test_rsa_sign_verify_digest() {
        let mut client = EHSMClient::new();

        let keyspecs = vec!["EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096"];
        let padding_modes = vec!["EH_RSA_PKCS1", "EH_RSA_PKCS1_PSS"];

        let msg = "unit test";
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let msg_digest256 = hasher.finalize();

        for keyspec in keyspecs.iter() {
            for padding_mode in padding_modes.iter() {
                let keyid = client
                    .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
                    .await
                    .unwrap();

                let signature_digest = client
                    .sign(
                        &keyid.to_owned(),
                        padding_mode,
                        "EH_SHA_256",
                        "EH_DIGEST",
                        &encode(msg_digest256.to_owned()).to_string()[..],
                    )
                    .await
                    .expect("sign fail");

                let verify_digest = client
                    .verify(
                        &keyid.to_owned(),
                        padding_mode,
                        "EH_SHA_256",
                        "EH_DIGEST",
                        &encode(msg_digest256.to_owned()).to_string()[..],
                        &signature_digest.to_owned(),
                    )
                    .await;

                assert!(
                    verify_digest.is_ok(),
                    "fail to verify_digest: keyspec = {}, padding_mode = {}",
                    keyspec,
                    padding_mode
                );
            }
        }
    }

    #[tokio::test]
    async fn test_sign_verify_invaild_paddingmod() {
        let mut client = EHSMClient::new();

        let msg = "unit test";

        let keyid = client
            .create_key("EH_RSA_2048", "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
            .await
            .unwrap();

        let signature_raw = client
            .sign(
                &keyid.to_owned(),
                "EH_PAD_NONE",
                "EH_SHA_256",
                "EH_RAW",
                &encode(msg).to_string()[..],
            )
            .await;

        assert!(signature_raw.is_err());
    }

    #[tokio::test]
    async fn test_ec_sign_verify_raw() {
        let mut client = EHSMClient::new();

        let keyspecs = vec![
            "EH_EC_P224",
            "EH_EC_P256",
            "EH_EC_P256K",
            "EH_EC_P384",
            "EH_EC_P521",
        ];

        let msg = "unit test";

        for keyspec in keyspecs.iter() {
            let keyid = client
                .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
                .await
                .unwrap();

            let signature_raw = client
                .sign(
                    &keyid.to_owned(),
                    "EH_PAD_NONE",
                    "EH_SHA_256",
                    "EH_RAW",
                    &encode(msg).to_string()[..],
                )
                .await
                .expect("sign fail");

            let verify_raw = client
                .verify(
                    &keyid.to_owned(),
                    "EH_PAD_NONE",
                    "EH_SHA_256",
                    "EH_RAW",
                    &encode(msg).to_string()[..],
                    &signature_raw.to_owned(),
                )
                .await;

            assert!(
                verify_raw.is_ok(),
                "fail to verify_raw: keyspec = {}",
                keyspec
            );
        }
    }

    #[tokio::test]
    async fn test_ec_sign_verify_digest() {
        let mut client = EHSMClient::new();

        let keyspecs = vec![
            "EH_EC_P224",
            "EH_EC_P256",
            "EH_EC_P256K",
            "EH_EC_P384",
            "EH_EC_P521",
        ];

        let msg = "unit test";
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let msg_digest256 = hasher.finalize();

        for keyspec in keyspecs.iter() {
            let keyid = client
                .create_key(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
                .await
                .unwrap();

            let signature_digest = client
                .sign(
                    &keyid.to_owned(),
                    "EH_PAD_NONE",
                    "EH_SHA_256",
                    "EH_DIGEST",
                    &encode(&msg_digest256.to_owned()),
                )
                .await
                .expect("sign fail");

            let verify_digest = client
                .verify(
                    &keyid.to_owned(),
                    "EH_PAD_NONE",
                    "EH_SHA_256",
                    "EH_DIGEST",
                    &encode(msg_digest256.to_owned()).to_string()[..],
                    &signature_digest.to_owned(),
                )
                .await;

            assert!(
                verify_digest.is_ok(),
                "fail to verify_digest: keyspec = {}",
                keyspec
            );
        }
    }

    #[tokio::test]
    async fn test_sm2_sign_verify_raw() {
        let mut client = EHSMClient::new();

        let msg = "unit test";

        let keyid = client
            .create_key("EH_SM2", "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
            .await
            .unwrap();

        let signature_raw = client
            .sign(
                &keyid.to_owned(),
                "EH_PAD_NONE",
                "EH_SM3",
                "EH_RAW",
                &encode(msg).to_string()[..],
            )
            .await
            .expect("sign fail");

        let verify_raw = client
            .verify(
                &keyid.to_owned(),
                "EH_PAD_NONE",
                "EH_SM3",
                "EH_RAW",
                &encode(msg).to_string()[..],
                &signature_raw.to_owned(),
            )
            .await;

        assert!(verify_raw.is_ok());
    }

    #[tokio::test]
    async fn test_sm2_sign_verify_digest() {
        let mut client = EHSMClient::new();

        let msg = "unit test";
        let msg_digest256 = Sm3::digest(msg);

        let keyid = client
            .create_key("EH_SM2", "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
            .await
            .unwrap();

        let signature_digest = client
            .sign(
                &keyid.to_owned(),
                "EH_PAD_NONE",
                "EH_SM3",
                "EH_DIGEST",
                &encode(msg_digest256.to_owned()).to_string()[..],
            )
            .await
            .expect("sign fail");

        let verify_digest = client
            .verify(
                &keyid.to_owned(),
                "EH_PAD_NONE",
                "EH_SM3",
                "EH_DIGEST",
                &encode(msg_digest256.to_owned()).to_string()[..],
                &signature_digest.to_owned(),
            )
            .await;

        assert!(verify_digest.is_ok());
    }

    #[tokio::test]
    async fn test_import_key() {
        let mut client = EHSMClient::new();

        let msg = "unit test";
        let aad = "aad";

        let keyspecs = vec![
            "EH_AES_GCM_128",
            "EH_AES_GCM_192",
            "EH_AES_GCM_256",
            "EH_SM4_CTR",
            "EH_SM4_CBC",
        ];
        let warpping_keyspec = ["EH_RSA_2048", "EH_RSA_3072", "EH_RSA_4096"];
        let padding_mode = ["EH_RSA_PKCS1", "EH_RSA_PKCS1_OAEP"];

        for keyspecs in keyspecs.iter() {
            for warpping_keyspec in warpping_keyspec.iter() {
                for padding_mode in padding_mode.iter() {
                    let keyid = client
                        .create_key(keyspecs, "EH_EXTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")
                        .await
                        .expect("fail to create external key.");

                    let (pubkey, import_token) = client
                        .get_parameters_for_import(&keyid, warpping_keyspec)
                        .await
                        .expect("fail to get parameters for import.");

                    // using key of rsa encrypt symmertic key
                    let key = crate::client::generate_random_key(keyspecs).unwrap();
                    let key_material =
                        crate::client::rsa_encrypt(&key, padding_mode, &pubkey).unwrap();

                    let result = client
                        .import_key_material(
                            &keyid,
                            padding_mode,
                            &encode(key_material).to_string()[..].to_owned(),
                            &import_token,
                        )
                        .await
                        .unwrap();

                    assert!(result);
                    //test external key
                    let ciphertext = client
                        .encrypt(
                            &keyid.to_owned(),
                            &encode(msg).to_string()[..].to_owned(),
                            Some(&encode(aad).to_string()[..]),
                        )
                        .await
                        .expect("fail to encrypt");

                    let plaintext_b64 = client
                        .decrypt(
                            &keyid.to_owned(),
                            &ciphertext.to_owned(),
                            Some(&encode(aad).to_string()[..]),
                        )
                        .await;
                    let plaintext =
                        String::from_utf8(decode(plaintext_b64.unwrap()).unwrap()[..].to_vec());

                    assert_eq!(plaintext.expect("decode base64 fail."), msg);
                }
            }
        }
    }
}
