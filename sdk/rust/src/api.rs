use async_trait::async_trait;
use anyhow::Result;

#[async_trait]
pub trait KMS {
    async fn create_key(
        &mut self,
        keyspec: &str,
        origin: &str,
        purpose: Option<&str>,
        padding_mode: Option<&str>,
        digest_mode: Option<&str>) -> Result<String>;

    async fn decrypt(&mut self, _keyid: &str, _data: &str, _aad: Option<&str>) -> Result<String>;

    async fn encrypt(&mut self, _keyid: &str, _data: &str, _aad: Option<&str>) -> Result<String>;
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