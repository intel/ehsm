// use async_trait::async_trait;
// use anyhow::{Result, anyhow};
// // use serde_json::{json, Map, Value};
// // use reqwest::{ClientBuilder};

// use crate::api::Secret;
// use crate::client::EHSMClient;
// // use crate::client;

// #[async_trait]
// impl Secret for EHSMClient {
//     #[warn(unused_variables)]
//     async fn create_secret(
//         &mut self,
//         secret_name: &str,
//         secret_data: &str,
//         encryption_key_id: Option<&str>,
//         description: Option<&str>,
//         rotation_interval: Option<u32>) -> Result<String> {
//             Ok("Not Implemented".to_string())
//         }
// }
