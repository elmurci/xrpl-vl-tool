use anyhow::{anyhow, Result};
use vaultrs::{client::{VaultClient, VaultClientSettingsBuilder}, kv2};
use std::{env, fs};

use crate::{enums::SecretProvider, structs::Secret};

pub async fn get_secret(secret_provider: SecretProvider, id: &str) -> Result<Option<Secret>> {
    match secret_provider {
        SecretProvider::Aws => get_aws_secret(id).await,
        SecretProvider::Vault => {
            let args: Vec<String> = id.split(":").map(|s| s.to_string()).collect();
            if args.len() != 2 {
                return Err(anyhow!("Invalid Vault secret format"));
            }
            get_vault_secret(&args[0], &args[1]).await
        },
        SecretProvider::Local => {
            let keys_content = fs::read_to_string(id);
            let secret = serde_json::from_str::<Secret>(&keys_content?)?;
            Ok(Some(secret))
        },
    }
}

pub async fn get_aws_secret(id: &str) -> Result<Option<Secret>> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    let resp = client.get_secret_value().secret_id(id).send().await?;
    if resp.secret_string.is_none() {
        Ok(None)
    } else {
        Ok(Some(serde_json::from_str::<Secret>(&resp.secret_string.unwrap())?))
    }
}

pub async fn get_vault_secret(mount: &str, path: &str) -> Result<Option<Secret>> {
    let vault_token = env::var("VAULT_TOKEN")?;
    let vault_endpoint = env::var("VAULT_ENDPOINT")?;
    if vault_token.is_empty() || vault_endpoint.is_empty() {
        return Err(anyhow!("VAULT_TOKEN and VAULT_ENDPOINT need to be set"));
    }
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(vault_endpoint)
            .token(vault_token)
            .build()
            .unwrap()
    ).unwrap();
    let keypair: Secret  = kv2::read(&client, mount, path).await.unwrap();
    Ok(Some(keypair))
}


