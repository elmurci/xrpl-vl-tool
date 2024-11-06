use anyhow::{anyhow, Result};
use vaultrs::{client::{VaultClient, VaultClientSettingsBuilder}, kv2};

use crate::{enums::SecretProvider, structs::Secret};

pub async fn get_secret(secret_provider: SecretProvider, id: &str) -> Result<Option<Secret>> {
    match secret_provider {
        SecretProvider::Aws => get_aws_secret(id).await,
        SecretProvider::Vault => {
            let args: Vec<String> = id.split(":").map(|s| s.to_string()).collect();
            if args.len() != 4 {
                return Err(anyhow!("Invalid Vault secret format"));
            }
            get_vault_secret(&args[0], &args[1], &args[2], &args[3]).await
        },
    }
}

pub async fn get_aws_secret(id: &str) -> Result<Option<Secret>> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    let resp = client.get_secret_value().secret_id(id).send().await?;
    if resp.secret_string.is_none() {
        return Ok(None);
    } else {
        Ok(Some(serde_json::from_str::<Secret>(&resp.secret_string.unwrap())?))
    }
}

pub async fn get_vault_secret(endpoint: &str, token: &str, mount: &str, path: &str) -> Result<Option<Secret>> {
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(endpoint)
            .token(token)
            .build()
            .unwrap()
    ).unwrap();
    let keypair: Secret  = kv2::read(&client, mount, path).await.unwrap();
    Ok(Some(keypair))
}


