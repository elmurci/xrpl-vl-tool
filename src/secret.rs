use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::env;
use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
    kv2,
};

use crate::crypto::{get_key_type, get_keypair_bytes_from_private_key_hex, KeyPairBytes, KeyPairHex, KeyType};

#[derive(Deserialize, Debug, Clone)]
pub struct Secret {
    pub key_pair_bytes: KeyPairBytes,
    pub key_type: KeyType,
    pub secret_provider: SecretProvider,
}

#[derive(Deserialize, Debug, Clone)]
pub enum SecretProvider {
    Aws,
    Vault,
    Local,
}

impl SecretProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretProvider::Aws => "aws",
            SecretProvider::Vault => "vault",
            SecretProvider::Local => "local",
        }
    }
    pub fn from_string_slice(input: &str) -> Result<SecretProvider> {
        match input {
            "aws" => Ok(SecretProvider::Aws),
            "vault" => Ok(SecretProvider::Vault),
            "local" => Ok(SecretProvider::Local),
            _ => Err(anyhow!("Could not parse secret provider value")),
        }
    }
}

pub fn get_secret_from_private_key_hex(private_key_hex: &str) -> Result<Secret> {
    let key_type = get_key_type(hex::decode(private_key_hex)?);
    let pk_hex = if key_type == KeyType::Ed25519 {
        &private_key_hex.chars().skip(2).collect::<String>()
    } else {
        private_key_hex
    };
    let key_pair_bytes = get_keypair_bytes_from_private_key_hex(pk_hex, key_type.clone())?;
        Ok(
            Secret {
                key_pair_bytes,
                key_type,
                secret_provider: SecretProvider::Local,
            }
        )
}

pub async fn get_secret(secret_provider: SecretProvider, secret_id: Option<String>) -> Result<Option<Secret>> {
    match secret_provider {
        SecretProvider::Aws => get_aws_secret(&secret_id.context("Could not get secret id")?).await,
        SecretProvider::Vault => {
            let args: Vec<String> = secret_id.context("Could not get secret id")?.split(":").map(|s| s.to_string()).collect();
            if args.len() != 2 {
                anyhow::bail!("Invalid Vault secret format");
            }
            get_vault_secret(&args[0], &args[1]).await
        }
        SecretProvider::Local => {
            let local_private_key_hex = env::var("VL_PK")?;
            Ok(
                Some(get_secret_from_private_key_hex(&local_private_key_hex)?)
            )
        }
    }
}

pub async fn get_aws_secret(id: &str) -> Result<Option<Secret>> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    let resp = client.get_secret_value().secret_id(id).send().await?;
    if resp.secret_string.is_none() {
        Ok(None)
    } else {
        Ok(Some(get_secret_from_private_key_hex(&resp.secret_string.context("Could not get aws secret string")?)?))
    }
}

pub async fn get_vault_secret(mount: &str, path: &str) -> Result<Option<Secret>> {
    let vault_token = env::var("VAULT_TOKEN")?;
    let vault_endpoint = env::var("VAULT_ENDPOINT")?;
    if vault_token.is_empty() || vault_endpoint.is_empty() {
        anyhow::bail!("VAULT_TOKEN and VAULT_ENDPOINT need to be set");
    }
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(vault_endpoint)
            .token(vault_token)
            .build()
            .context("Error building Vault client settings")?,
    )
    .context("Could not get Vault client")?;
    let key_pair_hex: KeyPairHex = kv2::read(&client, mount, path).await.context("Could not get the vault key")?;
    Ok(Some(get_secret_from_private_key_hex(&key_pair_hex.private_key_hex).context("Could not get vault secret string")?))
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use secp256k1::{hashes::hex::DisplayHex, Secp256k1};

    use super::*;

    #[tokio::test]
    async fn test_get_local_secret() {
        let secp = Secp256k1::new();
        let (secret_key, _public_key) = secp.generate_keypair(&mut OsRng);
        let secret_key_hex = secret_key.secret_bytes().to_upper_hex_string();
        env::set_var("VL_PK", secret_key_hex.clone());
        let local_secret = get_secret(SecretProvider::Local, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(local_secret.key_pair_bytes.private_key_bytes.to_upper_hex_string(), secret_key_hex);
    }
}
