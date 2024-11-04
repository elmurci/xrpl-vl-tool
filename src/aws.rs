use anyhow::Result;
use aws_sdk_secretsmanager::primitives::Blob;

pub async fn get_secret(name: &str) -> Result<Option<Blob>> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    let resp = client.get_secret_value().secret_id(name).send().await?;
    Ok(resp.secret_binary().map(|b| b.clone()))
}