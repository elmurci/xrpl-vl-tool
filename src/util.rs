use crate::crypto::verify_signature;
use crate::manifest::{serialize_manifest_data, DecodedManifest};
use crate::time::get_timestamp;
use crate::vl::{DecodedVl, Validator};
use anyhow::{Context, Result};
use color_eyre::owo_colors::OwoColorize;
use sha2::{Digest, Sha256, Sha512};
use std::fs;
use std::fs::File;
use std::io::prelude::*;

#[derive(Debug)]
pub enum Version {
    NodePublic,
    NodePrivate,
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        match version {
            Version::NodePublic => 28,
            Version::NodePrivate => 32,
        }
    }
}

pub fn generate_vl_file(content: &str, version: u8) -> Result<String> {
    let file_name = format!("generated_vl_v{}-{}.json", version, get_timestamp()?);
    let mut file = File::create(&file_name)?;
    file.write_all(content.as_bytes())?;
    Ok(file_name)
}

pub fn sha512_first_half(message: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let result = hasher.finalize();
    Ok(result[..32].to_vec())
}

pub fn double_sha256(hex_str: &str) -> Result<Vec<u8>> {
    let bin = hex::decode(hex_str).context("Invalid hex string")?;
    let hash = Sha256::digest(&bin);
    let hash2 = Sha256::digest(hash);
    Ok(hash2.to_vec())
}

pub fn hex_to_base58(hex_string: &str) -> Result<String> {
    let payload_str = format!("1C{}", hex_string);
    let payload_unhex = hex::decode(&payload_str).context("Invalid hex string")?;
    let checksum = &double_sha256(&payload_str)?[..4];
    let mut payload_with_checksum = payload_unhex.clone();
    payload_with_checksum.extend_from_slice(checksum);
    Ok(base58_encode(payload_with_checksum))
}

pub fn get_manifests(file_path: &str) -> Result<Vec<String>> {
    let contents = fs::read_to_string(file_path)?;
    let lines: Vec<String> = contents
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    Ok(lines)
}

pub fn base58_to_hex(base58_string: &str, version: Version) -> Result<String> {
    let decb58 = base58_decode(version, base58_string).context("Invalid base58 string")?;
    Ok(hex::encode(decb58))
}

pub fn bytes_to_base58(bytes: &[u8]) -> Result<String> {
    hex_to_base58(&hex::encode(bytes))
}

pub fn base58_encode<I: AsRef<[u8]>>(input: I) -> String {
    bs58::encode(input)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

pub fn base58_decode<I: AsRef<[u8]>>(version: Version, input: I) -> bs58::decode::Result<Vec<u8>> {
    bs58::decode(input)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .with_check(Some(version.into()))
        .into_vec()
        .map(|mut vec| {
            let _ = vec.remove(0);
            vec
        })
}

pub fn get_tick_or_cross(is_valid: bool) -> String {
    if is_valid {
        "✓".green().to_string()
    } else {
        "x".red().to_string()
    }
}

pub fn is_effective_date_already_present(vl: &DecodedVl, effective_date: i64) -> Result<bool> {
    for blob_v2 in vl
        .decoded_blobs_v2
        .clone()
        .context("Could not get blobs_v2")?
    {
        if blob_v2
            .decoded_blob
            .context("Could not get decoded blob v2")?
            .effective
            .context("Could not get effective date")?
            == effective_date
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn is_hex(s: &str) -> bool {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).is_ok()
}

pub fn get_key_bytes(key: &str) -> Result<Vec<u8>> {
    let mut k = key.to_owned();
    if key.len() >= 64 {
        if is_hex(&k) {
            if key.starts_with("ED") {
                let new_key = key.chars().skip(2).collect::<String>();
                k = new_key;
            }
            Ok(base58_decode(
                Version::NodePublic,
                hex_to_base58(&k).context("Could not convert hex to base58")?.as_str(),
            )?)
        } else {
            Ok(base58_decode(
                Version::NodePublic,
                k,
            )?)
        }        
    } else if key.len() != 33 {
        Ok(base58_decode(Version::NodePublic, key)?)
    } else {
        Ok(key.as_bytes().to_vec())
    }
}

pub fn verify_manifest(decoded_manifest: DecodedManifest) -> Result<DecodedManifest> {
    let mut manifest = decoded_manifest.clone();
    let payload = serialize_manifest_data(&manifest)?;

    let manifest_master_validation = verify_signature(
        base58_decode(
            Version::NodePublic,
            &decoded_manifest.master_public_key,
        )?,
        &payload,
        &decoded_manifest.master_signature,
    )?;

    let manifest_signing_validation = verify_signature(
        base58_decode(
            Version::NodePublic,
            &decoded_manifest.signing_public_key,
        )?,
        &payload,
        &decoded_manifest.signature,
    )?;

    if !manifest_master_validation || !manifest_signing_validation {
        anyhow::bail!("Could not verify manifest, either manifest_master_validation or manifest_signing_validation failed.");
    }

    manifest.verification = true;

    Ok(manifest)
}

pub fn print_validators_summary(mut validators: Vec<Validator>) -> Result<()> {
    for validator in validators.iter_mut() {
        if let Some(validator_manifest) = &validator.decoded_manifest {
            let validator_validation = verify_manifest(validator_manifest.clone())?;
            println!(
                "Validator: {} ({}) | Verification: {} | {}",
                &validator.validation_public_key,
                hex_to_base58(&validator.validation_public_key)?,
                get_tick_or_cross(validator_validation.verification),
                validator_manifest.clone().domain.unwrap_or("".to_string())
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tick_or_cross_valid() {
        let result = get_tick_or_cross(true);
        let expected = "✓".green().to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_get_tick_or_cross_invalid() {
        let result = get_tick_or_cross(false);
        let expected = "x".red().to_string();
        assert_eq!(result, expected);
    }
}
