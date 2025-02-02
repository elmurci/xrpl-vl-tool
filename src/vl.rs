use std::fs;

use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    crypto::{sign, verify_signature},
    errors::VlValidationError,
    manifest::{decode_manifest, DecodedManifest},
    secret::Secret,
    time::{blobs_have_no_time_gaps, convert_to_ripple_time},
    util::{
        base58_decode, base58_to_hex, get_manifests, is_effective_date_already_present, verify_manifest, Version
    },
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vl {
    pub public_key: String,
    pub manifest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>, // Only for v1
    #[serde(alias = "blobs-v2", skip_serializing_if = "Option::is_none")]
    pub blobs_v2: Option<Vec<BlobV2>>, // Only for v2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>, // Only for v1
    pub version: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecodedVl {
    pub public_key: String,
    pub manifest: DecodedManifest,
    pub blob: Option<String>,                  // Only for v1
    pub blobs_v2: Option<Vec<BlobV2>>,         // Only for v2
    pub decoded_blob: Option<DecodedBlob>,     // Only for v1
    pub decoded_blobs_v2: Option<Vec<BlobV2>>, // Only for v2
    pub signature: Option<String>,             // Only for v1
    pub version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_verification: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecodedBlob {
    pub sequence: u32,
    pub expiration: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective: Option<i64>,
    pub validators: Vec<Validator>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlobV2 {
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_blob: Option<DecodedBlob>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_verification: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    pub validation_public_key: String,
    pub manifest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_manifest: Option<DecodedManifest>,
}

impl Default for Vl {
    fn default() -> Vl {
        Vl {
            public_key: "".to_string(),
            manifest: "".to_string(),
            blob: None,
            blobs_v2: None,
            signature: None,
            version: 1,
        }
    }
}

pub async fn get_vl(url_or_file: &str) -> Result<Vl> {
    let url = Url::parse(url_or_file);

    let vl: Vl = if url.is_err() {
        serde_json::from_str(&fs::read_to_string(url_or_file)?)?
    } else {
        reqwest::get(url_or_file).await?.json::<Vl>().await?
    };
    Ok(vl)
}

pub async fn load_vl(url_or_file: &str) -> Result<DecodedVl> {
    let vl = get_vl(url_or_file).await?;

    // What version is this VL?
    let parsed_vl = match vl.version {
        1 => decode_vl_v1(&vl)?,
        2 => decode_vl_v2(&vl)?,
        _ => anyhow::bail!("Unsupported version"),
    };

    Ok(parsed_vl)
}

pub fn verify_vl(mut vl: DecodedVl) -> Result<DecodedVl> {
    let public_key_bytes = base58_decode(Version::NodePublic, vl.manifest.signing_public_key.clone())?;
    // Manifest Verification
    let manifest_verification = verify_manifest(vl.manifest.clone()).is_ok();
    vl.manifest.verification = manifest_verification;
    // With version 1 there is only one blob
    if vl.version == 1 {
        let mut decoded_blob = vl
            .decoded_blob
            .clone()
            .context("Could not get decoded blob")?;
        // Blob verification verifies each validator manifest
        for validator in decoded_blob.validators.iter_mut() {
            let verified_validator = verify_manifest(
                validator
                    .decoded_manifest
                    .clone()
                    .context("Could not get decoded manifest")?,
            )?;
            validator.decoded_manifest = Some(verified_validator.clone());
        }
        vl.decoded_blob = Some(decoded_blob);
        let verify_blob = verify_signature(
            public_key_bytes,
            &BASE64_STANDARD.decode(vl.blob.clone().context("Could not get blob from v1 vl")?)?,
            &vl.signature
                .clone()
                .context("Could not get signature from v1 vl")?,
        )?;
        vl.blob_verification = Some(verify_blob);
    } else {
        // With version 2, there might be multiple blobs
        let decoded_blobs_v2 = vl
            .decoded_blobs_v2
            .as_mut()
            .context("Could not get decoded blobs v2")?;
        for (index, blob_v2) in decoded_blobs_v2.iter_mut().enumerate() {
            let mut decoded_blob = blob_v2
                .clone()
                .decoded_blob
                .context("Could not get decoded blob")?;
            // If the manifest is not present in a blobs-v2 array entry,
            // then the top-level manifest will be used when checking the signature.
            if blob_v2.manifest.is_some() {
                verify_manifest(vl.manifest.clone())?;
            }
            // TODO: move to a function?
            for validator in decoded_blob.validators.iter_mut() {
                let verified_validator = verify_manifest(
                    validator
                        .decoded_manifest
                        .clone()
                        .context("Could not get decoded manifest")?,
                )?;
                validator.decoded_manifest = Some(verified_validator);
            }
            let blobs_v2 = &vl
                .blobs_v2
                .clone()
                .context("Could not get blobs v2 from vl")?[index];
            let verify_blob = verify_signature(
                public_key_bytes.clone(),
                &BASE64_STANDARD.decode(
                    blobs_v2
                        .blob
                        .clone()
                        .context("Could not get blob from blobs_v2")?,
                )?,
                &blobs_v2.signature.clone(),
            )?;
            blob_v2.blob_verification = Some(verify_blob);
            blob_v2.decoded_blob = Some(decoded_blob);
        }
        vl.decoded_blobs_v2 = Some(decoded_blobs_v2.clone());
    }

    Ok(vl)
}

#[allow(clippy::too_many_arguments)]
pub async fn sign_vl(
    version: u8,
    manifest: String,
    manifests_file: String,
    sequence: u32,
    expiration_in_days: u16,
    secret: Secret,
    effective: Option<i64>,
    v2_vl: Option<Vl>,
) -> Result<Vl> {
    let decoded_publisher_manifest = decode_manifest(&manifest)?;
    let signing_public_key_hex = hex::encode(secret.clone().key_pair_bytes.public_key_bytes).to_uppercase();
    let manifest_signing_public_key_hex = base58_to_hex(
        &decoded_publisher_manifest.signing_public_key,
        Version::NodePublic,
    )?.to_uppercase();
    
    if signing_public_key_hex != manifest_signing_public_key_hex {
        anyhow::bail!("Public key in the manifest does not match the public key in the secret")
    }
    
    if expiration_in_days == 0 {
        anyhow::bail!("Expiration has to be greater than 0");
    }

    if version == 2 && v2_vl.is_some() {
        let v = v2_vl.clone().context("Could not get v2 vl")?;
        if !v
            .blobs_v2
            .clone()
            .context("Could not get blobs v2")?
            .is_empty()
        {
            let blobs = v
                .blobs_v2
                .clone()
                .ok_or(anyhow!("Could not get blobs_v2"))?;
            let mut sequence_numbers: Vec<u32> = Vec::with_capacity(blobs.len());
            for blob_v2 in blobs.iter() {
                let decoded = BASE64_STANDARD.decode(blob_v2.blob.clone().context("Could not get v2 blob")?)?;
                let decoded_blob: DecodedBlob = serde_json::from_str(&String::from_utf8(decoded)?)?;
                sequence_numbers.push(decoded_blob.sequence);
            }
            if !sequence_numbers.iter().all(|&n| sequence > n) {
                anyhow::bail!(VlValidationError::InvalidSequence);
            }
        } else {
            anyhow::bail!(VlValidationError::MalformedVl);
        }
        // Make sure there is no gap when generating new UNLs
        if !blobs_have_no_time_gaps(v.blobs_v2.context("Missing blobs_v2")?)?{
            anyhow::bail!(VlValidationError::HasGaps);
        }
    }

    let mut vl = v2_vl.clone().unwrap_or_default();
    let manifests = get_manifests(&manifests_file)?;
    let mut validators: Vec<Validator> = vec![];

    for manifest in manifests {
        let decoded_manifest = decode_manifest(&manifest)?;
        let validator = Validator {
            validation_public_key: base58_to_hex(
                &decoded_manifest.master_public_key,
                Version::NodePublic,
            )?
            .to_uppercase(),
            manifest: Some(manifest),
            decoded_manifest: None,
        };
        validators.push(validator);
    }

    let now_ripple_timestamp = convert_to_ripple_time(Some((Utc::now()).timestamp()))?;
    let expiration_ripple_timestamp = convert_to_ripple_time(Some(
        (Utc::now() + Duration::days(expiration_in_days as i64)).timestamp(),
    ))?;

    let effective_ripple_timestamp = if version == 2 {
        let effective_date_time = convert_to_ripple_time(effective)?;
        if effective_date_time > expiration_ripple_timestamp {
            anyhow::bail!(VlValidationError::EffectiveDateBeforeExpiration);
        } else if effective_date_time < now_ripple_timestamp {
            anyhow::bail!(VlValidationError::PastEffectiveDate);
        } else if v2_vl.is_some()
            && is_effective_date_already_present(&decode_vl_v2(&vl)?, effective_date_time)?
        {
            anyhow::bail!(VlValidationError::EffectiveDateAlreadyPresent);
        }
        Some(effective_date_time)
    } else {
        None
    };

    let decoded_blob = DecodedBlob {
        sequence,
        expiration: expiration_ripple_timestamp,
        validators,
        effective: effective_ripple_timestamp,
    };

    let decoded_blob_payload = serde_json::to_string(&decoded_blob)?;
    let vl_blob = BASE64_STANDARD.encode(decoded_blob_payload.clone());
    let signature = sign(
        secret,
        decoded_blob_payload.clone().as_bytes(),
    )?;

    vl.public_key = base58_to_hex(
        &decoded_publisher_manifest.master_public_key,
        Version::NodePublic,
    )?
    .to_uppercase();
    vl.manifest = manifest.clone();

    // For version 1, we will generate a brand new file each time
    // For version 2, we can do the same but also start from an existing file.
    // The latter approach will add a new item to the blobs_v2 array

    if version == 1 {
        vl.signature = Some(signature.clone());
        vl.blob = Some(vl_blob);
    } else {
        if v2_vl.is_none() {
            vl.manifest = manifest;
            vl.blobs_v2 = Some(vec![]);
        }

        vl.blobs_v2
            .as_mut()
            .context("Could not get blobs_v2")?
            .push(BlobV2 {
                signature,
                manifest: None,
                blob: Some(BASE64_STANDARD.encode(decoded_blob_payload.clone())),
                decoded_blob: None,
                blob_verification: None,
            });
        vl.version = 2;
    }

    Ok(vl)
}

pub fn decode_vl_v1(vl: &Vl) -> Result<DecodedVl> {
    let decoded =
        BASE64_STANDARD.decode(vl.blob.clone().context("Could not decode VL (v1) Blob")?)?;
    let mut decoded_blob: DecodedBlob = serde_json::from_str(&String::from_utf8(decoded)?)?;
    for validator in decoded_blob.validators.iter_mut() {
        if validator.manifest.is_some() {
            let manifest = decode_manifest(
                &validator
                    .manifest
                    .clone()
                    .context("Could not decode manifest")?,
            )?;
            validator.decoded_manifest = Some(manifest.clone());
        }
    }
    let decoded_publisher_manifest = decode_manifest(&vl.manifest)?;
    Ok(DecodedVl {
        public_key: vl.public_key.clone(),
        manifest: decoded_publisher_manifest,
        blob: vl.blob.clone(),
        blobs_v2: vl.blobs_v2.clone(),
        decoded_blob: Some(decoded_blob),
        decoded_blobs_v2: None,
        signature: vl.signature.clone(),
        version: vl.version,
        blob_verification: None,
    })
}

pub fn decode_vl_v2(vl: &Vl) -> Result<DecodedVl> {
    let decoded_publisher_manifest = decode_manifest(&vl.manifest)?;
    let mut blobsv2: Vec<BlobV2> = vec![];
    // For each blob v2
    for blobv2 in vl
        .blobs_v2
        .clone()
        .context("Could not decode VL (v2) Blobs")?
    {
        let decoded =
            BASE64_STANDARD.decode(blobv2.blob.clone().context("Could not decode blob v2")?)?;
        let mut decoded_blob: DecodedBlob = serde_json::from_str(&String::from_utf8(decoded)?)?;
        for validator in decoded_blob.validators.iter_mut() {
            if validator.manifest.is_some() {
                let manifest = decode_manifest(
                    &validator
                        .manifest
                        .clone()
                        .context("Could not decode manifest")?,
                )?;
                validator.decoded_manifest = Some(manifest.clone());
            }
        }
        blobsv2.push(BlobV2 {
            signature: blobv2.signature,
            manifest: None,
            blob: None,
            decoded_blob: Some(decoded_blob),
            blob_verification: None,
        });
    }
    Ok(DecodedVl {
        public_key: vl.public_key.clone(),
        manifest: decoded_publisher_manifest,
        blob: None,
        blobs_v2: vl.blobs_v2.clone(),
        decoded_blob: None,
        decoded_blobs_v2: Some(blobsv2),
        signature: vl.signature.clone(),
        version: vl.version,
        blob_verification: None,
    })
}
