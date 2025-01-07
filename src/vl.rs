use std::fs;

use base64::{prelude::BASE64_STANDARD, Engine};
use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use url::Url;

use crate::{crypto::{sign, verify_signature}, enums::Version, errors::VlValidationError, manifest::decode_manifest, structs::{BlobV2, DecodedBlob, DecodedVl, Secret, Validator, Vl}, time::convert_to_ripple_time, util::{base58_to_hex, get_manifests, is_effective_date_already_present, verify_manifest}};

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
        1 => {
            decode_vl_v1(&vl)?
        },
        2 => {
            decode_vl_v2(&vl)?
        },
        _ => return Err(anyhow!("Unsupported version")),
    };

    Ok(parsed_vl)  
}

pub fn verify_vl(mut vl: DecodedVl) -> Result<DecodedVl> {
    
    let public_key = base58_to_hex(&vl.manifest.signing_public_key.clone(), Version::NodePublic).to_uppercase();
    // Manifest Verification
    let manifest_verification = verify_manifest(vl.manifest.clone()).is_ok();
    vl.manifest.verification =  manifest_verification;

    // With version 1 there is only one blob
    if vl.version == 1 {
        let mut decoded_blob = vl.decoded_blob.clone().expect("Could not get decoded blob");
        // Blob verification verifies each validator manifest
        for validator in decoded_blob.validators.iter_mut() {
            let verified_validator = verify_manifest(validator.decoded_manifest.clone().expect("Could not get decoded manifest"))?;
            validator.decoded_manifest = Some(verified_validator.clone());
        }
        vl.decoded_blob = Some(decoded_blob);
        let verify_blob = verify_signature(
            &public_key,
            &BASE64_STANDARD.decode(vl.blob.clone().expect("Could not get blob from v1 vl"))?,
            &vl.signature.clone().expect("Could not get signature from v1 vl"),
        )?;
        vl.blob_verification = Some(verify_blob);
    } else {
        // With version 2, there might be multiple blobs
        let decoded_blobs_v2 = vl.decoded_blobs_v2.as_mut().expect("Could not get decoded blobs v2");
        for (index, blob_v2) in decoded_blobs_v2.iter_mut().enumerate() {
            let mut decoded_blob = blob_v2.clone().decoded_blob.expect("Could not get decoded blob");
            // If the manifest is not present in a blobs-v2 array entry, 
            // then the top-level manifest will be used when checking the signature.
            if blob_v2.manifest.is_some() {
                verify_manifest(vl.manifest.clone())?;
            }
            // TODO: move to a function?
            for validator in decoded_blob.validators.iter_mut() {
                let verified_validator = verify_manifest(validator.decoded_manifest.clone().expect("Could not get decoded manifest"))?;
                validator.decoded_manifest = Some(verified_validator);
            }
            let blobs_v2 = &vl.blobs_v2.clone().expect("Could not get blobs v2 from vl")[index];
            let verify_blob = verify_signature(
                &public_key,
                &BASE64_STANDARD.decode(blobs_v2.blob.clone().expect("Could not get blob from blobs_v2"))?,
                &blobs_v2.signature.clone()
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

    if expiration_in_days == 0 {
        return Err(anyhow!("Expiration has to be greater than 0"));
    }

    if version == 2 && v2_vl.is_some() {
        let v = v2_vl.clone().unwrap();
        if !v.blobs_v2.clone().expect("Could not get blobs v2").is_empty() {
            let blobs = v.blobs_v2.clone().ok_or(anyhow!("Could not get blobs_v2"))?;
            let mut sequence_numbers: Vec<u32> = Vec::with_capacity(blobs.len());
            for blob_v2 in blobs.iter() {
                let decoded = BASE64_STANDARD.decode(blob_v2.blob.clone().unwrap())?;
                let decoded_blob: DecodedBlob = serde_json::from_str(&String::from_utf8(decoded)?)?;
                sequence_numbers.push(decoded_blob.sequence);
            }
            if !sequence_numbers.iter().all(|&n| sequence > n) {
                return Err(anyhow!(VlValidationError::InvalidSequence));
            }
        } else {
            return Err(anyhow!(VlValidationError::MalformedVl));
        }
    }

    let mut vl = v2_vl.clone().unwrap_or_default();    
    let manifests = get_manifests(&manifests_file)?;
    let mut validators: Vec<Validator> = vec![];

    for manifest in manifests {
        let decoded_manifest = decode_manifest(&manifest)?;
        let validator = Validator {
            validation_public_key: base58_to_hex(&decoded_manifest.master_public_key, Version::NodePublic)
                .to_uppercase(),
            manifest: Some(manifest),
            decoded_manifest: None,
        };
        validators.push(validator);
    }

    let now_ripple_timestamp =  convert_to_ripple_time(Some(
        (Utc::now()).timestamp(),
    ));
    let expiration_ripple_timestamp =  convert_to_ripple_time(Some(
        (Utc::now() + Duration::days(expiration_in_days as i64)).timestamp(),
    ));

    let effective_ripple_timestamp = if version == 2 {
        let effective_date_time = convert_to_ripple_time(effective);
        if effective_date_time > expiration_ripple_timestamp {
            return Err(anyhow!(VlValidationError::EffectiveDateBeforeExpiration));
        } else if effective_date_time < now_ripple_timestamp {
            return Err(anyhow!(VlValidationError::PastEffectiveDate));
        } else if v2_vl.is_some() && is_effective_date_already_present(&decode_vl_v2(&vl)?, effective_date_time)? {
            return Err(anyhow!(VlValidationError::EffectiveDateAlreadyPresent));
        }
        Some(effective_date_time)
    } else {
        None
    };

    let decoded_blob = DecodedBlob {
        sequence,
        expiration: expiration_ripple_timestamp,
        validators,
        effective: effective_ripple_timestamp
    };

    let decoded_blob_payload = serde_json::to_string(&decoded_blob)?;
    let vl_blob = BASE64_STANDARD.encode(decoded_blob_payload.clone());
    let signature = sign(
        &secret.public_key,
        &secret.private_key,
        decoded_blob_payload.clone().as_bytes(),
    )?;

    vl.public_key = base58_to_hex(&decoded_publisher_manifest.master_public_key, Version::NodePublic).to_uppercase();
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

        vl.blobs_v2.as_mut().expect("Could not get blobs_v2").push(
            BlobV2 {
                signature,
                manifest: None,
                blob: Some(BASE64_STANDARD.encode(decoded_blob_payload.clone())),
                decoded_blob: None,
                blob_verification: None,
            },
        );
        vl.version = 2;
    }

    Ok(vl)

}

pub fn decode_vl_v1(vl: &Vl) -> Result<DecodedVl> {
    let decoded = BASE64_STANDARD.decode(vl.blob.clone().expect("Could not decode VL (v1) Blob"))?;
    let mut decoded_blob: DecodedBlob = serde_json::from_str(&String::from_utf8(decoded)?)?;
    for validator in decoded_blob.validators.iter_mut() {
        if validator.manifest.is_some() {
            let manifest = decode_manifest(&validator.manifest.clone().expect("Could not decode manifest"))?;
            validator.decoded_manifest = Some(manifest.clone());
        }
    }
    let decoded_publisher_manifest = decode_manifest(&vl.manifest)?;
    Ok(
        DecodedVl {
            public_key: vl.public_key.clone(),
            manifest: decoded_publisher_manifest,
            blob: vl.blob.clone(),
            blobs_v2: vl.blobs_v2.clone(),
            decoded_blob: Some(decoded_blob),
            decoded_blobs_v2: None,
            signature: vl.signature.clone(),
            version: vl.version,
            blob_verification: None,
        }
    )
}

pub fn decode_vl_v2(vl: &Vl) -> Result<DecodedVl> {
    let decoded_publisher_manifest = decode_manifest(&vl.manifest)?;
    let mut blobsv2: Vec<BlobV2> = vec![];
    // For each blob v2
    for blobv2 in vl.blobs_v2.clone().expect("Could not decode VL (v2) Blobs") {
        let decoded = BASE64_STANDARD.decode(blobv2.blob.expect("Could not decode blob v2"))?;
        let mut decoded_blob: DecodedBlob = serde_json::from_str(&String::from_utf8(decoded)?)?;
        for validator in decoded_blob.validators.iter_mut() {
            if validator.manifest.is_some() {
                let manifest = decode_manifest(&validator.manifest.clone().expect("Could not decode manifest"))?;
                validator.decoded_manifest = Some(manifest.clone());
            }
        }
        blobsv2.push(
            BlobV2 { 
                signature: blobv2.signature,
                manifest: None,
                blob: None,
                decoded_blob: Some(decoded_blob),
                blob_verification: None,
            }
        );
    }
    Ok(
        DecodedVl {
            public_key: vl.public_key.clone(),
            manifest: decoded_publisher_manifest,
            blob: None,
            blobs_v2: vl.blobs_v2.clone(),
            decoded_blob: None,
            decoded_blobs_v2: Some(blobsv2),
            signature: vl.signature.clone(),
            version: vl.version,
            blob_verification: None,
        }
    )
}