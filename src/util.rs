use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use ed25519::signature::SignerMut;
use secp256k1::{ecdsa::Signature as Secp256k1Signature, Message, PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey as Secp256k1SecretKey};
use sha2::{Sha256, Sha512, Digest};
use ed25519_dalek::{Signature as Ed25519Signature, SecretKey as Ed25519SecretKey, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use url::Url;
use std::{fs, str::FromStr};
use crate::{enums::Version, structs::{DecodedBlob, DecodedManifest, Ed25519Verifier, Unl}};
use color_eyre::owo_colors::OwoColorize;

pub fn from_xrpl_date(date: u32) -> u32 {
    date + 946684800
}

pub fn decode_manifest(manifest_blob: &str) -> Result<DecodedManifest> {
    let manifest_bytes = BASE64_STANDARD.decode(manifest_blob)?;

    let mut remaining_bytes = &manifest_bytes[..];

    let mut result = DecodedManifest::default();

    while !remaining_bytes.is_empty() {
        let (manifest_field_type, data, rest) = match decode_next_field(remaining_bytes)? {
            Some(value) => value,
            None => break,
        };
        remaining_bytes = rest;

        let manifest_field_type = if manifest_field_type.len() == 1 {
            manifest_field_type[0] as u16
        } else {
            u16::from_be_bytes(manifest_field_type.try_into().expect("Invalid mtypefield length"))
        };

        match manifest_field_type {
            0x24 => {
                result.sequence = u32::from_be_bytes(data.try_into().expect("Invalid sequence length"));
            },
            0x71 => {
                result.master_public_key = bytes_to_base58(&data)?;
            },
            0x73 => {
                result.signing_public_key = bytes_to_base58(&data)?;
            },
            0x76 => {
                result.signature = hex::encode(data);
            },
            0x7012 => {
                result.master_signature = hex::encode(data);
            },
            0x77 => {
                result.domain = Some(String::from_utf8(data).expect("Invalid UTF-8 data").to_string());
            },
            _ => {
                println!("Unexpected parsed field: {:x?} {:x?} {:x?}", manifest_field_type, data, remaining_bytes);
            }
        }
    }

    Ok(result)
}

fn decode_next_field(barray: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>, &[u8])>> {
    if barray.len() < 2 {
        return Ok(None);
    }

    let mut cbyteindex = 0;
    let cbyte = barray[cbyteindex];
    let ctype = (cbyte & 0xf0) >> 4;
    let mut cfieldid = cbyte & 0x0f;
    let mut typefield = vec![cbyte];

    if ctype == 0x7 {
        // blob
        if cfieldid == 0 {
            // larger field id
            cbyteindex += 1;
            cfieldid = barray[cbyteindex];
            typefield.push(cfieldid);
        }

        cbyteindex += 1;
        let cfieldlen = barray[cbyteindex] as usize;
        cbyteindex += 1;
        return Ok(
            Some((
                typefield,
                barray[cbyteindex..(cbyteindex + cfieldlen)].to_vec(),
                &barray[(cbyteindex + cfieldlen)..],
            ))
        );
    }

    let cfieldlen = match ctype {
        0x2 => 4,  // int32
        0xf => 1,  // int8
        0x1 => 2,  // int16
        0x03 => 8, // int64
        _ => {
            println!("WARN: Unparsed field type");
            1
        }
    };

    cbyteindex += 1;

    Ok(
        Some((
            typefield,
            barray[cbyteindex..(cbyteindex + cfieldlen)].to_vec(),
            &barray[(cbyteindex + cfieldlen)..],
        ))
    )
}

pub fn sha512_first_half(message: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let result = hasher.finalize();
    Ok(result[..32].to_vec())
}

pub fn double_sha256(hex_str: &str) -> Vec<u8> {
    let bin = hex::decode(hex_str).expect("Invalid hex string");
    let hash = Sha256::digest(&bin);
    let hash2 = Sha256::digest(&hash);
    hash2.to_vec()
}

pub fn hex_to_base58(key: &str) -> Result<String> {
    let payload_str = format!("1C{}", key);
    let payload_unhex = hex::decode(&payload_str).expect("Invalid hex string");
    let checksum = &double_sha256(&payload_str)[..4];
    let mut payload_with_checksum = payload_unhex.clone();
    payload_with_checksum.extend_from_slice(checksum);
    Ok(
        base58_encode(payload_with_checksum)
    )
}

pub fn decode_unl(unl: Unl) -> Result<Unl> {
    let mut decoded_unl: Unl = unl.clone();
    let decoded = BASE64_STANDARD.decode(&unl.blob).unwrap();
    let mut decoded_blob: DecodedBlob = serde_json::from_str(&String::from_utf8(decoded)?)?;
    for validator in decoded_blob.validators.iter_mut() {
        let manifest = decode_manifest(&validator.manifest).expect("Could not decode manifest");
        validator.decoded_manifest = Some(manifest.clone());
    }
    decoded_unl.decoded_manifest = Some(decode_manifest(&unl.manifest)?);
    decoded_unl.decoded_blob = Some(decoded_blob);
    Ok(decoded_unl)
}

pub fn get_manifests(file_path: &str) -> Result<Vec<String>> {
    let contents = fs::read_to_string(file_path).expect(&format!("No such file: {}", file_path));
    let lines: Vec<String> = contents.split("\n")
        .map(|s: &str| s.to_string())
        .collect();
    Ok(lines)
}

pub async fn get_unl(url_or_file: &str) -> Result<Unl> {
    let url = Url::parse(
        &url_or_file
    );
    let unl: Unl;
    
    if url.is_err() {
        unl = serde_json::from_str(&fs::read_to_string(url_or_file)?)?;
    } else {
        unl = reqwest::get(url_or_file)
            .await?
        .json::<Unl>()
        .await?;
    }
    Ok(unl)
}

pub fn base58_to_hex(b58_str: &str) -> String {
    let decb58 = base58_decode(Version::NodePublic, b58_str).expect("Invalid base58 string");
    let payload_unhex = &decb58[..decb58.len() - 4];
    let checksum = &decb58[decb58.len() - 4..];
    let payload_hex = hex::encode(payload_unhex);
    let check = &double_sha256(&payload_hex)[..4] == checksum;
    if !check {
        println!("Checksum check: {}", check);
    }
    hex::encode(decb58)
}

pub fn bytes_to_base58(b58_bytes: &[u8]) -> Result<String> {
    hex_to_base58(&hex::encode(b58_bytes))
}

pub fn base58_encode<I: AsRef<[u8]>>(input: I) -> String {
    bs58::encode(input)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

pub fn base58_decode<I: AsRef<[u8]>>(version: Version, input: I) -> bs58::decode::Result<Vec<u8>> {
    bs58::decode(input)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .with_check(Some(version.value()))
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

pub fn sign(public_key_hex: &str, private_key_hex: &str, payload: &str) -> String {
    let is_ed25519 = public_key_hex.starts_with("ED");
    if is_ed25519 {
        let private_key_bytes: [u8;32] = get_key_bytes(private_key_hex).expect("Could not get bytes").try_into().expect("Could not conver key to u8;32");
        let mut signing_key = Ed25519SigningKey::from_bytes(&private_key_bytes);
        signing_key.sign(payload.as_bytes()).to_string()
    } else {
        // let secp = Secp256k1::new();
        // let secret_key = Secp256k1SecretKey::from_str(private_key_hex).expect("Invalid Secp256k1 Secret Key");
        // let message = Message::from_digest(sha512_first_half(payload.as_bytes().unwrap().try_into().unwrap())?);
        // let signature = secp.sign(&message, &secret_key);
        // signature.to_string()
        "TODO".to_string()
    }
}

pub fn verify_signature(public_key_hex: &str, payload: &[u8], signature: &str) -> bool {

    let is_ed25519 = public_key_hex.starts_with("ED");
    let public_key_bytes = get_key_bytes(public_key_hex).expect("Could not get bytes");
    if is_ed25519 {
        let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key_bytes[1..33].try_into().expect("Could not parse Public Key");
        let signature_bytes: [u8; SIGNATURE_LENGTH] = hex::decode(signature).expect("Could not decode Signature from Hex format").try_into().expect("Could not parse Signature");
        let verifying_key = Ed25519VerifyingKey::from_bytes(&public_key_bytes).expect("Invalid ED25519 Public Key");
        let signature = Ed25519Signature::from_bytes(&signature_bytes); 
        let verifier = Ed25519Verifier {
            verifying_key
        };
        verifier.verify(&hex::decode(hex::encode(payload)).unwrap(), &signature).is_ok()
    } else {
        let secp = Secp256k1::new();
        let signature = Secp256k1Signature::from_str(signature).expect("Invalid Secp256k1 Signature");
        let digest = sha512_first_half(payload);
        let p: [u8; 32] = digest.unwrap().try_into().unwrap();
        let message = Message::from_digest(p);
        let public_key = Secp256k1PublicKey::from_slice(&public_key_bytes).expect("Invalid Secp256k1 Public Key");
        secp.verify_ecdsa(&message, &signature, &public_key).is_ok()
    }
}

pub fn get_key_bytes(key: &str) -> Result<Vec<u8>> {
    if key.len() >= 64 {
       Ok( base58_decode(Version::NodePublic, hex_to_base58(key).unwrap().as_str())?)
    } else if key.len() != 33 {
        Ok(base58_decode(Version::NodePublic, key)?)
    } else {
        Ok(key.as_bytes().to_vec())
    }
}

pub fn serialize_manifest_data(decoded_manifest: &DecodedManifest) -> Result<Vec<u8>> {

    let mut serialized_manifest = Vec::new();
    let master_public_key = get_key_bytes(&decoded_manifest.master_public_key).expect("Could not get bytes");
    let signing_public_key = get_key_bytes(&decoded_manifest.signing_public_key).expect("Could not get bytes");

    let m: &[u8;1] = "M".as_bytes().try_into()?;
    let a: &[u8;1] = "A".as_bytes().try_into()?;
    let n: &[u8;1] = "N".as_bytes().try_into()?;
    let sequence_type = 0x24 as u8;
    let master_key_type = 0x71 as u8;
    let signing_key_type = 0x73 as u8;
    let domain_type = 0x77 as u8;

    // Prefix
    serialized_manifest.extend_from_slice(m);
    serialized_manifest.extend_from_slice(a);
    serialized_manifest.extend_from_slice(n);
    serialized_manifest.extend_from_slice(&[0]);

    // Sequence
    serialized_manifest.extend_from_slice(sequence_type.to_le_bytes().as_ref());
    serialized_manifest.extend_from_slice((decoded_manifest.sequence as u32).to_be_bytes().as_ref());

    // Master Public Key
    serialized_manifest.extend_from_slice(master_key_type.to_le_bytes().as_ref());
    serialized_manifest.extend_from_slice((master_public_key.len() as u8).to_be_bytes().as_ref());
    serialized_manifest.extend_from_slice(&master_public_key);

    // Signing Public Key
    serialized_manifest.extend_from_slice(signing_key_type.to_be_bytes().as_ref());
    serialized_manifest.extend_from_slice((signing_public_key.len() as u8).to_be_bytes().as_ref()); // PK Length
    serialized_manifest.extend_from_slice(&signing_public_key);

    // Domain
    if let Some(domain) = &decoded_manifest.domain {
        let domain = domain.as_bytes();
        serialized_manifest.extend_from_slice(domain_type.to_be_bytes().as_ref());
        serialized_manifest.extend_from_slice((domain.len() as u8).to_be_bytes().as_ref()); // PK Length
        serialized_manifest.extend_from_slice(domain);
    }

    Ok(serialized_manifest)

}