use crate::{
    enums::ManifestField, structs::DecodedManifest, util::{bytes_to_base58, get_key_bytes}
};
use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};

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
            u16::from_be_bytes(
                manifest_field_type
                    .try_into()
                    .expect("Invalid mtypefield length"),
            )
        };

        let field_type = ManifestField::from_value(&manifest_field_type)?;
        match field_type {
            ManifestField::Sequence => {
                result.sequence =
                    u32::from_be_bytes(data.try_into().expect("Invalid sequence length"));
            }
            ManifestField::MasterPublicKey => {
                result.master_public_key = bytes_to_base58(&data)?;
            }
            ManifestField::SigningPublicKey => {
                result.signing_public_key = bytes_to_base58(&data)?;
            }
            ManifestField::Signature => {
                result.signature = hex::encode(data);
            }
            ManifestField::MasterSignature => {
                result.master_signature = hex::encode(data);
            }
            ManifestField::Domain => {
                result.domain = Some(
                    String::from_utf8(data)
                        .expect("Invalid UTF-8 data")
                        .to_string(),
                );
            }
        }
    }

    Ok(result)
}

type DecodField<'a> = (Vec<u8>, Vec<u8>, &'a [u8]);

fn decode_next_field(barray: &[u8]) -> Result<Option<DecodField>> {
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
        return Ok(Some((
            typefield,
            barray[cbyteindex..(cbyteindex + cfieldlen)].to_vec(),
            &barray[(cbyteindex + cfieldlen)..],
        )));
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

    Ok(Some((
        typefield,
        barray[cbyteindex..(cbyteindex + cfieldlen)].to_vec(),
        &barray[(cbyteindex + cfieldlen)..],
    )))
}

pub fn serialize_manifest_data(decoded_manifest: &DecodedManifest) -> Result<Vec<u8>> {
    let mut serialized_manifest = Vec::new();
    let master_public_key =
        get_key_bytes(&decoded_manifest.master_public_key).expect("Could not get bytes");
    let signing_public_key =
        get_key_bytes(&decoded_manifest.signing_public_key).expect("Could not get bytes");

    // Prefix
    serialized_manifest.extend_from_slice(b"MAN");

    serialized_manifest.extend_from_slice(&[0]);

    // Sequence
    serialized_manifest.extend_from_slice(&[ManifestField::Sequence as u8]);
    serialized_manifest
        .extend_from_slice((decoded_manifest.sequence).to_be_bytes().as_ref());

    // Master Public Key
    serialized_manifest.extend_from_slice(&[ManifestField::MasterPublicKey as u8]);
    serialized_manifest.extend_from_slice((master_public_key.len() as u8).to_be_bytes().as_ref());
    serialized_manifest.extend_from_slice(&master_public_key);

    // Signing Public Key
    serialized_manifest.extend_from_slice(&[ManifestField::SigningPublicKey as u8]);
    serialized_manifest.extend_from_slice((signing_public_key.len() as u8).to_be_bytes().as_ref()); // PK Length
    serialized_manifest.extend_from_slice(&signing_public_key);

    // Domain
    if let Some(domain) = &decoded_manifest.domain {
        let domain = domain.as_bytes();
        serialized_manifest.extend_from_slice(&[ManifestField::Domain as u8]);
        serialized_manifest.extend_from_slice((domain.len() as u8).to_be_bytes().as_ref()); // PK Length
        serialized_manifest.extend_from_slice(domain);
    }

    Ok(serialized_manifest)
}
