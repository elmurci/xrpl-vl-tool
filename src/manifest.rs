use crate::{
    enums::{ManifestField, Version}, errors::DecodeManifestError, structs::DecodedManifest, util::{base58_decode, bytes_to_base58, get_key_bytes}
};
use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};

pub fn encode_manifest(
    sequence: u32,
    master_public_key: String,
    signing_public_key: String,
    signature: String,
    master_signature: String,
    domain: Option<String>,
) -> Result<String> {
    // Sequence: 0x24 | seq(4 bytes)
    let mut seq_bytes = vec![0x24];
    seq_bytes.extend_from_slice(&sequence.to_be_bytes());

    // Master public key
    let master_public_key_bytes = base58_decode(Version::NodePublic, &master_public_key)?;
    let mut mpk_bytes = vec![0x71]; 
    mpk_bytes.push(master_public_key_bytes.len() as u8);
    mpk_bytes.extend_from_slice(&master_public_key_bytes);

    // Signing public key
    let signing_public_key_bytes = base58_decode(Version::NodePublic, &signing_public_key)?;
    let mut signing_pk_bytes = vec![0x73];
    signing_pk_bytes.push(signing_public_key_bytes.len() as u8);
    signing_pk_bytes.extend_from_slice(&signing_public_key_bytes);

    // Signature (hex -> bytes)
    let signature_decoded = hex::decode(signature)?;
    let mut signature_bytes = vec![0x76];
    signature_bytes.push(signature_decoded.len() as u8);
    signature_bytes.extend_from_slice(&signature_decoded);

    // Domain (optional)
    let domain_bytes = if let Some(d) = domain {
        let dbytes = d.as_bytes();
        let mut db = vec![0x77];
        db.push(dbytes.len() as u8);
        db.extend_from_slice(dbytes);
        db
    } else {
        vec![]
    };

    // Master signature (hex -> bytes)
    let master_sig_decoded = hex::decode(master_signature)?;
    // FieldID: 0x7012 (two bytes: 0x70, 0x12)
    let mut master_signature_bytes = vec![0x70, 0x12];
    master_signature_bytes.push(master_sig_decoded.len() as u8);
    master_signature_bytes.extend_from_slice(&master_sig_decoded);

    // Concatenate all
    let mut serialized_manifest = vec![];
    serialized_manifest.extend_from_slice(&seq_bytes);
    serialized_manifest.extend_from_slice(&mpk_bytes);
    serialized_manifest.extend_from_slice(&signing_pk_bytes);
    serialized_manifest.extend_from_slice(&signature_bytes);
    serialized_manifest.extend_from_slice(&domain_bytes);
    serialized_manifest.extend_from_slice(&master_signature_bytes);

    // Base64 encode the final data
    Ok(BASE64_STANDARD.encode(serialized_manifest))
}

pub fn decode_manifest(manifest_blob: &str) -> Result<DecodedManifest> {
    let manifest_bytes = BASE64_STANDARD.decode(manifest_blob)
    .map_err(|err| {
        DecodeManifestError::Base64Error(format!("Could not decode Base64 Manifest: {}, [{}]", err, manifest_blob))
    })?;

    let mut remaining_bytes = &manifest_bytes[..];

    let mut result = DecodedManifest::default();

    while !remaining_bytes.is_empty() {
        let (manifest_field_type, data, rest) = match decode_next_field(remaining_bytes)
        .map_err(|err| {
            DecodeManifestError::NextFieldError(format!("decode_next_field failed: {}", err))
        })? {
            Some(value) => value,
            None => break,
        };
        remaining_bytes = rest;

        let manifest_field_type = if manifest_field_type.len() == 1 {
            manifest_field_type[0] as u16
        } else {
            u16::from_be_bytes(
                manifest_field_type.try_into().map_err(|_| {
                    DecodeManifestError::InvalidFieldLength(
                        "Invalid `manifest_field_type` length; expected 1 or 2 bytes".to_string(),
                    )
                })?
            )
        };

        let field_type = ManifestField::from_value(&manifest_field_type)
        .map_err(|err| {
            DecodeManifestError::Other(format!("Couldn't parse ManifestField: {}", err))
        })?;
        
        match field_type {
            ManifestField::Sequence => {
                result.sequence = u32::from_be_bytes(
                    data.try_into().map_err(|_| {
                        DecodeManifestError::InvalidFieldLength(
                            "Invalid sequence length; expected 4 bytes".to_string(),
                        )
                    })?
                );
            }
            ManifestField::MasterPublicKey => {
                result.master_public_key = bytes_to_base58(&data).map_err(|err| {
                    DecodeManifestError::Other(format!("Error converting to base58: {}", err))
                })?;
            }
            ManifestField::SigningPublicKey => {
                result.signing_public_key = bytes_to_base58(&data).map_err(|err| {
                    DecodeManifestError::Other(format!("Error converting to base58: {}", err))
                })?;
            }
            ManifestField::Signature => {
                result.signature = hex::encode(data);
            }
            ManifestField::MasterSignature => {
                result.master_signature = hex::encode(data);
            }
            ManifestField::Domain => {
                // Instead of `.expect(...)` we return a custom error if UTF-8 fails
                result.domain = Some(
                    String::from_utf8(data).map_err(|err| {
                        DecodeManifestError::Utf8Error(format!(
                            "Invalid UTF-8 data in Domain field: {}",
                            err
                        ))
                    })?
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
        get_key_bytes(&decoded_manifest.master_public_key).expect("Could not get Master Public Key bytes");
    let signing_public_key =
        get_key_bytes(&decoded_manifest.signing_public_key).expect("Could not get Signing Public Key bytes");

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
        serialized_manifest.extend_from_slice((domain.len() as u8).to_be_bytes().as_ref()); // Domain Length
        serialized_manifest.extend_from_slice(domain);
    }

    Ok(serialized_manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_valid_manifest_without_domain() {
        let manifest = "JAAAAAFxIe0Wqdp2/gl3yT498qNqAeNLM6fj4x+3/xiEbK0i0JEo53MhA5077HWE7RyCE2ricOZTqAXN6kom3ShR+ssRE+NZXSiIdkYwRAIgS8af2OZhoqOZpsqhr5nV2mmh0Pr9Mj5PIg7bKx94wuACIGyDRzTMJidtKN2rUEEDMECJT2pKpFtDJD+m+HcHcO2ncBJAS1wbIiBipI1oYw921hzocGeLLjMN+8ijpKf5EizOs5G98iqJS3DOjpjAzrGTNPDNjCIE4dnE+HWy33uTxkMlBA==";
        let decoded_manifest = decode_manifest(manifest).unwrap();
        assert_eq!(decoded_manifest.sequence, 1);
        assert_eq!(decoded_manifest.master_public_key, "nHBXRNjWjs52ghGwrEkZMbYsa76xhtyqW5wFwoWtjf8pZSFifx9E");
        assert_eq!(decoded_manifest.domain, None);
        assert_eq!(decoded_manifest.signing_public_key, "n9MgVP3JT1z1CA3azzTGvmUhoS3D9EfgMSVuiDQmCyQmw95bXFgt");
    }

    #[test]
    fn test_decode_valid_manifest_with_domain() {
        let manifest = "JAAAAAFxIe1wmHckcXaegqVGYymWfci/UclBGQFk6I18ycOTrUB8UnMhA8DziyNuw0Q7SFhXnP/d5g838JjxdulqFyAPyRz4ApUvdkcwRQIhANMLcUuME5k+ow4iZIkNDB3t2ZLybz70IKOIuW7rpyeVAiBu5Q2qqbALmcxRHAx3rr1ErXu8pYOYmlLh1pOCeO5pv3cNZWtpc2VycmVwZS5lc3ASQDkMGLzDu1azJ33rYJCNg/TOufVyC5nh8xPhtqMMDv7CFG+oRZjrYJMFG4G9aU8L15ezwgNiyIXVHSmxVtFb3Ak=";
        let decoded_manifest = decode_manifest(manifest).unwrap();
        assert_eq!(decoded_manifest.sequence, 1);
        assert_eq!(decoded_manifest.master_public_key, "nHUDpRzvY8fSRfQkmJMqjmVSaFmMEVxBNn2tNQy5VAhFJ6is6GFk");
        assert_eq!(decoded_manifest.domain, Some("ekiserrepe.es".to_string()));
        assert_eq!(decoded_manifest.signing_public_key, "n9MxDjQMr1DkzW3Z5X1guKJq4QNDEeYFPgqGgHfpzerGbHWGZvj4");
    }

    #[test]
    fn test_encode_manifest_without_domain() {
        let encoded_manifest = encode_manifest(
            2,
            "nHU1CDnwycUaaLY3xbLZXdRnyu2zqGGVa2DaPSoakr1KNGvDMmRM".to_string(),
            "n9KJtnsiUKpJhX5iVAKSYAFxuPxtvXSgysvycyoeuT1Td7PGruae".to_string(),
            "304402203675485E91ED22D5FAE0DED32A94FB42A6CEBD81D3036C9D3C46AAC587BC14480220115FEB55523F4AA340A2BDA734BDFB7D9F31AF3A397B582AEE96DB0FDA0CB5B8".to_string(),
            "8DF81CB9E5FEF68E20201911CD76A8FD24EC6E3A547B1B96DA0B804596FFDFEF7BA4127AB25D8A417D372E66B70B52E3E34F33138A464F4CD824151F43A90601".to_string(),
            None

        ).unwrap();
        assert_eq!(encoded_manifest, "JAAAAAJxIe3IUalyteie/j1ayTmjfuB8ViDryrVSIgvtCKHmHtrrYnMhAmTGwvr9oyVVBXlPWzIot320Dod6W0mOY8bh5aAPkTQldkYwRAIgNnVIXpHtItX64N7TKpT7QqbOvYHTA2ydPEaqxYe8FEgCIBFf61VSP0qjQKK9pzS9+32fMa86OXtYKu6W2w/aDLW4cBJAjfgcueX+9o4gIBkRzXao/STsbjpUexuW2guARZb/3+97pBJ6sl2KQX03Lma3C1Lj408zE4pGT0zYJBUfQ6kGAQ==");
    }

    #[test]
    fn test_encode_manifest_with_domain() {
        let encoded_manifest = encode_manifest(
            3,
            "nHUxjxKPeErbN7pNk9UWA5Ee7ZPMtesSeRGJtmdqkTxe94tqM2YX".to_string(),
            "n9LkWXS9HEY9adzT4y4J4Fbc1EFpKfuLf1gj2sTAktgZRukJcFiS".to_string(),
            "3045022100D269B56526FDE0C34523859534C6F01629493AE08B23109AD0E605B528D3F79102206EB51C12A03737048395C825ABCE275C0DF06A6D4208589B5B7C12795465CF7B".to_string(),
            "534504BE536E3D565DCBB8D558F18BCEF363D75A3CD5EC85511925BB8CEE292EEEC2FA5D9F44270B5947A62CCB19D73273EE759CE76337A978C48F21C4481F0C".to_string(),
            Some("tequ.dev".to_string())

        ).unwrap();
        assert_eq!(encoded_manifest, "JAAAAANxIe3T256FqbJnckZL6fzhIAB+UEqvev9GSPok4VWzWkj+bXMhAyKqTFBL4DxByKxxFIfO5yjIyyG3mi9abgq3siqYomIqdkcwRQIhANJptWUm/eDDRSOFlTTG8BYpSTrgiyMQmtDmBbUo0/eRAiButRwSoDc3BIOVyCWrzidcDfBqbUIIWJtbfBJ5VGXPe3cIdGVxdS5kZXZwEkBTRQS+U249Vl3LuNVY8YvO82PXWjzV7IVRGSW7jO4pLu7C+l2fRCcLWUemLMsZ1zJz7nWc52M3qXjEjyHESB8M");
    }

}