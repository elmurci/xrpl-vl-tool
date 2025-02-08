#![allow(clippy::too_many_arguments)]

macro_rules! test_data {
    ($fname:expr) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $fname) // assumes Linux ('/')!
    };
}

mod test {
    use anyhow::{Context, Result};
    use chrono::{NaiveDateTime, Utc};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use secp256k1::{hashes::hex::DisplayHex, Secp256k1};
    use xrpl_vl_tool::{
        crypto::{sign, KeyPairBytes, KeyType},
        manifest::{encode_manifest, serialize_manifest_data, DecodedManifest},
        secret::{Secret, SecretProvider},
        time::{convert_to_human_time, convert_to_ripple_time, convert_to_unix_time},
        util::{base58_to_hex, hex_to_base58, Version},
        vl::{decode_vl_v1, decode_vl_v2, get_vl, load_vl, sign_vl, verify_vl, Vl},
    };

    fn generate_manifest(
        master_secret: Secret,
        signing_secret: Secret,
        sequence: u32,
        domain: Option<String>,
    ) -> String {
        let mut master_public_key_bytes = master_secret.clone().key_pair_bytes.public_key_bytes;
        let mut signing_public_key_bytes = signing_secret.clone().key_pair_bytes.public_key_bytes;
        if master_secret.key_type == KeyType::Ed25519 {
            master_public_key_bytes.insert(0, 237);
        }
        let master_public_key =
            hex_to_base58(&master_public_key_bytes.to_upper_hex_string()).unwrap();
        if signing_secret.key_type == KeyType::Ed25519 {
            signing_public_key_bytes.insert(0, 237);
        }
        let signing_public_key =
            hex_to_base58(&signing_public_key_bytes.to_upper_hex_string()).unwrap();
        let serialized_manifest = serialize_manifest_data(&DecodedManifest {
            master_public_key: master_public_key.clone(),
            signing_public_key: signing_public_key.clone(),
            sequence,
            domain: domain.clone(),
            signature: "".to_string(),
            master_signature: "".to_string(),
            verification: false,
        })
        .unwrap();
        let master_signature = sign(master_secret, &serialized_manifest).unwrap();
        let signature = sign(signing_secret, &serialized_manifest).unwrap();
        encode_manifest(
            sequence,
            master_public_key.to_owned(),
            signing_public_key.to_owned(),
            signature,
            master_signature,
            domain,
        )
        .unwrap()
    }

    fn generate_secret(secret_type: &KeyType) -> Secret {
        match secret_type {
            KeyType::Ed25519 => {
                let mut csprng = OsRng;
                let signing_key: SigningKey = SigningKey::generate(&mut csprng);
                Secret {
                    key_pair_bytes: KeyPairBytes {
                        public_key_bytes: signing_key.verifying_key().to_bytes().to_vec(),
                        private_key_bytes: signing_key.to_bytes().to_vec(),
                    },
                    key_type: KeyType::Ed25519,
                    secret_provider: SecretProvider::Local,
                }
            }
            KeyType::Secp256k1 => {
                let secp = Secp256k1::new();
                let (private_key, public_key) = secp.generate_keypair(&mut OsRng);
                Secret {
                    key_pair_bytes: KeyPairBytes {
                        public_key_bytes: public_key.serialize().to_vec(),
                        private_key_bytes: private_key.secret_bytes().to_vec(),
                    },
                    key_type: KeyType::Secp256k1,
                    secret_provider: SecretProvider::Local,
                }
            }
        }
    }

    fn get_timestamp_from_string(date_time_string: String) -> Option<i64> {
        Some(
            NaiveDateTime::parse_from_str(&date_time_string, "%Y-%m-%d %H:%M")
                .expect("Could not parse effective timestamp, format is %Y-%m-%d %H:%M")
                .and_utc()
                .timestamp(),
        )
    }

    fn get_valid_effective_timestamp(add: i64) -> i64 {
        (Utc::now()).timestamp() + add
    }

    fn get_ripple_now() -> Result<i64> {
        convert_to_ripple_time(Some((Utc::now()).timestamp()))
            .context("Could not convert to Ripple time")
    }

    async fn test_sign_vl(
        version: u8,
        manifests_list: String,
        sequence: u32,
        expiration: i16,
        effective: Option<i64>,
        v2_vl: Option<Vl>,
        secret_type: KeyType,
        number_of_blobs: Option<u8>,
        manifest: Option<String>,
    ) -> Result<Vl> {
        let master_secret = generate_secret(&secret_type);
        let signing_secret = generate_secret(&secret_type);
        let publisher_manifest = if manifest.is_none() {
            generate_manifest(master_secret.clone(), signing_secret.clone(), 1, None)
        } else {
            manifest.unwrap()
        };
        if version == 2 && number_of_blobs.is_some() {
            let sig_secret = signing_secret.clone();
            let effective_date = effective.unwrap() + 1_000_000;
            let mut vl = v2_vl.unwrap_or_default();
            for index in 0..number_of_blobs.unwrap() {
                vl = sign_vl(
                    version,
                    publisher_manifest.clone(),
                    manifests_list.clone(),
                    sequence + (index as u32),
                    expiration,
                    sig_secret.clone(),
                    Some(effective_date + (index as i64)),
                    if vl.blobs_v2.is_none() {
                        None
                    } else {
                        Some(vl)
                    },
                )
                .await?;
            }
            Ok(vl)
        } else {
            sign_vl(
                version,
                publisher_manifest,
                manifests_list.clone(),
                sequence,
                expiration,
                signing_secret.clone(),
                effective,
                v2_vl,
            )
            .await
        }
    }

    // VL's that should verify (v1 and v2)

    #[tokio::test]
    async fn should_load_v1_valid_public_vl() {
        let vl = load_vl("https://vl.ripple.com").await.unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 1);
        assert!(verified_vl.blobs_v2.is_none());
        for validator in verified_vl.decoded_blob.clone().unwrap().validators {
            assert!(validator.decoded_manifest.unwrap().verification);
        }
        assert!(verified_vl.manifest.verification);
    }

    #[tokio::test]
    async fn v1_manifests_file_should_have_1_at_least() {
        // Sign
        let signed_vl = test_sign_vl(
            1,
            test_data!("empty_file").to_string(),
            91,
            365,
            None,
            None,
            KeyType::Secp256k1,
            None,
            None,
        )
        .await;
        assert!(
            signed_vl.err().unwrap().to_string() == "No manifests found in the file"
        );
    }

    #[tokio::test]
    async fn v2_manifests_file_should_have_1_at_least() {
        // Sign
        let signed_vl = test_sign_vl(
            2,
            test_data!("empty_file").to_string(),
            91,
            1365,
            get_timestamp_from_string("2026-09-05 22:56".to_owned()),
            None,
            KeyType::Secp256k1,
            Some(2),
            None,
        )
        .await;
        assert!(
            signed_vl.err().unwrap().to_string() == "No manifests found in the file"
        );
    }

    #[tokio::test]
    async fn should_load_v1_valid_generated_vl() {
        // Sign
        let signed_vl = test_sign_vl(
            1,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            365,
            None,
            None,
            KeyType::Secp256k1,
            Some(0),
            None,
        )
        .await
        .unwrap();
        // Decode
        let vl = decode_vl_v1(&signed_vl).unwrap();
        // Verify
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 1);
        assert!(verified_vl.blobs_v2.is_none());
        for validator in verified_vl.decoded_blob.clone().unwrap().validators {
            assert!(validator.decoded_manifest.unwrap().verification);
        }
        assert!(verified_vl.manifest.verification);
    }

    #[tokio::test]
    async fn should_load_v2_valid_vl() {
        let vl = load_vl("tests/data/vl_v2_2.json").await.unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 2);
        assert!(verified_vl.blobs_v2.clone().unwrap().len() == 2);
        assert!(verified_vl.blob.is_none());
        assert!(verified_vl.signature.is_none());
        for blob_v2 in verified_vl.decoded_blobs_v2.unwrap() {
            assert!(blob_v2.blob_verification.unwrap());
            for validator in blob_v2.decoded_blob.unwrap().validators {
                assert!(validator.decoded_manifest.unwrap().verification);
            }
        }
        assert!(verified_vl.manifest.verification);
    }

    #[tokio::test]
    async fn should_load_v2_valid_vl_from_scratch_secp256k1() {
        let signed_vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            365,
            get_timestamp_from_string("2025-09-05 23:56".to_owned()),
            None,
            KeyType::Secp256k1,
            None,
            None,
        )
        .await
        .unwrap();
        let vl = decode_vl_v2(&signed_vl).unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 2);
        assert!(verified_vl.blobs_v2.clone().unwrap().len() == 1);
        assert!(verified_vl.blob.is_none());
        assert!(verified_vl.signature.is_none());
        for blob_v2 in verified_vl.decoded_blobs_v2.unwrap() {
            assert!(blob_v2.blob_verification.unwrap());
            for validator in blob_v2.decoded_blob.unwrap().validators {
                assert!(validator.decoded_manifest.unwrap().verification);
            }
        }
        assert!(verified_vl.manifest.verification);
    }

    #[tokio::test]
    async fn should_load_v2_valid_vl_with_2_unl_secp256k1() {
        let signed_vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            1365,
            get_timestamp_from_string("2026-09-05 22:56".to_owned()),
            None,
            KeyType::Secp256k1,
            Some(2),
            None,
        )
        .await
        .unwrap();
        let vl = decode_vl_v2(&signed_vl).unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 2);
        assert!(verified_vl.blobs_v2.clone().unwrap().len() == 2);
        assert!(verified_vl.blob.is_none());
        assert!(verified_vl.signature.is_none());
        for blob_v2 in verified_vl.decoded_blobs_v2.unwrap() {
            assert!(blob_v2.blob_verification.unwrap());
            for validator in blob_v2.decoded_blob.unwrap().validators {
                assert!(validator.decoded_manifest.unwrap().verification);
            }
        }
        assert!(verified_vl.manifest.verification);
    }

    #[tokio::test]
    async fn should_ignore_empty_lines_and_load_v1_valid_generated_vl() {
        // Sign
        let signed_vl = test_sign_vl(
            1,
            test_data!("manifests_list_with_empty_lines.txt").to_string(),
            91,
            365,
            None,
            None,
            KeyType::Secp256k1,
            Some(0),
            None,
        )
        .await
        .unwrap();
        // Decode
        let vl = decode_vl_v1(&signed_vl).unwrap();
        // Verify
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 1);
        assert!(verified_vl.blobs_v2.is_none());
        for validator in verified_vl.decoded_blob.clone().unwrap().validators {
            assert!(validator.decoded_manifest.unwrap().verification);
        }
        assert!(verified_vl.manifest.verification);
    }

    #[tokio::test]
    async fn should_error_if_wrong_manifests_in_file() {
        // Sign
        let signed_vl = test_sign_vl(
            1,
            test_data!("manifests_list_with_errors.txt").to_string(),
            91,
            365,
            None,
            None,
            KeyType::Secp256k1,
            Some(0),
            None,
        )
        .await;
        assert!(signed_vl.is_err());
    }

    // VL wrong format

    #[tokio::test]
    async fn should_error_v1_invalid_format() {
        assert!(load_vl(test_data!("vl_v1_wrong_format.json"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn should_error_v2_invalid_format() {
        assert!(load_vl(test_data!("vl_v2_wrong_format.json"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn should_error_v1_invalid_master_manifest() {
        assert!(load_vl(test_data!("vl_v1_wrong_manifest_1.json"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn should_error_v1_invalid_validator_manifest() {
        assert!(load_vl(test_data!("vl_v1_wrong_manifest_2.json"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn should_error_v1_invalid_blob_format() {
        assert!(load_vl(test_data!("vl_v1_wrong_blob.json")).await.is_err());
    }

    #[tokio::test]
    async fn should_error_v2_invalid_master_manifest() {
        assert!(load_vl(test_data!("vl_v2_wrong_manifest_1.json"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn should_error_v2_invalid_validator_manifest() {
        assert!(load_vl(test_data!("vl_v2_wrong_manifest_2.json"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn should_error_v2_invalid_blob_format() {
        assert!(load_vl(test_data!("vl_v2_wrong_blob.json")).await.is_err());
    }

    // VL's that shouldn't verify (v1 and v2)

    #[tokio::test]
    async fn should_not_verify_master() {
        let vl = load_vl(test_data!("vl_v1_wrong_master_signature.json"))
            .await
            .unwrap();
        assert!(verify_vl(vl.clone()).is_err());
    }

    #[tokio::test]
    async fn should_not_verify_signing() {
        let vl = load_vl(test_data!("vl_v1_wrong_signing_signature.json"))
            .await
            .unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(!verified_vl.manifest.verification);
    }

    // Encode / Decode manifest
    #[tokio::test]
    async fn decode_valid_manifest() {
        let vl = load_vl(test_data!("vl.ripple.com.json")).await.unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.manifest.sequence == 1);
        assert!(
            verified_vl.manifest.master_public_key
                == "nHBe4vqSAzjpPRLKwSFzRFtmvzXaf5wPPmuVrQCAoJoS1zskgDA4"
        );
        assert!(
            verified_vl.manifest.signing_public_key
                == "nHUhPxhvYHHDsNrdnDEqJnkFHm1XcddQYH4RjLTNaVQJZSXXeNhU"
        );
        assert!(verified_vl.manifest.domain.is_none());
    }

    #[tokio::test]
    async fn encode_valid_manifest() {
        let file = test_data!("vl.ripple.com.json");
        let vl_json = get_vl(file).await.unwrap();
        let vl = load_vl(file).await.unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        let encoded_manifest = encode_manifest(
            verified_vl.manifest.sequence,
            verified_vl.manifest.master_public_key.clone(),
            verified_vl.manifest.signing_public_key.clone(),
            verified_vl.manifest.signature.clone(),
            verified_vl.manifest.master_signature.clone(),
            verified_vl.manifest.domain.clone(),
        )
        .unwrap();
        assert!(vl_json.manifest == encoded_manifest);
    }

    // The value is equal to the `master_public_key` in the publisher's manifest.
    #[tokio::test]
    async fn manifest_master_public_key_should_equal_public_key_v1() {
        let signed_vl = test_sign_vl(
            1,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            365,
            None,
            None,
            KeyType::Ed25519,
            None,
            None,
        )
        .await
        .unwrap();
        let vl = decode_vl_v1(&signed_vl).unwrap();
        assert!(
            base58_to_hex(&vl.manifest.master_public_key, Version::NodePublic)
                .unwrap()
                .to_uppercase()
                == vl.public_key
        );
    }

    #[tokio::test]
    async fn manifest_master_public_key_should_equal_public_key_v2() {
        let signed_vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            365,
            Some(get_valid_effective_timestamp(1000)),
            None,
            KeyType::Secp256k1,
            None,
            None,
        )
        .await
        .unwrap();
        let vl = decode_vl_v2(&signed_vl).unwrap();
        assert!(
            base58_to_hex(&vl.manifest.master_public_key, Version::NodePublic)
                .unwrap()
                .to_uppercase()
                == vl.public_key
        );
    }

    // Effective dates
    #[tokio::test]
    async fn v2_effective_date_should_be_greater_than_now() {
        let signed_vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            365,
            Some(get_valid_effective_timestamp(2000)),
            None,
            KeyType::Ed25519,
            None,
            None,
        )
        .await
        .unwrap();
        let vl = decode_vl_v2(&signed_vl).unwrap();
        assert!(
            vl.decoded_blobs_v2.clone().unwrap()[0]
                .decoded_blob
                .clone()
                .unwrap()
                .effective
                .unwrap()
                > get_ripple_now().unwrap()
        );
    }

    #[tokio::test]
    async fn v2_effective_date_cannot_be_repeated() {
        let signed_vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            365,
            Some(get_valid_effective_timestamp(2000)),
            None,
            KeyType::Secp256k1,
            None,
            None,
        )
        .await
        .unwrap();
        let vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            92,
            365,
            Some(get_valid_effective_timestamp(2000)),
            Some(signed_vl),
            KeyType::Ed25519,
            None,
            None,
        )
        .await;
        assert!(
            vl.err().unwrap().to_string() == "Exact same Effective date already present in the VL"
        );
    }

    // Sequence numbers

    #[tokio::test]
    async fn v2_sequence_number_should_not_be_equal_to_current() {
        let signed_vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            365,
            get_timestamp_from_string("2025-09-05 23:56".to_owned()),
            None,
            KeyType::Secp256k1,
            None,
            None,
        )
        .await
        .unwrap();
        let vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            1,
            get_timestamp_from_string("2024-01-05 23:56".to_owned()),
            Some(signed_vl),
            KeyType::Secp256k1,
            None,
            None,
        )
        .await;
        assert!(
            vl.err().unwrap().to_string() == "Sequence number must be greater than the current one"
        );
    }

    #[tokio::test]
    async fn v2_sequence_number_should_be_greater_than_current() {
        let signed_vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            365,
            get_timestamp_from_string("2025-09-05 23:56".to_owned()),
            None,
            KeyType::Secp256k1,
            None,
            None,
        )
        .await
        .unwrap();
        let vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            89,
            1,
            get_timestamp_from_string("2024-01-05 23:56".to_owned()),
            Some(signed_vl),
            KeyType::Secp256k1,
            None,
            None,
        )
        .await;
        assert!(
            vl.err().unwrap().to_string() == "Sequence number must be greater than the current one"
        );
    }

    #[tokio::test]
    async fn v1_manifest_signing_key_should_equal_secret_key() {
        let vl = test_sign_vl(
            1,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            1,
            get_timestamp_from_string("2025-09-05 23:56".to_owned()),
            None,
            KeyType::Secp256k1,
            None,
            Some("JAAAAApxIe3fL1Pf7Hk1j3vna8iErDEEjP9uKgDGKOrgbbd1CiR7EnMhA/ZWuPaVAZeJrY+N5ahIcs1m2GZWrBxzwLzKl3SAwUTzdkYwRAIgCHPeBlHQsT8BXeOx5oO2eU4kmYcuG/VRLe4GMcD8Y28CIBSVDXvxNb68biVHYEvj1b7fuU4MP4Kp+QK50NVO0vggcBJArtqH2rNsXmUuJd48pt+LsPZNt+KdzUaxc9r1ORxIgg9NWAu7J/F2K1B44nZC5fPhZgwhDcS3piNk2UzLiBNFDQ==".to_string())
        )
        .await;
        assert!(vl.is_err());
        assert!(
            vl.err().unwrap().to_string()
                == "Public key in the manifest does not match the public key in the secret"
        );
    }

    #[tokio::test]
    async fn v2_manifest_signing_key_should_equal_secret_key() {
        let vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            1,
            get_timestamp_from_string("2025-09-05 23:56".to_owned()),
            None,
            KeyType::Secp256k1,
            None,
            Some("JAAAAApxIe3fL1Pf7Hk1j3vna8iErDEEjP9uKgDGKOrgbbd1CiR7EnMhA/ZWuPaVAZeJrY+N5ahIcs1m2GZWrBxzwLzKl3SAwUTzdkYwRAIgCHPeBlHQsT8BXeOx5oO2eU4kmYcuG/VRLe4GMcD8Y28CIBSVDXvxNb68biVHYEvj1b7fuU4MP4Kp+QK50NVO0vggcBJArtqH2rNsXmUuJd48pt+LsPZNt+KdzUaxc9r1ORxIgg9NWAu7J/F2K1B44nZC5fPhZgwhDcS3piNk2UzLiBNFDQ==".to_string())
        )
        .await;
        assert!(vl.is_err());
        assert!(
            vl.err().unwrap().to_string()
                == "Public key in the manifest does not match the public key in the secret"
        );
    }

    // Expiration dates
    #[tokio::test]
    async fn v2_expiration_should_be_greater_than_effective() {
        let vl = test_sign_vl(
            2,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            1,
            get_timestamp_from_string("2025-09-05 23:56".to_owned()),
            None,
            KeyType::Secp256k1,
            None,
            None,
        )
        .await;
        let decoded_blob = decode_vl_v2(&vl.unwrap()).unwrap().decoded_blobs_v2.unwrap().get(0).unwrap().decoded_blob.clone().unwrap();
        assert_eq!(convert_to_human_time(convert_to_unix_time(decoded_blob.expiration)).unwrap(), "2025-09-06 23:56:00");
    }

    #[tokio::test]
    async fn v1_expiration_should_be_greater_than_now() {
        let vl = test_sign_vl(
            1,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            0,
            get_timestamp_from_string("2025-09-05 23:56".to_owned()),
            None,
            KeyType::Ed25519,
            None,
            None,
        )
        .await;
        assert!(vl.is_err());
    }

    #[tokio::test]
    async fn v2_expiration_should_be_greater_than_now() {
        let vl = test_sign_vl(
            1,
            test_data!("manifests_list_1.txt").to_string(),
            91,
            0,
            get_timestamp_from_string("2025-09-05 23:56".to_owned()),
            None,
            KeyType::Secp256k1,
            None,
            None,
        )
        .await;
        assert!(vl.is_err());
    }

    // If the manifest is not present in a blobs-v2 array entry, then the top-level manifest will be used when checking the signature.
    #[tokio::test]
    async fn should_load_v2_with_blob_v2_manifest() {
        // Sign
        let vl = get_vl(test_data!("vl_v2_1_with_blobv2_manifest.json"))
            .await
            .unwrap();
        // Decode
        let vl = decode_vl_v2(&vl).unwrap();
        assert!(verify_vl(vl.clone()).is_ok());
    }
}
