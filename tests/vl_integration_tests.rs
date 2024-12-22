

macro_rules! test_data {($fname:expr) => (
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $fname) // assumes Linux ('/')!
)}


mod test {
    use std::fs;
    use anyhow::Result;
    use chrono::Utc;
    use xrpl_vl_tool::{enums::{SecretProvider, Version}, manifest::encode_manifest, structs::Vl, time::convert_to_ripple_time, util::base58_to_hex, vl::{decode_vl_v1, decode_vl_v2, get_vl, load_vl, sign_vl, verify_vl}};

    fn get_manifest() -> String {
        fs::read_to_string(test_data!("manifest"))
        .expect("Should have been able to read the file")
    }

    fn get_ripple_now() -> i64 {
        convert_to_ripple_time(Some(
            (Utc::now()).timestamp(),
        ))
    }

    async fn test_sign_vl(version: u8, manifests_list: String, sequence: u32, expiration: u16, effective: Option<String>, v2_vl_file: Option<String>) -> Result<Vl> {
        sign_vl(
            version,
            get_manifest(),
            manifests_list,
            sequence,
            expiration,
            SecretProvider::Local,
            test_data!("local_keys.json").to_string(),
            effective,
            v2_vl_file,
        ).await
    }

    // VL's that should verify (v1 and v2)

    #[tokio::test]
    async fn should_load_v1_valid_public_vl() {
        let vl = load_vl("https://vl.ripple.com").await.unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 1);
        assert!(verified_vl.blobs_v2.is_none());
        for validator in verified_vl.decoded_blob.clone().unwrap().validators {
            assert!(validator.decoded_manifest.unwrap().verification == true);
        }
        assert!(verified_vl.manifest.verification == true);
    }

    #[tokio::test]
    async fn should_load_v1_valid_generated_vl() {
        // Sign
        let signed_vl = test_sign_vl(1, test_data!("manifests_list_1.txt").to_string(), 91, 365, None, None).await.unwrap();
        // Decode
        let vl = decode_vl_v1(&signed_vl).unwrap();
        // Verify
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 1);
        assert!(verified_vl.blobs_v2.is_none());
        for validator in verified_vl.decoded_blob.clone().unwrap().validators {
            assert!(validator.decoded_manifest.unwrap().verification == true);
        }
        assert!(verified_vl.manifest.verification == true);
    }

    #[tokio::test]
    async fn should_load_v2_valid_vl_with_1_unl() {
        let signed_vl = test_sign_vl(2, test_data!("manifests_list_1.txt").to_string(), 91, 365, Some("2025-09-05 23:56".to_owned()), None).await.unwrap();
        let vl = decode_vl_v2(&signed_vl).unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 2);
        assert!(verified_vl.blobs_v2.clone().unwrap().len() == 1);
        assert!(verified_vl.blob.is_none());
        assert!(verified_vl.signature.is_none());
        for blob_v2 in verified_vl.decoded_blobs_v2.unwrap() {
            assert!(blob_v2.blob_verification.unwrap() == true);
            for validator in blob_v2.decoded_blob.unwrap().validators {
                assert!(validator.decoded_manifest.unwrap().verification == true);
            }
        }
         assert!(verified_vl.manifest.verification == true);
    }

    #[tokio::test]
    async fn should_load_v2_valid_vl_with_2_unl() {
        let signed_vl = test_sign_vl(2, test_data!("manifests_list_1.txt").to_string(), 91, 365, Some("2025-09-05 22:56".to_owned()), Some(test_data!("vl_v2_1.json").to_owned())).await.unwrap();
        let vl = decode_vl_v2(&signed_vl).unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.version == 2);
        assert!(verified_vl.blobs_v2.clone().unwrap().len() == 2);
        assert!(verified_vl.blob.is_none());
        assert!(verified_vl.signature.is_none());
        for blob_v2 in verified_vl.decoded_blobs_v2.unwrap() {
            assert!(blob_v2.blob_verification.unwrap() == true);
            for validator in blob_v2.decoded_blob.unwrap().validators {
                assert!(validator.decoded_manifest.unwrap().verification == true);
            }
        }
        assert!(verified_vl.manifest.verification == true);
    }

    // // VL wrong format

    #[tokio::test]
    async fn should_error_v1_invalid_format() {
        assert!(load_vl(test_data!("vl_v1_wrong_format.json")).await.is_err() == true);
    }

    #[tokio::test]
    async fn should_error_v2_invalid_format() {
        assert!(load_vl(test_data!("vl_v2_wrong_format.json")).await.is_err() == true);
    }

    #[tokio::test]
    async fn should_error_v1_invalid_master_manifest() {
        assert!(load_vl(test_data!("vl_v1_wrong_manifest_1.json")).await.is_err() == true);
    }

    #[tokio::test]
    async fn should_error_v1_invalid_validator_manifest() {
        assert!(load_vl(test_data!("vl_v1_wrong_manifest_2.json")).await.is_err() == true);
    }

    #[tokio::test]
    async fn should_error_v1_invalid_blob_format() {
        assert!(load_vl(test_data!("vl_v1_wrong_blob.json")).await.is_err() == true);
    }

    #[tokio::test]
    async fn should_error_v2_invalid_master_manifest() {
        assert!(load_vl(test_data!("vl_v2_wrong_manifest_1.json")).await.is_err() == true);
    }

    #[tokio::test]
    async fn should_error_v2_invalid_validator_manifest() {
        assert!(load_vl(test_data!("vl_v2_wrong_manifest_2.json")).await.is_err() == true);
    }

    #[tokio::test]
    async fn should_error_v2_invalid_blob_format() {
        assert!(load_vl(test_data!("vl_v2_wrong_blob.json")).await.is_err() == true);
    }

    // VL's that shouldn't verify (v1 and v2)

    #[tokio::test]
    async fn should_not_verify_master() {
        let vl = load_vl(test_data!("vl_v1_wrong_master_signature.json")).await.unwrap();
        assert!(verify_vl(vl.clone()).is_err());
    }

    #[tokio::test]
    async fn should_not_verify_signing() {
        let vl = load_vl(test_data!("vl_v1_wrong_signing_signature.json")).await.unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.manifest.verification == false);
    }

    // Encode / Decode manifest
    #[tokio::test]
    async fn decode_valid_manifest() {
        let vl = load_vl(test_data!("vl.ripple.com.json")).await.unwrap();
        let verified_vl = verify_vl(vl.clone()).unwrap();
        assert!(verified_vl.manifest.sequence == 1);
        assert!(verified_vl.manifest.master_public_key == "nHBe4vqSAzjpPRLKwSFzRFtmvzXaf5wPPmuVrQCAoJoS1zskgDA4");
        assert!(verified_vl.manifest.signing_public_key == "nHUhPxhvYHHDsNrdnDEqJnkFHm1XcddQYH4RjLTNaVQJZSXXeNhU");
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
            verified_vl.manifest.domain.clone()
        ).unwrap();
        assert!(vl_json.manifest == encoded_manifest);
    }

    // The value is equal to the `master_public_key` in the publisher's manifest.
    #[tokio::test]
    async fn manifest_master_public_key_should_equal_public_key_v1() {
        let signed_vl = test_sign_vl(1, test_data!("manifests_list_1.txt").to_string(), 91, 365, None, None).await.unwrap();
        let vl = decode_vl_v1(&signed_vl).unwrap();
        assert!(base58_to_hex(&vl.manifest.master_public_key, Version::NodePublic).to_uppercase() == vl.public_key);
    }

    #[tokio::test]
    async fn manifest_master_public_key_should_equal_public_key_v2() {
        let signed_vl = test_sign_vl(2, test_data!("manifests_list_1.txt").to_string(), 91, 365, Some("2025-09-05 23:56".to_owned()), None).await.unwrap();
        let vl = decode_vl_v2(&signed_vl).unwrap();
        assert!(base58_to_hex(&vl.manifest.master_public_key, Version::NodePublic).to_uppercase() == vl.public_key);
    }

    // Effective dates
    #[tokio::test]
    async fn v2_effective_date_should_be_greater_than_now() {
        let signed_vl = test_sign_vl(2, test_data!("manifests_list_1.txt").to_string(), 91, 365, Some("2025-09-05 23:56".to_owned()), None).await.unwrap();
        let vl = decode_vl_v2(&signed_vl).unwrap();
        assert!(vl.decoded_blobs_v2.clone().unwrap()[0].decoded_blob.clone().unwrap().effective.unwrap() > get_ripple_now());
    }

    #[tokio::test]
    async fn v2_effective_date_cannot_be_repeated() {
        assert!(test_sign_vl(2, test_data!("manifests_list_1.txt").to_string(), 91, 365, Some("2025-09-05 23:56".to_owned()), Some(test_data!("vl_v2_1.json").to_owned())).await.is_err());
    }

    // Expiration dates
    #[tokio::test]
    async fn v2_expiration_should_be_greater_than_effective() {
        let vl = test_sign_vl(2, test_data!("manifests_list_1.txt").to_string(), 91, 1, Some("2025-09-05 23:56".to_owned()), None).await;
        assert!(vl.is_err());
    }

    #[tokio::test]
    async fn v1_expiration_should_be_greater_than_now() {
        let vl = test_sign_vl(1, test_data!("manifests_list_1.txt").to_string(), 91, 0, Some("2025-09-05 23:56".to_owned()), None).await;
        assert!(vl.is_err());
    }

    #[tokio::test]
    async fn v2_expiration_should_be_greater_than_now() {
        let vl = test_sign_vl(1, test_data!("manifests_list_1.txt").to_string(), 91, 0, Some("2025-09-05 23:56".to_owned()), None).await;
        assert!(vl.is_err());
    }

    // If the manifest is not present in a blobs-v2 array entry, then the top-level manifest will be used when checking the signature. 
    #[tokio::test]
    async fn should_load_v2_with_blob_v2_manifest() {
        // Sign
        let vl = get_vl(test_data!("vl_v2_1_with_blobv2_manifest.json")).await.unwrap();
        // Decode
        let vl = decode_vl_v2(&vl).unwrap();
        assert!(verify_vl(vl.clone()).is_ok());
    }

}