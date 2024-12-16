// Tests
// Version 1 and 2
// VL's that should verify
// VL's that shouldn't
// Effective dates
// Expiration dates
// Optional signatures (!!!)

macro_rules! test_data {($fname:expr) => (
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $fname) // assumes Linux ('/')!
  )}

mod test {
    use xrpl_vl_tool::vl::load_vl;

    #[tokio::test]
    async fn should_load_v1_valid_vl() {
        let vl = load_vl(test_data!("generated_unl_v1_1.json")).await.unwrap();
        println!("DecodedVL: {:?}", vl);
        assert!(vl.version == 1);
        assert!(vl.blobs_v2.is_none());
        assert!(vl.manifest_verification.unwrap() == true);
    }

    #[tokio::test]
    async fn should_load_v2_valid_vl_with_1_unl() {
        let vl = load_vl(test_data!("generated_unl_v2_1.json")).await.unwrap();
        assert!(vl.version == 2);
        assert!(vl.blobs_v2.unwrap().len() == 1);
        assert!(vl.blob.is_none());
        assert!(vl.manifest_verification.unwrap() == true);
    }

    #[tokio::test]
    async fn should_load_v2_valid_vl_with_2_unl() {
        let vl = load_vl(test_data!("generated_unl_v2_2.json")).await.unwrap();
        assert!(vl.version == 2);
        assert!(vl.blobs_v2.unwrap().len() == 2);
        assert!(vl.blob.is_none());
        assert!(vl.manifest_verification.unwrap() == true);
    }
}