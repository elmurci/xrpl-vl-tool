use assert_cmd::Command;
use predicates::str::contains;

const BIN_NAME: &str = "xrpl_vl_tool";

#[test]
fn test_cli_load_v1() {
    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("load").arg("tests/data/vl.ripple.com.json");

    cmd.assert().success().stdout(contains(
        "There are 35 validators in this VL. Sequence is: 80 | Blob Signature: ✓ | Manifest Signature: ✓ | Expires: 2025-10-31 00:00:00 | Version: 1 ",
    ));
}

#[test]
fn test_cli_load_v2() {
    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("load").arg("tests/data/vl_v2_1.json");

    cmd.assert().success().stdout(contains(
        "There are 1 UNL's in this Validators List | Version 2 | Manifest Signature: ✓",
    ));

    cmd.assert().success().stdout(contains(
        "1) There are 35 validators in this VL. Sequence is: 81 | Blob Signature: ✓ | Effective from: 2025-09-05 23:56:00 | Expires: 2025-12-22 11:23:05",
    ));
}

#[test]
fn test_cli_decode_manifest() {
    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("decode-manifest").arg("JAAAAAFxIe0md6v/0bM6xvvDBitx8eg5fBUF4cQsZNEa0bKP9z9HNHMh7V0AnEi5D4odY9X2sx+cY8B3OHNjJvMhARRPtTHmWnAhdkDFcg53dAQS1WDMQDLIs2wwwHpScrUnjp1iZwwTXVXXsaRxLztycioto3JgImGdukXubbrjeqCNU02f7Y/+6w0BcBJA3M0EOU+39hmB8vwfgernXZIDQ1+o0dnuXjX73oDLgsacwXzLBVOdBpSAsJwYD+nW8YaSacOHEsWaPlof05EsAg==");

    cmd.assert().success().stdout(contains("Sequence: 1"));
    cmd.assert().success().stdout(contains(
        "Master Public Key: nHBe4vqSAzjpPRLKwSFzRFtmvzXaf5wPPmuVrQCAoJoS1zskgDA4",
    ));
    cmd.assert().success().stdout(contains(
        "Signing Public Key: nHUhPxhvYHHDsNrdnDEqJnkFHm1XcddQYH4RjLTNaVQJZSXXeNhU",
    ));
    cmd.assert().success().stdout(contains(
        "Signature: C5720E77740412D560CC4032C8B36C30C07A5272B5278E9D62670C135D55D7B1A4712F3B72722A2DA3726022619DBA45EE6DBAE37AA08D534D9FED8FFEEB0D01",
    ));
    cmd.assert().success().stdout(contains(
        "Master Signature: DCCD04394FB7F61981F2FC1F81EAE75D9203435FA8D1D9EE5E35FBDE80CB82C69CC17CCB05539D069480B09C180FE9D6F1869269C38712C59A3E5A1FD3912C02",
    ));
    cmd.assert().success().stdout(contains("Domain: None"));
}

#[test]
fn test_cli_encode_manifest_no_args() {
    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("encode-manifest");

    cmd.assert().failure();
}

#[test]
fn test_cli_encode_manifest_missing_args() {
    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("encode-manifest").arg("--sequence").arg("1");

    let expected = r#"error: the following required arguments were not provided:
  --master-public-key <MASTER_PUBLIC_KEY>
  --signing-public-key <SIGNING_PUBLIC_KEY>
  --signature <SIGNATURE>
  --master-signature <MASTER_SIGNATURE>"#;

    cmd.assert()
        .failure()
        .stderr(predicates::str::contains(expected));

    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    let expected = r#"error: the following required arguments were not provided:
  --signing-public-key <SIGNING_PUBLIC_KEY>
  --signature <SIGNATURE>
  --master-signature <MASTER_SIGNATURE>"#;

    cmd.arg("encode-manifest")
        .arg("--sequence")
        .arg("1")
        .arg("--master-public-key")
        .arg("SOME_KEY");

    cmd.assert()
        .failure()
        .stderr(predicates::str::contains(expected));

    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    let expected = r#"error: the following required arguments were not provided:
  --signing-public-key <SIGNING_PUBLIC_KEY>
  --signature <SIGNATURE>"#;

    cmd.arg("encode-manifest")
        .arg("--sequence")
        .arg("1")
        .arg("--master-public-key")
        .arg("SOME_KEY")
        .arg("--master-signature")
        .arg("SOME_SIG");

    cmd.assert()
        .failure()
        .stderr(predicates::str::contains(expected));
}

#[test]
fn test_cli_encode_manifest_invalid_value_args() {
    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("encode-manifest").arg("--sequence").arg("a");

    cmd.assert().failure();
}

#[test]
fn test_cli_sign_missing_value_args() {
    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("sign").arg("--vl-version").arg("2");

    let expected = r#"error: the following required arguments were not provided:
  --publisher-manifest <PUBLISHER_MANIFEST>
  --manifests-file <MANIFESTS_FILE>
  --sequence <SEQUENCE>
  --expiration <EXPIRATION_IN_DAYS>
  --secret-provider <SECRET_PROVIDER>
  --secret-name <SECRET_NAME>
  --effective-date-day <EFFECTIVE_DATE_DAY>
  --effective-date-time <EFFECTIVE_DATE_TIME>"#;

    cmd.assert()
        .failure()
        .stderr(predicates::str::contains(expected));

    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("sign")
        .arg("--vl-version")
        .arg("1")
        .arg("--publisher-manifest")
        .arg("some_manifest")
        .arg("--manifests-file")
        .arg("some_path_to_file")
        .arg("--sequence")
        .arg("100")
        .arg("--secret-provider")
        .arg("aws")
        .arg("--secret-name")
        .arg("the_name");

    let expected = r#"error: the following required arguments were not provided:
  --expiration <EXPIRATION_IN_DAYS>"#;

    cmd.assert()
        .failure()
        .stderr(predicates::str::contains(expected));

    let mut cmd = Command::cargo_bin(BIN_NAME).unwrap();

    cmd.arg("sign")
        .arg("--vl-version")
        .arg("2")
        .arg("--publisher-manifest")
        .arg("some_manifest")
        .arg("--manifests-file")
        .arg("some_path_to_file")
        .arg("--sequence")
        .arg("100")
        .arg("--expiration")
        .arg("365")
        .arg("--secret-provider")
        .arg("AWS")
        .arg("--secret-name")
        .arg("the_name");

    let expected = r#"error: the following required arguments were not provided:
  --effective-date-day <EFFECTIVE_DATE_DAY>
  --effective-date-time <EFFECTIVE_DATE_TIME>"#;

    cmd.assert()
        .failure()
        .stderr(predicates::str::contains(expected));
}
