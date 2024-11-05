use clap::Parser;
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};

use crate::enums::Commands;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Unl {
    pub public_key: String,
    pub manifest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_manifest: Option<DecodedManifest>,
    pub blob: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_blob: Option<DecodedBlob>,
    pub signature: String,
    pub version: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecodedBlob {
    pub sequence: u32,
    pub expiration: i64,
    pub validators: Vec<Validator>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    pub validation_public_key: String,
    pub manifest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_manifest: Option<DecodedManifest>,
}

impl Default for Unl {
    fn default() -> Unl {
        Unl {
            public_key: "".to_string(),
            manifest: "".to_string(),
            decoded_manifest: None,
            blob: "".to_string(),
            decoded_blob: None,
            signature: "".to_string(),
            version: 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DecodedManifest {
    pub sequence: u32,
    pub master_public_key: String,
    pub signature: String,
    pub signing_public_key: String,
    pub master_signature: String,
    pub domain: Option<String>,
}

impl Default for DecodedManifest {
    fn default() -> DecodedManifest {
        DecodedManifest {
            sequence: 0,
            master_public_key: String::from(""),
            signature: String::from(""),
            signing_public_key: String::from(""),
            master_signature: String::from(""),
            domain: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AwsSecret {
    pub public_key: String,
    pub private_key: String,
}

pub struct Ed25519Signer<S>
where
    S: Signer<ed25519::Signature>,
{
    pub signing_key: S,
}

impl<S> Ed25519Signer<S>
where
    S: Signer<ed25519::Signature>,
{
    pub fn sign(&self, str: &str) -> ed25519::Signature {
        self.signing_key.sign(str.as_bytes())
    }
}

pub struct Ed25519Verifier<V> {
    pub verifying_key: V,
}

impl<V> Ed25519Verifier<V>
where
    V: Verifier<ed25519::Signature>,
{
    pub fn verify(
        &self,
        payload: &Vec<u8>,
        signature: &ed25519::Signature,
    ) -> Result<(), ed25519::Error> {
        self.verifying_key.verify(payload, signature)
    }
}
