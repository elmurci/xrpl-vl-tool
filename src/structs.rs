use ed25519_dalek::{Signer, Verifier};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Unl {
    pub public_key: String,
    pub manifest: String,
    pub decoded_manifest: Option<DecodedManifest>,
    pub blob: String,
    pub decoded_blob: Option<DecodedBlob>,
    pub signature: String,
    pub version: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecodedBlob {
    pub sequence: u32,
    pub expiration: u32,
    pub validators: Vec<Validator>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    pub validation_public_key: String,
    pub manifest: String,
    pub decoded_manifest: Option<DecodedManifest>,
}

// TODO
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

pub struct Ed25519Signer<S>
where
    S: Signer<ed25519::Signature>
{
    pub signing_key: S
}

impl<S> Ed25519Signer<S>
where
    S: Signer<ed25519::Signature>
{
    pub fn sign(&self, str: &str) -> ed25519::Signature {
        self.signing_key.sign(str.as_bytes())
    }
}

pub struct Ed25519Verifier<V> {
    pub verifying_key: V
}

impl<V> Ed25519Verifier<V>
where
    V: Verifier<ed25519::Signature>
{
    pub fn verify(
        &self,
        payload: &Vec<u8>,
        signature: &ed25519::Signature
    ) -> Result<(), ed25519::Error> {
        self.verifying_key.verify(payload, signature)
    }
}