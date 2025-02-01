use anyhow::{Context, Result};
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, SECRET_KEY_LENGTH,
    Signer, Verifier,
};
use secp256k1::{Keypair, Secp256k1};
use secp256k1::{
    ecdsa::Signature as Secp256k1Signature, Message, PublicKey as Secp256k1PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use std::str;
use std::str::FromStr;

use crate::secret::KeyType;
use crate::util::get_key_bytes;
use crate::util::sha512_first_half;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyPair {
    pub public_key_bytes: Vec<u8>, // 32 or 33 bytes
    pub private_key_bytes: [u8; SECRET_KEY_LENGTH], // 32 bytes
}

impl<V> Ed25519Verifier<V>
where
    V: Verifier<ed25519::Signature>,
{
    pub fn verify(
        &self,
        payload: &[u8],
        signature: &ed25519::Signature,
    ) -> Result<(), ed25519::Error> {
        self.verifying_key.verify(payload, signature)
    }
}

pub fn get_keypair_bytes_from_private_key_hex(private_key_hex: &str, secret_type: KeyType) -> Result<KeyPair> {
    let private_key_bytes: [u8; 32] = hex::decode(private_key_hex)
        .context("Could not decode from hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Private key should be 32 bytes long"))?;
    let keypair = match secret_type {
        KeyType::Secp256k1 => {
            let secp = Secp256k1::new();
            let secret_key = SecretKey::from_slice(&private_key_bytes).expect("32 bytes, within curve order");
            let keypair = Keypair::from_secret_key(&secp, &secret_key);
            KeyPair {
                public_key_bytes: keypair.public_key().serialize().into(),
                private_key_bytes: keypair.secret_bytes(),
            }
        }
        KeyType::Ed25519 => {
            let signing_key = Ed25519SigningKey::from_bytes(&private_key_bytes);
            let key_pair = signing_key.to_keypair_bytes();
            let (private_key, public_key) = key_pair.split_at(32);
            let private_key_bytes = <[u8; 32]>::try_from(private_key).unwrap();
            let public_key_bytes = <[u8; 32]>::try_from(public_key).unwrap();
            KeyPair {
                public_key_bytes: public_key_bytes.into(),
                private_key_bytes,
            }

        }
    };
    Ok(keypair)

}

pub fn sign(public_key_hex: &str, private_key_hex: &str, payload_bytes: &[u8]) -> Result<String> {
    let is_ed25519 = public_key_hex.starts_with("ED");
    let private_key_bytes: [u8; 32] = hex::decode(private_key_hex)
        .context("Could not decode from hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Private key should be 32 bytes long"))?;
    if is_ed25519 {
        let signing_key = Ed25519SigningKey::from_bytes(&private_key_bytes);
        Ok(signing_key.sign(payload_bytes).to_string())
    } else {
        let message_hash = sha512_first_half(payload_bytes)?;
        let msg = Message::from_digest_slice(message_hash.as_ref()).context("Could not get Message Hash")?;
        let private_key = SecretKey::from_slice(&private_key_bytes).context("Could not get Private Key Bytes")?;
        let signature = private_key.sign_ecdsa(msg).to_string().to_uppercase();
        Ok(signature)
    }
}

pub fn verify_signature(
    public_key_hex: &str,
    payload_bytes: &[u8],
    signature: &str,
) -> Result<bool> {
    let is_ed25519 = public_key_hex.starts_with("ED");
    let public_key_bytes = get_key_bytes(public_key_hex).context("Could not get bytes")?;
    if is_ed25519 {
        let public_key: [u8; PUBLIC_KEY_LENGTH] = public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Could not parse ed25519 public key"))?;
        let signature_bytes: [u8; SIGNATURE_LENGTH] = hex::decode(signature)
            .map_err(|e| anyhow::anyhow!("Could not decode signature: {}", e))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Could not parse signature"))?;
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&public_key).context("Invalid ED25519 Public Key")?;
        let signature = Ed25519Signature::from_bytes(&signature_bytes);
        let verifier = Ed25519Verifier { verifying_key };
        Ok(verifier.verify(payload_bytes, &signature).is_ok())
    } else {
        let public_key = Secp256k1PublicKey::from_slice(&public_key_bytes)
            .context("Invalid Secp256k1 Public Key")?;
        let message_hash = sha512_first_half(payload_bytes)?;
        let msg = Message::from_digest_slice(message_hash.as_ref())?;
        let sig = Secp256k1Signature::from_str(signature).context("Invalid Secp256k1 Signature")?;
        Ok(sig.verify(&msg, &public_key).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    #[tokio::test]
    async fn test_sign_and_verify_ed25519() {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let message = "Hello, world".as_bytes();
        let public_key_hex = format!("ED{}", hex::encode(signing_key.verifying_key().to_bytes()));
        let private_key_hex = hex::encode(signing_key.to_bytes());
        let signed_message = sign(&public_key_hex, &private_key_hex, message).unwrap();
        assert!(verify_signature(&public_key_hex, message, &signed_message).unwrap());
    }

    #[tokio::test]
    async fn test_sign_and_verify_secp256k1() {
        let secp = Secp256k1::new();
        let message = "Hello, world".as_bytes();
        let (private_key, public_key) = secp.generate_keypair(&mut OsRng);
        let private_key_hex = hex::encode(private_key.secret_bytes());
        let signed_message = sign(&public_key.to_string(), &private_key_hex, message).unwrap();
        assert!(verify_signature(&public_key.to_string(), message, &signed_message).unwrap());
    }
}
