use anyhow::Result;
use ed25519::signature::SignerMut;
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use secp256k1::{
    ecdsa::Signature as Secp256k1Signature, Message, PublicKey as Secp256k1PublicKey, SecretKey
};
use std::str;
use std::str::FromStr;

use crate::util::sha512_first_half;
use crate::{
    structs::Ed25519Verifier,
    util::get_key_bytes,
};

pub fn sign(public_key_hex: &str, private_key_hex: &str, payload: &str) -> Result<String> {
    let is_ed25519 = public_key_hex.starts_with("ED");
    let private_key_bytes: [u8; 32] = hex::decode(private_key_hex)
            .expect("Could not decode from hex")
            .try_into()
            .expect("Private key should be 32 bytes long");
    let payload_bytes = payload.as_bytes();
    if is_ed25519 {
        let mut signing_key = Ed25519SigningKey::from_bytes(&private_key_bytes);
        Ok(signing_key.sign(payload_bytes).to_string())
    } else {
        let message_hash = sha512_first_half(payload_bytes)?;
        let msg = Message::from_digest_slice(message_hash.as_ref()).unwrap();
        let private_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let signature = private_key.sign_ecdsa(msg).to_string().to_uppercase();
        Ok(signature)
    }
}

pub fn verify_signature(public_key_hex: &str, payload_bytes: &[u8], signature: &str) -> Result<bool> {
    let is_ed25519 = public_key_hex.starts_with("ED");
    let mut public_key_bytes = get_key_bytes(public_key_hex).expect("Could not get bytes");
    if is_ed25519 {
        public_key_bytes.remove(0);
        let public_key:[u8; PUBLIC_KEY_LENGTH]= public_key_bytes.try_into().expect("Could not parse ed25519 public key"); 
        let signature_bytes: [u8; SIGNATURE_LENGTH] = hex::decode(signature)?.try_into().expect("Could not parse signature");
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&public_key).expect("Invalid ED25519 Public Key");
        let signature = Ed25519Signature::from_bytes(&signature_bytes);
        let verifier = Ed25519Verifier { verifying_key };
        Ok(verifier.verify(payload_bytes, &signature).is_ok())
    } else {
        let public_key = Secp256k1PublicKey::from_slice(&public_key_bytes).expect("Invalid Secp256k1 Public Key");
        let message_hash = sha512_first_half(payload_bytes)?;
        let msg = Message::from_digest_slice(message_hash.as_ref()).unwrap();
        let sig = Secp256k1Signature::from_str(signature).expect("Invalid Secp256k1 Signature");
        Ok(sig.verify(&msg, &public_key).is_ok())
    }
}