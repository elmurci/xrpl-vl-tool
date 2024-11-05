use ed25519::signature::SignerMut;
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use secp256k1::{
    ecdsa::Signature as Secp256k1Signature, Message, PublicKey as Secp256k1PublicKey, Secp256k1,
};
use std::str::FromStr;

use crate::{
    structs::Ed25519Verifier,
    util::{get_key_bytes, sha512_first_half},
};

pub fn sign(public_key_hex: &str, private_key_hex: &str, payload: &str) -> String {
    let is_ed25519 = public_key_hex.starts_with("ED");
    if is_ed25519 {
        let private_key_bytes: [u8; 32] = hex::decode(private_key_hex)
            .expect("Could not decode from hex")
            .try_into()
            .expect("Could not convert to ed25519 key");
        let mut signing_key = Ed25519SigningKey::from_bytes(&private_key_bytes);
        signing_key.sign(payload.as_bytes()).to_string()
    } else {
        // let secp = Secp256k1::new();
        // let secret_key = Secp256k1SecretKey::from_str(private_key_hex).expect("Invalid Secp256k1 Secret Key");
        // let message = Message::from_digest(sha512_first_half(payload.as_bytes().unwrap().try_into().unwrap())?);
        // let signature = secp.sign(&message, &secret_key);
        // signature.to_string()
        todo!()
    }
}

pub fn verify_signature(public_key_hex: &str, payload: &[u8], signature: &str) -> bool {
    let is_ed25519 = public_key_hex.starts_with("ED");
    let public_key_bytes = get_key_bytes(public_key_hex).expect("Could not get bytes");
    if is_ed25519 {
        let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key_bytes[1..33]
            .try_into()
            .expect("Could not parse Public Key");
        let signature_bytes: [u8; SIGNATURE_LENGTH] = hex::decode(signature)
            .expect("Could not decode Signature from Hex format")
            .try_into()
            .expect("Could not parse Signature");
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&public_key_bytes).expect("Invalid ED25519 Public Key");
        let signature = Ed25519Signature::from_bytes(&signature_bytes);
        let verifier = Ed25519Verifier { verifying_key };
        verifier.verify(payload, &signature).is_ok()
    } else {
        let secp = Secp256k1::new();
        let signature =
            Secp256k1Signature::from_str(signature).expect("Invalid Secp256k1 Signature");
        let digest = sha512_first_half(payload);
        let p: [u8; 32] = digest.unwrap().try_into().unwrap();
        let message = Message::from_digest(p);
        let public_key = Secp256k1PublicKey::from_slice(&public_key_bytes)
            .expect("Invalid Secp256k1 Public Key");
        secp.verify_ecdsa(&message, &signature, &public_key).is_ok()
    }
}
