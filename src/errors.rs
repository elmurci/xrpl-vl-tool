use thiserror::Error;

#[derive(Error, Debug)]
pub enum VlValidationError {
    #[error("Effective date must be before expiration date")]
    EffectiveDateBeforeExpiration,
    #[error("Exact same Effective date already present in the VL")]
    EffectiveDateAlreadyPresent,
    #[error("Sequence number must be greater than the current one")]
    InvalidSequence,
    #[error("Malformed validators list")]
    MalformedVl,
    #[error("VL has gaps")]
    HasGaps,
}

#[derive(Error, Debug)]
pub enum DecodeManifestError {
    #[error("Could not decode the Base64 manifest")]
    Base64Error,
    #[error("Could not get next field decoding the manifest")]
    NextFieldError,
    #[error("Invalid field lentgh decoding the manifest")]
    InvalidFieldLength,
    #[error("UTF-8 decoding error")]
    Utf8Error,
    #[error("Invalid `manifest_field_type` length; expected 1 or 2 bytes")]
    InvalidManifestType,
    #[error("Couldn't parse ManifestField")]
    InvalidManifestValue,
}
