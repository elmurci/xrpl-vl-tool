use core::fmt;

#[derive(Debug)]
pub enum DecodeManifestError {
    Base64Error(String),
    NextFieldError(String),
    InvalidFieldLength(String),
    Utf8Error(String),
    Other(String),
}

impl fmt::Display for DecodeManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeManifestError::*;
        match self {
            Base64Error(msg) => write!(f, "Base64 error: {}", msg),
            NextFieldError(msg) => write!(f, "Failed to decode next field: {}", msg),
            InvalidFieldLength(msg) => write!(f, "Invalid field length: {}", msg),
            Utf8Error(msg) => write!(f, "UTF-8 error: {}", msg),
            Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

// This allows it to be used as a standard error in `Result<..., DecodeManifestError>`.
impl std::error::Error for DecodeManifestError {}