use clap::Subcommand;
use anyhow::{anyhow, Result};

#[derive(Subcommand)]
pub enum Commands {
    /// Loads and verifies a given Validation List. It accepts a file path or a url. Example: `./xrpl-unl-tool load {url_or_file_path}`
    Load { arg: Option<String> },
    /// Compares two Validation Lists. Example: `./xrpl-unl-tool compare {url_or_file_path_1} {url_or_file_path_2}`
    Compare { arg: Option<Vec<String>> },
    /// Prodces and signs a Validation List (connects to AWS to retrieve the keypair). Example: `./xrpl-unl-tool sign {publisher_manifest} {manifests_file} {sequence} {expiration_in_days} {aws_secret_name}`
    Sign { arg: Option<Vec<String>> },
}

#[derive(Debug)]
pub enum SecretProvider {
    Aws,
    Vault,
}

impl SecretProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretProvider::Aws => "aws",
            SecretProvider::Vault => "vault"
        }
    }
    pub fn from_str(input: &str) -> Result<SecretProvider> {
        match input {
            "aws"  => Ok(SecretProvider::Aws),
            "vault"  => Ok(SecretProvider::Vault),
            _      => Err(anyhow!("Could not parse secret provider value")),
        }
    }
}

#[derive(Debug)]
pub enum Version {
    // None,
    NodePublic,
    // NodePrivate,
    // AccountID,
    // AccountPublic,
    // AccountSecret,
    // // FamilyGenerator,
    // FamilySeed,
}

impl Version {
    pub fn value(&self) -> u8 {
        match *self {
            Version::NodePublic => 28,
            // Version::NodePrivate => 32,
            // Version::AccountID => 0,
            // Version::AccountPublic => 35,
            // Version::AccountSecret => 34,
            // Version::FamilySeed => 33,
        }
    }
}
