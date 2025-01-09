use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Loads and verifies a given Validation List. It accepts a file path or a url. Example: `./xrpl_vl_tool load {url_or_file_path}`
    Load { url_or_file: String },
    /// Produces and signs a Validation List
    Sign {
        /// The version of the Validation List (1 or 2)
        vl_version: u8,
        /// The publisher manifest
        publisher_manifest: String,
        /// Path to the file that holds the list of manifests, one per line
        manifests_file: String,
        /// The sequence number of the Validation List
        sequence: u32,
        /// The expiration in days of the Validation List
        expiration_in_days: u16,
        /// The secret provider to use: aws, vault or local. For local secret, this value should be the path to the file that holds the secret
        secret_provider: String,
        /// The secret id to use
        secret_name: String,
        /// The effective day (YYYY/MM/DD) for the Validation List (only for version 2)
        #[arg(required_if_eq("version", "2"))]
        effective_date_day: String,
        /// The effective time (HH:MM) for the Validation List (only for version 2)
        #[arg(required_if_eq("version", "2"))]
        effective_date_time: String,
        /// The effective time for the Validation List (only for version 2)
        v2_vl_file: Option<String>,
    },
    /// Encodes a manifest
    EncodeManifest {
        /// Manifest sequence number
        sequence: u32,
        /// Master Public Key
        master_public_key: String,
        /// Signing Public Key
        signing_public_key: String,
        /// Signature
        signature: String,
        /// Master Signature
        master_signature: String,
        /// Domain (optional)
        domain: Option<String>,
    },
    /// Decodes a manifest
    DecodeManifest { manifest: String },
}
