use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(version)]
#[clap(propagate_version = false)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Loads and verifies a given Validation List. It accepts a file path or a url. Example: `./xrpl_vl_tool load {url_or_file_path}`
    Load {
        /// The URL or file path of the Validation List. You can pass either.
        url_or_file: String,
    },
    /// Produces and signs a Validation List
    Sign {
        /// The version of the Validation List (1 or 2)
        #[arg(short = 'v', long = "vl_version")]
        vl_version: u8,
        /// The publisher manifest
        #[arg(short = 'p', long = "publisher_manifest")]
        publisher_manifest: String,
        /// Path to the file that holds the list of manifests, one per line
        #[arg(short = 'm', long = "manifests_file")]
        manifests_file: String,
        /// The sequence number of the Validation List
        #[arg(short = 's', long = "sequence")]
        sequence: u32,
        /// The expiration in days of the Validation List
        #[arg(short = 'e', long = "expiration")]
        expiration_in_days: u16,
        /// The secret provider to use: aws, vault or local. For local secret, this value should be the path to the file that holds the secret
        #[arg(short = 'x', long = "secret_provider")]
        secret_provider: String,
        /// The secret id to use
        #[arg(short = 'n', long = "secret_name")]
        secret_name: String,
        /// The effective day (YYYY/MM/DD) for the Validation List (only for version 2)
        #[arg(
            short = 'd',
            long = "effective_date_day",
            required_if_eq("vl_version", "2")
        )]
        effective_date_day: Option<String>,
        /// The effective time (HH:MM) for the Validation List (only for version 2)
        #[arg(
            short = 't',
            long = "effective_date_time",
            required_if_eq("vl_version", "2")
        )]
        effective_date_time: Option<String>,
        /// The effective time for the Validation List (only for version 2)
        #[arg(short = 'f', long = "v2_vl_file")]
        v2_vl_file: Option<String>,
    },
    /// Encodes a manifest
    EncodeManifest {
        /// Manifest sequence number
        #[arg(short = 's', long = "sequence")]
        sequence: u32,
        /// Master Public Key in Base58 format
        #[arg(short = 'm', long = "master_public_key")]
        master_public_key: String,
        /// Signing Public Key in Base58 format
        #[arg(short = 'p', long = "signing_public_key")]
        signing_public_key: String,
        /// Signature in Hex format
        #[arg(short = 'x', long = "signature")]
        signature: String,
        /// Master Signature in Hex format
        #[arg(short = 'y', long = "master_signature")]
        master_signature: String,
        /// Domain (optional)
        #[arg(short = 'd', long = "domain")]
        domain: Option<String>,
    },
    /// Decodes a manifest
    DecodeManifest {
        /// The manifest to decode
        manifest: String,
    },
}
