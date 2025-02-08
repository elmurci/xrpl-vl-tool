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
        #[arg(short = 'v', long = "vl-version")]
        vl_version: u8,
        /// The publisher manifest
        #[arg(short = 'p', long = "publisher-manifest")]
        publisher_manifest: String,
        /// Path to the file that holds the list of manifests, one per line
        #[arg(short = 'm', long = "manifests-file")]
        manifests_file: String,
        /// The sequence number of the Validation List
        #[arg(short = 's', long = "sequence")]
        sequence: u32,
        /// The expiration in days of the Validation List
        #[arg(short = 'e', long = "expiration")]
        expiration_in_days: i16,
        /// The secret provider to use: aws, vault or local. For local secret, this value should be the path to the file that holds the secret
        #[arg(short = 'x', long = "secret-provider")]
        secret_provider: String,
        #[arg(
            short = 'n',
            long = "secret-name",
            required_if_eq_any(
                [("secret_provider", "vault"), ("secret_provider", "aws")],
            )
        )]
        secret_name: Option<String>,
        /// The effective day (YYYY/MM/DD) for the Validation List (only for version 2)
        #[arg(
            short = 'd',
            long = "effective-date-day",
            required_if_eq("vl_version", "2")
        )]
        effective_date_day: Option<String>,
        /// The effective time (HH:MM) for the Validation List (only for version 2)
        #[arg(
            short = 't',
            long = "effective-date-time",
            required_if_eq("vl_version", "2")
        )]
        effective_date_time: Option<String>,
        /// Sometimes you might want to add a new UNL version to an existing Validators List, specify the path or URL to that VL here (only for version 2)
        #[arg(short = 'f', long = "v2-vl-file")]
        v2_vl_file: Option<String>,
    },
    /// Encodes a manifest
    EncodeManifest {
        /// Manifest sequence number
        #[arg(short = 's', long = "sequence")]
        sequence: u32,
        /// Master Public Key in Base58 format
        #[arg(short = 'm', long = "master-public-key")]
        master_public_key: String,
        /// Signing Public Key in Base58 format
        #[arg(short = 'p', long = "signing-public-key")]
        signing_public_key: String,
        /// Signature in Hex format
        #[arg(short = 'x', long = "signature")]
        signature: String,
        /// Master Signature in Hex format
        #[arg(short = 'y', long = "master-signature")]
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
