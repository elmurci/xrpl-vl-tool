use anstream::println;
use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use clap::Parser;
use color_eyre::owo_colors::OwoColorize;
use xrpl_vl_tool::cli::{Cli, Commands};
use xrpl_vl_tool::manifest::{decode_manifest, encode_manifest};
use xrpl_vl_tool::secret::{get_secret, SecretProvider};
use xrpl_vl_tool::time::{convert_to_human_time, convert_to_unix_time};
use xrpl_vl_tool::util::{generate_vl_file, get_tick_or_cross, print_validators_summary};
use xrpl_vl_tool::vl::{get_vl, load_vl, sign_vl, verify_vl};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Load { url_or_file } => {
            let vl = load_vl(url_or_file).await?;
            let verified_vl = verify_vl(vl)?;

            if verified_vl.version == 1 {
                // UNL Summary
                let decoded_blob = verified_vl.decoded_blob.clone().context("Could not get Decoded blob")?;
                let expiration_unix_timestamp = convert_to_unix_time(decoded_blob.expiration);
                println!("\nThere are {} validators in this VL. Sequence is: {} | Blob Signature: {} | Manifest Signature: {} | Expires: {} | Version: 1 \n", decoded_blob.validators.len().green(), decoded_blob.sequence.green(), get_tick_or_cross(verified_vl.blob_verification.context("Could not get blob verification")?), get_tick_or_cross(verified_vl.manifest.verification), convert_to_human_time(expiration_unix_timestamp)?);
                // Validators
                let _ = print_validators_summary(decoded_blob.validators);
            } else {
                let decoded_blobs_v2 = verified_vl
                    .decoded_blobs_v2
                    .clone()
                    .expect("Could not get decoded blobs v2");
                // Summary
                println!("\nThere are {} UNL's in this Validators List | Version 2 | Manifest Signature: {}\n", decoded_blobs_v2.len(), get_tick_or_cross(verified_vl.manifest.verification));
                for (index, blob_v2) in decoded_blobs_v2.iter().enumerate() {
                    let decoded_blob = blob_v2
                        .clone()
                        .decoded_blob
                        .expect("Could not get decoded blob");
                    let expiration_unix_timestamp = convert_to_unix_time(decoded_blob.expiration);
                    let effective_unix_timestamp = convert_to_unix_time(
                        decoded_blob
                            .effective
                            .expect("Could not get effective timestamp"),
                    );
                    // Summary
                    println!("\n{}) There are {} validators in this VL. Sequence is: {} | Blob Signature: {} | Effective from: {} | Expires: {} \n", index+1, decoded_blob.validators.len().green(), decoded_blob.sequence.green(), get_tick_or_cross(blob_v2.blob_verification.context("Could not get blob verification flag")?), convert_to_human_time(effective_unix_timestamp)?, convert_to_human_time(expiration_unix_timestamp)?);
                    // Validators
                    let _ = print_validators_summary(decoded_blob.validators);
                }
            }
        }
        Commands::Sign {
            vl_version,
            publisher_manifest,
            manifests_file,
            sequence,
            expiration_in_days,
            secret_provider,
            secret_name,
            effective_date_day,
            effective_date_time,
            v2_vl_file,
        } => {
            let effective = if *vl_version == 2 {
                Some(
                    NaiveDateTime::parse_from_str(
                        &format!(
                            "{} {}",
                            effective_date_day
                                .clone()
                                .context("Could not get effective date's day")?,
                            effective_date_time
                                .clone()
                                .context("Could not get effective date's time")?
                        ),
                        "%Y-%m-%d %H:%M",
                    )
                    .expect("Could not parse effective timestamp, format is %Y-%m-%d %H:%M")
                    .and_utc()
                    .timestamp(),
                )
            } else {
                None
            };
            let v2_vl = if v2_vl_file.is_some() {
                Some(get_vl(&v2_vl_file.clone().context("Could not get v2 vl file")?).await?)
            } else {
                None
            };

            let secret_provider: SecretProvider =
                SecretProvider::from_string_slice(secret_provider)?;
            let secret = get_secret(secret_provider, secret_name).await?;
            if secret.is_none() {
                anyhow::bail!("No secret was found");
            }

            let vl = sign_vl(
                *vl_version,
                publisher_manifest.clone(),
                manifests_file.clone(),
                *sequence,
                *expiration_in_days,
                secret.context("Could not get Secret")?,
                effective,
                v2_vl,
            )
            .await?;

            let vl_content = &serde_json::to_string(&vl)?;
            let file = generate_vl_file(vl_content, *vl_version);
            println!(
                "Validators List v{} file generated {} ({})",
                vl_version,
                get_tick_or_cross(file.is_ok()),
                file?
            );
        }
        Commands::EncodeManifest {
            sequence,
            master_public_key,
            signing_public_key,
            signature,
            master_signature,
            domain,
        } => {
            let encoded_manifest = encode_manifest(
                *sequence,
                master_public_key.clone(),
                signing_public_key.clone(),
                signature.clone(),
                master_signature.clone(),
                domain.clone(),
            )?;

            println!("\n Encoded manifest: \n\n {}", encoded_manifest);
        }
        Commands::DecodeManifest { manifest } => {
            let decoded_manifest = decode_manifest(manifest)?;

            println!("\n Decoded manifest: \n\n Sequence: {} \n Master Public Key: {} \n Signing Public Key: {} \n Signature: {} \n Master Signature: {} \n Domain: {:?} \n",
                decoded_manifest.sequence,
                decoded_manifest.master_public_key,
                decoded_manifest.signing_public_key,
                decoded_manifest.signature.to_uppercase(),
                decoded_manifest.master_signature.to_uppercase(),
                decoded_manifest.domain,
            );
        }
    }

    Ok(())
}
