use anyhow::{Context, Result};
use chrono::DateTime;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::vl::BlobV2;

pub fn convert_to_human_time(timestamp: i64) -> Result<String> {
    let dt = DateTime::from_timestamp(timestamp, 0).context("Could not get timestamp")?;
    Ok(format!("{}", dt.format("%Y-%m-%d %H:%M:%S")))
}
pub fn convert_to_ripple_time(tstamp: Option<i64>) -> Result<i64> {
    let ripple_epoch = 946684800; // Ripple epoch in seconds since UNIX epoch (1/1/2000)
    let current_time = match tstamp {
        Some(ts) => ts,
        None => {
            let start = SystemTime::now();
            let since_the_epoch = start
                .duration_since(UNIX_EPOCH)
                .context("Time went backwards")?;
            since_the_epoch.as_secs() as i64
        }
    };
    Ok(current_time - ripple_epoch)
}

pub fn convert_to_unix_time(rtstamp: i64) -> i64 {
    let ripple_epoch = 946684800; // Ripple epoch in seconds since UNIX epoch (1/1/2000)
    rtstamp + ripple_epoch
}

pub fn get_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Could not get time")?
        .as_secs())
}

pub fn blobs_have_no_time_gaps(mut blobs: Vec<BlobV2>) -> Result<bool> {

    // Sort by start date
    blobs.sort_by_key(|blob| blob.decoded_blob.as_ref().unwrap().effective.unwrap());

    // Early return if empty or only one blob
    if blobs.len() < 2 {
        return Ok(true)
    }

    // Compare consecutive blobs
    for pair in blobs.windows(2) {
        let current = &pair[0];
        let next = &pair[1];
        if next.decoded_blob.as_ref().context("Could not get Decoded Blob")?.effective.context("Could not get Effectivate date")? > current.decoded_blob.as_ref().context("Could not get Decoded Blob")?.expiration {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use crate::vl::DecodedBlob;

    use super::*;

    #[test]
    fn test_convert_to_human_time_utc() {
        let timestamp = 1609459200; // 2021-01-01 00:00:00 UTC
        let expected = "2021-01-01 00:00:00";
        let result = convert_to_human_time(timestamp).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_to_human_time_negative_timestamp_utc() {
        let timestamp = -2208988800; // 1900-01-01 00:00:00 UTC
        let expected = "1900-01-01 00:00:00";
        let result = convert_to_human_time(timestamp).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_to_human_time_zero_timestamp_utc() {
        let timestamp = 0; // 1970-01-01 00:00:00 UTC
        let expected = "1970-01-01 00:00:00";
        let result = convert_to_human_time(timestamp).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_blobs_have_no_time_gaps_ok() {
        let blobs = vec![
            BlobV2 {
                decoded_blob: Some(DecodedBlob {
                    effective: Some(1609459100),
                    expiration: 1609459120,
                    sequence: 1,
                    validators: vec![],
                }),
                signature: "".to_string(),
                manifest: None,
                blob: None,
                blob_verification: None,
            },
            BlobV2 {
                decoded_blob: Some(DecodedBlob {
                    effective: Some(1609459120),
                    expiration: 1609459130,
                    sequence: 1,
                    validators: vec![],
                }),
                signature: "".to_string(),
                manifest: None,
                blob: None,
                blob_verification: None,
            },
            BlobV2 {
                decoded_blob: Some(DecodedBlob {
                    effective: Some(1609459129),
                    expiration: 1609459180,
                    sequence: 1,
                    validators: vec![],
                }),
                signature: "".to_string(),
                manifest: None,
                blob: None,
                blob_verification: None,
            }
        ];
        assert_eq!(blobs_have_no_time_gaps(blobs).unwrap(), true);
    }

    #[test]
    fn test_blobs_have_time_gaps_ok() {
        let blobs = vec![
            BlobV2 {
                decoded_blob: Some(DecodedBlob {
                    effective: Some(1609459100),
                    expiration: 1609459150,
                    sequence: 1,
                    validators: vec![],
                }),
                signature: "".to_string(),
                manifest: None,
                blob: None,
                blob_verification: None,
            },
            BlobV2 {
                decoded_blob: Some(DecodedBlob {
                    effective: Some(1609459200),
                    expiration: 1609545600,
                    sequence: 1,
                    validators: vec![],
                }),
                signature: "".to_string(),
                manifest: None,
                blob: None,
                blob_verification: None,
            },
            BlobV2 {
                decoded_blob: Some(DecodedBlob {
                    effective: Some(1609545600),
                    expiration: 1609545700,
                    sequence: 1,
                    validators: vec![],
                }),
                signature: "".to_string(),
                manifest: None,
                blob: None,
                blob_verification: None,
            }
        ];
        assert_eq!(blobs_have_no_time_gaps(blobs).unwrap(), false);
    }
}
