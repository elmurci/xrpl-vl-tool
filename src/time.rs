use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn convert_to_human_time(timestamp: i64) -> String {
    let dt = DateTime::from_timestamp(timestamp, 0).unwrap();
    format!("{}", dt.format("%Y-%m-%d %H:%M:%S"))
}
pub fn convert_to_ripple_time(tstamp: Option<i64>) -> i64 {
    let ripple_epoch = 946684800; // Ripple epoch in seconds since UNIX epoch (1/1/2000)
    let current_time = match tstamp {
        Some(ts) => ts,
        None => {
            let start = SystemTime::now();
            let since_the_epoch = start
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            since_the_epoch.as_secs() as i64
        }
    };
    current_time - ripple_epoch
}

pub fn convert_to_unix_time(rtstamp: i64) -> i64 {
    let ripple_epoch = 946684800; // Ripple epoch in seconds since UNIX epoch (1/1/2000)
    rtstamp + ripple_epoch
}

pub fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Could not get time")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{FixedOffset, TimeZone};

    #[test]
    fn test_convert_to_human_time_utc() {
        let timestamp = 1609459200; // 2021-01-01 00:00:00 UTC
        let expected = "2021-01-01 00:00:00";
        let result = convert_to_human_time(timestamp);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_to_human_time_negative_timestamp_utc() {
        let timestamp = -2208988800; // 1900-01-01 00:00:00 UTC
        let expected = "1900-01-01 00:00:00";
        let result = convert_to_human_time(timestamp);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_to_human_time_zero_timestamp_utc() {
        let timestamp = 0; // 1970-01-01 00:00:00 UTC
        let expected = "1970-01-01 00:00:00";
        let result = convert_to_human_time(timestamp);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_to_human_time_non_utc() {
        let timestamp = 1609459200; // 2021-01-01 00:00:00 UTC
        let offset = FixedOffset::east_opt(3600).unwrap(); // UTC+1
        let expected = "2021-01-01 01:00:00 +01:00";
        let result = offset.timestamp_opt(timestamp, 0).unwrap().to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_to_human_time_non_utc_negative_timestamp() {
        let timestamp = -2208988800; // 1900-01-01 00:00:00 UTC
        let offset = FixedOffset::east_opt(3600).unwrap(); // UTC+1
        let expected = "1900-01-01 01:00:00 +01:00";
        let result = offset.timestamp_opt(timestamp, 0).unwrap().to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_to_human_time_non_utc_zero_timestamp() {
        let timestamp = 0; // 1970-01-01 00:00:00 UTC
        let offset = FixedOffset::east_opt(3600).unwrap(); // UTC+1
        let expected = "1970-01-01 01:00:00 +01:00";
        let result = offset.timestamp_opt(timestamp, 0).unwrap().to_string();
        assert_eq!(result, expected);
    }
}
