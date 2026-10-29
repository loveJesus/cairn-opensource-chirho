// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The blocking `ureq` transport under the S3 adapter — capped bodies, no redirects, 404-means-absent
//! — plus the pure epoch→`yyyymmddThhmmssZ` formatter signing timestamps come from.

use cairn_core_chirho::ports_chirho::{StoreErrorChirho, StoreResultChirho};
use std::io::Read;
use std::time::Duration;

/// Hard cap on any single response body, mirroring the replication transport: a compromised or
/// MITM'd endpoint must not OOM the host; a larger body is a transport error, never a truncation.
pub const MAX_S3_BODY_BYTES_CHIRHO: u64 = 256 * 1024 * 1024;

/// Blocking HTTP client for one S3-compatible endpoint. Redirects are never followed: an object
/// store answers directly, and refusing redirects denies a hostile endpoint an SSRF lever and keeps
/// signed headers from being replayed elsewhere.
pub(crate) struct S3HttpChirho {
    agent_chirho: ureq::Agent,
}

impl S3HttpChirho {
    pub(crate) fn new_chirho() -> Self {
        Self {
            agent_chirho: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .redirects(0)
                .build(),
        }
    }

    fn apply_headers_chirho(
        mut request_chirho: ureq::Request,
        headers_chirho: &[(String, String)],
    ) -> ureq::Request {
        for (name_chirho, value_chirho) in headers_chirho {
            request_chirho = request_chirho.set(name_chirho, value_chirho);
        }
        request_chirho
    }

    /// GET bytes; `404` is `None`; any other non-200 (transport fault, `403`, `3xx`, `500`) is an
    /// error, so a hostile response never masquerades as an absent object.
    pub(crate) fn get_optional_chirho(
        &self,
        url_chirho: &str,
        headers_chirho: &[(String, String)],
    ) -> StoreResultChirho<Option<Vec<u8>>> {
        let request_chirho =
            Self::apply_headers_chirho(self.agent_chirho.get(url_chirho), headers_chirho);
        match request_chirho.call() {
            Ok(response_chirho) => Ok(Some(read_capped_body_chirho(
                url_chirho,
                response_chirho,
                MAX_S3_BODY_BYTES_CHIRHO,
            )?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(error_chirho) => Err(transport_error_chirho(url_chirho, &error_chirho)),
        }
    }

    /// PUT bytes; only a 200 is success.
    pub(crate) fn put_chirho(
        &self,
        url_chirho: &str,
        headers_chirho: &[(String, String)],
        body_chirho: &[u8],
    ) -> StoreResultChirho<()> {
        let request_chirho =
            Self::apply_headers_chirho(self.agent_chirho.put(url_chirho), headers_chirho);
        match request_chirho.send_bytes(body_chirho) {
            Ok(response_chirho) if response_chirho.status() == 200 => Ok(()),
            Ok(response_chirho) => Err(StoreErrorChirho::backend_chirho(format!(
                "s3 PUT {url_chirho}: unexpected status {}",
                response_chirho.status()
            ))),
            Err(error_chirho) => Err(transport_error_chirho(url_chirho, &error_chirho)),
        }
    }
}

/// Render a `ureq` failure without ever touching request headers, so no signature or credential can
/// reach an error string (R4): only the URL, a status code, or ureq's transport kind/message appear.
fn transport_error_chirho(url_chirho: &str, error_chirho: &ureq::Error) -> StoreErrorChirho {
    match error_chirho {
        ureq::Error::Status(code_chirho, _) => StoreErrorChirho::backend_chirho(format!(
            "s3 request {url_chirho}: unexpected status {code_chirho}"
        )),
        ureq::Error::Transport(transport_chirho) => StoreErrorChirho::backend_chirho(format!(
            "s3 request {url_chirho}: transport {}",
            transport_chirho.kind()
        )),
    }
}

/// Read a 200 body up to `cap_chirho` (reading one byte past to tell at-cap from over-cap). Only a
/// 200 carries bytes we trust: with redirects disabled a 3xx surfaces as an `Ok` response and must
/// not read as an empty/absent object.
fn read_capped_body_chirho(
    url_chirho: &str,
    response_chirho: ureq::Response,
    cap_chirho: u64,
) -> StoreResultChirho<Vec<u8>> {
    if response_chirho.status() != 200 {
        return Err(StoreErrorChirho::backend_chirho(format!(
            "s3 GET {url_chirho}: unexpected status {}",
            response_chirho.status()
        )));
    }
    let mut buffer_chirho = Vec::new();
    response_chirho
        .into_reader()
        .take(cap_chirho + 1)
        .read_to_end(&mut buffer_chirho)
        .map_err(|error_chirho| {
            StoreErrorChirho::backend_chirho(format!("s3 GET {url_chirho}: read: {error_chirho}"))
        })?;
    if buffer_chirho.len() as u64 > cap_chirho {
        return Err(StoreErrorChirho::backend_chirho(format!(
            "s3 GET {url_chirho}: response body exceeds the body-size cap"
        )));
    }
    Ok(buffer_chirho)
}

/// Format an epoch-seconds instant as the SigV4 `yyyymmddThhmmssZ` timestamp (pure; days→civil via
/// the standard Gregorian era decomposition, pinned against oracle values below).
pub(crate) fn amz_timestamp_from_epoch_chirho(epoch_seconds_chirho: u64) -> String {
    let days_chirho = (epoch_seconds_chirho / 86_400) as i64;
    let seconds_of_day_chirho = epoch_seconds_chirho % 86_400;
    let (year_chirho, month_chirho, day_chirho) = civil_from_days_chirho(days_chirho);
    format!(
        "{year_chirho:04}{month_chirho:02}{day_chirho:02}T{:02}{:02}{:02}Z",
        seconds_of_day_chirho / 3_600,
        (seconds_of_day_chirho % 3_600) / 60,
        seconds_of_day_chirho % 60
    )
}

/// Days since 1970-01-01 → (year, month, day), valid for the whole u64-epoch range we can meet.
fn civil_from_days_chirho(days_chirho: i64) -> (i64, u32, u32) {
    let z_chirho = days_chirho + 719_468;
    let era_chirho = if z_chirho >= 0 {
        z_chirho
    } else {
        z_chirho - 146_096
    } / 146_097;
    let day_of_era_chirho = (z_chirho - era_chirho * 146_097) as u64;
    let year_of_era_chirho = (day_of_era_chirho - day_of_era_chirho / 1_460
        + day_of_era_chirho / 36_524
        - day_of_era_chirho / 146_096)
        / 365;
    let year_chirho = year_of_era_chirho as i64 + era_chirho * 400;
    let day_of_year_chirho = day_of_era_chirho
        - (365 * year_of_era_chirho + year_of_era_chirho / 4 - year_of_era_chirho / 100);
    let month_point_chirho = (5 * day_of_year_chirho + 2) / 153;
    let day_chirho = (day_of_year_chirho - (153 * month_point_chirho + 2) / 5 + 1) as u32;
    let month_chirho = if month_point_chirho < 10 {
        month_point_chirho + 3
    } else {
        month_point_chirho - 9
    } as u32;
    (
        if month_chirho <= 2 {
            year_chirho + 1
        } else {
            year_chirho
        },
        month_chirho,
        day_chirho,
    )
}

/// The current UTC instant as a SigV4 timestamp.
pub(crate) fn now_amz_timestamp_chirho() -> String {
    let epoch_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_secs())
        .unwrap_or(0);
    amz_timestamp_from_epoch_chirho(epoch_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    /// Pinned against an independent python `datetime` oracle, covering both leap-year shapes.
    #[test]
    fn formats_epoch_timestamps_like_the_oracle_chirho() {
        assert_eq!(amz_timestamp_from_epoch_chirho(0), "19700101T000000Z");
        assert_eq!(
            amz_timestamp_from_epoch_chirho(951_827_696),
            "20000229T123456Z"
        );
        assert_eq!(
            amz_timestamp_from_epoch_chirho(1_709_164_800),
            "20240229T000000Z"
        );
        assert_eq!(
            amz_timestamp_from_epoch_chirho(1_783_956_311),
            "20260713T152511Z"
        );
        assert_eq!(
            amz_timestamp_from_epoch_chirho(4_102_444_799),
            "20991231T235959Z"
        );
    }

    /// The cap boundary, over synthetic `ureq` responses so the tiny test cap needs no socket:
    /// exactly-at-cap is accepted; one byte past is refused as an error — never a silent truncation.
    #[test]
    fn refuses_a_body_past_the_cap_chirho() {
        let cap_chirho: u64 = 1_024;
        let at_cap_chirho =
            ureq::Response::new(200, "OK", &"x".repeat(cap_chirho as usize)).unwrap();
        let accepted_chirho =
            read_capped_body_chirho("http://test/at-cap", at_cap_chirho, cap_chirho).unwrap();
        assert_eq!(accepted_chirho.len() as u64, cap_chirho);
        let past_cap_chirho =
            ureq::Response::new(200, "OK", &"x".repeat((cap_chirho + 1) as usize)).unwrap();
        let message_chirho =
            read_capped_body_chirho("http://test/past-cap", past_cap_chirho, cap_chirho)
                .unwrap_err()
                .to_string();
        assert!(message_chirho.contains("body-size cap"), "{message_chirho}");
    }
}
