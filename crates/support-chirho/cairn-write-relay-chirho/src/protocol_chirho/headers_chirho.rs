// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Validates and hashes bounded end-to-end relay headers.

use super::{update_digest_field_chirho, RelayContractErrorChirho, RelayRefusalIdentityChirho};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const RELAY_HEADER_COUNT_MAX_CHIRHO: usize = 32;
const RELAY_HEADER_NAME_MAX_BYTES_CHIRHO: usize = 64;
const RELAY_HEADER_VALUE_MAX_BYTES_CHIRHO: usize = 16 * 1024;
const RELAY_HEADER_TOTAL_MAX_BYTES_CHIRHO: usize = 64 * 1024;
const RELAY_REQUEST_ALLOWED_HEADER_NAMES_CHIRHO: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "authorization",
    "content-encoding",
    "content-type",
    "cookie",
    "if-match",
    "if-none-match",
    "if-range",
    "origin",
    "range",
    "referer",
    "user-agent",
];
const RELAY_RESPONSE_ALLOWED_HEADER_NAMES_CHIRHO: &[&str] = &[
    "accept-ranges",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-range",
    "content-security-policy",
    "content-type",
    "etag",
    "expires",
    "last-modified",
    "location",
    "referrer-policy",
    "retry-after",
    "set-cookie",
    "strict-transport-security",
    "vary",
    "www-authenticate",
    "x-content-type-options",
    "x-frame-options",
];

pub fn relay_request_header_name_is_allowed_chirho(name_chirho: &str) -> bool {
    RELAY_REQUEST_ALLOWED_HEADER_NAMES_CHIRHO.contains(&name_chirho)
}

pub fn relay_response_header_name_is_allowed_chirho(name_chirho: &str) -> bool {
    RELAY_RESPONSE_ALLOWED_HEADER_NAMES_CHIRHO.contains(&name_chirho)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelayEndToEndHeadersChirho(BTreeMap<String, Vec<String>>);

impl RelayEndToEndHeadersChirho {
    pub fn try_request_chirho(
        headers_chirho: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, RelayContractErrorChirho> {
        Self::try_new_chirho(headers_chirho, RelayHeaderKindChirho::RequestChirho)
    }

    pub fn try_response_chirho(
        headers_chirho: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, RelayContractErrorChirho> {
        Self::try_new_chirho(headers_chirho, RelayHeaderKindChirho::ResponseChirho)
    }

    fn try_new_chirho(
        headers_chirho: impl IntoIterator<Item = (String, String)>,
        kind_chirho: RelayHeaderKindChirho,
    ) -> Result<Self, RelayContractErrorChirho> {
        let mut values_chirho = BTreeMap::new();
        for (name_chirho, value_chirho) in headers_chirho {
            values_chirho
                .entry(name_chirho)
                .or_insert_with(Vec::new)
                .push(value_chirho);
        }
        let headers_chirho = Self(values_chirho);
        headers_chirho.validate_chirho(kind_chirho)?;
        Ok(headers_chirho)
    }

    pub fn iter_chirho(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().flat_map(|(name_chirho, values_chirho)| {
            values_chirho
                .iter()
                .map(move |value_chirho| (name_chirho.as_str(), value_chirho.as_str()))
        })
    }

    pub(super) fn validate_chirho(
        &self,
        kind_chirho: RelayHeaderKindChirho,
    ) -> Result<(), RelayContractErrorChirho> {
        let header_count_chirho = self.0.values().map(Vec::len).sum::<usize>();
        if header_count_chirho > RELAY_HEADER_COUNT_MAX_CHIRHO {
            return Err(relay_header_error_chirho());
        }
        let mut total_bytes_chirho = 0_usize;
        for (name_chirho, values_chirho) in &self.0 {
            if values_chirho.is_empty()
                || name_chirho.is_empty()
                || name_chirho.len() > RELAY_HEADER_NAME_MAX_BYTES_CHIRHO
                || !name_chirho.bytes().all(is_lower_header_token_byte_chirho)
                || header_is_forbidden_chirho(name_chirho, kind_chirho)
            {
                return Err(relay_header_error_chirho());
            }
            for value_chirho in values_chirho {
                total_bytes_chirho = total_bytes_chirho
                    .saturating_add(name_chirho.len())
                    .saturating_add(value_chirho.len());
                if value_chirho.len() > RELAY_HEADER_VALUE_MAX_BYTES_CHIRHO
                    || value_chirho
                        .bytes()
                        .any(|byte_chirho| matches!(byte_chirho, b'\r' | b'\n' | 0))
                {
                    return Err(relay_header_error_chirho());
                }
            }
        }
        if total_bytes_chirho > RELAY_HEADER_TOTAL_MAX_BYTES_CHIRHO {
            return Err(relay_header_error_chirho());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum RelayHeaderKindChirho {
    RequestChirho,
    ResponseChirho,
}

pub(super) fn update_headers_digest_chirho(
    hasher_chirho: &mut blake3::Hasher,
    headers_chirho: &RelayEndToEndHeadersChirho,
) {
    update_digest_field_chirho(
        hasher_chirho,
        b"header-count-chirho",
        &(headers_chirho.0.values().map(Vec::len).sum::<usize>() as u64).to_le_bytes(),
    );
    for (name_chirho, values_chirho) in &headers_chirho.0 {
        for value_chirho in values_chirho {
            update_digest_field_chirho(
                hasher_chirho,
                b"header-name-chirho",
                name_chirho.as_bytes(),
            );
            update_digest_field_chirho(
                hasher_chirho,
                b"header-value-chirho",
                value_chirho.as_bytes(),
            );
        }
    }
}

fn is_lower_header_token_byte_chirho(byte_chirho: u8) -> bool {
    byte_chirho.is_ascii_lowercase()
        || byte_chirho.is_ascii_digit()
        || matches!(
            byte_chirho,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn header_is_forbidden_chirho(name_chirho: &str, kind_chirho: RelayHeaderKindChirho) -> bool {
    match kind_chirho {
        RelayHeaderKindChirho::RequestChirho => {
            !relay_request_header_name_is_allowed_chirho(name_chirho)
        }
        RelayHeaderKindChirho::ResponseChirho => {
            !relay_response_header_name_is_allowed_chirho(name_chirho)
        }
    }
}

fn relay_header_error_chirho() -> RelayContractErrorChirho {
    RelayContractErrorChirho::new_chirho(
        RelayRefusalIdentityChirho::RelayHeaderInvalidChirho,
        "relay end-to-end headers are not canonical, allowlisted, and bounded",
    )
}
