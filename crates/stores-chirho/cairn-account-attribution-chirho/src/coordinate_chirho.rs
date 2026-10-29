// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The account coordinate: one domain-separated digest of the trusted account principal, the name every attribution row and freeze is filed under.
//!
//! It is computed from the principal the trusted request context carries, never inferred from a leaf
//! subject or an email address (gpt #28839, #28874). It is unkeyed, so the same principal has the same
//! coordinate on every node of a group, which C5's propagation needs.

use crate::refusal_chirho::{refuse_chirho, AccountAttributionRefusalChirho};
use anyhow::Result;
use serde::{Deserialize, Serialize};

const ACCOUNT_COORDINATE_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-account-coordinate-v1-chirho";
const PRINCIPAL_MAX_BYTES_CHIRHO: usize = 512;
const COORDINATE_HEX_BYTES_CHIRHO: usize = 64;

/// It deserializes only through `from_hex_chirho`, so a path-shaped or non-hex value can never become a
/// coordinate and reach the account directory join (gpt #28899).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountCoordinateChirho(String);

impl TryFrom<String> for AccountCoordinateChirho {
    type Error = anyhow::Error;

    fn try_from(value_chirho: String) -> Result<Self> {
        Self::from_hex_chirho(&value_chirho)
    }
}

impl From<AccountCoordinateChirho> for String {
    fn from(coordinate_chirho: AccountCoordinateChirho) -> Self {
        coordinate_chirho.0
    }
}

impl AccountCoordinateChirho {
    /// The coordinate of a trusted account principal. A blank, oversized or control-bearing principal
    /// is refused rather than digested.
    pub fn from_principal_chirho(principal_chirho: &str) -> Result<Self> {
        if principal_chirho.trim().is_empty()
            || principal_chirho.len() > PRINCIPAL_MAX_BYTES_CHIRHO
            || principal_chirho.chars().any(char::is_control)
        {
            return Err(refuse_chirho(
                AccountAttributionRefusalChirho::AccountCoordinateInvalidChirho,
                "the principal is blank, oversized or carries a control character",
            ));
        }
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(ACCOUNT_COORDINATE_DOMAIN_V1_CHIRHO);
        hasher_chirho.update(&(principal_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(principal_chirho.as_bytes());
        Ok(Self(hasher_chirho.finalize().to_hex().to_string()))
    }

    /// A coordinate read back from a record or a path, validated as canonical hex.
    pub fn from_hex_chirho(hex_chirho: &str) -> Result<Self> {
        if !is_lower_hex_chirho(hex_chirho, COORDINATE_HEX_BYTES_CHIRHO) {
            return Err(refuse_chirho(
                AccountAttributionRefusalChirho::AccountCoordinateInvalidChirho,
                "the coordinate is not canonical hex",
            ));
        }
        Ok(Self(hex_chirho.to_string()))
    }

    pub fn as_hex_chirho(&self) -> &str {
        &self.0
    }
}

pub(crate) fn is_lower_hex_chirho(value_chirho: &str, len_chirho: usize) -> bool {
    value_chirho.len() == len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
