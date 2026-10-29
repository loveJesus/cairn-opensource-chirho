// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure identity model records.
//!
//! This crate owns serializable identity DTOs only. It does not read a cairn root, issue
//! credentials, write ledgers, sign records, or manage sessions.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalKindChirho {
    UserChirho,
    OwnerChirho,
}

impl PrincipalKindChirho {
    pub fn parse_chirho(value_chirho: &str) -> Result<Self> {
        match value_chirho {
            "user" => Ok(Self::UserChirho),
            "owner" => Ok(Self::OwnerChirho),
            other_chirho => bail!("unknown principal kind '{other_chirho}' (use user|owner)"),
        }
    }

    pub fn prefix_chirho(&self) -> &'static str {
        match self {
            Self::UserChirho => "user",
            Self::OwnerChirho => "owner",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub principal_chirho: String,
    pub kind_chirho: PrincipalKindChirho,
    pub wallet_chirho: String,
    pub pubkey_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn principal_kind_serialization_stays_stable_chirho() {
        assert_eq!(
            serde_json::to_string(&PrincipalKindChirho::OwnerChirho).unwrap(),
            "\"OwnerChirho\""
        );
        assert_eq!(
            serde_json::to_string(&PrincipalKindChirho::UserChirho).unwrap(),
            "\"UserChirho\""
        );
    }

    #[test]
    fn identity_record_serialization_stays_stable_chirho() {
        let record_chirho = IdentityRecordChirho {
            seq_chirho: 7,
            schema_chirho: "identity-record-v1-chirho".to_string(),
            principal_chirho: "user/abc123-chirho".to_string(),
            kind_chirho: PrincipalKindChirho::UserChirho,
            wallet_chirho: "wallet/user/abc123-chirho".to_string(),
            pubkey_chirho: "pubkey-hex-chirho".to_string(),
            at_ms_chirho: 123_456,
            sig_chirho: "sig-hex-chirho".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&record_chirho).unwrap(),
            r#"{"seq_chirho":7,"schema_chirho":"identity-record-v1-chirho","principal_chirho":"user/abc123-chirho","kind_chirho":"UserChirho","wallet_chirho":"wallet/user/abc123-chirho","pubkey_chirho":"pubkey-hex-chirho","at_ms_chirho":123456,"sig_chirho":"sig-hex-chirho"}"#
        );
    }
}
