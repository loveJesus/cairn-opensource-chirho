// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The signed attribution row and freeze record, and the exact bytes each signature covers.

use crate::coordinate_chirho::is_lower_hex_chirho;
use crate::refusal_chirho::{refuse_chirho, AccountAttributionRefusalChirho};
use crate::subject_owner_chirho::SubjectOwnerChirho;
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const ATTRIBUTION_RECORD_SCHEMA_V1_CHIRHO: &str = "account-attribution-record-v1-chirho";
pub const FREEZE_RECORD_SCHEMA_V1_CHIRHO: &str = "account-freeze-record-v1-chirho";
const ATTRIBUTION_MESSAGE_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-account-attribution-record-v1-chirho";
const FREEZE_MESSAGE_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-account-freeze-record-v1-chirho";
const KEY_ID_HEX_BYTES_CHIRHO: usize = 32;
const SUBJECT_MAX_BYTES_CHIRHO: usize = 256;
const REASON_MAX_BYTES_CHIRHO: usize = 64;

pub(crate) const ROLE_OWNED_CHIRHO: &str = "owned-chirho";
pub(crate) const ROLE_CONTRIBUTION_CHIRHO: &str = "contribution-chirho";
pub(crate) const NO_ACTOR_CHIRHO: &str = "no-actor-chirho";

/// One key attributed to one account's log, written before the key file exists. Its role says why:
/// OWNED, the account owns the key's subject (`container` is the account); or CONTRIBUTION, the account
/// wrote the key into a subject another owner holds (`actor` is the account, `container` is not). Role,
/// container and actor are signed with the rest, so the freeze extent binds them too (gpt #28945).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountAttributionRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub account_chirho: String,
    pub role_chirho: String,
    pub container_chirho: String,
    pub actor_chirho: String,
    pub subject_chirho: String,
    pub key_id_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

/// The one freeze of one account. After it, no new key may be attributed to the account. It also binds
/// the attribution EXTENT at freeze time: the row count and one digest over every row's signed message,
/// in order. So an inventory read later cannot come back shorter or different (gpt #28899): a deleted,
/// truncated, reordered or extended log no longer matches the freeze that names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountFreezeRecordChirho {
    pub schema_chirho: String,
    pub account_chirho: String,
    pub reason_chirho: String,
    pub attribution_count_chirho: u64,
    pub attribution_digest_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

const EXTENT_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-account-attribution-extent-v1-chirho";

/// One digest over every row's signed message, in order, each length-prefixed.
pub(crate) fn attribution_extent_digest_chirho<'a>(
    rows_chirho: impl Iterator<Item = &'a AccountAttributionRecordChirho>,
) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(EXTENT_DIGEST_DOMAIN_V1_CHIRHO);
    for row_chirho in rows_chirho {
        let message_chirho = row_chirho.message_chirho();
        hasher_chirho.update(&(message_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&message_chirho);
    }
    hasher_chirho.finalize().to_hex().to_string()
}

pub(crate) fn update_field_chirho(
    bytes_chirho: &mut Vec<u8>,
    label_chirho: &[u8],
    value_chirho: &[u8],
) {
    bytes_chirho.extend_from_slice(&(label_chirho.len() as u64).to_le_bytes());
    bytes_chirho.extend_from_slice(label_chirho);
    bytes_chirho.extend_from_slice(&(value_chirho.len() as u64).to_le_bytes());
    bytes_chirho.extend_from_slice(value_chirho);
}

impl AccountAttributionRecordChirho {
    /// The bytes the root signs: a domain, then every field but the signature, each length-prefixed.
    pub(crate) fn message_chirho(&self) -> Vec<u8> {
        let mut bytes_chirho = ATTRIBUTION_MESSAGE_DOMAIN_V1_CHIRHO.to_vec();
        update_field_chirho(&mut bytes_chirho, b"schema", self.schema_chirho.as_bytes());
        update_field_chirho(&mut bytes_chirho, b"seq", &self.seq_chirho.to_le_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"account",
            self.account_chirho.as_bytes(),
        );
        update_field_chirho(&mut bytes_chirho, b"role", self.role_chirho.as_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"container",
            self.container_chirho.as_bytes(),
        );
        update_field_chirho(&mut bytes_chirho, b"actor", self.actor_chirho.as_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"subject",
            self.subject_chirho.as_bytes(),
        );
        update_field_chirho(&mut bytes_chirho, b"key-id", self.key_id_chirho.as_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"at-ms",
            &self.at_ms_chirho.to_le_bytes(),
        );
        bytes_chirho
    }

    pub(crate) fn validate_chirho(&self) -> Result<()> {
        if self.schema_chirho != ATTRIBUTION_RECORD_SCHEMA_V1_CHIRHO
            || !is_lower_hex_chirho(&self.account_chirho, 64)
        {
            return Err(refuse_chirho(
                AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho,
                "the attribution row's schema or account is not in form",
            ));
        }
        // The one owner-label parser, so every container an admission can write also reads back.
        let container_ok_chirho =
            SubjectOwnerChirho::from_label_chirho(&self.container_chirho).is_ok();
        let actor_ok_chirho =
            self.actor_chirho == NO_ACTOR_CHIRHO || is_lower_hex_chirho(&self.actor_chirho, 64);
        // OWNED: this account holds the subject. CONTRIBUTION: this account wrote into another holder's.
        let role_ok_chirho = match self.role_chirho.as_str() {
            ROLE_OWNED_CHIRHO => self.container_chirho == self.account_chirho,
            ROLE_CONTRIBUTION_CHIRHO => {
                self.actor_chirho == self.account_chirho
                    && self.container_chirho != self.account_chirho
            }
            _ => false,
        };
        if !container_ok_chirho || !actor_ok_chirho || !role_ok_chirho {
            return Err(refuse_chirho(
                AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho,
                "the attribution row's role, container or actor is not in form",
            ));
        }
        validate_subject_and_key_id_chirho(&self.subject_chirho, &self.key_id_chirho)
    }
}

impl AccountFreezeRecordChirho {
    pub(crate) fn message_chirho(&self) -> Vec<u8> {
        let mut bytes_chirho = FREEZE_MESSAGE_DOMAIN_V1_CHIRHO.to_vec();
        update_field_chirho(&mut bytes_chirho, b"schema", self.schema_chirho.as_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"account",
            self.account_chirho.as_bytes(),
        );
        update_field_chirho(&mut bytes_chirho, b"reason", self.reason_chirho.as_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"attribution-count",
            &self.attribution_count_chirho.to_le_bytes(),
        );
        update_field_chirho(
            &mut bytes_chirho,
            b"attribution-digest",
            self.attribution_digest_chirho.as_bytes(),
        );
        update_field_chirho(
            &mut bytes_chirho,
            b"at-ms",
            &self.at_ms_chirho.to_le_bytes(),
        );
        bytes_chirho
    }

    pub(crate) fn validate_chirho(&self) -> Result<()> {
        if self.schema_chirho != FREEZE_RECORD_SCHEMA_V1_CHIRHO
            || !is_lower_hex_chirho(&self.account_chirho, 64)
            || !is_lower_hex_chirho(&self.attribution_digest_chirho, 64)
        {
            return Err(refuse_chirho(
                AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho,
                "the freeze record's schema or account is not in form",
            ));
        }
        validate_reason_chirho(&self.reason_chirho)
    }
}

/// The same short opaque-id charset as the root's privacy subjects.
pub(crate) fn validate_subject_chirho(subject_chirho: &str) -> Result<()> {
    let subject_ok_chirho = !subject_chirho.trim().is_empty()
        && subject_chirho.len() <= SUBJECT_MAX_BYTES_CHIRHO
        && subject_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        });
    if !subject_ok_chirho {
        return Err(refuse_chirho(
            AccountAttributionRefusalChirho::AttributionFieldInvalidChirho,
            "the subject or key id is not in form",
        ));
    }
    Ok(())
}

/// A subject in that charset, and a 16-byte key id in hex.
pub(crate) fn validate_subject_and_key_id_chirho(
    subject_chirho: &str,
    key_id_chirho: &str,
) -> Result<()> {
    validate_subject_chirho(subject_chirho)?;
    if !is_lower_hex_chirho(key_id_chirho, KEY_ID_HEX_BYTES_CHIRHO) {
        return Err(refuse_chirho(
            AccountAttributionRefusalChirho::AttributionFieldInvalidChirho,
            "the subject or key id is not in form",
        ));
    }
    Ok(())
}

/// A freeze reason is a short fixed label, never free text.
pub(crate) fn validate_reason_chirho(reason_chirho: &str) -> Result<()> {
    let ok_chirho = !reason_chirho.is_empty()
        && reason_chirho.len() <= REASON_MAX_BYTES_CHIRHO
        && reason_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase() || byte_chirho.is_ascii_digit() || byte_chirho == b'-'
        });
    if !ok_chirho {
        return Err(refuse_chirho(
            AccountAttributionRefusalChirho::AttributionFieldInvalidChirho,
            "the freeze reason is not a short lowercase label",
        ));
    }
    Ok(())
}
