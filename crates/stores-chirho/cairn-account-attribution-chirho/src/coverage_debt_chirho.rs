// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Root-scoped coverage debts: a closed set of debt kinds, each with a signed marker written the first time a key of that kind is admitted.
//!
//! A debt is data that no account's inventory lists but that some account's close may need (gpt #29035).
//! It is bound to SURVIVING SIGNED EVIDENCE: the subject of every debt-class key is owned by the debt
//! itself, in its root-signed owner record (`SubjectOwnerChirho::CoverageDebtChirho`, gpt #29054). The
//! marker is only a fast deny. Its presence proves the debt exists on this root; its absence proves
//! nothing, because a marker can be deleted while a debt-class key survives, so an account close must
//! still classify every surviving key. A missing directory reads as no markers; anything unreadable,
//! malformed, of an unknown kind, or not signed by this root refuses.

use crate::record_chirho::update_field_chirho;
use crate::store_chirho::{
    now_ms_chirho, unverified_chirho, verify_root_signature_chirho, ACCOUNT_ATTRIBUTION_DIR_CHIRHO,
    PRIVATE_FILE_MODE_CHIRHO,
};
use anyhow::Result;
use cairn_durable_chirho::{
    create_complete_file_durable_with_mode_chirho, read_identity_stable_bounded_regular_file_chirho,
};
use cairn_signer_chirho::signer_chirho::{existing_pubkey_hex_chirho, sign_message_chirho};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

pub const COVERAGE_DEBT_RECORD_SCHEMA_V1_CHIRHO: &str = "coverage-debt-record-v1-chirho";
const COVERAGE_DEBTS_DIR_CHIRHO: &str = "coverage-debts-chirho";
const COVERAGE_DEBT_MESSAGE_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-coverage-debt-record-v1-chirho";
const COVERAGE_DEBT_MAX_BYTES_CHIRHO: u64 = 4 * 1024;

/// The closed set of debt kinds. A new kind is added here, with its two fixed labels, only when a caller
/// proves one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoverageDebtChirho {
    /// Descriptor-D PostgreSQL evidence stored before per-account attribution exists (brick 2b-pg).
    PostgresEvidencePendingAttributionChirho,
}

impl CoverageDebtChirho {
    pub const ALL_CHIRHO: [Self; 1] = [Self::PostgresEvidencePendingAttributionChirho];

    /// The marker's name.
    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::PostgresEvidencePendingAttributionChirho => {
                "postgres-evidence-pending-attribution"
            }
        }
    }

    /// The owner label a debt-class subject's record and rows carry. It can never equal an account's
    /// 64-hex coordinate or the no-account label.
    pub fn owner_label_chirho(self) -> &'static str {
        match self {
            Self::PostgresEvidencePendingAttributionChirho => {
                "coverage-debt-postgres-evidence-pending-attribution-chirho"
            }
        }
    }

    pub fn from_label_chirho(label_chirho: &str) -> Option<Self> {
        Self::ALL_CHIRHO
            .into_iter()
            .find(|debt_chirho| debt_chirho.label_chirho() == label_chirho)
    }

    pub(crate) fn from_owner_label_chirho(label_chirho: &str) -> Option<Self> {
        Self::ALL_CHIRHO
            .into_iter()
            .find(|debt_chirho| debt_chirho.owner_label_chirho() == label_chirho)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDebtRecordChirho {
    pub schema_chirho: String,
    pub label_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

impl CoverageDebtRecordChirho {
    fn message_chirho(&self) -> Vec<u8> {
        let mut bytes_chirho = COVERAGE_DEBT_MESSAGE_DOMAIN_V1_CHIRHO.to_vec();
        update_field_chirho(&mut bytes_chirho, b"schema", self.schema_chirho.as_bytes());
        update_field_chirho(&mut bytes_chirho, b"label", self.label_chirho.as_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"at-ms",
            &self.at_ms_chirho.to_le_bytes(),
        );
        bytes_chirho
    }
}

fn debts_dir_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(COVERAGE_DEBTS_DIR_CHIRHO)
}

/// Record that this root carries the debt. Create-once: an existing marker stands. Admission calls this,
/// under the attribution lock, before it claims a debt-class key's subject.
pub(crate) fn record_coverage_debt_unlocked_chirho(
    root_chirho: &Path,
    debt_chirho: CoverageDebtChirho,
) -> Result<()> {
    let path_chirho =
        debts_dir_chirho(root_chirho).join(format!("{}.json", debt_chirho.label_chirho()));
    if path_chirho.exists() {
        return Ok(());
    }
    let mut record_chirho = CoverageDebtRecordChirho {
        schema_chirho: COVERAGE_DEBT_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        label_chirho: debt_chirho.label_chirho().to_string(),
        at_ms_chirho: now_ms_chirho(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(root_chirho, &record_chirho.message_chirho())?;
    // A concurrent writer's marker for the same debt is the same fact, so either outcome stands.
    create_complete_file_durable_with_mode_chirho(
        &path_chirho,
        &serde_json::to_vec(&record_chirho)?,
        PRIVATE_FILE_MODE_CHIRHO,
    )?;
    Ok(())
}

/// Every debt marker on this root, each verified, in kind order. A missing directory is the only empty.
/// An empty result is NOT proof that no debt-class key exists: see the module note.
pub fn coverage_debts_unlocked_chirho(root_chirho: &Path) -> Result<Vec<CoverageDebtChirho>> {
    let entries_chirho = match std::fs::read_dir(debts_dir_chirho(root_chirho)) {
        Ok(entries_chirho) => entries_chirho,
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
            return Ok(Vec::new())
        }
        Err(_) => return Err(unverified_chirho("the coverage debts cannot be listed")),
    };
    let mut debts_chirho = Vec::new();
    let mut pubkey_chirho: Option<String> = None;
    for entry_chirho in entries_chirho {
        let entry_chirho =
            entry_chirho.map_err(|_| unverified_chirho("a coverage debt entry cannot be read"))?;
        let name_chirho = entry_chirho.file_name().to_string_lossy().into_owned();
        let debt_chirho = name_chirho
            .strip_suffix(".json")
            .and_then(CoverageDebtChirho::from_label_chirho)
            .ok_or_else(|| {
                unverified_chirho("a coverage debt entry is not a known debt's marker")
            })?;
        let bytes_chirho = read_identity_stable_bounded_regular_file_chirho(
            &entry_chirho.path(),
            COVERAGE_DEBT_MAX_BYTES_CHIRHO,
        )
        .map_err(|_| unverified_chirho("a coverage debt marker is not a bounded regular file"))?;
        let record_chirho: CoverageDebtRecordChirho = serde_json::from_slice(&bytes_chirho)
            .map_err(|_| unverified_chirho("a coverage debt marker does not parse"))?;
        if record_chirho.schema_chirho != COVERAGE_DEBT_RECORD_SCHEMA_V1_CHIRHO
            || record_chirho.label_chirho != debt_chirho.label_chirho()
        {
            return Err(unverified_chirho(
                "a coverage debt marker is not in form for its name",
            ));
        }
        if pubkey_chirho.is_none() {
            pubkey_chirho = Some(
                existing_pubkey_hex_chirho(root_chirho)
                    .map_err(|_| unverified_chirho("the root has no existing signing key"))?,
            );
        }
        verify_root_signature_chirho(
            pubkey_chirho.as_deref().unwrap_or_default(),
            &record_chirho.message_chirho(),
            &record_chirho.sig_chirho,
        )?;
        debts_chirho.push(debt_chirho);
    }
    debts_chirho.sort();
    Ok(debts_chirho)
}
