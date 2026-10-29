// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The per-account attribution log and freeze file on disk: append under the attribution lock, freeze once, and read a verified inventory only after the freeze.
//!
//! Layout: `<root>/privacy-account-attribution-chirho/<account>/attribution-chirho.jsonl` and
//! `freeze-chirho.json`. Each account's log grows only with that account's private writes, so an append is
//! O(1) through the seqlog head sidecar and an inventory is O(that account's rows), never O(all history).
//! Rows and the freeze are signed by the root's instance key. Reads verify with the EXISTING public key,
//! which never mints one, and accept a signature only when verification returns `Ok(true)`.

use crate::coordinate_chirho::AccountCoordinateChirho;
use crate::record_chirho::{
    attribution_extent_digest_chirho, validate_reason_chirho, validate_subject_and_key_id_chirho,
    AccountAttributionRecordChirho, AccountFreezeRecordChirho, ATTRIBUTION_RECORD_SCHEMA_V1_CHIRHO,
    FREEZE_RECORD_SCHEMA_V1_CHIRHO, NO_ACTOR_CHIRHO, ROLE_CONTRIBUTION_CHIRHO, ROLE_OWNED_CHIRHO,
};
use crate::refusal_chirho::{refuse_chirho, AccountAttributionRefusalChirho};
use crate::subject_owner_chirho::SubjectOwnerChirho;
use anyhow::Result;
use cairn_durable_chirho::{
    create_complete_file_durable_with_mode_chirho,
    read_identity_stable_bounded_regular_file_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use cairn_seqlog_chirho::seqlog_chirho::{
    append_recovered_jsonl_unlocked_chirho, recover_jsonl_len_unlocked_chirho,
    with_named_lock_chirho,
};
use cairn_signer_chirho::signer_chirho::{
    existing_pubkey_hex_chirho, sign_message_chirho, verify_with_pubkey_chirho,
};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ACCOUNT_ATTRIBUTION_DIR_CHIRHO: &str = "privacy-account-attribution-chirho";
/// Its place in the root's lock order: after subject-rights and append-log, before blob-records and
/// erasure-records. No path may take it and then take subject-rights or append-log.
pub const ACCOUNT_ATTRIBUTION_LOCK_CHIRHO: &str = "privacy-account-attribution-chirho";
const ATTRIBUTION_LOG_FILE_CHIRHO: &str = "attribution-chirho.jsonl";
const FREEZE_FILE_CHIRHO: &str = "freeze-chirho.json";
const FREEZE_MAX_BYTES_CHIRHO: u64 = 4 * 1024;
pub(crate) const PRIVATE_FILE_MODE_CHIRHO: u32 = 0o600;

/// Run `action_chirho` while holding the attribution lock.
pub fn with_account_attribution_lock_chirho<T>(
    root_chirho: &Path,
    action_chirho: impl FnOnce() -> Result<T>,
) -> Result<T> {
    with_named_lock_chirho(root_chirho, ACCOUNT_ATTRIBUTION_LOCK_CHIRHO, action_chirho)
}

fn account_dir_chirho(root_chirho: &Path, account_chirho: &AccountCoordinateChirho) -> PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(account_chirho.as_hex_chirho())
}

pub(crate) fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed_chirho| elapsed_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn unverified_chirho(detail_chirho: &'static str) -> anyhow::Error {
    refuse_chirho(
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho,
        detail_chirho,
    )
}

/// Accept a root signature only on `Ok(true)`; `Ok(false)` and `Err` both refuse.
pub(crate) fn verify_root_signature_chirho(
    pubkey_chirho: &str,
    message_chirho: &[u8],
    sig_chirho: &str,
) -> Result<()> {
    match verify_with_pubkey_chirho(pubkey_chirho, message_chirho, sig_chirho) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(unverified_chirho("a record's signature does not verify")),
    }
}

/// A freeze record this root signed for this exact account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccountFreezeChirho {
    record_chirho: AccountFreezeRecordChirho,
}

impl VerifiedAccountFreezeChirho {
    pub fn record_chirho(&self) -> &AccountFreezeRecordChirho {
        &self.record_chirho
    }
}

/// The account's freeze, if it has one. Absence is `None`; anything else that is not a verified freeze
/// for this account refuses, so a corrupt or substituted freeze file never reads as "not frozen".
pub fn account_freeze_unlocked_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
) -> Result<Option<VerifiedAccountFreezeChirho>> {
    let path_chirho = account_dir_chirho(root_chirho, account_chirho).join(FREEZE_FILE_CHIRHO);
    let bytes_chirho = match read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        FREEZE_MAX_BYTES_CHIRHO,
    ) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(unverified_chirho(
                "the freeze file is not a bounded single regular file",
            ))
        }
    };
    let record_chirho: AccountFreezeRecordChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_| unverified_chirho("the freeze file does not parse"))?;
    record_chirho.validate_chirho()?;
    if record_chirho.account_chirho != account_chirho.as_hex_chirho() {
        return Err(unverified_chirho("the freeze file names another account"));
    }
    let pubkey_chirho = existing_pubkey_hex_chirho(root_chirho)
        .map_err(|_| unverified_chirho("the root has no existing signing key"))?;
    verify_root_signature_chirho(
        &pubkey_chirho,
        &record_chirho.message_chirho(),
        &record_chirho.sig_chirho,
    )?;
    Ok(Some(VerifiedAccountFreezeChirho { record_chirho }))
}

/// Refuse with `AccountFrozenChirho` when the account is frozen. It is also safe WITHOUT the lock, as an
/// early check that only spares work: a freeze is published by an atomic no-replace rename, so an
/// unlocked read sees no freeze or a complete one. The decision that counts is the re-check that
/// `append_account_attribution_unlocked_chirho` makes under the lock.
pub fn refuse_if_account_frozen_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
) -> Result<()> {
    if account_freeze_unlocked_chirho(root_chirho, account_chirho)?.is_some() {
        return Err(refuse_chirho(
            AccountAttributionRefusalChirho::AccountFrozenChirho,
            "a frozen account takes no new key",
        ));
    }
    Ok(())
}

/// Append one signed OWNED row, written by the account itself, for a key that does not exist yet. The
/// caller holds the attribution lock and writes the key file only after this returns. Refuses for a
/// frozen account. The key-creation path uses `admit_private_key_unlocked_chirho`, which also claims
/// the subject and records a different actor; this is the plain owned row it builds on.
pub fn append_account_attribution_unlocked_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
    subject_chirho: &str,
    key_id_chirho: &str,
) -> Result<AccountAttributionRecordChirho> {
    refuse_if_account_frozen_chirho(root_chirho, account_chirho)?;
    append_attribution_row_unlocked_chirho(
        root_chirho,
        account_chirho,
        AttributionRowChirho {
            role_chirho: ROLE_OWNED_CHIRHO,
            container_chirho: account_chirho.as_hex_chirho(),
            actor_chirho: account_chirho.as_hex_chirho(),
            subject_chirho,
            key_id_chirho,
        },
    )
}

/// What one row says, apart from the log it lands in and its sequence.
pub(crate) struct AttributionRowChirho<'a> {
    pub(crate) role_chirho: &'static str,
    pub(crate) container_chirho: &'a str,
    pub(crate) actor_chirho: &'a str,
    pub(crate) subject_chirho: &'a str,
    pub(crate) key_id_chirho: &'a str,
}

/// Sign and durably append one row to `account_chirho`'s log; the row is validated as it would be read.
pub(crate) fn append_attribution_row_unlocked_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
    row_chirho: AttributionRowChirho<'_>,
) -> Result<AccountAttributionRecordChirho> {
    validate_subject_and_key_id_chirho(row_chirho.subject_chirho, row_chirho.key_id_chirho)?;
    let dir_chirho = account_dir_chirho(root_chirho, account_chirho);
    std::fs::create_dir_all(&dir_chirho)
        .map_err(|_| unverified_chirho("the account's attribution directory cannot be created"))?;
    let path_chirho = dir_chirho.join(ATTRIBUTION_LOG_FILE_CHIRHO);
    let seq_chirho = recover_jsonl_len_unlocked_chirho(&path_chirho)?;
    let mut record_chirho = AccountAttributionRecordChirho {
        schema_chirho: ATTRIBUTION_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        seq_chirho,
        account_chirho: account_chirho.as_hex_chirho().to_string(),
        role_chirho: row_chirho.role_chirho.to_string(),
        container_chirho: row_chirho.container_chirho.to_string(),
        actor_chirho: row_chirho.actor_chirho.to_string(),
        subject_chirho: row_chirho.subject_chirho.to_string(),
        key_id_chirho: row_chirho.key_id_chirho.to_string(),
        at_ms_chirho: now_ms_chirho(),
        sig_chirho: String::new(),
    };
    record_chirho.validate_chirho()?;
    record_chirho.sig_chirho = sign_message_chirho(root_chirho, &record_chirho.message_chirho())?;
    append_recovered_jsonl_unlocked_chirho(&path_chirho, seq_chirho, &record_chirho)?;
    Ok(record_chirho)
}

/// Freeze the account, once. A second call returns the existing verified freeze, so a retried account
/// close is idempotent. The caller holds the attribution lock.
pub fn freeze_account_unlocked_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
    reason_chirho: &str,
) -> Result<VerifiedAccountFreezeChirho> {
    validate_reason_chirho(reason_chirho)?;
    if let Some(existing_chirho) = account_freeze_unlocked_chirho(root_chirho, account_chirho)? {
        return Ok(existing_chirho);
    }
    // The extent is read and verified under the same lock that orders every append, so no row can land
    // between this read and the freeze that binds it.
    let rows_chirho = read_verified_rows_unlocked_chirho(root_chirho, account_chirho)?;
    let mut record_chirho = AccountFreezeRecordChirho {
        schema_chirho: FREEZE_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        account_chirho: account_chirho.as_hex_chirho().to_string(),
        reason_chirho: reason_chirho.to_string(),
        attribution_count_chirho: rows_chirho.len() as u64,
        attribution_digest_chirho: attribution_extent_digest_chirho(rows_chirho.iter()),
        at_ms_chirho: now_ms_chirho(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(root_chirho, &record_chirho.message_chirho())?;
    let path_chirho = account_dir_chirho(root_chirho, account_chirho).join(FREEZE_FILE_CHIRHO);
    let bytes_chirho = serde_json::to_vec(&record_chirho)?;
    match create_complete_file_durable_with_mode_chirho(
        &path_chirho,
        &bytes_chirho,
        PRIVATE_FILE_MODE_CHIRHO,
    )? {
        CreateFileDurableOutcomeChirho::CreatedChirho => {
            Ok(VerifiedAccountFreezeChirho { record_chirho })
        }
        CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
            account_freeze_unlocked_chirho(root_chirho, account_chirho)?
                .ok_or_else(|| unverified_chirho("a freeze appeared and then vanished"))
        }
    }
}

/// Why a key is in an account's inventory. An R3 close treats the two differently (gpt #28945): only an
/// OWNED subject may go to the canonical subject erasure, and a CONTRIBUTION is coverage the close
/// cannot claim until a reviewed disposition resolves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttributionRoleChirho {
    /// The account owns the key's subject. `actor_chirho` is who wrote the key, when an account did.
    OwnedChirho {
        actor_chirho: Option<AccountCoordinateChirho>,
    },
    /// The account wrote the key into a subject `container_chirho` holds.
    ContributionChirho {
        container_chirho: SubjectOwnerChirho,
    },
}

/// One attributed key in an account's verified inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountInventoryEntryChirho {
    pub seq_chirho: u64,
    pub subject_chirho: String,
    pub key_id_chirho: String,
    pub role_chirho: AttributionRoleChirho,
}

/// An account's verified attribution as it stands: every row verified, and, when the account is
/// frozen, the whole log equal to the extent the freeze bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccountSnapshotChirho {
    freeze_chirho: Option<VerifiedAccountFreezeChirho>,
    entries_chirho: Vec<AccountInventoryEntryChirho>,
}

impl VerifiedAccountSnapshotChirho {
    pub fn freeze_chirho(&self) -> Option<&VerifiedAccountFreezeChirho> {
        self.freeze_chirho.as_ref()
    }

    pub fn entries_chirho(&self) -> &[AccountInventoryEntryChirho] {
        &self.entries_chirho
    }
}

/// A frozen account's complete, verified attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccountInventoryChirho {
    freeze_chirho: VerifiedAccountFreezeChirho,
    entries_chirho: Vec<AccountInventoryEntryChirho>,
}

impl VerifiedAccountInventoryChirho {
    pub fn freeze_chirho(&self) -> &VerifiedAccountFreezeChirho {
        &self.freeze_chirho
    }

    pub fn entries_chirho(&self) -> &[AccountInventoryEntryChirho] {
        &self.entries_chirho
    }
}

/// Read an account's attribution as it stands, frozen or not: the preflight an R3 close takes BEFORE it
/// freezes, so a close it must refuse never leaves the account frozen (gpt #28945). It is complete for the
/// moment it is read because the caller holds the attribution lock, and nothing can change it until the
/// caller releases that lock or freezes. A frozen account's log must also equal the extent its freeze
/// bound. It WRITES NOTHING (gpt #29003): a torn tail is refused, never recovered, so a refused close
/// leaves the log and every sidecar byte-identical; repair belongs to the paths that hold authority to
/// write, an admission or the freeze itself.
pub fn account_attribution_snapshot_unlocked_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
) -> Result<VerifiedAccountSnapshotChirho> {
    let freeze_chirho = account_freeze_unlocked_chirho(root_chirho, account_chirho)?;
    let rows_chirho = read_verified_rows_without_repair_chirho(root_chirho, account_chirho)?;
    if let Some(freeze_chirho) = &freeze_chirho {
        let frozen_chirho = freeze_chirho.record_chirho();
        if rows_chirho.len() as u64 != frozen_chirho.attribution_count_chirho
            || attribution_extent_digest_chirho(rows_chirho.iter())
                != frozen_chirho.attribution_digest_chirho
        {
            return Err(unverified_chirho(
                "the attribution log does not match the extent its freeze bound",
            ));
        }
    }
    let entries_chirho = rows_chirho
        .into_iter()
        .map(inventory_entry_chirho)
        .collect::<Result<Vec<_>>>()?;
    Ok(VerifiedAccountSnapshotChirho {
        freeze_chirho,
        entries_chirho,
    })
}

/// Read a frozen account's attribution: every row verified, and the whole log equal to the extent the
/// freeze bound. Refuses for an account that is not frozen, and for a log the freeze does not describe:
/// deleted, truncated, reordered or extended. The caller holds the attribution lock.
pub fn frozen_account_inventory_unlocked_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
) -> Result<VerifiedAccountInventoryChirho> {
    let snapshot_chirho =
        account_attribution_snapshot_unlocked_chirho(root_chirho, account_chirho)?;
    let freeze_chirho = snapshot_chirho.freeze_chirho.ok_or_else(|| {
        refuse_chirho(
            AccountAttributionRefusalChirho::AccountNotFrozenChirho,
            "freeze the account before reading its inventory",
        )
    })?;
    Ok(VerifiedAccountInventoryChirho {
        freeze_chirho,
        entries_chirho: snapshot_chirho.entries_chirho,
    })
}

/// A verified row as an inventory entry; its role, container and actor were validated on read.
fn inventory_entry_chirho(
    row_chirho: AccountAttributionRecordChirho,
) -> Result<AccountInventoryEntryChirho> {
    let role_chirho = if row_chirho.role_chirho == ROLE_CONTRIBUTION_CHIRHO {
        AttributionRoleChirho::ContributionChirho {
            container_chirho: SubjectOwnerChirho::from_label_chirho(&row_chirho.container_chirho)?,
        }
    } else if row_chirho.actor_chirho == NO_ACTOR_CHIRHO {
        AttributionRoleChirho::OwnedChirho { actor_chirho: None }
    } else {
        AttributionRoleChirho::OwnedChirho {
            actor_chirho: Some(AccountCoordinateChirho::from_hex_chirho(
                &row_chirho.actor_chirho,
            )?),
        }
    };
    Ok(AccountInventoryEntryChirho {
        seq_chirho: row_chirho.seq_chirho,
        subject_chirho: row_chirho.subject_chirho,
        key_id_chirho: row_chirho.key_id_chirho,
        role_chirho,
    })
}

/// Every row of the account's log, verified, WITHOUT any write: a log whose last line is torn refuses
/// rather than being recovered. The caller holds the lock.
fn read_verified_rows_without_repair_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
) -> Result<Vec<AccountAttributionRecordChirho>> {
    let path_chirho =
        account_dir_chirho(root_chirho, account_chirho).join(ATTRIBUTION_LOG_FILE_CHIRHO);
    let text_chirho = read_log_text_chirho(&path_chirho)
        .map_err(|_| unverified_chirho("the attribution log cannot be examined"))?
        .unwrap_or_default();
    if !text_chirho.is_empty() && !text_chirho.ends_with('\n') {
        return Err(unverified_chirho(
            "the attribution log has a torn tail, which a snapshot does not repair",
        ));
    }
    verify_rows_chirho(root_chirho, account_chirho, &text_chirho)
}

/// Every row of the account's log, verified: the schema and fields, a dense seq from 0, this account on
/// every row, and this root's signature; a torn final line is recovered first. The caller holds the lock
/// and the authority to write: an admission or a freeze.
fn read_verified_rows_unlocked_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
) -> Result<Vec<AccountAttributionRecordChirho>> {
    let path_chirho =
        account_dir_chirho(root_chirho, account_chirho).join(ATTRIBUTION_LOG_FILE_CHIRHO);
    let recovered_len_chirho = recover_jsonl_len_unlocked_chirho(&path_chirho)?;
    let text_chirho = read_log_text_chirho(&path_chirho)?.unwrap_or_default();
    let rows_chirho = verify_rows_chirho(root_chirho, account_chirho, &text_chirho)?;
    if rows_chirho.len() as u64 != recovered_len_chirho {
        return Err(unverified_chirho(
            "the attribution log's rows do not match its recovered length",
        ));
    }
    Ok(rows_chirho)
}

/// Parse and verify every line of one account's log text.
fn verify_rows_chirho(
    root_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
    text_chirho: &str,
) -> Result<Vec<AccountAttributionRecordChirho>> {
    let pubkey_chirho = if text_chirho.is_empty() {
        String::new()
    } else {
        existing_pubkey_hex_chirho(root_chirho)
            .map_err(|_| unverified_chirho("the root has no existing signing key"))?
    };
    let mut rows_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        let record_chirho: AccountAttributionRecordChirho = serde_json::from_str(line_chirho)
            .map_err(|_| unverified_chirho("an attribution row does not parse"))?;
        record_chirho.validate_chirho()?;
        if record_chirho.seq_chirho != index_chirho as u64 {
            return Err(unverified_chirho("an attribution row is out of sequence"));
        }
        if record_chirho.account_chirho != account_chirho.as_hex_chirho() {
            return Err(unverified_chirho(
                "an attribution row names another account",
            ));
        }
        verify_root_signature_chirho(
            &pubkey_chirho,
            &record_chirho.message_chirho(),
            &record_chirho.sig_chirho,
        )?;
        rows_chirho.push(record_chirho);
    }
    Ok(rows_chirho)
}
