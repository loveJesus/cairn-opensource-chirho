// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Customer mailbox/alias provisioning records, PII-safe: a mailbox local-part (and an alias target) can be a person's name, so the plaintext lives in a subject-bound private blob (crypto-shreddable) and the signed log carries only the public domain, a root-keyed blind index, and safe metadata.
//!
//! LOCAL foundation only. Creating the mailbox/alias on a live mail provider (e.g. Mailu) is a
//! separate, operator-gated blessed effect — this module never touches a provider. Latest record
//! per (domain, local-part hash) is the desired state; removal unbinds; history stays for audit.

use crate::{cas_chirho, privacy_chirho, seqlog_chirho};
use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAILBOX_RECORD_SCHEMA_V1_CHIRHO: &str = "mailbox-record-v1-chirho";
const MAILBOX_RECORD_SCHEMA_CHIRHO: &str = "mailbox-record-v2-chirho";
const MAILBOX_HASH_SCHEME_V1_CHIRHO: &str = "subject-salted-blake3-v1-chirho";
const MAILBOX_HASH_SCHEME_CHIRHO: &str = "root-private-blake3-keyed-v2-chirho";
const MAILBOX_INDEX_VERIFICATION_LEGACY_CHIRHO: &str = "legacy-v1-readable-chirho";
const MAILBOX_INDEX_VERIFICATION_VERIFIED_CHIRHO: &str = "verified-chirho";
const MAILBOX_INDEX_VERIFICATION_POST_ERASURE_CHIRHO: &str =
    "index-unverifiable-post-erasure-chirho";
const LOCAL_PART_MAX_LEN_CHIRHO: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxKindChirho {
    MailboxChirho,
    AliasChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxStatusChirho {
    ActiveChirho,
    RemovedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub owner_principal_chirho: String,
    pub domain_chirho: String,
    /// Root-private keyed blind index of the normalized local-part — lets the platform check
    /// existence and dedup without exposing an offline-dictionary target.
    pub local_part_hash_chirho: String,
    #[serde(
        default = "legacy_hash_scheme_chirho",
        skip_serializing_if = "is_legacy_hash_scheme_chirho"
    )]
    pub hash_scheme_chirho: String,
    /// The encrypted local-part plaintext (subject-bound private blob; crypto-shreddable).
    pub local_part_ref_chirho: privacy_chirho::PrivateBlobRefChirho,
    pub kind_chirho: MailboxKindChirho,
    /// For aliases, the encrypted forwarding target (subject-bound private blob).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_target_ref_chirho: Option<privacy_chirho::PrivateBlobRefChirho>,
    pub status_chirho: MailboxStatusChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub struct MailboxInputChirho {
    pub owner_principal_chirho: String,
    pub domain_chirho: String,
    pub local_part_chirho: String,
    pub kind_chirho: MailboxKindChirho,
    pub alias_target_chirho: Option<String>,
    pub status_chirho: MailboxStatusChirho,
}

/// One safe, PII-free row for listing — never carries the local-part or target plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxSafeRowChirho {
    pub seq_chirho: u64,
    pub domain_chirho: String,
    pub local_part_hash_chirho: String,
    pub hash_scheme_chirho: String,
    pub index_verification_chirho: String,
    pub kind_chirho: MailboxKindChirho,
    pub status_chirho: MailboxStatusChirho,
    pub live_chirho: bool,
    pub at_ms_chirho: u64,
    pub plaintext_included_chirho: bool,
}

fn mailboxes_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("mailboxes-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn jsonl_len_chirho(path_chirho: &Path) -> Result<u64> {
    if !path_chirho.exists() {
        return Ok(0);
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(text_chirho
        .lines()
        .filter(|l_chirho| !l_chirho.trim().is_empty())
        .count() as u64)
}

/// Per-owner, per-domain subject namespace for the private blobs (drives access + crypto-shred).
fn mailbox_subject_chirho(owner_principal_chirho: &str, domain_chirho: &str) -> String {
    let owner_hash_chirho = cas_chirho::hash_chirho(owner_principal_chirho.as_bytes());
    format!("mailbox/{}/{}", domain_chirho, &owner_hash_chirho.0[..24])
}

fn legacy_hash_scheme_chirho() -> String {
    MAILBOX_HASH_SCHEME_V1_CHIRHO.to_string()
}

fn is_legacy_hash_scheme_chirho(hash_scheme_chirho: &String) -> bool {
    hash_scheme_chirho == MAILBOX_HASH_SCHEME_V1_CHIRHO
}

fn local_part_hash_input_chirho(
    subject_chirho: &str,
    normalized_local_part_chirho: &str,
) -> Vec<u8> {
    let mut salted_chirho = subject_chirho.as_bytes().to_vec();
    salted_chirho.push(b':');
    salted_chirho.extend_from_slice(normalized_local_part_chirho.as_bytes());
    salted_chirho
}

/// Legacy v1 subject-salted hash, kept only so old rows can remain readable and labeled.
#[cfg(test)]
fn legacy_local_part_hash_chirho(
    subject_chirho: &str,
    normalized_local_part_chirho: &str,
) -> String {
    cas_chirho::hash_chirho(&local_part_hash_input_chirho(
        subject_chirho,
        normalized_local_part_chirho,
    ))
    .0
}

/// The keyed-hash key for the mailbox local-part index.
///
/// Lives here rather than in the runtime's `effect_chirho` because it is a MAILBOX fact: the whole
/// function is one domain constant bound to a generic derivation, and its only consumer is this
/// module. It reaches `cairn_signer_chirho` directly, which is where key derivation belongs and is
/// outside this pillar, so nothing about mail now depends on the execution runtime.
fn mailbox_local_part_index_key_chirho(root_chirho: &Path) -> Result<[u8; 32]> {
    signer_chirho::derive_instance_key_chirho(
        root_chirho,
        "cairn-mailbox-local-part-index-v1-chirho",
    )
}

/// Root-keyed blind index of the normalized local-part.
fn local_part_hash_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    normalized_local_part_chirho: &str,
) -> Result<String> {
    let key_chirho = mailbox_local_part_index_key_chirho(root_chirho)?;
    Ok(blake3::keyed_hash(
        &key_chirho,
        &local_part_hash_input_chirho(subject_chirho, normalized_local_part_chirho),
    )
    .to_hex()
    .to_string())
}

fn normalize_local_part_chirho(local_part_chirho: &str) -> String {
    local_part_chirho.trim().to_ascii_lowercase()
}

fn validate_local_part_chirho(local_part_chirho: &str) -> Result<()> {
    let normalized_chirho = normalize_local_part_chirho(local_part_chirho);
    if normalized_chirho.is_empty() || normalized_chirho.len() > LOCAL_PART_MAX_LEN_CHIRHO {
        bail!("mailbox local-part must be 1..={LOCAL_PART_MAX_LEN_CHIRHO} chars");
    }
    if normalized_chirho.starts_with('.') || normalized_chirho.ends_with('.') {
        bail!("mailbox local-part must not start or end with '.'");
    }
    if !normalized_chirho.chars().all(|c_chirho| {
        c_chirho.is_ascii_lowercase()
            || c_chirho.is_ascii_digit()
            || matches!(c_chirho, '.' | '_' | '+' | '-')
    }) {
        bail!("mailbox local-part may contain only a-z, 0-9, '.', '_', '+', '-'");
    }
    Ok(())
}

fn mailbox_message_chirho(record_chirho: &MailboxRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn validate_input_chirho(input_chirho: &MailboxInputChirho) -> Result<()> {
    if input_chirho.owner_principal_chirho.trim().is_empty() {
        bail!("mailbox owner principal must not be empty");
    }
    crate::dns_zone_chirho::validate_zone_domain_chirho(&input_chirho.domain_chirho)?;
    validate_local_part_chirho(&input_chirho.local_part_chirho)?;
    match input_chirho.kind_chirho {
        MailboxKindChirho::AliasChirho => {
            let target_chirho = input_chirho
                .alias_target_chirho
                .as_deref()
                .unwrap_or("")
                .trim();
            if target_chirho.is_empty() || target_chirho.len() > 320 || !target_chirho.contains('@')
            {
                bail!("an alias requires a target email address");
            }
        }
        MailboxKindChirho::MailboxChirho => {
            if input_chirho.alias_target_chirho.is_some() {
                bail!("a mailbox must not carry an alias target");
            }
        }
    }
    Ok(())
}

/// Append one signed mailbox/alias record, sealing the local-part (and alias target) plaintext into
/// subject-bound private blobs so no address plaintext ever enters the signed log.
pub fn emit_mailbox_chirho(
    root_chirho: &Path,
    input_chirho: MailboxInputChirho,
) -> Result<MailboxRecordChirho> {
    validate_input_chirho(&input_chirho)?;
    let subject_chirho = mailbox_subject_chirho(
        &input_chirho.owner_principal_chirho,
        &input_chirho.domain_chirho,
    );
    let normalized_chirho = normalize_local_part_chirho(&input_chirho.local_part_chirho);
    let hash_chirho = local_part_hash_chirho(root_chirho, &subject_chirho, &normalized_chirho)?;

    // Both the local part and an alias target are the owner's own data (gpt #28874): their keys join the
    // owner's account. Lock order: append-log -> account-attribution, inside the chokepoint.
    let attribution_chirho = privacy_chirho::PrivateBlobAttributionChirho::account_owned_chirho(
        &input_chirho.owner_principal_chirho,
    )?;
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let local_part_ref_chirho = privacy_chirho::store_private_blob_chirho(
            root_chirho,
            &attribution_chirho,
            &subject_chirho,
            input_chirho.local_part_chirho.trim().as_bytes(),
        )?;
        let alias_target_ref_chirho =
            match (&input_chirho.kind_chirho, &input_chirho.alias_target_chirho) {
                (MailboxKindChirho::AliasChirho, Some(target_chirho)) => {
                    Some(privacy_chirho::store_private_blob_chirho(
                        root_chirho,
                        &attribution_chirho,
                        &subject_chirho,
                        target_chirho.trim().as_bytes(),
                    )?)
                }
                _ => None,
            };
        let path_chirho = mailboxes_path_chirho(root_chirho);
        let mut record_chirho = MailboxRecordChirho {
            schema_chirho: MAILBOX_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: jsonl_len_chirho(&path_chirho)?,
            owner_principal_chirho: input_chirho.owner_principal_chirho.clone(),
            domain_chirho: input_chirho.domain_chirho.clone(),
            local_part_hash_chirho: hash_chirho.clone(),
            hash_scheme_chirho: MAILBOX_HASH_SCHEME_CHIRHO.to_string(),
            local_part_ref_chirho,
            kind_chirho: input_chirho.kind_chirho.clone(),
            alias_target_ref_chirho,
            status_chirho: input_chirho.status_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &mailbox_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

pub fn load_mailbox_records_chirho(root_chirho: &Path) -> Result<Vec<MailboxRecordChirho>> {
    let path_chirho = mailboxes_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho
        .lines()
        .filter(|l_chirho| !l_chirho.trim().is_empty())
    {
        records_chirho.push(serde_json::from_str(line_chirho).context("parse mailbox record")?);
    }
    Ok(records_chirho)
}

fn local_part_index_verification_chirho(
    root_chirho: &Path,
    record_chirho: &MailboxRecordChirho,
    subject_chirho: &str,
) -> Result<String> {
    match record_chirho.schema_chirho.as_str() {
        MAILBOX_RECORD_SCHEMA_V1_CHIRHO => {
            if record_chirho.hash_scheme_chirho != MAILBOX_HASH_SCHEME_V1_CHIRHO {
                bail!(
                    "mailbox record {} legacy schema has unsupported hash scheme '{}'",
                    record_chirho.seq_chirho,
                    record_chirho.hash_scheme_chirho
                );
            }
            Ok(MAILBOX_INDEX_VERIFICATION_LEGACY_CHIRHO.to_string())
        }
        MAILBOX_RECORD_SCHEMA_CHIRHO => {
            if record_chirho.hash_scheme_chirho != MAILBOX_HASH_SCHEME_CHIRHO {
                bail!(
                    "mailbox record {} v2 schema has unsupported hash scheme '{}'",
                    record_chirho.seq_chirho,
                    record_chirho.hash_scheme_chirho
                );
            }
            match privacy_chirho::private_blob_key_subject_chirho(
                root_chirho,
                &record_chirho.local_part_ref_chirho.key_id_chirho,
            )? {
                None => return Ok(MAILBOX_INDEX_VERIFICATION_POST_ERASURE_CHIRHO.to_string()),
                Some(key_subject_chirho) if key_subject_chirho != subject_chirho => bail!(
                    "mailbox record {} local-part key belongs to subject '{}', not '{}'",
                    record_chirho.seq_chirho,
                    key_subject_chirho,
                    subject_chirho
                ),
                Some(_) => {}
            }
            let local_part_bytes_chirho = privacy_chirho::load_private_blob_chirho(
                root_chirho,
                &record_chirho.local_part_ref_chirho,
            )
            .context("load mailbox local-part for blind-index verification")?;
            let local_part_chirho = std::str::from_utf8(&local_part_bytes_chirho)
                .context("mailbox local-part private blob must be utf-8")?;
            validate_local_part_chirho(local_part_chirho)?;
            let normalized_chirho = normalize_local_part_chirho(local_part_chirho);
            let expected_chirho =
                local_part_hash_chirho(root_chirho, subject_chirho, &normalized_chirho)?;
            if record_chirho.local_part_hash_chirho != expected_chirho {
                bail!(
                    "mailbox record {} local-part blind index mismatch",
                    record_chirho.seq_chirho
                );
            }
            Ok(MAILBOX_INDEX_VERIFICATION_VERIFIED_CHIRHO.to_string())
        }
        _ => bail!(
            "mailbox record {} schema mismatch",
            record_chirho.seq_chirho
        ),
    }
}

/// Fail-closed verification: seq contiguity, schema, domain/hash validity, signature, v2 blind-index
/// derivation, and that each private blob ref is bound to this record's owner+domain subject.
pub fn verify_mailbox_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_mailbox_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "mailbox seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.schema_chirho != MAILBOX_RECORD_SCHEMA_CHIRHO
            && record_chirho.schema_chirho != MAILBOX_RECORD_SCHEMA_V1_CHIRHO
        {
            bail!(
                "mailbox record {} schema mismatch",
                record_chirho.seq_chirho
            );
        }
        crate::dns_zone_chirho::validate_zone_domain_chirho(&record_chirho.domain_chirho)?;
        if record_chirho.local_part_hash_chirho.len() != 64
            || !record_chirho
                .local_part_hash_chirho
                .chars()
                .all(|c_chirho| c_chirho.is_ascii_hexdigit())
        {
            bail!(
                "mailbox record {} has a malformed local-part hash",
                record_chirho.seq_chirho
            );
        }
        let subject_chirho = mailbox_subject_chirho(
            &record_chirho.owner_principal_chirho,
            &record_chirho.domain_chirho,
        );
        privacy_chirho::verify_private_blob_ref_subject_chirho(
            root_chirho,
            "mailbox local-part",
            &record_chirho.local_part_ref_chirho,
            &subject_chirho,
        )?;
        if let Some(target_ref_chirho) = &record_chirho.alias_target_ref_chirho {
            privacy_chirho::verify_private_blob_ref_subject_chirho(
                root_chirho,
                "mailbox alias target",
                target_ref_chirho,
                &subject_chirho,
            )?;
        }
        local_part_index_verification_chirho(root_chirho, record_chirho, &subject_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &mailbox_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "mailbox record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

pub fn verified_mailbox_records_chirho(root_chirho: &Path) -> Result<Vec<MailboxRecordChirho>> {
    verify_mailbox_records_chirho(root_chirho)?;
    load_mailbox_records_chirho(root_chirho)
}

/// Owner-scoped safe rows (no plaintext): latest record per (domain, local-part hash) marks live.
pub fn mailbox_safe_rows_for_owner_chirho(
    root_chirho: &Path,
    owner_principal_chirho: &str,
) -> Result<Vec<MailboxSafeRowChirho>> {
    let records_chirho = verified_mailbox_records_chirho(root_chirho)?;
    let mut latest_seq_chirho: std::collections::BTreeMap<(String, String), u64> =
        std::collections::BTreeMap::new();
    for record_chirho in &records_chirho {
        if record_chirho.owner_principal_chirho != owner_principal_chirho {
            continue;
        }
        let key_chirho = (
            record_chirho.domain_chirho.clone(),
            record_chirho.local_part_hash_chirho.clone(),
        );
        let entry_chirho = latest_seq_chirho.entry(key_chirho).or_insert(0);
        if record_chirho.seq_chirho >= *entry_chirho {
            *entry_chirho = record_chirho.seq_chirho;
        }
    }
    let mut rows_chirho = Vec::new();
    for record_chirho in &records_chirho {
        if record_chirho.owner_principal_chirho != owner_principal_chirho {
            continue;
        }
        let key_chirho = (
            record_chirho.domain_chirho.clone(),
            record_chirho.local_part_hash_chirho.clone(),
        );
        let is_latest_chirho =
            latest_seq_chirho.get(&key_chirho) == Some(&record_chirho.seq_chirho);
        rows_chirho.push(MailboxSafeRowChirho {
            seq_chirho: record_chirho.seq_chirho,
            domain_chirho: record_chirho.domain_chirho.clone(),
            local_part_hash_chirho: record_chirho.local_part_hash_chirho.clone(),
            hash_scheme_chirho: record_chirho.hash_scheme_chirho.clone(),
            index_verification_chirho: local_part_index_verification_chirho(
                root_chirho,
                record_chirho,
                &mailbox_subject_chirho(
                    &record_chirho.owner_principal_chirho,
                    &record_chirho.domain_chirho,
                ),
            )?,
            kind_chirho: record_chirho.kind_chirho.clone(),
            status_chirho: record_chirho.status_chirho.clone(),
            live_chirho: is_latest_chirho
                && record_chirho.status_chirho == MailboxStatusChirho::ActiveChirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
            plaintext_included_chirho: false,
        });
    }
    rows_chirho.sort_by_key(|row_chirho| row_chirho.seq_chirho);
    Ok(rows_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let root_chirho =
            std::env::temp_dir().join(format!("cairn-mailbox-test-{n_chirho}-{}", now_ms_chirho()));
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    fn mailbox_input_chirho(local_chirho: &str) -> MailboxInputChirho {
        MailboxInputChirho {
            owner_principal_chirho: "owner/t".to_string(),
            domain_chirho: "cardshop.example".to_string(),
            local_part_chirho: local_chirho.to_string(),
            kind_chirho: MailboxKindChirho::MailboxChirho,
            alias_target_chirho: None,
            status_chirho: MailboxStatusChirho::ActiveChirho,
        }
    }

    fn resign_record_chirho(root_chirho: &Path, record_chirho: &mut MailboxRecordChirho) {
        record_chirho.sig_chirho.clear();
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &mailbox_message_chirho(record_chirho).unwrap(),
        )
        .unwrap();
    }

    fn write_single_record_chirho(root_chirho: &Path, record_chirho: &MailboxRecordChirho) {
        std::fs::write(
            mailboxes_path_chirho(root_chirho),
            format!("{}\n", serde_json::to_string(record_chirho).unwrap()),
        )
        .unwrap();
    }

    #[test]
    fn local_part_plaintext_never_enters_the_log_chirho() {
        let root_chirho = temp_root_chirho();
        // A personal-name local-part is exactly the PII case.
        emit_mailbox_chirho(&root_chirho, mailbox_input_chirho("john.smith")).unwrap();
        let log_chirho = std::fs::read_to_string(mailboxes_path_chirho(&root_chirho)).unwrap();
        assert!(
            !log_chirho.contains("john.smith"),
            "local-part plaintext must not be in the signed log"
        );
        assert_eq!(verify_mailbox_records_chirho(&root_chirho).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn local_part_blind_index_is_root_private_chirho() {
        let first_root_chirho = temp_root_chirho();
        let second_root_chirho = temp_root_chirho();
        let first_record_chirho =
            emit_mailbox_chirho(&first_root_chirho, mailbox_input_chirho("admin")).unwrap();
        let second_record_chirho =
            emit_mailbox_chirho(&second_root_chirho, mailbox_input_chirho("admin")).unwrap();
        assert_eq!(
            first_record_chirho.schema_chirho,
            MAILBOX_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(
            first_record_chirho.hash_scheme_chirho,
            MAILBOX_HASH_SCHEME_CHIRHO
        );
        assert_ne!(
            first_record_chirho.local_part_hash_chirho, second_record_chirho.local_part_hash_chirho,
            "same common local-part must not produce a root-independent dictionary target"
        );
        let subject_chirho = mailbox_subject_chirho(
            &first_record_chirho.owner_principal_chirho,
            &first_record_chirho.domain_chirho,
        );
        let legacy_hash_chirho = legacy_local_part_hash_chirho(&subject_chirho, "admin");
        assert_ne!(
            first_record_chirho.local_part_hash_chirho, legacy_hash_chirho,
            "v2 must not retain the old derivable subject-salted hash"
        );
        let _ = std::fs::remove_dir_all(&first_root_chirho);
        let _ = std::fs::remove_dir_all(&second_root_chirho);
    }

    #[test]
    fn signed_v2_record_with_legacy_hash_fails_closed_chirho() {
        let root_chirho = temp_root_chirho();
        let mut record_chirho =
            emit_mailbox_chirho(&root_chirho, mailbox_input_chirho("info")).unwrap();
        let subject_chirho = mailbox_subject_chirho(
            &record_chirho.owner_principal_chirho,
            &record_chirho.domain_chirho,
        );
        record_chirho.local_part_hash_chirho =
            legacy_local_part_hash_chirho(&subject_chirho, "info");
        resign_record_chirho(&root_chirho, &mut record_chirho);
        write_single_record_chirho(&root_chirho, &record_chirho);
        let error_chirho = verify_mailbox_records_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("blind index mismatch"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn legacy_v1_rows_stay_readable_and_labeled_chirho() {
        let root_chirho = temp_root_chirho();
        let mut record_chirho =
            emit_mailbox_chirho(&root_chirho, mailbox_input_chirho("legacy")).unwrap();
        let subject_chirho = mailbox_subject_chirho(
            &record_chirho.owner_principal_chirho,
            &record_chirho.domain_chirho,
        );
        record_chirho.schema_chirho = MAILBOX_RECORD_SCHEMA_V1_CHIRHO.to_string();
        record_chirho.hash_scheme_chirho = MAILBOX_HASH_SCHEME_V1_CHIRHO.to_string();
        record_chirho.local_part_hash_chirho =
            legacy_local_part_hash_chirho(&subject_chirho, "legacy");
        resign_record_chirho(&root_chirho, &mut record_chirho);
        write_single_record_chirho(&root_chirho, &record_chirho);
        let log_chirho = std::fs::read_to_string(mailboxes_path_chirho(&root_chirho)).unwrap();
        assert!(!log_chirho.contains("hash_scheme_chirho"));
        assert_eq!(verify_mailbox_records_chirho(&root_chirho).unwrap(), 1);
        let rows_chirho = mailbox_safe_rows_for_owner_chirho(&root_chirho, "owner/t").unwrap();
        assert_eq!(rows_chirho.len(), 1);
        assert_eq!(
            rows_chirho[0].hash_scheme_chirho,
            MAILBOX_HASH_SCHEME_V1_CHIRHO
        );
        assert_eq!(
            rows_chirho[0].index_verification_chirho,
            MAILBOX_INDEX_VERIFICATION_LEGACY_CHIRHO
        );
        assert!(rows_chirho[0].live_chirho);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn erased_v2_local_part_keeps_signed_row_verifiable_with_label_chirho() {
        let root_chirho = temp_root_chirho();
        let record_chirho =
            emit_mailbox_chirho(&root_chirho, mailbox_input_chirho("shredded")).unwrap();
        let subject_chirho = mailbox_subject_chirho(
            &record_chirho.owner_principal_chirho,
            &record_chirho.domain_chirho,
        );
        let rows_before_chirho =
            mailbox_safe_rows_for_owner_chirho(&root_chirho, "owner/t").unwrap();
        assert_eq!(
            rows_before_chirho[0].index_verification_chirho,
            MAILBOX_INDEX_VERIFICATION_VERIFIED_CHIRHO
        );
        assert!(privacy_chirho::erase_private_blob_key_for_subject_chirho(
            &root_chirho,
            &record_chirho.local_part_ref_chirho.key_id_chirho,
            &subject_chirho,
        )
        .unwrap());
        assert!(
            privacy_chirho::load_private_blob_chirho(
                &root_chirho,
                &record_chirho.local_part_ref_chirho
            )
            .is_err(),
            "local-part plaintext should be crypto-shredded"
        );
        assert_eq!(verify_mailbox_records_chirho(&root_chirho).unwrap(), 1);
        let rows_after_chirho =
            mailbox_safe_rows_for_owner_chirho(&root_chirho, "owner/t").unwrap();
        assert_eq!(rows_after_chirho.len(), 1);
        assert_eq!(
            rows_after_chirho[0].index_verification_chirho,
            MAILBOX_INDEX_VERIFICATION_POST_ERASURE_CHIRHO
        );
        assert!(rows_after_chirho[0].live_chirho);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn safe_rows_live_flag_and_removal_chirho() {
        let root_chirho = temp_root_chirho();
        emit_mailbox_chirho(&root_chirho, mailbox_input_chirho("orders")).unwrap();
        let mut removal_chirho = mailbox_input_chirho("orders");
        removal_chirho.status_chirho = MailboxStatusChirho::RemovedChirho;
        emit_mailbox_chirho(&root_chirho, removal_chirho).unwrap();
        let rows_chirho = mailbox_safe_rows_for_owner_chirho(&root_chirho, "owner/t").unwrap();
        assert_eq!(rows_chirho.len(), 2);
        // Latest record for orders is the removal, so nothing is live.
        assert!(!rows_chirho.iter().any(|r_chirho| r_chirho.live_chirho));
        assert!(rows_chirho
            .iter()
            .all(|r_chirho| !r_chirho.plaintext_included_chirho));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn tampered_mailbox_log_fails_closed_chirho() {
        let root_chirho = temp_root_chirho();
        emit_mailbox_chirho(&root_chirho, mailbox_input_chirho("info")).unwrap();
        let path_chirho = mailboxes_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        // Flip the kind enum to break the signature.
        std::fs::write(
            &path_chirho,
            text_chirho.replace("MailboxChirho", "AliasChirho"),
        )
        .unwrap();
        assert!(verify_mailbox_records_chirho(&root_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn alias_requires_target_mailbox_forbids_it_chirho() {
        let root_chirho = temp_root_chirho();
        let mut alias_no_target_chirho = mailbox_input_chirho("sales");
        alias_no_target_chirho.kind_chirho = MailboxKindChirho::AliasChirho;
        assert!(emit_mailbox_chirho(&root_chirho, alias_no_target_chirho).is_err());
        let mut mailbox_with_target_chirho = mailbox_input_chirho("sales");
        mailbox_with_target_chirho.alias_target_chirho = Some("x@y.example".to_string());
        assert!(emit_mailbox_chirho(&root_chirho, mailbox_with_target_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
