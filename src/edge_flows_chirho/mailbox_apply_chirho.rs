// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Mailbox apply scaffold: the signed, idempotent record of an intent to provision a domain's live mailboxes/aliases on a mail provider — with a stub performer that records intent WITHOUT any network call, and the live-provider (Mailu) path explicitly gated.
//!
//! The safe bridge to live email provisioning, mirroring the DNS apply scaffold. It records only how
//! many live mailbox/alias rows would be provisioned for a domain (counts, never an address);
//! `apply_live_chirho` is an explicit operator gate that errors until Mailu is configured and
//! authorized. No address plaintext is read or recorded here.

use crate::{dns_zone_chirho, mailbox_chirho, seqlog_chirho};
use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAILBOX_APPLY_RECORD_SCHEMA_CHIRHO: &str = "mailbox-apply-record-v1-chirho";
const STUB_PROVIDER_LABEL_CHIRHO: &str = "stub-no-network-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxApplyOutcomeChirho {
    StubRecordedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxApplyRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub owner_principal_chirho: String,
    pub domain_chirho: String,
    /// How many live mailbox/alias rows would be provisioned (a count, never an address).
    pub live_mailbox_count_chirho: usize,
    pub provider_label_chirho: String,
    pub idempotency_key_chirho: String,
    pub outcome_chirho: MailboxApplyOutcomeChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

fn mailbox_applies_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("mailbox-applies-chirho.jsonl")
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

fn mailbox_apply_message_chirho(record_chirho: &MailboxApplyRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

pub fn load_mailbox_apply_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<MailboxApplyRecordChirho>> {
    let path_chirho = mailbox_applies_path_chirho(root_chirho);
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
        records_chirho
            .push(serde_json::from_str(line_chirho).context("parse mailbox apply record")?);
    }
    Ok(records_chirho)
}

pub fn verify_mailbox_apply_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_mailbox_apply_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "mailbox apply seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.schema_chirho != MAILBOX_APPLY_RECORD_SCHEMA_CHIRHO {
            bail!(
                "mailbox apply record {} schema mismatch",
                record_chirho.seq_chirho
            );
        }
        dns_zone_chirho::validate_zone_domain_chirho(&record_chirho.domain_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &mailbox_apply_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "mailbox apply record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

pub fn verified_mailbox_apply_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<MailboxApplyRecordChirho>> {
    verify_mailbox_apply_records_chirho(root_chirho)?;
    load_mailbox_apply_records_chirho(root_chirho)
}

/// Record an intent to provision a domain's live mailboxes via the no-network stub performer.
/// Idempotent on (owner, domain, key). Counts the owner's live mailbox/alias rows for the domain;
/// reads no address plaintext and contacts no provider.
pub fn emit_mailbox_apply_stub_chirho(
    root_chirho: &Path,
    owner_principal_chirho: &str,
    domain_chirho: &str,
    idempotency_key_chirho: &str,
) -> Result<MailboxApplyRecordChirho> {
    if owner_principal_chirho.trim().is_empty() {
        bail!("mailbox apply owner principal must not be empty");
    }
    if idempotency_key_chirho.trim().is_empty() || idempotency_key_chirho.len() > 128 {
        bail!("mailbox apply idempotency key must be 1..=128 chars");
    }
    dns_zone_chirho::validate_zone_domain_chirho(domain_chirho)?;

    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let existing_chirho = load_mailbox_apply_records_chirho(root_chirho)?;
        if let Some(prior_chirho) = existing_chirho.iter().find(|r_chirho| {
            r_chirho.idempotency_key_chirho == idempotency_key_chirho
                && r_chirho.owner_principal_chirho == owner_principal_chirho
                && r_chirho.domain_chirho == domain_chirho
        }) {
            return Ok(prior_chirho.clone());
        }

        // Count this owner's live mailbox/alias rows for the domain (counts only, no addresses).
        let safe_rows_chirho = mailbox_chirho::mailbox_safe_rows_for_owner_chirho(
            root_chirho,
            owner_principal_chirho,
        )?;
        let live_count_chirho = safe_rows_chirho
            .iter()
            .filter(|row_chirho| {
                row_chirho.domain_chirho == domain_chirho && row_chirho.live_chirho
            })
            .count();
        if live_count_chirho == 0 {
            bail!("no live mailboxes for {domain_chirho}; set one before apply");
        }

        let path_chirho = mailbox_applies_path_chirho(root_chirho);
        let mut record_chirho = MailboxApplyRecordChirho {
            schema_chirho: MAILBOX_APPLY_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: jsonl_len_chirho(&path_chirho)?,
            owner_principal_chirho: owner_principal_chirho.to_string(),
            domain_chirho: domain_chirho.to_string(),
            live_mailbox_count_chirho: live_count_chirho,
            provider_label_chirho: STUB_PROVIDER_LABEL_CHIRHO.to_string(),
            idempotency_key_chirho: idempotency_key_chirho.to_string(),
            outcome_chirho: MailboxApplyOutcomeChirho::StubRecordedChirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &mailbox_apply_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

/// The live Mailu mailbox provisioning — an explicit operator gate, intentionally not implemented.
/// Enabling it requires Mailu configured, credentials, and L.J.'s authorization.
pub fn apply_live_chirho(
    _root_chirho: &Path,
    _owner_principal_chirho: &str,
    _domain_chirho: &str,
    _idempotency_key_chirho: &str,
) -> Result<MailboxApplyRecordChirho> {
    bail!("live Mailu mailbox provisioning is not enabled; this is an operator-gated step requiring a configured provider and explicit authorization")
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-mailbox-apply-test-{n_chirho}-{}",
            now_ms_chirho()
        ));
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    fn set_mailbox_chirho(root_chirho: &Path, local_chirho: &str) {
        mailbox_chirho::emit_mailbox_chirho(
            root_chirho,
            mailbox_chirho::MailboxInputChirho {
                owner_principal_chirho: "owner/t".to_string(),
                domain_chirho: "cardshop.example".to_string(),
                local_part_chirho: local_chirho.to_string(),
                kind_chirho: mailbox_chirho::MailboxKindChirho::MailboxChirho,
                alias_target_chirho: None,
                status_chirho: mailbox_chirho::MailboxStatusChirho::ActiveChirho,
            },
        )
        .unwrap();
    }

    #[test]
    fn stub_apply_counts_live_mailboxes_and_is_idempotent_chirho() {
        let root_chirho = temp_root_chirho();
        set_mailbox_chirho(&root_chirho, "orders");
        set_mailbox_chirho(&root_chirho, "support");
        let first_chirho =
            emit_mailbox_apply_stub_chirho(&root_chirho, "owner/t", "cardshop.example", "k1")
                .unwrap();
        assert_eq!(first_chirho.live_mailbox_count_chirho, 2);
        let again_chirho =
            emit_mailbox_apply_stub_chirho(&root_chirho, "owner/t", "cardshop.example", "k1")
                .unwrap();
        assert_eq!(again_chirho.seq_chirho, first_chirho.seq_chirho);
        assert_eq!(
            verified_mailbox_apply_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            1
        );
        // No address plaintext is ever in the apply log.
        let log_chirho =
            std::fs::read_to_string(mailbox_applies_path_chirho(&root_chirho)).unwrap();
        assert!(!log_chirho.contains("orders") && !log_chirho.contains("support"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn apply_without_live_mailbox_fails_and_live_is_gated_chirho() {
        let root_chirho = temp_root_chirho();
        assert!(
            emit_mailbox_apply_stub_chirho(&root_chirho, "owner/t", "cardshop.example", "k")
                .is_err()
        );
        let err_chirho =
            apply_live_chirho(&root_chirho, "owner/t", "cardshop.example", "k").unwrap_err();
        assert!(err_chirho.to_string().contains("operator-gated"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
