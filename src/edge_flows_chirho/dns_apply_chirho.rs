// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! DNS apply scaffold: the signed, idempotent record of an intent to apply a domain's desired zone to a provider — with a stub performer that records intent WITHOUT any network call, and the live-provider path explicitly gated.
//!
//! This is the safe bridge to live DNS. `emit_dns_apply_stub_chirho` resolves the verified desired
//! zone and records that it WOULD apply N records, idempotently (same key → same record, no
//! duplicate). `apply_live_chirho` is intentionally an explicit operator gate that returns an error
//! until a real authoritative-DNS provider is enabled — so the structure exists and is tested, but
//! nothing here can touch a provider.

use crate::{dns_zone_chirho, seqlog_chirho};
use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DNS_APPLY_RECORD_SCHEMA_CHIRHO: &str = "dns-apply-record-v1-chirho";
const STUB_PROVIDER_LABEL_CHIRHO: &str = "stub-no-network-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsApplyOutcomeChirho {
    /// Intent recorded by the stub performer; no provider was contacted.
    StubRecordedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsApplyRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub owner_principal_chirho: String,
    pub domain_chirho: String,
    /// The dns-zone record seq that was the desired state at apply time (provenance).
    pub applied_zone_seq_chirho: u64,
    pub zone_record_count_chirho: usize,
    pub provider_label_chirho: String,
    pub idempotency_key_chirho: String,
    pub outcome_chirho: DnsApplyOutcomeChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

fn dns_applies_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("dns-applies-chirho.jsonl")
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

fn dns_apply_message_chirho(record_chirho: &DnsApplyRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

pub fn load_dns_apply_records_chirho(root_chirho: &Path) -> Result<Vec<DnsApplyRecordChirho>> {
    let path_chirho = dns_applies_path_chirho(root_chirho);
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
        records_chirho.push(serde_json::from_str(line_chirho).context("parse dns apply record")?);
    }
    Ok(records_chirho)
}

pub fn verify_dns_apply_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_dns_apply_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "dns apply seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.schema_chirho != DNS_APPLY_RECORD_SCHEMA_CHIRHO {
            bail!(
                "dns apply record {} schema mismatch",
                record_chirho.seq_chirho
            );
        }
        dns_zone_chirho::validate_zone_domain_chirho(&record_chirho.domain_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &dns_apply_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "dns apply record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

pub fn verified_dns_apply_records_chirho(root_chirho: &Path) -> Result<Vec<DnsApplyRecordChirho>> {
    verify_dns_apply_records_chirho(root_chirho)?;
    load_dns_apply_records_chirho(root_chirho)
}

/// Record an intent to apply a domain's current desired zone via the no-network stub performer.
/// Idempotent: the same idempotency key returns the existing record without re-recording. Resolves
/// and binds the verified desired zone's seq for provenance. NEVER contacts a provider.
pub fn emit_dns_apply_stub_chirho(
    root_chirho: &Path,
    owner_principal_chirho: &str,
    domain_chirho: &str,
    idempotency_key_chirho: &str,
) -> Result<DnsApplyRecordChirho> {
    if owner_principal_chirho.trim().is_empty() {
        bail!("dns apply owner principal must not be empty");
    }
    if idempotency_key_chirho.trim().is_empty() || idempotency_key_chirho.len() > 128 {
        bail!("dns apply idempotency key must be 1..=128 chars");
    }
    dns_zone_chirho::validate_zone_domain_chirho(domain_chirho)?;

    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        // Idempotency: a prior record with this key for this owner+domain replays unchanged.
        let existing_chirho = load_dns_apply_records_chirho(root_chirho)?;
        if let Some(prior_chirho) = existing_chirho.iter().find(|r_chirho| {
            r_chirho.idempotency_key_chirho == idempotency_key_chirho
                && r_chirho.owner_principal_chirho == owner_principal_chirho
                && r_chirho.domain_chirho == domain_chirho
        }) {
            return Ok(prior_chirho.clone());
        }

        let zone_records_chirho = dns_zone_chirho::verified_dns_zone_records_chirho(root_chirho)?;
        let desired_chirho =
            dns_zone_chirho::desired_zone_for_domain_chirho(&zone_records_chirho, domain_chirho)
                .ok_or_else(|| {
                    anyhow::anyhow!("no desired DNS zone for {domain_chirho}; set one before apply")
                })?;

        let path_chirho = dns_applies_path_chirho(root_chirho);
        let mut record_chirho = DnsApplyRecordChirho {
            schema_chirho: DNS_APPLY_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: jsonl_len_chirho(&path_chirho)?,
            owner_principal_chirho: owner_principal_chirho.to_string(),
            domain_chirho: domain_chirho.to_string(),
            applied_zone_seq_chirho: desired_chirho.seq_chirho,
            zone_record_count_chirho: desired_chirho.records_chirho.len(),
            provider_label_chirho: STUB_PROVIDER_LABEL_CHIRHO.to_string(),
            idempotency_key_chirho: idempotency_key_chirho.to_string(),
            outcome_chirho: DnsApplyOutcomeChirho::StubRecordedChirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &dns_apply_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

/// The live authoritative-DNS provider apply — an explicit operator gate. It is intentionally not
/// implemented: enabling it requires a real provider, credentials, and L.J.'s authorization. The
/// signed apply record family and the stub performer above exist so the structure is proven first.
pub fn apply_live_chirho(
    _root_chirho: &Path,
    _owner_principal_chirho: &str,
    _domain_chirho: &str,
    _idempotency_key_chirho: &str,
) -> Result<DnsApplyRecordChirho> {
    bail!("live DNS provider apply is not enabled; this is an operator-gated step requiring a configured provider and explicit authorization")
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
            "cairn-dns-apply-test-{n_chirho}-{}",
            now_ms_chirho()
        ));
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    fn set_zone_chirho(root_chirho: &Path) {
        dns_zone_chirho::emit_dns_zone_chirho(
            root_chirho,
            dns_zone_chirho::DnsZoneInputChirho {
                owner_principal_chirho: "owner/t".to_string(),
                domain_chirho: "cardshop.example".to_string(),
                records_chirho: vec![dns_zone_chirho::DnsRecordChirho {
                    type_chirho: "A".to_string(),
                    name_chirho: "@".to_string(),
                    value_chirho: "192.0.2.1".to_string(),
                    ttl_chirho: 3600,
                    priority_chirho: None,
                }],
            },
        )
        .unwrap();
    }

    #[test]
    fn stub_apply_records_intent_and_is_idempotent_chirho() {
        let root_chirho = temp_root_chirho();
        set_zone_chirho(&root_chirho);
        let first_chirho =
            emit_dns_apply_stub_chirho(&root_chirho, "owner/t", "cardshop.example", "key-1")
                .unwrap();
        assert_eq!(
            first_chirho.outcome_chirho,
            DnsApplyOutcomeChirho::StubRecordedChirho
        );
        assert_eq!(first_chirho.zone_record_count_chirho, 1);
        assert_eq!(
            first_chirho.provider_label_chirho,
            STUB_PROVIDER_LABEL_CHIRHO
        );
        // Same idempotency key replays the same record; no second row appended.
        let again_chirho =
            emit_dns_apply_stub_chirho(&root_chirho, "owner/t", "cardshop.example", "key-1")
                .unwrap();
        assert_eq!(again_chirho.seq_chirho, first_chirho.seq_chirho);
        assert_eq!(
            verified_dns_apply_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            1
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn apply_without_a_desired_zone_fails_chirho() {
        let root_chirho = temp_root_chirho();
        assert!(
            emit_dns_apply_stub_chirho(&root_chirho, "owner/t", "cardshop.example", "k").is_err()
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn live_apply_is_gated_chirho() {
        let root_chirho = temp_root_chirho();
        let err_chirho =
            apply_live_chirho(&root_chirho, "owner/t", "cardshop.example", "k").unwrap_err();
        assert!(err_chirho.to_string().contains("operator-gated"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn tampered_apply_log_fails_closed_chirho() {
        let root_chirho = temp_root_chirho();
        set_zone_chirho(&root_chirho);
        emit_dns_apply_stub_chirho(&root_chirho, "owner/t", "cardshop.example", "key-1").unwrap();
        let path_chirho = dns_applies_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        std::fs::write(&path_chirho, text_chirho.replace("key-1", "key-forged")).unwrap();
        assert!(verify_dns_apply_records_chirho(&root_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
