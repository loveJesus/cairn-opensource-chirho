// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! DNS zones as stones: a signed, append-only desired-state record family for a domain's DNS records, so a zone change is versioned and one-click rollbackable (move the ref) before any live apply.
//!
//! This is the LOCAL foundation only. Applying a desired zone to a live authoritative-DNS provider
//! is a separate, gated blessed effect (operator-approved) — this module never touches the network.
//! Records are platform-signed and seq-contiguous like the other signed families; the latest record
//! for a domain is its desired state, and history stays for audit and rollback.

use crate::seqlog_chirho;
use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DNS_ZONE_RECORD_SCHEMA_CHIRHO: &str = "dns-zone-record-v1-chirho";
const DOMAIN_MAX_LEN_CHIRHO: usize = 253;
const VALUE_MAX_LEN_CHIRHO: usize = 2048;
const MAX_RECORDS_PER_ZONE_CHIRHO: usize = 200;
/// The DNS record types a desired zone may declare (kept to a safe, common allowlist).
const ALLOWED_TYPES_CHIRHO: [&str; 6] = ["A", "AAAA", "CNAME", "MX", "TXT", "CAA"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecordChirho {
    /// Record type (one of ALLOWED_TYPES_CHIRHO).
    pub type_chirho: String,
    /// Record name (subdomain label or "@" for the apex).
    pub name_chirho: String,
    /// Record value (IP, target host, or text content).
    pub value_chirho: String,
    pub ttl_chirho: u32,
    /// MX priority (required for MX, ignored otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_chirho: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsZoneRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub owner_principal_chirho: String,
    pub domain_chirho: String,
    pub records_chirho: Vec<DnsRecordChirho>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub struct DnsZoneInputChirho {
    pub owner_principal_chirho: String,
    pub domain_chirho: String,
    pub records_chirho: Vec<DnsRecordChirho>,
}

fn dns_zones_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("dns-zones-chirho.jsonl")
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

fn dns_zone_message_chirho(record_chirho: &DnsZoneRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

/// Validate a domain: lowercase DNS labels only (same discipline as host bindings).
pub fn validate_zone_domain_chirho(domain_chirho: &str) -> Result<()> {
    if domain_chirho.is_empty() || domain_chirho.len() > DOMAIN_MAX_LEN_CHIRHO {
        bail!("zone domain must be 1..={DOMAIN_MAX_LEN_CHIRHO} chars");
    }
    if domain_chirho != domain_chirho.to_ascii_lowercase() {
        bail!("zone domain must be lowercase");
    }
    for label_chirho in domain_chirho.split('.') {
        if label_chirho.is_empty() || label_chirho.len() > 63 {
            bail!("zone domain label must be 1..=63 chars");
        }
        if label_chirho.starts_with('-') || label_chirho.ends_with('-') {
            bail!("zone domain label must not start or end with '-'");
        }
        if !label_chirho.chars().all(|c_chirho| {
            c_chirho.is_ascii_lowercase() || c_chirho.is_ascii_digit() || c_chirho == '-'
        }) {
            bail!("zone domain may contain only a-z, 0-9, '-', and '.'");
        }
    }
    Ok(())
}

fn validate_record_chirho(record_chirho: &DnsRecordChirho) -> Result<()> {
    let type_upper_chirho = record_chirho.type_chirho.to_ascii_uppercase();
    if !ALLOWED_TYPES_CHIRHO.contains(&type_upper_chirho.as_str()) {
        bail!("unsupported DNS record type: {}", record_chirho.type_chirho);
    }
    if record_chirho.name_chirho.is_empty()
        || record_chirho.name_chirho.len() > DOMAIN_MAX_LEN_CHIRHO
    {
        bail!("DNS record name must be 1..={DOMAIN_MAX_LEN_CHIRHO} chars");
    }
    if record_chirho.value_chirho.is_empty()
        || record_chirho.value_chirho.len() > VALUE_MAX_LEN_CHIRHO
    {
        bail!("DNS record value must be 1..={VALUE_MAX_LEN_CHIRHO} chars");
    }
    if record_chirho
        .name_chirho
        .chars()
        .any(|c_chirho| c_chirho.is_whitespace())
    {
        bail!("DNS record name must not contain whitespace");
    }
    if type_upper_chirho == "MX" && record_chirho.priority_chirho.is_none() {
        bail!("MX records require a priority");
    }
    Ok(())
}

fn validate_input_chirho(input_chirho: &DnsZoneInputChirho) -> Result<()> {
    if input_chirho.owner_principal_chirho.trim().is_empty() {
        bail!("zone owner principal must not be empty");
    }
    validate_zone_domain_chirho(&input_chirho.domain_chirho)?;
    if input_chirho.records_chirho.len() > MAX_RECORDS_PER_ZONE_CHIRHO {
        bail!("a zone may declare at most {MAX_RECORDS_PER_ZONE_CHIRHO} records");
    }
    for record_chirho in &input_chirho.records_chirho {
        validate_record_chirho(record_chirho)?;
    }
    Ok(())
}

/// Append one signed desired-zone record (the new desired state for a domain).
pub fn emit_dns_zone_chirho(
    root_chirho: &Path,
    input_chirho: DnsZoneInputChirho,
) -> Result<DnsZoneRecordChirho> {
    validate_input_chirho(&input_chirho)?;
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let path_chirho = dns_zones_path_chirho(root_chirho);
        let mut record_chirho = DnsZoneRecordChirho {
            schema_chirho: DNS_ZONE_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: jsonl_len_chirho(&path_chirho)?,
            owner_principal_chirho: input_chirho.owner_principal_chirho.clone(),
            domain_chirho: input_chirho.domain_chirho.clone(),
            records_chirho: input_chirho.records_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &dns_zone_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

pub fn load_dns_zone_records_chirho(root_chirho: &Path) -> Result<Vec<DnsZoneRecordChirho>> {
    let path_chirho = dns_zones_path_chirho(root_chirho);
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
        records_chirho.push(serde_json::from_str(line_chirho).context("parse dns zone record")?);
    }
    Ok(records_chirho)
}

/// Fail-closed verification: seq contiguity, schema pin, field validity, and signature per record.
pub fn verify_dns_zone_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_dns_zone_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "dns zone seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.schema_chirho != DNS_ZONE_RECORD_SCHEMA_CHIRHO {
            bail!(
                "dns zone record {} schema mismatch",
                record_chirho.seq_chirho
            );
        }
        validate_zone_domain_chirho(&record_chirho.domain_chirho)?;
        for dns_record_chirho in &record_chirho.records_chirho {
            validate_record_chirho(dns_record_chirho)?;
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &dns_zone_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "dns zone record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

pub fn verified_dns_zone_records_chirho(root_chirho: &Path) -> Result<Vec<DnsZoneRecordChirho>> {
    verify_dns_zone_records_chirho(root_chirho)?;
    load_dns_zone_records_chirho(root_chirho)
}

/// The desired (latest) zone for a domain over verified records, or None if the domain is unbound.
pub fn desired_zone_for_domain_chirho(
    records_chirho: &[DnsZoneRecordChirho],
    domain_chirho: &str,
) -> Option<DnsZoneRecordChirho> {
    let domain_lower_chirho = domain_chirho.to_ascii_lowercase();
    records_chirho
        .iter()
        .filter(|record_chirho| record_chirho.domain_chirho == domain_lower_chirho)
        .max_by_key(|record_chirho| record_chirho.seq_chirho)
        .cloned()
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
            "cairn-dns-zone-test-{n_chirho}-{}",
            now_ms_chirho()
        ));
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    fn rec_chirho(type_chirho: &str, name_chirho: &str, value_chirho: &str) -> DnsRecordChirho {
        DnsRecordChirho {
            type_chirho: type_chirho.to_string(),
            name_chirho: name_chirho.to_string(),
            value_chirho: value_chirho.to_string(),
            ttl_chirho: 3600,
            priority_chirho: None,
        }
    }

    fn zone_chirho(
        domain_chirho: &str,
        records_chirho: Vec<DnsRecordChirho>,
    ) -> DnsZoneInputChirho {
        DnsZoneInputChirho {
            owner_principal_chirho: "owner/test".to_string(),
            domain_chirho: domain_chirho.to_string(),
            records_chirho,
        }
    }

    #[test]
    fn emit_verify_and_latest_desired_zone_chirho() {
        let root_chirho = temp_root_chirho();
        emit_dns_zone_chirho(
            &root_chirho,
            zone_chirho("cardshop.example", vec![rec_chirho("A", "@", "192.0.2.1")]),
        )
        .unwrap();
        emit_dns_zone_chirho(
            &root_chirho,
            zone_chirho(
                "cardshop.example",
                vec![
                    rec_chirho("A", "@", "192.0.2.2"),
                    rec_chirho("TXT", "@", "v=spf1 -all"),
                ],
            ),
        )
        .unwrap();
        let records_chirho = verified_dns_zone_records_chirho(&root_chirho).unwrap();
        assert_eq!(records_chirho.len(), 2);
        let desired_chirho =
            desired_zone_for_domain_chirho(&records_chirho, "CARDSHOP.example").unwrap();
        // Latest desired state wins.
        assert_eq!(desired_chirho.records_chirho.len(), 2);
        assert_eq!(desired_chirho.records_chirho[0].value_chirho, "192.0.2.2");
        assert!(desired_zone_for_domain_chirho(&records_chirho, "other.example").is_none());
    }

    #[test]
    fn tampered_zone_log_fails_closed_chirho() {
        let root_chirho = temp_root_chirho();
        emit_dns_zone_chirho(
            &root_chirho,
            zone_chirho("shop.example", vec![rec_chirho("A", "@", "192.0.2.1")]),
        )
        .unwrap();
        let path_chirho = dns_zones_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        std::fs::write(
            &path_chirho,
            text_chirho.replace("192.0.2.1", "203.0.113.9"),
        )
        .unwrap();
        assert!(verify_dns_zone_records_chirho(&root_chirho).is_err());
    }

    #[test]
    fn invalid_domains_and_records_rejected_chirho() {
        let root_chirho = temp_root_chirho();
        assert!(emit_dns_zone_chirho(
            &root_chirho,
            zone_chirho("Shop.Example", vec![rec_chirho("A", "@", "192.0.2.1")])
        )
        .is_err());
        assert!(emit_dns_zone_chirho(
            &root_chirho,
            zone_chirho("shop.example", vec![rec_chirho("WEIRD", "@", "x")])
        )
        .is_err());
        // MX without priority is rejected.
        assert!(emit_dns_zone_chirho(
            &root_chirho,
            zone_chirho(
                "shop.example",
                vec![rec_chirho("MX", "@", "mail.shop.example")]
            )
        )
        .is_err());
    }
}
