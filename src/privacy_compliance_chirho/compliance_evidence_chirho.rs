// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Builds signed compliance evidence packs from the live verifiable logs.

use crate::model_chirho::HashChirho;
#[cfg(test)]
use crate::{data_residency_chirho, legal_hold_chirho, privacy_chirho};
use crate::{effect_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[path = "compliance_evidence_chirho/source_snapshots_chirho.rs"]
mod source_snapshots_chirho;
use source_snapshots_chirho::{
    collect_source_snapshots_chirho, source_summaries_chirho, AccountingControlSnapshotChirho,
    SourceSnapshotChirho,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const COMPLIANCE_EVIDENCE_SCHEMA_CHIRHO: &str = "compliance-evidence-pack/v1-chirho";
const COMPLIANCE_EVIDENCE_RECEIPT_SCHEMA_CHIRHO: &str = "compliance-evidence-receipt-v1-chirho";
const COMPLIANCE_EVIDENCE_RECORD_SCHEMA_CHIRHO: &str = "compliance-evidence-record-v1-chirho";
const COMPLIANCE_EVIDENCE_VERIFY_REPORT_SCHEMA_CHIRHO: &str =
    "compliance-evidence-verify-report-v1-chirho";
const COMPLIANCE_EVIDENCE_LOCK_CHIRHO: &str = "compliance-evidence-chirho";
const CF6_WAVE1_MONEY_SPINE_ARCHIVE_TAG_CHIRHO: &str =
    "archive-chirho/26-07-20-cf6-wave1-money-spine";
const ARCHIVED_EXTERNAL_USAGE_SOURCE_CHIRHO: &str = "external.usage-chirho";
const ARCHIVED_EXTERNAL_PRICES_SOURCE_CHIRHO: &str = "external.provider-prices-chirho";
const ARCHIVED_COUPON_ISSUES_SOURCE_CHIRHO: &str = "promotions.coupon-issues-chirho";
const ARCHIVED_COUPON_REDEMPTIONS_SOURCE_CHIRHO: &str = "promotions.coupon-redemptions-chirho";
const ARCHIVED_STRIPE_IDENTITY_SOURCE_CHIRHO: &str =
    "promotions.stripe-identity-verifications-chirho";

const FRAMEWORK_SOC2_CHIRHO: &str = "soc2-chirho";
const FRAMEWORK_ISO27001_CHIRHO: &str = "iso27001-chirho";
const FRAMEWORK_ISO27701_CHIRHO: &str = "iso27701-chirho";
const FRAMEWORK_ISO27017_CHIRHO: &str = "iso27017-chirho";
const FRAMEWORK_ISO27018_CHIRHO: &str = "iso27018-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidenceSourceChirho {
    pub source_chirho: String,
    pub verifier_chirho: String,
    pub status_chirho: String,
    pub records_chirho: usize,
    pub prefix_digest_chirho: String,
    pub verified_chirho: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_chirho: Option<String>,
    pub notes_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceCoverageGapChirho {
    pub path_chirho: String,
    pub reason_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceControlEvidenceChirho {
    pub framework_chirho: String,
    pub control_chirho: String,
    pub title_chirho: String,
    pub assertion_chirho: String,
    pub source_refs_chirho: Vec<String>,
    pub status_chirho: String,
    pub notes_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidencePackChirho {
    pub schema_chirho: String,
    pub generated_ms_chirho: u64,
    pub generated_by_chirho: String,
    pub period_start_ms_chirho: u64,
    pub period_end_ms_chirho: u64,
    pub frameworks_chirho: Vec<String>,
    pub controls_chirho: Vec<ComplianceControlEvidenceChirho>,
    pub sources_chirho: Vec<ComplianceEvidenceSourceChirho>,
    pub coverage_gaps_chirho: Vec<ComplianceCoverageGapChirho>,
    pub source_digest_chirho: String,
    pub scope_notes_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidenceRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub pack_chirho: HashChirho,
    pub frameworks_chirho: Vec<String>,
    pub period_start_ms_chirho: u64,
    pub period_end_ms_chirho: u64,
    pub generated_by_chirho: String,
    pub control_count_chirho: usize,
    pub source_count_chirho: usize,
    pub source_digest_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidenceReceiptChirho {
    pub schema_chirho: String,
    pub pack_chirho: HashChirho,
    pub record_chirho: ComplianceEvidenceRecordChirho,
    pub controls_chirho: usize,
    pub evidence_backed_controls_chirho: usize,
    pub manual_controls_chirho: usize,
    pub failed_sources_chirho: usize,
    pub coverage_gaps_chirho: usize,
    pub pack_body_chirho: ComplianceEvidencePackChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedComplianceSourceVerdictChirho {
    pub source_chirho: String,
    pub status_chirho: String,
    pub verifier_disposition_chirho: String,
    pub recovery_tag_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidenceVerificationChirho {
    pub schema_chirho: String,
    pub records_chirho: usize,
    pub packs_chirho: usize,
    pub controls_chirho: usize,
    pub evidence_backed_controls_chirho: usize,
    pub manual_controls_chirho: usize,
    pub source_prefixes_chirho: usize,
    pub failed_sources_chirho: usize,
    pub coverage_gaps_chirho: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounting_prefix_verdicts_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archived_source_verdicts_chirho: Vec<ArchivedComplianceSourceVerdictChirho>,
    pub target_pack_chirho: Option<HashChirho>,
}

#[derive(Debug, Default)]
struct SourcePrefixVerdictsChirho {
    accounting_prefix_verdicts_chirho: Vec<String>,
    archived_source_verdicts_chirho: Vec<ArchivedComplianceSourceVerdictChirho>,
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn normalize_frameworks_chirho(frameworks_chirho: &[String]) -> Result<Vec<String>> {
    if frameworks_chirho.is_empty()
        || frameworks_chirho
            .iter()
            .any(|framework_chirho| framework_chirho.eq_ignore_ascii_case("all"))
    {
        return Ok(all_frameworks_chirho());
    }
    let mut selected_chirho = BTreeSet::new();
    for framework_chirho in frameworks_chirho {
        let key_chirho = framework_chirho
            .trim()
            .to_ascii_lowercase()
            .replace(['_', '-'], "");
        let canonical_chirho = match key_chirho.as_str() {
            "soc2" | "socii" | "soc2chirho" => FRAMEWORK_SOC2_CHIRHO,
            "iso27001" | "iso27001chirho" => FRAMEWORK_ISO27001_CHIRHO,
            "iso27701" | "iso27701chirho" => FRAMEWORK_ISO27701_CHIRHO,
            "iso27017" | "iso27017chirho" => FRAMEWORK_ISO27017_CHIRHO,
            "iso27018" | "iso27018chirho" => FRAMEWORK_ISO27018_CHIRHO,
            _ => bail!("unsupported compliance framework '{framework_chirho}'"),
        };
        selected_chirho.insert(canonical_chirho.to_string());
    }
    Ok(all_frameworks_chirho()
        .into_iter()
        .filter(|framework_chirho| selected_chirho.contains(framework_chirho))
        .collect())
}

fn all_frameworks_chirho() -> Vec<String> {
    vec![
        FRAMEWORK_SOC2_CHIRHO.to_string(),
        FRAMEWORK_ISO27001_CHIRHO.to_string(),
        FRAMEWORK_ISO27701_CHIRHO.to_string(),
        FRAMEWORK_ISO27017_CHIRHO.to_string(),
        FRAMEWORK_ISO27018_CHIRHO.to_string(),
    ]
}

pub fn generate_compliance_evidence_pack_chirho(
    root_chirho: &Path,
    frameworks_chirho: &[String],
    period_start_ms_chirho: u64,
    period_end_ms_chirho: u64,
    generated_by_chirho: &str,
) -> Result<ComplianceEvidenceReceiptChirho> {
    if period_end_ms_chirho <= period_start_ms_chirho {
        bail!("period_end_ms_chirho must be greater than period_start_ms_chirho");
    }
    validate_token_chirho("generated_by_chirho", generated_by_chirho)?;
    let frameworks_chirho = normalize_frameworks_chirho(frameworks_chirho)?;
    let snapshots_chirho = collect_source_snapshots_chirho(root_chirho)?;
    let sources_chirho = source_summaries_chirho(&snapshots_chirho)?;
    let coverage_gaps_chirho = coverage_gaps_chirho(root_chirho)?;
    let source_digest_chirho = digest_value_chirho(&serde_json::to_value(&sources_chirho)?)?;
    let generated_ms_chirho = now_ms_chirho();
    let pack_chirho = ComplianceEvidencePackChirho {
        schema_chirho: COMPLIANCE_EVIDENCE_SCHEMA_CHIRHO.to_string(),
        generated_ms_chirho,
        generated_by_chirho: generated_by_chirho.to_string(),
        period_start_ms_chirho,
        period_end_ms_chirho,
        controls_chirho: control_evidence_chirho(&frameworks_chirho),
        frameworks_chirho,
        sources_chirho,
        coverage_gaps_chirho,
        source_digest_chirho,
        scope_notes_chirho: vec![
            "This is substrate-generated control evidence, not a certification claim."
                .to_string(),
            "Certification still needs organizational policy, risk assessment, vendor review, auditor testing, and operating process evidence."
                .to_string(),
            "Source digests cover the verified log prefixes present when this pack was generated; later valid appends do not invalidate those prefixes."
                .to_string(),
            "Coverage gaps list any top-level *-chirho.jsonl log found in this root that this pack did not claim as source evidence."
                .to_string(),
        ],
    };
    let counts_chirho = control_counts_chirho(&pack_chirho.controls_chirho)?;
    let failed_sources_chirho = pack_chirho
        .sources_chirho
        .iter()
        .filter(|source_chirho| source_chirho.status_chirho == "failed-chirho")
        .count();
    let pack_hash_chirho = store_chirho::put_object_chirho(root_chirho, &pack_chirho)?;
    let record_chirho =
        append_compliance_evidence_record_chirho(root_chirho, &pack_hash_chirho, &pack_chirho)?;
    Ok(ComplianceEvidenceReceiptChirho {
        schema_chirho: COMPLIANCE_EVIDENCE_RECEIPT_SCHEMA_CHIRHO.to_string(),
        pack_chirho: pack_hash_chirho,
        record_chirho,
        controls_chirho: counts_chirho.total_chirho,
        evidence_backed_controls_chirho: counts_chirho.evidence_backed_chirho,
        manual_controls_chirho: counts_chirho.manual_required_chirho,
        failed_sources_chirho,
        coverage_gaps_chirho: pack_chirho.coverage_gaps_chirho.len(),
        pack_body_chirho: pack_chirho,
    })
}

pub fn load_compliance_evidence_pack_chirho(
    root_chirho: &Path,
    pack_chirho: &HashChirho,
) -> Result<ComplianceEvidencePackChirho> {
    store_chirho::get_object_chirho(root_chirho, pack_chirho)
}

pub fn load_compliance_evidence_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ComplianceEvidenceRecordChirho>> {
    load_jsonl_chirho(&compliance_evidence_records_path_chirho(root_chirho))
}

pub fn verify_compliance_evidence_chirho(
    root_chirho: &Path,
    target_pack_chirho: Option<&HashChirho>,
) -> Result<ComplianceEvidenceVerificationChirho> {
    let records_chirho = load_compliance_evidence_records_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut packs_chirho = 0_usize;
    let mut controls_chirho = 0_usize;
    let mut evidence_backed_controls_chirho = 0_usize;
    let mut manual_controls_chirho = 0_usize;
    let mut source_prefixes_chirho = 0_usize;
    let mut failed_sources_chirho = 0_usize;
    let mut coverage_gaps_chirho = 0_usize;
    let mut accounting_prefix_verdicts_chirho = Vec::new();
    let mut archived_source_verdicts_chirho = Vec::new();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "compliance evidence seq gap at index {index_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_record_chirho(record_chirho)?;
        let message_chirho = compliance_evidence_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "compliance evidence record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        if target_pack_chirho
            .is_some_and(|target_chirho| target_chirho != &record_chirho.pack_chirho)
        {
            continue;
        }
        let pack_chirho: ComplianceEvidencePackChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.pack_chirho)?;
        let actual_pack_hash_chirho = store_chirho::hash_object_chirho(&pack_chirho)?;
        if actual_pack_hash_chirho != record_chirho.pack_chirho {
            bail!("compliance evidence pack content hash mismatch");
        }
        validate_pack_against_record_chirho(&pack_chirho, record_chirho)?;
        let counts_chirho = control_counts_chirho(&pack_chirho.controls_chirho)?;
        controls_chirho += counts_chirho.total_chirho;
        evidence_backed_controls_chirho += counts_chirho.evidence_backed_chirho;
        manual_controls_chirho += counts_chirho.manual_required_chirho;
        let snapshots_chirho = collect_source_snapshots_chirho(root_chirho)?;
        let prefix_verdicts_chirho =
            verify_pack_source_prefixes_chirho(root_chirho, &pack_chirho, &snapshots_chirho)?;
        accounting_prefix_verdicts_chirho
            .extend(prefix_verdicts_chirho.accounting_prefix_verdicts_chirho);
        archived_source_verdicts_chirho
            .extend(prefix_verdicts_chirho.archived_source_verdicts_chirho);
        source_prefixes_chirho += pack_chirho.sources_chirho.len();
        failed_sources_chirho += pack_chirho
            .sources_chirho
            .iter()
            .filter(|source_chirho| source_chirho.status_chirho == "failed-chirho")
            .count();
        coverage_gaps_chirho += pack_chirho.coverage_gaps_chirho.len();
        packs_chirho += 1;
    }
    if target_pack_chirho.is_some() && packs_chirho == 0 {
        bail!("no compliance evidence record found for requested pack");
    }
    Ok(ComplianceEvidenceVerificationChirho {
        schema_chirho: COMPLIANCE_EVIDENCE_VERIFY_REPORT_SCHEMA_CHIRHO.to_string(),
        records_chirho: records_chirho.len(),
        packs_chirho,
        controls_chirho,
        evidence_backed_controls_chirho,
        manual_controls_chirho,
        source_prefixes_chirho,
        failed_sources_chirho,
        coverage_gaps_chirho,
        accounting_prefix_verdicts_chirho,
        archived_source_verdicts_chirho,
        target_pack_chirho: target_pack_chirho.cloned(),
    })
}

fn append_compliance_evidence_record_chirho(
    root_chirho: &Path,
    pack_hash_chirho: &HashChirho,
    pack_chirho: &ComplianceEvidencePackChirho,
) -> Result<ComplianceEvidenceRecordChirho> {
    seqlog_chirho::with_named_lock_chirho(root_chirho, COMPLIANCE_EVIDENCE_LOCK_CHIRHO, || {
        let path_chirho = compliance_evidence_records_path_chirho(root_chirho);
        let seq_chirho = load_compliance_evidence_records_chirho(root_chirho)?.len() as u64;
        let mut record_chirho = ComplianceEvidenceRecordChirho {
            schema_chirho: COMPLIANCE_EVIDENCE_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            pack_chirho: pack_hash_chirho.clone(),
            frameworks_chirho: pack_chirho.frameworks_chirho.clone(),
            period_start_ms_chirho: pack_chirho.period_start_ms_chirho,
            period_end_ms_chirho: pack_chirho.period_end_ms_chirho,
            generated_by_chirho: pack_chirho.generated_by_chirho.clone(),
            control_count_chirho: pack_chirho.controls_chirho.len(),
            source_count_chirho: pack_chirho.sources_chirho.len(),
            source_digest_chirho: pack_chirho.source_digest_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = compliance_evidence_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

fn control_evidence_chirho(frameworks_chirho: &[String]) -> Vec<ComplianceControlEvidenceChirho> {
    let mut controls_chirho = Vec::new();
    let wants_chirho = |framework_chirho: &str| {
        frameworks_chirho
            .iter()
            .any(|item_chirho| item_chirho == framework_chirho)
    };
    if wants_chirho(FRAMEWORK_SOC2_CHIRHO) {
        controls_chirho.extend([
            control_chirho(
                FRAMEWORK_SOC2_CHIRHO,
                "CC6.1-chirho",
                "Logical access control",
                "Identities, OAuth scopes, capability attenuation, and agent authority changes are signed and replay-verifiable.",
                &[
                    "identity.records-chirho",
                    "identity.sessions-chirho",
                    "identity.credential-resets-chirho",
                    "oauth.scoped-tokens-chirho",
                    "oauth.scoped-token-uses-chirho",
                    "oauth.connection-tokens-chirho",
                    "oauth.connection-token-uses-chirho",
                    "attenuation.grants-chirho",
                    "agent-authority.responses-chirho",
                ],
            ),
            control_chirho(
                FRAMEWORK_SOC2_CHIRHO,
                "CC7.2-chirho",
                "Logging and monitoring",
                "Blessed effects and operational append logs are signed, ordered, and checked before evidence is emitted.",
                &[
                    "effects.records-chirho",
                    "effects.volatile-records-chirho",
                    "realtime.events-chirho",
                    "ledger.entries-chirho",
                    "agent-reports.records-chirho",
                    "data-residency.attestations-chirho",
                ],
            ),
            control_chirho(
                FRAMEWORK_SOC2_CHIRHO,
                "CC8.1-chirho",
                "Change management",
                "App changes move content-addressed refs through review, route records, reflog entries, and rollback/reversion evidence.",
                &[
                    "apps.records-chirho",
                    "apps.routes-chirho",
                    "reviews.records-chirho",
                    "refs.reflog-chirho",
                    "reversion.rollback-events-chirho",
                ],
            ),
            manual_control_chirho(
                FRAMEWORK_SOC2_CHIRHO,
                "CC1-CC5-manual-chirho",
                "Governance and risk-process evidence",
                "Management governance, risk assessment, policy communication, and auditor operating-effectiveness testing are outside cairn's runtime logs.",
            ),
        ]);
    }
    if wants_chirho(FRAMEWORK_ISO27001_CHIRHO) {
        controls_chirho.extend([
            control_chirho(
                FRAMEWORK_ISO27001_CHIRHO,
                "A.5.15-chirho",
                "Access control",
                "Capability grants, scoped tokens, and owner/admin approvals define access boundaries in signed records.",
                &[
                    "attenuation.grants-chirho",
                    "oauth.scoped-tokens-chirho",
                    "oauth.connection-tokens-chirho",
                    "agent-authority.responses-chirho",
                ],
            ),
            control_chirho(
                FRAMEWORK_ISO27001_CHIRHO,
                "A.5.23-chirho",
                "Cloud service residency controls",
                "Tenant residency policies and operator-sourced region attestations are signed and verified as declared control evidence.",
                &[
                    "data-residency.policies-chirho",
                    "data-residency.attestations-chirho",
                ],
            ),
            control_chirho(
                FRAMEWORK_ISO27001_CHIRHO,
                "A.8.24-chirho",
                "Use of cryptography",
                "Private payloads are encrypted as crypto-shredded blobs and all safe metadata logs are signature-verified.",
                &[
                    "privacy.blob-records-chirho",
                    "privacy.access-records-chirho",
                    "privacy.erasure-records-chirho",
                    "privacy.erasure-propagations-chirho",
                    "legal-holds.records-chirho",
                    "effects.records-chirho",
                    "ledger.entries-chirho",
                ],
            ),
            control_chirho(
                FRAMEWORK_ISO27001_CHIRHO,
                "A.8.32-chirho",
                "Change control",
                "Content-addressed app versions, review records, and reflog/reversion records provide change evidence.",
                &[
                    "apps.records-chirho",
                    "reviews.records-chirho",
                    "refs.current-chirho",
                    "refs.reflog-chirho",
                    "reversion.compensations-chirho",
                ],
            ),
            manual_control_chirho(
                FRAMEWORK_ISO27001_CHIRHO,
                "org-process-manual-chirho",
                "ISMS organizational process",
                "Risk treatment, statement of applicability, management review, internal audit, vendor review, and corrective-action process require human/auditor evidence.",
            ),
        ]);
    }
    if wants_chirho(FRAMEWORK_ISO27701_CHIRHO) {
        controls_chirho.extend([
            control_chirho(
                FRAMEWORK_ISO27701_CHIRHO,
                "7.3.9-chirho",
                "Data subject access and portability",
                "Subject exports are generated from known safe signed logs plus private blob records and leave signed export evidence.",
                &[
                    "privacy.export-evidence-chirho",
                    "privacy.blob-records-chirho",
                    "privacy.access-records-chirho",
                    "privacy.erasure-records-chirho",
                    "privacy.erasure-propagations-chirho",
                    "legal-holds.records-chirho",
                ],
            ),
            control_chirho(
                FRAMEWORK_ISO27701_CHIRHO,
                "7.4.7-chirho",
                "Privacy by design",
                "Privacy scan, private-blob metadata, retention sweeps, and erasure evidence are checked before this pack is signed.",
                &[
                    "privacy.scan-findings-chirho",
                    "privacy.blob-records-chirho",
                    "privacy.access-records-chirho",
                    "privacy.erasure-records-chirho",
                    "privacy.replica-targets-chirho",
                    "privacy.erasure-propagations-chirho",
                    "legal-holds.records-chirho",
                    "data-residency.policies-chirho",
                    "data-residency.attestations-chirho",
                ],
            ),
            manual_control_chirho(
                FRAMEWORK_ISO27701_CHIRHO,
                "privacy-governance-manual-chirho",
                "PIMS governance process",
                "Controller/processor role records, privacy notices, DPIAs, vendor terms, and data-processing agreements are manual organizational evidence.",
            ),
        ]);
    }
    if wants_chirho(FRAMEWORK_ISO27017_CHIRHO) {
        controls_chirho.push(control_chirho(
            FRAMEWORK_ISO27017_CHIRHO,
            "CLD.9.5.1-chirho",
            "Cloud service operational monitoring",
            "Tenant/app operational activity is evidenced by signed app, realtime, and agent oversight logs.",
            &[
                "apps.records-chirho",
                "realtime.sessions-chirho",
                "agent-reports.records-chirho",
                "data-residency.attestations-chirho",
            ],
        ));
        controls_chirho.push(manual_control_chirho(
            FRAMEWORK_ISO27017_CHIRHO,
            "cloud-shared-responsibility-manual-chirho",
            "Cloud shared-responsibility documentation",
            "Provider responsibility matrices and cloud customer operating procedures are manual evidence.",
        ));
        controls_chirho.push(manual_control_chirho(
            FRAMEWORK_ISO27017_CHIRHO,
            "cloud-residency-provider-manual-chirho",
            "Provider residency assurance",
            "Cloud contract terms, provider-region guarantees, independent geolocation, and migration/replication procedures require manual organizational evidence.",
        ));
    }
    if wants_chirho(FRAMEWORK_ISO27018_CHIRHO) {
        controls_chirho.push(control_chirho(
            FRAMEWORK_ISO27018_CHIRHO,
            "PII.9.2-chirho",
            "Public cloud PII handling",
            "PII-bearing payloads stay behind private blob references, erasure keys, and zero-finding structural privacy scans.",
            &[
                "privacy.blob-records-chirho",
                "privacy.access-records-chirho",
                "privacy.erasure-propagations-chirho",
                "legal-holds.records-chirho",
                "privacy.scan-findings-chirho",
                "realtime.events-chirho",
                "data-residency.policies-chirho",
                "data-residency.attestations-chirho",
            ],
        ));
        controls_chirho.push(manual_control_chirho(
            FRAMEWORK_ISO27018_CHIRHO,
            "public-cloud-pii-manual-chirho",
            "Public cloud PII contractual evidence",
            "Cloud PII processor/customer contracts, notices, and subprocessor disclosures are manual evidence.",
        ));
    }
    controls_chirho
}
fn control_chirho(
    framework_chirho: &str,
    control_chirho: &str,
    title_chirho: &str,
    assertion_chirho: &str,
    source_refs_chirho: &[&str],
) -> ComplianceControlEvidenceChirho {
    ComplianceControlEvidenceChirho {
        framework_chirho: framework_chirho.to_string(),
        control_chirho: control_chirho.to_string(),
        title_chirho: title_chirho.to_string(),
        assertion_chirho: assertion_chirho.to_string(),
        source_refs_chirho: source_refs_chirho
            .iter()
            .map(|source_chirho| (*source_chirho).to_string())
            .collect(),
        status_chirho: "evidence-backed-chirho".to_string(),
        notes_chirho: vec![
            "Generated from live cairn logs and control read models.".to_string(),
            "Auditor judgment and organizational controls remain outside this object.".to_string(),
        ],
    }
}
fn manual_control_chirho(
    framework_chirho: &str,
    control_chirho: &str,
    title_chirho: &str,
    assertion_chirho: &str,
) -> ComplianceControlEvidenceChirho {
    ComplianceControlEvidenceChirho {
        framework_chirho: framework_chirho.to_string(),
        control_chirho: control_chirho.to_string(),
        title_chirho: title_chirho.to_string(),
        assertion_chirho: assertion_chirho.to_string(),
        source_refs_chirho: Vec::new(),
        status_chirho: "manual-required-chirho".to_string(),
        notes_chirho: vec![
            "This control needs organizational or auditor evidence outside the runtime."
                .to_string(),
            "The pack deliberately does not claim this manual control is met.".to_string(),
        ],
    }
}
fn archived_compliance_source_verdict_chirho(
    source_chirho: &str,
) -> Option<ArchivedComplianceSourceVerdictChirho> {
    matches!(
        source_chirho,
        ARCHIVED_EXTERNAL_USAGE_SOURCE_CHIRHO
            | ARCHIVED_EXTERNAL_PRICES_SOURCE_CHIRHO
            | ARCHIVED_COUPON_ISSUES_SOURCE_CHIRHO
            | ARCHIVED_COUPON_REDEMPTIONS_SOURCE_CHIRHO
            | ARCHIVED_STRIPE_IDENTITY_SOURCE_CHIRHO
    )
    .then(|| ArchivedComplianceSourceVerdictChirho {
        source_chirho: source_chirho.to_string(),
        status_chirho: "source-archived-chirho".to_string(),
        verifier_disposition_chirho: "recover-verifier-from-tag-chirho".to_string(),
        recovery_tag_chirho: CF6_WAVE1_MONEY_SPINE_ARCHIVE_TAG_CHIRHO.to_string(),
    })
}

fn verify_pack_source_prefixes_chirho(
    root_chirho: &Path,
    pack_chirho: &ComplianceEvidencePackChirho,
    current_snapshots_chirho: &[SourceSnapshotChirho],
) -> Result<SourcePrefixVerdictsChirho> {
    let current_by_source_chirho: BTreeMap<&str, &SourceSnapshotChirho> = current_snapshots_chirho
        .iter()
        .map(|snapshot_chirho| (snapshot_chirho.source_chirho.as_str(), snapshot_chirho))
        .collect();
    let mut verdicts_chirho = SourcePrefixVerdictsChirho::default();
    for source_chirho in &pack_chirho.sources_chirho {
        if persistent_effect_source_still_valid_chirho(root_chirho, source_chirho)? {
            continue;
        }
        // The accounting branch runs BEFORE the current-snapshot lookup: a captured
        // period-close row needs no live generator, so its artifact laws + typed verdict
        // stay reachable on roots where the legacy accounting snapshot no longer exists.
        if let Some(verdict_chirho) =
            accounting_period_close_source_still_valid_chirho(None, source_chirho)?
        {
            verdicts_chirho
                .accounting_prefix_verdicts_chirho
                .push(verdict_chirho.label_chirho().to_string());
            continue;
        }
        if let Some(verdict_chirho) =
            archived_compliance_source_verdict_chirho(&source_chirho.source_chirho)
        {
            verdicts_chirho
                .archived_source_verdicts_chirho
                .push(verdict_chirho);
            continue;
        }
        let current_chirho = current_by_source_chirho
            .get(source_chirho.source_chirho.as_str())
            .ok_or_else(|| {
                anyhow!(
                    "missing compliance source '{}'",
                    source_chirho.source_chirho
                )
            })?;
        if current_chirho.status_chirho != source_chirho.status_chirho {
            bail!(
                "compliance source '{}' status changed from {} to {}",
                source_chirho.source_chirho,
                source_chirho.status_chirho,
                current_chirho.status_chirho
            );
        }
        if current_chirho.records_chirho.len() < source_chirho.records_chirho {
            bail!(
                "compliance source '{}' lost records: expected prefix {}, current {}",
                source_chirho.source_chirho,
                source_chirho.records_chirho,
                current_chirho.records_chirho.len()
            );
        }
        if source_chirho.source_chirho == "privacy.scan-findings-chirho"
            && privacy_scan_findings_still_present_chirho(source_chirho, current_chirho)?
        {
            continue;
        }
        let current_prefix_chirho = &current_chirho.records_chirho[..source_chirho.records_chirho];
        let current_digest_chirho =
            digest_value_chirho(&serde_json::to_value(current_prefix_chirho)?)?;
        if current_digest_chirho != source_chirho.prefix_digest_chirho {
            bail!(
                "compliance source '{}' prefix digest mismatch",
                source_chirho.source_chirho
            );
        }
    }
    Ok(verdicts_chirho)
}
fn persistent_effect_source_still_valid_chirho(
    root_chirho: &Path,
    source_chirho: &ComplianceEvidenceSourceChirho,
) -> Result<bool> {
    if source_chirho.source_chirho != "effects.records-chirho" {
        return Ok(false);
    }
    if source_chirho.status_chirho != "verified-chirho" {
        return Ok(false);
    }
    let Some(idem_keys_value_chirho) = source_chirho.verified_chirho.get("effect_idem_keys_chirho")
    else {
        bail!(
            "compliance source 'effects.records-chirho' legacy snapshot lacks stable effect membership ids"
        );
    };
    let idem_keys_chirho = idem_keys_value_chirho.as_array().ok_or_else(|| {
        anyhow!("effects.records-chirho effect_idem_keys_chirho must be an array")
    })?;
    if idem_keys_chirho.len() != source_chirho.records_chirho {
        bail!(
            "compliance source 'effects.records-chirho' membership count mismatch: expected {}, found {}",
            source_chirho.records_chirho,
            idem_keys_chirho.len()
        );
    }
    let mut seen_chirho = BTreeSet::new();
    let mut selected_records_chirho = Vec::new();
    let mut captured_keys_chirho = Vec::new();
    for key_value_chirho in idem_keys_chirho {
        let key_chirho = key_value_chirho
            .as_str()
            .ok_or_else(|| anyhow!("effects.records-chirho effect id must be a string"))?;
        validate_effect_idem_key_chirho(key_chirho)?;
        if !seen_chirho.insert(key_chirho.to_string()) {
            bail!("compliance source 'effects.records-chirho' duplicate effect id");
        }
        let effect_chirho =
            effect_chirho::load_effect_chirho(root_chirho, &HashChirho(key_chirho.to_string()))?
                .ok_or_else(|| {
                    anyhow!(
                        "compliance source 'effects.records-chirho' missing effect {}",
                        key_chirho
                    )
                })?;
        if effect_chirho.idem_key_chirho.0 != key_chirho {
            bail!(
                "compliance source 'effects.records-chirho' effect id/path mismatch for {}",
                key_chirho
            );
        }
        selected_records_chirho.push(serde_json::to_value(effect_chirho)?);
        captured_keys_chirho.push(key_chirho.to_string());
    }
    let captured_key_digest_chirho =
        digest_value_chirho(&serde_json::to_value(&captured_keys_chirho)?)?;
    if let Some(expected_digest_chirho) = source_chirho
        .verified_chirho
        .get("effect_idem_key_digest_chirho")
        .and_then(|value_chirho| value_chirho.as_str())
    {
        if expected_digest_chirho != captured_key_digest_chirho {
            bail!("compliance source 'effects.records-chirho' effect id digest mismatch");
        }
    } else {
        bail!("compliance source 'effects.records-chirho' missing effect id digest");
    }
    let selected_digest_chirho =
        digest_value_chirho(&serde_json::to_value(&selected_records_chirho)?)?;
    if selected_digest_chirho != source_chirho.prefix_digest_chirho {
        bail!("compliance source 'effects.records-chirho' captured effect digest mismatch");
    }
    Ok(true)
}
fn validate_effect_idem_key_chirho(value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | ':' | '.')
        })
    {
        bail!("effects.records-chirho effect id must be a short path-safe token");
    }
    Ok(())
}
/// Typed verdict for the captured accounting period-close row (#5512-#5514 three-seat (A)):
/// the caller can always tell which laws ran — an artifact-only pass never impersonates a full
/// historical re-derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountingPrefixVerdictChirho {
    FullLedgerRederivationChirho,
    ArtifactOnlyLedgerRecoverableAtTagChirho,
}

impl AccountingPrefixVerdictChirho {
    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::FullLedgerRederivationChirho => "full-ledger-rederivation-chirho",
            Self::ArtifactOnlyLedgerRecoverableAtTagChirho => {
                "artifact-only-ledger-recoverable-at-tag-chirho"
            }
        }
    }
}

/// One injected legacy-ledger assertion for the accounting period-close row: re-derive the
/// captured ledger-prefix digest from the live store. `None` (post-wave-1 roots) yields the
/// typed artifact-only verdict; deep re-derivation is then recovered at the pre-removal
/// archive tag, never faked here.
pub trait AccountingLegacyLedgerViewChirho {
    fn assert_prefix_chirho(&self, cutoff_chirho: u64, expected_digest_chirho: &str) -> Result<()>;
}

/// The three artifact laws (canonical parse + captured-digest binding + balance/status) run
/// unconditionally; only the legacy-ledger prefix re-derivation rides the injected view.
/// Returns `None` when the source is not the accounting period-close row.
fn accounting_period_close_source_still_valid_chirho(
    ledger_view_chirho: Option<&dyn AccountingLegacyLedgerViewChirho>,
    source_chirho: &ComplianceEvidenceSourceChirho,
) -> Result<Option<AccountingPrefixVerdictChirho>> {
    if source_chirho.source_chirho != "accounting.period-close-chirho" {
        return Ok(None);
    }
    let snapshot_chirho: AccountingControlSnapshotChirho =
        serde_json::from_value(source_chirho.verified_chirho.clone())
            .context("parse accounting period-close compliance snapshot")?;
    if source_chirho.records_chirho != 1 {
        bail!("compliance source 'accounting.period-close-chirho' expected one captured snapshot");
    }
    let captured_records_chirho = vec![serde_json::to_value(&snapshot_chirho)?];
    let captured_digest_chirho =
        digest_value_chirho(&serde_json::to_value(&captured_records_chirho)?)?;
    if captured_digest_chirho != source_chirho.prefix_digest_chirho {
        bail!("compliance source 'accounting.period-close-chirho' captured digest mismatch");
    }
    let balanced_chirho = !snapshot_chirho
        .balanced_by_asset_chirho
        .values()
        .any(|amount_chirho| *amount_chirho != 0);
    let expected_status_chirho = if balanced_chirho {
        "verified-chirho"
    } else {
        "failed-chirho"
    };
    if source_chirho.status_chirho != expected_status_chirho {
        bail!(
            "compliance source 'accounting.period-close-chirho' status mismatch: expected {}, found {}",
            expected_status_chirho,
            source_chirho.status_chirho
        );
    }
    match ledger_view_chirho {
        Some(view_chirho) => {
            view_chirho.assert_prefix_chirho(
                snapshot_chirho.ledger_cutoff_chirho,
                &snapshot_chirho.ledger_source_digest_chirho,
            )?;
            Ok(Some(
                AccountingPrefixVerdictChirho::FullLedgerRederivationChirho,
            ))
        }
        None => Ok(Some(
            AccountingPrefixVerdictChirho::ArtifactOnlyLedgerRecoverableAtTagChirho,
        )),
    }
}
fn privacy_scan_findings_still_present_chirho(
    source_chirho: &ComplianceEvidenceSourceChirho,
    current_chirho: &SourceSnapshotChirho,
) -> Result<bool> {
    let Some(captured_findings_chirho) = source_chirho
        .verified_chirho
        .get("findings_chirho")
        .and_then(Value::as_array)
    else {
        return Ok(false);
    };
    let Some(current_findings_chirho) = current_chirho
        .verified_chirho
        .get("findings_chirho")
        .and_then(Value::as_array)
    else {
        return Ok(false);
    };
    let mut current_counts_chirho = BTreeMap::<String, usize>::new();
    for finding_chirho in current_findings_chirho {
        *current_counts_chirho
            .entry(serde_json::to_string(finding_chirho)?)
            .or_insert(0) += 1;
    }
    for finding_chirho in captured_findings_chirho {
        let key_chirho = serde_json::to_string(finding_chirho)?;
        let Some(count_chirho) = current_counts_chirho.get_mut(&key_chirho) else {
            bail!("compliance source 'privacy.scan-findings-chirho' finding no longer present");
        };
        if *count_chirho == 0 {
            bail!("compliance source 'privacy.scan-findings-chirho' finding no longer present");
        }
        *count_chirho -= 1;
    }
    Ok(true)
}
fn coverage_gaps_chirho(root_chirho: &Path) -> Result<Vec<ComplianceCoverageGapChirho>> {
    let claimed_chirho = claimed_jsonl_files_chirho();
    let historical_untyped_chirho = historical_untyped_jsonl_files_chirho();
    let mut gaps_chirho = Vec::new();
    for path_chirho in root_jsonl_paths_chirho(root_chirho)? {
        let Some(file_name_chirho) = path_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
        else {
            continue;
        };
        if !claimed_chirho.contains(file_name_chirho) {
            gaps_chirho.push(ComplianceCoverageGapChirho {
                path_chirho: file_name_chirho.to_string(),
                reason_chirho: if historical_untyped_chirho.contains(file_name_chirho) {
                    "historical-product-jsonl-without-active-typed-collector-chirho".to_string()
                } else {
                    "unmapped-production-jsonl-chirho".to_string()
                },
            });
        }
    }
    gaps_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.path_chirho.cmp(&right_chirho.path_chirho)
    });
    Ok(gaps_chirho)
}
fn claimed_jsonl_files_chirho() -> BTreeSet<&'static str> {
    let mut files_chirho: BTreeSet<&'static str> =
        claimed_source_files_chirho().into_keys().collect();
    files_chirho.insert("compliance-evidence-chirho.jsonl");
    files_chirho
}
fn historical_untyped_jsonl_files_chirho() -> BTreeSet<&'static str> {
    [
        "connect-accounts-chirho.jsonl",
        "knowledge-answers-chirho.jsonl",
        "knowledge-records-chirho.jsonl",
        "news-center-records-chirho.jsonl",
        "payouts-chirho.jsonl",
        "provider-invoices-chirho.jsonl",
        "reconciliation-reports-chirho.jsonl",
        "statements-chirho.jsonl",
        "stripe-dispute-observations-chirho.jsonl",
        "stripe-payout-intents-chirho.jsonl",
        "stripe-payout-observations-chirho.jsonl",
        "stripe-topup-observations-chirho.jsonl",
    ]
    .into_iter()
    .collect()
}
fn claimed_source_files_chirho() -> BTreeMap<&'static str, &'static str> {
    [
        (
            "topology-plan-index-chirho.jsonl",
            "placement.topology-plan-index-chirho",
        ),
        (
            "agent-authority-responses-chirho.jsonl",
            "agent-authority.responses-chirho",
        ),
        (
            "agent-report-budgets-chirho.jsonl",
            "agent-reports.budget-grants-chirho",
        ),
        (
            "agent-report-charges-chirho.jsonl",
            "agent-reports.charges-chirho",
        ),
        ("agent-reports-chirho.jsonl", "agent-reports.records-chirho"),
        (
            "app-input-policy-records-chirho.jsonl",
            "apps.input-policies-chirho",
        ),
        (
            "app-request-access-policy-records-chirho.jsonl",
            "apps.request-access-policies-chirho",
        ),
        (
            "app-key-authority-chirho.jsonl",
            "apps.key-authorities-chirho",
        ),
        ("app-records-chirho.jsonl", "apps.records-chirho"),
        ("app-params-records-chirho.jsonl", "apps.params-chirho"),
        (
            "app-build-request-records-chirho.jsonl",
            "apps.build-requests-chirho",
        ),
        (
            "app-static-asset-records-chirho.jsonl",
            "apps.static-assets-chirho",
        ),
        (
            "client-owner-bindings-chirho.jsonl",
            "apps.client-owner-bindings-chirho",
        ),
        (
            "app-response-policy-records-chirho.jsonl",
            "apps.response-policies-chirho",
        ),
        (
            "app-route-response-policy-records-chirho.jsonl",
            "apps.route-response-policies-chirho",
        ),
        ("app-route-records-chirho.jsonl", "apps.routes-chirho"),
        (
            "template-app-deploy-records-chirho.jsonl",
            "apps.template-deploys-chirho",
        ),
        (
            "template-registry-records-chirho.jsonl",
            "apps.template-registry-chirho",
        ),
        (
            "billing-compensations-chirho.jsonl",
            "billing.compensations-chirho",
        ),
        (
            "billing-policy-records-chirho.jsonl",
            "billing.policies-chirho",
        ),
        ("billing-usage-chirho.jsonl", "billing.usage-chirho"),
        (
            "capability-grants-chirho.jsonl",
            "attenuation.grants-chirho",
        ),
        (
            "compensation-executions-chirho.jsonl",
            "reversion.executions-chirho",
        ),
        (
            "compensations-chirho.jsonl",
            "reversion.compensations-chirho",
        ),
        ("credit-holds-chirho.jsonl", "holds.records-chirho"),
        (
            "data-residency-attestations-chirho.jsonl",
            "data-residency.attestations-chirho",
        ),
        (
            "data-residency-policies-chirho.jsonl",
            "data-residency.policies-chirho",
        ),
        ("domain-bindings-chirho.jsonl", "domains.bindings-chirho"),
        ("dns-applies-chirho.jsonl", "dns.applies-chirho"),
        ("dns-zones-chirho.jsonl", "dns.zones-chirho"),
        (
            "volatile-effects-chirho.jsonl",
            "effects.volatile-records-chirho",
        ),
        (
            "gate1-authority-log-chirho.jsonl",
            "gate1.authority-log-chirho",
        ),
        ("head-removals-chirho.jsonl", "refs.head-removals-chirho"),
        ("identities-chirho.jsonl", "identity.records-chirho"),
        (
            "identity-auth-attempts-chirho.jsonl",
            "identity.auth-attempts-chirho",
        ),
        (
            "identity-credential-change-attempts-chirho.jsonl",
            "identity.credential-change-attempts-chirho",
        ),
        (
            "identity-credential-resets-chirho.jsonl",
            "identity.credential-resets-chirho",
        ),
        (
            "identity-recovery-code-events-chirho.jsonl",
            "identity.recovery-code-events-chirho",
        ),
        (
            "identity-session-revocations-chirho.jsonl",
            "identity.session-revocations-chirho",
        ),
        ("identity-sessions-chirho.jsonl", "identity.sessions-chirho"),
        ("ledger-chirho.jsonl", "ledger.entries-chirho"),
        (
            "legal-hold-records-chirho.jsonl",
            "legal-holds.records-chirho",
        ),
        ("mailbox-applies-chirho.jsonl", "mailboxes.applies-chirho"),
        ("mailboxes-chirho.jsonl", "mailboxes.records-chirho"),
        (
            "manual-remediations-chirho.jsonl",
            "reversion.manual-resolutions-chirho",
        ),
        (
            "native-stateless-attestations-chirho.jsonl",
            "native.stateless-attestations-chirho",
        ),
        ("oauth-clients-chirho.jsonl", "oauth.clients-chirho"),
        (
            "oauth-connection-clients-chirho.jsonl",
            "oauth.connection-clients-chirho",
        ),
        (
            "connection-tokens-chirho.jsonl",
            "oauth.connection-tokens-chirho",
        ),
        (
            "connection-token-uses-chirho.jsonl",
            "oauth.connection-token-uses-chirho",
        ),
        (
            "onboarding-records-chirho.jsonl",
            "onboarding.records-chirho",
        ),
        ("pricebook-records-chirho.jsonl", "pricebook.records-chirho"),
        (
            "publication-applied-chirho.jsonl",
            "publication.applied-chirho",
        ),
        (
            "publication-intents-chirho.jsonl",
            "publication.intents-chirho",
        ),
        (
            "publication-owners-chirho.jsonl",
            "publication.owners-chirho",
        ),
        (
            "publication-reserved-slugs-chirho.jsonl",
            "publication.reserved-slugs-chirho",
        ),
        ("slug-claims-chirho.jsonl", "publication.slug-claims-chirho"),
        (
            "privacy-blob-records-chirho.jsonl",
            "privacy.blob-records-chirho",
        ),
        (
            "private-dag-values-chirho.jsonl",
            "privacy.private-dag-values-chirho",
        ),
        (
            "privacy-access-records-chirho.jsonl",
            "privacy.access-records-chirho",
        ),
        (
            "privacy-backup-key-policies-chirho.jsonl",
            "privacy.backup-key-policies-chirho",
        ),
        (
            "privacy-retention-records-chirho.jsonl",
            "privacy.retention-records-chirho",
        ),
        (
            "privacy-erasure-records-chirho.jsonl",
            "privacy.erasure-records-chirho",
        ),
        (
            "privacy-erasure-propagations-chirho.jsonl",
            "privacy.erasure-propagations-chirho",
        ),
        (
            "privacy-export-records-chirho.jsonl",
            "privacy.export-evidence-chirho",
        ),
        (
            "privacy-replica-targets-chirho.jsonl",
            "privacy.replica-targets-chirho",
        ),
        (
            "realtime-epilogues-chirho.jsonl",
            "realtime.epilogues-chirho",
        ),
        ("realtime-events-chirho.jsonl", "realtime.events-chirho"),
        ("realtime-sessions-chirho.jsonl", "realtime.sessions-chirho"),
        (
            "resource-policy-records-chirho.jsonl",
            "resource.policies-chirho",
        ),
        (
            "resource-policy-unset-records-chirho.jsonl",
            "resource.policy-unsets-chirho",
        ),
        ("resource-usage-chirho.jsonl", "resource.usage-chirho"),
        (
            "review-policy-envelopes-chirho.jsonl",
            // Intentional plural: compliance source labels use `reviews.*`; export labels use singular `review.*` for SecurityChangeAudit retention.
            "reviews.policy-envelopes-chirho",
        ),
        ("review-records-chirho.jsonl", "reviews.records-chirho"),
        ("reflog-chirho.jsonl", "refs.reflog-chirho"),
        (
            "rollback-completions-chirho.jsonl",
            "reversion.rollback-completions-chirho",
        ),
        (
            "rollback-events-chirho.jsonl",
            "reversion.rollback-events-chirho",
        ),
        ("run-intents-chirho.jsonl", "run-intents.records-chirho"),
        (
            "scoped-token-uses-chirho.jsonl",
            "oauth.scoped-token-uses-chirho",
        ),
        ("scoped-tokens-chirho.jsonl", "oauth.scoped-tokens-chirho"),
    ]
    .into_iter()
    .collect()
}

fn root_jsonl_paths_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    if !root_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    for entry_chirho in std::fs::read_dir(root_chirho)? {
        let path_chirho = entry_chirho?.path();
        if path_chirho
            .extension()
            .and_then(|ext_chirho| ext_chirho.to_str())
            == Some("jsonl")
        {
            paths_chirho.push(path_chirho);
        }
    }
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn validate_pack_against_record_chirho(
    pack_chirho: &ComplianceEvidencePackChirho,
    record_chirho: &ComplianceEvidenceRecordChirho,
) -> Result<()> {
    if pack_chirho.schema_chirho != COMPLIANCE_EVIDENCE_SCHEMA_CHIRHO {
        bail!(
            "unsupported compliance evidence schema '{}'",
            pack_chirho.schema_chirho
        );
    }
    if pack_chirho.frameworks_chirho != record_chirho.frameworks_chirho {
        bail!("compliance evidence framework mismatch");
    }
    if pack_chirho.period_start_ms_chirho != record_chirho.period_start_ms_chirho
        || pack_chirho.period_end_ms_chirho != record_chirho.period_end_ms_chirho
    {
        bail!("compliance evidence period mismatch");
    }
    if pack_chirho.generated_by_chirho != record_chirho.generated_by_chirho {
        bail!("compliance evidence generated_by mismatch");
    }
    if pack_chirho.controls_chirho.len() != record_chirho.control_count_chirho
        || pack_chirho.sources_chirho.len() != record_chirho.source_count_chirho
    {
        bail!("compliance evidence count mismatch");
    }
    control_counts_chirho(&pack_chirho.controls_chirho)?;
    let source_digest_chirho =
        digest_value_chirho(&serde_json::to_value(&pack_chirho.sources_chirho)?)?;
    if source_digest_chirho != pack_chirho.source_digest_chirho
        || source_digest_chirho != record_chirho.source_digest_chirho
    {
        bail!("compliance evidence source digest mismatch");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ControlCountsChirho {
    total_chirho: usize,
    evidence_backed_chirho: usize,
    manual_required_chirho: usize,
}

fn control_counts_chirho(
    controls_chirho: &[ComplianceControlEvidenceChirho],
) -> Result<ControlCountsChirho> {
    let mut counts_chirho = ControlCountsChirho {
        total_chirho: controls_chirho.len(),
        ..ControlCountsChirho::default()
    };
    for control_chirho in controls_chirho {
        match control_chirho.status_chirho.as_str() {
            "evidence-backed-chirho" => counts_chirho.evidence_backed_chirho += 1,
            "manual-required-chirho" => counts_chirho.manual_required_chirho += 1,
            other_chirho => bail!(
                "unsupported compliance control status '{}' for {}",
                other_chirho,
                control_chirho.control_chirho
            ),
        }
    }
    Ok(counts_chirho)
}

fn validate_record_chirho(record_chirho: &ComplianceEvidenceRecordChirho) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != COMPLIANCE_EVIDENCE_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported compliance evidence record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    if record_chirho.period_end_ms_chirho <= record_chirho.period_start_ms_chirho {
        bail!("compliance evidence record has invalid period");
    }
    validate_token_chirho("generated_by_chirho", &record_chirho.generated_by_chirho)?;
    let normalized_chirho = normalize_frameworks_chirho(&record_chirho.frameworks_chirho)?;
    if normalized_chirho != record_chirho.frameworks_chirho {
        bail!("compliance evidence record frameworks are not canonical");
    }
    if record_chirho.control_count_chirho == 0 || record_chirho.source_count_chirho == 0 {
        bail!("compliance evidence record is empty");
    }
    Ok(())
}

fn validate_token_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("{name_chirho} must be a short opaque token");
    }
    Ok(())
}

fn compliance_evidence_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("compliance-evidence-chirho.jsonl")
}

fn compliance_evidence_record_message_chirho(
    record_chirho: &ComplianceEvidenceRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

pub(super) fn digest_value_chirho(value_chirho: &Value) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(value_chirho)?)
        .to_hex()
        .to_string())
}

fn load_jsonl_chirho<T: for<'de> Deserialize<'de>>(path_chirho: &Path) -> Result<Vec<T>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho).with_context(|| {
            format!("decode {} line {}", path_chirho.display(), index_chirho + 1)
        })?);
    }
    Ok(records_chirho)
}

#[cfg(test)]
#[path = "compliance_evidence_chirho/tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "compliance_evidence_chirho/topology_index_evidence_tests_chirho.rs"]
mod topology_index_evidence_tests_chirho;
