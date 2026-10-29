// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Records and verifies per-subject legal holds that pause crypto-shred erasure.

use crate::seqlog_chirho;
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SUBJECT_RIGHTS_LOCK_CHIRHO: &str = "privacy-subject-rights-chirho";
const LEGAL_HOLD_RECORDS_LOCK_CHIRHO: &str = "legal-hold-records-chirho";
const LEGAL_HOLD_RECORD_SCHEMA_CHIRHO: &str = "legal-hold-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegalHoldActionChirho {
    PlaceChirho,
    ReleaseChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHoldRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub hold_id_chirho: String,
    pub subject_chirho: String,
    pub case_ref_chirho: String,
    pub reason_chirho: String,
    pub action_chirho: LegalHoldActionChirho,
    pub operator_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHoldVerifyReportChirho {
    pub records_chirho: usize,
    pub active_holds_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LegalHoldStateChirho {
    record_chirho: LegalHoldRecordChirho,
    active_chirho: bool,
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn legal_hold_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("legal-hold-records-chirho.jsonl")
}

pub fn place_legal_hold_chirho(
    root_chirho: &Path,
    hold_id_chirho: &str,
    subject_chirho: &str,
    case_ref_chirho: &str,
    reason_chirho: &str,
    operator_chirho: &str,
) -> Result<LegalHoldRecordChirho> {
    append_legal_hold_action_chirho(
        root_chirho,
        hold_id_chirho,
        subject_chirho,
        case_ref_chirho,
        reason_chirho,
        LegalHoldActionChirho::PlaceChirho,
        operator_chirho,
    )
}

pub fn release_legal_hold_chirho(
    root_chirho: &Path,
    hold_id_chirho: &str,
    reason_chirho: &str,
    operator_chirho: &str,
) -> Result<LegalHoldRecordChirho> {
    validate_safe_token_chirho("legal hold id", hold_id_chirho)?;
    validate_safe_token_chirho("legal hold reason", reason_chirho)?;
    validate_safe_token_chirho("legal hold operator", operator_chirho)?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, SUBJECT_RIGHTS_LOCK_CHIRHO, || {
        seqlog_chirho::with_named_lock_chirho(root_chirho, LEGAL_HOLD_RECORDS_LOCK_CHIRHO, || {
            let state_chirho = legal_hold_states_chirho(root_chirho)?;
            let active_chirho = state_chirho
                .get(hold_id_chirho)
                .filter(|state_chirho| state_chirho.active_chirho)
                .ok_or_else(|| anyhow!("legal hold '{hold_id_chirho}' is not active"))?;
            append_legal_hold_action_unlocked_chirho(
                root_chirho,
                hold_id_chirho,
                &active_chirho.record_chirho.subject_chirho,
                &active_chirho.record_chirho.case_ref_chirho,
                reason_chirho,
                LegalHoldActionChirho::ReleaseChirho,
                operator_chirho,
            )
        })
    })
}

pub fn load_legal_hold_records_chirho(root_chirho: &Path) -> Result<Vec<LegalHoldRecordChirho>> {
    load_jsonl_chirho(&legal_hold_records_path_chirho(root_chirho))
}

pub fn active_legal_holds_for_subject_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
) -> Result<Vec<LegalHoldRecordChirho>> {
    validate_safe_token_chirho("legal hold subject", subject_chirho)?;
    let mut records_chirho: Vec<_> = legal_hold_states_chirho(root_chirho)?
        .into_values()
        .filter(|state_chirho| {
            state_chirho.active_chirho
                && state_chirho.record_chirho.subject_chirho == subject_chirho
        })
        .map(|state_chirho| state_chirho.record_chirho)
        .collect();
    records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
    Ok(records_chirho)
}

pub fn verify_legal_holds_chirho(root_chirho: &Path) -> Result<LegalHoldVerifyReportChirho> {
    let records_chirho = load_legal_hold_records_chirho(root_chirho)?;
    let states_chirho = verify_legal_hold_records_chirho(root_chirho, &records_chirho)?;
    Ok(LegalHoldVerifyReportChirho {
        records_chirho: records_chirho.len(),
        active_holds_chirho: states_chirho
            .values()
            .filter(|state_chirho| state_chirho.active_chirho)
            .count(),
    })
}

fn append_legal_hold_action_chirho(
    root_chirho: &Path,
    hold_id_chirho: &str,
    subject_chirho: &str,
    case_ref_chirho: &str,
    reason_chirho: &str,
    action_chirho: LegalHoldActionChirho,
    operator_chirho: &str,
) -> Result<LegalHoldRecordChirho> {
    validate_safe_token_chirho("legal hold id", hold_id_chirho)?;
    validate_safe_token_chirho("legal hold subject", subject_chirho)?;
    validate_safe_token_chirho("legal hold case ref", case_ref_chirho)?;
    validate_safe_token_chirho("legal hold reason", reason_chirho)?;
    validate_safe_token_chirho("legal hold operator", operator_chirho)?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, SUBJECT_RIGHTS_LOCK_CHIRHO, || {
        seqlog_chirho::with_named_lock_chirho(root_chirho, LEGAL_HOLD_RECORDS_LOCK_CHIRHO, || {
            let state_chirho = legal_hold_states_chirho(root_chirho)?;
            match action_chirho {
                LegalHoldActionChirho::PlaceChirho => {
                    if state_chirho
                        .get(hold_id_chirho)
                        .is_some_and(|state_chirho| state_chirho.active_chirho)
                    {
                        bail!("legal hold '{hold_id_chirho}' is already active");
                    }
                }
                LegalHoldActionChirho::ReleaseChirho => {
                    if !state_chirho
                        .get(hold_id_chirho)
                        .is_some_and(|state_chirho| state_chirho.active_chirho)
                    {
                        bail!("legal hold '{hold_id_chirho}' is not active");
                    }
                }
            }
            append_legal_hold_action_unlocked_chirho(
                root_chirho,
                hold_id_chirho,
                subject_chirho,
                case_ref_chirho,
                reason_chirho,
                action_chirho,
                operator_chirho,
            )
        })
    })
}

fn append_legal_hold_action_unlocked_chirho(
    root_chirho: &Path,
    hold_id_chirho: &str,
    subject_chirho: &str,
    case_ref_chirho: &str,
    reason_chirho: &str,
    action_chirho: LegalHoldActionChirho,
    operator_chirho: &str,
) -> Result<LegalHoldRecordChirho> {
    let path_chirho = legal_hold_records_path_chirho(root_chirho);
    let seq_chirho = load_legal_hold_records_chirho(root_chirho)?.len() as u64;
    let mut record_chirho = LegalHoldRecordChirho {
        schema_chirho: LEGAL_HOLD_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        hold_id_chirho: hold_id_chirho.to_string(),
        subject_chirho: subject_chirho.to_string(),
        case_ref_chirho: case_ref_chirho.to_string(),
        reason_chirho: reason_chirho.to_string(),
        action_chirho,
        operator_chirho: operator_chirho.to_string(),
        at_ms_chirho: now_ms_chirho(),
        sig_chirho: String::new(),
    };
    let message_chirho = legal_hold_record_message_chirho(&record_chirho)?;
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
    seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
        &path_chirho,
        record_chirho.seq_chirho,
        &record_chirho,
    )?;
    Ok(record_chirho)
}

fn legal_hold_states_chirho(root_chirho: &Path) -> Result<BTreeMap<String, LegalHoldStateChirho>> {
    let records_chirho = load_legal_hold_records_chirho(root_chirho)?;
    verify_legal_hold_records_chirho(root_chirho, &records_chirho)
}

fn verify_legal_hold_records_chirho(
    root_chirho: &Path,
    records_chirho: &[LegalHoldRecordChirho],
) -> Result<BTreeMap<String, LegalHoldStateChirho>> {
    // A verifier never mints a key: an empty log needs none, and a non-empty one is checked against
    // the EXISTING key. Every erasure reads the holds first, so this is the erasure road too (C5 B3-a1).
    if records_chirho.is_empty() {
        return Ok(BTreeMap::new());
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut states_chirho: BTreeMap<String, LegalHoldStateChirho> = BTreeMap::new();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "legal hold seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_legal_hold_record_chirho(record_chirho)?;
        let message_chirho = legal_hold_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "legal hold record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        match record_chirho.action_chirho {
            LegalHoldActionChirho::PlaceChirho => {
                if states_chirho
                    .get(&record_chirho.hold_id_chirho)
                    .is_some_and(|state_chirho| state_chirho.active_chirho)
                {
                    bail!(
                        "legal hold '{}' placed while already active",
                        record_chirho.hold_id_chirho
                    );
                }
                states_chirho.insert(
                    record_chirho.hold_id_chirho.clone(),
                    LegalHoldStateChirho {
                        record_chirho: record_chirho.clone(),
                        active_chirho: true,
                    },
                );
            }
            LegalHoldActionChirho::ReleaseChirho => {
                let state_chirho = states_chirho
                    .get_mut(&record_chirho.hold_id_chirho)
                    .ok_or_else(|| {
                        anyhow!(
                            "legal hold '{}' released before placement",
                            record_chirho.hold_id_chirho
                        )
                    })?;
                if !state_chirho.active_chirho {
                    bail!(
                        "legal hold '{}' released while inactive",
                        record_chirho.hold_id_chirho
                    );
                }
                if state_chirho.record_chirho.subject_chirho != record_chirho.subject_chirho
                    || state_chirho.record_chirho.case_ref_chirho != record_chirho.case_ref_chirho
                {
                    bail!(
                        "legal hold '{}' release does not match placed subject/case",
                        record_chirho.hold_id_chirho
                    );
                }
                state_chirho.active_chirho = false;
            }
        }
    }
    Ok(states_chirho)
}

fn validate_legal_hold_record_chirho(record_chirho: &LegalHoldRecordChirho) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != LEGAL_HOLD_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported legal hold record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    validate_safe_token_chirho("legal hold id", &record_chirho.hold_id_chirho)?;
    validate_safe_token_chirho("legal hold subject", &record_chirho.subject_chirho)?;
    validate_safe_token_chirho("legal hold case ref", &record_chirho.case_ref_chirho)?;
    validate_safe_token_chirho("legal hold reason", &record_chirho.reason_chirho)?;
    validate_safe_token_chirho("legal hold operator", &record_chirho.operator_chirho)
}

fn validate_safe_token_chirho(label_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 256
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("{label_chirho} must be a short opaque token");
    }
    Ok(())
}

fn legal_hold_record_message_chirho(record_chirho: &LegalHoldRecordChirho) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

fn load_jsonl_chirho<T>(path_chirho: &Path) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut out_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        out_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(out_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let pid_chirho = std::process::id();
        std::env::temp_dir().join(format!(
            "cairn-legal-hold-test-{pid_chirho}-{n_chirho}-{}",
            now_ms_chirho()
        ))
    }

    #[test]
    fn legal_hold_place_release_and_verify_chirho() {
        let root_chirho = tmp_root_chirho();
        let placed_chirho = place_legal_hold_chirho(
            &root_chirho,
            "hold/case-1",
            "user/alice",
            "case/privacy-1",
            "litigation",
            "operator/legal",
        )
        .unwrap();
        assert_eq!(placed_chirho.seq_chirho, 0);
        assert_eq!(
            active_legal_holds_for_subject_chirho(&root_chirho, "user/alice")
                .unwrap()
                .len(),
            1
        );
        let report_chirho = verify_legal_holds_chirho(&root_chirho).unwrap();
        assert_eq!(report_chirho.records_chirho, 1);
        assert_eq!(report_chirho.active_holds_chirho, 1);
        let released_chirho =
            release_legal_hold_chirho(&root_chirho, "hold/case-1", "case-closed", "operator/legal")
                .unwrap();
        assert_eq!(released_chirho.seq_chirho, 1);
        assert!(
            active_legal_holds_for_subject_chirho(&root_chirho, "user/alice")
                .unwrap()
                .is_empty()
        );
        let report_chirho = verify_legal_holds_chirho(&root_chirho).unwrap();
        assert_eq!(report_chirho.records_chirho, 2);
        assert_eq!(report_chirho.active_holds_chirho, 0);
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn legal_hold_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
        let root_chirho = tmp_root_chirho();
        let placed_chirho = place_legal_hold_chirho(
            &root_chirho,
            "hold/case-1",
            "user/alice",
            "case/privacy-1",
            "litigation",
            "operator/legal",
        )
        .unwrap();
        let released_chirho =
            release_legal_hold_chirho(&root_chirho, "hold/case-1", "case-closed", "operator/legal")
                .unwrap();
        assert_eq!(placed_chirho.schema_chirho, LEGAL_HOLD_RECORD_SCHEMA_CHIRHO);
        assert_eq!(
            released_chirho.schema_chirho,
            LEGAL_HOLD_RECORD_SCHEMA_CHIRHO
        );
        let path_chirho = legal_hold_records_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        assert_eq!(
            text_chirho.matches(LEGAL_HOLD_RECORD_SCHEMA_CHIRHO).count(),
            2
        );

        std::fs::write(
            &path_chirho,
            text_chirho.replace(
                LEGAL_HOLD_RECORD_SCHEMA_CHIRHO,
                "legal-hold-record-v9-chirho",
            ),
        )
        .unwrap();
        let error_chirho = verify_legal_holds_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unsupported legal hold record schema"));

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn legacy_legal_hold_records_without_schema_still_verify_chirho() {
        let root_chirho = tmp_root_chirho();
        place_legal_hold_chirho(
            &root_chirho,
            "hold/case-1",
            "user/alice",
            "case/privacy-1",
            "litigation",
            "operator/legal",
        )
        .unwrap();
        release_legal_hold_chirho(&root_chirho, "hold/case-1", "case-closed", "operator/legal")
            .unwrap();

        let mut records_chirho = load_legal_hold_records_chirho(&root_chirho).unwrap();
        for record_chirho in &mut records_chirho {
            record_chirho.schema_chirho.clear();
            record_chirho.sig_chirho.clear();
            record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
                &root_chirho,
                &legal_hold_record_message_chirho(record_chirho).unwrap(),
            )
            .unwrap();
        }
        let legacy_text_chirho = records_chirho
            .iter()
            .map(|record_chirho| serde_json::to_string(record_chirho).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            legal_hold_records_path_chirho(&root_chirho),
            format!("{legacy_text_chirho}\n"),
        )
        .unwrap();
        let text_chirho =
            std::fs::read_to_string(legal_hold_records_path_chirho(&root_chirho)).unwrap();
        assert!(!text_chirho.contains("schema_chirho"));
        let report_chirho = verify_legal_holds_chirho(&root_chirho).unwrap();
        assert_eq!(report_chirho.records_chirho, 2);
        assert_eq!(report_chirho.active_holds_chirho, 0);

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn legal_hold_rejects_duplicate_active_place_chirho() {
        let root_chirho = tmp_root_chirho();
        place_legal_hold_chirho(
            &root_chirho,
            "hold/case-1",
            "user/alice",
            "case/privacy-1",
            "litigation",
            "operator/legal",
        )
        .unwrap();
        let error_chirho = place_legal_hold_chirho(
            &root_chirho,
            "hold/case-1",
            "user/alice",
            "case/privacy-1",
            "duplicate",
            "operator/legal",
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("already active"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}
