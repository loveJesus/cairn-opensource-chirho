// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::load_privacy_blob_records_chirho;
use crate::app_chirho;
use crate::cas_chirho;
use crate::dag_private_value_chirho;
use crate::effect_chirho;
use crate::model_chirho::{EffectChirho, HashChirho};
use crate::seqlog_chirho;
use crate::store_chirho;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const PRIVACY_SCAN_REPORT_SCHEMA_CHIRHO: &str = "privacy-scan-report-v1-chirho";
pub(super) const RUNTIME_JSON_SCAN_DIRS_CHIRHO: &[&str] = &[
    "effects-chirho",
    "runs-chirho",
    "runkeys-chirho",
    "runseals-chirho",
    "writer-fences-chirho",
    "gate1-authority-head-chirho",
    // Account attribution: its logs, freezes, subject owners and coverage debts (agy #28931).
    "privacy-account-attribution-chirho",
    // The leader's erasure-propagation requirements and bindings (C5 B3-a2-ii).
    "privacy-erasure-propagation-chirho",
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyScanFindingChirho {
    pub source_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_chirho: Option<u64>,
    pub path_chirho: String,
    pub kind_chirho: String,
    pub detail_chirho: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyScanReportChirho {
    pub schema_chirho: String,
    pub jsonl_files_chirho: usize,
    pub jsonl_rows_chirho: usize,
    pub json_objects_chirho: usize,
    pub effect_records_chirho: usize,
    pub effect_cas_objects_chirho: usize,
    pub effect_cas_json_objects_chirho: usize,
    pub effect_cas_private_ciphertexts_skipped_chirho: usize,
    pub effect_cas_binary_objects_skipped_chirho: usize,
    pub effect_form_fields_chirho: usize,
    #[serde(default)]
    pub seqlog_quarantine_files_chirho: usize,
    #[serde(default)]
    pub seqlog_quarantine_bytes_chirho: usize,
    pub findings_chirho: Vec<PrivacyScanFindingChirho>,
}

pub fn scan_privacy_surfaces_chirho(root_chirho: &Path) -> Result<PrivacyScanReportChirho> {
    let mut report_chirho = PrivacyScanReportChirho {
        schema_chirho: PRIVACY_SCAN_REPORT_SCHEMA_CHIRHO.to_string(),
        jsonl_files_chirho: 0,
        jsonl_rows_chirho: 0,
        json_objects_chirho: 0,
        effect_records_chirho: 0,
        effect_cas_objects_chirho: 0,
        effect_cas_json_objects_chirho: 0,
        effect_cas_private_ciphertexts_skipped_chirho: 0,
        effect_cas_binary_objects_skipped_chirho: 0,
        effect_form_fields_chirho: 0,
        seqlog_quarantine_files_chirho: 0,
        seqlog_quarantine_bytes_chirho: 0,
        findings_chirho: Vec::new(),
    };
    for path_chirho in root_jsonl_paths_chirho(root_chirho)? {
        report_chirho.jsonl_files_chirho += 1;
        let text_chirho = std::fs::read_to_string(&path_chirho)
            .with_context(|| format!("read {}", path_chirho.display()))?;
        for (i_chirho, line_chirho) in text_chirho.lines().enumerate() {
            if line_chirho.trim().is_empty() {
                continue;
            }
            report_chirho.jsonl_rows_chirho += 1;
            let value_chirho: Value = serde_json::from_str(line_chirho).with_context(|| {
                format!("parse {} line {}", path_chirho.display(), i_chirho + 1)
            })?;
            scan_json_value_chirho(
                &jsonl_source_name_chirho(root_chirho, &path_chirho),
                Some((i_chirho + 1) as u64),
                "$",
                &value_chirho,
                &mut report_chirho.findings_chirho,
            );
        }
    }
    let private_ciphertexts_chirho = private_ciphertext_hashes_for_scan_chirho(root_chirho)?;
    let public_app_param_hashes_chirho = public_app_params_hashes_for_scan_chirho(root_chirho)?;
    for path_chirho in runtime_json_paths_for_scan_chirho(root_chirho)? {
        let bytes_chirho = std::fs::read(&path_chirho)
            .with_context(|| format!("read {}", path_chirho.display()))?;
        let Ok(value_chirho) = serde_json::from_slice::<Value>(&bytes_chirho) else {
            continue;
        };
        report_chirho.json_objects_chirho += 1;
        scan_json_value_chirho(
            &object_source_name_chirho(root_chirho, &path_chirho),
            None,
            "$",
            &value_chirho,
            &mut report_chirho.findings_chirho,
        );
    }
    for path_chirho in object_paths_for_scan_chirho(root_chirho)? {
        let object_hash_chirho = object_hash_from_path_chirho(root_chirho, &path_chirho);
        if object_hash_chirho
            .as_ref()
            .is_some_and(|hash_chirho| public_app_param_hashes_chirho.contains(hash_chirho))
        {
            continue;
        }
        if object_path_is_private_ciphertext_chirho(
            root_chirho,
            &path_chirho,
            &private_ciphertexts_chirho,
        ) {
            continue;
        }
        // Intentional raw inventory read: privacy-scan must inspect the bytes that are actually
        // present on disk, while content-return paths use the verifying CAS getter.
        let bytes_chirho = std::fs::read(&path_chirho)
            .with_context(|| format!("read {}", path_chirho.display()))?;
        let Ok(value_chirho) = serde_json::from_slice::<Value>(&bytes_chirho) else {
            continue;
        };
        if public_app_params_wrapper_chirho(&value_chirho, &public_app_param_hashes_chirho)? {
            continue;
        }
        report_chirho.json_objects_chirho += 1;
        scan_json_value_chirho(
            &object_source_name_chirho(root_chirho, &path_chirho),
            None,
            "$",
            &value_chirho,
            &mut report_chirho.findings_chirho,
        );
    }
    scan_seqlog_quarantine_sidecars_chirho(root_chirho, &mut report_chirho)?;
    scan_effect_cas_surfaces_chirho(root_chirho, &private_ciphertexts_chirho, &mut report_chirho)?;
    Ok(report_chirho)
}

fn private_ciphertext_hashes_for_scan_chirho(root_chirho: &Path) -> Result<BTreeSet<String>> {
    Ok(load_privacy_blob_records_chirho(root_chirho)?
        .into_iter()
        .map(|record_chirho| record_chirho.blob_chirho.ciphertext_chirho.0)
        .collect())
}

fn public_app_params_hashes_for_scan_chirho(root_chirho: &Path) -> Result<BTreeSet<String>> {
    app_chirho::verify_app_params_chirho(root_chirho)?;
    Ok(app_chirho::load_app_params_records_chirho(root_chirho)?
        .into_iter()
        .map(|record_chirho| record_chirho.params_chirho.0)
        .collect())
}

fn public_app_params_wrapper_chirho(
    value_chirho: &Value,
    public_app_param_hashes_chirho: &BTreeSet<String>,
) -> Result<bool> {
    let Some(object_chirho) = value_chirho.as_object() else {
        return Ok(false);
    };
    if object_chirho.len() != 1 {
        return Ok(false);
    }
    let Some(params_chirho) = object_chirho.get("app_params_chirho") else {
        return Ok(false);
    };
    let hash_chirho = store_chirho::hash_object_chirho(params_chirho)?;
    Ok(public_app_param_hashes_chirho.contains(&hash_chirho.0))
}

fn object_path_is_private_ciphertext_chirho(
    root_chirho: &Path,
    path_chirho: &Path,
    private_ciphertexts_chirho: &BTreeSet<String>,
) -> bool {
    object_hash_from_path_chirho(root_chirho, path_chirho)
        .as_ref()
        .is_some_and(|hash_chirho| private_ciphertexts_chirho.contains(hash_chirho))
}

fn object_hash_from_path_chirho(root_chirho: &Path, path_chirho: &Path) -> Option<String> {
    let objects_dir_chirho = root_chirho.join("objects-chirho");
    let relative_chirho = path_chirho.strip_prefix(objects_dir_chirho).ok()?;
    let mut components_chirho = relative_chirho.components();
    let shard_chirho = components_chirho.next()?.as_os_str().to_str()?;
    let rest_chirho = components_chirho.next()?.as_os_str().to_str()?;
    if components_chirho.next().is_some() {
        return None;
    }
    Some(format!("{shard_chirho}{rest_chirho}"))
}

fn root_jsonl_paths_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    if !root_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    collect_jsonl_paths_chirho(root_chirho, root_chirho, &mut paths_chirho)?;
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn collect_jsonl_paths_chirho(
    root_chirho: &Path,
    dir_chirho: &Path,
    paths_chirho: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry_chirho in std::fs::read_dir(dir_chirho)? {
        let path_chirho = entry_chirho?.path();
        if path_chirho.is_dir() {
            if privacy_scan_skip_dir_chirho(root_chirho, &path_chirho) {
                continue;
            }
            collect_jsonl_paths_chirho(root_chirho, &path_chirho, paths_chirho)?;
            continue;
        }
        // seqlog `.head-chirho` sidecars: deliberately excluded — see the by-design pin test.
        if path_chirho
            .extension()
            .and_then(|ext_chirho| ext_chirho.to_str())
            == Some("jsonl")
        {
            paths_chirho.push(path_chirho);
        }
    }
    Ok(())
}

fn scan_seqlog_quarantine_sidecars_chirho(
    root_chirho: &Path,
    report_chirho: &mut PrivacyScanReportChirho,
) -> Result<()> {
    for path_chirho in seqlog_chirho::seqlog_quarantine_sidecar_paths_chirho(root_chirho)? {
        let bytes_chirho = std::fs::read(&path_chirho)
            .with_context(|| format!("read {}", path_chirho.display()))?;
        report_chirho.seqlog_quarantine_files_chirho += 1;
        report_chirho.seqlog_quarantine_bytes_chirho += bytes_chirho.len();
        let Ok(text_chirho) = std::str::from_utf8(&bytes_chirho) else {
            continue;
        };
        inspect_unstructured_body_text_chirho(
            &format!(
                "seqlog-quarantine:{}",
                object_source_name_chirho(root_chirho, &path_chirho)
            ),
            None,
            "$.fragment_chirho",
            text_chirho,
            &mut report_chirho.findings_chirho,
        );
    }
    Ok(())
}

fn privacy_scan_skip_dir_chirho(root_chirho: &Path, path_chirho: &Path) -> bool {
    let relative_chirho = path_chirho.strip_prefix(root_chirho).unwrap_or(path_chirho);
    let first_chirho = relative_chirho
        .components()
        .next()
        .and_then(|component_chirho| component_chirho.as_os_str().to_str())
        .unwrap_or("");
    matches!(
        first_chirho,
        "locks-chirho"
            | "native-workers-chirho"
            | "objects-chirho"
            | "privacy-keys-chirho"
            | "identity-keys-chirho"
            | "writer-fences-chirho"
            | "gate1-authority-head-chirho"
    )
}
fn jsonl_source_name_chirho(root_chirho: &Path, path_chirho: &Path) -> String {
    path_chirho
        .strip_prefix(root_chirho)
        .unwrap_or(path_chirho)
        .display()
        .to_string()
}

fn object_paths_for_scan_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    let objects_dir_chirho = root_chirho.join("objects-chirho");
    if !objects_dir_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    for shard_chirho in std::fs::read_dir(&objects_dir_chirho)? {
        let shard_path_chirho = shard_chirho?.path();
        if !shard_path_chirho.is_dir() {
            continue;
        }
        for object_chirho in std::fs::read_dir(shard_path_chirho)? {
            let object_path_chirho = object_chirho?.path();
            if object_path_chirho.is_file() {
                paths_chirho.push(object_path_chirho);
            }
        }
    }
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn runtime_json_paths_for_scan_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    let mut paths_chirho = Vec::new();
    for dir_chirho in RUNTIME_JSON_SCAN_DIRS_CHIRHO {
        let path_chirho = root_chirho.join(dir_chirho);
        if path_chirho.exists() {
            collect_regular_files_chirho(&path_chirho, &mut paths_chirho)?;
        }
    }
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn scan_effect_cas_surfaces_chirho(
    root_chirho: &Path,
    private_ciphertexts_chirho: &BTreeSet<String>,
    report_chirho: &mut PrivacyScanReportChirho,
) -> Result<()> {
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    if effects_dir_chirho.exists() {
        for path_chirho in collect_regular_files_sorted_chirho(&effects_dir_chirho)? {
            let bytes_chirho = std::fs::read(&path_chirho)
                .with_context(|| format!("read {}", path_chirho.display()))?;
            let Ok(effect_chirho) = serde_json::from_slice::<EffectChirho>(&bytes_chirho) else {
                continue;
            };
            report_chirho.effect_records_chirho += 1;
            let source_chirho = object_source_name_chirho(root_chirho, &path_chirho);
            scan_effect_cas_objects_chirho(
                root_chirho,
                private_ciphertexts_chirho,
                &source_chirho,
                &effect_chirho,
                report_chirho,
            )?;
        }
    }

    for record_chirho in effect_chirho::load_volatile_effect_records_chirho(root_chirho)? {
        report_chirho.effect_records_chirho += 1;
        let source_chirho = format!(
            "volatile-effects-chirho.jsonl#seq={}",
            record_chirho.seq_chirho
        );
        scan_effect_cas_objects_chirho(
            root_chirho,
            private_ciphertexts_chirho,
            &source_chirho,
            &record_chirho.effect_chirho,
            report_chirho,
        )?;
    }
    Ok(())
}

fn scan_effect_cas_objects_chirho(
    root_chirho: &Path,
    private_ciphertexts_chirho: &BTreeSet<String>,
    source_chirho: &str,
    effect_chirho: &EffectChirho,
    report_chirho: &mut PrivacyScanReportChirho,
) -> Result<()> {
    scan_effect_cas_object_chirho(
        root_chirho,
        private_ciphertexts_chirho,
        source_chirho,
        "request",
        &effect_chirho.request_chirho,
        report_chirho,
    )?;
    if let Some(response_chirho) = &effect_chirho.response_chirho {
        scan_effect_cas_object_chirho(
            root_chirho,
            private_ciphertexts_chirho,
            source_chirho,
            "response",
            response_chirho,
            report_chirho,
        )?;
    }
    Ok(())
}

fn scan_effect_cas_object_chirho(
    root_chirho: &Path,
    private_ciphertexts_chirho: &BTreeSet<String>,
    source_chirho: &str,
    role_chirho: &str,
    hash_chirho: &HashChirho,
    report_chirho: &mut PrivacyScanReportChirho,
) -> Result<()> {
    if private_ciphertexts_chirho.contains(&hash_chirho.0) {
        report_chirho.effect_cas_private_ciphertexts_skipped_chirho += 1;
        return Ok(());
    }
    // A private DAG value earns a skip only by being ABSENT from the public plane. Skipping on the
    // record alone hides a real hazard: two effect roles can share one address (legacy reify sends
    // the value as its own request bytes), so a plaintext object sitting in public CAS would be
    // waved through because a private record happened to exist at the same hash — the scan would
    // go quiet over exactly the leak it exists to report.
    //
    // ABSENT means NotFound and nothing else. `cas_chirho::get_chirho` also fails on a CONTENT
    // ADDRESS MISMATCH — a tampered public object — and treating every error alike would launder
    // that tamper into a clean skip whenever a private record happened to exist at the same hash:
    // the loudest signal this scan can receive, converted into a counter that reads as healthy.
    //
    // And the skip is earned by a record that VERIFIES, not by a line that CLAIMS. The JSONL is
    // parsed without checking signatures, so a single appended line naming a hash nothing else
    // backs — no ciphertext, no key, no subject binding — used to buy a counted "private skip":
    // the scan reporting zero findings over evidence that is not there. A claimed-but-unverifiable
    // record now propagates its own error rather than becoming a quiet pass.
    //
    // The four outcomes are read from `read_verified_chirho` rather than reconstructed from
    // `get_chirho`'s collapsed `io::Error`. Recovering them from an error KIND worked — the getter
    // returns the original error, so `NotFound` really did mean ABSENT — but it worked by an
    // invariant nothing stated and no check enforced, on the one branch in this function where
    // being wrong means skipping a plaintext object instead of reporting it. So this is a
    // dependency removed, not a behaviour changed: only genuine absence may reach the skip, exactly
    // as before, and now the compiler is what says so.
    let bytes_chirho = match cas_chirho::read_verified_chirho(root_chirho, hash_chirho) {
        cas_chirho::CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => bytes_chirho,
        cas_chirho::CasReadOutcomeChirho::AbsentChirho(error_chirho) => {
            if dag_private_value_chirho::verified_private_dag_value_record_chirho(
                root_chirho,
                hash_chirho,
            )?
            .is_some()
            {
                report_chirho.effect_cas_private_ciphertexts_skipped_chirho += 1;
                return Ok(());
            }
            return Err(error_chirho)
                .with_context(|| format!("load effect {role_chirho} object {}", hash_chirho.0));
        }
        cas_chirho::CasReadOutcomeChirho::TamperedChirho { actual_chirho, .. } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "content address mismatch: requested {}, actual {}",
                    hash_chirho.0, actual_chirho.0
                ),
            ))
            .with_context(|| format!("load effect {role_chirho} object {}", hash_chirho.0));
        }
        cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => {
            return Err(error_chirho)
                .with_context(|| format!("load effect {role_chirho} object {}", hash_chirho.0));
        }
    };
    if serde_json::from_slice::<Value>(&bytes_chirho).is_ok() {
        report_chirho.effect_cas_json_objects_chirho += 1;
        return Ok(());
    }
    let Ok(text_chirho) = std::str::from_utf8(&bytes_chirho) else {
        report_chirho.effect_cas_binary_objects_skipped_chirho += 1;
        return Ok(());
    };
    report_chirho.effect_cas_objects_chirho += 1;
    let surface_chirho = format!("{source_chirho}:{role_chirho}:{}", hash_chirho.0);
    inspect_unstructured_body_text_chirho(
        &surface_chirho,
        None,
        "$.body_chirho",
        text_chirho,
        &mut report_chirho.findings_chirho,
    );
    if text_chirho.contains('=') {
        for (key_chirho, value_chirho) in url::form_urlencoded::parse(text_chirho.as_bytes()) {
            if value_chirho.trim().is_empty() {
                continue;
            }
            report_chirho.effect_form_fields_chirho += 1;
            inspect_privacy_string_chirho(
                &surface_chirho,
                None,
                &format!("$.form_chirho.{key_chirho}"),
                &value_chirho,
                &mut report_chirho.findings_chirho,
            );
        }
    }
    Ok(())
}

fn inspect_unstructured_body_text_chirho(
    source_chirho: &str,
    line_chirho: Option<u64>,
    path_chirho: &str,
    text_chirho: &str,
    findings_chirho: &mut Vec<PrivacyScanFindingChirho>,
) {
    if looks_like_email_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "email-like-chirho".to_string(),
            detail_chirho: "string resembles an email address; raw value is intentionally omitted"
                .to_string(),
        });
    }
    if contains_luhn_card_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "payment-card-like-chirho".to_string(),
            detail_chirho: "string contains a Luhn-valid card-like digit sequence; raw value is intentionally omitted"
                .to_string(),
        });
    }
    if contains_ssn_like_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "ssn-like-chirho".to_string(),
            detail_chirho:
                "string contains a high-confidence SSN-like pattern; raw value is intentionally omitted"
                    .to_string(),
        });
    }
}

fn collect_regular_files_chirho(dir_chirho: &Path, paths_chirho: &mut Vec<PathBuf>) -> Result<()> {
    for entry_chirho in std::fs::read_dir(dir_chirho)? {
        let path_chirho = entry_chirho?.path();
        if path_chirho.is_dir() {
            collect_regular_files_chirho(&path_chirho, paths_chirho)?;
        } else if path_chirho.is_file() {
            paths_chirho.push(path_chirho);
        }
    }
    Ok(())
}

fn collect_regular_files_sorted_chirho(dir_chirho: &Path) -> Result<Vec<PathBuf>> {
    let mut paths_chirho = Vec::new();
    collect_regular_files_chirho(dir_chirho, &mut paths_chirho)?;
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn object_source_name_chirho(root_chirho: &Path, path_chirho: &Path) -> String {
    path_chirho
        .strip_prefix(root_chirho)
        .unwrap_or(path_chirho)
        .display()
        .to_string()
}

fn scan_json_value_chirho(
    source_chirho: &str,
    line_chirho: Option<u64>,
    path_chirho: &str,
    value_chirho: &Value,
    findings_chirho: &mut Vec<PrivacyScanFindingChirho>,
) {
    match value_chirho {
        Value::Object(map_chirho) => {
            for (key_chirho, child_chirho) in map_chirho {
                scan_json_value_chirho(
                    source_chirho,
                    line_chirho,
                    &format!("{path_chirho}.{key_chirho}"),
                    child_chirho,
                    findings_chirho,
                );
            }
        }
        Value::Array(items_chirho) => {
            for (i_chirho, child_chirho) in items_chirho.iter().enumerate() {
                scan_json_value_chirho(
                    source_chirho,
                    line_chirho,
                    &format!("{path_chirho}[{i_chirho}]"),
                    child_chirho,
                    findings_chirho,
                );
            }
        }
        Value::String(text_chirho) => {
            inspect_privacy_string_chirho(
                source_chirho,
                line_chirho,
                path_chirho,
                text_chirho,
                findings_chirho,
            );
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

pub(super) fn inspect_privacy_string_chirho(
    source_chirho: &str,
    line_chirho: Option<u64>,
    path_chirho: &str,
    text_chirho: &str,
    findings_chirho: &mut Vec<PrivacyScanFindingChirho>,
) {
    if let Ok(json_chirho) = serde_json::from_str::<Value>(text_chirho) {
        scan_json_value_chirho(
            source_chirho,
            line_chirho,
            path_chirho,
            &json_chirho,
            findings_chirho,
        );
        return;
    }
    if looks_like_crypto_hex_value_chirho(text_chirho) {
        return;
    }
    if privacy_scan_crypto_field_chirho(path_chirho)
        && (looks_like_crypto_hex_value_chirho(text_chirho)
            || looks_like_prefixed_crypto_value_chirho(text_chirho))
    {
        return;
    }
    if privacy_scan_hash_shaped_metadata_field_chirho(path_chirho)
        && (looks_like_crypto_hex_value_chirho(text_chirho)
            || looks_like_prefixed_crypto_value_chirho(text_chirho))
    {
        return;
    }
    if privacy_scan_safe_ref_field_chirho(path_chirho)
        && looks_like_safe_ref_value_chirho(text_chirho)
    {
        return;
    }
    if privacy_scan_timestamp_field_chirho(path_chirho)
        && looks_like_timestamp_value_chirho(text_chirho)
    {
        return;
    }
    if privacy_scan_root_path_metadata_field_chirho(path_chirho)
        && looks_like_safe_ref_value_chirho(text_chirho)
    {
        return;
    }
    if looks_like_email_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "email-like-chirho".to_string(),
            detail_chirho: "string resembles an email address; raw value is intentionally omitted"
                .to_string(),
        });
    }
    if contains_luhn_card_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "payment-card-like-chirho".to_string(),
            detail_chirho: "string contains a Luhn-valid card-like digit sequence; raw value is intentionally omitted"
                .to_string(),
        });
    }
    if contains_ssn_like_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "ssn-like-chirho".to_string(),
            detail_chirho:
                "string contains a high-confidence SSN-like pattern; raw value is intentionally omitted"
                    .to_string(),
        });
    }
    if phone_like_field_chirho(path_chirho) && looks_like_phone_number_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "phone-like-chirho".to_string(),
            detail_chirho:
                "phone-classified field contains a phone-like value; raw value is intentionally omitted"
                    .to_string(),
        });
    }
    if name_like_field_chirho(path_chirho) && looks_like_person_name_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "person-name-like-chirho".to_string(),
            detail_chirho:
                "name-classified field contains a human-name-like value; raw value is intentionally omitted"
                    .to_string(),
        });
    }
    if address_like_field_chirho(path_chirho) && looks_like_postal_address_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "postal-address-like-chirho".to_string(),
            detail_chirho:
                "address-classified field contains a postal-address-like value; raw value is intentionally omitted"
                    .to_string(),
        });
    }
    if birth_date_like_field_chirho(path_chirho) && looks_like_birth_date_value_chirho(text_chirho)
    {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "birth-date-like-chirho".to_string(),
            detail_chirho:
                "birth-date-classified field contains a date-like value; raw value is intentionally omitted"
                    .to_string(),
        });
    }
    if high_risk_free_text_field_chirho(path_chirho) && raw_free_text_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "raw-free-text-field-chirho".to_string(),
            detail_chirho:
                "high-risk content field contains raw free text; store it as a private blob instead"
                    .to_string(),
        });
    }
    if semantic_pii_field_chirho(path_chirho) && raw_free_text_chirho(text_chirho) {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "semantic-pii-free-text-field-chirho".to_string(),
            detail_chirho:
                "semantic PII-classified field contains raw free text; store it as a private blob instead"
                    .to_string(),
        });
    } else if !privacy_scan_classified_string_field_chirho(path_chirho)
        && raw_free_text_chirho(text_chirho)
    {
        findings_chirho.push(PrivacyScanFindingChirho {
            source_chirho: source_chirho.to_string(),
            line_chirho,
            path_chirho: path_chirho.to_string(),
            kind_chirho: "unclassified-free-text-field-chirho".to_string(),
            detail_chirho:
                "unclassified string field contains raw free text; classify the field or store content as a private blob"
                    .to_string(),
        });
    }
}

pub(super) fn privacy_scan_field_chirho(path_chirho: &str) -> &str {
    let mut trimmed_chirho = path_chirho;
    loop {
        let Some(without_close_chirho) = trimmed_chirho.strip_suffix(']') else {
            break;
        };
        let Some(open_chirho) = without_close_chirho.rfind('[') else {
            break;
        };
        let index_chirho = &without_close_chirho[open_chirho + 1..];
        if !index_chirho
            .chars()
            .all(|ch_chirho| ch_chirho.is_ascii_digit())
        {
            break;
        }
        trimmed_chirho = &without_close_chirho[..open_chirho];
    }
    trimmed_chirho.rsplit('.').next().unwrap_or(trimmed_chirho)
}

fn privacy_scan_crypto_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho);
    if privacy_scan_run_hash_map_field_chirho(path_chirho) {
        return true;
    }
    matches!(
        field_chirho,
        "app_ref_chirho"
            | "artifact_chirho"
            | "added_doc_chirho"
            | "base_chirho"
            | "billing_policy_chirho"
            | "ciphertext_chirho"
            | "customer_chirho"
            | "dag_chirho"
            | "doc_chirho"
            | "effect_chirho"
            | "effect_idem_keys_chirho"
            | "effect_response_chirho"
            | "from_chirho"
            | "idem_key_chirho"
            | "idempotency_key_chirho"
            | "key_id_chirho"
            | "mac_chirho"
            | "node_chirho"
            | "nonce_chirho"
            | "parents_chirho"
            | "pack_chirho"
            | "previous_chirho"
            | "price_book_chirho"
            | "proof_chirho"
            | "pubkey_chirho"
            | "request_chirho"
            | "resource_policy_chirho"
            | "related_effect_ids_chirho"
            | "related_run_ids_chirho"
            | "run_chirho"
            | "response_chirho"
            | "sig_chirho"
            | "snapshot_chirho"
            | "trace_chirho"
            | "final_state_chirho"
            | "new_state_chirho"
            | "previous_state_chirho"
            | "state_chirho"
            | "to_chirho"
    ) || field_chirho.ends_with("_digest_chirho")
        || field_chirho.ends_with("_hash_chirho")
        || field_chirho.ends_with("_ref_chirho")
        || field_chirho.ends_with("_sig_chirho")
}

fn privacy_scan_hash_shaped_metadata_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho);
    matches!(
        field_chirho,
        "candidate_chirho"
            | "impl_wasm_chirho"
            | "module_chirho"
            | "previous_module_chirho"
            | "root_dag_chirho"
            | "route_dag_chirho"
    ) || field_chirho.ends_with("_dag_chirho")
}

fn privacy_scan_run_hash_map_field_chirho(path_chirho: &str) -> bool {
    path_chirho.contains(".inputs_chirho.") || path_chirho.contains(".outputs_chirho.")
}

fn privacy_scan_safe_ref_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho);
    matches!(
        field_chirho,
        "key_chirho"
            | "principal_chirho"
            | "ref_chirho"
            | "row_key_chirho"
            | "source_ref_chirho"
            | "wallet_chirho"
    ) || field_chirho.ends_with("_key_chirho")
        || field_chirho.ends_with("_ref_chirho")
        || field_chirho.ends_with("_id_chirho")
}

fn privacy_scan_classified_string_field_chirho(path_chirho: &str) -> bool {
    privacy_scan_crypto_field_chirho(path_chirho)
        || high_risk_free_text_field_chirho(path_chirho)
        || phone_like_field_chirho(path_chirho)
        || name_like_field_chirho(path_chirho)
        || address_like_field_chirho(path_chirho)
        || birth_date_like_field_chirho(path_chirho)
        || bounded_display_text_field_chirho(path_chirho)
        || structured_metadata_field_chirho(path_chirho)
}

fn semantic_pii_field_chirho(path_chirho: &str) -> bool {
    name_like_field_chirho(path_chirho)
        || address_like_field_chirho(path_chirho)
        || birth_date_like_field_chirho(path_chirho)
}

fn looks_like_crypto_hex_value_chirho(text_chirho: &str) -> bool {
    matches!(text_chirho.len(), 32 | 48 | 64 | 128)
        && text_chirho
            .chars()
            .all(|ch_chirho| ch_chirho.is_ascii_hexdigit())
}

fn looks_like_prefixed_crypto_value_chirho(text_chirho: &str) -> bool {
    let Some((prefix_chirho, suffix_chirho)) = text_chirho.rsplit_once(':') else {
        return false;
    };
    !prefix_chirho.is_empty()
        && prefix_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '.')
        })
        && looks_like_crypto_hex_value_chirho(suffix_chirho)
}

fn high_risk_free_text_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho);
    matches!(
        field_chirho,
        "message_chirho"
            | "screenshot_chirho"
            | "system_chirho"
            | "transcript_chirho"
            | "prompt_chirho"
            | "answer_chirho"
            | "note_chirho"
            | "reason_chirho"
            | "request_chirho"
            | "query_chirho"
    )
}

fn bounded_display_text_field_chirho(path_chirho: &str) -> bool {
    if compliance_source_error_field_chirho(path_chirho) {
        return true;
    }
    let field_chirho = privacy_scan_field_chirho(path_chirho);
    matches!(
        field_chirho,
        "assertion_chirho"
            | "detail_chirho"
            | "details_chirho"
            | "disabled_reason_chirho"
            | "excluded_reason_chirho"
            | "honest_scope_chirho"
            | "lede_chirho"
            | "memo_chirho"
            | "notes_chirho"
            | "redaction_note_chirho"
            | "scope_notes_chirho"
            | "summary_chirho"
            | "title_chirho"
            | "unavailable_reason_chirho"
    )
}

fn compliance_source_error_field_chirho(path_chirho: &str) -> bool {
    privacy_scan_field_chirho(path_chirho) == "error_chirho"
        && path_chirho.contains(".sources_chirho[")
}

fn structured_metadata_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho);
    matches!(
        field_chirho,
        "account_chirho"
            | "actor_chirho"
            | "alg_chirho"
            | "app_chirho"
            | "app_ref_chirho"
            | "asset_chirho"
            | "caller_chirho"
            | "case_ref_chirho"
            | "customer_chirho"
            | "id_chirho"
            | "idempotency_key_chirho"
            | "kind_chirho"
            | "operator_chirho"
            | "owner_chirho"
            | "provider_chirho"
            | "region_chirho"
            | "requester_chirho"
            | "role_chirho"
            | "source_chirho"
            | "status_chirho"
            | "subject_chirho"
            | "tenant_chirho"
            | "user_id_chirho"
    ) || field_chirho.ends_with("_hash_chirho")
        || field_chirho.ends_with("_id_chirho")
        || field_chirho.ends_with("_key_chirho")
        || field_chirho.ends_with("_ref_chirho")
        || field_chirho.ends_with("_sig_chirho")
        || field_chirho.ends_with("_token_chirho")
}

fn privacy_scan_root_path_metadata_field_chirho(path_chirho: &str) -> bool {
    matches!(
        privacy_scan_field_chirho(path_chirho),
        "canonical_root_chirho"
    )
}

pub(super) fn privacy_scan_timestamp_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho);
    field_chirho == "at_chirho"
        || field_chirho == "timestamp_chirho"
        || field_chirho.ends_with("_at_chirho")
        || field_chirho.ends_with("_timestamp_chirho")
}

pub(super) fn looks_like_timestamp_value_chirho(text_chirho: &str) -> bool {
    let trimmed_chirho = text_chirho.trim();
    !trimmed_chirho.is_empty()
        && trimmed_chirho.len() <= 40
        && trimmed_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_digit()
                || matches!(ch_chirho, '-' | ':' | '.' | 'T' | 'Z' | '+' | ' ')
        })
        && trimmed_chirho
            .chars()
            .filter(|ch_chirho| ch_chirho.is_ascii_digit())
            .count()
            >= 4
}

fn raw_free_text_chirho(text_chirho: &str) -> bool {
    let trimmed_chirho = text_chirho.trim();
    trimmed_chirho.len() > 24
        && trimmed_chirho.chars().any(char::is_whitespace)
        && !safe_ref_like_chirho(trimmed_chirho)
}

fn safe_ref_like_chirho(text_chirho: &str) -> bool {
    text_chirho.len() <= 256
        && text_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric()
                || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.' | '#')
        })
}

fn looks_like_safe_ref_value_chirho(text_chirho: &str) -> bool {
    safe_ref_like_chirho(text_chirho)
        && (text_chirho.contains('/')
            || text_chirho.contains(':')
            || looks_like_crypto_hex_value_chirho(text_chirho))
}

fn looks_like_email_chirho(text_chirho: &str) -> bool {
    text_chirho
        .split(|ch_chirho: char| {
            ch_chirho.is_whitespace()
                || matches!(
                    ch_chirho,
                    '<' | '>' | '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';'
                )
        })
        .any(|token_chirho| {
            let Some((left_chirho, right_chirho)) = token_chirho.split_once('@') else {
                return false;
            };
            !left_chirho.is_empty()
                && right_chirho.contains('.')
                && right_chirho.chars().all(|ch_chirho| {
                    ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '.')
                })
        })
}

fn contains_luhn_card_chirho(text_chirho: &str) -> bool {
    let mut digits_chirho = String::new();
    for ch_chirho in text_chirho.chars() {
        if ch_chirho.is_ascii_digit() {
            digits_chirho.push(ch_chirho);
            if digits_chirho.len() > 19 {
                digits_chirho.remove(0);
            }
            if digits_chirho.len() >= 13 && luhn_valid_chirho(&digits_chirho) {
                return true;
            }
        } else if ch_chirho != ' ' && ch_chirho != '-' {
            digits_chirho.clear();
        }
    }
    false
}

fn luhn_valid_chirho(digits_chirho: &str) -> bool {
    if !(13..=19).contains(&digits_chirho.len()) {
        return false;
    }
    let mut sum_chirho = 0_u32;
    let mut double_chirho = false;
    for ch_chirho in digits_chirho.chars().rev() {
        let Some(mut digit_chirho) = ch_chirho.to_digit(10) else {
            return false;
        };
        if double_chirho {
            digit_chirho *= 2;
            if digit_chirho > 9 {
                digit_chirho -= 9;
            }
        }
        sum_chirho += digit_chirho;
        double_chirho = !double_chirho;
    }
    sum_chirho != 0 && sum_chirho.is_multiple_of(10)
}

pub(super) fn contains_ssn_like_chirho(text_chirho: &str) -> bool {
    let chars_chirho = text_chirho.chars().collect::<Vec<_>>();
    if chars_chirho.len() < 11 {
        return false;
    }
    for start_chirho in 0..=(chars_chirho.len() - 11) {
        if !ssn_boundary_chirho(
            start_chirho
                .checked_sub(1)
                .map(|i_chirho| chars_chirho[i_chirho]),
        ) || !ssn_boundary_chirho(chars_chirho.get(start_chirho + 11).copied())
        {
            continue;
        }
        if chars_chirho[start_chirho + 3] != '-' || chars_chirho[start_chirho + 6] != '-' {
            continue;
        }
        if ![0_usize, 1, 2, 4, 5, 7, 8, 9, 10]
            .iter()
            .all(|offset_chirho| chars_chirho[start_chirho + *offset_chirho].is_ascii_digit())
        {
            continue;
        }
        let area_chirho = digits_value_chirho(&chars_chirho[start_chirho..start_chirho + 3]);
        let group_chirho = digits_value_chirho(&chars_chirho[start_chirho + 4..start_chirho + 6]);
        let serial_chirho = digits_value_chirho(&chars_chirho[start_chirho + 7..start_chirho + 11]);
        if area_chirho != 0
            && area_chirho != 666
            && area_chirho < 900
            && group_chirho != 0
            && serial_chirho != 0
        {
            return true;
        }
    }
    false
}

fn ssn_boundary_chirho(ch_chirho: Option<char>) -> bool {
    match ch_chirho {
        Some(ch_chirho) => !ch_chirho.is_ascii_alphanumeric(),
        None => true,
    }
}

fn digits_value_chirho(chars_chirho: &[char]) -> u16 {
    chars_chirho.iter().fold(0_u16, |value_chirho, ch_chirho| {
        value_chirho * 10 + ch_chirho.to_digit(10).unwrap_or(0) as u16
    })
}

pub(super) fn phone_like_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho).to_ascii_lowercase();
    field_chirho.contains("phone")
        || field_chirho.contains("telephone")
        || field_chirho.contains("mobile")
        || field_chirho.contains("fax")
}

fn name_like_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho).to_ascii_lowercase();
    matches!(
        field_chirho.as_str(),
        "name_chirho"
            | "full_name_chirho"
            | "first_name_chirho"
            | "last_name_chirho"
            | "display_name_chirho"
            | "legal_name_chirho"
            | "cardholder_name_chirho"
            | "customer_name_chirho"
    ) || field_chirho.contains("person_name")
        || field_chirho.contains("recipient_name")
}

fn looks_like_person_name_chirho(text_chirho: &str) -> bool {
    let trimmed_chirho = text_chirho.trim();
    if !(3..=80).contains(&trimmed_chirho.len())
        || trimmed_chirho.contains('@')
        || trimmed_chirho.contains('/')
        || trimmed_chirho.contains(':')
        || trimmed_chirho
            .chars()
            .any(|ch_chirho| ch_chirho.is_ascii_digit())
    {
        return false;
    }
    let words_chirho = trimmed_chirho.split_whitespace().collect::<Vec<_>>();
    if !(2..=5).contains(&words_chirho.len()) {
        return false;
    }
    words_chirho.iter().all(|word_chirho| {
        let stripped_chirho =
            word_chirho.trim_matches(|ch_chirho: char| matches!(ch_chirho, '\'' | '-' | '.' | ','));
        let alpha_count_chirho = stripped_chirho
            .chars()
            .filter(|ch_chirho| ch_chirho.is_alphabetic())
            .count();
        alpha_count_chirho >= 2
            && stripped_chirho
                .chars()
                .all(|ch_chirho| ch_chirho.is_alphabetic() || matches!(ch_chirho, '\'' | '-' | '.'))
    })
}

fn address_like_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho).to_ascii_lowercase();
    field_chirho.contains("address")
        || field_chirho.contains("street")
        || field_chirho.contains("postal")
        || field_chirho.contains("zip")
}

fn looks_like_postal_address_chirho(text_chirho: &str) -> bool {
    let trimmed_chirho = text_chirho.trim();
    if trimmed_chirho.len() < 5 || trimmed_chirho.len() > 160 {
        return false;
    }
    let lower_chirho = format!(" {} ", trimmed_chirho.to_ascii_lowercase());
    let has_digit_chirho = trimmed_chirho
        .chars()
        .any(|ch_chirho| ch_chirho.is_ascii_digit());
    let has_street_suffix_chirho = [
        " street ",
        " st ",
        " avenue ",
        " ave ",
        " road ",
        " rd ",
        " boulevard ",
        " blvd ",
        " lane ",
        " ln ",
        " drive ",
        " dr ",
        " court ",
        " ct ",
        " way ",
        " place ",
        " pl ",
    ]
    .iter()
    .any(|suffix_chirho| lower_chirho.contains(suffix_chirho));
    (has_digit_chirho && has_street_suffix_chirho) || looks_like_postal_code_chirho(trimmed_chirho)
}

fn looks_like_postal_code_chirho(text_chirho: &str) -> bool {
    let trimmed_chirho = text_chirho.trim();
    let bytes_chirho = trimmed_chirho.as_bytes();
    if bytes_chirho.len() == 5 && bytes_chirho.iter().all(u8::is_ascii_digit) {
        return true;
    }
    bytes_chirho.len() == 10
        && bytes_chirho[5] == b'-'
        && bytes_chirho[..5].iter().all(u8::is_ascii_digit)
        && bytes_chirho[6..].iter().all(u8::is_ascii_digit)
}

fn birth_date_like_field_chirho(path_chirho: &str) -> bool {
    let field_chirho = privacy_scan_field_chirho(path_chirho).to_ascii_lowercase();
    field_chirho.contains("birth") || field_chirho.contains("dob")
}

fn looks_like_birth_date_value_chirho(text_chirho: &str) -> bool {
    let trimmed_chirho = text_chirho.trim();
    if trimmed_chirho.len() < 6 || trimmed_chirho.len() > 16 {
        return false;
    }
    let digit_count_chirho = trimmed_chirho
        .chars()
        .filter(|ch_chirho| ch_chirho.is_ascii_digit())
        .count();
    (6..=8).contains(&digit_count_chirho)
        && trimmed_chirho
            .chars()
            .all(|ch_chirho| ch_chirho.is_ascii_digit() || matches!(ch_chirho, '-' | '/' | '.'))
}

pub(super) fn looks_like_phone_number_chirho(text_chirho: &str) -> bool {
    let trimmed_chirho = text_chirho.trim();
    if trimmed_chirho.is_empty()
        || !trimmed_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_digit()
                || ch_chirho.is_ascii_whitespace()
                || matches!(ch_chirho, '+' | '(' | ')' | '-' | '.')
        })
    {
        return false;
    }
    let digits_chirho = trimmed_chirho
        .chars()
        .filter(|ch_chirho| ch_chirho.is_ascii_digit())
        .collect::<String>();
    let normalized_chirho = if digits_chirho.len() == 11 && digits_chirho.starts_with('1') {
        &digits_chirho[1..]
    } else {
        digits_chirho.as_str()
    };
    let bytes_chirho = normalized_chirho.as_bytes();
    bytes_chirho.len() == 10
        && (b'2'..=b'9').contains(&bytes_chirho[0])
        && (b'2'..=b'9').contains(&bytes_chirho[3])
}
/// Production root logs that the const-aware source inventory (2026-09-09) proved had NEVER been
/// entered into any review inventory — privacy scan, subject export, or compliance evidence. Their
/// file names live in `const` items, and until that day every inventory guard saw only
/// `root_chirho.join("literal")`, so the whole family stayed green-by-invisibility.
///
/// They are recorded here as PENDING, not reviewed: entering them into the reviewed lists would
/// claim a privacy/export/compliance review nobody performed. The three inventory guards subtract
/// this set from their gaps AND assert every member is still unclaimed, so the set can only shrink
/// — reviewing a log means claiming it in all three inventories and deleting it here. The runtime
/// compliance pack is unaffected: on any root where these files exist it still reports them as
/// `unmapped-production-jsonl-chirho` coverage gaps. Value: the owning crate.
pub fn production_logs_pending_owner_review_chirho() -> BTreeMap<&'static str, &'static str> {
    const PLACEMENT_AUTHORITY_CHIRHO: &str = "cairn-tenant-placement-authority-chirho";
    [
        "infrastructure-budget-events-chirho.jsonl",
        "node-capacity-attestations-chirho.jsonl",
        "node-lifecycle-transitions-chirho.jsonl",
        "node-usage-measurements-chirho.jsonl",
        "tenant-placement-records-chirho.jsonl",
        "tenant-root-move-stages-chirho.jsonl",
        "topology-grant-attestations-chirho.jsonl",
    ]
    .into_iter()
    .map(|file_chirho| (file_chirho, PLACEMENT_AUTHORITY_CHIRHO))
    .collect()
}

/// For the three inventory guards: the literal-root-file gaps that are not the recorded pending
/// set. Refuses when a pending entry is no longer a gap — that log was claimed somewhere, so the
/// pending record is stale and must be deleted rather than silently kept.
#[cfg(test)]
pub fn unexplained_literal_root_gaps_chirho(
    missing_chirho: &BTreeSet<String>,
) -> std::result::Result<BTreeSet<String>, String> {
    let pending_chirho = production_logs_pending_owner_review_chirho();
    let stale_chirho = pending_chirho
        .keys()
        .filter(|file_chirho| !missing_chirho.contains(**file_chirho))
        .copied()
        .collect::<Vec<_>>();
    if !stale_chirho.is_empty() {
        return Err(format!(
            "pending-owner-review entries are no longer gaps of this inventory: {stale_chirho:?}. \
             Either the log was reviewed and claimed (delete it from \
             production_logs_pending_owner_review_chirho) or the source inventory stopped seeing \
             const-named logs (check literal_scanner_resolves_same_file_string_consts_chirho)"
        ));
    }
    Ok(missing_chirho
        .iter()
        .filter(|file_chirho| !pending_chirho.contains_key(file_chirho.as_str()))
        .cloned()
        .collect())
}

pub fn reviewed_signed_log_files_chirho() -> BTreeSet<&'static str> {
    [
        // Unsigned infrastructure index: two verified content hashes, no subject or plan body.
        "topology-plan-index-chirho.jsonl",
        "agent-authority-responses-chirho.jsonl",
        "agent-report-budgets-chirho.jsonl",
        "agent-report-charges-chirho.jsonl",
        "agent-reports-chirho.jsonl",
        "app-build-request-records-chirho.jsonl",
        "app-static-asset-records-chirho.jsonl",
        "client-owner-bindings-chirho.jsonl",
        "app-input-policy-records-chirho.jsonl",
        "app-request-access-policy-records-chirho.jsonl",
        // K1: an app's openings to limited keys (app, owner, route, action, DAG, logical resource names); no subject rows.
        "app-key-authority-chirho.jsonl",
        "app-params-records-chirho.jsonl",
        "app-records-chirho.jsonl",
        "app-response-policy-records-chirho.jsonl",
        "app-route-response-policy-records-chirho.jsonl",
        "app-route-records-chirho.jsonl",
        "billing-compensations-chirho.jsonl",
        "billing-policy-records-chirho.jsonl",
        "billing-usage-chirho.jsonl",
        "capability-grants-chirho.jsonl",
        "compensation-executions-chirho.jsonl",
        "compensations-chirho.jsonl",
        "compliance-evidence-chirho.jsonl",
        "connect-accounts-chirho.jsonl",
        "credit-holds-chirho.jsonl",
        "crm-connectors-chirho.jsonl",
        "crm-email-deliveries-chirho.jsonl",
        "crm-customers-chirho.jsonl",
        "crm-interactions-chirho.jsonl",
        "crm-read-models-chirho.jsonl",
        "data-residency-attestations-chirho.jsonl",
        "data-residency-policies-chirho.jsonl",
        "dns-applies-chirho.jsonl",
        "dns-zones-chirho.jsonl",
        "domain-bindings-chirho.jsonl",
        "external-usage-chirho.jsonl",
        "feedback-chirho.jsonl",
        "feedback-policy-records-chirho.jsonl",
        "feedback-retention-records-chirho.jsonl",
        "gate1-authority-log-chirho.jsonl",
        "head-removals-chirho.jsonl",
        "identities-chirho.jsonl",
        "identity-auth-attempts-chirho.jsonl",
        "identity-credential-change-attempts-chirho.jsonl",
        "identity-credential-resets-chirho.jsonl",
        "identity-recovery-code-events-chirho.jsonl",
        "identity-session-revocations-chirho.jsonl",
        "identity-sessions-chirho.jsonl",
        "knowledge-answers-chirho.jsonl",
        "knowledge-records-chirho.jsonl",
        "ledger-chirho.jsonl",
        "legal-hold-records-chirho.jsonl",
        "mailbox-applies-chirho.jsonl",
        "mailboxes-chirho.jsonl",
        "manual-remediations-chirho.jsonl",
        "native-stateless-attestations-chirho.jsonl",
        "news-center-records-chirho.jsonl",
        "oauth-clients-chirho.jsonl",
        "oauth-connection-clients-chirho.jsonl",
        "connection-tokens-chirho.jsonl",
        "connection-token-uses-chirho.jsonl",
        "onboarding-records-chirho.jsonl",
        "payouts-chirho.jsonl",
        "stripe-payout-intents-chirho.jsonl",
        "pricebook-records-chirho.jsonl",
        "privacy-access-records-chirho.jsonl",
        "privacy-blob-records-chirho.jsonl",
        "private-dag-values-chirho.jsonl",
        "privacy-backup-key-policies-chirho.jsonl",
        "privacy-erasure-propagations-chirho.jsonl",
        "privacy-erasure-records-chirho.jsonl",
        "privacy-export-records-chirho.jsonl",
        "privacy-replica-targets-chirho.jsonl",
        "privacy-retention-records-chirho.jsonl",
        "provider-invoices-chirho.jsonl",
        "publication-applied-chirho.jsonl",
        "publication-intents-chirho.jsonl",
        "publication-owners-chirho.jsonl",
        "publication-reserved-slugs-chirho.jsonl",
        "slug-claims-chirho.jsonl",
        "provider-price-records-chirho.jsonl",
        "realtime-epilogues-chirho.jsonl",
        "realtime-events-chirho.jsonl",
        "realtime-sessions-chirho.jsonl",
        "reconciliation-reports-chirho.jsonl",
        "reflog-chirho.jsonl",
        "resource-policy-records-chirho.jsonl",
        "resource-policy-unset-records-chirho.jsonl",
        "resource-usage-chirho.jsonl",
        "review-policy-envelopes-chirho.jsonl",
        "review-records-chirho.jsonl",
        "rollback-completions-chirho.jsonl",
        "rollback-events-chirho.jsonl",
        "run-intents-chirho.jsonl",
        "scoped-token-uses-chirho.jsonl",
        "scoped-tokens-chirho.jsonl",
        "statements-chirho.jsonl",
        "stripe-dispute-observations-chirho.jsonl",
        "stripe-payout-observations-chirho.jsonl",
        "stripe-topup-observations-chirho.jsonl",
        "template-app-deploy-records-chirho.jsonl",
        "template-registry-records-chirho.jsonl",
        "support-approval-decisions-chirho.jsonl",
        "support-approval-requests-chirho.jsonl",
        "support-approval-uses-chirho.jsonl",
        "support-content-access-chirho.jsonl",
        "support-delegation-uses-chirho.jsonl",
        "support-dogfood-records-chirho.jsonl",
        "support-thread-events-chirho.jsonl",
        "volatile-effects-chirho.jsonl",
    ]
    .into_iter()
    .collect()
}
