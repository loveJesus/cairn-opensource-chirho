// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Records tenant residency policy and point-in-time region attestations.

use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::{refs_chirho, store_chirho};
use cairn_placement_chirho as placement_chirho;
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_tenant_chirho::tenant_chirho;
use cairn_writer_head_chirho::writer_head_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DATA_RESIDENCY_POLICY_SCHEMA_CHIRHO: &str = "data-residency-policy/v1-chirho";
const DATA_RESIDENCY_ATTESTATION_SCHEMA_CHIRHO: &str = "data-residency-attestation/v1-chirho";
const DATA_RESIDENCY_POLICY_RECORD_SCHEMA_CHIRHO: &str = "data-residency-policy-record-v1-chirho";
const DATA_RESIDENCY_ATTESTATION_RECORD_SCHEMA_CHIRHO: &str =
    "data-residency-attestation-record-v1-chirho";
pub const DATA_RESIDENCY_POLICY_SET_REPORT_SCHEMA_CHIRHO: &str =
    "data-residency-policy-set-report-v1-chirho";
pub const DATA_RESIDENCY_POLICY_CURRENT_REPORT_SCHEMA_CHIRHO: &str =
    "data-residency-policy-current-report-v1-chirho";
pub const DATA_RESIDENCY_ATTESTATION_REPORT_SCHEMA_CHIRHO: &str =
    "data-residency-attestation-report-v1-chirho";
pub const DATA_RESIDENCY_PLACEMENT_CHECK_SCHEMA_CHIRHO: &str =
    "data-residency-placement-check-v1-chirho";
pub const DATA_RESIDENCY_VERIFY_REPORT_SCHEMA_CHIRHO: &str =
    "data-residency-verify-report-v1-chirho";
const DATA_RESIDENCY_POLICY_LOCK_CHIRHO: &str = "data-residency-policy-chirho";
const DATA_RESIDENCY_ATTESTATION_LOCK_CHIRHO: &str = "data-residency-attestation-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyPolicyChirho {
    pub schema_chirho: String,
    pub tenant_chirho: String,
    pub allowed_data_regions_chirho: Vec<String>,
    pub allowed_processing_regions_chirho: Vec<String>,
    pub deny_unattested_processing_chirho: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_chirho: Option<HashChirho>,
    pub scope_notes_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyPolicyRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub tenant_chirho: String,
    pub policy_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_chirho: Option<HashChirho>,
    pub operator_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyAttestationChirho {
    pub schema_chirho: String,
    pub tenant_chirho: String,
    pub policy_chirho: HashChirho,
    pub host_region_chirho: String,
    pub processing_region_chirho: String,
    pub data_region_chirho: String,
    pub region_source_chirho: String,
    pub compliant_chirho: bool,
    pub violations_chirho: Vec<String>,
    pub at_ms_chirho: u64,
    pub scope_notes_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyAttestationRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub tenant_chirho: String,
    pub policy_chirho: HashChirho,
    pub attestation_chirho: HashChirho,
    pub host_region_chirho: String,
    pub processing_region_chirho: String,
    pub data_region_chirho: String,
    pub region_source_chirho: String,
    pub compliant_chirho: bool,
    pub operator_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyPlacementCheckChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub tenant_chirho: String,
    pub policy_chirho: HashChirho,
    pub candidate_chirho: String,
    pub candidate_region_chirho: String,
    pub data_regions_chirho: Vec<String>,
    pub eligible_chirho: bool,
    pub violations_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyPolicySetReportChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub policy_chirho: DataResidencyPolicyChirho,
    pub record_chirho: DataResidencyPolicyRecordChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyPolicyCurrentReportChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub policy_hash_chirho: HashChirho,
    pub policy_chirho: DataResidencyPolicyChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyAttestationReportChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub attestation_chirho: DataResidencyAttestationChirho,
    pub record_chirho: DataResidencyAttestationRecordChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidencyVerifyReportChirho {
    pub schema_chirho: String,
    pub tenant_chirho: tenant_chirho::TenantIdChirho,
    pub policy_records_chirho: usize,
    pub attestation_records_chirho: usize,
    pub noncompliant_attestations_chirho: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_policy_chirho: Option<HashChirho>,
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn set_data_residency_policy_chirho(
    root_chirho: &Path,
    data_regions_chirho: &[String],
    processing_regions_chirho: &[String],
    operator_chirho: &str,
    deny_unattested_processing_chirho: bool,
) -> Result<(DataResidencyPolicyChirho, DataResidencyPolicyRecordChirho)> {
    let tenant_chirho = tenant_for_root_chirho(root_chirho)?;
    validate_safe_token_chirho("operator_chirho", operator_chirho)?;
    let allowed_data_regions_chirho = normalize_regions_chirho("data region", data_regions_chirho)?;
    let allowed_processing_regions_chirho =
        normalize_regions_chirho("processing region", processing_regions_chirho)?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, DATA_RESIDENCY_POLICY_LOCK_CHIRHO, || {
        let previous_chirho = current_policy_hash_chirho(root_chirho)?;
        let policy_chirho = DataResidencyPolicyChirho {
            schema_chirho: DATA_RESIDENCY_POLICY_SCHEMA_CHIRHO.to_string(),
            tenant_chirho: tenant_chirho.clone(),
            allowed_data_regions_chirho,
            allowed_processing_regions_chirho,
            deny_unattested_processing_chirho,
            previous_chirho: previous_chirho.clone(),
            scope_notes_chirho: vec![
                "Residency policy pins this tenant root to declared data and processing regions."
                    .to_string(),
                "This is declare-and-gate policy evidence; it can detect/refuse out-of-policy placement, but it does not migrate data or prove physical provider topology."
                    .to_string(),
            ],
        };
        validate_policy_chirho(&policy_chirho)?;
        let policy_hash_chirho = store_chirho::put_object_chirho(root_chirho, &policy_chirho)?;
        let path_chirho = policy_records_path_chirho(root_chirho);
        let seq_chirho = load_data_residency_policy_records_chirho(root_chirho)?.len() as u64;
        let mut record_chirho = DataResidencyPolicyRecordChirho {
            schema_chirho: DATA_RESIDENCY_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            tenant_chirho,
            policy_chirho: policy_hash_chirho.clone(),
            previous_chirho,
            operator_chirho: operator_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &policy_record_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        writer_head_chirho::with_head_commit_chirho(root_chirho, || {
            refs_chirho::commit_head_chirho(
                root_chirho,
                &policy_ref_chirho(&record_chirho.tenant_chirho),
                refs_chirho::HeadPreconditionChirho::AnyCurrentChirho,
                policy_hash_chirho,
                "data-residency-policy",
            )
        })?;
        Ok((policy_chirho, record_chirho))
    })
}

pub fn current_data_residency_policy_chirho(
    root_chirho: &Path,
) -> Result<Option<(HashChirho, DataResidencyPolicyChirho)>> {
    let Some(policy_hash_chirho) = current_policy_hash_chirho(root_chirho)? else {
        return Ok(None);
    };
    let policy_chirho: DataResidencyPolicyChirho =
        store_chirho::get_object_chirho(root_chirho, &policy_hash_chirho)?;
    validate_policy_chirho(&policy_chirho)?;
    Ok(Some((policy_hash_chirho, policy_chirho)))
}

pub fn attest_data_residency_chirho(
    root_chirho: &Path,
    host_region_chirho: &str,
    processing_region_chirho: &str,
    data_region_chirho: &str,
    region_source_chirho: &str,
    operator_chirho: &str,
) -> Result<(
    DataResidencyAttestationChirho,
    DataResidencyAttestationRecordChirho,
)> {
    let tenant_chirho = tenant_for_root_chirho(root_chirho)?;
    validate_safe_token_chirho("operator_chirho", operator_chirho)?;
    validate_safe_token_chirho("region_source_chirho", region_source_chirho)?;
    let host_region_chirho = normalize_region_chirho("host region", host_region_chirho)?;
    let processing_region_chirho =
        normalize_region_chirho("processing region", processing_region_chirho)?;
    let data_region_chirho = normalize_region_chirho("data region", data_region_chirho)?;
    let (policy_hash_chirho, policy_chirho) = current_data_residency_policy_chirho(root_chirho)?
        .ok_or_else(|| anyhow!("no data residency policy for tenant '{tenant_chirho}'"))?;
    let violations_chirho = residency_violations_chirho(
        &policy_chirho,
        &host_region_chirho,
        &processing_region_chirho,
        std::slice::from_ref(&data_region_chirho),
    );
    let attestation_chirho = DataResidencyAttestationChirho {
        schema_chirho: DATA_RESIDENCY_ATTESTATION_SCHEMA_CHIRHO.to_string(),
        tenant_chirho: tenant_chirho.clone(),
        policy_chirho: policy_hash_chirho.clone(),
        host_region_chirho,
        processing_region_chirho,
        data_region_chirho,
        region_source_chirho: region_source_chirho.to_string(),
        compliant_chirho: violations_chirho.is_empty(),
        violations_chirho,
        at_ms_chirho: now_ms_chirho(),
        scope_notes_chirho: vec![
            "Attestation compares operator-sourced host, processing, and data region assertions to the current tenant residency policy."
                .to_string(),
            "It proves that a signed assertion was checked at this time; it does not independently geolocate hardware or storage."
                .to_string(),
        ],
    };
    let attestation_hash_chirho =
        store_chirho::put_object_chirho(root_chirho, &attestation_chirho)?;
    let record_chirho = append_attestation_record_chirho(
        root_chirho,
        &attestation_chirho,
        &attestation_hash_chirho,
        operator_chirho,
    )?;
    Ok((attestation_chirho, record_chirho))
}

pub fn data_residency_policy_set_report_chirho(
    policy_chirho: DataResidencyPolicyChirho,
    record_chirho: DataResidencyPolicyRecordChirho,
) -> DataResidencyPolicySetReportChirho {
    DataResidencyPolicySetReportChirho {
        schema_chirho: DATA_RESIDENCY_POLICY_SET_REPORT_SCHEMA_CHIRHO.to_string(),
        policy_chirho,
        record_chirho,
    }
}

pub fn data_residency_policy_current_report_chirho(
    policy_hash_chirho: HashChirho,
    policy_chirho: DataResidencyPolicyChirho,
) -> DataResidencyPolicyCurrentReportChirho {
    DataResidencyPolicyCurrentReportChirho {
        schema_chirho: DATA_RESIDENCY_POLICY_CURRENT_REPORT_SCHEMA_CHIRHO.to_string(),
        policy_hash_chirho,
        policy_chirho,
    }
}

pub fn data_residency_attestation_report_chirho(
    attestation_chirho: DataResidencyAttestationChirho,
    record_chirho: DataResidencyAttestationRecordChirho,
) -> DataResidencyAttestationReportChirho {
    DataResidencyAttestationReportChirho {
        schema_chirho: DATA_RESIDENCY_ATTESTATION_REPORT_SCHEMA_CHIRHO.to_string(),
        attestation_chirho,
        record_chirho,
    }
}

pub fn check_placement_candidate_residency_chirho(
    root_chirho: &Path,
    candidate_chirho: &placement_chirho::PlacementCandidateChirho,
) -> Result<DataResidencyPlacementCheckChirho> {
    let tenant_chirho = tenant_for_root_chirho(root_chirho)?;
    let (policy_hash_chirho, policy_chirho) = current_data_residency_policy_chirho(root_chirho)?
        .ok_or_else(|| anyhow!("no data residency policy for tenant '{tenant_chirho}'"))?;
    let candidate_region_chirho =
        normalize_region_chirho("candidate region", &candidate_chirho.region_chirho)?;
    let data_regions_chirho = normalize_regions_chirho(
        "candidate data region",
        &candidate_chirho.data_regions_chirho,
    )?;
    let violations_chirho = residency_violations_chirho(
        &policy_chirho,
        &candidate_region_chirho,
        &candidate_region_chirho,
        &data_regions_chirho,
    );
    Ok(DataResidencyPlacementCheckChirho {
        schema_chirho: DATA_RESIDENCY_PLACEMENT_CHECK_SCHEMA_CHIRHO.to_string(),
        tenant_chirho,
        policy_chirho: policy_hash_chirho,
        candidate_chirho: candidate_chirho.candidate_chirho.clone(),
        candidate_region_chirho,
        data_regions_chirho,
        eligible_chirho: violations_chirho.is_empty(),
        violations_chirho,
    })
}

pub fn validate_data_residency_policy_set_report_schema_chirho(
    report_chirho: &DataResidencyPolicySetReportChirho,
) -> Result<()> {
    validate_data_residency_report_schema_chirho(
        &report_chirho.schema_chirho,
        DATA_RESIDENCY_POLICY_SET_REPORT_SCHEMA_CHIRHO,
        "data residency policy set report",
    )
}

pub fn validate_data_residency_policy_current_report_schema_chirho(
    report_chirho: &DataResidencyPolicyCurrentReportChirho,
) -> Result<()> {
    validate_data_residency_report_schema_chirho(
        &report_chirho.schema_chirho,
        DATA_RESIDENCY_POLICY_CURRENT_REPORT_SCHEMA_CHIRHO,
        "data residency policy current report",
    )
}

pub fn validate_data_residency_attestation_report_schema_chirho(
    report_chirho: &DataResidencyAttestationReportChirho,
) -> Result<()> {
    validate_data_residency_report_schema_chirho(
        &report_chirho.schema_chirho,
        DATA_RESIDENCY_ATTESTATION_REPORT_SCHEMA_CHIRHO,
        "data residency attestation report",
    )
}

pub fn validate_data_residency_placement_check_schema_chirho(
    check_chirho: &DataResidencyPlacementCheckChirho,
) -> Result<()> {
    validate_data_residency_report_schema_chirho(
        &check_chirho.schema_chirho,
        DATA_RESIDENCY_PLACEMENT_CHECK_SCHEMA_CHIRHO,
        "data residency placement check",
    )
}

fn validate_data_residency_report_schema_chirho(
    schema_chirho: &str,
    expected_chirho: &str,
    label_chirho: &str,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("unsupported {label_chirho} schema '{schema_chirho}'");
    }
    Ok(())
}

pub fn residency_placement_constraints_chirho(
    policy_chirho: &DataResidencyPolicyChirho,
) -> Result<Vec<placement_chirho::PlacementHardConstraintChirho>> {
    validate_policy_chirho(policy_chirho)?;
    let shared_regions_chirho = policy_chirho
        .allowed_processing_regions_chirho
        .iter()
        .filter(|region_chirho| {
            policy_chirho
                .allowed_data_regions_chirho
                .contains(region_chirho)
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if shared_regions_chirho.len() != 1
        || policy_chirho.allowed_processing_regions_chirho.len() != 1
        || policy_chirho.allowed_data_regions_chirho.len() != 1
    {
        bail!(
            "placement hard-constraint adapter requires one shared data/processing region; use residency candidate checks for multi-region policies"
        );
    }
    let region_chirho = shared_regions_chirho
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("data residency policy has no shared placement region"))?;
    Ok(vec![
        placement_chirho::PlacementHardConstraintChirho::RequiredRegionChirho {
            region_chirho: region_chirho.clone(),
        },
        placement_chirho::PlacementHardConstraintChirho::DataResidencyRegionChirho {
            region_chirho,
        },
    ])
}

pub fn load_data_residency_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<DataResidencyPolicyRecordChirho>> {
    load_jsonl_chirho(&policy_records_path_chirho(root_chirho))
}

pub fn load_data_residency_attestation_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<DataResidencyAttestationRecordChirho>> {
    load_jsonl_chirho(&attestation_records_path_chirho(root_chirho))
}

pub fn verify_data_residency_chirho(root_chirho: &Path) -> Result<DataResidencyVerifyReportChirho> {
    let tenant_chirho = tenant_chirho::tenant_id_for_root_chirho(root_chirho)?;
    let tenant_id_chirho = tenant_chirho.as_tenant_id_chirho();
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let policy_records_chirho = load_data_residency_policy_records_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in policy_records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "data residency policy seq gap at index {index_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_policy_record_chirho(record_chirho)?;
        if tenant_id_chirho.is_some_and(|id_chirho| id_chirho != record_chirho.tenant_chirho) {
            bail!(
                "data residency policy record {} tenant mismatch",
                record_chirho.seq_chirho
            );
        }
        let policy_chirho: DataResidencyPolicyChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.policy_chirho)?;
        validate_policy_chirho(&policy_chirho)?;
        if policy_chirho.tenant_chirho != record_chirho.tenant_chirho
            || policy_chirho.previous_chirho != record_chirho.previous_chirho
        {
            bail!(
                "data residency policy record {} does not match policy object",
                record_chirho.seq_chirho
            );
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &policy_record_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "data residency policy record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    let attestation_records_chirho = load_data_residency_attestation_records_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in attestation_records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "data residency attestation seq gap at index {index_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_attestation_record_chirho(record_chirho)?;
        if tenant_id_chirho.is_some_and(|id_chirho| id_chirho != record_chirho.tenant_chirho) {
            bail!(
                "data residency attestation record {} tenant mismatch",
                record_chirho.seq_chirho
            );
        }
        let attestation_chirho: DataResidencyAttestationChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.attestation_chirho)?;
        validate_attestation_against_record_chirho(
            root_chirho,
            &attestation_chirho,
            record_chirho,
        )?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &attestation_record_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "data residency attestation record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    let current_policy_chirho = current_policy_hash_chirho(root_chirho)?;
    let noncompliant_attestations_chirho = attestation_records_chirho
        .iter()
        .filter(|record_chirho| !record_chirho.compliant_chirho)
        .count();
    if let Some(last_record_chirho) = policy_records_chirho.last() {
        if current_policy_chirho.as_ref() != Some(&last_record_chirho.policy_chirho) {
            bail!("data residency current ref does not point at the last policy record");
        }
    }
    Ok(DataResidencyVerifyReportChirho {
        schema_chirho: DATA_RESIDENCY_VERIFY_REPORT_SCHEMA_CHIRHO.to_string(),
        tenant_chirho,
        policy_records_chirho: policy_records_chirho.len(),
        attestation_records_chirho: attestation_records_chirho.len(),
        noncompliant_attestations_chirho,
        current_policy_chirho,
    })
}

fn append_attestation_record_chirho(
    root_chirho: &Path,
    attestation_chirho: &DataResidencyAttestationChirho,
    attestation_hash_chirho: &HashChirho,
    operator_chirho: &str,
) -> Result<DataResidencyAttestationRecordChirho> {
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        DATA_RESIDENCY_ATTESTATION_LOCK_CHIRHO,
        || {
            let path_chirho = attestation_records_path_chirho(root_chirho);
            let seq_chirho =
                load_data_residency_attestation_records_chirho(root_chirho)?.len() as u64;
            let mut record_chirho = DataResidencyAttestationRecordChirho {
                schema_chirho: DATA_RESIDENCY_ATTESTATION_RECORD_SCHEMA_CHIRHO.to_string(),
                seq_chirho,
                tenant_chirho: attestation_chirho.tenant_chirho.clone(),
                policy_chirho: attestation_chirho.policy_chirho.clone(),
                attestation_chirho: attestation_hash_chirho.clone(),
                host_region_chirho: attestation_chirho.host_region_chirho.clone(),
                processing_region_chirho: attestation_chirho.processing_region_chirho.clone(),
                data_region_chirho: attestation_chirho.data_region_chirho.clone(),
                region_source_chirho: attestation_chirho.region_source_chirho.clone(),
                compliant_chirho: attestation_chirho.compliant_chirho,
                operator_chirho: operator_chirho.to_string(),
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
                root_chirho,
                &attestation_record_message_chirho(&record_chirho)?,
            )?;
            seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
                &path_chirho,
                record_chirho.seq_chirho,
                &record_chirho,
            )?;
            Ok(record_chirho)
        },
    )
}

fn validate_attestation_against_record_chirho(
    root_chirho: &Path,
    attestation_chirho: &DataResidencyAttestationChirho,
    record_chirho: &DataResidencyAttestationRecordChirho,
) -> Result<()> {
    validate_attestation_chirho(attestation_chirho)?;
    if attestation_chirho.tenant_chirho != record_chirho.tenant_chirho
        || attestation_chirho.policy_chirho != record_chirho.policy_chirho
        || attestation_chirho.host_region_chirho != record_chirho.host_region_chirho
        || attestation_chirho.processing_region_chirho != record_chirho.processing_region_chirho
        || attestation_chirho.data_region_chirho != record_chirho.data_region_chirho
        || attestation_chirho.region_source_chirho != record_chirho.region_source_chirho
        || attestation_chirho.compliant_chirho != record_chirho.compliant_chirho
    {
        bail!(
            "data residency attestation record {} does not match attestation object",
            record_chirho.seq_chirho
        );
    }
    let policy_chirho: DataResidencyPolicyChirho =
        store_chirho::get_object_chirho(root_chirho, &attestation_chirho.policy_chirho)?;
    validate_policy_chirho(&policy_chirho)?;
    if policy_chirho.tenant_chirho != attestation_chirho.tenant_chirho {
        bail!(
            "data residency attestation record {} policy tenant mismatch",
            record_chirho.seq_chirho
        );
    }
    let violations_chirho = residency_violations_chirho(
        &policy_chirho,
        &attestation_chirho.host_region_chirho,
        &attestation_chirho.processing_region_chirho,
        std::slice::from_ref(&attestation_chirho.data_region_chirho),
    );
    if violations_chirho != attestation_chirho.violations_chirho
        || violations_chirho.is_empty() != attestation_chirho.compliant_chirho
    {
        bail!(
            "data residency attestation record {} compliance no longer recomputes",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

fn residency_violations_chirho(
    policy_chirho: &DataResidencyPolicyChirho,
    host_region_chirho: &str,
    processing_region_chirho: &str,
    data_regions_chirho: &[String],
) -> Vec<String> {
    let mut violations_chirho = Vec::new();
    if host_region_chirho != processing_region_chirho {
        violations_chirho.push(format!(
            "host region {host_region_chirho} does not match declared processing region {processing_region_chirho}"
        ));
    }
    if !policy_chirho
        .allowed_processing_regions_chirho
        .contains(&processing_region_chirho.to_string())
    {
        violations_chirho.push(format!(
            "processing region {processing_region_chirho} is outside allowed processing regions"
        ));
    }
    if data_regions_chirho.is_empty() {
        violations_chirho.push("candidate has no declared data region".to_string());
    }
    for data_region_chirho in data_regions_chirho {
        if !policy_chirho
            .allowed_data_regions_chirho
            .contains(data_region_chirho)
        {
            violations_chirho.push(format!(
                "data region {data_region_chirho} is outside allowed data regions"
            ));
        }
    }
    violations_chirho
}

fn current_policy_hash_chirho(root_chirho: &Path) -> Result<Option<HashChirho>> {
    let tenant_chirho = tenant_chirho::tenant_id_for_root_chirho(root_chirho)?;
    let Some(id_chirho) = tenant_chirho.as_tenant_id_chirho() else {
        return Ok(None);
    };
    Ok(refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&policy_ref_chirho(id_chirho))
        .cloned())
}

fn policy_ref_chirho(tenant_chirho: &str) -> String {
    format!("data-residency/{tenant_chirho}")
}

fn tenant_for_root_chirho(root_chirho: &Path) -> Result<String> {
    tenant_chirho::tenant_id_for_root_chirho(root_chirho)?
        .into_tenant_id_chirho()
        .ok_or_else(|| {
            anyhow!("data residency requires a tenant root; pass --tenant <tenant_chirho>")
        })
}

fn normalize_regions_chirho(label_chirho: &str, regions_chirho: &[String]) -> Result<Vec<String>> {
    if regions_chirho.is_empty() {
        bail!("{label_chirho} list must not be empty");
    }
    let mut regions_chirho = regions_chirho
        .iter()
        .map(|region_chirho| normalize_region_chirho(label_chirho, region_chirho))
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect::<Vec<_>>();
    regions_chirho.sort();
    Ok(regions_chirho)
}

fn normalize_region_chirho(label_chirho: &str, region_chirho: &str) -> Result<String> {
    let region_chirho = region_chirho.trim().to_ascii_lowercase();
    if region_chirho.is_empty()
        || region_chirho.len() > 64
        || region_chirho.starts_with('-')
        || region_chirho.ends_with('-')
        || !region_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase() || byte_chirho.is_ascii_digit() || byte_chirho == b'-'
        })
    {
        bail!("{label_chirho} must be a lowercase region token like eu-fsn1 or us-east-1");
    }
    Ok(region_chirho)
}

fn validate_safe_token_chirho(label_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("{label_chirho} must be a short opaque token");
    }
    Ok(())
}

fn validate_policy_chirho(policy_chirho: &DataResidencyPolicyChirho) -> Result<()> {
    if policy_chirho.schema_chirho != DATA_RESIDENCY_POLICY_SCHEMA_CHIRHO {
        bail!(
            "unsupported data residency policy schema '{}'",
            policy_chirho.schema_chirho
        );
    }
    tenant_chirho::validate_tenant_id_chirho(&policy_chirho.tenant_chirho)?;
    normalize_regions_chirho("data region", &policy_chirho.allowed_data_regions_chirho)?;
    normalize_regions_chirho(
        "processing region",
        &policy_chirho.allowed_processing_regions_chirho,
    )?;
    Ok(())
}

fn validate_attestation_chirho(attestation_chirho: &DataResidencyAttestationChirho) -> Result<()> {
    if attestation_chirho.schema_chirho != DATA_RESIDENCY_ATTESTATION_SCHEMA_CHIRHO {
        bail!(
            "unsupported data residency attestation schema '{}'",
            attestation_chirho.schema_chirho
        );
    }
    tenant_chirho::validate_tenant_id_chirho(&attestation_chirho.tenant_chirho)?;
    normalize_region_chirho("host region", &attestation_chirho.host_region_chirho)?;
    normalize_region_chirho(
        "processing region",
        &attestation_chirho.processing_region_chirho,
    )?;
    normalize_region_chirho("data region", &attestation_chirho.data_region_chirho)?;
    validate_safe_token_chirho(
        "region_source_chirho",
        &attestation_chirho.region_source_chirho,
    )?;
    Ok(())
}

fn validate_policy_record_chirho(record_chirho: &DataResidencyPolicyRecordChirho) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != DATA_RESIDENCY_POLICY_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported data residency policy record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    tenant_chirho::validate_tenant_id_chirho(&record_chirho.tenant_chirho)?;
    validate_safe_token_chirho("operator_chirho", &record_chirho.operator_chirho)
}

fn validate_attestation_record_chirho(
    record_chirho: &DataResidencyAttestationRecordChirho,
) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != DATA_RESIDENCY_ATTESTATION_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported data residency attestation record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    tenant_chirho::validate_tenant_id_chirho(&record_chirho.tenant_chirho)?;
    normalize_region_chirho("host region", &record_chirho.host_region_chirho)?;
    normalize_region_chirho("processing region", &record_chirho.processing_region_chirho)?;
    normalize_region_chirho("data region", &record_chirho.data_region_chirho)?;
    validate_safe_token_chirho("region_source_chirho", &record_chirho.region_source_chirho)?;
    validate_safe_token_chirho("operator_chirho", &record_chirho.operator_chirho)
}

fn policy_record_message_chirho(
    record_chirho: &DataResidencyPolicyRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn attestation_record_message_chirho(
    record_chirho: &DataResidencyAttestationRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn policy_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("data-residency-policies-chirho.jsonl")
}

fn attestation_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("data-residency-attestations-chirho.jsonl")
}

fn load_jsonl_chirho<T: for<'de> Deserialize<'de>>(path_chirho: &Path) -> Result<Vec<T>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for (line_index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho).with_context(|| {
            format!(
                "decode {} line {}",
                path_chirho.display(),
                line_index_chirho + 1
            )
        })?);
    }
    Ok(records_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let now_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration_chirho| duration_chirho.as_millis())
            .unwrap_or(0);
        let pid_chirho = std::process::id();
        std::env::temp_dir().join(format!(
            "cairn-residency-test-{pid_chirho}-{n_chirho}-{now_chirho}"
        ))
    }

    fn tenant_root_chirho() -> (PathBuf, PathBuf) {
        let platform_root_chirho = tmp_root_chirho();
        let tenant_root_chirho =
            tenant_chirho::prepare_tenant_root_chirho(&platform_root_chirho, "tenant-a-chirho")
                .unwrap();
        (platform_root_chirho, tenant_root_chirho)
    }

    #[test]
    fn residency_policy_sets_current_ref_and_verifies_chirho() {
        let (platform_root_chirho, root_chirho) = tenant_root_chirho();
        let (_policy_chirho, record_chirho) = set_data_residency_policy_chirho(
            &root_chirho,
            &[String::from("eu-fsn1")],
            &[String::from("eu-fsn1")],
            "operator/residency-chirho",
            true,
        )
        .unwrap();
        assert_eq!(record_chirho.seq_chirho, 0);
        let (current_hash_chirho, current_chirho) =
            current_data_residency_policy_chirho(&root_chirho)
                .unwrap()
                .unwrap();
        assert_eq!(current_hash_chirho, record_chirho.policy_chirho);
        assert_eq!(current_chirho.allowed_data_regions_chirho, vec!["eu-fsn1"]);
        let report_chirho = verify_data_residency_chirho(&root_chirho).unwrap();
        assert_eq!(
            report_chirho.schema_chirho,
            DATA_RESIDENCY_VERIFY_REPORT_SCHEMA_CHIRHO
        );
        assert_eq!(report_chirho.policy_records_chirho, 1);
        assert_eq!(report_chirho.noncompliant_attestations_chirho, 0);
        assert_eq!(
            report_chirho.current_policy_chirho,
            Some(record_chirho.policy_chirho)
        );
        let _ = std::fs::remove_dir_all(platform_root_chirho);
    }

    #[test]
    fn data_residency_operator_reports_are_schema_tagged_chirho() {
        let (platform_root_chirho, root_chirho) = tenant_root_chirho();
        let (policy_chirho, policy_record_chirho) = set_data_residency_policy_chirho(
            &root_chirho,
            &[String::from("eu-fsn1")],
            &[String::from("eu-fsn1")],
            "operator/residency-chirho",
            true,
        )
        .unwrap();
        let policy_set_report_chirho =
            data_residency_policy_set_report_chirho(policy_chirho.clone(), policy_record_chirho);
        assert_eq!(
            policy_set_report_chirho.schema_chirho,
            DATA_RESIDENCY_POLICY_SET_REPORT_SCHEMA_CHIRHO
        );
        validate_data_residency_policy_set_report_schema_chirho(&policy_set_report_chirho).unwrap();
        assert_eq!(
            serde_json::to_value(&policy_set_report_chirho).unwrap()["schema_chirho"],
            DATA_RESIDENCY_POLICY_SET_REPORT_SCHEMA_CHIRHO
        );
        let mut legacy_policy_set_report_chirho = policy_set_report_chirho.clone();
        legacy_policy_set_report_chirho.schema_chirho.clear();
        validate_data_residency_policy_set_report_schema_chirho(&legacy_policy_set_report_chirho)
            .unwrap();
        let legacy_policy_set_value_chirho =
            serde_json::to_value(&legacy_policy_set_report_chirho).unwrap();
        assert!(legacy_policy_set_value_chirho
            .get("schema_chirho")
            .is_none());
        let legacy_policy_set_json_chirho =
            serde_json::to_string(&legacy_policy_set_report_chirho).unwrap();
        let legacy_policy_set_roundtrip_chirho: DataResidencyPolicySetReportChirho =
            serde_json::from_str(&legacy_policy_set_json_chirho).unwrap();
        assert!(legacy_policy_set_roundtrip_chirho.schema_chirho.is_empty());
        let mut bad_policy_set_report_chirho = policy_set_report_chirho.clone();
        bad_policy_set_report_chirho.schema_chirho =
            "data-residency-policy-set-report-v9-chirho".to_string();
        let error_chirho =
            validate_data_residency_policy_set_report_schema_chirho(&bad_policy_set_report_chirho)
                .unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("unsupported data residency policy set report schema"));

        let (current_hash_chirho, current_policy_chirho) =
            current_data_residency_policy_chirho(&root_chirho)
                .unwrap()
                .unwrap();
        let current_report_chirho =
            data_residency_policy_current_report_chirho(current_hash_chirho, current_policy_chirho);
        assert_eq!(
            current_report_chirho.schema_chirho,
            DATA_RESIDENCY_POLICY_CURRENT_REPORT_SCHEMA_CHIRHO
        );
        validate_data_residency_policy_current_report_schema_chirho(&current_report_chirho)
            .unwrap();
        let mut legacy_current_report_chirho = current_report_chirho.clone();
        legacy_current_report_chirho.schema_chirho.clear();
        validate_data_residency_policy_current_report_schema_chirho(&legacy_current_report_chirho)
            .unwrap();
        let legacy_current_value_chirho =
            serde_json::to_value(&legacy_current_report_chirho).unwrap();
        assert!(legacy_current_value_chirho.get("schema_chirho").is_none());
        let legacy_current_json_chirho =
            serde_json::to_string(&legacy_current_report_chirho).unwrap();
        let legacy_current_roundtrip_chirho: DataResidencyPolicyCurrentReportChirho =
            serde_json::from_str(&legacy_current_json_chirho).unwrap();
        assert!(legacy_current_roundtrip_chirho.schema_chirho.is_empty());
        let mut bad_current_report_chirho = current_report_chirho.clone();
        bad_current_report_chirho.schema_chirho =
            "data-residency-policy-current-report-v9-chirho".to_string();
        let error_chirho =
            validate_data_residency_policy_current_report_schema_chirho(&bad_current_report_chirho)
                .unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("unsupported data residency policy current report schema"));

        let (attestation_chirho, attestation_record_chirho) = attest_data_residency_chirho(
            &root_chirho,
            "eu-fsn1",
            "eu-fsn1",
            "eu-fsn1",
            "config/host-region-chirho",
            "operator/residency-chirho",
        )
        .unwrap();
        let attestation_report_chirho =
            data_residency_attestation_report_chirho(attestation_chirho, attestation_record_chirho);
        assert_eq!(
            attestation_report_chirho.schema_chirho,
            DATA_RESIDENCY_ATTESTATION_REPORT_SCHEMA_CHIRHO
        );
        validate_data_residency_attestation_report_schema_chirho(&attestation_report_chirho)
            .unwrap();
        assert_eq!(
            serde_json::to_value(&attestation_report_chirho).unwrap()["schema_chirho"],
            DATA_RESIDENCY_ATTESTATION_REPORT_SCHEMA_CHIRHO
        );
        let mut legacy_attestation_report_chirho = attestation_report_chirho.clone();
        legacy_attestation_report_chirho.schema_chirho.clear();
        validate_data_residency_attestation_report_schema_chirho(&legacy_attestation_report_chirho)
            .unwrap();
        let legacy_attestation_value_chirho =
            serde_json::to_value(&legacy_attestation_report_chirho).unwrap();
        assert!(legacy_attestation_value_chirho
            .get("schema_chirho")
            .is_none());
        let legacy_attestation_json_chirho =
            serde_json::to_string(&legacy_attestation_report_chirho).unwrap();
        let legacy_attestation_roundtrip_chirho: DataResidencyAttestationReportChirho =
            serde_json::from_str(&legacy_attestation_json_chirho).unwrap();
        assert!(legacy_attestation_roundtrip_chirho.schema_chirho.is_empty());
        let mut bad_attestation_report_chirho = attestation_report_chirho.clone();
        bad_attestation_report_chirho.schema_chirho =
            "data-residency-attestation-report-v9-chirho".to_string();
        let error_chirho = validate_data_residency_attestation_report_schema_chirho(
            &bad_attestation_report_chirho,
        )
        .unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("unsupported data residency attestation report schema"));

        let _ = std::fs::remove_dir_all(platform_root_chirho);
    }

    #[test]
    fn residency_attestation_records_compliance_and_violations_chirho() {
        let (platform_root_chirho, root_chirho) = tenant_root_chirho();
        set_data_residency_policy_chirho(
            &root_chirho,
            &[String::from("eu-fsn1")],
            &[String::from("eu-fsn1")],
            "operator/residency-chirho",
            true,
        )
        .unwrap();
        let (ok_chirho, _ok_record_chirho) = attest_data_residency_chirho(
            &root_chirho,
            "eu-fsn1",
            "eu-fsn1",
            "eu-fsn1",
            "config/host-region-chirho",
            "operator/residency-chirho",
        )
        .unwrap();
        assert!(ok_chirho.compliant_chirho);
        let (bad_chirho, _bad_record_chirho) = attest_data_residency_chirho(
            &root_chirho,
            "us-east-1",
            "us-east-1",
            "eu-fsn1",
            "config/host-region-chirho",
            "operator/residency-chirho",
        )
        .unwrap();
        assert!(!bad_chirho.compliant_chirho);
        assert!(bad_chirho
            .violations_chirho
            .iter()
            .any(|violation_chirho| violation_chirho.contains("processing region")));
        let report_chirho = verify_data_residency_chirho(&root_chirho).unwrap();
        assert_eq!(report_chirho.attestation_records_chirho, 2);
        assert_eq!(report_chirho.noncompliant_attestations_chirho, 1);
        let _ = std::fs::remove_dir_all(platform_root_chirho);
    }

    #[test]
    fn residency_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
        let (platform_root_chirho, root_chirho) = tenant_root_chirho();
        let (_policy_chirho, policy_record_chirho) = set_data_residency_policy_chirho(
            &root_chirho,
            &[String::from("eu-fsn1")],
            &[String::from("eu-fsn1")],
            "operator/residency-chirho",
            true,
        )
        .unwrap();
        let (_attestation_chirho, attestation_record_chirho) = attest_data_residency_chirho(
            &root_chirho,
            "eu-fsn1",
            "eu-fsn1",
            "eu-fsn1",
            "config/host-region-chirho",
            "operator/residency-chirho",
        )
        .unwrap();
        assert_eq!(
            policy_record_chirho.schema_chirho,
            DATA_RESIDENCY_POLICY_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(
            attestation_record_chirho.schema_chirho,
            DATA_RESIDENCY_ATTESTATION_RECORD_SCHEMA_CHIRHO
        );

        let policy_path_chirho = policy_records_path_chirho(&root_chirho);
        let attestation_path_chirho = attestation_records_path_chirho(&root_chirho);
        let policy_text_chirho = std::fs::read_to_string(&policy_path_chirho).unwrap();
        let attestation_text_chirho = std::fs::read_to_string(&attestation_path_chirho).unwrap();
        assert!(policy_text_chirho.contains(DATA_RESIDENCY_POLICY_RECORD_SCHEMA_CHIRHO));
        assert!(attestation_text_chirho.contains(DATA_RESIDENCY_ATTESTATION_RECORD_SCHEMA_CHIRHO));

        std::fs::write(
            &policy_path_chirho,
            policy_text_chirho.replace(
                DATA_RESIDENCY_POLICY_RECORD_SCHEMA_CHIRHO,
                "data-residency-policy-record-v9-chirho",
            ),
        )
        .unwrap();
        let policy_error_chirho = verify_data_residency_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(policy_error_chirho.contains("unsupported data residency policy record schema"));

        std::fs::write(&policy_path_chirho, policy_text_chirho).unwrap();
        std::fs::write(
            &attestation_path_chirho,
            attestation_text_chirho.replace(
                DATA_RESIDENCY_ATTESTATION_RECORD_SCHEMA_CHIRHO,
                "data-residency-attestation-record-v9-chirho",
            ),
        )
        .unwrap();
        let attestation_error_chirho = verify_data_residency_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(attestation_error_chirho
            .contains("unsupported data residency attestation record schema"));

        let _ = std::fs::remove_dir_all(platform_root_chirho);
    }

    #[test]
    fn legacy_data_residency_records_without_schema_still_verify_chirho() {
        let (platform_root_chirho, root_chirho) = tenant_root_chirho();
        let tenant_chirho = tenant_for_root_chirho(&root_chirho).unwrap();
        let policy_chirho = DataResidencyPolicyChirho {
            schema_chirho: DATA_RESIDENCY_POLICY_SCHEMA_CHIRHO.to_string(),
            tenant_chirho: tenant_chirho.clone(),
            allowed_data_regions_chirho: vec!["eu-fsn1".to_string()],
            allowed_processing_regions_chirho: vec!["eu-fsn1".to_string()],
            deny_unattested_processing_chirho: true,
            previous_chirho: None,
            scope_notes_chirho: Vec::new(),
        };
        let policy_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &policy_chirho)
            .expect("store legacy policy object");
        let mut policy_record_chirho = DataResidencyPolicyRecordChirho {
            schema_chirho: String::new(),
            seq_chirho: 0,
            tenant_chirho: tenant_chirho.clone(),
            policy_chirho: policy_hash_chirho.clone(),
            previous_chirho: None,
            operator_chirho: "operator/residency-chirho".to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        policy_record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &policy_record_message_chirho(&policy_record_chirho).unwrap(),
        )
        .unwrap();
        seqlog_chirho::append_jsonl_unlocked_chirho(
            &policy_records_path_chirho(&root_chirho),
            &policy_record_chirho,
        )
        .unwrap();
        refs_chirho::set_branch_chirho(
            &root_chirho,
            &policy_ref_chirho(&tenant_chirho),
            policy_hash_chirho.clone(),
        )
        .unwrap();

        let attestation_chirho = DataResidencyAttestationChirho {
            schema_chirho: DATA_RESIDENCY_ATTESTATION_SCHEMA_CHIRHO.to_string(),
            tenant_chirho: tenant_chirho.clone(),
            policy_chirho: policy_hash_chirho.clone(),
            host_region_chirho: "eu-fsn1".to_string(),
            processing_region_chirho: "eu-fsn1".to_string(),
            data_region_chirho: "eu-fsn1".to_string(),
            region_source_chirho: "config/host-region-chirho".to_string(),
            compliant_chirho: true,
            violations_chirho: Vec::new(),
            at_ms_chirho: now_ms_chirho(),
            scope_notes_chirho: Vec::new(),
        };
        let attestation_hash_chirho =
            store_chirho::put_object_chirho(&root_chirho, &attestation_chirho)
                .expect("store legacy attestation object");
        let mut attestation_record_chirho = DataResidencyAttestationRecordChirho {
            schema_chirho: String::new(),
            seq_chirho: 0,
            tenant_chirho,
            policy_chirho: policy_hash_chirho,
            attestation_chirho: attestation_hash_chirho,
            host_region_chirho: "eu-fsn1".to_string(),
            processing_region_chirho: "eu-fsn1".to_string(),
            data_region_chirho: "eu-fsn1".to_string(),
            region_source_chirho: "config/host-region-chirho".to_string(),
            compliant_chirho: true,
            operator_chirho: "operator/residency-chirho".to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        attestation_record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &attestation_record_message_chirho(&attestation_record_chirho).unwrap(),
        )
        .unwrap();
        seqlog_chirho::append_jsonl_unlocked_chirho(
            &attestation_records_path_chirho(&root_chirho),
            &attestation_record_chirho,
        )
        .unwrap();

        let policy_text_chirho =
            std::fs::read_to_string(policy_records_path_chirho(&root_chirho)).unwrap();
        let attestation_text_chirho =
            std::fs::read_to_string(attestation_records_path_chirho(&root_chirho)).unwrap();
        assert!(!policy_text_chirho.contains("schema_chirho"));
        assert!(!attestation_text_chirho.contains("schema_chirho"));
        let report_chirho = verify_data_residency_chirho(&root_chirho).unwrap();
        assert_eq!(report_chirho.policy_records_chirho, 1);
        assert_eq!(report_chirho.attestation_records_chirho, 1);

        let _ = std::fs::remove_dir_all(platform_root_chirho);
    }

    #[test]
    fn residency_placement_check_filters_candidates_chirho() {
        let (platform_root_chirho, root_chirho) = tenant_root_chirho();
        set_data_residency_policy_chirho(
            &root_chirho,
            &[String::from("eu-fsn1")],
            &[String::from("eu-fsn1")],
            "operator/residency-chirho",
            true,
        )
        .unwrap();
        let good_chirho = placement_chirho::PlacementCandidateChirho {
            candidate_chirho: "worker-eu-chirho".to_string(),
            region_chirho: "eu-fsn1".to_string(),
            hardware_chirho: Vec::new(),
            features_chirho: Vec::new(),
            resident_modules_chirho: Vec::new(),
            user_caches_chirho: Vec::new(),
            resident_models_chirho: Vec::new(),
            data_regions_chirho: vec!["eu-fsn1".to_string()],
            accelerators_chirho: Vec::new(),
            egress_price_micros_per_gib_chirho: None,
        };
        let bad_chirho = placement_chirho::PlacementCandidateChirho {
            candidate_chirho: "worker-us-chirho".to_string(),
            region_chirho: "us-east-1".to_string(),
            data_regions_chirho: vec!["us-east-1".to_string()],
            ..good_chirho.clone()
        };
        let good_check_chirho =
            check_placement_candidate_residency_chirho(&root_chirho, &good_chirho).unwrap();
        assert_eq!(
            good_check_chirho.schema_chirho,
            DATA_RESIDENCY_PLACEMENT_CHECK_SCHEMA_CHIRHO
        );
        validate_data_residency_placement_check_schema_chirho(&good_check_chirho).unwrap();
        assert_eq!(
            serde_json::to_value(&good_check_chirho).unwrap()["schema_chirho"],
            DATA_RESIDENCY_PLACEMENT_CHECK_SCHEMA_CHIRHO
        );
        let mut legacy_check_chirho = good_check_chirho.clone();
        legacy_check_chirho.schema_chirho.clear();
        validate_data_residency_placement_check_schema_chirho(&legacy_check_chirho).unwrap();
        let legacy_check_json_chirho = serde_json::to_string(&legacy_check_chirho).unwrap();
        assert!(!legacy_check_json_chirho.contains("schema_chirho"));
        let legacy_check_roundtrip_chirho: DataResidencyPlacementCheckChirho =
            serde_json::from_str(&legacy_check_json_chirho).unwrap();
        assert!(legacy_check_roundtrip_chirho.schema_chirho.is_empty());
        let mut bad_schema_check_chirho = good_check_chirho.clone();
        bad_schema_check_chirho.schema_chirho =
            "data-residency-placement-check-v9-chirho".to_string();
        let error_chirho =
            validate_data_residency_placement_check_schema_chirho(&bad_schema_check_chirho)
                .unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("unsupported data residency placement check schema"));
        assert!(good_check_chirho.eligible_chirho);
        let bad_check_chirho =
            check_placement_candidate_residency_chirho(&root_chirho, &bad_chirho).unwrap();
        assert!(!bad_check_chirho.eligible_chirho);
        assert_eq!(bad_check_chirho.violations_chirho.len(), 2);
        let (_policy_hash_chirho, policy_chirho) =
            current_data_residency_policy_chirho(&root_chirho)
                .unwrap()
                .unwrap();
        let descriptor_chirho = placement_chirho::PlacementDescriptorChirho {
            module_chirho: HashChirho("module-for-residency-test-chirho".to_string()),
            hard_constraints_chirho: residency_placement_constraints_chirho(&policy_chirho)
                .unwrap(),
            affinities_chirho: Vec::new(),
            metadata_chirho: std::collections::BTreeMap::new(),
        };
        let rankings_chirho = placement_chirho::rank_placement_candidates_chirho(
            &descriptor_chirho,
            &[good_chirho, bad_chirho],
        )
        .unwrap();
        assert!(rankings_chirho
            .iter()
            .any(
                |score_chirho| score_chirho.candidate_chirho == "worker-eu-chirho"
                    && score_chirho.eligible_chirho
            ));
        assert!(rankings_chirho
            .iter()
            .any(
                |score_chirho| score_chirho.candidate_chirho == "worker-us-chirho"
                    && !score_chirho.eligible_chirho
            ));
        let _ = std::fs::remove_dir_all(platform_root_chirho);
    }

    #[test]
    fn residency_tampered_policy_log_is_rejected_chirho() {
        let (platform_root_chirho, root_chirho) = tenant_root_chirho();
        set_data_residency_policy_chirho(
            &root_chirho,
            &[String::from("eu-fsn1")],
            &[String::from("eu-fsn1")],
            "operator/residency-chirho",
            true,
        )
        .unwrap();
        let path_chirho = policy_records_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        std::fs::write(
            &path_chirho,
            text_chirho.replace("operator/residency-chirho", "operator/tampered-chirho"),
        )
        .unwrap();
        assert!(verify_data_residency_chirho(&root_chirho).is_err());
        let _ = std::fs::remove_dir_all(platform_root_chirho);
    }

    #[test]
    fn residency_requires_tenant_root_chirho() {
        let root_chirho = tmp_root_chirho();
        let error_chirho = set_data_residency_policy_chirho(
            &root_chirho,
            &[String::from("eu-fsn1")],
            &[String::from("eu-fsn1")],
            "operator/residency-chirho",
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("--tenant"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}
