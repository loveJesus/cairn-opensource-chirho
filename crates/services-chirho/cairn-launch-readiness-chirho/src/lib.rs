// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Reports local contact evidence without inheriting another installation's readiness.

use anyhow::Result;
use cairn_chirho::{model_chirho::HashChirho, operator_evidence_chirho};
use cairn_operator_smoke_chirho::contact_example_smoke_chirho;
use serde::Serialize;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub const LAUNCH_READINESS_REPORT_SCHEMA_CHIRHO: &str = "launch-readiness-report-v6-chirho";
const LAUNCH_READINESS_CONTACT_EVIDENCE_SCHEMA_CHIRHO: &str =
    "launch-readiness-contact-evidence-v2-chirho";
const LAUNCH_READINESS_GATE_SCHEMA_CHIRHO: &str = "launch-readiness-gate-v2-chirho";

#[derive(Clone, Debug, Serialize)]
pub struct LaunchReadinessReportChirho {
    pub schema_chirho: &'static str,
    pub candidate_chirho: String,
    pub scope_chirho: String,
    pub root_scope_chirho: String,
    pub manifest_source_chirho: String,
    pub manifest_hash_chirho: HashChirho,
    pub production_ready_chirho: bool,
    pub blockers_chirho: Vec<LaunchReadinessGateChirho>,
    pub external_evidence_chirho: Vec<LaunchReadinessGateChirho>,
    pub local_candidate_ready_chirho: bool,
    pub contact_chirho: LaunchReadinessContactEvidenceChirho,
    pub deferred_chirho: Vec<LaunchReadinessGateChirho>,
    pub honest_scope_chirho: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LaunchReadinessContactEvidenceChirho {
    pub schema_chirho: &'static str,
    pub source_report_schema_chirho: &'static str,
    pub app_chirho: String,
    pub owner_chirho: String,
    pub server_chirho: String,
    pub submit_status_chirho: u16,
    pub list_status_chirho: u16,
    pub served_read_posture_chirho: String,
    pub operator_read_posture_chirho: String,
    pub app_state_status_chirho: u16,
    pub app_reveal_status_chirho: u16,
    pub missing_auth_status_chirho: u16,
    pub contact_key_chirho: String,
    pub contact_raw_body_absent_from_cas_chirho: bool,
    pub contact_private_blob_roundtrip_chirho: bool,
    pub contact_safe_surfaces_pii_free_chirho: bool,
    pub privacy_scan_findings_chirho: usize,
    pub persistent_effect_records_chirho: usize,
    pub volatile_effect_records_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LaunchReadinessGateChirho {
    pub schema_chirho: &'static str,
    pub name_chirho: String,
    pub status_chirho: String,
    pub required_for_production_chirho: bool,
    pub evidence_chirho: String,
    pub required_evidence_chirho: Vec<String>,
}

pub fn default_launch_readiness_manifest_path_chirho() -> PathBuf {
    contact_example_smoke_chirho::default_contact_example_manifest_path_chirho()
}

pub fn run_launch_readiness_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
) -> Result<LaunchReadinessReportChirho> {
    let contact_report_chirho = contact_example_smoke_chirho::run_contact_example_smoke_chirho(
        root_chirho,
        manifest_path_chirho,
    )?;
    Ok(build_launch_readiness_report_chirho(
        root_chirho,
        manifest_path_chirho,
        &contact_report_chirho,
    ))
}

pub fn build_launch_readiness_report_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
    contact_report_chirho: &contact_example_smoke_chirho::ContactExampleSmokeReportChirho,
) -> LaunchReadinessReportChirho {
    let contact_chirho = summarize_contact_smoke_chirho(contact_report_chirho);
    let local_candidate_ready_chirho = contact_local_candidate_ready_chirho(&contact_chirho);
    let blockers_chirho = production_blockers_chirho();
    let external_evidence_chirho = external_production_evidence_chirho();
    let deferred_chirho = deferred_non_blockers_chirho();

    LaunchReadinessReportChirho {
        schema_chirho: LAUNCH_READINESS_REPORT_SCHEMA_CHIRHO,
        candidate_chirho: "narrow public contact workflow".to_string(),
        scope_chirho:
            "operator readiness for the current narrow public contact workflow".to_string(),
        root_scope_chirho: operator_evidence_chirho::redacted_local_root_scope_chirho(root_chirho),
        manifest_source_chirho: operator_evidence_chirho::redacted_manifest_source_chirho(
            manifest_path_chirho,
        ),
        manifest_hash_chirho: contact_report_chirho.manifest_hash_chirho.clone(),
        production_ready_chirho: local_candidate_ready_chirho && blockers_chirho.is_empty(),
        blockers_chirho,
        external_evidence_chirho,
        local_candidate_ready_chirho,
        contact_chirho,
        deferred_chirho,
        honest_scope_chirho: vec![
            "runs the shipped contact example over localhost".to_string(),
            "the pinned tree serves contact submit but refuses the legacy served contact-list read".to_string(),
            "local reports do not establish hosting, provider delivery, operational custody, or production readiness".to_string(),
            "no private deployment history or operator risk acceptance is inherited by this source distribution".to_string(),
            "path-redacts local roots and manifest paths while retaining content hashes".to_string(),
            "no live providers are contacted without explicitly configured private provider credentials".to_string(),
            "money movement, public signup, public webhooks, and real-user delivery require separate authorization and installation-specific evidence".to_string(),
        ],
    }
}

pub fn has_production_blockers_chirho(report_chirho: &LaunchReadinessReportChirho) -> bool {
    !report_chirho.blockers_chirho.is_empty() || !report_chirho.production_ready_chirho
}

pub fn launch_readiness_text_chirho(report_chirho: &LaunchReadinessReportChirho) -> String {
    let mut out_chirho = String::new();
    writeln!(
        out_chirho,
        "launch readiness: production_ready={} production_blockers={} external_evidence={}",
        report_chirho.production_ready_chirho,
        report_chirho.blockers_chirho.len(),
        report_chirho.external_evidence_chirho.len()
    )
    .unwrap();
    append_gate_lines_chirho(
        &mut out_chirho,
        "external-evidence",
        "external-evidence-detail",
        &report_chirho.external_evidence_chirho,
    );
    append_gate_lines_chirho(
        &mut out_chirho,
        "blocker",
        "blocker-required-evidence",
        &report_chirho.blockers_chirho,
    );
    writeln!(
        out_chirho,
        "local workflow: candidate={} local_candidate_ready={} (local proof is not launch readiness)",
        report_chirho.candidate_chirho, report_chirho.local_candidate_ready_chirho
    )
    .unwrap();
    writeln!(
        out_chirho,
        "manifest={} root_scope={} manifest_source={} app={} owner={} server={}",
        report_chirho.manifest_hash_chirho.0,
        report_chirho.root_scope_chirho,
        report_chirho.manifest_source_chirho,
        report_chirho.contact_chirho.app_chirho,
        report_chirho.contact_chirho.owner_chirho,
        report_chirho.contact_chirho.server_chirho
    )
    .unwrap();
    writeln!(
        out_chirho,
        "wire submit={} list={} app_state={} app_reveal={} missing_auth={}",
        report_chirho.contact_chirho.submit_status_chirho,
        report_chirho.contact_chirho.list_status_chirho,
        report_chirho.contact_chirho.app_state_status_chirho,
        report_chirho.contact_chirho.app_reveal_status_chirho,
        report_chirho.contact_chirho.missing_auth_status_chirho
    )
    .unwrap();
    writeln!(
        out_chirho,
        "read served_posture={} operator_posture={}",
        report_chirho.contact_chirho.served_read_posture_chirho,
        report_chirho.contact_chirho.operator_read_posture_chirho
    )
    .unwrap();
    writeln!(
        out_chirho,
        "privacy contact_raw_absent={} pii_free contact={} scan_findings={}",
        report_chirho
            .contact_chirho
            .contact_raw_body_absent_from_cas_chirho,
        report_chirho
            .contact_chirho
            .contact_safe_surfaces_pii_free_chirho,
        report_chirho.contact_chirho.privacy_scan_findings_chirho
    )
    .unwrap();
    if !report_chirho.deferred_chirho.is_empty() {
        writeln!(
            out_chirho,
            "deferred={}",
            report_chirho.deferred_chirho.len()
        )
        .unwrap();
        append_gate_lines_chirho(
            &mut out_chirho,
            "deferred",
            "deferred-required-evidence",
            &report_chirho.deferred_chirho,
        );
    }
    out_chirho
}

fn append_gate_lines_chirho(
    out_chirho: &mut String,
    row_label_chirho: &str,
    detail_label_chirho: &str,
    gates_chirho: &[LaunchReadinessGateChirho],
) {
    for gate_chirho in gates_chirho {
        writeln!(
            out_chirho,
            "{row_label_chirho}\t{}\t{}\t{}",
            gate_chirho.name_chirho, gate_chirho.status_chirho, gate_chirho.evidence_chirho
        )
        .unwrap();
        for required_chirho in &gate_chirho.required_evidence_chirho {
            writeln!(
                out_chirho,
                "{detail_label_chirho}\t{}\t{}",
                gate_chirho.name_chirho, required_chirho
            )
            .unwrap();
        }
    }
}

fn summarize_contact_smoke_chirho(
    report_chirho: &contact_example_smoke_chirho::ContactExampleSmokeReportChirho,
) -> LaunchReadinessContactEvidenceChirho {
    let served_read_posture_chirho = report_chirho
        .read_evidence_chirho
        .iter()
        .find(|read_chirho| {
            read_chirho.path_posture_chirho()
                == contact_example_smoke_chirho::CONTACT_EXAMPLE_SERVED_READ_POSTURE_CHIRHO
        })
        .map(|read_chirho| read_chirho.path_posture_chirho())
        .unwrap_or("missing-served-read-evidence-chirho")
        .to_string();
    let operator_read_posture_chirho = report_chirho
        .read_evidence_chirho
        .iter()
        .find(|read_chirho| {
            read_chirho.path_posture_chirho()
                == contact_example_smoke_chirho::CONTACT_EXAMPLE_OPERATOR_READ_POSTURE_CHIRHO
        })
        .map(|read_chirho| read_chirho.path_posture_chirho())
        .unwrap_or("missing-operator-read-evidence-chirho")
        .to_string();
    LaunchReadinessContactEvidenceChirho {
        schema_chirho: LAUNCH_READINESS_CONTACT_EVIDENCE_SCHEMA_CHIRHO,
        source_report_schema_chirho: report_chirho.schema_chirho,
        app_chirho: report_chirho.app_chirho.clone(),
        owner_chirho: report_chirho.owner_chirho.clone(),
        server_chirho: report_chirho.server_chirho.clone(),
        submit_status_chirho: report_chirho.submit_chirho.status_chirho,
        list_status_chirho: report_chirho.list_refresh_chirho.status_chirho,
        served_read_posture_chirho,
        operator_read_posture_chirho,
        app_state_status_chirho: report_chirho.app_state_chirho.status_chirho,
        app_reveal_status_chirho: report_chirho.reveal_chirho.status_chirho,
        missing_auth_status_chirho: report_chirho.missing_owner_session_chirho.status_chirho,
        contact_key_chirho: report_chirho.persisted_chirho.contact_key_chirho.clone(),
        contact_raw_body_absent_from_cas_chirho: report_chirho
            .private_body_chirho
            .raw_body_absent_from_cas_chirho,
        contact_private_blob_roundtrip_chirho: report_chirho
            .private_body_chirho
            .private_blob_roundtrip_verified_chirho,
        contact_safe_surfaces_pii_free_chirho: report_chirho
            .persisted_chirho
            .contact_safe_surfaces_pii_free_chirho,
        privacy_scan_findings_chirho: report_chirho.privacy_scan_chirho.findings_chirho.len(),
        persistent_effect_records_chirho: report_chirho
            .persisted_chirho
            .persistent_effect_records_chirho,
        volatile_effect_records_chirho: report_chirho
            .persisted_chirho
            .volatile_effect_records_chirho,
    }
}

fn contact_local_candidate_ready_chirho(
    contact_chirho: &LaunchReadinessContactEvidenceChirho,
) -> bool {
    contact_chirho.submit_status_chirho == 200
        && contact_chirho.list_status_chirho == 200
        && contact_chirho.app_state_status_chirho == 200
        && contact_chirho.app_reveal_status_chirho == 200
        && contact_chirho.missing_auth_status_chirho == 401
        && contact_chirho.contact_raw_body_absent_from_cas_chirho
        && contact_chirho.contact_private_blob_roundtrip_chirho
        && contact_chirho.contact_safe_surfaces_pii_free_chirho
        && contact_chirho.privacy_scan_findings_chirho == 0
}

fn production_blockers_chirho() -> Vec<LaunchReadinessGateChirho> {
    vec![
        gate_chirho(
            "current-tree-contact-list-re-serve-chirho",
            "blocked-current-tree-chirho",
            true,
            "contact submit remains served, but the legacy served contact-list read is refused; a generic non-money published-projection source still needs review",
            &[
                "do not fabricate Fresh or StandingWriteRate evidence over the legacy versioned/query store",
                "review authority, cost, canonical-view, and host-composition behavior before enabling a replacement served contact read",
                "rerun local and installation-bound contact/read evidence after that implementation",
            ],
        ),
        gate_chirho(
            "installation-production-evidence-chirho",
            "not-established-chirho",
            true,
            "this source distribution contains no installation-specific production evidence or inherited operator risk acceptance",
            &[
                "bind tested source and executable bytes to the process actually serving requests",
                "verify restore, signing and private-key custody, privacy, authority, monitoring, and failure recovery for the selected installation",
                "obtain explicit authorization and independent evidence before enabling providers, money movement, public signup, public webhooks, or real-user delivery",
            ],
        ),
    ]
}

fn external_production_evidence_chirho() -> Vec<LaunchReadinessGateChirho> {
    Vec::new()
}

fn deferred_non_blockers_chirho() -> Vec<LaunchReadinessGateChirho> {
    vec![
        gate_chirho(
            "perffection-migration-chirho",
            "deferred",
            false,
            "first launch candidate is generic contact-to-CRM, not a full perffection.com migration",
            &["not required to clear the first lead-to-CRM/contact production blocker set"],
        ),
        gate_chirho(
            "live-llm-generation-chirho",
            "deferred",
            false,
            "agent-authored fixtures are checked in; no live LLM generation is invoked",
            &["not required until L.J. explicitly promotes live generation into the authoring workflow"],
        ),
        gate_chirho(
            "media-provider-integrations-chirho",
            "deferred",
            false,
            "media provider effects remain deterministic stubs until demand-pulled",
            &["not required unless the first hosted app chooses a media/provider-dependent workflow"],
        ),
    ]
}

fn gate_chirho(
    name_chirho: &str,
    status_chirho: &str,
    required_for_production_chirho: bool,
    evidence_chirho: &str,
    required_evidence_chirho: &[&str],
) -> LaunchReadinessGateChirho {
    LaunchReadinessGateChirho {
        schema_chirho: LAUNCH_READINESS_GATE_SCHEMA_CHIRHO,
        name_chirho: name_chirho.to_string(),
        status_chirho: status_chirho.to_string(),
        required_for_production_chirho,
        evidence_chirho: evidence_chirho.to_string(),
        required_evidence_chirho: required_evidence_chirho
            .iter()
            .map(|entry_chirho| entry_chirho.to_string())
            .collect(),
    }
}

#[cfg(test)]
mod tests_chirho;
