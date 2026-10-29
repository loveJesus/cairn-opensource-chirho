// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Proves a checked-in agent-authored app backend can be reviewed, promoted, served, and rolled back.

use anyhow::{bail, Context, Result};
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{
    agent_report_chirho, app_chirho, app_source_manifest_chirho, cas_chirho, dag_module_chirho,
    effect_chirho, identity_chirho, operator_evidence_chirho, refs_chirho, review_chirho,
};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::cas_absence_evidence_chirho::raw_body_absent_from_public_cas_chirho;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const AGENT_AUTHORED_BACKEND_SMOKE_REPORT_SCHEMA_CHIRHO: &str =
    "agent-authored-backend-smoke-report-v2-chirho";
const AGENT_AUTHORED_BACKEND_WIRE_EVIDENCE_SCHEMA_CHIRHO: &str =
    "agent-authored-backend-wire-evidence-v1-chirho";
const AGENT_BACKEND_APP_CHIRHO: &str = "agent-demo";
const AGENT_UNDECLARED_EFFECT_APP_CHIRHO: &str = "agent-demo-undeclared";
const AGENT_PRODUCER_CHIRHO: &str = "agent/codex-demo-chirho";
const AGENT_GENERATION_CHIRHO: &str = "checked-in-agent-authored-demo-chirho";

#[derive(Clone, Debug, Serialize)]
pub struct AgentAuthoredBackendSmokeReportChirho {
    pub schema_chirho: &'static str,
    pub manifest_source_chirho: String,
    pub manifest_hash_chirho: HashChirho,
    pub overcap_manifest_source_chirho: String,
    pub overcap_manifest_hash_chirho: HashChirho,
    pub undeclared_effect_manifest_source_chirho: String,
    pub undeclared_effect_manifest_hash_chirho: HashChirho,
    pub brief_source_chirho: String,
    pub brief_hash_chirho: HashChirho,
    pub root_scope_chirho: String,
    pub app_chirho: String,
    pub owner_chirho: String,
    pub producer_chirho: String,
    pub generation_chirho: String,
    pub module_metadata_chirho: BTreeMap<String, String>,
    pub candidate_chirho: app_source_manifest_chirho::AppSourceCandidateReportChirho,
    pub review_diff_chirho: review_chirho::ReviewSurfaceDiffChirho,
    pub overcap_candidate_chirho: app_source_manifest_chirho::AppSourceCandidateReportChirho,
    pub overcap_review_diff_chirho: review_chirho::ReviewSurfaceDiffChirho,
    pub overcap_promotion_rejected_chirho: bool,
    pub overcap_app_ref_absent_chirho: bool,
    pub undeclared_effect_candidate_chirho:
        app_source_manifest_chirho::AppSourceCandidateReportChirho,
    pub undeclared_effect_review_diff_chirho: review_chirho::ReviewSurfaceDiffChirho,
    pub undeclared_effect_promotion_chirho: review_chirho::ReviewRecordChirho,
    pub agent_report_seq_chirho: u64,
    pub agent_report_chirho: HashChirho,
    pub agent_reports_verified_chirho: usize,
    pub promotion_chirho: review_chirho::ReviewRecordChirho,
    pub review_records_verified_chirho: usize,
    pub input_policy_chirho: String,
    pub server_chirho: String,
    pub missing_policy_chirho: AgentAuthoredBackendWireEvidenceChirho,
    pub undeclared_effect_chirho: AgentAuthoredBackendWireEvidenceChirho,
    pub undeclared_effect_runtime_blocked_chirho: bool,
    pub serve_chirho: AgentAuthoredBackendWireEvidenceChirho,
    pub rollback_chirho: AgentAuthoredBackendWireEvidenceChirho,
    pub missing_policy_raw_body_absent_from_cas_chirho: bool,
    pub persistent_effect_records_chirho: usize,
    pub volatile_effect_records_chirho: usize,
    pub app_ref_removed_after_rollback_chirho: bool,
    pub undeclared_effect_app_ref_removed_after_rollback_chirho: bool,
    pub honest_live_llm_used_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentAuthoredBackendWireEvidenceChirho {
    pub schema_chirho: &'static str,
    pub method_chirho: String,
    pub path_chirho: String,
    pub status_chirho: u16,
    pub body_bytes_chirho: usize,
    pub body_chirho: HashChirho,
    pub contains_expected_chirho: bool,
}

#[derive(Clone, Debug)]
struct HttpSmokeResponseChirho {
    status_chirho: u16,
    body_chirho: Vec<u8>,
}

pub fn default_agent_authored_backend_manifest_path_chirho() -> PathBuf {
    crate::workspace_root_for_operator_smoke_chirho()
        .join("examples-chirho")
        .join("agent-authored-backend-source-manifest-chirho.example.json")
}

pub fn default_agent_authored_backend_brief_path_chirho() -> PathBuf {
    crate::workspace_root_for_operator_smoke_chirho()
        .join("examples-chirho")
        .join("agent-authored-backend-brief-chirho.md")
}

pub fn default_agent_authored_backend_overcap_manifest_path_chirho() -> PathBuf {
    crate::workspace_root_for_operator_smoke_chirho()
        .join("examples-chirho")
        .join("agent-authored-backend-overcap-source-manifest-chirho.example.json")
}

pub fn default_agent_authored_backend_undeclared_effect_manifest_path_chirho() -> PathBuf {
    crate::workspace_root_for_operator_smoke_chirho()
        .join("examples-chirho")
        .join("agent-authored-backend-undeclared-effect-source-manifest-chirho.example.json")
}

pub fn run_agent_authored_backend_smoke_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
    overcap_manifest_path_chirho: &Path,
    undeclared_effect_manifest_path_chirho: &Path,
    brief_path_chirho: &Path,
) -> Result<AgentAuthoredBackendSmokeReportChirho> {
    let manifest_bytes_chirho = std::fs::read(manifest_path_chirho)
        .with_context(|| format!("read {}", manifest_path_chirho.display()))?;
    let overcap_manifest_bytes_chirho = std::fs::read(overcap_manifest_path_chirho)
        .with_context(|| format!("read {}", overcap_manifest_path_chirho.display()))?;
    let undeclared_effect_manifest_bytes_chirho =
        std::fs::read(undeclared_effect_manifest_path_chirho).with_context(|| {
            format!("read {}", undeclared_effect_manifest_path_chirho.display())
        })?;
    let brief_bytes_chirho = std::fs::read(brief_path_chirho)
        .with_context(|| format!("read {}", brief_path_chirho.display()))?;
    let manifest_hash_chirho = cas_chirho::add_chirho(root_chirho, &manifest_bytes_chirho)?;
    let overcap_manifest_hash_chirho =
        cas_chirho::add_chirho(root_chirho, &overcap_manifest_bytes_chirho)?;
    let undeclared_effect_manifest_hash_chirho =
        cas_chirho::add_chirho(root_chirho, &undeclared_effect_manifest_bytes_chirho)?;
    let brief_hash_chirho = cas_chirho::add_chirho(root_chirho, &brief_bytes_chirho)?;
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )?
    .principal_chirho;

    let candidate_chirho =
        app_source_manifest_chirho::build_app_source_candidate_from_path_for_owner_chirho(
            root_chirho,
            manifest_path_chirho,
            &owner_chirho,
        )?;
    if candidate_chirho.app_chirho != AGENT_BACKEND_APP_CHIRHO {
        bail!("agent-authored backend manifest app changed");
    }
    let module_hash_chirho = candidate_chirho
        .modules_chirho
        .first()
        .ok_or_else(|| anyhow::anyhow!("agent-authored candidate has no module"))?
        .module_chirho
        .clone();
    let module_chirho =
        dag_module_chirho::validate_stored_dag_module_chirho(root_chirho, &module_hash_chirho)?;
    let module_metadata_chirho = module_chirho.metadata_chirho.clone();
    if module_metadata_chirho
        .get("producer_chirho")
        .map(String::as_str)
        != Some(AGENT_PRODUCER_CHIRHO)
        || module_metadata_chirho
            .get("generation_chirho")
            .map(String::as_str)
            != Some(AGENT_GENERATION_CHIRHO)
        || module_metadata_chirho
            .get("brief_chirho")
            .map(String::as_str)
            != Some("agent-authored-backend-brief-chirho.md")
    {
        bail!("agent-authored backend module metadata did not bind producer and brief");
    }

    let overcap_candidate_chirho =
        app_source_manifest_chirho::build_app_source_candidate_from_path_for_owner_chirho(
            root_chirho,
            overcap_manifest_path_chirho,
            &owner_chirho,
        )?;
    let undeclared_effect_candidate_chirho =
        app_source_manifest_chirho::build_app_source_candidate_from_path_for_owner_chirho(
            root_chirho,
            undeclared_effect_manifest_path_chirho,
            &owner_chirho,
        )?;
    if undeclared_effect_candidate_chirho.app_chirho != AGENT_UNDECLARED_EFFECT_APP_CHIRHO {
        bail!("undeclared-effect backend manifest app changed");
    }

    agent_report_chirho::grant_agent_report_budget_chirho(
        root_chirho,
        agent_report_chirho::AgentReportBudgetGrantInputChirho {
            agent_principal_chirho: AGENT_PRODUCER_CHIRHO.to_string(),
            granted_by_chirho: owner_chirho.clone(),
            amount_token_chirho: 20,
            reason_chirho: "Agent-authored backend smoke report budget".to_string(),
        },
    )?;
    let agent_record_chirho = agent_report_chirho::emit_agent_report_chirho(
        root_chirho,
        agent_report_chirho::AgentReportInputChirho {
            producer_principal_chirho: AGENT_PRODUCER_CHIRHO.to_string(),
            category_chirho: agent_report_chirho::AgentReportCategoryChirho::InformationalChirho,
            priority_chirho: agent_report_chirho::AgentReportPriorityChirho::NormalChirho,
            happened_chirho: "Agent authored a pure backend source manifest candidate".to_string(),
            affected_chirho: "The local agent-demo app candidate DAG and module metadata"
                .to_string(),
            why_matters_chirho: "Operators can review declared surface before promotion"
                .to_string(),
            evidence_refs_chirho: vec![
                agent_report_chirho::AgentReportEvidenceRefChirho {
                    kind_chirho: agent_report_chirho::AgentReportEvidenceKindChirho::ObjectChirho,
                    ref_chirho: manifest_hash_chirho.0.clone(),
                },
                agent_report_chirho::AgentReportEvidenceRefChirho {
                    kind_chirho: agent_report_chirho::AgentReportEvidenceKindChirho::ObjectChirho,
                    ref_chirho: overcap_manifest_hash_chirho.0.clone(),
                },
                agent_report_chirho::AgentReportEvidenceRefChirho {
                    kind_chirho: agent_report_chirho::AgentReportEvidenceKindChirho::ObjectChirho,
                    ref_chirho: undeclared_effect_manifest_hash_chirho.0.clone(),
                },
                agent_report_chirho::AgentReportEvidenceRefChirho {
                    kind_chirho: agent_report_chirho::AgentReportEvidenceKindChirho::ObjectChirho,
                    ref_chirho: brief_hash_chirho.0.clone(),
                },
                agent_report_chirho::AgentReportEvidenceRefChirho {
                    kind_chirho: agent_report_chirho::AgentReportEvidenceKindChirho::ObjectChirho,
                    ref_chirho: candidate_chirho.root_dag_chirho.0.clone(),
                },
                agent_report_chirho::AgentReportEvidenceRefChirho {
                    kind_chirho: agent_report_chirho::AgentReportEvidenceKindChirho::ObjectChirho,
                    ref_chirho: undeclared_effect_candidate_chirho.root_dag_chirho.0.clone(),
                },
            ],
            related_run_ids_chirho: Vec::new(),
            related_effect_ids_chirho: Vec::new(),
            requested_action_chirho: None,
        },
    )?;
    let agent_reports_verified_chirho =
        agent_report_chirho::verify_agent_report_records_chirho(root_chirho)?;

    let review_diff_chirho = review_chirho::review_current_app_candidate_chirho(
        root_chirho,
        AGENT_BACKEND_APP_CHIRHO,
        candidate_chirho.root_dag_chirho.clone(),
    )?;
    if review_diff_chirho.live_chirho.is_some()
        || review_diff_chirho.candidate_node_count_chirho != 1
        || !review_diff_chirho.added_capabilities_chirho.is_empty()
        || review_diff_chirho.candidate_cost_token_chirho != 0
    {
        bail!("agent-authored candidate review surface was not pure and capability-free");
    }

    let overcap_review_diff_chirho = review_chirho::review_current_app_candidate_chirho(
        root_chirho,
        &overcap_candidate_chirho.app_chirho,
        overcap_candidate_chirho.root_dag_chirho.clone(),
    )?;
    if !overcap_review_diff_chirho
        .added_capabilities_chirho
        .iter()
        .any(|cap_chirho| cap_chirho.starts_with("WriteStoreChirho("))
    {
        bail!("over-capability agent manifest was not surfaced by review_diff");
    }
    let overcap_promotion_error_chirho = review_chirho::promote_candidate_chirho(
        root_chirho,
        &overcap_candidate_chirho.app_chirho,
        &owner_chirho,
        overcap_candidate_chirho.root_dag_chirho.clone(),
        false,
        false,
    )
    .err()
    .map(|error_chirho| error_chirho.to_string())
    .unwrap_or_default();
    let overcap_promotion_rejected_chirho =
        overcap_promotion_error_chirho.contains("candidate adds capabilities");
    if !overcap_promotion_rejected_chirho {
        bail!("over-capability agent manifest promoted without explicit escalation acceptance");
    }
    let refs_after_overcap_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let overcap_app_ref_absent_chirho = !refs_after_overcap_chirho
        .branches_chirho
        .contains_key("app/agent-demo-overcap");
    if !overcap_app_ref_absent_chirho {
        bail!("over-capability agent manifest moved a live app ref");
    }

    let undeclared_effect_review_diff_chirho = review_chirho::review_current_app_candidate_chirho(
        root_chirho,
        &undeclared_effect_candidate_chirho.app_chirho,
        undeclared_effect_candidate_chirho.root_dag_chirho.clone(),
    )?;
    if undeclared_effect_review_diff_chirho.live_chirho.is_some()
        || undeclared_effect_review_diff_chirho.candidate_node_count_chirho != 1
        || !undeclared_effect_review_diff_chirho
            .added_capabilities_chirho
            .is_empty()
        || undeclared_effect_review_diff_chirho.candidate_cost_token_chirho != 0
    {
        bail!("undeclared-effect review was not capability-free before runtime confinement proof");
    }
    let undeclared_effect_promotion_chirho = review_chirho::promote_candidate_chirho(
        root_chirho,
        &undeclared_effect_candidate_chirho.app_chirho,
        &owner_chirho,
        undeclared_effect_candidate_chirho.root_dag_chirho.clone(),
        false,
        false,
    )?;

    let promotion_chirho = review_chirho::promote_candidate_chirho(
        root_chirho,
        AGENT_BACKEND_APP_CHIRHO,
        &owner_chirho,
        candidate_chirho.root_dag_chirho.clone(),
        false,
        false,
    )?;
    let review_records_verified_chirho = review_chirho::verify_review_records_chirho(root_chirho)?;

    let safe_body_chirho = b"build safely";
    let (
        missing_policy_chirho,
        undeclared_effect_chirho,
        serve_chirho,
        rollback_chirho,
        server_chirho,
        missing_policy_raw_body_absent_from_cas_chirho,
    ) = run_agent_backend_http_smoke_chirho(root_chirho, &owner_chirho, safe_body_chirho)?;
    if !missing_policy_raw_body_absent_from_cas_chirho {
        bail!("agent-authored backend raw body entered CAS before signed input policy");
    }
    let undeclared_effect_runtime_blocked_chirho = undeclared_effect_chirho.status_chirho == 400
        && undeclared_effect_chirho.contains_expected_chirho;
    if !undeclared_effect_runtime_blocked_chirho {
        bail!("undeclared-effect backend was not blocked by runtime confinement");
    }
    let persistent_effect_records_chirho = persistent_effect_record_count_chirho(root_chirho)?;
    let volatile_effect_records_chirho =
        effect_chirho::load_volatile_effect_records_chirho(root_chirho)?.len();
    if persistent_effect_records_chirho != 0 || volatile_effect_records_chirho != 0 {
        bail!("pure agent-authored backend produced effect records");
    }
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let app_ref_removed_after_rollback_chirho =
        !refs_chirho.branches_chirho.contains_key("app/agent-demo");
    let undeclared_effect_app_ref_removed_after_rollback_chirho = !refs_chirho
        .branches_chirho
        .contains_key("app/agent-demo-undeclared");
    if !app_ref_removed_after_rollback_chirho {
        bail!("agent-authored backend app ref still present after rollback");
    }
    if !undeclared_effect_app_ref_removed_after_rollback_chirho {
        bail!("undeclared-effect backend app ref still present after rollback");
    }

    Ok(AgentAuthoredBackendSmokeReportChirho {
        schema_chirho: AGENT_AUTHORED_BACKEND_SMOKE_REPORT_SCHEMA_CHIRHO,
        manifest_source_chirho: operator_evidence_chirho::redacted_manifest_source_chirho(
            manifest_path_chirho,
        ),
        manifest_hash_chirho,
        overcap_manifest_source_chirho:
            operator_evidence_chirho::redacted_overcap_manifest_source_chirho(
                overcap_manifest_path_chirho,
            ),
        overcap_manifest_hash_chirho,
        undeclared_effect_manifest_source_chirho:
            operator_evidence_chirho::redacted_undeclared_effect_manifest_source_chirho(
                undeclared_effect_manifest_path_chirho,
            ),
        undeclared_effect_manifest_hash_chirho,
        brief_source_chirho: operator_evidence_chirho::redacted_brief_source_chirho(
            brief_path_chirho,
        ),
        brief_hash_chirho,
        root_scope_chirho: operator_evidence_chirho::redacted_local_root_scope_chirho(root_chirho),
        app_chirho: AGENT_BACKEND_APP_CHIRHO.to_string(),
        owner_chirho,
        producer_chirho: AGENT_PRODUCER_CHIRHO.to_string(),
        generation_chirho: AGENT_GENERATION_CHIRHO.to_string(),
        module_metadata_chirho,
        candidate_chirho,
        review_diff_chirho,
        overcap_candidate_chirho,
        overcap_review_diff_chirho,
        overcap_promotion_rejected_chirho,
        overcap_app_ref_absent_chirho,
        undeclared_effect_candidate_chirho,
        undeclared_effect_review_diff_chirho,
        undeclared_effect_promotion_chirho,
        agent_report_seq_chirho: agent_record_chirho.seq_chirho,
        agent_report_chirho: agent_record_chirho.report_chirho,
        agent_reports_verified_chirho,
        promotion_chirho,
        review_records_verified_chirho,
        input_policy_chirho: "plain-chirho".to_string(),
        server_chirho,
        missing_policy_chirho,
        undeclared_effect_chirho,
        undeclared_effect_runtime_blocked_chirho,
        serve_chirho,
        rollback_chirho,
        missing_policy_raw_body_absent_from_cas_chirho,
        persistent_effect_records_chirho,
        volatile_effect_records_chirho,
        app_ref_removed_after_rollback_chirho,
        undeclared_effect_app_ref_removed_after_rollback_chirho,
        honest_live_llm_used_chirho: false,
    })
}

fn run_agent_backend_http_smoke_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    safe_body_chirho: &[u8],
) -> Result<(
    AgentAuthoredBackendWireEvidenceChirho,
    AgentAuthoredBackendWireEvidenceChirho,
    AgentAuthoredBackendWireEvidenceChirho,
    AgentAuthoredBackendWireEvidenceChirho,
    String,
    bool,
)> {
    let port_chirho = unused_local_port_chirho()?;
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let server_chirho = format!("http://{addr_chirho}");
    let root_for_server_chirho = root_chirho.to_path_buf();
    let runtime_chirho = tokio::runtime::Runtime::new()?;
    runtime_chirho.block_on(async {
        let server_task_chirho = tokio::spawn(async move {
            cairn_serve_runtime_chirho::serve_quiet_chirho(&root_for_server_chirho, port_chirho, 8, String::new())
                .await
        });
        wait_for_serve_health_chirho(&addr_chirho)?;

        let missing_policy_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/agent-demo",
            safe_body_chirho,
        )?;
        let missing_policy_text_chirho = http_body_text_chirho(&missing_policy_response_chirho);
        // The body names only the input gate's fixed identity; the verifier's own answer attributes
        // the cause, so the smoke asks the verifier directly rather than reading detail from the body.
        let missing_policy_cause_chirho =
            app_chirho::app_input_mode_chirho(root_chirho, "agent-demo", None, owner_chirho)
                .err()
                .map(|error_chirho| format!("{error_chirho:#}"))
                .unwrap_or_default();
        if missing_policy_response_chirho.status_chirho != 400
            || !fixed_identity_body_chirho(&missing_policy_text_chirho, APP_INPUT_REFUSED_CHIRHO)
            || !missing_policy_cause_chirho.contains("needs a signed input policy")
        {
            bail!("agent-authored backend did not fail closed before signed input policy");
        }
        let missing_policy_chirho = wire_evidence_chirho(
            "POST",
            "/app-chirho/agent-demo",
            &missing_policy_response_chirho,
            APP_INPUT_REFUSED_CHIRHO,
        );
        let safe_body_hash_chirho = cas_chirho::hash_chirho(safe_body_chirho);
        // ABSENT means NotFound and nothing else. The `is_err()` this replaced also swallowed
        // UNREADABLE — a mode-000 object file or shard directory — and recorded "the body never
        // entered CAS" over a body that may be sitting there intact. This bool ships in the report.
        let missing_policy_raw_body_absent_from_cas_chirho = raw_body_absent_from_public_cas_chirho(
            root_chirho,
            &safe_body_hash_chirho,
            "agent-authored backend pre-policy body",
        )?;

        app_chirho::set_app_input_policy_chirho(
            root_chirho,
            AGENT_BACKEND_APP_CHIRHO,
            None,
            owner_chirho,
            app_chirho::AppInputModeChirho::PlainChirho,
        )?;
        app_chirho::set_app_input_policy_chirho(
            root_chirho,
            AGENT_UNDECLARED_EFFECT_APP_CHIRHO,
            None,
            owner_chirho,
            app_chirho::AppInputModeChirho::PlainChirho,
        )?;
        let undeclared_effect_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/agent-demo-undeclared",
            b"attempt host write",
        )?;
        let undeclared_effect_text_chirho =
            http_body_text_chirho(&undeclared_effect_response_chirho);
        // The exported constant is the body's first line, the refusal IDENTITY, and a knowledge line
        // must follow it (the trusted observation's classification). Expectation and subject could
        // move in lockstep if the constant ever widened to carry detail, so the needle clause
        // witnesses NON-LEAK independently of the constant. Neither can carry the other.
        if undeclared_effect_response_chirho.status_chirho != 400
            || !undeclared_effect_text_chirho
                .starts_with(cairn_serve_runtime_chirho::APP_EXECUTION_REFUSAL_BODY_CHIRHO)
            || !undeclared_effect_text_chirho.contains("\nknowledge: ")
            || undeclared_effect_text_chirho.contains("expected 1 imports")
        {
            bail!(
                "undeclared-effect backend was not blocked at the runtime import boundary: status={} body={}",
                undeclared_effect_response_chirho.status_chirho,
                undeclared_effect_text_chirho
            );
        }
        let undeclared_effect_evidence_chirho = wire_evidence_chirho(
            "POST",
            "/app-chirho/agent-demo-undeclared",
            &undeclared_effect_response_chirho,
            cairn_serve_runtime_chirho::APP_EXECUTION_REFUSAL_BODY_CHIRHO,
        );

        let serve_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/agent-demo",
            safe_body_chirho,
        )?;
        let serve_text_chirho = http_body_text_chirho(&serve_response_chirho);
        if serve_response_chirho.status_chirho != 200 || serve_text_chirho != "BUILD SAFELY" {
            bail!("agent-authored backend did not serve the reviewed pure transform");
        }
        let serve_evidence_chirho = wire_evidence_chirho(
            "POST",
            "/app-chirho/agent-demo",
            &serve_response_chirho,
            "BUILD SAFELY",
        );

        app_chirho::undeploy_app_chirho(root_chirho, AGENT_BACKEND_APP_CHIRHO, owner_chirho)?;
        app_chirho::undeploy_app_chirho(
            root_chirho,
            AGENT_UNDECLARED_EFFECT_APP_CHIRHO,
            owner_chirho,
        )?;
        let rollback_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/agent-demo",
            safe_body_chirho,
        )?;
        // An unknown app answers its fixed identity and never echoes the requested name.
        if rollback_response_chirho.status_chirho != 404
            || !fixed_identity_body_chirho(
                &http_body_text_chirho(&rollback_response_chirho),
                APP_NOT_FOUND_CHIRHO,
            )
        {
            bail!("agent-authored backend rollback did not remove the served app ref");
        }
        let rollback_evidence_chirho = wire_evidence_chirho(
            "POST",
            "/app-chirho/agent-demo",
            &rollback_response_chirho,
            APP_NOT_FOUND_CHIRHO,
        );

        server_task_chirho.abort();
        Ok((
            missing_policy_chirho,
            undeclared_effect_evidence_chirho,
            serve_evidence_chirho,
            rollback_evidence_chirho,
            server_chirho,
            missing_policy_raw_body_absent_from_cas_chirho,
        ))
    })
}

/// The input gate's and app selection's fixed public identities (the serve runtime's public error answers).
const APP_INPUT_REFUSED_CHIRHO: &str = "app-input-refused-chirho";
const APP_NOT_FOUND_CHIRHO: &str = "app-not-found-chirho";

/// Whether a body is exactly one fixed identity: its plain line, or its two bounded JSON fields when the
/// route declares JSON.
fn fixed_identity_body_chirho(text_chirho: &str, identity_chirho: &str) -> bool {
    text_chirho == format!("error: {identity_chirho}\n")
        || serde_json::from_str::<serde_json::Value>(text_chirho).ok()
            == Some(serde_json::json!({ "ok_chirho": false, "error_chirho": identity_chirho }))
}

fn wire_evidence_chirho(
    method_chirho: &str,
    path_chirho: &str,
    response_chirho: &HttpSmokeResponseChirho,
    expected_chirho: &str,
) -> AgentAuthoredBackendWireEvidenceChirho {
    AgentAuthoredBackendWireEvidenceChirho {
        schema_chirho: AGENT_AUTHORED_BACKEND_WIRE_EVIDENCE_SCHEMA_CHIRHO,
        method_chirho: method_chirho.to_string(),
        path_chirho: path_chirho.to_string(),
        status_chirho: response_chirho.status_chirho,
        body_bytes_chirho: response_chirho.body_chirho.len(),
        body_chirho: cas_chirho::hash_chirho(&response_chirho.body_chirho),
        contains_expected_chirho: http_body_text_chirho(response_chirho).contains(expected_chirho),
    }
}

fn try_http_get_for_smoke_chirho(
    addr_chirho: &str,
    path_chirho: &str,
) -> Result<HttpSmokeResponseChirho> {
    try_http_request_for_smoke_chirho(addr_chirho, "GET", path_chirho, b"")
}

fn try_http_request_for_smoke_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    body_chirho: &[u8],
) -> Result<HttpSmokeResponseChirho> {
    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho)?;
    stream_chirho.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request_chirho = format!(
        "{method_chirho} {path_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\n"
    );
    if !body_chirho.is_empty() {
        request_chirho.push_str("content-type: text/plain\r\n");
        request_chirho.push_str(&format!("content-length: {}\r\n", body_chirho.len()));
    }
    request_chirho.push_str("\r\n");
    stream_chirho.write_all(request_chirho.as_bytes())?;
    stream_chirho.write_all(body_chirho)?;
    let mut response_chirho = Vec::new();
    stream_chirho.read_to_end(&mut response_chirho)?;
    let header_end_chirho = response_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("missing HTTP headers"))?;
    let header_text_chirho = String::from_utf8_lossy(&response_chirho[..header_end_chirho]);
    let status_chirho = header_text_chirho
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing HTTP status line"))?
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("missing HTTP status code"))?
        .parse::<u16>()?;
    Ok(HttpSmokeResponseChirho {
        status_chirho,
        body_chirho: response_chirho[header_end_chirho + 4..].to_vec(),
    })
}

fn http_body_text_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    String::from_utf8_lossy(&response_chirho.body_chirho).to_string()
}

fn wait_for_serve_health_chirho(addr_chirho: &str) -> Result<()> {
    for _attempt_chirho in 0..100 {
        if let Ok(response_chirho) = try_http_get_for_smoke_chirho(addr_chirho, "/healthz-chirho") {
            if response_chirho.status_chirho == 200 {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    bail!("serve_chirho did not become healthy at {addr_chirho}");
}

fn unused_local_port_chirho() -> Result<u16> {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener_chirho.local_addr()?.port())
}

fn persistent_effect_record_count_chirho(root_chirho: &Path) -> Result<usize> {
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    if !effects_dir_chirho.exists() {
        return Ok(0);
    }
    Ok(std::fs::read_dir(effects_dir_chirho)?.count())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-{label_chirho}-{nanos_chirho}-{n_chirho}"))
    }

    #[test]
    fn agent_authored_backend_smoke_emits_reviewed_served_evidence_chirho() {
        let root_chirho = temp_root_chirho("agent-authored-backend-smoke");
        let manifest_path_chirho = default_agent_authored_backend_manifest_path_chirho();
        let overcap_manifest_path_chirho =
            default_agent_authored_backend_overcap_manifest_path_chirho();
        let undeclared_effect_manifest_path_chirho =
            default_agent_authored_backend_undeclared_effect_manifest_path_chirho();
        let brief_path_chirho = default_agent_authored_backend_brief_path_chirho();
        let report_chirho = run_agent_authored_backend_smoke_chirho(
            &root_chirho,
            &manifest_path_chirho,
            &overcap_manifest_path_chirho,
            &undeclared_effect_manifest_path_chirho,
            &brief_path_chirho,
        )
        .unwrap();
        assert_eq!(
            report_chirho.schema_chirho,
            AGENT_AUTHORED_BACKEND_SMOKE_REPORT_SCHEMA_CHIRHO
        );
        assert_eq!(report_chirho.app_chirho, AGENT_BACKEND_APP_CHIRHO);
        assert_eq!(report_chirho.producer_chirho, AGENT_PRODUCER_CHIRHO);
        assert_eq!(report_chirho.generation_chirho, AGENT_GENERATION_CHIRHO);
        assert_eq!(
            report_chirho.manifest_hash_chirho,
            cas_chirho::hash_chirho(&std::fs::read(&manifest_path_chirho).unwrap())
        );
        assert_eq!(
            report_chirho.overcap_manifest_hash_chirho,
            cas_chirho::hash_chirho(&std::fs::read(&overcap_manifest_path_chirho).unwrap())
        );
        assert_eq!(
            report_chirho.undeclared_effect_manifest_hash_chirho,
            cas_chirho::hash_chirho(
                &std::fs::read(&undeclared_effect_manifest_path_chirho).unwrap()
            )
        );
        assert_eq!(
            report_chirho.brief_hash_chirho,
            cas_chirho::hash_chirho(&std::fs::read(&brief_path_chirho).unwrap())
        );
        assert_eq!(
            report_chirho.manifest_source_chirho,
            operator_evidence_chirho::MANIFEST_SOURCE_REDACTED_CHIRHO
        );
        assert_eq!(
            report_chirho.overcap_manifest_source_chirho,
            operator_evidence_chirho::OVERCAP_MANIFEST_SOURCE_REDACTED_CHIRHO
        );
        assert_eq!(
            report_chirho.undeclared_effect_manifest_source_chirho,
            operator_evidence_chirho::UNDECLARED_EFFECT_MANIFEST_SOURCE_REDACTED_CHIRHO
        );
        assert_eq!(
            report_chirho.brief_source_chirho,
            operator_evidence_chirho::BRIEF_SOURCE_REDACTED_CHIRHO
        );
        assert_eq!(
            report_chirho.root_scope_chirho,
            operator_evidence_chirho::LOCAL_ROOT_REDACTED_CHIRHO
        );
        assert_eq!(
            report_chirho.candidate_chirho.schema_chirho,
            app_source_manifest_chirho::APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO
        );
        assert_eq!(report_chirho.candidate_chirho.nodes_chirho.len(), 1);
        assert_eq!(report_chirho.review_diff_chirho.live_chirho, None);
        assert!(report_chirho
            .review_diff_chirho
            .added_capabilities_chirho
            .is_empty());
        assert_eq!(
            report_chirho.review_diff_chirho.candidate_cost_token_chirho,
            0
        );
        assert!(report_chirho
            .overcap_review_diff_chirho
            .added_capabilities_chirho
            .iter()
            .any(|cap_chirho| cap_chirho.starts_with("WriteStoreChirho(")));
        assert!(report_chirho.overcap_promotion_rejected_chirho);
        assert!(report_chirho.overcap_app_ref_absent_chirho);
        assert!(report_chirho
            .undeclared_effect_review_diff_chirho
            .added_capabilities_chirho
            .is_empty());
        assert_eq!(
            report_chirho
                .undeclared_effect_review_diff_chirho
                .candidate_cost_token_chirho,
            0
        );
        assert_eq!(report_chirho.undeclared_effect_chirho.status_chirho, 400);
        assert!(
            report_chirho
                .undeclared_effect_chirho
                .contains_expected_chirho
        );
        assert!(report_chirho.undeclared_effect_runtime_blocked_chirho);
        assert_eq!(report_chirho.agent_reports_verified_chirho, 1);
        assert_eq!(report_chirho.review_records_verified_chirho, 2);
        assert_eq!(report_chirho.missing_policy_chirho.status_chirho, 400);
        assert!(report_chirho.missing_policy_chirho.contains_expected_chirho);
        assert!(report_chirho.missing_policy_raw_body_absent_from_cas_chirho);
        assert_eq!(report_chirho.serve_chirho.status_chirho, 200);
        assert!(report_chirho.serve_chirho.contains_expected_chirho);
        assert_eq!(report_chirho.rollback_chirho.status_chirho, 404);
        assert!(report_chirho.rollback_chirho.contains_expected_chirho);
        assert_eq!(report_chirho.persistent_effect_records_chirho, 0);
        assert_eq!(report_chirho.volatile_effect_records_chirho, 0);
        assert!(report_chirho.app_ref_removed_after_rollback_chirho);
        assert!(report_chirho.undeclared_effect_app_ref_removed_after_rollback_chirho);
        assert!(!report_chirho.honest_live_llm_used_chirho);
        assert_eq!(
            report_chirho
                .module_metadata_chirho
                .get("producer_chirho")
                .map(String::as_str),
            Some(AGENT_PRODUCER_CHIRHO)
        );
        let json_chirho = serde_json::to_string(&report_chirho).unwrap();
        for hash_chirho in [
            &report_chirho.manifest_hash_chirho,
            &report_chirho.overcap_manifest_hash_chirho,
            &report_chirho.undeclared_effect_manifest_hash_chirho,
            &report_chirho.brief_hash_chirho,
        ] {
            assert!(json_chirho.contains(&hash_chirho.0));
        }
        for label_chirho in [
            operator_evidence_chirho::MANIFEST_SOURCE_REDACTED_CHIRHO,
            operator_evidence_chirho::OVERCAP_MANIFEST_SOURCE_REDACTED_CHIRHO,
            operator_evidence_chirho::UNDECLARED_EFFECT_MANIFEST_SOURCE_REDACTED_CHIRHO,
            operator_evidence_chirho::BRIEF_SOURCE_REDACTED_CHIRHO,
            operator_evidence_chirho::LOCAL_ROOT_REDACTED_CHIRHO,
        ] {
            assert!(json_chirho.contains(label_chirho));
        }
        for forbidden_field_chirho in [
            "\"manifest_path_chirho\"",
            "\"overcap_manifest_path_chirho\"",
            "\"undeclared_effect_manifest_path_chirho\"",
            "\"brief_path_chirho\"",
            "\"root_chirho\"",
        ] {
            assert!(!json_chirho.contains(forbidden_field_chirho));
        }
        for forbidden_path_chirho in [
            root_chirho.display().to_string(),
            manifest_path_chirho.display().to_string(),
            overcap_manifest_path_chirho.display().to_string(),
            undeclared_effect_manifest_path_chirho.display().to_string(),
            brief_path_chirho.display().to_string(),
        ] {
            assert!(!json_chirho.contains(&forbidden_path_chirho));
        }
        assert!(!json_chirho.contains("live LLM generated"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}
