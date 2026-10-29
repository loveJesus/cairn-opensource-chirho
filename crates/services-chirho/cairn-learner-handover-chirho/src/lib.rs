// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! SP14.3 learner handover drill: fixture-only evidence over apps, signed effects, refs, and query projection.

use anyhow::{bail, Context, Result};
use cairn_chirho::model_chirho::{EffectChirho, HashChirho};
use cairn_chirho::{
    app_chirho, app_source_manifest_chirho, effect_chirho, operator_evidence_chirho, query_chirho,
    refs_chirho, verify_chirho, writer_head_chirho,
};
use cairn_operator_smoke_chirho::contact_example_smoke_chirho;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const LEARNER_HANDOVER_DRILL_REPORT_SCHEMA_CHIRHO: &str =
    "learner-handover-drill-report-v2-chirho";
const HANDOVER_FIXTURE_PREFIX_CHIRHO: &str = "cairn-learner-handover-fixture";
const HANDOVER_STEP_TOTAL_CHIRHO: usize = 5;

#[derive(Clone, Debug, Serialize)]
pub struct LearnerHandoverDrillReportChirho {
    pub schema_chirho: &'static str,
    pub root_scope_chirho: String,
    pub fixture_source_chirho: String,
    pub steps_run_chirho: usize,
    pub steps_total_chirho: usize,
    pub app_listing_chirho: LearnerHandoverAppListingChirho,
    pub signed_effects_chirho: LearnerHandoverSignedEffectsChirho,
    pub route_rollback_chirho: LearnerHandoverRouteRollbackChirho,
    pub query_projection_chirho: LearnerHandoverQueryProjectionChirho,
    pub existing_write_surfaces_chirho: Vec<String>,
    pub honest_scope_chirho: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LearnerHandoverAppListingChirho {
    pub verified_apps_chirho: usize,
    pub apps_chirho: Vec<LearnerHandoverAppSummaryChirho>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LearnerHandoverAppSummaryChirho {
    pub app_chirho: String,
    pub active_chirho: bool,
    pub owner_present_chirho: bool,
    pub route_count_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LearnerHandoverSignedEffectsChirho {
    pub persistent_effects_verified_chirho: usize,
    pub volatile_effects_verified_chirho: usize,
    pub volatile_effect_objects_verified_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LearnerHandoverRouteRollbackChirho {
    pub branch_chirho: String,
    pub app_chirho: String,
    pub route_chirho: String,
    pub original_dag_chirho: HashChirho,
    pub temporary_dag_chirho: HashChirho,
    pub restored_dag_chirho: HashChirho,
    pub reflog_entries_after_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LearnerHandoverQueryProjectionChirho {
    pub rows_projected_chirho: usize,
    pub contact_rows_after_rebuild_chirho: usize,
    pub served_read_posture_chirho: String,
    pub operator_read_posture_chirho: String,
}

pub fn default_learner_handover_fixture_root_chirho() -> PathBuf {
    unique_temp_root_chirho(HANDOVER_FIXTURE_PREFIX_CHIRHO)
}

pub fn run_learner_handover_drill_chirho(
    requested_root_chirho: Option<&Path>,
    allow_non_fixture_root_chirho: bool,
) -> Result<LearnerHandoverDrillReportChirho> {
    let root_holder_chirho = LearnerHandoverRootChirho::prepare_chirho(
        requested_root_chirho,
        allow_non_fixture_root_chirho,
    )?;
    let fixture_root_chirho = root_holder_chirho.path_chirho.as_path();
    let runtime_root_chirho =
        contact_example_smoke_chirho::contact_example_smoke_runtime_root_chirho(
            fixture_root_chirho,
        )?;
    let root_chirho = runtime_root_chirho.as_path();
    let manifest_chirho =
        contact_example_smoke_chirho::default_contact_example_manifest_path_chirho();
    let smoke_chirho = contact_example_smoke_chirho::run_contact_example_smoke_chirho(
        root_chirho,
        &manifest_chirho,
    )
    .context("run learner handover contact fixture")?;
    if smoke_chirho.schema_chirho
        != contact_example_smoke_chirho::CONTACT_EXAMPLE_SMOKE_REPORT_SCHEMA_CHIRHO
    {
        bail!("contact fixture did not emit the expected schema");
    }

    let apps_chirho = app_chirho::verified_deployed_apps_chirho(root_chirho)?;
    let app_listing_chirho = app_listing_chirho(&apps_chirho);
    let signed_effects_chirho = signed_effect_audit_chirho(root_chirho)?;
    let route_rollback_chirho = route_rollback_drill_chirho(
        root_chirho,
        &smoke_chirho.owner_chirho,
        &smoke_chirho.deploy_chirho,
    )?;
    let rows_projected_chirho = query_chirho::project_chirho(root_chirho)?;
    let contact_rows_after_rebuild_chirho =
        query_chirho::query_prefix_chirho(root_chirho, "contacts-chirho", 50)?.len();

    Ok(LearnerHandoverDrillReportChirho {
        schema_chirho: LEARNER_HANDOVER_DRILL_REPORT_SCHEMA_CHIRHO,
        root_scope_chirho: operator_evidence_chirho::redacted_local_root_scope_chirho(root_chirho),
        fixture_source_chirho: root_holder_chirho.source_chirho.clone(),
        steps_run_chirho: HANDOVER_STEP_TOTAL_CHIRHO,
        steps_total_chirho: HANDOVER_STEP_TOTAL_CHIRHO,
        app_listing_chirho,
        signed_effects_chirho,
        route_rollback_chirho,
        query_projection_chirho: LearnerHandoverQueryProjectionChirho {
            rows_projected_chirho,
            contact_rows_after_rebuild_chirho,
            served_read_posture_chirho:
                contact_example_smoke_chirho::CONTACT_EXAMPLE_SERVED_READ_POSTURE_CHIRHO
                    .to_string(),
            operator_read_posture_chirho:
                contact_example_smoke_chirho::CONTACT_EXAMPLE_OPERATOR_READ_POSTURE_CHIRHO
                    .to_string(),
        },
        existing_write_surfaces_chirho: vec![
            "app-source manifest deploy and signed app/route record seqlogs".to_string(),
            "refs-chirho.json plus reflog-chirho.jsonl route rollback".to_string(),
            "effects-chirho and volatile-effects-chirho.jsonl signed effect evidence".to_string(),
            "versioned-chirho.redb and disposable readmodel-chirho.sqlite query projection".to_string(),
        ],
        honest_scope_chirho: vec![
            "fixture-only local drill; no hosted root, provider, public signup, production money, or user traffic action was performed".to_string(),
            "filesystem paths are redacted; app names, route names, counts, and content hashes are the evidence".to_string(),
            "the current tree keeps contact submit served, refuses the legacy served contact-list read, and uses the direct no-effect query API only for operator evidence".to_string(),
            "the CF7 credits-demo is the ledger-native served-read exemplar; a generic non-money published-projection source remains a separate reviewed primitive".to_string(),
        ],
    })
}

fn app_listing_chirho(
    apps_chirho: &[app_chirho::AppStatusChirho],
) -> LearnerHandoverAppListingChirho {
    LearnerHandoverAppListingChirho {
        verified_apps_chirho: apps_chirho.len(),
        apps_chirho: apps_chirho
            .iter()
            .map(|app_chirho| LearnerHandoverAppSummaryChirho {
                app_chirho: app_chirho.app_chirho.clone(),
                active_chirho: app_chirho.active_chirho,
                owner_present_chirho: app_chirho.owner_principal_chirho.is_some(),
                route_count_chirho: app_chirho.routes_chirho.len(),
            })
            .collect(),
    }
}

fn signed_effect_audit_chirho(root_chirho: &Path) -> Result<LearnerHandoverSignedEffectsChirho> {
    let volatile_report_chirho = verify_chirho::verify_volatile_effect_records_chirho(root_chirho)?;
    Ok(LearnerHandoverSignedEffectsChirho {
        persistent_effects_verified_chirho: load_persistent_effects_chirho(root_chirho)?.len(),
        volatile_effects_verified_chirho: volatile_report_chirho.records_chirho,
        volatile_effect_objects_verified_chirho: volatile_report_chirho.objects_chirho,
    })
}

fn load_persistent_effects_chirho(root_chirho: &Path) -> Result<Vec<EffectChirho>> {
    let dir_chirho = root_chirho.join("effects-chirho");
    if !dir_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    for entry_chirho in std::fs::read_dir(&dir_chirho)? {
        let path_chirho = entry_chirho?.path();
        if path_chirho.is_file() {
            paths_chirho.push(path_chirho);
        }
    }
    paths_chirho.sort();
    let mut effects_chirho = Vec::new();
    for path_chirho in paths_chirho {
        let bytes_chirho =
            std::fs::read(&path_chirho).with_context(|| "read path-redacted persistent effect")?;
        let effect_record_chirho: EffectChirho =
            serde_json::from_slice(&bytes_chirho).context("decode persistent effect")?;
        effect_chirho::verify_effect_chirho(root_chirho, &effect_record_chirho)?;
        effects_chirho.push(effect_record_chirho);
    }
    Ok(effects_chirho)
}

fn route_rollback_drill_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    deploy_chirho: &app_source_manifest_chirho::AppSourceDeployReportChirho,
) -> Result<LearnerHandoverRouteRollbackChirho> {
    let branch_chirho = "app-route/contact/contact-list".to_string();
    let status_chirho = app_chirho::app_status_chirho(root_chirho, "contact")?;
    let original_dag_chirho = status_chirho
        .routes_chirho
        .get("contact-list")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("contact fixture did not deploy contact-list route"))?;
    let original_ref_target_chirho = refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&branch_chirho)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("contact fixture did not create contact-list route ref"))?;
    let temporary_dag_chirho = deploy_chirho
        .modules_chirho
        .iter()
        .map(|module_chirho| module_chirho.dag_chirho.clone())
        .find(|dag_chirho| dag_chirho != &original_dag_chirho)
        .ok_or_else(|| {
            anyhow::anyhow!("contact fixture did not include a distinct temporary DAG")
        })?;
    if original_dag_chirho == temporary_dag_chirho {
        bail!("contact fixture route DAGs are not distinct enough for rollback drill");
    }
    app_chirho::deploy_app_route_chirho(
        root_chirho,
        "contact",
        "contact-list",
        temporary_dag_chirho.clone(),
        owner_chirho,
    )?;
    writer_head_chirho::with_head_commit_chirho(root_chirho, || {
        let current_chirho = refs_chirho::load_refs_chirho(root_chirho)?
            .branches_chirho
            .get(&branch_chirho)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no such branch '{branch_chirho}' to roll back"))?;
        refs_chirho::commit_head_chirho(
            root_chirho,
            &branch_chirho,
            refs_chirho::HeadPreconditionChirho::ExpectedChirho(current_chirho),
            original_ref_target_chirho,
            "rollback",
        )
    })?;
    let restored_chirho = app_chirho::app_status_chirho(root_chirho, "contact")?
        .routes_chirho
        .get("contact-list")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("contact-list route missing after rollback"))?;
    if restored_chirho != original_dag_chirho {
        bail!("contact-list route rollback did not restore the original DAG");
    }
    let reflog_entries_after_chirho = refs_chirho::reflog_chirho(root_chirho)?
        .into_iter()
        .filter(|entry_chirho| entry_chirho.branch_chirho == branch_chirho)
        .count();
    Ok(LearnerHandoverRouteRollbackChirho {
        branch_chirho,
        app_chirho: "contact".to_string(),
        route_chirho: "contact-list".to_string(),
        original_dag_chirho,
        temporary_dag_chirho,
        restored_dag_chirho: restored_chirho,
        reflog_entries_after_chirho,
    })
}

struct LearnerHandoverRootChirho {
    path_chirho: PathBuf,
    source_chirho: String,
    cleanup_chirho: bool,
}

impl LearnerHandoverRootChirho {
    fn prepare_chirho(
        requested_root_chirho: Option<&Path>,
        allow_non_fixture_root_chirho: bool,
    ) -> Result<Self> {
        match requested_root_chirho {
            Some(root_chirho) => {
                ensure_fixture_root_chirho(root_chirho, allow_non_fixture_root_chirho)?;
                std::fs::create_dir_all(root_chirho)
                    .with_context(|| "create learner handover fixture root")?;
                Ok(Self {
                    path_chirho: root_chirho.to_path_buf(),
                    source_chirho: if allow_non_fixture_root_chirho {
                        "operator-overridden-root-chirho".to_string()
                    } else {
                        "provided-fixture-root-chirho".to_string()
                    },
                    cleanup_chirho: false,
                })
            }
            None => {
                let path_chirho = default_learner_handover_fixture_root_chirho();
                std::fs::create_dir_all(&path_chirho)
                    .with_context(|| "create disposable learner handover fixture root")?;
                Ok(Self {
                    path_chirho,
                    source_chirho: "created-disposable-fixture-root-chirho".to_string(),
                    cleanup_chirho: true,
                })
            }
        }
    }
}

impl Drop for LearnerHandoverRootChirho {
    fn drop(&mut self) {
        if self.cleanup_chirho {
            let _ = std::fs::remove_dir_all(&self.path_chirho);
        }
    }
}

fn ensure_fixture_root_chirho(
    root_chirho: &Path,
    allow_non_fixture_root_chirho: bool,
) -> Result<()> {
    if allow_non_fixture_root_chirho {
        return Ok(());
    }
    let candidate_chirho = canonical_candidate_chirho(root_chirho)?;
    let temp_chirho = std::env::temp_dir()
        .canonicalize()
        .context("canonicalize temp dir for learner handover fixture guard")?;
    let name_ok_chirho = candidate_chirho
        .file_name()
        .and_then(|name_chirho| name_chirho.to_str())
        .is_some_and(|name_chirho| name_chirho.starts_with(HANDOVER_FIXTURE_PREFIX_CHIRHO));
    if !candidate_chirho.starts_with(&temp_chirho) || !name_ok_chirho {
        bail!(
            "learner handover drill refuses non-fixture root; use --fixture-root-chirho under temp with prefix {HANDOVER_FIXTURE_PREFIX_CHIRHO} or pass --allow-non-fixture-root-chirho"
        );
    }
    Ok(())
}

fn canonical_candidate_chirho(root_chirho: &Path) -> Result<PathBuf> {
    if root_chirho.exists() {
        return root_chirho
            .canonicalize()
            .with_context(|| "canonicalize learner handover root");
    }
    let parent_chirho = root_chirho
        .parent()
        .ok_or_else(|| anyhow::anyhow!("learner handover root has no parent"))?
        .canonicalize()
        .with_context(|| "canonicalize learner handover root parent")?;
    let name_chirho = root_chirho
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("learner handover root has no file name"))?;
    Ok(parent_chirho.join(name_chirho))
}

fn unique_temp_root_chirho(prefix_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_nanos())
        .unwrap_or(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("{prefix_chirho}-{nanos_chirho}-{n_chirho}"))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn learner_handover_drill_runs_fixture_and_redacts_paths_chirho() {
        let report_chirho = run_learner_handover_drill_chirho(None, false).unwrap();
        assert_eq!(
            report_chirho.schema_chirho,
            LEARNER_HANDOVER_DRILL_REPORT_SCHEMA_CHIRHO
        );
        assert_eq!(
            report_chirho.steps_run_chirho,
            report_chirho.steps_total_chirho
        );
        assert_eq!(report_chirho.app_listing_chirho.verified_apps_chirho, 1);
        assert!(
            report_chirho
                .signed_effects_chirho
                .persistent_effects_verified_chirho
                > 0
        );
        assert_eq!(
            report_chirho
                .query_projection_chirho
                .served_read_posture_chirho,
            contact_example_smoke_chirho::CONTACT_EXAMPLE_SERVED_READ_POSTURE_CHIRHO
        );
        assert_eq!(
            report_chirho
                .query_projection_chirho
                .operator_read_posture_chirho,
            contact_example_smoke_chirho::CONTACT_EXAMPLE_OPERATOR_READ_POSTURE_CHIRHO
        );
        assert_eq!(
            report_chirho.route_rollback_chirho.original_dag_chirho,
            report_chirho.route_rollback_chirho.restored_dag_chirho
        );
        assert_ne!(
            report_chirho.route_rollback_chirho.original_dag_chirho,
            report_chirho.route_rollback_chirho.temporary_dag_chirho
        );
        assert!(
            report_chirho
                .route_rollback_chirho
                .reflog_entries_after_chirho
                >= 3
        );
        assert!(
            report_chirho
                .query_projection_chirho
                .contact_rows_after_rebuild_chirho
                >= 1
        );
        let json_chirho = serde_json::to_string(&report_chirho).unwrap();
        assert!(!json_chirho.contains(std::env::temp_dir().to_string_lossy().as_ref()));
    }

    #[test]
    fn learner_handover_drill_refuses_non_fixture_root_chirho() {
        let root_chirho = unique_temp_root_chirho("cairn-real-root");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let error_chirho = run_learner_handover_drill_chirho(Some(&root_chirho), false)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("refuses non-fixture root"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
