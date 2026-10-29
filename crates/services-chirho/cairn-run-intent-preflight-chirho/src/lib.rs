// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Read-only run-intent startup recovery preflight report.

#[cfg(test)]
mod tests_chirho;

use anyhow::{bail, Result};
use cairn_chirho::model_chirho::{DagChirho, HashChirho};
use cairn_chirho::{cas_chirho, dag_private_value_chirho, effect_chirho, store_chirho};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

const RUN_INTENT_STARTUP_PREFLIGHT_REPORT_SCHEMA_CHIRHO: &str =
    "run-intent-startup-preflight-report-v1-chirho";
const RUN_INTENT_PENDING_CHIRHO: &str = "pending-chirho";
const RUN_INTENT_RUNNING_CHIRHO: &str = "running-chirho";

#[derive(Clone, Debug, clap::Args)]
pub struct RunIntentStartupPreflightArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "fail-on-findings")]
    pub fail_on_findings_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunIntentStartupPreflightReportChirho {
    pub schema_chirho: String,
    pub records_chirho: usize,
    pub verified_chirho: bool,
    pub unfinished_chirho: usize,
    pub pending_chirho: usize,
    pub running_chirho: usize,
    pub resume_prereq_failed_chirho: usize,
    pub findings_chirho: Vec<String>,
    pub startup_recovery_would_block_chirho: bool,
    pub read_only_chirho: bool,
    pub resume_not_attempted_chirho: bool,
    pub honest_scope_chirho: Vec<String>,
}

pub fn run_run_intent_startup_preflight_command_chirho(
    root_chirho: &Path,
    args_chirho: &RunIntentStartupPreflightArgsChirho,
) -> Result<()> {
    let report_chirho = run_intent_startup_preflight_report_chirho(root_chirho);
    if args_chirho.json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "run-intent startup preflight: records={} verified={} unfinished={} pending={} running={} findings={} would_block={}",
            report_chirho.records_chirho,
            report_chirho.verified_chirho,
            report_chirho.unfinished_chirho,
            report_chirho.pending_chirho,
            report_chirho.running_chirho,
            report_chirho.findings_chirho.len(),
            report_chirho.startup_recovery_would_block_chirho
        );
        for scope_chirho in &report_chirho.honest_scope_chirho {
            println!("scope: {scope_chirho}");
        }
        if !report_chirho.findings_chirho.is_empty() {
            println!(
                "run-intent startup preflight findings: {:?}",
                report_chirho.findings_chirho
            );
        }
    }
    if args_chirho.fail_on_findings_chirho {
        ensure_run_intent_startup_preflight_clean_chirho(&report_chirho)?;
    }
    Ok(())
}

pub fn run_intent_startup_preflight_report_chirho(
    root_chirho: &Path,
) -> RunIntentStartupPreflightReportChirho {
    let mut report_chirho = RunIntentStartupPreflightReportChirho {
        schema_chirho: RUN_INTENT_STARTUP_PREFLIGHT_REPORT_SCHEMA_CHIRHO.to_string(),
        records_chirho: 0,
        verified_chirho: false,
        unfinished_chirho: 0,
        pending_chirho: 0,
        running_chirho: 0,
        resume_prereq_failed_chirho: 0,
        findings_chirho: Vec::new(),
        startup_recovery_would_block_chirho: false,
        read_only_chirho: true,
        resume_not_attempted_chirho: true,
        honest_scope_chirho: vec![
            "read-only startup recovery preflight; verifies run-intent records and checks resume prerequisites without appending records or running DAGs".to_string(),
            "does not repair run-intent logs, does not mark intents running/failed/done, and does not execute unfinished work".to_string(),
            "intended as a hosted deploy preflight before restarting a newer binary against an existing root".to_string(),
        ],
    };
    let records_chirho =
        match effect_chirho::run_intent_chirho::load_run_intent_records_chirho(root_chirho) {
            Ok(records_chirho) => records_chirho,
            Err(error_chirho) => {
                report_chirho
                    .findings_chirho
                    .push(format!("run-intent-load-failed-chirho: {error_chirho}"));
                report_chirho.startup_recovery_would_block_chirho = true;
                return report_chirho;
            }
        };
    report_chirho.records_chirho = records_chirho.len();
    if let Err(error_chirho) =
        effect_chirho::run_intent_chirho::verify_run_intent_records_chirho(root_chirho)
    {
        report_chirho
            .findings_chirho
            .push(format!("run-intent-verify-failed-chirho: {error_chirho}"));
        report_chirho.startup_recovery_would_block_chirho = true;
        return report_chirho;
    }
    report_chirho.verified_chirho = true;
    let mut latest_by_run_chirho =
        BTreeMap::<HashChirho, effect_chirho::run_intent_chirho::RunIntentRecordChirho>::new();
    for record_chirho in &records_chirho {
        latest_by_run_chirho.insert(record_chirho.run_chirho.clone(), record_chirho.clone());
    }
    for record_chirho in latest_by_run_chirho.values() {
        if !run_intent_unfinished_status_chirho(&record_chirho.status_chirho) {
            continue;
        }
        report_chirho.unfinished_chirho += 1;
        match record_chirho.status_chirho.as_str() {
            RUN_INTENT_PENDING_CHIRHO => report_chirho.pending_chirho += 1,
            RUN_INTENT_RUNNING_CHIRHO => report_chirho.running_chirho += 1,
            _ => {}
        }
        if let Err(error_chirho) =
            check_run_intent_resume_prerequisites_chirho(root_chirho, record_chirho)
        {
            report_chirho.resume_prereq_failed_chirho += 1;
            report_chirho.findings_chirho.push(format!(
                "run-intent-resume-prereq-failed-chirho: run={} status={}: {error_chirho}",
                record_chirho.run_chirho.0, record_chirho.status_chirho
            ));
        }
    }
    report_chirho.startup_recovery_would_block_chirho = !report_chirho.findings_chirho.is_empty();
    report_chirho
}

pub fn ensure_run_intent_startup_preflight_clean_chirho(
    report_chirho: &RunIntentStartupPreflightReportChirho,
) -> Result<()> {
    if report_chirho.startup_recovery_would_block_chirho
        || !report_chirho.findings_chirho.is_empty()
    {
        bail!(
            "run-intent startup preflight found blockers: {}",
            report_chirho.findings_chirho.len()
        );
    }
    Ok(())
}

fn check_run_intent_resume_prerequisites_chirho(
    root_chirho: &Path,
    record_chirho: &effect_chirho::run_intent_chirho::RunIntentRecordChirho,
) -> Result<()> {
    match &record_chirho.request_private_subject_chirho {
        Some(subject_chirho) => {
            dag_private_value_chirho::load_private_dag_value_bytes_chirho(
                root_chirho,
                subject_chirho,
                &record_chirho.request_chirho,
            )
            .map(|_bytes_chirho| ())?;
        }
        None => {
            cas_chirho::get_chirho(root_chirho, &record_chirho.request_chirho)
                .map(|_bytes_chirho| ())?;
        }
    }
    let _dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &record_chirho.dag_chirho)?;
    let _context_chirho = effect_chirho::run_intent_chirho::resume_request_context_chirho(
        root_chirho,
        &record_chirho.scope_chirho,
    )?;
    Ok(())
}

fn run_intent_unfinished_status_chirho(status_chirho: &str) -> bool {
    matches!(
        status_chirho,
        RUN_INTENT_PENDING_CHIRHO | RUN_INTENT_RUNNING_CHIRHO
    )
}
