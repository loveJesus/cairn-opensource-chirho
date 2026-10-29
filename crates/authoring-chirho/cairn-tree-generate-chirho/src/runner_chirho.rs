// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Bounded G1 generation loop over tree-build and app-source-review subprocess gates.

use crate::model_chirho::{
    honest_scope_chirho, BriefEvidenceChirho, GenerateOptionsChirho, GeneratedSourceEvidenceChirho,
    GenerationCountersChirho, GenerationStepChirho, LocalFileEvidenceChirho,
    TreeGenerateBriefChirho, TreeGenerateReportChirho, TREE_GENERATE_BRIEF_SCHEMA_CHIRHO,
    TREE_GENERATE_REPORT_SCHEMA_CHIRHO,
};
use crate::provider_chirho::{generate_source_plan_chirho, ProviderRequestChirho};
use crate::source_plan_chirho::{apply_source_plan_chirho, count_source_files_chirho};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

const STEP_TOTAL_CHIRHO: usize = 5;
const REDACTION_MARKER_CHIRHO: &str = "[operator-local-redacted-chirho]";

pub fn run_tree_generation_chirho(
    options_chirho: &GenerateOptionsChirho,
) -> TreeGenerateReportChirho {
    let redactions_chirho = RedactionSetChirho::from_options_chirho(options_chirho);
    match run_tree_generation_inner_chirho(options_chirho) {
        Ok(report_chirho) => report_chirho,
        Err(error_chirho) => {
            failure_report_chirho(options_chirho, error_chirho.to_string(), &redactions_chirho)
        }
    }
}

fn run_tree_generation_inner_chirho(
    options_chirho: &GenerateOptionsChirho,
) -> Result<TreeGenerateReportChirho> {
    validate_options_chirho(options_chirho)?;
    let mut redactions_chirho = RedactionSetChirho::from_options_chirho(options_chirho);
    let brief_bytes_chirho = std::fs::read(&options_chirho.brief_path_chirho)
        .with_context(|| format!("read {}", options_chirho.brief_path_chirho.display()))?;
    let brief_chirho: TreeGenerateBriefChirho =
        serde_json::from_slice(&brief_bytes_chirho).context("parse tree-generate brief JSON")?;
    if brief_chirho.schema_chirho != TREE_GENERATE_BRIEF_SCHEMA_CHIRHO {
        bail!("brief schema must be {TREE_GENERATE_BRIEF_SCHEMA_CHIRHO}");
    }
    let brief_evidence_chirho = file_evidence_chirho(
        "operator-local-brief-redacted-chirho",
        &brief_bytes_chirho,
        "brief-blake3",
    );
    let (authoring_context_text_chirho, authoring_context_evidence_chirho) =
        read_optional_context_chirho(options_chirho.authoring_context_chirho.as_deref())?;
    redactions_chirho.push_brief_chirho(&brief_chirho);
    let scratch_chirho = scratch_dir_chirho("g1-tree-generate-chirho")?;
    redactions_chirho.push_path_chirho(&scratch_chirho);
    let mut counters_chirho = GenerationCountersChirho {
        metering_not_billing_chirho: true,
        ..GenerationCountersChirho::default()
    };
    let mut steps_chirho = Vec::new();
    let mut diagnostics_chirho: Option<String> = None;
    let mut last_error_chirho = None;
    let mut last_provider_chirho = "not-completed-chirho".to_string();
    let mut last_model_chirho = "not-completed-chirho".to_string();

    for attempt_chirho in 0..options_chirho.max_iterations_chirho {
        if counters_chirho.provider_calls_attempted_chirho
            >= options_chirho.max_provider_calls_chirho
        {
            break;
        }
        counters_chirho.provider_calls_attempted_chirho += 1;
        let provider_output_chirho = match generate_source_plan_chirho(ProviderRequestChirho {
            root_chirho: &options_chirho.runtime_root_chirho,
            mode_chirho: &options_chirho.provider_mode_chirho,
            stub_scenario_chirho: &options_chirho.stub_scenario_chirho,
            config_secret_chirho: options_chirho.provider_config_secret_chirho.as_deref(),
            brief_chirho: &brief_chirho,
            authoring_context_chirho: authoring_context_text_chirho.as_deref(),
            diagnostics_chirho: diagnostics_chirho.as_deref(),
            attempt_chirho,
        }) {
            Ok(provider_output_chirho) => provider_output_chirho,
            Err(error_chirho) => {
                last_error_chirho =
                    Some(redactions_chirho.redact_report_text_chirho(&error_chirho.to_string()));
                break;
            }
        };
        last_provider_chirho.clone_from(&provider_output_chirho.provider_chirho);
        last_model_chirho.clone_from(&provider_output_chirho.model_chirho);
        counters_chirho.provider_calls_completed_chirho += 1;
        counters_chirho.prompt_bytes_chirho += provider_output_chirho.prompt_bytes_chirho;
        counters_chirho.completion_bytes_chirho += provider_output_chirho.completion_bytes_chirho;
        counters_chirho.prompt_tokens_chirho = add_option_chirho(
            counters_chirho.prompt_tokens_chirho,
            provider_output_chirho.prompt_tokens_chirho,
        );
        counters_chirho.completion_tokens_chirho = add_option_chirho(
            counters_chirho.completion_tokens_chirho,
            provider_output_chirho.completion_tokens_chirho,
        );

        let attempt_root_chirho = scratch_chirho.join(format!("attempt-{attempt_chirho}-chirho"));
        std::fs::create_dir_all(&attempt_root_chirho)?;
        let mut attempt_redactions_chirho = redactions_chirho.clone();
        attempt_redactions_chirho.push_path_chirho(&attempt_root_chirho);
        if let Err(error_chirho) =
            apply_source_plan_chirho(&provider_output_chirho.plan_chirho, &attempt_root_chirho)
        {
            let message_chirho =
                attempt_redactions_chirho.provider_safe_text_chirho(&error_chirho.to_string());
            diagnostics_chirho = Some(message_chirho.clone());
            last_error_chirho = Some(message_chirho);
            counters_chirho.repair_iterations_chirho += 1;
            continue;
        }
        match run_attempt_chirho(
            options_chirho,
            &attempt_root_chirho,
            &mut steps_chirho,
            &attempt_redactions_chirho,
        ) {
            Ok(review_chirho) => {
                copy_tree_chirho(&attempt_root_chirho, &options_chirho.output_root_chirho)?;
                let file_count_chirho =
                    count_source_files_chirho(&options_chirho.output_root_chirho)?;
                return Ok(TreeGenerateReportChirho {
                    schema_chirho: TREE_GENERATE_REPORT_SCHEMA_CHIRHO,
                    ok_chirho: true,
                    adapter_readiness_not_delivery_evidence_chirho: true,
                    no_auto_promote_path_chirho: true,
                    provider_chirho: provider_output_chirho.provider_chirho,
                    model_chirho: provider_output_chirho.model_chirho,
                    brief_chirho: BriefEvidenceChirho {
                        source_chirho: brief_evidence_chirho.source_chirho,
                        digest_chirho: brief_evidence_chirho.digest_chirho,
                        byte_count_chirho: brief_evidence_chirho.byte_count_chirho,
                        raw_text_in_report_chirho: false,
                    },
                    authoring_context_chirho: authoring_context_evidence_chirho,
                    generated_source_chirho: GeneratedSourceEvidenceChirho {
                        output_root_chirho: redacted_path_chirho(
                            &options_chirho.output_root_chirho,
                        ),
                        manifest_chirho: Some(
                            "generated-source-manifest-redacted-chirho".to_string(),
                        ),
                        file_count_chirho,
                        generated_source_private_scoped_chirho: false,
                    },
                    counters_chirho,
                    step_count_run_chirho: steps_chirho.len(),
                    step_count_total_chirho: step_total_for_budget_chirho(options_chirho),
                    steps_chirho,
                    review_report_chirho: Some(review_chirho),
                    honest_scope_chirho: honest_scope_chirho(),
                    error_chirho: None,
                });
            }
            Err(error_chirho) => {
                let message_chirho =
                    attempt_redactions_chirho.provider_safe_text_chirho(&error_chirho.to_string());
                diagnostics_chirho = Some(message_chirho.clone());
                last_error_chirho = Some(message_chirho);
                counters_chirho.repair_iterations_chirho += 1;
            }
        }
    }
    let mut report_chirho = failure_report_chirho(
        options_chirho,
        last_error_chirho.unwrap_or_else(|| "generation budget exhausted".to_string()),
        &redactions_chirho,
    );
    report_chirho.brief_chirho = BriefEvidenceChirho {
        source_chirho: brief_evidence_chirho.source_chirho,
        digest_chirho: brief_evidence_chirho.digest_chirho,
        byte_count_chirho: brief_evidence_chirho.byte_count_chirho,
        raw_text_in_report_chirho: false,
    };
    report_chirho.authoring_context_chirho = authoring_context_evidence_chirho;
    report_chirho.counters_chirho = counters_chirho;
    report_chirho.provider_chirho = last_provider_chirho;
    report_chirho.model_chirho = last_model_chirho;
    report_chirho.step_count_run_chirho = steps_chirho.len();
    report_chirho.step_count_total_chirho = step_total_for_budget_chirho(options_chirho);
    report_chirho.steps_chirho = steps_chirho;
    Ok(report_chirho)
}

fn run_attempt_chirho(
    options_chirho: &GenerateOptionsChirho,
    app_root_chirho: &Path,
    steps_chirho: &mut Vec<GenerationStepChirho>,
    redactions_chirho: &RedactionSetChirho,
) -> Result<serde_json::Value> {
    let mut step_redactions_chirho = redactions_chirho.clone();
    step_redactions_chirho.push_path_chirho(app_root_chirho);
    step_redactions_chirho.push_path_chirho(&options_chirho.output_root_chirho);
    step_redactions_chirho.push_path_chirho(&options_chirho.runtime_root_chirho);
    run_step_chirho(
        steps_chirho,
        &step_redactions_chirho,
        "tree-build-check-chirho",
        Command::new(&options_chirho.tree_build_chirho)
            .arg("check")
            .arg("--json")
            .arg(app_root_chirho),
    )?;
    run_step_chirho(
        steps_chirho,
        &step_redactions_chirho,
        "cargo-build-wasm-examples-chirho",
        Command::new("cargo")
            .current_dir(app_root_chirho)
            .arg("build")
            .arg("-q")
            .arg("--examples")
            .arg("--target")
            .arg("wasm32-unknown-unknown"),
    )?;
    run_step_chirho(
        steps_chirho,
        &step_redactions_chirho,
        "tree-build-test-chirho",
        Command::new(&options_chirho.tree_build_chirho)
            .arg("test")
            .arg("--json")
            .arg(app_root_chirho),
    )?;
    let manifest_chirho = app_root_chirho.join(".emitted-manifest-chirho.json");
    let emit_chirho = run_step_chirho(
        steps_chirho,
        &step_redactions_chirho,
        "tree-build-emit-chirho",
        Command::new(&options_chirho.tree_build_chirho)
            .arg("emit")
            .arg(app_root_chirho),
    )?;
    std::fs::write(&manifest_chirho, &emit_chirho)
        .with_context(|| format!("write {}", manifest_chirho.display()))?;
    let review_chirho = run_step_chirho(
        steps_chirho,
        &step_redactions_chirho,
        "app-source-review-chirho",
        Command::new(&options_chirho.cairn_cli_chirho)
            .arg("--root")
            .arg(&options_chirho.runtime_root_chirho)
            .arg("app-source-review")
            .arg("--manifest")
            .arg(&manifest_chirho)
            .arg("--owner")
            .arg(&options_chirho.owner_chirho)
            .arg("--json"),
    )?;
    let value_chirho: serde_json::Value =
        serde_json::from_slice(&review_chirho).context("parse app-source-review JSON")?;
    Ok(value_chirho)
}

pub(crate) fn run_step_chirho(
    steps_chirho: &mut Vec<GenerationStepChirho>,
    redactions_chirho: &RedactionSetChirho,
    name_chirho: &str,
    command_chirho: &mut Command,
) -> Result<Vec<u8>> {
    let output_chirho = command_chirho
        .output()
        .with_context(|| format!("run {name_chirho}"))?;
    let ok_chirho = output_chirho.status.success();
    let detail_chirho = if ok_chirho {
        "ok".to_string()
    } else {
        redactions_chirho.provider_safe_text_chirho(&command_failure_detail_chirho(
            &output_chirho.stdout,
            &output_chirho.stderr,
        ))
    };
    steps_chirho.push(GenerationStepChirho {
        index_chirho: steps_chirho.len(),
        name_chirho: name_chirho.to_string(),
        ok_chirho,
        detail_chirho: detail_chirho.clone(),
    });
    if !ok_chirho {
        bail!("{name_chirho} failed: {detail_chirho}");
    }
    Ok(output_chirho.stdout)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RedactionSetChirho {
    values_chirho: Vec<String>,
}

impl RedactionSetChirho {
    pub(crate) fn from_options_chirho(options_chirho: &GenerateOptionsChirho) -> Self {
        let mut redactions_chirho = Self::default();
        redactions_chirho.push_path_chirho(&options_chirho.brief_path_chirho);
        redactions_chirho.push_path_chirho(&options_chirho.output_root_chirho);
        redactions_chirho.push_path_chirho(&options_chirho.runtime_root_chirho);
        if let Some(authoring_context_chirho) = options_chirho.authoring_context_chirho.as_deref() {
            redactions_chirho.push_path_chirho(authoring_context_chirho);
        }
        redactions_chirho.push_home_paths_chirho();
        redactions_chirho
    }

    fn push_brief_chirho(&mut self, brief_chirho: &TreeGenerateBriefChirho) {
        self.push_text_chirho(&brief_chirho.public_request_chirho);
        if let Some(notes_chirho) = brief_chirho.private_operator_notes_chirho.as_deref() {
            self.push_text_chirho(notes_chirho);
        }
        for constraint_chirho in &brief_chirho.constraints_chirho {
            self.push_text_chirho(constraint_chirho);
        }
    }

    pub(crate) fn push_text_chirho(&mut self, value_chirho: &str) {
        let trimmed_chirho = value_chirho.trim();
        if trimmed_chirho.len() >= 8
            && !self
                .values_chirho
                .iter()
                .any(|existing_chirho| existing_chirho == trimmed_chirho)
        {
            self.values_chirho.push(trimmed_chirho.to_string());
        }
    }

    pub(crate) fn push_path_chirho(&mut self, path_chirho: &Path) {
        self.push_text_chirho(&path_chirho.display().to_string());
        if let Ok(canonical_chirho) = std::fs::canonicalize(path_chirho) {
            self.push_text_chirho(&canonical_chirho.display().to_string());
            self.push_private_var_variant_chirho(&canonical_chirho);
        }
        self.push_private_var_variant_chirho(path_chirho);
    }

    fn push_home_paths_chirho(&mut self) {
        if let Some(home_chirho) = std::env::var_os("HOME") {
            let home_chirho = PathBuf::from(home_chirho);
            self.push_path_chirho(&home_chirho);
            self.push_path_chirho(&home_chirho.join(".cargo"));
            self.push_path_chirho(&home_chirho.join(".rustup"));
        }
        if let Some(cargo_home_chirho) = std::env::var_os("CARGO_HOME") {
            self.push_path_chirho(&PathBuf::from(cargo_home_chirho));
        }
        if let Some(rustup_home_chirho) = std::env::var_os("RUSTUP_HOME") {
            self.push_path_chirho(&PathBuf::from(rustup_home_chirho));
        }
    }

    fn push_private_var_variant_chirho(&mut self, path_chirho: &Path) {
        let path_text_chirho = path_chirho.display().to_string();
        if let Some(rest_chirho) = path_text_chirho.strip_prefix("/var/") {
            self.push_text_chirho(&format!("/private/var/{rest_chirho}"));
        } else if let Some(rest_chirho) = path_text_chirho.strip_prefix("/private/var/") {
            self.push_text_chirho(&format!("/var/{rest_chirho}"));
        }
    }

    fn sorted_values_chirho(&self) -> Vec<&str> {
        let mut values_chirho: Vec<&str> = self.values_chirho.iter().map(String::as_str).collect();
        values_chirho.sort_by_key(|value_chirho| std::cmp::Reverse(value_chirho.len()));
        values_chirho
    }

    fn redact_literal_values_chirho(&self, text_chirho: &str) -> String {
        let mut out_chirho = text_chirho.to_string();
        for redaction_chirho in self.sorted_values_chirho() {
            out_chirho = out_chirho.replace(redaction_chirho, REDACTION_MARKER_CHIRHO);
        }
        out_chirho
    }

    pub(crate) fn redact_report_text_chirho(&self, text_chirho: &str) -> String {
        scrub_absolute_path_tokens_chirho(&self.redact_literal_values_chirho(text_chirho))
    }

    pub(crate) fn provider_safe_text_chirho(&self, text_chirho: &str) -> String {
        self.redact_report_text_chirho(text_chirho)
            .chars()
            .take(2000)
            .collect()
    }
}

fn scrub_absolute_path_tokens_chirho(text_chirho: &str) -> String {
    let chars_chirho: Vec<char> = text_chirho.chars().collect();
    let mut out_chirho = String::with_capacity(text_chirho.len());
    let mut index_chirho = 0usize;
    while index_chirho < chars_chirho.len() {
        if is_inside_http_url_token_chirho(&chars_chirho, index_chirho) {
            out_chirho.push(chars_chirho[index_chirho]);
            index_chirho += 1;
            continue;
        }
        if chars_chirho[index_chirho] == '/'
            || starts_dotdot_path_chirho(&chars_chirho, index_chirho)
        {
            let mut end_chirho = if chars_chirho[index_chirho] == '/' {
                index_chirho + 1
            } else {
                index_chirho + 3
            };
            while end_chirho < chars_chirho.len()
                && !is_path_suffix_boundary_chirho(chars_chirho[end_chirho])
            {
                end_chirho += 1;
            }
            let token_chirho: String = chars_chirho[index_chirho..end_chirho].iter().collect();
            if token_chirho.len() > 1 {
                out_chirho.push_str(REDACTION_MARKER_CHIRHO);
                index_chirho = end_chirho;
                continue;
            }
        }
        out_chirho.push(chars_chirho[index_chirho]);
        index_chirho += 1;
    }
    out_chirho
}

fn is_path_suffix_boundary_chirho(char_chirho: char) -> bool {
    char_chirho.is_whitespace()
        || matches!(
            char_chirho,
            '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '{' | '}' | '[' | ']' | ',' | ';'
        )
}

fn starts_dotdot_path_chirho(chars_chirho: &[char], index_chirho: usize) -> bool {
    chars_chirho.get(index_chirho) == Some(&'.')
        && chars_chirho.get(index_chirho + 1) == Some(&'.')
        && chars_chirho.get(index_chirho + 2) == Some(&'/')
}

fn is_inside_http_url_token_chirho(chars_chirho: &[char], index_chirho: usize) -> bool {
    let mut start_chirho = index_chirho;
    while start_chirho > 0 && !is_url_token_boundary_chirho(chars_chirho[start_chirho - 1]) {
        start_chirho -= 1;
    }
    let mut end_chirho = index_chirho;
    while end_chirho + 1 < chars_chirho.len()
        && !is_url_token_boundary_chirho(chars_chirho[end_chirho + 1])
    {
        end_chirho += 1;
    }
    let token_chirho: String = chars_chirho[start_chirho..=end_chirho].iter().collect();
    token_chirho.contains("http://") || token_chirho.contains("https://")
}

fn is_url_token_boundary_chirho(char_chirho: char) -> bool {
    char_chirho.is_whitespace()
        || matches!(
            char_chirho,
            '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '{' | '}' | '[' | ']' | ','
        )
}

fn command_failure_detail_chirho(stdout_chirho: &[u8], stderr_chirho: &[u8]) -> String {
    let mut text_chirho = String::new();
    text_chirho.push_str(&String::from_utf8_lossy(stderr_chirho));
    if !stdout_chirho.is_empty() {
        text_chirho.push_str("\nstdout:\n");
        text_chirho.push_str(&String::from_utf8_lossy(stdout_chirho));
    }
    text_chirho.chars().take(2000).collect()
}

fn failure_report_chirho(
    options_chirho: &GenerateOptionsChirho,
    error_chirho: String,
    redactions_chirho: &RedactionSetChirho,
) -> TreeGenerateReportChirho {
    TreeGenerateReportChirho {
        schema_chirho: TREE_GENERATE_REPORT_SCHEMA_CHIRHO,
        ok_chirho: false,
        adapter_readiness_not_delivery_evidence_chirho: true,
        no_auto_promote_path_chirho: true,
        provider_chirho: "not-completed-chirho".to_string(),
        model_chirho: "not-completed-chirho".to_string(),
        brief_chirho: BriefEvidenceChirho {
            source_chirho: "operator-local-brief-redacted-chirho".to_string(),
            digest_chirho: "brief-blake3:not-read-chirho".to_string(),
            byte_count_chirho: 0,
            raw_text_in_report_chirho: false,
        },
        authoring_context_chirho: None,
        generated_source_chirho: GeneratedSourceEvidenceChirho {
            output_root_chirho: redacted_path_chirho(&options_chirho.output_root_chirho),
            manifest_chirho: None,
            file_count_chirho: 0,
            generated_source_private_scoped_chirho: false,
        },
        counters_chirho: GenerationCountersChirho {
            metering_not_billing_chirho: true,
            ..GenerationCountersChirho::default()
        },
        step_count_run_chirho: 0,
        step_count_total_chirho: step_total_for_budget_chirho(options_chirho),
        steps_chirho: Vec::new(),
        review_report_chirho: None,
        honest_scope_chirho: honest_scope_chirho(),
        error_chirho: Some(redactions_chirho.redact_report_text_chirho(&error_chirho)),
    }
}

fn step_total_for_budget_chirho(options_chirho: &GenerateOptionsChirho) -> usize {
    STEP_TOTAL_CHIRHO.saturating_mul(options_chirho.max_iterations_chirho)
}

fn read_optional_context_chirho(
    path_chirho: Option<&Path>,
) -> Result<(Option<String>, Option<LocalFileEvidenceChirho>)> {
    let Some(path_chirho) = path_chirho else {
        return Ok((None, None));
    };
    let bytes_chirho =
        std::fs::read(path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    let text_chirho = String::from_utf8(bytes_chirho.clone()).context("authoring context UTF-8")?;
    let evidence_chirho = file_evidence_chirho(
        "operator-local-authoring-context-redacted-chirho",
        &bytes_chirho,
        "context-blake3",
    );
    Ok((Some(text_chirho), Some(evidence_chirho)))
}

fn file_evidence_chirho(
    source_chirho: &str,
    bytes_chirho: &[u8],
    prefix_chirho: &str,
) -> LocalFileEvidenceChirho {
    LocalFileEvidenceChirho {
        source_chirho: source_chirho.to_string(),
        digest_chirho: format!("{prefix_chirho}:{}", blake3::hash(bytes_chirho).to_hex()),
        byte_count_chirho: bytes_chirho.len(),
    }
}

fn add_option_chirho(left_chirho: Option<u64>, right_chirho: Option<u64>) -> Option<u64> {
    match (left_chirho, right_chirho) {
        (Some(left_chirho), Some(right_chirho)) => Some(left_chirho + right_chirho),
        (Some(left_chirho), None) => Some(left_chirho),
        (None, Some(right_chirho)) => Some(right_chirho),
        (None, None) => None,
    }
}

fn validate_options_chirho(options_chirho: &GenerateOptionsChirho) -> Result<()> {
    if options_chirho.max_iterations_chirho == 0 {
        bail!("max_iterations_chirho must be positive");
    }
    if options_chirho.max_provider_calls_chirho == 0 {
        bail!("max_provider_calls_chirho must be positive");
    }
    if options_chirho.output_root_chirho.exists()
        && options_chirho
            .output_root_chirho
            .read_dir()?
            .next()
            .is_some()
    {
        bail!("output root must not already contain files");
    }
    Ok(())
}

fn scratch_dir_chirho(label_chirho: &str) -> Result<PathBuf> {
    let root_chirho = std::env::temp_dir().join(format!(
        "{label_chirho}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&root_chirho)?;
    Ok(root_chirho)
}

fn copy_tree_chirho(from_chirho: &Path, to_chirho: &Path) -> Result<()> {
    if to_chirho.exists() {
        std::fs::remove_dir_all(to_chirho)
            .with_context(|| format!("remove {}", to_chirho.display()))?;
    }
    copy_tree_rec_chirho(from_chirho, to_chirho)
}

fn copy_tree_rec_chirho(from_chirho: &Path, to_chirho: &Path) -> Result<()> {
    std::fs::create_dir_all(to_chirho)?;
    for entry_chirho in std::fs::read_dir(from_chirho)? {
        let entry_chirho = entry_chirho?;
        if !should_copy_generated_entry_chirho(&entry_chirho.file_name()) {
            continue;
        }
        let source_chirho = entry_chirho.path();
        let target_chirho = to_chirho.join(entry_chirho.file_name());
        let meta_chirho = std::fs::symlink_metadata(&source_chirho)?;
        if meta_chirho.file_type().is_symlink() {
            let link_chirho = std::fs::read_link(&source_chirho)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(link_chirho, &target_chirho)?;
            #[cfg(not(unix))]
            std::fs::write(&target_chirho, link_chirho.to_string_lossy().as_bytes())?;
        } else if meta_chirho.is_dir() {
            copy_tree_rec_chirho(&source_chirho, &target_chirho)?;
        } else if meta_chirho.is_file() {
            std::fs::copy(&source_chirho, &target_chirho)?;
        }
    }
    Ok(())
}

pub(crate) fn should_copy_generated_entry_chirho(name_chirho: &std::ffi::OsStr) -> bool {
    let Some(name_chirho) = name_chirho.to_str() else {
        return true;
    };
    !matches!(name_chirho, "target" | ".emitted-manifest-chirho.json")
}

fn redacted_path_chirho(path_chirho: &Path) -> String {
    path_chirho
        .file_name()
        .and_then(|name_chirho| name_chirho.to_str())
        .map(|name_chirho| format!("operator-local-path-redacted-chirho/{name_chirho}"))
        .unwrap_or_else(|| "operator-local-path-redacted-chirho".to_string())
}
