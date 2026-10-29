// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Schema-tagged models for the G1 generator report and provider exchange.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

pub const TREE_GENERATE_BRIEF_SCHEMA_CHIRHO: &str = "tree-generate-brief-v1-chirho";
pub const TREE_GENERATE_REPORT_SCHEMA_CHIRHO: &str = "tree-generate-report-v1-chirho";
pub const TREE_GENERATE_PROVIDER_RESPONSE_SCHEMA_CHIRHO: &str =
    "tree-generate-provider-response-v1-chirho";
pub const TREE_GENERATE_OPENROUTER_CONFIG_SCHEMA_CHIRHO: &str =
    "tree-generate-openrouter-config-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderModeChirho {
    DeterministicStubChirho,
    OpenRouterChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StubScenarioChirho {
    ValidContactChirho,
    HostileCapabilityChirho,
    BrokenLoopChirho,
}

#[derive(Clone, Debug)]
pub struct GenerateOptionsChirho {
    pub brief_path_chirho: PathBuf,
    pub output_root_chirho: PathBuf,
    pub runtime_root_chirho: PathBuf,
    pub owner_chirho: String,
    pub provider_mode_chirho: ProviderModeChirho,
    pub stub_scenario_chirho: StubScenarioChirho,
    pub provider_config_secret_chirho: Option<String>,
    pub authoring_context_chirho: Option<PathBuf>,
    pub tree_build_chirho: PathBuf,
    pub cairn_cli_chirho: PathBuf,
    pub max_iterations_chirho: usize,
    pub max_provider_calls_chirho: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TreeGenerateBriefChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub public_request_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_operator_notes_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints_chirho: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TreeGenerateProviderResponseChirho {
    pub schema_chirho: String,
    pub source_plan_chirho: GeneratedSourcePlanChirho,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum GeneratedSourcePlanChirho {
    ScaffoldContactChirho {
        #[serde(default)]
        hostile_capability_chirho: bool,
    },
    FilesChirho {
        files_chirho: Vec<GeneratedFileChirho>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedFileChirho {
    pub path_chirho: String,
    pub content_chirho: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenRouterConfigChirho {
    pub schema_chirho: String,
    pub api_key_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url_chirho: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TreeGenerateReportChirho {
    pub schema_chirho: &'static str,
    pub ok_chirho: bool,
    pub adapter_readiness_not_delivery_evidence_chirho: bool,
    pub no_auto_promote_path_chirho: bool,
    pub provider_chirho: String,
    pub model_chirho: String,
    pub brief_chirho: BriefEvidenceChirho,
    pub authoring_context_chirho: Option<LocalFileEvidenceChirho>,
    pub generated_source_chirho: GeneratedSourceEvidenceChirho,
    pub counters_chirho: GenerationCountersChirho,
    pub step_count_run_chirho: usize,
    pub step_count_total_chirho: usize,
    pub steps_chirho: Vec<GenerationStepChirho>,
    pub review_report_chirho: Option<Value>,
    pub honest_scope_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_chirho: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BriefEvidenceChirho {
    pub source_chirho: String,
    pub digest_chirho: String,
    pub byte_count_chirho: usize,
    pub raw_text_in_report_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LocalFileEvidenceChirho {
    pub source_chirho: String,
    pub digest_chirho: String,
    pub byte_count_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct GeneratedSourceEvidenceChirho {
    pub output_root_chirho: String,
    pub manifest_chirho: Option<String>,
    pub file_count_chirho: usize,
    pub generated_source_private_scoped_chirho: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GenerationCountersChirho {
    pub provider_calls_attempted_chirho: usize,
    pub provider_calls_completed_chirho: usize,
    pub repair_iterations_chirho: usize,
    pub prompt_bytes_chirho: usize,
    pub completion_bytes_chirho: usize,
    pub prompt_tokens_chirho: Option<u64>,
    pub completion_tokens_chirho: Option<u64>,
    pub metering_not_billing_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct GenerationStepChirho {
    pub index_chirho: usize,
    pub name_chirho: String,
    pub ok_chirho: bool,
    pub detail_chirho: String,
}

pub fn honest_scope_chirho() -> Vec<String> {
    vec![
        "G1 is operator-run generation-loop tooling upstream of the unchanged candidate/review/promote gate.".to_string(),
        "OpenRouter support is adapter readiness, not delivery evidence; no live provider call is exercised by this packet.".to_string(),
        "G1 briefs are operator-local files. Product-mode brief intake as private blobs from byte one is a later slice.".to_string(),
        "Sending a brief to a hosted provider is an external disclosure, acceptable here only for operator-run briefs.".to_string(),
        "Generated source is not private-scoped once the operator proceeds to candidate/review; it is stored like authored source.".to_string(),
        "Generated source trees are deterministic under the stub; review report hashes are not claimed byte-stable across runs because compiled WASM artifacts can carry path-dependent bytes.".to_string(),
        "Diagnostic scrubbing targets path-shaped tokens, not bare identifiers; sensitive local paths are covered by position-independent literal redaction.".to_string(),
        "No auto-promote path is added, and no public/live/self-serve LLM generation nonclaim is retired.".to_string(),
        "Spend counters are local metering evidence, not Ring A billing or customer charges.".to_string(),
    ]
}
