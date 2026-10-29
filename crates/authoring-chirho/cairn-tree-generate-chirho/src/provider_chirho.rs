// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Provider adapters for G1 generation. Tests use the deterministic stub; OpenRouter is readiness.

use crate::model_chirho::{
    GeneratedSourcePlanChirho, OpenRouterConfigChirho, ProviderModeChirho, StubScenarioChirho,
    TreeGenerateBriefChirho, TreeGenerateProviderResponseChirho,
    TREE_GENERATE_OPENROUTER_CONFIG_SCHEMA_CHIRHO, TREE_GENERATE_PROVIDER_RESPONSE_SCHEMA_CHIRHO,
};
use anyhow::{bail, Context, Result};
use cairn_model_provider_chirho::{
    OPENROUTER_CHAT_COMPLETIONS_URL_CHIRHO, OPENROUTER_DEEPSEEK_V4_MODEL_CHIRHO,
    OPENROUTER_PROVIDER_CHIRHO,
};
use cairn_secret_chirho::secret_chirho;
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct ProviderRequestChirho<'a> {
    pub root_chirho: &'a Path,
    pub mode_chirho: &'a ProviderModeChirho,
    pub stub_scenario_chirho: &'a StubScenarioChirho,
    pub config_secret_chirho: Option<&'a str>,
    pub brief_chirho: &'a TreeGenerateBriefChirho,
    pub authoring_context_chirho: Option<&'a str>,
    pub diagnostics_chirho: Option<&'a str>,
    pub attempt_chirho: usize,
}

#[derive(Clone, Debug)]
pub struct ProviderOutputChirho {
    pub provider_chirho: String,
    pub model_chirho: String,
    pub prompt_bytes_chirho: usize,
    pub completion_bytes_chirho: usize,
    pub prompt_tokens_chirho: Option<u64>,
    pub completion_tokens_chirho: Option<u64>,
    pub plan_chirho: GeneratedSourcePlanChirho,
}

pub fn generate_source_plan_chirho(
    request_chirho: ProviderRequestChirho<'_>,
) -> Result<ProviderOutputChirho> {
    match request_chirho.mode_chirho {
        ProviderModeChirho::DeterministicStubChirho => deterministic_stub_chirho(&request_chirho),
        ProviderModeChirho::OpenRouterChirho => openrouter_chirho(&request_chirho),
    }
}

fn deterministic_stub_chirho(
    request_chirho: &ProviderRequestChirho<'_>,
) -> Result<ProviderOutputChirho> {
    let plan_chirho = match request_chirho.stub_scenario_chirho {
        StubScenarioChirho::ValidContactChirho => {
            GeneratedSourcePlanChirho::ScaffoldContactChirho {
                hostile_capability_chirho: false,
            }
        }
        StubScenarioChirho::HostileCapabilityChirho => {
            GeneratedSourcePlanChirho::ScaffoldContactChirho {
                hostile_capability_chirho: true,
            }
        }
        StubScenarioChirho::BrokenLoopChirho => GeneratedSourcePlanChirho::FilesChirho {
            files_chirho: vec![crate::model_chirho::GeneratedFileChirho {
                path_chirho: "not-a-tree-chirho.txt".to_string(),
                content_chirho: "this is deliberately not a tree-build app".to_string(),
            }],
        },
    };
    let prompt_chirho = prompt_chirho(request_chirho);
    let completion_chirho = serde_json::to_string(&TreeGenerateProviderResponseChirho {
        schema_chirho: TREE_GENERATE_PROVIDER_RESPONSE_SCHEMA_CHIRHO.to_string(),
        source_plan_chirho: plan_chirho.clone(),
    })?;
    Ok(ProviderOutputChirho {
        provider_chirho: "deterministic-stub-chirho".to_string(),
        model_chirho: format!("{:?}", request_chirho.stub_scenario_chirho),
        prompt_bytes_chirho: prompt_chirho.len(),
        completion_bytes_chirho: completion_chirho.len(),
        prompt_tokens_chirho: None,
        completion_tokens_chirho: None,
        plan_chirho,
    })
}

fn openrouter_chirho(request_chirho: &ProviderRequestChirho<'_>) -> Result<ProviderOutputChirho> {
    let secret_name_chirho = request_chirho
        .config_secret_chirho
        .ok_or_else(|| anyhow::anyhow!("openrouter provider requires --provider-config-secret"))?;
    let config_text_chirho = secret_chirho::resolve_secret_string_chirho(
        request_chirho.root_chirho,
        secret_name_chirho,
    )?;
    let config_chirho: OpenRouterConfigChirho = serde_json::from_str(&config_text_chirho)
        .map_err(|_| anyhow::anyhow!("tree generate OpenRouter config secret is not valid JSON"))?;
    if config_chirho.schema_chirho != TREE_GENERATE_OPENROUTER_CONFIG_SCHEMA_CHIRHO {
        bail!(
            "tree generate OpenRouter config schema must be {}",
            TREE_GENERATE_OPENROUTER_CONFIG_SCHEMA_CHIRHO
        );
    }
    if config_chirho.api_key_chirho.trim().is_empty() {
        bail!("tree generate OpenRouter config api_key_chirho must not be empty");
    }
    let model_chirho = config_chirho
        .model_chirho
        .clone()
        .unwrap_or_else(|| OPENROUTER_DEEPSEEK_V4_MODEL_CHIRHO.to_string());
    let url_chirho = config_chirho
        .base_url_chirho
        .clone()
        .unwrap_or_else(|| OPENROUTER_CHAT_COMPLETIONS_URL_CHIRHO.to_string());
    let prompt_chirho = prompt_chirho(request_chirho);
    let body_chirho = serde_json::json!({
        "model": model_chirho,
        "messages": [
            {
                "role": "system",
                "content": "Return only JSON matching tree-generate-provider-response-v1-chirho."
            },
            { "role": "user", "content": prompt_chirho }
        ],
        "max_tokens": 4096
    });
    let response_chirho = ureq::post(&url_chirho)
        .set(
            "authorization",
            &format!("Bearer {}", config_chirho.api_key_chirho),
        )
        .set("content-type", "application/json")
        .send_json(body_chirho)
        .context("send OpenRouter generation request")?;
    let text_chirho = response_chirho
        .into_string()
        .context("read OpenRouter generation response")?;
    let parsed_chirho: OpenRouterChatResponseChirho =
        serde_json::from_str(&text_chirho).context("parse OpenRouter response JSON")?;
    let content_chirho = parsed_chirho
        .choices_chirho
        .first()
        .and_then(|choice_chirho| choice_chirho.message_chirho.content_chirho.as_deref())
        .ok_or_else(|| anyhow::anyhow!("OpenRouter response missing choices[0].message.content"))?;
    let provider_response_chirho = parse_provider_response_chirho(content_chirho)?;
    Ok(ProviderOutputChirho {
        provider_chirho: OPENROUTER_PROVIDER_CHIRHO.to_string(),
        model_chirho,
        prompt_bytes_chirho: prompt_chirho.len(),
        completion_bytes_chirho: content_chirho.len(),
        prompt_tokens_chirho: parsed_chirho
            .usage_chirho
            .as_ref()
            .and_then(|usage_chirho| usage_chirho.prompt_tokens_chirho),
        completion_tokens_chirho: parsed_chirho
            .usage_chirho
            .as_ref()
            .and_then(|usage_chirho| usage_chirho.completion_tokens_chirho),
        plan_chirho: provider_response_chirho.source_plan_chirho,
    })
}

pub(crate) fn prompt_chirho(request_chirho: &ProviderRequestChirho<'_>) -> String {
    let mut prompt_chirho = format!(
        "Build a CAIRN tree-build source tree for app {}.\nPublic request:\n{}\n",
        request_chirho.brief_chirho.app_chirho, request_chirho.brief_chirho.public_request_chirho
    );
    if let Some(notes_chirho) = request_chirho
        .brief_chirho
        .private_operator_notes_chirho
        .as_deref()
    {
        prompt_chirho.push_str("\nOperator-local notes disclosed to this provider:\n");
        prompt_chirho.push_str(notes_chirho);
        prompt_chirho.push('\n');
    }
    if !request_chirho.brief_chirho.constraints_chirho.is_empty() {
        prompt_chirho.push_str("\nConstraints:\n");
        for constraint_chirho in &request_chirho.brief_chirho.constraints_chirho {
            prompt_chirho.push_str("- ");
            prompt_chirho.push_str(constraint_chirho);
            prompt_chirho.push('\n');
        }
    }
    if let Some(context_chirho) = request_chirho.authoring_context_chirho {
        prompt_chirho.push_str("\nAuthoring context JSON:\n");
        prompt_chirho.push_str(context_chirho);
        prompt_chirho.push('\n');
    }
    if let Some(diagnostics_chirho) = request_chirho.diagnostics_chirho {
        prompt_chirho.push_str("\nPrevious diagnostics to repair:\n");
        prompt_chirho.push_str(diagnostics_chirho);
        prompt_chirho.push('\n');
    }
    prompt_chirho.push_str(
        "\nReturn JSON with schema_chirho and source_plan_chirho. The source must stop at review; do not ask to promote.",
    );
    prompt_chirho
}

fn parse_provider_response_chirho(text_chirho: &str) -> Result<TreeGenerateProviderResponseChirho> {
    let trimmed_chirho = text_chirho.trim();
    let json_chirho = trimmed_chirho
        .strip_prefix("```json")
        .and_then(|body_chirho| body_chirho.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(trimmed_chirho);
    let response_chirho: TreeGenerateProviderResponseChirho =
        serde_json::from_str(json_chirho).context("parse tree-generate provider response")?;
    if response_chirho.schema_chirho != TREE_GENERATE_PROVIDER_RESPONSE_SCHEMA_CHIRHO {
        bail!(
            "provider response schema must be {}",
            TREE_GENERATE_PROVIDER_RESPONSE_SCHEMA_CHIRHO
        );
    }
    Ok(response_chirho)
}

#[derive(Debug, Deserialize)]
struct OpenRouterChatResponseChirho {
    #[serde(rename = "choices")]
    choices_chirho: Vec<OpenRouterChoiceChirho>,
    #[serde(default, rename = "usage")]
    usage_chirho: Option<OpenRouterUsageChirho>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterChoiceChirho {
    #[serde(rename = "message")]
    message_chirho: OpenRouterMessageChirho,
}

#[derive(Debug, Deserialize)]
struct OpenRouterMessageChirho {
    #[serde(default, rename = "content")]
    content_chirho: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterUsageChirho {
    #[serde(default, rename = "prompt_tokens")]
    prompt_tokens_chirho: Option<u64>,
    #[serde(default, rename = "completion_tokens")]
    completion_tokens_chirho: Option<u64>,
}
