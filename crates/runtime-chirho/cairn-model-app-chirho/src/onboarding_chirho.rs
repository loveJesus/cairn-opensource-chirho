// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pure onboarding DTOs, validation, and canonical signed-message contracts with no I/O.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

const MAX_STEPS_CHIRHO: usize = 16;
const MAX_TITLE_CHARS_CHIRHO: usize = 120;
const MAX_STEP_TITLE_CHARS_CHIRHO: usize = 96;
const MAX_BODY_CHARS_CHIRHO: usize = 1_200;
const MAX_TARGET_CHARS_CHIRHO: usize = 160;
pub const ONBOARDING_RECORD_SCHEMA_CHIRHO: &str = "onboarding-record-v1-chirho";
pub const ONBOARDING_RECORD_V2_SCHEMA_CHIRHO: &str = "onboarding-record-v2-chirho";
const ONBOARDING_TRANSITION_OPERATION_SCHEMA_CHIRHO: &str =
    "onboarding-transition-operation-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingStepChirho {
    pub title_chirho: String,
    pub body_chirho: String,
    pub target_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingGuideChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub title_chirho: String,
    pub steps_chirho: Vec<OnboardingStepChirho>,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub guide_chirho: HashChirho,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transition_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_writer_fence_epoch_chirho: Option<u64>,
    pub sig_chirho: String,
}

pub fn parse_onboarding_step_spec_chirho(spec_chirho: &str) -> Result<OnboardingStepChirho> {
    let (title_target_chirho, body_chirho) = spec_chirho.split_once('=').ok_or_else(|| {
        anyhow!("onboarding step must look like title=body or title@selector=body")
    })?;
    let (title_chirho, target_chirho) = match title_target_chirho.split_once('@') {
        Some((title_chirho, target_chirho)) => {
            let target_chirho = target_chirho.trim();
            let target_chirho = if target_chirho.is_empty() {
                None
            } else {
                Some(target_chirho.to_string())
            };
            (title_chirho.trim().to_string(), target_chirho)
        }
        None => (title_target_chirho.trim().to_string(), None),
    };
    Ok(OnboardingStepChirho {
        title_chirho,
        body_chirho: body_chirho.trim().to_string(),
        target_chirho,
    })
}

pub fn validate_app_name_chirho(app_chirho: &str) -> Result<()> {
    if app_chirho.trim().is_empty() {
        bail!("app_chirho is required");
    }
    if app_chirho.contains('/') || app_chirho.chars().any(char::is_whitespace) {
        bail!("app_chirho must not contain slashes or whitespace");
    }
    Ok(())
}

pub fn validate_onboarding_guide_chirho(guide_chirho: &OnboardingGuideChirho) -> Result<()> {
    validate_app_name_chirho(&guide_chirho.app_chirho)?;
    if guide_chirho.owner_principal_chirho.trim().is_empty() {
        bail!("owner_principal_chirho is required");
    }
    validate_text_chirho(
        &guide_chirho.title_chirho,
        "title_chirho",
        1,
        MAX_TITLE_CHARS_CHIRHO,
    )?;
    if guide_chirho.steps_chirho.is_empty() {
        bail!("onboarding guide needs at least one step");
    }
    if guide_chirho.steps_chirho.len() > MAX_STEPS_CHIRHO {
        bail!("onboarding guide has too many steps");
    }
    for (i_chirho, step_chirho) in guide_chirho.steps_chirho.iter().enumerate() {
        validate_text_chirho(
            &step_chirho.title_chirho,
            &format!("steps_chirho[{i_chirho}].title_chirho"),
            1,
            MAX_STEP_TITLE_CHARS_CHIRHO,
        )?;
        validate_text_chirho(
            &step_chirho.body_chirho,
            &format!("steps_chirho[{i_chirho}].body_chirho"),
            1,
            MAX_BODY_CHARS_CHIRHO,
        )?;
        if let Some(target_chirho) = &step_chirho.target_chirho {
            validate_text_chirho(
                target_chirho,
                &format!("steps_chirho[{i_chirho}].target_chirho"),
                1,
                MAX_TARGET_CHARS_CHIRHO,
            )?;
        }
    }
    Ok(())
}

pub fn validate_onboarding_record_schema_chirho(
    record_chirho: &OnboardingRecordChirho,
) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != ONBOARDING_RECORD_SCHEMA_CHIRHO
        && record_chirho.schema_chirho != ONBOARDING_RECORD_V2_SCHEMA_CHIRHO
    {
        bail!(
            "onboarding record {} has unsupported schema '{}'",
            record_chirho.seq_chirho,
            record_chirho.schema_chirho
        );
    }
    Ok(())
}

fn validate_text_chirho(
    value_chirho: &str,
    label_chirho: &str,
    min_chirho: usize,
    max_chirho: usize,
) -> Result<()> {
    let count_chirho = value_chirho.chars().count();
    if count_chirho < min_chirho {
        bail!("{label_chirho} is required");
    }
    if count_chirho > max_chirho {
        bail!("{label_chirho} exceeds {max_chirho} characters");
    }
    if value_chirho
        .chars()
        .any(|ch_chirho| ch_chirho.is_control() && ch_chirho != '\n' && ch_chirho != '\t')
    {
        bail!("{label_chirho} contains unsupported control characters");
    }
    Ok(())
}

pub fn onboarding_transition_operation_bytes_chirho(
    record_chirho: &OnboardingRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct OnboardingTransitionOperationChirho<'a> {
        schema_chirho: &'static str,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
    }
    Ok(serde_json::to_vec(&OnboardingTransitionOperationChirho {
        schema_chirho: ONBOARDING_TRANSITION_OPERATION_SCHEMA_CHIRHO,
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
    })?)
}

pub fn onboarding_record_message_chirho(record_chirho: &OnboardingRecordChirho) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct OnboardingRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        guide_chirho: &'a HashChirho,
        previous_chirho: &'a Option<HashChirho>,
        at_ms_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        transition_id_chirho: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prepared_writer_fence_epoch_chirho: Option<u64>,
    }
    Ok(serde_json::to_vec(&OnboardingRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: (!record_chirho.schema_chirho.is_empty())
            .then_some(record_chirho.schema_chirho.as_str()),
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        guide_chirho: &record_chirho.guide_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
        transition_id_chirho: (!record_chirho.transition_id_chirho.is_empty())
            .then_some(record_chirho.transition_id_chirho.as_str()),
        prepared_writer_fence_epoch_chirho: record_chirho.prepared_writer_fence_epoch_chirho,
    })?)
}
