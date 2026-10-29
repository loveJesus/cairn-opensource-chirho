// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Strict-validate the untrusted LLM completion into vetted deploy params — the trust boundary of the
//! app-builder dag. The model produces only free text; this pure node parses it as a single JSON
//! object and accepts it ONLY if it matches the vetted landing shape exactly (exact keys, non-empty
//! strings, 2-4 features each with exactly a non-empty title and body). Anything else fails closed:
//! the node returns an `Err`, and the guest turns that into a non-deploy error envelope so the
//! blessed template-deploy door never fires on bad output. On success it derives a URL-safe slug and
//! a content-keyed idempotency id so an identical build is reproducible.
//! Part of the `view_build_chirho` dag.

use crate::types_chirho::app_params_landing_v1_chirho::{
    AppParamsLandingV1Chirho, TemplateFeatureChirho,
};
use crate::types_chirho::deploy_request_v1_chirho::DeployRequestV1Chirho;
use crate::types_chirho::llm_completion_v1_chirho::LlmCompletionV1Chirho;

/// The vetted template this validated build deploys into (the deploy door's `schema_chirho`).
pub const DEPLOY_REQUEST_SCHEMA_CHIRHO: &str = "template-app-deploy-request-v1-chirho";

/// Domain-separation prefix for the content-keyed idempotency id, so this app's build keys can never
/// collide with another producer's keys over the same params.
const IDEM_DOMAIN_CHIRHO: &str = "perffection-app-builder-v1";

/// The exact top-level keys the vetted landing params object must carry — no more, no less.
const REQUIRED_PARAM_KEYS_CHIRHO: [&str; 4] = [
    "business_name_chirho",
    "tagline_chirho",
    "contact_chirho",
    "features_chirho",
];

/// The exact keys each feature object must carry.
const REQUIRED_FEATURE_KEYS_CHIRHO: [&str; 2] = ["title_chirho", "body_chirho"];

const MIN_FEATURES_CHIRHO: usize = 2;
const MAX_FEATURES_CHIRHO: usize = 4;

/// Max length of the derived slug id (kept short and plain so it is a safe URL/key segment).
const MAX_SLUG_LEN_CHIRHO: usize = 48;

/// in completion: LlmCompletionV1Chirho (untrusted model text) -> out deploy_request: DeployRequestV1Chirho.
/// `Ok` only on a fully-valid completion; `Err(reason)` on anything else (the guest fails closed).
pub fn validate_build_params_chirho(
    completion_chirho: &LlmCompletionV1Chirho,
) -> Result<DeployRequestV1Chirho, String> {
    let params_chirho = parse_and_validate_params_chirho(&completion_chirho.text_chirho)?;
    let slug_chirho = slugify_chirho(&params_chirho.business_name_chirho)?;
    let idem_key_chirho = idem_key_chirho(&slug_chirho, &params_chirho)?;
    Ok(DeployRequestV1Chirho {
        schema_chirho: DEPLOY_REQUEST_SCHEMA_CHIRHO.to_string(),
        slug_chirho,
        idem_key_chirho,
        params_chirho,
    })
}

/// Parse the completion text as one JSON object and strict-validate it as vetted landing params.
/// Defensively strips a leading/trailing markdown code fence first; everything else must already be
/// exactly the shape we render from.
fn parse_and_validate_params_chirho(text_chirho: &str) -> Result<AppParamsLandingV1Chirho, String> {
    let cleaned_chirho = strip_code_fences_chirho(text_chirho);
    let value_chirho: serde_json::Value = serde_json::from_str(cleaned_chirho)
        .map_err(|e_chirho| format!("completion is not valid JSON: {e_chirho}"))?;
    let object_chirho = value_chirho
        .as_object()
        .ok_or_else(|| "completion must be a JSON object".to_string())?;

    exact_keys_chirho("params", object_chirho, &REQUIRED_PARAM_KEYS_CHIRHO)?;

    let business_name_chirho =
        non_empty_string_field_chirho(object_chirho, "business_name_chirho")?;
    let tagline_chirho = non_empty_string_field_chirho(object_chirho, "tagline_chirho")?;
    let contact_chirho = non_empty_string_field_chirho(object_chirho, "contact_chirho")?;
    let features_chirho = validate_features_chirho(&object_chirho["features_chirho"])?;

    Ok(AppParamsLandingV1Chirho {
        business_name_chirho,
        tagline_chirho,
        contact_chirho,
        features_chirho,
    })
}

/// Validate the `features_chirho` value: a JSON array of 2-4 objects, each having exactly a non-empty
/// `title_chirho` and `body_chirho`.
fn validate_features_chirho(
    value_chirho: &serde_json::Value,
) -> Result<Vec<TemplateFeatureChirho>, String> {
    let array_chirho = value_chirho
        .as_array()
        .ok_or_else(|| "features_chirho must be an array".to_string())?;
    if array_chirho.len() < MIN_FEATURES_CHIRHO || array_chirho.len() > MAX_FEATURES_CHIRHO {
        return Err(format!(
            "features_chirho must have {MIN_FEATURES_CHIRHO} to {MAX_FEATURES_CHIRHO} items, found {}",
            array_chirho.len()
        ));
    }
    let mut features_chirho = Vec::with_capacity(array_chirho.len());
    for (index_chirho, feature_value_chirho) in array_chirho.iter().enumerate() {
        let feature_object_chirho = feature_value_chirho
            .as_object()
            .ok_or_else(|| format!("feature {index_chirho} must be a JSON object"))?;
        exact_keys_chirho(
            &format!("feature {index_chirho}"),
            feature_object_chirho,
            &REQUIRED_FEATURE_KEYS_CHIRHO,
        )?;
        features_chirho.push(TemplateFeatureChirho {
            title_chirho: non_empty_string_field_chirho(feature_object_chirho, "title_chirho")?,
            body_chirho: non_empty_string_field_chirho(feature_object_chirho, "body_chirho")?,
        });
    }
    Ok(features_chirho)
}

/// Require an object's key set to be EXACTLY `required_chirho` — reject any missing or extra key.
fn exact_keys_chirho(
    label_chirho: &str,
    object_chirho: &serde_json::Map<String, serde_json::Value>,
    required_chirho: &[&str],
) -> Result<(), String> {
    for key_chirho in required_chirho {
        if !object_chirho.contains_key(*key_chirho) {
            return Err(format!("{label_chirho} is missing key '{key_chirho}'"));
        }
    }
    for key_chirho in object_chirho.keys() {
        if !required_chirho.contains(&key_chirho.as_str()) {
            return Err(format!("{label_chirho} has unexpected key '{key_chirho}'"));
        }
    }
    Ok(())
}

/// Read a field that must be a JSON string with non-whitespace content; return the trimmed value.
fn non_empty_string_field_chirho(
    object_chirho: &serde_json::Map<String, serde_json::Value>,
    key_chirho: &str,
) -> Result<String, String> {
    let raw_chirho = object_chirho
        .get(key_chirho)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("'{key_chirho}' must be a string"))?;
    let trimmed_chirho = raw_chirho.trim();
    if trimmed_chirho.is_empty() {
        return Err(format!("'{key_chirho}' must not be blank"));
    }
    Ok(trimmed_chirho.to_string())
}

/// Strip a single leading/trailing markdown code fence (```json ... ```), defensively, so a model
/// that wraps its JSON in a fence despite the instruction still validates. Anything else is left as
/// is for the strict parser to judge.
fn strip_code_fences_chirho(text_chirho: &str) -> &str {
    let trimmed_chirho = text_chirho.trim();
    let Some(after_open_chirho) = trimmed_chirho.strip_prefix("```") else {
        return trimmed_chirho;
    };
    // Drop the rest of the opening fence line (e.g. the `json` language tag), then a trailing fence.
    let body_chirho = match after_open_chirho.split_once('\n') {
        Some((_lang_chirho, rest_chirho)) => rest_chirho,
        None => after_open_chirho,
    };
    body_chirho
        .trim()
        .strip_suffix("```")
        .unwrap_or(body_chirho)
        .trim()
}

/// Derive a URL-safe slug from the business name: lowercase, runs of non-alphanumerics collapse to a
/// single '-', leading/trailing '-' trimmed, ASCII `[a-z0-9-]` only. Fails closed if nothing usable
/// remains (so a name of only punctuation can't yield an empty slug).
fn slugify_chirho(business_name_chirho: &str) -> Result<String, String> {
    let mut slug_chirho = String::with_capacity(business_name_chirho.len());
    let mut last_was_dash_chirho = false;
    for ch_chirho in business_name_chirho.chars() {
        if ch_chirho.is_ascii_alphanumeric() {
            slug_chirho.push(ch_chirho.to_ascii_lowercase());
            last_was_dash_chirho = false;
        } else if !last_was_dash_chirho {
            slug_chirho.push('-');
            last_was_dash_chirho = true;
        }
    }
    let slug_chirho = slug_chirho.trim_matches('-').to_string();
    if slug_chirho.is_empty() {
        return Err("business_name_chirho has no slug-able characters".to_string());
    }
    Ok(slug_chirho)
}

/// A short, plain, content-keyed idempotency id: lowercase-hex BLAKE3 of
/// (`IDEM_DOMAIN_CHIRHO` + slug + canonical params JSON), truncated. Same build -> same id, so an
/// identical re-submission is idempotent; `[a-z0-9-]`, <= `MAX_SLUG_LEN_CHIRHO` chars.
fn idem_key_chirho(
    slug_chirho: &str,
    params_chirho: &AppParamsLandingV1Chirho,
) -> Result<String, String> {
    let canonical_params_chirho = serde_json::to_string(params_chirho)
        .map_err(|e_chirho| format!("cannot canonicalize params: {e_chirho}"))?;
    let preimage_chirho = format!("{IDEM_DOMAIN_CHIRHO}\n{slug_chirho}\n{canonical_params_chirho}");
    let hex_chirho = blake3::hash(preimage_chirho.as_bytes())
        .to_hex()
        .to_string();
    Ok(hex_chirho.chars().take(MAX_SLUG_LEN_CHIRHO).collect())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn completion_chirho(text_chirho: &str) -> LlmCompletionV1Chirho {
        LlmCompletionV1Chirho {
            text_chirho: text_chirho.to_string(),
        }
    }

    const VALID_JSON_CHIRHO: &str = r#"{"business_name_chirho":"Riverbend Roasters","tagline_chirho":"Small-batch coffee.","contact_chirho":"hello@riverbend.example","features_chirho":[{"title_chirho":"Single-origin","body_chirho":"Roasted weekly."},{"title_chirho":"Cozy cafe","body_chirho":"Open early."}]}"#;

    #[test]
    fn happy_path_returns_a_deploy_request_chirho() {
        let deploy_request_chirho =
            validate_build_params_chirho(&completion_chirho(VALID_JSON_CHIRHO)).unwrap();
        // The schema names the vetted deploy contract.
        assert_eq!(
            deploy_request_chirho.schema_chirho,
            DEPLOY_REQUEST_SCHEMA_CHIRHO
        );
        // The slug is derived from the business name.
        assert_eq!(deploy_request_chirho.slug_chirho, "riverbend-roasters");
        // The validated params round-trip into the typed struct.
        assert_eq!(
            deploy_request_chirho.params_chirho.business_name_chirho,
            "Riverbend Roasters"
        );
        assert_eq!(deploy_request_chirho.params_chirho.features_chirho.len(), 2);
        // The idempotency key is a short, plain id.
        assert!(!deploy_request_chirho.idem_key_chirho.is_empty());
        assert!(deploy_request_chirho.idem_key_chirho.len() <= MAX_SLUG_LEN_CHIRHO);
        assert!(deploy_request_chirho
            .idem_key_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_lowercase()
                || c_chirho.is_ascii_digit()
                || c_chirho == '-'));
    }

    #[test]
    fn raw_params_object_text_is_the_data_path_the_fixed_guest_feeds_chirho() {
        // The blessed llm door returns the RAW model-completion content (the params object itself),
        // not a `{"text_chirho":...}` wrapper. The fixed guest reads those bytes straight into
        // `text_chirho`, so this is exactly what the validator sees on a real build. Proves that data
        // path yields Ok with a slugified slug, a stable content-keyed idem key, and the parsed params.
        let raw_params_text_chirho = r#"{"business_name_chirho":"Acme","tagline_chirho":"We build","contact_chirho":"hi@acme.test","features_chirho":[{"title_chirho":"Fast","body_chirho":"Quick"},{"title_chirho":"Safe","body_chirho":"Secure"}]}"#;
        let deploy_request_chirho =
            validate_build_params_chirho(&completion_chirho(raw_params_text_chirho)).unwrap();
        // The vetted deploy schema is named.
        assert_eq!(
            deploy_request_chirho.schema_chirho,
            DEPLOY_REQUEST_SCHEMA_CHIRHO
        );
        // The slug is derived (slugified) from the business name.
        assert_eq!(deploy_request_chirho.slug_chirho, "acme");
        // The params parsed out of the raw object text, intact.
        assert_eq!(
            deploy_request_chirho.params_chirho.business_name_chirho,
            "Acme"
        );
        assert_eq!(
            deploy_request_chirho.params_chirho.tagline_chirho,
            "We build"
        );
        assert_eq!(
            deploy_request_chirho.params_chirho.contact_chirho,
            "hi@acme.test"
        );
        assert_eq!(deploy_request_chirho.params_chirho.features_chirho.len(), 2);
        assert_eq!(
            deploy_request_chirho.params_chirho.features_chirho[0].title_chirho,
            "Fast"
        );
        // The idem key is a short, plain, content-keyed id, stable for the same raw input.
        assert!(!deploy_request_chirho.idem_key_chirho.is_empty());
        assert!(deploy_request_chirho.idem_key_chirho.len() <= MAX_SLUG_LEN_CHIRHO);
        let again_chirho =
            validate_build_params_chirho(&completion_chirho(raw_params_text_chirho)).unwrap();
        assert_eq!(
            deploy_request_chirho.idem_key_chirho,
            again_chirho.idem_key_chirho
        );
    }

    #[test]
    fn the_idem_key_is_stable_for_the_same_build_chirho() {
        let a_chirho = validate_build_params_chirho(&completion_chirho(VALID_JSON_CHIRHO)).unwrap();
        let b_chirho = validate_build_params_chirho(&completion_chirho(VALID_JSON_CHIRHO)).unwrap();
        assert_eq!(a_chirho.idem_key_chirho, b_chirho.idem_key_chirho);
    }

    #[test]
    fn the_idem_key_changes_with_the_params_chirho() {
        let other_json_chirho = r#"{"business_name_chirho":"Riverbend Roasters","tagline_chirho":"DIFFERENT tagline.","contact_chirho":"hello@riverbend.example","features_chirho":[{"title_chirho":"Single-origin","body_chirho":"Roasted weekly."},{"title_chirho":"Cozy cafe","body_chirho":"Open early."}]}"#;
        let a_chirho = validate_build_params_chirho(&completion_chirho(VALID_JSON_CHIRHO)).unwrap();
        let b_chirho = validate_build_params_chirho(&completion_chirho(other_json_chirho)).unwrap();
        assert_ne!(a_chirho.idem_key_chirho, b_chirho.idem_key_chirho);
    }

    #[test]
    fn defensive_code_fences_are_stripped_chirho() {
        let fenced_chirho = format!("```json\n{VALID_JSON_CHIRHO}\n```");
        let deploy_request_chirho =
            validate_build_params_chirho(&completion_chirho(&fenced_chirho)).unwrap();
        assert_eq!(deploy_request_chirho.slug_chirho, "riverbend-roasters");
    }

    #[test]
    fn slugify_collapses_punctuation_and_trims_chirho() {
        let json_chirho = r#"{"business_name_chirho":"  J & J's  Café!! ","tagline_chirho":"t","contact_chirho":"c","features_chirho":[{"title_chirho":"a","body_chirho":"b"},{"title_chirho":"c","body_chirho":"d"}]}"#;
        let deploy_request_chirho =
            validate_build_params_chirho(&completion_chirho(json_chirho)).unwrap();
        assert_eq!(deploy_request_chirho.slug_chirho, "j-j-s-caf");
    }

    #[test]
    fn rejects_non_json_chirho() {
        assert!(validate_build_params_chirho(&completion_chirho("not json at all")).is_err());
        assert!(validate_build_params_chirho(&completion_chirho("")).is_err());
    }

    #[test]
    fn rejects_non_object_top_level_chirho() {
        assert!(validate_build_params_chirho(&completion_chirho("[1,2,3]")).is_err());
        assert!(validate_build_params_chirho(&completion_chirho("\"a string\"")).is_err());
    }

    #[test]
    fn rejects_a_missing_key_chirho() {
        // No contact_chirho.
        let json_chirho = r#"{"business_name_chirho":"X","tagline_chirho":"t","features_chirho":[{"title_chirho":"a","body_chirho":"b"},{"title_chirho":"c","body_chirho":"d"}]}"#;
        assert!(validate_build_params_chirho(&completion_chirho(json_chirho)).is_err());
    }

    #[test]
    fn rejects_an_extra_key_chirho() {
        let json_chirho = r#"{"business_name_chirho":"X","tagline_chirho":"t","contact_chirho":"c","features_chirho":[{"title_chirho":"a","body_chirho":"b"},{"title_chirho":"c","body_chirho":"d"}],"sneaky_chirho":"x"}"#;
        assert!(validate_build_params_chirho(&completion_chirho(json_chirho)).is_err());
    }

    #[test]
    fn rejects_a_blank_string_chirho() {
        let json_chirho = r#"{"business_name_chirho":"   ","tagline_chirho":"t","contact_chirho":"c","features_chirho":[{"title_chirho":"a","body_chirho":"b"},{"title_chirho":"c","body_chirho":"d"}]}"#;
        assert!(validate_build_params_chirho(&completion_chirho(json_chirho)).is_err());
    }

    #[test]
    fn rejects_too_few_and_too_many_features_chirho() {
        let one_feature_chirho = r#"{"business_name_chirho":"X","tagline_chirho":"t","contact_chirho":"c","features_chirho":[{"title_chirho":"a","body_chirho":"b"}]}"#;
        assert!(validate_build_params_chirho(&completion_chirho(one_feature_chirho)).is_err());
        let five_features_chirho = r#"{"business_name_chirho":"X","tagline_chirho":"t","contact_chirho":"c","features_chirho":[{"title_chirho":"a","body_chirho":"b"},{"title_chirho":"c","body_chirho":"d"},{"title_chirho":"e","body_chirho":"f"},{"title_chirho":"g","body_chirho":"h"},{"title_chirho":"i","body_chirho":"j"}]}"#;
        assert!(validate_build_params_chirho(&completion_chirho(five_features_chirho)).is_err());
    }

    #[test]
    fn rejects_a_feature_with_wrong_keys_or_blank_field_chirho() {
        let extra_feature_key_chirho = r#"{"business_name_chirho":"X","tagline_chirho":"t","contact_chirho":"c","features_chirho":[{"title_chirho":"a","body_chirho":"b","x_chirho":1},{"title_chirho":"c","body_chirho":"d"}]}"#;
        assert!(
            validate_build_params_chirho(&completion_chirho(extra_feature_key_chirho)).is_err()
        );
        let blank_feature_body_chirho = r#"{"business_name_chirho":"X","tagline_chirho":"t","contact_chirho":"c","features_chirho":[{"title_chirho":"a","body_chirho":"   "},{"title_chirho":"c","body_chirho":"d"}]}"#;
        assert!(
            validate_build_params_chirho(&completion_chirho(blank_feature_body_chirho)).is_err()
        );
    }

    #[test]
    fn rejects_a_business_name_with_no_slugable_chars_chirho() {
        let json_chirho = r#"{"business_name_chirho":"!!!","tagline_chirho":"t","contact_chirho":"c","features_chirho":[{"title_chirho":"a","body_chirho":"b"},{"title_chirho":"c","body_chirho":"d"}]}"#;
        assert!(validate_build_params_chirho(&completion_chirho(json_chirho)).is_err());
    }
}
