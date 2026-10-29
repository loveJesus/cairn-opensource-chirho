// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only authoring context pack for untrusted source generators.

use crate::blessed_catalog_chirho::{
    blessed_catalog_entries_chirho, BlessedCardParamsChirho, BlessedContractEntryChirho,
};
use cairn_capability_chirho::capability_plain_chirho::{
    describe_review_capability_label_with_dictionary_chirho, review_capability_power_body_chirho,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const AUTHORING_CONTEXT_SCHEMA_CHIRHO: &str = "tree-build-authoring-context-v1-chirho";
pub const AUTHORING_CONTEXT_REPORT_SCHEMA_CHIRHO: &str =
    "tree-build-authoring-context-report-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoringContextReportChirho {
    pub schema_chirho: String,
    pub output_path_chirho: String,
    pub artifact_blake3_chirho: String,
    pub artifact_bytes_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoringContextPackChirho {
    pub schema_chirho: String,
    pub purpose_chirho: String,
    pub honest_scope_chirho: Vec<String>,
    pub blessed_catalog_chirho: Vec<BlessedContractDescriptorChirho>,
    pub authoring_conventions_chirho: Vec<AuthoringConventionChirho>,
    pub typed_port_rules_chirho: Vec<TypedPortRuleChirho>,
    pub worked_examples_chirho: Vec<WorkedExampleChirho>,
    pub voice_layer_chirho: VoiceLayerDisciplineChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlessedContractDescriptorChirho {
    pub catalog_name_chirho: String,
    pub contract_ref_chirho: String,
    pub owner_what_it_does_chirho: String,
    pub plain_power_chirho: String,
    pub required_card_fields_chirho: Vec<String>,
    pub technical_capability_specs_chirho: Vec<String>,
    pub technical_review_power_lines_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoringConventionChirho {
    pub name_chirho: String,
    pub rule_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedPortRuleChirho {
    pub name_chirho: String,
    pub rule_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkedExampleChirho {
    pub name_chirho: String,
    pub path_chirho: String,
    pub why_this_example_chirho: String,
    pub commands_chirho: Vec<String>,
    pub demonstrates_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceLayerDisciplineChirho {
    pub customer_word_source_chirho: String,
    pub descriptor_floor_chirho: String,
    pub review_bar_chirho: String,
    pub source_question_chirho: String,
}

pub fn authoring_context_pack_chirho() -> Result<AuthoringContextPackChirho, String> {
    let blessed_catalog_chirho = blessed_catalog_entries_chirho()
        .iter()
        .map(blessed_descriptor_chirho)
        .collect::<Result<Vec<_>, _>>()?;
    let pack_chirho = AuthoringContextPackChirho {
        schema_chirho: AUTHORING_CONTEXT_SCHEMA_CHIRHO.to_string(),
        purpose_chirho: "Make AI-authored source expressible in a way that is obviously safe: authors may shape templates, pure nodes, and DAG wiring; the invariant substrate remains pure-WASM, blessed-effects-only, review-before-run, signed append-only truth, and rollback.".to_string(),
        honest_scope_chirho: vec![
            "This pack is advisory context for untrusted source generation; it is not authority.".to_string(),
            "Candidates still resolve blessed names against the registry during build/review.".to_string(),
            "The owner review gate is unchanged; this pack does not approve or promote anything.".to_string(),
            "No LLM call, provider secret, runtime write, or persisted artifact family is created by G0.".to_string(),
        ],
        blessed_catalog_chirho,
        authoring_conventions_chirho: authoring_conventions_chirho(),
        typed_port_rules_chirho: typed_port_rules_chirho(),
        worked_examples_chirho: vec![contact_worked_example_chirho()],
        voice_layer_chirho: VoiceLayerDisciplineChirho {
            customer_word_source_chirho: "Customer-facing words come from descriptor and voice data at the source, not from frontend translation tables.".to_string(),
            descriptor_floor_chirho: "Best-effort denylist floor: owner-facing fields must not ask for tokens, keys, raw hashes, raw capability forms, or common technical acronyms.".to_string(),
            review_bar_chirho: "The bar remains design review and L.J. read-through; the denylist cannot prove plain language by itself.".to_string(),
            source_question_chirho: "Would a UI have to translate this? If yes, fix the primitive or descriptor source.".to_string(),
        },
    };
    validate_authoring_context_descriptors_chirho(&pack_chirho)?;
    Ok(pack_chirho)
}

pub fn write_authoring_context_chirho(
    output_chirho: &Path,
) -> Result<AuthoringContextReportChirho, String> {
    let pack_chirho = authoring_context_pack_chirho()?;
    let mut bytes_chirho =
        serde_json::to_vec_pretty(&pack_chirho).map_err(|error_chirho| error_chirho.to_string())?;
    bytes_chirho.push(b'\n');
    if let Some(parent_chirho) = output_chirho.parent() {
        std::fs::create_dir_all(parent_chirho).map_err(|error_chirho| {
            format!(
                "create authoring-context output dir {}: {error_chirho}",
                parent_chirho.display()
            )
        })?;
    }
    std::fs::write(output_chirho, &bytes_chirho).map_err(|error_chirho| {
        format!(
            "write authoring-context output {}: {error_chirho}",
            output_chirho.display()
        )
    })?;
    Ok(AuthoringContextReportChirho {
        schema_chirho: AUTHORING_CONTEXT_REPORT_SCHEMA_CHIRHO.to_string(),
        output_path_chirho: output_chirho.display().to_string(),
        artifact_blake3_chirho: blake3::hash(&bytes_chirho).to_hex().to_string(),
        artifact_bytes_chirho: bytes_chirho.len(),
    })
}

pub fn validate_authoring_context_descriptors_chirho(
    pack_chirho: &AuthoringContextPackChirho,
) -> Result<(), String> {
    for entry_chirho in &pack_chirho.blessed_catalog_chirho {
        validate_owner_descriptor_text_chirho(
            &format!(
                "{}.owner_what_it_does_chirho",
                entry_chirho.catalog_name_chirho
            ),
            &entry_chirho.owner_what_it_does_chirho,
        )?;
        validate_owner_descriptor_text_chirho(
            &format!("{}.plain_power_chirho", entry_chirho.catalog_name_chirho),
            &entry_chirho.plain_power_chirho,
        )?;
    }
    validate_owner_descriptor_text_chirho(
        "voice_layer_chirho.customer_word_source_chirho",
        &pack_chirho.voice_layer_chirho.customer_word_source_chirho,
    )?;
    validate_owner_descriptor_text_chirho(
        "voice_layer_chirho.source_question_chirho",
        &pack_chirho.voice_layer_chirho.source_question_chirho,
    )?;
    Ok(())
}

pub fn validate_owner_descriptor_text_chirho(
    field_chirho: &str,
    text_chirho: &str,
) -> Result<(), String> {
    let lower_chirho = text_chirho.to_ascii_lowercase();
    let forbidden_phrases_chirho = [
        "oauth",
        "api key",
        "secret key",
        "private key",
        "access token",
        "paste your token",
        "paste token",
        "llm",
        "crm",
        "mcp",
        "wasm",
    ];
    for phrase_chirho in forbidden_phrases_chirho {
        if lower_chirho.contains(phrase_chirho) {
            return Err(format!(
                "{field_chirho} contains owner-facing jargon/secret phrase '{phrase_chirho}'"
            ));
        }
    }
    let raw_forms_chirho = [
        "write-store:",
        "query:",
        "paid:",
        "identity:",
        "template-app-deploy:",
    ];
    for form_chirho in raw_forms_chirho {
        if text_chirho.contains(form_chirho) {
            return Err(format!(
                "{field_chirho} contains raw capability form '{form_chirho}'"
            ));
        }
    }
    if contains_bare_hex64_chirho(text_chirho) {
        return Err(format!("{field_chirho} contains a bare 64-hex hash"));
    }
    Ok(())
}

fn blessed_descriptor_chirho(
    entry_chirho: &BlessedContractEntryChirho,
) -> Result<BlessedContractDescriptorChirho, String> {
    let capability_specs_chirho = entry_chirho.capabilities_for_card_chirho(
        &sample_params_for_contract_chirho(entry_chirho.contract_chirho),
    )?;
    let technical_review_power_lines_chirho = capability_specs_chirho
        .iter()
        .map(|spec_chirho| {
            match describe_review_capability_label_with_dictionary_chirho(spec_chirho) {
                Some(line_chirho) => format!(
                    "form={}\tcategory={}\tplain={}",
                    line_chirho.form_id_chirho,
                    line_chirho.category_chirho,
                    line_chirho.plain_chirho
                ),
                None => review_capability_power_body_chirho(spec_chirho),
            }
        })
        .collect();
    Ok(BlessedContractDescriptorChirho {
        catalog_name_chirho: entry_chirho.contract_chirho.to_string(),
        contract_ref_chirho: format!("blessed-contract:{}", entry_chirho.contract_hash_chirho()),
        owner_what_it_does_chirho: entry_chirho.owner_what_it_does_chirho.to_string(),
        plain_power_chirho: entry_chirho.owner_power_chirho.to_string(),
        required_card_fields_chirho: required_fields_for_contract_chirho(
            entry_chirho.contract_chirho,
        ),
        technical_capability_specs_chirho: capability_specs_chirho,
        technical_review_power_lines_chirho,
    })
}

fn sample_params_for_contract_chirho(contract_chirho: &str) -> BlessedCardParamsChirho<'static> {
    match contract_chirho {
        "query" => BlessedCardParamsChirho {
            scope_chirho: "contact-submissions-chirho",
            caller_chirho: Some("owner-contact-steward-chirho"),
            max_rows_chirho: Some(25),
            max_tokens_chirho: None,
            max_price_per_token_chirho: None,
        },
        "llm" => BlessedCardParamsChirho {
            scope_chirho: "draft-helper-chirho",
            caller_chirho: Some("owner-contact-steward-chirho"),
            max_rows_chirho: None,
            max_tokens_chirho: Some(2048),
            max_price_per_token_chirho: Some(2),
        },
        "postgres-reversible" => BlessedCardParamsChirho {
            scope_chirho: "credits-balance-chirho",
            caller_chirho: Some("owner-credits-steward-chirho"),
            max_rows_chirho: None,
            max_tokens_chirho: None,
            max_price_per_token_chirho: None,
        },
        "template-app-deploy" => BlessedCardParamsChirho {
            scope_chirho: "contact-page-template-chirho",
            caller_chirho: None,
            max_rows_chirho: None,
            max_tokens_chirho: None,
            max_price_per_token_chirho: None,
        },
        _ => BlessedCardParamsChirho {
            scope_chirho: "contact-submissions-chirho",
            caller_chirho: None,
            max_rows_chirho: None,
            max_tokens_chirho: None,
            max_price_per_token_chirho: None,
        },
    }
}

fn required_fields_for_contract_chirho(contract_chirho: &str) -> Vec<String> {
    match contract_chirho {
        "query" => vec!["scope_chirho", "caller_chirho", "max_rows_chirho"],
        "llm" => vec![
            "scope_chirho",
            "caller_chirho",
            "max_tokens_chirho",
            "max_price_per_token_chirho",
        ],
        "postgres-reversible" => vec!["scope_chirho", "caller_chirho"],
        _ => vec!["scope_chirho"],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn authoring_conventions_chirho() -> Vec<AuthoringConventionChirho> {
    vec![
        convention_chirho("tree-is-source-chirho", "The app tree is the authoring source; JSON manifests are compiled interchange."),
        convention_chirho("pure-first-chirho", "App-authored code stays pure by default; effects are requested only by naming blessed catalog cards."),
        convention_chirho("review-before-run-chirho", "Generated source stops at candidate/review until an owner promotes the reviewed hash."),
        convention_chirho("templates-are-html-chirho", "Templates remain editable files; Rust should not build HTML strings by hand."),
        convention_chirho("styles-are-assets-chirho", "Styles compile to signed content-addressed assets that the served app can reference by reviewed name."),
    ]
}

fn typed_port_rules_chirho() -> Vec<TypedPortRuleChirho> {
    vec![
        port_rule_chirho(
            "default-bytes-chirho",
            "Absent schema declarations keep the legacy bytes default.",
        ),
        port_rule_chirho(
            "declared-schema-hash-chirho",
            "When either side declares a schema, the wire must match by schema hash.",
        ),
        port_rule_chirho(
            "invalid-schema-red-chirho",
            "Invalid schema files fail check with a stable finding instead of being ignored.",
        ),
        port_rule_chirho(
            "one-producer-per-input-chirho",
            "Each input has exactly one producer: a wire or a pinned content stone.",
        ),
    ]
}

fn contact_worked_example_chirho() -> WorkedExampleChirho {
    WorkedExampleChirho {
        name_chirho: "tree-contact-chirho".to_string(),
        path_chirho: "examples-chirho/tree-contact-chirho".to_string(),
        why_this_example_chirho: "Guide-as-golden contact tree demonstrating private-data handling discipline, pure validation/render nodes, and reviewed source emission.".to_string(),
        commands_chirho: vec![
            "tree-build-chirho check --json examples-chirho/tree-contact-chirho".to_string(),
            "tree-build-chirho test --json examples-chirho/tree-contact-chirho".to_string(),
            "tree-build-chirho emit examples-chirho/tree-contact-chirho".to_string(),
        ],
        demonstrates_chirho: vec![
            "request passes through validation before rendering".to_string(),
            "source tree emits a reviewable app-source manifest".to_string(),
            "private-data handling remains part of the app discipline".to_string(),
        ],
    }
}

fn convention_chirho(name_chirho: &str, rule_chirho: &str) -> AuthoringConventionChirho {
    AuthoringConventionChirho {
        name_chirho: name_chirho.to_string(),
        rule_chirho: rule_chirho.to_string(),
    }
}

fn port_rule_chirho(name_chirho: &str, rule_chirho: &str) -> TypedPortRuleChirho {
    TypedPortRuleChirho {
        name_chirho: name_chirho.to_string(),
        rule_chirho: rule_chirho.to_string(),
    }
}

fn contains_bare_hex64_chirho(text_chirho: &str) -> bool {
    text_chirho
        .split(|char_chirho: char| !char_chirho.is_ascii_alphanumeric())
        .any(|part_chirho| {
            part_chirho.len() == 64
                && part_chirho
                    .chars()
                    .all(|char_chirho| char_chirho.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_output_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let now_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "tree-build-authoring-context-{label_chirho}-{now_chirho}-{n_chirho}"
            ))
            .join("context-chirho.json")
    }

    #[test]
    fn authoring_context_has_required_structure_chirho() {
        let pack_chirho = authoring_context_pack_chirho().unwrap();
        assert_eq!(pack_chirho.schema_chirho, AUTHORING_CONTEXT_SCHEMA_CHIRHO);
        assert!(!pack_chirho.blessed_catalog_chirho.is_empty());
        assert!(!pack_chirho.authoring_conventions_chirho.is_empty());
        assert!(!pack_chirho.typed_port_rules_chirho.is_empty());
        assert_eq!(
            pack_chirho.worked_examples_chirho[0].path_chirho,
            "examples-chirho/tree-contact-chirho"
        );
        assert!(pack_chirho
            .honest_scope_chirho
            .iter()
            .any(|line_chirho| line_chirho.contains("not authority")));
    }

    #[test]
    fn authoring_context_is_deterministic_without_golden_hash_chirho() {
        let first_chirho =
            serde_json::to_vec_pretty(&authoring_context_pack_chirho().unwrap()).unwrap();
        let second_chirho =
            serde_json::to_vec_pretty(&authoring_context_pack_chirho().unwrap()).unwrap();
        assert_eq!(first_chirho, second_chirho);
    }

    #[test]
    fn owner_descriptor_floor_rejects_guarded_classes_chirho() {
        assert!(validate_owner_descriptor_text_chirho("field", "paste your OAuth token").is_err());
        assert!(validate_owner_descriptor_text_chirho("field", "add an API key").is_err());
        assert!(
            validate_owner_descriptor_text_chirho("field", "write-store:contacts-chirho").is_err()
        );
        assert!(validate_owner_descriptor_text_chirho(
            "field",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_err());
    }

    #[test]
    fn owner_descriptor_floor_allows_catalog_fields_chirho() {
        let pack_chirho = authoring_context_pack_chirho().unwrap();
        validate_authoring_context_descriptors_chirho(&pack_chirho).unwrap();
    }

    #[test]
    fn write_authoring_context_reports_hash_without_pinning_it_chirho() {
        let output_chirho = tmp_output_chirho("write");
        let report_chirho = write_authoring_context_chirho(&output_chirho).unwrap();
        let bytes_chirho = std::fs::read(&output_chirho).unwrap();
        assert_eq!(
            report_chirho.schema_chirho,
            AUTHORING_CONTEXT_REPORT_SCHEMA_CHIRHO
        );
        assert_eq!(report_chirho.artifact_bytes_chirho, bytes_chirho.len());
        assert_eq!(
            report_chirho.artifact_blake3_chirho,
            blake3::hash(&bytes_chirho).to_hex().to_string()
        );
        let parsed_chirho: AuthoringContextPackChirho =
            serde_json::from_slice(&bytes_chirho).unwrap();
        assert_eq!(parsed_chirho.schema_chirho, AUTHORING_CONTEXT_SCHEMA_CHIRHO);
        let _ = std::fs::remove_dir_all(output_chirho.parent().unwrap());
    }
}
