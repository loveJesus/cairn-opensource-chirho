// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Served spend-bounded LLM effect — the provider PORT, a deterministic STUB, and the
//! plaintext-free evidence TYPES. This leaf holds NO money law and touches no effect dispatch; the
//! CF3 Hold -> Finalize/Release ladder over an injected port is a ROOT MODULE
//! (`src/execution_runtime_chirho/effect_chirho/llm_served_chirho.rs`) mirroring
//! `postgres_reversible_chirho.rs`, because that ladder needs root-private admission, app pricing,
//! viewer-subject sealing, and the run-intent invocation scope. This leaf is the LLM analogue of
//! `cairn-postgres-effect-chirho` (provider + types only), keeping the root a thin dispatcher
//! (boundary doc ruling 6, read against its own postgres precedent — the earlier "the ladder lives
//! here" claim mis-scoped the split). It depends on nothing of Cairn's, so the confinement stays
//! leaf: a provider adapter can never reach the money port or the store.
//!
//! Wire contract (given to the app authoring seat, PFE #22285):
//! - request `llm-request-v1-chirho`: what a pure node asks of the card;
//! - response `llm-response-v1-chirho`: what the effect returns after sealing and metering;
//! - refusal `llm-refusal-v1-chirho`: a typed body the product renders as a sentence.
//!
//! Privacy (boundary doc ruling 4): the prompt and the completion are viewer-subject private blobs
//! at the effect layer (step 2); the EVIDENCE this leaf builds carries only counts, the model
//! label, and blake3 hashes — never the prompt or completion text. The stub is deterministic and
//! free: identical requests give identical completions, distinct requests give distinct ones, so
//! the step-2 ladder can meter it without a network or any spend.

use serde::{Deserialize, Serialize};

/// The one response format the served card asks for: a strict JSON object the pure mapper clamps
/// into a bounded page document. No free-form prose leaves the model into the document path.
pub const LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO: &str = "json-object";

pub const LLM_REQUEST_SCHEMA_CHIRHO: &str = "llm-request-v1-chirho";
pub const LLM_RESPONSE_SCHEMA_CHIRHO: &str = "llm-response-v1-chirho";
pub const LLM_REFUSAL_SCHEMA_CHIRHO: &str = "llm-refusal-v1-chirho";

/// What a pure node asks of the blessed `llm` card. `max_tokens_chirho` may only LOWER the card's
/// ceiling, never raise it (enforced by the step-2 ladder, not here); the caller and scope come
/// from the card binding, never the body, so nothing here identifies the caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmRequestChirho {
    pub schema_chirho: String,
    pub system_chirho: String,
    pub user_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens_chirho: Option<u32>,
    pub response_format_chirho: String,
}

impl LlmRequestChirho {
    /// Reject anything that is not the exact wire shape this port serves, before a provider sees
    /// it: the schema tag and the one supported response format. Fail closed.
    pub fn validate_chirho(&self) -> Result<(), LlmRefusalCodeChirho> {
        if self.schema_chirho != LLM_REQUEST_SCHEMA_CHIRHO
            || self.response_format_chirho != LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO
        {
            return Err(LlmRefusalCodeChirho::ResponseUnparseableChirho);
        }
        Ok(())
    }
}

/// The response the EFFECT returns to the next pure node, AFTER step 2 seals the completion as a
/// viewer-subject blob and meters the cost. `completion_chirho` is the sealed value's text at the
/// point a route renders it (like a viewer-state read); the evidence beside it carries only hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmResponseChirho {
    pub schema_chirho: String,
    pub completion_chirho: String,
    pub tokens_in_chirho: u32,
    pub tokens_out_chirho: u32,
    pub model_chirho: String,
    pub evidence_chirho: LlmEvidenceChirho,
}

/// A typed refusal body the product renders as a sentence; never a secret, never engine prose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmRefusalChirho {
    pub schema_chirho: String,
    pub refusal_code_chirho: LlmRefusalCodeChirho,
    pub message_chirho: String,
}

impl LlmRefusalChirho {
    pub fn new_chirho(code_chirho: LlmRefusalCodeChirho) -> Self {
        Self {
            schema_chirho: LLM_REFUSAL_SCHEMA_CHIRHO.to_string(),
            message_chirho: code_chirho.fixed_message_chirho().to_string(),
            refusal_code_chirho: code_chirho,
        }
    }
}

/// The closed refusal vocabulary. `OverCeilingChirho` and `InsufficientCreditChirho` are the money
/// ladder's (step 2) before any provider call; the rest are the provider's. On ANY of them the
/// step-2 ladder releases the whole Hold — no charge (the customer refund); provider-side
/// settlement is tracked separately (PFE gpt #22299), and only the stub, whose failure is
/// synthetic, may treat a refusal as costing nothing upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LlmRefusalCodeChirho {
    OverCeilingChirho,
    InsufficientCreditChirho,
    ProviderUnavailableChirho,
    TimeoutChirho,
    ResponseUnparseableChirho,
}

impl LlmRefusalCodeChirho {
    /// The product catalog owns the customer sentence; this is only a fixed, secret-free label.
    pub fn fixed_message_chirho(self) -> &'static str {
        match self {
            Self::OverCeilingChirho => "the request exceeds the draft's size limit",
            Self::InsufficientCreditChirho => "not enough credit for a draft",
            Self::ProviderUnavailableChirho => "the drafting service is unavailable",
            Self::TimeoutChirho => "the drafting service did not answer in time",
            Self::ResponseUnparseableChirho => "we could not draft; start blank",
        }
    }
}

/// Plaintext-free evidence about one completion. Hashes and counts only: never the prompt, never
/// the completion text. The step-2 ladder persists this publicly while the text rests in
/// viewer-subject private blobs whose refs it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmEvidenceChirho {
    pub prompt_hash_chirho: String,
    pub completion_hash_chirho: String,
    pub tokens_in_chirho: u32,
    pub tokens_out_chirho: u32,
    pub model_chirho: String,
    pub provider_message_id_hash_chirho: String,
}

/// What a provider actually returns for one request: either a completion with its metered counts,
/// or a typed refusal. The prompt/completion text lives here transiently; sealing into a
/// viewer-subject blob is the step-2 effect layer's job, not the port's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LlmProviderOutcomeChirho {
    CompletedChirho(LlmProviderCompletionChirho),
    RefusedChirho(LlmRefusalCodeChirho),
}

/// A provider's raw completion, before sealing/metering. `provider_message_id_chirho` is the
/// provider's own id for the call; the evidence stores only its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlmProviderCompletionChirho {
    pub completion_chirho: String,
    pub tokens_in_chirho: u32,
    pub tokens_out_chirho: u32,
    pub model_chirho: String,
    pub provider_message_id_chirho: String,
}

/// The injected provider port. The step-2 ladder holds ONE of these (the stub now, a real adapter
/// only under L.J.'s grant), so the money law never names a concrete provider — the same
/// open-only/injection-only shape Descriptor-D uses for the money port.
pub trait LlmProviderChirho {
    fn complete_chirho(&self, request_chirho: &LlmRequestChirho) -> LlmProviderOutcomeChirho;
}

fn hash_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

/// Build plaintext-free evidence from a request and a provider completion. The prompt hash binds
/// the request's system+user; nothing here carries the text itself.
pub fn llm_evidence_chirho(
    request_chirho: &LlmRequestChirho,
    completion_chirho: &LlmProviderCompletionChirho,
) -> LlmEvidenceChirho {
    let mut prompt_bytes_chirho = Vec::new();
    prompt_bytes_chirho.extend_from_slice(request_chirho.system_chirho.as_bytes());
    prompt_bytes_chirho.push(0);
    prompt_bytes_chirho.extend_from_slice(request_chirho.user_chirho.as_bytes());
    LlmEvidenceChirho {
        prompt_hash_chirho: hash_chirho(&prompt_bytes_chirho),
        completion_hash_chirho: hash_chirho(completion_chirho.completion_chirho.as_bytes()),
        tokens_in_chirho: completion_chirho.tokens_in_chirho,
        tokens_out_chirho: completion_chirho.tokens_out_chirho,
        model_chirho: completion_chirho.model_chirho.clone(),
        provider_message_id_hash_chirho: hash_chirho(
            completion_chirho.provider_message_id_chirho.as_bytes(),
        ),
    }
}

/// The deterministic, free, no-network provider. It returns a valid JSON-object completion keyed
/// off the request, so two distinct briefs give two distinct pages and the same brief always gives
/// the same page — enough for the step-2 ladder and the served proof to meter a real mapping
/// without a provider or any spend. Its "model" names itself so no shareable surface implies a real
/// vendor. It never refuses (its failure would be synthetic and is exercised by injecting a
/// refusing test provider, not by the stub).
#[derive(Clone, Copy, Debug, Default)]
pub struct StubLlmProviderChirho;

pub const STUB_MODEL_LABEL_CHIRHO: &str = "cairn-stub-deterministic-chirho";

// The document field limits the pure mapper clamps to (PFE #22329). The stub stays inside them so
// its output is a well-behaved completion, and the mapper's clamp is defence in depth, not a crutch.
const BUSINESS_NAME_MAX_CHIRHO: usize = 80;
const HEADLINE_MAX_CHIRHO: usize = 140;
const SUMMARY_MAX_CHIRHO: usize = 600;
const SERVICE_TITLE_MAX_CHIRHO: usize = 72;
const SERVICE_BODY_MAX_CHIRHO: usize = 320;
const CONTACT_HEADING_MAX_CHIRHO: usize = 80;
const CONTACT_PHONE_MAX_CHIRHO: usize = 40;
const CONTACT_EMAIL_MAX_CHIRHO: usize = 254;
const CONTACT_DETAILS_MAX_CHIRHO: usize = 400;

/// Truncate to at most `max_chars` characters on a char boundary (never a byte split).
fn clamp_chirho(value_chirho: &str, max_chars_chirho: usize) -> String {
    value_chirho.chars().take(max_chars_chirho).collect()
}

/// The value after a `Label:` line in the guided brief, trimmed; `None` if the label is absent.
fn brief_value_chirho(user_chirho: &str, label_chirho: &str) -> Option<String> {
    user_chirho.lines().find_map(|line_chirho| {
        line_chirho
            .trim()
            .strip_prefix(label_chirho)
            .map(|value_chirho| value_chirho.trim().to_string())
    })
}

/// The deterministic stub completion in the mapper's document shape (PFE #22329): a real completion
/// synthesized from the guided brief so the mapping is exercised end to end. The "copy exactly"
/// fields (phone, email) are carried VERBATIM from the brief — the property the mapper enforces and
/// the reason the draft can carry the customer's real contact with no dropped-contact notice. A seed
/// fragment in the summary guarantees distinct briefs render distinct pages even when named fields
/// coincide. Keys are the mapper's contract (not our identifiers), so they are unsuffixed.
fn stub_document_completion_chirho(user_chirho: &str, seed_chirho: &str) -> String {
    let business_name_chirho = clamp_chirho(
        &brief_value_chirho(user_chirho, "Business name:")
            .unwrap_or_else(|| "Your business".into()),
        BUSINESS_NAME_MAX_CHIRHO,
    );
    let services_chirho: Vec<serde_json::Value> =
        brief_value_chirho(user_chirho, "Services to list:")
            .map(|list_chirho| {
                list_chirho
                    .split(';')
                    .map(|service_chirho| service_chirho.trim())
                    .filter(|service_chirho| !service_chirho.is_empty())
                    .take(3)
                    .map(|service_chirho| {
                        serde_json::json!({
                            "title": clamp_chirho(service_chirho, SERVICE_TITLE_MAX_CHIRHO),
                            "body": clamp_chirho(
                                &format!("{service_chirho} at {business_name_chirho}."),
                                SERVICE_BODY_MAX_CHIRHO,
                            ),
                        })
                    })
                    .collect()
            })
            .filter(|services_chirho: &Vec<serde_json::Value>| !services_chirho.is_empty())
            .unwrap_or_else(|| {
                vec![serde_json::json!({
                    "title": "Our work",
                    "body": clamp_chirho(
                        &format!("What {business_name_chirho} offers."),
                        SERVICE_BODY_MAX_CHIRHO,
                    ),
                })]
            });
    let contact_phone_chirho = clamp_chirho(
        &brief_value_chirho(user_chirho, "Phone (copy exactly):").unwrap_or_default(),
        CONTACT_PHONE_MAX_CHIRHO,
    );
    let contact_email_chirho = clamp_chirho(
        &brief_value_chirho(user_chirho, "Email (copy exactly):").unwrap_or_default(),
        CONTACT_EMAIL_MAX_CHIRHO,
    );
    let contact_details_chirho = clamp_chirho(
        &brief_value_chirho(user_chirho, "Hours or how to reach us:")
            .unwrap_or_else(|| format!("Reach {business_name_chirho} during business hours.")),
        CONTACT_DETAILS_MAX_CHIRHO,
    );
    let document_chirho = serde_json::json!({
        "business_name": business_name_chirho,
        "headline": clamp_chirho(&format!("Welcome to {business_name_chirho}"), HEADLINE_MAX_CHIRHO),
        "summary": clamp_chirho(
            &format!(
                "{business_name_chirho} — a starting draft from your brief. Reference {}.",
                &seed_chirho[..8]
            ),
            SUMMARY_MAX_CHIRHO,
        ),
        "services": services_chirho,
        "contact_heading": clamp_chirho("Get in touch", CONTACT_HEADING_MAX_CHIRHO),
        "contact_phone": contact_phone_chirho,
        "contact_email": contact_email_chirho,
        "contact_details": contact_details_chirho,
    });
    serde_json::to_string(&document_chirho).expect("a serde_json::Value serializes")
}

impl LlmProviderChirho for StubLlmProviderChirho {
    fn complete_chirho(&self, request_chirho: &LlmRequestChirho) -> LlmProviderOutcomeChirho {
        if request_chirho.validate_chirho().is_err() {
            return LlmProviderOutcomeChirho::RefusedChirho(
                LlmRefusalCodeChirho::ResponseUnparseableChirho,
            );
        }
        let mut seed_bytes_chirho = Vec::new();
        seed_bytes_chirho.extend_from_slice(request_chirho.system_chirho.as_bytes());
        seed_bytes_chirho.push(0);
        seed_bytes_chirho.extend_from_slice(request_chirho.user_chirho.as_bytes());
        let seed_chirho = hash_chirho(&seed_bytes_chirho);
        let completion_chirho =
            stub_document_completion_chirho(&request_chirho.user_chirho, &seed_chirho);
        // Deterministic token counts derived from lengths, so the meter is a function of the brief.
        let tokens_in_chirho =
            ((request_chirho.system_chirho.len() + request_chirho.user_chirho.len()) / 4 + 1)
                as u32;
        let tokens_out_chirho = (completion_chirho.len() / 4 + 1) as u32;
        LlmProviderOutcomeChirho::CompletedChirho(LlmProviderCompletionChirho {
            completion_chirho,
            tokens_in_chirho,
            tokens_out_chirho,
            model_chirho: STUB_MODEL_LABEL_CHIRHO.to_string(),
            provider_message_id_chirho: format!("stub-{seed_chirho}"),
        })
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    // A guided brief in the labelled shape PFE's builder writes, so the stub exercises the real
    // brief -> document mapping. `name` distinguishes briefs; phone and email are the copy-exactly
    // fields.
    fn request_chirho(name_chirho: &str) -> LlmRequestChirho {
        LlmRequestChirho {
            schema_chirho: LLM_REQUEST_SCHEMA_CHIRHO.to_string(),
            system_chirho: "You draft a small business landing page.".to_string(),
            user_chirho: format!(
                "Business name: {name_chirho}\nServices to list: first; second\nPhone (copy exactly): +1 (555) 010-2400\nEmail (copy exactly): hello@example.test\nHours or how to reach us: Mon-Fri 9-5"
            ),
            max_tokens_chirho: Some(1200),
            response_format_chirho: LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO.to_string(),
        }
    }

    fn completion_of_chirho(
        outcome_chirho: LlmProviderOutcomeChirho,
    ) -> LlmProviderCompletionChirho {
        match outcome_chirho {
            LlmProviderOutcomeChirho::CompletedChirho(completion_chirho) => completion_chirho,
            LlmProviderOutcomeChirho::RefusedChirho(code_chirho) => {
                panic!("expected a completion, got refusal {code_chirho:?}")
            }
        }
    }

    #[test]
    fn the_stub_is_deterministic_and_returns_valid_json_a_mapper_can_parse_chirho() {
        let stub_chirho = StubLlmProviderChirho;
        let a_chirho =
            completion_of_chirho(stub_chirho.complete_chirho(&request_chirho("A bakery")));
        let b_chirho =
            completion_of_chirho(stub_chirho.complete_chirho(&request_chirho("A bakery")));
        assert_eq!(a_chirho, b_chirho, "same brief -> same completion");
        let parsed_chirho: serde_json::Value =
            serde_json::from_str(&a_chirho.completion_chirho).expect("completion is a JSON object");
        assert!(parsed_chirho.is_object());
        assert!(a_chirho.tokens_in_chirho > 0 && a_chirho.tokens_out_chirho > 0);
        assert_eq!(a_chirho.model_chirho, STUB_MODEL_LABEL_CHIRHO);
    }

    #[test]
    fn distinct_briefs_give_distinct_pages_and_distinct_completion_hashes_chirho() {
        let stub_chirho = StubLlmProviderChirho;
        let a_chirho =
            completion_of_chirho(stub_chirho.complete_chirho(&request_chirho("A bakery")));
        let b_chirho =
            completion_of_chirho(stub_chirho.complete_chirho(&request_chirho("A plant shop")));
        assert_ne!(a_chirho.completion_chirho, b_chirho.completion_chirho);
        let ev_a_chirho = llm_evidence_chirho(&request_chirho("A bakery"), &a_chirho);
        let ev_b_chirho = llm_evidence_chirho(&request_chirho("A plant shop"), &b_chirho);
        assert_ne!(
            ev_a_chirho.completion_hash_chirho,
            ev_b_chirho.completion_hash_chirho
        );
        assert_ne!(
            ev_a_chirho.prompt_hash_chirho,
            ev_b_chirho.prompt_hash_chirho
        );
    }

    #[test]
    fn the_brief_name_and_copy_exactly_contact_flow_into_the_document_verbatim_chirho() {
        let completion_chirho = completion_of_chirho(
            StubLlmProviderChirho.complete_chirho(&request_chirho("Cedar Bakery")),
        );
        let doc_chirho: serde_json::Value =
            serde_json::from_str(&completion_chirho.completion_chirho).unwrap();
        assert_eq!(doc_chirho["business_name"], "Cedar Bakery");
        // The copy-exactly fields are carried verbatim, so the draft never drops the real contact.
        assert_eq!(doc_chirho["contact_phone"], "+1 (555) 010-2400");
        assert_eq!(doc_chirho["contact_email"], "hello@example.test");
        let services_chirho = doc_chirho["services"].as_array().unwrap();
        assert_eq!(services_chirho.len(), 2);
        assert_eq!(services_chirho[0]["title"], "first");
        assert!(doc_chirho["headline"]
            .as_str()
            .unwrap()
            .contains("Cedar Bakery"));
    }

    #[test]
    fn a_brief_with_no_labels_still_yields_a_valid_document_within_the_field_limits_chirho() {
        // An unguided brief falls back to safe defaults and never exceeds a clamp.
        let request_chirho = LlmRequestChirho {
            schema_chirho: LLM_REQUEST_SCHEMA_CHIRHO.to_string(),
            system_chirho: "You draft a small business landing page.".to_string(),
            user_chirho: "just some free text with no labels".to_string(),
            max_tokens_chirho: None,
            response_format_chirho: LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO.to_string(),
        };
        let completion_chirho =
            completion_of_chirho(StubLlmProviderChirho.complete_chirho(&request_chirho));
        let doc_chirho: serde_json::Value =
            serde_json::from_str(&completion_chirho.completion_chirho).unwrap();
        assert!(
            doc_chirho["business_name"]
                .as_str()
                .unwrap()
                .chars()
                .count()
                <= BUSINESS_NAME_MAX_CHIRHO
        );
        assert!(doc_chirho["summary"].as_str().unwrap().chars().count() <= SUMMARY_MAX_CHIRHO);
        assert_eq!(doc_chirho["contact_phone"], "");
        assert_eq!(doc_chirho["services"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_request_with_the_wrong_schema_or_format_refuses_before_a_provider_call_chirho() {
        let mut wrong_schema_chirho = request_chirho("A bakery");
        wrong_schema_chirho.schema_chirho = "llm-request-v2-chirho".to_string();
        assert_eq!(
            wrong_schema_chirho.validate_chirho(),
            Err(LlmRefusalCodeChirho::ResponseUnparseableChirho)
        );
        let mut wrong_format_chirho = request_chirho("A bakery");
        wrong_format_chirho.response_format_chirho = "free-text".to_string();
        assert_eq!(
            wrong_format_chirho.validate_chirho(),
            Err(LlmRefusalCodeChirho::ResponseUnparseableChirho)
        );
        assert!(matches!(
            StubLlmProviderChirho.complete_chirho(&wrong_format_chirho),
            LlmProviderOutcomeChirho::RefusedChirho(
                LlmRefusalCodeChirho::ResponseUnparseableChirho
            )
        ));
    }

    #[test]
    fn the_evidence_carries_no_prompt_or_completion_text_only_hashes_and_counts_chirho() {
        let request_chirho = request_chirho("A very distinctive brief phrase xyzzy");
        let completion_chirho =
            completion_of_chirho(StubLlmProviderChirho.complete_chirho(&request_chirho));
        let evidence_chirho = llm_evidence_chirho(&request_chirho, &completion_chirho);
        let serialized_chirho = serde_json::to_string(&evidence_chirho).unwrap();
        assert!(
            !serialized_chirho.contains("xyzzy"),
            "no prompt text in evidence"
        );
        assert!(
            !serialized_chirho.contains(&completion_chirho.completion_chirho),
            "no completion text in evidence"
        );
        // The public model label legitimately contains "stub-"; the real check is that the RAW
        // provider message id is absent, present only as its hash.
        assert!(
            !serialized_chirho.contains(&completion_chirho.provider_message_id_chirho),
            "no raw provider id in evidence, only its hash"
        );
        assert_eq!(evidence_chirho.prompt_hash_chirho.len(), 64);
        assert_eq!(evidence_chirho.completion_hash_chirho.len(), 64);
        assert_eq!(evidence_chirho.provider_message_id_hash_chirho.len(), 64);
    }

    #[test]
    fn the_three_wire_shapes_decode_strictly_and_the_refusal_codes_round_trip_chirho() {
        // Unknown fields are rejected on every wire shape (deny_unknown_fields).
        assert!(serde_json::from_str::<LlmRequestChirho>(
            r#"{"schema_chirho":"llm-request-v1-chirho","system_chirho":"s","user_chirho":"u","response_format_chirho":"json-object","extra_chirho":1}"#
        )
        .is_err());
        // Every refusal code round-trips through kebab-case serde.
        for code_chirho in [
            LlmRefusalCodeChirho::OverCeilingChirho,
            LlmRefusalCodeChirho::InsufficientCreditChirho,
            LlmRefusalCodeChirho::ProviderUnavailableChirho,
            LlmRefusalCodeChirho::TimeoutChirho,
            LlmRefusalCodeChirho::ResponseUnparseableChirho,
        ] {
            let body_chirho = LlmRefusalChirho::new_chirho(code_chirho);
            let text_chirho = serde_json::to_string(&body_chirho).unwrap();
            let back_chirho: LlmRefusalChirho = serde_json::from_str(&text_chirho).unwrap();
            assert_eq!(back_chirho.refusal_code_chirho, code_chirho);
            assert_eq!(back_chirho.schema_chirho, LLM_REFUSAL_SCHEMA_CHIRHO);
            assert!(!back_chirho.message_chirho.is_empty());
        }
    }
}
