// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The served spend-bounded LLM effect's CF3 money ladder over an injected provider port.
//!
//! Mirrors `postgres_reversible_chirho.rs`: the ordinary effect executor always supplies `None`, so
//! naming the `llm_chirho` paid-effect subtype never opens a provider by itself. A reviewed local or
//! host composition injects [`LlmServedRuntimePortChirho`]; the port receives only the already-admitted
//! signed contract and engine-derived invocation scope, and holds ONE [`LlmProviderChirho`] (the
//! deterministic stub now, a real adapter only under L.J.'s grant).
//!
//! Money law (boundary doc, Finding 1): a draft is priced as ONE FIXED per-call amount resolved from
//! the signed price book BEFORE the Hold (CF3's terminal carries no partial amount, so per-token
//! metering — and the per-token `OverCeiling` refusal — are a separate ledger-reviewed follow-on). A
//! completed draft Finalizes that price; a provider refusal maps to `DefiniteNoEffect` and Releases
//! the whole Hold (nothing charged). Same-intent-K idempotency (one Hold, one provider call, one
//! charge on a retry) is INHERITED from the coordinator + ledger adapter, proven by the reversible-
//! PostgreSQL money-conservation tests; this module does not re-implement it.
//!
//! Privacy (boundary doc ruling 4): the prompt rests as a viewer-subject private blob (the request
//! evidence); the completion rides the effect RESPONSE and rests sealed to its viewer via the effect
//! arm's `sealed_value_subject_chirho` (like a viewer-state read), never public CAS; the provider
//! evidence carries only counts, the model label, and hashes (`LlmEvidenceChirho`), never the prompt
//! or completion text.

use super::run_intent_chirho::{
    current_run_intent_effect_invocation_chirho, RunIntentEffectInvocationChirho,
};
use crate::blessed_chirho::EffectAdmissionChirho;
use crate::model_chirho::{CapabilityChirho, HashChirho, RequestContextChirho};
use account_evidence_chirho::AccountEvidenceChirho;
use anyhow::{bail, Context, Result};
use cairn_effect_commit_chirho::coordinator_chirho::{
    effect_provider_evidence_ref_chirho, BlessedEffectProviderPortChirho,
    EffectCommitCoordinatorChirho, EffectCommitEvidencePortChirho,
    EffectCommitJournalCompositionPortChirho, EffectCommitRunResultChirho,
    EffectEvidencePortErrorChirho, EffectProviderEvidenceBytesChirho,
    EffectProviderObservationChirho, EffectProviderPortErrorChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho,
    verify_effect_intent_line_chirho, EffectIntentChirho, EffectIntentSignerPortChirho,
    VerifiedEffectIntentChirho, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho;
use cairn_effect_commit_ledger_chirho::public_evidence_chirho::{
    PublicEffectEvidenceKindChirho, PublicEffectEvidenceRefusalChirho,
    RootPublicEffectEvidenceStoreChirho, EFFECT_COMMIT_EVIDENCE_DIRECTORY_CHIRHO,
    MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_llm_served_effect_chirho::{
    llm_evidence_chirho, LlmProviderChirho, LlmProviderOutcomeChirho, LlmRefusalChirho,
    LlmRefusalCodeChirho, LlmRequestChirho, LlmResponseChirho, LLM_RESPONSE_SCHEMA_CHIRHO,
};
use cairn_undo_plan_chirho::contract_chirho::{
    EffectPricingSourceRequirementChirho, EffectReconciliationRequirementChirho,
    EffectResultCachePostureChirho, LLM_SERVED_EFFECT_SUBTYPE_CHIRHO,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const LLM_PROVIDER_RESULT_REF_DOMAIN_CHIRHO: &[u8] =
    b"cairn-llm-served-provider-result-ref-v1-chirho";
const LLM_REQUEST_IDENTITY_REF_DOMAIN_CHIRHO: &[u8] =
    b"cairn-llm-served-request-identity-ref-v1-chirho";
static LLM_EVIDENCE_TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

/// What the served LLM effect returns to the effect arm: the response bytes plus, when a completion
/// was produced, the viewer subject the arm must seal it to (so the draft rests private). A refusal
/// body carries no PII, so its subject is `None`.
pub struct LlmServedEffectOutcomeChirho {
    pub response_chirho: Vec<u8>,
    pub private_subject_chirho: Option<String>,
}

/// Exact, engine-derived input to the injected LLM runtime. Fields stay private so a caller cannot
/// replace the admission token or invocation coordinate after the paid door checks.
pub struct LlmServedExecutionChirho<'execution_chirho> {
    root_chirho: &'execution_chirho Path,
    admission_chirho: &'execution_chirho EffectAdmissionChirho,
    request_context_chirho: &'execution_chirho RequestContextChirho,
    invocation_chirho: RunIntentEffectInvocationChirho,
    request_bytes_chirho: &'execution_chirho [u8],
}

impl<'execution_chirho> LlmServedExecutionChirho<'execution_chirho> {
    pub fn root_chirho(&self) -> &'execution_chirho Path {
        self.root_chirho
    }

    pub fn request_context_chirho(&self) -> &'execution_chirho RequestContextChirho {
        self.request_context_chirho
    }

    pub fn request_bytes_chirho(&self) -> &'execution_chirho [u8] {
        self.request_bytes_chirho
    }

    pub(crate) fn admission_chirho(&self) -> &'execution_chirho EffectAdmissionChirho {
        self.admission_chirho
    }
}

/// Injected provider composition. Implementations own provider, journal, signing, evidence, and
/// billing-kind wiring; this trait grants no defaults and performs no ambient lookup.
pub trait LlmServedRuntimePortChirho {
    fn execute_chirho(
        &mut self,
        execution_chirho: LlmServedExecutionChirho<'_>,
    ) -> Result<LlmServedEffectOutcomeChirho>;
}

/// Verified app-specific price and payer law. `UserPaysChirho` only for cohort 1 (boundary doc
/// ruling 2); policy-paid and subsidy modes refuse before intent until a signed policy is composed.
pub struct LlmServedMoneyPolicyChirho {
    price_book_chirho: HashChirho,
    amount_chirho: u64,
}

impl LlmServedMoneyPolicyChirho {
    pub fn new_chirho(price_book_chirho: HashChirho, amount_chirho: u64) -> Result<Self> {
        if amount_chirho == 0 {
            bail!("served LLM verified price must be positive");
        }
        Ok(Self {
            price_book_chirho,
            amount_chirho,
        })
    }
}

/// App-specific pricing authority. The app card and request cannot reach this port; local/host
/// composition must inject it explicitly and implementations must return a verified price-book ref.
pub trait LlmServedMoneyPolicyPortChirho {
    fn resolve_money_policy_chirho(
        &self,
        root_chirho: &Path,
        request_context_chirho: &RequestContextChirho,
        effect_chirho: &str,
    ) -> Result<LlmServedMoneyPolicyChirho>;
}

/// First retained pricing composition: the signed app price book is authoritative and the verified
/// request principal pays. The fixed per-call price is `effect_prices_chirho["llm_chirho"]`.
pub struct AppPriceBookUserPaysLlmPolicyChirho;

impl LlmServedMoneyPolicyPortChirho for AppPriceBookUserPaysLlmPolicyChirho {
    fn resolve_money_policy_chirho(
        &self,
        root_chirho: &Path,
        request_context_chirho: &RequestContextChirho,
        effect_chirho: &str,
    ) -> Result<LlmServedMoneyPolicyChirho> {
        let resolved_price_chirho = crate::effect_pricing_chirho::resolve_price_chirho(
            root_chirho,
            &request_context_chirho.app_chirho,
            effect_chirho,
        )?;
        let amount_chirho = u64::try_from(resolved_price_chirho.price_chirho)
            .ok()
            .filter(|amount_chirho| *amount_chirho > 0)
            .ok_or_else(|| anyhow::anyhow!("served LLM resolved price must be positive"))?;
        LlmServedMoneyPolicyChirho::new_chirho(
            resolved_price_chirho.price_book_chirho,
            amount_chirho,
        )
    }
}

/// Local-proof composition. Callers inject an already-open journal, signers, money policy, and the
/// one provider (the stub). It never creates journal genesis, kind policy, or key material.
pub struct LocalLlmServedCompositionChirho<'composition_chirho> {
    root_chirho: PathBuf,
    journal_chirho: &'composition_chirho mut dyn EffectCommitJournalCompositionPortChirho,
    intent_signer_chirho: &'composition_chirho dyn EffectIntentSignerPortChirho,
    terminal_signer_chirho: &'composition_chirho dyn EffectTerminalSignerPortChirho,
    money_policy_chirho: &'composition_chirho dyn LlmServedMoneyPolicyPortChirho,
    provider_chirho: &'composition_chirho dyn LlmProviderChirho,
    billing_kind_chirho: AssetKindIdChirho,
}

impl<'composition_chirho> LocalLlmServedCompositionChirho<'composition_chirho> {
    #[allow(clippy::too_many_arguments)]
    pub fn open_chirho(
        root_chirho: &Path,
        journal_chirho: &'composition_chirho mut dyn EffectCommitJournalCompositionPortChirho,
        intent_signer_chirho: &'composition_chirho dyn EffectIntentSignerPortChirho,
        terminal_signer_chirho: &'composition_chirho dyn EffectTerminalSignerPortChirho,
        money_policy_chirho: &'composition_chirho dyn LlmServedMoneyPolicyPortChirho,
        provider_chirho: &'composition_chirho dyn LlmProviderChirho,
        billing_kind_chirho: AssetKindIdChirho,
    ) -> Result<Self> {
        let continuation_chirho = journal_chirho
            .current_continuation_chirho(&billing_kind_chirho)
            .map_err(anyhow::Error::new)?
            .ok_or_else(|| {
                anyhow::Error::new(LlmServedActivationErrorChirho::BootstrapRefusedChirho {
                    detail_chirho: "served LLM billing kind has no current registry policy"
                        .to_owned(),
                })
            })?;
        if !continuation_chirho.settlement_owner_present_chirho {
            return Err(anyhow::Error::new(
                LlmServedActivationErrorChirho::BootstrapRefusedChirho {
                    detail_chirho: "served LLM billing kind has no settlement owner".to_owned(),
                },
            ));
        }
        Ok(Self {
            root_chirho: root_chirho.to_path_buf(),
            journal_chirho,
            intent_signer_chirho,
            terminal_signer_chirho,
            money_policy_chirho,
            provider_chirho,
            billing_kind_chirho,
        })
    }

    fn derived_intent_chirho(
        &self,
        execution_chirho: &LlmServedExecutionChirho<'_>,
        request_ref_chirho: DigestChirho,
    ) -> Result<EffectIntentChirho> {
        let admission_chirho = execution_chirho.admission_chirho();
        let contract_set_digest_chirho = admission_chirho
            .contract_set_digest_chirho()
            .ok_or_else(|| anyhow::anyhow!("served LLM admission lacks its contract-set digest"))?;
        let contract_digest_chirho = admission_chirho
            .contract_digest_chirho()
            .ok_or_else(|| anyhow::anyhow!("served LLM admission lacks its contract digest"))?;
        let door_chirho = admission_chirho
            .door_chirho()
            .ok_or_else(|| anyhow::anyhow!("served LLM admission lacks its door coordinate"))?;
        let context_chirho = execution_chirho.request_context_chirho();
        let money_policy_chirho = self
            .money_policy_chirho
            .resolve_money_policy_chirho(
                &self.root_chirho,
                context_chirho,
                LLM_SERVED_EFFECT_SUBTYPE_CHIRHO,
            )
            .map_err(|error_chirho| {
                anyhow::Error::new(LlmServedActivationErrorChirho::MoneyPolicyRefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                })
            })?;
        if context_chirho.price_book_chirho.as_ref() != Some(&money_policy_chirho.price_book_chirho)
        {
            return Err(anyhow::Error::new(
                LlmServedActivationErrorChirho::MoneyPolicyRefusedChirho {
                    detail_chirho: "request context does not bind the current verified price book"
                        .to_owned(),
                },
            ));
        }
        let continuation_chirho = self
            .journal_chirho
            .current_continuation_chirho(&self.billing_kind_chirho)
            .map_err(anyhow::Error::new)?
            .ok_or_else(|| anyhow::anyhow!("served LLM billing kind has no current policy"))?;
        if !continuation_chirho.settlement_owner_present_chirho {
            bail!("served LLM billing kind has no settlement owner");
        }
        // The served LLM money-obligation identity is WHO pays (user), for WHICH app, OWNED by whom.
        // token_hash + client_id are excluded (they rotate on a benign session/client refresh; see
        // `request_identity_ref_chirho`), so a legitimate same-payer retry deduplicates instead of
        // refusing as a coordinate conflict; the price is bound distinctly via evidence refs + price.
        let request_context_ref_chirho = request_identity_ref_chirho(context_chirho);
        let mut evidence_refs_chirho = BTreeSet::new();
        evidence_refs_chirho.insert(DigestChirho(money_policy_chirho.price_book_chirho.0));
        Ok(EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: self
                .journal_chirho
                .effect_intent_cut_chirho()
                .map_err(anyhow::Error::new)?,
            contract_set_digest_chirho: DigestChirho(contract_set_digest_chirho.0.clone()),
            door_chirho: door_chirho.clone(),
            reversion_contract_digest_chirho: DigestChirho(contract_digest_chirho.0.clone()),
            request_ref_chirho,
            request_context_ref_chirho,
            evidence_refs_chirho: evidence_refs_chirho.into_iter().collect(),
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: money_policy_chirho.amount_chirho,
                kind_id_chirho: self.billing_kind_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho(
                context_chirho.user_principal_chirho.clone(),
                self.billing_kind_chirho.clone(),
            ),
            effect_step_chirho: execution_chirho.invocation_chirho.effect_step_chirho,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: context_chirho.user_principal_chirho.clone(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        })
    }
}

impl LlmServedRuntimePortChirho for LocalLlmServedCompositionChirho<'_> {
    fn execute_chirho(
        &mut self,
        execution_chirho: LlmServedExecutionChirho<'_>,
    ) -> Result<LlmServedEffectOutcomeChirho> {
        if execution_chirho.root_chirho() != self.root_chirho {
            bail!("served LLM composition cannot be worn by another Cairn root");
        }
        // A malformed request never reaches a provider or a Hold: it is a typed refusal body.
        if serde_json::from_slice::<LlmRequestChirho>(execution_chirho.request_bytes_chirho())
            .ok()
            .filter(|request_chirho| request_chirho.validate_chirho().is_ok())
            .is_none()
        {
            return Ok(refusal_outcome_chirho(
                LlmRefusalCodeChirho::ResponseUnparseableChirho,
            ));
        }
        let request_ref_chirho = DigestChirho(
            blake3::hash(execution_chirho.request_bytes_chirho())
                .to_hex()
                .to_string(),
        );
        let candidate_chirho =
            self.derived_intent_chirho(&execution_chirho, request_ref_chirho.clone())?;
        let signed_candidate_chirho =
            sign_effect_intent_chirho(candidate_chirho, self.intent_signer_chirho)?;
        let candidate_line_chirho = canonical_effect_intent_line_chirho(&signed_candidate_chirho)?;
        // The prompt rests as the requesting user's own private blob before the intent binds its ref.
        let request_evidence_chirho = LlmServedRequestEvidenceChirho::new_chirho(
            &self.root_chirho,
            execution_chirho.request_context_chirho(),
        )?;
        let loaded_request_chirho = request_evidence_chirho
            .create_or_load_chirho(&request_ref_chirho, execution_chirho.request_bytes_chirho())?;
        if loaded_request_chirho != execution_chirho.request_bytes_chirho() {
            bail!("served LLM request ref already binds different private bytes");
        }
        let bound_line_chirho = create_or_load_invocation_intent_line_chirho(
            &self.root_chirho,
            &execution_chirho.invocation_chirho.invocation_ref_chirho,
            &candidate_line_chirho,
        )?;
        let verified_bound_chirho =
            verify_effect_intent_line_chirho(&bound_line_chirho, self.intent_signer_chirho)?;
        match classify_invocation_obligation_chirho(
            verified_bound_chirho.intent_chirho(),
            &signed_candidate_chirho,
        ) {
            InvocationObligationMatchChirho::SameChirho => {}
            InvocationObligationMatchChirho::IdentityConflictChirho => {
                return Err(anyhow::Error::new(
                    LlmServedActivationErrorChirho::InvocationObligationConflictChirho,
                ));
            }
            InvocationObligationMatchChirho::PriceChangedChirho => {
                return Err(anyhow::Error::new(
                    LlmServedActivationErrorChirho::InvocationPriceChangedChirho,
                ));
            }
        }

        let mut evidence_chirho = LlmServedEffectCommitEvidenceChirho::new_chirho(
            &self.root_chirho,
            execution_chirho.request_context_chirho(),
        )?;
        let mut provider_adapter_chirho = LlmBlessedProviderAdapterChirho::new_chirho(
            self.provider_chirho,
            execution_chirho.request_bytes_chirho(),
        );
        let commit_result_chirho = {
            let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
                &mut provider_adapter_chirho,
                &mut evidence_chirho,
                &mut *self.journal_chirho,
                self.intent_signer_chirho,
                self.terminal_signer_chirho,
            );
            coordinator_chirho.execute_chirho(&bound_line_chirho)?
            // coordinator dropped here, releasing its &mut of the provider adapter so we can read it
        };
        match commit_result_chirho {
            EffectCommitRunResultChirho::InDoubtChirho {
                intent_ref_chirho, ..
            } => Err(anyhow::Error::new(
                LlmServedActivationErrorChirho::InDoubtChirho { intent_ref_chirho },
            )),
            EffectCommitRunResultChirho::TerminalChirho { .. } => {
                match provider_adapter_chirho.take_outcome_chirho() {
                    Some(LlmProviderOutcomeChirho::CompletedChirho(completion_chirho)) => {
                        // The completion rides the response and is sealed to the requesting viewer.
                        let response_chirho = LlmResponseChirho {
                            schema_chirho: LLM_RESPONSE_SCHEMA_CHIRHO.to_owned(),
                            completion_chirho: completion_chirho.completion_chirho.clone(),
                            tokens_in_chirho: completion_chirho.tokens_in_chirho,
                            tokens_out_chirho: completion_chirho.tokens_out_chirho,
                            model_chirho: completion_chirho.model_chirho.clone(),
                            evidence_chirho: {
                                let request_chirho: LlmRequestChirho = serde_json::from_slice(
                                    execution_chirho.request_bytes_chirho(),
                                )?;
                                llm_evidence_chirho(&request_chirho, &completion_chirho)
                            },
                        };
                        Ok(LlmServedEffectOutcomeChirho {
                            response_chirho: serde_json::to_vec(&response_chirho)?,
                            private_subject_chirho: Some(
                                execution_chirho
                                    .request_context_chirho()
                                    .user_principal_chirho
                                    .clone(),
                            ),
                        })
                    }
                    Some(LlmProviderOutcomeChirho::RefusedChirho(code_chirho)) => {
                        Ok(refusal_outcome_chirho(code_chirho))
                    }
                    None => bail!("served LLM terminal without a recorded provider outcome"),
                }
            }
        }
    }
}

/// A typed refusal body the product renders as a sentence; carries no PII, so no seal subject.
fn refusal_outcome_chirho(code_chirho: LlmRefusalCodeChirho) -> LlmServedEffectOutcomeChirho {
    let body_chirho = LlmRefusalChirho::new_chirho(code_chirho);
    LlmServedEffectOutcomeChirho {
        response_chirho: serde_json::to_vec(&body_chirho).unwrap_or_default(),
        private_subject_chirho: None,
    }
}

/// The blessed provider adapter the coordinator drives. It wraps the injected [`LlmProviderChirho`]
/// and records the outcome so the composition can build the sealed response after the terminal.
struct LlmBlessedProviderAdapterChirho<'adapter_chirho> {
    provider_chirho: &'adapter_chirho dyn LlmProviderChirho,
    request_bytes_chirho: &'adapter_chirho [u8],
    outcome_chirho: Option<LlmProviderOutcomeChirho>,
}

impl<'adapter_chirho> LlmBlessedProviderAdapterChirho<'adapter_chirho> {
    fn new_chirho(
        provider_chirho: &'adapter_chirho dyn LlmProviderChirho,
        request_bytes_chirho: &'adapter_chirho [u8],
    ) -> Self {
        Self {
            provider_chirho,
            request_bytes_chirho,
            outcome_chirho: None,
        }
    }

    fn take_outcome_chirho(&mut self) -> Option<LlmProviderOutcomeChirho> {
        self.outcome_chirho.take()
    }

    fn observe_chirho(
        &mut self,
        intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        // The adapter holds the exact request bytes the composition sealed; re-hash them against the
        // signed intent before parsing, so a wrong request can never be metered against this intent.
        if blake3::hash(self.request_bytes_chirho).to_hex().to_string()
            != intent_chirho.intent_chirho().request_ref_chirho.0
        {
            return Err(EffectProviderPortErrorChirho::InvalidResponseChirho {
                detail_chirho: "served LLM request bytes do not match the signed request ref"
                    .to_owned(),
            });
        }
        let request_chirho: LlmRequestChirho = serde_json::from_slice(self.request_bytes_chirho)
            .map_err(
                |error_chirho| EffectProviderPortErrorChirho::InvalidResponseChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        match self.provider_chirho.complete_chirho(&request_chirho) {
            LlmProviderOutcomeChirho::CompletedChirho(completion_chirho) => {
                let evidence_chirho = llm_evidence_chirho(&request_chirho, &completion_chirho);
                let evidence_bytes_chirho =
                    serde_json::to_vec(&evidence_chirho).map_err(|error_chirho| {
                        EffectProviderPortErrorChirho::InvalidResponseChirho {
                            detail_chirho: error_chirho.to_string(),
                        }
                    })?;
                let result_ref_chirho =
                    llm_provider_result_ref_chirho(completion_chirho.completion_chirho.as_bytes());
                self.outcome_chirho =
                    Some(LlmProviderOutcomeChirho::CompletedChirho(completion_chirho));
                Ok(EffectProviderObservationChirho::CommittedChirho {
                    result_ref_chirho,
                    evidence_chirho: provider_evidence_chirho(evidence_bytes_chirho)?,
                })
            }
            LlmProviderOutcomeChirho::RefusedChirho(code_chirho) => {
                let evidence_bytes_chirho =
                    serde_json::to_vec(&LlmRefusalChirho::new_chirho(code_chirho)).map_err(
                        |error_chirho| EffectProviderPortErrorChirho::InvalidResponseChirho {
                            detail_chirho: error_chirho.to_string(),
                        },
                    )?;
                self.outcome_chirho = Some(LlmProviderOutcomeChirho::RefusedChirho(code_chirho));
                Ok(EffectProviderObservationChirho::DefiniteNoEffectChirho {
                    evidence_chirho: provider_evidence_chirho(evidence_bytes_chirho)?,
                })
            }
        }
    }
}

impl BlessedEffectProviderPortChirho for LlmBlessedProviderAdapterChirho<'_> {
    fn execute_or_replay_chirho(
        &mut self,
        intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        self.observe_chirho(intent_chirho)
    }

    fn query_by_key_chirho(
        &mut self,
        intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        // The stub is a deterministic pure function of the request, so replay re-derives the same
        // observation; a real provider would instead read its own store by the exact intent K.
        self.observe_chirho(intent_chirho)
    }
}

fn llm_provider_result_ref_chirho(completion_bytes_chirho: &[u8]) -> DigestChirho {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(LLM_PROVIDER_RESULT_REF_DOMAIN_CHIRHO);
    hasher_chirho.update(&(completion_bytes_chirho.len() as u64).to_be_bytes());
    hasher_chirho.update(completion_bytes_chirho);
    DigestChirho(hasher_chirho.finalize().to_hex().to_string())
}

fn provider_evidence_chirho(
    bytes_chirho: Vec<u8>,
) -> Result<EffectProviderEvidenceBytesChirho, EffectProviderPortErrorChirho> {
    EffectProviderEvidenceBytesChirho::new_chirho(bytes_chirho).map_err(|error_chirho| {
        EffectProviderPortErrorChirho::InvalidResponseChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

/// The served LLM money-obligation IDENTITY: a domain-separated, length-prefixed digest over ONLY
/// `user_principal + app + owner_principal` — WHO pays, for WHICH app, OWNED by whom. This is the
/// value a served LLM intent binds in the shared `request_context_ref_chirho` field (the reversible
/// PostgreSQL effect binds its own full context there instead; nothing shared re-derives either, so
/// narrowing what THIS effect binds is local and safe).
///
/// `token_hash` + `client_id` are DELIBERATELY EXCLUDED: they rotate on a benign session/client
/// refresh, and binding them would refuse a legitimate same-payer retry as an invocation conflict
/// (the S2d retry-dedup finding, claude2 #22618/#22620, confirmed @5e4d7efc). `price_book` +
/// `billing_policy` are excluded too: the price is bound by `evidence_refs_chirho` +
/// `resolved_price_chirho`, so a price re-version is caught by the obligation and reported with its
/// OWN identity, never conflated with a payer/app/owner conflict.
fn request_identity_ref_chirho(context_chirho: &RequestContextChirho) -> DigestChirho {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(LLM_REQUEST_IDENTITY_REF_DOMAIN_CHIRHO);
    for field_chirho in [
        context_chirho.user_principal_chirho.as_str(),
        context_chirho.app_chirho.as_str(),
        context_chirho.owner_principal_chirho.as_str(),
    ] {
        hasher_chirho.update(&(field_chirho.len() as u64).to_be_bytes());
        hasher_chirho.update(field_chirho.as_bytes());
    }
    DigestChirho(hasher_chirho.finalize().to_hex().to_string())
}

/// How a retry candidate relates to the obligation already bound at this invocation coordinate.
enum InvocationObligationMatchChirho {
    /// Field-for-field the same obligation — dedupe to the existing charge (one Hold, one charge).
    SameChirho,
    /// A DIFFERENT payer, app, owner, request, or structural coordinate is presented where another
    /// obligation is already bound — the money-AUTHORITY violation. Refuse loudly.
    IdentityConflictChirho,
    /// Same identity, same request, same coordinate, but the resolved PRICE moved (an operator
    /// price-book re-version between the first attempt and this retry). A benign version bump, not an
    /// impersonation: still refuse (never reuse a stale price), but say so DISTINCTLY so
    /// reconciliation handles it rather than an authority alarm.
    PriceChangedChirho,
}

/// Classify a retry candidate against the obligation loaded from this invocation coordinate.
///
/// IDENTITY and structural fields are compared FIRST, so an authority conflict is never masked by a
/// coincident price move; the pricing fields (`resolved_price_chirho` + `evidence_refs_chirho`, which
/// today carries only the price-book digest) are compared second. EVERY field is still compared — the
/// split changes only the refusal IDENTITY, never whether a mismatch refuses. At a fixed invocation
/// coordinate the structural fields (schema, journal genesis, door, contract digests, step) are
/// determined by run+node+step and cannot vary; they stay in the identity check as defense in depth.
fn classify_invocation_obligation_chirho(
    bound_chirho: &EffectIntentChirho,
    candidate_chirho: &EffectIntentChirho,
) -> InvocationObligationMatchChirho {
    let identity_matches_chirho = bound_chirho.schema_chirho == candidate_chirho.schema_chirho
        && bound_chirho
            .journal_cut_chirho
            .journal_genesis_digest_chirho
            == candidate_chirho
                .journal_cut_chirho
                .journal_genesis_digest_chirho
        && bound_chirho.contract_set_digest_chirho == candidate_chirho.contract_set_digest_chirho
        && bound_chirho.door_chirho == candidate_chirho.door_chirho
        && bound_chirho.reversion_contract_digest_chirho
            == candidate_chirho.reversion_contract_digest_chirho
        && bound_chirho.request_ref_chirho == candidate_chirho.request_ref_chirho
        && bound_chirho.request_context_ref_chirho == candidate_chirho.request_context_ref_chirho
        && bound_chirho.payer_account_chirho == candidate_chirho.payer_account_chirho
        && bound_chirho.effect_step_chirho == candidate_chirho.effect_step_chirho
        && bound_chirho.attribution_chirho == candidate_chirho.attribution_chirho
        && bound_chirho.original_effect_key_chirho == candidate_chirho.original_effect_key_chirho;
    if !identity_matches_chirho {
        return InvocationObligationMatchChirho::IdentityConflictChirho;
    }
    let price_matches_chirho = bound_chirho.resolved_price_chirho
        == candidate_chirho.resolved_price_chirho
        && bound_chirho.evidence_refs_chirho == candidate_chirho.evidence_refs_chirho;
    if !price_matches_chirho {
        return InvocationObligationMatchChirho::PriceChangedChirho;
    }
    InvocationObligationMatchChirho::SameChirho
}

#[derive(Debug)]
pub enum LlmServedActivationErrorChirho {
    ContractLawRefusedChirho { detail_chirho: String },
    CompositionUnavailableChirho,
    VerifiedContextUnavailableChirho,
    InvocationScopeUnavailableChirho,
    BootstrapRefusedChirho { detail_chirho: String },
    MoneyPolicyRefusedChirho { detail_chirho: String },
    InvocationObligationConflictChirho,
    InvocationPriceChangedChirho,
    InDoubtChirho { intent_ref_chirho: DigestChirho },
}

impl std::fmt::Display for LlmServedActivationErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContractLawRefusedChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "served LLM contract law refused: {detail_chirho}"
                )
            }
            Self::CompositionUnavailableChirho => {
                formatter_chirho.write_str("served LLM provider composition is not installed")
            }
            Self::VerifiedContextUnavailableChirho => formatter_chirho
                .write_str("served LLM paid door needs verified RequestContextChirho"),
            Self::InvocationScopeUnavailableChirho => formatter_chirho
                .write_str("served LLM paid door needs an active run-intent invocation scope"),
            Self::BootstrapRefusedChirho { detail_chirho } => write!(
                formatter_chirho,
                "served LLM bootstrap preflight refused before intent: {detail_chirho}"
            ),
            Self::MoneyPolicyRefusedChirho { detail_chirho } => write!(
                formatter_chirho,
                "served LLM verified money policy refused before intent: {detail_chirho}"
            ),
            Self::InvocationObligationConflictChirho => formatter_chirho.write_str(
                "served LLM invocation coordinate already binds a different verified obligation",
            ),
            Self::InvocationPriceChangedChirho => formatter_chirho.write_str(
                "served LLM invocation coordinate already bound at a different resolved price (a price-book re-version); reconcile rather than reuse",
            ),
            Self::InDoubtChirho { intent_ref_chirho } => write!(
                formatter_chirho,
                "served LLM provider outcome remains in-doubt for intent {}",
                intent_ref_chirho.0
            ),
        }
    }
}

impl std::error::Error for LlmServedActivationErrorChirho {}

/// Fail-closed adapter from the generic paid-effect executor into the served LLM ladder.
pub(crate) fn run_llm_served_chirho(
    root_chirho: &Path,
    admission_chirho: &EffectAdmissionChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    request_bytes_chirho: &[u8],
    runtime_chirho: Option<&mut dyn LlmServedRuntimePortChirho>,
) -> Result<LlmServedEffectOutcomeChirho> {
    if !matches!(
        admission_chirho.capability_chirho(),
        CapabilityChirho::PaidEffectChirho { effect_chirho, .. }
            if effect_chirho == LLM_SERVED_EFFECT_SUBTYPE_CHIRHO
    ) {
        return Err(anyhow::Error::new(
            LlmServedActivationErrorChirho::ContractLawRefusedChirho {
                detail_chirho: "admission does not name the served LLM subtype".to_owned(),
            },
        ));
    }
    if admission_chirho.reconciliation_requirement_chirho()
        != Some(&EffectReconciliationRequirementChirho::QueryByEffectKeyChirho)
        || admission_chirho.pricing_source_requirement_chirho()
            != Some(&EffectPricingSourceRequirementChirho::VerifiedPriceBookChirho)
        || admission_chirho.effect_result_cache_posture_chirho()
            != Some(&EffectResultCachePostureChirho::NeverReuseEffectResultChirho)
    {
        return Err(anyhow::Error::new(
            LlmServedActivationErrorChirho::ContractLawRefusedChirho {
                detail_chirho:
                    "signed contract lacks its exact reconciliation, pricing, or cache law"
                        .to_owned(),
            },
        ));
    }
    let runtime_chirho = runtime_chirho.ok_or_else(|| {
        anyhow::Error::new(LlmServedActivationErrorChirho::CompositionUnavailableChirho)
    })?;
    let request_context_chirho = request_context_chirho.ok_or_else(|| {
        anyhow::Error::new(LlmServedActivationErrorChirho::VerifiedContextUnavailableChirho)
    })?;
    let invocation_chirho = current_run_intent_effect_invocation_chirho().ok_or_else(|| {
        anyhow::Error::new(LlmServedActivationErrorChirho::InvocationScopeUnavailableChirho)
    })?;
    runtime_chirho.execute_chirho(LlmServedExecutionChirho {
        root_chirho,
        admission_chirho,
        request_context_chirho,
        invocation_chirho,
        request_bytes_chirho,
    })
}

// ---------------------------------------------------------------------------------------------------
// Evidence adapters (LOAN: minimal, over the generic public-evidence + private-blob stores; the
// forward-path effect-commit evidence adapter should be extracted and shared with
// postgres_reversible_chirho after S2 lands — recorded in the served-LLM tasklist).
// ---------------------------------------------------------------------------------------------------

/// The coordinator's evidence port for the served LLM effect. Public coordinates (intent + terminal
/// lines) go to the shared public-evidence store; the provider evidence (`LlmEvidenceChirho`, counts
/// and hashes, no PII) rests as a private blob. The LLM effect is compensation-free, so the
/// compensation method is a plain intent-line store.
struct LlmServedEffectCommitEvidenceChirho {
    root_chirho: PathBuf,
    account_evidence_chirho: AccountEvidenceChirho,
}

impl LlmServedEffectCommitEvidenceChirho {
    fn new_chirho(root_chirho: &Path, context_chirho: &RequestContextChirho) -> Result<Self> {
        Ok(Self {
            root_chirho: root_chirho.to_path_buf(),
            account_evidence_chirho: AccountEvidenceChirho::for_request_chirho(
                root_chirho,
                context_chirho,
            )?,
        })
    }
}

impl EffectCommitEvidencePortChirho for LlmServedEffectCommitEvidenceChirho {
    fn store_intent_line_chirho(
        &mut self,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        RootPublicEffectEvidenceStoreChirho::new_chirho(&self.root_chirho)
            .store_line_chirho(
                PublicEffectEvidenceKindChirho::IntentChirho,
                &intent_ref_chirho.0,
                canonical_line_chirho.as_bytes(),
            )
            .map_err(public_evidence_store_error_chirho)
    }

    fn load_intent_line_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<Option<String>, EffectEvidencePortErrorChirho> {
        RootPublicEffectEvidenceStoreChirho::new_chirho(&self.root_chirho)
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::IntentChirho,
                &intent_ref_chirho.0,
                MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
            )
            .map_err(public_evidence_load_error_chirho)?
            .map(String::from_utf8)
            .transpose()
            .map_err(evidence_unavailable_chirho)
    }

    fn create_or_load_compensation_intent_line_chirho(
        &mut self,
        _compensation_key_chirho: &str,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<String, EffectEvidencePortErrorChirho> {
        // The served LLM effect authors no compensation intents, so this reduces to storing the
        // intent line and returning it (the coordinator never drives it on the forward LLM path).
        self.store_intent_line_chirho(intent_ref_chirho, canonical_line_chirho)?;
        Ok(canonical_line_chirho.to_owned())
    }

    fn store_provider_evidence_chirho(
        &mut self,
        evidence_ref_chirho: &DigestChirho,
        evidence_bytes_chirho: &[u8],
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        validate_digest_chirho(&evidence_ref_chirho.0).map_err(evidence_unavailable_chirho)?;
        if effect_provider_evidence_ref_chirho(evidence_bytes_chirho) != *evidence_ref_chirho {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "provider evidence bytes do not match their content ref".to_owned(),
            });
        }
        let path_chirho = self
            .account_evidence_chirho
            .index_path_chirho("provider-chirho", &evidence_ref_chirho.0)
            .map_err(evidence_unavailable_chirho)?;
        let loaded_chirho = self
            .account_evidence_chirho
            .create_or_load_chirho(
                &path_chirho,
                "provider",
                &evidence_ref_chirho.0,
                evidence_bytes_chirho,
                "served LLM provider evidence",
            )
            .map_err(evidence_unavailable_chirho)?;
        if loaded_chirho != evidence_bytes_chirho {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "provider evidence ref already binds different private bytes"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn store_terminal_outcome_line_chirho(
        &mut self,
        outcome_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        RootPublicEffectEvidenceStoreChirho::new_chirho(&self.root_chirho)
            .store_line_chirho(
                PublicEffectEvidenceKindChirho::TerminalChirho,
                &outcome_ref_chirho.0,
                canonical_line_chirho.as_bytes(),
            )
            .map_err(public_evidence_store_error_chirho)
    }
}

/// The prompt bytes for one served LLM request, stored as the requesting user's own private blob and
/// indexed only by opaque ref under that user's account (never the prompt text in the index).
struct LlmServedRequestEvidenceChirho {
    account_evidence_chirho: AccountEvidenceChirho,
}

impl LlmServedRequestEvidenceChirho {
    fn new_chirho(root_chirho: &Path, context_chirho: &RequestContextChirho) -> Result<Self> {
        Ok(Self {
            account_evidence_chirho: AccountEvidenceChirho::for_request_chirho(
                root_chirho,
                context_chirho,
            )?,
        })
    }

    fn create_or_load_chirho(
        &self,
        request_ref_chirho: &DigestChirho,
        request_bytes_chirho: &[u8],
    ) -> Result<Vec<u8>> {
        validate_digest_chirho(&request_ref_chirho.0)?;
        if blake3::hash(request_bytes_chirho).to_hex().as_str() != request_ref_chirho.0 {
            bail!("served LLM request bytes do not match their content ref");
        }
        let path_chirho = self
            .account_evidence_chirho
            .index_path_chirho("requests-chirho", &request_ref_chirho.0)?;
        let loaded_chirho = self.account_evidence_chirho.create_or_load_chirho(
            &path_chirho,
            "request",
            &request_ref_chirho.0,
            request_bytes_chirho,
            "served LLM request evidence",
        )?;
        if blake3::hash(&loaded_chirho).to_hex().as_str() != request_ref_chirho.0 {
            bail!("stored served LLM request evidence does not match its ref");
        }
        Ok(loaded_chirho)
    }
}

fn create_or_load_invocation_intent_line_chirho(
    root_chirho: &Path,
    invocation_ref_chirho: &HashChirho,
    proposed_line_chirho: &str,
) -> Result<String> {
    validate_digest_chirho(&invocation_ref_chirho.0)?;
    let path_chirho =
        llm_evidence_path_chirho(root_chirho, "invocations-chirho", &invocation_ref_chirho.0)?;
    let loaded_chirho = create_or_load_bytes_chirho(&path_chirho, proposed_line_chirho.as_bytes())?;
    String::from_utf8(loaded_chirho).context("decode invocation-bound signed intent line")
}

fn llm_evidence_path_chirho(
    root_chirho: &Path,
    family_chirho: &str,
    coordinate_chirho: &str,
) -> Result<PathBuf> {
    validate_digest_chirho(coordinate_chirho)?;
    Ok(root_chirho
        .join(EFFECT_COMMIT_EVIDENCE_DIRECTORY_CHIRHO)
        .join("llm-served-chirho")
        .join(family_chirho)
        .join(format!("{coordinate_chirho}.json")))
}

fn validate_digest_chirho(value_chirho: &str) -> Result<()> {
    if value_chirho.len() != 64
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
    {
        bail!("served LLM evidence coordinate must be a 64-byte lowercase hex digest");
    }
    Ok(())
}

fn create_or_load_bytes_chirho(path_chirho: &Path, proposed_chirho: &[u8]) -> Result<Vec<u8>> {
    if path_chirho.exists() {
        return fs::read(path_chirho).with_context(|| format!("read {}", path_chirho.display()));
    }
    let parent_chirho = path_chirho
        .parent()
        .ok_or_else(|| anyhow::anyhow!("served LLM evidence path has no parent"))?;
    fs::create_dir_all(parent_chirho)?;
    let counter_chirho = LLM_EVIDENCE_TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let temp_chirho = parent_chirho.join(format!(
        ".candidate-chirho-{}-{counter_chirho}",
        std::process::id()
    ));
    crate::durable_chirho::write_file_durable_chirho(&temp_chirho, proposed_chirho)?;
    match fs::hard_link(&temp_chirho, path_chirho) {
        Ok(()) => crate::durable_chirho::fsync_dir_chirho(parent_chirho)?,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error_chirho) => {
            let _ = fs::remove_file(&temp_chirho);
            return Err(error_chirho.into());
        }
    }
    let _ = fs::remove_file(&temp_chirho);
    fs::read(path_chirho).with_context(|| format!("read {}", path_chirho.display()))
}

fn evidence_unavailable_chirho(
    error_chirho: impl std::fmt::Display,
) -> EffectEvidencePortErrorChirho {
    EffectEvidencePortErrorChirho::UnavailableChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

fn public_evidence_load_error_chirho(
    error_chirho: PublicEffectEvidenceRefusalChirho,
) -> EffectEvidencePortErrorChirho {
    evidence_unavailable_chirho(error_chirho)
}

fn public_evidence_store_error_chirho(
    error_chirho: PublicEffectEvidenceRefusalChirho,
) -> EffectEvidencePortErrorChirho {
    match &error_chirho {
        PublicEffectEvidenceRefusalChirho::InvalidCoordinateChirho
        | PublicEffectEvidenceRefusalChirho::OversizedLineChirho
        | PublicEffectEvidenceRefusalChirho::ImmutableCollisionChirho => {
            EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: error_chirho.to_string(),
            }
        }
        PublicEffectEvidenceRefusalChirho::UnavailableChirho { .. } => {
            evidence_unavailable_chirho(error_chirho)
        }
    }
}

#[path = "llm_served_chirho/account_evidence_chirho.rs"]
mod account_evidence_chirho;

#[cfg(test)]
#[path = "llm_served_chirho/account_evidence_tests_chirho.rs"]
mod account_evidence_tests_chirho;

#[cfg(test)]
#[path = "llm_served_chirho/tests_chirho.rs"]
mod tests_chirho;
