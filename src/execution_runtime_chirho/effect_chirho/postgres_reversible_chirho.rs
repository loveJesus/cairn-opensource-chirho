// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Descriptor-D's explicit reversible-PostgreSQL composition seam.
//!
//! The ordinary effect executor always supplies `None`, so registering a descriptor or carrying a
//! matching capability never opens PostgreSQL by itself. A reviewed local or host composition must
//! inject this port; the port receives only the already-admitted signed contract and engine-derived
//! invocation scope. The first local composition is intentionally reviewed-but-uncomposed for the
//! hosted serve root.

use super::run_intent_chirho::{
    current_run_intent_effect_invocation_chirho, RunIntentEffectInvocationChirho,
};
use crate::blessed_chirho::EffectAdmissionChirho;
use crate::model_chirho::{CapabilityChirho, HashChirho, RequestContextChirho};
use anyhow::{bail, Result};
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitCoordinatorChirho, EffectCommitCoordinatorErrorChirho,
    EffectCommitJournalCommittedEvidenceIdentityChirho, EffectCommitJournalCompositionPortChirho,
    EffectCommitRunResultChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho,
    verify_effect_intent_line_chirho, EffectIntentChirho, EffectIntentSignerPortChirho,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
pub use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalDispositionChirho;
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho;
#[cfg(test)]
use cairn_effect_commit_ledger_chirho::LedgerEffectCommitAdapterChirho;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, HlcChirho};
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_postgres_effect_chirho::ports_chirho::ReversiblePostgresDatabasePortChirho;
use cairn_postgres_effect_chirho::{AdapterEvidenceKeyChirho, ReversiblePostgresProviderChirho};
use cairn_undo_plan_chirho::contract_chirho::{
    EffectPricingSourceRequirementChirho, EffectReconciliationRequirementChirho,
    EffectResultCachePostureChirho, POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[path = "postgres_reversible_chirho/compensation_authority_chirho.rs"]
mod compensation_authority_chirho;
#[path = "postgres_reversible_chirho/compensation_execution_chirho.rs"]
mod compensation_execution_chirho;
#[path = "postgres_reversible_chirho/evidence_chirho.rs"]
mod evidence_chirho;

pub use compensation_authority_chirho::{
    mint_verified_current_undo_plan_authority_chirho, CurrentPostgresCompensationPreviewChirho,
    CurrentPostgresCompensationPreviewVerdictChirho, VerifiedCurrentUndoPlanAuthorityChirho,
    VerifiedCurrentUndoPlanAuthorityErrorChirho,
};
pub use compensation_execution_chirho::CurrentPostgresCompensationExecutionChirho;

use evidence_chirho::{
    create_or_load_invocation_intent_line_chirho, RootEffectCommitEvidenceChirho,
    RootPostgresPrivateEvidenceChirho, RootPostgresRequestEvidenceChirho,
};

pub const ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO: &str = "adapter-evidence-key-chirho";
const POSTGRES_EFFECT_RESPONSE_SCHEMA_CHIRHO: &str =
    "descriptor-d-postgres-effect-response-v1-chirho";
const COMMITTED_EVIDENCE_PENDING_LOG_PREFIX_CHIRHO: &str =
    "CairnResidentCommittedEvidencePendingChirho";

enum CommittedEvidencePendingLogSinkChirho {
    StderrChirho,
    #[cfg(test)]
    CaptureChirho(std::sync::Arc<std::sync::Mutex<Vec<String>>>),
}

impl CommittedEvidencePendingLogSinkChirho {
    fn emit_chirho(&self, identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho) {
        let line_chirho = format!(
            "{COMMITTED_EVIDENCE_PENDING_LOG_PREFIX_CHIRHO}:identity_chirho={}",
            identity_chirho.as_str_chirho()
        );
        match self {
            Self::StderrChirho => eprintln!("{line_chirho}"),
            #[cfg(test)]
            Self::CaptureChirho(lines_chirho) => lines_chirho
                .lock()
                .expect("capture committed-evidence origin")
                .push(line_chirho),
        }
    }
}

/// Exact, engine-derived input to the injected Descriptor-D runtime. Fields stay private so a
/// caller cannot replace the admission token or invocation coordinate after the paid door checks.
pub struct PostgresReversibleExecutionChirho<'execution_chirho> {
    root_chirho: &'execution_chirho Path,
    admission_chirho: &'execution_chirho EffectAdmissionChirho,
    request_context_chirho: &'execution_chirho RequestContextChirho,
    invocation_chirho: RunIntentEffectInvocationChirho,
    request_bytes_chirho: &'execution_chirho [u8],
}

impl<'execution_chirho> PostgresReversibleExecutionChirho<'execution_chirho> {
    pub fn root_chirho(&self) -> &'execution_chirho Path {
        self.root_chirho
    }

    pub fn request_context_chirho(&self) -> &'execution_chirho RequestContextChirho {
        self.request_context_chirho
    }

    pub fn invocation_ref_chirho(&self) -> &crate::model_chirho::HashChirho {
        &self.invocation_chirho.invocation_ref_chirho
    }

    pub fn run_chirho(&self) -> &crate::model_chirho::HashChirho {
        &self.invocation_chirho.run_chirho
    }

    pub fn node_chirho(&self) -> &crate::model_chirho::HashChirho {
        &self.invocation_chirho.node_chirho
    }

    pub fn effect_step_chirho(&self) -> u32 {
        self.invocation_chirho.effect_step_chirho
    }

    pub fn request_bytes_chirho(&self) -> &'execution_chirho [u8] {
        self.request_bytes_chirho
    }

    pub(crate) fn admission_chirho(&self) -> &'execution_chirho EffectAdmissionChirho {
        self.admission_chirho
    }
}

/// Injected provider composition. Implementations own provider, journal, signing, evidence, and
/// custody wiring; this trait grants no defaults and performs no ambient lookup.
pub trait PostgresReversibleRuntimePortChirho {
    fn execute_chirho(
        &mut self,
        execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> Result<Vec<u8>>;
}

/// Root-owned payer mode returned by the injected money-policy authority. No variant carries a
/// principal: the paid door derives principals only from the already-verified request context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostgresReversiblePayerModeChirho {
    /// The verified request principal pays and attribution is `CauserChirho`.
    UserPaysChirho,
    /// The verified app owner pays under the returned signed policy ref.
    PolicyOwnerPaysChirho,
    /// The verified request principal pays under the returned signed policy ref (for example,
    /// subsidy fall-through); attribution remains the policy, so payer equality stays independent.
    PolicyUserPaysChirho,
}

/// Verified app-specific price and payer law. Construction is validated, while verification of
/// the returned refs belongs to the injection-only composition port that produced it.
pub struct PostgresReversibleMoneyPolicyChirho {
    price_book_chirho: HashChirho,
    billing_policy_chirho: Option<HashChirho>,
    amount_chirho: u64,
    payer_mode_chirho: PostgresReversiblePayerModeChirho,
}

impl PostgresReversibleMoneyPolicyChirho {
    pub fn new_chirho(
        price_book_chirho: HashChirho,
        billing_policy_chirho: Option<HashChirho>,
        amount_chirho: u64,
        payer_mode_chirho: PostgresReversiblePayerModeChirho,
    ) -> Result<Self> {
        if amount_chirho == 0 {
            bail!("Descriptor-D verified price must be positive");
        }
        if matches!(
            payer_mode_chirho,
            PostgresReversiblePayerModeChirho::PolicyOwnerPaysChirho
                | PostgresReversiblePayerModeChirho::PolicyUserPaysChirho
        ) && billing_policy_chirho.is_none()
        {
            bail!("Descriptor-D policy-paid mode needs a verified policy ref");
        }
        Ok(Self {
            price_book_chirho,
            billing_policy_chirho,
            amount_chirho,
            payer_mode_chirho,
        })
    }
}

/// App-specific pricing and payer authority. The app card and request cannot reach this port;
/// local/host composition must inject it explicitly and implementations must return verified refs.
pub trait PostgresReversibleMoneyPolicyPortChirho {
    fn resolve_money_policy_chirho(
        &self,
        root_chirho: &Path,
        request_context_chirho: &RequestContextChirho,
        effect_chirho: &str,
    ) -> Result<PostgresReversibleMoneyPolicyChirho>;
}

/// First retained pricing composition: the signed app price book is authoritative and the
/// verified request principal pays. App-paid/subsidy modes remain unavailable until a retained
/// signed policy implementation is composed; absence never infers them.
pub struct AppPriceBookUserPaysPolicyChirho;

impl PostgresReversibleMoneyPolicyPortChirho for AppPriceBookUserPaysPolicyChirho {
    fn resolve_money_policy_chirho(
        &self,
        root_chirho: &Path,
        request_context_chirho: &RequestContextChirho,
        effect_chirho: &str,
    ) -> Result<PostgresReversibleMoneyPolicyChirho> {
        let resolved_price_chirho = crate::effect_pricing_chirho::resolve_price_chirho(
            root_chirho,
            &request_context_chirho.app_chirho,
            effect_chirho,
        )?;
        let amount_chirho = u64::try_from(resolved_price_chirho.price_chirho)
            .ok()
            .filter(|amount_chirho| *amount_chirho > 0)
            .ok_or_else(|| anyhow::anyhow!("Descriptor-D resolved price must be positive"))?;
        PostgresReversibleMoneyPolicyChirho::new_chirho(
            resolved_price_chirho.price_book_chirho,
            None,
            amount_chirho,
            PostgresReversiblePayerModeChirho::UserPaysChirho,
        )
    }
}

/// Local-proof composition. It is open-only: callers inject an already-open journal and database,
/// while the constructor resolves the one real evidence key through Cairn's secret store. It never
/// creates journal genesis, kind policy, PostgreSQL schema, or key material.
pub struct LocalPostgresEffectCompositionChirho<'composition_chirho, DatabaseChirho> {
    root_chirho: PathBuf,
    journal_chirho: &'composition_chirho mut dyn EffectCommitJournalCompositionPortChirho,
    database_chirho: &'composition_chirho mut DatabaseChirho,
    intent_signer_chirho: &'composition_chirho dyn EffectIntentSignerPortChirho,
    terminal_signer_chirho: &'composition_chirho dyn EffectTerminalSignerPortChirho,
    money_policy_chirho: &'composition_chirho dyn PostgresReversibleMoneyPolicyPortChirho,
    evidence_key_chirho: AdapterEvidenceKeyChirho,
    billing_kind_chirho: AssetKindIdChirho,
    committed_evidence_log_sink_chirho: CommittedEvidencePendingLogSinkChirho,
}

impl<'composition_chirho, DatabaseChirho>
    LocalPostgresEffectCompositionChirho<'composition_chirho, DatabaseChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
{
    /// Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/README-chirho.md`.
    pub fn open_chirho(
        root_chirho: &Path,
        journal_chirho: &'composition_chirho mut dyn EffectCommitJournalCompositionPortChirho,
        database_chirho: &'composition_chirho mut DatabaseChirho,
        intent_signer_chirho: &'composition_chirho dyn EffectIntentSignerPortChirho,
        terminal_signer_chirho: &'composition_chirho dyn EffectTerminalSignerPortChirho,
        money_policy_chirho: &'composition_chirho dyn PostgresReversibleMoneyPolicyPortChirho,
        billing_kind_chirho: AssetKindIdChirho,
    ) -> Result<Self> {
        database_chirho
            .verify_schema_ready_chirho()
            .map_err(|error_chirho| {
                anyhow::Error::new(
                    PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )
            })?;
        let continuation_chirho = journal_chirho
            .current_continuation_chirho(&billing_kind_chirho)
            .map_err(|error_chirho| {
                anyhow::Error::new(
                    PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )
            })?
            .ok_or_else(|| {
                anyhow::Error::new(
                    PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho {
                        detail_chirho: "Descriptor-D billing kind has no current registry policy"
                            .to_owned(),
                    },
                )
            })?;
        if !continuation_chirho.settlement_owner_present_chirho {
            return Err(anyhow::Error::new(
                PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho {
                    detail_chirho: "Descriptor-D billing kind has no settlement owner".to_owned(),
                },
            ));
        }
        let evidence_key_chirho =
            load_adapter_evidence_key_chirho(root_chirho).map_err(|error_chirho| {
                anyhow::Error::new(
                    PostgresReversibleActivationErrorChirho::CustodyUnavailableChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )
            })?;
        Ok(Self {
            root_chirho: root_chirho.to_path_buf(),
            journal_chirho,
            database_chirho,
            intent_signer_chirho,
            terminal_signer_chirho,
            money_policy_chirho,
            evidence_key_chirho,
            billing_kind_chirho,
            committed_evidence_log_sink_chirho: CommittedEvidencePendingLogSinkChirho::StderrChirho,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_committed_evidence_log_capture_chirho(
        mut self,
        lines_chirho: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> Self {
        self.committed_evidence_log_sink_chirho =
            CommittedEvidencePendingLogSinkChirho::CaptureChirho(lines_chirho);
        self
    }
}

impl<DatabaseChirho> PostgresReversibleRuntimePortChirho
    for LocalPostgresEffectCompositionChirho<'_, DatabaseChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
{
    /// Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/README-chirho.md`.
    fn execute_chirho(
        &mut self,
        execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> Result<Vec<u8>> {
        if execution_chirho.root_chirho() != self.root_chirho {
            bail!("Descriptor-D composition cannot be worn by another Cairn root");
        }
        self.database_chirho
            .verify_schema_ready_chirho()
            .map_err(|error_chirho| {
                anyhow::Error::new(
                    PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )
            })?;
        let _request_chirho = cairn_postgres_effect_chirho::parse_canonical_request_chirho(
            execution_chirho.request_bytes_chirho(),
        )?;
        let request_ref_chirho = DigestChirho(
            blake3::hash(execution_chirho.request_bytes_chirho())
                .to_hex()
                .to_string(),
        );
        // Money policy is a deterministic composition preflight. Refuse it before request
        // evidence or an effect intent exists, preserving the open-only bootstrap law.
        let candidate_chirho =
            self.derived_intent_chirho(&execution_chirho, request_ref_chirho.clone())?;
        let signed_candidate_chirho =
            sign_effect_intent_chirho(candidate_chirho, self.intent_signer_chirho)?;
        let candidate_line_chirho = canonical_effect_intent_line_chirho(&signed_candidate_chirho)?;
        let request_evidence_chirho =
            RootPostgresRequestEvidenceChirho::new_chirho(&self.root_chirho);
        let loaded_request_chirho = request_evidence_chirho
            .create_or_load_chirho(&request_ref_chirho, execution_chirho.request_bytes_chirho())?;
        if loaded_request_chirho != execution_chirho.request_bytes_chirho() {
            bail!("Descriptor-D request ref already binds different private bytes");
        }
        let bound_line_chirho = create_or_load_invocation_intent_line_chirho(
            &self.root_chirho,
            execution_chirho.invocation_ref_chirho(),
            &candidate_line_chirho,
        )?;
        let verified_bound_chirho =
            verify_effect_intent_line_chirho(&bound_line_chirho, self.intent_signer_chirho)?;
        if !same_invocation_obligation_chirho(
            verified_bound_chirho.intent_chirho(),
            &signed_candidate_chirho,
        ) {
            return Err(anyhow::Error::new(
                PostgresReversibleActivationErrorChirho::InvocationObligationConflictChirho,
            ));
        }

        let mut private_evidence_chirho =
            RootPostgresPrivateEvidenceChirho::new_chirho(&self.root_chirho);
        let mut effect_evidence_chirho =
            RootEffectCommitEvidenceChirho::new_chirho(&self.root_chirho);
        let mut provider_chirho = ReversiblePostgresProviderChirho::new_chirho(
            &mut *self.database_chirho,
            &mut private_evidence_chirho,
            &request_evidence_chirho,
            &self.evidence_key_chirho,
        );
        let committed_evidence_log_sink_chirho = &self.committed_evidence_log_sink_chirho;
        let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut effect_evidence_chirho,
            &mut *self.journal_chirho,
            self.intent_signer_chirho,
            self.terminal_signer_chirho,
        );
        let commit_result_chirho = coordinator_chirho
            .execute_chirho(&bound_line_chirho)
            .inspect_err(|error_chirho| {
                if let EffectCommitCoordinatorErrorChirho::JournalCommittedEvidencePendingChirho {
                    identity_chirho,
                    ..
                } = &error_chirho
                {
                    committed_evidence_log_sink_chirho.emit_chirho(*identity_chirho);
                }
            })?;
        match commit_result_chirho {
            EffectCommitRunResultChirho::InDoubtChirho {
                intent_ref_chirho,
                hold_receipt_chirho,
            } => Err(anyhow::Error::new(
                PostgresReversibleActivationErrorChirho::InDoubtChirho {
                    intent_ref_chirho,
                    hold_seq_chirho: hold_receipt_chirho.seq_chirho,
                },
            )),
            EffectCommitRunResultChirho::TerminalChirho {
                intent_ref_chirho,
                hold_receipt_chirho,
                terminal_receipt_chirho,
                outcome_ref_chirho,
                disposition_chirho,
            } => serde_json::to_vec(&PostgresEffectResponseChirho {
                schema_chirho: POSTGRES_EFFECT_RESPONSE_SCHEMA_CHIRHO.to_owned(),
                intent_ref_chirho,
                hold_seq_chirho: hold_receipt_chirho.seq_chirho,
                hold_record_digest_chirho: hold_receipt_chirho.record_digest_chirho,
                hold_hlc_chirho: hold_receipt_chirho.hlc_chirho,
                terminal_seq_chirho: terminal_receipt_chirho.seq_chirho,
                terminal_record_digest_chirho: terminal_receipt_chirho.record_digest_chirho,
                terminal_hlc_chirho: terminal_receipt_chirho.hlc_chirho,
                outcome_ref_chirho,
                disposition_chirho,
            })
            .map_err(Into::into),
        }
    }
}

impl<DatabaseChirho> LocalPostgresEffectCompositionChirho<'_, DatabaseChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
{
    /// Reconcile every live CF3 Hold through the provider's query-by-K contract. This is an
    /// operator/composition loop, never an app-selectable effect mode.
    /// Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/README-chirho.md`.
    pub fn reconcile_all_in_doubt_chirho(&mut self) -> Result<Vec<EffectCommitRunResultChirho>> {
        self.database_chirho
            .verify_schema_ready_chirho()
            .map_err(|error_chirho| {
                anyhow::Error::new(
                    PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )
            })?;
        let request_evidence_chirho =
            RootPostgresRequestEvidenceChirho::new_chirho(&self.root_chirho);
        let mut private_evidence_chirho =
            RootPostgresPrivateEvidenceChirho::new_chirho(&self.root_chirho);
        let mut effect_evidence_chirho =
            RootEffectCommitEvidenceChirho::new_chirho(&self.root_chirho);
        let mut provider_chirho = ReversiblePostgresProviderChirho::new_chirho(
            &mut *self.database_chirho,
            &mut private_evidence_chirho,
            &request_evidence_chirho,
            &self.evidence_key_chirho,
        );
        let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut effect_evidence_chirho,
            &mut *self.journal_chirho,
            self.intent_signer_chirho,
            self.terminal_signer_chirho,
        );
        coordinator_chirho
            .reconcile_all_in_doubt_chirho()
            .map_err(Into::into)
    }

    fn derived_intent_chirho(
        &self,
        execution_chirho: &PostgresReversibleExecutionChirho<'_>,
        request_ref_chirho: DigestChirho,
    ) -> Result<EffectIntentChirho> {
        let admission_chirho = execution_chirho.admission_chirho();
        let contract_set_digest_chirho =
            admission_chirho
                .contract_set_digest_chirho()
                .ok_or_else(|| {
                    anyhow::anyhow!("Descriptor-D admission lacks its contract-set digest")
                })?;
        let contract_digest_chirho = admission_chirho
            .contract_digest_chirho()
            .ok_or_else(|| anyhow::anyhow!("Descriptor-D admission lacks its contract digest"))?;
        let door_chirho = admission_chirho
            .door_chirho()
            .ok_or_else(|| anyhow::anyhow!("Descriptor-D admission lacks its door coordinate"))?;
        let context_chirho = execution_chirho.request_context_chirho();
        let money_policy_chirho = self
            .money_policy_chirho
            .resolve_money_policy_chirho(
                &self.root_chirho,
                context_chirho,
                POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO,
            )
            .map_err(|error_chirho| {
                anyhow::Error::new(
                    PostgresReversibleActivationErrorChirho::MoneyPolicyRefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )
            })?;
        if context_chirho.price_book_chirho.as_ref() != Some(&money_policy_chirho.price_book_chirho)
            || context_chirho.billing_policy_chirho != money_policy_chirho.billing_policy_chirho
        {
            return Err(anyhow::Error::new(
                PostgresReversibleActivationErrorChirho::MoneyPolicyRefusedChirho {
                    detail_chirho:
                        "request context does not bind the current verified price and payer law"
                            .to_owned(),
                },
            ));
        }
        let continuation_chirho = self
            .journal_chirho
            .current_continuation_chirho(&self.billing_kind_chirho)
            .map_err(anyhow::Error::new)?
            .ok_or_else(|| anyhow::anyhow!("Descriptor-D billing kind has no current policy"))?;
        if !continuation_chirho.settlement_owner_present_chirho {
            bail!("Descriptor-D billing kind has no settlement owner");
        }
        let (payer_principal_chirho, attribution_chirho) =
            match money_policy_chirho.payer_mode_chirho {
                PostgresReversiblePayerModeChirho::UserPaysChirho => (
                    context_chirho.user_principal_chirho.clone(),
                    AttributionChirho::CauserChirho {
                        principal_chirho: context_chirho.user_principal_chirho.clone(),
                    },
                ),
                PostgresReversiblePayerModeChirho::PolicyOwnerPaysChirho => {
                    let policy_chirho = money_policy_chirho
                        .billing_policy_chirho
                        .as_ref()
                        .ok_or_else(|| {
                            anyhow::Error::new(
                                PostgresReversibleActivationErrorChirho::MoneyPolicyRefusedChirho {
                                    detail_chirho:
                                        "policy-owner payer mode lacks its verified policy ref"
                                            .to_owned(),
                                },
                            )
                        })?;
                    (
                        context_chirho.owner_principal_chirho.clone(),
                        AttributionChirho::PolicyChirho {
                            policy_ref_chirho: DigestChirho(policy_chirho.0.clone()),
                        },
                    )
                }
                PostgresReversiblePayerModeChirho::PolicyUserPaysChirho => {
                    let policy_chirho = money_policy_chirho
                        .billing_policy_chirho
                        .as_ref()
                        .ok_or_else(|| {
                            anyhow::Error::new(
                                PostgresReversibleActivationErrorChirho::MoneyPolicyRefusedChirho {
                                    detail_chirho:
                                        "policy-user payer mode lacks its verified policy ref"
                                            .to_owned(),
                                },
                            )
                        })?;
                    (
                        context_chirho.user_principal_chirho.clone(),
                        AttributionChirho::PolicyChirho {
                            policy_ref_chirho: DigestChirho(policy_chirho.0.clone()),
                        },
                    )
                }
            };
        let request_context_ref_chirho = DigestChirho(
            blake3::hash(&serde_json::to_vec(context_chirho)?)
                .to_hex()
                .to_string(),
        );
        let mut evidence_refs_chirho = BTreeSet::new();
        evidence_refs_chirho.insert(DigestChirho(money_policy_chirho.price_book_chirho.0));
        if let Some(policy_chirho) = money_policy_chirho.billing_policy_chirho {
            evidence_refs_chirho.insert(DigestChirho(policy_chirho.0));
        }
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
                payer_principal_chirho,
                self.billing_kind_chirho.clone(),
            ),
            effect_step_chirho: execution_chirho.effect_step_chirho(),
            attribution_chirho,
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        })
    }
}

#[derive(Debug)]
pub enum PostgresReversibleActivationErrorChirho {
    ContractLawRefusedChirho {
        detail_chirho: String,
    },
    CompositionUnavailableChirho,
    VerifiedContextUnavailableChirho,
    InvocationScopeUnavailableChirho,
    BootstrapRefusedChirho {
        detail_chirho: String,
    },
    CustodyUnavailableChirho {
        detail_chirho: String,
    },
    MoneyPolicyRefusedChirho {
        detail_chirho: String,
    },
    InvocationObligationConflictChirho,
    InDoubtChirho {
        intent_ref_chirho: DigestChirho,
        hold_seq_chirho: u64,
    },
}

impl std::fmt::Display for PostgresReversibleActivationErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContractLawRefusedChirho { detail_chirho } => write!(
                formatter_chirho,
                "Descriptor-D contract law refused: {detail_chirho}"
            ),
            Self::CompositionUnavailableChirho => formatter_chirho
                .write_str("Descriptor-D PostgreSQL composition is not installed"),
            Self::VerifiedContextUnavailableChirho => formatter_chirho
                .write_str("Descriptor-D paid door needs verified RequestContextChirho"),
            Self::InvocationScopeUnavailableChirho => formatter_chirho
                .write_str("Descriptor-D paid door needs an active run-intent invocation scope"),
            Self::BootstrapRefusedChirho { detail_chirho } => write!(
                formatter_chirho,
                "Descriptor-D PostgreSQL bootstrap preflight refused before intent: {detail_chirho}"
            ),
            Self::CustodyUnavailableChirho { detail_chirho } => write!(
                formatter_chirho,
                "Descriptor-D adapter evidence custody is unavailable: {detail_chirho}"
            ),
            Self::MoneyPolicyRefusedChirho { detail_chirho } => write!(
                formatter_chirho,
                "Descriptor-D verified money policy refused before intent: {detail_chirho}"
            ),
            Self::InvocationObligationConflictChirho => formatter_chirho.write_str(
                "Descriptor-D invocation coordinate already binds a different verified obligation",
            ),
            Self::InDoubtChirho {
                intent_ref_chirho,
                hold_seq_chirho,
            } => write!(
                formatter_chirho,
                "Descriptor-D provider outcome remains in-doubt for intent {} at Hold seq {hold_seq_chirho}",
                intent_ref_chirho.0
            ),
        }
    }
}

impl std::error::Error for PostgresReversibleActivationErrorChirho {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostgresEffectResponseChirho {
    schema_chirho: String,
    intent_ref_chirho: DigestChirho,
    hold_seq_chirho: u64,
    hold_record_digest_chirho: DigestChirho,
    hold_hlc_chirho: HlcChirho,
    terminal_seq_chirho: u64,
    terminal_record_digest_chirho: DigestChirho,
    terminal_hlc_chirho: HlcChirho,
    outcome_ref_chirho: DigestChirho,
    disposition_chirho: EffectTerminalDispositionChirho,
}

/// Parse the one canonical Descriptor-D terminal transport emitted by the real composition. The
/// host may classify committed versus definite-no-effect only through this helper; lossy or
/// noncanonical JSON is refused before any projection feed decision.
pub fn parse_canonical_postgres_effect_terminal_disposition_chirho(
    bytes_chirho: &[u8],
) -> Result<EffectTerminalDispositionChirho> {
    let response_chirho: PostgresEffectResponseChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_error_chirho| anyhow::anyhow!("Descriptor-D terminal transport is malformed"))?;
    if response_chirho.schema_chirho != POSTGRES_EFFECT_RESPONSE_SCHEMA_CHIRHO {
        bail!("Descriptor-D terminal transport schema is unsupported");
    }
    if serde_json::to_vec(&response_chirho)? != bytes_chirho {
        bail!("Descriptor-D terminal transport is not byte-canonical");
    }
    Ok(response_chirho.disposition_chirho)
}

fn same_invocation_obligation_chirho(
    bound_chirho: &EffectIntentChirho,
    candidate_chirho: &EffectIntentChirho,
) -> bool {
    bound_chirho.schema_chirho == candidate_chirho.schema_chirho
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
        && bound_chirho.evidence_refs_chirho == candidate_chirho.evidence_refs_chirho
        && bound_chirho.resolved_price_chirho == candidate_chirho.resolved_price_chirho
        && bound_chirho.payer_account_chirho == candidate_chirho.payer_account_chirho
        && bound_chirho.effect_step_chirho == candidate_chirho.effect_step_chirho
        && bound_chirho.attribution_chirho == candidate_chirho.attribution_chirho
        && bound_chirho.original_effect_key_chirho == candidate_chirho.original_effect_key_chirho
}

fn load_adapter_evidence_key_chirho(root_chirho: &Path) -> Result<AdapterEvidenceKeyChirho> {
    let secret_ref_chirho =
        cairn_secret_chirho::secret_chirho::secret_ref_chirho(ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO)?;
    let secret_chirho = cairn_secret_chirho::secret_chirho::resolve_secret_ref_chirho(
        root_chirho,
        &secret_ref_chirho,
    )?;
    let bytes_chirho: [u8; 32] = secret_chirho
        .as_bytes_chirho()
        .try_into()
        .map_err(|_| anyhow::anyhow!("adapter evidence key must be exactly 32 bytes"))?;
    AdapterEvidenceKeyChirho::new_chirho(bytes_chirho).map_err(Into::into)
}

/// Read-only startup custody preflight for the one Descriptor-D adapter evidence key. The host
/// uses this before listen; it gains no key bytes and performs no provider, journal, or feed work.
pub fn verify_local_postgres_effect_adapter_custody_chirho(root_chirho: &Path) -> Result<()> {
    load_adapter_evidence_key_chirho(root_chirho).map(|_key_chirho| ())
}

/// Fail-closed adapter from the generic paid-effect executor into Descriptor-D.
/// Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/README-chirho.md`.
pub(crate) fn run_postgres_reversible_chirho(
    root_chirho: &Path,
    admission_chirho: &EffectAdmissionChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    request_bytes_chirho: &[u8],
    runtime_chirho: Option<&mut dyn PostgresReversibleRuntimePortChirho>,
) -> Result<Vec<u8>> {
    if !matches!(
        admission_chirho.capability_chirho(),
        CapabilityChirho::PaidEffectChirho { effect_chirho, .. }
            if effect_chirho == POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO
    ) {
        return Err(anyhow::Error::new(
            PostgresReversibleActivationErrorChirho::ContractLawRefusedChirho {
                detail_chirho: "admission does not name the reversible PostgreSQL subtype"
                    .to_owned(),
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
            PostgresReversibleActivationErrorChirho::ContractLawRefusedChirho {
                detail_chirho:
                    "signed contract lacks its exact reconciliation, pricing, or cache law"
                        .to_owned(),
            },
        ));
    }
    let runtime_chirho = runtime_chirho.ok_or_else(|| {
        anyhow::Error::new(PostgresReversibleActivationErrorChirho::CompositionUnavailableChirho)
    })?;
    let request_context_chirho = request_context_chirho.ok_or_else(|| {
        anyhow::Error::new(
            PostgresReversibleActivationErrorChirho::VerifiedContextUnavailableChirho,
        )
    })?;
    let invocation_chirho = current_run_intent_effect_invocation_chirho().ok_or_else(|| {
        anyhow::Error::new(
            PostgresReversibleActivationErrorChirho::InvocationScopeUnavailableChirho,
        )
    })?;
    runtime_chirho.execute_chirho(PostgresReversibleExecutionChirho {
        root_chirho,
        admission_chirho,
        request_context_chirho,
        invocation_chirho,
        request_bytes_chirho,
    })
}

#[cfg(test)]
#[path = "postgres_reversible_chirho/committed_evidence_origin_tests_chirho.rs"]
mod committed_evidence_origin_tests_chirho;
#[cfg(test)]
#[path = "postgres_reversible_chirho/terminal_transport_tests_chirho.rs"]
mod terminal_transport_tests_chirho;
#[cfg(test)]
#[path = "postgres_reversible_chirho/tests_chirho.rs"]
mod tests_chirho;
