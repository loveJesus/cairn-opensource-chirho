// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Root-backed evidence adapters for Descriptor-D.
//!
//! Canonical intent and terminal lines are public coordinates. Request, provider, and before-image
//! bytes go through Cairn's existing subject-bound, crypto-shreddable private-blob store; only their
//! opaque refs appear in the adapter indexes.

use crate::model_chirho::HashChirho;
use crate::privacy_chirho::{
    load_private_blob_chirho, store_private_blob_chirho, verify_private_blob_ref_subject_chirho,
    NotAccountScopedReasonChirho, PrivateBlobAttributionChirho, PrivateBlobRefChirho,
};
use anyhow::{bail, Context, Result};
use cairn_effect_commit_chirho::coordinator_chirho::{
    effect_provider_evidence_ref_chirho, EffectCommitEvidencePortChirho,
    EffectEvidencePortErrorChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    effect_compensation_key_chirho, effect_intent_ref_chirho, verify_effect_intent_line_chirho,
    EffectIntentSignerPortChirho, VerifiedEffectIntentChirho,
};
use cairn_effect_commit_chirho::terminal_chirho::{
    verify_effect_terminal_outcome_line_chirho, EffectTerminalDispositionChirho,
    EffectTerminalSignerPortChirho, VerifiedEffectTerminalOutcomeChirho,
};
use cairn_effect_commit_ledger_chirho::public_evidence_chirho::{
    PublicEffectEvidenceKindChirho, PublicEffectEvidenceRefusalChirho,
    RootPublicEffectEvidenceStoreChirho, EFFECT_COMMIT_EVIDENCE_DIRECTORY_CHIRHO,
    MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_postgres_effect_chirho::ports_chirho::{
    OriginalEffectEvidenceErrorChirho, PostgresOriginalEffectEvidencePortChirho,
    PostgresPrivateEvidencePortChirho, PrivateEvidencePortErrorChirho, SensitiveBytesChirho,
    VerifiedOriginalPostgresEffectChirho,
};
use cairn_postgres_effect_chirho::{
    canonical_forward_receipt_bytes_chirho, parse_canonical_committed_decision_chirho,
    postgres_provider_result_ref_chirho, PostgresRequestEvidenceErrorChirho,
    PostgresRequestEvidencePortChirho, ReversiblePostgresEffectCoordinateChirho,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const COMPENSATION_BINDING_SCHEMA_CHIRHO: &str = "effect-compensation-evidence-binding-v1-chirho";

/// Every Descriptor-D private store's attribution, until brick 2b-pg attributes it per account: the
/// named interim reason, never an account guessed without the intent's own (see its variant).
fn pending_attribution_chirho() -> PrivateBlobAttributionChirho {
    PrivateBlobAttributionChirho::not_account_scoped_chirho(
        NotAccountScopedReasonChirho::PostgresEvidencePendingAttributionChirho,
    )
}
static EVIDENCE_TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub(super) struct RootEffectCommitEvidenceChirho {
    root_chirho: PathBuf,
}

impl RootEffectCommitEvidenceChirho {
    pub(super) fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
        }
    }
}

#[derive(Clone)]
pub(super) struct RootPostgresRequestEvidenceChirho {
    root_chirho: PathBuf,
}

impl RootPostgresRequestEvidenceChirho {
    pub(super) fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
        }
    }

    pub(super) fn create_or_load_chirho(
        &self,
        request_ref_chirho: &DigestChirho,
        request_bytes_chirho: &[u8],
    ) -> Result<Vec<u8>> {
        validate_digest_chirho(&request_ref_chirho.0)?;
        if blake3::hash(request_bytes_chirho).to_hex().as_str() != request_ref_chirho.0 {
            bail!("PostgreSQL request bytes do not match their content ref");
        }
        let path_chirho = evidence_path_chirho(
            &self.root_chirho,
            LegacyEvidenceFamilyChirho::RequestsChirho,
            &request_ref_chirho.0,
            "json",
        )?;
        if !path_chirho.exists() {
            let blob_chirho = store_private_blob_chirho(
                &self.root_chirho,
                &pending_attribution_chirho(),
                &request_ref_chirho.0,
                request_bytes_chirho,
            )?;
            let proposed_chirho = serde_json::to_vec(&blob_chirho)?;
            let _ = create_or_load_bytes_chirho(&path_chirho, &proposed_chirho)?;
        }
        let blob_chirho: PrivateBlobRefChirho = serde_json::from_slice(&fs::read(&path_chirho)?)
            .context("decode PostgreSQL request private-blob ref")?;
        verify_private_blob_ref_subject_chirho(
            &self.root_chirho,
            "Descriptor-D PostgreSQL request evidence",
            &blob_chirho,
            &request_ref_chirho.0,
        )?;
        let loaded_chirho = load_private_blob_chirho(&self.root_chirho, &blob_chirho)?;
        if blake3::hash(&loaded_chirho).to_hex().as_str() != request_ref_chirho.0 {
            bail!("stored PostgreSQL request evidence does not match its ref");
        }
        Ok(loaded_chirho)
    }
}

impl PostgresRequestEvidencePortChirho for RootPostgresRequestEvidenceChirho {
    fn load_request_bytes_chirho(
        &self,
        request_ref_chirho: &DigestChirho,
    ) -> Result<Vec<u8>, PostgresRequestEvidenceErrorChirho> {
        let path_chirho = evidence_path_chirho(
            &self.root_chirho,
            LegacyEvidenceFamilyChirho::RequestsChirho,
            &request_ref_chirho.0,
            "json",
        )
        .map_err(request_unavailable_chirho)?;
        if !path_chirho.exists() {
            return Err(PostgresRequestEvidenceErrorChirho::MissingChirho);
        }
        let blob_chirho: PrivateBlobRefChirho =
            serde_json::from_slice(&fs::read(&path_chirho).map_err(request_unavailable_chirho)?)
                .map_err(request_unavailable_chirho)?;
        verify_private_blob_ref_subject_chirho(
            &self.root_chirho,
            "Descriptor-D PostgreSQL request evidence",
            &blob_chirho,
            &request_ref_chirho.0,
        )
        .map_err(request_unavailable_chirho)?;
        let bytes_chirho = load_private_blob_chirho(&self.root_chirho, &blob_chirho)
            .map_err(request_unavailable_chirho)?;
        if blake3::hash(&bytes_chirho).to_hex().as_str() != request_ref_chirho.0 {
            return Err(request_unavailable_chirho(
                "stored request bytes do not match their ref",
            ));
        }
        Ok(bytes_chirho)
    }
}

#[derive(Clone)]
pub(super) struct RootPostgresPrivateEvidenceChirho {
    root_chirho: PathBuf,
}

impl RootPostgresPrivateEvidenceChirho {
    pub(super) fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
        }
    }
}

pub(super) struct RootPostgresOriginalEffectEvidenceChirho<'evidence_chirho> {
    root_chirho: PathBuf,
    intent_ref_chirho: DigestChirho,
    terminal_outcome_ref_chirho: DigestChirho,
    intent_verifier_chirho: &'evidence_chirho dyn EffectIntentSignerPortChirho,
    terminal_verifier_chirho: &'evidence_chirho dyn EffectTerminalSignerPortChirho,
}

impl<'evidence_chirho> RootPostgresOriginalEffectEvidenceChirho<'evidence_chirho> {
    pub(super) fn new_chirho(
        root_chirho: &Path,
        intent_ref_chirho: DigestChirho,
        terminal_outcome_ref_chirho: DigestChirho,
        intent_verifier_chirho: &'evidence_chirho dyn EffectIntentSignerPortChirho,
        terminal_verifier_chirho: &'evidence_chirho dyn EffectTerminalSignerPortChirho,
    ) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            intent_ref_chirho,
            terminal_outcome_ref_chirho,
            intent_verifier_chirho,
            terminal_verifier_chirho,
        }
    }
}

impl PostgresOriginalEffectEvidencePortChirho for RootPostgresOriginalEffectEvidenceChirho<'_> {
    fn load_verified_original_effect_chirho(
        &self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<VerifiedOriginalPostgresEffectChirho, OriginalEffectEvidenceErrorChirho> {
        let effect_evidence_chirho = RootEffectCommitEvidenceChirho::new_chirho(&self.root_chirho);
        let verified_intent_chirho = effect_evidence_chirho
            .load_verified_intent_chirho(&self.intent_ref_chirho, self.intent_verifier_chirho)?;
        let coordinate_chirho =
            ReversiblePostgresEffectCoordinateChirho::from_verified_intent_chirho(
                &verified_intent_chirho,
            )
            .map_err(original_evidence_invalid_chirho)?;
        if verified_intent_chirho
            .intent_chirho()
            .original_effect_key_chirho
            .is_some()
            || coordinate_chirho.effect_idem_key_chirho() != original_effect_idem_key_chirho
            || verified_intent_chirho
                .intent_chirho()
                .request_ref_chirho
                .0
                .len()
                != 64
        {
            return Err(original_evidence_invalid_chirho(
                "signed original intent is not the requested forward effect",
            ));
        }

        let request_evidence_chirho =
            RootPostgresRequestEvidenceChirho::new_chirho(&self.root_chirho);
        let request_bytes_chirho = request_evidence_chirho
            .load_request_bytes_chirho(&verified_intent_chirho.intent_chirho().request_ref_chirho)
            .map_err(original_evidence_unavailable_chirho)?;

        let verified_terminal_chirho = effect_evidence_chirho.load_verified_terminal_chirho(
            &self.terminal_outcome_ref_chirho,
            self.terminal_verifier_chirho,
        )?;
        if verified_terminal_chirho.outcome_ref_chirho() != &self.terminal_outcome_ref_chirho
            || verified_terminal_chirho.outcome_chirho().intent_ref_chirho != self.intent_ref_chirho
        {
            return Err(original_evidence_invalid_chirho(
                "signed terminal does not bind the selected original intent",
            ));
        }
        let result_ref_chirho = match &verified_terminal_chirho.outcome_chirho().disposition_chirho
        {
            EffectTerminalDispositionChirho::CommittedChirho { result_ref_chirho } => {
                result_ref_chirho
            }
            EffectTerminalDispositionChirho::DefiniteNoEffectChirho => {
                return Err(original_evidence_invalid_chirho(
                    "definite-no-effect terminal has no reversible provider state",
                ));
            }
        };
        let provider_bytes_chirho = effect_evidence_chirho
            .load_provider_evidence_bytes_chirho(
                &verified_terminal_chirho
                    .outcome_chirho()
                    .provider_evidence_ref_chirho,
            )
            .map_err(original_evidence_unavailable_chirho)?;
        if postgres_provider_result_ref_chirho(&provider_bytes_chirho) != *result_ref_chirho {
            return Err(original_evidence_invalid_chirho(
                "provider evidence does not bind the signed terminal result ref",
            ));
        }
        let decision_chirho = parse_canonical_committed_decision_chirho(&provider_bytes_chirho)
            .map_err(original_evidence_invalid_chirho)?;
        if decision_chirho.k_chirho != coordinate_chirho.effect_intent_key_chirho()
            || decision_chirho.contract_digest_chirho != *coordinate_chirho.contract_digest_chirho()
            || decision_chirho.journal_binding_chirho != *coordinate_chirho.journal_binding_chirho()
            || decision_chirho
                .forward_receipt_chirho
                .effect_idem_key_chirho
                != *original_effect_idem_key_chirho
        {
            return Err(original_evidence_invalid_chirho(
                "provider decision does not bind the signed original coordinate",
            ));
        }
        let forward_receipt_bytes_chirho =
            canonical_forward_receipt_bytes_chirho(&decision_chirho.forward_receipt_chirho)
                .map_err(original_evidence_invalid_chirho)?;
        Ok(VerifiedOriginalPostgresEffectChirho {
            original_effect_idem_key_chirho: original_effect_idem_key_chirho.clone(),
            request_bytes_chirho,
            forward_receipt_bytes_chirho,
        })
    }
}

impl PostgresPrivateEvidencePortChirho for RootPostgresPrivateEvidenceChirho {
    fn load_subject_blob_chirho(
        &self,
        subject_chirho: &HashChirho,
        blob_ref_chirho: &PrivateBlobRefChirho,
    ) -> Result<SensitiveBytesChirho, PrivateEvidencePortErrorChirho> {
        verify_private_blob_ref_subject_chirho(
            &self.root_chirho,
            "Descriptor-D PostgreSQL before-image",
            blob_ref_chirho,
            &subject_chirho.0,
        )
        .map_err(private_evidence_unavailable_chirho)?;
        load_private_blob_chirho(&self.root_chirho, blob_ref_chirho)
            .map(SensitiveBytesChirho::new_chirho)
            .map_err(private_evidence_unavailable_chirho)
    }

    fn store_subject_blob_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> Result<PrivateBlobRefChirho, PrivateEvidencePortErrorChirho> {
        validate_digest_chirho(&subject_chirho.0).map_err(private_evidence_unavailable_chirho)?;
        store_private_blob_chirho(
            &self.root_chirho,
            &pending_attribution_chirho(),
            &subject_chirho.0,
            bytes_chirho,
        )
        .map_err(private_evidence_unavailable_chirho)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompensationEvidenceBindingChirho {
    schema_chirho: String,
    compensation_key_chirho: String,
    intent_ref_chirho: DigestChirho,
    canonical_line_chirho: String,
}

impl EffectCommitEvidencePortChirho for RootEffectCommitEvidenceChirho {
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
        compensation_key_chirho: &str,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<String, EffectEvidencePortErrorChirho> {
        self.store_intent_line_chirho(intent_ref_chirho, canonical_line_chirho)?;
        let binding_chirho = CompensationEvidenceBindingChirho {
            schema_chirho: COMPENSATION_BINDING_SCHEMA_CHIRHO.to_owned(),
            compensation_key_chirho: compensation_key_chirho.to_owned(),
            intent_ref_chirho: intent_ref_chirho.clone(),
            canonical_line_chirho: canonical_line_chirho.to_owned(),
        };
        let bytes_chirho =
            serde_json::to_vec(&binding_chirho).map_err(evidence_unavailable_chirho)?;
        let key_digest_chirho = blake3::hash(compensation_key_chirho.as_bytes())
            .to_hex()
            .to_string();
        let path_chirho = evidence_path_chirho(
            &self.root_chirho,
            LegacyEvidenceFamilyChirho::CompensationsChirho,
            &key_digest_chirho,
            "json",
        )
        .map_err(evidence_unavailable_chirho)?;
        let loaded_chirho = create_or_load_bytes_chirho(&path_chirho, &bytes_chirho)
            .map_err(evidence_unavailable_chirho)?;
        let loaded_chirho: CompensationEvidenceBindingChirho =
            serde_json::from_slice(&loaded_chirho).map_err(evidence_unavailable_chirho)?;
        if loaded_chirho.schema_chirho != COMPENSATION_BINDING_SCHEMA_CHIRHO
            || loaded_chirho.compensation_key_chirho != compensation_key_chirho
            || loaded_chirho.intent_ref_chirho != *intent_ref_chirho
            || loaded_chirho.canonical_line_chirho != canonical_line_chirho
        {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "compensation coordinate already binds different intent bytes"
                    .to_owned(),
            });
        }
        Ok(loaded_chirho.canonical_line_chirho)
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
        let path_chirho = evidence_path_chirho(
            &self.root_chirho,
            LegacyEvidenceFamilyChirho::ProviderChirho,
            &evidence_ref_chirho.0,
            "json",
        )
        .map_err(evidence_unavailable_chirho)?;
        if !path_chirho.exists() {
            let blob_chirho = store_private_blob_chirho(
                &self.root_chirho,
                &pending_attribution_chirho(),
                &evidence_ref_chirho.0,
                evidence_bytes_chirho,
            )
            .map_err(evidence_unavailable_chirho)?;
            let proposed_chirho =
                serde_json::to_vec(&blob_chirho).map_err(evidence_unavailable_chirho)?;
            let _ = create_or_load_bytes_chirho(&path_chirho, &proposed_chirho)
                .map_err(evidence_unavailable_chirho)?;
        }
        let blob_chirho: PrivateBlobRefChirho =
            serde_json::from_slice(&fs::read(&path_chirho).map_err(evidence_unavailable_chirho)?)
                .map_err(evidence_unavailable_chirho)?;
        verify_private_blob_ref_subject_chirho(
            &self.root_chirho,
            "Descriptor-D PostgreSQL provider evidence",
            &blob_chirho,
            &evidence_ref_chirho.0,
        )
        .map_err(evidence_unavailable_chirho)?;
        let loaded_chirho = load_private_blob_chirho(&self.root_chirho, &blob_chirho)
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

impl RootEffectCommitEvidenceChirho {
    pub(super) fn load_verified_compensation_intent_line_chirho(
        &self,
        original_effect_key_chirho: &str,
        intent_verifier_chirho: &dyn EffectIntentSignerPortChirho,
    ) -> Result<Option<(String, VerifiedEffectIntentChirho)>> {
        let compensation_key_chirho = effect_compensation_key_chirho(original_effect_key_chirho)
            .context("derive compensation evidence key")?;
        let key_digest_chirho = blake3::hash(compensation_key_chirho.as_bytes())
            .to_hex()
            .to_string();
        let path_chirho = evidence_path_chirho(
            &self.root_chirho,
            LegacyEvidenceFamilyChirho::CompensationsChirho,
            &key_digest_chirho,
            "json",
        )?;
        if !path_chirho.exists() {
            return Ok(None);
        }
        let binding_chirho: CompensationEvidenceBindingChirho =
            serde_json::from_slice(&fs::read(path_chirho)?)?;
        if binding_chirho.schema_chirho != COMPENSATION_BINDING_SCHEMA_CHIRHO
            || binding_chirho.compensation_key_chirho != compensation_key_chirho
        {
            bail!("stored compensation evidence binding is invalid");
        }
        let verified_chirho = self
            .load_verified_intent_chirho(&binding_chirho.intent_ref_chirho, intent_verifier_chirho)
            .map_err(|error_chirho| anyhow::anyhow!(error_chirho.to_string()))?;
        if effect_intent_ref_chirho(verified_chirho.intent_chirho())?
            != binding_chirho.intent_ref_chirho
            || verified_chirho
                .intent_chirho()
                .original_effect_key_chirho
                .as_deref()
                != Some(original_effect_key_chirho)
        {
            bail!("stored compensation intent does not bind the original effect");
        }
        let canonical_line_chirho = self
            .load_intent_line_chirho(&binding_chirho.intent_ref_chirho)
            .map_err(|error_chirho| anyhow::anyhow!(error_chirho.to_string()))?
            .ok_or_else(|| anyhow::anyhow!("stored compensation intent line is missing"))?;
        if canonical_line_chirho != binding_chirho.canonical_line_chirho {
            bail!("stored compensation intent line diverges from its binding");
        }
        Ok(Some((canonical_line_chirho, verified_chirho)))
    }

    pub(super) fn load_verified_intent_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
        verifier_chirho: &dyn EffectIntentSignerPortChirho,
    ) -> Result<VerifiedEffectIntentChirho, OriginalEffectEvidenceErrorChirho> {
        let line_chirho = self
            .load_intent_line_chirho(intent_ref_chirho)
            .map_err(original_evidence_unavailable_chirho)?
            .ok_or(OriginalEffectEvidenceErrorChirho::MissingChirho)?;
        let verified_chirho = verify_effect_intent_line_chirho(&line_chirho, verifier_chirho)
            .map_err(original_evidence_invalid_chirho)?;
        if cairn_effect_commit_chirho::intent_chirho::effect_intent_ref_chirho(
            verified_chirho.intent_chirho(),
        )
        .map_err(original_evidence_invalid_chirho)?
            != *intent_ref_chirho
        {
            return Err(original_evidence_invalid_chirho(
                "stored signed intent does not match its selected ref",
            ));
        }
        Ok(verified_chirho)
    }

    pub(super) fn load_verified_terminal_chirho(
        &self,
        outcome_ref_chirho: &DigestChirho,
        verifier_chirho: &dyn EffectTerminalSignerPortChirho,
    ) -> Result<VerifiedEffectTerminalOutcomeChirho, OriginalEffectEvidenceErrorChirho> {
        let line_chirho = self
            .load_terminal_line_chirho(outcome_ref_chirho)
            .map_err(original_evidence_unavailable_chirho)?
            .ok_or(OriginalEffectEvidenceErrorChirho::MissingChirho)?;
        let verified_chirho =
            verify_effect_terminal_outcome_line_chirho(&line_chirho, verifier_chirho)
                .map_err(original_evidence_invalid_chirho)?;
        if verified_chirho.outcome_ref_chirho() != outcome_ref_chirho {
            return Err(original_evidence_invalid_chirho(
                "stored signed terminal does not match its selected ref",
            ));
        }
        Ok(verified_chirho)
    }

    fn load_terminal_line_chirho(
        &self,
        outcome_ref_chirho: &DigestChirho,
    ) -> Result<Option<String>, EffectEvidencePortErrorChirho> {
        RootPublicEffectEvidenceStoreChirho::new_chirho(&self.root_chirho)
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::TerminalChirho,
                &outcome_ref_chirho.0,
                MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
            )
            .map_err(public_evidence_load_error_chirho)?
            .map(String::from_utf8)
            .transpose()
            .map_err(evidence_unavailable_chirho)
    }

    fn load_provider_evidence_bytes_chirho(
        &self,
        evidence_ref_chirho: &DigestChirho,
    ) -> Result<Vec<u8>, EffectEvidencePortErrorChirho> {
        let path_chirho = evidence_path_chirho(
            &self.root_chirho,
            LegacyEvidenceFamilyChirho::ProviderChirho,
            &evidence_ref_chirho.0,
            "json",
        )
        .map_err(evidence_unavailable_chirho)?;
        if !path_chirho.exists() {
            return Err(EffectEvidencePortErrorChirho::UnavailableChirho {
                detail_chirho: "provider evidence is missing".to_owned(),
            });
        }
        let blob_chirho: PrivateBlobRefChirho =
            serde_json::from_slice(&fs::read(&path_chirho).map_err(evidence_unavailable_chirho)?)
                .map_err(evidence_unavailable_chirho)?;
        verify_private_blob_ref_subject_chirho(
            &self.root_chirho,
            "Descriptor-D PostgreSQL provider evidence",
            &blob_chirho,
            &evidence_ref_chirho.0,
        )
        .map_err(evidence_unavailable_chirho)?;
        let bytes_chirho = load_private_blob_chirho(&self.root_chirho, &blob_chirho)
            .map_err(evidence_unavailable_chirho)?;
        if effect_provider_evidence_ref_chirho(&bytes_chirho) != *evidence_ref_chirho {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "provider evidence bytes do not match their content ref".to_owned(),
            });
        }
        Ok(bytes_chirho)
    }
}

pub(super) fn create_or_load_invocation_intent_line_chirho(
    root_chirho: &Path,
    invocation_ref_chirho: &HashChirho,
    proposed_line_chirho: &str,
) -> Result<String> {
    validate_digest_chirho(&invocation_ref_chirho.0)?;
    let path_chirho = evidence_path_chirho(
        root_chirho,
        LegacyEvidenceFamilyChirho::InvocationsChirho,
        &invocation_ref_chirho.0,
        "json",
    )?;
    let loaded_chirho = create_or_load_bytes_chirho(&path_chirho, proposed_line_chirho.as_bytes())?;
    String::from_utf8(loaded_chirho).context("decode invocation-bound signed intent line")
}

#[derive(Clone, Copy)]
enum LegacyEvidenceFamilyChirho {
    RequestsChirho,
    CompensationsChirho,
    ProviderChirho,
    InvocationsChirho,
}

impl LegacyEvidenceFamilyChirho {
    fn as_str_chirho(self) -> &'static str {
        match self {
            Self::RequestsChirho => "requests-chirho",
            Self::CompensationsChirho => "compensations-chirho",
            Self::ProviderChirho => "provider-chirho",
            Self::InvocationsChirho => "invocations-chirho",
        }
    }
}

fn evidence_path_chirho(
    root_chirho: &Path,
    family_chirho: LegacyEvidenceFamilyChirho,
    coordinate_chirho: &str,
    extension_chirho: &str,
) -> Result<PathBuf> {
    validate_digest_chirho(coordinate_chirho)?;
    Ok(root_chirho
        .join(EFFECT_COMMIT_EVIDENCE_DIRECTORY_CHIRHO)
        .join(family_chirho.as_str_chirho())
        .join(format!("{coordinate_chirho}.{extension_chirho}")))
}

fn validate_digest_chirho(value_chirho: &str) -> Result<()> {
    if value_chirho.len() != 64
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
    {
        bail!("effect evidence coordinate must be a 64-byte lowercase hex digest");
    }
    Ok(())
}

fn create_or_load_bytes_chirho(path_chirho: &Path, proposed_chirho: &[u8]) -> Result<Vec<u8>> {
    if path_chirho.exists() {
        return fs::read(path_chirho).with_context(|| format!("read {}", path_chirho.display()));
    }
    let parent_chirho = path_chirho
        .parent()
        .ok_or_else(|| anyhow::anyhow!("effect evidence path has no parent"))?;
    fs::create_dir_all(parent_chirho)?;
    let counter_chirho = EVIDENCE_TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
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

fn request_unavailable_chirho(
    error_chirho: impl std::fmt::Display,
) -> PostgresRequestEvidenceErrorChirho {
    PostgresRequestEvidenceErrorChirho::UnavailableChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

fn private_evidence_unavailable_chirho(
    error_chirho: impl std::fmt::Display,
) -> PrivateEvidencePortErrorChirho {
    PrivateEvidencePortErrorChirho::UnavailableChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

fn original_evidence_invalid_chirho(
    error_chirho: impl std::fmt::Display,
) -> OriginalEffectEvidenceErrorChirho {
    OriginalEffectEvidenceErrorChirho::InvalidChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

fn original_evidence_unavailable_chirho(
    error_chirho: impl std::fmt::Display,
) -> OriginalEffectEvidenceErrorChirho {
    OriginalEffectEvidenceErrorChirho::UnavailableChirho {
        detail_chirho: error_chirho.to_string(),
    }
}
