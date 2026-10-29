// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Reviews candidate app DAGs by declared surface and signed promote/reject decisions.

use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho};
use crate::{
    app_chirho, effect_pricing_chirho, identity_chirho, refs_chirho, seqlog_chirho, store_chirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_model_app_chirho::app_head_transition_chirho::app_action_is_reviewed_deploy_chirho;
use cairn_review_policy_chirho::{ReviewDagSurfaceChirho, ReviewResolvedPriceChirho};
use cairn_review_use_case_chirho as review_use_case_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionAuthorityPortChirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub use cairn_model_review_chirho::{
    ReviewDecisionChirho, ReviewPaidEffectCostChirho, ReviewPolicyEnvelopeEvidenceChirho,
    ReviewPolicyEnvelopeRecordChirho, ReviewPolicyEnvelopeScopeChirho, ReviewRecordChirho,
    ReviewSourceEvidenceChirho, ReviewSourceManifestEvidenceChirho, ReviewSurfaceDiffChirho,
    REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO, REVIEW_RECORD_SCHEMA_CHIRHO,
};

struct ReviewAppendInputChirho {
    app_chirho: String,
    owner_principal_chirho: String,
    live_before_chirho: Option<HashChirho>,
    candidate_chirho: HashChirho,
    source_review_report_chirho: Option<HashChirho>,
    source_manifest_chirho: Option<ReviewSourceManifestEvidenceChirho>,
    decision_chirho: ReviewDecisionChirho,
    accepted_capability_escalation_chirho: bool,
    accepted_cost_increase_chirho: bool,
    review_policy_envelope_chirho: Option<ReviewPolicyEnvelopeEvidenceChirho>,
    app_record_seq_chirho: Option<u64>,
    reason_chirho: Option<String>,
    diff_chirho: ReviewSurfaceDiffChirho,
}
pub type PromoteCandidateReviewEvidenceInputChirho<'a> =
    review_use_case_chirho::PromoteCandidateInputChirho<'a>;

#[derive(Clone, Debug)]
struct VerifiedReviewPolicyEnvelopeChirho {
    record_chirho: ReviewPolicyEnvelopeRecordChirho,
    line_hash_chirho: HashChirho,
}
struct RootReviewPortChirho<'a> {
    root_chirho: &'a Path,
    head_transition_authority_chirho: Option<&'a dyn HeadTransitionAuthorityPortChirho>,
}

impl<'a> RootReviewPortChirho<'a> {
    fn local_chirho(root_chirho: &'a Path) -> Self {
        Self {
            root_chirho,
            head_transition_authority_chirho: None,
        }
    }

    fn elected_chirho(
        root_chirho: &'a Path,
        authority_chirho: &'a dyn HeadTransitionAuthorityPortChirho,
    ) -> Self {
        Self {
            root_chirho,
            head_transition_authority_chirho: Some(authority_chirho),
        }
    }
}

impl review_use_case_chirho::ReviewCandidatePortChirho for RootReviewPortChirho<'_> {
    fn dag_surface_chirho(&self, dag_chirho: &HashChirho) -> Result<ReviewDagSurfaceChirho> {
        load_dag_surface_chirho(self.root_chirho, dag_chirho)
    }

    fn resolved_prices_chirho(
        &self,
        app_chirho: &str,
        paid_effect_counts_chirho: &BTreeMap<String, u64>,
        price_book_chirho: &Option<HashChirho>,
        warnings_chirho: &mut Vec<String>,
    ) -> Result<BTreeMap<String, ReviewResolvedPriceChirho>> {
        resolve_review_prices_chirho(
            self.root_chirho,
            app_chirho,
            paid_effect_counts_chirho,
            price_book_chirho,
            warnings_chirho,
        )
    }
}
impl review_use_case_chirho::ReviewSourceEvidencePortChirho for RootReviewPortChirho<'_> {
    fn load_source_review_report_chirho(
        &self,
        source_review_report_chirho: &HashChirho,
    ) -> Result<review_use_case_chirho::LoadedSourceReviewReportChirho> {
        let report_chirho: crate::app_source_manifest_chirho::AppSourceReviewReportChirho =
            store_chirho::get_object_chirho(self.root_chirho, source_review_report_chirho)
                .with_context(|| {
                    format!(
                        "review source report {} is not in the store",
                        source_review_report_chirho.0
                    )
                })?;
        crate::app_source_manifest_chirho::validate_app_source_review_declaration_binding_chirho(
            self.root_chirho,
            &report_chirho,
        )?;
        let canonical_hash_chirho =
            crate::app_source_manifest_chirho::hash_app_source_review_report_chirho(
                &report_chirho,
            )?;
        Ok(review_use_case_chirho::LoadedSourceReviewReportChirho {
            source_review_report_chirho: source_review_report_chirho.clone(),
            canonical_hash_chirho,
            report_chirho,
        })
    }

    fn validate_effective_source_manifest_chirho(
        &self,
        effective_manifest_hash_chirho: &HashChirho,
    ) -> Result<()> {
        let _effective_manifest_chirho: serde_json::Value =
            store_chirho::get_object_chirho(self.root_chirho, effective_manifest_hash_chirho)
                .with_context(|| {
                    format!(
                        "review source manifest {} is not a stored manifest object",
                        effective_manifest_hash_chirho.0
                    )
                })?;
        Ok(())
    }

    fn validate_raw_source_manifest_chirho(
        &self,
        raw_manifest_hash_chirho: &HashChirho,
    ) -> Result<()> {
        let raw_manifest_bytes_chirho =
            crate::cas_chirho::get_chirho(self.root_chirho, raw_manifest_hash_chirho)
                .with_context(|| {
                    format!(
                        "review raw source manifest {} is not in CAS",
                        raw_manifest_hash_chirho.0
                    )
                })?;
        if crate::cas_chirho::hash_chirho(&raw_manifest_bytes_chirho) != *raw_manifest_hash_chirho {
            bail!(
                "review raw source manifest {} failed content-address verification",
                raw_manifest_hash_chirho.0
            );
        }
        Ok(())
    }
}
impl review_use_case_chirho::ReviewDecisionPortChirho for RootReviewPortChirho<'_> {
    fn current_live_chirho(&self, app_chirho: &str) -> Result<Option<HashChirho>> {
        current_app_dag_chirho(self.root_chirho, app_chirho)
    }

    fn current_price_book_chirho(&self, app_chirho: &str) -> Result<Option<HashChirho>> {
        effect_pricing_chirho::current_price_book_hash_chirho(self.root_chirho, app_chirho)
    }

    fn authorize_owner_chirho(&self, app_chirho: &str, owner_principal_chirho: &str) -> Result<()> {
        validate_owner_chirho(self.root_chirho, app_chirho, owner_principal_chirho)
    }

    fn enforce_review_policy_envelope_chirho(
        &self,
        input_chirho: review_use_case_chirho::ReviewPolicyEnvelopeDecisionInputChirho<'_>,
    ) -> Result<ReviewPolicyEnvelopeEvidenceChirho> {
        enforce_current_review_policy_envelope_chirho(
            self.root_chirho,
            input_chirho.app_chirho,
            input_chirho.owner_principal_chirho,
            input_chirho.candidate_chirho,
            input_chirho.diff_chirho,
            input_chirho.candidate_contract_refs_chirho,
        )
    }

    fn publish_candidate_chirho(
        &self,
        app_chirho: &str,
        owner_principal_chirho: &str,
        candidate_chirho: &HashChirho,
        source_review_report_chirho: Option<&HashChirho>,
    ) -> Result<u64> {
        let verified_bindings_chirho = source_review_report_chirho
            .map(|source_review_report_chirho| -> Result<Vec<crate::app_source_manifest_chirho::AppSourceUndoPlanBindingChirho>> {
                let report_chirho =
                    crate::app_source_manifest_chirho::load_app_source_review_report_for_promotion_chirho(
                        self.root_chirho,
                        app_chirho,
                        owner_principal_chirho,
                        source_review_report_chirho,
                        Some(candidate_chirho),
                    )?;
                let bindings_chirho = report_chirho
                    .candidate_chirho
                    .undo_plan_bindings_chirho
                    .context("reviewed descriptor-v2 source report has no undo-plan bindings")?;
                Ok(bindings_chirho
                    .into_iter()
                    .filter(|binding_chirho| binding_chirho.dag_chirho == *candidate_chirho)
                    .collect::<Vec<_>>())
            })
            .transpose()?;
        crate::app_source_manifest_chirho::verify_descriptor_v2_deployment_chirho(
            self.root_chirho,
            &BTreeSet::from([candidate_chirho.clone()]),
            verified_bindings_chirho.as_deref(),
        )?;
        if let Some(seq_chirho) = current_reviewed_app_record_seq_for_candidate_chirho(
            self.root_chirho,
            app_chirho,
            owner_principal_chirho,
            candidate_chirho,
        )? {
            return Ok(seq_chirho);
        }
        let app_record_chirho =
            if let Some(authority_chirho) = self.head_transition_authority_chirho {
                app_chirho::deploy_app_with_head_transition_authority_chirho(
                    self.root_chirho,
                    app_chirho,
                    candidate_chirho.clone(),
                    owner_principal_chirho,
                    authority_chirho,
                )?
            } else {
                app_chirho::deploy_app_chirho(
                    self.root_chirho,
                    app_chirho,
                    candidate_chirho.clone(),
                    owner_principal_chirho,
                )?
            };
        Ok(app_record_chirho.seq_chirho)
    }

    fn record_decision_chirho(
        &self,
        input_chirho: review_use_case_chirho::ReviewDecisionRecordInputChirho,
    ) -> Result<ReviewRecordChirho> {
        append_review_record_chirho(
            self.root_chirho,
            ReviewAppendInputChirho {
                app_chirho: input_chirho.app_chirho,
                owner_principal_chirho: input_chirho.owner_principal_chirho,
                live_before_chirho: input_chirho.live_before_chirho,
                candidate_chirho: input_chirho.candidate_chirho,
                source_review_report_chirho: input_chirho.source_review_report_chirho,
                source_manifest_chirho: input_chirho.source_manifest_chirho,
                decision_chirho: input_chirho.decision_chirho,
                accepted_capability_escalation_chirho: input_chirho
                    .accepted_capability_escalation_chirho,
                accepted_cost_increase_chirho: input_chirho.accepted_cost_increase_chirho,
                review_policy_envelope_chirho: input_chirho.review_policy_envelope_chirho,
                app_record_seq_chirho: input_chirho.app_record_seq_chirho,
                reason_chirho: input_chirho.reason_chirho,
                diff_chirho: input_chirho.diff_chirho,
            },
        )
    }
}

fn review_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("review-records-chirho.jsonl")
}

fn review_policy_envelopes_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("review-policy-envelopes-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn review_current_app_candidate_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    candidate_chirho: HashChirho,
) -> Result<ReviewSurfaceDiffChirho> {
    let live_chirho = current_app_dag_chirho(root_chirho, app_chirho)?;
    review_candidate_against_live_chirho(root_chirho, app_chirho, live_chirho, candidate_chirho)
}

pub fn review_candidate_against_live_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    live_chirho: Option<HashChirho>,
    candidate_chirho: HashChirho,
) -> Result<ReviewSurfaceDiffChirho> {
    let price_book_chirho =
        effect_pricing_chirho::current_price_book_hash_chirho(root_chirho, app_chirho)?;
    review_candidate_against_live_with_price_book_chirho(
        root_chirho,
        app_chirho,
        live_chirho,
        candidate_chirho,
        price_book_chirho,
    )
}

fn review_candidate_against_live_with_price_book_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    live_chirho: Option<HashChirho>,
    candidate_chirho: HashChirho,
    price_book_chirho: Option<HashChirho>,
) -> Result<ReviewSurfaceDiffChirho> {
    validate_app_name_chirho(app_chirho)?;
    let port_chirho = RootReviewPortChirho::local_chirho(root_chirho);
    review_use_case_chirho::review_candidate_against_live_chirho(
        &port_chirho,
        review_use_case_chirho::ReviewCandidateAgainstLiveInputChirho {
            app_chirho,
            live_chirho,
            candidate_chirho,
            price_book_chirho,
        },
    )
}
pub fn promote_candidate_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: HashChirho,
    accept_capability_escalation_chirho: bool,
    accept_cost_increase_chirho: bool,
) -> Result<ReviewRecordChirho> {
    promote_candidate_with_review_evidence_chirho(
        root_chirho,
        PromoteCandidateReviewEvidenceInputChirho {
            app_chirho,
            owner_principal_chirho,
            candidate_chirho,
            accept_capability_escalation_chirho,
            accept_cost_increase_chirho,
            require_review_policy_envelope_chirho: false,
            source_evidence_chirho: ReviewSourceEvidenceChirho::default(),
        },
    )
}
pub fn promote_candidate_with_source_review_report_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: HashChirho,
    accept_capability_escalation_chirho: bool,
    accept_cost_increase_chirho: bool,
    source_review_report_chirho: Option<HashChirho>,
) -> Result<ReviewRecordChirho> {
    promote_candidate_with_review_evidence_chirho(
        root_chirho,
        PromoteCandidateReviewEvidenceInputChirho {
            app_chirho,
            owner_principal_chirho,
            candidate_chirho,
            accept_capability_escalation_chirho,
            accept_cost_increase_chirho,
            require_review_policy_envelope_chirho: false,
            source_evidence_chirho: ReviewSourceEvidenceChirho {
                source_review_report_chirho,
                source_manifest_chirho: None,
            },
        },
    )
}
pub fn promote_candidate_with_source_manifest_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: HashChirho,
    accept_capability_escalation_chirho: bool,
    accept_cost_increase_chirho: bool,
    source_manifest_chirho: Option<ReviewSourceManifestEvidenceChirho>,
) -> Result<ReviewRecordChirho> {
    promote_candidate_with_review_evidence_chirho(
        root_chirho,
        PromoteCandidateReviewEvidenceInputChirho {
            app_chirho,
            owner_principal_chirho,
            candidate_chirho,
            accept_capability_escalation_chirho,
            accept_cost_increase_chirho,
            require_review_policy_envelope_chirho: false,
            source_evidence_chirho: ReviewSourceEvidenceChirho {
                source_review_report_chirho: None,
                source_manifest_chirho,
            },
        },
    )
}
pub fn promote_candidate_with_review_evidence_chirho(
    root_chirho: &Path,
    input_chirho: PromoteCandidateReviewEvidenceInputChirho<'_>,
) -> Result<ReviewRecordChirho> {
    let port_chirho = RootReviewPortChirho::local_chirho(root_chirho);
    review_use_case_chirho::promote_candidate_with_review_evidence_chirho(
        &port_chirho,
        input_chirho,
    )
}

/// Promote a reviewed candidate through the same review-use-case path while the app-head write
/// consumes the caller's elected authority. The review record remains owned by this module; only
/// the existing app deployment door changes authority era.
pub fn promote_candidate_with_review_evidence_and_head_transition_authority_chirho(
    root_chirho: &Path,
    input_chirho: PromoteCandidateReviewEvidenceInputChirho<'_>,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<ReviewRecordChirho> {
    let port_chirho = RootReviewPortChirho::elected_chirho(root_chirho, authority_chirho);
    review_use_case_chirho::promote_candidate_with_review_evidence_chirho(
        &port_chirho,
        input_chirho,
    )
}
pub fn reject_candidate_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: HashChirho,
    reason_chirho: &str,
) -> Result<ReviewRecordChirho> {
    reject_candidate_with_review_evidence_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        candidate_chirho,
        reason_chirho,
        ReviewSourceEvidenceChirho::default(),
    )
}

pub fn reject_candidate_with_source_review_report_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: HashChirho,
    reason_chirho: &str,
    source_review_report_chirho: Option<HashChirho>,
) -> Result<ReviewRecordChirho> {
    reject_candidate_with_review_evidence_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        candidate_chirho,
        reason_chirho,
        ReviewSourceEvidenceChirho {
            source_review_report_chirho,
            source_manifest_chirho: None,
        },
    )
}

pub fn reject_candidate_with_source_manifest_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: HashChirho,
    reason_chirho: &str,
    source_manifest_chirho: Option<ReviewSourceManifestEvidenceChirho>,
) -> Result<ReviewRecordChirho> {
    reject_candidate_with_review_evidence_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        candidate_chirho,
        reason_chirho,
        ReviewSourceEvidenceChirho {
            source_review_report_chirho: None,
            source_manifest_chirho,
        },
    )
}

pub fn reject_candidate_with_review_evidence_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: HashChirho,
    reason_chirho: &str,
    source_evidence_chirho: ReviewSourceEvidenceChirho,
) -> Result<ReviewRecordChirho> {
    let port_chirho = RootReviewPortChirho::local_chirho(root_chirho);
    review_use_case_chirho::reject_candidate_with_review_evidence_chirho(
        &port_chirho,
        review_use_case_chirho::RejectCandidateInputChirho {
            app_chirho,
            owner_principal_chirho,
            candidate_chirho,
            reason_chirho,
            source_evidence_chirho,
        },
    )
}

pub fn set_review_policy_envelope_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    allowed_capability_labels_chirho: Vec<String>,
    max_candidate_cost_token_chirho: i64,
    allowed_contract_refs_chirho: Vec<String>,
) -> Result<ReviewPolicyEnvelopeRecordChirho> {
    validate_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let path_chirho = review_policy_envelopes_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = ReviewPolicyEnvelopeRecordChirho {
            seq_chirho,
            schema_chirho: REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            scope_chirho: ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
                owner_principal_chirho: owner_principal_chirho.to_string(),
            },
            allowed_capability_labels_chirho: allowed_capability_labels_chirho.clone(),
            max_candidate_cost_token_chirho,
            allowed_contract_refs_chirho: allowed_contract_refs_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        validate_review_policy_envelope_record_chirho(&record_chirho)?;
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &review_policy_envelope_message_chirho(&record_chirho)?,
        )?;
        Ok(record_chirho)
    })
}

pub fn load_review_policy_envelope_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ReviewPolicyEnvelopeRecordChirho>> {
    Ok(
        load_review_policy_envelopes_with_hashes_chirho(root_chirho)?
            .into_iter()
            .map(|envelope_chirho| envelope_chirho.record_chirho)
            .collect(),
    )
}

pub fn verify_review_policy_envelopes_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(verified_review_policy_envelopes_chirho(root_chirho)?.len())
}

pub fn load_review_records_chirho(root_chirho: &Path) -> Result<Vec<ReviewRecordChirho>> {
    let path_chirho = review_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: ReviewRecordChirho = serde_json::from_str(line_chirho)?;
        validate_review_record_schema_chirho(&record_chirho)?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub fn verified_review_records_chirho(root_chirho: &Path) -> Result<Vec<ReviewRecordChirho>> {
    app_chirho::verify_apps_chirho(root_chirho)?;
    effect_pricing_chirho::verify_price_books_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_review_records_chirho(root_chirho)?;
    let app_records_chirho = app_chirho::load_app_records_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "review record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_review_record_chirho(record_chirho)?;
        validate_review_source_evidence_chirho(
            root_chirho,
            &record_chirho.candidate_chirho,
            &record_chirho.diff_chirho,
            &record_chirho.source_review_report_chirho,
            &record_chirho.source_manifest_chirho,
        )?;
        validate_review_policy_envelope_evidence_chirho(root_chirho, record_chirho)?;
        validate_owner_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let expected_diff_chirho = review_candidate_against_live_with_price_book_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            record_chirho.live_before_chirho.clone(),
            record_chirho.candidate_chirho.clone(),
            record_chirho.diff_chirho.price_book_chirho.clone(),
        )?;
        if record_chirho.diff_chirho != expected_diff_chirho {
            bail!(
                "review record {} diff no longer matches source DAGs",
                record_chirho.seq_chirho
            );
        }
        match record_chirho.decision_chirho {
            ReviewDecisionChirho::PromoteChirho => {
                let app_seq_chirho = record_chirho.app_record_seq_chirho.ok_or_else(|| {
                    anyhow!(
                        "review record {} missing app_record_seq_chirho",
                        record_chirho.seq_chirho
                    )
                })?;
                let app_record_chirho = app_records_chirho
                    .get(app_seq_chirho as usize)
                    .ok_or_else(|| {
                        anyhow!(
                            "review record {} points at missing app record {}",
                            record_chirho.seq_chirho,
                            app_seq_chirho
                        )
                    })?;
                if app_record_chirho.app_chirho != record_chirho.app_chirho
                    || app_record_chirho.owner_principal_chirho
                        != record_chirho.owner_principal_chirho
                    || app_record_chirho.dag_chirho.as_ref()
                        != Some(&record_chirho.candidate_chirho)
                    || !app_action_is_reviewed_deploy_chirho(&app_record_chirho.action_chirho)
                {
                    bail!(
                        "review record {} promotion app record mismatch",
                        record_chirho.seq_chirho
                    );
                }
                if !record_chirho
                    .diff_chirho
                    .added_capabilities_chirho
                    .is_empty()
                    && !record_chirho.accepted_capability_escalation_chirho
                {
                    bail!(
                        "review record {} promoted a capability escalation without acceptance",
                        record_chirho.seq_chirho
                    );
                }
                if record_chirho.diff_chirho.cost_delta_token_chirho > 0
                    && !record_chirho.accepted_cost_increase_chirho
                {
                    bail!(
                        "review record {} promoted a cost increase without acceptance",
                        record_chirho.seq_chirho
                    );
                }
            }
            ReviewDecisionChirho::RejectChirho => {
                if record_chirho.app_record_seq_chirho.is_some() {
                    bail!(
                        "review record {} rejection must not point at an app deploy",
                        record_chirho.seq_chirho
                    );
                }
                if record_chirho
                    .reason_chirho
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    bail!(
                        "review record {} rejection needs a reason",
                        record_chirho.seq_chirho
                    );
                }
            }
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &review_record_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "review record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

pub fn verify_review_records_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(verified_review_records_chirho(root_chirho)?.len())
}

pub fn latest_promoted_source_review_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: &HashChirho,
    source_review_report_chirho: &HashChirho,
) -> Result<Option<ReviewRecordChirho>> {
    Ok(verified_review_records_chirho(root_chirho)?
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.owner_principal_chirho == owner_principal_chirho
                && record_chirho.candidate_chirho == *candidate_chirho
                && record_chirho.source_review_report_chirho.as_ref()
                    == Some(source_review_report_chirho)
                && matches!(
                    record_chirho.decision_chirho,
                    ReviewDecisionChirho::PromoteChirho
                )
        }))
}

fn load_review_policy_envelopes_with_hashes_chirho(
    root_chirho: &Path,
) -> Result<Vec<VerifiedReviewPolicyEnvelopeChirho>> {
    let path_chirho = review_policy_envelopes_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut envelopes_chirho = Vec::new();
    for (line_idx_chirho, line_chirho) in text_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if trimmed_chirho.is_empty() {
            continue;
        }
        let record_chirho: ReviewPolicyEnvelopeRecordChirho = serde_json::from_str(trimmed_chirho)
            .with_context(|| {
                format!(
                    "parse review-policy envelope line {} from {}",
                    line_idx_chirho,
                    path_chirho.display()
                )
            })?;
        validate_review_policy_envelope_record_chirho(&record_chirho)?;
        let canonical_chirho = serde_json::to_string(&record_chirho)?;
        if canonical_chirho != trimmed_chirho {
            bail!(
                "review-policy envelope line {} is not canonical byte-for-byte",
                line_idx_chirho
            );
        }
        let line_hash_chirho =
            HashChirho(blake3::hash(trimmed_chirho.as_bytes()).to_hex().to_string());
        envelopes_chirho.push(VerifiedReviewPolicyEnvelopeChirho {
            record_chirho,
            line_hash_chirho,
        });
    }
    Ok(envelopes_chirho)
}

fn verified_review_policy_envelopes_chirho(
    root_chirho: &Path,
) -> Result<Vec<VerifiedReviewPolicyEnvelopeChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let envelopes_chirho = load_review_policy_envelopes_with_hashes_chirho(root_chirho)?;
    for (idx_chirho, envelope_chirho) in envelopes_chirho.iter().enumerate() {
        if envelope_chirho.record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "review-policy envelope seq gap at index {idx_chirho}: entry seq is {}",
                envelope_chirho.record_chirho.seq_chirho
            );
        }
        validate_owner_chirho(
            root_chirho,
            &envelope_chirho.record_chirho.app_chirho,
            review_policy_envelope_owner_chirho(&envelope_chirho.record_chirho),
        )?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &review_policy_envelope_message_chirho(&envelope_chirho.record_chirho)?,
            &envelope_chirho.record_chirho.sig_chirho,
        )? {
            bail!(
                "review-policy envelope {} signature invalid",
                envelope_chirho.record_chirho.seq_chirho
            );
        }
    }
    Ok(envelopes_chirho)
}
fn enforce_current_review_policy_envelope_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: &HashChirho,
    diff_chirho: &ReviewSurfaceDiffChirho,
    candidate_contract_refs_chirho: &BTreeSet<String>,
) -> Result<ReviewPolicyEnvelopeEvidenceChirho> {
    let envelopes_chirho = verified_review_policy_envelopes_chirho(root_chirho)?;
    let latest_chirho = envelopes_chirho.iter().rev().find(|envelope_chirho| {
        review_policy_envelope_matches_chirho(
            &envelope_chirho.record_chirho,
            app_chirho,
            owner_principal_chirho,
        )
    });
    let Some(latest_chirho) = latest_chirho else {
        return Ok(ReviewPolicyEnvelopeEvidenceChirho::AbsentChirho {
            checked_envelope_count_chirho: envelopes_chirho.len(),
        });
    };
    enforce_review_policy_envelope_against_candidate_chirho(
        root_chirho,
        &latest_chirho.record_chirho,
        app_chirho,
        owner_principal_chirho,
        candidate_chirho,
        diff_chirho,
        candidate_contract_refs_chirho,
    )?;
    Ok(ReviewPolicyEnvelopeEvidenceChirho::BoundChirho {
        envelope_seq_chirho: latest_chirho.record_chirho.seq_chirho,
        envelope_line_hash_chirho: latest_chirho.line_hash_chirho.clone(),
    })
}
fn validate_review_policy_envelope_evidence_chirho(
    root_chirho: &Path,
    record_chirho: &ReviewRecordChirho,
) -> Result<()> {
    let Some(evidence_chirho) = &record_chirho.review_policy_envelope_chirho else {
        return Ok(());
    };
    let envelopes_chirho = verified_review_policy_envelopes_chirho(root_chirho)?;
    match evidence_chirho {
        ReviewPolicyEnvelopeEvidenceChirho::AbsentChirho {
            checked_envelope_count_chirho,
        } => {
            if *checked_envelope_count_chirho > envelopes_chirho.len() {
                bail!(
                    "review record {} checked {} review-policy envelope(s), but only {} exist",
                    record_chirho.seq_chirho,
                    checked_envelope_count_chirho,
                    envelopes_chirho.len()
                );
            }
            for envelope_chirho in envelopes_chirho.iter().take(*checked_envelope_count_chirho) {
                if review_policy_envelope_matches_chirho(
                    &envelope_chirho.record_chirho,
                    &record_chirho.app_chirho,
                    &record_chirho.owner_principal_chirho,
                ) {
                    bail!(
                        "review record {} claims no review-policy envelope, but envelope {} was in the checked prefix",
                        record_chirho.seq_chirho,
                        envelope_chirho.record_chirho.seq_chirho
                    );
                }
            }
            Ok(())
        }
        ReviewPolicyEnvelopeEvidenceChirho::BoundChirho {
            envelope_seq_chirho,
            envelope_line_hash_chirho,
        } => {
            let envelope_chirho = envelopes_chirho
                .get(*envelope_seq_chirho as usize)
                .ok_or_else(|| {
                    anyhow!(
                        "review record {} points at missing review-policy envelope {}",
                        record_chirho.seq_chirho,
                        envelope_seq_chirho
                    )
                })?;
            if envelope_chirho.record_chirho.seq_chirho != *envelope_seq_chirho
                || &envelope_chirho.line_hash_chirho != envelope_line_hash_chirho
            {
                bail!(
                    "review record {} review-policy envelope binding mismatch",
                    record_chirho.seq_chirho
                );
            }
            let candidate_contract_refs_chirho =
                review_use_case_chirho::contract_refs_for_review_record_chirho(
                    &RootReviewPortChirho::local_chirho(root_chirho),
                    record_chirho,
                )?;
            enforce_review_policy_envelope_against_candidate_chirho(
                root_chirho,
                &envelope_chirho.record_chirho,
                &record_chirho.app_chirho,
                &record_chirho.owner_principal_chirho,
                &record_chirho.candidate_chirho,
                &record_chirho.diff_chirho,
                &candidate_contract_refs_chirho,
            )
        }
    }
}
fn enforce_review_policy_envelope_against_candidate_chirho(
    root_chirho: &Path,
    envelope_chirho: &ReviewPolicyEnvelopeRecordChirho,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: &HashChirho,
    diff_chirho: &ReviewSurfaceDiffChirho,
    candidate_contract_refs_chirho: &BTreeSet<String>,
) -> Result<()> {
    let candidate_surface_chirho = load_dag_surface_chirho(root_chirho, candidate_chirho)?;
    let candidate_capability_labels_chirho = candidate_surface_chirho
        .capabilities_chirho
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    cairn_review_policy_chirho::enforce_review_policy_envelope_chirho(
        cairn_review_policy_chirho::ReviewPolicyEnvelopeCheckInputChirho {
            envelope_chirho,
            app_chirho,
            owner_principal_chirho,
            candidate_capability_labels_chirho: &candidate_capability_labels_chirho,
            candidate_cost_token_chirho: diff_chirho.candidate_cost_token_chirho,
            candidate_contract_refs_chirho,
        },
    )
}
fn review_policy_envelope_matches_chirho(
    envelope_chirho: &ReviewPolicyEnvelopeRecordChirho,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> bool {
    envelope_chirho.app_chirho == app_chirho
        && review_policy_envelope_owner_chirho(envelope_chirho) == owner_principal_chirho
}
fn review_policy_envelope_owner_chirho(envelope_chirho: &ReviewPolicyEnvelopeRecordChirho) -> &str {
    match &envelope_chirho.scope_chirho {
        ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
            owner_principal_chirho,
        } => owner_principal_chirho,
    }
}
fn load_dag_surface_chirho(
    root_chirho: &Path,
    dag_chirho: &HashChirho,
) -> Result<ReviewDagSurfaceChirho> {
    let dag_obj_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_chirho)
        .with_context(|| format!("review DAG {} is not in the store", dag_chirho.0))?;
    let mut capabilities_chirho = BTreeMap::new();
    let mut paid_effect_counts_chirho = BTreeMap::new();
    for node_chirho in &dag_obj_chirho.nodes_chirho {
        let node_def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_chirho).with_context(|| {
                format!(
                    "DAG {} node {} is not a NodeDefChirho",
                    dag_chirho.0, node_chirho.0
                )
            })?;
        for capability_chirho in &node_def_chirho.capabilities_chirho {
            let label_chirho =
                cairn_review_policy_chirho::review_capability_label_chirho(capability_chirho);
            *capabilities_chirho.entry(label_chirho).or_insert(0) += 1;
            if let CapabilityChirho::PaidEffectChirho { effect_chirho, .. } = capability_chirho {
                *paid_effect_counts_chirho
                    .entry(effect_chirho.clone())
                    .or_insert(0) += 1;
            }
        }
    }
    Ok(ReviewDagSurfaceChirho {
        node_count_chirho: dag_obj_chirho.nodes_chirho.len(),
        edge_count_chirho: dag_obj_chirho.edges_chirho.len(),
        nodes_chirho: dag_obj_chirho.nodes_chirho.into_iter().collect(),
        capabilities_chirho,
        paid_effect_counts_chirho,
    })
}

fn current_app_dag_chirho(root_chirho: &Path, app_chirho: &str) -> Result<Option<HashChirho>> {
    validate_app_name_chirho(app_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    Ok(
        app_chirho::maybe_resolve_app_dag_chirho(root_chirho, &refs_chirho, app_chirho)?
            .map(|resolved_chirho| resolved_chirho.dag_chirho),
    )
}

// Collect the DISTINCT typed capabilities across a DAG's nodes, in first-seen order — the honest
// set of everything the app can do to the world, from the content-addressed node definitions.
// `collect_dag_capabilities_chirho` moved to `cairn_core_chirho::dag_capability_scan_chirho`. It
// had no root dependencies -- only this crate's re-exported model types and object store -- and
// three consumers across two pillars plus the CLI, so it belonged below all of them. Moving it took
// the app_authoring -> governance_flows edge to zero and broke that pillar cycle.

/// The plain-language capability summary of a deployed app's root DAG (or None when the app is
/// not deployed) — the "what can this app do?" review answer, for the owner UI, API, and MCP.
pub fn app_capability_summary_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<crate::capability_plain_chirho::CapabilitySummaryChirho>> {
    match current_app_dag_chirho(root_chirho, app_chirho)? {
        Some(dag_chirho) => {
            let capabilities_chirho =
                crate::dag_capability_scan_chirho::collect_dag_capabilities_chirho(
                    root_chirho,
                    &dag_chirho,
                )?;
            Ok(Some(
                crate::capability_plain_chirho::summarize_capabilities_chirho(&capabilities_chirho),
            ))
        }
        None => Ok(None),
    }
}

fn resolve_review_prices_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    counts_chirho: &BTreeMap<String, u64>,
    price_book_chirho: &Option<HashChirho>,
    warnings_chirho: &mut Vec<String>,
) -> Result<BTreeMap<String, ReviewResolvedPriceChirho>> {
    let mut out_chirho = BTreeMap::new();
    for effect_chirho in counts_chirho.keys() {
        let (unit_cost_token_chirho, source_chirho) = resolve_review_price_chirho(
            root_chirho,
            app_chirho,
            effect_chirho,
            price_book_chirho,
            warnings_chirho,
        )?;
        out_chirho.insert(
            effect_chirho.clone(),
            ReviewResolvedPriceChirho {
                unit_cost_token_chirho,
                source_chirho,
            },
        );
    }
    Ok(out_chirho)
}

fn resolve_review_price_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    effect_chirho: &str,
    price_book_chirho: &Option<HashChirho>,
    warnings_chirho: &mut Vec<String>,
) -> Result<(i64, String)> {
    if let Some(hash_chirho) = price_book_chirho {
        let book_chirho: effect_pricing_chirho::PriceBookChirho =
            store_chirho::get_object_chirho(root_chirho, hash_chirho).with_context(|| {
                format!("review price book {} is not in the store", hash_chirho.0)
            })?;
        if book_chirho.app_chirho != app_chirho {
            bail!(
                "review price book {} belongs to app '{}', not '{app_chirho}'",
                hash_chirho.0,
                book_chirho.app_chirho
            );
        }
        if let Some(price_chirho) = book_chirho.effect_prices_chirho.get(effect_chirho).copied() {
            if price_chirho <= 0 {
                bail!(
                    "review price book {} has non-positive price for effect '{effect_chirho}'",
                    hash_chirho.0
                );
            }
            return Ok((price_chirho, format!("pricebook:{}", hash_chirho.0)));
        }
        if let Some(price_chirho) = book_chirho.price_per_request_chirho {
            if price_chirho <= 0 {
                bail!(
                    "review price book {} has non-positive request price",
                    hash_chirho.0
                );
            }
            return Ok((price_chirho, format!("pricebook:{}", hash_chirho.0)));
        }
    }
    match effect_pricing_chirho::registered_effect_price_chirho(effect_chirho) {
        Some((price_chirho, _provider_chirho)) => {
            Ok((price_chirho, "registered-effect".to_string()))
        }
        None => {
            warnings_chirho.push(format!(
                "unknown paid effect '{effect_chirho}' has no price"
            ));
            Ok((0, "unknown".to_string()))
        }
    }
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
fn current_reviewed_app_record_seq_for_candidate_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    candidate_chirho: &HashChirho,
) -> Result<Option<u64>> {
    let status_chirho = app_chirho::app_status_chirho(root_chirho, app_chirho)?;
    if !status_chirho.active_chirho
        || status_chirho.owner_principal_chirho.as_deref() != Some(owner_principal_chirho)
        || status_chirho.dag_chirho.as_ref() != Some(candidate_chirho)
    {
        return Ok(None);
    }
    let selected_chirho = app_chirho::verified_app_records_chirho(root_chirho)?
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.owner_principal_chirho == owner_principal_chirho
                && record_chirho.dag_chirho.as_ref() == Some(candidate_chirho)
        })
        .ok_or_else(|| anyhow!("current app candidate has no verified deploy record"))?;
    if !app_action_is_reviewed_deploy_chirho(&selected_chirho.action_chirho) {
        bail!(
            "cannot promote an already-live unreviewed dev candidate in place; run source review and promotion before moving the app live"
        );
    }
    Ok(Some(selected_chirho.seq_chirho))
}

fn append_review_record_chirho(
    root_chirho: &Path,
    input_chirho: ReviewAppendInputChirho,
) -> Result<ReviewRecordChirho> {
    validate_review_source_evidence_chirho(
        root_chirho,
        &input_chirho.candidate_chirho,
        &input_chirho.diff_chirho,
        &input_chirho.source_review_report_chirho,
        &input_chirho.source_manifest_chirho,
    )?;
    let path_chirho = review_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = ReviewRecordChirho {
            seq_chirho,
            schema_chirho: REVIEW_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: input_chirho.app_chirho,
            owner_principal_chirho: input_chirho.owner_principal_chirho,
            live_before_chirho: input_chirho.live_before_chirho,
            candidate_chirho: input_chirho.candidate_chirho,
            source_review_report_chirho: input_chirho.source_review_report_chirho,
            source_manifest_chirho: input_chirho.source_manifest_chirho,
            decision_chirho: input_chirho.decision_chirho,
            accepted_capability_escalation_chirho: input_chirho
                .accepted_capability_escalation_chirho,
            accepted_cost_increase_chirho: input_chirho.accepted_cost_increase_chirho,
            review_policy_envelope_chirho: input_chirho.review_policy_envelope_chirho,
            app_record_seq_chirho: input_chirho.app_record_seq_chirho,
            reason_chirho: input_chirho.reason_chirho,
            diff_chirho: input_chirho.diff_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &review_record_message_chirho(&record_chirho)?,
        )?;
        Ok(record_chirho)
    })
}

fn validate_review_record_chirho(record_chirho: &ReviewRecordChirho) -> Result<()> {
    validate_review_record_schema_chirho(record_chirho)?;
    validate_app_name_chirho(&record_chirho.app_chirho)?;
    if record_chirho.owner_principal_chirho.trim().is_empty()
        || record_chirho
            .owner_principal_chirho
            .chars()
            .any(char::is_whitespace)
    {
        bail!("review owner principal is invalid");
    }
    if let Some(reason_chirho) = &record_chirho.reason_chirho {
        validate_reason_chirho(reason_chirho)?;
    }
    Ok(())
}

fn validate_review_policy_envelope_record_chirho(
    record_chirho: &ReviewPolicyEnvelopeRecordChirho,
) -> Result<()> {
    validate_review_policy_envelope_schema_chirho(record_chirho)?;
    cairn_review_policy_chirho::validate_review_policy_envelope_shape_chirho(record_chirho)
}

fn validate_review_record_schema_chirho(record_chirho: &ReviewRecordChirho) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != REVIEW_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "review record {} has unsupported schema '{}'",
            record_chirho.seq_chirho,
            record_chirho.schema_chirho
        );
    }
    Ok(())
}

fn validate_review_policy_envelope_schema_chirho(
    record_chirho: &ReviewPolicyEnvelopeRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO {
        bail!(
            "review-policy envelope {} has unsupported schema '{}'",
            record_chirho.seq_chirho,
            record_chirho.schema_chirho
        );
    }
    Ok(())
}

fn validate_review_source_evidence_chirho(
    root_chirho: &Path,
    candidate_chirho: &HashChirho,
    diff_chirho: &ReviewSurfaceDiffChirho,
    source_review_report_chirho: &Option<HashChirho>,
    source_manifest_chirho: &Option<ReviewSourceManifestEvidenceChirho>,
) -> Result<()> {
    let port_chirho = RootReviewPortChirho::local_chirho(root_chirho);
    review_use_case_chirho::validate_review_source_evidence_chirho(
        &port_chirho,
        review_use_case_chirho::ReviewSourceEvidenceInputChirho {
            candidate_chirho,
            diff_chirho,
            source_review_report_chirho,
            source_manifest_chirho,
        },
    )
    .map(|_| ())
}

fn validate_owner_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<()> {
    if let Some(existing_owner_chirho) =
        app_chirho::verified_app_owner_chirho(root_chirho, app_chirho)?
    {
        if existing_owner_chirho != owner_principal_chirho {
            bail!("app '{app_chirho}' is owned by '{existing_owner_chirho}', not '{owner_principal_chirho}'");
        }
    }
    if !owner_principal_chirho.starts_with("owner/")
        || owner_principal_chirho.chars().any(char::is_whitespace)
    {
        bail!("review owner must be an owner/<id> principal");
    }
    let owner_chirho = identity_chirho::find_identity_chirho(root_chirho, owner_principal_chirho)?
        .ok_or_else(|| anyhow!("unknown owner principal '{owner_principal_chirho}'"))?;
    if owner_chirho.kind_chirho != identity_chirho::PrincipalKindChirho::OwnerChirho {
        bail!("review owner must be an owner principal");
    }
    Ok(())
}

fn validate_app_name_chirho(app_chirho: &str) -> Result<()> {
    if app_chirho.trim().is_empty()
        || app_chirho.contains('/')
        || app_chirho.chars().any(char::is_whitespace)
    {
        bail!("app_chirho must not be empty or contain slashes/whitespace");
    }
    Ok(())
}

fn validate_reason_chirho(reason_chirho: &str) -> Result<()> {
    if reason_chirho.trim().is_empty() || reason_chirho.chars().any(char::is_control) {
        bail!("review rejection reason must not be empty or contain control characters");
    }
    Ok(())
}

fn review_record_message_chirho(record_chirho: &ReviewRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn review_policy_envelope_message_chirho(
    record_chirho: &ReviewPolicyEnvelopeRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

#[cfg(test)]
mod tests_chirho;
