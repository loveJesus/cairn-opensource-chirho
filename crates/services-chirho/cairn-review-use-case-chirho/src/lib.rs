// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Injectable review use-case orchestration.
//!
//! This crate owns review use-case sequencing but not the authority-bearing operations. Callers
//! provide already-trusted ports for current refs, DAG surfaces, price books, resolved paid-effect
//! prices, owner authorization, candidate publication, and signed review record persistence.

use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_app_chirho::AppSourceReviewReportChirho;
use cairn_model_review_chirho::{
    ReviewDecisionChirho, ReviewPolicyEnvelopeEvidenceChirho, ReviewRecordChirho,
    ReviewSourceEvidenceChirho, ReviewSourceManifestEvidenceChirho, ReviewSurfaceDiffChirho,
};
use cairn_review_policy_chirho::{
    ReviewDagSurfaceChirho, ReviewLoadedSourceReportChirho, ReviewResolvedPriceChirho,
    ReviewSourceEvidenceBindingInputChirho, ReviewSurfaceDiffInputChirho,
};
use std::collections::{BTreeMap, BTreeSet};

pub trait ReviewCandidatePortChirho {
    fn dag_surface_chirho(&self, dag_chirho: &HashChirho) -> Result<ReviewDagSurfaceChirho>;

    fn resolved_prices_chirho(
        &self,
        app_chirho: &str,
        paid_effect_counts_chirho: &BTreeMap<String, u64>,
        price_book_chirho: &Option<HashChirho>,
        warnings_chirho: &mut Vec<String>,
    ) -> Result<BTreeMap<String, ReviewResolvedPriceChirho>>;
}

pub struct ReviewCandidatePortFnsChirho<DagSurfaceFnChirho, ResolvedPricesFnChirho> {
    pub dag_surface_chirho: DagSurfaceFnChirho,
    pub resolved_prices_chirho: ResolvedPricesFnChirho,
}

impl<DagSurfaceFnChirho, ResolvedPricesFnChirho> ReviewCandidatePortChirho
    for ReviewCandidatePortFnsChirho<DagSurfaceFnChirho, ResolvedPricesFnChirho>
where
    DagSurfaceFnChirho: Fn(&HashChirho) -> Result<ReviewDagSurfaceChirho>,
    ResolvedPricesFnChirho: Fn(
        &str,
        &BTreeMap<String, u64>,
        &Option<HashChirho>,
        &mut Vec<String>,
    ) -> Result<BTreeMap<String, ReviewResolvedPriceChirho>>,
{
    fn dag_surface_chirho(&self, dag_chirho: &HashChirho) -> Result<ReviewDagSurfaceChirho> {
        (self.dag_surface_chirho)(dag_chirho)
    }

    fn resolved_prices_chirho(
        &self,
        app_chirho: &str,
        paid_effect_counts_chirho: &BTreeMap<String, u64>,
        price_book_chirho: &Option<HashChirho>,
        warnings_chirho: &mut Vec<String>,
    ) -> Result<BTreeMap<String, ReviewResolvedPriceChirho>> {
        (self.resolved_prices_chirho)(
            app_chirho,
            paid_effect_counts_chirho,
            price_book_chirho,
            warnings_chirho,
        )
    }
}

pub struct ReviewCandidateAgainstLiveInputChirho<'a> {
    pub app_chirho: &'a str,
    pub live_chirho: Option<HashChirho>,
    pub candidate_chirho: HashChirho,
    pub price_book_chirho: Option<HashChirho>,
}

pub trait ReviewSourceEvidencePortChirho {
    fn load_source_review_report_chirho(
        &self,
        source_review_report_chirho: &HashChirho,
    ) -> Result<LoadedSourceReviewReportChirho>;

    fn validate_effective_source_manifest_chirho(
        &self,
        effective_manifest_hash_chirho: &HashChirho,
    ) -> Result<()>;

    fn validate_raw_source_manifest_chirho(
        &self,
        raw_manifest_hash_chirho: &HashChirho,
    ) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedSourceReviewReportChirho {
    pub source_review_report_chirho: HashChirho,
    pub canonical_hash_chirho: HashChirho,
    pub report_chirho: AppSourceReviewReportChirho,
}

pub struct ReviewSourceEvidenceInputChirho<'a> {
    pub candidate_chirho: &'a HashChirho,
    pub diff_chirho: &'a ReviewSurfaceDiffChirho,
    pub source_review_report_chirho: &'a Option<HashChirho>,
    pub source_manifest_chirho: &'a Option<ReviewSourceManifestEvidenceChirho>,
}

pub trait ReviewDecisionPortChirho:
    ReviewCandidatePortChirho + ReviewSourceEvidencePortChirho
{
    fn current_live_chirho(&self, app_chirho: &str) -> Result<Option<HashChirho>>;

    fn current_price_book_chirho(&self, app_chirho: &str) -> Result<Option<HashChirho>>;

    fn authorize_owner_chirho(&self, app_chirho: &str, owner_principal_chirho: &str) -> Result<()>;

    fn enforce_review_policy_envelope_chirho(
        &self,
        input_chirho: ReviewPolicyEnvelopeDecisionInputChirho<'_>,
    ) -> Result<ReviewPolicyEnvelopeEvidenceChirho>;

    fn publish_candidate_chirho(
        &self,
        app_chirho: &str,
        owner_principal_chirho: &str,
        candidate_chirho: &HashChirho,
        source_review_report_chirho: Option<&HashChirho>,
    ) -> Result<u64>;

    fn record_decision_chirho(
        &self,
        input_chirho: ReviewDecisionRecordInputChirho,
    ) -> Result<ReviewRecordChirho>;
}

pub struct PromoteCandidateInputChirho<'a> {
    pub app_chirho: &'a str,
    pub owner_principal_chirho: &'a str,
    pub candidate_chirho: HashChirho,
    pub accept_capability_escalation_chirho: bool,
    pub accept_cost_increase_chirho: bool,
    pub require_review_policy_envelope_chirho: bool,
    pub source_evidence_chirho: ReviewSourceEvidenceChirho,
}

pub struct RejectCandidateInputChirho<'a> {
    pub app_chirho: &'a str,
    pub owner_principal_chirho: &'a str,
    pub candidate_chirho: HashChirho,
    pub reason_chirho: &'a str,
    pub source_evidence_chirho: ReviewSourceEvidenceChirho,
}

pub struct ReviewDecisionRecordInputChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub live_before_chirho: Option<HashChirho>,
    pub candidate_chirho: HashChirho,
    pub source_review_report_chirho: Option<HashChirho>,
    pub source_manifest_chirho: Option<ReviewSourceManifestEvidenceChirho>,
    pub decision_chirho: ReviewDecisionChirho,
    pub accepted_capability_escalation_chirho: bool,
    pub accepted_cost_increase_chirho: bool,
    pub review_policy_envelope_chirho: Option<ReviewPolicyEnvelopeEvidenceChirho>,
    pub app_record_seq_chirho: Option<u64>,
    pub reason_chirho: Option<String>,
    pub diff_chirho: ReviewSurfaceDiffChirho,
}

pub struct ReviewPolicyEnvelopeDecisionInputChirho<'a> {
    pub app_chirho: &'a str,
    pub owner_principal_chirho: &'a str,
    pub candidate_chirho: &'a HashChirho,
    pub diff_chirho: &'a ReviewSurfaceDiffChirho,
    pub candidate_contract_refs_chirho: &'a BTreeSet<String>,
}

pub fn review_candidate_against_live_chirho<PortChirho: ReviewCandidatePortChirho + ?Sized>(
    port_chirho: &PortChirho,
    input_chirho: ReviewCandidateAgainstLiveInputChirho<'_>,
) -> Result<ReviewSurfaceDiffChirho> {
    let live_summary_chirho = match &input_chirho.live_chirho {
        Some(live_chirho) => Some(port_chirho.dag_surface_chirho(live_chirho)?),
        None => None,
    };
    let candidate_summary_chirho =
        port_chirho.dag_surface_chirho(&input_chirho.candidate_chirho)?;
    let empty_paid_counts_chirho = BTreeMap::new();
    let live_paid_counts_chirho = live_summary_chirho
        .as_ref()
        .map(|summary_chirho| &summary_chirho.paid_effect_counts_chirho)
        .unwrap_or(&empty_paid_counts_chirho);
    let mut warnings_chirho = Vec::new();
    let live_prices_chirho = port_chirho.resolved_prices_chirho(
        input_chirho.app_chirho,
        live_paid_counts_chirho,
        &input_chirho.price_book_chirho,
        &mut warnings_chirho,
    )?;
    let candidate_prices_chirho = port_chirho.resolved_prices_chirho(
        input_chirho.app_chirho,
        &candidate_summary_chirho.paid_effect_counts_chirho,
        &input_chirho.price_book_chirho,
        &mut warnings_chirho,
    )?;

    cairn_review_policy_chirho::review_surface_diff_chirho(ReviewSurfaceDiffInputChirho {
        app_chirho: input_chirho.app_chirho,
        live_chirho: input_chirho.live_chirho,
        candidate_chirho: input_chirho.candidate_chirho,
        price_book_chirho: input_chirho.price_book_chirho,
        live_summary_chirho: live_summary_chirho.as_ref(),
        candidate_summary_chirho: &candidate_summary_chirho,
        live_prices_chirho: &live_prices_chirho,
        candidate_prices_chirho: &candidate_prices_chirho,
        warnings_chirho,
    })
}

pub fn validate_review_source_evidence_chirho<
    PortChirho: ReviewSourceEvidencePortChirho + ?Sized,
>(
    port_chirho: &PortChirho,
    input_chirho: ReviewSourceEvidenceInputChirho<'_>,
) -> Result<BTreeSet<String>> {
    let source_review_report_chirho = match input_chirho.source_review_report_chirho {
        Some(source_review_report_chirho) => {
            Some(port_chirho.load_source_review_report_chirho(source_review_report_chirho)?)
        }
        None => None,
    };
    let policy_source_report_chirho =
        source_review_report_chirho
            .as_ref()
            .map(|report_chirho| ReviewLoadedSourceReportChirho {
                source_review_report_chirho: &report_chirho.source_review_report_chirho,
                canonical_hash_chirho: &report_chirho.canonical_hash_chirho,
                report_chirho: &report_chirho.report_chirho,
            });
    let report_source_manifest_chirho =
        cairn_review_policy_chirho::validate_review_source_evidence_binding_chirho(
            ReviewSourceEvidenceBindingInputChirho {
                candidate_chirho: input_chirho.candidate_chirho,
                diff_chirho: input_chirho.diff_chirho,
                source_review_report_chirho: policy_source_report_chirho,
                source_manifest_chirho: input_chirho.source_manifest_chirho.as_ref(),
            },
        )?;
    if let Some(report_source_manifest_chirho) = &report_source_manifest_chirho {
        validate_source_manifest_evidence_chirho(port_chirho, report_source_manifest_chirho)?;
    }
    if let Some(source_manifest_chirho) = input_chirho.source_manifest_chirho {
        validate_source_manifest_evidence_chirho(port_chirho, source_manifest_chirho)?;
    }
    Ok(source_review_report_chirho
        .as_ref()
        .map(|report_chirho| {
            report_chirho
                .report_chirho
                .candidate_chirho
                .contract_refs_chirho
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default())
}

pub fn contract_refs_for_review_record_chirho<
    PortChirho: ReviewSourceEvidencePortChirho + ?Sized,
>(
    port_chirho: &PortChirho,
    record_chirho: &ReviewRecordChirho,
) -> Result<BTreeSet<String>> {
    validate_review_source_evidence_chirho(
        port_chirho,
        ReviewSourceEvidenceInputChirho {
            candidate_chirho: &record_chirho.candidate_chirho,
            diff_chirho: &record_chirho.diff_chirho,
            source_review_report_chirho: &record_chirho.source_review_report_chirho,
            source_manifest_chirho: &record_chirho.source_manifest_chirho,
        },
    )
}

fn validate_source_manifest_evidence_chirho<PortChirho: ReviewSourceEvidencePortChirho + ?Sized>(
    port_chirho: &PortChirho,
    source_manifest_chirho: &ReviewSourceManifestEvidenceChirho,
) -> Result<()> {
    port_chirho.validate_effective_source_manifest_chirho(
        &source_manifest_chirho.effective_manifest_hash_chirho,
    )?;
    if let Some(raw_manifest_hash_chirho) = &source_manifest_chirho.raw_manifest_hash_chirho {
        port_chirho.validate_raw_source_manifest_chirho(raw_manifest_hash_chirho)?;
    }
    Ok(())
}

pub fn promote_candidate_with_review_evidence_chirho<
    PortChirho: ReviewDecisionPortChirho + ?Sized,
>(
    port_chirho: &PortChirho,
    input_chirho: PromoteCandidateInputChirho<'_>,
) -> Result<ReviewRecordChirho> {
    let (live_before_chirho, diff_chirho) = review_current_candidate_chirho(
        port_chirho,
        input_chirho.app_chirho,
        input_chirho.candidate_chirho.clone(),
    )?;
    if !diff_chirho.added_capabilities_chirho.is_empty()
        && !input_chirho.accept_capability_escalation_chirho
    {
        bail!("candidate adds capabilities; pass --accept-capability-escalation to promote");
    }
    if diff_chirho.cost_delta_token_chirho > 0 && !input_chirho.accept_cost_increase_chirho {
        bail!("candidate increases per-invocation cost; pass --accept-cost-increase to promote");
    }
    let candidate_contract_refs_chirho = validate_review_source_evidence_chirho(
        port_chirho,
        ReviewSourceEvidenceInputChirho {
            candidate_chirho: &input_chirho.candidate_chirho,
            diff_chirho: &diff_chirho,
            source_review_report_chirho: &input_chirho
                .source_evidence_chirho
                .source_review_report_chirho,
            source_manifest_chirho: &input_chirho.source_evidence_chirho.source_manifest_chirho,
        },
    )?;
    let review_policy_envelope_chirho = port_chirho.enforce_review_policy_envelope_chirho(
        ReviewPolicyEnvelopeDecisionInputChirho {
            app_chirho: input_chirho.app_chirho,
            owner_principal_chirho: input_chirho.owner_principal_chirho,
            candidate_chirho: &input_chirho.candidate_chirho,
            diff_chirho: &diff_chirho,
            candidate_contract_refs_chirho: &candidate_contract_refs_chirho,
        },
    )?;
    if input_chirho.require_review_policy_envelope_chirho
        && matches!(
            review_policy_envelope_chirho,
            ReviewPolicyEnvelopeEvidenceChirho::AbsentChirho { .. }
        )
    {
        bail!("learner promotion requires a review-policy envelope");
    }
    let app_record_seq_chirho = port_chirho.publish_candidate_chirho(
        input_chirho.app_chirho,
        input_chirho.owner_principal_chirho,
        &input_chirho.candidate_chirho,
        input_chirho
            .source_evidence_chirho
            .source_review_report_chirho
            .as_ref(),
    )?;
    port_chirho.record_decision_chirho(ReviewDecisionRecordInputChirho {
        app_chirho: input_chirho.app_chirho.to_string(),
        owner_principal_chirho: input_chirho.owner_principal_chirho.to_string(),
        live_before_chirho,
        candidate_chirho: input_chirho.candidate_chirho,
        source_review_report_chirho: input_chirho
            .source_evidence_chirho
            .source_review_report_chirho,
        source_manifest_chirho: input_chirho.source_evidence_chirho.source_manifest_chirho,
        decision_chirho: ReviewDecisionChirho::PromoteChirho,
        accepted_capability_escalation_chirho: input_chirho.accept_capability_escalation_chirho,
        accepted_cost_increase_chirho: input_chirho.accept_cost_increase_chirho,
        review_policy_envelope_chirho: Some(review_policy_envelope_chirho),
        app_record_seq_chirho: Some(app_record_seq_chirho),
        reason_chirho: None,
        diff_chirho,
    })
}

pub fn reject_candidate_with_review_evidence_chirho<
    PortChirho: ReviewDecisionPortChirho + ?Sized,
>(
    port_chirho: &PortChirho,
    input_chirho: RejectCandidateInputChirho<'_>,
) -> Result<ReviewRecordChirho> {
    validate_reason_chirho(input_chirho.reason_chirho)?;
    let (live_before_chirho, diff_chirho) = review_current_candidate_chirho(
        port_chirho,
        input_chirho.app_chirho,
        input_chirho.candidate_chirho.clone(),
    )?;
    port_chirho
        .authorize_owner_chirho(input_chirho.app_chirho, input_chirho.owner_principal_chirho)?;
    validate_review_source_evidence_chirho(
        port_chirho,
        ReviewSourceEvidenceInputChirho {
            candidate_chirho: &input_chirho.candidate_chirho,
            diff_chirho: &diff_chirho,
            source_review_report_chirho: &input_chirho
                .source_evidence_chirho
                .source_review_report_chirho,
            source_manifest_chirho: &input_chirho.source_evidence_chirho.source_manifest_chirho,
        },
    )?;
    port_chirho.record_decision_chirho(ReviewDecisionRecordInputChirho {
        app_chirho: input_chirho.app_chirho.to_string(),
        owner_principal_chirho: input_chirho.owner_principal_chirho.to_string(),
        live_before_chirho,
        candidate_chirho: input_chirho.candidate_chirho,
        source_review_report_chirho: input_chirho
            .source_evidence_chirho
            .source_review_report_chirho,
        source_manifest_chirho: input_chirho.source_evidence_chirho.source_manifest_chirho,
        decision_chirho: ReviewDecisionChirho::RejectChirho,
        accepted_capability_escalation_chirho: false,
        accepted_cost_increase_chirho: false,
        review_policy_envelope_chirho: None,
        app_record_seq_chirho: None,
        reason_chirho: Some(input_chirho.reason_chirho.to_string()),
        diff_chirho,
    })
}

fn review_current_candidate_chirho<PortChirho: ReviewDecisionPortChirho + ?Sized>(
    port_chirho: &PortChirho,
    app_chirho: &str,
    candidate_chirho: HashChirho,
) -> Result<(Option<HashChirho>, ReviewSurfaceDiffChirho)> {
    validate_app_name_chirho(app_chirho)?;
    let live_before_chirho = port_chirho.current_live_chirho(app_chirho)?;
    let price_book_chirho = port_chirho.current_price_book_chirho(app_chirho)?;
    let diff_chirho = review_candidate_against_live_chirho(
        port_chirho,
        ReviewCandidateAgainstLiveInputChirho {
            app_chirho,
            live_chirho: live_before_chirho.clone(),
            candidate_chirho,
            price_book_chirho,
        },
    )?;
    Ok((live_before_chirho, diff_chirho))
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

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_model_app_chirho::{AppSourceCandidateReportChirho, AppSourceManifestEvidenceChirho};
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    struct FakeReviewPortChirho {
        surfaces_chirho: BTreeMap<HashChirho, ReviewDagSurfaceChirho>,
        prices_chirho: BTreeMap<String, ReviewResolvedPriceChirho>,
    }

    struct FakeSourceEvidencePortChirho {
        report_chirho: LoadedSourceReviewReportChirho,
    }

    struct FakeDecisionPortChirho {
        surfaces_chirho: BTreeMap<HashChirho, ReviewDagSurfaceChirho>,
        prices_chirho: BTreeMap<String, ReviewResolvedPriceChirho>,
        live_chirho: Option<HashChirho>,
        price_book_chirho: Option<HashChirho>,
        calls_chirho: RefCell<Vec<String>>,
    }

    impl ReviewCandidatePortChirho for FakeReviewPortChirho {
        fn dag_surface_chirho(&self, dag_chirho: &HashChirho) -> Result<ReviewDagSurfaceChirho> {
            Ok(self
                .surfaces_chirho
                .get(dag_chirho)
                .expect("test DAG surface exists")
                .clone())
        }

        fn resolved_prices_chirho(
            &self,
            _app_chirho: &str,
            paid_effect_counts_chirho: &BTreeMap<String, u64>,
            _price_book_chirho: &Option<HashChirho>,
            _warnings_chirho: &mut Vec<String>,
        ) -> Result<BTreeMap<String, ReviewResolvedPriceChirho>> {
            Ok(paid_effect_counts_chirho
                .keys()
                .filter_map(|effect_chirho| {
                    self.prices_chirho
                        .get(effect_chirho)
                        .map(|price_chirho| (effect_chirho.clone(), price_chirho.clone()))
                })
                .collect())
        }
    }

    impl ReviewSourceEvidencePortChirho for FakeSourceEvidencePortChirho {
        fn load_source_review_report_chirho(
            &self,
            source_review_report_chirho: &HashChirho,
        ) -> Result<LoadedSourceReviewReportChirho> {
            assert_eq!(
                source_review_report_chirho,
                &self.report_chirho.source_review_report_chirho
            );
            Ok(self.report_chirho.clone())
        }

        fn validate_effective_source_manifest_chirho(
            &self,
            effective_manifest_hash_chirho: &HashChirho,
        ) -> Result<()> {
            assert_eq!(
                effective_manifest_hash_chirho,
                &hash_chirho("effective_chirho")
            );
            Ok(())
        }

        fn validate_raw_source_manifest_chirho(
            &self,
            raw_manifest_hash_chirho: &HashChirho,
        ) -> Result<()> {
            assert_eq!(raw_manifest_hash_chirho, &hash_chirho("raw_chirho"));
            Ok(())
        }
    }

    impl ReviewCandidatePortChirho for FakeDecisionPortChirho {
        fn dag_surface_chirho(&self, dag_chirho: &HashChirho) -> Result<ReviewDagSurfaceChirho> {
            self.calls_chirho
                .borrow_mut()
                .push(format!("surface:{}", dag_chirho.0));
            Ok(self
                .surfaces_chirho
                .get(dag_chirho)
                .expect("test DAG surface exists")
                .clone())
        }

        fn resolved_prices_chirho(
            &self,
            _app_chirho: &str,
            paid_effect_counts_chirho: &BTreeMap<String, u64>,
            _price_book_chirho: &Option<HashChirho>,
            _warnings_chirho: &mut Vec<String>,
        ) -> Result<BTreeMap<String, ReviewResolvedPriceChirho>> {
            self.calls_chirho.borrow_mut().push("prices".to_string());
            Ok(paid_effect_counts_chirho
                .keys()
                .filter_map(|effect_chirho| {
                    self.prices_chirho
                        .get(effect_chirho)
                        .map(|price_chirho| (effect_chirho.clone(), price_chirho.clone()))
                })
                .collect())
        }
    }

    impl ReviewSourceEvidencePortChirho for FakeDecisionPortChirho {
        fn load_source_review_report_chirho(
            &self,
            _source_review_report_chirho: &HashChirho,
        ) -> Result<LoadedSourceReviewReportChirho> {
            unreachable!("decision tests use direct source manifest evidence")
        }

        fn validate_effective_source_manifest_chirho(
            &self,
            effective_manifest_hash_chirho: &HashChirho,
        ) -> Result<()> {
            self.calls_chirho
                .borrow_mut()
                .push(format!("effective:{}", effective_manifest_hash_chirho.0));
            Ok(())
        }

        fn validate_raw_source_manifest_chirho(
            &self,
            raw_manifest_hash_chirho: &HashChirho,
        ) -> Result<()> {
            self.calls_chirho
                .borrow_mut()
                .push(format!("raw:{}", raw_manifest_hash_chirho.0));
            Ok(())
        }
    }

    impl ReviewDecisionPortChirho for FakeDecisionPortChirho {
        fn current_live_chirho(&self, _app_chirho: &str) -> Result<Option<HashChirho>> {
            self.calls_chirho
                .borrow_mut()
                .push("current-live".to_string());
            Ok(self.live_chirho.clone())
        }

        fn current_price_book_chirho(&self, _app_chirho: &str) -> Result<Option<HashChirho>> {
            self.calls_chirho
                .borrow_mut()
                .push("current-price-book".to_string());
            Ok(self.price_book_chirho.clone())
        }

        fn authorize_owner_chirho(
            &self,
            _app_chirho: &str,
            owner_principal_chirho: &str,
        ) -> Result<()> {
            self.calls_chirho
                .borrow_mut()
                .push(format!("authorize:{owner_principal_chirho}"));
            Ok(())
        }

        fn enforce_review_policy_envelope_chirho(
            &self,
            _input_chirho: ReviewPolicyEnvelopeDecisionInputChirho<'_>,
        ) -> Result<ReviewPolicyEnvelopeEvidenceChirho> {
            self.calls_chirho
                .borrow_mut()
                .push("review-policy-envelope".to_string());
            Ok(ReviewPolicyEnvelopeEvidenceChirho::AbsentChirho {
                checked_envelope_count_chirho: 0,
            })
        }

        fn publish_candidate_chirho(
            &self,
            _app_chirho: &str,
            owner_principal_chirho: &str,
            candidate_chirho: &HashChirho,
            _source_review_report_chirho: Option<&HashChirho>,
        ) -> Result<u64> {
            self.calls_chirho.borrow_mut().push(format!(
                "publish:{owner_principal_chirho}:{}",
                candidate_chirho.0
            ));
            Ok(7)
        }

        fn record_decision_chirho(
            &self,
            input_chirho: ReviewDecisionRecordInputChirho,
        ) -> Result<ReviewRecordChirho> {
            self.calls_chirho
                .borrow_mut()
                .push(format!("record:{:?}", input_chirho.decision_chirho));
            Ok(ReviewRecordChirho {
                seq_chirho: 0,
                schema_chirho: String::new(),
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
                at_ms_chirho: 1,
                sig_chirho: "sig-chirho".to_string(),
            })
        }
    }

    fn hash_chirho(label_chirho: &str) -> HashChirho {
        HashChirho(label_chirho.to_string())
    }

    fn surface_chirho(
        nodes_chirho: &[HashChirho],
        paid_effect_counts_chirho: BTreeMap<String, u64>,
    ) -> ReviewDagSurfaceChirho {
        ReviewDagSurfaceChirho {
            node_count_chirho: nodes_chirho.len(),
            edge_count_chirho: nodes_chirho.len().saturating_sub(1),
            nodes_chirho: nodes_chirho.iter().cloned().collect::<BTreeSet<_>>(),
            capabilities_chirho: BTreeMap::new(),
            paid_effect_counts_chirho,
        }
    }

    fn surface_with_capability_chirho(
        nodes_chirho: &[HashChirho],
        capability_chirho: &str,
    ) -> ReviewDagSurfaceChirho {
        ReviewDagSurfaceChirho {
            node_count_chirho: nodes_chirho.len(),
            edge_count_chirho: nodes_chirho.len().saturating_sub(1),
            nodes_chirho: nodes_chirho.iter().cloned().collect::<BTreeSet<_>>(),
            capabilities_chirho: BTreeMap::from([(capability_chirho.to_string(), 1)]),
            paid_effect_counts_chirho: BTreeMap::new(),
        }
    }

    fn fake_decision_port_chirho(
        live_chirho: Option<HashChirho>,
        candidate_chirho: HashChirho,
        candidate_surface_chirho: ReviewDagSurfaceChirho,
    ) -> FakeDecisionPortChirho {
        let mut surfaces_chirho = BTreeMap::new();
        if let Some(live_chirho) = &live_chirho {
            surfaces_chirho.insert(
                live_chirho.clone(),
                surface_chirho(&[hash_chirho("live-node_chirho")], BTreeMap::new()),
            );
        }
        surfaces_chirho.insert(candidate_chirho, candidate_surface_chirho);
        FakeDecisionPortChirho {
            surfaces_chirho,
            prices_chirho: BTreeMap::new(),
            live_chirho,
            price_book_chirho: None,
            calls_chirho: RefCell::new(Vec::new()),
        }
    }

    fn review_diff_chirho(candidate_chirho: HashChirho) -> ReviewSurfaceDiffChirho {
        ReviewSurfaceDiffChirho {
            app_chirho: "demo_chirho".to_string(),
            live_chirho: None,
            candidate_chirho,
            price_book_chirho: None,
            live_node_count_chirho: 0,
            candidate_node_count_chirho: 1,
            live_edge_count_chirho: 0,
            candidate_edge_count_chirho: 0,
            added_nodes_chirho: Vec::new(),
            removed_nodes_chirho: Vec::new(),
            added_capabilities_chirho: Vec::new(),
            removed_capabilities_chirho: Vec::new(),
            live_paid_effects_chirho: Vec::new(),
            candidate_paid_effects_chirho: Vec::new(),
            live_cost_token_chirho: 0,
            candidate_cost_token_chirho: 0,
            cost_delta_token_chirho: 0,
            warnings_chirho: Vec::new(),
        }
    }

    #[test]
    fn review_candidate_uses_injected_loader_and_prices_chirho() {
        let live_chirho = hash_chirho("live_chirho");
        let candidate_chirho = hash_chirho("candidate_chirho");
        let price_book_chirho = hash_chirho("pricebook_chirho");
        let mut candidate_paid_chirho = BTreeMap::new();
        candidate_paid_chirho.insert("email_chirho".to_string(), 2);

        let port_chirho = FakeReviewPortChirho {
            surfaces_chirho: BTreeMap::from([
                (
                    live_chirho.clone(),
                    surface_chirho(&[hash_chirho("a_chirho")], BTreeMap::new()),
                ),
                (
                    candidate_chirho.clone(),
                    surface_chirho(
                        &[hash_chirho("a_chirho"), hash_chirho("b_chirho")],
                        candidate_paid_chirho,
                    ),
                ),
            ]),
            prices_chirho: BTreeMap::from([(
                "email_chirho".to_string(),
                ReviewResolvedPriceChirho {
                    unit_cost_token_chirho: 5,
                    source_chirho: "test-price-chirho".to_string(),
                },
            )]),
        };

        let diff_chirho = review_candidate_against_live_chirho(
            &port_chirho,
            ReviewCandidateAgainstLiveInputChirho {
                app_chirho: "demo_chirho",
                live_chirho: Some(live_chirho.clone()),
                candidate_chirho: candidate_chirho.clone(),
                price_book_chirho: Some(price_book_chirho.clone()),
            },
        )
        .unwrap();

        assert_eq!(diff_chirho.live_chirho, Some(live_chirho));
        assert_eq!(diff_chirho.candidate_chirho, candidate_chirho);
        assert_eq!(diff_chirho.price_book_chirho, Some(price_book_chirho));
        assert_eq!(
            diff_chirho.added_nodes_chirho,
            vec![hash_chirho("b_chirho")]
        );
        assert_eq!(diff_chirho.candidate_cost_token_chirho, 10);
        assert_eq!(diff_chirho.cost_delta_token_chirho, 10);
    }

    #[test]
    fn source_evidence_validation_uses_injected_report_and_manifest_checks_chirho() {
        let candidate_chirho = hash_chirho("candidate_chirho");
        let diff_chirho = review_diff_chirho(candidate_chirho.clone());
        let source_manifest_chirho = ReviewSourceManifestEvidenceChirho {
            effective_manifest_hash_chirho: hash_chirho("effective_chirho"),
            raw_manifest_hash_chirho: Some(hash_chirho("raw_chirho")),
        };
        let source_review_report_chirho = hash_chirho("source-review-report_chirho");
        let report_chirho = cairn_model_app_chirho::AppSourceReviewReportChirho {
            schema_chirho: String::new(),
            source_review_report_chirho: None,
            candidate_chirho: AppSourceCandidateReportChirho {
                schema_chirho: String::new(),
                app_chirho: "demo_chirho".to_string(),
                owner_chirho: "owner/demo_chirho".to_string(),
                request_access_policy_chirho: None,
                source_manifest_chirho: Some(AppSourceManifestEvidenceChirho {
                    effective_manifest_hash_chirho: hash_chirho("effective_chirho"),
                    raw_manifest_hash_chirho: Some(hash_chirho("raw_chirho")),
                }),
                root_dag_chirho: candidate_chirho.clone(),
                nodes_chirho: Vec::new(),
                dags_chirho: Vec::new(),
                modules_chirho: Vec::new(),
                assets_chirho: Vec::new(),
                contract_refs_chirho: Vec::new(),
                undo_plan_bindings_chirho: None,
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                routes_chirho: Vec::new(),
            },
            review_chirho: diff_chirho.clone(),
            non_authoritative_chirho: true,
        };
        let port_chirho = FakeSourceEvidencePortChirho {
            report_chirho: LoadedSourceReviewReportChirho {
                source_review_report_chirho: source_review_report_chirho.clone(),
                canonical_hash_chirho: source_review_report_chirho.clone(),
                report_chirho,
            },
        };

        validate_review_source_evidence_chirho(
            &port_chirho,
            ReviewSourceEvidenceInputChirho {
                candidate_chirho: &candidate_chirho,
                diff_chirho: &diff_chirho,
                source_review_report_chirho: &Some(source_review_report_chirho),
                source_manifest_chirho: &Some(source_manifest_chirho),
            },
        )
        .unwrap();
    }

    #[test]
    fn promote_decision_rejects_capability_escalation_before_publish_chirho() {
        let candidate_chirho = hash_chirho("candidate_chirho");
        let port_chirho = fake_decision_port_chirho(
            None,
            candidate_chirho.clone(),
            surface_with_capability_chirho(&[hash_chirho("candidate-node_chirho")], "WriteStore"),
        );

        let error_chirho = promote_candidate_with_review_evidence_chirho(
            &port_chirho,
            PromoteCandidateInputChirho {
                app_chirho: "demo_chirho",
                owner_principal_chirho: "owner/demo_chirho",
                candidate_chirho,
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
                require_review_policy_envelope_chirho: false,
                source_evidence_chirho: ReviewSourceEvidenceChirho::default(),
            },
        )
        .unwrap_err();

        assert!(error_chirho
            .to_string()
            .contains("candidate adds capabilities"));
        assert!(!port_chirho
            .calls_chirho
            .borrow()
            .iter()
            .any(|call_chirho| call_chirho.starts_with("publish:")));
    }

    #[test]
    fn promote_decision_publishes_and_records_after_source_evidence_chirho() {
        let candidate_chirho = hash_chirho("candidate_chirho");
        let source_manifest_chirho = ReviewSourceManifestEvidenceChirho {
            effective_manifest_hash_chirho: hash_chirho("effective_chirho"),
            raw_manifest_hash_chirho: Some(hash_chirho("raw_chirho")),
        };
        let port_chirho = fake_decision_port_chirho(
            None,
            candidate_chirho.clone(),
            surface_chirho(&[hash_chirho("candidate-node_chirho")], BTreeMap::new()),
        );

        let record_chirho = promote_candidate_with_review_evidence_chirho(
            &port_chirho,
            PromoteCandidateInputChirho {
                app_chirho: "demo_chirho",
                owner_principal_chirho: "owner/demo_chirho",
                candidate_chirho,
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
                require_review_policy_envelope_chirho: false,
                source_evidence_chirho: ReviewSourceEvidenceChirho {
                    source_review_report_chirho: None,
                    source_manifest_chirho: Some(source_manifest_chirho),
                },
            },
        )
        .unwrap();

        assert_eq!(
            record_chirho.decision_chirho,
            ReviewDecisionChirho::PromoteChirho
        );
        assert_eq!(record_chirho.app_record_seq_chirho, Some(7));
        let calls_chirho = port_chirho.calls_chirho.borrow();
        let effective_index_chirho = calls_chirho
            .iter()
            .position(|call_chirho| call_chirho.starts_with("effective:"))
            .unwrap();
        let envelope_index_chirho = calls_chirho
            .iter()
            .position(|call_chirho| call_chirho == "review-policy-envelope")
            .unwrap();
        let publish_index_chirho = calls_chirho
            .iter()
            .position(|call_chirho| call_chirho.starts_with("publish:"))
            .unwrap();
        let record_index_chirho = calls_chirho
            .iter()
            .position(|call_chirho| call_chirho.starts_with("record:"))
            .unwrap();
        assert!(envelope_index_chirho < publish_index_chirho);
        assert!(effective_index_chirho < publish_index_chirho);
        assert!(publish_index_chirho < record_index_chirho);
    }

    #[test]
    fn reject_decision_authorizes_owner_and_records_without_publish_chirho() {
        let candidate_chirho = hash_chirho("candidate_chirho");
        let port_chirho = fake_decision_port_chirho(
            None,
            candidate_chirho.clone(),
            surface_chirho(&[hash_chirho("candidate-node_chirho")], BTreeMap::new()),
        );

        let record_chirho = reject_candidate_with_review_evidence_chirho(
            &port_chirho,
            RejectCandidateInputChirho {
                app_chirho: "demo_chirho",
                owner_principal_chirho: "owner/demo_chirho",
                candidate_chirho,
                reason_chirho: "not ready yet",
                source_evidence_chirho: ReviewSourceEvidenceChirho::default(),
            },
        )
        .unwrap();

        assert_eq!(
            record_chirho.decision_chirho,
            ReviewDecisionChirho::RejectChirho
        );
        assert_eq!(
            record_chirho.reason_chirho.as_deref(),
            Some("not ready yet")
        );
        let calls_chirho = port_chirho.calls_chirho.borrow();
        assert!(calls_chirho
            .iter()
            .any(|call_chirho| call_chirho == "authorize:owner/demo_chirho"));
        assert!(!calls_chirho
            .iter()
            .any(|call_chirho| call_chirho.starts_with("publish:")));
    }
}
