// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only current-control-plane witness for the owner-only Subscribe authorization path.

#[cfg(test)]
mod tests_chirho;

mod cursor_chirho;
mod digests_chirho;

pub use cursor_chirho::{
    mint_gate1_subscription_cursor_chirho, resume_gate1_subscription_cursor_chirho,
    OpaqueSubscriptionCursorTokenChirho, SubscriptionCursorMintOutcomeChirho,
    SubscriptionCursorResumeOutcomeChirho, ValidatedSubscriptionCursorChirho,
};
pub use digests_chirho::{
    derive_subscription_binding_digests_chirho, SubscriptionBindingDigestOutcomeChirho,
    SubscriptionBindingDigestsChirho,
};

use anyhow::{anyhow, bail, Result};
use cairn_chirho::app_chirho::{
    self, AppActionChirho, AppRecordChirho, AppRouteActionChirho, AppRouteRecordChirho,
};
use cairn_chirho::app_source_manifest_chirho::{
    self, AppSourceReviewReportChirho, SubscriptionViewAuthorizationChirho,
    SubscriptionViewDeclarationReportChirho, SubscriptionViewScopeChirho,
};
use cairn_chirho::effect_chirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::refs_chirho;
use cairn_chirho::review_chirho::{self, ReviewDecisionChirho, ReviewRecordChirho};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionViewTargetChirho {
    AppRootChirho,
    RouteChirho { route_chirho: String },
}

pub enum SubscriptionControlPlaneWitnessOutcomeChirho {
    VerifiedChirho(Box<VerifiedSubscriptionControlPlaneWitnessChirho>),
    ResnapshotRequiredChirho,
}

/// Exact verified evidence cannot be constructed, printed, or serialized by a caller.
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::VerifiedSubscriptionControlPlaneWitnessChirho;
/// let _witness_chirho = VerifiedSubscriptionControlPlaneWitnessChirho {};
/// ```
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::VerifiedSubscriptionControlPlaneWitnessChirho;
/// fn print_witness_chirho(witness_chirho: &VerifiedSubscriptionControlPlaneWitnessChirho) {
///     println!("{witness_chirho:?}");
/// }
/// ```
pub struct VerifiedSubscriptionControlPlaneWitnessChirho {
    root_identity_digest_chirho: HashChirho,
    authenticated_principal_chirho: String,
    app_record_chirho: AppRecordChirho,
    route_record_chirho: Option<AppRouteRecordChirho>,
    review_record_chirho: ReviewRecordChirho,
    source_review_report_chirho: AppSourceReviewReportChirho,
    source_review_report_hash_chirho: HashChirho,
    effective_manifest_hash_chirho: HashChirho,
    declaration_chirho: SubscriptionViewDeclarationReportChirho,
    app_active_dag_chirho: HashChirho,
    target_active_dag_chirho: HashChirho,
}

impl VerifiedSubscriptionControlPlaneWitnessChirho {
    fn exact_evidence_agrees_chirho(&self) -> bool {
        app_record_matches_current_authority_chirho(
            &self.app_record_chirho,
            &self.authenticated_principal_chirho,
            &self.app_active_dag_chirho,
        ) && self.review_record_chirho.owner_principal_chirho == self.authenticated_principal_chirho
            && self.review_record_chirho.app_record_seq_chirho
                == Some(self.app_record_chirho.seq_chirho)
            && self.app_record_chirho.dag_chirho.as_ref()
                == Some(&self.review_record_chirho.candidate_chirho)
            && self
                .review_record_chirho
                .source_review_report_chirho
                .as_ref()
                == Some(&self.source_review_report_hash_chirho)
            && self
                .source_review_report_chirho
                .candidate_chirho
                .root_dag_chirho
                == *self
                    .app_record_chirho
                    .dag_chirho
                    .as_ref()
                    .unwrap_or(&self.app_active_dag_chirho)
            && self
                .source_review_report_chirho
                .candidate_chirho
                .source_manifest_chirho
                .as_ref()
                .is_some_and(|evidence_chirho| {
                    evidence_chirho.effective_manifest_hash_chirho
                        == self.effective_manifest_hash_chirho
                })
            && self
                .source_review_report_chirho
                .candidate_chirho
                .modules_chirho
                .iter()
                .any(|module_chirho| {
                    module_chirho.dag_chirho
                        == *self
                            .route_record_chirho
                            .as_ref()
                            .and_then(|record_chirho| record_chirho.dag_chirho.as_ref())
                            .or(self.app_record_chirho.dag_chirho.as_ref())
                            .unwrap_or(&self.target_active_dag_chirho)
                        && module_chirho
                            .subscription_views_chirho
                            .contains(&self.declaration_chirho)
                })
            && self
                .route_record_chirho
                .as_ref()
                .is_none_or(|record_chirho| {
                    route_record_matches_current_authority_chirho(
                        record_chirho,
                        &self.authenticated_principal_chirho,
                        &self.target_active_dag_chirho,
                    )
                })
    }
}

fn app_record_matches_current_authority_chirho(
    record_chirho: &AppRecordChirho,
    authenticated_principal_chirho: &str,
    active_dag_chirho: &HashChirho,
) -> bool {
    record_chirho.owner_principal_chirho == authenticated_principal_chirho
        && record_chirho.action_chirho == AppActionChirho::DeployChirho
        && record_chirho.dag_chirho.as_ref() == Some(active_dag_chirho)
}

fn route_record_matches_current_authority_chirho(
    record_chirho: &AppRouteRecordChirho,
    authenticated_principal_chirho: &str,
    active_dag_chirho: &HashChirho,
) -> bool {
    record_chirho.owner_principal_chirho == authenticated_principal_chirho
        && record_chirho.action_chirho == AppRouteActionChirho::DeployRouteChirho
        && record_chirho.dag_chirho.as_ref() == Some(active_dag_chirho)
}

pub fn current_subscription_control_plane_witness_chirho(
    root_chirho: &Path,
    authenticated_principal_chirho: &str,
    app_chirho: &str,
    target_chirho: &SubscriptionViewTargetChirho,
    view_chirho: &str,
) -> SubscriptionControlPlaneWitnessOutcomeChirho {
    match try_current_subscription_control_plane_witness_chirho(
        root_chirho,
        authenticated_principal_chirho,
        app_chirho,
        target_chirho,
        view_chirho,
    ) {
        Ok(witness_chirho) => {
            SubscriptionControlPlaneWitnessOutcomeChirho::VerifiedChirho(Box::new(witness_chirho))
        }
        Err(_) => SubscriptionControlPlaneWitnessOutcomeChirho::ResnapshotRequiredChirho,
    }
}

fn try_current_subscription_control_plane_witness_chirho(
    root_chirho: &Path,
    authenticated_principal_chirho: &str,
    app_name_chirho: &str,
    target_chirho: &SubscriptionViewTargetChirho,
    view_chirho: &str,
) -> Result<VerifiedSubscriptionControlPlaneWitnessChirho> {
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let app_record_chirho = app_chirho::verified_selected_app_record_chirho(
        root_chirho,
        &refs_chirho,
        app_name_chirho,
    )?;
    let app_active_dag_chirho = app_record_chirho
        .dag_chirho
        .clone()
        .ok_or_else(|| anyhow!("current app DAG is unavailable"))?;
    if !app_record_matches_current_authority_chirho(
        &app_record_chirho,
        authenticated_principal_chirho,
        &app_active_dag_chirho,
    ) {
        bail!("current app record is unavailable");
    }
    let app_evidence_dag_chirho = app_record_chirho
        .dag_chirho
        .clone()
        .ok_or_else(|| anyhow!("current app record DAG is unavailable"))?;

    let (route_record_chirho, target_active_dag_chirho, target_evidence_dag_chirho) =
        match target_chirho {
            SubscriptionViewTargetChirho::AppRootChirho => (
                None,
                app_active_dag_chirho.clone(),
                app_evidence_dag_chirho.clone(),
            ),
            SubscriptionViewTargetChirho::RouteChirho { route_chirho } => {
                let route_record_chirho = app_chirho::verified_selected_app_route_record_chirho(
                    root_chirho,
                    &refs_chirho,
                    app_name_chirho,
                    route_chirho,
                    authenticated_principal_chirho,
                )?;
                let route_active_dag_chirho = route_record_chirho
                    .dag_chirho
                    .clone()
                    .ok_or_else(|| anyhow!("current app route record DAG is unavailable"))?;
                (
                    Some(route_record_chirho),
                    route_active_dag_chirho.clone(),
                    route_active_dag_chirho,
                )
            }
        };

    let review_record_chirho = review_chirho::verified_review_records_chirho(root_chirho)?
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_name_chirho
                && record_chirho.owner_principal_chirho == authenticated_principal_chirho
                && record_chirho.decision_chirho == ReviewDecisionChirho::PromoteChirho
                && record_chirho.app_record_seq_chirho == Some(app_record_chirho.seq_chirho)
                && record_chirho.candidate_chirho == app_evidence_dag_chirho
                && record_chirho.source_review_report_chirho.is_some()
        })
        .ok_or_else(|| anyhow!("current reviewed promote evidence is unavailable"))?;
    let source_review_report_hash_chirho = review_record_chirho
        .source_review_report_chirho
        .clone()
        .ok_or_else(|| anyhow!("current reviewed promote source is unavailable"))?;
    let source_review_report_chirho =
        app_source_manifest_chirho::load_app_source_review_report_for_promotion_chirho(
            root_chirho,
            app_name_chirho,
            authenticated_principal_chirho,
            &source_review_report_hash_chirho,
            Some(&app_evidence_dag_chirho),
        )?;
    let effective_manifest_hash_chirho = source_review_report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .as_ref()
        .map(|evidence_chirho| evidence_chirho.effective_manifest_hash_chirho.clone())
        .ok_or_else(|| anyhow!("current reviewed source manifest is unavailable"))?;

    let mut declarations_chirho = source_review_report_chirho
        .candidate_chirho
        .modules_chirho
        .iter()
        .filter(|module_chirho| module_chirho.dag_chirho == target_evidence_dag_chirho)
        .flat_map(|module_chirho| module_chirho.subscription_views_chirho.iter())
        .filter(|declaration_chirho| {
            declaration_chirho.view_chirho == view_chirho
                && declaration_chirho.authorization_chirho
                    == SubscriptionViewAuthorizationChirho::OwnerOnlyChirho
                && match (&declaration_chirho.scope_chirho, target_chirho) {
                    (
                        SubscriptionViewScopeChirho::AppRootChirho,
                        SubscriptionViewTargetChirho::AppRootChirho,
                    ) => true,
                    (
                        SubscriptionViewScopeChirho::RouteChirho {
                            route_chirho: declaration_route_chirho,
                        },
                        SubscriptionViewTargetChirho::RouteChirho { route_chirho },
                    ) => declaration_route_chirho == route_chirho,
                    _ => false,
                }
        });
    let declaration_chirho = declarations_chirho
        .next()
        .cloned()
        .ok_or_else(|| anyhow!("current reviewed subscription view is unavailable"))?;
    if declarations_chirho.next().is_some() {
        bail!("current reviewed subscription view is ambiguous");
    }
    let root_public_key_chirho = effect_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let root_identity_digest_chirho =
        digests_chirho::root_identity_digest_from_public_key_chirho(&root_public_key_chirho)?;

    let witness_chirho = VerifiedSubscriptionControlPlaneWitnessChirho {
        root_identity_digest_chirho,
        authenticated_principal_chirho: authenticated_principal_chirho.to_string(),
        app_record_chirho,
        route_record_chirho,
        review_record_chirho,
        source_review_report_chirho,
        source_review_report_hash_chirho,
        effective_manifest_hash_chirho,
        declaration_chirho,
        app_active_dag_chirho,
        target_active_dag_chirho,
    };
    if !witness_chirho.exact_evidence_agrees_chirho() {
        bail!("current subscription control-plane evidence does not agree");
    }
    Ok(witness_chirho)
}
