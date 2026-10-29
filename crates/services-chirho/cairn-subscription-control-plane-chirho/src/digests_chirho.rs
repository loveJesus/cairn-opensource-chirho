// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure domain-separated Subscribe digests over an exact verified control-plane witness.

use super::VerifiedSubscriptionControlPlaneWitnessChirho;
use anyhow::Result;
use cairn_chirho::{model_chirho::HashChirho, store_chirho};

const ROOT_IDENTITY_DOMAIN_CHIRHO: &str = "subscribe-root-identity-v1-chirho";
const APP_IDENTITY_DOMAIN_CHIRHO: &str = "subscribe-app-identity-v1-chirho";
const ROUTE_IDENTITY_DOMAIN_CHIRHO: &str = "subscribe-route-identity-v1-chirho";
const VIEW_IDENTITY_DOMAIN_CHIRHO: &str = "subscribe-view-identity-v1-chirho";
const PRINCIPAL_IDENTITY_DOMAIN_CHIRHO: &str = "subscribe-principal-identity-v1-chirho";
const DEPENDENCY_SET_DOMAIN_CHIRHO: &str = "subscribe-dependency-set-v1-chirho";
const GENERATION_DOMAIN_CHIRHO: &str = "subscribe-generation-v1-chirho";
const CONTROL_PLANE_DOMAIN_CHIRHO: &str = "subscribe-control-plane-evidence-v1-chirho";
const AUTHORIZATION_BINDING_DOMAIN_CHIRHO: &str = "subscribe-authorization-binding-v1-chirho";
const GATE1_AUTHORITY_SOURCE_KIND_CHIRHO: &str = "gate1-authority-log-chirho";

pub enum SubscriptionBindingDigestOutcomeChirho {
    DerivedChirho(Box<SubscriptionBindingDigestsChirho>),
    ResnapshotRequiredChirho,
}

/// Opaque binding digests support constant-time role comparisons only.
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::SubscriptionBindingDigestsChirho;
/// let _digests_chirho = SubscriptionBindingDigestsChirho {};
/// ```
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::SubscriptionBindingDigestsChirho;
/// fn print_digests_chirho(digests_chirho: &SubscriptionBindingDigestsChirho) {
///     println!("{digests_chirho:?}");
/// }
/// ```
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::SubscriptionBindingDigestsChirho;
/// fn compare_digests_chirho(
///     left_chirho: &SubscriptionBindingDigestsChirho,
///     right_chirho: &SubscriptionBindingDigestsChirho,
/// ) {
///     let _same_chirho = left_chirho == right_chirho;
/// }
/// ```
pub struct SubscriptionBindingDigestsChirho {
    root_identity_digest_chirho: HashChirho,
    view_identity_digest_chirho: HashChirho,
    dependency_set_digest_chirho: HashChirho,
    subscription_generation_chirho: HashChirho,
    control_plane_evidence_digest_chirho: HashChirho,
    authorization_binding_digest_chirho: HashChirho,
}

pub(super) struct SubscriptionCursorDigestComponentsChirho {
    pub(super) root_identity_digest_chirho: HashChirho,
    pub(super) view_identity_digest_chirho: HashChirho,
    pub(super) dependency_set_digest_chirho: HashChirho,
    pub(super) subscription_generation_chirho: HashChirho,
    pub(super) authorization_binding_digest_chirho: HashChirho,
}

impl SubscriptionBindingDigestsChirho {
    pub fn subscription_generation_matches_chirho(&self, other_chirho: &Self) -> bool {
        constant_time_digest_matches_chirho(
            &self.subscription_generation_chirho,
            &other_chirho.subscription_generation_chirho,
        )
    }

    pub fn control_plane_evidence_matches_chirho(&self, other_chirho: &Self) -> bool {
        constant_time_digest_matches_chirho(
            &self.control_plane_evidence_digest_chirho,
            &other_chirho.control_plane_evidence_digest_chirho,
        )
    }

    pub fn authorization_binding_matches_chirho(&self, other_chirho: &Self) -> bool {
        constant_time_digest_matches_chirho(
            &self.authorization_binding_digest_chirho,
            &other_chirho.authorization_binding_digest_chirho,
        )
    }

    pub(super) fn cursor_components_chirho(&self) -> SubscriptionCursorDigestComponentsChirho {
        SubscriptionCursorDigestComponentsChirho {
            root_identity_digest_chirho: self.root_identity_digest_chirho.clone(),
            view_identity_digest_chirho: self.view_identity_digest_chirho.clone(),
            dependency_set_digest_chirho: self.dependency_set_digest_chirho.clone(),
            subscription_generation_chirho: self.subscription_generation_chirho.clone(),
            authorization_binding_digest_chirho: self.authorization_binding_digest_chirho.clone(),
        }
    }
}

pub(super) fn constant_time_digest_matches_chirho(
    left_chirho: &HashChirho,
    right_chirho: &HashChirho,
) -> bool {
    constant_time_eq::constant_time_eq(left_chirho.0.as_bytes(), right_chirho.0.as_bytes())
}

pub fn derive_subscription_binding_digests_chirho(
    witness_chirho: &VerifiedSubscriptionControlPlaneWitnessChirho,
) -> SubscriptionBindingDigestOutcomeChirho {
    match try_derive_subscription_binding_digests_chirho(witness_chirho) {
        Ok(digests_chirho) => {
            SubscriptionBindingDigestOutcomeChirho::DerivedChirho(Box::new(digests_chirho))
        }
        Err(_) => SubscriptionBindingDigestOutcomeChirho::ResnapshotRequiredChirho,
    }
}

pub(super) fn root_identity_digest_from_public_key_chirho(
    root_public_key_chirho: &str,
) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(&(
        ("domain_chirho", ROOT_IDENTITY_DOMAIN_CHIRHO),
        ("root_public_key_chirho", root_public_key_chirho),
    ))
}

fn identity_digest_chirho(domain_chirho: &str, identity_chirho: &str) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(&(
        ("domain_chirho", domain_chirho),
        ("identity_chirho", identity_chirho),
    ))
}

fn try_derive_subscription_binding_digests_chirho(
    witness_chirho: &VerifiedSubscriptionControlPlaneWitnessChirho,
) -> Result<SubscriptionBindingDigestsChirho> {
    let app_identity_digest_chirho = identity_digest_chirho(
        APP_IDENTITY_DOMAIN_CHIRHO,
        &witness_chirho.app_record_chirho.app_chirho,
    )?;
    let route_identity_digest_chirho = witness_chirho
        .route_record_chirho
        .as_ref()
        .map(|record_chirho| {
            identity_digest_chirho(ROUTE_IDENTITY_DOMAIN_CHIRHO, &record_chirho.route_chirho)
        })
        .transpose()?;
    let view_identity_digest_chirho = identity_digest_chirho(
        VIEW_IDENTITY_DOMAIN_CHIRHO,
        &witness_chirho.declaration_chirho.view_chirho,
    )?;
    let principal_identity_digest_chirho = identity_digest_chirho(
        PRINCIPAL_IDENTITY_DOMAIN_CHIRHO,
        &witness_chirho.authenticated_principal_chirho,
    )?;
    let dependency_set_digest_chirho = store_chirho::hash_object_chirho(&(
        ("domain_chirho", DEPENDENCY_SET_DOMAIN_CHIRHO),
        (
            "dependencies_chirho",
            &witness_chirho.declaration_chirho.dependencies_chirho,
        ),
    ))?;
    let subscription_generation_chirho = store_chirho::hash_object_chirho(&(
        ("domain_chirho", GENERATION_DOMAIN_CHIRHO),
        (
            "reviewed_declaration_hash_chirho",
            &witness_chirho.declaration_chirho.declaration_chirho,
        ),
        (
            "active_target_dag_chirho",
            &witness_chirho.target_active_dag_chirho,
        ),
        (
            "dependency_set_digest_chirho",
            &dependency_set_digest_chirho,
        ),
    ))?;
    let control_plane_evidence_digest_chirho = store_chirho::hash_object_chirho(&(
        ("domain_chirho", CONTROL_PLANE_DOMAIN_CHIRHO),
        ("app_record_chirho", &witness_chirho.app_record_chirho),
        (
            "route_record_chirho",
            witness_chirho.route_record_chirho.as_ref(),
        ),
        (
            "app_active_ref_target_chirho",
            &witness_chirho.app_active_dag_chirho,
        ),
        (
            "target_active_ref_target_chirho",
            &witness_chirho.target_active_dag_chirho,
        ),
        (
            "source_review_report_chirho",
            &witness_chirho.source_review_report_chirho,
        ),
        (
            "source_review_report_hash_chirho",
            &witness_chirho.source_review_report_hash_chirho,
        ),
        (
            "effective_manifest_hash_chirho",
            &witness_chirho.effective_manifest_hash_chirho,
        ),
        (
            "reviewed_declaration_hash_chirho",
            &witness_chirho.declaration_chirho.declaration_chirho,
        ),
        (
            "promote_review_record_chirho",
            &witness_chirho.review_record_chirho,
        ),
    ))?;
    let authorization_binding_digest_chirho = store_chirho::hash_object_chirho(&(
        ("domain_chirho", AUTHORIZATION_BINDING_DOMAIN_CHIRHO),
        (
            "root_identity_digest_chirho",
            &witness_chirho.root_identity_digest_chirho,
        ),
        ("source_kind_chirho", GATE1_AUTHORITY_SOURCE_KIND_CHIRHO),
        ("app_identity_digest_chirho", &app_identity_digest_chirho),
        (
            "route_identity_digest_chirho",
            route_identity_digest_chirho.as_ref(),
        ),
        ("view_identity_digest_chirho", &view_identity_digest_chirho),
        (
            "principal_identity_digest_chirho",
            &principal_identity_digest_chirho,
        ),
        (
            "control_plane_evidence_digest_chirho",
            &control_plane_evidence_digest_chirho,
        ),
        (
            "subscription_generation_chirho",
            &subscription_generation_chirho,
        ),
    ))?;

    Ok(SubscriptionBindingDigestsChirho {
        root_identity_digest_chirho: witness_chirho.root_identity_digest_chirho.clone(),
        view_identity_digest_chirho,
        dependency_set_digest_chirho,
        subscription_generation_chirho,
        control_plane_evidence_digest_chirho,
        authorization_binding_digest_chirho,
    })
}
