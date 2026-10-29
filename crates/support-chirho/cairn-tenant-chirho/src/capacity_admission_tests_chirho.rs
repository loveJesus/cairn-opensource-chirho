// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! No evidence is not sufficiency, a capacity refusal refuses by its OWN half, and the label
//! boundary is what keeps coordinates out of an operator response.

use super::*;
use crate::migration_completeness_chirho::{
    preliminary_migration_check_chirho, verify_migration_completeness_chirho,
    PreliminaryMigrationHalfChirho, RootSurfaceEnumeratorChirho,
};
use crate::self_containment_chirho::{
    verify_tenant_self_containment_chirho, SelfContainmentVerdictChirho, TenantLogReferenceChirho,
    TenantObjectResolverChirho,
};
use std::collections::BTreeSet;

struct FixedSurfacesChirho;

impl RootSurfaceEnumeratorChirho for FixedSurfacesChirho {
    fn observed_surfaces_chirho(&self) -> Vec<String> {
        vec!["refs-chirho".to_string()]
    }
}

/// The other halves passing, so ONLY the capacity half can refuse.
///
/// This is the fixture discipline the rest of this gate already uses: a tamper arm that leaves a
/// second possible refusal standing cannot tell you which one fired.
fn passing_completeness_chirho() -> crate::migration_completeness_chirho::CompletenessVerdictChirho
{
    let declared_chirho: BTreeSet<String> = ["refs-chirho".to_string()].into_iter().collect();
    verify_migration_completeness_chirho(&declared_chirho, &FixedSurfacesChirho)
}

fn passing_self_containment_chirho() -> SelfContainmentVerdictChirho {
    struct AllPresentChirho;
    impl TenantObjectResolverChirho for AllPresentChirho {
        fn resolves_in_tenant_chirho(&self, _hash_chirho: &str) -> bool {
            true
        }
    }
    verify_tenant_self_containment_chirho(
        &[TenantLogReferenceChirho {
            log_name_chirho: "app-log-chirho".to_string(),
            seq_chirho: 1,
            hash_chirho: "aaa".to_string(),
        }],
        &AllPresentChirho,
    )
}

fn passing_disposition_chirho() -> crate::surface_disposition_chirho::DispositionVerdictChirho {
    crate::surface_disposition_chirho::verify_surface_dispositions_chirho(
        &["objects-chirho".to_string()],
        None,
    )
}

fn check_with_capacity_chirho(
    capacity_chirho: Option<&TenantCapacityAdmissionVerdictChirho>,
) -> Result<
    crate::migration_completeness_chirho::PreliminaryMigrationCheckChirho,
    Vec<crate::migration_completeness_chirho::PreliminaryMigrationHalfFailureChirho>,
> {
    preliminary_migration_check_chirho(
        &passing_completeness_chirho(),
        &passing_self_containment_chirho(),
        &passing_disposition_chirho(),
        None,
        capacity_chirho,
    )
}

fn verdict_chirho(
    considered_chirho: usize,
    refusals_chirho: &[&str],
) -> TenantCapacityAdmissionVerdictChirho {
    TenantCapacityAdmissionVerdictChirho {
        considered_chirho,
        refusals_chirho: refusals_chirho
            .iter()
            .map(|refusal_chirho| refusal_chirho.to_string())
            .collect(),
        evidence_identity_chirho: "test-evidence-identity-chirho".to_string(),
    }
}

/// ARM 1 — positive control. Without this, every other arm here could pass on a broken fixture.
#[test]
fn a_sufficient_capacity_verdict_admits_the_target_chirho() {
    let admitted_chirho = verdict_chirho(3, &[]);
    assert!(admitted_chirho.is_admitted_over_evidence_chirho());
    check_with_capacity_chirho(Some(&admitted_chirho))
        .expect("every half passes over real evidence, capacity included");
}

/// ARM 2 — an insufficient target refuses by the CAPACITY half, and by no other.
#[test]
fn an_insufficient_capacity_verdict_refuses_by_its_own_half_chirho() {
    let refused_chirho = verdict_chirho(3, &["durable-bytes-insufficient-chirho"]);
    let failures_chirho = check_with_capacity_chirho(Some(&refused_chirho))
        .expect_err("an insufficient target must refuse");
    assert_eq!(failures_chirho.len(), 1, "other halves must stay silent");
    let failure_chirho = &failures_chirho[0];
    assert_eq!(
        failure_chirho.half_chirho(),
        PreliminaryMigrationHalfChirho::CapacityAdmissionChirho,
        "the refusal must name capacity, not a neighbouring half"
    );
    assert_ne!(
        failure_chirho.half_chirho(),
        PreliminaryMigrationHalfChirho::RequiredSurfacesChirho
    );
    assert_ne!(
        failure_chirho.half_chirho(),
        PreliminaryMigrationHalfChirho::ClassifierIdentityChirho
    );
    assert_eq!(
        failure_chirho.surfaces_chirho(),
        &["durable-bytes-insufficient-chirho"]
    );
}

/// ARM 3 — THE VACUITY ARM, and the one the obvious implementation gets wrong.
///
/// A target that offered no capacity evidence has an EMPTY refusal list, which reads exactly like a
/// pass. It is not one: nothing was checked. Every other half in this gate carries the same guard.
#[test]
fn a_capacity_verdict_with_nothing_considered_is_not_a_pass_chirho() {
    let nothing_considered_chirho = verdict_chirho(0, &[]);
    assert!(
        !nothing_considered_chirho.is_admitted_over_evidence_chirho(),
        "no clause considered is NOT CHECKED, never sufficient"
    );
    let failures_chirho = check_with_capacity_chirho(Some(&nothing_considered_chirho))
        .expect_err("an unchecked target must refuse");
    assert_eq!(failures_chirho.len(), 1);
    assert_eq!(
        failures_chirho[0].half_chirho(),
        PreliminaryMigrationHalfChirho::CapacityAdmissionChirho
    );
}

/// ARM 4 — a refusal kind this crate does not understand still surfaces as the capacity half.
///
/// Offer-side freshness is decided in the placement crates and cannot be named here. The half must
/// carry it through opaquely rather than dropping what it cannot classify.
#[test]
fn an_offer_freshness_refusal_surfaces_as_the_capacity_half_chirho() {
    let stale_offer_chirho = verdict_chirho(4, &["offered-measurement-replayed-chirho"]);
    let failures_chirho =
        check_with_capacity_chirho(Some(&stale_offer_chirho)).expect_err("a stale offer refuses");
    assert_eq!(
        failures_chirho[0].half_chirho(),
        PreliminaryMigrationHalfChirho::CapacityAdmissionChirho
    );
    assert_eq!(
        failures_chirho[0].surfaces_chirho(),
        &["offered-measurement-replayed-chirho"]
    );
}

/// ARM 5 — the label boundary, and its HONEST LIMIT.
///
/// A punctuation-bearing or overlong coordinate is replaced before it can reach an operator
/// response. **But a bare alphanumeric identifier under the length limit passes through unchanged**,
/// so the sanitizer is not what makes this safe on its own — the port contract is. An implementer
/// must emit LABELS, never node ids or evidence digests. This arm pins both halves of that truth so
/// a later reader cannot mistake the door for a guarantee it does not give.
#[test]
fn a_punctuated_coordinate_is_replaced_but_a_bare_identifier_is_not_chirho() {
    let punctuated_chirho = verdict_chirho(2, &["node/b94bca78:durable-bytes"]);
    let failures_chirho =
        check_with_capacity_chirho(Some(&punctuated_chirho)).expect_err("a refused target refuses");
    assert_eq!(
        failures_chirho[0].surfaces_chirho(),
        &[crate::migration_completeness_chirho::UNREPORTABLE_MIGRATION_SURFACE_CHIRHO],
        "a coordinate carrying separators must never reach an operator response"
    );

    let bare_identifier_chirho = verdict_chirho(2, &["b94bca78a118db2a"]);
    let leaked_chirho = check_with_capacity_chirho(Some(&bare_identifier_chirho))
        .expect_err("a refused target refuses");
    assert_eq!(
        leaked_chirho[0].surfaces_chirho(),
        &["b94bca78a118db2a"],
        "the sanitizer accepts bare alphanumerics: safety here is the PORT CONTRACT, not this door"
    );
}

/// ARM 6 — the scaffolding boundary, pinned so it cannot be forgotten.
///
/// `None` skips the half entirely and the check still passes. That is brick 1's deliberate shape and
/// it is exactly why this file does not discharge CF8 clause 6: the production road must make
/// absence fail closed before "evidence drives the migration" is true.
#[test]
fn an_absent_capacity_verdict_skips_the_half_chirho() {
    check_with_capacity_chirho(None)
        .expect("absence SKIPS today — brick 2/3 must make this fail closed");
}
