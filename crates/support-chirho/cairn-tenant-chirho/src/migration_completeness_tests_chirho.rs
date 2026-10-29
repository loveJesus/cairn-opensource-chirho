// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Unknown refuses, absent only reports, and a preliminary check needs all three halves over evidence.

use super::super::self_containment_chirho::{
    verify_tenant_self_containment_chirho, TenantLogReferenceChirho, TenantObjectResolverChirho,
};
use super::*;

struct FixedSurfacesChirho {
    surfaces_chirho: Vec<String>,
}

impl RootSurfaceEnumeratorChirho for FixedSurfacesChirho {
    fn observed_surfaces_chirho(&self) -> Vec<String> {
        self.surfaces_chirho.clone()
    }
}

fn observed_chirho(names_chirho: &[&str]) -> FixedSurfacesChirho {
    FixedSurfacesChirho {
        surfaces_chirho: names_chirho
            .iter()
            .map(|n_chirho| n_chirho.to_string())
            .collect(),
    }
}

fn declared_chirho(names_chirho: &[&str]) -> BTreeSet<String> {
    names_chirho
        .iter()
        .map(|n_chirho| n_chirho.to_string())
        .collect()
}

/// A disposition verdict that passes over real evidence, for preliminary check composition tests.
fn passing_disposition_chirho() -> crate::surface_disposition_chirho::DispositionVerdictChirho {
    crate::surface_disposition_chirho::verify_surface_dispositions_chirho(
        &["objects-chirho".to_string()],
        None,
    )
}

fn stale_disposition_digest_chirho(
) -> crate::surface_disposition_chirho::DispositionPopulationDigestChirho {
    serde_json::from_str(&format!("\"{}\"", "0".repeat(64)))
        .expect("test-only stale classifier digest")
}

/// A self-containment verdict that passes over real evidence, for preliminary check composition tests.
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

fn failing_self_containment_chirho(surface_chirho: &str) -> SelfContainmentVerdictChirho {
    SelfContainmentVerdictChirho {
        references_checked_chirho: 1,
        refusals_chirho: vec![SelfContainmentRefusalChirho::DanglingReferenceChirho {
            log_name_chirho: surface_chirho.to_owned(),
            seq_chirho: 9_876_543_210,
            hash_chirho: "private-content-address-must-not-escape-chirho".to_owned(),
        }],
    }
}

fn failed_half_chirho(
    failures_chirho: &[PreliminaryMigrationHalfFailureChirho],
    half_chirho: PreliminaryMigrationHalfChirho,
) -> &PreliminaryMigrationHalfFailureChirho {
    failures_chirho
        .iter()
        .find(|failure_chirho| failure_chirho.half_chirho() == half_chirho)
        .expect("the requested failed half must be present")
}

fn assert_only_failed_half_chirho(
    result_chirho: Result<
        PreliminaryMigrationCheckChirho,
        Vec<PreliminaryMigrationHalfFailureChirho>,
    >,
    half_chirho: PreliminaryMigrationHalfChirho,
    expected_surfaces_chirho: &[&str],
) {
    let failures_chirho = result_chirho.expect_err("the selected half must refuse");
    assert_eq!(failures_chirho.len(), 1, "other halves must stay silent");
    let failure_chirho = failed_half_chirho(&failures_chirho, half_chirho);
    assert_eq!(failure_chirho.surfaces_chirho(), expected_surfaces_chirho);
    assert_eq!(failure_chirho.dropped_surface_count_chirho(), 0);
}

#[test]
fn a_fully_declared_root_is_complete_chirho() {
    let verdict_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho", "objects-chirho", "logs-chirho"]),
        &observed_chirho(&["refs-chirho", "objects-chirho"]),
    );
    assert!(verdict_chirho.is_complete_over_evidence_chirho());
    assert!(verdict_chirho.refusals_chirho.is_empty());
}

#[test]
fn an_undeclared_surface_refuses_because_migration_would_leave_it_behind_chirho() {
    // THE FAIL-CLOSED DIRECTION. Something exists that the manifest does not cover; skipping what you
    // do not recognise is how data is lost quietly.
    let verdict_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho"]),
        &observed_chirho(&["refs-chirho", "mystery-surface-chirho"]),
    );
    assert!(!verdict_chirho.is_complete_over_evidence_chirho());
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec![CompletenessRefusalChirho::UnknownSurfaceChirho {
            surface_chirho: "mystery-surface-chirho".to_string(),
        }]
    );
}

#[test]
fn a_declared_but_absent_surface_reports_and_does_not_refuse_chirho() {
    // THE ASYMMETRY. A root need not use every surface the platform defines, so this is ordinary —
    // but it is surfaced, because the other reading is that the manifest is pointed at the wrong root.
    let verdict_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho", "never-used-chirho"]),
        &observed_chirho(&["refs-chirho"]),
    );
    assert!(
        verdict_chirho.is_complete_over_evidence_chirho(),
        "an unused declared surface is not a migration hazard"
    );
    assert_eq!(
        verdict_chirho.declared_but_absent_chirho,
        vec!["never-used-chirho".to_string()]
    );
}

#[test]
fn a_root_that_enumerated_nothing_is_not_complete_chirho() {
    // The same vacuity guard the self-containment verdict carries: zero observed surfaces means the
    // check did not happen, not that it passed.
    let verdict_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho"]),
        &observed_chirho(&[]),
    );
    assert!(verdict_chirho.refusals_chirho.is_empty(), "nothing unknown");
    assert!(
        !verdict_chirho.is_complete_over_evidence_chirho(),
        "but nothing was observed, so nothing was checked"
    );
}

#[test]
fn a_preliminary_check_needs_all_three_halves_chirho() {
    let complete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho"]),
        &observed_chirho(&["refs-chirho"]),
    );
    let preliminary_check_chirho = preliminary_migration_check_chirho(
        &complete_chirho,
        &passing_self_containment_chirho(),
        &passing_disposition_chirho(),
        None,
        None,
    )
    .expect("all three halves pass over real evidence");
    assert_eq!(preliminary_check_chirho.references_checked_chirho(), 1);
    assert_eq!(preliminary_check_chirho.surfaces_observed_chirho(), 1);
    assert_eq!(
        preliminary_check_chirho
            .disposition_population_digest_chirho()
            .as_str_chirho(),
        crate::surface_disposition_chirho::disposition_population_digest_chirho().as_str_chirho()
    );
}

#[test]
fn a_preliminary_check_refuses_stale_classifier_evidence_by_its_own_identity_chirho() {
    let complete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho"]),
        &observed_chirho(&["refs-chirho"]),
    );
    let mut stale_disposition_chirho = passing_disposition_chirho();
    stale_disposition_chirho.disposition_population_digest_chirho =
        stale_disposition_digest_chirho();
    assert_only_failed_half_chirho(
        preliminary_migration_check_chirho(
            &complete_chirho,
            &passing_self_containment_chirho(),
            &stale_disposition_chirho,
            None,
            None,
        ),
        PreliminaryMigrationHalfChirho::ClassifierIdentityChirho,
        &[],
    );

    let mut stale_required_chirho =
        crate::surface_disposition_chirho::verify_required_surfaces_chirho(
            &["objects-chirho".to_owned()],
            &["objects-chirho".to_owned()],
        );
    stale_required_chirho.disposition_population_digest_chirho = stale_disposition_digest_chirho();
    assert_only_failed_half_chirho(
        preliminary_migration_check_chirho(
            &complete_chirho,
            &passing_self_containment_chirho(),
            &passing_disposition_chirho(),
            Some(&stale_required_chirho),
            None,
        ),
        PreliminaryMigrationHalfChirho::ClassifierIdentityChirho,
        &[],
    );
}

#[test]
fn a_preliminary_check_is_refused_when_only_completeness_passes_chirho() {
    // THE COMPOSITION RULE. Completeness alone says "you were shown everything" and nothing about
    // whether what you were shown resolves. A vacuous self-containment verdict must not be accepted.
    struct NoneChirho;
    impl TenantObjectResolverChirho for NoneChirho {
        fn resolves_in_tenant_chirho(&self, _hash_chirho: &str) -> bool {
            false
        }
    }
    let vacuous_self_containment_chirho = verify_tenant_self_containment_chirho(&[], &NoneChirho);
    let complete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho"]),
        &observed_chirho(&["refs-chirho"]),
    );
    assert_only_failed_half_chirho(
        preliminary_migration_check_chirho(
            &complete_chirho,
            &vacuous_self_containment_chirho,
            &passing_disposition_chirho(),
            None,
            None,
        ),
        PreliminaryMigrationHalfChirho::SelfContainmentChirho,
        &[],
    );
}

#[test]
fn a_preliminary_check_is_refused_when_only_self_containment_passes_chirho() {
    let incomplete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&[]),
        &observed_chirho(&["mystery-chirho"]),
    );
    assert_only_failed_half_chirho(
        preliminary_migration_check_chirho(
            &incomplete_chirho,
            &passing_self_containment_chirho(),
            &passing_disposition_chirho(),
            None,
            None,
        ),
        PreliminaryMigrationHalfChirho::CompletenessChirho,
        &["mystery-chirho"],
    );
}

#[test]
fn a_preliminary_check_reports_every_failure_not_just_the_first_chirho() {
    let incomplete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&[]),
        &observed_chirho(&["completeness-surface-chirho"]),
    );
    let failures_chirho = preliminary_migration_check_chirho(
        &incomplete_chirho,
        &failing_self_containment_chirho("containment-log-chirho"),
        &passing_disposition_chirho(),
        None,
        None,
    )
    .expect_err("both independently failing halves must be retained");
    assert_eq!(failures_chirho.len(), 2);
    assert_eq!(
        failed_half_chirho(
            &failures_chirho,
            PreliminaryMigrationHalfChirho::CompletenessChirho,
        )
        .surfaces_chirho(),
        &["completeness-surface-chirho"]
    );
    assert_eq!(
        failed_half_chirho(
            &failures_chirho,
            PreliminaryMigrationHalfChirho::SelfContainmentChirho,
        )
        .surfaces_chirho(),
        &["containment-log-chirho"]
    );
}

// ---------------------------------------------------------------------------------------------
// The declared set is the PROJECTION MANIFEST, not a restated copy of it.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_declared_log_surface_set_is_the_projection_manifest_plus_the_carried_unprojected_logs_chirho(
) {
    let declared_set_chirho = declared_log_surfaces_chirho();
    // Non-vacuity first. An empty declared set would make EVERY observed surface unknown, which
    // looks like a working fail-closed guard while actually measuring nothing about the manifest.
    assert!(
        !declared_set_chirho.is_empty(),
        "the declared log-surface set is empty — completeness would refuse everything for the wrong \
         reason, and the refusal would look exactly like a real finding"
    );
    // Equality with the source, so a transformation bug that silently DROPPED surfaces cannot pass.
    // A dropped surface is the dangerous direction: it becomes undeclared, and undeclared refuses,
    // so the damage shows up as a confusing red on a healthy root rather than as a quiet pass.
    //
    // RETARGETED 2026-10-26 (CF8 Step B), with the fixture unchanged. This arm asserted equality with
    // the manifest alone. The set is now the manifest PLUS the carried logs the projection must not
    // read, which are its complement and not a copy of it. A dropped surface on either side still
    // fails this equality. A log added to both lists fails
    // `the_log_lists_are_disjoint_and_reach_their_consumers_chirho`.
    let manifest_set_chirho: BTreeSet<String> = static_surface_manifest_chirho()
        .iter()
        .chain(CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO)
        .map(|surface_chirho| (*surface_chirho).to_string())
        .collect();
    assert_eq!(
        declared_set_chirho, manifest_set_chirho,
        "the declared log-surface set drifted from static_surface_manifest_chirho plus \
         CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO; each log is declared in exactly one of the two, \
         because a restated list drifts and the drift is silent"
    );
}

#[test]
fn a_surface_absent_from_the_real_manifest_refuses_by_name_chirho() {
    // The fail-closed direction, driven by the REAL declared set rather than a fixture.
    let verdict_chirho = verify_migration_completeness_chirho(
        &declared_log_surfaces_chirho(),
        &observed_chirho(&["a-surface-the-platform-never-declared-chirho.jsonl"]),
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec![CompletenessRefusalChirho::UnknownSurfaceChirho {
            surface_chirho: "a-surface-the-platform-never-declared-chirho.jsonl".to_string(),
        }],
        "an undeclared surface must refuse BY NAME against the real manifest — a migration that \
         silently skipped it would leave that data behind"
    );
    assert!(!verdict_chirho.is_complete_over_evidence_chirho());
}

#[test]
fn a_surface_present_in_the_real_manifest_does_not_refuse_chirho() {
    // The other half of the non-vacuity pair, and it is the one that catches an over-broad set.
    // Alone, the refusal test above would still pass if the declared set were EMPTY; alone, this
    // test would still pass if the declared set contained everything. Together they pin both edges.
    let known_surface_chirho = static_surface_manifest_chirho()
        .first()
        .expect("the projection manifest must not be empty");
    let verdict_chirho = verify_migration_completeness_chirho(
        &declared_log_surfaces_chirho(),
        &observed_chirho(&[known_surface_chirho]),
    );
    assert!(
        verdict_chirho.refusals_chirho.is_empty(),
        "surface {known_surface_chirho} is in the projection manifest and must not be refused — a \
         declared set that refuses its own manifest is wired to the wrong list"
    );
    assert!(verdict_chirho.is_complete_over_evidence_chirho());
}

#[test]
fn a_preliminary_check_is_refused_when_only_the_disposition_half_fails_chirho() {
    // The edge the third half exists for. Completeness and self-containment both pass — the root
    // was fully shown and everything it names resolves locally — and it STILL must not be movable,
    // because nothing has decided what happens to the signing key. "Present and accounted for" is
    // not "carried", and before this half existed that root would have held a preliminary check.
    let complete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["a-surface-nobody-decided-about-chirho"]),
        &observed_chirho(&["a-surface-nobody-decided-about-chirho"]),
    );
    // RETARGETED: this used the signing key as its undisposed surface, and the key is now disposed
    // through the staged custody mechanism. The property under test is unchanged — a surface whose
    // disposition question is unanswered must refuse the preliminary check on that half ALONE — so the
    // fixture moves to a surface nobody has decided about, which is what "undisposed" now means.
    let undisposed_chirho = crate::surface_disposition_chirho::verify_surface_dispositions_chirho(
        &["a-surface-nobody-decided-about-chirho".to_string()],
        None,
    );
    assert_only_failed_half_chirho(
        preliminary_migration_check_chirho(
            &complete_chirho,
            &passing_self_containment_chirho(),
            &undisposed_chirho,
            None,
            None,
        ),
        PreliminaryMigrationHalfChirho::DispositionChirho,
        &["a-surface-nobody-decided-about-chirho"],
    );
}

#[test]
fn a_preliminary_check_names_a_self_containment_surface_without_hash_detail_chirho() {
    let complete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho"]),
        &observed_chirho(&["refs-chirho"]),
    );
    let result_chirho = preliminary_migration_check_chirho(
        &complete_chirho,
        &failing_self_containment_chirho("journal-surface-chirho"),
        &passing_disposition_chirho(),
        None,
        None,
    );
    assert_only_failed_half_chirho(
        result_chirho.clone(),
        PreliminaryMigrationHalfChirho::SelfContainmentChirho,
        &["journal-surface-chirho"],
    );
    let output_chirho = format!("{:?}", result_chirho.unwrap_err());
    assert!(!output_chirho.contains("private-content-address"));
    assert!(!output_chirho.contains("9876543210"));
}

#[test]
fn a_preliminary_check_names_a_required_surface_without_cross_contamination_chirho() {
    let complete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&["refs-chirho"]),
        &observed_chirho(&["refs-chirho"]),
    );
    let required_chirho = crate::surface_disposition_chirho::verify_required_surfaces_chirho(
        &["objects-chirho".to_owned()],
        &[],
    );
    assert_only_failed_half_chirho(
        preliminary_migration_check_chirho(
            &complete_chirho,
            &passing_self_containment_chirho(),
            &passing_disposition_chirho(),
            Some(&required_chirho),
            None,
        ),
        PreliminaryMigrationHalfChirho::RequiredSurfacesChirho,
        &["objects-chirho"],
    );
}

#[test]
fn hostile_surface_names_are_replaced_and_never_echoed_chirho() {
    let long_surface_chirho = "x".repeat(PRELIMINARY_MIGRATION_SURFACE_NAME_LIMIT_CHIRHO + 1);
    let punctuated_surface_chirho = "hostile\noperator-output-chirho";
    let incomplete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&[]),
        &FixedSurfacesChirho {
            surfaces_chirho: vec![
                long_surface_chirho.clone(),
                punctuated_surface_chirho.to_owned(),
            ],
        },
    );
    let failures_chirho = preliminary_migration_check_chirho(
        &incomplete_chirho,
        &passing_self_containment_chirho(),
        &passing_disposition_chirho(),
        None,
        None,
    )
    .expect_err("hostile undeclared names must refuse safely");
    let failure_chirho = failed_half_chirho(
        &failures_chirho,
        PreliminaryMigrationHalfChirho::CompletenessChirho,
    );
    assert_eq!(
        failure_chirho.surfaces_chirho(),
        &[UNREPORTABLE_MIGRATION_SURFACE_CHIRHO]
    );
    assert_eq!(failure_chirho.dropped_surface_count_chirho(), 1);
    let operator_output_chirho = format!("{failure_chirho:?} {failure_chirho}");
    assert!(!operator_output_chirho.contains(&long_surface_chirho));
    assert!(!operator_output_chirho.contains(punctuated_surface_chirho));
    assert!(!operator_output_chirho.contains('\n'));
}

#[test]
fn over_cap_surface_details_report_the_exact_dropped_count_chirho() {
    let surfaces_chirho: Vec<String> = (0..(PRELIMINARY_MIGRATION_SURFACE_DETAIL_LIMIT_CHIRHO + 2))
        .map(|index_chirho| format!("surface-{index_chirho:02}-chirho"))
        .collect();
    let incomplete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&[]),
        &FixedSurfacesChirho { surfaces_chirho },
    );
    let failures_chirho = preliminary_migration_check_chirho(
        &incomplete_chirho,
        &passing_self_containment_chirho(),
        &passing_disposition_chirho(),
        None,
        None,
    )
    .expect_err("an over-cap population must still refuse");
    let failure_chirho = failed_half_chirho(
        &failures_chirho,
        PreliminaryMigrationHalfChirho::CompletenessChirho,
    );
    assert_eq!(
        failure_chirho.surfaces_chirho().len(),
        PRELIMINARY_MIGRATION_SURFACE_DETAIL_LIMIT_CHIRHO
    );
    assert_eq!(failure_chirho.dropped_surface_count_chirho(), 2);
    assert!(failure_chirho
        .to_string()
        .contains("dropped_surface_count_chirho=2"));

    let mut crowded_hostile_surfaces_chirho: Vec<String> = (0
        ..PRELIMINARY_MIGRATION_SURFACE_DETAIL_LIMIT_CHIRHO)
        .map(|index_chirho| format!("valid-{index_chirho:02}-chirho"))
        .collect();
    crowded_hostile_surfaces_chirho.push("hidden\ncontrol-chirho".to_owned());
    let crowded_incomplete_chirho = verify_migration_completeness_chirho(
        &declared_chirho(&[]),
        &FixedSurfacesChirho {
            surfaces_chirho: crowded_hostile_surfaces_chirho,
        },
    );
    let crowded_failures_chirho = preliminary_migration_check_chirho(
        &crowded_incomplete_chirho,
        &passing_self_containment_chirho(),
        &passing_disposition_chirho(),
        None,
        None,
    )
    .expect_err("the hostile surface must not disappear behind the cap");
    let crowded_failure_chirho = failed_half_chirho(
        &crowded_failures_chirho,
        PreliminaryMigrationHalfChirho::CompletenessChirho,
    );
    assert_eq!(
        crowded_failure_chirho.surfaces_chirho().len(),
        PRELIMINARY_MIGRATION_SURFACE_DETAIL_LIMIT_CHIRHO
    );
    assert!(crowded_failure_chirho
        .surfaces_chirho()
        .iter()
        .any(|surface_chirho| surface_chirho == UNREPORTABLE_MIGRATION_SURFACE_CHIRHO));
    assert_eq!(crowded_failure_chirho.dropped_surface_count_chirho(), 1);
    assert!(crowded_failure_chirho
        .to_string()
        .contains("dropped_surface_count_chirho=1"));
}
