// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::migration_eligibility_chirho::*;
use crate::migration_completeness_chirho::{
    PreliminaryMigrationHalfChirho, UNREPORTABLE_MIGRATION_SURFACE_CHIRHO,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

fn fresh_root_chirho(label_chirho: &str) -> PathBuf {
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-eligibility-{label_chirho}-{}-{n_chirho}-chirho",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_chirho).expect("create fixture root");
    root_chirho
}

fn has_failed_half_chirho(
    failures_chirho: &[crate::migration_completeness_chirho::PreliminaryMigrationHalfFailureChirho],
    half_chirho: PreliminaryMigrationHalfChirho,
) -> bool {
    failures_chirho
        .iter()
        .any(|failure_chirho| failure_chirho.half_chirho() == half_chirho)
}

#[test]
fn an_undisposed_surface_refuses_and_names_the_disposition_half_chirho() {
    // ATTRIBUTING for the half, not merely for the refusal. A minimal root fails more than one half,
    // so asserting "it refused" would pass no matter which half spoke. The assertion names
    // `disposition-chirho` specifically, because that is the half this brick's ruling moved.
    let root_chirho = fresh_root_chirho("undisposed");
    std::fs::create_dir_all(root_chirho.join("a-surface-nobody-has-disposed-chirho"))
        .expect("create an undisposed surface");

    let refusal_chirho = preliminary_check_for_root_chirho(&root_chirho, None, None, None, None)
        .expect_err("a root carrying an undisposed surface is not eligible");
    match refusal_chirho {
        MigrationEligibilityRefusalChirho::HalvesFailedChirho { failed_chirho } => {
            assert!(
                has_failed_half_chirho(
                    &failed_chirho,
                    PreliminaryMigrationHalfChirho::DispositionChirho,
                ),
                "the disposition half must be named; got {failed_chirho:?}"
            );
        }
        // The other variant means "I could not look", which is a different answer and would make
        // this arm pass while measuring nothing about dispositions.
        other_chirho => panic!("expected a failed half, got {other_chirho:?}"),
    }
}

#[test]
fn an_unreadable_root_refuses_as_unreadable_not_as_a_failed_half_chirho() {
    // THREE cases, not two: readable-and-eligible, readable-and-refused, and could-not-look. The
    // third must keep its own identity — collapsing it into a failed half would let an unreadable
    // root read as a clean, considered refusal.
    let missing_chirho = fresh_root_chirho("unreadable").join("no-such-root-chirho");
    let refusal_chirho = preliminary_check_for_root_chirho(&missing_chirho, None, None, None, None)
        .expect_err("a root that cannot be read is not eligible");
    assert_eq!(
        refusal_chirho,
        MigrationEligibilityRefusalChirho::RootUnreadableChirho
    );
    assert!(!matches!(
        refusal_chirho,
        MigrationEligibilityRefusalChirho::HalvesFailedChirho { .. }
    ));
}

#[test]
fn writer_fences_no_longer_fails_the_disposition_half_chirho() {
    // THE RULING, MEASURED THROUGH THE PATH THAT CONSUMES IT. `writer-fences-chirho` was ruled
    // rebuilt-at-target so that roots carrying an elected fence could become eligible at all. This
    // asserts the consequence rather than the table: a root whose ONLY unusual surface is the fence
    // must not fail on `disposition-chirho`. It may still fail other halves — this fixture is
    // minimal — which is exactly why the assertion is about that half and not about success.
    let root_chirho = fresh_root_chirho("fenced");
    std::fs::create_dir_all(root_chirho.join("writer-fences-chirho"))
        .expect("create the fence surface");

    if let Err(MigrationEligibilityRefusalChirho::HalvesFailedChirho { failed_chirho }) =
        preliminary_check_for_root_chirho(&root_chirho, None, None, None, None)
    {
        assert!(
            !has_failed_half_chirho(
                &failed_chirho,
                PreliminaryMigrationHalfChirho::DispositionChirho,
            ),
            "writer-fences-chirho still fails the disposition half, so the ruling did not reach \
             the path that consumes it; got {failed_chirho:?}"
        );
    }
}

#[test]
fn a_configured_namespace_parent_is_carried_only_when_it_is_supplied_chirho() {
    // FOUND BY RUNNING THE DRILL, not by reading. A real root's ledger config said
    // `storage_namespace_chirho = "item6-drill-parent-chirho/ledger-chirho"`, so its journal lived
    // under a directory the OPERATOR named. No fixed table can name that, and the root refused the
    // disposition verdict on the one surface that is unambiguously load-bearing.
    //
    // THE SAME ROOT, TWICE, IS THE WHOLE ARM. Supplying the configured namespace must make the
    // difference — if this passed either way, the input would be decoration and a literal table row
    // would have been the real fix.
    let root_chirho = fresh_root_chirho("configured-ns");
    std::fs::create_dir_all(root_chirho.join("an-operator-named-parent-chirho"))
        .expect("create the configured namespace parent");

    // WITHOUT the input: the parent is undisposed and the disposition half refuses.
    match preliminary_check_for_root_chirho(&root_chirho, None, None, None, None) {
        Err(MigrationEligibilityRefusalChirho::HalvesFailedChirho { failed_chirho }) => assert!(
            has_failed_half_chirho(
                &failed_chirho,
                PreliminaryMigrationHalfChirho::DispositionChirho,
            ),
            "without the namespace the disposition half must refuse; got {failed_chirho:?}"
        ),
        other_chirho => panic!("expected a failed disposition half, got {other_chirho:?}"),
    }

    // WITH it: that surface is carried, so the disposition half no longer names it. Other halves may
    // still fail on this minimal fixture — asserting success would pass for unrelated reasons.
    if let Err(MigrationEligibilityRefusalChirho::HalvesFailedChirho { failed_chirho }) =
        preliminary_check_for_root_chirho(
            &root_chirho,
            Some("an-operator-named-parent-chirho"),
            None,
            None,
            None,
        )
    {
        assert!(
            !has_failed_half_chirho(
                &failed_chirho,
                PreliminaryMigrationHalfChirho::DispositionChirho,
            ),
            "the supplied namespace parent is still refusing; got {failed_chirho:?}"
        );
    }
}

#[test]
fn the_configured_namespace_root_surface_is_the_first_path_component_chirho() {
    use crate::surface_disposition_chirho::configured_namespace_root_surface_chirho;
    // A surface enumeration sees ROOT-LEVEL directories, so a nested configured namespace resolves
    // to its first component — that is the directory that actually shows up and must be disposed.
    assert_eq!(
        configured_namespace_root_surface_chirho("item6-drill-parent-chirho/ledger-chirho"),
        Some("item6-drill-parent-chirho".to_string())
    );
    assert_eq!(
        configured_namespace_root_surface_chirho("ledger-storage-chirho"),
        Some("ledger-storage-chirho".to_string())
    );
    // Leading separators and an empty configuration must not yield an empty surface name, which
    // would silently carry a surface called "".
    assert_eq!(
        configured_namespace_root_surface_chirho("/leading-chirho/x"),
        Some("leading-chirho".to_string())
    );
    assert_eq!(configured_namespace_root_surface_chirho(""), None);
}

#[test]
fn non_charset_filesystem_surface_never_escapes_the_eligibility_refusal_chirho() {
    let root_chirho = fresh_root_chirho("non-charset");
    let hostile_name_chirho = "hostile\n\u{2603}-chirho";
    std::fs::create_dir_all(root_chirho.join(hostile_name_chirho))
        .expect("create a filesystem surface outside the accepted operator alphabet");

    let refusal_chirho = preliminary_check_for_root_chirho(&root_chirho, None, None, None, None)
        .expect_err("an undeclared filesystem surface must refuse");
    let MigrationEligibilityRefusalChirho::HalvesFailedChirho { failed_chirho } = refusal_chirho
    else {
        panic!("a readable hostile root must not be reported as unreadable");
    };
    for half_chirho in [
        PreliminaryMigrationHalfChirho::CompletenessChirho,
        PreliminaryMigrationHalfChirho::DispositionChirho,
    ] {
        let failure_chirho = failed_chirho
            .iter()
            .find(|failure_chirho| failure_chirho.half_chirho() == half_chirho)
            .expect("both filesystem-derived halves must refuse");
        assert_eq!(
            failure_chirho.surfaces_chirho(),
            &[UNREPORTABLE_MIGRATION_SURFACE_CHIRHO]
        );
    }
    let operator_output_chirho = format!("{failed_chirho:?}");
    assert!(!operator_output_chirho.contains("hostile"));
    assert!(!operator_output_chirho.contains('\n'));
    assert!(!operator_output_chirho.contains('\u{2603}'));
}

// ---- CF8 Step B (2026-10-26, AICEO #29534), through the live gate. ----
//
// These arms ask `preliminary_check_for_root_chirho` itself, the function the resident migration
// path calls, rather than the classifier underneath it. Each root is built from scratch with the
// same bytes, so a source and a target that should agree do agree, and a target that should differ
// differs in exactly one place.

/// A projection-manifest log that holds the reference keeping self-containment non-vacuous on its own.
const CF8_MANIFEST_LOG_CHIRHO: &str = "feedback-chirho.jsonl";
/// The carried unprojected log whose reference shows the scan reads the new logs.
const CF8_REFERENCING_LOG_CHIRHO: &str = "ref-snapshot-log-chirho.jsonl";
/// One carried log's head sidecar, present the way a seqlog writer leaves it.
const CF8_SIDECAR_CHIRHO: &str = "head-removals-chirho.jsonl.head-chirho";

/// The newly ruled surfaces a migrated target must hold, by name and by kind (directory or file).
fn cf8_required_surfaces_chirho() -> Vec<(&'static str, bool)> {
    let mut required_chirho: Vec<(&'static str, bool)> =
        crate::surface_disposition_chirho::CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO
            .iter()
            .map(|log_chirho| (*log_chirho, false))
            .collect();
    required_chirho.extend([
        (CF8_SIDECAR_CHIRHO, false),
        ("app-build-request-state-chirho.redb", false),
        ("template-app-deploy-state-chirho.redb", false),
        ("publication-intent-state-chirho.redb", false),
        (crate::tenant_chirho::GEO_GENESIS_GUARD_DIR_CHIRHO, true),
        ("gate1-authority-head-chirho", true),
        (
            crate::tenant_chirho::CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO,
            false,
        ),
    ]);
    required_chirho
}

/// The newly ruled surfaces a target may lack, because their own code rebuilds them there.
const CF8_DISPOSABLE_SURFACES_CHIRHO: [(&str, bool); 2] = [
    ("readmodel-chirho.sqlite", false),
    ("native-workers-chirho", true),
];

/// One root holding every surface CF8 Step B ruled. Two logs each name one CAS object: a projection
/// manifest log, and a carried unprojected log. `store_carried_log_object_chirho` decides whether the
/// second log's object is actually stored.
fn cf8_census_root_chirho(label_chirho: &str, store_carried_log_object_chirho: bool) -> PathBuf {
    use cairn_core_chirho::cas_chirho;
    let root_chirho = fresh_root_chirho(label_chirho);
    let manifest_object_chirho =
        cas_chirho::add_chirho(&root_chirho, b"cf8-manifest-object-chirho")
            .expect("store the manifest log's object");
    let carried_bytes_chirho = b"cf8-carried-log-object-chirho";
    let carried_object_chirho = if store_carried_log_object_chirho {
        cas_chirho::add_chirho(&root_chirho, carried_bytes_chirho)
            .expect("store the carried log's object")
    } else {
        cas_chirho::hash_chirho(carried_bytes_chirho)
    };
    for (surface_chirho, is_dir_chirho) in cf8_required_surfaces_chirho()
        .into_iter()
        .chain(CF8_DISPOSABLE_SURFACES_CHIRHO)
    {
        let path_chirho = root_chirho.join(surface_chirho);
        if is_dir_chirho {
            std::fs::create_dir_all(&path_chirho).expect("create a ruled directory surface");
        } else {
            std::fs::write(&path_chirho, b"cf8-stand-in-chirho\n")
                .expect("create a ruled file surface");
        }
    }
    std::fs::write(
        root_chirho.join(CF8_MANIFEST_LOG_CHIRHO),
        format!("{{\"object_chirho\":\"{}\"}}\n", manifest_object_chirho.0),
    )
    .expect("write the manifest log's reference");
    std::fs::write(
        root_chirho.join(CF8_REFERENCING_LOG_CHIRHO),
        format!("{{\"object_chirho\":\"{}\"}}\n", carried_object_chirho.0),
    )
    .expect("write the carried log's reference");
    root_chirho
}

/// Ask the live gate about `target_chirho`, with `source_chirho` as the root it moves from.
fn cf8_check_against_source_chirho(
    target_chirho: &std::path::Path,
    source_chirho: &std::path::Path,
) -> Result<
    crate::migration_completeness_chirho::PreliminaryMigrationCheckChirho,
    MigrationEligibilityRefusalChirho,
> {
    use crate::migration_completeness_chirho::RootSurfaceEnumeratorChirho;
    use crate::root_surfaces_chirho::{
        RootSurfaceSnapshotChirho, TenantScopedArtifactResolverChirho,
    };
    let source_surfaces_chirho = RootSurfaceSnapshotChirho::open_chirho(source_chirho)
        .expect("read the source's surfaces")
        .observed_surfaces_chirho();
    let source_resolver_chirho = TenantScopedArtifactResolverChirho::for_root_chirho(source_chirho);
    preliminary_check_for_root_chirho(
        target_chirho,
        None,
        Some(&source_resolver_chirho),
        Some(&source_surfaces_chirho),
        None,
    )
}

/// Every failed half, by name, with the surfaces it reported.
fn cf8_failed_halves_chirho(
    outcome_chirho: Result<
        crate::migration_completeness_chirho::PreliminaryMigrationCheckChirho,
        MigrationEligibilityRefusalChirho,
    >,
) -> Vec<(&'static str, Vec<String>)> {
    match outcome_chirho {
        Err(MigrationEligibilityRefusalChirho::HalvesFailedChirho { failed_chirho }) => {
            failed_chirho
                .iter()
                .map(|failure_chirho| {
                    (
                        failure_chirho.half_chirho().name_chirho(),
                        failure_chirho.surfaces_chirho().to_vec(),
                    )
                })
                .collect()
        }
        other_chirho => panic!("expected failed halves, got {other_chirho:?}"),
    }
}

#[test]
fn cf8_ruled_surfaces_pass_the_live_gate_when_the_target_holds_them_chirho() {
    let source_chirho = cf8_census_root_chirho("cf8-pass-source", true);
    let target_chirho = cf8_census_root_chirho("cf8-pass-target", true);
    let check_chirho = cf8_check_against_source_chirho(&target_chirho, &source_chirho)
        .expect("a target holding every ruled surface passes every half");
    // TWO references: the manifest log's and the carried unprojected log's. A reference scan that
    // skipped the carried logs would count one, and still pass.
    assert_eq!(check_chirho.references_checked_chirho(), 2);
}

#[test]
fn every_carried_census_surface_is_required_at_the_target_and_no_disposable_one_is_chirho() {
    let source_chirho = cf8_census_root_chirho("cf8-required-source", true);
    for (index_chirho, (surface_chirho, is_dir_chirho)) in
        cf8_required_surfaces_chirho().into_iter().enumerate()
    {
        let target_chirho =
            cf8_census_root_chirho(&format!("cf8-required-target-{index_chirho}"), true);
        let path_chirho = target_chirho.join(surface_chirho);
        if is_dir_chirho {
            std::fs::remove_dir_all(&path_chirho).expect("remove a required directory");
        } else {
            std::fs::remove_file(&path_chirho).expect("remove a required file");
        }
        assert_eq!(
            cf8_failed_halves_chirho(cf8_check_against_source_chirho(
                &target_chirho,
                &source_chirho
            )),
            vec![("required-surfaces-chirho", vec![surface_chirho.to_string()])],
            "{surface_chirho} travels, so a target without it must refuse on that half alone"
        );
    }
    for (index_chirho, (surface_chirho, is_dir_chirho)) in
        CF8_DISPOSABLE_SURFACES_CHIRHO.into_iter().enumerate()
    {
        let target_chirho =
            cf8_census_root_chirho(&format!("cf8-disposable-target-{index_chirho}"), true);
        let path_chirho = target_chirho.join(surface_chirho);
        if is_dir_chirho {
            std::fs::remove_dir_all(&path_chirho).expect("remove a disposable directory");
        } else {
            std::fs::remove_file(&path_chirho).expect("remove a disposable file");
        }
        cf8_check_against_source_chirho(&target_chirho, &source_chirho).unwrap_or_else(
            |refusal_chirho| {
                panic!(
                    "{surface_chirho} is rebuilt at the target, not required: {refusal_chirho:?}"
                )
            },
        );
    }
}

#[test]
fn a_carried_logs_reference_lost_at_the_target_refuses_against_the_source_chirho() {
    // The target lacks only the object the carried unprojected log names. The manifest log's
    // reference still resolves, so self-containment is non-vacuous without the carried log, and
    // this refusal happens only because the scan reads it.
    let source_chirho = cf8_census_root_chirho("cf8-lost-source", true);
    let target_chirho = cf8_census_root_chirho("cf8-lost-target", false);
    assert_eq!(
        cf8_failed_halves_chirho(cf8_check_against_source_chirho(
            &target_chirho,
            &source_chirho
        )),
        vec![(
            "self-containment-chirho",
            vec![CF8_REFERENCING_LOG_CHIRHO.to_string()]
        )],
    );
}

#[test]
fn the_three_unruled_census_surfaces_still_refuse_the_live_gate_by_name_chirho() {
    // Rows 12, 16 and 21. Both roots hold the surface, so only the halves that judge it can speak:
    // completeness does not know it, and nothing disposes of it.
    for (index_chirho, (surface_chirho, is_dir_chirho)) in [
        ("versioned-chirho.redb", false),
        ("privacy-account-attribution-chirho", true),
        ("seqlog-quarantine-chirho", true),
    ]
    .into_iter()
    .enumerate()
    {
        let source_chirho =
            cf8_census_root_chirho(&format!("cf8-unruled-source-{index_chirho}"), true);
        let target_chirho =
            cf8_census_root_chirho(&format!("cf8-unruled-target-{index_chirho}"), true);
        for root_chirho in [&source_chirho, &target_chirho] {
            let path_chirho = root_chirho.join(surface_chirho);
            if is_dir_chirho {
                std::fs::create_dir_all(&path_chirho).expect("create an unruled directory");
            } else {
                std::fs::write(&path_chirho, b"cf8-stand-in-chirho\n")
                    .expect("create an unruled file");
            }
        }
        assert_eq!(
            cf8_failed_halves_chirho(cf8_check_against_source_chirho(
                &target_chirho,
                &source_chirho
            )),
            vec![
                ("completeness-chirho", vec![surface_chirho.to_string()]),
                ("disposition-chirho", vec![surface_chirho.to_string()]),
            ],
            "{surface_chirho} has no ruling and must keep the root refused"
        );
    }
}

#[test]
fn a_platform_only_log_refuses_the_live_gate_as_known_but_not_movable_chirho() {
    let log_chirho = crate::surface_disposition_chirho::PLATFORM_ONLY_LOG_SURFACES_CHIRHO[0];
    let sidecar_chirho = format!("{log_chirho}.head-chirho");
    let source_chirho = cf8_census_root_chirho("cf8-platform-source", true);
    let target_chirho = cf8_census_root_chirho("cf8-platform-target", true);
    for root_chirho in [&source_chirho, &target_chirho] {
        std::fs::write(root_chirho.join(log_chirho), b"{}\n").expect("write a platform log");
        std::fs::write(root_chirho.join(&sidecar_chirho), b"{}\n").expect("write its sidecar");
    }
    let mut expected_surfaces_chirho = vec![log_chirho.to_string(), sidecar_chirho];
    expected_surfaces_chirho.sort();
    // Completeness knows both, so only the disposition half refuses.
    assert_eq!(
        cf8_failed_halves_chirho(cf8_check_against_source_chirho(
            &target_chirho,
            &source_chirho
        )),
        vec![("disposition-chirho", expected_surfaces_chirho)],
    );
}
