// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Local temp-dir tests for the drill-root layout schema + validator. No host, no root creation, no
//! writer-era signing: fixtures build a well-formed staged root under a temp namespace, and each
//! malformed variant refuses by a distinct named reason.

use super::*;
use cairn_writer_head_chirho::writer_head_chirho::{
    issue_elected_writer_fence_for_root_chirho, ConsistencyGroupIdChirho,
};
use std::sync::atomic::{AtomicU64, Ordering};

fn unique_base_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-drill-root-layout-{label_chirho}-{}-{counter_chirho}-chirho",
        std::process::id()
    ))
}

fn write_private_chirho(path_chirho: &Path, bytes_chirho: &[u8]) {
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho).expect("create fixture parent");
    }
    std::fs::write(path_chirho, bytes_chirho).expect("write private fixture file");
    set_private_mode_chirho(path_chirho);
}

#[cfg(unix)]
fn set_private_mode_chirho(path_chirho: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600))
        .expect("set 0600 fixture mode");
}

#[cfg(not(unix))]
fn set_private_mode_chirho(_path_chirho: &Path) {}

#[cfg(unix)]
fn set_broad_mode_chirho(path_chirho: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o644))
        .expect("set 0644 fixture mode");
}

/// A fully well-formed, freshly-staged drill root under a temp namespace, plus the pieces tests
/// rewrite to make one binding malformed at a time.
struct DrillRootFixtureChirho {
    base_chirho: PathBuf,
    selected_root_chirho: PathBuf,
    cluster_config_chirho: PathBuf,
    ledger_config_chirho: PathBuf,
    authorization_chirho: PathBuf,
    canonical_selected_chirho: PathBuf,
    root_path_string_chirho: String,
}

impl Drop for DrillRootFixtureChirho {
    fn drop(&mut self) {
        let _ignored_chirho = std::fs::remove_dir_all(&self.base_chirho);
    }
}

impl DrillRootFixtureChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        let base_chirho = unique_base_chirho(label_chirho);
        let selected_root_chirho = base_chirho.join("current-root-chirho");
        std::fs::create_dir_all(&selected_root_chirho).expect("create staged drill root");
        // A staged drill root is a BORN root, not a directory with the right name. Before step (6b)
        // existed this fixture stopped at the line above, so every green in this file was a green
        // about validating an empty directory — which is exactly the production defect step (6b)
        // closes. Provision the named lock surface so the happy path passes for the right reason.
        std::fs::create_dir_all(selected_root_chirho.join(NAMED_LOCK_SURFACE_CHIRHO))
            .expect("provision the named lock surface");
        let canonical_selected_chirho = selected_root_chirho
            .canonicalize()
            .expect("canonicalize staged drill root");
        // Derive the group's canonical root string EXACTLY as the primitive does, so the group
        // binding is well-formed regardless of how the path is rendered.
        let root_path_string_chirho =
            match consistency_group_for_root_chirho(&selected_root_chirho).expect("derive group") {
                ConsistencyGroupIdChirho::RootPathChirho {
                    canonical_root_chirho,
                } => canonical_root_chirho,
                ConsistencyGroupIdChirho::TenantChirho { .. } => {
                    panic!("a fresh temp root must be a platform root")
                }
            };
        let cluster_config_chirho = base_chirho.join("cluster-chirho.json");
        let ledger_config_chirho = base_chirho.join("ledger-chirho.toml");
        let authorization_chirho = base_chirho.join("activation-chirho.json");
        let fixture_chirho = Self {
            base_chirho,
            selected_root_chirho,
            cluster_config_chirho,
            ledger_config_chirho,
            authorization_chirho,
            canonical_selected_chirho,
            root_path_string_chirho,
        };
        write_private_chirho(
            &fixture_chirho.authorization_chirho,
            b"{\"opaque_chirho\":true}\n",
        );
        fixture_chirho.write_cluster_chirho(
            &fixture_chirho.root_path_string_chirho,
            Some(&fixture_chirho.authorization_chirho.to_string_lossy()),
        );
        fixture_chirho
            .write_ledger_chirho(&fixture_chirho.canonical_selected_chirho.to_string_lossy());
        fixture_chirho
    }

    fn layout_chirho(&self) -> Item6DrillRootLayoutChirho {
        Item6DrillRootLayoutChirho {
            selected_root_chirho: self.selected_root_chirho.clone(),
            drill_namespace_chirho: self.base_chirho.clone(),
            cluster_config_chirho: self.cluster_config_chirho.clone(),
            ledger_config_chirho: self.ledger_config_chirho.clone(),
        }
    }

    fn write_cluster_chirho(&self, root_path_chirho: &str, authorization_chirho: Option<&str>) {
        let auth_field_chirho = match authorization_chirho {
            Some(path_chirho) => {
                format!(",\n  \"writer_era_activation_authorization_chirho\": \"{path_chirho}\"")
            }
            None => String::new(),
        };
        let bytes_chirho = format!(
            r#"{{
  "group_chirho": {{ "kind_chirho": "root", "root_path_chirho": "{root_path_chirho}" }},
  "local_raft_id_chirho": 1,
  "members_chirho": [
    {{ "raft_id_chirho": 1, "pubkey_chirho": "{}", "url_chirho": "http://127.0.0.1:8300", "learner_chirho": false }}
  ],
  "durable_dir_chirho": "{}",
  "sign_root_chirho": "{}",
  "listen_addr_chirho": "127.0.0.1:8300",
  "tick_ms_chirho": 50{auth_field_chirho}
}}"#,
            "a".repeat(64),
            self.base_chirho.join("raft-chirho").display(),
            self.base_chirho.join("sign-chirho").display(),
        )
        .into_bytes();
        write_private_chirho(&self.cluster_config_chirho, &bytes_chirho);
    }

    fn write_ledger_chirho(&self, root_chirho: &str) {
        let bytes_chirho = format!("root_chirho = \"{root_chirho}\"\nport_chirho = 8788\n");
        write_private_chirho(&self.ledger_config_chirho, bytes_chirho.as_bytes());
    }
}

fn assert_validate_refuses_chirho(
    layout_chirho: &Item6DrillRootLayoutChirho,
    expected_chirho: Item6DrillRootLayoutRefusalChirho,
) {
    let error_chirho = validate_item6_drill_root_layout_chirho(layout_chirho)
        .expect_err("malformed drill-root layout must refuse");
    assert_eq!(
        error_chirho.downcast_ref::<Item6DrillRootLayoutRefusalChirho>(),
        Some(&expected_chirho),
        "unexpected refusal: {error_chirho:#}"
    );
}

// ---------------------------------------------------------------------------------------------
// Pure path-convention (lexical; no filesystem) — the genuinely-new 6.5-b invariant.
// ---------------------------------------------------------------------------------------------

fn assert_convention_chirho(
    selected_chirho: &str,
    namespace_chirho: &str,
    expected_chirho: Result<(), Item6DrillRootLayoutRefusalChirho>,
) {
    assert_eq!(
        check_item6_drill_root_path_convention_chirho(
            Path::new(selected_chirho),
            Path::new(namespace_chirho)
        ),
        expected_chirho
    );
}

#[test]
fn path_convention_accepts_a_canonical_namespaced_drill_root_chirho() {
    assert_convention_chirho(
        "/var/lib/cairn-item6-drill-chirho/boaz3/current-root-chirho",
        CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
        Ok(()),
    );
    // A production-lookalike sibling namespace is NOT falsely caught by the component-wise check.
    assert_convention_chirho(
        "/var/lib/cairn-chirho-drill-chirho/owner/current-root-chirho",
        "/var/lib/cairn-chirho-drill-chirho",
        Ok(()),
    );
}

#[test]
fn path_convention_rejects_production_and_elector_roots_chirho() {
    use Item6DrillRootLayoutRefusalChirho as RefusalChirho;
    assert_convention_chirho(
        FORBIDDEN_PRODUCTION_ROOT_CHIRHO,
        CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
        Err(RefusalChirho::SelectedRootIsProductionRootChirho),
    );
    assert_convention_chirho(
        "/var/lib/cairn-chirho/current-root-chirho",
        CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
        Err(RefusalChirho::SelectedRootIsProductionRootChirho),
    );
    assert_convention_chirho(
        FORBIDDEN_ELECTOR_ROOT_CHIRHO,
        CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
        Err(RefusalChirho::SelectedRootIsElectorRootChirho),
    );
    assert_convention_chirho(
        "/var/lib/cairn-elector-chirho/group",
        CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
        Err(RefusalChirho::SelectedRootIsElectorRootChirho),
    );
}

#[test]
fn path_convention_rejects_relative_denormalized_outside_and_bad_namespace_chirho() {
    use Item6DrillRootLayoutRefusalChirho as RefusalChirho;
    assert_convention_chirho(
        "relative/current-root-chirho",
        CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
        Err(RefusalChirho::SelectedRootNotAbsoluteChirho),
    );
    // A `..` component would otherwise escape the namespace lexically — it is refused, not resolved.
    assert_convention_chirho(
        "/var/lib/cairn-item6-drill-chirho/../cairn-chirho/current-root-chirho",
        CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
        Err(RefusalChirho::SelectedRootNotNormalizedChirho),
    );
    assert_convention_chirho(
        "/opt/cairn-item6-drill-chirho/owner/current-root-chirho",
        CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
        Err(RefusalChirho::SelectedRootOutsideDrillNamespaceChirho),
    );
    assert_convention_chirho(
        "/var/lib/cairn-item6-drill-chirho/owner/current-root-chirho",
        "relative-namespace-chirho",
        Err(RefusalChirho::DrillNamespaceInvalidChirho),
    );
    // A namespace that IS the production root cannot bless a drill root.
    assert_convention_chirho(
        "/var/lib/cairn-item6-drill-chirho/owner/current-root-chirho",
        FORBIDDEN_PRODUCTION_ROOT_CHIRHO,
        Err(RefusalChirho::DrillNamespaceInvalidChirho),
    );
}

// ---------------------------------------------------------------------------------------------
// Canonical forbidden-root backstop (filesystem; resolves symlinks + case folds). The lexical
// convention check above reasons on raw components and is blind to a symlink or a case variant;
// this backstop re-asserts the never-production / never-elector invariant on the canonical path.
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn canonical_backstop_refuses_symlink_to_forbidden_root_chirho() {
    // A dir standing in for the production root `/var/lib/cairn-chirho`: a real forbidden dir the
    // hermetic test can create, since the real constant lives outside any temp tree. A never-elected
    // Local-era production root left on a host is exactly the case the era-freshness check CANNOT
    // catch (it is fresh), so the drill-namespace convention must own it.
    let base_chirho = unique_base_chirho("canonical-backstop");
    let forbidden_fixture_chirho = base_chirho.join("prod-fixture-chirho");
    let namespace_chirho = base_chirho.join("var-lib-cairn-item6-drill-chirho");
    let host_dir_chirho = namespace_chirho.join("owner-host-chirho");
    std::fs::create_dir_all(&forbidden_fixture_chirho).expect("create forbidden fixture");
    std::fs::create_dir_all(&host_dir_chirho).expect("create drill host dir");
    let canonical_forbidden_chirho = forbidden_fixture_chirho
        .canonicalize()
        .expect("canonicalize forbidden fixture");
    let forbidden_roots_chirho: [&Path; 1] = [canonical_forbidden_chirho.as_path()];

    // The selected drill root is a SYMLINK under the namespace pointing at the forbidden fixture.
    let selected_root_chirho = host_dir_chirho.join("current-root-chirho");
    std::os::unix::fs::symlink(&forbidden_fixture_chirho, &selected_root_chirho)
        .expect("stage the symlinked drill root");

    // (pre-fix behavior) the LEXICAL convention check is BLIND to the symlink: the raw path is
    // absolute, normalized, not lexically a forbidden root, and lexically under the namespace, so it
    // PASSES on the raw path — which is precisely why the canonical backstop is required.
    check_item6_drill_root_path_convention_chirho(&selected_root_chirho, &namespace_chirho)
        .expect("lexical convention is blind to the symlink and passes on the raw path");

    // (the fix) the CANONICAL backstop resolves the symlink to the forbidden fixture and REFUSES,
    // with its own distinct named reason (before this fix the layout reached the later custody steps).
    let refusal_chirho = check_canonical_selected_root_not_forbidden_against_chirho(
        &selected_root_chirho,
        &forbidden_roots_chirho,
    )
    .expect_err("canonical backstop must refuse a symlink resolving to a forbidden root");
    assert_eq!(
        refusal_chirho,
        Item6DrillRootLayoutRefusalChirho::CanonicalSelectedRootIsForbiddenChirho
    );

    // Positive control: a real (non-symlink) drill root under the same namespace canonicalizes to
    // itself, which is NOT under the forbidden fixture, so the backstop accepts.
    let safe_root_chirho = host_dir_chirho.join("safe-root-chirho");
    std::fs::create_dir_all(&safe_root_chirho).expect("create safe drill root");
    check_canonical_selected_root_not_forbidden_against_chirho(
        &safe_root_chirho,
        &forbidden_roots_chirho,
    )
    .expect("a safe drill root under the namespace passes the canonical backstop");

    // The public entry point (real production/elector constants) must NOT false-positive on either
    // the safe real root or the safe symlink, both of which resolve nowhere near the real constants.
    check_canonical_selected_root_not_forbidden_chirho(&safe_root_chirho)
        .expect("public backstop accepts a safe temp root under the real constants");
    check_canonical_selected_root_not_forbidden_chirho(&selected_root_chirho)
        .expect("public backstop accepts a temp symlink resolving nowhere near the real roots");

    std::fs::remove_dir_all(&base_chirho).expect("clean up fixture");
}

// ---------------------------------------------------------------------------------------------
// Custody bindings + freshness (filesystem; reuse the geo-node checks/primitives).
// ---------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------
// Initialisation (step 6b) — the gap step (7) could not see.
//
// `writer_authority_era_chirho` maps a MISSING writer fence to `LocalChirho`, which is also what a
// correctly staged pre-activation root reports. Before step (6b) existed, this crate's own fixture —
// a bare `create_dir_all` — validated clean and returned `custody_verified_chirho: true`, so the
// suite's green was a statement about an empty directory. These arms pin the three distinct ways
// initialisation fails, and each asserts it is NOT one of the others.
// ---------------------------------------------------------------------------------------------

/// Bind the constant to the DISPOSITION AUTHORITY rather than trusting a literal.
///
/// **This proves the surface TRAVELS with a root. It does NOT prove birth created it** — that claim
/// was measured false and is gone from this module. The guard is still worth having: if the surface
/// ever stops being carried-with-the-root, step (6b) is keyed on the wrong thing and this fires.
#[test]
fn the_named_lock_surface_is_required_to_travel_with_the_root_chirho() {
    use cairn_tenant_chirho::surface_disposition_chirho::{
        disposition_for_surface_chirho, surface_travels_with_the_root_chirho,
        SurfaceDispositionChirho,
    };
    let disposition_chirho = disposition_for_surface_chirho(NAMED_LOCK_SURFACE_CHIRHO)
        .expect("the named lock surface must be a known root surface");
    assert_eq!(
        disposition_chirho,
        SurfaceDispositionChirho::CarriedWithTheRootChirho,
        "step (6b) keys on a surface that must travel with a root; if it stops being \
         carried-with-the-root, the check is keyed on the wrong thing"
    );
    assert!(surface_travels_with_the_root_chirho(disposition_chirho));
}

#[test]
fn a_never_opened_root_refuses_by_its_own_identity_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("uninitialized");
    std::fs::remove_dir_all(
        fixture_chirho
            .selected_root_chirho
            .join(NAMED_LOCK_SURFACE_CHIRHO),
    )
    .expect("remove the named lock surface");
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::SelectedRootNeverOpenedChirho,
    );
}

/// The whole point of step (6b): an EMPTY DIRECTORY must not validate. Before the fix this exact
/// layout returned `custody_verified_chirho: true`.
#[test]
fn a_bare_directory_is_not_a_drill_root_and_is_not_reported_already_activated_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("bare-directory");
    std::fs::remove_dir_all(
        fixture_chirho
            .selected_root_chirho
            .join(NAMED_LOCK_SURFACE_CHIRHO),
    )
    .expect("remove the named lock surface");
    let error_chirho = validate_item6_drill_root_layout_chirho(&fixture_chirho.layout_chirho())
        .expect_err("a bare directory must not validate as a staged drill root");
    let refusal_chirho = error_chirho.downcast_ref::<Item6DrillRootLayoutRefusalChirho>();
    assert_eq!(
        refusal_chirho,
        Some(&Item6DrillRootLayoutRefusalChirho::SelectedRootNeverOpenedChirho)
    );
    // The identity assertion that carries the causal claim: the pre-fix world reported this root as
    // FRESH (it passed step 7 entirely), and a naive fix would report it as already-activated.
    assert_ne!(
        refusal_chirho,
        Some(&Item6DrillRootLayoutRefusalChirho::SelectedRootAlreadyActivatedChirho)
    );
}

/// A present-but-not-a-directory surface is its OWN refusal. Folding it into "not initialized" would
/// be the same collapse the three identities exist to prevent.
#[test]
fn a_non_directory_lock_surface_refuses_as_structurally_invalid_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("invalid-structure");
    let surface_chirho = fixture_chirho
        .selected_root_chirho
        .join(NAMED_LOCK_SURFACE_CHIRHO);
    std::fs::remove_dir_all(&surface_chirho).expect("remove the named lock surface");
    std::fs::write(&surface_chirho, b"not a directory\n")
        .expect("write a regular file in its place");
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::SelectedRootStructureInvalidChirho,
    );
}

/// PRESENT BUT UNREADABLE is the case that eats fixes. `Path::exists()` reports `false` on
/// permission-denied, so a check written with it would post this root into the ABSENT branch and the
/// original defect would survive behind a smaller door. This arm exists to make that regression
/// impossible to land silently.
#[cfg(unix)]
#[test]
fn an_unreadable_lock_surface_is_not_reported_as_absent_chirho() {
    use std::os::unix::fs::PermissionsExt;
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("unreadable-structure");
    let root_chirho = fixture_chirho.selected_root_chirho.clone();
    // Remove SEARCH permission on the root so resolving a child refuses with PermissionDenied
    // rather than NotFound. Restored by the guard below whatever the assertions do.
    struct RestoreModeChirho(PathBuf);
    impl Drop for RestoreModeChirho {
        fn drop(&mut self) {
            let _ignored_chirho =
                std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    let _restore_chirho = RestoreModeChirho(root_chirho.clone());
    std::fs::set_permissions(&root_chirho, std::fs::Permissions::from_mode(0o600))
        .expect("drop search permission on the staged root");

    // Running as root bypasses the permission bit entirely, which would make this arm vacuous
    // rather than failing — so detect that world and say so instead of asserting into it.
    // A SKIP THAT RETURNS IS GREEN-BY-EMPTINESS. An earlier version printed and returned here, so
    // under CI as root this arm would report success having proven nothing — on the one arm that
    // distinguishes unreadable from absent. A distinguishing arm that cannot be exercised is a
    // NON-PASS, and the only honest way to say that in this harness is to fail.
    assert!(
        std::fs::symlink_metadata(root_chirho.join(NAMED_LOCK_SURFACE_CHIRHO)).is_err(),
        "CANNOT EXERCISE: permission bits are not enforced for this user (running as root?), so the \
         unreadable case cannot be staged. This arm proves nothing here and is failing rather than \
         reporting a green it did not earn."
    );
    assert_eq!(
        check_selected_root_has_been_opened_chirho(&root_chirho),
        Err(Item6DrillRootLayoutRefusalChirho::SelectedRootStructureUnreadableChirho),
        "an unreadable lock surface must NOT be reported as absent"
    );
    assert_ne!(
        check_selected_root_has_been_opened_chirho(&root_chirho),
        Err(Item6DrillRootLayoutRefusalChirho::SelectedRootNeverOpenedChirho)
    );
}

/// THE KNOWN LIMIT, PINNED AS BEHAVIOUR RATHER THAN LEFT AS A SURPRISE.
///
/// Step (6b) asks "has a named lock ever opened this root", not "was this born". A root whose birth
/// BEGAN, took a lock, and failed before completing carries the surface and therefore PASSES. This
/// arm asserts that it passes — **not because passing is desirable, but because the limitation is
/// real and an unrecorded limitation is how the next reader inherits a guarantee nobody proved.**
///
/// If a genuine birth marker is ever found, this arm should go RED and be retargeted to assert a
/// refusal. That is the intended migration and it is why the arm exists.
#[test]
fn a_touched_but_not_born_root_passes_and_that_is_the_known_limit_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("touched-not-born");
    // The fixture provisions the lock surface exactly as a partial birth would have, and NOTHING
    // else that a completed birth writes. Under the honest predicate this is indistinguishable
    // from a fully born root, which is the whole point.
    let resolved_chirho = validate_item6_drill_root_layout_chirho(&fixture_chirho.layout_chirho())
        .expect("KNOWN LIMIT: a touched-but-not-born root currently validates");
    assert!(
        resolved_chirho.custody_verified_chirho,
        "recording the limit exactly: custody_verified is returned true for a root that may never \
         have completed birth"
    );
}

#[test]
fn well_formed_drill_root_validates_and_resolves_its_members_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("well-formed");
    let resolved_chirho = validate_item6_drill_root_layout_chirho(&fixture_chirho.layout_chirho())
        .expect("a well-formed staged drill root validates");

    assert_eq!(
        resolved_chirho.schema_chirho,
        ITEM6_DRILL_ROOT_LAYOUT_SCHEMA_V1_CHIRHO
    );
    assert!(resolved_chirho.custody_verified_chirho);
    assert_eq!(resolved_chirho.writer_era_chirho, "local-chirho");
    assert_eq!(
        resolved_chirho.durable_dir_chirho,
        fixture_chirho.base_chirho.join("raft-chirho")
    );
    assert_eq!(
        resolved_chirho.sign_root_chirho,
        fixture_chirho.base_chirho.join("sign-chirho")
    );
    // A DECLARED path is recorded (Some) — the ceremony/declared flow is preserved by the step-6 fix.
    assert_eq!(
        resolved_chirho.writer_era_activation_authorization_chirho,
        Some(fixture_chirho.authorization_chirho.clone())
    );
    assert_eq!(
        resolved_chirho.consistency_group_id_chirho,
        consistency_group_for_root_chirho(&fixture_chirho.selected_root_chirho)
            .unwrap()
            .canonical_id_chirho()
    );
}

#[test]
fn validator_enforces_the_path_convention_before_touching_the_filesystem_chirho() {
    // selected_root is the production root; the config paths do not exist. The path convention
    // refuses at step 1, before any custody read.
    let layout_chirho = Item6DrillRootLayoutChirho::under_canonical_namespace_chirho(
        PathBuf::from("/var/lib/cairn-chirho/current-root-chirho"),
        PathBuf::from("/nonexistent-cluster-chirho.json"),
        PathBuf::from("/nonexistent-ledger-chirho.toml"),
    );
    assert_validate_refuses_chirho(
        &layout_chirho,
        Item6DrillRootLayoutRefusalChirho::SelectedRootIsProductionRootChirho,
    );
}

#[test]
fn wrong_consistency_group_binding_refuses_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("wrong-group");
    fixture_chirho.write_cluster_chirho(
        &format!("{}-other-chirho", fixture_chirho.root_path_string_chirho),
        Some(&fixture_chirho.authorization_chirho.to_string_lossy()),
    );
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::ConsistencyGroupMismatchChirho,
    );
}

#[test]
fn ledger_config_root_binding_mismatch_refuses_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("config-root");
    let other_root_chirho = fixture_chirho.base_chirho.join("other-root-chirho");
    std::fs::create_dir_all(&other_root_chirho).unwrap();
    fixture_chirho
        .write_ledger_chirho(&other_root_chirho.canonicalize().unwrap().to_string_lossy());
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::ConfigRootBindingMismatchChirho,
    );
}

/// RULED (seed-first step-6 skip): a cluster config that OMITS the writer-era activation
/// authorization path describes a seed-first drill root — the seed latches Elected via H3 regenesis
/// and mints no geo ceremony file — so step (6) is SKIPPED and validation proceeds.
///
/// This test FLIPPED when the skip was ruled: it formerly asserted the OMITTED path REFUSED
/// `WriterEraAuthorizationPathMissingChirho` (a refusal identity now removed). Its fixture is
/// unchanged (still `write_cluster_chirho(root, None)`), so the new green is a statement about the
/// code, not the test.
///
/// MIGRATION PATH — if this ever fails:
/// * it REFUSES on the omit-path shape (any writer-era reason) => the ruled seed-first skip
///   regressed (step 6 went back to hard-requiring the geo file). Re-read
///   `spec-chirho/workstream-state-chirho/validator-restage-prep-chirho.md` BEFORE "fixing" the test.
/// * it refuses at some OTHER step => a different binding broke on the seed-first shape; diagnose
///   that step and leave step 6 alone.
/// * it resolves with `Some(_)` in `writer_era_activation_authorization_chirho` => step 6 did NOT
///   skip; the config-omits-path branch is not being taken.
#[test]
fn omitted_writer_era_authorization_path_skips_step6_and_validates_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("omitted-auth-path");
    fixture_chirho.write_cluster_chirho(&fixture_chirho.root_path_string_chirho, None);
    let resolved_chirho = validate_item6_drill_root_layout_chirho(&fixture_chirho.layout_chirho())
        .expect("a seed-first drill root that omits the writer-era activation path skips step 6");
    // Step 6 was SKIPPED, not run: the resolved evidence records no declared authorization path.
    assert_eq!(
        resolved_chirho.writer_era_activation_authorization_chirho, None,
        "an omitted writer-era activation path must be recorded as None, proving step 6 was skipped"
    );
    // Freshness (step 7) still held: the staged root is pre-activation (Local era).
    assert_eq!(resolved_chirho.writer_era_chirho, "local-chirho");
    assert!(resolved_chirho.custody_verified_chirho);
}

/// STEP 6 IS NOT DEAD (declared-path negative control #1): a config that DECLARES the writer-era
/// activation path still has step (6) verify the file. When the declared file is absent, step 6
/// refuses `WriterEraAuthorizationFileInvalidChirho` exactly as before the seed-first skip. This is
/// also the ceremony-flow expectation the 6.5-f build contract depends on (the drill config declares
/// the path; the activation file does not exist until f-5, so the validator must stop at step 6 with
/// this reason). Left unchanged by the step-6 fix; it MUST keep passing.
#[test]
fn missing_writer_era_authorization_file_refuses_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("missing-auth-file");
    std::fs::remove_file(&fixture_chirho.authorization_chirho)
        .expect("remove the declared authorization file");
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::WriterEraAuthorizationFileInvalidChirho,
    );
}

/// STEP 6 IS NOT DEAD (declared-path negative control #2): a config that DECLARES a NON-ABSOLUTE
/// writer-era activation path is verified and refused `WriterEraAuthorizationFileInvalidChirho` via
/// the opaque file check's `is_absolute` gate. The seed-first skip is ONLY for the OMITTED case, so a
/// declared-but-invalid path must still refuse — this exercises the `!is_absolute()` branch that the
/// declared-but-absent-file sibling above does not reach.
#[test]
fn declared_non_absolute_writer_era_authorization_path_refuses_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("declared-relative-auth-path");
    // The cluster config DECLARES a path, but a relative one — the opaque file check refuses it.
    fixture_chirho.write_cluster_chirho(
        &fixture_chirho.root_path_string_chirho,
        Some("relative-activation-chirho.json"),
    );
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::WriterEraAuthorizationFileInvalidChirho,
    );
}

/// The property the hosted seed-first drill depends on: a freshly-staged, pre-activation drill root
/// whose cluster config OMITS the writer-era activation path (the seed-first shape) passes ALL of
/// steps 1-7 and emits its full resolved layout evidence — path convention + canonical backstop,
/// both custody bindings, the group + config-root bindings, the SKIPPED step (6), and Local-era
/// freshness. This is the end-to-end counterpart to the focused step-6-skip arm above; its declared
/// twin is `well_formed_drill_root_validates_and_resolves_its_members_chirho`.
#[test]
fn seed_first_shaped_root_omitting_activation_validates_all_seven_steps_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("seed-first-all-steps");
    fixture_chirho.write_cluster_chirho(&fixture_chirho.root_path_string_chirho, None);
    let resolved_chirho = validate_item6_drill_root_layout_chirho(&fixture_chirho.layout_chirho())
        .expect("a seed-first drill root (omitting the geo activation path) passes all 7 steps");

    // Schema + custody verdict — reaching here means steps 1-5 and 7 all passed.
    assert_eq!(
        resolved_chirho.schema_chirho,
        ITEM6_DRILL_ROOT_LAYOUT_SCHEMA_V1_CHIRHO
    );
    assert!(resolved_chirho.custody_verified_chirho);
    assert_eq!(resolved_chirho.writer_era_chirho, "local-chirho");
    // Step (6) skipped: no declared geo ceremony file on the seed-first shape.
    assert_eq!(
        resolved_chirho.writer_era_activation_authorization_chirho,
        None
    );
    // The reused geo-node bindings still resolved their members from the cluster config.
    assert_eq!(
        resolved_chirho.durable_dir_chirho,
        fixture_chirho.base_chirho.join("raft-chirho")
    );
    assert_eq!(
        resolved_chirho.sign_root_chirho,
        fixture_chirho.base_chirho.join("sign-chirho")
    );
    assert_eq!(
        resolved_chirho.consistency_group_id_chirho,
        consistency_group_for_root_chirho(&fixture_chirho.selected_root_chirho)
            .unwrap()
            .canonical_id_chirho()
    );
}

#[cfg(unix)]
#[test]
fn broad_mode_cluster_config_refuses_custody_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("cluster-custody");
    set_broad_mode_chirho(&fixture_chirho.cluster_config_chirho);
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::ClusterConfigCustodyChirho,
    );
}

#[cfg(unix)]
#[test]
fn broad_mode_ledger_config_refuses_custody_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("ledger-custody");
    set_broad_mode_chirho(&fixture_chirho.ledger_config_chirho);
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::LedgerConfigCustodyChirho,
    );
}

#[test]
fn already_elected_activated_root_refuses_as_not_fresh_chirho() {
    let fixture_chirho = DrillRootFixtureChirho::new_chirho("already-activated");
    // Latch an elected writer fence so the staged root is no longer Local (pre-activation).
    issue_elected_writer_fence_for_root_chirho(&fixture_chirho.selected_root_chirho, 1)
        .expect("issue an elected writer fence for the test");
    assert_validate_refuses_chirho(
        &fixture_chirho.layout_chirho(),
        Item6DrillRootLayoutRefusalChirho::SelectedRootAlreadyActivatedChirho,
    );
}
