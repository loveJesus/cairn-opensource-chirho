// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Brick #5's AUTHOR-side arms: the typed mode stamps the marker the consumer fence refuses, and
//! refuses an invocation whose issuer naming disagrees with the mode it declared.
//!
//! **What these arms do NOT prove, said here so the suite is not read wider than it is.** They prove
//! the mode is legible and self-consistent. They do NOT prove a test-kind issuer cannot become a
//! production issuer — that is CUSTODY (the pin is derived from a pre-provisioned secret, so a key
//! absent from a root cannot be pinned on it), and no arm in this file touches it. An operator who
//! points a `TestKindChirho` run at the production issuer secret AND renames it to the reserved
//! prefix gets a production key wearing a marker, and every assertion below still passes. The
//! consumer-side refusal lives in `cairn-ledger-host-chirho`'s `test_kind_fence_tests_chirho`.

use super::ledger_host_artifact_derivation_tests_chirho::{
    activation_pin_chirho, issuer_pin_chirho, valid_inputs_chirho,
};
use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::ledger_host_artifact_derivation_chirho::derive_ledger_host_artifacts_chirho;
use crate::ledger_host_authoring_inputs_chirho::LedgerHostAuthoringInputsV1Chirho;
use crate::ledger_host_authoring_mode_chirho::{
    LedgerHostAuthoringModeChirho, LedgerHostAuthoringModeCoordinateChirho,
};
use crate::ledger_host_custody_binding_chirho::{
    bind_custody_and_derive_ledger_host_artifacts_chirho, LedgerHostCustodyRequestChirho,
};
use cairn_config_chirho::config_chirho::{
    LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO,
    LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO,
};
use std::path::PathBuf;

const PRODUCTION_ISSUER_SECRET_NAME_CHIRHO: &str = "offline-kind-issuer-secret-chirho";

fn reserved_chirho(suffix_chirho: &str) -> String {
    format!("{LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO}{suffix_chirho}")
}

/// The reviewed document with a reserved-prefixed issuer principal — the shape a test-kind run must
/// supply. Everything else is the same document the derivation arms use.
fn test_kind_inputs_chirho() -> LedgerHostAuthoringInputsV1Chirho {
    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.issuer_principal_chirho = reserved_chirho("kind-issuer-chirho");
    inputs_chirho
}

/// A root that exists and carries no secret store, so any road that gets past the mode law fails at
/// custody with a plainly different identity.
fn empty_root_chirho() -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-authoring-mode-chirho-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// The mode decides the marker, and both branches are exercised — an arm that only checked the
/// production branch would pass against a function that never stamps anything.
#[test]
fn the_mode_decides_whether_the_emitted_config_carries_the_marker_chirho() {
    let production_chirho = derive_ledger_host_artifacts_chirho(
        &valid_inputs_chirho(),
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
        crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
        LedgerHostAuthoringModeChirho::ProductionChirho,
    )
    .expect("the production posture must still author (positive control)");
    assert!(
        production_chirho.config_chirho.test_kind_chirho.is_none(),
        "a production authoring run must emit no test-kind marker"
    );

    let test_kind_chirho = derive_ledger_host_artifacts_chirho(
        &test_kind_inputs_chirho(),
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
        crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
        LedgerHostAuthoringModeChirho::TestKindChirho,
    )
    .expect("the test-kind posture must author (positive control)");
    let marker_chirho = test_kind_chirho
        .config_chirho
        .test_kind_chirho
        .as_ref()
        .expect("a test-kind authoring run must emit the marker");
    assert_eq!(
        marker_chirho.schema_chirho,
        LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO
    );

    // The marker is not decoration: the emitted config still satisfies the serve boundary's own
    // law, which requires the marker and the reserved principal to agree.
    test_kind_chirho.config_chirho.validate_chirho().unwrap();
}

/// The four naming arms, asserted by exact VARIANT and by exact COORDINATE.
///
/// The two refusals are deliberate mirrors of each other, so every arm also asserts it is not its
/// mirror: a fixture aimed at "you forgot the drill naming" would otherwise pass against a law that
/// emitted "you reached for the drill's key" for every disagreement, and half the law would be
/// untested while green.
#[test]
fn the_mode_refuses_issuer_naming_that_disagrees_with_it_chirho() {
    // POSITIVE CONTROLS: both agreeing invocations pass, so the four refusals below cannot be a
    // law that refuses everything.
    LedgerHostAuthoringModeChirho::ProductionChirho
        .refuse_mismatched_issuer_naming_chirho(
            PRODUCTION_ISSUER_SECRET_NAME_CHIRHO,
            &valid_inputs_chirho().issuer_principal_chirho,
        )
        .unwrap();
    LedgerHostAuthoringModeChirho::TestKindChirho
        .refuse_mismatched_issuer_naming_chirho(
            &reserved_chirho("issuer-secret-chirho"),
            &test_kind_inputs_chirho().issuer_principal_chirho,
        )
        .unwrap();

    let missing_secret_chirho = LedgerHostAuthoringModeChirho::TestKindChirho
        .refuse_mismatched_issuer_naming_chirho(
            PRODUCTION_ISSUER_SECRET_NAME_CHIRHO,
            &test_kind_inputs_chirho().issuer_principal_chirho,
        )
        .unwrap_err();
    assert_eq!(
        missing_secret_chirho,
        LedgerRegenesisRefusalChirho::AuthoringTestKindReservedNameMissingChirho {
            coordinate_chirho: LedgerHostAuthoringModeCoordinateChirho::IssuerSecretNameChirho,
        }
    );

    let missing_principal_chirho = LedgerHostAuthoringModeChirho::TestKindChirho
        .refuse_mismatched_issuer_naming_chirho(
            &reserved_chirho("issuer-secret-chirho"),
            &valid_inputs_chirho().issuer_principal_chirho,
        )
        .unwrap_err();
    assert_eq!(
        missing_principal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringTestKindReservedNameMissingChirho {
            coordinate_chirho: LedgerHostAuthoringModeCoordinateChirho::IssuerPrincipalChirho,
        }
    );

    let reserved_secret_chirho = LedgerHostAuthoringModeChirho::ProductionChirho
        .refuse_mismatched_issuer_naming_chirho(
            &reserved_chirho("issuer-secret-chirho"),
            &valid_inputs_chirho().issuer_principal_chirho,
        )
        .unwrap_err();
    assert_eq!(
        reserved_secret_chirho,
        LedgerRegenesisRefusalChirho::AuthoringProductionReservedNameRefusedChirho {
            coordinate_chirho: LedgerHostAuthoringModeCoordinateChirho::IssuerSecretNameChirho,
        }
    );

    let reserved_principal_chirho = LedgerHostAuthoringModeChirho::ProductionChirho
        .refuse_mismatched_issuer_naming_chirho(
            PRODUCTION_ISSUER_SECRET_NAME_CHIRHO,
            &test_kind_inputs_chirho().issuer_principal_chirho,
        )
        .unwrap_err();
    assert_eq!(
        reserved_principal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringProductionReservedNameRefusedChirho {
            coordinate_chirho: LedgerHostAuthoringModeCoordinateChirho::IssuerPrincipalChirho,
        }
    );

    // Each direction is NOT its mirror, and each coordinate is NOT its sibling.
    assert_ne!(missing_secret_chirho, reserved_secret_chirho);
    assert_ne!(missing_principal_chirho, reserved_principal_chirho);
    assert_ne!(missing_secret_chirho, missing_principal_chirho);
    assert_ne!(reserved_secret_chirho, reserved_principal_chirho);
}

/// The law is WIRED, and it runs before the secret store is touched.
///
/// Both calls below aim at a root with no secret store, so a road that reached custody would refuse
/// with a custody identity. The mode-mismatched call must instead refuse with the mode identity,
/// which is only possible if the mode law ran first. The matched call is the control: it must reach
/// the custody refusal, or this arm would pass against a road that refuses everything with the mode
/// identity.
#[test]
fn the_custody_road_runs_the_mode_law_before_reading_any_secret_chirho() {
    let root_chirho = empty_root_chirho();
    let inputs_chirho = valid_inputs_chirho();

    let control_chirho =
        bind_custody_and_derive_ledger_host_artifacts_chirho(LedgerHostCustodyRequestChirho {
            selected_root_chirho: &root_chirho,
            inputs_chirho: &inputs_chirho,
            destination_authority_enrollment_chirho:
                crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
            issuer_secret_name_chirho: PRODUCTION_ISSUER_SECRET_NAME_CHIRHO,
            activation_secret_name_chirho: None,
            mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
        })
        .expect_err("a root with no secret store cannot bind custody");
    assert!(
        !matches!(
            control_chirho,
            LedgerRegenesisRefusalChirho::AuthoringProductionReservedNameRefusedChirho { .. }
                | LedgerRegenesisRefusalChirho::AuthoringTestKindReservedNameMissingChirho { .. }
        ),
        "an agreeing invocation must fail at custody, not at the mode law, got: {control_chirho:?}"
    );

    let refusal_chirho =
        bind_custody_and_derive_ledger_host_artifacts_chirho(LedgerHostCustodyRequestChirho {
            selected_root_chirho: &root_chirho,
            inputs_chirho: &inputs_chirho,
            destination_authority_enrollment_chirho:
                crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
            issuer_secret_name_chirho: &reserved_chirho("issuer-secret-chirho"),
            activation_secret_name_chirho: None,
            mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
        })
        .expect_err("a production run naming a reserved issuer secret must be refused");
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringProductionReservedNameRefusedChirho {
            coordinate_chirho: LedgerHostAuthoringModeCoordinateChirho::IssuerSecretNameChirho,
        },
        "the mode law must fire before custody; a custody refusal here means it moved below the \
         secret reads"
    );

    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}
