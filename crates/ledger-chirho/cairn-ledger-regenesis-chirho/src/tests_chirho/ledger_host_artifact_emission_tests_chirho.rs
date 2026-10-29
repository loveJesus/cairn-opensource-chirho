// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Adversarial arms for brick #4, artifact emission. Every arm asks one of the four questions this
//! brick's failure modes are made of: **could it overwrite an authority artifact? could it leave
//! half an authoring on disk? could it leave a secret-adjacent file another user can read? are the
//! bytes it wrote the bytes the consumer will accept?**
//!
//! Four conventions make a green here mean something.
//! 1. **Refusal IDENTITY, never merely "an error"** — and where a neighbouring refusal could
//!    plausibly fire instead, the arm asserts it did NOT.
//! 2. **A positive control per arm.** Every arm first proves the unmutated fixture EMITS, so no arm
//!    can pass because the fixture went bad and refused for a reason nobody chose.
//! 3. **A refusal is checked at the FILESYSTEM, not only at the return value.** Asserting the
//!    refusal identity says nothing about what is on disk, and what is on disk is this brick's
//!    entire subject. So the refusal arms assert absence of the artifact that was not reached AND
//!    byte-equality of anything that was already there.
//! 4. **The document is reused, not re-authored** — the reviewed input document comes from brick
//!    #2's fixture, so these arms cannot be tuned to a document shaped to satisfy them.

use super::ledger_host_artifact_derivation_tests_chirho::valid_inputs_chirho;
use super::temp_root_chirho;
use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::ledger_host_artifact_emission_chirho::{
    author_and_emit_ledger_host_artifacts_chirho, ledger_host_config_digest_chirho,
    LedgerHostArtifactKindChirho, LedgerHostEmissionRequestChirho,
    LedgerHostEmittedArtifactsChirho,
};
use crate::ledger_host_authoring_inputs_chirho::LedgerHostAuthoringInputsV1Chirho;
use crate::ledger_host_authoring_mode_chirho::LedgerHostAuthoringModeChirho;
use crate::plan_chirho::{
    canonical_plan_bytes_chirho, load_verified_plan_chirho, LedgerRegenesisPlanV1Chirho,
};
use cairn_config_chirho::config_chirho::{
    parse_config_chirho, LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO, LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
};
use cairn_secret_chirho::secret_chirho::set_secret_chirho;
use std::fs;
use std::path::{Path, PathBuf};

const ISSUER_SECRET_NAME_CHIRHO: &str = "emission-offline-issuer-chirho";
const ACTIVATION_SECRET_NAME_CHIRHO: &str = "emission-offline-activation-chirho";
const CONFIG_OUTPUT_CHIRHO: &str = "authored-host-config-chirho.toml";
const PLAN_OUTPUT_CHIRHO: &str = "authored-regenesis-plan-chirho.json";
const SERVE_PORT_CHIRHO: u16 = 8_912;
/// Distinct seed bytes per role, so any arm that plants one role's value under another name makes a
/// real collision rather than an accidental one.
const ROLE_SEEDS_CHIRHO: [u8; 6] = [1, 2, 3, 4, 5, 6];
const ISSUER_SEED_CHIRHO: u8 = 7;
const ACTIVATION_SEED_CHIRHO: u8 = 8;

struct EmissionFixtureChirho {
    root_chirho: PathBuf,
}

impl Drop for EmissionFixtureChirho {
    fn drop(&mut self) {
        // Restore traversal on anything an arm deliberately made unwritable, so a permission arm
        // cannot leave a temp tree behind that this cleanup silently fails to remove.
        #[cfg(unix)]
        restore_tree_modes_chirho(&self.root_chirho);
        let _removed_chirho = fs::remove_dir_all(&self.root_chirho);
    }
}

#[cfg(unix)]
fn restore_tree_modes_chirho(path_chirho: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata_chirho) = fs::symlink_metadata(path_chirho) else {
        return;
    };
    if !metadata_chirho.is_dir() {
        return;
    }
    let _restored_chirho = fs::set_permissions(path_chirho, fs::Permissions::from_mode(0o700));
    let Ok(entries_chirho) = fs::read_dir(path_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho.flatten() {
        restore_tree_modes_chirho(&entry_chirho.path());
    }
}

/// A directory outside any fixture root that the arm using it creates and destroys, so an arm
/// proving "nothing may be written HERE" cannot leave the very artifact it forbids lying in a
/// shared directory for the next run to trip over.
struct OwnedTempDirChirho {
    path_chirho: PathBuf,
}

impl OwnedTempDirChirho {
    fn create_chirho() -> Self {
        let path_chirho = temp_root_chirho();
        fs::create_dir(&path_chirho).unwrap();
        Self { path_chirho }
    }

    fn basename_chirho(&self) -> String {
        self.path_chirho
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for OwnedTempDirChirho {
    fn drop(&mut self) {
        let _removed_chirho = fs::remove_dir_all(&self.path_chirho);
    }
}

/// A root whose eight secrets are pre-provisioned, well formed, and pairwise distinct. Nothing here
/// creates a key through the code under test; a secret exists because this fixture wrote it,
/// exactly as an operator would with `secret-set`.
fn fixture_chirho() -> EmissionFixtureChirho {
    let root_chirho = temp_root_chirho();
    fs::create_dir(&root_chirho).unwrap();
    let signer_secrets_chirho = valid_inputs_chirho().signer_secrets_chirho;
    let names_chirho = [
        signer_secrets_chirho.journal_chirho,
        signer_secrets_chirho.config_chirho,
        signer_secrets_chirho.feeder_chirho,
        signer_secrets_chirho.kind_root_chirho,
        signer_secrets_chirho.effect_intent_chirho,
        signer_secrets_chirho.effect_terminal_chirho,
    ];
    for (name_chirho, seed_chirho) in names_chirho.iter().zip(ROLE_SEEDS_CHIRHO) {
        set_secret_chirho(&root_chirho, name_chirho, &[seed_chirho; 32]).unwrap();
    }
    set_secret_chirho(
        &root_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        &[ISSUER_SEED_CHIRHO; 32],
    )
    .unwrap();
    set_secret_chirho(
        &root_chirho,
        ACTIVATION_SECRET_NAME_CHIRHO,
        &[ACTIVATION_SEED_CHIRHO; 32],
    )
    .unwrap();
    EmissionFixtureChirho { root_chirho }
}

fn emit_chirho(
    fixture_chirho: &EmissionFixtureChirho,
    inputs_chirho: &LedgerHostAuthoringInputsV1Chirho,
    issuer_secret_name_chirho: &str,
    activation_secret_name_chirho: Option<&str>,
    config_output_chirho: &str,
    plan_output_chirho: &str,
) -> Result<LedgerHostEmittedArtifactsChirho, LedgerRegenesisRefusalChirho> {
    author_and_emit_ledger_host_artifacts_chirho(LedgerHostEmissionRequestChirho {
        selected_root_chirho: &fixture_chirho.root_chirho,
        inputs_chirho,
        destination_authority_enrollment_chirho:
            crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
        issuer_secret_name_chirho,
        activation_secret_name_chirho,
        config_output_chirho: Path::new(config_output_chirho),
        plan_output_chirho: Path::new(plan_output_chirho),
        serve_port_chirho: SERVE_PORT_CHIRHO,
        // Emission arms are about the filesystem laws, not about brick #5's posture; the mode's own
        // laws are pinned in `ledger_host_authoring_mode_tests_chirho`.
        mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
    })
}

/// The unmutated call every arm runs first as its positive control, into its own fresh root.
fn emit_default_chirho(
    fixture_chirho: &EmissionFixtureChirho,
) -> Result<LedgerHostEmittedArtifactsChirho, LedgerRegenesisRefusalChirho> {
    emit_chirho(
        fixture_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
        CONFIG_OUTPUT_CHIRHO,
        PLAN_OUTPUT_CHIRHO,
    )
}

fn config_path_chirho(fixture_chirho: &EmissionFixtureChirho) -> PathBuf {
    fixture_chirho.root_chirho.join(CONFIG_OUTPUT_CHIRHO)
}

fn plan_path_chirho(fixture_chirho: &EmissionFixtureChirho) -> PathBuf {
    fixture_chirho.root_chirho.join(PLAN_OUTPUT_CHIRHO)
}

fn absent_chirho(path_chirho: &Path) -> bool {
    matches!(fs::symlink_metadata(path_chirho), Err(error_chirho)
        if error_chirho.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(unix)]
fn mode_chirho(path_chirho: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path_chirho)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// A positive control every refusal arm shares: prove this fixture's unmutated request EMITS, in a
/// root of its own, so a later refusal cannot be the fixture failing for an unchosen reason.
fn prove_the_unmutated_request_emits_chirho() {
    let control_chirho = fixture_chirho();
    let report_chirho = emit_default_chirho(&control_chirho).unwrap();
    assert!(!absent_chirho(&report_chirho.config_path_chirho));
    assert!(!absent_chirho(&report_chirho.plan_path_chirho));
}

/// The round trip that matters: not "the bytes parse", but "the loader that will actually consume
/// these artifacts accepts them". `load_verified_plan_chirho` is the regenesis entry point's own
/// front door — it applies the config CUSTODY check (regular file, non-symlink, `mode & 0o077 == 0`,
/// same uid as the root), re-parses the config through the serving parser, re-canonicalizes the
/// plan bytes, re-derives the plan digest and compares it to the reviewed one, and runs the
/// coordinate, policy, config-binding and namespace-layout laws. An arm that only re-parsed the two
/// files would pass over a config this consumer refuses.
#[test]
fn emitted_artifacts_are_accepted_by_the_loader_that_will_consume_them_chirho() {
    let fixture_chirho = fixture_chirho();
    let report_chirho = emit_default_chirho(&fixture_chirho).unwrap();

    let verified_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &report_chirho.config_path_chirho,
        &report_chirho.plan_path_chirho,
        &report_chirho.plan_digest_chirho,
    )
    .expect("the emitted pair must satisfy the loader that consumes it");
    assert_eq!(
        verified_chirho.plan_digest_chirho,
        report_chirho.plan_digest_chirho
    );

    // Round-trip back into the types the bytes came from, independently of that loader.
    let config_bytes_chirho = fs::read(&report_chirho.config_path_chirho).unwrap();
    let parsed_chirho =
        parse_config_chirho(std::str::from_utf8(&config_bytes_chirho).unwrap()).unwrap();
    let host_block_chirho = parsed_chirho.ledger_host_chirho.unwrap();
    assert_eq!(
        host_block_chirho.schema_chirho, LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
        "an activation authority was authored, so the derived schema must be v2"
    );
    assert_eq!(parsed_chirho.port_chirho, SERVE_PORT_CHIRHO);
    assert_eq!(
        Path::new(&parsed_chirho.root_chirho)
            .canonicalize()
            .unwrap(),
        fixture_chirho.root_chirho.canonicalize().unwrap(),
        "the emitted config must bind the selected root"
    );
    assert_eq!(
        report_chirho.config_digest_chirho,
        ledger_host_config_digest_chirho(&config_bytes_chirho),
        "the reported config digest must be the digest of the bytes actually written"
    );

    let plan_bytes_chirho = fs::read(&report_chirho.plan_path_chirho).unwrap();
    let plan_chirho: LedgerRegenesisPlanV1Chirho =
        serde_json::from_slice(&plan_bytes_chirho).unwrap();
    assert_eq!(
        plan_bytes_chirho,
        canonical_plan_bytes_chirho(&plan_chirho).unwrap(),
        "the emitted plan bytes must already be canonical, or the loader refuses them"
    );

    // The custody proof travels with the artifacts rather than being left behind.
    assert_eq!(
        report_chirho
            .custody_evidence_chirho
            .proven_runtime_signer_count_chirho,
        6
    );
    assert_eq!(
        report_chirho
            .custody_evidence_chirho
            .proven_offline_authority_count_chirho,
        2
    );
    assert!(
        report_chirho
            .custody_evidence_chirho
            .provider_connection_secret_checked_chirho
    );
}

/// Both artifacts sit beside a secret store, and the serve path's own custody check refuses any
/// config with `mode & 0o077` set — so a group- or world-readable emission is both a disclosure and
/// a config that will not boot.
#[cfg(unix)]
#[test]
fn both_emitted_artifacts_are_owner_only_chirho() {
    let fixture_chirho = fixture_chirho();
    let report_chirho = emit_default_chirho(&fixture_chirho).unwrap();

    // Positive control for the instrument: a file deliberately written at 0644 must read back as
    // 0644, so a mode reader that returned a constant could not make the assertions below pass.
    let control_chirho = fixture_chirho.root_chirho.join("mode-control-chirho.txt");
    fs::write(&control_chirho, b"mode control").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&control_chirho, fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert_eq!(mode_chirho(&control_chirho), 0o644);

    assert_eq!(mode_chirho(&report_chirho.config_path_chirho), 0o600);
    assert_eq!(mode_chirho(&report_chirho.plan_path_chirho), 0o600);
}

/// No-overwrite, arm one of two: an occupied CONFIG output. The plan is written first, so this arm
/// also proves the refusal happens in the resolution phase rather than after a write — if the
/// ordering ever moved, the plan would be on disk here.
#[test]
fn an_occupied_config_output_refuses_and_writes_nothing_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let occupant_chirho = b"an operator's existing reviewed config".to_vec();
    fs::write(config_path_chirho(&fixture_chirho), &occupant_chirho).unwrap();

    let refusal_chirho = emit_default_chirho(&fixture_chirho).unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    // The neighbouring path refusals refuse with the same shape, so name the one that fired.
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::RegenesisPlanChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputWriteRefusedChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    assert_eq!(
        fs::read(config_path_chirho(&fixture_chirho)).unwrap(),
        occupant_chirho,
        "the occupying artifact must be byte-identical; a refusal that truncated it would be an \
         overwrite wearing a refusal's clothes"
    );
    assert!(
        absent_chirho(&plan_path_chirho(&fixture_chirho)),
        "a refusal must leave nothing behind, and the plan is the file this road writes first"
    );
}

/// No-overwrite, arm two of two: an occupied PLAN output, checked independently because one road
/// writes two files and a law proven for one of them is not a law.
#[test]
fn an_occupied_plan_output_refuses_and_writes_nothing_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let occupant_chirho = b"an operator's existing reviewed plan".to_vec();
    fs::write(plan_path_chirho(&fixture_chirho), &occupant_chirho).unwrap();

    let refusal_chirho = emit_default_chirho(&fixture_chirho).unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::RegenesisPlanChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    assert_eq!(
        fs::read(plan_path_chirho(&fixture_chirho)).unwrap(),
        occupant_chirho
    );
    assert!(absent_chirho(&config_path_chirho(&fixture_chirho)));
}

/// A DANGLING symlink is "occupied", which is why the check reads `symlink_metadata` rather than
/// `metadata`: `metadata` follows the link and reports NotFound for a broken one.
///
/// **What this arm does and does not establish.** Mutating the check to `metadata` makes the
/// emission refuse with the generic `AuthoringOutputWriteRefusedChirho` instead — because
/// `O_CREAT | O_EXCL` refuses a symlink outright with `EEXIST` and creates nothing at the target
/// (measured directly). So this arm pins the refusal an operator READS, and the containment it might
/// look like it pins is the kernel's. The two later assertions still matter: they are what would
/// notice if that ever stopped being true.
#[cfg(unix)]
#[test]
fn a_dangling_symlink_at_an_output_counts_as_occupied_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let target_chirho = fixture_chirho.root_chirho.join("never-created-chirho.toml");
    std::os::unix::fs::symlink(&target_chirho, config_path_chirho(&fixture_chirho)).unwrap();
    // Positive control for the fixture itself: the link really is dangling, so this arm is about
    // symlink handling rather than about an ordinary existing file.
    assert!(absent_chirho(&target_chirho));

    let refusal_chirho = emit_default_chirho(&fixture_chirho).unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    assert!(
        fs::symlink_metadata(config_path_chirho(&fixture_chirho))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the symlink must be untouched"
    );
    assert!(
        absent_chirho(&target_chirho),
        "nothing may be created through the link"
    );
    assert!(absent_chirho(&plan_path_chirho(&fixture_chirho)));
}

/// The rollback arm, and the only refusal in this brick that can fire with an artifact already on
/// disk. The config's parent is made unwritable, so resolution and freshness both pass, custody and
/// derivation both pass, the plan is written — and then the config write fails for real.
///
/// If this ever fails with the request SUCCEEDING, the likely cause is running as a user who
/// bypasses directory permissions (root); the arm is about the rollback, not about the permission,
/// and it needs a write failure it can cause deterministically.
#[cfg(unix)]
#[test]
fn a_failed_config_write_removes_the_plan_it_had_already_written_chirho() {
    use std::os::unix::fs::PermissionsExt;
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let sealed_dir_chirho = fixture_chirho.root_chirho.join("sealed-chirho");
    fs::create_dir(&sealed_dir_chirho).unwrap();
    let config_output_chirho = format!("sealed-chirho/{CONFIG_OUTPUT_CHIRHO}");
    fs::set_permissions(&sealed_dir_chirho, fs::Permissions::from_mode(0o500)).unwrap();

    let result_chirho = emit_chirho(
        &fixture_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
        &config_output_chirho,
        PLAN_OUTPUT_CHIRHO,
    );
    let refusal_chirho = result_chirho.expect_err(
        "creating a file inside a mode-0500 directory must fail; if this succeeded, this process \
         bypasses directory permissions and the arm cannot cause the write failure it needs",
    );
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputWriteRefusedChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    // The neighbour that would mean the arm never reached a write at all.
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    assert!(
        absent_chirho(&plan_path_chirho(&fixture_chirho)),
        "the plan was written before the config failed; a refusal that leaves it behind leaves \
         half an authoring on disk"
    );
    assert!(absent_chirho(&sealed_dir_chirho.join(CONFIG_OUTPUT_CHIRHO)));
    fs::set_permissions(&sealed_dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();
}

/// The mirror of the rollback arm, and the arm that pins the WRITE ORDER.
///
/// Sealing the PLAN's parent makes the first write fail, so the config must never be reached. Both
/// files absent therefore says two things at once: nothing survives this refusal, and the config —
/// the authority artifact — is written LAST. If the order were ever swapped, this arm would find a
/// config on disk after a failed emission, with no rollback behind it, because the rollback only
/// removes the artifact written first.
#[cfg(unix)]
#[test]
fn a_failed_plan_write_never_reaches_the_config_chirho() {
    use std::os::unix::fs::PermissionsExt;
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let sealed_dir_chirho = fixture_chirho.root_chirho.join("sealed-plan-chirho");
    fs::create_dir(&sealed_dir_chirho).unwrap();
    let plan_output_chirho = format!("sealed-plan-chirho/{PLAN_OUTPUT_CHIRHO}");
    fs::set_permissions(&sealed_dir_chirho, fs::Permissions::from_mode(0o500)).unwrap();

    let refusal_chirho = emit_chirho(
        &fixture_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
        CONFIG_OUTPUT_CHIRHO,
        &plan_output_chirho,
    )
    .expect_err(
        "creating a file inside a mode-0500 directory must fail; if this succeeded, this process \
         bypasses directory permissions and the arm cannot cause the write failure it needs",
    );
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputWriteRefusedChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::RegenesisPlanChirho,
        }
    );
    assert!(
        absent_chirho(&config_path_chirho(&fixture_chirho)),
        "the config must be written after the plan, so a failed plan write must leave no config; a \
         config here would be an authority artifact surviving a failed authoring"
    );
    assert!(absent_chirho(&sealed_dir_chirho.join(PLAN_OUTPUT_CHIRHO)));
    fs::set_permissions(&sealed_dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();
}

/// Outputs must land inside the selected root. The escape is spelled with `..` rather than with a
/// foreign absolute path because `..` is the shape an operator actually types, and because it
/// proves the check runs on the RESOLVED parent — a textual check would see a path starting with
/// the root and pass.
///
/// **The escape target is a directory this arm OWNS, and that is not tidiness.** An earlier draft
/// escaped into the shared temp directory itself. When the containment check was mutated away to
/// prove this arm causal, the emission did what the arm says it must not: it wrote a real config
/// into that shared directory — where nothing removed it, and where its mere presence then failed
/// this arm's absence assertion on a LATER, unmutated run. An arm whose own failure mode poisons
/// the next run manufactures false alarms about correct code, so the escape lands somewhere this
/// arm creates fresh and destroys.
#[test]
fn an_output_escaping_the_selected_root_refuses_and_writes_nothing_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let outside_chirho = OwnedTempDirChirho::create_chirho();
    let escaped_chirho = format!(
        "../{}/{CONFIG_OUTPUT_CHIRHO}",
        outside_chirho.basename_chirho()
    );
    let outside_path_chirho = outside_chirho.path_chirho.join(CONFIG_OUTPUT_CHIRHO);

    let refusal_chirho = emit_chirho(
        &fixture_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
        &escaped_chirho,
        PLAN_OUTPUT_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputOutsideRootChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputPathRefusedChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    assert!(
        absent_chirho(&outside_path_chirho),
        "nothing may be written outside the selected root"
    );
    assert!(absent_chirho(&plan_path_chirho(&fixture_chirho)));
}

/// A parent that does not exist is refused as UNRESOLVABLE rather than as outside-the-root, and
/// nothing is created — this road creates no directory.
#[test]
fn an_output_in_a_missing_directory_refuses_without_creating_it_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let missing_parent_chirho = fixture_chirho.root_chirho.join("missing-chirho");

    let refusal_chirho = emit_chirho(
        &fixture_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
        &format!("missing-chirho/{CONFIG_OUTPUT_CHIRHO}"),
        PLAN_OUTPUT_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputPathRefusedChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputOutsideRootChirho {
            artifact_chirho: LedgerHostArtifactKindChirho::HostConfigChirho,
        }
    );
    assert!(absent_chirho(&missing_parent_chirho));
    assert!(absent_chirho(&plan_path_chirho(&fixture_chirho)));
}

/// Two outputs naming one object. Spelled with `./` so the two request paths differ as TEXT and
/// agree only once resolved: a comparison made before resolution would pass this and then let the
/// second write decide which artifact survived.
#[test]
fn two_outputs_naming_one_object_refuse_before_any_write_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let aliased_chirho = format!("./{CONFIG_OUTPUT_CHIRHO}");

    let refusal_chirho = emit_chirho(
        &fixture_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
        CONFIG_OUTPUT_CHIRHO,
        &aliased_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringOutputsAliasChirho
    );
    assert!(absent_chirho(&config_path_chirho(&fixture_chirho)));
    assert!(absent_chirho(&plan_path_chirho(&fixture_chirho)));
}

/// A custody refusal must reach the caller unchanged and write nothing. This also pins the ORDER
/// the module documents: the cheap path checks run first, so an absent secret is only reached once
/// both outputs are known to be resolvable and free.
#[test]
fn a_custody_refusal_reaches_the_caller_and_leaves_no_artifact_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();

    let refusal_chirho = emit_chirho(
        &fixture_chirho,
        &valid_inputs_chirho(),
        "emission-issuer-that-was-never-provisioned-chirho",
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
        CONFIG_OUTPUT_CHIRHO,
        PLAN_OUTPUT_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretRefusedChirho,
        "a custody refusal must arrive with its own identity, never re-wrapped as an output defect"
    );
    assert!(absent_chirho(&config_path_chirho(&fixture_chirho)));
    assert!(absent_chirho(&plan_path_chirho(&fixture_chirho)));
}

/// A document refusal likewise. Chosen deliberately: two registries pointed at one storage object
/// is the aliasing the CONFIG validator cannot see, so this is the one law whose absence would make
/// a wrong config emit cleanly and boot.
#[test]
fn a_document_refusal_reaches_the_caller_and_leaves_no_artifact_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let mut aliased_registries_chirho = valid_inputs_chirho();
    aliased_registries_chirho
        .source_registry_path_chirho
        .clone_from(&aliased_registries_chirho.kind_registry_path_chirho);
    assert_ne!(aliased_registries_chirho, valid_inputs_chirho());

    let refusal_chirho = emit_chirho(
        &fixture_chirho,
        &aliased_registries_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
        CONFIG_OUTPUT_CHIRHO,
        PLAN_OUTPUT_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsPathAliasRefusedChirho
    );
    assert!(absent_chirho(&config_path_chirho(&fixture_chirho)));
    assert!(absent_chirho(&plan_path_chirho(&fixture_chirho)));
}

/// The activation-less road emits a v1 config that the same loader accepts. Without this arm the
/// optional half of the request would be exercised nowhere, and "activation is optional" would be a
/// claim about a code path nothing runs.
#[test]
fn an_activation_less_request_emits_a_v1_config_the_loader_accepts_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.activation_principal_chirho = None;

    let report_chirho = emit_chirho(
        &fixture_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        None,
        CONFIG_OUTPUT_CHIRHO,
        PLAN_OUTPUT_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        report_chirho
            .custody_evidence_chirho
            .proven_offline_authority_count_chirho,
        1,
        "only the issuer was proven; an activation authority nobody supplied must not be counted"
    );

    load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &report_chirho.config_path_chirho,
        &report_chirho.plan_path_chirho,
        &report_chirho.plan_digest_chirho,
    )
    .expect("an activation-less pair must still satisfy the loader that consumes it");
    let config_text_chirho = fs::read_to_string(&report_chirho.config_path_chirho).unwrap();
    let host_block_chirho = parse_config_chirho(&config_text_chirho)
        .unwrap()
        .ledger_host_chirho
        .unwrap();
    assert_eq!(
        host_block_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO
    );
    assert!(host_block_chirho.activation_authority_chirho.is_none());
}

/// A root that is not an existing non-symlink directory refuses before anything else happens. The
/// symlinked-root case is the interesting half: it canonicalizes fine, so a check that only
/// canonicalized would accept a root an operator can redirect after review.
#[cfg(unix)]
#[test]
fn a_symlinked_selected_root_refuses_chirho() {
    prove_the_unmutated_request_emits_chirho();
    let fixture_chirho = fixture_chirho();
    let link_chirho = temp_root_chirho();
    std::os::unix::fs::symlink(&fixture_chirho.root_chirho, &link_chirho).unwrap();

    let refusal_chirho =
        author_and_emit_ledger_host_artifacts_chirho(LedgerHostEmissionRequestChirho {
            selected_root_chirho: &link_chirho,
            inputs_chirho: &valid_inputs_chirho(),
            destination_authority_enrollment_chirho:
                crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
            issuer_secret_name_chirho: ISSUER_SECRET_NAME_CHIRHO,
            activation_secret_name_chirho: Some(ACTIVATION_SECRET_NAME_CHIRHO),
            config_output_chirho: Path::new(CONFIG_OUTPUT_CHIRHO),
            plan_output_chirho: Path::new(PLAN_OUTPUT_CHIRHO),
            serve_port_chirho: SERVE_PORT_CHIRHO,
            mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
        })
        .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::SelectedRootUnavailableChirho
    );
    assert!(absent_chirho(&config_path_chirho(&fixture_chirho)));
    assert!(absent_chirho(&plan_path_chirho(&fixture_chirho)));
    let _removed_chirho = fs::remove_file(&link_chirho);
}
