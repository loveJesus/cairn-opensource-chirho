// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The lost-race backstop arm for `write_marker_no_replace_chirho` (8.2c review hardening). Every
//! single-threaded public-API arm either refuses at the pre-write scan or creates fresh files, so
//! none reaches the ONE genesis-create door's re-read: create → `AlreadyExists` (a concurrent winner
//! got there first) → re-read → byte-mismatch → refuse. This module is a CHILD of
//! `intent_guard_chirho` (not the sibling `tests_chirho` tree) so it can call the private
//! `write_marker_no_replace_chirho` directly and inject that exact race deterministically — no
//! threads, no flakiness — by pre-planting the winner's bytes at the marker path before the call.
//! Removing the re-read backstop turns both refusal arms into `Ok(())` (the lost race silently
//! accepted as a successful same-plan write), so those two arms are the backstop's mutation pins.

use super::{
    build_signed_intent_marker_chirho, geo_genesis_guard_marker_path_chirho,
    write_marker_no_replace_chirho,
};
use crate::codec_chirho::canonical_record_bytes_chirho;
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGuardHolderRoleChirho};
use crate::intent_chirho::AuthoritativeGeoGenesisIntentV1Chirho;
use crate::scalar_chirho::GeoGitCommitIdChirho;
use crate::tests_chirho::fixtures_chirho::{
    provision_signer_chirho, verified_valid_plan_chirho, PLAN_AUTHORITY_SEED_CHIRHO,
};
use crate::trust_chirho::{GeoGenesisMessageClassChirho, GeoRoleSignerChirho, GeoSignerRoleChirho};
use crate::verify_chirho::VerifiedGeoGenesisPlanChirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn plan_authority_signer_chirho() -> GeoRoleSignerChirho {
    provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    )
}

fn unique_temp_dir_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ordinal_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-geo-82h-{label_chirho}-{nanos_chirho}-{ordinal_chirho}"
    ))
}

/// Plant the concurrent winner's bytes at the marker path with a plain regular-file write, so the
/// guard's own no-replace create meets an existing object exactly as it would after losing a race.
fn plant_bytes_chirho(path_chirho: &Path, bytes_chirho: &[u8]) {
    std::fs::create_dir_all(path_chirho.parent().unwrap()).unwrap();
    std::fs::write(path_chirho, bytes_chirho).unwrap();
}

/// Plan A's canonical marker bytes plus the plan-authority public key those bytes are signed under —
/// the two inputs `write_marker_no_replace_chirho` takes for a plan-A write.
fn plan_a_marker_and_key_chirho(
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
) -> (
    Vec<u8>,
    AuthoritativeGeoGenesisIntentV1Chirho,
    GeoRoleSignerChirho,
) {
    let signer_chirho = plan_authority_signer_chirho();
    let marker_chirho =
        build_signed_intent_marker_chirho(verified_plan_chirho, &signer_chirho).unwrap();
    (
        marker_chirho.canonical_bytes_chirho().to_vec(),
        marker_chirho.intent_chirho().clone(),
        signer_chirho,
    )
}

/// Honestly re-sign a mutated intent with the plan authority, returning canonical bytes: a VALID but
/// DIFFERENT-plan marker (the exact shape a concurrent winner of a different genesis would leave).
fn resign_intent_bytes_chirho(
    mut intent_chirho: AuthoritativeGeoGenesisIntentV1Chirho,
    signer_chirho: &GeoRoleSignerChirho,
) -> Vec<u8> {
    let unsigned_bytes_chirho =
        canonical_record_bytes_chirho(&intent_chirho.to_unsigned_chirho()).unwrap();
    let signature_chirho = signer_chirho
        .sign_class_chirho(
            GeoGenesisMessageClassChirho::IntentMarkerChirho,
            &unsigned_bytes_chirho,
        )
        .unwrap();
    intent_chirho.signature_chirho = signature_chirho;
    canonical_record_bytes_chirho(&intent_chirho).unwrap()
}

// =============================================================================================
// Backstop pin 1 (money/authority): a lost race to a VALID DIFFERENT-plan marker refuses — never
// accepted as a same-plan write. This is the branch the 8.2c review found unpinned.
// =============================================================================================

#[test]
fn write_marker_backstop_refuses_a_lost_race_to_a_different_plan_marker_chirho() {
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();
    let (plan_a_bytes_chirho, plan_a_intent_chirho, signer_chirho) =
        plan_a_marker_and_key_chirho(&verified_plan_chirho);
    let plan_authority_key_chirho = signer_chirho.public_key_chirho();

    // A concurrent winner of a DIFFERENT genesis (different source commit) got the create first and
    // left its own validly-signed marker at the path — the state a lost race produces AFTER this
    // reserver's pre-write scan already saw the path empty.
    let mut foreign_intent_chirho = plan_a_intent_chirho;
    foreign_intent_chirho.source_commit_chirho = GeoGitCommitIdChirho::new_chirho([9; 20]).unwrap();
    let foreign_bytes_chirho = resign_intent_bytes_chirho(foreign_intent_chirho, &signer_chirho);
    assert_ne!(foreign_bytes_chirho, plan_a_bytes_chirho);

    let dir_chirho = unique_temp_dir_chirho("lost-race-diff");
    let marker_path_chirho = geo_genesis_guard_marker_path_chirho(&dir_chirho);
    plant_bytes_chirho(&marker_path_chirho, &foreign_bytes_chirho);

    // create → AlreadyExists (winner got there first) → re-read backstop → different valid plan →
    // refuse. Neutering the re-read makes this `Ok(())`: the lost race silently accepted.
    let result_chirho = write_marker_no_replace_chirho(
        &marker_path_chirho,
        &plan_a_bytes_chirho,
        &plan_authority_key_chirho,
        GeoGuardHolderRoleChirho::OperatorGuardChirho,
    );
    assert_eq!(
        result_chirho,
        Err(GeoGenesisRefusalChirho::GenesisAlreadyReservedChirho {
            holder_role_chirho: GeoGuardHolderRoleChirho::OperatorGuardChirho,
        }),
        "the create door lost the race to a valid different-plan marker and MUST refuse; an Ok here \
         means the re-read backstop is gone and a lost race is being accepted as a same-plan write"
    );
    // The winner's bytes are untouched — no rewrite, no delete.
    assert_eq!(
        std::fs::read(&marker_path_chirho).unwrap(),
        foreign_bytes_chirho
    );

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

// =============================================================================================
// Backstop pin 2 (fail-closed): a lost race to MALFORMED bytes fails closed as unverifiable — never
// absence, never success.
// =============================================================================================

#[test]
fn write_marker_backstop_refuses_a_lost_race_to_malformed_bytes_chirho() {
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();
    let (plan_a_bytes_chirho, _plan_a_intent_chirho, signer_chirho) =
        plan_a_marker_and_key_chirho(&verified_plan_chirho);
    let plan_authority_key_chirho = signer_chirho.public_key_chirho();

    let dir_chirho = unique_temp_dir_chirho("lost-race-malformed");
    let marker_path_chirho = geo_genesis_guard_marker_path_chirho(&dir_chirho);
    plant_bytes_chirho(&marker_path_chirho, b"this is not a geo-genesis marker");

    let result_chirho = write_marker_no_replace_chirho(
        &marker_path_chirho,
        &plan_a_bytes_chirho,
        &plan_authority_key_chirho,
        GeoGuardHolderRoleChirho::MemberChirho,
    );
    assert_eq!(
        result_chirho,
        Err(GeoGenesisRefusalChirho::GuardMarkerUnverifiableChirho {
            holder_role_chirho: GeoGuardHolderRoleChirho::MemberChirho,
        }),
        "the create door lost the race to malformed bytes and MUST fail closed; an Ok here means the \
         re-read backstop is gone and a torn/foreign object is being accepted as a same-plan write"
    );

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

// =============================================================================================
// Positive control: the create door itself works — a fresh path is created, and a byte-identical
// existing object (won an OWN-plan race, or a same-plan retry residue) is accepted with no rewrite.
// This proves the two refusal arms above are non-vacuous: the door really does return Ok when it
// should, so their Err results are the backstop firing, not a broken harness.
// =============================================================================================

#[test]
fn write_marker_creates_fresh_then_accepts_byte_identical_with_no_rewrite_chirho() {
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();
    let (plan_a_bytes_chirho, _plan_a_intent_chirho, signer_chirho) =
        plan_a_marker_and_key_chirho(&verified_plan_chirho);
    let plan_authority_key_chirho = signer_chirho.public_key_chirho();

    let dir_chirho = unique_temp_dir_chirho("fresh-and-identical");
    let marker_path_chirho = geo_genesis_guard_marker_path_chirho(&dir_chirho);

    // (a) Absent → create → re-read Identical → Ok, and the bytes are durable.
    assert_eq!(
        write_marker_no_replace_chirho(
            &marker_path_chirho,
            &plan_a_bytes_chirho,
            &plan_authority_key_chirho,
            GeoGuardHolderRoleChirho::OperatorGuardChirho,
        ),
        Ok(())
    );
    assert_eq!(
        std::fs::read(&marker_path_chirho).unwrap(),
        plan_a_bytes_chirho
    );

    // (b) Same bytes already present → create → AlreadyExists → re-read Identical → Ok, no rewrite.
    assert_eq!(
        write_marker_no_replace_chirho(
            &marker_path_chirho,
            &plan_a_bytes_chirho,
            &plan_authority_key_chirho,
            GeoGuardHolderRoleChirho::OperatorGuardChirho,
        ),
        Ok(())
    );
    assert_eq!(
        std::fs::read(&marker_path_chirho).unwrap(),
        plan_a_bytes_chirho
    );

    let _ = std::fs::remove_dir_all(&dir_chirho);
}
