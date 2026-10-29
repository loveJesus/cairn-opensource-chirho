// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Durable one-time fork-impossible intent-guard arms (8.2c, money/authority bar): an empty control
//! installs the full marker set once; a same-plan retry is byte-identical and rewrites nothing; a
//! partial-marker crash resumes only missing byte-identical markers; a prior valid different-plan
//! marker refuses before ANY output; malformed marker bytes fail closed (never absence); the
//! marker-first orchestrator has the durable set in place before the root action runs; and guard
//! roots plus member signers must bind the verified plan population.

use super::fixtures_chirho::{
    provision_signer_chirho, verified_valid_plan_chirho, MEMBER_SEEDS_CHIRHO,
    PLAN_AUTHORITY_SEED_CHIRHO,
};
use crate::codec_chirho::canonical_record_bytes_chirho;
use crate::digest_chirho::GeoOperatorGuardIdentityChirho;
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGuardHolderRoleChirho};
use crate::intent_chirho::{AuthoritativeGeoGenesisIntentV1Chirho, GeoMarkerHolderV1Chirho};
use crate::intent_guard_chirho::{
    build_signed_intent_marker_chirho, geo_genesis_guard_marker_path_chirho,
    reserve_genesis_intent_chirho, reserve_intent_then_run_root_chirho, GeoGuardRootsChirho,
    GeoMemberGuardRootChirho, GeoOperatorGuardRootChirho,
};
use crate::scalar_chirho::{GeoEd25519SignatureChirho, GeoGitCommitIdChirho, GeoUtcMinuteChirho};
use crate::trust_chirho::{GeoGenesisMessageClassChirho, GeoRoleSignerChirho, GeoSignerRoleChirho};
use crate::verify_chirho::VerifiedGeoGenesisPlanChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// --- shared helpers --------------------------------------------------------------------------

fn now_chirho() -> GeoUtcMinuteChirho {
    GeoUtcMinuteChirho::new_chirho(2000).unwrap()
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
        "cairn-geo-82c-{label_chirho}-{nanos_chirho}-{ordinal_chirho}"
    ))
}

fn plan_authority_signer_chirho() -> GeoRoleSignerChirho {
    provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    )
}

fn member_signers_chirho() -> Vec<GeoRoleSignerChirho> {
    MEMBER_SEEDS_CHIRHO
        .iter()
        .map(|seed_chirho| provision_signer_chirho(GeoSignerRoleChirho::MemberChirho, *seed_chirho))
        .collect()
}

/// A set of fresh temp-dir guard roots plus the derived marker paths, bound to the verified plan.
struct GuardFixtureChirho {
    roots_chirho: GeoGuardRootsChirho,
    operator_identity_chirho: GeoOperatorGuardIdentityChirho,
    operator_marker_path_chirho: PathBuf,
    member_marker_paths_chirho: Vec<PathBuf>,
    root_dirs_chirho: Vec<PathBuf>,
}

impl GuardFixtureChirho {
    fn cleanup_chirho(&self) {
        for dir_chirho in &self.root_dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

fn guard_fixture_chirho(verified_plan_chirho: &VerifiedGeoGenesisPlanChirho) -> GuardFixtureChirho {
    let operator_dir_chirho = unique_temp_dir_chirho("op");
    let operator_identity_chirho = GeoOperatorGuardIdentityChirho::new_chirho([200; 32]).unwrap();
    let operator_root_chirho = GeoOperatorGuardRootChirho::new_chirho(
        operator_dir_chirho.clone(),
        operator_identity_chirho,
    );
    let operator_marker_path_chirho = geo_genesis_guard_marker_path_chirho(&operator_dir_chirho);

    let mut member_roots_chirho = Vec::new();
    let mut member_marker_paths_chirho = Vec::new();
    let mut root_dirs_chirho = vec![operator_dir_chirho];
    for member_chirho in &verified_plan_chirho
        .plan_chirho()
        .topology_chirho
        .members_chirho
    {
        let dir_chirho = unique_temp_dir_chirho("mem");
        member_marker_paths_chirho.push(geo_genesis_guard_marker_path_chirho(&dir_chirho));
        member_roots_chirho.push(GeoMemberGuardRootChirho::new_chirho(
            member_chirho.role_chirho,
            member_chirho.raft_id_chirho,
            member_chirho.node_key_chirho,
            dir_chirho.clone(),
        ));
        root_dirs_chirho.push(dir_chirho);
    }
    let roots_chirho = GeoGuardRootsChirho::bind_to_plan_chirho(
        verified_plan_chirho,
        operator_root_chirho,
        member_roots_chirho,
    )
    .unwrap();
    GuardFixtureChirho {
        roots_chirho,
        operator_identity_chirho,
        operator_marker_path_chirho,
        member_marker_paths_chirho,
        root_dirs_chirho,
    }
}

/// The exact canonical marker bytes for a plan, computed independently of the guard write path.
fn marker_bytes_chirho(
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    signer_chirho: &GeoRoleSignerChirho,
) -> Vec<u8> {
    build_signed_intent_marker_chirho(verified_plan_chirho, signer_chirho)
        .unwrap()
        .canonical_bytes_chirho()
        .to_vec()
}

/// Honestly re-sign a mutated intent marker with the plan authority, returning canonical bytes. Used
/// to plant a VALID but DIFFERENT-plan marker at a guard root.
fn resign_marker_bytes_chirho(
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

fn plant_marker_file_chirho(path_chirho: &std::path::Path, bytes_chirho: &[u8]) {
    std::fs::create_dir_all(path_chirho.parent().unwrap()).unwrap();
    std::fs::write(path_chirho, bytes_chirho).unwrap();
}

// =============================================================================================
// Arm 1: empty control — one successful reservation installs the full marker set.
// =============================================================================================

#[test]
fn empty_roots_reserve_once_installs_the_full_marker_set_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let signer_chirho = plan_authority_signer_chirho();
    let members_chirho = member_signers_chirho();
    let fixture_chirho = guard_fixture_chirho(&verified_plan_chirho);

    let reservation_chirho = reserve_genesis_intent_chirho(
        &verified_plan_chirho,
        &fixture_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
    )
    .unwrap();

    // The operator guard marker and every member marker are durable and byte-identical to each other.
    let expected_chirho = reservation_chirho.marker_canonical_bytes_chirho();
    assert_eq!(
        std::fs::read(&fixture_chirho.operator_marker_path_chirho).unwrap(),
        expected_chirho
    );
    for path_chirho in &fixture_chirho.member_marker_paths_chirho {
        assert_eq!(std::fs::read(path_chirho).unwrap(), expected_chirho);
    }

    // The marker set binds the plan population: one operator-guard holder with the custody identity,
    // three member holders.
    let set_chirho = reservation_chirho.marker_set_chirho();
    assert_eq!(set_chirho.member_markers_chirho.len(), 3);
    match set_chirho.operator_guard_chirho.holder_chirho {
        GeoMarkerHolderV1Chirho::OperatorGuardChirho {
            guard_identity_chirho,
        } => assert_eq!(
            guard_identity_chirho,
            fixture_chirho.operator_identity_chirho
        ),
        _ => panic!("operator-guard slot must hold an operator-guard receipt"),
    }
    // The set ref computes deterministically.
    assert!(reservation_chirho.intent_marker_set_ref_chirho().is_ok());

    fixture_chirho.cleanup_chirho();
}

// =============================================================================================
// Arm 1b / crash window 4: a same-plan retry is byte-identical and rewrites nothing.
// =============================================================================================

#[test]
fn same_plan_retry_is_byte_identical_and_rewrites_nothing_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let signer_chirho = plan_authority_signer_chirho();
    let members_chirho = member_signers_chirho();
    let fixture_chirho = guard_fixture_chirho(&verified_plan_chirho);

    let first_chirho = reserve_genesis_intent_chirho(
        &verified_plan_chirho,
        &fixture_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
    )
    .unwrap();
    let first_bytes_chirho = std::fs::read(&fixture_chirho.operator_marker_path_chirho).unwrap();

    // A second reservation with the same plan/roots/signers/time is the recovery door: idempotent,
    // byte-identical, no rewrite.
    let second_chirho = reserve_genesis_intent_chirho(
        &verified_plan_chirho,
        &fixture_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
    )
    .unwrap();
    assert_eq!(first_chirho, second_chirho);
    assert_eq!(
        std::fs::read(&fixture_chirho.operator_marker_path_chirho).unwrap(),
        first_bytes_chirho
    );

    fixture_chirho.cleanup_chirho();
}

// =============================================================================================
// Crash windows 2/3: a partial marker crash resumes only missing byte-identical markers.
// =============================================================================================

#[test]
fn partial_marker_crash_resumes_only_missing_byte_identical_markers_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let signer_chirho = plan_authority_signer_chirho();
    let members_chirho = member_signers_chirho();
    let fixture_chirho = guard_fixture_chirho(&verified_plan_chirho);
    let canonical_chirho = marker_bytes_chirho(&verified_plan_chirho, &signer_chirho);

    // Simulate a crash AFTER the operator marker and the first member marker were durable, before the
    // rest. Plant those two byte-identical markers directly.
    plant_marker_file_chirho(
        &fixture_chirho.operator_marker_path_chirho,
        &canonical_chirho,
    );
    plant_marker_file_chirho(
        &fixture_chirho.member_marker_paths_chirho[0],
        &canonical_chirho,
    );

    let reservation_chirho = reserve_genesis_intent_chirho(
        &verified_plan_chirho,
        &fixture_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
    )
    .unwrap();

    // Every marker path now holds the exact same byte-identical marker; nothing was deleted.
    for path_chirho in [&fixture_chirho.operator_marker_path_chirho]
        .into_iter()
        .chain(fixture_chirho.member_marker_paths_chirho.iter())
    {
        assert_eq!(std::fs::read(path_chirho).unwrap(), canonical_chirho);
    }
    assert_eq!(
        reservation_chirho.marker_canonical_bytes_chirho(),
        canonical_chirho.as_slice()
    );

    fixture_chirho.cleanup_chirho();
}

// =============================================================================================
// Arm 2: a prior VALID DIFFERENT-plan marker refuses before ANY output, named by role.
// =============================================================================================

#[test]
fn prior_valid_different_plan_marker_at_operator_refuses_before_any_output_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let signer_chirho = plan_authority_signer_chirho();
    let members_chirho = member_signers_chirho();
    let fixture_chirho = guard_fixture_chirho(&verified_plan_chirho);

    // A valid, honestly re-signed marker for a DIFFERENT source commit — a different genesis.
    let mut foreign_intent_chirho =
        build_signed_intent_marker_chirho(&verified_plan_chirho, &signer_chirho)
            .unwrap()
            .intent_chirho()
            .clone();
    foreign_intent_chirho.source_commit_chirho = GeoGitCommitIdChirho::new_chirho([7; 20]).unwrap();
    let foreign_bytes_chirho = resign_marker_bytes_chirho(foreign_intent_chirho, &signer_chirho);
    plant_marker_file_chirho(
        &fixture_chirho.operator_marker_path_chirho,
        &foreign_bytes_chirho,
    );

    let refusal_chirho = reserve_genesis_intent_chirho(
        &verified_plan_chirho,
        &fixture_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        GeoGenesisRefusalChirho::GenesisAlreadyReservedChirho {
            holder_role_chirho: GeoGuardHolderRoleChirho::OperatorGuardChirho,
        }
    );

    // Refuse BEFORE any output: the foreign marker is untouched and no member marker was written.
    assert_eq!(
        std::fs::read(&fixture_chirho.operator_marker_path_chirho).unwrap(),
        foreign_bytes_chirho
    );
    for path_chirho in &fixture_chirho.member_marker_paths_chirho {
        assert!(!path_chirho.exists());
    }

    fixture_chirho.cleanup_chirho();
}

#[test]
fn prior_valid_different_plan_marker_at_member_refuses_before_operator_write_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let signer_chirho = plan_authority_signer_chirho();
    let members_chirho = member_signers_chirho();
    let fixture_chirho = guard_fixture_chirho(&verified_plan_chirho);

    let mut foreign_intent_chirho =
        build_signed_intent_marker_chirho(&verified_plan_chirho, &signer_chirho)
            .unwrap()
            .intent_chirho()
            .clone();
    foreign_intent_chirho.source_commit_chirho = GeoGitCommitIdChirho::new_chirho([8; 20]).unwrap();
    let foreign_bytes_chirho = resign_marker_bytes_chirho(foreign_intent_chirho, &signer_chirho);
    // Plant the foreign marker at the SECOND member root; the operator root stays empty.
    plant_marker_file_chirho(
        &fixture_chirho.member_marker_paths_chirho[1],
        &foreign_bytes_chirho,
    );

    let refusal_chirho = reserve_genesis_intent_chirho(
        &verified_plan_chirho,
        &fixture_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        GeoGenesisRefusalChirho::GenesisAlreadyReservedChirho {
            holder_role_chirho: GeoGuardHolderRoleChirho::MemberChirho,
        }
    );

    // The pre-write scan refuses before the operator marker is written.
    assert!(!fixture_chirho.operator_marker_path_chirho.exists());
    assert!(!fixture_chirho.member_marker_paths_chirho[0].exists());

    fixture_chirho.cleanup_chirho();
}

// =============================================================================================
// Arm 3: malformed / unverifiable marker bytes fail closed, NEVER counted as absence.
// =============================================================================================

#[test]
fn malformed_marker_fails_closed_never_absence_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let signer_chirho = plan_authority_signer_chirho();
    let members_chirho = member_signers_chirho();

    // (a) Garbage bytes at the operator marker path.
    let fixture_a_chirho = guard_fixture_chirho(&verified_plan_chirho);
    plant_marker_file_chirho(
        &fixture_a_chirho.operator_marker_path_chirho,
        b"this is not a geo-genesis marker",
    );
    let refusal_a_chirho = reserve_genesis_intent_chirho(
        &verified_plan_chirho,
        &fixture_a_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
    )
    .unwrap_err();
    assert_eq!(
        refusal_a_chirho,
        GeoGenesisRefusalChirho::GuardMarkerUnverifiableChirho {
            holder_role_chirho: GeoGuardHolderRoleChirho::OperatorGuardChirho,
        }
    );
    for path_chirho in &fixture_a_chirho.member_marker_paths_chirho {
        assert!(!path_chirho.exists());
    }
    fixture_a_chirho.cleanup_chirho();

    // (b) A well-formed marker whose signature does not verify (bad-signature != absence, != reserved).
    let fixture_b_chirho = guard_fixture_chirho(&verified_plan_chirho);
    let mut tampered_intent_chirho =
        build_signed_intent_marker_chirho(&verified_plan_chirho, &signer_chirho)
            .unwrap()
            .intent_chirho()
            .clone();
    let mut sig_bytes_chirho = *tampered_intent_chirho.signature_chirho.as_bytes_chirho();
    sig_bytes_chirho[7] ^= 0x01;
    tampered_intent_chirho.signature_chirho =
        GeoEd25519SignatureChirho::new_chirho(sig_bytes_chirho).unwrap();
    let tampered_bytes_chirho = canonical_record_bytes_chirho(&tampered_intent_chirho).unwrap();
    plant_marker_file_chirho(
        &fixture_b_chirho.operator_marker_path_chirho,
        &tampered_bytes_chirho,
    );
    let refusal_b_chirho = reserve_genesis_intent_chirho(
        &verified_plan_chirho,
        &fixture_b_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
    )
    .unwrap_err();
    assert_eq!(
        refusal_b_chirho,
        GeoGenesisRefusalChirho::GuardMarkerUnverifiableChirho {
            holder_role_chirho: GeoGuardHolderRoleChirho::OperatorGuardChirho,
        }
    );
    fixture_b_chirho.cleanup_chirho();
}

// =============================================================================================
// Arm 4: marker-first — the durable marker set is in place before the root action runs.
// =============================================================================================

#[test]
fn marker_set_is_durable_before_root_action_runs_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let signer_chirho = plan_authority_signer_chirho();
    let members_chirho = member_signers_chirho();
    let fixture_chirho = guard_fixture_chirho(&verified_plan_chirho);
    let expected_chirho = marker_bytes_chirho(&verified_plan_chirho, &signer_chirho);

    // The root action observes the operator guard marker already durable and byte-identical. If the
    // orchestrator ran the root action BEFORE reserving the intent (root-first), this closure would
    // see no marker and the assertion here would make the test red — that is the marker-first proof.
    let operator_path_chirho = fixture_chirho.operator_marker_path_chirho.clone();
    let expected_for_action_chirho = expected_chirho.clone();
    let (reservation_chirho, saw_marker_chirho) = reserve_intent_then_run_root_chirho(
        &verified_plan_chirho,
        &fixture_chirho.roots_chirho,
        &signer_chirho,
        &members_chirho,
        now_chirho(),
        move || {
            let bytes_chirho = std::fs::read(&operator_path_chirho)
                .expect("marker must be durable before the root action runs");
            assert_eq!(bytes_chirho, expected_for_action_chirho);
            Ok(true)
        },
    )
    .unwrap();

    assert!(saw_marker_chirho);
    assert_eq!(
        reservation_chirho.marker_canonical_bytes_chirho(),
        expected_chirho.as_slice()
    );

    fixture_chirho.cleanup_chirho();
}

// =============================================================================================
// Arm 5: guard roots and member signers must bind the verified plan population.
// =============================================================================================

#[test]
fn guard_roots_must_bind_the_plan_population_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let operator_identity_chirho = GeoOperatorGuardIdentityChirho::new_chirho([200; 32]).unwrap();
    let operator_root_chirho = GeoOperatorGuardRootChirho::new_chirho(
        unique_temp_dir_chirho("op"),
        operator_identity_chirho,
    );

    // Only two of the three plan members are supplied → the root set does not cover the plan.
    let members_chirho = &verified_plan_chirho
        .plan_chirho()
        .topology_chirho
        .members_chirho;
    let short_roots_chirho: Vec<GeoMemberGuardRootChirho> = members_chirho[..2]
        .iter()
        .map(|member_chirho| {
            GeoMemberGuardRootChirho::new_chirho(
                member_chirho.role_chirho,
                member_chirho.raft_id_chirho,
                member_chirho.node_key_chirho,
                unique_temp_dir_chirho("mem"),
            )
        })
        .collect();
    assert_eq!(
        GeoGuardRootsChirho::bind_to_plan_chirho(
            &verified_plan_chirho,
            operator_root_chirho.clone(),
            short_roots_chirho,
        )
        .err(),
        Some(GeoGenesisRefusalChirho::GuardRootBindingRefusedChirho)
    );

    // A foreign member coordinate (wrong node key on the last member) also refuses.
    let mut foreign_roots_chirho: Vec<GeoMemberGuardRootChirho> = members_chirho
        .iter()
        .map(|member_chirho| {
            GeoMemberGuardRootChirho::new_chirho(
                member_chirho.role_chirho,
                member_chirho.raft_id_chirho,
                member_chirho.node_key_chirho,
                unique_temp_dir_chirho("mem"),
            )
        })
        .collect();
    foreign_roots_chirho[2] = GeoMemberGuardRootChirho::new_chirho(
        members_chirho[2].role_chirho,
        members_chirho[2].raft_id_chirho,
        members_chirho[0].node_key_chirho,
        unique_temp_dir_chirho("mem"),
    );
    assert_eq!(
        GeoGuardRootsChirho::bind_to_plan_chirho(
            &verified_plan_chirho,
            operator_root_chirho,
            foreign_roots_chirho,
        )
        .err(),
        Some(GeoGenesisRefusalChirho::GuardRootBindingRefusedChirho)
    );
}

#[test]
fn member_signers_must_cover_the_plan_population_chirho() {
    let (verified_plan_chirho, _ledger_plan_chirho) = verified_valid_plan_chirho();
    let signer_chirho = plan_authority_signer_chirho();
    let fixture_chirho = guard_fixture_chirho(&verified_plan_chirho);

    // Only two of the three member signers are supplied → a plan member has no matching signer.
    let short_members_chirho: Vec<GeoRoleSignerChirho> = MEMBER_SEEDS_CHIRHO[..2]
        .iter()
        .map(|seed_chirho| provision_signer_chirho(GeoSignerRoleChirho::MemberChirho, *seed_chirho))
        .collect();
    assert_eq!(
        reserve_genesis_intent_chirho(
            &verified_plan_chirho,
            &fixture_chirho.roots_chirho,
            &signer_chirho,
            &short_members_chirho,
            now_chirho(),
        )
        .err(),
        Some(GeoGenesisRefusalChirho::GuardMemberSignerRefusedChirho)
    );

    fixture_chirho.cleanup_chirho();
}
