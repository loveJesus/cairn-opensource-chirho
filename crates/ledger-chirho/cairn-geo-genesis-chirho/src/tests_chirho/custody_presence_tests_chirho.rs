// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pre-genesis custody-checkpoint arms (8.3, ruling 3): the exact operator-supplied inputs bind to the
//! verified plan and REFUSE by a DISTINCT reason on any absent/unverifiable input — the dedicated key
//! pins, per-member node/WireGuard public-key pins, the roster projection, the operator guard-root
//! location, and the two custody-evidence attestations. The checkpoint generates NOTHING and creates
//! no file: the guard root stays empty across the call.

use super::fixtures_chirho::{
    author_custody_attestation_chirho, custody_domain_chirho, derived_pk_chirho,
    member_wireguard_key_chirho, plan_roster_projection_chirho, provision_signer_chirho,
    split_pins_chirho, verified_valid_plan_chirho, ACCEPTANCE_AUTHORITY_SEED_CHIRHO,
    CUSTODY_AUTHORITY_SEED_CHIRHO, MEMBER_SEEDS_CHIRHO, PLAN_AUTHORITY_SEED_CHIRHO,
};
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoMemberCoordinateChirho};
use crate::{
    verify_custody_presence_chirho, GeoGenesisTrustPinsChirho, GeoMemberCustodyPinV1Chirho,
    GeoOperatorCustodyConfigV1Chirho, GeoOperatorGuardIdentityChirho, GeoOperatorGuardRootChirho,
    GeoRaftIdChirho, GeoSignerRoleChirho,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ordinal_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-geo-83-custody-{nanos_chirho}-{ordinal_chirho}"
    ))
}

/// A private, same-owner guard-root directory (0o700 on unix) plus a fixture identity.
fn temp_guard_root_chirho() -> (GeoOperatorGuardRootChirho, PathBuf) {
    let dir_chirho = unique_temp_dir_chirho();
    std::fs::create_dir_all(&dir_chirho).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir_chirho, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let identity_chirho = GeoOperatorGuardIdentityChirho::new_chirho([77; 32]).unwrap();
    (
        GeoOperatorGuardRootChirho::new_chirho(dir_chirho.clone(), identity_chirho),
        dir_chirho,
    )
}

fn member_pins_chirho() -> Vec<GeoMemberCustodyPinV1Chirho> {
    (0..3usize)
        .map(|index_chirho| {
            let seed_chirho = MEMBER_SEEDS_CHIRHO[index_chirho];
            GeoMemberCustodyPinV1Chirho {
                raft_id_chirho: GeoRaftIdChirho::new_chirho(index_chirho as u64 + 1).unwrap(),
                node_key_chirho: derived_pk_chirho(seed_chirho),
                wireguard_key_chirho: member_wireguard_key_chirho(seed_chirho),
            }
        })
        .collect()
}

/// A fully valid operator custody config bound to the fixture plan, over the supplied guard root.
fn valid_config_chirho(
    guard_root_chirho: GeoOperatorGuardRootChirho,
) -> GeoOperatorCustodyConfigV1Chirho {
    let custody_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::CustodyAuthorityChirho,
        CUSTODY_AUTHORITY_SEED_CHIRHO,
    );
    let custody_pin_chirho = custody_signer_chirho.public_key_chirho();
    let plan_attestation_chirho = author_custody_attestation_chirho(
        &custody_signer_chirho,
        custody_domain_chirho(1),
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        custody_pin_chirho,
    );
    let acceptance_attestation_chirho = author_custody_attestation_chirho(
        &custody_signer_chirho,
        custody_domain_chirho(2),
        derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        custody_pin_chirho,
    );
    GeoOperatorCustodyConfigV1Chirho {
        trust_pins_chirho: split_pins_chirho(),
        custody_authority_pin_chirho: custody_pin_chirho,
        roster_projection_chirho: plan_roster_projection_chirho(),
        member_pins_chirho: member_pins_chirho(),
        operator_guard_root_chirho: guard_root_chirho,
        plan_custody_attestation_chirho: plan_attestation_chirho,
        acceptance_custody_attestation_chirho: acceptance_attestation_chirho,
    }
}

#[test]
fn valid_custody_presence_binds_the_plan_and_generates_nothing_chirho() {
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();
    let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
    let config_chirho = valid_config_chirho(guard_root_chirho);

    let before_chirho = std::fs::read_dir(&guard_dir_chirho).unwrap().count();
    let presence_chirho =
        verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap();
    let after_chirho = std::fs::read_dir(&guard_dir_chirho).unwrap().count();

    assert_eq!(presence_chirho.member_count_chirho(), 3);
    assert_eq!(
        presence_chirho.roster_projection_chirho(),
        plan_roster_projection_chirho()
    );
    assert_eq!(
        presence_chirho.plan_digest_chirho(),
        verified_plan_chirho.plan_digest_chirho()
    );
    assert_ne!(
        presence_chirho
            .non_equivalence_chirho()
            .plan_domain_chirho(),
        presence_chirho
            .non_equivalence_chirho()
            .acceptance_domain_chirho()
    );
    // Generates nothing: the guard root is untouched (no marker, no key, no subdir).
    assert_eq!(before_chirho, 0);
    assert_eq!(after_chirho, 0);

    std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
}

#[test]
fn absent_or_unverifiable_input_refuses_by_distinct_reason_chirho() {
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();

    // (1) Dedicated key pins: a plan-authority pin that is not the key the plan was authored under.
    {
        let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
        let mut config_chirho = valid_config_chirho(guard_root_chirho);
        config_chirho.trust_pins_chirho = GeoGenesisTrustPinsChirho::new_split_chirho(
            derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO + 3),
            derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        )
        .unwrap();
        assert_eq!(
            verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap_err(),
            GeoGenesisRefusalChirho::CustodyPresencePlanKeyPinMismatchChirho
        );
        std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
    }

    // (2) Roster projection: a held projection that does not equal the plan's.
    {
        let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
        let mut config_chirho = valid_config_chirho(guard_root_chirho);
        config_chirho.roster_projection_chirho =
            crate::GeoRosterProjectionDigestChirho::new_chirho([99; 32]).unwrap();
        assert_eq!(
            verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap_err(),
            GeoGenesisRefusalChirho::CustodyPresenceRosterProjectionMismatchChirho
        );
        std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
    }

    // (3) Member node-key pin: a wrong node key for one member.
    {
        let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
        let mut config_chirho = valid_config_chirho(guard_root_chirho);
        config_chirho.member_pins_chirho[1].node_key_chirho = derived_pk_chirho(200);
        assert_eq!(
            verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap_err(),
            GeoGenesisRefusalChirho::CustodyPresenceMemberPinRefusedChirho {
                coordinate_chirho: GeoMemberCoordinateChirho::NodeKeyChirho
            }
        );
        std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
    }

    // (3b) Member WireGuard-key pin: a wrong WireGuard key for one member.
    {
        let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
        let mut config_chirho = valid_config_chirho(guard_root_chirho);
        config_chirho.member_pins_chirho[0].wireguard_key_chirho = member_wireguard_key_chirho(250);
        assert_eq!(
            verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap_err(),
            GeoGenesisRefusalChirho::CustodyPresenceMemberPinRefusedChirho {
                coordinate_chirho: GeoMemberCoordinateChirho::WireGuardKeyChirho
            }
        );
        std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
    }

    // (3c) Member pin coverage: one pin dropped (an absent per-member key pin).
    {
        let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
        let mut config_chirho = valid_config_chirho(guard_root_chirho);
        config_chirho.member_pins_chirho.pop();
        assert_eq!(
            verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap_err(),
            GeoGenesisRefusalChirho::CustodyPresenceMemberPinRefusedChirho {
                coordinate_chirho: GeoMemberCoordinateChirho::RaftIdChirho
            }
        );
        std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
    }

    // (4) Operator guard root: an absent location (the directory does not exist).
    {
        let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
        std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
        let config_chirho = valid_config_chirho(guard_root_chirho);
        assert_eq!(
            verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap_err(),
            GeoGenesisRefusalChirho::CustodyPresenceGuardRootUnverifiableChirho
        );
    }

    // (5) Custody evidence: two attestations under the SAME domain (non-equivalence fails).
    {
        let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
        let mut config_chirho = valid_config_chirho(guard_root_chirho);
        let custody_signer_chirho = provision_signer_chirho(
            GeoSignerRoleChirho::CustodyAuthorityChirho,
            CUSTODY_AUTHORITY_SEED_CHIRHO,
        );
        config_chirho.acceptance_custody_attestation_chirho = author_custody_attestation_chirho(
            &custody_signer_chirho,
            custody_domain_chirho(1),
            derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
            custody_signer_chirho.public_key_chirho(),
        );
        assert_eq!(
            verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap_err(),
            GeoGenesisRefusalChirho::CustodySameDomainChirho
        );
        std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn guard_root_custody_refuses_broad_mode_and_symlink_chirho() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();

    // Broad mode: a world/group-accessible guard root refuses.
    let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
    std::fs::set_permissions(&guard_dir_chirho, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config_chirho = valid_config_chirho(guard_root_chirho);
    assert_eq!(
        verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::CustodyPresenceGuardRootUnverifiableChirho
    );
    std::fs::set_permissions(&guard_dir_chirho, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(&guard_dir_chirho).unwrap();

    // Symlink: a guard root that is a symlink (even to a private dir) refuses.
    let (_unused_root_chirho, real_dir_chirho) = temp_guard_root_chirho();
    let link_path_chirho = unique_temp_dir_chirho();
    symlink(&real_dir_chirho, &link_path_chirho).unwrap();
    let link_root_chirho = GeoOperatorGuardRootChirho::new_chirho(
        link_path_chirho.clone(),
        GeoOperatorGuardIdentityChirho::new_chirho([77; 32]).unwrap(),
    );
    let symlink_config_chirho = valid_config_chirho(link_root_chirho);
    assert_eq!(
        verify_custody_presence_chirho(&verified_plan_chirho, &symlink_config_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::CustodyPresenceGuardRootUnverifiableChirho
    );
    std::fs::remove_file(&link_path_chirho).unwrap();
    std::fs::remove_dir_all(&real_dir_chirho).unwrap();
}
