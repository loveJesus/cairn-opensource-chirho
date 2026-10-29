// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The pre-genesis custody checkpoint (design ruling 3): it BINDS and REFUSES-on-absent/unverifiable
//! the exact operator-supplied inputs genesis must never self-provision — the two dedicated key pins,
//! every per-member node + WireGuard public-key pin (anchored to the signed-roster projection), the
//! operator guard-root location (custody config, never plan-selected), and the two custody-evidence
//! non-equivalence attestations — and generates NONE of them.

use crate::custody_chirho::{
    verify_custody_non_equivalence_chirho, GeoCustodyAttestationV1Chirho,
    VerifiedCustodyNonEquivalenceChirho,
};
use crate::digest_chirho::{
    GeoGenesisPlanDigestChirho, GeoOperatorGuardIdentityChirho, GeoRosterProjectionDigestChirho,
};
use crate::error_chirho::{
    GeoGenesisRefusalChirho, GeoGenesisResultChirho, GeoMemberCoordinateChirho,
};
use crate::intent_guard_chirho::GeoOperatorGuardRootChirho;
use crate::scalar_chirho::{
    GeoEd25519PublicKeyChirho, GeoRaftIdChirho, GeoWireGuardPublicKeyChirho,
};
use crate::trust_chirho::{GeoGenesisTrustPinsChirho, GeoSignerRoleChirho};
use crate::verify_chirho::VerifiedGeoGenesisPlanChirho;
use std::path::Path;

/// One operator-held per-member public-key custody pin: the node + WireGuard public identities the
/// operator independently expects for the member at `raft_id`. No secret material is representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoMemberCustodyPinV1Chirho {
    pub raft_id_chirho: GeoRaftIdChirho,
    pub node_key_chirho: GeoEd25519PublicKeyChirho,
    pub wireguard_key_chirho: GeoWireGuardPublicKeyChirho,
}

/// The operator-private custody config surface (design ruling 3): the separately custody-verified
/// inputs that live OUTSIDE the plan/packet. In production these are loaded from custody-verified
/// config (8.7); this is the verified in-memory shape the checkpoint consumes. It holds only the two
/// dedicated key PINS, the held roster projection, the per-member public-key pins, the guard-root
/// LOCATION, the pinned custody authority, and the two custody attestations — never a private key,
/// seed, secret name, or token, none of which are representable here.
#[derive(Clone, Debug)]
pub struct GeoOperatorCustodyConfigV1Chirho {
    pub trust_pins_chirho: GeoGenesisTrustPinsChirho,
    pub custody_authority_pin_chirho: GeoEd25519PublicKeyChirho,
    pub roster_projection_chirho: GeoRosterProjectionDigestChirho,
    pub member_pins_chirho: Vec<GeoMemberCustodyPinV1Chirho>,
    pub operator_guard_root_chirho: GeoOperatorGuardRootChirho,
    pub plan_custody_attestation_chirho: GeoCustodyAttestationV1Chirho,
    pub acceptance_custody_attestation_chirho: GeoCustodyAttestationV1Chirho,
}

/// The bound custody presence: proof that every operator-supplied genesis input was present, custody-
/// valid, and bound one-to-one to the verified plan. Its fields are private and there is no public
/// constructor, so a caller cannot fabricate a "present" custody posture — the only way to obtain one
/// is through `verify_custody_presence_chirho`. It carries ONLY safe projections (a plan digest, the
/// roster projection, a member count, the opaque guard identity, and the two authenticated custody
/// domains), never a key, path, or secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedGenesisCustodyPresenceChirho {
    plan_digest_chirho: GeoGenesisPlanDigestChirho,
    roster_projection_chirho: GeoRosterProjectionDigestChirho,
    member_count_chirho: usize,
    operator_guard_identity_chirho: GeoOperatorGuardIdentityChirho,
    non_equivalence_chirho: VerifiedCustodyNonEquivalenceChirho,
}

impl VerifiedGenesisCustodyPresenceChirho {
    /// The verified plan digest this custody posture is bound to.
    pub fn plan_digest_chirho(&self) -> GeoGenesisPlanDigestChirho {
        self.plan_digest_chirho
    }

    /// The custody-held signed-roster projection the member pins are anchored to (equals the plan's).
    pub fn roster_projection_chirho(&self) -> GeoRosterProjectionDigestChirho {
        self.roster_projection_chirho
    }

    /// The number of plan members whose public-key pins were bound one-to-one.
    pub fn member_count_chirho(&self) -> usize {
        self.member_count_chirho
    }

    /// The opaque operator guard-root identity (never the path).
    pub fn operator_guard_identity_chirho(&self) -> GeoOperatorGuardIdentityChirho {
        self.operator_guard_identity_chirho
    }

    /// The two authenticated distinct custody domains for the dedicated keys.
    pub fn non_equivalence_chirho(&self) -> VerifiedCustodyNonEquivalenceChirho {
        self.non_equivalence_chirho
    }
}

/// Bind and REFUSE-on-absent/unverifiable the exact operator-supplied inputs the genesis must never
/// self-provision, generating NONE. Each input class refuses by its own distinct reason:
/// - the two dedicated key pins: the custody plan-authority pin must equal the verified plan's signer
///   key (the acceptance pin's presence + curve validity + distinctness are guaranteed by the pins);
/// - the signed-roster projection: the operator-held projection must equal the plan's;
/// - every per-member node + WireGuard public-key pin: the pins must cover the plan population one-to-
///   one by raft id, with each node/WireGuard key equal to its plan member;
/// - the operator guard-root location: present + metadata-custody valid (never plan-selected);
/// - the two custody-evidence attestations: the 8.2b non-equivalence predicate under the pinned
///   custody authority.
///
/// This performs NO file creation, NO key generation, and NO runtime start; it only reads the guard
/// root's metadata and compares in-memory values.
pub fn verify_custody_presence_chirho(
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    config_chirho: &GeoOperatorCustodyConfigV1Chirho,
) -> GeoGenesisResultChirho<VerifiedGenesisCustodyPresenceChirho> {
    let plan_chirho = verified_plan_chirho.plan_chirho();

    // (1) The two dedicated key pins. The plan-authority pin must equal the key the plan is authored
    // under; a plan the operator did not custody-pin refuses. (The acceptance pin's presence, curve
    // validity, and distinctness from the plan pin are established by `GeoGenesisTrustPinsChirho`.)
    let plan_authority_pin_chirho = config_chirho
        .trust_pins_chirho
        .expected_authority_key_chirho(GeoSignerRoleChirho::PlanAuthorityChirho)
        .ok_or(GeoGenesisRefusalChirho::CustodyPresencePlanKeyPinMismatchChirho)?;
    if plan_authority_pin_chirho != verified_plan_chirho.plan_signer_key_chirho() {
        return Err(GeoGenesisRefusalChirho::CustodyPresencePlanKeyPinMismatchChirho);
    }

    // (2) The signed-roster projection the per-member pins are anchored to.
    if config_chirho.roster_projection_chirho
        != plan_chirho.topology_chirho.roster_projection_chirho
    {
        return Err(GeoGenesisRefusalChirho::CustodyPresenceRosterProjectionMismatchChirho);
    }

    // (3) Every per-member node + WireGuard public-key pin, one-to-one against the plan population.
    bind_member_pins_chirho(&config_chirho.member_pins_chirho, verified_plan_chirho)?;

    // (4) The operator guard-root LOCATION (custody config, never plan-selected): present and metadata-
    // custody valid.
    verify_guard_root_custody_chirho(config_chirho.operator_guard_root_chirho.root_chirho())?;

    // (5) The two custody-evidence attestations (8.2b non-equivalence): distinct authenticated domains
    // for the two dedicated keys under the pinned custody authority.
    let non_equivalence_chirho = verify_custody_non_equivalence_chirho(
        Some(&config_chirho.plan_custody_attestation_chirho),
        Some(&config_chirho.acceptance_custody_attestation_chirho),
        &config_chirho.custody_authority_pin_chirho,
        &config_chirho.trust_pins_chirho,
    )?;

    Ok(VerifiedGenesisCustodyPresenceChirho {
        plan_digest_chirho: verified_plan_chirho.plan_digest_chirho(),
        roster_projection_chirho: config_chirho.roster_projection_chirho,
        member_count_chirho: plan_chirho.topology_chirho.members_chirho.len(),
        operator_guard_identity_chirho: config_chirho.operator_guard_root_chirho.identity_chirho(),
        non_equivalence_chirho,
    })
}

/// Bind the operator's per-member public-key pins to the verified plan population one-to-one. The pins
/// are sorted by raft id, must be the same cardinality as the plan, ascending-strict by raft id (no
/// duplicate or foreign pin), and each pin's raft id / node key / WireGuard key must equal its plan
/// member. A missing, foreign, duplicate, or mismatched pin refuses by the offending coordinate.
fn bind_member_pins_chirho(
    member_pins_chirho: &[GeoMemberCustodyPinV1Chirho],
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
) -> GeoGenesisResultChirho<()> {
    let members_chirho = &verified_plan_chirho
        .plan_chirho()
        .topology_chirho
        .members_chirho;
    if member_pins_chirho.len() != members_chirho.len() {
        return Err(
            GeoGenesisRefusalChirho::CustodyPresenceMemberPinRefusedChirho {
                coordinate_chirho: GeoMemberCoordinateChirho::RaftIdChirho,
            },
        );
    }
    let mut sorted_pins_chirho = member_pins_chirho.to_vec();
    sorted_pins_chirho.sort_by_key(|pin_chirho| pin_chirho.raft_id_chirho.get_chirho());
    // Ascending-strict by raft id rejects a duplicate or a foreign pin before the plan match.
    if !sorted_pins_chirho
        .windows(2)
        .all(|pair_chirho| pair_chirho[0].raft_id_chirho < pair_chirho[1].raft_id_chirho)
    {
        return Err(
            GeoGenesisRefusalChirho::CustodyPresenceMemberPinRefusedChirho {
                coordinate_chirho: GeoMemberCoordinateChirho::RaftIdChirho,
            },
        );
    }
    for (pin_chirho, member_chirho) in sorted_pins_chirho.iter().zip(members_chirho.iter()) {
        if pin_chirho.raft_id_chirho != member_chirho.raft_id_chirho {
            return Err(
                GeoGenesisRefusalChirho::CustodyPresenceMemberPinRefusedChirho {
                    coordinate_chirho: GeoMemberCoordinateChirho::RaftIdChirho,
                },
            );
        }
        if pin_chirho.node_key_chirho != member_chirho.node_key_chirho {
            return Err(
                GeoGenesisRefusalChirho::CustodyPresenceMemberPinRefusedChirho {
                    coordinate_chirho: GeoMemberCoordinateChirho::NodeKeyChirho,
                },
            );
        }
        if pin_chirho.wireguard_key_chirho != member_chirho.wireguard_key_chirho {
            return Err(
                GeoGenesisRefusalChirho::CustodyPresenceMemberPinRefusedChirho {
                    coordinate_chirho: GeoMemberCoordinateChirho::WireGuardKeyChirho,
                },
            );
        }
    }
    Ok(())
}

/// Metadata custody on the operator guard-root directory: it must exist, not be a symlink, be a
/// directory, and be privately permissioned. This READS metadata only — it never creates the root, the
/// guard subdirectory, or the marker (that is the 8.2c/8.6 durable guard). The same-owner check against
/// the operator config file is deferred to 8.7 (the in-memory config carries no config-file anchor).
fn verify_guard_root_custody_chirho(root_chirho: &Path) -> GeoGenesisResultChirho<()> {
    let metadata_chirho = std::fs::symlink_metadata(root_chirho).map_err(|_error_chirho| {
        GeoGenesisRefusalChirho::CustodyPresenceGuardRootUnverifiableChirho
    })?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        return Err(GeoGenesisRefusalChirho::CustodyPresenceGuardRootUnverifiableChirho);
    }
    if !private_dir_mode_chirho(&metadata_chirho) {
        return Err(GeoGenesisRefusalChirho::CustodyPresenceGuardRootUnverifiableChirho);
    }
    Ok(())
}

#[cfg(unix)]
fn private_dir_mode_chirho(metadata_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata_chirho.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_dir_mode_chirho(_metadata_chirho: &std::fs::Metadata) -> bool {
    true
}
