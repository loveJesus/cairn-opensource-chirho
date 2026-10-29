// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The durable one-time fork-impossible genesis intent guard (design section 7): it writes the
//! immutable signed intent marker no-replace to the operator guard root (the single authoritative
//! gate) and every member root before any ledger-root mutation, refuses a second or different
//! genesis, fails closed on unverifiable marker bytes, and admits only byte-identical same-plan retry.

use crate::codec_chirho::{
    canonical_blake3_hex_chirho, canonical_record_bytes_chirho, MAX_GEO_RECORD_BYTES_CHIRHO,
};
use crate::digest_chirho::{
    GeoGenesisIntentDigestChirho, GeoGenesisPlanDigestChirho, GeoIntentMarkerSetRefChirho,
    GeoOperatorGuardIdentityChirho,
};
use crate::error_chirho::{
    GeoGenesisRefusalChirho, GeoGenesisResultChirho, GeoGuardHolderRoleChirho,
};
use crate::intent_chirho::{
    parse_canonical_intent_chirho, AuthoritativeGeoGenesisIntentV1Chirho,
    GeoGenesisIntentSchemaChirho, GeoGenesisMarkerReceiptSchemaChirho,
    GeoGenesisMarkerReceiptV1Chirho, GeoIntentMarkerSetV1Chirho, GeoMarkerHolderV1Chirho,
    UnsignedGeoGenesisMarkerReceiptV1Chirho,
};
use crate::metadata_chirho::{GeoGenesisPhaseChirho, GeoMemberRoleChirho};
use crate::scalar_chirho::{
    GeoEd25519PublicKeyChirho, GeoEd25519SignatureChirho, GeoGenesisInstanceIdChirho,
    GeoRaftIdChirho, GeoUtcMinuteChirho,
};
use crate::topology_chirho::GeoMemberPlanV1Chirho;
use crate::trust_chirho::{
    verify_class_signature_chirho, GeoGenesisMessageClassChirho, GeoRoleSignerChirho,
};
use crate::verify_chirho::VerifiedGeoGenesisPlanChirho;
use cairn_durable_chirho::{
    create_file_durable_chirho, read_identity_stable_bounded_regular_file_chirho,
};
use std::path::{Path, PathBuf};

/// The fixed guard namespace directory; the marker path is derived in code and appears in no artifact.
/// It is defined beside the other root markers in `cairn-tenant-chirho`, so the control-plane law's
/// evidence probe (C2.1) reads the same name this guard writes.
pub use cairn_tenant_chirho::tenant_chirho::GEO_GENESIS_GUARD_DIR_CHIRHO;
/// The fixed immutable intent-marker child name (design section 7.1).
pub const AUTHORITATIVE_INTENT_FILE_CHIRHO: &str =
    "authoritative-geo-genesis-intent-v1-chirho.json";

/// Derive the fixed marker path under a root. The path is code-derived — neither the plan nor the
/// acceptance packet contains it (design section 7.1).
pub fn geo_genesis_guard_marker_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho
        .join(GEO_GENESIS_GUARD_DIR_CHIRHO)
        .join(AUTHORITATIVE_INTENT_FILE_CHIRHO)
}

/// The separately custody-verified operator guard root: the SINGLE authoritative one-time gate
/// (ruling 2). Its path and opaque identity are supplied through custody configuration and are NEVER
/// selected by the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoOperatorGuardRootChirho {
    root_chirho: PathBuf,
    identity_chirho: GeoOperatorGuardIdentityChirho,
}

impl GeoOperatorGuardRootChirho {
    /// Bind a custody-supplied operator guard root path to its custody-supplied opaque identity.
    pub fn new_chirho(
        root_chirho: PathBuf,
        identity_chirho: GeoOperatorGuardIdentityChirho,
    ) -> Self {
        Self {
            root_chirho,
            identity_chirho,
        }
    }

    /// The code-derived marker path under this root.
    pub fn marker_path_chirho(&self) -> PathBuf {
        geo_genesis_guard_marker_path_chirho(&self.root_chirho)
    }

    /// The custody-supplied guard-root directory itself; the 8.3 custody checkpoint reads its metadata
    /// (presence, non-symlink, directory, private mode) without writing to it. Never emitted in any
    /// plan or packet — this is an in-crate accessor for the pre-genesis custody check only.
    pub(crate) fn root_chirho(&self) -> &Path {
        &self.root_chirho
    }

    /// The custody-supplied opaque guard identity.
    pub fn identity_chirho(&self) -> GeoOperatorGuardIdentityChirho {
        self.identity_chirho
    }
}

/// One planned member's guard root (defense-in-depth), keyed to its exact plan coordinate so the root
/// set can be bound one-to-one against the verified plan population.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoMemberGuardRootChirho {
    role_chirho: GeoMemberRoleChirho,
    raft_id_chirho: GeoRaftIdChirho,
    node_key_chirho: GeoEd25519PublicKeyChirho,
    root_chirho: PathBuf,
}

impl GeoMemberGuardRootChirho {
    /// Bind a member's custody-supplied storage root to its exact plan coordinate.
    pub fn new_chirho(
        role_chirho: GeoMemberRoleChirho,
        raft_id_chirho: GeoRaftIdChirho,
        node_key_chirho: GeoEd25519PublicKeyChirho,
        root_chirho: PathBuf,
    ) -> Self {
        Self {
            role_chirho,
            raft_id_chirho,
            node_key_chirho,
            root_chirho,
        }
    }

    /// The code-derived marker path under this member root.
    pub fn marker_path_chirho(&self) -> PathBuf {
        geo_genesis_guard_marker_path_chirho(&self.root_chirho)
    }
}

/// The complete set of guard roots for one genesis: the single authoritative operator guard root plus
/// one defense-in-depth root per planned member. Constructed only against a verified plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoGuardRootsChirho {
    operator_root_chirho: GeoOperatorGuardRootChirho,
    member_roots_chirho: Vec<GeoMemberGuardRootChirho>,
}

impl GeoGuardRootsChirho {
    /// Bind the operator guard root (custody, never plan-selected) plus one member root per planned
    /// member. The member roots must cover the verified plan population one-to-one by role, Raft id,
    /// and node key; missing, foreign, duplicated, or mis-coordinated member roots refuse. Roots are
    /// sorted by Raft id to match the plan's canonical member order.
    pub fn bind_to_plan_chirho(
        verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
        operator_root_chirho: GeoOperatorGuardRootChirho,
        mut member_roots_chirho: Vec<GeoMemberGuardRootChirho>,
    ) -> GeoGenesisResultChirho<Self> {
        member_roots_chirho.sort_by_key(|root_chirho| root_chirho.raft_id_chirho);
        validate_member_roots_bind_plan_chirho(
            &member_roots_chirho,
            &verified_plan_chirho
                .plan_chirho()
                .topology_chirho
                .members_chirho,
        )?;
        Ok(Self {
            operator_root_chirho,
            member_roots_chirho,
        })
    }

    fn operator_marker_path_chirho(&self) -> PathBuf {
        self.operator_root_chirho.marker_path_chirho()
    }

    fn require_bound_to_plan_chirho(
        &self,
        verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    ) -> GeoGenesisResultChirho<()> {
        validate_member_roots_bind_plan_chirho(
            &self.member_roots_chirho,
            &verified_plan_chirho
                .plan_chirho()
                .topology_chirho
                .members_chirho,
        )
    }
}

fn validate_member_roots_bind_plan_chirho(
    member_roots_chirho: &[GeoMemberGuardRootChirho],
    plan_members_chirho: &[GeoMemberPlanV1Chirho],
) -> GeoGenesisResultChirho<()> {
    if member_roots_chirho.len() != plan_members_chirho.len() {
        return Err(GeoGenesisRefusalChirho::GuardRootBindingRefusedChirho);
    }
    // Ascending-strict by Raft id: rejects a duplicate or foreign member root before the plan match.
    if !member_roots_chirho
        .windows(2)
        .all(|pair_chirho| pair_chirho[0].raft_id_chirho < pair_chirho[1].raft_id_chirho)
    {
        return Err(GeoGenesisRefusalChirho::GuardRootBindingRefusedChirho);
    }
    // The plan members are ascending by Raft id (topology validation), so a position-wise compare of
    // the two ascending sequences binds each root to its exact plan member.
    for (root_chirho, member_chirho) in member_roots_chirho.iter().zip(plan_members_chirho) {
        if root_chirho.role_chirho != member_chirho.role_chirho
            || root_chirho.raft_id_chirho != member_chirho.raft_id_chirho
            || root_chirho.node_key_chirho != member_chirho.node_key_chirho
        {
            return Err(GeoGenesisRefusalChirho::GuardRootBindingRefusedChirho);
        }
    }
    Ok(())
}

/// A freshly built, signed immutable intent marker plus its canonical bytes and content-address. The
/// bytes are deterministic from the verified plan, so a same-plan retry rebuilds byte-identical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIntentMarkerChirho {
    intent_chirho: AuthoritativeGeoGenesisIntentV1Chirho,
    canonical_bytes_chirho: Vec<u8>,
    marker_ref_chirho: GeoGenesisIntentDigestChirho,
}

impl SignedIntentMarkerChirho {
    /// The signed intent marker record.
    pub fn intent_chirho(&self) -> &AuthoritativeGeoGenesisIntentV1Chirho {
        &self.intent_chirho
    }

    /// The exact canonical bytes durably written to every guard root.
    pub fn canonical_bytes_chirho(&self) -> &[u8] {
        &self.canonical_bytes_chirho
    }

    /// The blake3 content-address of the canonical marker bytes.
    pub fn marker_ref_chirho(&self) -> GeoGenesisIntentDigestChirho {
        self.marker_ref_chirho
    }
}

/// Build and sign the immutable intent marker from a verified plan. Every marker coordinate is copied
/// from the verified plan (so recovery/refusal diagnostics need no absent plan file), the phase is
/// `IntentReservedChirho` by type, and the plan-authority signer signs the `IntentMarkerChirho` class
/// over the explicit unsigned canonical bytes — any other signer role refuses at the message-class
/// gate. This function signs with an EXISTING key; it never generates one.
pub fn build_signed_intent_marker_chirho(
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    plan_authority_signer_chirho: &GeoRoleSignerChirho,
) -> GeoGenesisResultChirho<SignedIntentMarkerChirho> {
    let plan_chirho = verified_plan_chirho.plan_chirho();
    let mut intent_chirho = AuthoritativeGeoGenesisIntentV1Chirho {
        schema_chirho: GeoGenesisIntentSchemaChirho::V1Chirho,
        instance_id_chirho: plan_chirho.instance_id_chirho,
        plan_ref_chirho: verified_plan_chirho.plan_digest_chirho(),
        prd_chirho: plan_chirho.prd_chirho.prd_content_chirho,
        ledger_plan_chirho: plan_chirho.ledger_chirho.ledger_regenesis_plan_chirho,
        fresh_root_identity_chirho: plan_chirho.ledger_chirho.fresh_root_identity_chirho,
        consistency_group_chirho: plan_chirho.ledger_chirho.consistency_group_chirho,
        tenant_root_chirho: plan_chirho.ledger_chirho.tenant_root_chirho,
        roster_projection_chirho: plan_chirho.topology_chirho.roster_projection_chirho,
        source_commit_chirho: plan_chirho.builds_chirho.reviewed_source_commit_chirho,
        rulings_chirho: plan_chirho.rulings_chirho,
        trust_profile_chirho: plan_chirho.trust_profile_chirho,
        intent_signer_key_chirho: plan_authority_signer_chirho.public_key_chirho(),
        phase_chirho: GeoGenesisPhaseChirho::IntentReservedChirho,
        signature_chirho: placeholder_signature_chirho()?,
    };
    intent_chirho.validate_structural_chirho()?;

    let unsigned_bytes_chirho = canonical_record_bytes_chirho(&intent_chirho.to_unsigned_chirho())?;
    let signature_chirho = plan_authority_signer_chirho.sign_class_chirho(
        GeoGenesisMessageClassChirho::IntentMarkerChirho,
        &unsigned_bytes_chirho,
    )?;
    intent_chirho.signature_chirho = signature_chirho;

    let canonical_bytes_chirho = canonical_record_bytes_chirho(&intent_chirho)?;
    let marker_ref_chirho = GeoGenesisIntentDigestChirho::from_hex_chirho(
        &canonical_blake3_hex_chirho(&canonical_bytes_chirho),
    )?;
    Ok(SignedIntentMarkerChirho {
        intent_chirho,
        canonical_bytes_chirho,
        marker_ref_chirho,
    })
}

fn placeholder_signature_chirho() -> GeoGenesisResultChirho<GeoEd25519SignatureChirho> {
    GeoEd25519SignatureChirho::new_chirho([0u8; 64])
}

/// A private reservation token proving the complete durable intent marker set is installed. Its fields
/// are private and there is no public constructor, so the only way to obtain one is through
/// `reserve_genesis_intent_chirho` — a caller cannot fabricate a "reserved" genesis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoGenesisIntentReservationChirho {
    marker_ref_chirho: GeoGenesisIntentDigestChirho,
    marker_canonical_bytes_chirho: Vec<u8>,
    marker_set_chirho: GeoIntentMarkerSetV1Chirho,
}

impl GeoGenesisIntentReservationChirho {
    /// The content-address of the durable intent marker.
    pub fn marker_ref_chirho(&self) -> GeoGenesisIntentDigestChirho {
        self.marker_ref_chirho
    }

    /// The exact canonical marker bytes durably written to every guard root.
    pub fn marker_canonical_bytes_chirho(&self) -> &[u8] {
        &self.marker_canonical_bytes_chirho
    }

    /// The complete verified intent marker set (operator-guard receipt plus every member receipt).
    pub fn marker_set_chirho(&self) -> &GeoIntentMarkerSetV1Chirho {
        &self.marker_set_chirho
    }

    /// The content-address of the complete verified marker set (design section 7.2).
    pub fn intent_marker_set_ref_chirho(
        &self,
    ) -> GeoGenesisResultChirho<GeoIntentMarkerSetRefChirho> {
        let bytes_chirho = canonical_record_bytes_chirho(&self.marker_set_chirho)?;
        GeoIntentMarkerSetRefChirho::from_hex_chirho(&canonical_blake3_hex_chirho(&bytes_chirho))
    }
}

/// Reserve the one-time genesis intent (design section 7): build and sign the immutable marker, refuse
/// before any write if a valid different-plan marker or malformed bytes sit at ANY guard root, then
/// write the byte-identical marker no-replace to the operator guard root FIRST and every member root,
/// re-reading each. Returns a private reservation token or a fail-closed refusal. `now_chirho` is the
/// caller-injected coarse minute — reading a clock is an effect and does not happen inside the guard.
///
/// Fork-impossibility rests on `create_file_durable_chirho`'s atomic nonexistence claim: a concurrent
/// winner is never modified, so two genesis attempts cannot both create the operator guard marker;
/// the loser sees the winner's bytes and refuses. Byte-identical same-plan retry is the only recovery
/// door — there is no cleanup, delete, wipe, or second-generation path.
pub fn reserve_genesis_intent_chirho(
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    guard_roots_chirho: &GeoGuardRootsChirho,
    plan_authority_signer_chirho: &GeoRoleSignerChirho,
    member_signers_chirho: &[GeoRoleSignerChirho],
    now_chirho: GeoUtcMinuteChirho,
) -> GeoGenesisResultChirho<GeoGenesisIntentReservationChirho> {
    let plan_chirho = verified_plan_chirho.plan_chirho();
    let plan_authority_key_chirho = plan_authority_signer_chirho.public_key_chirho();

    // The guard roots must bind THIS verified plan; a set bound to a different plan refuses here.
    guard_roots_chirho.require_bound_to_plan_chirho(verified_plan_chirho)?;

    // 1. Build the immutable signed marker (deterministic from the verified plan).
    let signed_marker_chirho =
        build_signed_intent_marker_chirho(verified_plan_chirho, plan_authority_signer_chirho)?;
    let canonical_chirho = signed_marker_chirho.canonical_bytes_chirho.as_slice();

    // 2. Pre-write scan of EVERY guard path (operator first). A valid different-plan marker or
    //    malformed bytes at ANY path refuses BEFORE a single marker is written.
    classify_guard_path_chirho(
        &guard_roots_chirho.operator_marker_path_chirho(),
        canonical_chirho,
        &plan_authority_key_chirho,
        GeoGuardHolderRoleChirho::OperatorGuardChirho,
    )?;
    for member_root_chirho in &guard_roots_chirho.member_roots_chirho {
        classify_guard_path_chirho(
            &member_root_chirho.marker_path_chirho(),
            canonical_chirho,
            &plan_authority_key_chirho,
            GeoGuardHolderRoleChirho::MemberChirho,
        )?;
    }

    // 3. Marker-FIRST write order: the operator guard root (the single authoritative gate) BEFORE any
    //    member root. Each write is the one no-replace create door, re-read and byte-compared.
    write_marker_no_replace_chirho(
        &guard_roots_chirho.operator_marker_path_chirho(),
        canonical_chirho,
        &plan_authority_key_chirho,
        GeoGuardHolderRoleChirho::OperatorGuardChirho,
    )?;
    for member_root_chirho in &guard_roots_chirho.member_roots_chirho {
        write_marker_no_replace_chirho(
            &member_root_chirho.marker_path_chirho(),
            canonical_chirho,
            &plan_authority_key_chirho,
            GeoGuardHolderRoleChirho::MemberChirho,
        )?;
    }

    // 4. Build the marker receipts once every marker is durable.
    let marker_ref_chirho = signed_marker_chirho.marker_ref_chirho;
    let plan_ref_chirho = verified_plan_chirho.plan_digest_chirho();
    let instance_chirho = plan_chirho.instance_id_chirho;

    let operator_receipt_chirho = build_operator_guard_receipt_chirho(
        instance_chirho,
        plan_ref_chirho,
        marker_ref_chirho,
        guard_roots_chirho.operator_root_chirho.identity_chirho,
        now_chirho,
        plan_authority_signer_chirho,
    )?;

    let mut member_receipts_chirho =
        Vec::with_capacity(guard_roots_chirho.member_roots_chirho.len());
    for member_root_chirho in &guard_roots_chirho.member_roots_chirho {
        let signer_chirho =
            member_signer_for_chirho(member_signers_chirho, &member_root_chirho.node_key_chirho)?;
        member_receipts_chirho.push(build_member_receipt_chirho(
            instance_chirho,
            plan_ref_chirho,
            marker_ref_chirho,
            member_root_chirho.role_chirho,
            member_root_chirho.raft_id_chirho,
            member_root_chirho.node_key_chirho,
            now_chirho,
            signer_chirho,
        )?);
    }

    // 5. Assemble and validate: structural checks plus binding the set to the plan population.
    let marker_set_chirho = GeoIntentMarkerSetV1Chirho {
        marker_ref_chirho,
        operator_guard_chirho: operator_receipt_chirho,
        member_markers_chirho: member_receipts_chirho,
    };
    marker_set_chirho.validate_structural_chirho()?;
    validate_marker_set_binds_plan_chirho(
        &marker_set_chirho,
        verified_plan_chirho,
        guard_roots_chirho,
        marker_ref_chirho,
    )?;

    Ok(GeoGenesisIntentReservationChirho {
        marker_ref_chirho,
        marker_canonical_bytes_chirho: signed_marker_chirho.canonical_bytes_chirho,
        marker_set_chirho,
    })
}

/// Reserve the one-time genesis intent and only THEN run a root action — the marker-first enforcement
/// seam (design section 7.3). The intent set is durable before `root_action_chirho` runs; a root
/// action that ran first would observe no marker, the authority failure this ordering exists to make
/// unrepresentable. Root-first is rejected. In 8.2c the root action is injected; 8.7 wires the real
/// ledger publication, which consumes the returned reservation.
pub fn reserve_intent_then_run_root_chirho<RootActionChirho, OutcomeChirho>(
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    guard_roots_chirho: &GeoGuardRootsChirho,
    plan_authority_signer_chirho: &GeoRoleSignerChirho,
    member_signers_chirho: &[GeoRoleSignerChirho],
    now_chirho: GeoUtcMinuteChirho,
    root_action_chirho: RootActionChirho,
) -> GeoGenesisResultChirho<(GeoGenesisIntentReservationChirho, OutcomeChirho)>
where
    RootActionChirho: FnOnce() -> GeoGenesisResultChirho<OutcomeChirho>,
{
    let reservation_chirho = reserve_genesis_intent_chirho(
        verified_plan_chirho,
        guard_roots_chirho,
        plan_authority_signer_chirho,
        member_signers_chirho,
        now_chirho,
    )?;
    let outcome_chirho = root_action_chirho()?;
    Ok((reservation_chirho, outcome_chirho))
}

/// The classification of one guard path that is NOT a refusal: absent (will be created) or already
/// byte-identical (a same-plan retry residue).
enum GuardPathStatusChirho {
    AbsentChirho,
    IdenticalChirho,
}

/// Classify a guard path without writing. Absent → will create; byte-identical → same-plan resume; a
/// valid different-plan marker → `GenesisAlreadyReservedChirho`; anything malformed, non-canonical,
/// wrongly signed, unreadable, or a symlink → `GuardMarkerUnverifiableChirho`. A missing file is the
/// only "absence"; every present-but-not-identical object fails closed and is never counted as absence.
fn classify_guard_path_chirho(
    marker_path_chirho: &Path,
    canonical_chirho: &[u8],
    plan_authority_key_chirho: &GeoEd25519PublicKeyChirho,
    role_chirho: GeoGuardHolderRoleChirho,
) -> GeoGenesisResultChirho<GuardPathStatusChirho> {
    match read_identity_stable_bounded_regular_file_chirho(
        marker_path_chirho,
        MAX_GEO_RECORD_BYTES_CHIRHO as u64,
    ) {
        Ok(bytes_chirho) => {
            if bytes_chirho == canonical_chirho {
                Ok(GuardPathStatusChirho::IdenticalChirho)
            } else if existing_marker_is_valid_chirho(&bytes_chirho, plan_authority_key_chirho) {
                Err(GeoGenesisRefusalChirho::GenesisAlreadyReservedChirho {
                    holder_role_chirho: role_chirho,
                })
            } else {
                Err(GeoGenesisRefusalChirho::GuardMarkerUnverifiableChirho {
                    holder_role_chirho: role_chirho,
                })
            }
        }
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            Ok(GuardPathStatusChirho::AbsentChirho)
        }
        Err(_error_chirho) => Err(GeoGenesisRefusalChirho::GuardMarkerUnverifiableChirho {
            holder_role_chirho: role_chirho,
        }),
    }
}

/// Whether existing bytes are a valid authoritative intent marker: wire-law + structural parse AND a
/// signature that verifies against the plan-authority key over the `IntentMarkerChirho` class. Used
/// only to name a present-but-different object a reserved genesis vs corrupt bytes; both refuse.
fn existing_marker_is_valid_chirho(
    bytes_chirho: &[u8],
    plan_authority_key_chirho: &GeoEd25519PublicKeyChirho,
) -> bool {
    let Ok(intent_chirho) = parse_canonical_intent_chirho(bytes_chirho) else {
        return false;
    };
    let Ok(unsigned_bytes_chirho) =
        canonical_record_bytes_chirho(&intent_chirho.to_unsigned_chirho())
    else {
        return false;
    };
    verify_class_signature_chirho(
        plan_authority_key_chirho,
        GeoGenesisMessageClassChirho::IntentMarkerChirho,
        &unsigned_bytes_chirho,
        &intent_chirho.signature_chirho,
    )
    .is_ok()
}

/// Write the marker no-replace, then re-read and re-classify. This is the ONE genesis-create door: the
/// atomic nonexistence claim. Whether we win the claim or lose a race, the re-read requires
/// byte-identical bytes — a lost race to a different plan or a torn/foreign object fails closed here,
/// never as success. An identical existing file is left untouched (no rewrite, no delete).
fn write_marker_no_replace_chirho(
    marker_path_chirho: &Path,
    canonical_chirho: &[u8],
    plan_authority_key_chirho: &GeoEd25519PublicKeyChirho,
    role_chirho: GeoGuardHolderRoleChirho,
) -> GeoGenesisResultChirho<()> {
    create_file_durable_chirho(marker_path_chirho, canonical_chirho)
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::GuardMarkerIoRefusedChirho)?;
    match classify_guard_path_chirho(
        marker_path_chirho,
        canonical_chirho,
        plan_authority_key_chirho,
        role_chirho,
    )? {
        GuardPathStatusChirho::IdenticalChirho => Ok(()),
        // Absence immediately after a successful create is an I/O fault, never success.
        GuardPathStatusChirho::AbsentChirho => {
            Err(GeoGenesisRefusalChirho::GuardMarkerIoRefusedChirho)
        }
    }
}

fn member_signer_for_chirho<'signers_chirho>(
    member_signers_chirho: &'signers_chirho [GeoRoleSignerChirho],
    node_key_chirho: &GeoEd25519PublicKeyChirho,
) -> GeoGenesisResultChirho<&'signers_chirho GeoRoleSignerChirho> {
    member_signers_chirho
        .iter()
        .find(|signer_chirho| signer_chirho.public_key_chirho() == *node_key_chirho)
        .ok_or(GeoGenesisRefusalChirho::GuardMemberSignerRefusedChirho)
}

fn build_operator_guard_receipt_chirho(
    instance_chirho: GeoGenesisInstanceIdChirho,
    plan_ref_chirho: GeoGenesisPlanDigestChirho,
    marker_ref_chirho: GeoGenesisIntentDigestChirho,
    guard_identity_chirho: GeoOperatorGuardIdentityChirho,
    now_chirho: GeoUtcMinuteChirho,
    plan_authority_signer_chirho: &GeoRoleSignerChirho,
) -> GeoGenesisResultChirho<GeoGenesisMarkerReceiptV1Chirho> {
    build_marker_receipt_chirho(
        instance_chirho,
        plan_ref_chirho,
        marker_ref_chirho,
        GeoMarkerHolderV1Chirho::OperatorGuardChirho {
            guard_identity_chirho,
        },
        now_chirho,
        GeoGenesisMessageClassChirho::OperatorGuardMarkerReceiptChirho,
        plan_authority_signer_chirho,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_member_receipt_chirho(
    instance_chirho: GeoGenesisInstanceIdChirho,
    plan_ref_chirho: GeoGenesisPlanDigestChirho,
    marker_ref_chirho: GeoGenesisIntentDigestChirho,
    role_chirho: GeoMemberRoleChirho,
    raft_id_chirho: GeoRaftIdChirho,
    node_key_chirho: GeoEd25519PublicKeyChirho,
    now_chirho: GeoUtcMinuteChirho,
    member_signer_chirho: &GeoRoleSignerChirho,
) -> GeoGenesisResultChirho<GeoGenesisMarkerReceiptV1Chirho> {
    build_marker_receipt_chirho(
        instance_chirho,
        plan_ref_chirho,
        marker_ref_chirho,
        GeoMarkerHolderV1Chirho::MemberChirho {
            role_chirho,
            raft_id_chirho,
            node_key_chirho,
        },
        now_chirho,
        GeoGenesisMessageClassChirho::MemberMarkerReceiptChirho,
        member_signer_chirho,
    )
}

/// Build one signed marker receipt: assemble the explicit unsigned receipt, sign its canonical bytes
/// over the given class with the given signer, and attach the signature. The signer's role must own
/// the class — a member signer cannot sign an operator-guard receipt and vice versa.
fn build_marker_receipt_chirho(
    instance_chirho: GeoGenesisInstanceIdChirho,
    plan_ref_chirho: GeoGenesisPlanDigestChirho,
    marker_ref_chirho: GeoGenesisIntentDigestChirho,
    holder_chirho: GeoMarkerHolderV1Chirho,
    now_chirho: GeoUtcMinuteChirho,
    class_chirho: GeoGenesisMessageClassChirho,
    signer_chirho: &GeoRoleSignerChirho,
) -> GeoGenesisResultChirho<GeoGenesisMarkerReceiptV1Chirho> {
    let unsigned_chirho = UnsignedGeoGenesisMarkerReceiptV1Chirho {
        schema_chirho: GeoGenesisMarkerReceiptSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho,
        plan_ref_chirho,
        marker_ref_chirho,
        holder_chirho,
        durable_at_chirho: now_chirho,
        receipt_signer_key_chirho: signer_chirho.public_key_chirho(),
    };
    let unsigned_bytes_chirho = canonical_record_bytes_chirho(&unsigned_chirho)?;
    let signature_chirho = signer_chirho.sign_class_chirho(class_chirho, &unsigned_bytes_chirho)?;
    Ok(GeoGenesisMarkerReceiptV1Chirho {
        schema_chirho: unsigned_chirho.schema_chirho,
        instance_id_chirho: unsigned_chirho.instance_id_chirho,
        plan_ref_chirho: unsigned_chirho.plan_ref_chirho,
        marker_ref_chirho: unsigned_chirho.marker_ref_chirho,
        holder_chirho: unsigned_chirho.holder_chirho,
        durable_at_chirho: unsigned_chirho.durable_at_chirho,
        receipt_signer_key_chirho: unsigned_chirho.receipt_signer_key_chirho,
        signature_chirho,
    })
}

/// Bind the produced marker set to the verified plan population (design section 7.2): the operator
/// receipt holds the exact custody guard identity, every member receipt maps to exactly one plan
/// member by role/Raft/node key and is signed by that member's key, and every receipt carries the
/// exact instance, plan ref, and marker ref.
fn validate_marker_set_binds_plan_chirho(
    marker_set_chirho: &GeoIntentMarkerSetV1Chirho,
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    guard_roots_chirho: &GeoGuardRootsChirho,
    marker_ref_chirho: GeoGenesisIntentDigestChirho,
) -> GeoGenesisResultChirho<()> {
    let plan_chirho = verified_plan_chirho.plan_chirho();
    let plan_ref_chirho = verified_plan_chirho.plan_digest_chirho();
    let instance_chirho = plan_chirho.instance_id_chirho;

    if marker_set_chirho.marker_ref_chirho != marker_ref_chirho {
        return Err(GeoGenesisRefusalChirho::MarkerSetPlanBindingRefusedChirho);
    }
    match marker_set_chirho.operator_guard_chirho.holder_chirho {
        GeoMarkerHolderV1Chirho::OperatorGuardChirho {
            guard_identity_chirho,
        } if guard_identity_chirho == guard_roots_chirho.operator_root_chirho.identity_chirho => {}
        _ => return Err(GeoGenesisRefusalChirho::MarkerSetPlanBindingRefusedChirho),
    }
    require_receipt_binds_chirho(
        &marker_set_chirho.operator_guard_chirho,
        instance_chirho,
        plan_ref_chirho,
        marker_ref_chirho,
    )?;

    let members_chirho = &plan_chirho.topology_chirho.members_chirho;
    if marker_set_chirho.member_markers_chirho.len() != members_chirho.len() {
        return Err(GeoGenesisRefusalChirho::MarkerSetPlanBindingRefusedChirho);
    }
    // The plan members and the marker receipts are both ascending by Raft id, so a position-wise
    // compare binds each receipt to its exact plan member.
    for (receipt_chirho, member_chirho) in marker_set_chirho
        .member_markers_chirho
        .iter()
        .zip(members_chirho)
    {
        match receipt_chirho.holder_chirho {
            GeoMarkerHolderV1Chirho::MemberChirho {
                role_chirho,
                raft_id_chirho,
                node_key_chirho,
            } if role_chirho == member_chirho.role_chirho
                && raft_id_chirho == member_chirho.raft_id_chirho
                && node_key_chirho == member_chirho.node_key_chirho
                && receipt_chirho.receipt_signer_key_chirho == member_chirho.node_key_chirho => {}
            _ => return Err(GeoGenesisRefusalChirho::MarkerSetPlanBindingRefusedChirho),
        }
        require_receipt_binds_chirho(
            receipt_chirho,
            instance_chirho,
            plan_ref_chirho,
            marker_ref_chirho,
        )?;
    }
    Ok(())
}

fn require_receipt_binds_chirho(
    receipt_chirho: &GeoGenesisMarkerReceiptV1Chirho,
    instance_chirho: GeoGenesisInstanceIdChirho,
    plan_ref_chirho: GeoGenesisPlanDigestChirho,
    marker_ref_chirho: GeoGenesisIntentDigestChirho,
) -> GeoGenesisResultChirho<()> {
    if receipt_chirho.instance_id_chirho != instance_chirho
        || receipt_chirho.plan_ref_chirho != plan_ref_chirho
        || receipt_chirho.marker_ref_chirho != marker_ref_chirho
    {
        return Err(GeoGenesisRefusalChirho::MarkerSetPlanBindingRefusedChirho);
    }
    Ok(())
}

// A child of THIS module (not the sibling `tests_chirho` tree) so it can reach the private
// `write_marker_no_replace_chirho` and drive its create → AlreadyExists → re-read → byte-mismatch →
// refuse backstop directly — the only lost-race branch no single-threaded public-API arm can reach.
// The file lives under `tests_chirho/` (kept out of the operator-only source-census, which scans only
// top-level `src/*.rs`).
#[cfg(test)]
#[path = "tests_chirho/intent_guard_backstop_tests_chirho.rs"]
mod intent_guard_backstop_tests_chirho;
