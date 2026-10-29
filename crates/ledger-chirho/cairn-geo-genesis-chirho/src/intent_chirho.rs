// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The no-second-genesis marker and receipt record types (design section 7): the immutable intent
//! marker, its marker/publication/member-admission receipts, and their explicit unsigned companions.
//! This is the wire law + structural shape (phase-by-type, set sort/uniqueness/bounds, holder-kind);
//! the durable marker-first ordering, filesystem guard, signing, and plan-population binding are 8.2c.

use crate::codec_chirho::parse_canonical_chirho;
use crate::digest_chirho::{
    GeoConsistencyGroupDigestChirho, GeoGenesisIntentDigestChirho, GeoGenesisPlanDigestChirho,
    GeoLedgerPublicationManifestDigestChirho, GeoLedgerRegenesisPlanDigestChirho,
    GeoNodeBuildEvidenceRefChirho, GeoNodeConfigEvidenceRefChirho, GeoOperatorGuardIdentityChirho,
    GeoPrdContentDigestChirho, GeoRosterProjectionDigestChirho,
};
use crate::error_chirho::{
    GeoGenesisRefusalChirho, GeoGenesisResultChirho, GeoMemberCoordinateChirho,
};
use crate::metadata_chirho::{
    GeoGenesisPhaseChirho, GeoMemberAdmissionPhaseChirho, GeoMemberRoleChirho,
};
use crate::ruling_chirho::{GeoGenesisRulingSetV1Chirho, GeoGenesisTrustProfileChirho};
use crate::scalar_chirho::{
    GeoAppliedConfIndexChirho, GeoAppliedRosterRevisionChirho, GeoEd25519PublicKeyChirho,
    GeoEd25519SignatureChirho, GeoElectionTermChirho, GeoFreshRootIdentityChirho,
    GeoGenesisInstanceIdChirho, GeoGitCommitIdChirho, GeoRaftIdChirho, GeoTenantRootIdentityChirho,
    GeoUtcMinuteChirho,
};
use crate::topology_chirho::{GEO_MAX_MEMBERS_CHIRHO, GEO_MIN_MEMBERS_CHIRHO};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Closed intent-marker schema token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisIntentSchemaChirho {
    V1Chirho,
}

/// The immutable no-second-genesis intent marker (design section 7.1). Later publication and
/// acceptance are separate receipts and never rewrite it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeGeoGenesisIntentV1Chirho {
    pub schema_chirho: GeoGenesisIntentSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub prd_chirho: GeoPrdContentDigestChirho,
    pub ledger_plan_chirho: GeoLedgerRegenesisPlanDigestChirho,
    pub fresh_root_identity_chirho: GeoFreshRootIdentityChirho,
    pub consistency_group_chirho: GeoConsistencyGroupDigestChirho,
    pub tenant_root_chirho: GeoTenantRootIdentityChirho,
    pub roster_projection_chirho: GeoRosterProjectionDigestChirho,
    pub source_commit_chirho: GeoGitCommitIdChirho,
    pub rulings_chirho: GeoGenesisRulingSetV1Chirho,
    pub trust_profile_chirho: GeoGenesisTrustProfileChirho,
    pub intent_signer_key_chirho: GeoEd25519PublicKeyChirho,
    pub phase_chirho: GeoGenesisPhaseChirho,
    pub signature_chirho: GeoEd25519SignatureChirho,
}

/// The explicit unsigned companion of the intent marker (design section 10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedAuthoritativeGeoGenesisIntentV1Chirho {
    pub schema_chirho: GeoGenesisIntentSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub prd_chirho: GeoPrdContentDigestChirho,
    pub ledger_plan_chirho: GeoLedgerRegenesisPlanDigestChirho,
    pub fresh_root_identity_chirho: GeoFreshRootIdentityChirho,
    pub consistency_group_chirho: GeoConsistencyGroupDigestChirho,
    pub tenant_root_chirho: GeoTenantRootIdentityChirho,
    pub roster_projection_chirho: GeoRosterProjectionDigestChirho,
    pub source_commit_chirho: GeoGitCommitIdChirho,
    pub rulings_chirho: GeoGenesisRulingSetV1Chirho,
    pub trust_profile_chirho: GeoGenesisTrustProfileChirho,
    pub intent_signer_key_chirho: GeoEd25519PublicKeyChirho,
    pub phase_chirho: GeoGenesisPhaseChirho,
}

impl AuthoritativeGeoGenesisIntentV1Chirho {
    /// The explicit unsigned view whose canonical bytes are the signing/verification input (8.2c).
    pub fn to_unsigned_chirho(&self) -> UnsignedAuthoritativeGeoGenesisIntentV1Chirho {
        UnsignedAuthoritativeGeoGenesisIntentV1Chirho {
            schema_chirho: self.schema_chirho,
            instance_id_chirho: self.instance_id_chirho,
            plan_ref_chirho: self.plan_ref_chirho,
            prd_chirho: self.prd_chirho,
            ledger_plan_chirho: self.ledger_plan_chirho,
            fresh_root_identity_chirho: self.fresh_root_identity_chirho,
            consistency_group_chirho: self.consistency_group_chirho,
            tenant_root_chirho: self.tenant_root_chirho,
            roster_projection_chirho: self.roster_projection_chirho,
            source_commit_chirho: self.source_commit_chirho,
            rulings_chirho: self.rulings_chirho,
            trust_profile_chirho: self.trust_profile_chirho,
            intent_signer_key_chirho: self.intent_signer_key_chirho,
            phase_chirho: self.phase_chirho,
        }
    }

    /// Structural validation: the marker's fixed phase is `IntentReservedChirho`.
    pub fn validate_structural_chirho(&self) -> GeoGenesisResultChirho<()> {
        require_phase_chirho(
            self.phase_chirho,
            GeoGenesisPhaseChirho::IntentReservedChirho,
        )
    }
}

/// The closed set of marker holders (design section 7.2), internally tagged so an unknown field or
/// unknown holder kind refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "holder_kind_chirho",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GeoMarkerHolderV1Chirho {
    OperatorGuardChirho {
        guard_identity_chirho: GeoOperatorGuardIdentityChirho,
    },
    MemberChirho {
        role_chirho: GeoMemberRoleChirho,
        raft_id_chirho: GeoRaftIdChirho,
        node_key_chirho: GeoEd25519PublicKeyChirho,
    },
}

impl GeoMarkerHolderV1Chirho {
    fn is_operator_guard_chirho(&self) -> bool {
        matches!(self, Self::OperatorGuardChirho { .. })
    }

    fn member_coordinates_chirho(&self) -> Option<(GeoRaftIdChirho, GeoEd25519PublicKeyChirho)> {
        match self {
            Self::MemberChirho {
                raft_id_chirho,
                node_key_chirho,
                ..
            } => Some((*raft_id_chirho, *node_key_chirho)),
            Self::OperatorGuardChirho { .. } => None,
        }
    }
}

/// Closed marker-receipt schema token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisMarkerReceiptSchemaChirho {
    V1Chirho,
}

/// A durable-intent-presence receipt (design section 7.2). Proves the marker is durably present, not
/// member admission, publication, or acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGenesisMarkerReceiptV1Chirho {
    pub schema_chirho: GeoGenesisMarkerReceiptSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub marker_ref_chirho: GeoGenesisIntentDigestChirho,
    pub holder_chirho: GeoMarkerHolderV1Chirho,
    pub durable_at_chirho: GeoUtcMinuteChirho,
    pub receipt_signer_key_chirho: GeoEd25519PublicKeyChirho,
    pub signature_chirho: GeoEd25519SignatureChirho,
}

/// The explicit unsigned companion of the marker receipt (design section 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedGeoGenesisMarkerReceiptV1Chirho {
    pub schema_chirho: GeoGenesisMarkerReceiptSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub marker_ref_chirho: GeoGenesisIntentDigestChirho,
    pub holder_chirho: GeoMarkerHolderV1Chirho,
    pub durable_at_chirho: GeoUtcMinuteChirho,
    pub receipt_signer_key_chirho: GeoEd25519PublicKeyChirho,
}

impl GeoGenesisMarkerReceiptV1Chirho {
    /// The explicit unsigned view (design section 10).
    pub fn to_unsigned_chirho(&self) -> UnsignedGeoGenesisMarkerReceiptV1Chirho {
        UnsignedGeoGenesisMarkerReceiptV1Chirho {
            schema_chirho: self.schema_chirho,
            instance_id_chirho: self.instance_id_chirho,
            plan_ref_chirho: self.plan_ref_chirho,
            marker_ref_chirho: self.marker_ref_chirho,
            holder_chirho: self.holder_chirho,
            durable_at_chirho: self.durable_at_chirho,
            receipt_signer_key_chirho: self.receipt_signer_key_chirho,
        }
    }
}

/// The complete verified intent marker set (design section 7.2): the operator-guard receipt plus the
/// sorted member-marker receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoIntentMarkerSetV1Chirho {
    pub marker_ref_chirho: GeoGenesisIntentDigestChirho,
    pub operator_guard_chirho: GeoGenesisMarkerReceiptV1Chirho,
    pub member_markers_chirho: Vec<GeoGenesisMarkerReceiptV1Chirho>,
}

impl GeoIntentMarkerSetV1Chirho {
    /// Structural validation: the operator-guard slot holds an operator-guard receipt, every member
    /// slot holds a member receipt, and the member markers are a bounded, ascending-unique set by
    /// their holder's Raft id and node key. Binding the set to the plan population is 8.2c.
    pub fn validate_structural_chirho(&self) -> GeoGenesisResultChirho<()> {
        if !self
            .operator_guard_chirho
            .holder_chirho
            .is_operator_guard_chirho()
        {
            return Err(GeoGenesisRefusalChirho::MarkerHolderKindRefusedChirho);
        }
        let count_chirho = self.member_markers_chirho.len();
        if !(GEO_MIN_MEMBERS_CHIRHO..=GEO_MAX_MEMBERS_CHIRHO).contains(&count_chirho) {
            return Err(GeoGenesisRefusalChirho::SetCountOutOfRangeChirho);
        }
        let mut previous_raft_chirho: Option<GeoRaftIdChirho> = None;
        let mut node_keys_chirho = BTreeSet::new();
        for marker_chirho in &self.member_markers_chirho {
            let (raft_chirho, node_key_chirho) = marker_chirho
                .holder_chirho
                .member_coordinates_chirho()
                .ok_or(GeoGenesisRefusalChirho::MarkerHolderKindRefusedChirho)?;
            if let Some(previous_chirho) = previous_raft_chirho {
                if raft_chirho <= previous_chirho {
                    return Err(GeoGenesisRefusalChirho::MembersNotSortedChirho);
                }
            }
            previous_raft_chirho = Some(raft_chirho);
            if !node_keys_chirho.insert(node_key_chirho) {
                return Err(GeoGenesisRefusalChirho::DuplicateMemberCoordinateChirho {
                    coordinate_chirho: GeoMemberCoordinateChirho::NodeKeyChirho,
                });
            }
        }
        Ok(())
    }
}

/// Closed publication-receipt schema token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisPublicationReceiptSchemaChirho {
    V1Chirho,
}

/// The single authoritative ledger-publication receipt (design section 7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGenesisPublicationReceiptV1Chirho {
    pub schema_chirho: GeoGenesisPublicationReceiptSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub marker_ref_chirho: GeoGenesisIntentDigestChirho,
    pub ledger_plan_chirho: GeoLedgerRegenesisPlanDigestChirho,
    pub fresh_root_identity_chirho: GeoFreshRootIdentityChirho,
    pub ledger_publication_manifest_chirho: GeoLedgerPublicationManifestDigestChirho,
    pub published_epoch_chirho: u64,
    pub published_at_chirho: GeoUtcMinuteChirho,
    pub phase_chirho: GeoGenesisPhaseChirho,
    pub receipt_signer_key_chirho: GeoEd25519PublicKeyChirho,
    pub signature_chirho: GeoEd25519SignatureChirho,
}

/// The explicit unsigned companion of the publication receipt (design section 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedGeoGenesisPublicationReceiptV1Chirho {
    pub schema_chirho: GeoGenesisPublicationReceiptSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub marker_ref_chirho: GeoGenesisIntentDigestChirho,
    pub ledger_plan_chirho: GeoLedgerRegenesisPlanDigestChirho,
    pub fresh_root_identity_chirho: GeoFreshRootIdentityChirho,
    pub ledger_publication_manifest_chirho: GeoLedgerPublicationManifestDigestChirho,
    pub published_epoch_chirho: u64,
    pub published_at_chirho: GeoUtcMinuteChirho,
    pub phase_chirho: GeoGenesisPhaseChirho,
    pub receipt_signer_key_chirho: GeoEd25519PublicKeyChirho,
}

impl GeoGenesisPublicationReceiptV1Chirho {
    /// The explicit unsigned view (design section 10).
    pub fn to_unsigned_chirho(&self) -> UnsignedGeoGenesisPublicationReceiptV1Chirho {
        UnsignedGeoGenesisPublicationReceiptV1Chirho {
            schema_chirho: self.schema_chirho,
            instance_id_chirho: self.instance_id_chirho,
            plan_ref_chirho: self.plan_ref_chirho,
            marker_ref_chirho: self.marker_ref_chirho,
            ledger_plan_chirho: self.ledger_plan_chirho,
            fresh_root_identity_chirho: self.fresh_root_identity_chirho,
            ledger_publication_manifest_chirho: self.ledger_publication_manifest_chirho,
            published_epoch_chirho: self.published_epoch_chirho,
            published_at_chirho: self.published_at_chirho,
            phase_chirho: self.phase_chirho,
            receipt_signer_key_chirho: self.receipt_signer_key_chirho,
        }
    }

    /// Structural validation: the fixed phase is `RootPublishedChirho`.
    pub fn validate_structural_chirho(&self) -> GeoGenesisResultChirho<()> {
        require_phase_chirho(
            self.phase_chirho,
            GeoGenesisPhaseChirho::RootPublishedChirho,
        )
    }
}

/// Closed member-admission-receipt schema token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisMemberAdmissionReceiptSchemaChirho {
    V1Chirho,
}

/// A single planned member's admission receipt (design section 7.2). Its phase is admitted-by-type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGenesisMemberAdmissionReceiptV1Chirho {
    pub schema_chirho: GeoGenesisMemberAdmissionReceiptSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub marker_ref_chirho: GeoGenesisIntentDigestChirho,
    pub fresh_root_identity_chirho: GeoFreshRootIdentityChirho,
    pub consistency_group_chirho: GeoConsistencyGroupDigestChirho,
    pub tenant_root_chirho: GeoTenantRootIdentityChirho,
    pub role_chirho: GeoMemberRoleChirho,
    pub raft_id_chirho: GeoRaftIdChirho,
    pub node_key_chirho: GeoEd25519PublicKeyChirho,
    pub winner_term_chirho: GeoElectionTermChirho,
    pub applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho,
    pub applied_conf_index_chirho: GeoAppliedConfIndexChirho,
    pub build_evidence_ref_chirho: GeoNodeBuildEvidenceRefChirho,
    pub config_evidence_ref_chirho: GeoNodeConfigEvidenceRefChirho,
    pub admitted_at_chirho: GeoUtcMinuteChirho,
    pub phase_chirho: GeoMemberAdmissionPhaseChirho,
    pub receipt_signer_key_chirho: GeoEd25519PublicKeyChirho,
    pub signature_chirho: GeoEd25519SignatureChirho,
}

/// The explicit unsigned companion of the member-admission receipt (design section 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedGeoGenesisMemberAdmissionReceiptV1Chirho {
    pub schema_chirho: GeoGenesisMemberAdmissionReceiptSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub marker_ref_chirho: GeoGenesisIntentDigestChirho,
    pub fresh_root_identity_chirho: GeoFreshRootIdentityChirho,
    pub consistency_group_chirho: GeoConsistencyGroupDigestChirho,
    pub tenant_root_chirho: GeoTenantRootIdentityChirho,
    pub role_chirho: GeoMemberRoleChirho,
    pub raft_id_chirho: GeoRaftIdChirho,
    pub node_key_chirho: GeoEd25519PublicKeyChirho,
    pub winner_term_chirho: GeoElectionTermChirho,
    pub applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho,
    pub applied_conf_index_chirho: GeoAppliedConfIndexChirho,
    pub build_evidence_ref_chirho: GeoNodeBuildEvidenceRefChirho,
    pub config_evidence_ref_chirho: GeoNodeConfigEvidenceRefChirho,
    pub admitted_at_chirho: GeoUtcMinuteChirho,
    pub phase_chirho: GeoMemberAdmissionPhaseChirho,
    pub receipt_signer_key_chirho: GeoEd25519PublicKeyChirho,
}

impl GeoGenesisMemberAdmissionReceiptV1Chirho {
    /// The explicit unsigned view (design section 10).
    pub fn to_unsigned_chirho(&self) -> UnsignedGeoGenesisMemberAdmissionReceiptV1Chirho {
        UnsignedGeoGenesisMemberAdmissionReceiptV1Chirho {
            schema_chirho: self.schema_chirho,
            instance_id_chirho: self.instance_id_chirho,
            plan_ref_chirho: self.plan_ref_chirho,
            marker_ref_chirho: self.marker_ref_chirho,
            fresh_root_identity_chirho: self.fresh_root_identity_chirho,
            consistency_group_chirho: self.consistency_group_chirho,
            tenant_root_chirho: self.tenant_root_chirho,
            role_chirho: self.role_chirho,
            raft_id_chirho: self.raft_id_chirho,
            node_key_chirho: self.node_key_chirho,
            winner_term_chirho: self.winner_term_chirho,
            applied_roster_revision_chirho: self.applied_roster_revision_chirho,
            applied_conf_index_chirho: self.applied_conf_index_chirho,
            build_evidence_ref_chirho: self.build_evidence_ref_chirho,
            config_evidence_ref_chirho: self.config_evidence_ref_chirho,
            admitted_at_chirho: self.admitted_at_chirho,
            phase_chirho: self.phase_chirho,
            receipt_signer_key_chirho: self.receipt_signer_key_chirho,
        }
    }
}

/// The publication result and its admitted topology (design section 7.2): one authoritative-root
/// receipt plus the sorted member-admission receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoRootPublicationSetV1Chirho {
    pub authoritative_root_chirho: GeoGenesisPublicationReceiptV1Chirho,
    pub member_admissions_chirho: Vec<GeoGenesisMemberAdmissionReceiptV1Chirho>,
}

impl GeoRootPublicationSetV1Chirho {
    /// Structural validation: the root receipt's fixed phase plus a bounded, ascending-unique
    /// admission set by Raft id and node key. Binding the admissions to the plan population is 8.2b.
    pub fn validate_structural_chirho(&self) -> GeoGenesisResultChirho<()> {
        self.authoritative_root_chirho
            .validate_structural_chirho()?;
        validate_admission_set_chirho(&self.member_admissions_chirho)
    }
}

/// Bounded, ascending-unique admission-set check by Raft id and node key.
pub(crate) fn validate_admission_set_chirho(
    admissions_chirho: &[GeoGenesisMemberAdmissionReceiptV1Chirho],
) -> GeoGenesisResultChirho<()> {
    if !(GEO_MIN_MEMBERS_CHIRHO..=GEO_MAX_MEMBERS_CHIRHO).contains(&admissions_chirho.len()) {
        return Err(GeoGenesisRefusalChirho::SetCountOutOfRangeChirho);
    }
    if !admissions_chirho
        .windows(2)
        .all(|pair_chirho| pair_chirho[0].raft_id_chirho < pair_chirho[1].raft_id_chirho)
    {
        return Err(GeoGenesisRefusalChirho::MembersNotSortedChirho);
    }
    let mut node_keys_chirho = BTreeSet::new();
    for admission_chirho in admissions_chirho {
        if !node_keys_chirho.insert(admission_chirho.node_key_chirho) {
            return Err(GeoGenesisRefusalChirho::DuplicateMemberCoordinateChirho {
                coordinate_chirho: GeoMemberCoordinateChirho::NodeKeyChirho,
            });
        }
    }
    Ok(())
}

fn require_phase_chirho(
    actual_chirho: GeoGenesisPhaseChirho,
    expected_chirho: GeoGenesisPhaseChirho,
) -> GeoGenesisResultChirho<()> {
    if actual_chirho == expected_chirho {
        Ok(())
    } else {
        Err(GeoGenesisRefusalChirho::PhaseRefusedChirho)
    }
}

/// Parse a candidate intent marker for review: wire law plus the fixed-phase check.
pub fn parse_canonical_intent_chirho(
    bytes_chirho: &[u8],
) -> GeoGenesisResultChirho<AuthoritativeGeoGenesisIntentV1Chirho> {
    let intent_chirho: AuthoritativeGeoGenesisIntentV1Chirho =
        parse_canonical_chirho(bytes_chirho)?;
    intent_chirho.validate_structural_chirho()?;
    Ok(intent_chirho)
}
