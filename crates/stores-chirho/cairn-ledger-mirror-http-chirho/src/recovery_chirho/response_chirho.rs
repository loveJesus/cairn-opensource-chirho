// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fixed, detail-free holder refusals for the recovery-head HTTP boundary.

use cairn_mirror_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};

macro_rules! define_recovery_head_refusals_chirho {
    ($( $constant_chirho:ident => $wire_chirho:literal ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) struct LedgerMirrorRecoveryHeadRefusalChirho(&'static str);

        impl LedgerMirrorRecoveryHeadRefusalChirho {
            $( pub(crate) const $constant_chirho: Self = Self($wire_chirho); )+

            pub(crate) const ALL_CHIRHO: &'static [Self] = &[
                $( Self::$constant_chirho, )+
            ];

            pub(crate) const fn as_str_chirho(self) -> &'static str {
                self.0
            }

            pub(crate) fn from_wire_bytes_chirho(bytes_chirho: &[u8]) -> Option<Self> {
                Self::ALL_CHIRHO.iter().copied().find(|identity_chirho| {
                    identity_chirho.as_str_chirho().as_bytes() == bytes_chirho
                })
            }
        }
    };
}

define_recovery_head_refusals_chirho!(
    UNAVAILABLE_CHIRHO => "LedgerMirrorRecoveryHeadUnavailableChirho",
    REQUEST_REFUSED_CHIRHO => "LedgerMirrorRecoveryHeadRequestRefusedChirho",
    JOINED_VIEW_REFUSED_CHIRHO => "LedgerMirrorRecoveryHeadJoinedViewRefusedChirho",
    PLACEMENT_ELECTION_POPULATION_MISMATCH_CHIRHO =>
        "LedgerMirrorRecoveryHeadPlacementElectionPopulationMismatchChirho",
    AUTHENTICATED_MEMBER_POPULATION_INCOMPLETE_CHIRHO =>
        "LedgerMirrorRecoveryHeadAuthenticatedMemberPopulationIncompleteChirho",
    AUTHENTICATED_MEMBER_POPULATION_EXCESS_CHIRHO =>
        "LedgerMirrorRecoveryHeadAuthenticatedMemberPopulationExcessChirho",
    AUTHENTICATED_MEMBER_BINDING_MISMATCH_CHIRHO =>
        "LedgerMirrorRecoveryHeadAuthenticatedMemberBindingMismatchChirho",
    AUTHENTICATED_MEMBER_IDENTITY_REFUSED_CHIRHO =>
        "LedgerMirrorRecoveryHeadAuthenticatedMemberIdentityRefusedChirho",
    ELECTION_ROLE_RESOLUTION_REFUSED_CHIRHO =>
        "LedgerMirrorRecoveryHeadElectionRoleResolutionRefusedChirho",
    ELECTED_LEADER_UNASSIGNED_CHIRHO =>
        "LedgerMirrorRecoveryHeadElectedLeaderUnassignedChirho",
    ELECTION_TOPOLOGY_MISMATCH_CHIRHO =>
        "LedgerMirrorRecoveryHeadElectionTopologyMismatchChirho",
    TARGET_NODE_MISMATCH_CHIRHO => "LedgerMirrorRecoveryHeadTargetNodeMismatchChirho",
    CONSISTENCY_GROUP_MISMATCH_CHIRHO =>
        "LedgerMirrorRecoveryHeadConsistencyGroupMismatchChirho",
    ASSIGNMENT_MISMATCH_CHIRHO => "LedgerMirrorRecoveryHeadAssignmentMismatchChirho",
    TERM_MISMATCH_CHIRHO => "LedgerMirrorRecoveryHeadTermMismatchChirho",
    MEMBERSHIP_VIEW_MISMATCH_CHIRHO => "LedgerMirrorRecoveryHeadMembershipViewMismatchChirho",
    REQUESTER_AUTHORITY_REFUSED_CHIRHO =>
        "LedgerMirrorRecoveryHeadRequesterAuthorityRefusedChirho",
    HOLDER_SELECTION_REFUSED_CHIRHO =>
        "LedgerMirrorRecoveryHeadHolderSelectionRefusedChirho",
    SOURCE_READ_REFUSED_CHIRHO => "LedgerMirrorRecoveryHeadSourceReadRefusedChirho",
    RECEIPT_SIGNING_REFUSED_CHIRHO =>
        "LedgerMirrorRecoveryHeadReceiptSigningRefusedChirho",
    RECEIPT_ENCODING_REFUSED_CHIRHO =>
        "LedgerMirrorRecoveryHeadReceiptEncodingRefusedChirho",
);

impl LedgerMirrorRecoveryHeadRefusalChirho {
    pub(crate) const fn from_join_refusal_chirho(
        refusal_chirho: &MirrorContractErrorChirho,
    ) -> Self {
        match refusal_chirho.identity_chirho() {
            MirrorRefusalIdentityChirho::MirrorPlacementElectionPopulationMismatchChirho => {
                Self::PLACEMENT_ELECTION_POPULATION_MISMATCH_CHIRHO
            }
            MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberPopulationIncompleteChirho => {
                Self::AUTHENTICATED_MEMBER_POPULATION_INCOMPLETE_CHIRHO
            }
            MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberPopulationExcessChirho => {
                Self::AUTHENTICATED_MEMBER_POPULATION_EXCESS_CHIRHO
            }
            MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberBindingMismatchChirho => {
                Self::AUTHENTICATED_MEMBER_BINDING_MISMATCH_CHIRHO
            }
            MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberIdentityRefusedChirho => {
                Self::AUTHENTICATED_MEMBER_IDENTITY_REFUSED_CHIRHO
            }
            MirrorRefusalIdentityChirho::MirrorElectionRoleResolutionRefusedChirho => {
                Self::ELECTION_ROLE_RESOLUTION_REFUSED_CHIRHO
            }
            MirrorRefusalIdentityChirho::MirrorElectedLeaderUnassignedChirho => {
                Self::ELECTED_LEADER_UNASSIGNED_CHIRHO
            }
            MirrorRefusalIdentityChirho::MirrorElectionTopologyMismatchChirho => {
                Self::ELECTION_TOPOLOGY_MISMATCH_CHIRHO
            }
            MirrorRefusalIdentityChirho::MirrorWireTooLargeChirho
            | MirrorRefusalIdentityChirho::MirrorWireDecodeRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorSchemaUnsupportedChirho
            | MirrorRefusalIdentityChirho::MirrorOriginNodeInvalidChirho
            | MirrorRefusalIdentityChirho::MirrorOriginUnrosteredChirho
            | MirrorRefusalIdentityChirho::MirrorReceiverUnrosteredChirho
            | MirrorRefusalIdentityChirho::MirrorConsistencyGroupMismatchChirho
            | MirrorRefusalIdentityChirho::MirrorRecipientMismatchChirho
            | MirrorRefusalIdentityChirho::MirrorFrameDigestMismatchChirho
            | MirrorRefusalIdentityChirho::MirrorManifestDigestMismatchChirho
            | MirrorRefusalIdentityChirho::MirrorTermInvalidChirho
            | MirrorRefusalIdentityChirho::MirrorSenderNotLeaderChirho
            | MirrorRefusalIdentityChirho::MirrorLeaseExpiredChirho
            | MirrorRefusalIdentityChirho::MirrorRequestSignatureInvalidChirho
            | MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho
            | MirrorRefusalIdentityChirho::MirrorCallerKeyMissingChirho
            | MirrorRefusalIdentityChirho::MirrorCallerKeyInvalidChirho
            | MirrorRefusalIdentityChirho::MirrorClosureUnverifiedChirho
            | MirrorRefusalIdentityChirho::MirrorSealedFamilyIncompleteChirho
            | MirrorRefusalIdentityChirho::MirrorKeyBytesOnWireChirho
            | MirrorRefusalIdentityChirho::MirrorCustodyConfirmationMissingChirho
            | MirrorRefusalIdentityChirho::MirrorHolderSetUnsatisfiableChirho
            | MirrorRefusalIdentityChirho::MirrorRegionSpreadUnsatisfiedChirho
            | MirrorRefusalIdentityChirho::MirrorResidencyVetoChirho
            | MirrorRefusalIdentityChirho::MirrorReceiptDigestMismatchChirho
            | MirrorRefusalIdentityChirho::MirrorReceiptAuthenticationRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorPreparedSlotUnreadableChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizedHighWaterUnreadableChirho
            | MirrorRefusalIdentityChirho::MirrorPreparedSlotVerificationRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorPreparedSlotUnavailableChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizePreparedBindingRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizedReplayBindingRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorAssignedNodePopulationRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorPrepareFollowerContinuityRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorPrepareFollowerHighWaterMissingChirho
            | MirrorRefusalIdentityChirho::MirrorPrepareFollowerGenesisContinuityRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorPrepareFinalizedReplayBindingRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorPrepareStoreOutcomeAmbiguousChirho
            | MirrorRefusalIdentityChirho::MirrorPrepareReceiptEvidencePendingChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizeEvidenceConstructionRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizeStoreOutcomeAmbiguousChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizeCommittedEvidencePendingChirho
            | MirrorRefusalIdentityChirho::MirrorHolderUnavailableChirho
            | MirrorRefusalIdentityChirho::MirrorOutcomeAmbiguousChirho => {
                Self::JOINED_VIEW_REFUSED_CHIRHO
            }
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn fixed_recovery_refusals_round_trip_and_unknown_bodies_stay_unknown_chirho() {
        for &identity_chirho in LedgerMirrorRecoveryHeadRefusalChirho::ALL_CHIRHO {
            assert_eq!(
                LedgerMirrorRecoveryHeadRefusalChirho::from_wire_bytes_chirho(
                    identity_chirho.as_str_chirho().as_bytes()
                ),
                Some(identity_chirho)
            );
        }
        assert_eq!(
            LedgerMirrorRecoveryHeadRefusalChirho::from_wire_bytes_chirho(
                b"LedgerMirrorRecoveryHeadUnavailableChirhoX"
            ),
            None
        );
    }

    #[test]
    fn every_join_identity_maps_to_its_fixed_recovery_boundary_identity_chirho() {
        for (refusal_chirho, expected_chirho) in [
            (
                MirrorContractErrorChirho::placement_election_population_mismatch_chirho(),
                LedgerMirrorRecoveryHeadRefusalChirho::PLACEMENT_ELECTION_POPULATION_MISMATCH_CHIRHO,
            ),
            (
                MirrorContractErrorChirho::authenticated_member_population_incomplete_chirho(),
                LedgerMirrorRecoveryHeadRefusalChirho::AUTHENTICATED_MEMBER_POPULATION_INCOMPLETE_CHIRHO,
            ),
            (
                MirrorContractErrorChirho::authenticated_member_population_excess_chirho(),
                LedgerMirrorRecoveryHeadRefusalChirho::AUTHENTICATED_MEMBER_POPULATION_EXCESS_CHIRHO,
            ),
            (
                MirrorContractErrorChirho::authenticated_member_binding_mismatch_chirho(),
                LedgerMirrorRecoveryHeadRefusalChirho::AUTHENTICATED_MEMBER_BINDING_MISMATCH_CHIRHO,
            ),
            (
                MirrorContractErrorChirho::authenticated_member_identity_refused_chirho(),
                LedgerMirrorRecoveryHeadRefusalChirho::AUTHENTICATED_MEMBER_IDENTITY_REFUSED_CHIRHO,
            ),
            (
                MirrorContractErrorChirho::election_role_resolution_refused_chirho(),
                LedgerMirrorRecoveryHeadRefusalChirho::ELECTION_ROLE_RESOLUTION_REFUSED_CHIRHO,
            ),
            (
                MirrorContractErrorChirho::elected_leader_unassigned_chirho(),
                LedgerMirrorRecoveryHeadRefusalChirho::ELECTED_LEADER_UNASSIGNED_CHIRHO,
            ),
            (
                MirrorContractErrorChirho::election_topology_mismatch_chirho(),
                LedgerMirrorRecoveryHeadRefusalChirho::ELECTION_TOPOLOGY_MISMATCH_CHIRHO,
            ),
        ] {
            assert_eq!(
                LedgerMirrorRecoveryHeadRefusalChirho::from_join_refusal_chirho(
                    &refusal_chirho
                ),
                expected_chirho
            );
        }
        assert_eq!(
            LedgerMirrorRecoveryHeadRefusalChirho::from_join_refusal_chirho(
                &MirrorContractErrorChirho::sender_not_leader_chirho()
            ),
            LedgerMirrorRecoveryHeadRefusalChirho::JOINED_VIEW_REFUSED_CHIRHO
        );
    }
}
