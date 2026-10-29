// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The mirror's fail-closed named refusals plus its contract error, reusing the write-relay's
//! execution-knowledge conservatism so a pre-durable refusal can never be misread as post-durable.

use cairn_write_relay_chirho::RelayExecutionKnowledgeChirho;
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! define_mirror_refusal_identities_chirho {
    ($( $identity_chirho:ident ),+ $(,)?) => {
        /// Every distinct reason a mirror prepare/finalize can be refused. Each maps to a fixed
        /// string so a refusal is a NAMED outcome, never a bare error, and a receiver never
        /// accept-and-degrades.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum MirrorRefusalIdentityChirho {
            $( $identity_chirho, )+
        }

        impl MirrorRefusalIdentityChirho {
            pub const fn as_str_chirho(self) -> &'static str {
                match self {
                    $( Self::$identity_chirho => stringify!($identity_chirho), )+
                }
            }

            /// The declaration macro derives this slice from the enum variants, so decoding and
            /// round-trip coverage cannot silently omit a newly added identity.
            pub const ALL_CHIRHO: &'static [Self] = &[
                $( Self::$identity_chirho, )+
            ];

            pub fn from_str_chirho(value_chirho: &str) -> Option<Self> {
                Self::ALL_CHIRHO
                    .iter()
                    .copied()
                    .find(|identity_chirho| identity_chirho.as_str_chirho() == value_chirho)
            }
        }
    };
}

define_mirror_refusal_identities_chirho!(
    // Wire / schema shape (reused meanings from the relay envelope contract).
    MirrorWireTooLargeChirho,
    MirrorWireDecodeRefusedChirho,
    MirrorSchemaUnsupportedChirho,
    // Roster / identity.
    MirrorOriginNodeInvalidChirho,
    MirrorOriginUnrosteredChirho,
    MirrorReceiverUnrosteredChirho,
    MirrorConsistencyGroupMismatchChirho,
    MirrorRecipientMismatchChirho,
    // Frame / manifest digest binding.
    MirrorFrameDigestMismatchChirho,
    MirrorManifestDigestMismatchChirho,
    // Authority: the OQ-4 inverted-leadership seam. These are the money/authority refusals.
    MirrorTermInvalidChirho,
    MirrorSenderNotLeaderChirho,
    MirrorLeaseExpiredChirho,
    MirrorRequestSignatureInvalidChirho,
    MirrorMembershipViewMismatchChirho,
    // The two-authority join fires before any frame is read, so an unresolved view stores nothing.
    MirrorPlacementElectionPopulationMismatchChirho,
    MirrorAuthenticatedMemberPopulationIncompleteChirho,
    MirrorAuthenticatedMemberPopulationExcessChirho,
    MirrorAuthenticatedMemberBindingMismatchChirho,
    MirrorAuthenticatedMemberIdentityRefusedChirho,
    MirrorElectionRoleResolutionRefusedChirho,
    MirrorElectedLeaderUnassignedChirho,
    MirrorElectionTopologyMismatchChirho,
    // Idempotency layering (the mirror-internal key never substitutes for the caller key).
    MirrorCallerKeyMissingChirho,
    MirrorCallerKeyInvalidChirho,
    // Sealed closure / privacy.
    MirrorClosureUnverifiedChirho,
    MirrorSealedFamilyIncompleteChirho,
    MirrorKeyBytesOnWireChirho,
    MirrorCustodyConfirmationMissingChirho,
    // N3_SPREAD holder-set selection (fail-closed, no accept-and-degrade).
    MirrorHolderSetUnsatisfiableChirho,
    MirrorRegionSpreadUnsatisfiedChirho,
    MirrorResidencyVetoChirho,
    // Receipt authentication.
    MirrorReceiptDigestMismatchChirho,
    MirrorReceiptAuthenticationRefusedChirho,
    // Holder-side durable state and positional prepare/finalize outcomes. These identities keep a
    // pre-commit refusal distinct from a durable write whose receipt could not be returned.
    MirrorPreparedSlotUnreadableChirho,
    MirrorFinalizedHighWaterUnreadableChirho,
    MirrorPreparedSlotVerificationRefusedChirho,
    MirrorPreparedSlotUnavailableChirho,
    MirrorFinalizePreparedBindingRefusedChirho,
    MirrorFinalizedReplayBindingRefusedChirho,
    MirrorAssignedNodePopulationRefusedChirho,
    // Holder-store prepare refusals raised STRICTLY BEFORE the prepared slot is written. They keep
    // the safe definitely-not-executed default, and they exist so a deterministic pre-durable
    // refusal is not reported as an in-doubt one. A poisoned lock or an unreadable store is
    // deliberately NOT in this family: a panic mid-write cannot prove nothing landed, so those stay
    // on the conservative ambiguous identity below.
    MirrorPrepareFollowerContinuityRefusedChirho,
    MirrorPrepareFollowerHighWaterMissingChirho,
    MirrorPrepareFollowerGenesisContinuityRefusedChirho,
    MirrorPrepareFinalizedReplayBindingRefusedChirho,
    MirrorPrepareStoreOutcomeAmbiguousChirho,
    MirrorPrepareReceiptEvidencePendingChirho,
    MirrorFinalizeEvidenceConstructionRefusedChirho,
    MirrorFinalizeStoreOutcomeAmbiguousChirho,
    MirrorFinalizeCommittedEvidencePendingChirho,
    // Transport / in-doubt.
    MirrorHolderUnavailableChirho,
    MirrorOutcomeAmbiguousChirho,
);

/// A mirror refusal carrying its named identity, a fixed detail, and whether the durable prepare
/// might already have landed. Modeled on `RelayContractErrorChirho`: the default is
/// `DefinitelyNotExecutedChirho`, so a new refusal is safe (no durable state) unless it is explicitly
/// marked post-durable. "Executed" for the mirror means "the inert closure reached durable storage",
/// never "an effect ran" — the mirror never runs an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorContractErrorChirho {
    identity_chirho: MirrorRefusalIdentityChirho,
    detail_chirho: &'static str,
    execution_knowledge_chirho: RelayExecutionKnowledgeChirho,
}

impl MirrorContractErrorChirho {
    pub const fn new_chirho(
        identity_chirho: MirrorRefusalIdentityChirho,
        detail_chirho: &'static str,
    ) -> Self {
        Self {
            identity_chirho,
            detail_chirho,
            execution_knowledge_chirho: RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        }
    }

    /// Mark this refusal as raised AFTER the inert closure may have reached durable storage, so a
    /// retry treats the prepare as in-doubt rather than as a clean pre-durable refusal.
    pub const fn after_prepare_may_be_durable_chirho(mut self) -> Self {
        self.execution_knowledge_chirho = RelayExecutionKnowledgeChirho::MayHaveExecutedChirho;
        self
    }

    pub const fn identity_chirho(&self) -> MirrorRefusalIdentityChirho {
        self.identity_chirho
    }

    pub const fn detail_chirho(&self) -> &'static str {
        self.detail_chirho
    }

    pub const fn execution_knowledge_chirho(&self) -> RelayExecutionKnowledgeChirho {
        self.execution_knowledge_chirho
    }

    pub const fn caller_key_missing_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorCallerKeyMissingChirho,
            "mirror prepare has no caller idempotency key; the mirror-internal key does not substitute",
        )
    }

    pub const fn holder_set_unsatisfiable_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorHolderSetUnsatisfiableChirho,
            "the fixed N3_SPREAD 3-holder set cannot be formed; the write refuses (no accept-and-degrade)",
        )
    }

    pub const fn region_spread_unsatisfied_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorRegionSpreadUnsatisfiedChirho,
            "no policy-allowed foreign-region holder is available for the required failure-domain spread",
        )
    }

    pub const fn sender_not_leader_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorSenderNotLeaderChirho,
            "the frame origin is not the current leader for the group at the bound term in the receiver's view",
        )
    }

    pub const fn placement_election_population_mismatch_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorPlacementElectionPopulationMismatchChirho,
            "the verified tenant placement and live election do not name the same exact serving population",
        )
    }

    pub const fn authenticated_member_population_incomplete_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberPopulationIncompleteChirho,
            "the live authenticated transport population is smaller than the exact mirror topology",
        )
    }

    pub const fn authenticated_member_population_excess_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberPopulationExcessChirho,
            "the live authenticated transport population is larger than the exact mirror topology",
        )
    }

    pub const fn authenticated_member_binding_mismatch_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberBindingMismatchChirho,
            "the live authenticated transport members do not equal the placement-bound transport set",
        )
    }

    pub const fn authenticated_member_identity_refused_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberIdentityRefusedChirho,
            "the live authenticated member map contains an invalid or duplicate durable identity",
        )
    }

    pub const fn election_role_resolution_refused_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorElectionRoleResolutionRefusedChirho,
            "the live election role map names an unknown or duplicate authenticated member",
        )
    }

    pub const fn elected_leader_unassigned_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorElectedLeaderUnassignedChirho,
            "the live election names a leader outside the placement-authorized serving set",
        )
    }

    pub const fn election_topology_mismatch_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorElectionTopologyMismatchChirho,
            "the live authenticated voter/learner topology is not exactly three placement voters plus its held observer",
        )
    }

    pub const fn residency_veto_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorResidencyVetoChirho,
            "tenant residency policy vetoes at least one placement-selected mirror holder",
        )
    }

    pub const fn receiver_unrostered_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorReceiverUnrosteredChirho,
            "this receiver is not a rostered member of the exact joined view the frame binds",
        )
    }

    pub const fn term_invalid_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorTermInvalidChirho,
            "the frame's bound term is stale relative to the receiver's known current term",
        )
    }

    pub const fn lease_expired_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorLeaseExpiredChirho,
            "the leader's remaining-duration lease is absent, unparseable, or exhausted at receipt",
        )
    }

    pub const fn key_bytes_on_wire_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorKeyBytesOnWireChirho,
            "a sealed member carries a key-material-shaped value where only a short key id is allowed",
        )
    }

    pub const fn custody_confirmation_missing_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorCustodyConfirmationMissingChirho,
            "the key-custody confirmation placeholder is absent or unconfirmed; 7.2a fails closed",
        )
    }

    pub const fn closure_unverified_chirho() -> Self {
        Self::new_chirho(
            MirrorRefusalIdentityChirho::MirrorClosureUnverifiedChirho,
            "durably stored bytes did not re-verify against their content address; the mirror counts absent",
        )
    }

    /// Reconstruct a fixed holder refusal received over HTTP. Identities raised after a durable
    /// prepare remain conservatively in-doubt; all earlier contract refusals retain the safe
    /// definitely-not-executed default.
    pub const fn from_fixed_wire_identity_chirho(
        identity_chirho: MirrorRefusalIdentityChirho,
    ) -> Self {
        let refusal_chirho = Self::new_chirho(
            identity_chirho,
            "the holder returned this fixed detail-free refusal identity",
        );
        match identity_chirho {
            MirrorRefusalIdentityChirho::MirrorPreparedSlotUnreadableChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizedHighWaterUnreadableChirho
            | MirrorRefusalIdentityChirho::MirrorPreparedSlotVerificationRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorPreparedSlotUnavailableChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizePreparedBindingRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizedReplayBindingRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorAssignedNodePopulationRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorPrepareStoreOutcomeAmbiguousChirho
            | MirrorRefusalIdentityChirho::MirrorPrepareReceiptEvidencePendingChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizeEvidenceConstructionRefusedChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizeStoreOutcomeAmbiguousChirho
            | MirrorRefusalIdentityChirho::MirrorFinalizeCommittedEvidencePendingChirho
            | MirrorRefusalIdentityChirho::MirrorOutcomeAmbiguousChirho => {
                refusal_chirho.after_prepare_may_be_durable_chirho()
            }
            _ => refusal_chirho,
        }
    }
}

impl fmt::Display for MirrorContractErrorChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter_chirho,
            "{}: {}",
            self.identity_chirho.as_str_chirho(),
            self.detail_chirho
        )
    }
}

impl std::error::Error for MirrorContractErrorChirho {}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn every_identity_round_trips_through_its_fixed_string_chirho() {
        // A named refusal is only useful if its wire string survives a round trip, because a
        // receiver's signed outcome names the refusal by that exact string. Walk the WHOLE list, not
        // a hand-picked sample; the declaration macro puts every new enum variant in this slice.
        let mut seen_chirho = std::collections::BTreeSet::new();
        for &identity_chirho in MirrorRefusalIdentityChirho::ALL_CHIRHO {
            assert_eq!(
                MirrorRefusalIdentityChirho::from_str_chirho(identity_chirho.as_str_chirho()),
                Some(identity_chirho)
            );
            assert!(
                seen_chirho.insert(identity_chirho.as_str_chirho()),
                "two identities share the fixed string {}; a decoder could not tell them apart",
                identity_chirho.as_str_chirho()
            );
        }
        assert_eq!(
            seen_chirho.len(),
            MirrorRefusalIdentityChirho::ALL_CHIRHO.len(),
            "every identity must contribute one distinct fixed string"
        );
        // An unknown string decodes to None rather than to a neighbouring identity.
        assert_eq!(
            MirrorRefusalIdentityChirho::from_str_chirho("MirrorNoSuchRefusalChirho"),
            None
        );
    }

    #[test]
    fn the_two_authority_join_refusals_are_named_and_pre_durable_chirho() {
        // The join runs before any frame is read, so each of its refusals must state that nothing
        // durable happened — a `MayHaveExecutedChirho` here would make a retry treat a view that was
        // never resolvable as an in-doubt prepare.
        for error_chirho in [
            MirrorContractErrorChirho::placement_election_population_mismatch_chirho(),
            MirrorContractErrorChirho::authenticated_member_population_incomplete_chirho(),
            MirrorContractErrorChirho::authenticated_member_population_excess_chirho(),
            MirrorContractErrorChirho::authenticated_member_binding_mismatch_chirho(),
            MirrorContractErrorChirho::authenticated_member_identity_refused_chirho(),
            MirrorContractErrorChirho::election_role_resolution_refused_chirho(),
            MirrorContractErrorChirho::elected_leader_unassigned_chirho(),
            MirrorContractErrorChirho::election_topology_mismatch_chirho(),
        ] {
            assert_eq!(
                error_chirho.execution_knowledge_chirho(),
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
            );
            assert!(MirrorRefusalIdentityChirho::from_str_chirho(
                error_chirho.identity_chirho().as_str_chirho()
            )
            .is_some());
        }
    }

    #[test]
    fn a_fresh_refusal_defaults_to_definitely_not_durable_chirho() {
        // The safe default: a refusal proves nothing durable landed unless it explicitly says so.
        let error_chirho = MirrorContractErrorChirho::sender_not_leader_chirho();
        assert_eq!(
            error_chirho.execution_knowledge_chirho(),
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
        );
        assert_eq!(
            error_chirho
                .after_prepare_may_be_durable_chirho()
                .execution_knowledge_chirho(),
            RelayExecutionKnowledgeChirho::MayHaveExecutedChirho
        );
    }
}
