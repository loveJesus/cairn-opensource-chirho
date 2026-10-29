// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Every refusal the leader's propagation store answers with: the custody contract's own, or one of the store's, always a fixed name and never a key, subject or path.

use cairn_key_custody_chirho::KeyCustodyErrorChirho;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaderRefusalIdentityChirho {
    /// A requirement at the in-flight seq is already bound: a committed seq is not an in-flight retry.
    ErasureRequirementSeqAlreadyBoundChirho,
    /// The subject's directory holds a seq beyond the in-flight one, or a binding without its
    /// requirement: the root's erasure log is behind this store.
    ErasureRequirementSeqRollbackRefusedChirho,
    /// The root's evidence does not name exactly the subject's unbound earlier seqs.
    ErasureRequirementEvidenceStaleChirho,
    /// A requirement another requirement carries can never be bound itself.
    ErasureRequirementAlreadySucceededChirho,
    /// A binding was asked for a requirement the subject's directory does not hold.
    ErasureRequirementMissingChirho,
    /// The binding already stored names another erasure record.
    ErasureRequirementBindingConflictChirho,
    /// The subject's directory already holds the most requirements it may.
    ErasureRequirementSubjectFullChirho,
    /// A requirement carries one the subject's directory no longer holds, so its coverage would shrink.
    ErasureRequirementCarriedMissingChirho,
    /// A carried requirement is bound, so two terminal readings of it would disagree.
    ErasureRequirementCarriedBoundChirho,
    /// A receipt was offered for a requirement that is not bound, so nothing may be propagated for it.
    ErasureReceiptRequirementUnboundChirho,
    /// A receipt names another group or subject, or a holder the requirement does not name.
    ErasureReceiptNotForRequirementChirho,
    /// A receipt does not close its holder's share by itself, so storing it would only spend a slot.
    ErasureReceiptDoesNotCloseChirho,
    /// Other bytes are already stored at that receipt's path.
    ErasureReceiptConflictChirho,
    /// The holder already has the most receipts one requirement keeps.
    ErasureReceiptHolderFullChirho,
    /// Propagation was asked for a requirement that is not bound: nothing is sent for it on its own.
    ErasurePropagationRequirementUnboundChirho,
    /// This node is not the elected leader with a live lease, so it sends nothing.
    ErasurePropagationNotLeaderChirho,
    /// The current view is another group than the requirement's.
    ErasurePropagationViewGroupMismatchChirho,
    /// The propagation policy asks for more than the design's limits, or for no attempt at all.
    ErasurePropagationPolicyOutOfLimitsChirho,
    /// An attempt's identity names another group, tenant or genesis instance than this store's.
    ErasureAttemptContextMismatchChirho,
    /// The subject holds no requirement with the attempt's requirement digest, or no bound requirement names
    /// the erasure record asked about.
    ErasureAttemptUnknownChirho,
    /// The attempt's requirement is carried by a successor: it is discharged with its carrier and never
    /// propagated on its own.
    ErasureAttemptCarriedChirho,
    /// The attempt's requirement is bound to another erasure record than the identity names.
    ErasureAttemptRecordMismatchChirho,
    /// A subject's directory holds more entries than one scan may read.
    LeaderStoreScanTooLargeChirho,
    /// The store's state is unreadable, out of form, or not where it belongs.
    LeaderStoreUnreadableChirho,
    /// A durable write did not complete.
    LeaderStoreWriteFailedChirho,
    /// The store's lock was asked for while holding a lock the root takes before it.
    LeaderStoreLockOrderRefusedChirho,
    /// The store's lock could not be taken.
    LeaderStoreLockUnavailableChirho,
    /// The root's existing key could not sign, or it is not the store's issuer.
    LeaderSignerUnavailableChirho,
}

impl LeaderRefusalIdentityChirho {
    pub fn as_str_chirho(self) -> &'static str {
        match self {
            Self::ErasureRequirementSeqAlreadyBoundChirho => {
                "ErasureRequirementSeqAlreadyBoundChirho"
            }
            Self::ErasureRequirementSeqRollbackRefusedChirho => {
                "ErasureRequirementSeqRollbackRefusedChirho"
            }
            Self::ErasureRequirementEvidenceStaleChirho => "ErasureRequirementEvidenceStaleChirho",
            Self::ErasureRequirementAlreadySucceededChirho => {
                "ErasureRequirementAlreadySucceededChirho"
            }
            Self::ErasureRequirementMissingChirho => "ErasureRequirementMissingChirho",
            Self::ErasureRequirementBindingConflictChirho => {
                "ErasureRequirementBindingConflictChirho"
            }
            Self::ErasureRequirementSubjectFullChirho => "ErasureRequirementSubjectFullChirho",
            Self::ErasureRequirementCarriedMissingChirho => {
                "ErasureRequirementCarriedMissingChirho"
            }
            Self::ErasureRequirementCarriedBoundChirho => "ErasureRequirementCarriedBoundChirho",
            Self::ErasureReceiptRequirementUnboundChirho => {
                "ErasureReceiptRequirementUnboundChirho"
            }
            Self::ErasureReceiptNotForRequirementChirho => "ErasureReceiptNotForRequirementChirho",
            Self::ErasureReceiptDoesNotCloseChirho => "ErasureReceiptDoesNotCloseChirho",
            Self::ErasureReceiptConflictChirho => "ErasureReceiptConflictChirho",
            Self::ErasureReceiptHolderFullChirho => "ErasureReceiptHolderFullChirho",
            Self::ErasurePropagationRequirementUnboundChirho => {
                "ErasurePropagationRequirementUnboundChirho"
            }
            Self::ErasurePropagationNotLeaderChirho => "ErasurePropagationNotLeaderChirho",
            Self::ErasurePropagationViewGroupMismatchChirho => {
                "ErasurePropagationViewGroupMismatchChirho"
            }
            Self::ErasurePropagationPolicyOutOfLimitsChirho => {
                "ErasurePropagationPolicyOutOfLimitsChirho"
            }
            Self::ErasureAttemptContextMismatchChirho => "ErasureAttemptContextMismatchChirho",
            Self::ErasureAttemptUnknownChirho => "ErasureAttemptUnknownChirho",
            Self::ErasureAttemptCarriedChirho => "ErasureAttemptCarriedChirho",
            Self::ErasureAttemptRecordMismatchChirho => "ErasureAttemptRecordMismatchChirho",
            Self::LeaderStoreScanTooLargeChirho => "LeaderStoreScanTooLargeChirho",
            Self::LeaderStoreUnreadableChirho => "LeaderStoreUnreadableChirho",
            Self::LeaderStoreWriteFailedChirho => "LeaderStoreWriteFailedChirho",
            Self::LeaderStoreLockOrderRefusedChirho => "LeaderStoreLockOrderRefusedChirho",
            Self::LeaderStoreLockUnavailableChirho => "LeaderStoreLockUnavailableChirho",
            Self::LeaderSignerUnavailableChirho => "LeaderSignerUnavailableChirho",
        }
    }
}

/// The store's refusal: the custody contract refused a record, or the store refused or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaderRefusalChirho {
    ContractChirho(KeyCustodyErrorChirho),
    LeaderChirho(LeaderRefusalIdentityChirho),
}

impl LeaderRefusalChirho {
    pub fn leader_identity_chirho(&self) -> Option<LeaderRefusalIdentityChirho> {
        match self {
            Self::ContractChirho(_) => None,
            Self::LeaderChirho(identity_chirho) => Some(*identity_chirho),
        }
    }

    pub fn contract_error_chirho(&self) -> Option<&KeyCustodyErrorChirho> {
        match self {
            Self::ContractChirho(error_chirho) => Some(error_chirho),
            Self::LeaderChirho(_) => None,
        }
    }
}

impl From<KeyCustodyErrorChirho> for LeaderRefusalChirho {
    fn from(error_chirho: KeyCustodyErrorChirho) -> Self {
        Self::ContractChirho(error_chirho)
    }
}

impl From<LeaderRefusalIdentityChirho> for LeaderRefusalChirho {
    fn from(identity_chirho: LeaderRefusalIdentityChirho) -> Self {
        Self::LeaderChirho(identity_chirho)
    }
}

impl fmt::Display for LeaderRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractChirho(error_chirho) => write!(formatter_chirho, "{error_chirho}"),
            Self::LeaderChirho(identity_chirho) => {
                formatter_chirho.write_str(identity_chirho.as_str_chirho())
            }
        }
    }
}

impl std::error::Error for LeaderRefusalChirho {}
