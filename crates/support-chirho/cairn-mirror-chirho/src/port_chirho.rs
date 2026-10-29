// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The mirror holder port: prepare (durably store an inert sealed closure, verify, sign a receipt)
//! and finalize (mark a prepared closure visible after the leader's local commit, sign a receipt).
//!
//! The one structural difference from the write-relay: this port's execute step is
//! durable-store-then-receipt. It NEVER re-enters a served request path and NEVER runs an effect —
//! there is no authority door on the receiver because there is no mutation to authorize, only durable
//! storage of already-sealed bytes. A mirror counts only after the sealed bytes reach their native
//! durable + verified commit and the receipt is signed (RECEIPT_GATED_SERVING / NATIVE_DURABILITY).

use crate::frame_chirho::{FinalizeMirrorReceiptFrameV1Chirho, PrepareMirrorClosureFrameV1Chirho};
use crate::receipt_chirho::MirrorReceiptChirho;
use crate::refusal_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
use cairn_write_relay_chirho::RelayExecutionKnowledgeChirho;
use std::fmt;
/// A durable mirror holder. Implementations authenticate the frame, apply the inverted-leadership
/// authority check, durably store + verify the inert sealed closure, and return a signed receipt.
/// They receive no root mutation callback, run no effect, and never re-enter a served path. The
/// contract is synchronous because the production F1 journal's durability boundary and private HTTP
/// client are synchronous; an async caller may schedule the adapter as blocking I/O.
pub trait MirrorHolderPortChirho: Send + Sync {
    fn prepare_durably_chirho(
        &self,
        frame_chirho: &PrepareMirrorClosureFrameV1Chirho,
    ) -> Result<MirrorReceiptChirho, MirrorHolderFailureChirho>;

    fn finalize_chirho(
        &self,
        frame_chirho: &FinalizeMirrorReceiptFrameV1Chirho,
    ) -> Result<MirrorReceiptChirho, MirrorHolderFailureChirho>;
}

/// A prepare/finalize failure: a named contract refusal, or a transport failure whose durable-store
/// knowledge is fixed here so a post-store ambiguity can never inherit the pre-store default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorHolderFailureChirho {
    ContractChirho(MirrorContractErrorChirho),
    TransportChirho(MirrorTransportFailureChirho),
}

impl MirrorHolderFailureChirho {
    pub fn identity_chirho(&self) -> MirrorRefusalIdentityChirho {
        match self {
            Self::ContractChirho(error_chirho) => error_chirho.identity_chirho(),
            Self::TransportChirho(error_chirho) => error_chirho.identity_chirho(),
        }
    }

    pub fn execution_knowledge_chirho(&self) -> RelayExecutionKnowledgeChirho {
        match self {
            Self::ContractChirho(error_chirho) => error_chirho.execution_knowledge_chirho(),
            Self::TransportChirho(error_chirho) => error_chirho.execution_knowledge_chirho(),
        }
    }
}

impl From<MirrorContractErrorChirho> for MirrorHolderFailureChirho {
    fn from(error_chirho: MirrorContractErrorChirho) -> Self {
        Self::ContractChirho(error_chirho)
    }
}

impl From<MirrorTransportFailureChirho> for MirrorHolderFailureChirho {
    fn from(error_chirho: MirrorTransportFailureChirho) -> Self {
        Self::TransportChirho(error_chirho)
    }
}

impl fmt::Display for MirrorHolderFailureChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractChirho(error_chirho) => error_chirho.fmt(formatter_chirho),
            Self::TransportChirho(error_chirho) => error_chirho.fmt(formatter_chirho),
        }
    }
}

impl std::error::Error for MirrorHolderFailureChirho {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MirrorTransportFailureChirho {
    identity_chirho: MirrorRefusalIdentityChirho,
    execution_knowledge_chirho: RelayExecutionKnowledgeChirho,
}

impl MirrorTransportFailureChirho {
    /// The holder could not be reached before any durable store began: definitely nothing landed.
    pub const fn holder_unavailable_before_store_chirho() -> Self {
        Self {
            identity_chirho: MirrorRefusalIdentityChirho::MirrorHolderUnavailableChirho,
            execution_knowledge_chirho: RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        }
    }

    /// The store may have reached durability but the outcome could not be confirmed: in-doubt.
    pub const fn outcome_ambiguous_after_store_chirho() -> Self {
        Self {
            identity_chirho: MirrorRefusalIdentityChirho::MirrorOutcomeAmbiguousChirho,
            execution_knowledge_chirho: RelayExecutionKnowledgeChirho::MayHaveExecutedChirho,
        }
    }

    pub const fn identity_chirho(self) -> MirrorRefusalIdentityChirho {
        self.identity_chirho
    }

    pub const fn execution_knowledge_chirho(self) -> RelayExecutionKnowledgeChirho {
        self.execution_knowledge_chirho
    }
}

impl fmt::Display for MirrorTransportFailureChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.identity_chirho.as_str_chirho())
    }
}

impl std::error::Error for MirrorTransportFailureChirho {}
