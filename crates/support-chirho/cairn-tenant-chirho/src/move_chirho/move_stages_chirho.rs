// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The order a tenant root moves in, and the two windows that must never overlap.
//!
//! CF8 clause 4 asks for *"a crash/retry-safe tenant-root move [that] preserves one writer, complete
//! signed history, projections, privacy-key custody/erasure obligations, and audit coordinates through
//! handoff and source retirement."* Almost all of that is ordering, and ordering is what this module is.
//!
//! **The invariant is ONE WRITER, and it is not the same as one key.** Two copies of a signing key
//! existing at once is SAFE and unavoidable — a move that never had two copies had a moment with zero,
//! which is data loss. Two WRITERS at once is the thing that corrupts a history. So the design keeps
//! the key-copy window deliberately wide and the writer window a single instant:
//!
//! ```text
//! Prepared        writer = SOURCE   key at source only
//! SurfacesCarried writer = SOURCE   key at source only      (bytes at target, unverified authority)
//! CustodyPlaced   writer = SOURCE   key at BOTH             <- deliberate overlap, deliberately safe
//! WriterHandedOff writer = TARGET   key at both             <- the only instant the writer moves
//! SourceRetired   writer = TARGET   key at target only      <- erasure, and only now
//! ```
//!
//! **Custody before handoff, erasure after.** Handing the writer over before the key is at the target
//! leaves a writer that cannot sign; erasing the source before handoff leaves a crash with no key
//! anywhere. Both orderings are refused, and each has its own refusal identity because they are
//! opposite mistakes with opposite fixes.
//!
//! **Crash/retry safety is replay, not a flag.** The stage is DERIVED from the recorded sequence, so a
//! resumed move re-drives from whatever the log says and a stage already recorded is a no-op. Nothing
//! stores "how far did I get" — the only answer that survives a crash between doing and recording is
//! the one the log gives.
//!
//! Pure: no I/O, no clock. Whoever carries bytes and erases keys is an adapter; this says in what order.

use serde::{Deserialize, Serialize};

/// How far a move has got. Ordered, and every transition is one step forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MoveStageChirho {
    /// Nothing has moved. The source is the writer and holds the only key.
    PreparedChirho,
    /// Content is at the target and verified there. No authority has moved.
    SurfacesCarriedChirho,
    /// The target holds the signing key too. The source is STILL the writer.
    CustodyPlacedChirho,
    /// The writer is the target. The single instant authority moves.
    WriterHandedOffChirho,
    /// The source key is erased. Only reachable after handoff.
    SourceRetiredChirho,
}

/// Which side may write. Derived from the stage; never stored separately, so it cannot drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveWriterChirho {
    SourceChirho,
    TargetChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveAdvanceRefusalChirho {
    /// Before any row exists, only `PreparedChirho` can establish the move. Keeping this in the
    /// transition law means append and replay cannot disagree about a special first-row rule.
    FirstStageMustBePreparedChirho { offered_chirho: MoveStageChirho },
    /// A stage that is not the immediate successor. Skipping is how a move ends up with the writer
    /// somewhere the key is not.
    NotTheNextStageChirho {
        current_chirho: MoveStageChirho,
        offered_chirho: MoveStageChirho,
    },
    /// Handing the writer to a target that does not yet hold the key: a writer that cannot sign.
    HandoffBeforeCustodyChirho,
    /// Erasing the source key before the writer moved: a crash here leaves NO key anywhere.
    RetirementBeforeHandoffChirho,
    /// The move already finished. A completed move is not a place to add stages.
    AlreadyRetiredChirho,
}

/// Who may write at this stage. The writer moves at exactly one transition.
pub fn writer_at_chirho(stage_chirho: MoveStageChirho) -> MoveWriterChirho {
    match stage_chirho {
        MoveStageChirho::PreparedChirho
        | MoveStageChirho::SurfacesCarriedChirho
        | MoveStageChirho::CustodyPlacedChirho => MoveWriterChirho::SourceChirho,
        MoveStageChirho::WriterHandedOffChirho | MoveStageChirho::SourceRetiredChirho => {
            MoveWriterChirho::TargetChirho
        }
    }
}

/// Does the SOURCE still hold its signing key at this stage?
///
/// True until retirement, including after handoff. That overlap is the point: the key outlives the
/// authority so that a crash during handoff leaves a recoverable move rather than an unsignable root.
pub fn source_holds_key_at_chirho(stage_chirho: MoveStageChirho) -> bool {
    stage_chirho != MoveStageChirho::SourceRetiredChirho
}

/// Does the TARGET hold the signing key at this stage?
pub fn target_holds_key_at_chirho(stage_chirho: MoveStageChirho) -> bool {
    stage_chirho >= MoveStageChirho::CustodyPlacedChirho
}

fn next_stage_chirho(stage_chirho: MoveStageChirho) -> Option<MoveStageChirho> {
    Some(match stage_chirho {
        MoveStageChirho::PreparedChirho => MoveStageChirho::SurfacesCarriedChirho,
        MoveStageChirho::SurfacesCarriedChirho => MoveStageChirho::CustodyPlacedChirho,
        MoveStageChirho::CustodyPlacedChirho => MoveStageChirho::WriterHandedOffChirho,
        MoveStageChirho::WriterHandedOffChirho => MoveStageChirho::SourceRetiredChirho,
        MoveStageChirho::SourceRetiredChirho => return None,
    })
}

/// Advance one stage, or say precisely why not.
///
/// Re-offering the CURRENT stage is an `Ok` no-op rather than a refusal: a resumed move cannot know
/// whether its last write landed, so re-driving must be safe. That is the same reason the budget's
/// terminal resolution returns its existing outcome instead of erroring.
pub fn advance_stage_chirho(
    current_chirho: Option<MoveStageChirho>,
    offered_chirho: MoveStageChirho,
) -> Result<MoveStageChirho, MoveAdvanceRefusalChirho> {
    let Some(current_chirho) = current_chirho else {
        return if offered_chirho == MoveStageChirho::PreparedChirho {
            Ok(MoveStageChirho::PreparedChirho)
        } else {
            Err(MoveAdvanceRefusalChirho::FirstStageMustBePreparedChirho { offered_chirho })
        };
    };
    if offered_chirho == current_chirho {
        return Ok(current_chirho);
    }
    if current_chirho == MoveStageChirho::SourceRetiredChirho {
        return Err(MoveAdvanceRefusalChirho::AlreadyRetiredChirho);
    }
    // The two orderings that matter get their own identities BEFORE the generic successor check, so an
    // operator is told which mistake they made rather than "wrong stage".
    if offered_chirho == MoveStageChirho::WriterHandedOffChirho
        && !target_holds_key_at_chirho(current_chirho)
    {
        return Err(MoveAdvanceRefusalChirho::HandoffBeforeCustodyChirho);
    }
    if offered_chirho == MoveStageChirho::SourceRetiredChirho
        && writer_at_chirho(current_chirho) != MoveWriterChirho::TargetChirho
    {
        return Err(MoveAdvanceRefusalChirho::RetirementBeforeHandoffChirho);
    }
    match next_stage_chirho(current_chirho) {
        Some(next_chirho) if next_chirho == offered_chirho => Ok(next_chirho),
        _ => Err(MoveAdvanceRefusalChirho::NotTheNextStageChirho {
            current_chirho,
            offered_chirho,
        }),
    }
}

#[cfg(test)]
#[path = "move_stages_tests_chirho.rs"]
mod move_stages_tests_chirho;
