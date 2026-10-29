// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The sink-side winner-term fence: a write target refuses any term that is not strictly current.
//!
//! Design:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`
//! :738-740 and :794-795. Modelled and mutation-proven in
//! `cairn-ledger-sim-chirho::model_gd7_reconciliation_chirho` (`AppendAtSinkChirho` :1124,
//! `RevokeBarrierChirho` :1101, `RestartSinkChirho` :1112). **The model is the spec; this is a port,
//! not a re-derivation.**
//!
//! # THERE ARE TWO WINNER TERMS IN ITEM 5. THIS FENCE TAKES THE SECOND ONE.
//!
//! Both are called "winner term" in conversation and they are deliberately different coordinates.
//! Taking the wrong one produces a fence that refuses ALL correct traffic while passing every test in
//! this module, so the distinction is written here rather than left to a reader's inference.
//!
//! - **HISTORICAL winner term** — carried by the minted obligation. It records WHICH FORK the losing
//!   effect came from. It is evidence about the past, and **by construction it belongs to a deposed
//!   fork**. THIS FENCE MUST NOT COMPARE IT.
//! - **CURRENT winner term** — read as `published_raft_term_chirho` from a fresh resident generation
//!   guard inside the eventual compensation append. `VerifiedEffectCompensationChirho` carries refs,
//!   not a term; those refs must not be dereferenced to manufacture this operand. Any future term
//!   field on that capability is a historical coordinate, not proof of current authority.
//!
//! **The failure mode if the historical term were used is worth stating, because it survives a green
//! suite.** A historical term is by definition from a deposed fork, so it is ALWAYS below the sink's
//! high-water. `StaleWinnerTermChirho` would fire on every legitimate compensation: 100% of correct
//! traffic refused, by name, exactly as specified — unit tests green, refusals well-formed, and
//! nothing compensable at the hosted drill. A liveness failure wearing a safety fence's clothes.
//!
//! The model agrees and nothing here is a reinterpretation of it: `RevokeBarrierChirho` advances both
//! the current term and the sink high-water while the obligation keeps the term it was SIGNED with.
//! That signature term is the authority that signed the append — current at signing, stale if an
//! election intervened before it landed. That is the current coordinate.
//!
//! # THE CHECK IS NOW WIRED — 5b made the paragraph that stood here false
//!
//! This block used to say the check *"has no production operand yet and cannot refuse anything in
//! production."* **That was true until 5b landed and is now wrong.** The compensation append in
//! `resident_authority_chirho.rs` reads this cell under the resident writer lock and runs the check
//! below, scoped by `matches!` to `EffectCompensationHoldChirho` and returning before the append
//! match, so a refusal prevents the append rather than accompanying it.
//!
//! The live term is the generation guard's snapshot, and what makes that snapshot trustworthy is
//! **not** that the guard is still alive — a `u64` copied out of a live thing stops tracking it. It
//! is a positive executed check earlier in the same call: the fence is minted from
//! `prepared_fence_chirho`, its epoch's geo term extracted, and a mismatch against the snapshot
//! returns `FenceTermMismatchChirho`. Reaching the compensation check therefore *implies* the
//! snapshot equals the active fence's own term.
//!
//! ## Reachability, ruled rather than left incidental
//!
//! Only **exact equality** passes. The cell is written at birth and may move mid-life through two
//! evidence-confined production paths: an accepted GD7 winner handoff carrying its verified fork
//! witness, or an ordinary election carrying fresh domain-separated receipts from the exact two
//! non-leader holders that finalized the current local tail. A Bound reopen and a compensation
//! caller's local term remain insufficient. If neither proof exists, a term advance still refuses
//! `UnseenWinnerTermChirho` before the append.
//!
//! Caller census is stated by reachability rather than spelling. The primitive has four production-
//! compiled references: birth recovery, the reached GD7 winner-witness mover, the reached ordinary-
//! election two-holder mover, and one deliberately uncomposed revoke/accept operation in the
//! dead-code-gated GD7 module. Thus three references are production-reachable today. The fourth is
//! not evidence of a fourth authority path merely because it compiles.
//!
//! The capability proves the exact compensation intent and transports its refs. It supplies no
//! fencing term. Only the resident generation guard can supply the live term, and the sink check then
//! compares that term with accepted durable history.
//!
//! # It guards the COMPENSATION path, not all four mutation variants
//!
//! Ordinary appends are already term-fenced locally — `FenceTermMismatchChirho` compares the writer
//! fence's term against the published Raft term inside the same append. Compensation needs winner-term
//! fencing **in addition**, and the reason is the whole point: a compensation obligation may have been
//! minted on a LOSING FORK, and the local writer fence cannot see that. It knows this node's term; it
//! does not know whether the obligation in hand came from a winner the cluster later deposed. Merging
//! the two fences would delete exactly that distinction, so they stay separate.
//!
//! # IT STANDS IN FRONT OF AN IRREVERSIBLE EFFECT, NOT MERELY A JOURNAL ROW
//!
//! Measured in the production ordering: the compensation hold is APPENDED FIRST, and only then does
//! the provider call run. So a refusal at this append **prevents the provider call** rather than
//! discovering afterwards that it should not have happened.
//!
//! The path is OPERATOR-reachable, not merely internal: the CLI's compensation preview/execute entry
//! points reach this append through the coordinator, so the fence stands in front of an irreversible
//! provider call on an operator-initiated spend reversal.
//!
//! That ordering is what makes this a money fence rather than a bookkeeping check, and it is the
//! property the design asks for — the term compared inside the append before either the provider-call
//! counter or the journal-append counter may move. A gate that can only fire AFTER an irreversible
//! external effect cannot prevent anything; it can only strand a half-state. **If anyone ever moves
//! the provider call ahead of the hold append, this fence silently degrades from prevention to
//! after-the-fact detection, and no test in this module would notice.**
//!
//! # Why a sink fence rather than a borrow
//!
//! Protecting against release-between-mint-and-consume has two cures and they are not
//! interchangeable. In-process, a lifetime-bound capability that BORROWS the guard makes early
//! release a borrowck error. **GD7 spans two processes** — the held learner and the resident winner
//! actor talk over a roster-authenticated channel — and no borrow spans that. So the cure is
//! persistent sink state: the write target compares the supplied term against the highest it has
//! **ever accepted** and refuses anything not strictly current.
//!
//! # STRICTLY CURRENT MEANS EQUAL, NOT MERELY NOT-LOWER
//!
//! The comparison is EQUALITY. `>=` is the reading that comes to mind first and it is wrong: it would
//! accept a term ABOVE the highest accepted, which is an election this sink has never seen and
//! therefore never verified. Both directions are refusals, and they are **different refusals** —
//! below means a deposed writer is still trying, above means the sink is behind the cluster. Drill
//! evidence that cannot tell those apart cannot distinguish a stale writer from an unseen election.
//!
//! # THE FENCE MUST NEVER BE ADVANCED BY THE APPEND IT GUARDS
//!
//! This is the trap, and the writer fence next door legitimately does the opposite: it re-issues and
//! atomically writes its own state inside the append, which is safe there because a term-equality
//! check gates it first. **Do not copy that half here.** If an ordinary append advanced this
//! high-water, the fence would become self-authorizing — it would move to whatever the writer
//! claimed, and a stale obligation would carry its own permission. Advance happens ONLY on the
//! verified accept-current-winner path, mirroring `RevokeBarrierChirho`; birth-time
//! create-or-recover is a distinct resident lifecycle operation.
//!
//! # Keyed per consistency group, and genesis is deliberately NOT in the key
//!
//! The resident identity binds and re-verifies genesis separately, so a genesis change already fails
//! closed before append authority opens. The high-water follows the consistency-group authority
//! coordinate and does not duplicate a genesis component in its key.

use super::contract_chirho::consistency_group_digest_suffix_chirho;
use crate::storage_chirho::StableLedgerExclusiveLockGuardChirho;
use anyhow::{Context, Result};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use serde::{Deserialize, Serialize};

/// Directory holding one monotone cell per consistency group.
const SINK_TERM_FENCES_DIR_CHIRHO: &str = "sink-term-fences-chirho";

/// Schema tag of the persisted cell.
const SINK_TERM_FENCE_SCHEMA_CHIRHO: &str = "sink-term-fence-v1-chirho";

/// Bound on the persisted cell, so a corrupt or grown object cannot be read unbounded.
const MAX_SINK_TERM_FENCE_FILE_BYTES_CHIRHO: u64 = 4 * 1024;

/// The logical storage key for one group's fence cell.
///
/// Takes the group DIGEST rather than the group id, because the append has already computed the
/// digest by the time the fence is consulted and recomputing it would put a second derivation of the
/// same coordinate in the tree.
/// **VALIDATES the coordinate and puts only its SUFFIX in the filename. Returns `Result`.**
///
/// The first version took the digest verbatim into `format!` and returned `String`. That was a real
/// defect, found in review and not by any test: a canonical group digest is
/// `writer-fence-group-blake3-chirho:<64 hex>` — **it contains a COLON** — and the storage layer
/// rejects any byte outside ASCII alphanumerics and `- _ . /` as an unsafe logical path. So every
/// PRODUCTION coordinate would have failed at the path check before any I/O, and the fence would have
/// refused 100% of legitimate compensations as a storage error.
///
/// **No test could have caught it, because the fixtures were UNREACHABLE SHAPES.** Every durable arm
/// used `"group-digest-chirho"` and the key-shape arm used `"abc123"` — all colon-free, none
/// production-shaped. A fixture that cannot occur in production tests a function that does not exist.
/// That is the same species as a tamper fixture that does not violate the property it pins.
///
/// **A key builder that cannot fail is one that will eventually be handed something illegal.**
/// Returning `Result` and validating here makes the coordinate legal by construction rather than by
/// the caller having passed something well-formed. `held_transfer_chirho` already derives paths this
/// way from the same helper; this now follows that established pattern instead of inventing one.
pub fn sink_term_fence_storage_key_chirho(group_digest_chirho: &str) -> Result<String> {
    let suffix_chirho =
        consistency_group_digest_suffix_chirho(group_digest_chirho).ok_or_else(|| {
            anyhow::anyhow!(
                "sink term fence coordinate is not a canonical consistency-group digest: expected \
                 the writer-fence group-digest form, refusing to derive a storage key from it"
            )
        })?;
    Ok(format!(
        "{SINK_TERM_FENCES_DIR_CHIRHO}/{suffix_chirho}.json"
    ))
}

/// The persisted high-water mark: the highest winner term this sink has ever accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkTermFenceStateChirho {
    pub schema_chirho: String,
    pub group_digest_chirho: String,
    pub highest_accepted_winner_term_chirho: u64,
}

/// Why the sink refuses a supplied winner term.
///
/// Three distinct names on purpose. A single `TermMismatch` would collapse two opposite situations —
/// a deposed writer that will not stop, and a sink that has not learned about a real election — into
/// one line of drill evidence, and the operator response to those differs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SinkTermFenceRefusalChirho {
    /// Supplied term is BELOW the highest ever accepted: a deposed writer is still trying.
    StaleWinnerTermChirho {
        supplied_term_chirho: u64,
        highest_accepted_term_chirho: u64,
    },
    /// Supplied term is ABOVE the highest ever accepted: an election this sink never accepted.
    UnseenWinnerTermChirho {
        supplied_term_chirho: u64,
        highest_accepted_term_chirho: u64,
    },
    /// No cell exists for this group. Fail closed: a sink that has accepted nothing accepts nothing.
    NoAcceptedWinnerTermChirho { supplied_term_chirho: u64 },
}

impl SinkTermFenceRefusalChirho {
    /// Stable name for evidence and assertions, so a test can pin WHICH refusal fired.
    pub fn name_chirho(&self) -> &'static str {
        match self {
            Self::StaleWinnerTermChirho { .. } => "StaleWinnerTermChirho",
            Self::UnseenWinnerTermChirho { .. } => "UnseenWinnerTermChirho",
            Self::NoAcceptedWinnerTermChirho { .. } => "NoAcceptedWinnerTermChirho",
        }
    }
}

/// The whole fence decision, as a pure function of persisted state and the supplied term.
///
/// Pure on purpose: the decision is testable without a store, and no caller can reach a variant of it
/// that skipped the I/O. `state` is `None` when no cell exists.
pub fn verify_supplied_winner_term_is_strictly_current_chirho(
    state_chirho: Option<&SinkTermFenceStateChirho>,
    supplied_term_chirho: u64,
) -> Result<(), SinkTermFenceRefusalChirho> {
    let Some(state_chirho) = state_chirho else {
        return Err(SinkTermFenceRefusalChirho::NoAcceptedWinnerTermChirho {
            supplied_term_chirho,
        });
    };
    let highest_accepted_term_chirho = state_chirho.highest_accepted_winner_term_chirho;
    if supplied_term_chirho == highest_accepted_term_chirho {
        return Ok(());
    }
    if supplied_term_chirho < highest_accepted_term_chirho {
        return Err(SinkTermFenceRefusalChirho::StaleWinnerTermChirho {
            supplied_term_chirho,
            highest_accepted_term_chirho,
        });
    }
    Err(SinkTermFenceRefusalChirho::UnseenWinnerTermChirho {
        supplied_term_chirho,
        highest_accepted_term_chirho,
    })
}

/// Read one group's fence cell, bounded. `None` when the group has no cell yet.
///
/// Guard-bound like the mutators, and for the same reason: the compensation refusal DECIDES on what
/// this returns, so a reader free to name any storage would leave the decision safe-by-census while
/// the write path beside it is safe-by-construction. There is no legitimate guard-free production
/// reader — the whole population is three files inside this crate, with no CLI, verify, or
/// observability consumer — so `pub` was unearned surface.
pub(crate) fn read_sink_term_fence_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    group_digest_chirho: &str,
) -> Result<Option<SinkTermFenceStateChirho>> {
    let path_chirho =
        StoragePathChirho::new_chirho(sink_term_fence_storage_key_chirho(group_digest_chirho)?);
    let Some(bytes_chirho) = writer_lock_guard_chirho
        .storage_chirho()
        .read_bounded_object_chirho(&path_chirho, MAX_SINK_TERM_FENCE_FILE_BYTES_CHIRHO)
        .with_context(|| format!("read sink term fence for group {group_digest_chirho}"))?
    else {
        return Ok(None);
    };
    let state_chirho: SinkTermFenceStateChirho = serde_json::from_slice(&bytes_chirho)
        .with_context(|| format!("decode sink term fence for group {group_digest_chirho}"))?;
    if state_chirho.schema_chirho != SINK_TERM_FENCE_SCHEMA_CHIRHO {
        anyhow::bail!(
            "sink term fence for group {group_digest_chirho} has schema {}, expected {}",
            state_chirho.schema_chirho,
            SINK_TERM_FENCE_SCHEMA_CHIRHO
        );
    }
    if state_chirho.group_digest_chirho != group_digest_chirho {
        // A cell that names a different group is a misfiled or copied file. Refuse rather than
        // fence one group's appends against another group's term.
        anyhow::bail!(
            "sink term fence at group {group_digest_chirho} names group {}",
            state_chirho.group_digest_chirho
        );
    }
    Ok(Some(state_chirho))
}

/// Create the cell once during the exact Pending-to-Bound resident birth transaction.
///
/// The resident writer-lock witness makes read-then-create indivisible across processes. Existing
/// bytes are never adopted here: fresh birth must distinguish its own new cell from unowned residue,
/// while recovered Pending birth performs that classification before calling this helper.
pub(crate) fn create_sink_term_fence_at_birth_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    group_digest_chirho: &str,
    accepted_term_chirho: u64,
) -> Result<SinkTermFenceStateChirho> {
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .context("verify sink term fence birth writer-lock custody")?;
    if read_sink_term_fence_chirho(writer_lock_guard_chirho, group_digest_chirho)?.is_some() {
        anyhow::bail!("SinkTermFenceAlreadyExistsAtBirthChirho");
    }
    write_and_reread_sink_term_fence_chirho(
        writer_lock_guard_chirho,
        SinkTermFenceStateChirho {
            schema_chirho: SINK_TERM_FENCE_SCHEMA_CHIRHO.to_owned(),
            group_digest_chirho: group_digest_chirho.to_owned(),
            highest_accepted_winner_term_chirho: accepted_term_chirho,
        },
    )
}

/// Advance the high-water mark monotonically under the resident writer lock.
///
/// **CALL THIS ONLY FROM REVIEWED BIRTH OR EVIDENCE-CONFINED ACCEPT-NEW-WINNER MOVERS.** Never let an
/// append advance the fence from its own supplied term: the high-water would follow the writer's
/// claim, and a stale obligation would carry its own permission. The ordinary-election mover may run
/// immediately before a compensation append only after its private, independently verified proof is
/// minted. That is why this is a separate function rather than a side effect of the check above.
///
/// Monotone: a lower or equal term is a no-op success, so a replayed revoke cannot walk the fence
/// backwards. Only a strictly higher term rewrites the cell.
pub(crate) fn advance_accepted_winner_term_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    group_digest_chirho: &str,
    accepted_term_chirho: u64,
) -> Result<SinkTermFenceStateChirho> {
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .context("verify sink term fence advance writer-lock custody")?;
    let existing_chirho =
        read_sink_term_fence_chirho(writer_lock_guard_chirho, group_digest_chirho)?
            .ok_or_else(|| anyhow::anyhow!("SinkTermFenceMissingAtAdvanceChirho"))?;
    if accepted_term_chirho <= existing_chirho.highest_accepted_winner_term_chirho {
        return Ok(existing_chirho);
    }

    write_and_reread_sink_term_fence_chirho(
        writer_lock_guard_chirho,
        SinkTermFenceStateChirho {
            schema_chirho: SINK_TERM_FENCE_SCHEMA_CHIRHO.to_owned(),
            group_digest_chirho: group_digest_chirho.to_owned(),
            highest_accepted_winner_term_chirho: accepted_term_chirho,
        },
    )
}

fn write_and_reread_sink_term_fence_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    next_chirho: SinkTermFenceStateChirho,
) -> Result<SinkTermFenceStateChirho> {
    let bytes_chirho =
        serde_json::to_vec(&next_chirho).context("serialize sink term fence state")?;
    let path_chirho = StoragePathChirho::new_chirho(sink_term_fence_storage_key_chirho(
        &next_chirho.group_digest_chirho,
    )?);
    writer_lock_guard_chirho
        .storage_chirho()
        .atomic_write_chirho(&path_chirho, &bytes_chirho)
        .with_context(|| {
            format!(
                "write sink term fence for group {}",
                next_chirho.group_digest_chirho
            )
        })?;
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .context("verify sink term fence writer-lock custody after write")?;
    let persisted_chirho =
        read_sink_term_fence_chirho(writer_lock_guard_chirho, &next_chirho.group_digest_chirho)?
            .ok_or_else(|| anyhow::anyhow!("SinkTermFenceWriteDisappearedChirho"))?;
    if persisted_chirho != next_chirho {
        anyhow::bail!("SinkTermFenceWriteVerificationMismatchChirho");
    }
    Ok(persisted_chirho)
}

#[cfg(test)]
#[path = "sink_term_fence_tests_chirho.rs"]
mod sink_term_fence_tests_chirho;
