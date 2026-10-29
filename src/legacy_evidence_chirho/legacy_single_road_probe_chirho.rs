// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Refuses an evidence read when the root still carries a Gate-1 authority-mode branch, so a read
//! that assumes one road cannot silently answer from the wrong one.
//!
//! # Why this is its own module
//!
//! All three retained evidence modules — ledger, holds, billing — need this gate BY DESIGN, and none
//! of them reaches it THROUGH another, so it belongs to none of them. Putting it in
//! `legacy_ledger_evidence_chirho` would make a billing→ledger crate edge whose only reason is a
//! shared gate; putting it in a shared *readers* module would fail the one-sentence-per-module rule,
//! because a fail-closed gate is not a reader. (Agreed both seats, #7672.)
//!
//! **The design claim and the code claim differ today, and the time index belongs in this sentence
//! rather than in a paragraph elsewhere:** only the ledger module calls this now, through
//! `verified_entries_single_road_chirho`. Holds and billing rebase onto it in bricks (a2-2) and
//! (a2-3) and do not call it yet. The placement argument above depends only on the design half — but
//! "all three need it" would otherwise be read as "all three call it", which is a false reading of a
//! true sentence.
//!
//! The extraction has an architecture result beyond tidiness: `cairn_model_gate1_chirho` was
//! imported by `legacy_ledger_evidence_chirho` for this probe and for **nothing else**, so the
//! module whose whole purpose is to be road-free stops importing the road.

use crate::refs_chirho;
use anyhow::{bail, Result};
use cairn_model_gate1_chirho::GATE1_AUTHORITY_MODE_BRANCH_CHIRHO;
use std::path::Path;

/// Refuse when the root carries a Gate-1 authority-mode branch at all.
///
/// # What this DOES and DOES NOT know
///
/// **Presence-only, deliberately.** It checks whether the refs branch EXISTS; it does not load or
/// decode the mode record. Decoding would mean verifying that record's signature, which drags the
/// gate1 mode machinery into the modules whose whole purpose is to be free of it — so the richer
/// probe is the one with an attack surface, while a presence check has no signature logic, no
/// checkpoint status, and cannot be fooled. (claude_chirho's argument, and it inverts the instinct
/// that a more thorough check is a safer one.)
///
/// **CONSEQUENCE, RECORDED AS A DECISION RATHER THAN A FOOTNOTE:** a root that was flipped to
/// authority-log and then flipped BACK still carries the branch, so this refuses that root too.
/// That is stricter than the real mode reader. It is correct under fail-closed, and a future reader
/// should meet it as a choice rather than as a bug.
///
/// **The refusal states what was OBSERVED, never what it implies.** This probe does NOT know the
/// root is in authority-log mode — that is precisely the inference it declines to make — so saying
/// so would be a false claim about exactly the flipped-back root above, and would send an operator
/// hunting a state that may not exist.
///
/// # Why refuse rather than warn
///
/// These reads feed the SUBJECT EXPORT path. A warning is only as good as whoever reads it, and the
/// artifact TRAVELS while the warning does not. Refusing a flipped root is recoverable — an operator
/// investigates, and under fresh regenesis there is no such root to refuse. Silently answering from
/// the JSONL when an authority stream may be the real evidence is not: the document is already out.
/// A gate that can only fire after the artifact has left can strand a bad state but never prevent
/// one.
///
/// # Why it is here at all — THREE STATES, not one
///
/// An earlier version of this comment said only "belt-and-braces, NOT a live defence". That is true
/// of the post-deletion world and FALSE TODAY, and the contradiction was caught by a test rather
/// than by reading: this probe changed what a flipped root returns, and the fixture now named
/// `the_dispatcher_rejects_tampered_gate1_authority_rows_chirho` went red on it. A comment the next
/// reader believes must not disagree with a failing test, so all three states are named:
///
/// 1. **INERT in production today.** Every caller of `write_gate1_authority_mode_record_chirho` is a
///    test — the guard-crate fixtures, three `*_tests_chirho.rs` files, and one inside the mode
///    module's OWN `#[cfg(test)] mod tests_chirho`, which a filename-based filter reports as
///    production and which was resolved rather than assumed. So no production read changes.
/// 2. **ACTIVE against TEST-flipped roots today.** Fixtures that call
///    `activate_gate1_authority_for_ledger_test_chirho` build exactly the root this refuses. That is
///    a real present-tense behaviour change, and that retargeted fixture is where it shows.
/// 3. **BELT-AND-BRACES after the deletion**, when neither flipped roots nor the writer exist —
///    `write_gate1_authority_mode_record_chirho` lives inside `src/economic_flows_chirho`, so the
///    creation path goes with it.
///
/// Do not read this as a live production defence, and do not delete it as dead code. It exists
/// because a mechanism cannot expire the way a written acceptance can. Regenesis-compatible: a fresh
/// root carries no such branch, so it never fires on the path actually intended.
pub(crate) fn refuse_if_gate1_authority_branch_present_chirho(root_chirho: &Path) -> Result<()> {
    // A missing refs file is NOT an error here: `load_refs_chirho` returns a default `RefsChirho`
    // with empty branches, which is what makes the regenesis-compatible claim above true rather
    // than fail-closed-but-wrong. If it errored instead, the `?` would refuse every fresh root.
    let loaded_refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    if loaded_refs_chirho
        .branches_chirho
        .contains_key(GATE1_AUTHORITY_MODE_BRANCH_CHIRHO)
    {
        bail!(
            "root carries a gate-1 authority-mode branch ('{GATE1_AUTHORITY_MODE_BRANCH_CHIRHO}'); \
             refusing rather than answering from the JSONL, because this read cannot tell which \
             road is authoritative"
        );
    }
    Ok(())
}
