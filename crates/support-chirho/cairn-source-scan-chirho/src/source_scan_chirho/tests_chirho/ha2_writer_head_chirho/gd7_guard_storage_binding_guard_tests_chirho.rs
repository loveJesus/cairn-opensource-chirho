// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! No production function takes BOTH a storage and a writer-lock guard — the pairing that let a guard
//! authorize a write to a storage it never locked.
//!
//! **What was measured before the binding existed.** A guard acquired on root A's writer-fence lock,
//! handed root B's storage, wrote `highest_accepted_winner_term_chirho: 7` durably to root B's disk
//! with root B's lock never acquired. Positive controls in that arm: two distinct roots, and root B
//! asserted empty first. `verify_custody_chirho()` did not catch it and could not — it proves the
//! guard still holds *its own* descriptor, and says nothing about the storage passed alongside it.
//!
//! **Why a guard and not a test.** The fix put the storage INSIDE the lock, so the mismatched call is
//! now unconstructible — which means there is no runtime behaviour left for a test to assert. But
//! "no mutator takes both" is a property of a **set** (ten signatures at the time of the fix, across
//! two modules), not of one signature. A property of a set is what a source guard holds: it costs no
//! dependency, it catches re-introduction anywhere in the family, and it fires on files nobody thought
//! to check.
//!
//! # WHAT THIS GUARD CANNOT CATCH
//!
//! It is a text heuristic over production sources. It reads a signature as the span from `fn ` to the
//! first `) ->` or `) {`, so a signature whose parameter list contains a nested `) ->` (a closure or
//! fn-pointer parameter) is read short and could hide a pairing. It cannot see a struct that carries
//! both a storage and a guard as FIELDS and passes itself — the pairing would be real and invisible
//! here. And it judges only the shape: a function taking one parameter that internally reaches a
//! foreign storage is outside its reach.
//!
//! **Green here is not proof the binding holds; it is proof no production signature reintroduces the
//! two-parameter shape.** The needle assertion below exists so a rename cannot turn this into an empty
//! green census — an unfindable needle is a FAILURE, never a pass.

use super::super::*;

const GUARD_TYPE_CHIRHO: &str = "StableLedgerExclusiveLockGuardChirho";
const STORAGE_PARAM_CHIRHO: &str = "storage_chirho: &FsLedgerStorageChirho";
const FENCE_MODULE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/sink_term_fence_chirho.rs";
const FENCE_READER_CHIRHO: &str = "fn read_sink_term_fence_chirho(";

/// Signature spans that name both a storage parameter and a writer-lock guard.
fn signatures_pairing_storage_and_guard_chirho(source_chirho: &str) -> Vec<String> {
    let mut offending_chirho = Vec::new();
    let mut cursor_chirho = 0usize;
    while let Some(relative_chirho) = source_chirho[cursor_chirho..].find("fn ") {
        let start_chirho = cursor_chirho + relative_chirho;
        let tail_chirho = &source_chirho[start_chirho..];
        let arrow_chirho = tail_chirho.find(") ->");
        let brace_chirho = tail_chirho.find(") {");
        let end_chirho = match (arrow_chirho, brace_chirho) {
            (Some(arrow_chirho), Some(brace_chirho)) => arrow_chirho.min(brace_chirho),
            (Some(only_chirho), None) | (None, Some(only_chirho)) => only_chirho,
            (None, None) => break,
        };
        let signature_chirho = &tail_chirho[..end_chirho];
        if signature_chirho.contains(GUARD_TYPE_CHIRHO)
            && signature_chirho.contains(STORAGE_PARAM_CHIRHO)
        {
            let name_chirho = signature_chirho
                .lines()
                .next()
                .unwrap_or(signature_chirho)
                .trim()
                .to_owned();
            offending_chirho.push(name_chirho);
        }
        cursor_chirho = start_chirho + 3;
    }
    offending_chirho
}

#[test]
fn no_production_signature_takes_both_a_storage_and_a_writer_lock_guard_chirho() {
    let mut guard_type_mentions_chirho = 0usize;
    let mut offenders_chirho: Vec<(String, String)> = Vec::new();

    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);

        guard_type_mentions_chirho += source_chirho.matches(GUARD_TYPE_CHIRHO).count();
        for signature_chirho in signatures_pairing_storage_and_guard_chirho(&source_chirho) {
            offenders_chirho.push((relative_chirho.clone(), signature_chirho));
        }
    }

    // POSITIVE CONTROL, and it must come first: if the guard type has been renamed or moved out of
    // the production surface, every assertion below passes VACUOUSLY. An unfindable needle is a
    // failure, not a green.
    assert!(
        guard_type_mentions_chirho > 0,
        "{GUARD_TYPE_CHIRHO} was not found anywhere in the production surface, so this guard measured \
         NOTHING. It has been renamed, moved, or gated out. Re-point the needle before trusting any \
         result from this file -- an empty census is not evidence of absence."
    );

    assert!(
        offenders_chirho.is_empty(),
        "a production signature takes BOTH a storage and a writer-lock guard, which is the pairing \
         that let a guard authorize a write to a storage it never locked (measured: a root-A guard \
         wrote term 7 to root B's disk, root B's lock never acquired). The storage now lives INSIDE \
         the lock -- take the guard alone and use writer_lock_guard_chirho.storage_chirho(). \
         Offending signatures: {offenders_chirho:?}"
    );
}

#[test]
fn the_fence_reader_is_guard_bound_and_names_no_storage_of_its_own_chirho() {
    let mut inspected_chirho = 0usize;
    let mut reader_signatures_chirho = 0usize;

    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if relative_chirho != FENCE_MODULE_CHIRHO {
            continue;
        }
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);
        inspected_chirho += 1;

        // Collected rather than looped-and-panicked: the loop form reported only the FIRST
        // offender and read to clippy as a loop that never loops. Naming the whole set is what a
        // reviewer needs, and it makes the empty case an explicit assertion rather than a fallthrough.
        let paired_chirho = signatures_pairing_storage_and_guard_chirho(&source_chirho);
        assert!(
            paired_chirho.is_empty(),
            "fence module signatures pair storage and guard: {paired_chirho:?}"
        );

        let Some(start_chirho) = source_chirho.find(FENCE_READER_CHIRHO) else {
            continue;
        };
        reader_signatures_chirho += 1;
        let tail_chirho = &source_chirho[start_chirho..];
        let end_chirho = tail_chirho
            .find(") ->")
            .expect("fence reader signature must terminate");
        let signature_chirho = &tail_chirho[..end_chirho];
        assert!(
            !signature_chirho.contains("FsLedgerStorageChirho"),
            "read_sink_term_fence_chirho names a storage parameter of its own. The COMPENSATION \
             REFUSAL DECIDES on what this reader returns, so a reader free to name any storage leaves \
             that decision safe-by-census while the write path beside it is safe-by-construction. Take \
             the guard and use writer_lock_guard_chirho.storage_chirho(). Signature: {signature_chirho}"
        );
        assert!(
            signature_chirho.contains(GUARD_TYPE_CHIRHO),
            "read_sink_term_fence_chirho no longer takes a writer-lock guard, so nothing binds the read \
             to a locked storage: {signature_chirho}"
        );
    }

    // POSITIVE CONTROL FIRST, as above: a moved module or renamed reader would make every assertion
    // above pass by never running. An unfindable needle is a failure, not a green.
    assert_eq!(
        inspected_chirho, 1,
        "expected to inspect exactly one fence module at {FENCE_MODULE_CHIRHO}, inspected \
         {inspected_chirho} -- the module moved or left the production surface, so this guard measured \
         nothing"
    );
    assert_eq!(
        reader_signatures_chirho, 1,
        "expected exactly one {FENCE_READER_CHIRHO} definition, found {reader_signatures_chirho} -- \
         renamed or duplicated, either of which makes this guard's result meaningless"
    );
}
