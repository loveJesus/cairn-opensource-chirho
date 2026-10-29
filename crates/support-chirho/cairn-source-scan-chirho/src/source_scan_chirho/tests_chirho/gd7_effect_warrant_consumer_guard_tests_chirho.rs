// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins the reviewed set of production readers of the public effect-warrant projection.
//!
//! The projection stores WARRANTS, not commit receipts: producers publish a signed line BEFORE the
//! money append it warrants, so a crash between the two leaves an orphan line with no journal
//! record. That residue is safe only while every reader resolves its ref from an already-verified
//! record and then looks the warrant up — an orphan is unreachable rather than merely ignored.
//!
//! A NEW production reader is exactly how that stops being true: a consumer that enumerates the
//! store, or that treats "the line is present" as "the effect committed", would convert an inert
//! orphan into a false commitment claim on a money path. This guard fails when the reader set
//! changes, so the next such consumer arrives through review instead of quietly.
//!
//! This is a confinement guard: it gets STRICTER as readers are removed, and it never needs
//! retiring. It pins the SET, not a count, so a reader that moves file is a failure rather than a
//! silent pass.

use super::super::*;
use std::collections::BTreeSet;

/// The read door. Every retrieval of a warrant goes through this one method on the store.
const WARRANT_READ_NEEDLE_CHIRHO: &str = "load_bounded_chirho(";
/// The store type whose presence makes a file a warrant consumer rather than an unrelated user of
/// a similarly named method.
const WARRANT_STORE_NEEDLE_CHIRHO: &str = "RootPublicEffectEvidenceStoreChirho";

/// The reviewed readers, each with the reason it is allowed to read a warrant.
///
/// Adding a row here is a REVIEW ACT: the new consumer must resolve its ref from a verified
/// journal record (or equivalent authority) before loading, and must not enumerate the store.
const REVIEWED_WARRANT_READERS_CHIRHO: &[(&str, &str)] = &[
    (
        "crates/ledger-chirho/cairn-effect-commit-ledger-chirho/src/public_evidence_chirho.rs",
        "the store itself: defines the read door and its store-or-match immutability check",
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/plan_chirho/evidence_adapter_chirho.rs",
        "GD7 plan reader: loads by a ref the reducer took from the VERIFIED losing suffix, then \
         re-verifies signature, recomputes the ref, and checks losing journal-genesis equality",
    ),
    // The resident warrant PUBLISHER is deliberately absent: it never reads the projection itself.
    // Its immutable store-or-match happens inside `store_line_chirho`, so the only reader on the
    // write path is the store. If the publisher ever gains a direct load, that is a new reader and
    // this guard will say so.
    (
        "src/execution_runtime_chirho/effect_chirho/postgres_reversible_chirho/evidence_chirho.rs",
        "CF3 root evidence adapter: its coordinator resolves the journal receipt FIRST and refuses \
         MissingJournalReceiptChirho before any warrant load",
    ),
    (
        "src/execution_runtime_chirho/effect_chirho/llm_served_chirho.rs",
        "served-LLM effect-commit adapter: a second EffectCommitEvidencePortChirho driven by the \
         shared EffectCommitCoordinatorChirho (the reviewed coordinator the CF3 row names), so the \
         intent ref it loads is coordinator-derived, never enumerated; the read is a bounded \
         single-ref lookup (load_bounded_chirho) and commitment is the journal append plus terminal \
         line, never intent-line presence",
    ),
];

fn warrant_reader_paths_chirho() -> BTreeSet<String> {
    let root_chirho = workspace_root_chirho();
    workspace_production_rs_files_chirho()
        .into_iter()
        .filter(|path_chirho| {
            let Ok(raw_chirho) = std::fs::read_to_string(path_chirho) else {
                return false;
            };
            let production_chirho = production_text_chirho(&raw_chirho);
            production_chirho.contains(WARRANT_STORE_NEEDLE_CHIRHO)
                && production_chirho.contains(WARRANT_READ_NEEDLE_CHIRHO)
        })
        .filter_map(|path_chirho| {
            path_chirho
                .strip_prefix(&root_chirho)
                .ok()
                .map(|relative_chirho| relative_chirho.to_string_lossy().replace('\\', "/"))
        })
        .collect()
}

/// The reviewed set is the WHOLE set. A new production reader fails here by name.
#[test]
fn public_effect_warrant_readers_are_exactly_the_reviewed_set_chirho() {
    let reviewed_chirho: BTreeSet<String> = REVIEWED_WARRANT_READERS_CHIRHO
        .iter()
        .map(|(path_chirho, _reason_chirho)| (*path_chirho).to_owned())
        .collect();
    let observed_chirho = warrant_reader_paths_chirho();

    // Positive control: the instrument must be able to see anything at all. A filter that silently
    // matches nothing would pass the set comparison only by being empty on both sides.
    assert!(
        !observed_chirho.is_empty(),
        "the warrant-reader scan found NO production files at all -- the instrument is broken, \
         not the world"
    );

    let unreviewed_chirho: Vec<&String> = observed_chirho.difference(&reviewed_chirho).collect();
    assert!(
        unreviewed_chirho.is_empty(),
        "a NEW production reader of the public effect-warrant projection appeared: {unreviewed_chirho:?}. \
         Warrants are not commit receipts. Before allowing this reader, confirm it resolves its ref \
         from a verified journal record and does not enumerate the store, then add it to \
         REVIEWED_WARRANT_READERS_CHIRHO with that reason."
    );

    let departed_chirho: Vec<&String> = reviewed_chirho.difference(&observed_chirho).collect();
    assert!(
        departed_chirho.is_empty(),
        "a reviewed warrant reader is no longer found at its path: {departed_chirho:?}. If it was \
         deleted, REMOVE its row so this guard tightens; if it MOVED, update the row. A stale row \
         silently shrinks this guard's coverage."
    );
}

/// The store must expose no listing door. Enumeration is the journal's job; a `read_dir` here is
/// how "what committed" would start being answered from warrants.
#[test]
fn public_effect_warrant_store_has_no_enumeration_door_chirho() {
    let store_path_chirho = workspace_root_chirho().join(
        "crates/ledger-chirho/cairn-effect-commit-ledger-chirho/src/public_evidence_chirho.rs",
    );
    assert!(store_path_chirho.is_file(), "warrant store module moved");
    let raw_chirho = std::fs::read_to_string(&store_path_chirho).expect("read warrant store");
    let production_chirho = production_text_chirho(&raw_chirho);

    // Positive control: the needle set is only meaningful if this really is the store.
    assert!(
        production_chirho.contains("fn store_line_chirho("),
        "warrant store module no longer defines its write door -- wrong file or renamed API"
    );
    for enumeration_needle_chirho in ["read_dir", "WalkDir", "glob("] {
        assert!(
            !production_chirho.contains(enumeration_needle_chirho),
            "the warrant store grew an enumeration door ({enumeration_needle_chirho}). Listing \
             warrants invites presence-as-commitment reasoning; enumerate the journal instead."
        );
    }
}
