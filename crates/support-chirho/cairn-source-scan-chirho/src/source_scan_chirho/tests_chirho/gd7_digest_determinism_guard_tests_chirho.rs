// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The GD7 mint-receipt path is a DIGEST, so the digested types must serialize deterministically.
//!
//! # Why this exists — the failure it guards is BELOW every collision test
//!
//! The GD7 obligation-mint receipt path is derived from the canonical digest of the obligation and
//! its binding. That makes exactly-once depend on one property: **the same semantic obligation must
//! always produce the same bytes.** If it can produce two byte sequences, it produces two digests,
//! two receipt paths, and two receipts — and `AlreadyMinted` never fires.
//!
//! **Every existing collision arm stays green while that happens, because they all compare
//! OBLIGATIONS rather than ENCODINGS.** The hazard lives one layer below the level those tests
//! operate at, which is why it needs its own guard rather than another collision case.
//!
//! Canonicalization here is `serde_json::to_vec` — no key sorting. For a struct over a fixed field
//! set that IS deterministic: serde emits declaration order. It stops being deterministic the moment
//! an unordered collection or a float enters the digested closure. A `HashMap`/`HashSet` has no
//! defined iteration order, so two runs can emit two orderings of one value; floats have multiple
//! textual forms for one number.
//!
//! `#[serde(skip_serializing_if = "Option::is_none")]` is NOT a hazard here and is deliberately not
//! forbidden: `None` always omits and `Some` always emits, so serialization stays a function. What it
//! breaks is injectivity in REVERSE — two byte forms can parse to one value — which bears on a
//! round-trip check, not on one-value-two-digests.
//!
//! # WHAT THIS GUARD CANNOT CATCH — read before trusting a green run
//!
//! It is a TEXT HEURISTIC over NAMED types. It will not see:
//! - a map or float introduced through a **type alias** (`type FooChirho = HashMap<..>`);
//! - one introduced through a **generic parameter** instantiated elsewhere;
//! - one inside a **newly nested type** this guard does not know to follow — the closure list below
//!   is maintained by hand, so a new field of a new type is invisible until someone adds it here.
//!
//! That last one is the real limit: **this guard is only as complete as its closure list.** It is
//! still worth having, because the common regression — someone adds a `HashMap` field to an existing
//! digested struct — is exactly what it catches, and that is the change most likely to be made without
//! thinking about serialization order.

use crate::source_scan_chirho::{
    workspace_production_rs_files_chirho, workspace_relative_chirho, workspace_root_chirho,
};

/// The file holding the GD7 mint types whose digests determine the receipt path.
const OBLIGATION_MINT_SRC_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/plan_chirho/obligation_mint_chirho/mod.rs";

/// Type names in the DIGESTED CLOSURE — the digested value and everything reachable from it.
///
/// Maintained by hand, which is this guard's stated limit. A new nested type must be added here or it
/// is unguarded; the header says so rather than letting a green run imply completeness.
const DIGESTED_CLOSURE_TYPES_CHIRHO: &[&str] = &[
    "Gd7EffectPlanObligationChirho",
    "Gd7LosingEffectObligationBindingChirho",
    "Gd7EffectPlanObligationKindChirho",
    "Gd7EffectLineageChirho",
    "Gd7LosingEffectObligationTerminalStateChirho",
    // Added after the GD7 mint closure: `consistency_group_digest_chirho` is a SECOND
    // `serde_json::to_vec` digest on a KEY-DETERMINING path, and its blast radius is wider than the
    // closure this guard was built for. If this enum ever gains a map or float, the group digest goes
    // non-deterministic, and BOTH the sink term fence and the writer fence lose their stable storage
    // coordinate — with no other arm going red. Measured when added: two `String` variants, no hazard.
    "ConsistencyGroupIdChirho",
];

/// Field types that make `serde_json::to_vec` non-deterministic for one value.
///
/// Not a style list. Each of these has NO single byte form for one semantic value: unordered
/// collections have no defined iteration order, and floats have multiple textual representations.
const NON_DETERMINISTIC_FIELD_TYPES_CHIRHO: &[&str] =
    &["HashMap", "HashSet", "f32", "f64", "BTreeMap<f", "IndexMap"];

fn read_source_chirho(rel_path_chirho: &str) -> String {
    let path_chirho = workspace_root_chirho().join(rel_path_chirho);
    std::fs::read_to_string(&path_chirho)
        .unwrap_or_else(|e_chirho| panic!("read {}: {e_chirho}", path_chirho.display()))
}

/// The body of one type declaration, from its `struct`/`enum` line to the matching close.
///
/// Crude on purpose — brace counting over the declaration is enough to keep one type's fields out of
/// its neighbour's, and a parser here would be more machinery than the check is worth.
fn type_body_chirho(source_chirho: &str, type_name_chirho: &str) -> Option<String> {
    let start_chirho = source_chirho
        .find(&format!("struct {type_name_chirho}"))
        .or_else(|| source_chirho.find(&format!("enum {type_name_chirho}")))?;
    let rest_chirho = &source_chirho[start_chirho..];
    let open_chirho = rest_chirho.find('{')?;
    let mut depth_chirho = 0usize;
    for (index_chirho, char_chirho) in rest_chirho[open_chirho..].char_indices() {
        match char_chirho {
            '{' => depth_chirho += 1,
            '}' => {
                depth_chirho -= 1;
                if depth_chirho == 0 {
                    return Some(rest_chirho[open_chirho..=open_chirho + index_chirho].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// Find one type's declaration ANYWHERE in production source, returning (relative path, body).
///
/// **The first version of this guard read ONE file and the closure spans SEVERAL.** Three of the five
/// types are defined outside the mint module and imported into it, so a single-file search located
/// two and missed three. The unfindable-is-a-failure rule caught that; had unresolved types been a
/// SKIP, the guard would have reported green while covering 40% of its own list — coverage silently
/// shrinking while success is reported, which is the failure this guard's own header warns about.
fn find_type_body_chirho(type_name_chirho: &str) -> Option<(String, String)> {
    for path_chirho in workspace_production_rs_files_chirho() {
        let Ok(source_chirho) = std::fs::read_to_string(&path_chirho) else {
            continue;
        };
        if let Some(body_chirho) = type_body_chirho(&source_chirho, type_name_chirho) {
            return Some((workspace_relative_chirho(&path_chirho), body_chirho));
        }
    }
    None
}

#[test]
fn the_gd7_digested_closure_serializes_deterministically_chirho() {
    // Non-vacuity: an emptied closure list makes the loop run zero times and report green forever.
    assert!(
        DIGESTED_CLOSURE_TYPES_CHIRHO.len() >= 5,
        "the digested-closure list shrank to {} — a shorter list is a NARROWER guard reporting the \
         same success, which is how coverage dies quietly",
        DIGESTED_CLOSURE_TYPES_CHIRHO.len()
    );

    let mut unresolved_chirho = Vec::new();
    for type_name_chirho in DIGESTED_CLOSURE_TYPES_CHIRHO {
        let Some((found_in_chirho, body_chirho)) = find_type_body_chirho(type_name_chirho) else {
            // A type that cannot be found is NOT a pass. It means the name drifted or the type moved,
            // and a guard that silently skips what it cannot locate measures less every year.
            unresolved_chirho.push(*type_name_chirho);
            continue;
        };
        for forbidden_chirho in NON_DETERMINISTIC_FIELD_TYPES_CHIRHO {
            assert!(
                !body_chirho.contains(forbidden_chirho),
                "{type_name_chirho} (in {found_in_chirho}) is in the GD7 DIGESTED closure and now names {forbidden_chirho}. \
                 The mint-receipt path IS the canonical digest, so a value that can serialize two ways \
                 produces two paths, two receipts, and AlreadyMinted never fires — while every \
                 collision test stays green, because those compare obligations rather than encodings. \
                 If this type genuinely needs that field, the digest needs a canonical encoding \
                 first: sort the keys or use an ordered representation, and say so at the digest site"
            );
        }
    }

    assert!(
        unresolved_chirho.is_empty(),
        "these digested-closure types could not be located in {OBLIGATION_MINT_SRC_CHIRHO}: \
         {unresolved_chirho:?}. Either a name drifted or a type moved — RESOLVE it rather than \
         removing it from the list, because deleting an unfindable entry silently shrinks what this \
         guard covers"
    );
}

#[test]
fn positive_control_the_forbidden_needles_and_the_extractor_both_work_chirho() {
    // A guard whose needles cannot fire, or whose extractor returns nothing, is decoration. Prove
    // both halves against known-true inputs so a green run above means "no map found" rather than
    // "the instrument stopped measuring".
    let sample_chirho = "struct SampleChirho {\n    field_chirho: HashMap<String, u64>,\n}";
    let body_chirho =
        type_body_chirho(sample_chirho, "SampleChirho").expect("the extractor must find a struct");
    assert!(
        NON_DETERMINISTIC_FIELD_TYPES_CHIRHO
            .iter()
            .any(|needle_chirho| body_chirho.contains(needle_chirho)),
        "the forbidden-needle list failed its own positive control"
    );
    // And the extractor must NOT bleed into a neighbouring type.
    let two_chirho =
        "struct AChirho {\n    a_chirho: u64,\n}\nstruct BChirho {\n    b_chirho: f64,\n}";
    let a_body_chirho = type_body_chirho(two_chirho, "AChirho").expect("first struct");
    assert!(
        !a_body_chirho.contains("f64"),
        "the extractor bled into the next type — one struct's fields would be attributed to another"
    );
    assert!(
        !NON_DETERMINISTIC_FIELD_TYPES_CHIRHO.is_empty(),
        "the forbidden list emptied out — the loop above would pass over nothing"
    );
    assert!(
        read_source_chirho(OBLIGATION_MINT_SRC_CHIRHO).len() > 500,
        "the mint source read back nearly empty — the guard would pass vacuously"
    );
    let _ = workspace_relative_chirho(&workspace_root_chirho());
}

// -------------------------------------------------------------------------------------------
// The GD7 actor-owned command surface: production caller census.
//
// THE FAMILY SPANS TWO HANDLES, and the header has to say so or the guard's own doc becomes the
// thing that misleads. Six of these methods live on `ResidentEffectJournalHandleChirho`; one,
// `mint_losing_effect_obligation_chirho`, is a HELD-COORDINATOR command on
// `ResidentGd7HeldCoordinatorHandleChirho`. What makes them one family is not their receiver but
// their shape: each is a public wire method whose authority lives entirely inward of an actor
// mailbox send. A reader who took "wire methods on ResidentEffectJournalHandleChirho" literally
// would conclude the mint was out of scope and that this census had not grown when it had.
//
// The GD7 wire methods were widened from `pub(crate)` to `pub` so the custody-verified actor world
// in `cairn-ledger-regenesis-chirho` — a crate DOWNSTREAM of the one that owns them — could drive
// the mailbox at all. Nothing about safety rested on that visibility: a handle is obtainable only
// through the custody-verified opener, and every verification lives inward of the mailbox send. But
// visibility WAS an accidental signal that a new production consumer had appeared, and widening
// removed it.
//
// This census restores that signal as a WATCH rather than a wall. It does not forbid a production
// caller; it makes one impossible to add silently. The triggers those methods are waiting for are
// named and expected — D3's release path and R4's composition surface — and when one arrives, this
// guard fires, the reviewer sees it, and the expected set is updated deliberately.
//
// THE POPULATION GREW FROM FOUR TO FIVE, and that is what this guard is for. The fifth is
// `compose_gd7_compensation_chirho`, which had sat in the actor module as `pub(crate)` under a
// `dead_code` allow naming its own future ("the public composition caller is wired by the later
// GD7 actor integration surface"). The success ladder is that caller, so the method moved into the
// wire-handle file beside its siblings, lost the allow by CONSUMPTION rather than suppression, and
// joined this census in the same commit that widened it. The needle count is deliberately spelled
// as an array length rather than a literal so a future addition cannot silently skip the array.
//
// THEN FROM FIVE TO SIX, by the same mechanism twice over. The sixth is
// `mint_losing_effect_obligation_chirho`, the held coordinator's actor-owned mint trigger. Its
// internal mint carried a `dead_code` allow reading "item 5a deliberately has no production caller
// until item 5b composes mint and consume" — an allow naming its own future exactly as compose's
// did — and that allow likewise died by CONSUMPTION when this command became its caller. The
// pattern is worth naming because it is now twice-observed: on this path a `dead_code` allow that
// names the trigger it is waiting for is a SCHEDULED census entry, not debt.
//
// THEN FROM SIX TO SEVEN, and this one was a MISS rather than a schedule. The seventh is
// `import_converged_compensation_receipt_gd7_chirho`, a `pub` method of the wire-handle file that
// had sat outside this census with no `dead_code` allow at all, so the allow-names-its-trigger
// pattern above had nothing to flag, and a production caller of it would not have tripped this
// guard (found 2026-10-26 by a read-only C1 map). A hand-kept list misses exactly the entry nobody
// announced, so the population is now DERIVED as well as listed:
// `every_pub_wire_handle_method_is_in_the_gd7_census_chirho` fails when the wire-handle file declares
// a `pub` method this array does not name.
// -------------------------------------------------------------------------------------------

/// The seven GD7 actor-owned command methods, each paired with the file its DEFINITION lives in.
///
/// THE HOME FILE IS DATA RATHER THAN PROSE, and that is the census amendment's working half. When
/// the family lived on one handle, "the wire-handle file" could be a single constant and the
/// positive control could assert every needle resolved there. The sixth command is defined on a
/// DIFFERENT handle, so that assertion became false for a correct tree — the classic shape of a
/// guard failing on right code and getting weakened instead of fixed. Pairing each needle with its
/// own home keeps the positive control exact per needle rather than loosening it to "somewhere".
///
/// A definition line matches the same needle a call would, so the expected population is
/// "definitions only" rather than "empty".
const GD7_WIRE_METHOD_NEEDLES_CHIRHO: [(&str, &str); 7] = [
    ("advance_gd7_sink_term_chirho(", GD7_WIRE_HANDLE_FILE_CHIRHO),
    (
        "release_converged_gd7_hold_chirho(",
        GD7_WIRE_HANDLE_FILE_CHIRHO,
    ),
    (
        "complete_gd7_compensation_chirho(",
        GD7_WIRE_HANDLE_FILE_CHIRHO,
    ),
    (
        "converge_and_certify_gd7_chirho(",
        GD7_WIRE_HANDLE_FILE_CHIRHO,
    ),
    (
        "import_converged_compensation_receipt_gd7_chirho(",
        GD7_WIRE_HANDLE_FILE_CHIRHO,
    ),
    (
        "compose_gd7_compensation_chirho(",
        GD7_WIRE_HANDLE_FILE_CHIRHO,
    ),
    (
        "mint_losing_effect_obligation_chirho(",
        GD7_HELD_COORDINATOR_MAILBOX_FILE_CHIRHO,
    ),
];

const GD7_WIRE_HANDLE_FILE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/gd7_wire_handle_chirho.rs";

/// The held coordinator's own mailbox — the second handle this family now spans.
const GD7_HELD_COORDINATOR_MAILBOX_FILE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/mailbox_chirho.rs";

/// Files allowed to mention a wire-method name in production, and why. Anything else is a NEW
/// PRODUCTION CALLER and must be reviewed.
///
/// `release_converged_gd7_hold_chirho` appears on BOTH layers: the handle's wire wrapper and
/// `ResidentLedgerAuthorityChirho`'s authority implementation, which carries the same name one
/// layer inward, plus the dispatch arm that connects them. That is a delegation pattern, not a
/// defect — but it means a raw count of this name is NOT a count of wire callers, and any future
/// reader tightening this guard must resolve the receiver rather than the spelling.
fn gd7_wire_expected_files_chirho() -> Vec<&'static str> {
    vec![
        // The wire wrappers themselves — the definitions the needles necessarily match.
        GD7_WIRE_HANDLE_FILE_CHIRHO,
        // The actor's dispatch arms: inward of the mailbox, reached only by a delivered command.
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/command_dispatch_chirho.rs",
        // The same-named authority implementation one layer in, and the advance's inner entry.
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_append_chirho.rs",
        // The held coordinator's OWN mailbox, which defines the mint command's wire method. Only
        // the mint needle is expected to match here — the other six belong to a different handle
        // and would be a genuine finding if they appeared in this file.
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/mailbox_chirho.rs",
    ]
}

#[test]
fn gd7_wire_methods_have_no_unreviewed_production_callers_chirho() {
    let mut unexpected_chirho = Vec::new();
    let mut total_matches_chirho = 0usize;
    for (needle_chirho, _home_file_chirho) in GD7_WIRE_METHOD_NEEDLES_CHIRHO {
        for (file_chirho, line_chirho, text_chirho) in
            crate::source_scan_chirho::production_source_lines_matching_chirho(needle_chirho)
        {
            total_matches_chirho += 1;
            if !gd7_wire_expected_files_chirho().contains(&file_chirho.as_str()) {
                unexpected_chirho.push((needle_chirho, file_chirho, line_chirho, text_chirho));
            }
        }
    }

    // NON-VACUITY. A census that matched nothing would pass this guard while measuring an empty
    // set — green-by-emptiness, the exact failure this family is prone to. The definitions alone
    // guarantee matches, so zero means the scanner stopped seeing the file, not that the tree is
    // clean.
    assert!(
        total_matches_chirho >= GD7_WIRE_METHOD_NEEDLES_CHIRHO.len(),
        "the census matched {total_matches_chirho} lines for {} needles; at least each definition \
         must match, so this guard is measuring nothing and is not merely green",
        GD7_WIRE_METHOD_NEEDLES_CHIRHO.len()
    );

    assert!(
        unexpected_chirho.is_empty(),
        "NEW PRODUCTION CALLER(S) of a GD7 wire method. This is a reviewed event, not a failure to \
         route around: these methods cross the actor mailbox and their triggers are owned by D3's \
         release path and R4's composition surface. If this caller IS that trigger, add its file to \
         gd7_wire_expected_files_chirho with a reason. If it is not, it should probably be calling \
         the authority implementation one layer inward instead.\nunexpected: {unexpected_chirho:#?}"
    );
}

// -------------------------------------------------------------------------------------------
// The adoption plan-resolution no-fallback census.
//
// `Gd7WinnerHandoffStoreChirho::load_accepted_plan_chirho` used to resolve the held-signed sealed
// plan through a fixed reconciliation group-HEAD read on the WINNER's own storage. That head only
// ever exists on the HELD root, so on a genuine two-root deployment the winner's whole
// adoption-evidence surface refused before it could stage anything. It now resolves by the accepted
// barrier's own checkpoint ref through the content-addressed loader.
//
// THE NO-FALLBACK PROPERTY IS CARRIED BY ABSENCE, WHICH IS WHY IT NEEDS A GUARD. There is no
// "don't fall back" branch to test: the head read is simply gone, so the forbidden path is
// unrepresentable rather than merely unreachable. That is the strongest shape available — and the
// weakest to REGRESSIONS, because re-adding one line restores it silently. A behavioural arm cannot
// cover it either: in a real world the head and the barrier name the SAME sealed plan, so a
// surviving fallback would resolve the identical object and no test could tell.
// -------------------------------------------------------------------------------------------

const GD7_HEAD_LOADER_NEEDLE_CHIRHO: &str =
    "load_authenticated_active_gd7_reconciliation_for_group_chirho(";

const GD7_WINNER_HANDOFF_FILE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/current_view_chirho/winner_handoff_chirho.rs";

#[test]
fn winner_handoff_no_head_fallback_in_adoption_plan_resolution_chirho() {
    // RESOLVE, DO NOT SPELL. The winner-handoff file legitimately NAMES the head loader in
    // `load_accepted_plan_chirho`'s doc comment, which explains what the fix removed and why. A
    // raw count would therefore be 1 and a naive `== 0` guard would fail on correct code — the
    // false-positive that gets a guard weakened instead of fixed. Only CODE lines count.
    let head_loader_code_lines_chirho: Vec<_> =
        crate::source_scan_chirho::production_source_lines_matching_chirho(
            GD7_HEAD_LOADER_NEEDLE_CHIRHO,
        )
        .into_iter()
        .filter(|(file_chirho, _line_chirho, text_chirho)| {
            file_chirho == GD7_WINNER_HANDOFF_FILE_CHIRHO
                && !text_chirho.trim_start().starts_with("//")
        })
        .collect();

    assert!(
        head_loader_code_lines_chirho.is_empty(),
        "THE HEAD FALLBACK CAME BACK. A winner-side group-head read is not a smaller version of \
         the barrier-ref resolution — the append funnel treats a group head as an ACTIVE HOLD by \
         bare presence, never parsed, so putting one in the winner's read path is how the winner \
         strands its own ordinary writes. If a head read is genuinely needed here, that is a \
         reviewed design change and this guard is where it gets reviewed.\nfound: \
         {head_loader_code_lines_chirho:#?}"
    );

    // NON-VACUITY, both halves. The needle must still match SOMEWHERE in production, or the
    // scanner has stopped seeing the loader and the emptiness above says nothing; and the
    // winner-handoff file must still be IN the scanned population, or the filter above could
    // never have matched regardless of what the file contains.
    assert!(
        !crate::source_scan_chirho::production_source_lines_matching_chirho(
            GD7_HEAD_LOADER_NEEDLE_CHIRHO
        )
        .is_empty(),
        "the head loader must still exist somewhere in production — it is the correct reader for \
         held-side paths. Zero matches anywhere means the scanner is blind, not that the tree is \
         clean"
    );
    assert!(
        crate::source_scan_chirho::production_source_lines_matching_chirho(
            "load_accepted_plan_chirho("
        )
        .iter()
        .any(|(file_chirho, _line_chirho, _text_chirho)| file_chirho
            == GD7_WINNER_HANDOFF_FILE_CHIRHO),
        "the winner-handoff file must be in the scanned production population, or the filter in \
         this guard is measuring an empty set by construction"
    );
}

#[test]
fn every_pub_wire_handle_method_is_in_the_gd7_census_chirho() {
    // DERIVE THE POPULATION, DON'T ONLY LIST IT. Every `pub` method the wire-handle file declares
    // is a wire method by that file's own contract, so each must have a needle above; the seventh
    // sat outside the list because nothing announced it.
    let source_chirho = read_source_chirho(GD7_WIRE_HANDLE_FILE_CHIRHO);
    let declared_chirho: Vec<&str> = source_chirho
        .lines()
        .map(str::trim_start)
        .filter(|line_chirho| line_chirho.starts_with("pub ") && line_chirho.contains("fn "))
        .filter_map(|line_chirho| line_chirho.split("fn ").nth(1))
        .map(|rest_chirho| {
            rest_chirho
                .split(['(', '<'])
                .next()
                .unwrap_or_default()
                .trim()
        })
        .collect();
    // NON-VACUITY: a parse that matched nothing would pass this check on any tree.
    assert!(
        !declared_chirho.is_empty(),
        "parsed no `pub` method from the wire-handle file; the parse is broken, not the tree"
    );
    let missing_chirho: Vec<&str> = declared_chirho
        .iter()
        .copied()
        .filter(|name_chirho| {
            !GD7_WIRE_METHOD_NEEDLES_CHIRHO
                .iter()
                .any(|(needle_chirho, _home_chirho)| *needle_chirho == format!("{name_chirho}("))
        })
        .collect();
    assert!(
        missing_chirho.is_empty(),
        "the wire-handle file declares `pub` method(s) this census does not name, so a production \
         caller of them would not trip the guard: {missing_chirho:?}. Add each to \
         GD7_WIRE_METHOD_NEEDLES_CHIRHO with its home file."
    );
}

#[test]
fn positive_control_the_gd7_wire_census_can_see_its_own_definitions_chirho() {
    // Proves the instrument, not the tree: if the scanner's production population ever stops
    // including a defining file, the census above would go quietly green on an empty set.
    //
    // EACH NEEDLE IS CHECKED IN ITS OWN HOME, not in a single shared file. When the sixth command
    // joined the family this control failed on a CORRECT tree, because the mint is defined on the
    // held-coordinator handle rather than the wire handle. The weak repair would have been to accept
    // a hit anywhere; that would have kept the control green while letting a needle silently stop
    // resolving in the file that actually defines it. Pairing each needle with its home keeps the
    // control exactly as strong as it was for one file, across two.
    for (needle_chirho, home_file_chirho) in GD7_WIRE_METHOD_NEEDLES_CHIRHO {
        let hits_chirho =
            crate::source_scan_chirho::production_source_lines_matching_chirho(needle_chirho);
        assert!(
            hits_chirho
                .iter()
                .any(|(file_chirho, _line_chirho, _text_chirho)| file_chirho == home_file_chirho),
            "the census must find {needle_chirho:?} in its OWN defining file {home_file_chirho:?}; \
             not finding it means the scanner is not reading that file and the guard is blind"
        );
    }
}
