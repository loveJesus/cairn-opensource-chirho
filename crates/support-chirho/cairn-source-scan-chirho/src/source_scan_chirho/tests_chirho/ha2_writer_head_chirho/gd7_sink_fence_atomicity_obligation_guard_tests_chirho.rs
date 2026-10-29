// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The strict-current sink check has no production caller yet, and the design requires that check to
//! be ATOMIC WITH the append rather than merely ordered before it. Lifecycle create/advance callers
//! are intentionally outside this population; this guard fires only when the append check changes.
//!
//! **Why a guard rather than a note.** The obligation was first recorded in a tasklist, which is
//! below all three tiers — construction, guard, census — because a note does not execute. The risk it
//! must catch is specific: item 5b satisfies *"appended first"*, which is easy, natural, and looks
//! correct, and nothing anywhere goes red to raise atomicity. A note cannot catch that; this can.
//!
//! **The design states THREE properties in one clause** and only two were credited when the fence
//! landed — `cf8-gd7-deposed-fork-reconciliation-design-chirho.md:737-740`: *"refuses anything not
//! strictly current — monotonic, persistent across restart, **checked INSIDE the append**."*
//! Strictly-current and persistence are pinned by the fence's own arms. **Inside-the-append is not
//! pinnable today because the fence has no call site** — the property has no subject until 5b wires
//! it, so it is an obligation on the wiring rather than a gap in the fence.
//!
//! **Appended-first is not inside-the-append.** Ordering establishes the check precedes the
//! irreversible provider call; atomicity establishes it cannot be separated from the write. A check
//! sitting immediately *before* an append satisfies the first and leaves a TOCTOU window; only the
//! second closes it.
//!
//! # WHAT THIS GUARD CANNOT CATCH
//!
//! It is a text heuristic over production sources. It sees a **call by name** and cannot see a caller
//! reached through a trait object, a macro expansion, a re-export under another name, or generated
//! code. It also cannot judge *whether* a wiring achieved atomicity — it only forces the question to
//! be asked out loud at the moment the first caller appears. **A green run here means no production
//! caller was found by name, not that the fence is safely wired. The watched symbol itself must be
//! found exactly once: an unfindable or renamed needle is a failure, never an empty green census.**
//! The ordering assertion below is likewise a source-order proxy: it does not prove that every
//! anchor belongs to one execution path. That behavioral proof remains a reviewer responsibility.

use super::super::*;

const SINK_TERM_FENCE_MODULE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/sink_term_fence_chirho.rs";

const SINK_FENCE_CHECK_CHIRHO: &str = "verify_supplied_winner_term_is_strictly_current_chirho(";
const RESIDENT_AUTHORITY_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs";
const SINK_TERM_LIFECYCLE_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_lifecycle_chirho.rs";
const ADVANCE_CALL_CHIRHO: &str = "advance_accepted_winner_term_chirho(";

fn assert_ordered_anchors_chirho(source_chirho: &str, anchors_chirho: &[&str]) {
    let mut offset_chirho = 0usize;
    for anchor_chirho in anchors_chirho {
        let Some(relative_offset_chirho) = source_chirho[offset_chirho..].find(anchor_chirho)
        else {
            panic!("missing required ordering anchor: {anchor_chirho}");
        };
        offset_chirho += relative_offset_chirho + anchor_chirho.len();
    }
}

#[test]
fn gd7_sink_fence_check_gains_no_production_caller_without_stating_atomicity_chirho() {
    let mut inspected_fence_files_chirho = 0usize;
    let mut check_definitions_chirho = 0usize;
    let mut compensation_call_sites_chirho = 0usize;
    let mut advance_lifecycle_call_sites_chirho = 0usize;

    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);

        if relative_chirho == SINK_TERM_FENCE_MODULE_CHIRHO {
            inspected_fence_files_chirho += 1;
            check_definitions_chirho += source_chirho.matches(SINK_FENCE_CHECK_CHIRHO).count();
            continue;
        }

        if relative_chirho == RESIDENT_AUTHORITY_PATH_CHIRHO {
            compensation_call_sites_chirho +=
                source_chirho.matches(SINK_FENCE_CHECK_CHIRHO).count();
            assert_ordered_anchors_chirho(
                &source_chirho,
                &[
                    "verify_custody_chirho()",
                    // Guard-derived, not sibling-direct: this anchor is the regression pin against
                    // the authority open decision sliding back to naming a storage of its own while
                    // the write path beside it is safe by construction. If this anchor goes MISSING,
                    // read the call at the compensation check before assuming a reorder: a revert to
                    // `&self.authority_storage_chirho` fails here and that is the intended catch.
                    "read_sink_term_fence_chirho(&writer_lock_guard_chirho",
                    SINK_FENCE_CHECK_CHIRHO,
                    "let append_chirho = match mutation_chirho",
                ],
            );
            continue;
        }

        if relative_chirho == SINK_TERM_LIFECYCLE_PATH_CHIRHO {
            advance_lifecycle_call_sites_chirho +=
                source_chirho.matches(ADVANCE_CALL_CHIRHO).count();
            continue;
        }

        assert!(
            !source_chirho.contains(SINK_FENCE_CHECK_CHIRHO),
            "{relative_chirho} calls {SINK_FENCE_CHECK_CHIRHO} - the strict-current sink check has \
             gained a production caller. THE DESIGN REQUIRES THE CHECK TO BE ATOMIC WITH THE \
             COMPENSATION APPEND, NOT MERELY ORDERED BEFORE IT \
             (cf8-gd7-deposed-fork-reconciliation-design-chirho.md:737-740, 'checked INSIDE the \
             append'). Lifecycle create/advance calls do not satisfy or violate this obligation. If \
             you are wiring item 5b: satisfy append atomicity and retarget this guard to assert it, \
             or report that atomicity is impossible at this seam; do not relax it to ordering and \
             do not delete this arm to get green."
        );
    }

    assert!(
        inspected_fence_files_chirho > 0,
        "the sink term fence module was not found in the production surface; this guard would pass \
         over an empty target set. Resolve the module path rather than deleting the assertion — an \
         unfindable target must be a FAILURE, never a skip, or coverage shrinks while the guard \
         keeps reporting success"
    );
    assert_eq!(
        check_definitions_chirho, 1,
        "the watched strict-current sink check must resolve exactly once inside its module. A rename \
         or missing needle is a FAILURE, not a zero-caller success; resolve the symbol and update \
         this guard rather than shrinking its population"
    );
    assert_eq!(
        compensation_call_sites_chirho, 1,
        "the strict-current sink check must have exactly one production compensation caller in \
         the resident authority append module; a missing or extra caller is a wiring failure"
    );
    assert_eq!(
        advance_lifecycle_call_sites_chirho, 1,
        "the lifecycle advance must retain exactly one allowlisted production caller; removing \
         this arm would shrink the guarded mutation population"
    );
}
