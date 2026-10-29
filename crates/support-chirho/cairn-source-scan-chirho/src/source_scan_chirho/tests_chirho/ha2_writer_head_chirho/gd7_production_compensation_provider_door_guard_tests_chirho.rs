// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Proves no SHIPPING binary can reach a GD7 compensation-provider door.
//!
//! WHAT THIS BOUNDS, stated as the money/authority invariant it is: the only two openers that hand a
//! completing compensation provider into a resident actor are E-A
//! (`open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho`) and E-B (the
//! winner-side `..._with_shared_elector_and_gd7_compensation_provider_chirho`). A build that can
//! reach either door can autonomously COMPLETE a compensation. The production
//! `cairn-ledger-geo-node-chirho` binary and the `cairn-cli-chirho` binary must therefore be
//! PROVABLY INCAPABLE of naming a provider door: the widening lives only in the distinct
//! `cairn-ledger-geo-node-testkind-chirho` crate, and this census fails if any shipping file joins
//! the door's caller population.
//!
//! HONEST SCOPE, so nobody reads this wider than it is. It is anti-mistake, not anti-adversary: it
//! keys on the door's own CALL form (the symbol immediately followed by `(`), so it sees the
//! definition and the natural caller, while NOT matching the host crate's public re-exports
//! (`NAME,`) or a doc mention (`` `NAME` ``). An author who re-exports a door under another name or
//! wraps it behind a helper in an already-listed file walks past this census. The load-bearing
//! defense against the completing widening is the refusing default in the resident actor (absence of
//! a provider IS the refusing posture) plus review of this file set; this guard keeps the shipping
//! source free of the door SYMBOL so no build flag can link a call into a production binary.
//!
//! COMPANION ANY-FORM CENSUS. Because the call-form sweep above walks past an aliased re-import or a
//! wrapper, a second test in this file
//! (`gd7_compensation_provider_door_symbol_absent_from_shipping_source_any_form_chirho`) runs a
//! BARE-SYMBOL sweep over exactly the two dirs the invariant protects — `cairn-ledger-geo-node-chirho`
//! and `cairn-cli-chirho`. Within those two dirs a `use ...::NAME as alias` import, a `pub use`
//! re-export, or a helper wrapper of the door symbol is now caught by the GUARD, not only by review.
//! It does not reach a rename laundered through a THIRD crate that never names the door symbol itself;
//! the refusing default plus review of this file set remain the backstop for that residual.

use super::super::*;

/// Both provider doors, keyed by their CALL form: the symbol immediately followed by `(`. This
/// matches the `pub fn NAME(` DEFINITION and every `NAME(...)` CALL, and deliberately does NOT match
/// a `use`-block re-export (`NAME,`) or a doc-comment link (`` `NAME` ``) — mirroring the sibling
/// winner-lane guard, which keys on its acquisition symbol the same way.
const EA_DOOR_CALL_NEEDLE_CHIRHO: &str =
    "open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho(";
const EB_DOOR_CALL_NEEDLE_CHIRHO: &str =
    "open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho(";
const EA_DOOR_DEFINITION_NEEDLE_CHIRHO: &str =
    "pub fn open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho(";
const EB_DOOR_DEFINITION_NEEDLE_CHIRHO: &str =
    "pub fn open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho(";

/// The same two doors as BARE SYMBOLS — no trailing `(`. A `.contains` on either matches EVERY
/// textual appearance of the door: a call, a `use ...::NAME as alias` re-import (the original symbol
/// still sits to the left of `as`), a `pub use` re-export, a wrapper, or a doc mention. This is the
/// broader any-form pair the shipping-scope census below uses; it is deliberately wider than the
/// CALL-form needles above. E-A is NOT a substring of E-B (E-A carries `_with_gd7_`, E-B carries
/// `_with_shared_elector_and_gd7_`), so the two never collide, and neither appears in the geo-node
/// crate's `//!` mention of this GUARD's own name
/// (`gd7_compensation_provider_door_has_no_shipping_binary_caller_chirho`), which names the guard, not
/// a door — so matching only these door identifiers keeps that one lawful reference out of scope.
const EA_DOOR_SYMBOL_NEEDLE_CHIRHO: &str =
    "open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho";
const EB_DOOR_SYMBOL_NEEDLE_CHIRHO: &str =
    "open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho";

/// The one module that DEFINES both doors. E-A is not a substring of E-B (E-B carries
/// `_with_shared_elector_and_gd7_`, E-A carries `_with_gd7_`), so the two needles never collide.
const DOOR_DEFINITION_MODULE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho.rs";

/// The lawful test-kind callers: BOTH live in the distinct testkind crate, one per road, and that
/// is the whole widening — a hosted test-kind binary that can complete a compensation — in a crate
/// no production build links (Guard B keeps it a dev-only edge).
///
/// - `eb_winner_opener_chirho.rs` — the SERVE road's winner posture, door E-B (shared elector).
/// - `ea_seeding_opener_chirho.rs` — the SEEDING road's single-voter posture, door E-A, injected
///   into the credits-demo geo-seed road so a hosted drill root can be seeded from a test-kind
///   config (E1-e-2).
///
/// EVERY ENTRY HERE MUST BE INSIDE `cairn-ledger-geo-node-testkind-chirho`. An addition anywhere
/// else is not a population update, it is a new admission through a money-authority door — the
/// exact error this guard caught once already, when the seeding road in
/// `cairn-operator-smoke-chirho` was going to name a door directly and would thereby have made the
/// SHIPPING CLI (reachable from that crate by three link paths) able to complete a compensation.
const TESTKIND_WINNER_OPENER_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/src/eb_winner_opener_chirho.rs";
const TESTKIND_DOOR_CALLERS_CHIRHO: [&str; 2] = [
    "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/src/ea_seeding_opener_chirho.rs",
    TESTKIND_WINNER_OPENER_CHIRHO,
];

/// The crate every lawful test-kind caller must sit inside, asserted separately below so the
/// population list cannot quietly grow an entry from another crate.
const TESTKIND_CRATE_DIR_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/";

/// The shipping binaries that must NEVER name a compensation-provider door. Keyed with a trailing
/// slash so the sibling `cairn-ledger-geo-node-testkind-chirho/` crate (which legitimately carries
/// the door) is not swept in: after `cairn-ledger-geo-node-` the shipping crate is `chirho/` and the
/// testkind crate is `testkind-chirho/`, so the prefix cannot match the testkind path.
const SHIPPING_GEO_NODE_DIR_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-geo-node-chirho/";
const SHIPPING_CLI_DIR_CHIRHO: &str = "crates/cairn-cli-chirho/";

/// THE MONEY/AUTHORITY INVARIANT, executed rather than asserted in prose: no shipping binary reaches
/// a completing compensation-provider door.
///
/// The population is asserted as a SET (not a count) so a new caller names itself in the failure,
/// and the door DEFINITION is asserted present FIRST so a needle drift cannot make the whole census
/// green-by-emptiness. The lawful production population is exactly the one module that DEFINES the
/// doors plus the callers inside `cairn-ledger-geo-node-testkind-chirho` — TWO today: the winner-side
/// opener and the seeding opener. That crate is the ONE sanctioned home for the widening; any file
/// OUTSIDE it naming a door is a new admission through a money-authority door.
///
/// The count is stated as "two today" rather than frozen at two on purpose: a further lawful caller
/// INSIDE the sanctioned crate is a reviewed population update, while a caller outside it is a breach.
/// The crate-bound assertion below fires FIRST precisely so those two cases cannot be confused — and so
/// the tempting wrong fix, appending the offending path to the expected set, is refused by name.
#[test]
fn gd7_compensation_provider_door_has_no_shipping_binary_caller_chirho() {
    let production_files_chirho = workspace_production_rs_files_chirho();
    let mut door_call_sites_chirho = Vec::new();
    let mut door_definition_sites_chirho = Vec::new();
    for path_chirho in production_files_chirho {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production source");
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if source_chirho.contains(EA_DOOR_CALL_NEEDLE_CHIRHO)
            || source_chirho.contains(EB_DOOR_CALL_NEEDLE_CHIRHO)
        {
            door_call_sites_chirho.push(relative_chirho.clone());
        }
        if source_chirho.contains(EA_DOOR_DEFINITION_NEEDLE_CHIRHO)
            || source_chirho.contains(EB_DOOR_DEFINITION_NEEDLE_CHIRHO)
        {
            door_definition_sites_chirho.push(relative_chirho.clone());
        }
    }
    door_call_sites_chirho.sort();
    door_call_sites_chirho.dedup();
    door_definition_sites_chirho.sort();
    door_definition_sites_chirho.dedup();

    // POSITIVE CONTROL FIRST: both door definitions must be found in the one runtime-actor module,
    // else the needle drifted and every absence below is green-by-emptiness.
    assert_eq!(
        door_definition_sites_chirho,
        vec![DOOR_DEFINITION_MODULE_CHIRHO.to_owned()],
        "both compensation-provider door definitions must live in exactly the one runtime-actor \
         module; an empty or different set means the census stopped measuring the real doors"
    );

    // THE INVARIANT, stated directly: no shipping geo-node file and no CLI file may name a
    // compensation-provider door. A production node that could reach the door could autonomously
    // complete a compensation — the exact hole this guard exists to prevent.
    let shipping_callers_chirho: Vec<&String> = door_call_sites_chirho
        .iter()
        .filter(|path_chirho| {
            path_chirho.starts_with(SHIPPING_GEO_NODE_DIR_CHIRHO)
                || path_chirho.starts_with(SHIPPING_CLI_DIR_CHIRHO)
        })
        .collect();
    assert!(
        shipping_callers_chirho.is_empty(),
        "a SHIPPING binary reaches a GD7 compensation-provider door, so a production node could \
         autonomously complete a compensation. Offending files: {shipping_callers_chirho:?}"
    );

    // THE CRATE BOUND, asserted BEFORE the exact set and independently of it. The set equality
    // below would also catch a foreign file, but it would read as "the reviewed list is stale" —
    // the tempting fix being to append the new path. This assertion says the other thing outright:
    // a caller outside the testkind crate is never a population update, whatever the list says.
    let foreign_callers_chirho: Vec<&String> = door_call_sites_chirho
        .iter()
        .filter(|path_chirho| {
            *path_chirho != DOOR_DEFINITION_MODULE_CHIRHO
                && !path_chirho.starts_with(TESTKIND_CRATE_DIR_CHIRHO)
        })
        .collect();
    assert!(
        foreign_callers_chirho.is_empty(),
        "a file OUTSIDE {TESTKIND_CRATE_DIR_CHIRHO} calls a GD7 compensation-provider door. Do NOT \
         resolve this by adding the path to the expected population: the widening is confined to \
         the testkind crate because no production build links it, and any other crate may be \
         reachable from a shipping binary. Offending files: {foreign_callers_chirho:?}"
    );

    // FAIL-CLOSED SET: the whole production population naming a compensation-provider door (call
    // form) is EXACTLY the two door definitions (one module) plus the testkind-crate callers. A new
    // file is a new admission through a money-authority door and names itself in the failure; a
    // MISSING testkind caller means one of the widening's lawful door references vanished (a hosted
    // drill road lost its completing path), which is equally worth a red.
    let mut expected_door_population_chirho = vec![DOOR_DEFINITION_MODULE_CHIRHO.to_owned()];
    expected_door_population_chirho.extend(
        TESTKIND_DOOR_CALLERS_CHIRHO
            .iter()
            .map(|path_chirho| (*path_chirho).to_owned()),
    );
    expected_door_population_chirho.sort();
    assert_eq!(
        door_call_sites_chirho, expected_door_population_chirho,
        "the compensation-provider door's production call population must be exactly the door \
         definitions plus the testkind callers; a new file is a new admission through a \
         money-authority door"
    );
}

/// The lawful caller population alone does not prove WHICH compensation-provider door the hosted
/// winner selects: both E-A and E-B are permitted inside the test-kind crate. Pin the money-bearing
/// distinction directly. E-B reuses the running geo node's shared elector; E-A would start a durable
/// single-voter self-election and create a second writer on the same root.
#[test]
fn testkind_winner_opener_selects_shared_elector_capstone_door_chirho() {
    let opener_path_chirho = workspace_root_chirho().join(TESTKIND_WINNER_OPENER_CHIRHO);
    let opener_source_chirho =
        std::fs::read_to_string(&opener_path_chirho).expect("read test-kind winner opener");
    let opener_chirho = production_text_chirho(&opener_source_chirho);

    assert_eq!(
        opener_chirho
            .match_indices(EB_DOOR_SYMBOL_NEEDLE_CHIRHO)
            .count(),
        2,
        "the test-kind winner opener must import and call the shared-elector E-B capstone door"
    );
    assert_eq!(
        opener_chirho
            .match_indices(EA_DOOR_SYMBOL_NEEDLE_CHIRHO)
            .count(),
        0,
        "the test-kind winner opener must never name the self-electing E-A door"
    );
}

/// THE MONEY/AUTHORITY INVARIANT, hardened to ANY FORM over exactly the two dirs it protects: no file
/// under the shipping geo-node crate or the CLI crate may NAME a compensation-provider door in ANY
/// textual form — not only a `NAME(` call. The sibling call-form census above is a broad ANTI-MISTAKE
/// sweep over every production file; this is a narrower but STRONGER sweep over the two shipping dirs,
/// so an aliased `use ...::NAME as x` import, a `pub use` re-export, or a helper wrapper of the door
/// symbol is caught by the guard rather than only by review. This closes the exact evasion the
/// call-form census names in its own honest scope: a re-import under another name walks past `NAME(`
/// but still carries the bare symbol on the `use` line.
///
/// POSITIVE CONTROL FIRST: the bare door symbol is asserted present somewhere in the whole production
/// tree (the runtime-actor module that DEFINES both doors) before the shipping-scope absence is
/// trusted, so a needle drift cannot make the two-dir emptiness green-by-emptiness. Matching only the
/// door identifiers keeps the geo-node crate's lawful doc mention of THIS guard's own name out of
/// scope (that comment names the guard, not a door symbol).
#[test]
fn gd7_compensation_provider_door_symbol_absent_from_shipping_source_any_form_chirho() {
    let production_files_chirho = workspace_production_rs_files_chirho();
    let mut any_form_door_files_chirho = Vec::new();
    let mut shipping_door_files_chirho = Vec::new();
    for path_chirho in production_files_chirho {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production source");
        let source_chirho = production_text_chirho(&raw_source_chirho);
        // ANY FORM: the bare door SYMBOL, not the call form. This catches a `use ...::NAME as alias`
        // re-import, a `pub use` re-export, a wrapper, or a doc mention — every textual appearance of
        // the symbol, which the call-form census above does not see.
        if !source_chirho.contains(EA_DOOR_SYMBOL_NEEDLE_CHIRHO)
            && !source_chirho.contains(EB_DOOR_SYMBOL_NEEDLE_CHIRHO)
        {
            continue;
        }
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if relative_chirho.starts_with(SHIPPING_GEO_NODE_DIR_CHIRHO)
            || relative_chirho.starts_with(SHIPPING_CLI_DIR_CHIRHO)
        {
            shipping_door_files_chirho.push(relative_chirho.clone());
        }
        any_form_door_files_chirho.push(relative_chirho);
    }
    any_form_door_files_chirho.sort();
    any_form_door_files_chirho.dedup();
    shipping_door_files_chirho.sort();
    shipping_door_files_chirho.dedup();

    // POSITIVE CONTROL FIRST: the any-form door symbol must match the runtime-actor module that
    // DEFINES both doors, else the needle drifted and the shipping-scope absence below is
    // green-by-emptiness.
    assert!(
        any_form_door_files_chirho.contains(&DOOR_DEFINITION_MODULE_CHIRHO.to_owned()),
        "the any-form door-symbol needle must match the runtime-actor module that defines both \
         doors; a drifted or empty match means this census stopped measuring the real door symbol. \
         Any-form matches found: {any_form_door_files_chirho:?}"
    );

    // THE INVARIANT, any-form: no shipping geo-node file and no CLI file may NAME a
    // compensation-provider door in ANY form. A `use ...::NAME as alias` re-import, a re-export, or a
    // wrapper would let a production binary reach a completing door while the call-form census stayed
    // green — this guard fails on the SYMBOL, so no such evasion reaches a shipping binary unreviewed.
    assert!(
        shipping_door_files_chirho.is_empty(),
        "a SHIPPING binary NAMES a GD7 compensation-provider door in some form (call, `use ... as` \
         alias, re-export, or wrapper), so a production node could reach a completing compensation. \
         Offending files: {shipping_door_files_chirho:?}"
    );
}
