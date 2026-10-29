// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Proves no SHIPPING binary can reach the DEV-ONLY test-kind resident door.
//!
//! WHAT THIS BOUNDS, stated as the money/authority invariant it is: `open_resident_effect_journal_
//! handle_testkind_chirho` is the exact inverse-fenced twin of the production single-node door — it
//! opens the SAME fenced resident actor (elected write + mint authority) but REQUIRES a test-kind
//! host config where the production door refuses one. A build that can reach this door can open the
//! elected write and mint authority of a SYNTHETIC test-kind root. That is lawful ONLY from the
//! dev-only `cairn-ledger-geo-node-testkind-chirho` crate, which no production build links; the
//! shipping `cairn-ledger-geo-node-chirho`, `cairn-serve-runtime-chirho`, and `cairn-cli-chirho`
//! binaries must be PROVABLY INCAPABLE of naming the door, so a shipping serve path can never open a
//! a1-shaped test-kind root behind a dev flag. This census fails if any shipping file joins the
//! door's caller population.
//!
//! HONEST SCOPE, so nobody reads this wider than it is. It is anti-mistake, not anti-adversary: the
//! primary census keys on the door's own CALL form (the symbol immediately followed by `(`), so it
//! sees the definition and the natural caller, while NOT matching the host crate's public re-exports
//! (`NAME,`) or a doc mention (`` `NAME` ``). An author who re-exports the door under another name or
//! wraps it behind a helper in an already-listed file walks past the call-form sweep. The
//! load-bearing defense against opening a production ledger through this door is the inverse fence
//! itself (`require_test_kind_marked_host_config_chirho`, which fails closed on an unmarked config)
//! plus review of this file set; this guard keeps the shipping source free of the door SYMBOL so no
//! build flag can link a call into a production binary.
//!
//! COMPANION ANY-FORM CENSUS. Because the call-form sweep walks past an aliased re-import or a
//! wrapper, a second test here
//! (`open_resident_effect_journal_handle_testkind_door_symbol_absent_from_shipping_source_any_form_chirho`)
//! runs a BARE-SYMBOL sweep over exactly the three dirs the invariant protects. Within those dirs a
//! `use ...::NAME as alias` import, a `pub use` re-export, or a helper wrapper of the door symbol is
//! caught by the GUARD, not only by review. It does not reach a rename laundered through a fourth
//! crate that never names the door symbol itself; the inverse fence plus review of this file set
//! remain the backstop for that residual.

use super::super::*;

/// The dev-only test-kind door, keyed by its CALL form: the symbol immediately followed by `(`. This
/// matches the `pub fn NAME(` DEFINITION and every `NAME(...)` CALL, and deliberately does NOT match a
/// `use`-block re-export (`NAME,`) or a doc-comment link (`` `NAME` ``) — mirroring the sibling
/// compensation-provider door guard, which keys on its door symbols the same way.
const DOOR_CALL_NEEDLE_CHIRHO: &str = "open_resident_effect_journal_handle_testkind_chirho(";
const DOOR_DEFINITION_NEEDLE_CHIRHO: &str =
    "pub fn open_resident_effect_journal_handle_testkind_chirho(";

/// The same door as a BARE SYMBOL — no trailing `(`. A `.contains` matches EVERY textual appearance:
/// a call, a `use ...::NAME as alias` re-import, a `pub use` re-export, a wrapper, or a doc mention.
/// This is the broader any-form needle the shipping-scope census below uses. The production door
/// `open_resident_effect_journal_handle_chirho` is NOT a substring of this symbol (this one carries
/// `_testkind_` between `_handle_` and `_chirho`), and this symbol is NOT a substring of the guard's
/// own name (`..._testkind_door_has_no_shipping_binary_caller_chirho` carries `_door_` where this
/// carries `_chirho`), so the two never collide and the guard's own name mention stays out of scope.
const DOOR_SYMBOL_NEEDLE_CHIRHO: &str = "open_resident_effect_journal_handle_testkind_chirho";

/// The one module that DEFINES the door.
const DOOR_DEFINITION_MODULE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho.rs";

/// The ONE lawful caller: the normal-settlement opener in the distinct testkind crate. That is the
/// whole widening — a dev-only opener that can open a synthetic test-kind root's resident authority —
/// in a crate no production build links (`testkind_geo_node_stays_a_dev_only_edge_chirho` keeps it a
/// dev-only edge). EVERY ENTRY HERE MUST BE INSIDE `cairn-ledger-geo-node-testkind-chirho`.
const TESTKIND_WRAPPER_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/src/ec_normal_settlement_opener_chirho.rs";

/// The crate every lawful test-kind caller must sit inside, asserted separately so the population
/// list cannot quietly grow an entry from another crate.
const TESTKIND_CRATE_DIR_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/";

/// The shipping binaries that must NEVER name the dev-only test-kind door. Keyed with a trailing
/// slash so the sibling `cairn-ledger-geo-node-testkind-chirho/` crate (which legitimately carries
/// the opener) is not swept in: after `cairn-ledger-geo-node-` the shipping crate is `chirho/` and the
/// testkind crate is `testkind-chirho/`, so the prefix cannot match the testkind path.
const SHIPPING_GEO_NODE_DIR_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-geo-node-chirho/";
const SHIPPING_SERVE_RUNTIME_DIR_CHIRHO: &str = "crates/cairn-serve-runtime-chirho/";
const SHIPPING_CLI_DIR_CHIRHO: &str = "crates/cairn-cli-chirho/";

fn is_shipping_dir_chirho(path_chirho: &str) -> bool {
    path_chirho.starts_with(SHIPPING_GEO_NODE_DIR_CHIRHO)
        || path_chirho.starts_with(SHIPPING_SERVE_RUNTIME_DIR_CHIRHO)
        || path_chirho.starts_with(SHIPPING_CLI_DIR_CHIRHO)
}

/// THE MONEY/AUTHORITY INVARIANT, executed rather than asserted in prose: no shipping binary reaches
/// the dev-only test-kind resident door.
///
/// The population is asserted as a SET (not a count) so a new caller names itself in the failure, and
/// the door DEFINITION is asserted present FIRST so a needle drift cannot make the whole census
/// green-by-emptiness. The lawful production population is exactly the one module that DEFINES the door
/// plus the ONE opener inside `cairn-ledger-geo-node-testkind-chirho`. That crate is the ONE sanctioned
/// home for the widening; any file OUTSIDE it naming the door is a new admission through a
/// money-authority door.
///
/// A further lawful caller INSIDE the sanctioned crate would be a reviewed population update, while a
/// caller outside it is a breach. The crate-bound assertion fires FIRST so those two cases cannot be
/// confused, and so the tempting wrong fix — appending the offending path to the expected set — is
/// refused by name.
#[test]
fn open_resident_effect_journal_handle_testkind_door_has_no_shipping_binary_caller_chirho() {
    let production_files_chirho = workspace_production_rs_files_chirho();
    let mut door_call_sites_chirho = Vec::new();
    let mut door_definition_sites_chirho = Vec::new();
    for path_chirho in production_files_chirho {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production source");
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if source_chirho.contains(DOOR_CALL_NEEDLE_CHIRHO) {
            door_call_sites_chirho.push(relative_chirho.clone());
        }
        if source_chirho.contains(DOOR_DEFINITION_NEEDLE_CHIRHO) {
            door_definition_sites_chirho.push(relative_chirho.clone());
        }
    }
    door_call_sites_chirho.sort();
    door_call_sites_chirho.dedup();
    door_definition_sites_chirho.sort();
    door_definition_sites_chirho.dedup();

    // POSITIVE CONTROL FIRST: the door definition must be found in the one runtime-actor module, else
    // the needle drifted and every absence below is green-by-emptiness.
    assert_eq!(
        door_definition_sites_chirho,
        vec![DOOR_DEFINITION_MODULE_CHIRHO.to_owned()],
        "the dev-only test-kind door definition must live in exactly the one runtime-actor module; \
         an empty or different set means the census stopped measuring the real door"
    );

    // THE INVARIANT, stated directly: no shipping geo-node, serve-runtime, or CLI file may name the
    // dev-only test-kind door. A shipping build that could reach it could open the elected write and
    // mint authority of a synthetic test-kind root — the exact hole this guard exists to prevent.
    let shipping_callers_chirho: Vec<&String> = door_call_sites_chirho
        .iter()
        .filter(|path_chirho| is_shipping_dir_chirho(path_chirho))
        .collect();
    assert!(
        shipping_callers_chirho.is_empty(),
        "a SHIPPING binary reaches the dev-only test-kind door, so a production build could open a \
         synthetic test-kind root's elected write and mint authority. Offending files: \
         {shipping_callers_chirho:?}"
    );

    // THE CRATE BOUND, asserted BEFORE the exact set and independently of it. The set equality below
    // would also catch a foreign file, but it would read as "the reviewed list is stale" — the
    // tempting fix being to append the new path. This assertion says the other thing outright: a
    // caller outside the testkind crate is never a population update, whatever the list says.
    let foreign_callers_chirho: Vec<&String> = door_call_sites_chirho
        .iter()
        .filter(|path_chirho| {
            *path_chirho != DOOR_DEFINITION_MODULE_CHIRHO
                && !path_chirho.starts_with(TESTKIND_CRATE_DIR_CHIRHO)
        })
        .collect();
    assert!(
        foreign_callers_chirho.is_empty(),
        "a file OUTSIDE {TESTKIND_CRATE_DIR_CHIRHO} calls the dev-only test-kind door. Do NOT resolve \
         this by adding the path to the expected population: the widening is confined to the testkind \
         crate because no production build links it, and any other crate may be reachable from a \
         shipping binary. Offending files: {foreign_callers_chirho:?}"
    );

    // FAIL-CLOSED SET: the whole production population naming the door (call form) is EXACTLY the door
    // definition plus the one testkind-crate opener. A new file is a new admission through a
    // money-authority door and names itself in the failure; a MISSING testkind opener means the
    // widening's lawful reference vanished (the dev-context proof lost its opener), equally worth a red.
    let expected_door_population_chirho = {
        let mut expected_chirho = vec![
            DOOR_DEFINITION_MODULE_CHIRHO.to_owned(),
            TESTKIND_WRAPPER_CHIRHO.to_owned(),
        ];
        expected_chirho.sort();
        expected_chirho
    };
    assert_eq!(
        door_call_sites_chirho, expected_door_population_chirho,
        "the dev-only test-kind door's production call population must be exactly the door definition \
         plus the testkind opener; a new file is a new admission through a money-authority door"
    );
}

/// THE MONEY/AUTHORITY INVARIANT, hardened to ANY FORM over exactly the three dirs it protects: no
/// file under the shipping geo-node crate, the serve-runtime crate, or the CLI crate may NAME the
/// dev-only test-kind door in ANY textual form — not only a `NAME(` call. The call-form census above
/// is a broad ANTI-MISTAKE sweep over every production file; this is a narrower but STRONGER sweep
/// over the three shipping dirs, so an aliased `use ...::NAME as x` import, a `pub use` re-export, or
/// a helper wrapper of the door symbol is caught by the guard rather than only by review.
///
/// POSITIVE CONTROL FIRST: the bare door symbol is asserted present in the runtime-actor module that
/// DEFINES the door before the shipping-scope absence is trusted, so a needle drift cannot make the
/// three-dir emptiness green-by-emptiness.
#[test]
fn open_resident_effect_journal_handle_testkind_door_symbol_absent_from_shipping_source_any_form_chirho(
) {
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
        if !source_chirho.contains(DOOR_SYMBOL_NEEDLE_CHIRHO) {
            continue;
        }
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if is_shipping_dir_chirho(&relative_chirho) {
            shipping_door_files_chirho.push(relative_chirho.clone());
        }
        any_form_door_files_chirho.push(relative_chirho);
    }
    any_form_door_files_chirho.sort();
    any_form_door_files_chirho.dedup();
    shipping_door_files_chirho.sort();
    shipping_door_files_chirho.dedup();

    // POSITIVE CONTROL FIRST: the any-form door symbol must match the runtime-actor module that
    // DEFINES the door, else the needle drifted and the shipping-scope absence below is
    // green-by-emptiness.
    assert!(
        any_form_door_files_chirho.contains(&DOOR_DEFINITION_MODULE_CHIRHO.to_owned()),
        "the any-form door-symbol needle must match the runtime-actor module that defines the door; a \
         drifted or empty match means this census stopped measuring the real door symbol. Any-form \
         matches found: {any_form_door_files_chirho:?}"
    );

    // THE INVARIANT, any-form: no shipping geo-node, serve-runtime, or CLI file may NAME the door in
    // ANY form. A `use ...::NAME as alias` re-import, a re-export, or a wrapper would let a production
    // binary reach the door while the call-form census stayed green — this guard fails on the SYMBOL,
    // so no such evasion reaches a shipping binary unreviewed.
    assert!(
        shipping_door_files_chirho.is_empty(),
        "a SHIPPING binary NAMES the dev-only test-kind door in some form (call, `use ... as` alias, \
         re-export, or wrapper), so a production build could open a synthetic test-kind root's elected \
         write and mint authority. Offending files: {shipping_door_files_chirho:?}"
    );
}
