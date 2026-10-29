// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pins the D4 no-alternate-door rule: one withholding presence site, and no confirmation read.

use super::super::*;

/// The append funnel. Everything this guard forbids, it forbids HERE.
const APPEND_FUNNEL_FILE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs";
const HOLD_STORE_FILE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/store_chirho.rs";

const WITHHELD_PREDICATE_NEEDLE_CHIRHO: &str =
    "gd7_reconciliation_group_ordinary_writes_withheld_chirho(";
const HOLD_PATH_RESOLVER_NEEDLE_CHIRHO: &str =
    "gd7_reconciliation_group_ordinary_write_hold_path_chirho(";

/// Reading the confirmation, in any form. The append predicate may do NONE of these.
const CONFIRMATION_READ_NEEDLES_CHIRHO: &[&str] = &[
    "load_verified_write_restoration_confirmation_chirho",
    "parse_and_verify_write_restoration_confirmation_chirho",
    "gd7_write_restoration_confirmation_path_chirho",
    "Gd7WriteRestorationConfirmationChirho",
];

/// Ways the sibling hold's BYTES could be reached. Presence may be tested; content may not.
const HOLD_BYTE_READ_NEEDLES_CHIRHO: &[&str] = &[
    "read_all_chirho(&hold_path_chirho",
    "read_bounded_chirho(&hold_path_chirho",
    "read_exact_range_chirho(&hold_path_chirho",
];

/// THE PRE-REGISTERED D4 ARM, in its directional form.
///
/// The CONFIRMATION is zero-read from the append funnel: it is confirmation and audit, never
/// permission, so a presence test of it would be the presence-grants inversion in a new costume.
/// The SIBLING HOLD may be presence-tested, but only in the WITHHOLDING direction and only at one
/// site — `object_len` on a resolved path, never a byte read. Absence is pass-through, so stale or
/// malformed content can never admit a writer.
///
/// This is a SET assertion naming files, not a count: a count can be satisfied by moving a call
/// rather than removing it, and the round-2/round-3 history of the sibling guard is exactly that
/// lesson.
#[test]
fn gd7_ordinary_write_hold_has_one_withholding_site_and_no_confirmation_read_chirho() {
    let production_files_chirho = workspace_production_rs_files_chirho();
    let mut withheld_sites_chirho = Vec::new();
    let mut hold_resolver_sites_chirho = Vec::new();
    let mut confirmation_read_in_funnel_chirho = Vec::new();
    let mut hold_byte_read_sites_chirho = Vec::new();
    let mut funnel_seen_chirho = false;

    for path_chirho in production_files_chirho {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production source");
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let relative_chirho = workspace_relative_chirho(&path_chirho);

        let withheld_count_chirho = source_chirho
            .matches(WITHHELD_PREDICATE_NEEDLE_CHIRHO)
            .count();
        if withheld_count_chirho > 0 {
            withheld_sites_chirho.push((relative_chirho.clone(), withheld_count_chirho));
        }
        if source_chirho.contains(HOLD_PATH_RESOLVER_NEEDLE_CHIRHO) {
            hold_resolver_sites_chirho.push(relative_chirho.clone());
        }
        for needle_chirho in HOLD_BYTE_READ_NEEDLES_CHIRHO {
            if source_chirho.contains(needle_chirho) {
                hold_byte_read_sites_chirho
                    .push((relative_chirho.clone(), (*needle_chirho).to_owned()));
            }
        }
        if relative_chirho == APPEND_FUNNEL_FILE_CHIRHO {
            funnel_seen_chirho = true;
            // The root module only re-exports the independently guarded implementation. Scan the
            // actual append funnel body here; treating a multiline re-export as an executable read
            // would make this guard reject the module boundary rather than the permission path.
            let mut in_confirmation_reexport_chirho = false;
            let executable_lines_chirho = source_chirho
                .lines()
                .filter(|line_chirho| {
                    if relative_chirho != APPEND_FUNNEL_FILE_CHIRHO {
                        return true;
                    }
                    if line_chirho.contains("pub use write_restoration_chirho::{") {
                        in_confirmation_reexport_chirho = true;
                        return false;
                    }
                    if in_confirmation_reexport_chirho {
                        if line_chirho.trim() == "};" {
                            in_confirmation_reexport_chirho = false;
                        }
                        return false;
                    }
                    true
                })
                .collect::<Vec<_>>();
            for needle_chirho in CONFIRMATION_READ_NEEDLES_CHIRHO {
                if executable_lines_chirho
                    .iter()
                    .any(|line_chirho| line_chirho.contains(needle_chirho))
                {
                    confirmation_read_in_funnel_chirho.push((*needle_chirho).to_owned());
                }
            }
        }
    }
    withheld_sites_chirho.sort();
    hold_resolver_sites_chirho.sort();
    confirmation_read_in_funnel_chirho.sort();
    hold_byte_read_sites_chirho.sort();

    // POSITIVE CONTROL. Without this, a scanner that silently stopped enumerating would report a
    // clean sweep of an empty set -- green by emptiness, at the level of the guard's own input.
    assert!(
        funnel_seen_chirho,
        "the append funnel file was never scanned, so this guard measured nothing. Expected to \
         find {APPEND_FUNNEL_FILE_CHIRHO}. MIGRATION: if the funnel moved, retarget \
         APPEND_FUNNEL_FILE_CHIRHO -- do not delete this assertion."
    );

    assert_eq!(
        withheld_sites_chirho,
        vec![
            (HOLD_STORE_FILE_CHIRHO.to_owned(), 1),
            (APPEND_FUNNEL_FILE_CHIRHO.to_owned(), 1),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>(),
        "the ordinary-write barrier must have EXACTLY ONE definition and EXACTLY ONE production \
         presence site (the append funnel). A second site is a second door, even when each site \
         looks harmless alone."
    );
    assert_eq!(
        hold_resolver_sites_chirho,
        vec![HOLD_STORE_FILE_CHIRHO.to_owned()],
        "only the hold's own store module may resolve its path: a caller that assembles the path \
         elsewhere could remove the barrier without going through the reviewed door"
    );
    assert!(
        hold_byte_read_sites_chirho.is_empty(),
        "the sibling hold's BYTES must never be read -- presence withholds, content decides \
         nothing. Found: {hold_byte_read_sites_chirho:?}"
    );
    assert!(
        confirmation_read_in_funnel_chirho.is_empty(),
        "the append funnel must have ZERO read paths to the write-restoration confirmation. The \
         confirmation is audit, never permission; a presence test of it would re-create the \
         presence-grants inversion under a new name. Found: {confirmation_read_in_funnel_chirho:?}"
    );
}
