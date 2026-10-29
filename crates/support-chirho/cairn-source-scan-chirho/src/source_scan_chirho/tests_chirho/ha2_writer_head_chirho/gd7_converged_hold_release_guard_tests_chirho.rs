// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pins the sole production door that may supersede the GD7 resident active-head ref.

use super::super::*;

const RELEASE_SYMBOL_NEEDLE_CHIRHO: &str = "release_converged_reconciliation_hold_chirho(";
const RELEASE_DEFINITION_NEEDLE_CHIRHO: &str =
    "pub(crate) fn release_converged_reconciliation_hold_chirho(";
const HEAD_PATH_RESOLVER_NEEDLE_CHIRHO: &str = "gd7_reconciliation_group_head_path_chirho(";
const HEAD_REMOVE_NEEDLE_CHIRHO: &str = "remove_chirho(&head_path_chirho)";

#[test]
fn gd7_converged_hold_release_is_the_single_live_head_supersede_door_chirho() {
    let production_files_chirho = workspace_production_rs_files_chirho();
    let mut release_sites_chirho = Vec::new();
    let mut release_definition_sites_chirho = Vec::new();
    let mut head_supersede_sites_chirho = Vec::new();
    let mut resolver_sites_chirho = Vec::new();
    let mut head_supersede_count_chirho = 0usize;
    for path_chirho in production_files_chirho {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production source");
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let resolver_count_chirho = source_chirho
            .matches(HEAD_PATH_RESOLVER_NEEDLE_CHIRHO)
            .count();
        if resolver_count_chirho > 0 {
            resolver_sites_chirho.push((relative_chirho.clone(), resolver_count_chirho));
        }
        if source_chirho.contains(RELEASE_SYMBOL_NEEDLE_CHIRHO) {
            release_sites_chirho.push(relative_chirho.clone());
        }
        if source_chirho.contains(RELEASE_DEFINITION_NEEDLE_CHIRHO) {
            release_definition_sites_chirho.push(relative_chirho.clone());
        }
        if source_chirho.contains(HEAD_REMOVE_NEEDLE_CHIRHO) {
            let removal_count_chirho = source_chirho.matches(HEAD_REMOVE_NEEDLE_CHIRHO).count();
            head_supersede_count_chirho += removal_count_chirho;
            head_supersede_sites_chirho.push((
                relative_chirho,
                resolver_count_chirho,
                removal_count_chirho,
            ));
        }
    }
    release_sites_chirho.sort();
    release_definition_sites_chirho.sort();
    head_supersede_sites_chirho.sort();
    resolver_sites_chirho.sort();
    assert_eq!(
        release_definition_sites_chirho,
        vec!["crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_revoke_chirho.rs"],
        "the release operation must remain one live production door"
    );
    assert_eq!(
        release_sites_chirho,
        vec![
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_append_chirho.rs".to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_revoke_chirho.rs".to_owned(),
        ],
        "the release operation's definition and reviewed resident caller must stay live"
    );
    assert_eq!(
        head_supersede_sites_chirho,
        vec![(
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_revoke_chirho.rs".to_owned(),
            1,
            1,
        )],
        "every production active-head removal must be in the sole resolver-bearing release module"
    );
    assert_eq!(
        head_supersede_count_chirho, 1,
        "the production GD7 active-head removal census must resolve to exactly one site"
    );
    // TARGET-RESOLVED, NOT SPELLING-KEYED — the arm that makes this guard mean its name.
    //
    // `HEAD_REMOVE_NEEDLE_CHIRHO` above is a LITERAL, so it only sees a removal whose local happens
    // to be called `head_path_chirho`. A door that resolves the same path into any other variable
    // walks straight past it — measured, not theorised: an alternate door in
    // `held_coordinator_chirho.rs` using `alternate_path_chirho` passed this guard while the
    // byte-identical door using `head_path_chirho` failed it. The only difference was the name.
    //
    // The resolver census is the fix because it keys on the TARGET rather than on how a call is
    // spelled: a door cannot remove the active head without first naming its path, and the only way
    // to name it is this resolver. So pinning WHO may resolve it bounds who may supersede it,
    // whatever they call their local.
    //
    // The two sites are not interchangeable. `store_chirho.rs` OWNS the head — it constructs the
    // path and reads/commits the head VALUE — and none of its four uses is a removal.
    // `sink_term_revoke_chirho.rs` is the release door. A NEW file in this set is a new door and
    // must be reviewed as one; a changed COUNT inside an existing file is a review signal rather
    // than a defect on its own, and the honest response is to read the new call, not to re-pin the
    // number.
    //
    // KNOWN OPEN, named rather than implied closed: a door that RECEIVES the head path as a
    // PARAMETER never calls the resolver, so this census cannot see it. That is a smaller hole than
    // a rename — it needs a caller that already holds the path — but it is real, and it is why this
    // guard bounds the resolver rather than claiming to bound every possible removal.
    //
    // Same class, measured separately (gpt's reviewer arm, 2026-08-03): a removal through a
    // hand-built StoragePathChirho assembled from a formatted string — no resolver call, no
    // head-path local — also passes this census. Both are the ADVERSARY class: a door built to
    // avoid the resolver. This guard is anti-mistake, not anti-adversary — it catches the natural
    // door (one that names the path the only supported way); an author with commit access defeats
    // any text census, and the load-bearing defenses against that class are the liveness arm (the
    // append refuses while a hold is present) and review of this file set.
    assert_eq!(
        resolver_sites_chirho,
        vec![
            (
                "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/store_chirho.rs"
                    .to_owned(),
                5,
            ),
            (
                "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_revoke_chirho.rs"
                    .to_owned(),
                1,
            ),
        ],
        "the production GD7 active-head resolver census changed: a new file here is a new candidate \
         supersede door and must be reviewed before it lands"
    );
    let release_path_chirho = workspace_root_chirho().join(&release_definition_sites_chirho[0]);
    let release_raw_source_chirho =
        std::fs::read_to_string(release_path_chirho).expect("read release module");
    let release_source_chirho = production_text_chirho(&release_raw_source_chirho);
    assert!(
        release_source_chirho.contains("convergence_chirho.adopted_checkpoint_ref_chirho()"),
        "release must bind the convergence certificate to the adopted checkpoint by its \
         `adopted_checkpoint_ref_chirho` field — the AdoptedHeld cut being superseded — not its \
         `checkpoint_ref_chirho` (the PlanSealed plan cut, which a genuine post-adoption certificate \
         never equals to the adopted cut)"
    );
}
