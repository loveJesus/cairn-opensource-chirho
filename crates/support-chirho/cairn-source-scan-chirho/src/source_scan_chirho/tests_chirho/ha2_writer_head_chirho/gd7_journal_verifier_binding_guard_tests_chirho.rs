// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Keep ordinary-record authentication on the config-pinned journal root and winner identity on
//! the separate control key. Record labels remain hygiene only and may never select either root.

use super::super::*;

const GEO_TRANSFER_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/held_evidence_transfer_chirho.rs";
const WINNER_HISTORY_PATH_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/current_view_chirho/winner_history_chirho.rs";
const FORK_BASELINE_PATH_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/current_view_chirho/fork_baseline_chirho.rs";
const HELD_STORE_PATH_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/current_view_chirho/held_evidence_transfer_chirho/held_store_chirho.rs";

fn compact_production_source_chirho(relative_chirho: &str) -> String {
    let path_chirho = workspace_production_rs_files_chirho()
        .into_iter()
        .find(|path_chirho| workspace_relative_chirho(path_chirho) == relative_chirho)
        .unwrap_or_else(|| panic!("production source disappeared: {relative_chirho}"));
    let raw_chirho =
        std::fs::read_to_string(&path_chirho).unwrap_or_else(|_| panic!("read {relative_chirho}"));
    production_text_chirho(&raw_chirho)
        .chars()
        .filter(|character_chirho| !character_chirho.is_whitespace())
        .collect()
}

#[test]
fn gd7_geo_transfer_selects_record_trust_only_from_host_config_chirho() {
    let source_chirho = compact_production_source_chirho(GEO_TRANSFER_PATH_CHIRHO);
    assert_eq!(
        source_chirho
            .matches("configured_held_gd7_journal_verifier_chirho(")
            .count(),
        1,
        "GD7 geo transfer must have one config-derived journal verifier; migration path: review every additional trust selector"
    );
    assert!(
        !source_chirho.contains("PinnedGd7LedgerRecordVerifierChirho"),
        "GD7 geo transfer reconstructed a journal verifier outside host config; migration path: restore the role-bound config constructor"
    );
}

#[test]
fn gd7_record_labels_never_rebind_to_the_selected_winner_node_chirho() {
    let history_chirho = compact_production_source_chirho(WINNER_HISTORY_PATH_CHIRHO);
    assert!(
        history_chirho.contains(
            "record_chirho.key_id_chirho!=injected_journal_key_id_chirho"
        ),
        "winner-history staging lost injected-journal label hygiene; migration path: compare with the injected journal label without selecting trust from it"
    );

    let held_store_chirho = compact_production_source_chirho(HELD_STORE_PATH_CHIRHO);
    assert!(
        !held_store_chirho.contains("winner_ledger_verifier_chirho.key_id_chirho()"),
        "held evidence store rebound the journal-verifier label to winner identity; migration path: retain only the independent control-verifier identity check"
    );

    let baseline_chirho = compact_production_source_chirho(FORK_BASELINE_PATH_CHIRHO);
    assert!(
        !baseline_chirho
            .contains("winner_journal_ports_chirho.signer_chirho.key_id_chirho()"),
        "fork-baseline staging rebound a journal label to winner identity; migration path: the journal reader authenticates records while the control signer authenticates the baseline root"
    );
}
