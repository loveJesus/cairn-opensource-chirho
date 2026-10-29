// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Reviewed semantic roles for production files that own raw ledger-journal coordinates.

pub(super) fn source_owns_journal_impl_chirho(file_chirho: &str) -> bool {
    file_chirho.starts_with("crates/ledger-chirho/cairn-ledger-log-chirho/src/journal")
        || file_chirho == "crates/ledger-chirho/cairn-ledger-log-chirho/src/losing_suffix_chirho.rs"
}

pub(super) fn role_for_writer_chirho(file_chirho: &str) -> Option<&'static str> {
    if file_chirho
        == "crates/ledger-chirho/cairn-ledger-composition-chirho/src/composition_chirho.rs"
    {
        Some("runtime-raw-composition")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-effect-commit-ledger-chirho/src/adapter_chirho.rs"
    {
        Some("runtime-effect-adapter")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs"
        || file_chirho
            == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_open_view_chirho.rs"
    {
        Some("sealed-resident-authority")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho.rs"
    {
        Some("resident-serving-authority-owner")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/recovery_adoption_chirho.rs"
    {
        Some("mirror-recovery-candidate-verifier")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho.rs"
    {
        Some("gd7-held-read-only-observer")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/adoption_chirho.rs"
    {
        Some("gd7-held-adoption-materializer")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/adoption_commit_chirho.rs"
    {
        Some("gd7-held-adoption-restart-verifier")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/activation_chirho.rs"
    {
        Some("reviewed-h3-activation-verifier")
    } else if file_chirho
        == "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs"
    {
        Some("sealed-preactivation-resident-birth")
    } else if file_chirho == "crates/ledger-chirho/cairn-ledger-log-chirho/src/registry_chirho.rs" {
        Some("runtime-actor-registry")
    } else if file_chirho.starts_with("crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/") {
        Some("offline-regenesis")
    } else if file_chirho.starts_with("crates/ledger-chirho/cairn-ledger-sim-chirho/src/") {
        Some("simulation")
    } else if file_chirho.starts_with("crates/ledger-chirho/cairn-ledger-read-model-chirho/src/") {
        Some("read-model-observer")
    } else if file_chirho.starts_with("crates/cairn-serve-runtime-chirho/src/") {
        Some("served-runtime-observer")
    } else if source_owns_journal_impl_chirho(file_chirho) {
        Some("journal-substrate")
    } else {
        None
    }
}
