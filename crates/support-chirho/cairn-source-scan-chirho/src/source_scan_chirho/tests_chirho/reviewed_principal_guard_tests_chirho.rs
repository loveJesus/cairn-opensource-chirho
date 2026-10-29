// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The reviewed-principal registration (C1 A3) has exactly one production caller, the credits-demo
//! setup, and only the test-kind geo seed binary hands that setup a reviewed payer. Every other
//! production construction passes `None` (claude2 #29250, Agy #29261).

use super::{
    production_text_chirho, workspace_production_rs_files_chirho, workspace_relative_chirho,
};
use std::collections::BTreeSet;

const REVIEWED_REGISTRATION_NAME_CHIRHO: &str = "register_identity_with_reviewed_principal_chirho";
const IDENTITY_MODULE_PREFIX_CHIRHO: &str = "src/edge_flows_chirho/identity_chirho";
const SETUP_FILE_CHIRHO: &str =
    "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/setup_chirho.rs";
const SEED_BIN_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/src/bin/cairn-ledger-geo-node-testkind-seed-chirho.rs";
const REVIEWED_PAYER_NAME_CHIRHO: &str = "reviewed_payer_principal_chirho";
/// The only forms the field may take outside the seed binary. Setup alone also declares it and reads
/// it; every other production construction passes None explicitly (claude2 #29330).
const NONE_INIT_CHIRHO: &str = "reviewed_payer_principal_chirho: None";
const SETUP_DECLARATION_CHIRHO: &str = "pub reviewed_payer_principal_chirho: Option<";
const SETUP_READ_CHIRHO: &str = "inputs_chirho.reviewed_payer_principal_chirho";

/// Every production file, as (workspace-relative path, production text).
fn production_sources_chirho() -> Vec<(String, String)> {
    workspace_production_rs_files_chirho()
        .into_iter()
        .map(|path_chirho| {
            let relative_chirho = workspace_relative_chirho(&path_chirho);
            let text_chirho = std::fs::read_to_string(&path_chirho)
                .unwrap_or_else(|error_chirho| panic!("read {relative_chirho}: {error_chirho}"));
            let production_chirho = production_text_chirho(&text_chirho).into_owned();
            (relative_chirho, production_chirho)
        })
        .collect()
}

/// The bare identifier, not a call form, so a renamed import (`... as other`) is still seen.
#[test]
fn the_reviewed_principal_registration_has_one_production_caller_chirho() {
    let mut mentions_chirho = BTreeSet::new();
    for (relative_chirho, text_chirho) in production_sources_chirho() {
        if relative_chirho.starts_with(IDENTITY_MODULE_PREFIX_CHIRHO) {
            continue;
        }
        if text_chirho.contains(REVIEWED_REGISTRATION_NAME_CHIRHO) {
            mentions_chirho.insert(relative_chirho);
        }
    }
    assert_eq!(
        mentions_chirho,
        BTreeSet::from([SETUP_FILE_CHIRHO.to_string()]),
        "the reviewed-principal registration may be named only by the credits-demo setup; a new \
         caller joins this census by name, in review"
    );
}

/// Conservative: outside the seed binary, every mention of the field must be an explicit `None`
/// construction, or setup's own declaration or read. A shorthand init, a local, or a `Some` fails.
#[test]
fn only_the_testkind_seed_hands_setup_a_reviewed_payer_chirho() {
    let mut violations_chirho = BTreeSet::new();
    let mut none_sites_chirho = 0_usize;
    let mut seed_mentions_chirho = 0_usize;
    for (relative_chirho, text_chirho) in production_sources_chirho() {
        for line_chirho in text_chirho.lines() {
            if !line_chirho.contains(REVIEWED_PAYER_NAME_CHIRHO) {
                continue;
            }
            if relative_chirho == SEED_BIN_CHIRHO {
                seed_mentions_chirho += 1;
                continue;
            }
            none_sites_chirho += line_chirho.matches(NONE_INIT_CHIRHO).count();
            let mut rest_chirho = line_chirho.replace(NONE_INIT_CHIRHO, "");
            if relative_chirho == SETUP_FILE_CHIRHO {
                rest_chirho = rest_chirho
                    .replace(SETUP_DECLARATION_CHIRHO, "")
                    .replace(SETUP_READ_CHIRHO, "");
            }
            if rest_chirho.contains(REVIEWED_PAYER_NAME_CHIRHO) {
                violations_chirho.insert(format!("{relative_chirho}: {}", line_chirho.trim()));
            }
        }
    }
    // Positive controls: the census reads the None constructions and the seed binary's own use.
    assert!(
        none_sites_chirho >= 2,
        "positive control: the census must see the None constructions, found {none_sites_chirho}"
    );
    assert!(
        seed_mentions_chirho >= 1,
        "positive control: the seed binary must name the field"
    );
    assert!(
        violations_chirho.is_empty(),
        "only the test-kind geo seed binary may hand setup a reviewed payer: {violations_chirho:?}"
    );
}
