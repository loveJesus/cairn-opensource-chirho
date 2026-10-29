// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Money proof for the served-LLM dev bootstrap: the payer is credited EXACTLY `--amount`, held is
//! zero, supply is conserved (minted == in circulation), the settlement owner is established but not
//! yet credited, and a production (non-test-kind) posture is refused by identity. Balances are read
//! back through the real ledger-host read door, never the legacy `ledger-balances` command.

use super::*;
use cairn_config_chirho::config_chirho::load_config_chirho;
use cairn_serve_runtime_chirho::LedgerHostProjectionReadPortChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const PAYER_CHIRHO: &str = "dev-payer-chirho";
const SETTLEMENT_OWNER_CHIRHO: &str = "dev-settlement-owner-chirho";
const BILLING_KIND_CHIRHO: &str = "llm-credit-chirho";

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-served-llm-dev-bootstrap-{label_chirho}-{}-{nanos_chirho}-{counter_chirho}-chirho",
        std::process::id()
    ))
}

/// POSITIVE CONTROL + conservation proof: one bootstrap funds the payer with EXACTLY `--amount`,
/// leaves no Hold, conserves supply, and establishes (but does not credit) the settlement owner.
/// Because this arm proves the mint really credits the payer, a neutered mint would redden it — the
/// mutation result is recorded in the brick report.
#[test]
fn bootstrap_funds_payer_exactly_chirho() {
    let root_chirho = temp_root_chirho("funds");
    let amount_chirho = 137_u64;

    let report_chirho = run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: PAYER_CHIRHO,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    })
    .expect("the dev bootstrap must fund the payer");

    // The report binds the money coordinates and carries the regenesis digests.
    assert_eq!(report_chirho.payer_principal_chirho, PAYER_CHIRHO);
    assert_eq!(
        report_chirho.settlement_owner_principal_chirho,
        SETTLEMENT_OWNER_CHIRHO
    );
    assert_eq!(report_chirho.billing_kind_chirho, BILLING_KIND_CHIRHO);
    assert_eq!(report_chirho.amount_chirho, amount_chirho);
    assert!(
        report_chirho.test_kind_marked_chirho,
        "the authored ledger is test-kind"
    );
    assert_eq!(
        report_chirho.plan_digest_chirho.len(),
        64,
        "plan digest is a blake3 hex"
    );
    assert!(
        !report_chirho.packet_digest_chirho.is_empty(),
        "regenesis produced a packet digest"
    );
    assert!(
        !report_chirho.publication_manifest_digest_chirho.is_empty(),
        "regenesis produced a publication manifest digest"
    );

    // PROOF via the real ledger-host read door (not the legacy `ledger-balances` command).
    let canonical_root_chirho = root_chirho
        .canonicalize()
        .expect("canonical bootstrap root");
    let config_path_chirho = dev_bootstrap_config_path_chirho(&canonical_root_chirho);
    let config_chirho = load_config_chirho(&config_path_chirho).expect("load authored config");
    let ledger_host_chirho = config_chirho
        .ledger_host_chirho
        .clone()
        .expect("authored config carries a ledger host block");
    let port_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &canonical_root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )
    .expect("open the published dev ledger host");
    let balances_chirho = port_chirho
        .read_substrate_balances_chirho()
        .expect("read substrate balances");

    let payer_key_chirho = (PAYER_CHIRHO.to_owned(), BILLING_KIND_CHIRHO.to_owned());
    assert_eq!(
        balances_chirho
            .account_nets_chirho
            .get(&payer_key_chirho)
            .copied(),
        Some(amount_chirho),
        "payer credited exactly --amount"
    );
    assert_eq!(
        balances_chirho
            .account_held_chirho
            .get(&payer_key_chirho)
            .copied()
            .unwrap_or(0),
        0,
        "no Hold on the payer after a bare mint"
    );
    assert!(
        balances_chirho
            .account_held_chirho
            .values()
            .all(|held_chirho| *held_chirho == 0),
        "no Hold anywhere on a freshly funded ledger"
    );
    assert_eq!(
        balances_chirho
            .net_supply_by_kind_chirho
            .get(BILLING_KIND_CHIRHO)
            .copied(),
        Some(amount_chirho),
        "supply conserved: minted == in circulation"
    );

    // The settlement owner is a config member on the billing kind (its per-draft credit destination)
    // but has no balance until the served-LLM Finalize credits it.
    let settlement_key_chirho = (
        SETTLEMENT_OWNER_CHIRHO.to_owned(),
        BILLING_KIND_CHIRHO.to_owned(),
    );
    assert_eq!(
        balances_chirho
            .account_nets_chirho
            .get(&settlement_key_chirho)
            .copied()
            .unwrap_or(0),
        0,
        "settlement owner is established but not yet credited"
    );
    assert!(
        ledger_host_chirho
            .members_chirho
            .iter()
            .any(|member_chirho| {
                member_chirho.owner_chirho == SETTLEMENT_OWNER_CHIRHO
                    && member_chirho.kind_id_chirho == BILLING_KIND_CHIRHO
            }),
        "settlement owner is a config member on the billing kind"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The dev/production posture gate refuses a non-test-kind (production) host config by identity, and
/// admits the test-kind config this bootstrap authors — both directions on one real config.
#[test]
fn refuses_production_posture_by_identity_chirho() {
    let root_chirho = temp_root_chirho("posture");
    let request_chirho = ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: PAYER_CHIRHO,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho: 10,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    };
    let kind_issuer_principal_chirho = format!(
        "{LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO}{KIND_ISSUER_PRINCIPAL_SUFFIX_CHIRHO}"
    );
    let config_chirho = build_ledger_host_config_chirho(
        &root_chirho,
        &request_chirho,
        &kind_issuer_principal_chirho,
    )
    .expect("author config");
    let ledger_host_chirho = config_chirho
        .ledger_host_chirho
        .expect("authored config carries a ledger host block");

    // The authored (test-kind) config passes the gate.
    refuse_production_posture_chirho(&ledger_host_chirho)
        .expect("a test-kind dev config passes the posture gate");

    // A production (unmarked) config is refused by the stable identity.
    let mut production_host_chirho = ledger_host_chirho.clone();
    production_host_chirho.test_kind_chirho = None;
    let error_chirho = refuse_production_posture_chirho(&production_host_chirho)
        .expect_err("a production posture must be refused");
    assert!(
        error_chirho
            .to_string()
            .contains(SERVED_LLM_DEV_BOOTSTRAP_PRODUCTION_REFUSAL_CHIRHO),
        "the refusal carries the stable production-posture identity"
    );
}

/// A zero amount is refused up front, before any secret, key, or ledger substrate is written.
#[test]
fn zero_amount_refuses_before_mutation_chirho() {
    let root_chirho = temp_root_chirho("zero");
    let error_chirho = run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: PAYER_CHIRHO,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho: 0,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    })
    .expect_err("a zero amount must refuse");
    assert!(
        error_chirho
            .to_string()
            .contains("must be greater than zero"),
        "the zero-amount refusal is explicit"
    );
    assert!(
        !root_chirho.join(FRESH_PARENT_CHIRHO).exists(),
        "no ledger substrate is published on a refused bootstrap"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
