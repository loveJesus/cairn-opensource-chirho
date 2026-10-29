// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! a2 — the DEV-CONTEXT E2E engine proof: one served-LLM draft completes on a1's DURABLE test-kind
//! root, driven through cairn-chirho's real DAG runtime over the FENCED resident handle this crate's
//! `testkind_normal_settlement_resident_opener_chirho` opens.
//!
//! This is the vertical S2b-S3 proved only through the in-memory test harness journal, now driven on
//! a real durable single-node root: fund the payer via a1 (single-node regenesis mint-to-payer), open
//! the durable root through the dev-only test-kind resident door, and run ONE `llm_chirho` paid-effect
//! DAG. The money ladder is asserted through the SAME ledger-host substrate read a1's own proof uses
//! (`read_substrate_balances_chirho`, never the legacy ledger-balances command): payer debited the
//! fixed price, settlement owner credited it, supply conserved, no lingering Hold. The completion
//! rests SEALED to the requesting viewer (readable back only under the viewer principal; the drafted
//! business name reaches no plaintext surface at rest).
//!
//! HOME / CYCLE NOTE. This test lives in the testkind crate (Option 2) because the E2E needs BOTH
//! cairn-chirho (the composition + `run_dag_with_intent_and_effect_runtime_chirho`) AND this crate's
//! wrapper opener; testkind transitively normal-deps cairn-chirho (via cairn-serve-runtime-chirho and
//! cairn-operator-smoke-chirho), so cairn-chirho dev-depping testkind would be a cargo cycle. There is
//! no cairn-chirho -> testkind NORMAL path (the dev-only-edge guard forbids it), so this crate
//! dev-depping cairn-chirho adds no reverse edge and no cycle.

use cairn_chirho::app_chirho::deploy_app_with_head_transition_authority_chirho;
use cairn_chirho::dag_private_value_chirho::load_private_dag_value_bytes_chirho;
use cairn_chirho::durable_chirho::cas_lifecycle_chirho::migrate_cas_lifecycle_offline_chirho;
use cairn_chirho::effect_chirho::llm_served_chirho::{
    AppPriceBookUserPaysLlmPolicyChirho, LocalLlmServedCompositionChirho,
};
use cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_chirho;
use cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho;
use cairn_chirho::effect_pricing_chirho::set_price_book_with_head_transition_authority_chirho;
use cairn_chirho::identity_chirho::{register_identity_chirho, PrincipalKindChirho};
use cairn_chirho::model_chirho::{
    CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, PortChirho, RequestContextChirho,
};
use cairn_chirho::{cas_chirho, store_chirho};
use cairn_config_chirho::config_chirho::{load_config_chirho, LedgerHostConfigChirho};
use cairn_ledger_geo_node_testkind_chirho::{
    testkind_normal_settlement_resident_opener_chirho, TestkindSettlementReportingProviderChirho,
};
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho,
    open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho,
    HostLedgerSignersChirho, NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use cairn_llm_served_effect_chirho::{
    LlmRequestChirho, LlmResponseChirho, StubLlmProviderChirho, LLM_REQUEST_SCHEMA_CHIRHO,
    LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO, LLM_RESPONSE_SCHEMA_CHIRHO,
};
use cairn_serve_runtime_chirho::LedgerHostProjectionReadPortChirho;
use cairn_served_llm_dev_bootstrap_chirho::{
    run_served_llm_dev_bootstrap_chirho, ServedLlmDevBootstrapRequestChirho,
};
use cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho;
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, LLM_SERVED_EFFECT_SUBTYPE_CHIRHO,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const AMOUNT_CHIRHO: u64 = 137;
const LLM_PRICE_CHIRHO: u64 = 7;
const BILLING_KIND_CHIRHO: &str = "llm-credit-chirho";
const SETTLEMENT_OWNER_CHIRHO: &str = "dev-settlement-owner-chirho";
const APP_CHIRHO: &str = "served-llm-dev-e2e-chirho";
const CONFIG_FILE_CHIRHO: &str = "served-llm-dev-config-chirho.toml";

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-served-llm-dev-e2e-{label_chirho}-{}-{nanos_chirho}-{counter_chirho}-chirho",
        std::process::id()
    ))
}

/// The `effect_contract_set` a paid-effect node must carry, built from the SAME canonical
/// descriptor-v2 contract set the runtime verifies against (the in-crate harness uses a `pub(crate)`
/// helper over exactly these two `cairn-undo-plan-chirho` calls; we reach them directly).
fn effect_contract_set_chirho() -> HashChirho {
    contract_set_digest_chirho(&canonical_authoring_reversion_contract_set_chirho())
        .expect("canonical descriptor-v2 contract set")
}

/// A single `llm_chirho` paid-effect node wired into a one-node DAG. A paid effect routes straight to
/// the injected `llm_served` port; the `impl_wasm` marker is never executed as WASM.
fn store_llm_dag_chirho(root_chirho: &Path) -> HashChirho {
    let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: "served-llm-dev-e2e-node-chirho".to_owned(),
        impl_wasm_chirho: cas_chirho::add_chirho(root_chirho, b"served-llm-dev-e2e-node-chirho")
            .unwrap(),
        entry_chirho: "served_llm_dev_e2e_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho,
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            caller_chirho: "served-llm-dev-e2e-runtime-chirho".to_owned(),
        }],
        effect_contract_set_chirho: Some(effect_contract_set_chirho()),
        fuel_limit_chirho: 0,
        ..NodeDefChirho::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

/// A valid `llm-request-v1-chirho` guided brief. `business_name_chirho` rides both the prompt and the
/// stub completion, so ONE needle proves neither the prompt nor the completion leaks in plaintext.
fn valid_request_bytes_chirho(business_name_chirho: &str) -> Vec<u8> {
    let request_chirho = LlmRequestChirho {
        schema_chirho: LLM_REQUEST_SCHEMA_CHIRHO.to_owned(),
        system_chirho: "You draft a small business landing page.".to_owned(),
        user_chirho: format!(
            "Business name: {business_name_chirho}\nServices to list: bread; cakes\nPhone (copy exactly): 555-0100\nEmail (copy exactly): hi@example.test\nHours: 9-5 daily"
        ),
        max_tokens_chirho: None,
        response_format_chirho: LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO.to_owned(),
    };
    serde_json::to_vec(&request_chirho).unwrap()
}

fn contains_subslice_chirho(haystack_chirho: &[u8], needle_chirho: &[u8]) -> bool {
    !needle_chirho.is_empty()
        && haystack_chirho.len() >= needle_chirho.len()
        && haystack_chirho
            .windows(needle_chirho.len())
            .any(|window_chirho| window_chirho == needle_chirho)
}

/// Walk the WHOLE root tree for a plaintext needle, failing CLOSED: EVERY enumerated path must be
/// read successfully, so a `read_dir`, directory-entry, file-type, or file-read error REFUSES the
/// scan (`Err`) rather than silently reporting "no plaintext". Returns `(found, read_count)` only
/// when the entire tree was read; the caller may assert `!found` (no PII at rest) ONLY on that
/// complete-coverage `Ok`, never on a partial read that skipped the surface holding the secret. The
/// completion rests only as a sealed viewer-subject blob (ciphertext), so the plaintext needle must
/// appear on NO surface.
fn scan_root_for_needle_chirho(
    root_chirho: &Path,
    needle_chirho: &[u8],
) -> std::io::Result<(bool, u64)> {
    fn walk_chirho(
        dir_chirho: &Path,
        needle_chirho: &[u8],
        read_count_chirho: &mut u64,
    ) -> std::io::Result<bool> {
        for entry_chirho in std::fs::read_dir(dir_chirho)? {
            let entry_chirho = entry_chirho?;
            let path_chirho = entry_chirho.path();
            if entry_chirho.file_type()?.is_dir() {
                if walk_chirho(&path_chirho, needle_chirho, read_count_chirho)? {
                    return Ok(true);
                }
            } else {
                let bytes_chirho = std::fs::read(&path_chirho)?;
                *read_count_chirho += 1;
                if contains_subslice_chirho(&bytes_chirho, needle_chirho) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    let mut read_count_chirho = 0;
    let found_chirho = walk_chirho(root_chirho, needle_chirho, &mut read_count_chirho)?;
    Ok((found_chirho, read_count_chirho))
}

/// POSITIVE CONTROL for the fail-closed plaintext scanner. On a fully readable tree the scan
/// completes (`Ok`), reads every file, and can both MISS an absent needle and FIND a planted one
/// (liveness — the instrument can fire). Planting a SINGLE unreadable file (mode `000`) then makes
/// the same scan REFUSE (`Err`) instead of silently returning "clean", which proves the
/// no-plaintext claim rests on COMPLETE coverage rather than on a partial read that skipped the
/// surface holding the secret. The fail-closed scan uses an ABSENT needle so the walk cannot
/// early-return `Ok(true)` before it must read the unreadable surface (order-independent).
#[cfg(unix)]
#[test]
fn the_plaintext_scanner_refuses_an_unreadable_surface_chirho() {
    use std::os::unix::fs::PermissionsExt;

    let root_chirho = temp_root_chirho("scanner-fail-closed-control");
    std::fs::create_dir_all(root_chirho.join("nested-chirho")).unwrap();
    std::fs::write(root_chirho.join("a-chirho.bin"), b"harmless-chirho").unwrap();
    std::fs::write(
        root_chirho.join("nested-chirho/b-chirho.bin"),
        b"also-harmless-chirho",
    )
    .unwrap();

    // Liveness 1: a fully readable tree scans to completion, reads every file, and misses an
    // absent needle.
    let (found_chirho, read_count_chirho) =
        scan_root_for_needle_chirho(&root_chirho, b"absent-needle-chirho")
            .expect("a fully readable tree must scan to completion");
    assert!(!found_chirho, "the control tree holds no needle yet");
    assert_eq!(
        read_count_chirho, 2,
        "the scan must read BOTH planted files"
    );

    // Liveness 2: the instrument must be able to FIRE — a planted needle is found.
    std::fs::write(
        root_chirho.join("nested-chirho/c-chirho.bin"),
        b"prefix-present-needle-chirho-suffix",
    )
    .unwrap();
    let (found_chirho, _read_count_chirho) =
        scan_root_for_needle_chirho(&root_chirho, b"present-needle-chirho")
            .expect("a fully readable tree must scan to completion");
    assert!(found_chirho, "the scan must find a planted needle");

    // FAIL-CLOSED: one unreadable file (mode 000) makes the WHOLE scan refuse, not skip. The needle
    // is absent, so the walk cannot short-circuit before it must read the sealed surface.
    let unreadable_chirho = root_chirho.join("sealed-chirho.bin");
    std::fs::write(&unreadable_chirho, b"sealed-body-chirho").unwrap();
    std::fs::set_permissions(&unreadable_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
    let refusal_chirho = scan_root_for_needle_chirho(&root_chirho, b"absent-needle-chirho");
    assert!(
        refusal_chirho.is_err(),
        "an unreadable surface must REFUSE the scan (fail-closed), never silently report clean"
    );

    // Restore perms so cleanup can remove the tree.
    let _restored_chirho =
        std::fs::set_permissions(&unreadable_chirho, std::fs::Permissions::from_mode(0o644));
    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}

/// Fund a fresh test-kind root through a1's dev bootstrap, returning the canonical root, its config
/// path, and the parsed ledger-host config block. The payer is `payer_chirho` (the same principal the
/// serving side authenticates as), so the served-LLM Hold later debits the account a1 funded.
fn fund_a1_root_chirho(
    label_chirho: &str,
    payer_chirho: &str,
) -> (PathBuf, PathBuf, LedgerHostConfigChirho) {
    let root_chirho = temp_root_chirho(label_chirho);
    let report_chirho = run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: payer_chirho,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho: AMOUNT_CHIRHO,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    })
    .expect("a1 dev bootstrap must fund the payer");
    assert_eq!(report_chirho.config_file_chirho, CONFIG_FILE_CHIRHO);
    let canonical_root_chirho = root_chirho
        .canonicalize()
        .expect("canonical bootstrap root");
    let config_path_chirho = canonical_root_chirho.join(&report_chirho.config_file_chirho);
    let config_chirho = load_config_chirho(&config_path_chirho).expect("load a1 authored config");
    let ledger_host_chirho = config_chirho
        .ledger_host_chirho
        .expect("a1 config carries a ledger host block");
    (
        canonical_root_chirho,
        config_path_chirho,
        ledger_host_chirho,
    )
}

/// THE PROOF + POSITIVE CONTROL: one served-LLM draft completes on a1's durable root, the money
/// ladder conserves (payer debited the fixed price, settlement credited it, supply unchanged, no
/// Hold), and the completion rests SEALED to the requesting viewer with no plaintext at rest.
///
/// Because this arm proves the ladder really charges settlement, neutering the settlement credit (or
/// the payer debit) in the composition reddens the named balance assertions below.
///
/// a1's config carries `loss_witness_exempt_chirho: true` and this test opens the root through the
/// dedicated normal-settlement dev door (`testkind_normal_settlement_resident_opener_chirho`), which
/// selects the exemption-permitted opener mode — so the resident actor derives no CF8 loss-witness
/// plan (a single-node dev served-money root has no drill to witness). Any drill/shared-elector/
/// compensation door selects the mandatory-witness mode and would refuse this exempt config with
/// `Cf8LossWitnessDrillExemptionRefusedChirho`; that door-level confinement is proven separately in
/// `an_exempt_config_through_a_drill_door_cannot_suppress_the_witness_chirho`.
#[test]
fn served_llm_draft_completes_on_a1_root_conserved_and_sealed_chirho() {
    let root_chirho = temp_root_chirho("complete-ids");
    std::fs::create_dir_all(&root_chirho).unwrap();
    // Register the owner (app authority) and the user (the payer) FIRST, so the payer principal a1
    // funds is exactly the principal the served-LLM effect authenticates as and debits.
    let owner_chirho = register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
        .expect("register owner identity")
        .principal_chirho;
    let user_chirho = register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho)
        .expect("register user identity")
        .principal_chirho;

    // Fund the payer via a1 on THIS root (the bootstrap creates the ledger genesis + mint alongside
    // the identity records already written above).
    let report_chirho = run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: &user_chirho,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho: AMOUNT_CHIRHO,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    })
    .expect("a1 dev bootstrap must fund the payer");
    let canonical_root_chirho = root_chirho.canonicalize().expect("canonical root");
    let config_path_chirho = canonical_root_chirho.join(&report_chirho.config_file_chirho);
    let ledger_host_chirho = load_config_chirho(&config_path_chirho)
        .expect("load a1 config")
        .ledger_host_chirho
        .expect("a1 config carries a ledger host block");

    // a1's regenesis root carries no CAS lifecycle state, but the ELECTED app-control-plane deploy
    // path (deploy_app + price book through the resident authority) requires an initialized CAS
    // lifecycle. The root is quiescent here (a1 finished; no resident actor open yet), so the
    // sanctioned offline migration is the correct initializer for this populated dev root. Durable-
    // store setup only — it touches no money, authority, or ledger state.
    migrate_cas_lifecycle_offline_chirho(&canonical_root_chirho)
        .expect("initialize the CAS lifecycle on a1's populated dev root");

    // Build the one-node llm DAG and load the six runtime signers (custody-derived from the root's
    // own secret store).
    let dag_hash_chirho = store_llm_dag_chirho(&canonical_root_chirho);
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&ledger_host_chirho.signer_secrets_chirho)
            .expect("derive signer refs from config");
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&canonical_root_chirho, &signer_refs_chirho)
            .expect("load the runtime signers");

    let pii_needle_chirho = "Zzyzx-A2-Served-Completion-Needle-Chirho";
    let request_bytes_chirho = valid_request_bytes_chirho(pii_needle_chirho);

    let payload_hash_chirho;
    {
        // Open the durable root through the DEV-ONLY test-kind resident door. This handle IS the
        // elected write authority: a1's regenesis root requires the elected authority for every
        // app-control-plane and ledger write, so the app deploy, the price book, and the served
        // effect all go through it.
        let mut handle_chirho = testkind_normal_settlement_resident_opener_chirho(
            &canonical_root_chirho,
            &config_path_chirho,
            &ledger_host_chirho,
        )
        .expect("open a1's durable test-kind root through the dev-only door");

        // Deploy the app (bound to the llm dag) and set the price book (llm_chirho = 7), both through
        // the resident handle's elected head-transition authority.
        deploy_app_with_head_transition_authority_chirho(
            &canonical_root_chirho,
            APP_CHIRHO,
            dag_hash_chirho.clone(),
            &owner_chirho,
            handle_chirho.head_transition_authority_chirho(),
        )
        .expect("deploy the e2e app bound to the llm dag");
        let (price_book_chirho, _, _) = set_price_book_with_head_transition_authority_chirho(
            &canonical_root_chirho,
            APP_CHIRHO,
            &owner_chirho,
            None,
            BTreeMap::from([(
                LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
                LLM_PRICE_CHIRHO as i64,
            )]),
            0,
            handle_chirho.head_transition_authority_chirho(),
        )
        .expect("set the served-LLM price book");

        let context_chirho = RequestContextChirho {
            user_principal_chirho: user_chirho.clone(),
            app_chirho: APP_CHIRHO.to_owned(),
            owner_principal_chirho: owner_chirho.clone(),
            client_id_chirho: "client-served-llm-dev-e2e-chirho".to_owned(),
            token_hash_chirho: "token-served-llm-dev-e2e-chirho".to_owned(),
            price_book_chirho: Some(price_book_chirho),
            billing_policy_chirho: None,
            key_limit_chirho: None,
        };

        let mut composition_chirho = LocalLlmServedCompositionChirho::open_chirho(
            &canonical_root_chirho,
            &mut handle_chirho,
            signers_chirho.effect_intent_signer_chirho(),
            signers_chirho.effect_terminal_signer_chirho(),
            &AppPriceBookUserPaysLlmPolicyChirho,
            &StubLlmProviderChirho,
            AssetKindIdChirho(BILLING_KIND_CHIRHO.to_owned()),
        )
        .expect("open the served-LLM composition over the fenced resident handle");

        // PRIVATE input: the prompt carries the drafted business name (PII), so it is stored as a
        // viewer-subject private blob (not public CAS) before it reaches the DAG. This satisfies the
        // "no PII at rest" proof target; the public-input run_dag variant would rest the prompt in
        // public CAS.
        let run_report_chirho = run_dag_with_private_input_intent_and_effect_runtime_chirho(
            &canonical_root_chirho,
            &dag_hash_chirho,
            &user_chirho,
            &request_bytes_chirho,
            Some(&context_chirho),
            DagEffectRuntimePortsChirho {
                projection_read_chirho: None,
                postgres_reversible_chirho: None,
                llm_served_chirho: Some(&mut composition_chirho),
                // A signed-in run: its context attributes its private values.
                private_attribution_chirho: None,
            },
        )
        .expect("one served-LLM draft must complete through the DAG runtime");

        // THE CARD COMPLETES: the payload is a real stub first-draft body carrying the drafted name.
        let response_chirho: LlmResponseChirho =
            serde_json::from_slice(&run_report_chirho.payload_chirho)
                .expect("the completion payload is an llm-response-v1");
        assert_eq!(response_chirho.schema_chirho, LLM_RESPONSE_SCHEMA_CHIRHO);
        assert!(
            response_chirho
                .completion_chirho
                .contains(pii_needle_chirho),
            "the completed draft must carry the drafted business name"
        );
        payload_hash_chirho = run_report_chirho.payload_hash_chirho;

        // Drop the composition then the handle so the exclusive ledger lock is released before the
        // read-only substrate read below opens the journal.
        drop(composition_chirho);
        drop(handle_chirho);
    }

    // THE MONEY LADDER, via the ledger-host substrate read a1's own proof uses (never ledger-balances).
    let port_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &canonical_root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )
    .expect("open the durable ledger host read door");
    let balances_chirho = port_chirho
        .read_substrate_balances_chirho()
        .expect("read verified substrate balances");

    let payer_key_chirho = (user_chirho.clone(), BILLING_KIND_CHIRHO.to_owned());
    let settlement_key_chirho = (
        SETTLEMENT_OWNER_CHIRHO.to_owned(),
        BILLING_KIND_CHIRHO.to_owned(),
    );
    let payer_net_chirho = balances_chirho
        .account_nets_chirho
        .get(&payer_key_chirho)
        .copied()
        .expect("payer has a ledger account");
    let settlement_net_chirho = balances_chirho
        .account_nets_chirho
        .get(&settlement_key_chirho)
        .copied()
        .unwrap_or(0);
    assert_eq!(
        payer_net_chirho,
        AMOUNT_CHIRHO - LLM_PRICE_CHIRHO,
        "payer net must be minted amount minus the fixed per-draft price"
    );
    assert_eq!(
        settlement_net_chirho, LLM_PRICE_CHIRHO,
        "settlement owner must be credited exactly the fixed per-draft price"
    );
    // Money conservation on the served leg: what the payer was debited equals what settlement gained.
    let payer_debit_chirho = AMOUNT_CHIRHO - payer_net_chirho;
    assert_eq!(
        payer_debit_chirho, settlement_net_chirho,
        "the served leg conserves money: the payer's debit equals settlement's credit"
    );
    assert_eq!(
        payer_debit_chirho, LLM_PRICE_CHIRHO,
        "exactly the fixed per-draft price moved from payer to settlement"
    );
    assert_eq!(
        balances_chirho
            .net_supply_by_kind_chirho
            .get(BILLING_KIND_CHIRHO)
            .copied(),
        Some(AMOUNT_CHIRHO),
        "supply is conserved: a within-kind settlement never changes minted supply"
    );
    assert!(
        balances_chirho
            .account_held_chirho
            .values()
            .all(|held_chirho| *held_chirho == 0),
        "no Hold remains anywhere after the draft Finalizes"
    );
    drop(port_chirho);

    // SEALED TO THE VIEWER: the completion rests only as a viewer-subject private blob. The viewer
    // reads it back through the private plane; the plaintext needle reaches NO surface at rest.
    let sealed_bytes_chirho = load_private_dag_value_bytes_chirho(
        &canonical_root_chirho,
        &user_chirho,
        &payload_hash_chirho,
    )
    .expect("the viewer reads back its own sealed completion");
    let sealed_response_chirho: LlmResponseChirho = serde_json::from_slice(&sealed_bytes_chirho)
        .expect("the sealed completion is an llm-response");
    assert!(
        sealed_response_chirho
            .completion_chirho
            .contains(pii_needle_chirho),
        "the viewer's sealed completion carries the drafted business name"
    );

    // VIEWER ISOLATION (proves the store_seal_response_subject alignment SEALS, not leaks): a DIFFERENT
    // principal cannot resolve the viewer's sealed completion, and the completion is NOT resolvable as
    // a public CAS object. The run_dag path learned the viewer subject only; it opened no new access.
    let other_principal_chirho = format!("{owner_chirho}-not-the-viewer-chirho");
    assert!(
        other_principal_chirho != user_chirho,
        "the isolation probe principal must differ from the viewer"
    );
    assert!(
        load_private_dag_value_bytes_chirho(
            &canonical_root_chirho,
            &other_principal_chirho,
            &payload_hash_chirho,
        )
        .is_err(),
        "a non-viewer principal must NOT resolve the viewer's sealed completion (no cross-viewer read)"
    );
    assert!(
        cas_chirho::get_chirho(&canonical_root_chirho, &payload_hash_chirho).is_err(),
        "the sealed completion must not be resolvable as a public CAS object (no public read)"
    );

    // Fail-closed: the scan must read EVERY surface under the root (an unreadable path returns
    // `Err`, never a silent "clean"). Only a complete-coverage `Ok` earns the no-plaintext assert.
    let (found_chirho, read_count_chirho) = scan_root_for_needle_chirho(
        &canonical_root_chirho,
        pii_needle_chirho.as_bytes(),
    )
    .expect(
        "the plaintext scan must read every surface under the root to completion (fail-closed); \
             an unreadable path refuses the scan rather than under-reporting",
    );
    assert!(
        read_count_chirho > 0,
        "the surface scan must have read at least one file (else it proves nothing)"
    );
    assert!(
        !found_chirho,
        "the drafted business name must not rest in plaintext on ANY surface under the root"
    );

    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}

/// FAIL-CLOSED: the dev-only door (through the wrapper) REFUSES a root a1 never bootstrapped, and
/// seeds NO ledger genesis. The config handed in is a valid test-kind config from a separately funded
/// donor root, so the refusal cannot be the inverse fence — it must be absent ledger/custody, which is
/// exactly the `open_existing_durable_single_node` refusal that must never silently re-genesis.
#[test]
fn bootstrap_never_ran_refuses_and_seeds_no_genesis_chirho() {
    // A valid test-kind config from a donor root a1 DID bootstrap (so the fence would pass).
    let (_donor_root_chirho, _donor_config_path_chirho, donor_config_chirho) =
        fund_a1_root_chirho("donor", "donor-payer-chirho");

    // A fresh root a1 NEVER bootstrapped: no config file, no secrets, no ledger.
    let never_root_chirho = temp_root_chirho("never-ran");
    std::fs::create_dir_all(&never_root_chirho).unwrap();
    let never_config_path_chirho = never_root_chirho.join(CONFIG_FILE_CHIRHO);

    let error_chirho = testkind_normal_settlement_resident_opener_chirho(
        &never_root_chirho,
        &never_config_path_chirho,
        &donor_config_chirho,
    )
    .map(|_handle_chirho| ())
    .expect_err("opening an un-bootstrapped root must refuse");
    let error_text_chirho = format!("{error_chirho:#}");
    assert!(
        !error_text_chirho.contains(NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the refusal must NOT be the inverse fence (the config IS test-kind); it must be absent \
         ledger/custody, got: {error_text_chirho}"
    );
    assert!(
        !never_root_chirho
            .join("fresh-ledger-parent-chirho")
            .exists(),
        "the dev-only door must never silently seed genesis on an un-bootstrapped root"
    );

    let _removed_a_chirho = std::fs::remove_dir_all(&never_root_chirho);
    let _removed_b_chirho = std::fs::remove_dir_all(&_donor_root_chirho);
}

/// FAIL-CLOSED: the dev-only door (through the wrapper) REFUSES a production (non-test-kind) config by
/// the inverse-fence identity, before touching the root. Breaking `require_test_kind_marked_host_config_chirho`
/// so it admits an unmarked config reddens this arm.
#[test]
fn the_dev_door_refuses_a_production_config_via_the_wrapper_chirho() {
    let (donor_root_chirho, donor_config_path_chirho, mut production_config_chirho) =
        fund_a1_root_chirho("production-config", "prod-payer-chirho");
    // Strip the test-kind marker in memory: this is now a production-shaped config.
    production_config_chirho.test_kind_chirho = None;

    let error_chirho = testkind_normal_settlement_resident_opener_chirho(
        &donor_root_chirho,
        &donor_config_path_chirho,
        &production_config_chirho,
    )
    .map(|_handle_chirho| ())
    .expect_err("the dev-only door must refuse a production (unmarked) config");
    let error_text_chirho = format!("{error_chirho:#}");
    assert!(
        error_text_chirho.contains(NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the dev-only door must refuse a production config by the inverse-fence identity, got: \
         {error_text_chirho}"
    );

    let _removed_chirho = std::fs::remove_dir_all(&donor_root_chirho);
}

/// THE CONFINEMENT PROOF (required door-level negative): the SAME exempt config a1 authors, opened
/// through a real DRILL door (the GD7 compensation-provider entrypoint, which selects the
/// mandatory-witness opener mode), CANNOT suppress its loss-witness. The actor refuses at startup with
/// `Cf8LossWitnessDrillExemptionRefusedChirho`, before any plan is skipped — proving the exemption is
/// confined to WHO opened the actor (only the dedicated dev door), not to the argument shape. This
/// must go through the actual door, because mode selection + propagation are exactly what a hand-picked
/// enum passed to the derive helper cannot exercise.
#[test]
fn an_exempt_config_through_a_drill_door_cannot_suppress_the_witness_chirho() {
    // a1 authors loss_witness_exempt_chirho: true; this is that exact exempt, custody-valid root.
    let (canonical_root_chirho, config_path_chirho, ledger_host_chirho) =
        fund_a1_root_chirho("drill-door-negative", "drill-door-neg-payer-chirho");

    // Open the exempt root through a real GD7 compensation-provider DRILL door (mandatory-witness
    // opener mode). It reaches the loss-witness gate after validate + custody on the valid root, and
    // fails closed: a drill cannot borrow the dev exemption by presenting an exempt marker.
    let error_chirho = open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho(
        &canonical_root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
        None,
        Box::new(TestkindSettlementReportingProviderChirho::new_chirho()),
    )
    .map(|_handle_chirho| ())
    .expect_err("a drill door must refuse an exempt config's witness suppression");
    let error_text_chirho = format!("{error_chirho:#}");
    assert!(
        error_text_chirho.contains("Cf8LossWitnessDrillExemptionRefusedChirho"),
        "a drill door must refuse an exempt marker with the drill-exemption identity, got: \
         {error_text_chirho}"
    );

    let _removed_chirho = std::fs::remove_dir_all(&canonical_root_chirho);
}
