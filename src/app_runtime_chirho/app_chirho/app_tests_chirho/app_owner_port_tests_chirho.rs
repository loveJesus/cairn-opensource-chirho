// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::{DagChirho, HashChirho};
use crate::store_chirho;
use cairn_economic_governance_chirho::ports_chirho::EconomicGovernanceAppOwnerPortChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-app-owner-port-test-{nanos_chirho}-{n_chirho}"
    ))
}

fn fake_dag_chirho(root_chirho: &std::path::Path, marker_chirho: &[u8]) -> HashChirho {
    let marker_hash_chirho = crate::cas_chirho::add_chirho(root_chirho, marker_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

fn write_identity_records_chirho(
    root_chirho: &std::path::Path,
    records_chirho: &[identity_chirho::IdentityRecordChirho],
) {
    let mut jsonl_chirho = String::new();
    for record_chirho in records_chirho {
        jsonl_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        jsonl_chirho.push('\n');
    }
    std::fs::write(root_chirho.join("identities-chirho.jsonl"), jsonl_chirho).unwrap();
}

fn assert_deploy_refuses_identity_mutation_without_app_state_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &identity_chirho::IdentityRecordChirho,
    expected_error_chirho: &str,
    marker_chirho: &[u8],
) {
    let app_chirho = "identity-authority-app";
    let dag_chirho = fake_dag_chirho(root_chirho, marker_chirho);
    let records_before_chirho = load_app_records_chirho(root_chirho).unwrap();
    let refs_before_chirho = refs_chirho::load_refs_chirho(root_chirho).unwrap();

    let error_chirho = deploy_app_chirho(
        root_chirho,
        app_chirho,
        dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains(expected_error_chirho),
        "unexpected deploy refusal: {error_chirho}"
    );
    assert_eq!(
        load_app_records_chirho(root_chirho).unwrap(),
        records_before_chirho,
        "identity refusal must precede any app record append"
    );
    assert_eq!(
        refs_chirho::load_refs_chirho(root_chirho).unwrap(),
        refs_before_chirho,
        "identity refusal must precede any app branch movement"
    );
}

#[test]
fn app_owner_gate_refuses_forged_identity_signature_before_app_state_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let mut forged_owner_chirho = owner_chirho.clone();
    let replacement_chirho = if forged_owner_chirho.sig_chirho.starts_with('0') {
        "1"
    } else {
        "0"
    };
    forged_owner_chirho
        .sig_chirho
        .replace_range(..1, replacement_chirho);
    write_identity_records_chirho(&root_chirho, &[forged_owner_chirho]);

    assert_deploy_refuses_identity_mutation_without_app_state_chirho(
        &root_chirho,
        &owner_chirho,
        "identity entry 0 signature invalid",
        b"forged identity signature",
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_owner_gate_refuses_identity_seq_gap_before_app_state_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let mut gapped_owner_chirho = owner_chirho.clone();
    gapped_owner_chirho.seq_chirho = 1;
    write_identity_records_chirho(&root_chirho, &[gapped_owner_chirho]);

    assert_deploy_refuses_identity_mutation_without_app_state_chirho(
        &root_chirho,
        &owner_chirho,
        "identity seq gap at index 0: entry seq is 1",
        b"identity seq gap",
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn root_app_owner_port_preserves_verified_owner_gate_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_a_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let owner_b_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "port-owner-app",
        fake_dag_chirho(&root_chirho, b"port owner app"),
        &owner_a_chirho.principal_chirho,
    )
    .unwrap();

    let port_chirho = RootAppOwnerPortChirho;
    assert_eq!(
        port_chirho
            .verified_app_owner_chirho(&root_chirho, "port-owner-app")
            .unwrap(),
        Some(owner_a_chirho.principal_chirho.clone())
    );
    port_chirho
        .ensure_app_owner_chirho(
            &root_chirho,
            "port-owner-app",
            &owner_a_chirho.principal_chirho,
        )
        .unwrap();
    let error_chirho = port_chirho
        .ensure_app_owner_chirho(
            &root_chirho,
            "port-owner-app",
            &owner_b_chirho.principal_chirho,
        )
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("is owned by"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
