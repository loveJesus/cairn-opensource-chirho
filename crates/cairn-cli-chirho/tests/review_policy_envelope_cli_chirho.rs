// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::model_chirho::{DagChirho, HashChirho, NodeDefChirho, PortChirho};
use cairn_chirho::{app_chirho, cas_chirho, identity_chirho, store_chirho};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-review-policy-cli-test-{n_chirho}-{}",
        now_ms_chirho()
    ))
}

fn node_chirho(root_chirho: &Path, name_chirho: &str) -> HashChirho {
    let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let wasm_chirho = cas_chirho::add_chirho(root_chirho, name_chirho.as_bytes()).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &NodeDefChirho {
            name_chirho: name_chirho.to_string(),
            impl_wasm_chirho: wasm_chirho,
            entry_chirho: name_chirho.to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho,
            }],
            fuel_limit_chirho: 1,
            ..Default::default()
        },
    )
    .unwrap()
}

fn dag_chirho(root_chirho: &Path, name_chirho: &str) -> HashChirho {
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_chirho(root_chirho, name_chirho)],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

#[test]
fn review_promote_prints_no_envelope_label_chirho() {
    let root_chirho = temp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let live_chirho = dag_chirho(&root_chirho, "review_policy_cli_live_chirho");
    app_chirho::deploy_app_chirho(&root_chirho, "reviewpolicycli", live_chirho, &owner_chirho)
        .unwrap();
    let candidate_chirho = dag_chirho(&root_chirho, "review_policy_cli_candidate_chirho");

    let output_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-chirho"))
        .args([
            "--root",
            root_chirho.to_str().unwrap(),
            "review-promote",
            "--app",
            "reviewpolicycli",
            "--owner",
            &owner_chirho,
            "--candidate",
            &candidate_chirho.0,
        ])
        .output()
        .unwrap();

    assert!(
        output_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output_chirho.stdout).contains(
            "review_policy_envelope=none:no review-policy envelope bound this promote:checked=0"
        ),
        "stdout: {}",
        String::from_utf8_lossy(&output_chirho.stdout)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
