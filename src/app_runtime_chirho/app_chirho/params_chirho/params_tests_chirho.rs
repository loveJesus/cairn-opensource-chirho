// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::model_chirho::{DagChirho, HashChirho};
use crate::{cas_chirho, identity_chirho, store_chirho};
use std::path::{Path, PathBuf};
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
    std::env::temp_dir().join(format!("cairn-app-params-test-{nanos_chirho}-{n_chirho}"))
}

fn owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho
}

fn fake_dag_chirho(root_chirho: &Path) -> HashChirho {
    let marker_chirho = cas_chirho::add_chirho(root_chirho, b"app-params-test").unwrap();
    let dag_chirho = DagChirho {
        nodes_chirho: vec![marker_chirho],
        edges_chirho: Vec::new(),
    };
    store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap()
}

fn object_path_for_hash_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&hash_chirho.0[0..2])
        .join(&hash_chirho.0[2..])
}

#[test]
fn app_params_select_route_override_and_verify_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let root_dag_chirho = fake_dag_chirho(&root_chirho);
    let route_dag_chirho = fake_dag_chirho(&root_chirho);
    crate::app_chirho::deploy_app_chirho(&root_chirho, "template", root_dag_chirho, &owner_chirho)
        .unwrap();
    crate::app_chirho::deploy_app_route_chirho(
        &root_chirho,
        "template",
        "landing",
        route_dag_chirho,
        &owner_chirho,
    )
    .unwrap();

    set_app_params_chirho(
        &root_chirho,
        "template",
        None,
        &owner_chirho,
        &serde_json::json!({"business_name_chirho":"Root Cafe"}),
        true,
    )
    .unwrap();
    set_app_params_chirho(
        &root_chirho,
        "template",
        Some("landing"),
        &owner_chirho,
        &serde_json::json!({"business_name_chirho":"Route Cafe"}),
        true,
    )
    .unwrap();

    assert_eq!(verify_app_params_chirho(&root_chirho).unwrap(), 2);
    let root_params_chirho =
        app_params_chirho(&root_chirho, "template", None, &owner_chirho).unwrap();
    assert_eq!(
        root_params_chirho.unwrap().value_chirho["business_name_chirho"],
        "Root Cafe"
    );
    let route_params_chirho =
        app_params_chirho(&root_chirho, "template", Some("landing"), &owner_chirho).unwrap();
    assert_eq!(
        route_params_chirho.unwrap().value_chirho["business_name_chirho"],
        "Route Cafe"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_params_fail_closed_on_tamper_missing_object_and_unknown_route_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho);
    crate::app_chirho::deploy_app_chirho(&root_chirho, "template", dag_chirho, &owner_chirho)
        .unwrap();

    let route_error_chirho = set_app_params_chirho(
        &root_chirho,
        "template",
        Some("missing"),
        &owner_chirho,
        &serde_json::json!({"business_name_chirho":"Ignored"}),
        true,
    )
    .unwrap_err();
    let route_error_text_chirho = route_error_chirho.to_string();
    assert!(route_error_text_chirho.contains("route"));
    assert!(route_error_text_chirho.contains("missing"));

    let record_chirho = set_app_params_chirho(
        &root_chirho,
        "template",
        None,
        &owner_chirho,
        &serde_json::json!({"business_name_chirho":"Root Cafe"}),
        true,
    )
    .unwrap();
    let records_path_chirho = app_params_records_path_chirho(&root_chirho);
    let text_chirho = std::fs::read_to_string(&records_path_chirho).unwrap();
    std::fs::write(
        &records_path_chirho,
        text_chirho.replace("\"required_chirho\":true", "\"required_chirho\":false"),
    )
    .unwrap();
    let tamper_error_chirho = verify_app_params_chirho(&root_chirho).unwrap_err();
    assert!(tamper_error_chirho
        .to_string()
        .contains("signature invalid"));

    // The signed log is restored rather than deleted: a log seen present that disappears is refused, never read as
    // empty (the shared absence brick).
    std::fs::write(&records_path_chirho, &text_chirho).unwrap();
    set_app_params_hash_chirho(
        &root_chirho,
        "template",
        None,
        &owner_chirho,
        record_chirho.params_chirho.clone(),
        true,
    )
    .unwrap();
    std::fs::remove_file(object_path_for_hash_chirho(
        &root_chirho,
        &record_chirho.params_chirho,
    ))
    .unwrap();
    let missing_error_chirho =
        app_params_chirho(&root_chirho, "template", None, &owner_chirho).unwrap_err();
    let missing_error_text_chirho = missing_error_chirho.to_string();
    assert!(missing_error_text_chirho.contains("app params record"));
    assert!(missing_error_text_chirho.contains("missing params"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
