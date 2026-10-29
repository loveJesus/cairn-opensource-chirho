// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::model_chirho::DagChirho;
use crate::{app_chirho, identity_chirho, store_chirho};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-app-static-asset-{label_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho).unwrap();
    }
    let mut out_chirho = String::new();
    for record_chirho in records_chirho {
        out_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        out_chirho.push('\n');
    }
    std::fs::write(path_chirho, out_chirho).unwrap();
}

fn fake_dag_chirho(root_chirho: &Path, marker_chirho: &[u8]) -> HashChirho {
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

fn cas_object_path_for_test_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&hash_chirho.0[0..2])
        .join(&hash_chirho.0[2..])
}

fn deployed_owner_app_chirho(label_chirho: &str) -> (PathBuf, String) {
    let root_chirho = tmp_root_chirho(label_chirho);
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    app_chirho::deploy_app_chirho(
        &root_chirho,
        "asset-app-chirho",
        fake_dag_chirho(&root_chirho, label_chirho.as_bytes()),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    (root_chirho, owner_chirho.principal_chirho)
}

#[test]
fn css_asset_record_serves_by_name_and_hash_chirho() {
    let (root_chirho, owner_chirho) = deployed_owner_app_chirho("success");
    let record_chirho = set_app_static_asset_bytes_chirho(
        &root_chirho,
        "asset-app-chirho",
        &owner_chirho,
        "site-chirho.css",
        "text/css",
        b"body { color: #123456; }\n",
    )
    .unwrap();

    assert_eq!(
        record_chirho.content_type_chirho,
        APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(verify_app_static_assets_chirho(&root_chirho).unwrap(), 1);
    let by_name_chirho =
        app_static_asset_by_name_chirho(&root_chirho, "asset-app-chirho", "site-chirho.css")
            .unwrap()
            .unwrap();
    assert_eq!(
        by_name_chirho.record_chirho.asset_chirho,
        record_chirho.asset_chirho
    );
    let by_hash_chirho = app_static_asset_by_hash_chirho(
        &root_chirho,
        "asset-app-chirho",
        &record_chirho.asset_chirho,
    )
    .unwrap()
    .unwrap();
    assert_eq!(by_hash_chirho.record_chirho.name_chirho, "site-chirho.css");
    assert_eq!(
        app_static_asset_bytes_chirho(&root_chirho, &by_hash_chirho).unwrap(),
        b"body { color: #123456; }\n"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn binary_asset_record_serves_by_name_and_hash_chirho() {
    let (root_chirho, owner_chirho) = deployed_owner_app_chirho("binary");
    let png_bytes_chirho = b"\x89PNG\r\n\x1a\nproof-chirho";
    let record_chirho = set_app_static_asset_bytes_chirho(
        &root_chirho,
        "asset-app-chirho",
        &owner_chirho,
        "logo-chirho.png",
        "image/png",
        png_bytes_chirho,
    )
    .unwrap();

    assert_eq!(
        record_chirho.content_type_chirho,
        APP_STATIC_ASSET_PNG_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(verify_app_static_assets_chirho(&root_chirho).unwrap(), 1);
    let by_name_chirho =
        app_static_asset_by_name_chirho(&root_chirho, "asset-app-chirho", "logo-chirho.png")
            .unwrap()
            .unwrap();
    assert_eq!(
        by_name_chirho.record_chirho.asset_chirho,
        record_chirho.asset_chirho
    );
    assert_eq!(
        app_static_asset_bytes_chirho(&root_chirho, &by_name_chirho).unwrap(),
        png_bytes_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn font_asset_record_serves_by_name_and_hash_chirho() {
    let (root_chirho, owner_chirho) = deployed_owner_app_chirho("font");
    let font_bytes_chirho = b"wOF2 font proof chirho";
    let record_chirho = set_app_static_asset_bytes_chirho(
        &root_chirho,
        "asset-app-chirho",
        &owner_chirho,
        "brand-chirho.woff2",
        "font/woff2",
        font_bytes_chirho,
    )
    .unwrap();

    assert_eq!(
        record_chirho.content_type_chirho,
        cairn_model_app_chirho::APP_STATIC_ASSET_WOFF2_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(verify_app_static_assets_chirho(&root_chirho).unwrap(), 1);
    let by_name_chirho =
        app_static_asset_by_name_chirho(&root_chirho, "asset-app-chirho", "brand-chirho.woff2")
            .unwrap()
            .unwrap();
    assert_eq!(
        by_name_chirho.record_chirho.asset_chirho,
        record_chirho.asset_chirho
    );
    assert_eq!(
        app_static_asset_bytes_chirho(&root_chirho, &by_name_chirho).unwrap(),
        font_bytes_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn css_asset_record_rejects_wrong_owner_chirho() {
    let (root_chirho, _owner_chirho) = deployed_owner_app_chirho("owner");
    let other_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let error_chirho = set_app_static_asset_bytes_chirho(
        &root_chirho,
        "asset-app-chirho",
        &other_chirho.principal_chirho,
        "site-chirho.css",
        "text/css",
        b"body{}",
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("is owned by"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn css_asset_record_rejects_unsupported_mime_chirho() {
    let (root_chirho, owner_chirho) = deployed_owner_app_chirho("mime");
    let error_chirho = set_app_static_asset_bytes_chirho(
        &root_chirho,
        "asset-app-chirho",
        &owner_chirho,
        "site-chirho.css",
        "text/html",
        b"<script></script>",
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("must be one of"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn static_asset_verification_fails_when_cas_bytes_are_tampered_chirho() {
    let (root_chirho, owner_chirho) = deployed_owner_app_chirho("cas-tamper");
    let record_chirho = set_app_static_asset_bytes_chirho(
        &root_chirho,
        "asset-app-chirho",
        &owner_chirho,
        "site-chirho.css",
        "text/css",
        b"body { color: green; }",
    )
    .unwrap();
    std::fs::write(
        cas_object_path_for_test_chirho(&root_chirho, &record_chirho.asset_chirho),
        b"body { color: red; }",
    )
    .unwrap();

    let error_chirho = verify_app_static_assets_chirho(&root_chirho).unwrap_err();
    let error_text_chirho = format!("{error_chirho:#}");
    assert!(
        error_text_chirho.contains("content address mismatch"),
        "{error_text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn css_asset_record_rejects_tampered_signature_chirho() {
    let (root_chirho, owner_chirho) = deployed_owner_app_chirho("tamper");
    let mut record_chirho = set_app_static_asset_bytes_chirho(
        &root_chirho,
        "asset-app-chirho",
        &owner_chirho,
        "site-chirho.css",
        "text/css",
        b"body{}",
    )
    .unwrap();
    record_chirho.byte_len_chirho += 1;
    write_jsonl_chirho(
        &app_static_asset_records_path_chirho(&root_chirho),
        &[record_chirho],
    );

    let error_chirho = verify_app_static_assets_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("byte length mismatch"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn css_asset_name_route_lookup_fails_closed_when_missing_chirho() {
    let (root_chirho, _owner_chirho) = deployed_owner_app_chirho("missing");
    assert!(app_static_asset_by_name_chirho(
        &root_chirho,
        "asset-app-chirho",
        "missing-chirho.css"
    )
    .unwrap()
    .is_none());

    let _ = std::fs::remove_dir_all(&root_chirho);
}
