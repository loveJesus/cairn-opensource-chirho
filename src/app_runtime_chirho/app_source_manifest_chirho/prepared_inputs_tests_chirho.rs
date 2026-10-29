// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Prepared-input law pins (#6085/#6090/#6098/#6102/#6103): missing/oversized/symlink refusals,
//! and the prepared set's exact manifest/base binding with ZERO root writes on refusal.

use super::prepared_inputs_chirho::cargo_example_build_command_chirho;
use super::*;
use std::ffi::OsStr;
use std::path::PathBuf;

// ---- prepared-input law pins (#6085/#6090/#6098/#6102/#6103) ----

#[test]
fn cargo_example_build_is_lockfile_bound_chirho() {
    let command_chirho = cargo_example_build_command_chirho(
        std::path::Path::new("/reviewed/app-root-chirho"),
        "credits-demo-chirho",
        "render_balance_guest_chirho",
        &["json-chirho".to_string()],
        Some(std::path::Path::new("Cargo.toml")),
        "wasm32-unknown-unknown",
        Some(std::path::Path::new("/reviewed/target-chirho")),
    );
    let args_chirho = command_chirho.get_args().collect::<Vec<_>>();
    assert_eq!(
        args_chirho
            .iter()
            .filter(|arg_chirho| **arg_chirho == OsStr::new("--locked"))
            .count(),
        1,
        "every app-source Cargo example build must use the reviewed lockfile"
    );
    assert!(args_chirho.windows(2).any(|pair_chirho| pair_chirho
        == [
            OsStr::new("--target-dir"),
            OsStr::new("/reviewed/target-chirho")
        ]));
}

fn prepared_law_manifest_chirho(asset_path_chirho: &str) -> AppSourceManifestChirho {
    AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "prepared-law-app-chirho".to_string(),
        owner_chirho: "owner/aaaaaaaaaaaaaaaa".to_string(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: vec![AppSourceAssetManifestChirho {
            name_chirho: "styles-chirho.css".to_string(),
            content_type_chirho: "text/css".to_string(),
            source_chirho: AppSourceAssetSourceChirho::PathChirho {
                path_chirho: PathBuf::from(asset_path_chirho),
            },
        }],
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    }
}

fn prepared_law_tmp_dir_chirho(label_chirho: &str) -> PathBuf {
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-prepared-law-{label_chirho}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir_chirho).unwrap();
    dir_chirho
}

#[test]
fn prepared_preflight_refuses_missing_and_oversized_assets_chirho() {
    let base_chirho = prepared_law_tmp_dir_chirho("missing");
    let manifest_chirho = prepared_law_manifest_chirho("assets_chirho/styles-chirho.css");
    let bytes_chirho = serde_json::to_vec(&manifest_chirho).unwrap();
    let missing_chirho =
        match preflight_app_source_manifest_inputs_chirho(&base_chirho, &bytes_chirho) {
            Err(error_chirho) => error_chirho,
            Ok(_prepared_chirho) => panic!("missing asset must refuse"),
        };
    assert!(missing_chirho.to_string().contains("missing"));

    std::fs::create_dir_all(base_chirho.join("assets_chirho")).unwrap();
    std::fs::write(
        base_chirho.join("assets_chirho/styles-chirho.css"),
        vec![b'a'; (1024 * 1024 + 1) as usize],
    )
    .unwrap();
    let oversized_chirho =
        match preflight_app_source_manifest_inputs_chirho(&base_chirho, &bytes_chirho) {
            Err(error_chirho) => error_chirho,
            Ok(_prepared_chirho) => panic!("oversized asset must refuse"),
        };
    assert!(oversized_chirho.to_string().contains("byte limit"));
    let _ = std::fs::remove_dir_all(&base_chirho);
}

#[cfg(unix)]
#[test]
fn prepared_preflight_refuses_symlink_escape_and_symlink_root_chirho() {
    let base_chirho = prepared_law_tmp_dir_chirho("symlink");
    let outside_chirho = prepared_law_tmp_dir_chirho("outside");
    std::fs::write(outside_chirho.join("secret-chirho.css"), b"outside").unwrap();
    std::fs::create_dir_all(base_chirho.join("assets_chirho")).unwrap();
    std::os::unix::fs::symlink(
        outside_chirho.join("secret-chirho.css"),
        base_chirho.join("assets_chirho/styles-chirho.css"),
    )
    .unwrap();
    let manifest_chirho = prepared_law_manifest_chirho("assets_chirho/styles-chirho.css");
    let bytes_chirho = serde_json::to_vec(&manifest_chirho).unwrap();
    let escape_chirho =
        match preflight_app_source_manifest_inputs_chirho(&base_chirho, &bytes_chirho) {
            Err(error_chirho) => error_chirho,
            Ok(_prepared_chirho) => panic!("symlink escape must refuse"),
        };
    assert!(escape_chirho.to_string().contains("symlink"));

    // The app root ITSELF as a symlink refuses before any containment reasoning.
    let root_link_chirho = outside_chirho.join("root-link-chirho");
    std::os::unix::fs::symlink(&base_chirho, &root_link_chirho).unwrap();
    let root_chirho =
        match preflight_app_source_manifest_inputs_chirho(&root_link_chirho, &bytes_chirho) {
            Err(error_chirho) => error_chirho,
            Ok(_prepared_chirho) => panic!("symlink app root must refuse"),
        };
    assert!(root_chirho.to_string().contains("symlink"));
    let _ = std::fs::remove_dir_all(&base_chirho);
    let _ = std::fs::remove_dir_all(&outside_chirho);
}

#[test]
fn prepared_set_binds_exact_manifest_and_base_with_zero_root_writes_chirho() {
    let base_a_chirho = prepared_law_tmp_dir_chirho("base-a");
    std::fs::create_dir_all(base_a_chirho.join("assets_chirho")).unwrap();
    std::fs::write(
        base_a_chirho.join("assets_chirho/styles-chirho.css"),
        b"a-bytes",
    )
    .unwrap();
    let manifest_a_chirho = prepared_law_manifest_chirho("assets_chirho/styles-chirho.css");
    let bytes_a_chirho = serde_json::to_vec(&manifest_a_chirho).unwrap();
    let prepared_chirho =
        preflight_app_source_manifest_inputs_chirho(&base_a_chirho, &bytes_a_chirho).unwrap();

    // Prepared-A / build-B refuses BEFORE any root write (#6102 mutation).
    let mut manifest_b_chirho = prepared_law_manifest_chirho("assets_chirho/styles-chirho.css");
    manifest_b_chirho.app_chirho = "prepared-law-app-b-chirho".to_string();
    let bytes_b_chirho = serde_json::to_vec(&manifest_b_chirho).unwrap();
    let root_chirho = prepared_law_tmp_dir_chirho("root");
    let mismatch_chirho = build_app_source_review_from_prepared_bytes_for_owner_chirho(
        &root_chirho,
        &bytes_b_chirho,
        &base_a_chirho,
        "owner/aaaaaaaaaaaaaaaa",
        &prepared_chirho,
    )
    .unwrap_err();
    assert!(mismatch_chirho
        .to_string()
        .contains("different manifest bytes"));
    assert_eq!(
        std::fs::read_dir(&root_chirho).unwrap().count(),
        0,
        "a refused prepared build must leave the root EMPTY (zero writes on any surface)"
    );

    // Base substitution refuses the same way (#6102 mutation).
    let base_b_chirho = prepared_law_tmp_dir_chirho("base-b");
    std::fs::create_dir_all(base_b_chirho.join("assets_chirho")).unwrap();
    std::fs::write(
        base_b_chirho.join("assets_chirho/styles-chirho.css"),
        b"a-bytes",
    )
    .unwrap();
    let substituted_chirho = build_app_source_review_from_prepared_bytes_for_owner_chirho(
        &root_chirho,
        &bytes_a_chirho,
        &base_b_chirho,
        "owner/aaaaaaaaaaaaaaaa",
        &prepared_chirho,
    )
    .unwrap_err();
    assert!(substituted_chirho
        .to_string()
        .contains("different app root"));
    assert_eq!(std::fs::read_dir(&root_chirho).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&base_a_chirho);
    let _ = std::fs::remove_dir_all(&base_b_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn captured_cargo_artifact_bytes_are_the_reviewed_node_bytes_chirho() {
    let base_chirho = prepared_law_tmp_dir_chirho("captured-cargo");
    std::fs::create_dir_all(base_chirho.join("examples")).unwrap();
    std::fs::write(
        base_chirho.join("Cargo.toml"),
        "# For God so loved the world. - John 3:16\n[package]\n\
name = \"captured-cargo-chirho\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        base_chirho.join("examples/node_guest_chirho.rs"),
        "// For God so loved the world. - John 3:16\nfn main() {}\n",
    )
    .unwrap();
    let artifact_path_chirho =
        PathBuf::from("target/wasm32-unknown-unknown/debug/examples/node_guest_chirho.wasm");
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "captured-cargo-app-chirho".to_string(),
        owner_chirho: "owner/aaaaaaaaaaaaaaaa".to_string(),
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "captured_node".to_string(),
            name_chirho: "captured_node_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: Vec::new(),
            source_chirho: AppSourceNodeSourceChirho::CargoExampleChirho {
                package_chirho: "captured-cargo-chirho".to_string(),
                example_chirho: "node_guest_chirho".to_string(),
                features_chirho: Vec::new(),
                manifest_path_chirho: Some(PathBuf::from("Cargo.toml")),
                target_chirho: Some("wasm32-unknown-unknown".to_string()),
                artifact_path_chirho: artifact_path_chirho.clone(),
            },
        }],
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "captured_dag".to_string(),
            nodes_chirho: vec!["captured_node".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::DagIdChirho {
                id_chirho: "captured_dag".to_string(),
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let manifest_bytes_chirho = serde_json::to_vec(&manifest_chirho).unwrap();
    let captured_bytes_chirho =
        include_bytes!("../../../examples-chirho/upcase-chirho.wat").to_vec();
    let captured_digest_chirho = blake3::hash(&captured_bytes_chirho).to_hex().to_string();
    let captured_chirho = AppSourceCapturedNodeArtifactChirho {
        artifact_path_chirho: artifact_path_chirho.clone(),
        artifact_blake3_chirho: captured_digest_chirho,
        bytes_chirho: captured_bytes_chirho.clone(),
    };
    let prepared_chirho = preflight_app_source_manifest_inputs_with_captured_node_artifacts_chirho(
        &base_chirho,
        &manifest_bytes_chirho,
        &[captured_chirho],
    )
    .unwrap();

    // A later target-file mutation is not read by the prepared promotion path.
    let declared_artifact_chirho = base_chirho.join(&artifact_path_chirho);
    std::fs::create_dir_all(declared_artifact_chirho.parent().unwrap()).unwrap();
    std::fs::write(&declared_artifact_chirho, b"different-later-bytes-chirho").unwrap();
    std::fs::write(
        base_chirho.join("examples/node_guest_chirho.rs"),
        "// For God so loved the world. - John 3:16\ncompile_error!(\"later mutation\");\n",
    )
    .unwrap();

    let root_chirho = prepared_law_tmp_dir_chirho("captured-cargo-root");
    let review_chirho = build_app_source_review_from_prepared_bytes_for_owner_chirho(
        &root_chirho,
        &manifest_bytes_chirho,
        &base_chirho,
        "owner/aaaaaaaaaaaaaaaa",
        &prepared_chirho,
    )
    .unwrap();
    let node_hash_chirho = &review_chirho.candidate_chirho.nodes_chirho[0].node_chirho;
    let node_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(&root_chirho, node_hash_chirho).unwrap();
    assert_eq!(
        cas_chirho::get_chirho(&root_chirho, &node_chirho.impl_wasm_chirho).unwrap(),
        captured_bytes_chirho,
        "review/promotion input must be the fixture-bound captured Cargo artifact bytes"
    );
    let _ = std::fs::remove_dir_all(base_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
}
