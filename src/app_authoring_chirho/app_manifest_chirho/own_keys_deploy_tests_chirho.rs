// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K3's deploy arms: a route may hold the owner's keys only in an app-wide signed-in app, only as a read, only at the
//! exact prefix, and never in a route opened to keys. Each refusal is shown beside the control that differs from it
//! only in the refused cause.
//! Workflow: the owner's keys page (K3),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/own-keys-page-chirho.md`.

use super::*;
use crate::identity_chirho;
use crate::model_chirho::{DagChirho, NodeDefChirho};
use crate::refs_chirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-own-keys-deploy-{label_chirho}-{}-{}",
        std::process::id(),
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho
}

/// A stored one-node DAG holding `capabilities_chirho`; `name_chirho` keeps each DAG's identity distinct.
fn dag_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let node_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &NodeDefChirho {
            name_chirho: name_chirho.to_string(),
            capabilities_chirho,
            ..Default::default()
        },
    )
    .unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

fn own_keys_read_chirho(prefix_chirho: &str) -> CapabilityChirho {
    CapabilityChirho::ReadStoreChirho {
        prefix_chirho: prefix_chirho.to_string(),
    }
}

fn manifest_chirho(
    app_chirho: &str,
    owner_chirho: &str,
    policy_chirho: Option<AppRequestAccessPolicyChirho>,
    root_dag_chirho: HashChirho,
    routes_chirho: Vec<AppDeployRouteManifestChirho>,
) -> AppDeployManifestChirho {
    AppDeployManifestChirho {
        request_access_policy_chirho: policy_chirho,
        request_body_policy_chirho: None,
        schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_chirho: owner_chirho.to_string(),
        root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
            hash_chirho: root_dag_chirho,
        }),
        input_mode_chirho: None,
        response_content_type_chirho: None,
        params_chirho: None,
        routes_chirho,
        runtime_packages_chirho: Vec::new(),
    }
}

fn app_ref_moved_chirho(root_chirho: &Path, app_chirho: &str) -> bool {
    refs_chirho::load_refs_chirho(root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key(&format!("app/{app_chirho}"))
}

#[test]
fn a_route_reads_the_owners_keys_only_in_an_app_wide_signed_in_app_chirho() {
    let root_chirho = tmp_root_chirho("policy");
    let owner_chirho = owner_chirho(&root_chirho);
    let keys_dag_chirho = dag_chirho(
        &root_chirho,
        "own-keys-read-chirho",
        vec![own_keys_read_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO)],
    );
    let mut manifest_chirho = manifest_chirho(
        "own-keys-policy",
        &owner_chirho,
        None,
        keys_dag_chirho,
        Vec::new(),
    );
    for policy_chirho in [None, Some(AppRequestAccessPolicyChirho::PublicChirho)] {
        manifest_chirho.request_access_policy_chirho = policy_chirho;
        let error_chirho = deploy_app_manifest_chirho(&root_chirho, &manifest_chirho)
            .expect_err("a public app may not read the owner's keys");
        assert!(
            error_chirho
                .to_string()
                .contains("own-keys capabilities require app-wide AuthenticatedChirho"),
            "{error_chirho:#}"
        );
        assert!(!app_ref_moved_chirho(&root_chirho, "own-keys-policy"));
    }
    // The control: the same app, signed-in only.
    manifest_chirho.request_access_policy_chirho =
        Some(AppRequestAccessPolicyChirho::AuthenticatedChirho);
    validate_manifest_chirho(&root_chirho, &manifest_chirho)
        .expect("a signed-in app may read the owner's keys");
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn the_owners_keys_are_held_only_as_a_read_at_their_exact_prefix_chirho() {
    let root_chirho = tmp_root_chirho("shape");
    let owner_chirho = owner_chirho(&root_chirho);
    let signed_in_chirho = Some(AppRequestAccessPolicyChirho::AuthenticatedChirho);
    let write_dag_chirho = dag_chirho(
        &root_chirho,
        "own-keys-write-chirho",
        vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: OWN_KEYS_CAPABILITY_PREFIX_CHIRHO.to_string(),
        }],
    );
    let error_chirho = validate_manifest_chirho(
        &root_chirho,
        &manifest_chirho(
            "own-keys-write",
            &owner_chirho,
            signed_in_chirho.clone(),
            write_dag_chirho,
            Vec::new(),
        ),
    )
    .expect_err("no route may write the owner's keys");
    assert!(
        error_chirho
            .to_string()
            .contains("the owner's keys are read only"),
        "{error_chirho:#}"
    );
    let deeper_dag_chirho = dag_chirho(
        &root_chirho,
        "own-keys-deeper-chirho",
        vec![own_keys_read_chirho("own-keys-chirho/someone-else/")],
    );
    let error_chirho = validate_manifest_chirho(
        &root_chirho,
        &manifest_chirho(
            "own-keys-deeper",
            &owner_chirho,
            signed_in_chirho,
            deeper_dag_chirho,
            Vec::new(),
        ),
    )
    .expect_err("the owner's keys are held only at their exact prefix");
    assert!(
        error_chirho
            .to_string()
            .contains("own-keys capability scope must be exactly"),
        "{error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn a_route_holding_the_owners_keys_cannot_be_opened_to_keys_chirho() {
    let root_chirho = tmp_root_chirho("opened");
    let owner_chirho = owner_chirho(&root_chirho);
    let home_dag_chirho = dag_chirho(&root_chirho, "home-chirho", Vec::new());
    let keys_dag_chirho = dag_chirho(
        &root_chirho,
        "account-keys-chirho",
        vec![own_keys_read_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO)],
    );
    let route_chirho =
        |key_access_chirho: Option<AppRouteKeyAccessChirho>| AppDeployRouteManifestChirho {
            route_chirho: "account".to_string(),
            source_chirho: AppDeployDagSourceChirho::DagChirho {
                hash_chirho: keys_dag_chirho.clone(),
            },
            input_mode_chirho: None,
            request_body_policy_chirho: None,
            key_access_chirho,
            response_content_type_chirho: None,
            params_chirho: None,
        };
    let opened_chirho = manifest_chirho(
        "own-keys-opened",
        &owner_chirho,
        Some(AppRequestAccessPolicyChirho::AuthenticatedChirho),
        home_dag_chirho.clone(),
        vec![route_chirho(Some(AppRouteKeyAccessChirho::OpenChirho {
            action_chirho: "page-read-chirho".to_string(),
            resources_chirho: Vec::new(),
        }))],
    );
    let error_chirho = validate_manifest_chirho(&root_chirho, &opened_chirho)
        .expect_err("a route holding the owner's keys is never key-callable");
    assert!(
        error_chirho
            .to_string()
            .contains("cannot be opened to keys: its DAG holds a capability no key may reach"),
        "{error_chirho:#}"
    );
    // The deploy refuses with it, and moves no ref.
    let error_chirho = deploy_app_manifest_chirho(&root_chirho, &opened_chirho).unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .contains("cannot be opened to keys"),
        "{error_chirho:#}"
    );
    assert!(!app_ref_moved_chirho(&root_chirho, "own-keys-opened"));
    // The control, through the same validation: the same route, closed to keys, is valid. (A real deploy of an
    // effectful DAG also needs verified undo-plan bindings, which only a tree-built manifest carries.)
    let closed_chirho = manifest_chirho(
        "own-keys-opened",
        &owner_chirho,
        Some(AppRequestAccessPolicyChirho::AuthenticatedChirho),
        home_dag_chirho,
        vec![route_chirho(None)],
    );
    validate_manifest_chirho(&root_chirho, &closed_chirho)
        .expect("the same route, closed to keys, is valid");
    let _ = std::fs::remove_dir_all(root_chirho);
}
