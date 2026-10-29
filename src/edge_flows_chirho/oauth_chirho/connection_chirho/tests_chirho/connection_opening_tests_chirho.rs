// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 CP2's arms for the opening precondition and its race with registration (PFE #26751, requirement 2):
//! - an app with a legacy client cannot open, and the refused first opening retires nothing and records nothing;
//! - registration first, with the opening forced to wait behind it, makes the opening refuse;
//! - opening first, with registration forced to wait behind it, lands the registration in the connection store.
//!
//! The holds run inside each one's locked section, so the second party truly meets the root's append lock.

use super::super::{
    issue_scoped_token_with_rate_limit_chirho, register_client_chirho, ScopedTokenRateLimitChirho,
};
use super::*;
use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho};
use cairn_model_app_chirho::AppKeyAuthorityRouteChirho;
use identity_chirho::PrincipalKindChirho;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const APP_CHIRHO: &str = "racedapp";

static NEXT_ROOT_CHIRHO: AtomicU64 = AtomicU64::new(0);

fn own_root_chirho(label_chirho: &str) -> PathBuf {
    let number_chirho = NEXT_ROOT_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-k4-opening-{label_chirho}-{}-{number_chirho}-chirho",
        std::process::id()
    ));
    std::fs::create_dir(&root_chirho).unwrap();
    root_chirho
}

/// A deployed, unopened app with a view route, its owner, and the view's DAG (the opening's target).
fn unopened_app_chirho(root_chirho: &Path) -> (String, HashChirho) {
    let owner_chirho =
        identity_chirho::register_identity_chirho(root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap()
            .principal_chirho;
    let dag_chirho = |label_chirho: &str| {
        let wasm_chirho =
            crate::cas_chirho::add_chirho(root_chirho, label_chirho.as_bytes()).unwrap();
        let node_chirho = crate::store_chirho::put_object_chirho(
            root_chirho,
            &NodeDefChirho {
                name_chirho: label_chirho.to_string(),
                impl_wasm_chirho: wasm_chirho,
                entry_chirho: "run_chirho".to_string(),
                capabilities_chirho: vec![CapabilityChirho::ReadStoreChirho {
                    prefix_chirho: "viewer-state-chirho/".to_string(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
        crate::store_chirho::put_object_chirho(
            root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap()
    };
    let home_chirho = dag_chirho("home");
    let view_chirho = dag_chirho("view");
    app_chirho::deploy_app_chirho(root_chirho, APP_CHIRHO, home_chirho, &owner_chirho).unwrap();
    app_chirho::deploy_app_route_chirho(
        root_chirho,
        APP_CHIRHO,
        "view",
        view_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    (owner_chirho, view_chirho)
}

fn openings_chirho(view_chirho: &HashChirho) -> Vec<AppKeyAuthorityRouteChirho> {
    vec![AppKeyAuthorityRouteChirho {
        route_chirho: "view".to_string(),
        action_chirho: "page-read-chirho".to_string(),
        dag_chirho: view_chirho.clone(),
        resources_chirho: vec!["page-document-chirho".to_string()],
    }]
}

fn lines_chirho(path_chirho: &Path) -> usize {
    std::fs::read_to_string(path_chirho)
        .map(|text_chirho| text_chirho.lines().count())
        .unwrap_or(0)
}

/// AN APP WITH A LEGACY CLIENT CANNOT OPEN, AND THE REFUSED FIRST OPENING CHANGES NOTHING: with a legacy client and a
/// live legacy key, the opt-in refuses by name before any retirement, so the key's session is not revoked, no
/// authority is recorded, and the token log is unchanged.
#[test]
fn an_app_with_a_legacy_client_cannot_open_and_the_refusal_changes_nothing_chirho() {
    let root_chirho = own_root_chirho("refused");
    let (owner_chirho, view_chirho) = unopened_app_chirho(&root_chirho);
    let client_chirho = register_client_chirho(&root_chirho, APP_CHIRHO, &owner_chirho).unwrap();
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "k4-opening-secret-chirho",
    )
    .unwrap()
    .principal_chirho;
    issue_scoped_token_with_rate_limit_chirho(
        &root_chirho,
        &user_chirho,
        "k4-opening-secret-chirho",
        &client_chirho.client_id_chirho,
        Vec::new(),
        Some(ScopedTokenRateLimitChirho {
            window_ms_chirho: 60_000,
            max_invokes_chirho: 5,
            device_id_chirho: None,
        }),
    )
    .unwrap();
    let revocations_chirho = root_chirho.join("identity-session-revocations-chirho.jsonl");
    let tokens_chirho = root_chirho.join("scoped-tokens-chirho.jsonl");
    let before_chirho = (
        lines_chirho(&revocations_chirho),
        lines_chirho(&tokens_chirho),
    );

    let refusal_chirho = crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
        &root_chirho,
        APP_CHIRHO,
        &owner_chirho,
        openings_chirho(&view_chirho),
    )
    .unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("OpeningWithLegacyClientChirho"),
        "the opening refuses by name: {refusal_chirho:#}"
    );
    assert!(
        app_chirho::app_key_authority_record_chirho(&root_chirho, APP_CHIRHO)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        (
            lines_chirho(&revocations_chirho),
            lines_chirho(&tokens_chirho)
        ),
        before_chirho,
        "no retirement and no token row: the refused opening changed nothing"
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// REGISTRATION FIRST: the registration holds inside its locked section while an opening is started. The opening meets
/// the lock, runs only after the legacy client is written, and refuses.
#[test]
fn a_registration_holding_the_lock_makes_a_racing_opening_refuse_chirho() {
    let root_chirho = own_root_chirho("registration-first");
    let (owner_chirho, view_chirho) = unopened_app_chirho(&root_chirho);
    let (entered_chirho, entered_rx_chirho) = mpsc::channel::<()>();
    let (release_chirho, release_rx_chirho) = mpsc::channel::<()>();
    let registering_root_chirho = root_chirho.clone();
    let registering_owner_chirho = owner_chirho.clone();
    let registration_chirho = std::thread::spawn(move || {
        set_registration_hold_chirho(move || {
            entered_chirho.send(()).unwrap();
            release_rx_chirho.recv().unwrap();
            Ok(())
        });
        register_client_in_store_chirho(
            &registering_root_chirho,
            APP_CHIRHO,
            &registering_owner_chirho,
        )
        .map(|(_, store_chirho)| store_chirho)
    });
    entered_rx_chirho
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    let opening_root_chirho = root_chirho.clone();
    let opening_owner_chirho = owner_chirho.clone();
    let opening_chirho = std::thread::spawn(move || {
        crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
            &opening_root_chirho,
            APP_CHIRHO,
            &opening_owner_chirho,
            openings_chirho(&view_chirho),
        )
        .map_err(|error_chirho| format!("{error_chirho:#}"))
    });
    std::thread::sleep(Duration::from_millis(200));
    release_chirho.send(()).unwrap();
    assert_eq!(
        registration_chirho.join().unwrap().unwrap(),
        KeyStoreChirho::LegacyChirho
    );
    let opening_outcome_chirho = opening_chirho.join().unwrap();
    assert!(
        matches!(&opening_outcome_chirho, Err(refusal_chirho) if refusal_chirho.contains("OpeningWithLegacyClientChirho")),
        "the opening, behind the registration, refuses: {opening_outcome_chirho:?}"
    );
    assert!(
        app_chirho::app_key_authority_record_chirho(&root_chirho, APP_CHIRHO)
            .unwrap()
            .is_none()
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// OPENING FIRST: the opening holds inside its locked section while a registration is started. The registration meets
/// the lock, runs only after the opening is recorded, rechecks the app's mode, and lands in the connection store.
#[test]
fn an_opening_holding_the_lock_lands_a_racing_registration_in_the_connection_store_chirho() {
    let root_chirho = own_root_chirho("opening-first");
    let (owner_chirho, view_chirho) = unopened_app_chirho(&root_chirho);
    let (entered_chirho, entered_rx_chirho) = mpsc::channel::<()>();
    let (release_chirho, release_rx_chirho) = mpsc::channel::<()>();
    let opening_root_chirho = root_chirho.clone();
    let opening_owner_chirho = owner_chirho.clone();
    let opening_chirho = std::thread::spawn(move || {
        crate::app_manifest_chirho::set_opt_in_hold_chirho(move || {
            entered_chirho.send(()).unwrap();
            release_rx_chirho.recv().unwrap();
            Ok(())
        });
        crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
            &opening_root_chirho,
            APP_CHIRHO,
            &opening_owner_chirho,
            openings_chirho(&view_chirho),
        )
        .map_err(|error_chirho| format!("{error_chirho:#}"))
    });
    entered_rx_chirho
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    let registering_root_chirho = root_chirho.clone();
    let registering_owner_chirho = owner_chirho.clone();
    let registration_chirho = std::thread::spawn(move || {
        register_client_in_store_chirho(
            &registering_root_chirho,
            APP_CHIRHO,
            &registering_owner_chirho,
        )
        .map(|(_, store_chirho)| store_chirho)
        .map_err(|error_chirho| format!("{error_chirho:#}"))
    });
    std::thread::sleep(Duration::from_millis(200));
    release_chirho.send(()).unwrap();
    assert_eq!(opening_chirho.join().unwrap(), Ok(()));
    assert_eq!(
        registration_chirho.join().unwrap(),
        Ok(KeyStoreChirho::ConnectionChirho),
        "the registration, behind the opening, lands in the connection store"
    );
    assert_eq!(
        (
            lines_chirho(&clients_path_chirho(&root_chirho)),
            lines_chirho(&connection_clients_path_chirho(&root_chirho))
        ),
        (0, 1)
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
}
