// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 CP1's arms for the connection client store:
//! - an opened app's client registers only in the connection store, and only by the app's verified owner;
//! - an unopened app's client stays in the legacy store, as before;
//! - a client in both stores refuses;
//! - a connection log the engine cannot examine refuses every lookup, never falling back;
//! - the log verifies dense, signed rows of its own schema;
//! - an app whose mode cannot be known refuses registration.

use super::super::{find_client_chirho, register_client_chirho};
use super::*;
use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho};
use cairn_model_app_chirho::AppKeyAuthorityRouteChirho;
use identity_chirho::PrincipalKindChirho;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const OPENED_APP_CHIRHO: &str = "connected";
const UNOPENED_APP_CHIRHO: &str = "legacyonly";

static NEXT_ROOT_CHIRHO: AtomicU64 = AtomicU64::new(0);

/// A root of this arm's own, created exclusively.
fn own_root_chirho(label_chirho: &str) -> PathBuf {
    let number_chirho = NEXT_ROOT_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-k4-clients-{label_chirho}-{}-{number_chirho}-chirho",
        std::process::id()
    ));
    std::fs::create_dir(&root_chirho).unwrap();
    root_chirho
}

fn new_owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(root_chirho, PrincipalKindChirho::OwnerChirho)
        .unwrap()
        .principal_chirho
}

/// A one-node viewer-state read DAG, stored under `label_chirho`.
fn read_dag_chirho(root_chirho: &Path, label_chirho: &str) -> HashChirho {
    let wasm_chirho = crate::cas_chirho::add_chirho(root_chirho, label_chirho.as_bytes()).unwrap();
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
}

/// Deploy `app_chirho` (a root and a view route) for `owner_chirho`, and open the view to page reads when `open_chirho`.
fn deploy_chirho(root_chirho: &Path, app_chirho: &str, owner_chirho: &str, open_chirho: bool) {
    let home_chirho = read_dag_chirho(root_chirho, &format!("{app_chirho}-home"));
    let view_chirho = read_dag_chirho(root_chirho, &format!("{app_chirho}-view"));
    app_chirho::deploy_app_chirho(root_chirho, app_chirho, home_chirho, owner_chirho).unwrap();
    app_chirho::deploy_app_route_chirho(
        root_chirho,
        app_chirho,
        "view",
        view_chirho.clone(),
        owner_chirho,
    )
    .unwrap();
    if open_chirho {
        app_chirho::append_app_key_authority_record_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            vec![AppKeyAuthorityRouteChirho {
                route_chirho: "view".to_string(),
                action_chirho: "page-read-chirho".to_string(),
                dag_chirho: view_chirho,
                resources_chirho: vec!["page-document-chirho".to_string()],
            }],
        )
        .unwrap();
    }
}

fn lines_chirho(path_chirho: &Path) -> usize {
    std::fs::read_to_string(path_chirho)
        .map(|text_chirho| text_chirho.lines().count())
        .unwrap_or(0)
}

fn within_deadline_chirho<T: Send + 'static>(
    call_chirho: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (sender_chirho, receiver_chirho) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender_chirho.send(call_chirho());
    });
    receiver_chirho.recv_timeout(Duration::from_secs(5)).ok()
}

/// AN OPENED APP'S CLIENT IS A CONNECTION CLIENT, FROM ITS VERIFIED OWNER ONLY: the app's owner registers it into the
/// connection store, and the legacy store gains nothing; another Owner of the same root is refused (the app-owner check
/// is new enforcement on this road, PFE #26751), and neither store gains a row.
#[test]
fn an_opened_apps_client_registers_in_the_connection_store_by_its_owner_only_chirho() {
    let root_chirho = own_root_chirho("opened");
    let owner_chirho = new_owner_chirho(&root_chirho);
    let other_owner_chirho = new_owner_chirho(&root_chirho);
    deploy_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho, true);

    let (client_chirho, store_chirho) =
        register_client_in_store_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho).unwrap();
    assert_eq!(store_chirho, KeyStoreChirho::ConnectionChirho);
    assert_eq!(
        client_chirho.schema_chirho,
        CONNECTION_CLIENT_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(
        lines_chirho(&clients_path_chirho(&root_chirho)),
        0,
        "the legacy store gained nothing"
    );
    assert_eq!(
        find_client_in_store_chirho(&root_chirho, &client_chirho.client_id_chirho)
            .unwrap()
            .map(|(_, store_chirho)| store_chirho),
        Some(KeyStoreChirho::ConnectionChirho)
    );

    let refusal_chirho =
        register_client_chirho(&root_chirho, OPENED_APP_CHIRHO, &other_owner_chirho).unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("is owned by"),
        "another Owner is refused by the app-owner check: {refusal_chirho:#}"
    );
    assert_eq!(
        (
            lines_chirho(&clients_path_chirho(&root_chirho)),
            lines_chirho(&connection_clients_path_chirho(&root_chirho))
        ),
        (0, 1),
        "the refusal wrote to neither store"
    );
    assert_eq!(verify_connection_clients_chirho(&root_chirho).unwrap(), 1);
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// AN UNOPENED APP KEEPS TODAY'S ROAD: its client goes to the legacy store, and the road still checks only that the
/// registrant is an Owner. That is deliberate, preserved for operator and recovery registration, not a claim that it
/// checks the app's owner. A User is refused.
#[test]
fn an_unopened_apps_client_stays_in_the_legacy_store_as_before_chirho() {
    let root_chirho = own_root_chirho("unopened");
    let owner_chirho = new_owner_chirho(&root_chirho);
    let other_owner_chirho = new_owner_chirho(&root_chirho);
    deploy_chirho(&root_chirho, UNOPENED_APP_CHIRHO, &owner_chirho, false);

    let (client_chirho, store_chirho) =
        register_client_in_store_chirho(&root_chirho, UNOPENED_APP_CHIRHO, &owner_chirho).unwrap();
    assert_eq!(store_chirho, KeyStoreChirho::LegacyChirho);
    assert_eq!(
        client_chirho.schema_chirho,
        OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO
    );
    let (_, other_store_chirho) =
        register_client_in_store_chirho(&root_chirho, UNOPENED_APP_CHIRHO, &other_owner_chirho)
            .unwrap();
    assert_eq!(
        other_store_chirho,
        KeyStoreChirho::LegacyChirho,
        "today's road, unchanged: an Owner who is not the app's owner still registers an unopened app's client"
    );
    let user_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho)
            .unwrap()
            .principal_chirho;
    assert!(register_client_chirho(&root_chirho, UNOPENED_APP_CHIRHO, &user_chirho).is_err());
    assert_eq!(
        (
            lines_chirho(&clients_path_chirho(&root_chirho)),
            lines_chirho(&connection_clients_path_chirho(&root_chirho))
        ),
        (2, 0)
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// A CLIENT IN BOTH STORES REFUSES: no engine writes one, so a lookup and the verifier refuse it rather than choosing.
#[test]
fn a_client_in_both_stores_refuses_chirho() {
    let root_chirho = own_root_chirho("both");
    let owner_chirho = new_owner_chirho(&root_chirho);
    deploy_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho, true);
    let (client_chirho, _) =
        register_client_in_store_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho).unwrap();
    let mut planted_chirho = client_chirho.clone();
    planted_chirho.seq_chirho = 0;
    planted_chirho.schema_chirho = OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO.to_string();
    std::fs::write(
        clients_path_chirho(&root_chirho),
        format!("{}\n", serde_json::to_string(&planted_chirho).unwrap()),
    )
    .unwrap();
    for refusal_chirho in [
        find_client_chirho(&root_chirho, &client_chirho.client_id_chirho).map(|_| ()),
        verify_connection_clients_chirho(&root_chirho).map(|_| ()),
    ] {
        assert!(
            format!("{:#}", refusal_chirho.unwrap_err()).contains("ClientInBothStoresChirho"),
            "a client in both stores refuses by name"
        );
    }
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// A CONNECTION CLIENT LOG THE ENGINE CANNOT EXAMINE REFUSES EVERY LOOKUP, promptly, even of a legacy client: it never
/// falls back to the legacy store alone. A pipe and a link are the faults; absence is the control.
#[test]
fn an_unexaminable_connection_client_log_refuses_every_lookup_chirho() {
    let root_chirho = own_root_chirho("unexaminable");
    let owner_chirho = new_owner_chirho(&root_chirho);
    deploy_chirho(&root_chirho, UNOPENED_APP_CHIRHO, &owner_chirho, false);
    let legacy_id_chirho = register_client_chirho(&root_chirho, UNOPENED_APP_CHIRHO, &owner_chirho)
        .unwrap()
        .client_id_chirho;
    assert!(
        find_client_chirho(&root_chirho, &legacy_id_chirho)
            .unwrap()
            .is_some(),
        "the control: an absent connection log is no connection clients"
    );
    let connection_log_chirho = connection_clients_path_chirho(&root_chirho);
    for fault_chirho in ["pipe", "link"] {
        if fault_chirho == "pipe" {
            assert!(std::process::Command::new("mkfifo")
                .arg(&connection_log_chirho)
                .status()
                .unwrap()
                .success());
        } else {
            std::os::unix::fs::symlink(clients_path_chirho(&root_chirho), &connection_log_chirho)
                .unwrap();
        }
        let lookup_root_chirho = root_chirho.clone();
        let lookup_id_chirho = legacy_id_chirho.clone();
        let outcome_chirho = within_deadline_chirho(move || {
            find_client_chirho(&lookup_root_chirho, &lookup_id_chirho)
                .map(|found_chirho| found_chirho.is_some())
        });
        assert!(
            matches!(outcome_chirho, Some(Err(_))),
            "{fault_chirho}: the lookup refuses promptly, never falling back: {outcome_chirho:?}"
        );
        std::fs::remove_file(&connection_log_chirho).unwrap();
    }
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// THE CONNECTION CLIENT LOG VERIFIES DENSE, SIGNED ROWS OF ITS OWN SCHEMA: two opened apps' clients verify; a tampered
/// row, a sequence gap, and a legacy-schema row each refuse.
#[test]
fn the_connection_client_log_verifies_dense_signed_rows_chirho() {
    let root_chirho = own_root_chirho("verify");
    let owner_chirho = new_owner_chirho(&root_chirho);
    deploy_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho, true);
    deploy_chirho(&root_chirho, "connectedtoo", &owner_chirho, true);
    register_client_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho).unwrap();
    register_client_chirho(&root_chirho, "connectedtoo", &owner_chirho).unwrap();
    assert_eq!(verify_connection_clients_chirho(&root_chirho).unwrap(), 2);

    let log_chirho = connection_clients_path_chirho(&root_chirho);
    let original_chirho = std::fs::read_to_string(&log_chirho).unwrap();
    let rows_chirho: Vec<&str> = original_chirho.lines().collect();
    let mut tampered_chirho: serde_json::Value = serde_json::from_str(rows_chirho[1]).unwrap();
    tampered_chirho["at_ms_chirho"] = serde_json::Value::from(1_u64);
    let cases_chirho = [
        (
            "tampered",
            format!("{}\n{}\n", rows_chirho[0], tampered_chirho),
        ),
        ("gap", format!("{}\n", rows_chirho[1])),
        (
            "legacy schema",
            format!(
                "{}\n{}\n",
                rows_chirho[0].replace(
                    CONNECTION_CLIENT_RECORD_SCHEMA_CHIRHO,
                    OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO
                ),
                rows_chirho[1]
            ),
        ),
    ];
    for (label_chirho, text_chirho) in cases_chirho {
        std::fs::write(&log_chirho, text_chirho).unwrap();
        assert!(
            verify_connection_clients_chirho(&root_chirho).is_err(),
            "{label_chirho}: the connection client log refuses"
        );
    }
    std::fs::write(&log_chirho, original_chirho).unwrap();
    assert_eq!(
        verify_connection_clients_chirho(&root_chirho).unwrap(),
        2,
        "restored, it verifies"
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// AN APP WHOSE MODE CANNOT BE KNOWN REFUSES REGISTRATION: with its key-authority log replaced by a pipe, registration
/// refuses, promptly, and is never taken for an app that opens nothing.
#[test]
fn an_app_whose_mode_cannot_be_known_refuses_registration_chirho() {
    let root_chirho = own_root_chirho("mode");
    let owner_chirho = new_owner_chirho(&root_chirho);
    deploy_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho, true);
    let authority_log_chirho = root_chirho.join("app-key-authority-chirho.jsonl");
    assert!(authority_log_chirho.exists(), "the opening's own log");
    std::fs::remove_file(&authority_log_chirho).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(&authority_log_chirho)
        .status()
        .unwrap()
        .success());
    let register_root_chirho = root_chirho.clone();
    let register_owner_chirho = owner_chirho.clone();
    let outcome_chirho = within_deadline_chirho(move || {
        register_client_chirho(
            &register_root_chirho,
            OPENED_APP_CHIRHO,
            &register_owner_chirho,
        )
        .map(|_| ())
    });
    assert!(
        matches!(outcome_chirho, Some(Err(_))),
        "registration refuses an app whose mode cannot be known: {outcome_chirho:?}"
    );
    assert_eq!(
        (
            lines_chirho(&clients_path_chirho(&root_chirho)),
            lines_chirho(&connection_clients_path_chirho(&root_chirho))
        ),
        (0, 0),
        "and writes to neither store"
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
}
