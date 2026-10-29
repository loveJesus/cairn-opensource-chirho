// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Account Create brick 1's engine arms for selection by app (PFE #26824), over the connection-client view's summary:
//! - an app's connection clients read as none, exactly one (by its id) or several, and a second client turns one into
//!   several for good; another app's client, and a legacy client, are not this app's;
//! - a fault refuses, and never reads as none: a tampered row, a log seen present that goes missing, a log the engine
//!   cannot examine;
//! - warm selection folds nothing, on a small root and on a large one, and a new client is folded exactly once;
//! - the form's choices by app are the one client's choices by id; none, several, a legacy-only or unknown app is
//!   nothing; a fault refuses; a client in both stores refuses by name on the app's road too;
//! - the return rule's table, dot segments and percent-encoding included (PFE #26837);
//! - the issuance refuses a return outside the client's app before anything is appended, beside a same-app control.

use super::super::{
    clients_path_chirho, token_view_metrics_chirho, OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO,
};
use super::connection_client_view_chirho::{
    connection_client_for_app_chirho, AppConnectionClientChirho,
};
use super::connection_fixture_chirho::*;
use super::*;
use identity_chirho::PrincipalKindChirho;
use std::time::Duration;

/// A second opened app, beside the fixture's.
const OTHER_OPENED_APP_CHIRHO: &str = "alsoconnected";

/// A root with its owner, two apps opened to limited keys and one unopened, and no clients yet.
struct SelectionWorldChirho {
    root_chirho: PathBuf,
    owner_chirho: String,
}

impl SelectionWorldChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        let root_chirho = own_root_chirho(label_chirho);
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        for app_chirho in [OPENED_APP_CHIRHO, OTHER_OPENED_APP_CHIRHO] {
            let view_chirho = deploy_app_chirho(&root_chirho, app_chirho, &owner_chirho);
            crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
                &root_chirho,
                app_chirho,
                &owner_chirho,
                view_opening_chirho(&view_chirho),
            )
            .unwrap();
        }
        deploy_app_chirho(&root_chirho, PLAIN_APP_CHIRHO, &owner_chirho);
        Self {
            root_chirho,
            owner_chirho,
        }
    }

    /// A new client for `app_chirho`, and the store it went to.
    fn register_chirho(&self, root_chirho: &Path, app_chirho: &str) -> (String, KeyStoreChirho) {
        let (client_chirho, store_chirho) =
            register_client_in_store_chirho(root_chirho, app_chirho, &self.owner_chirho).unwrap();
        (client_chirho.client_id_chirho, store_chirho)
    }
}

fn selected_chirho(root_chirho: &Path, app_chirho: &str) -> AppConnectionClientChirho {
    connection_client_for_app_chirho(root_chirho, app_chirho).unwrap()
}

/// AN APP'S CONNECTION CLIENTS READ AS NONE, ONE OR SEVERAL, AND SEVERAL IS FOR GOOD: before any client the app has
/// none; its first connection client is one, by its id; another app's client and a legacy client change nothing for it;
/// its second client makes it several, and a third keeps it so. An app nobody deployed reads as none.
#[test]
fn an_apps_connection_clients_read_as_none_one_or_several_chirho() {
    let world_chirho = SelectionWorldChirho::new_chirho("select-app");
    let root_chirho = &world_chirho.root_chirho;
    assert_eq!(
        selected_chirho(root_chirho, OPENED_APP_CHIRHO),
        AppConnectionClientChirho::NoneChirho,
        "no client log yet"
    );
    let (first_chirho, store_chirho) = world_chirho.register_chirho(root_chirho, OPENED_APP_CHIRHO);
    assert_eq!(store_chirho, KeyStoreChirho::ConnectionChirho);
    assert_eq!(
        selected_chirho(root_chirho, OPENED_APP_CHIRHO),
        AppConnectionClientChirho::OneChirho(first_chirho.clone())
    );
    let (_legacy_chirho, store_chirho) =
        world_chirho.register_chirho(root_chirho, PLAIN_APP_CHIRHO);
    assert_eq!(store_chirho, KeyStoreChirho::LegacyChirho);
    let (other_chirho, _store_chirho) =
        world_chirho.register_chirho(root_chirho, OTHER_OPENED_APP_CHIRHO);
    assert_eq!(
        (
            selected_chirho(root_chirho, OPENED_APP_CHIRHO),
            selected_chirho(root_chirho, OTHER_OPENED_APP_CHIRHO),
            selected_chirho(root_chirho, PLAIN_APP_CHIRHO),
        ),
        (
            AppConnectionClientChirho::OneChirho(first_chirho),
            AppConnectionClientChirho::OneChirho(other_chirho.clone()),
            AppConnectionClientChirho::NoneChirho,
        ),
        "another app's client and a legacy client are not this app's"
    );
    for _ in 0..2 {
        world_chirho.register_chirho(root_chirho, OPENED_APP_CHIRHO);
        assert_eq!(
            selected_chirho(root_chirho, OPENED_APP_CHIRHO),
            AppConnectionClientChirho::SeveralChirho
        );
    }
    assert_eq!(
        (
            selected_chirho(root_chirho, OTHER_OPENED_APP_CHIRHO),
            selected_chirho(root_chirho, "nosuchapp"),
        ),
        (
            AppConnectionClientChirho::OneChirho(other_chirho),
            AppConnectionClientChirho::NoneChirho,
        )
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

/// A FAULT REFUSES AN APP'S SELECTION, AND NEVER READS AS NONE: a tampered row (its app changed, its signature kept)
/// refuses, and the restored log reads again; a log seen present that goes missing refuses; on a root whose connection
/// log never existed, absence reads as none (the control), and a log that is a pipe or a link refuses promptly.
#[test]
fn a_fault_refuses_an_apps_selection_and_never_reads_as_none_chirho() {
    let world_chirho = SelectionWorldChirho::new_chirho("select-fault");
    let root_chirho = world_chirho.root_chirho.clone();
    let (client_chirho, _store_chirho) =
        world_chirho.register_chirho(&root_chirho, OPENED_APP_CHIRHO);
    let log_chirho = connection_clients_path_chirho(&root_chirho);
    let original_chirho = std::fs::read_to_string(&log_chirho).unwrap();
    assert_eq!(
        selected_chirho(&root_chirho, OPENED_APP_CHIRHO),
        AppConnectionClientChirho::OneChirho(client_chirho.clone())
    );
    let tampered_chirho = original_chirho.replace(
        &format!("\"app_chirho\":\"{OPENED_APP_CHIRHO}\""),
        &format!("\"app_chirho\":\"{OTHER_OPENED_APP_CHIRHO}\""),
    );
    assert_ne!(
        tampered_chirho, original_chirho,
        "the tamper changed the row"
    );
    let staged_chirho = root_chirho.join("connection-clients-tampered-chirho.jsonl");
    std::fs::write(&staged_chirho, &tampered_chirho).unwrap();
    std::fs::rename(&staged_chirho, &log_chirho).unwrap();
    for app_chirho in [OPENED_APP_CHIRHO, OTHER_OPENED_APP_CHIRHO] {
        let outcome_chirho = connection_client_for_app_chirho(&root_chirho, app_chirho);
        assert!(
            outcome_chirho.is_err(),
            "{app_chirho}: a tampered row refuses, never one or none: {outcome_chirho:?}"
        );
    }
    std::fs::write(&staged_chirho, &original_chirho).unwrap();
    std::fs::rename(&staged_chirho, &log_chirho).unwrap();
    assert_eq!(
        selected_chirho(&root_chirho, OPENED_APP_CHIRHO),
        AppConnectionClientChirho::OneChirho(client_chirho),
        "the restored log reads again"
    );
    std::fs::remove_file(&log_chirho).unwrap();
    let missing_chirho = connection_client_for_app_chirho(&root_chirho, OPENED_APP_CHIRHO);
    assert!(
        missing_chirho.is_err(),
        "a log seen present that goes missing refuses, never none: {missing_chirho:?}"
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();

    let world_chirho = SelectionWorldChirho::new_chirho("select-unexaminable");
    let root_chirho = world_chirho.root_chirho.clone();
    world_chirho.register_chirho(&root_chirho, PLAIN_APP_CHIRHO);
    let log_chirho = connection_clients_path_chirho(&root_chirho);
    assert_eq!(
        selected_chirho(&root_chirho, OPENED_APP_CHIRHO),
        AppConnectionClientChirho::NoneChirho,
        "the control: a connection log that never existed is no connection clients"
    );
    for fault_chirho in ["pipe", "link"] {
        if fault_chirho == "pipe" {
            assert!(std::process::Command::new("mkfifo")
                .arg(&log_chirho)
                .status()
                .unwrap()
                .success());
        } else {
            std::os::unix::fs::symlink(clients_path_chirho(&root_chirho), &log_chirho).unwrap();
        }
        let (sender_chirho, receiver_chirho) = std::sync::mpsc::channel();
        let lookup_root_chirho = root_chirho.clone();
        std::thread::spawn(move || {
            let _ = sender_chirho.send(
                connection_client_for_app_chirho(&lookup_root_chirho, OPENED_APP_CHIRHO)
                    .map_err(|error_chirho| format!("{error_chirho:#}")),
            );
        });
        let outcome_chirho = receiver_chirho.recv_timeout(Duration::from_secs(5));
        assert!(
            matches!(outcome_chirho, Ok(Err(_))),
            "{fault_chirho}: the selection refuses promptly: {outcome_chirho:?}"
        );
        std::fs::remove_file(&log_chirho).unwrap();
    }
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// WARM SELECTION BY APP FOLDS NOTHING, ON A SMALL ROOT AND A LARGE ONE: on a fresh copy the first selection folds
/// every connection client (the counter's live control), and every warm selection after it folds none, whether the root
/// holds two connection clients or two hundred and two. One more client for the selected app is folded exactly once, and
/// turns its one into several: the changed-client control.
#[test]
fn warm_selection_by_app_folds_nothing_on_small_and_large_roots_chirho() {
    let world_chirho = SelectionWorldChirho::new_chirho("select-growth");
    let small_chirho = world_chirho.root_chirho.clone();
    let (selected_id_chirho, _store_chirho) =
        world_chirho.register_chirho(&small_chirho, OPENED_APP_CHIRHO);
    world_chirho.register_chirho(&small_chirho, OTHER_OPENED_APP_CHIRHO);
    let large_chirho = fresh_copy_chirho(&small_chirho);
    for _ in 0..200 {
        world_chirho.register_chirho(&large_chirho, OTHER_OPENED_APP_CHIRHO);
    }
    for _ in 0..20 {
        world_chirho.register_chirho(&large_chirho, PLAIN_APP_CHIRHO);
    }
    for (label_chirho, root_chirho, clients_chirho) in [
        ("small", &small_chirho, 2_u64),
        ("large", &large_chirho, 202_u64),
    ] {
        let cold_chirho = fresh_copy_chirho(root_chirho);
        let before_chirho = token_view_metrics_chirho::connection_client_folds_chirho();
        assert_eq!(
            selected_chirho(&cold_chirho, OPENED_APP_CHIRHO),
            AppConnectionClientChirho::OneChirho(selected_id_chirho.clone())
        );
        assert_eq!(
            token_view_metrics_chirho::connection_client_folds_chirho() - before_chirho,
            clients_chirho,
            "{label_chirho}: the first load folds every connection client (the live control)"
        );
        for _ in 0..5 {
            let before_chirho = token_view_metrics_chirho::connection_client_folds_chirho();
            assert_eq!(
                selected_chirho(&cold_chirho, OPENED_APP_CHIRHO),
                AppConnectionClientChirho::OneChirho(selected_id_chirho.clone())
            );
            assert_eq!(
                token_view_metrics_chirho::connection_client_folds_chirho() - before_chirho,
                0,
                "{label_chirho}: a warm selection folds nothing"
            );
        }
        world_chirho.register_chirho(&cold_chirho, OPENED_APP_CHIRHO);
        let before_chirho = token_view_metrics_chirho::connection_client_folds_chirho();
        assert_eq!(
            selected_chirho(&cold_chirho, OPENED_APP_CHIRHO),
            AppConnectionClientChirho::SeveralChirho,
            "{label_chirho}: a second client makes the app several"
        );
        assert!(
            token_view_metrics_chirho::connection_client_folds_chirho() - before_chirho <= 1,
            "{label_chirho}: the new client is folded at most once, here or at its registration"
        );
        std::fs::remove_dir_all(&cold_chirho).unwrap();
    }
    std::fs::remove_dir_all(&small_chirho).unwrap();
    std::fs::remove_dir_all(&large_chirho).unwrap();
}

fn by_app_chirho(app_chirho: &str) -> ConnectionSelectorChirho {
    ConnectionSelectorChirho::AppChirho(app_chirho.to_string())
}

/// THE FORM'S CHOICES BY APP ARE ITS ONE CLIENT'S CHOICES BY ID: with one connection client, selecting the app offers
/// exactly what selecting the client offers. An app with several connection clients, an app with only a legacy client,
/// and an app nobody deployed offer nothing (request-invalid on the road). A log the engine cannot examine refuses.
#[test]
fn the_choices_by_app_are_its_one_clients_choices_chirho() {
    let world_chirho = SelectionWorldChirho::new_chirho("select-choices");
    let root_chirho = world_chirho.root_chirho.clone();
    let (client_chirho, _store_chirho) =
        world_chirho.register_chirho(&root_chirho, OPENED_APP_CHIRHO);
    world_chirho.register_chirho(&root_chirho, PLAIN_APP_CHIRHO);
    let by_id_chirho = connection_form_choices_chirho(
        &root_chirho,
        &ConnectionSelectorChirho::ClientChirho(client_chirho.clone()),
    )
    .unwrap();
    assert!(
        by_id_chirho.is_some(),
        "the control: the client's own choices"
    );
    assert_eq!(
        connection_form_choices_chirho(&root_chirho, &by_app_chirho(OPENED_APP_CHIRHO)).unwrap(),
        by_id_chirho
    );
    for app_chirho in [PLAIN_APP_CHIRHO, "nosuchapp", OTHER_OPENED_APP_CHIRHO] {
        assert_eq!(
            connection_form_choices_chirho(&root_chirho, &by_app_chirho(app_chirho)).unwrap(),
            None,
            "{app_chirho}: no connection client"
        );
    }
    world_chirho.register_chirho(&root_chirho, OPENED_APP_CHIRHO);
    assert_eq!(
        connection_form_choices_chirho(&root_chirho, &by_app_chirho(OPENED_APP_CHIRHO)).unwrap(),
        None,
        "several connection clients: never the first, the latest or a default"
    );
    assert!(
        connection_form_choices_chirho(
            &root_chirho,
            &ConnectionSelectorChirho::ClientChirho(client_chirho)
        )
        .unwrap()
        .is_some(),
        "the explicit client still offers its choices"
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();

    let world_chirho = SelectionWorldChirho::new_chirho("select-choices-fault");
    let root_chirho = world_chirho.root_chirho.clone();
    assert!(std::process::Command::new("mkfifo")
        .arg(connection_clients_path_chirho(&root_chirho))
        .status()
        .unwrap()
        .success());
    let (sender_chirho, receiver_chirho) = std::sync::mpsc::channel();
    let lookup_root_chirho = root_chirho.clone();
    std::thread::spawn(move || {
        let _ = sender_chirho.send(
            connection_form_choices_chirho(&lookup_root_chirho, &by_app_chirho(OPENED_APP_CHIRHO))
                .map(|choices_chirho| choices_chirho.is_some())
                .map_err(|error_chirho| format!("{error_chirho:#}")),
        );
    });
    let outcome_chirho = receiver_chirho.recv_timeout(Duration::from_secs(5));
    assert!(
        matches!(outcome_chirho, Ok(Err(_))),
        "a log the engine cannot examine refuses, never offering nothing: {outcome_chirho:?}"
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// A CLIENT IN BOTH STORES REFUSES BY NAME ON THE APP'S ROAD TOO: the app's one connection client, planted also in the
/// legacy store, is refused when the app selects it, as when its id does.
#[test]
fn a_client_in_both_stores_refuses_on_the_apps_road_chirho() {
    let world_chirho = SelectionWorldChirho::new_chirho("select-both");
    let root_chirho = world_chirho.root_chirho.clone();
    let (client_chirho, _store_chirho) = register_client_in_store_chirho(
        &root_chirho,
        OPENED_APP_CHIRHO,
        &world_chirho.owner_chirho,
    )
    .unwrap();
    let mut planted_chirho = client_chirho.clone();
    planted_chirho.seq_chirho = 0;
    planted_chirho.schema_chirho = OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO.to_string();
    std::fs::write(
        clients_path_chirho(&root_chirho),
        format!("{}\n", serde_json::to_string(&planted_chirho).unwrap()),
    )
    .unwrap();
    for selector_chirho in [
        by_app_chirho(OPENED_APP_CHIRHO),
        ConnectionSelectorChirho::ClientChirho(client_chirho.client_id_chirho),
    ] {
        let refusal_chirho = connection_form_choices_chirho(&root_chirho, &selector_chirho);
        assert!(
            format!("{:#}", refusal_chirho.unwrap_err()).contains("ClientInBothStoresChirho"),
            "{selector_chirho:?}: a client in both stores refuses by name"
        );
    }
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// THE RETURN RULE: exactly `/app-chirho/<the app>/<one route name>`, in URL-unreserved characters, at most 256 bytes.
/// Dots inside a name are fine; a dot segment is not (a browser resolves `..` away, PFE #26837). Another app, a query, a
/// fragment, percent-encoding, a backslash, a control character, whitespace, an empty or extra segment, a trailing
/// slash, another prefix, a scheme or a protocol-relative path are each refused. The shape-only check accepts any app's
/// well-formed path and refuses the same malformed ones.
#[test]
fn the_return_rule_takes_only_a_named_route_of_the_app_chirho() {
    let app_chirho = "perffection-workspace";
    let account_chirho = "/app-chirho/perffection-workspace/account-chirho";
    assert!(connection_return_path_for_app_chirho(
        app_chirho,
        account_chirho
    ));
    assert!(connection_return_path_for_app_chirho(
        "a.b",
        "/app-chirho/a.b/r_1~x.y"
    ));
    let longest_route_chirho =
        "r".repeat(CONNECTION_RETURN_MAX_BYTES_CHIRHO - "/app-chirho/a/".len());
    assert!(connection_return_path_for_app_chirho(
        "a",
        &format!("/app-chirho/a/{longest_route_chirho}")
    ));
    assert!(!connection_return_path_for_app_chirho(
        "a",
        &format!("/app-chirho/a/{longest_route_chirho}r")
    ));
    for refused_chirho in [
        "/app-chirho/other-app/account-chirho",
        "/app-chirho/perffection-workspace/..",
        "/app-chirho/perffection-workspace/.",
        "/app-chirho/../account-chirho",
        "/app-chirho/./account-chirho",
        "/app-chirho/perffection-workspace/",
        "/app-chirho/perffection-workspace",
        "/app-chirho//account-chirho",
        "/app-chirho/perffection-workspace/account-chirho/",
        "/app-chirho/perffection-workspace/account-chirho/more",
        "/app-chirho/perffection-workspace/account-chirho?x=1",
        "/app-chirho/perffection-workspace/account-chirho#top",
        "/app-chirho/perffection-workspace/%2E%2E",
        "/app-chirho/perffection-workspace/account%2Fchirho",
        "/app-chirho/perffection-workspace/account\\chirho",
        "/app-chirho/perffection-workspace/account\u{0}chirho",
        "/app-chirho/perffection-workspace/account chirho",
        " /app-chirho/perffection-workspace/account-chirho",
        "/app-chirho/perffection-workspace/account-chirho ",
        "/APP-CHIRHO/perffection-workspace/account-chirho",
        "/app-chirho-x/perffection-workspace/account-chirho",
        "//evil.example/app-chirho/perffection-workspace/account-chirho",
        "https://evil.example/app-chirho/perffection-workspace/account-chirho",
        "",
    ] {
        assert!(
            !connection_return_path_for_app_chirho(app_chirho, refused_chirho),
            "refused for the app: {refused_chirho:?}"
        );
        assert!(
            refused_chirho == "/app-chirho/other-app/account-chirho"
                || !connection_return_path_well_formed_chirho(refused_chirho),
            "refused by shape: {refused_chirho:?}"
        );
    }
    assert!(connection_return_path_well_formed_chirho(
        "/app-chirho/other-app/account-chirho"
    ));
}

/// THE ISSUANCE REFUSES A RETURN OUTSIDE THE CLIENT'S APP BEFORE ANYTHING IS APPENDED: a return to another app's route,
/// or a dot segment, is request-invalid with no attempt row, no key and no session; the same request with the client's
/// own app route creates the connection (the control).
#[test]
fn the_issuance_refuses_a_foreign_return_before_any_append_chirho() {
    let world_chirho = world_chirho("select-return");
    let root_chirho = &world_chirho.root_chirho;
    let client_id_chirho = world_chirho
        .connection_client_chirho
        .client_id_chirho
        .clone();
    let written_chirho = || {
        (
            identity_chirho::load_auth_attempts_chirho(root_chirho)
                .unwrap()
                .len(),
            std::fs::read_to_string(root_chirho.join(CONNECTION_TOKENS_CHIRHO))
                .map(|text_chirho| text_chirho.lines().count())
                .unwrap_or(0),
            std::fs::read_to_string(root_chirho.join("identity-sessions-chirho.jsonl"))
                .map(|text_chirho| text_chirho.lines().count())
                .unwrap_or(0),
        )
    };
    let serve_chirho = |return_chirho: &str| {
        issue_connection_key_served_chirho(
            root_chirho,
            &ConnectionServedRequestChirho {
                principal_chirho: &world_chirho.user_chirho,
                credential_chirho: SECRET_CHIRHO,
                client_id_chirho: &client_id_chirho,
                actions_chirho: &page_read_chirho(),
                return_chirho: Some(return_chirho),
            },
            &identity_chirho::SignInVelocityChirho {
                principal_successes_per_hour_chirho: 100,
            },
        )
    };
    let before_chirho = written_chirho();
    for foreign_chirho in [
        format!("/app-chirho/{PLAIN_APP_CHIRHO}/view"),
        format!("/app-chirho/{OPENED_APP_CHIRHO}/.."),
        format!("/app-chirho/{OPENED_APP_CHIRHO}/view?x=1"),
    ] {
        let refusal_chirho = serve_chirho(&foreign_chirho).unwrap_err();
        assert!(
            matches!(
                ConnectionServedRefusalChirho::of_chirho(&refusal_chirho),
                ConnectionServedRefusalChirho::RequestInvalidChirho
            ),
            "{foreign_chirho}"
        );
        assert!(
            !refusal_chirho.failure_recorded_chirho,
            "{foreign_chirho}: no failure is recorded"
        );
        assert_eq!(
            written_chirho(),
            before_chirho,
            "{foreign_chirho}: nothing appended"
        );
    }
    assert!(
        matches!(
            serve_chirho(&format!("/app-chirho/{OPENED_APP_CHIRHO}/view")),
            Ok(ConnectionServedOutcomeChirho::CreatedChirho(_))
        ),
        "the control: the client's own app route"
    );
    let (attempts_chirho, keys_chirho, sessions_chirho) = written_chirho();
    assert_eq!(
        (attempts_chirho, keys_chirho, sessions_chirho),
        (
            before_chirho.0 + 1,
            before_chirho.1 + 1,
            before_chirho.2 + 1
        )
    );
}
