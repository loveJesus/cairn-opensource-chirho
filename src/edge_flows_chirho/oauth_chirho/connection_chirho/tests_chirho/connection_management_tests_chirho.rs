// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 CP5's arms: what ends a key still ends a connection (PFE #26763; the design's Part 1 carrier).
//! - K3's key list shows a principal's keys from both stores, a connection's actions included;
//! - Disconnect (revoke by key id) ends a connection through its shared session, leaves the row listed as ended, and
//!   leaves the principal's other keys working;
//! - another principal's Disconnect of that id is the one unknown-key refusal;
//! - a credential reset ends a principal's keys in both stores, and no other principal's;
//! - a token log the engine cannot examine, or a connection row that does not verify, makes the list fail, so K3's
//!   page answers unavailable and never an empty list.

use super::super::{
    issue_limited_key_chirho, list_own_keys_chirho, resolve_bearer_for_app_chirho,
    revoke_own_key_chirho, run_own_keys_read_chirho, scoped_key_id_chirho, BearerKeyChirho,
    OwnKeysReadRequestChirho, ScopedKeyRowChirho, ScopedTokenIssueChirho, UnknownScopedKeyChirho,
    BROWSER_SESSION_CLIENT_ID_CHIRHO, OWN_KEYS_READ_REQUEST_SCHEMA_CHIRHO,
};
use super::connection_fixture_chirho::*;
use super::*;
use crate::model_chirho::RequestContextChirho;
use cairn_capability_chirho::capability_key_grant_chirho::OWN_KEYS_CAPABILITY_PREFIX_CHIRHO;
use identity_chirho::PrincipalKindChirho;
use std::io::Write;

const NEW_SECRET_CHIRHO: &str = "k4-token-new-secret-chirho";

fn row_for_chirho(
    rows_chirho: &[ScopedKeyRowChirho],
    issue_chirho: &ScopedTokenIssueChirho,
) -> ScopedKeyRowChirho {
    let key_id_chirho = scoped_key_id_chirho(&issue_chirho.record_chirho.token_hash_chirho);
    rows_chirho
        .iter()
        .find(|row_chirho| row_chirho.key_id_chirho == key_id_chirho)
        .cloned()
        .expect("the key is listed")
}

fn answers_chirho(world_chirho: &TokenWorldChirho, app_chirho: &str, token_chirho: &str) -> bool {
    resolve_bearer_for_app_chirho(&world_chirho.root_chirho, app_chirho, token_chirho)
        .unwrap()
        .is_some()
}

/// THE KEY LIST SHOWS BOTH STORES, AND DISCONNECT ENDS ONLY THE CONNECTION: the owner's list holds her legacy key and
/// her connection, the connection's row showing its action. Disconnecting it by its key id (twice: a repeat answers the
/// same) ends it on its next request and leaves its row listed as ended, while the legacy key keeps working.
#[test]
fn the_key_list_shows_both_stores_and_disconnect_ends_only_the_connection_chirho() {
    let world_chirho = world_chirho("list");
    let legacy_chirho = world_chirho.legacy_key_chirho().unwrap();
    let connection_chirho = world_chirho.connection_key_chirho().unwrap();
    let rows_chirho =
        list_own_keys_chirho(&world_chirho.root_chirho, &world_chirho.user_chirho).unwrap();
    assert_eq!(rows_chirho.len(), 2);
    let connection_row_chirho = row_for_chirho(&rows_chirho, &connection_chirho);
    assert_eq!(
        (
            connection_row_chirho.app_chirho.as_str(),
            connection_row_chirho.scopes_chirho.clone(),
            connection_row_chirho.live_chirho
        ),
        (OPENED_APP_CHIRHO, page_read_chirho(), true)
    );
    let legacy_row_chirho = row_for_chirho(&rows_chirho, &legacy_chirho);
    assert_eq!(
        (
            legacy_row_chirho.app_chirho.as_str(),
            legacy_row_chirho.live_chirho
        ),
        (PLAIN_APP_CHIRHO, true)
    );

    for _ in 0..2 {
        revoke_own_key_chirho(
            &world_chirho.root_chirho,
            &world_chirho.user_chirho,
            &connection_row_chirho.key_id_chirho,
        )
        .unwrap();
    }
    let rows_chirho =
        list_own_keys_chirho(&world_chirho.root_chirho, &world_chirho.user_chirho).unwrap();
    assert_eq!(
        rows_chirho.len(),
        2,
        "an ended key stays listed until it expires"
    );
    assert!(!row_for_chirho(&rows_chirho, &connection_chirho).live_chirho);
    assert!(row_for_chirho(&rows_chirho, &legacy_chirho).live_chirho);
    assert!(!answers_chirho(
        &world_chirho,
        OPENED_APP_CHIRHO,
        &connection_chirho.token_chirho
    ));
    assert!(matches!(
        resolve_bearer_for_app_chirho(
            &world_chirho.root_chirho,
            PLAIN_APP_CHIRHO,
            &legacy_chirho.token_chirho
        ),
        Ok(Some(BearerKeyChirho::LegacyChirho(_)))
    ));
}

/// ANOTHER PRINCIPAL CANNOT DISCONNECT A CONNECTION: the id is looked up only among the caller's own keys, so another
/// principal's attempt is the one unknown-key refusal and the connection keeps answering.
#[test]
fn another_principal_cannot_disconnect_a_connection_chirho() {
    let world_chirho = world_chirho("other-principal");
    let connection_chirho = world_chirho.connection_key_chirho().unwrap();
    let other_chirho = identity_chirho::register_identity_with_credential_chirho(
        &world_chirho.root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let refusal_chirho = revoke_own_key_chirho(
        &world_chirho.root_chirho,
        &other_chirho,
        &scoped_key_id_chirho(&connection_chirho.record_chirho.token_hash_chirho),
    )
    .unwrap_err();
    assert!(
        refusal_chirho
            .downcast_ref::<UnknownScopedKeyChirho>()
            .is_some(),
        "{refusal_chirho:#}"
    );
    assert!(answers_chirho(
        &world_chirho,
        OPENED_APP_CHIRHO,
        &connection_chirho.token_chirho
    ));
}

/// A CREDENTIAL RESET ENDS A PRINCIPAL'S KEYS IN BOTH STORES AND NO OTHER PRINCIPAL'S: through the shared sessions, as
/// for a legacy key; a connection issued with the new credential then works.
#[test]
fn a_credential_reset_ends_a_principals_keys_in_both_stores_chirho() {
    let world_chirho = world_chirho("reset");
    let legacy_chirho = world_chirho.legacy_key_chirho().unwrap();
    let connection_chirho = world_chirho.connection_key_chirho().unwrap();
    let other_chirho = identity_chirho::register_identity_with_credential_chirho(
        &world_chirho.root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let connection_issue_chirho = |principal_chirho: &str, secret_chirho: &str| {
        issue_limited_key_chirho(
            &world_chirho.root_chirho,
            principal_chirho,
            secret_chirho,
            &world_chirho.connection_client_chirho.client_id_chirho,
            &page_read_chirho(),
            None,
        )
        .unwrap()
    };
    let others_chirho = connection_issue_chirho(&other_chirho, SECRET_CHIRHO);

    identity_chirho::reset_identity_credential_chirho(
        &world_chirho.root_chirho,
        &world_chirho.user_chirho,
        NEW_SECRET_CHIRHO,
        "operator-chirho",
        "k4 cp5 arm",
    )
    .unwrap();
    assert!(!answers_chirho(
        &world_chirho,
        PLAIN_APP_CHIRHO,
        &legacy_chirho.token_chirho
    ));
    assert!(!answers_chirho(
        &world_chirho,
        OPENED_APP_CHIRHO,
        &connection_chirho.token_chirho
    ));
    assert!(
        answers_chirho(
            &world_chirho,
            OPENED_APP_CHIRHO,
            &others_chirho.token_chirho
        ),
        "another principal's connection is untouched"
    );
    let fresh_chirho = connection_issue_chirho(&world_chirho.user_chirho, NEW_SECRET_CHIRHO);
    assert!(answers_chirho(
        &world_chirho,
        OPENED_APP_CHIRHO,
        &fresh_chirho.token_chirho
    ));
}

/// What a fault leaves where a key log should be.
enum KeyLogFaultChirho {
    /// A directory at the log's path, before any key is written there: the shared absence rule refuses it.
    DirectoryChirho,
    /// A line that does not parse, after the user's key: the view refuses it.
    UnparsableRowChirho,
}

/// A KEY LOG THE ENGINE CANNOT EXAMINE OR VERIFY MAKES THE LIST FAIL, SO K3'S PAGE IS UNAVAILABLE, NEVER EMPTY: each
/// fault leaves the user's list an error and the blessed read's answer `unavailable-chirho` with no rows, where an
/// empty list would read as "no connections". While a key log cannot be examined, issuance in the other store refuses
/// too, since the cap counts both stores. The control, unfaulted, answers available with the user's key.
#[test]
fn a_faulted_key_log_makes_the_key_page_unavailable_never_empty_chirho() {
    let cases_chirho: [(&str, Option<(&str, KeyLogFaultChirho)>); 4] = [
        ("control", None),
        (
            "a directory where the connection token log goes",
            Some((CONNECTION_TOKENS_CHIRHO, KeyLogFaultChirho::DirectoryChirho)),
        ),
        (
            "a directory where the legacy token log goes",
            Some((LEGACY_TOKENS_CHIRHO, KeyLogFaultChirho::DirectoryChirho)),
        ),
        (
            "an unparsable row in the connection token log",
            Some((
                CONNECTION_TOKENS_CHIRHO,
                KeyLogFaultChirho::UnparsableRowChirho,
            )),
        ),
    ];
    let mut failures_chirho = Vec::new();
    for (name_chirho, fault_chirho) in cases_chirho {
        let world_chirho = world_chirho("page");
        match &fault_chirho {
            Some((log_chirho, KeyLogFaultChirho::DirectoryChirho)) => {
                // The user's one key goes to the OTHER store first, so the faulted log holds none of the user's keys.
                let in_connection_log_chirho = *log_chirho == CONNECTION_TOKENS_CHIRHO;
                let issue_other_chirho = || {
                    if in_connection_log_chirho {
                        world_chirho.legacy_key_chirho()
                    } else {
                        world_chirho.connection_key_chirho()
                    }
                };
                issue_other_chirho().unwrap();
                std::fs::create_dir(world_chirho.root_chirho.join(log_chirho)).unwrap();
                // Issuance in the healthy store refuses too: the cap counts both stores and cannot count this one.
                if issue_other_chirho().is_ok() {
                    failures_chirho.push(format!(
                        "{name_chirho}: a key was issued while a key log could not be examined"
                    ));
                }
            }
            Some((log_chirho, KeyLogFaultChirho::UnparsableRowChirho)) => {
                world_chirho.connection_key_chirho().unwrap();
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(world_chirho.root_chirho.join(log_chirho))
                    .unwrap()
                    .write_all(b"{\"not\": \"a key\"}\n")
                    .unwrap();
            }
            None => {
                world_chirho.connection_key_chirho().unwrap();
            }
        }
        let listed_chirho =
            list_own_keys_chirho(&world_chirho.root_chirho, &world_chirho.user_chirho);
        let answer_chirho = run_own_keys_read_chirho(
            &world_chirho.root_chirho,
            OWN_KEYS_CAPABILITY_PREFIX_CHIRHO,
            &OwnKeysReadRequestChirho {
                schema_chirho: OWN_KEYS_READ_REQUEST_SCHEMA_CHIRHO.to_string(),
                user_principal_chirho: None,
                app_params_chirho: None,
            },
            Some(&RequestContextChirho {
                user_principal_chirho: world_chirho.user_chirho.clone(),
                app_chirho: PLAIN_APP_CHIRHO.to_string(),
                owner_principal_chirho: String::new(),
                client_id_chirho: BROWSER_SESSION_CLIENT_ID_CHIRHO.to_string(),
                token_hash_chirho: "browser-session-token-hash-chirho".to_string(),
                price_book_chirho: None,
                billing_policy_chirho: None,
                key_limit_chirho: None,
            }),
        )
        .unwrap();
        let answer_chirho: serde_json::Value =
            serde_json::from_slice(&answer_chirho.response_chirho).unwrap();
        let state_chirho = answer_chirho["state_chirho"].as_str().unwrap_or_default();
        let as_expected_chirho = match fault_chirho {
            None => {
                listed_chirho
                    .as_ref()
                    .is_ok_and(|rows_chirho| rows_chirho.len() == 1)
                    && state_chirho == "available-chirho"
            }
            Some(_) => {
                listed_chirho.is_err()
                    && state_chirho == "unavailable-chirho"
                    && answer_chirho.get("keys_chirho").is_none()
            }
        };
        if !as_expected_chirho {
            failures_chirho.push(format!(
                "{name_chirho}: listed {:?}, answered {answer_chirho}",
                listed_chirho.map(|rows_chirho| rows_chirho.len())
            ));
        }
    }
    assert!(failures_chirho.is_empty(), "{failures_chirho:#?}");
}
