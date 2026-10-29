// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 CP3 and CP4's arms for the connection token and use logs (PFE #26763):
//! - a connection key and its uses live only in the connection logs, numbered from 0 in their own namespace;
//! - a key hash in both token logs refuses every lookup and the connection verifier;
//! - the five-slot cap counts both token logs across apps, decided under the one root lock, in both race orders;
//! - a rate budget belongs to its key, not to a store, so uses in both stores share it;
//! - the use door refuses a key that is not the verified key at its seq in its own store, before any row;
//! - a faulted row in either token log refuses every lookup rather than falling back;
//! - a connection key's run is refused by the limited-key resume rule.
//!
//! Unreachable from the suite, stated rather than claimed: issuance's own store check, for a LEGACY key through a
//! connection client, is redundant today with the app-mode check, which refuses the same request with the same refusal
//! earlier on the legacy road. A LIMITED key through a connection client on the legacy road refuses by name (Part 2;
//! `connection_lifetime_tests_chirho.rs`): only the connection's own road issues one.

use super::super::{
    issue_limited_key_chirho, issue_scoped_token_after_login_at_chirho,
    issue_scoped_token_with_rate_limit_chirho, key_listing_chirho, limited_key_grants_now_chirho,
    public_default_rate_limit_chirho, record_scoped_token_use_chirho,
    resolve_bearer_for_app_chirho, revoke_own_key_chirho, scoped_key_id_chirho,
    scoped_token_message_chirho, verify_scoped_token_uses_chirho, verify_scoped_tokens_chirho,
    BearerKeyChirho, IssuedKeyKindChirho, LegacyKeyForLimitedAppChirho, RateLimitExceededChirho,
    ScopedTokenCapReachedChirho, ScopedTokenIssueChirho, ScopedTokenRateLimitChirho,
};
use super::connection_fixture_chirho::*;
use super::*;
use cairn_capability_chirho::capability_key_grant_chirho::limited_key_scopes_chirho;
use identity_chirho::PrincipalKindChirho;
use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;

/// Append `record_chirho` to the log `name_chirho`, signed by the root, as a row its own log verifies: the fault rows
/// below are signed, so each refusal is the fault's and never a bad signature's.
fn append_signed_chirho(
    world_chirho: &TokenWorldChirho,
    name_chirho: &str,
    mut record_chirho: ScopedTokenRecordChirho,
) {
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &world_chirho.root_chirho,
        &scoped_token_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    let mut line_chirho = serde_json::to_string(&record_chirho).unwrap();
    line_chirho.push('\n');
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(world_chirho.root_chirho.join(name_chirho))
        .unwrap()
        .write_all(line_chirho.as_bytes())
        .unwrap();
}

fn fresh_hash_chirho(label_chirho: &str) -> String {
    crate::cas_chirho::hash_chirho(label_chirho.as_bytes()).0
}

/// A CONNECTION KEY AND ITS USES LIVE ONLY IN THE CONNECTION LOGS, NUMBERED FROM 0: a legacy key and a connection key
/// are each seq 0 of their own store, so are their uses, each use names its key within its own store, and the explicit
/// old and new verifiers each pass over their own logs.
#[test]
fn a_connection_key_and_its_uses_live_only_in_the_connection_logs_from_zero_chirho() {
    let world_chirho = world_chirho("dense");
    let legacy_chirho = world_chirho.legacy_key_chirho().unwrap();
    let first_chirho = world_chirho.connection_key_chirho().unwrap();
    let second_chirho = world_chirho.connection_key_chirho().unwrap();
    assert_eq!(
        (
            legacy_chirho.record_chirho.seq_chirho,
            first_chirho.record_chirho.seq_chirho,
            second_chirho.record_chirho.seq_chirho
        ),
        (0, 0, 1),
        "each store numbers its keys from 0"
    );
    assert_eq!(
        KeyStoreChirho::of_token_chirho(&second_chirho.record_chirho),
        KeyStoreChirho::ConnectionChirho
    );
    assert_eq!(world_chirho.token_lines_chirho(), (1, 2));
    assert_eq!(
        verify_scoped_tokens_chirho(&world_chirho.root_chirho).unwrap(),
        1
    );
    assert_eq!(
        verify_connection_tokens_chirho(&world_chirho.root_chirho).unwrap(),
        2
    );

    match resolve_bearer_for_app_chirho(
        &world_chirho.root_chirho,
        OPENED_APP_CHIRHO,
        &second_chirho.token_chirho,
    )
    .unwrap()
    {
        Some(BearerKeyChirho::LimitedChirho { record_chirho, .. }) => {
            assert_eq!(record_chirho, second_chirho.record_chirho)
        }
        other_chirho => panic!("the connection key resolves as a limited key: {other_chirho:?}"),
    }

    let legacy_use_chirho =
        record_scoped_token_use_chirho(&world_chirho.root_chirho, &legacy_chirho.record_chirho)
            .unwrap()
            .unwrap();
    let connection_use_chirho =
        record_scoped_token_use_chirho(&world_chirho.root_chirho, &second_chirho.record_chirho)
            .unwrap()
            .unwrap();
    assert_eq!(
        (
            legacy_use_chirho.seq_chirho,
            legacy_use_chirho.scoped_token_seq_chirho
        ),
        (0, 0)
    );
    assert_eq!(
        (
            connection_use_chirho.seq_chirho,
            connection_use_chirho.scoped_token_seq_chirho
        ),
        (0, 1),
        "the use names its key by the CONNECTION log's seq"
    );
    assert_eq!(
        connection_use_chirho.schema_chirho,
        CONNECTION_TOKEN_USE_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(world_chirho.use_lines_chirho(), (1, 1));
    assert_eq!(
        verify_scoped_token_uses_chirho(&world_chirho.root_chirho).unwrap(),
        1
    );
    assert_eq!(
        verify_connection_token_uses_chirho(&world_chirho.root_chirho).unwrap(),
        1
    );
}

/// A CONNECTION CLIENT NEVER ISSUES A LEGACY KEY: the legacy road refuses it as an app that takes only limited keys,
/// and neither token log gains a row.
#[test]
fn a_connection_client_never_issues_a_legacy_key_chirho() {
    let world_chirho = world_chirho("no-legacy");
    let refusal_chirho = issue_scoped_token_with_rate_limit_chirho(
        &world_chirho.root_chirho,
        &world_chirho.user_chirho,
        SECRET_CHIRHO,
        &world_chirho.connection_client_chirho.client_id_chirho,
        Vec::new(),
        Some(public_default_rate_limit_chirho()),
    )
    .unwrap_err();
    assert!(
        refusal_chirho
            .downcast_ref::<LegacyKeyForLimitedAppChirho>()
            .is_some(),
        "{refusal_chirho:#}"
    );
    assert_eq!(world_chirho.token_lines_chirho(), (0, 0));
}

/// A KEY HASH IN BOTH TOKEN LOGS REFUSES: a validly signed legacy row carrying a connection key's hash makes every
/// lookup of that key refuse, from either app, and the connection verifier refuse, while the legacy log alone still
/// verifies (so the refusal is the duplication's, not a bad row's).
#[test]
fn a_key_hash_in_both_token_logs_refuses_every_lookup_chirho() {
    let world_chirho = world_chirho("both-stores");
    let legacy_chirho = world_chirho.legacy_key_chirho().unwrap();
    let connection_chirho = world_chirho.connection_key_chirho().unwrap();
    assert!(matches!(
        resolve_bearer_for_app_chirho(
            &world_chirho.root_chirho,
            OPENED_APP_CHIRHO,
            &connection_chirho.token_chirho
        ),
        Ok(Some(BearerKeyChirho::LimitedChirho { .. }))
    ));

    let mut copy_chirho = legacy_chirho.record_chirho.clone();
    copy_chirho.seq_chirho = 1;
    copy_chirho.token_hash_chirho = connection_chirho.record_chirho.token_hash_chirho.clone();
    append_signed_chirho(&world_chirho, LEGACY_TOKENS_CHIRHO, copy_chirho);
    assert_eq!(
        verify_scoped_tokens_chirho(&world_chirho.root_chirho).unwrap(),
        2
    );

    for app_chirho in [OPENED_APP_CHIRHO, PLAIN_APP_CHIRHO] {
        let refusal_chirho = refusal_text_chirho(resolve_bearer_for_app_chirho(
            &world_chirho.root_chirho,
            app_chirho,
            &connection_chirho.token_chirho,
        ));
        assert!(
            refusal_chirho.contains("TokenInBothStoresChirho"),
            "{app_chirho}: {refusal_chirho}"
        );
    }
    let refusal_chirho =
        refusal_text_chirho(verify_connection_tokens_chirho(&world_chirho.root_chirho));
    assert!(
        refusal_chirho.contains("TokenInBothStoresChirho"),
        "{refusal_chirho}"
    );
}

/// THE CAP COUNTS BOTH TOKEN LOGS ACROSS APPS: three legacy keys and two connection keys fill the five slots, so a
/// sixth refuses in either store and writes no key (the legacy road has signed in, so its session is written; the
/// connection road writes none); ending a connection key frees a slot that a legacy key then takes.
#[test]
fn the_cap_counts_both_token_logs_across_apps_chirho() {
    let world_chirho = world_chirho("cap");
    for _ in 0..3 {
        world_chirho.legacy_key_chirho().unwrap();
    }
    let connection_keys_chirho: Vec<ScopedTokenIssueChirho> = (0..2)
        .map(|_| world_chirho.connection_key_chirho().unwrap())
        .collect();
    for refusal_chirho in [
        world_chirho.legacy_key_chirho().unwrap_err(),
        world_chirho.connection_key_chirho().unwrap_err(),
    ] {
        assert!(
            refusal_chirho
                .downcast_ref::<ScopedTokenCapReachedChirho>()
                .is_some(),
            "{refusal_chirho:#}"
        );
    }
    assert_eq!(world_chirho.token_lines_chirho(), (3, 2));

    revoke_own_key_chirho(
        &world_chirho.root_chirho,
        &world_chirho.user_chirho,
        &scoped_key_id_chirho(&connection_keys_chirho[0].record_chirho.token_hash_chirho),
    )
    .unwrap();
    world_chirho.legacy_key_chirho().unwrap();
    assert!(world_chirho
        .connection_key_chirho()
        .unwrap_err()
        .downcast_ref::<ScopedTokenCapReachedChirho>()
        .is_some());
    assert_eq!(world_chirho.token_lines_chirho(), (4, 2));
}

/// THE LAST SLOT GOES TO ONE ISSUANCE, IN BOTH ORDERS: with four live keys, one issuance holds the lock after deciding
/// its cap and before writing; the other meets the lock and refuses once it can count. A legacy issuance has signed in
/// already; a connection proves its credential inside its own road (Part 2), so it meets the lock after its proof. Each
/// pair spans the two logs and the two apps. A decision taken before the lock would admit both.
#[test]
fn a_race_for_the_last_slot_across_logs_admits_exactly_one_chirho() {
    for holder_is_connection_chirho in [true, false] {
        let world_chirho = world_chirho(if holder_is_connection_chirho {
            "race-connection-holds"
        } else {
            "race-legacy-holds"
        });
        for _ in 0..2 {
            world_chirho.legacy_key_chirho().unwrap();
            world_chirho.connection_key_chirho().unwrap();
        }
        type IssueChirho<'world_chirho> =
            Box<dyn FnOnce() -> Result<ScopedTokenIssueChirho> + Send + 'world_chirho>;
        let issue_chirho = |connection_chirho: bool| -> IssueChirho<'_> {
            let root_chirho = &world_chirho.root_chirho;
            if connection_chirho {
                let client_chirho = world_chirho.connection_client_chirho.clone();
                let user_chirho = world_chirho.user_chirho.clone();
                let grants_chirho = limited_key_grants_now_chirho(
                    root_chirho,
                    OPENED_APP_CHIRHO,
                    &page_read_chirho(),
                )
                .unwrap();
                Box::new(move || {
                    issue_connection_key_at_chirho(
                        root_chirho,
                        &client_chirho,
                        &user_chirho,
                        SECRET_CHIRHO,
                        grants_chirho,
                        public_default_rate_limit_chirho(),
                        now_ms_chirho,
                    )
                })
            } else {
                let login_chirho = identity_chirho::login_identity_with_credential_chirho(
                    root_chirho,
                    &world_chirho.user_chirho,
                    SECRET_CHIRHO,
                )
                .unwrap();
                let client_chirho = world_chirho.legacy_client_chirho.clone();
                Box::new(move || {
                    issue_scoped_token_after_login_at_chirho(
                        root_chirho,
                        client_chirho,
                        login_chirho,
                        IssuedKeyKindChirho::LegacyChirho(Vec::new()),
                        Some(public_default_rate_limit_chirho()),
                        now_ms_chirho,
                    )
                })
            }
        };
        // A legacy issuer signs in first; a connection proves inside its road. Either way the waiter is past its proof
        // and ready to count while the holder still holds the lock.
        let holder_issue_chirho = issue_chirho(holder_is_connection_chirho);
        let waiter_issue_chirho = issue_chirho(!holder_is_connection_chirho);
        let (entered_chirho, entered_rx_chirho) = mpsc::channel::<()>();
        let (release_chirho, release_rx_chirho) = mpsc::channel::<()>();
        std::thread::scope(|scope_chirho| {
            let holder_chirho = scope_chirho.spawn(move || {
                set_issuance_hold_chirho(move || {
                    entered_chirho.send(()).unwrap();
                    release_rx_chirho.recv().unwrap();
                    Ok(())
                });
                holder_issue_chirho()
            });
            entered_rx_chirho
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            let waiter_chirho = scope_chirho.spawn(waiter_issue_chirho);
            std::thread::sleep(Duration::from_millis(300));
            release_chirho.send(()).unwrap();
            assert!(holder_chirho.join().unwrap().is_ok());
            let refusal_chirho = waiter_chirho.join().unwrap().unwrap_err();
            assert!(
                refusal_chirho
                    .downcast_ref::<ScopedTokenCapReachedChirho>()
                    .is_some(),
                "{refusal_chirho:#}"
            );
        });
        assert_eq!(
            world_chirho.token_lines_chirho(),
            if holder_is_connection_chirho {
                (2, 3)
            } else {
                (3, 2)
            }
        );
        assert_eq!(
            key_listing_chirho::live_rate_limited_keys_chirho(
                &world_chirho.root_chirho,
                &world_chirho.user_chirho,
                now_ms_chirho()
            )
            .unwrap(),
            5
        );
    }
}

/// A RATE BUDGET BELONGS TO ITS KEY, NOT TO A STORE: an app opened under K1 keeps its legacy client, and a connection
/// client registers after; one user holds a limited key through each, with the same policy. Their uses share one budget
/// of three, so the fourth refuses through either key, while each log's own verifier still passes.
#[test]
fn a_rate_budget_spans_both_stores_chirho() {
    let root_chirho = own_root_chirho("budget");
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap()
            .principal_chirho;
    let view_chirho = deploy_app_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho);
    let (legacy_client_chirho, _) =
        register_client_in_store_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho).unwrap();
    with_k1_era_opening_chirho(|| {
        crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
            &root_chirho,
            OPENED_APP_CHIRHO,
            &owner_chirho,
            view_opening_chirho(&view_chirho),
        )
    })
    .unwrap();
    let (connection_client_chirho, store_chirho) =
        register_client_in_store_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho).unwrap();
    assert_eq!(store_chirho, KeyStoreChirho::ConnectionChirho);
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let policy_chirho = ScopedTokenRateLimitChirho {
        window_ms_chirho: 60_000,
        max_invokes_chirho: 3,
        device_id_chirho: None,
    };
    let key_chirho = |client_chirho: &OauthClientRecordChirho| {
        issue_limited_key_chirho(
            &root_chirho,
            &user_chirho,
            SECRET_CHIRHO,
            &client_chirho.client_id_chirho,
            &page_read_chirho(),
            Some(policy_chirho.clone()),
        )
        .unwrap()
        .record_chirho
    };
    let legacy_store_key_chirho = key_chirho(&legacy_client_chirho);
    let connection_key_chirho = key_chirho(&connection_client_chirho);
    assert_eq!(
        (
            KeyStoreChirho::of_token_chirho(&legacy_store_key_chirho),
            KeyStoreChirho::of_token_chirho(&connection_key_chirho)
        ),
        (
            KeyStoreChirho::LegacyChirho,
            KeyStoreChirho::ConnectionChirho
        )
    );
    for record_chirho in [
        &legacy_store_key_chirho,
        &connection_key_chirho,
        &legacy_store_key_chirho,
    ] {
        record_scoped_token_use_chirho(&root_chirho, record_chirho).unwrap();
    }
    for record_chirho in [&connection_key_chirho, &legacy_store_key_chirho] {
        let refusal_chirho =
            record_scoped_token_use_chirho(&root_chirho, record_chirho).unwrap_err();
        assert!(
            refusal_chirho
                .downcast_ref::<RateLimitExceededChirho>()
                .is_some(),
            "{refusal_chirho:#}"
        );
    }
    assert_eq!(verify_scoped_token_uses_chirho(&root_chirho).unwrap(), 2);
    assert_eq!(
        verify_connection_token_uses_chirho(&root_chirho).unwrap(),
        1
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

/// THE USE DOOR REFUSES A KEY THAT IS NOT THE VERIFIED KEY AT ITS SEQ IN ITS OWN STORE: a connection key relabelled as
/// a legacy one would name legacy seq 0, another key, and the reverse likewise; each refuses by name and neither use
/// log gains a row, while the genuine records then record.
#[test]
fn the_use_door_refuses_a_key_named_in_the_wrong_store_chirho() {
    let world_chirho = world_chirho("misnamed");
    let legacy_chirho = world_chirho.legacy_key_chirho().unwrap();
    let connection_chirho = world_chirho.connection_key_chirho().unwrap();
    let mut as_legacy_chirho = connection_chirho.record_chirho.clone();
    as_legacy_chirho.schema_chirho = KeyStoreChirho::LegacyChirho
        .token_schema_chirho()
        .to_string();
    let mut as_connection_chirho = legacy_chirho.record_chirho.clone();
    as_connection_chirho.schema_chirho = CONNECTION_TOKEN_RECORD_SCHEMA_CHIRHO.to_string();
    for record_chirho in [&as_legacy_chirho, &as_connection_chirho] {
        let refusal_chirho = refusal_text_chirho(record_scoped_token_use_chirho(
            &world_chirho.root_chirho,
            record_chirho,
        ));
        assert!(
            refusal_chirho.contains("UseNamesAnotherKeyChirho"),
            "{refusal_chirho}"
        );
    }
    assert_eq!(world_chirho.use_lines_chirho(), (0, 0));
    record_scoped_token_use_chirho(&world_chirho.root_chirho, &legacy_chirho.record_chirho)
        .unwrap();
    record_scoped_token_use_chirho(&world_chirho.root_chirho, &connection_chirho.record_chirho)
        .unwrap();
    assert_eq!(world_chirho.use_lines_chirho(), (1, 1));
}

/// One faulted row and the refusal it must produce.
struct TokenFaultChirho {
    name_chirho: &'static str,
    /// The log the row is written to.
    log_chirho: &'static str,
    refusal_chirho: &'static str,
    plant_chirho: fn(
        &TokenWorldChirho,
        &ScopedTokenRecordChirho,
        &ScopedTokenRecordChirho,
    ) -> ScopedTokenRecordChirho,
}

/// A FAULTED ROW IN EITHER TOKEN LOG REFUSES EVERY LOOKUP: each fault, signed by the root, makes both keys' lookups
/// refuse with the fault's own refusal, since a lookup reads both stores; nothing falls back. The control row, written
/// the same way without a fault, leaves both keys resolving.
#[test]
fn a_faulted_token_row_refuses_every_lookup_chirho() {
    let faults_chirho = [
        TokenFaultChirho {
            name_chirho: "control: a valid connection row",
            log_chirho: CONNECTION_TOKENS_CHIRHO,
            refusal_chirho: "",
            plant_chirho: |_world_chirho, _legacy_chirho, connection_chirho| {
                let mut row_chirho = connection_chirho.clone();
                row_chirho.seq_chirho = 1;
                row_chirho.token_hash_chirho = fresh_hash_chirho("control");
                row_chirho
            },
        },
        TokenFaultChirho {
            name_chirho: "a legacy-schema row in the connection log",
            log_chirho: CONNECTION_TOKENS_CHIRHO,
            refusal_chirho: "unsupported connection token record schema",
            plant_chirho: |_world_chirho, _legacy_chirho, connection_chirho| {
                let mut row_chirho = connection_chirho.clone();
                row_chirho.seq_chirho = 1;
                row_chirho.token_hash_chirho = fresh_hash_chirho("legacy-schema");
                row_chirho.schema_chirho = KeyStoreChirho::LegacyChirho
                    .token_schema_chirho()
                    .to_string();
                row_chirho
            },
        },
        TokenFaultChirho {
            name_chirho: "a key that is not limited, in the connection log",
            log_chirho: CONNECTION_TOKENS_CHIRHO,
            refusal_chirho: "is not a limited key",
            plant_chirho: |world_chirho, legacy_chirho, _connection_chirho| {
                let mut row_chirho = legacy_chirho.clone();
                row_chirho.seq_chirho = 1;
                row_chirho.token_hash_chirho = fresh_hash_chirho("not-limited");
                row_chirho.schema_chirho = CONNECTION_TOKEN_RECORD_SCHEMA_CHIRHO.to_string();
                row_chirho.client_id_chirho = world_chirho
                    .connection_client_chirho
                    .client_id_chirho
                    .clone();
                row_chirho.app_chirho = OPENED_APP_CHIRHO.to_string();
                row_chirho
            },
        },
        TokenFaultChirho {
            name_chirho: "a connection key naming a legacy client",
            log_chirho: CONNECTION_TOKENS_CHIRHO,
            refusal_chirho: "live in different stores",
            plant_chirho: |world_chirho, _legacy_chirho, connection_chirho| {
                let mut row_chirho = connection_chirho.clone();
                row_chirho.seq_chirho = 1;
                row_chirho.token_hash_chirho = fresh_hash_chirho("legacy-client");
                row_chirho.client_id_chirho =
                    world_chirho.legacy_client_chirho.client_id_chirho.clone();
                row_chirho.app_chirho = PLAIN_APP_CHIRHO.to_string();
                // Only the store match is violated: the grant set is made again for the legacy client's app and bound
                // into the signed scopes, so it still verifies.
                let mut grants_chirho = row_chirho.limited_grants_chirho.clone().unwrap();
                grants_chirho.app_chirho = PLAIN_APP_CHIRHO.to_string();
                row_chirho.scopes_chirho = limited_key_scopes_chirho(&grants_chirho).unwrap();
                row_chirho.limited_grants_chirho = Some(grants_chirho);
                row_chirho
            },
        },
        TokenFaultChirho {
            name_chirho: "a seq gap in the connection log",
            log_chirho: CONNECTION_TOKENS_CHIRHO,
            refusal_chirho: "seq gap",
            plant_chirho: |_world_chirho, _legacy_chirho, connection_chirho| {
                let mut row_chirho = connection_chirho.clone();
                row_chirho.seq_chirho = 2;
                row_chirho.token_hash_chirho = fresh_hash_chirho("gap");
                row_chirho
            },
        },
        TokenFaultChirho {
            name_chirho: "a legacy-log key naming the connection client",
            log_chirho: LEGACY_TOKENS_CHIRHO,
            refusal_chirho: "live in different stores",
            plant_chirho: |world_chirho, legacy_chirho, _connection_chirho| {
                let mut row_chirho = legacy_chirho.clone();
                row_chirho.seq_chirho = 1;
                row_chirho.token_hash_chirho = fresh_hash_chirho("connection-client");
                row_chirho.client_id_chirho = world_chirho
                    .connection_client_chirho
                    .client_id_chirho
                    .clone();
                row_chirho.app_chirho = OPENED_APP_CHIRHO.to_string();
                row_chirho
            },
        },
    ];
    let mut failures_chirho = Vec::new();
    for fault_chirho in &faults_chirho {
        let world_chirho = world_chirho("fault");
        let legacy_chirho = world_chirho.legacy_key_chirho().unwrap();
        let connection_chirho = world_chirho.connection_key_chirho().unwrap();
        let row_chirho = (fault_chirho.plant_chirho)(
            &world_chirho,
            &legacy_chirho.record_chirho,
            &connection_chirho.record_chirho,
        );
        append_signed_chirho(&world_chirho, fault_chirho.log_chirho, row_chirho);
        for (app_chirho, token_chirho) in [
            (OPENED_APP_CHIRHO, &connection_chirho.token_chirho),
            (PLAIN_APP_CHIRHO, &legacy_chirho.token_chirho),
        ] {
            let outcome_chirho =
                resolve_bearer_for_app_chirho(&world_chirho.root_chirho, app_chirho, token_chirho);
            let as_expected_chirho = match (&outcome_chirho, fault_chirho.refusal_chirho) {
                (Ok(Some(_)), "") => true,
                (Err(refusal_chirho), expected_chirho) if !expected_chirho.is_empty() => {
                    format!("{refusal_chirho:#}").contains(expected_chirho)
                }
                _ => false,
            };
            if !as_expected_chirho {
                failures_chirho.push(format!(
                    "{} ({app_chirho}): {outcome_chirho:?}",
                    fault_chirho.name_chirho
                ));
            }
        }
    }
    assert!(failures_chirho.is_empty(), "{failures_chirho:#?}");
}

/// A CONNECTION KEY'S RUN IS REFUSED BY THE LIMITED-KEY RESUME RULE, not as a key with no row: its row is in the
/// connection token log, which the resume's legacy lookup never reads.
#[test]
fn a_connection_keys_run_is_refused_by_the_limited_key_rule_chirho() {
    let world_chirho = world_chirho("resume");
    let key_chirho = world_chirho.connection_key_chirho().unwrap();
    assert!(connection_token_hash_recorded_chirho(
        &world_chirho.root_chirho,
        &key_chirho.record_chirho.token_hash_chirho
    )
    .unwrap());
    let scope_chirho = crate::effect_chirho::run_intent_chirho::RunIntentScopeChirho {
        kind_chirho: "app-run-chirho".to_string(),
        app_hash_chirho: None,
        user_principal_hash_chirho: None,
        owner_principal_hash_chirho: None,
        client_id_hash_chirho: None,
        token_hash_chirho: Some(key_chirho.record_chirho.token_hash_chirho.clone()),
        price_book_chirho: None,
        billing_policy_chirho: None,
    };
    let refusal_chirho = refusal_text_chirho(
        crate::effect_chirho::run_intent_chirho::resume_request_context_chirho(
            &world_chirho.root_chirho,
            &scope_chirho,
        ),
    );
    assert!(
        refusal_chirho.contains("limited key's run is not resumed"),
        "{refusal_chirho}"
    );
}
