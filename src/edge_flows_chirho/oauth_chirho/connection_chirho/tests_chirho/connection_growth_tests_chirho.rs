// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4's growth witness (PFE #26773): in a root holding both stores, a warm lookup and use of a connection key, and of a
//! legacy key beside it, do the same counted work whether the histories are small or large. Since Part 2 the histories
//! are of 30-day connection keys beside 24-hour legacy keys, and the arm says so. The large root adds
//! unrelated connection clients (other opened apps' clients, and more clients of the measured app), more users, and
//! keys and uses in both stores.
//!
//! - **The claim is warm work only.** Cold verification (the hourly pass, the verify commands) and retention are outside
//!   it; the arm uses a verify command only as the live control of one counter.
//! - **The counters are live.** Each root is copied to a fresh path, so the first lookup and use there load every view
//!   on this thread, which checks every key, folds every use and every connection client, and parses the session log.
//!   One key appended to the original root, warm from its build, is then folded exactly once.

use super::super::{
    issue_limited_key_chirho, issue_scoped_token_with_rate_limit_chirho,
    public_default_rate_limit_chirho, record_scoped_token_use_chirho,
    resolve_bearer_for_app_chirho, token_view_metrics_chirho, ScopedTokenIssueChirho,
};
use super::connection_fixture_chirho::*;
use super::*;
use identity_chirho::PrincipalKindChirho;

/// The counted work on this thread: session-log parses, key checks, use folds, client-log reads, connection-client
/// folds, and whole reads of the connection key or use log.
type WorkChirho = [u64; 6];

const SESSION_PARSES_CHIRHO: usize = 0;
const KEY_CHECKS_CHIRHO: usize = 1;
const USE_FOLDS_CHIRHO: usize = 2;
const CONNECTION_CLIENT_FOLDS_CHIRHO: usize = 4;
const CONNECTION_LOG_READS_CHIRHO: usize = 5;

fn work_chirho() -> WorkChirho {
    let (key_checks_chirho, use_folds_chirho) = token_view_metrics_chirho::counts_chirho();
    [
        identity_chirho::session_read_metrics_chirho::count_chirho(),
        key_checks_chirho,
        use_folds_chirho,
        token_view_metrics_chirho::client_reads_chirho(),
        token_view_metrics_chirho::connection_client_folds_chirho(),
        token_view_metrics_chirho::connection_log_reads_chirho(),
    ]
}

fn since_chirho(before_chirho: WorkChirho) -> WorkChirho {
    let now_chirho = work_chirho();
    std::array::from_fn(|index_chirho| now_chirho[index_chirho] - before_chirho[index_chirho])
}

/// One warm request: the key resolves for its app, and its use is recorded through the door.
fn round_chirho(root_chirho: &Path, app_chirho: &str, issue_chirho: &ScopedTokenIssueChirho) {
    let bearer_chirho =
        resolve_bearer_for_app_chirho(root_chirho, app_chirho, &issue_chirho.token_chirho)
            .unwrap()
            .expect("the key resolves");
    record_scoped_token_use_chirho(root_chirho, bearer_chirho.record_chirho())
        .unwrap()
        .expect("a rate-limited key records its use");
}

/// One history's size.
struct HistoryChirho {
    label_chirho: &'static str,
    unrelated_clients_chirho: usize,
    other_users_chirho: usize,
    keys_per_store_chirho: usize,
    uses_per_key_chirho: usize,
}

/// What a grown root holds, for the first-load control's floors.
struct GrownChirho {
    world_chirho: TokenWorldChirho,
    connection_chirho: ScopedTokenIssueChirho,
    legacy_chirho: ScopedTokenIssueChirho,
    keys_chirho: u64,
    uses_chirho: u64,
    connection_clients_chirho: u64,
}

fn grown_root_chirho(history_chirho: &HistoryChirho) -> GrownChirho {
    let world_chirho = world_chirho(history_chirho.label_chirho);
    let root_chirho = world_chirho.root_chirho.clone();
    let owner_chirho = world_chirho
        .connection_client_chirho
        .owner_principal_chirho
        .clone();
    // Unrelated connection clients: other apps opened to limited keys, each with its client, and more clients of the
    // measured app.
    for index_chirho in 0..history_chirho.unrelated_clients_chirho {
        let app_chirho = if index_chirho % 2 == 0 {
            let app_chirho = format!("otherapp{}", char::from(b'a' + index_chirho as u8));
            let view_chirho = deploy_app_chirho(&root_chirho, &app_chirho, &owner_chirho);
            crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
                &root_chirho,
                &app_chirho,
                &owner_chirho,
                view_opening_chirho(&view_chirho),
            )
            .unwrap();
            app_chirho
        } else {
            OPENED_APP_CHIRHO.to_string()
        };
        let (_client_chirho, store_chirho) =
            register_client_in_store_chirho(&root_chirho, &app_chirho, &owner_chirho).unwrap();
        assert_eq!(store_chirho, KeyStoreChirho::ConnectionChirho);
    }
    let use_chirho = |issue_chirho: &ScopedTokenIssueChirho| {
        for _ in 0..history_chirho.uses_per_key_chirho {
            record_scoped_token_use_chirho(&root_chirho, &issue_chirho.record_chirho)
                .unwrap()
                .unwrap();
        }
    };
    // Other users' keys and uses, in both stores.
    for _ in 0..history_chirho.other_users_chirho {
        let user_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            PrincipalKindChirho::UserChirho,
            SECRET_CHIRHO,
        )
        .unwrap()
        .principal_chirho;
        for _ in 0..history_chirho.keys_per_store_chirho {
            let connection_chirho = issue_limited_key_chirho(
                &root_chirho,
                &user_chirho,
                SECRET_CHIRHO,
                &world_chirho.connection_client_chirho.client_id_chirho,
                &page_read_chirho(),
                None,
            )
            .unwrap();
            let legacy_chirho = issue_scoped_token_with_rate_limit_chirho(
                &root_chirho,
                &user_chirho,
                SECRET_CHIRHO,
                &world_chirho.legacy_client_chirho.client_id_chirho,
                Vec::new(),
                Some(public_default_rate_limit_chirho()),
            )
            .unwrap();
            use_chirho(&connection_chirho);
            use_chirho(&legacy_chirho);
        }
    }
    // The measured user's two keys, one per store.
    let connection_chirho = world_chirho.connection_key_chirho().unwrap();
    let legacy_chirho = world_chirho.legacy_key_chirho().unwrap();
    use_chirho(&connection_chirho);
    use_chirho(&legacy_chirho);
    let keys_chirho =
        (2 + 2 * history_chirho.other_users_chirho * history_chirho.keys_per_store_chirho) as u64;
    GrownChirho {
        keys_chirho,
        uses_chirho: keys_chirho * history_chirho.uses_per_key_chirho as u64,
        connection_clients_chirho: 1 + history_chirho.unrelated_clients_chirho as u64,
        world_chirho,
        connection_chirho,
        legacy_chirho,
    }
}

/// THE GROWTH WITNESS. A warm round, a connection key's and a legacy key's, is [no session parse, no key check, one use
/// fold (the previous round's), no client read, no connection-client fold, no connection-log read] in the small root
/// and in the large one. The first load on a fresh path checks every key, folds every use and every connection client,
/// and parses the session log, so the counters are live; the large root's first load is larger, so the histories
/// differ. One appended key is folded exactly once, and a verify command reads the connection logs (the live control of
/// the read counter, outside the claim).
///
/// MIGRATION PATH: a warm round that checks keys, folds connection clients or reads a connection log is a whole-history
/// read or refold on the bearer road: the cost then grows with every connection, the thing this witness exists to stop.
#[test]
fn a_warm_lookup_and_use_is_flat_in_both_stores_histories_chirho() {
    let histories_chirho = [
        HistoryChirho {
            label_chirho: "growth-small",
            unrelated_clients_chirho: 0,
            other_users_chirho: 0,
            keys_per_store_chirho: 0,
            uses_per_key_chirho: 2,
        },
        HistoryChirho {
            label_chirho: "growth-large",
            unrelated_clients_chirho: 8,
            other_users_chirho: 5,
            keys_per_store_chirho: 2,
            uses_per_key_chirho: 6,
        },
    ];
    let mut first_key_checks_chirho = Vec::new();
    for history_chirho in &histories_chirho {
        let label_chirho = history_chirho.label_chirho;
        let grown_chirho = grown_root_chirho(history_chirho);
        let life_chirho = |key_chirho: &ScopedTokenIssueChirho| {
            key_chirho.record_chirho.expires_ms_chirho - key_chirho.record_chirho.issued_ms_chirho
        };
        assert_eq!(
            [
                life_chirho(&grown_chirho.connection_chirho),
                life_chirho(&grown_chirho.legacy_chirho)
            ],
            [
                identity_chirho::CONNECTION_SESSION_LIFETIME_MS_CHIRHO,
                identity_chirho::BROWSER_SESSION_LIFETIME_MS_CHIRHO
            ],
            "{label_chirho}: a 30-day connection key beside a 24-hour legacy key"
        );
        let root_chirho = fresh_copy_chirho(&grown_chirho.world_chirho.root_chirho);

        // The first load, on this thread: every view is built from the whole history.
        let before_chirho = work_chirho();
        round_chirho(
            &root_chirho,
            OPENED_APP_CHIRHO,
            &grown_chirho.connection_chirho,
        );
        let first_chirho = since_chirho(before_chirho);
        assert!(
            first_chirho[SESSION_PARSES_CHIRHO] >= 1,
            "{label_chirho}: the first load parses the session log: {first_chirho:?}"
        );
        assert!(
            first_chirho[KEY_CHECKS_CHIRHO] >= grown_chirho.keys_chirho,
            "{label_chirho}: the first load checks every key in both stores: {first_chirho:?}"
        );
        assert!(
            first_chirho[USE_FOLDS_CHIRHO] >= grown_chirho.uses_chirho,
            "{label_chirho}: the first load folds every use in both stores: {first_chirho:?}"
        );
        assert!(
            first_chirho[CONNECTION_CLIENT_FOLDS_CHIRHO] >= grown_chirho.connection_clients_chirho,
            "{label_chirho}: the first load folds every connection client: {first_chirho:?}"
        );
        eprintln!(
            "K4 GROWTH {label_chirho}: first load {first_chirho:?} over {} keys, {} uses, {} connection clients",
            grown_chirho.keys_chirho, grown_chirho.uses_chirho, grown_chirho.connection_clients_chirho
        );
        first_key_checks_chirho.push(first_chirho[KEY_CHECKS_CHIRHO]);

        // Warm rounds, one store's key after the other: a warm-up, then the measured round.
        for (store_chirho, app_chirho, issue_chirho) in [
            (
                "connection",
                OPENED_APP_CHIRHO,
                &grown_chirho.connection_chirho,
            ),
            ("legacy", PLAIN_APP_CHIRHO, &grown_chirho.legacy_chirho),
        ] {
            round_chirho(&root_chirho, app_chirho, issue_chirho);
            let before_chirho = work_chirho();
            round_chirho(&root_chirho, app_chirho, issue_chirho);
            assert_eq!(
                since_chirho(before_chirho),
                [0, 0, 1, 0, 0, 0],
                "{label_chirho}: a warm {store_chirho} round"
            );
        }

        // One appended key is folded exactly once, by the next round. This control runs on the ORIGINAL root, warm from
        // its build on this thread: an issuance on the copy fails its writer-head transition check (measured: "head
        // transition id does not match the canonical unsigned operation tuple"), so the copy takes only reads and use
        // appends.
        let original_chirho = &grown_chirho.world_chirho.root_chirho;
        issue_limited_key_chirho(
            original_chirho,
            &grown_chirho.world_chirho.user_chirho,
            SECRET_CHIRHO,
            &grown_chirho
                .world_chirho
                .connection_client_chirho
                .client_id_chirho,
            &page_read_chirho(),
            None,
        )
        .unwrap();
        let before_chirho = work_chirho();
        round_chirho(
            original_chirho,
            OPENED_APP_CHIRHO,
            &grown_chirho.connection_chirho,
        );
        let appended_chirho = since_chirho(before_chirho);
        assert_eq!(
            (
                appended_chirho[KEY_CHECKS_CHIRHO],
                appended_chirho[CONNECTION_LOG_READS_CHIRHO]
            ),
            (1, 0),
            "{label_chirho}: the appended key is folded once and no connection log is read: {appended_chirho:?}"
        );

        // The read counter's live control: a verify command reads the connection key log (cold, outside the claim).
        let before_chirho = work_chirho();
        verify_connection_tokens_chirho(&root_chirho).unwrap();
        assert!(
            since_chirho(before_chirho)[CONNECTION_LOG_READS_CHIRHO] >= 1,
            "{label_chirho}: a verify command reads the connection key log"
        );
        std::fs::remove_dir_all(&root_chirho).unwrap();
    }
    assert!(
        first_key_checks_chirho[1] > first_key_checks_chirho[0],
        "the large root's first load is larger: {first_key_checks_chirho:?}"
    );
}
