// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 2's lifetime arms (PFE #26787): a connection's fixed 30 days, against browser sessions' and legacy-store
//! keys' unchanged 24 hours.
//! - A connection key and its session share both instants, and the key resolves through the expiry instant, past a
//!   browser session's life, and refuses one millisecond later.
//! - A browser session ending leaves the connection live; Disconnect and a credential reset end it.
//! - An ended connection stays listed, not live and holding no slot, until its original expiry.
//! - The session's token never leaves the engine, and only the connection's own road writes the connection store.

use super::super::key_listing_chirho::{
    list_own_keys_at_chirho, live_rate_limited_keys_chirho, revoke_own_key_at_chirho,
};
use super::super::limited_key_chirho::resolve_bearer_for_app_at_chirho;
use super::super::{
    issue_limited_key_chirho, issue_scoped_token_after_login_at_chirho,
    limited_key_grants_now_chirho, public_default_rate_limit_chirho, scoped_key_id_chirho,
    IssuedKeyKindChirho, LegacyKeyForLimitedAppChirho, ScopedTokenIssueChirho,
};
use super::connection_fixture_chirho::*;
use super::*;
use identity_chirho::{
    PrincipalKindChirho, BROWSER_SESSION_LIFETIME_MS_CHIRHO, CONNECTION_SESSION_LIFETIME_MS_CHIRHO,
};

/// A credential the reset arm moves the user to: past the floor, unlike the fixture's.
const RESET_CREDENTIAL_CHIRHO: &str = "k4-reset-credential-chirho";

/// The verified session `key_chirho` was issued from.
fn session_of_chirho(
    world_chirho: &TokenWorldChirho,
    key_chirho: &ScopedTokenIssueChirho,
) -> identity_chirho::IdentitySessionChirho {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(&world_chirho.root_chirho).unwrap();
    identity_chirho::verified_session_for_token_chirho(
        &world_chirho.root_chirho,
        &pubkey_chirho,
        &key_chirho.record_chirho.principal_chirho,
        key_chirho.record_chirho.session_seq_chirho,
    )
    .unwrap()
    .expect("the key's session is in the verified index")
}

/// Whether the opened app's bearer road answers `key_chirho` at `at_chirho`.
fn answers_at_chirho(
    world_chirho: &TokenWorldChirho,
    key_chirho: &ScopedTokenIssueChirho,
    at_chirho: u64,
) -> bool {
    resolve_bearer_for_app_at_chirho(
        &world_chirho.root_chirho,
        OPENED_APP_CHIRHO,
        &key_chirho.token_chirho,
        at_chirho,
    )
    .unwrap()
    .is_some()
}

/// A CONNECTION LIVES 30 DAYS, NO MORE: its session is the connection's 30 days, the key carries the session's two
/// instants, and the key resolves past a browser session's life and at its expiry instant, then refuses one
/// millisecond later.
#[test]
fn a_connection_lives_thirty_days_and_refuses_after_chirho() {
    let world_chirho = world_chirho("thirty-days");
    let key_chirho = world_chirho.connection_key_chirho().unwrap();
    let session_chirho = session_of_chirho(&world_chirho, &key_chirho);
    assert_eq!(
        session_chirho.expires_ms_chirho - session_chirho.issued_ms_chirho,
        CONNECTION_SESSION_LIFETIME_MS_CHIRHO
    );
    assert_eq!(
        (
            key_chirho.record_chirho.issued_ms_chirho,
            key_chirho.record_chirho.expires_ms_chirho
        ),
        (
            session_chirho.issued_ms_chirho,
            session_chirho.expires_ms_chirho
        ),
        "the key carries its session's instants"
    );
    let issued_chirho = session_chirho.issued_ms_chirho;
    for (offset_chirho, answers_chirho) in [
        (BROWSER_SESSION_LIFETIME_MS_CHIRHO + 1, true),
        (CONNECTION_SESSION_LIFETIME_MS_CHIRHO, true),
        (CONNECTION_SESSION_LIFETIME_MS_CHIRHO + 1, false),
    ] {
        assert_eq!(
            answers_at_chirho(&world_chirho, &key_chirho, issued_chirho + offset_chirho),
            answers_chirho,
            "at issue + {offset_chirho} ms"
        );
    }
}

/// A BROWSER SESSION ENDING LEAVES THE CONNECTION LIVE: the owner signs in and out, and the connection, whose session is
/// its own, still answers, now and two days on.
#[test]
fn a_browser_session_ending_leaves_the_connection_live_chirho() {
    let world_chirho = world_chirho("browser-ends");
    let key_chirho = world_chirho.connection_key_chirho().unwrap();
    let browser_chirho = identity_chirho::login_identity_with_credential_chirho(
        &world_chirho.root_chirho,
        &world_chirho.user_chirho,
        SECRET_CHIRHO,
    )
    .unwrap();
    identity_chirho::revoke_session_token_chirho(
        &world_chirho.root_chirho,
        &world_chirho.user_chirho,
        &browser_chirho.token_chirho,
        "owner-chirho",
        "sign-out-chirho",
    )
    .unwrap();
    assert_eq!(
        identity_chirho::validate_session_token_chirho(
            &world_chirho.root_chirho,
            &world_chirho.user_chirho,
            &browser_chirho.token_chirho,
        )
        .unwrap(),
        None,
        "the browser session ended"
    );
    let now_chirho = now_ms_chirho();
    assert!(answers_at_chirho(&world_chirho, &key_chirho, now_chirho));
    assert!(answers_at_chirho(
        &world_chirho,
        &key_chirho,
        now_chirho + 2 * BROWSER_SESSION_LIFETIME_MS_CHIRHO
    ));
}

/// BROWSERS AND THE LEGACY STORE KEEP 24 HOURS: a login, a legacy key, and a limited key still in the legacy store (an
/// app opened under K1 keeps its legacy client) all get a browser session's life.
#[test]
fn browser_sessions_and_legacy_store_keys_keep_twenty_four_hours_chirho() {
    let world_chirho = world_chirho("still-a-day");
    let root_chirho = &world_chirho.root_chirho;
    let browser_chirho = identity_chirho::login_identity_with_credential_chirho(
        root_chirho,
        &world_chirho.user_chirho,
        SECRET_CHIRHO,
    )
    .unwrap();
    let legacy_chirho = world_chirho.legacy_key_chirho().unwrap();

    let owner_chirho =
        identity_chirho::register_identity_chirho(root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap()
            .principal_chirho;
    let view_chirho = deploy_app_chirho(root_chirho, "keptlegacy", &owner_chirho);
    let (kept_client_chirho, kept_store_chirho) =
        register_client_in_store_chirho(root_chirho, "keptlegacy", &owner_chirho).unwrap();
    assert_eq!(kept_store_chirho, KeyStoreChirho::LegacyChirho);
    with_k1_era_opening_chirho(|| {
        crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
            root_chirho,
            "keptlegacy",
            &owner_chirho,
            view_opening_chirho(&view_chirho),
        )
        .unwrap();
    });
    let limited_legacy_chirho = issue_limited_key_chirho(
        root_chirho,
        &world_chirho.user_chirho,
        SECRET_CHIRHO,
        &kept_client_chirho.client_id_chirho,
        &page_read_chirho(),
        None,
    )
    .unwrap();
    assert!(limited_legacy_chirho
        .record_chirho
        .limited_grants_chirho
        .is_some());
    assert_eq!(
        KeyStoreChirho::of_token_chirho(&limited_legacy_chirho.record_chirho),
        KeyStoreChirho::LegacyChirho
    );
    let lives_chirho = [
        browser_chirho.session_chirho.expires_ms_chirho
            - browser_chirho.session_chirho.issued_ms_chirho,
        legacy_chirho.record_chirho.expires_ms_chirho
            - legacy_chirho.record_chirho.issued_ms_chirho,
        limited_legacy_chirho.record_chirho.expires_ms_chirho
            - limited_legacy_chirho.record_chirho.issued_ms_chirho,
    ];
    assert_eq!(lives_chirho, [BROWSER_SESSION_LIFETIME_MS_CHIRHO; 3]);
}

/// DISCONNECT AND RESET END A 30-DAY CONNECTION: Disconnected two days on, it refuses at once, stays listed as ended
/// and holds no slot until its original expiry, then leaves the list. A credential reset ends another.
#[test]
fn disconnect_and_reset_end_a_thirty_day_connection_chirho() {
    let world_chirho = world_chirho("thirty-day-end");
    let root_chirho = &world_chirho.root_chirho;
    let user_chirho = &world_chirho.user_chirho;
    let ended_chirho = world_chirho.connection_key_chirho().unwrap();
    let key_id_chirho = scoped_key_id_chirho(&ended_chirho.record_chirho.token_hash_chirho);
    let two_days_chirho =
        ended_chirho.record_chirho.issued_ms_chirho + 2 * BROWSER_SESSION_LIFETIME_MS_CHIRHO;
    assert!(answers_at_chirho(
        &world_chirho,
        &ended_chirho,
        two_days_chirho
    ));
    revoke_own_key_at_chirho(root_chirho, user_chirho, &key_id_chirho, two_days_chirho).unwrap();
    assert!(!answers_at_chirho(
        &world_chirho,
        &ended_chirho,
        two_days_chirho + 1
    ));
    let row_chirho = |at_chirho: u64| {
        list_own_keys_at_chirho(root_chirho, user_chirho, at_chirho)
            .unwrap()
            .into_iter()
            .find(|row_chirho| row_chirho.key_id_chirho == key_id_chirho)
    };
    let listed_chirho = row_chirho(two_days_chirho + 1).expect("an ended connection stays listed");
    assert!(!listed_chirho.live_chirho);
    assert_eq!(
        listed_chirho.expires_ms_chirho,
        ended_chirho.record_chirho.expires_ms_chirho
    );
    assert_eq!(
        live_rate_limited_keys_chirho(root_chirho, user_chirho, two_days_chirho + 1).unwrap(),
        0,
        "an ended connection holds no slot"
    );
    assert!(row_chirho(ended_chirho.record_chirho.expires_ms_chirho).is_some());
    assert!(row_chirho(ended_chirho.record_chirho.expires_ms_chirho + 1).is_none());

    let reset_chirho = world_chirho.connection_key_chirho().unwrap();
    assert!(answers_at_chirho(
        &world_chirho,
        &reset_chirho,
        now_ms_chirho()
    ));
    identity_chirho::reset_identity_credential_chirho(
        root_chirho,
        user_chirho,
        RESET_CREDENTIAL_CHIRHO,
        "operator-chirho",
        "k4-part2-reset-chirho",
    )
    .unwrap();
    assert!(!answers_at_chirho(
        &world_chirho,
        &reset_chirho,
        now_ms_chirho()
    ));
}

/// THE SESSION'S TOKEN NEVER LEAVES THE ENGINE: the issuance returns the connection's bearer and its record, nothing
/// in either hashes to the session's token, and the bearer is no session. The cookie road finds a session only by its
/// token's hash, so it refuses the bearer.
#[test]
fn a_connections_session_token_never_leaves_the_engine_chirho() {
    let world_chirho = world_chirho("no-egress");
    let key_chirho = world_chirho.connection_key_chirho().unwrap();
    let session_chirho = session_of_chirho(&world_chirho, &key_chirho);
    assert_eq!(
        identity_chirho::validate_session_token_chirho(
            &world_chirho.root_chirho,
            &world_chirho.user_chirho,
            &key_chirho.token_chirho,
        )
        .unwrap(),
        None
    );
    let returned_chirho = format!("{key_chirho:?}");
    let hex_runs_chirho: Vec<&str> = returned_chirho
        .split(|character_chirho: char| !character_chirho.is_ascii_hexdigit())
        .filter(|run_chirho| run_chirho.len() == 64)
        .collect();
    assert!(
        hex_runs_chirho.contains(&key_chirho.token_chirho.as_str()),
        "the scan sees the bearer, so it sees 64-hex values"
    );
    for run_chirho in hex_runs_chirho {
        assert_ne!(
            crate::cas_chirho::hash_chirho(run_chirho.as_bytes()).0,
            session_chirho.token_hash_chirho,
            "a returned value is the session's token"
        );
    }
}

/// ONLY THE CONNECTION'S OWN ROAD WRITES THE CONNECTION STORE: the sign-in-first road refuses a limited key for a
/// connection client by name, and a legacy key for it as before, writing no key.
#[test]
fn the_sign_in_first_road_refuses_a_connection_key_chirho() {
    let world_chirho = world_chirho("one-road");
    let root_chirho = &world_chirho.root_chirho;
    let issue_chirho = |kind_chirho: IssuedKeyKindChirho| {
        issue_scoped_token_after_login_at_chirho(
            root_chirho,
            world_chirho.connection_client_chirho.clone(),
            identity_chirho::login_identity_with_credential_chirho(
                root_chirho,
                &world_chirho.user_chirho,
                SECRET_CHIRHO,
            )
            .unwrap(),
            kind_chirho,
            Some(public_default_rate_limit_chirho()),
            now_ms_chirho,
        )
    };
    let limited_chirho = issue_chirho(IssuedKeyKindChirho::LimitedChirho(
        limited_key_grants_now_chirho(root_chirho, OPENED_APP_CHIRHO, &page_read_chirho()).unwrap(),
    ));
    assert!(
        refusal_text_chirho(limited_chirho).contains("ConnectionKeyRoadChirho"),
        "a limited key for a connection client refuses by name on the sign-in-first road"
    );
    assert!(issue_chirho(IssuedKeyKindChirho::LegacyChirho(Vec::new()))
        .unwrap_err()
        .downcast_ref::<LegacyKeyForLimitedAppChirho>()
        .is_some());
    assert_eq!(world_chirho.token_lines_chirho(), (0, 0));
}
