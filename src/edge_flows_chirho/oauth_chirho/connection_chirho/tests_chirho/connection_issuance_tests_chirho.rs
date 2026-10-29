// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 2's issuance arms (PFE #26787): a connection decides before it creates.
//! - A credential reset racing an issuance either refuses its old proof or ends what it issued, never between: at each
//!   hold, a non-blocking probe shows which locks the issuance holds, so no claim rests on timing.
//! - A cap refusal writes neither a session nor a key.
//! - Repeated creation and ending leaves one session per connection, and a cap decision reads the principal's
//!   unexpired rows (the population this counts), not its live ones, until they expire.
//! - A write failure after the first write names what is on disk and what is uncertain; restoring the log restores
//!   issuance, and the unused session holds no slot.

use super::super::key_listing_chirho::{
    list_own_keys_at_chirho, live_rate_limited_keys_chirho, revoke_own_key_at_chirho,
};
use super::super::{
    issue_limited_key_chirho, limited_key_grants_now_chirho, public_default_rate_limit_chirho,
    resolve_bearer_for_app_chirho, scoped_key_id_chirho, ScopedTokenCapReachedChirho,
    LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO,
};
use super::connection_fixture_chirho::*;
use super::*;
use identity_chirho::session_read_metrics_chirho::key_record_reads_chirho;
use identity_chirho::CONNECTION_SESSION_LIFETIME_MS_CHIRHO;
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::time::Duration;

/// The session log, as the identity module names it.
const SESSIONS_CHIRHO: &str = "identity-sessions-chirho.jsonl";
/// A credential the reset moves the user to: past the floor, unlike the fixture's.
const RESET_CREDENTIAL_CHIRHO: &str = "k4-reset-credential-chirho";
/// How many connections the churn arm creates and ends.
const CHURN_CHIRHO: usize = 12;

fn reset_chirho(world_chirho: &TokenWorldChirho) -> Result<()> {
    identity_chirho::reset_identity_credential_chirho(
        &world_chirho.root_chirho,
        &world_chirho.user_chirho,
        RESET_CREDENTIAL_CHIRHO,
        "operator-chirho",
        "k4-part2-race-chirho",
    )
    .map(|_report_chirho| ())
}

/// Hold one connection issuance where `set_hold_chirho` puts its hold, and there probe, on the issuance's own thread,
/// which locks it holds: (the principal's credential lock, the root append lock). The probe is a non-blocking try on
/// each lock's file, so the answer needs no timing. Then race a credential reset against it, release it, and require
/// that the reset, which can only land after the writes, ended the connection. Returns the probe.
fn locks_held_at_hold_chirho(
    label_chirho: &str,
    set_hold_chirho: impl FnOnce(Box<dyn FnOnce() -> Result<()>>) + Send,
) -> (bool, bool) {
    let world_chirho = world_chirho(label_chirho);
    let (held_chirho, held_rx_chirho) = mpsc::channel::<(bool, bool)>();
    let (release_chirho, release_rx_chirho) = mpsc::channel::<()>();
    let root_chirho = world_chirho.root_chirho.clone();
    let user_chirho = world_chirho.user_chirho.clone();
    let world_ref_chirho = &world_chirho;
    std::thread::scope(|scope_chirho| {
        let holder_chirho = scope_chirho.spawn(move || {
            set_hold_chirho(Box::new(move || {
                held_chirho
                    .send(identity_chirho::connection_issue_locks_held_chirho(
                        &root_chirho,
                        &user_chirho,
                    )?)
                    .unwrap();
                release_rx_chirho.recv().unwrap();
                Ok(())
            }));
            world_ref_chirho.connection_key_chirho()
        });
        let locks_chirho = held_rx_chirho
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        let resetter_chirho = scope_chirho.spawn(move || reset_chirho(world_ref_chirho));
        release_chirho.send(()).unwrap();
        let key_chirho = holder_chirho.join().unwrap().unwrap();
        resetter_chirho.join().unwrap().unwrap();
        assert_eq!(world_chirho.token_lines_chirho(), (0, 1));
        assert!(
            resolve_bearer_for_app_chirho(
                &world_chirho.root_chirho,
                OPENED_APP_CHIRHO,
                &key_chirho.token_chirho
            )
            .unwrap()
            .is_none(),
            "a reset that landed after the writes must end the connection"
        );
        locks_chirho
    })
}

/// A RESET CANNOT LAND BETWEEN A CONNECTION'S PROOF AND ITS WRITES, AND THE PROOF IS OUTSIDE THE APPEND LOCK: just after
/// its proof, the issuance holds the principal's credential lock, which a reset needs, and not yet the root append lock,
/// so the argon2 work never ran under it. The reset raced against it lands after the writes and ends the connection.
#[test]
fn a_reset_cannot_land_between_a_connections_proof_and_its_writes_chirho() {
    assert_eq!(
        locks_held_at_hold_chirho("reset-at-proof", |hold_chirho| {
            identity_chirho::set_connection_proved_hold_chirho(hold_chirho)
        }),
        (true, false),
        "(credential lock, append lock) held just after the proof"
    );
}

/// THE CAP IS DECIDED UNDER BOTH LOCKS: at its cap decision, before its writes, the issuance holds the principal's
/// credential lock and the root append lock. The reset raced against it lands after the writes and ends the connection.
#[test]
fn a_reset_racing_an_issuance_waits_then_ends_it_chirho() {
    assert_eq!(
        locks_held_at_hold_chirho("reset-at-cap", |hold_chirho| {
            set_issuance_hold_chirho(hold_chirho)
        }),
        (true, true),
        "(credential lock, append lock) held at the cap decision"
    );
}

/// A RESET BEFORE AN ISSUANCE REFUSES ITS OLD CREDENTIAL: neither a session nor a key is written, and the new
/// credential issues.
#[test]
fn a_reset_before_an_issuance_refuses_its_old_credential_chirho() {
    let world_chirho = world_chirho("reset-before");
    reset_chirho(&world_chirho).unwrap();
    let sessions_before_chirho = world_chirho.lines_chirho(SESSIONS_CHIRHO);
    let refusal_chirho = refusal_text_chirho(world_chirho.connection_key_chirho());
    assert!(
        refusal_chirho.contains("invalid credential_chirho"),
        "{refusal_chirho}"
    );
    assert_eq!(
        world_chirho.lines_chirho(SESSIONS_CHIRHO),
        sessions_before_chirho
    );
    assert_eq!(world_chirho.token_lines_chirho(), (0, 0));
    issue_limited_key_chirho(
        &world_chirho.root_chirho,
        &world_chirho.user_chirho,
        RESET_CREDENTIAL_CHIRHO,
        &world_chirho.connection_client_chirho.client_id_chirho,
        &page_read_chirho(),
        None,
    )
    .unwrap();
    assert_eq!(world_chirho.token_lines_chirho(), (0, 1));
}

/// A CAP REFUSAL APPENDS NO SESSION AND NO KEY: with the five slots full, a sixth connection refuses at its cap, after its proof, and
/// the session and key logs are unchanged.
#[test]
fn a_cap_refusal_writes_neither_session_nor_key_chirho() {
    let world_chirho = world_chirho("cap-writes-nothing");
    for _ in 0..LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO {
        world_chirho.connection_key_chirho().unwrap();
    }
    let sessions_before_chirho = world_chirho.lines_chirho(SESSIONS_CHIRHO);
    assert_eq!(
        sessions_before_chirho,
        LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO
    );
    assert!(world_chirho
        .connection_key_chirho()
        .unwrap_err()
        .downcast_ref::<ScopedTokenCapReachedChirho>()
        .is_some());
    assert_eq!(
        world_chirho.lines_chirho(SESSIONS_CHIRHO),
        sessions_before_chirho
    );
    assert_eq!(
        world_chirho.token_lines_chirho(),
        (0, LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO)
    );
}

/// CHURN, COUNTED: twelve connections created and ended leave twelve sessions and twelve keys, one each. Since K4
/// Part 3 the day admits ten connections, so ten are created a day ago and two now (the premise is unchanged: twelve,
/// all ended). Every ended row stays listed until its original expiry, so the population a cap decision reads
/// is the principal's twelve UNEXPIRED rows: one key-record read each, while none is live. Past their 30 days that
/// population is empty, and five new connections fit.
#[test]
fn churn_leaves_one_session_per_connection_and_counts_unexpired_rows_chirho() {
    let world_chirho = world_chirho("churn");
    let root_chirho = &world_chirho.root_chirho;
    let user_chirho = &world_chirho.user_chirho;
    let issue_at_chirho = |at_chirho: u64| {
        issue_connection_key_at_chirho(
            root_chirho,
            &world_chirho.connection_client_chirho,
            user_chirho,
            SECRET_CHIRHO,
            limited_key_grants_now_chirho(root_chirho, OPENED_APP_CHIRHO, &page_read_chirho())
                .unwrap(),
            public_default_rate_limit_chirho(),
            move || at_chirho,
        )
        .unwrap()
    };
    // The first day is a day and a millisecond ago, so every key's session is ended after its issue instant, as a
    // revocation stamped by the real clock must be.
    let second_day_chirho = now_ms_chirho();
    let first_day_chirho = second_day_chirho - CONNECTION_ISSUANCE_WINDOW_MS_CHIRHO - 1;
    let mut last_expiry_chirho = 0;
    for index_chirho in 0..CHURN_CHIRHO {
        let at_chirho = if index_chirho < CONNECTION_ISSUANCES_PER_DAY_CHIRHO {
            first_day_chirho
        } else {
            second_day_chirho
        };
        let key_chirho = issue_at_chirho(at_chirho);
        last_expiry_chirho = key_chirho.record_chirho.expires_ms_chirho;
        revoke_own_key_at_chirho(
            root_chirho,
            user_chirho,
            &scoped_key_id_chirho(&key_chirho.record_chirho.token_hash_chirho),
            at_chirho,
        )
        .unwrap();
    }
    assert_eq!(world_chirho.lines_chirho(SESSIONS_CHIRHO), CHURN_CHIRHO);
    assert_eq!(world_chirho.token_lines_chirho(), (0, CHURN_CHIRHO));

    let now_chirho = second_day_chirho;
    let rows_chirho = list_own_keys_at_chirho(root_chirho, user_chirho, now_chirho).unwrap();
    assert_eq!(rows_chirho.len(), CHURN_CHIRHO);
    assert!(rows_chirho.iter().all(|row_chirho| !row_chirho.live_chirho));
    let reads_before_chirho = key_record_reads_chirho();
    assert_eq!(
        live_rate_limited_keys_chirho(root_chirho, user_chirho, now_chirho).unwrap(),
        0
    );
    assert_eq!(
        key_record_reads_chirho() - reads_before_chirho,
        CHURN_CHIRHO as u64,
        "a cap decision reads one key record per unexpired row"
    );

    let past_chirho = last_expiry_chirho + 1;
    assert!(
        list_own_keys_at_chirho(root_chirho, user_chirho, past_chirho)
            .unwrap()
            .is_empty()
    );
    let reads_before_chirho = key_record_reads_chirho();
    assert_eq!(
        live_rate_limited_keys_chirho(root_chirho, user_chirho, past_chirho).unwrap(),
        0
    );
    assert_eq!(key_record_reads_chirho() - reads_before_chirho, 0);
    assert!(last_expiry_chirho <= now_chirho + CONNECTION_SESSION_LIFETIME_MS_CHIRHO);

    for _ in 0..LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO {
        issue_at_chirho(past_chirho);
    }
}

fn set_mode_chirho(path_chirho: &Path, mode_chirho: u32) {
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(mode_chirho)).unwrap();
}

/// The fault these arms inject is a log that refuses an append; a user that a read-only file does not stop (root)
/// cannot inject it, so the arm says so rather than passing.
fn assert_append_refused_chirho(path_chirho: &Path) {
    assert!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(path_chirho)
            .is_err(),
        "this arm needs a user a read-only file refuses: {}",
        path_chirho.display()
    );
}

/// A FAILURE AFTER THE SESSION NAMES THE SESSION AND THE UNCERTAIN KEY: with the key log read-only, the session is
/// written and the key's append fails. The fault names the session's seq and says the key is uncertain and how to
/// proceed, never "nothing was created". Restored, issuance works, the unused session holds no slot, and every log
/// verifies.
#[test]
fn a_key_write_failure_names_the_committed_session_chirho() {
    let world_chirho = world_chirho("fault-key");
    let root_chirho = &world_chirho.root_chirho;
    world_chirho.connection_key_chirho().unwrap();
    let tokens_path_chirho = root_chirho.join(CONNECTION_TOKENS_CHIRHO);
    set_mode_chirho(&tokens_path_chirho, 0o444);
    assert_append_refused_chirho(&tokens_path_chirho);
    let sessions_before_chirho = world_chirho.lines_chirho(SESSIONS_CHIRHO);
    let refusal_chirho = world_chirho.connection_key_chirho().unwrap_err();
    set_mode_chirho(&tokens_path_chirho, 0o644);
    let fault_chirho = refusal_chirho
        .downcast_ref::<ConnectionIssueFaultChirho>()
        .unwrap_or_else(|| panic!("not a named fault: {refusal_chirho:#}"))
        .clone();
    let ConnectionIssueFaultChirho::KeyUncertainChirho {
        session_seq_chirho, ..
    } = fault_chirho
    else {
        panic!("the session was written, so the fault is the key's: {fault_chirho:?}");
    };
    let text_chirho = format!("{refusal_chirho:#}");
    assert!(
        text_chirho.contains(&format!("session {session_seq_chirho} is on disk"))
            && text_chirho.contains("Do not issue again blindly"),
        "{text_chirho}"
    );
    assert_eq!(
        world_chirho.lines_chirho(SESSIONS_CHIRHO),
        sessions_before_chirho + 1
    );
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho).unwrap();
    let session_chirho = identity_chirho::verified_session_for_token_chirho(
        root_chirho,
        &pubkey_chirho,
        &world_chirho.user_chirho,
        session_seq_chirho,
    )
    .unwrap()
    .expect("the named session is on disk");
    assert_eq!(
        session_chirho.expires_ms_chirho - session_chirho.issued_ms_chirho,
        CONNECTION_SESSION_LIFETIME_MS_CHIRHO
    );
    assert_eq!(world_chirho.token_lines_chirho(), (0, 1));

    let next_chirho = world_chirho.connection_key_chirho().unwrap();
    assert_ne!(
        next_chirho.record_chirho.session_seq_chirho,
        session_seq_chirho
    );
    assert_eq!(world_chirho.token_lines_chirho(), (0, 2));
    assert_eq!(
        live_rate_limited_keys_chirho(root_chirho, &world_chirho.user_chirho, now_ms_chirho())
            .unwrap(),
        2,
        "the unused session holds no slot"
    );
    verify_connection_tokens_chirho(root_chirho).unwrap();
    identity_chirho::verify_sessions_chirho(root_chirho).unwrap();
}

/// A FAILURE AT THE SESSION WRITES NO KEY: with the session log read-only, the session's append fails, the fault says
/// the session is uncertain and no key was written, and no key is. Restored, issuance works.
#[test]
fn a_session_write_failure_writes_no_key_chirho() {
    let world_chirho = world_chirho("fault-session");
    world_chirho.connection_key_chirho().unwrap();
    let sessions_path_chirho = world_chirho.root_chirho.join(SESSIONS_CHIRHO);
    set_mode_chirho(&sessions_path_chirho, 0o444);
    assert_append_refused_chirho(&sessions_path_chirho);
    let refusal_chirho = world_chirho.connection_key_chirho().unwrap_err();
    set_mode_chirho(&sessions_path_chirho, 0o644);
    assert!(
        matches!(
            refusal_chirho.downcast_ref::<ConnectionIssueFaultChirho>(),
            Some(ConnectionIssueFaultChirho::SessionUncertainChirho { .. })
        ),
        "{refusal_chirho:#}"
    );
    assert!(format!("{refusal_chirho:#}").contains("no key was written"));
    assert_eq!(world_chirho.lines_chirho(SESSIONS_CHIRHO), 1);
    assert_eq!(world_chirho.token_lines_chirho(), (0, 1));
    world_chirho.connection_key_chirho().unwrap();
    assert_eq!(world_chirho.token_lines_chirho(), (0, 2));
}
