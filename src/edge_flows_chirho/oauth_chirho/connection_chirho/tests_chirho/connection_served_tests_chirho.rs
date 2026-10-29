// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3's served issuance, the engine half (PFE #26801, #26804): the attempt law and the outcomes, each against the
//! rows actually appended.
//! - A creation appends its session, its key and one success row as `token-chirho`; a wrong password one failure row
//!   and nothing else.
//! - Every other refusal appends no attempt row: the request's checks, the pre-check, the cap and the day. The legacy
//!   token road's cap refusal keeps its success row, so the two laws stay told apart.
//! - A session fault is not-created; a key fault, and a success row that cannot be appended, are uncertain, and the
//!   outcome never prints the bearer.
//! - The form offers a connection client's opened actions, and nothing for any other client.

use super::super::{
    issue_scoped_token_with_public_auth_limit_outcome_chirho, list_own_keys_chirho,
    revoke_own_key_chirho, scoped_key_id_chirho, ScopedTokenCapReachedChirho,
    ScopedTokenIssueChirho, LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO,
};
use super::connection_fixture_chirho::*;
use super::*;
use identity_chirho::{
    IdentityAuthAttemptOutcomeChirho, PublicAuthRefusalChirho, SignInVelocityChirho,
    AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
};
use std::os::unix::fs::PermissionsExt;

/// The session and attempt logs, as the identity module names them.
const SESSIONS_CHIRHO: &str = "identity-sessions-chirho.jsonl";
const ATTEMPTS_CHIRHO: &str = "identity-auth-attempts-chirho.jsonl";
/// A sign-in velocity these arms do not measure: high enough that only the limit under test refuses.
const VELOCITY_CHIRHO: SignInVelocityChirho = SignInVelocityChirho {
    principal_successes_per_hour_chirho: 100,
};

type ServedChirho = std::result::Result<ConnectionServedOutcomeChirho, PublicAuthRefusalChirho>;

fn served_chirho(
    world_chirho: &TokenWorldChirho,
    credential_chirho: &str,
    client_id_chirho: &str,
    actions_chirho: &[String],
) -> ServedChirho {
    issue_connection_key_served_chirho(
        &world_chirho.root_chirho,
        &ConnectionServedRequestChirho {
            principal_chirho: &world_chirho.user_chirho,
            credential_chirho,
            client_id_chirho,
            actions_chirho,
            return_chirho: None,
        },
        &VELOCITY_CHIRHO,
    )
}

fn create_chirho(world_chirho: &TokenWorldChirho) -> ServedChirho {
    served_chirho(
        world_chirho,
        SECRET_CHIRHO,
        &world_chirho.connection_client_chirho.client_id_chirho,
        &page_read_chirho(),
    )
}

/// The attempt rows on disk, as (endpoint, outcome).
fn attempt_rows_chirho(
    world_chirho: &TokenWorldChirho,
) -> Vec<(String, IdentityAuthAttemptOutcomeChirho)> {
    identity_chirho::load_auth_attempts_chirho(&world_chirho.root_chirho)
        .unwrap()
        .into_iter()
        .map(|record_chirho| (record_chirho.endpoint_chirho, record_chirho.outcome_chirho))
        .collect()
}

/// What the arms compare before and after: the session, legacy key, connection key and attempt lines.
fn written_chirho(world_chirho: &TokenWorldChirho) -> (usize, (usize, usize), usize) {
    (
        world_chirho.lines_chirho(SESSIONS_CHIRHO),
        world_chirho.token_lines_chirho(),
        world_chirho.lines_chirho(ATTEMPTS_CHIRHO),
    )
}

fn refusal_kind_chirho(outcome_chirho: ServedChirho) -> (ConnectionServedRefusalChirho, bool) {
    let refusal_chirho = outcome_chirho.unwrap_err();
    (
        ConnectionServedRefusalChirho::of_chirho(&refusal_chirho),
        refusal_chirho.failure_recorded_chirho,
    )
}

fn set_mode_chirho(path_chirho: &Path, mode_chirho: u32) {
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(mode_chirho)).unwrap();
}

/// The fault is a log that refuses an append; a user a read-only file does not stop (root) cannot inject it.
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

/// A CREATION APPENDS ITS SESSION, ITS KEY AND ONE SUCCESS ROW: the outcome carries the bearer for the one-time page,
/// and the one new attempt row is a success under `token-chirho`. Its Debug never prints the bearer.
#[test]
fn a_served_creation_appends_its_session_key_and_one_success_row_chirho() {
    let world_chirho = world_chirho("served-created");
    let before_chirho = written_chirho(&world_chirho);
    let outcome_chirho = create_chirho(&world_chirho).unwrap();
    let ConnectionServedOutcomeChirho::CreatedChirho(issue_chirho) = &outcome_chirho else {
        panic!("not created: {outcome_chirho:?}");
    };
    assert!(!format!("{outcome_chirho:?}").contains(&issue_chirho.token_chirho));
    assert!(format!("{outcome_chirho:?}").contains("never printed"));
    assert_eq!(
        written_chirho(&world_chirho),
        (before_chirho.0 + 1, (0, 1), before_chirho.2 + 1)
    );
    assert_eq!(
        attempt_rows_chirho(&world_chirho),
        vec![(
            AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO.to_string(),
            IdentityAuthAttemptOutcomeChirho::SuccessChirho
        )]
    );
}

/// A WRONG PASSWORD APPENDS ONE FAILURE ROW AND NOTHING ELSE: the refusal is a recorded credential mismatch, the one
/// new row a failure under `token-chirho`, and no session or key is appended.
#[test]
fn a_wrong_password_appends_one_failure_row_and_nothing_else_chirho() {
    let world_chirho = world_chirho("served-mismatch");
    let before_chirho = written_chirho(&world_chirho);
    let client_id_chirho = world_chirho
        .connection_client_chirho
        .client_id_chirho
        .clone();
    assert_eq!(
        refusal_kind_chirho(served_chirho(
            &world_chirho,
            "not-the-secret-chirho",
            &client_id_chirho,
            &page_read_chirho()
        )),
        (
            ConnectionServedRefusalChirho::CredentialMismatchChirho,
            true
        )
    );
    assert_eq!(
        written_chirho(&world_chirho),
        (before_chirho.0, before_chirho.1, before_chirho.2 + 1)
    );
    assert_eq!(
        attempt_rows_chirho(&world_chirho),
        vec![(
            AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO.to_string(),
            IdentityAuthAttemptOutcomeChirho::FailureChirho
        )]
    );
}

/// THE REQUEST'S CHECKS REFUSE BEFORE THE SIGN-IN, WITH NO ATTEMPT ROW: an unknown client, a legacy client, an action
/// the app does not open, no action, and a repeated action each refuse as an invalid request, and nothing is written.
#[test]
fn the_requests_checks_refuse_with_no_attempt_row_chirho() {
    let world_chirho = world_chirho("served-request");
    let connection_id_chirho = world_chirho
        .connection_client_chirho
        .client_id_chirho
        .clone();
    let legacy_id_chirho = world_chirho.legacy_client_chirho.client_id_chirho.clone();
    let before_chirho = written_chirho(&world_chirho);
    let read_chirho = page_read_chirho();
    let repeated_chirho = vec![read_chirho[0].clone(), read_chirho[0].clone()];
    for (client_id_chirho, actions_chirho) in [
        ("client/0000000000000000", read_chirho.clone()),
        (legacy_id_chirho.as_str(), read_chirho.clone()),
        (
            connection_id_chirho.as_str(),
            vec!["page-save-chirho".to_string()],
        ),
        (connection_id_chirho.as_str(), Vec::new()),
        (connection_id_chirho.as_str(), repeated_chirho),
    ] {
        assert_eq!(
            refusal_kind_chirho(served_chirho(
                &world_chirho,
                SECRET_CHIRHO,
                client_id_chirho,
                &actions_chirho
            )),
            (ConnectionServedRefusalChirho::RequestInvalidChirho, false),
            "{client_id_chirho} {actions_chirho:?}"
        );
    }
    assert_eq!(written_chirho(&world_chirho), before_chirho);
}

/// THE PRE-CHECK REFUSES BEFORE THE DOOR, WITH NO ATTEMPT ROW: with a velocity of one success an hour, the first
/// creation appends its success row and the second refuses as a rate limit, appending nothing.
#[test]
fn the_pre_check_refuses_with_no_attempt_row_chirho() {
    let world_chirho = world_chirho("served-velocity");
    let client_id_chirho = world_chirho
        .connection_client_chirho
        .client_id_chirho
        .clone();
    let once_chirho = SignInVelocityChirho {
        principal_successes_per_hour_chirho: 1,
    };
    let serve_chirho = || {
        issue_connection_key_served_chirho(
            &world_chirho.root_chirho,
            &ConnectionServedRequestChirho {
                principal_chirho: &world_chirho.user_chirho,
                credential_chirho: SECRET_CHIRHO,
                client_id_chirho: &client_id_chirho,
                actions_chirho: &page_read_chirho(),
                return_chirho: None,
            },
            &once_chirho,
        )
    };
    assert!(matches!(
        serve_chirho(),
        Ok(ConnectionServedOutcomeChirho::CreatedChirho(_))
    ));
    let before_chirho = written_chirho(&world_chirho);
    assert_eq!(
        refusal_kind_chirho(serve_chirho()),
        (ConnectionServedRefusalChirho::RateLimitedChirho, false)
    );
    assert_eq!(written_chirho(&world_chirho), before_chirho);
}

/// THE CAP AND THE DAY APPEND NO ATTEMPT ROW, AND THE LEGACY ROAD IS UNCHANGED (PFE #26804): five served creations
/// append five success rows; the sixth refuses at the cap with none. The legacy token road, refused at the same cap,
/// still appends the success row its sign-in made before its cap was read: no failed row, which is not no row. Ended
/// and replaced, the connections spend the day, and the eleventh refuses at the day with no row.
#[test]
fn the_cap_and_the_day_append_no_attempt_row_unlike_the_legacy_cap_chirho() {
    let world_chirho = world_chirho("served-cap-day");
    let root_chirho = &world_chirho.root_chirho;
    let mut keys_chirho = Vec::new();
    for _ in 0..LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO {
        let ConnectionServedOutcomeChirho::CreatedChirho(issue_chirho) =
            create_chirho(&world_chirho).unwrap()
        else {
            panic!("the slots have room");
        };
        keys_chirho.push(*issue_chirho);
    }
    let before_chirho = written_chirho(&world_chirho);
    assert_eq!(
        before_chirho.2,
        LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO
    );
    assert_eq!(
        refusal_kind_chirho(create_chirho(&world_chirho)),
        (ConnectionServedRefusalChirho::SlotsFullChirho, false)
    );
    assert_eq!(
        written_chirho(&world_chirho),
        before_chirho,
        "the K4 cap appends no row"
    );

    let legacy_refusal_chirho = issue_scoped_token_with_public_auth_limit_outcome_chirho(
        root_chirho,
        &world_chirho.user_chirho,
        SECRET_CHIRHO,
        &world_chirho.legacy_client_chirho.client_id_chirho,
        Vec::new(),
        None,
        &VELOCITY_CHIRHO,
    )
    .unwrap_err();
    assert!(legacy_refusal_chirho
        .error_chirho
        .downcast_ref::<ScopedTokenCapReachedChirho>()
        .is_some());
    assert!(!legacy_refusal_chirho.failure_recorded_chirho);
    assert_eq!(
        attempt_rows_chirho(&world_chirho).last(),
        Some(&(
            AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO.to_string(),
            IdentityAuthAttemptOutcomeChirho::SuccessChirho
        )),
        "the legacy cap refusal follows the success row its sign-in appended"
    );
    assert_eq!(
        world_chirho.lines_chirho(ATTEMPTS_CHIRHO),
        before_chirho.2 + 1
    );

    let ended_chirho = |key_chirho: &ScopedTokenIssueChirho| {
        revoke_own_key_chirho(
            root_chirho,
            &world_chirho.user_chirho,
            &scoped_key_id_chirho(&key_chirho.record_chirho.token_hash_chirho),
        )
        .unwrap();
    };
    keys_chirho.iter().for_each(ended_chirho);
    for _ in
        0..(CONNECTION_ISSUANCES_PER_DAY_CHIRHO - LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO)
    {
        let ConnectionServedOutcomeChirho::CreatedChirho(issue_chirho) =
            create_chirho(&world_chirho).unwrap()
        else {
            panic!("the day has room");
        };
        ended_chirho(&issue_chirho);
    }
    let before_chirho = written_chirho(&world_chirho);
    assert_eq!(
        refusal_kind_chirho(create_chirho(&world_chirho)),
        (ConnectionServedRefusalChirho::RateLimitedChirho, false)
    );
    assert_eq!(
        written_chirho(&world_chirho),
        before_chirho,
        "the day appends no row"
    );
}

/// THE FAULTS: with the session log read-only, the session's append fails, no key is written, no row is appended, and
/// the refusal reads not-created. With the key log read-only, the session is written, the key's append fails, and the
/// outcome is uncertain, with no attempt row: a connection may exist, and its bearer is never in hand.
#[test]
fn a_session_fault_is_not_created_and_a_key_fault_is_uncertain_chirho() {
    let world_chirho = world_chirho("served-faults");
    assert!(matches!(
        create_chirho(&world_chirho),
        Ok(ConnectionServedOutcomeChirho::CreatedChirho(_))
    ));

    let sessions_path_chirho = world_chirho.root_chirho.join(SESSIONS_CHIRHO);
    set_mode_chirho(&sessions_path_chirho, 0o444);
    assert_append_refused_chirho(&sessions_path_chirho);
    let before_chirho = written_chirho(&world_chirho);
    let session_fault_chirho = refusal_kind_chirho(create_chirho(&world_chirho));
    set_mode_chirho(&sessions_path_chirho, 0o644);
    assert_eq!(
        session_fault_chirho,
        (ConnectionServedRefusalChirho::NotCreatedChirho, false)
    );
    assert_eq!(written_chirho(&world_chirho), before_chirho);

    let tokens_path_chirho = world_chirho.root_chirho.join(CONNECTION_TOKENS_CHIRHO);
    set_mode_chirho(&tokens_path_chirho, 0o444);
    assert_append_refused_chirho(&tokens_path_chirho);
    let before_chirho = written_chirho(&world_chirho);
    let key_fault_chirho = create_chirho(&world_chirho);
    set_mode_chirho(&tokens_path_chirho, 0o644);
    let Ok(ConnectionServedOutcomeChirho::UncertainChirho { cause_chirho }) = key_fault_chirho
    else {
        panic!("a key fault is uncertain: {key_fault_chirho:?}");
    };
    assert!(
        cause_chirho.contains("ConnectionKeyUncertainChirho"),
        "{cause_chirho}"
    );
    assert_eq!(
        written_chirho(&world_chirho),
        (before_chirho.0 + 1, before_chirho.1, before_chirho.2),
        "the session is written, and no key or attempt row"
    );
}

/// AFTER THE KEY, A SUCCESS ROW THAT CANNOT BE APPENDED LEAVES THE CONNECTION UNCERTAIN (PFE #26801): with the attempt
/// log read-only, the session and the key are written and the success row is not. The outcome is uncertain, never a
/// pre-append refusal; the connection is live and listed; and the outcome holds no bearer.
#[test]
fn a_success_row_that_cannot_be_appended_leaves_the_connection_uncertain_chirho() {
    let world_chirho = world_chirho("served-evidence");
    assert!(matches!(
        create_chirho(&world_chirho),
        Ok(ConnectionServedOutcomeChirho::CreatedChirho(_))
    ));
    let attempts_path_chirho = world_chirho.root_chirho.join(ATTEMPTS_CHIRHO);
    set_mode_chirho(&attempts_path_chirho, 0o444);
    assert_append_refused_chirho(&attempts_path_chirho);
    let before_chirho = written_chirho(&world_chirho);
    let outcome_chirho = create_chirho(&world_chirho);
    set_mode_chirho(&attempts_path_chirho, 0o644);
    let Ok(ConnectionServedOutcomeChirho::UncertainChirho { cause_chirho }) = &outcome_chirho
    else {
        panic!("a lost success row is uncertain: {outcome_chirho:?}");
    };
    assert!(
        cause_chirho.contains("success row could not be appended"),
        "{cause_chirho}"
    );
    assert_eq!(
        written_chirho(&world_chirho),
        (
            before_chirho.0 + 1,
            (0, before_chirho.1 .1 + 1),
            before_chirho.2
        )
    );
    let rows_chirho =
        list_own_keys_chirho(&world_chirho.root_chirho, &world_chirho.user_chirho).unwrap();
    assert_eq!(
        rows_chirho
            .iter()
            .filter(|row_chirho| row_chirho.live_chirho)
            .count(),
        2,
        "it is live and holds a slot"
    );
}

/// THE FORM'S CHOICES: a connection client's app and its opened actions; nothing for a legacy client or an unknown id.
#[test]
fn the_form_offers_a_connection_clients_opened_actions_chirho() {
    let world_chirho = world_chirho("served-choices");
    let root_chirho = &world_chirho.root_chirho;
    assert_eq!(
        connection_form_choices_chirho(
            root_chirho,
            &ConnectionSelectorChirho::ClientChirho(
                world_chirho
                    .connection_client_chirho
                    .client_id_chirho
                    .clone()
            )
        )
        .unwrap(),
        Some(ConnectionFormChoicesChirho {
            client_id_chirho: world_chirho
                .connection_client_chirho
                .client_id_chirho
                .clone(),
            app_chirho: OPENED_APP_CHIRHO.to_string(),
            actions_chirho: page_read_chirho(),
        })
    );
    assert_eq!(
        connection_form_choices_chirho(
            root_chirho,
            &ConnectionSelectorChirho::ClientChirho(
                world_chirho.legacy_client_chirho.client_id_chirho.clone()
            )
        )
        .unwrap(),
        None
    );
    assert_eq!(
        connection_form_choices_chirho(
            root_chirho,
            &ConnectionSelectorChirho::ClientChirho("client/0000000000000000".to_string())
        )
        .unwrap(),
        None
    );
}
