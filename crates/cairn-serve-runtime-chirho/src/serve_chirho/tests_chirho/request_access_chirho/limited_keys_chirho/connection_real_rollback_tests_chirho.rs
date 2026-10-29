// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 CP7: R15 over the carrier's REAL writes, then roll-forward (PFE #26763, #26764). The successor writes a
//! connection as K4 does: the keyed app opens before its client registers, so the client, its keys and their uses land
//! in the connection logs. Beside it: an unopened app's legacy key, browser sign-in and an operator recovery code.
//!
//! - **A valid root first.** The explicit old and new client, key and use verifiers pass on the successor's root, each
//!   log dense from 0, so both stores hold a seq 0.
//! - **R15 over a copy reproduces the isolated row** the placement measurement pinned
//!   (`connection_rollback_tests_chirho.rs`), with nothing moved by hand. It runs through R15's JSON road and its CLI
//!   mint road, run as the host runs it (`--root <platform> --tenant <t> oauth-token`). Each mints for the unopened
//!   app's client and refuses the connection's. R15's own `oauth-verify` sees one oauth client, and the connection logs
//!   leave R15's run byte-identical.
//! - **Roll forward** on the copy R15 wrote. The successor's six verifiers pass over R15's appended rows. The
//!   connection whose principal R15 reset by a recovery code is ended. The other connection answers again, and the
//!   legacy keys R15 minted answer.
//!
//! Run: `CAIRN_R15_TWIN_CHIRHO=<R15's macOS twin> cargo test -p cairn-serve-runtime-chirho --lib connection_real -- --ignored`.

use super::app_route_fixture_chirho::{
    counted_road_runtime_chirho, write_request_chirho, GROWTH_APP_CHIRHO,
};
use super::limited_key_fixture_chirho::*;
use super::limited_key_rollback_tests_chirho::{
    control_app_chirho, keyed_path_chirho, r15_twin_chirho, sign_in_chirho, token_of_chirho,
    RootCopyChirho, TwinServerChirho,
};
use super::*;
use std::path::{Path, PathBuf};
use std::process::Command;

const PAGE_TEXT_CHIRHO: &str = "the page a connection saved";
const NEW_CREDENTIAL_CHIRHO: &str = "recovered-credential-value-chirho";
const CONTROL_VIEW_CHIRHO: &str = "/app-chirho/routegrowth/view";
const CONNECTION_LOGS_CHIRHO: [&str; 3] = [
    "oauth-connection-clients-chirho.jsonl",
    "connection-tokens-chirho.jsonl",
    "connection-token-uses-chirho.jsonl",
];

/// The successor's real writes: user 1's legacy key on the unopened app, used once; user 0's connection, which saved a
/// page; user 1's connection; and user 0's operator recovery code.
pub(super) struct RealStateChirho {
    pub(super) tenant_chirho: KeyedTenantChirho,
    control_key_chirho: String,
    control_client_chirho: String,
    /// User 0's connection: R15's recovery resets user 0's credential.
    pub(super) reset_connection_chirho: String,
    /// User 1's connection: nothing ends it.
    pub(super) kept_connection_chirho: String,
    recovery_code_chirho: String,
    dirs_chirho: Vec<PathBuf>,
}

impl Drop for RealStateChirho {
    fn drop(&mut self) {
        for dir_chirho in &self.dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

/// The two connections are issued by the production carrier, so their sessions are the connection's 30 days (K4 Part 2).
pub(super) fn real_state_chirho(label_chirho: &str) -> RealStateChirho {
    // The keyed app opens before its client registers, so its client is a connection client (K4).
    let tenant_chirho = KeyedTenantChirho::new_chirho(label_chirho, OpeningsChirho::PAGE_CHIRHO, 2);
    let (dirs_chirho, control_key_chirho) = control_app_chirho(&tenant_chirho, label_chirho);
    let control_client_chirho =
        cairn_chirho::oauth_chirho::load_clients_chirho(&tenant_chirho.root_chirho)
            .unwrap()
            .into_iter()
            .find(|client_chirho| client_chirho.app_chirho == GROWTH_APP_CHIRHO)
            .expect("the unopened app's client")
            .client_id_chirho;
    with_successor_served_chirho(&tenant_chirho.root_chirho, |addr_chirho| {
        let (status_chirho, body_chirho) = probe_chirho(
            addr_chirho,
            "GET",
            CONTROL_VIEW_CHIRHO,
            &[("authorization", &bearer_chirho(&control_key_chirho))],
            b"",
        );
        assert_eq!(
            status_chirho, 200,
            "the legacy key's first use: {body_chirho}"
        );
    });
    let reset_headers_chirho =
        tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO, PAGE_SAVE_CHIRHO]);
    let kept_headers_chirho = tenant_chirho.limited_bearer_chirho(1, &[PAGE_READ_CHIRHO]);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) = post_route_chirho(
            &state_chirho,
            &reset_headers_chirho,
            SAVE_ROUTE_CHIRHO,
            write_request_chirho(None, PAGE_TEXT_CHIRHO),
        )
        .await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "the connection's save: {body_chirho}"
        );
    });
    let (principal_chirho, _) = tenant_chirho.user_chirho(0);
    let recovery_code_chirho = identity_chirho::mint_operator_recovery_code_chirho(
        &tenant_chirho.root_chirho,
        principal_chirho,
    )
    .unwrap()
    .recovery_code_chirho;
    RealStateChirho {
        reset_connection_chirho: token_of_chirho(&reset_headers_chirho),
        kept_connection_chirho: token_of_chirho(&kept_headers_chirho),
        tenant_chirho,
        control_key_chirho,
        control_client_chirho,
        recovery_code_chirho,
        dirs_chirho,
    }
}

/// The explicit old and new verifiers over one tenant root, each in its own numbering: (legacy clients, keys, uses;
/// connection clients, keys, uses).
pub(super) fn six_verifiers_chirho(root_chirho: &Path) -> [usize; 6] {
    use cairn_chirho::oauth_chirho;
    [
        oauth_chirho::verify_clients_chirho(root_chirho).unwrap(),
        oauth_chirho::verify_scoped_tokens_chirho(root_chirho).unwrap(),
        oauth_chirho::verify_scoped_token_uses_chirho(root_chirho).unwrap(),
        oauth_chirho::verify_connection_clients_chirho(root_chirho).unwrap(),
        oauth_chirho::verify_connection_tokens_chirho(root_chirho).unwrap(),
        oauth_chirho::verify_connection_token_uses_chirho(root_chirho).unwrap(),
    ]
}

/// The bytes of the connection logs, by name: R15 must leave them untouched.
fn connection_log_bytes_chirho(root_chirho: &Path) -> Vec<(String, Vec<u8>)> {
    CONNECTION_LOGS_CHIRHO
        .iter()
        .map(|name_chirho| {
            (
                (*name_chirho).to_string(),
                std::fs::read(root_chirho.join(name_chirho)).unwrap(),
            )
        })
        .collect()
}

fn mint_request_chirho(
    principal_chirho: &str,
    credential_chirho: &str,
    client_chirho: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "principal_chirho": principal_chirho,
        "credential_chirho": credential_chirho,
        "client_id_chirho": client_chirho,
        "scopes_chirho": [],
    }))
    .unwrap()
}

/// R15's CLI against the copy, as the host runs it: `--root <platform> --tenant <t> <command…>`. Its exit success,
/// stdout and stderr.
fn r15_cli_chirho(
    twin_chirho: &Path,
    copy_chirho: &RootCopyChirho,
    command_chirho: &[&str],
) -> (bool, String, String) {
    let tenant_chirho = copy_chirho
        .tenant_root_chirho
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let output_chirho = Command::new(twin_chirho)
        .arg("--root")
        .arg(&copy_chirho.platform_chirho)
        .arg("--tenant")
        .arg(&tenant_chirho)
        .args(command_chirho)
        .output()
        .unwrap();
    (
        output_chirho.status.success(),
        String::from_utf8_lossy(&output_chirho.stdout).into_owned(),
        String::from_utf8_lossy(&output_chirho.stderr).into_owned(),
    )
}

/// R15 over a copy, through its JSON road and the browser and recovery controls, as the carrier and 30-day arms both
/// run it: one row of every status, and the legacy key R15's JSON road minted.
pub(super) fn r15_row_chirho(
    twin_chirho: &Path,
    copy_chirho: &RootCopyChirho,
    state_chirho: &RealStateChirho,
    connection_tokens_chirho: &[&String],
) -> (String, String) {
    let tenant_chirho = &state_chirho.tenant_chirho;
    let connection_client_chirho = tenant_chirho.client_id_chirho.clone();
    let (user0_chirho, credential0_chirho) = tenant_chirho.user_chirho(0);
    let (user1_chirho, credential1_chirho) = tenant_chirho.user_chirho(1);
    let json_chirho = [("content-type", "application/json")];
    let r15_chirho = TwinServerChirho::start_chirho(twin_chirho, copy_chirho);
    let addr_chirho = r15_chirho.addr_chirho.clone();
    let status_chirho = |method_chirho: &str,
                         path_chirho: &str,
                         headers_chirho: &[(&str, &str)],
                         body_chirho: &[u8]| {
        probe_chirho(
            &addr_chirho,
            method_chirho,
            path_chirho,
            headers_chirho,
            body_chirho,
        )
    };
    let (legacy_chirho, _) = status_chirho(
        "GET",
        CONTROL_VIEW_CHIRHO,
        &[(
            "authorization",
            &bearer_chirho(&state_chirho.control_key_chirho),
        )],
        b"",
    );
    let (mint_chirho, minted_chirho) = status_chirho(
        "POST",
        "/auth-chirho/token-chirho",
        &json_chirho,
        &mint_request_chirho(
            user1_chirho,
            credential1_chirho,
            &state_chirho.control_client_chirho,
        ),
    );
    let json_minted_chirho = serde_json::from_str::<serde_json::Value>(&minted_chirho).unwrap()
        ["token_chirho"]
        .as_str()
        .unwrap()
        .to_string();
    let (minted_use_chirho, _) = status_chirho(
        "GET",
        CONTROL_VIEW_CHIRHO,
        &[("authorization", &bearer_chirho(&json_minted_chirho))],
        b"",
    );
    let (sign_in_status_chirho, cookie_chirho) =
        sign_in_chirho(&addr_chirho, user1_chirho, credential1_chirho);
    let cookie_chirho = cookie_chirho.expect("R15 sets a session cookie");
    let (signed_in_view_chirho, _) = status_chirho(
        "GET",
        CONTROL_VIEW_CHIRHO,
        &[("cookie", &cookie_chirho)],
        b"",
    );
    let connection_statuses_chirho: Vec<u16> = connection_tokens_chirho
        .iter()
        .map(|token_chirho| {
            status_chirho(
                "GET",
                &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
                &[("authorization", &bearer_chirho(token_chirho))],
                b"",
            )
            .0
        })
        .collect();
    let (connection_mint_chirho, _) = status_chirho(
        "POST",
        "/auth-chirho/token-chirho",
        &json_chirho,
        &mint_request_chirho(user0_chirho, credential0_chirho, &connection_client_chirho),
    );
    let recover_body_chirho = serde_json::to_vec(&serde_json::json!({
        "principal_chirho": user0_chirho,
        "recovery_code_chirho": state_chirho.recovery_code_chirho,
        "new_credential_chirho": NEW_CREDENTIAL_CHIRHO,
    }))
    .unwrap();
    let (recovery_chirho, _) = status_chirho(
        "POST",
        "/auth-chirho/recover-chirho",
        &[
            ("content-type", "application/json"),
            ("x-forwarded-for", "203.0.113.9"),
        ],
        &recover_body_chirho,
    );
    let (after_recovery_chirho, after_cookie_chirho) =
        sign_in_chirho(&addr_chirho, user0_chirho, NEW_CREDENTIAL_CHIRHO);
    drop(r15_chirho);
    let row_chirho = format!(
            "legacy key {legacy_chirho}; legacy mint {mint_chirho}, its use {minted_use_chirho}; sign-in \
             {sign_in_status_chirho}, signed-in view {signed_in_view_chirho}; connection keys \
             {connection_statuses_chirho:?}; mint for the connection's client {connection_mint_chirho}; recovery \
             {recovery_chirho}, sign-in after it {after_recovery_chirho} ({})",
            if after_cookie_chirho.is_some() { "cookie set" } else { "no cookie" }
        );
    (row_chirho, json_minted_chirho)
}

/// R15 OVER THE CARRIER'S REAL WRITES, THEN ROLL FORWARD.
///
/// MIGRATION PATH: a different R15 row means R15's twin, or the successor's records, changed; read it, never wave it
/// through. A connection that R15 serves, or mints for, means the carrier leaked into a log R15 reads. A successor
/// verifier refusing after R15 means R15 wrote something the successor cannot read back.
#[test]
#[ignore = "runs R15's twin: set CAIRN_R15_TWIN_CHIRHO and pass --ignored"]
fn r15_over_real_connection_writes_then_roll_forward_chirho() {
    let twin_chirho = r15_twin_chirho();
    let state_chirho = real_state_chirho("k4-real");
    let tenant_chirho = &state_chirho.tenant_chirho;
    let connection_client_chirho = tenant_chirho.client_id_chirho.clone();
    assert_eq!(
        cairn_chirho::oauth_chirho::find_client_in_store_chirho(
            &tenant_chirho.root_chirho,
            &connection_client_chirho
        )
        .unwrap()
        .map(|(_client_chirho, store_chirho)| store_chirho),
        Some(cairn_chirho::oauth_chirho::KeyStoreChirho::ConnectionChirho)
    );

    // A valid root: every log dense from 0, both stores holding a seq 0.
    assert_eq!(
        six_verifiers_chirho(&tenant_chirho.root_chirho),
        [1, 1, 1, 1, 2, 1],
        "legacy clients, keys, uses; connection clients, keys, uses"
    );

    // R15 over a copy, through its JSON road and the browser and recovery controls.
    let copy_chirho = RootCopyChirho::of_chirho(&tenant_chirho.root_chirho, "k4-real-r15");
    let connection_bytes_chirho = connection_log_bytes_chirho(&copy_chirho.tenant_root_chirho);
    let (row_chirho, json_minted_chirho) = r15_row_chirho(
        &twin_chirho,
        &copy_chirho,
        &state_chirho,
        &[
            &state_chirho.reset_connection_chirho,
            &state_chirho.kept_connection_chirho,
        ],
    );
    assert_eq!(
        row_chirho,
        "legacy key 200; legacy mint 200, its use 200; sign-in 303, signed-in view 200; connection keys [403, 403]; \
         mint for the connection's client 400; recovery 200, sign-in after it 303 (cookie set)",
        "R15 over the real carrier: the isolated row, with no row moved by hand"
    );
    let (user1_chirho, credential1_chirho) = tenant_chirho.user_chirho(1);

    // R15's CLI mint road, as the host runs it: it mints for the unopened app's client and refuses the connection's.
    let (cli_mint_ok_chirho, cli_minted_chirho, cli_mint_err_chirho) = r15_cli_chirho(
        &twin_chirho,
        &copy_chirho,
        &[
            "oauth-token",
            "--principal",
            user1_chirho,
            "--credential",
            credential1_chirho,
            "--client",
            &state_chirho.control_client_chirho,
        ],
    );
    assert!(
        cli_mint_ok_chirho,
        "R15's CLI mints for the unopened app: {cli_mint_err_chirho}"
    );
    let cli_token_chirho = cli_minted_chirho
        .split('\t')
        .find_map(|field_chirho| field_chirho.trim().strip_prefix("token="))
        .expect("R15's CLI prints the key it minted")
        .to_string();
    let (cli_refused_ok_chirho, _, cli_refusal_chirho) = r15_cli_chirho(
        &twin_chirho,
        &copy_chirho,
        &[
            "oauth-token",
            "--principal",
            user1_chirho,
            "--credential",
            credential1_chirho,
            "--client",
            &connection_client_chirho,
        ],
    );
    assert!(
        !cli_refused_ok_chirho && cli_refusal_chirho.contains("unknown oauth client"),
        "R15's CLI refuses the connection's client as unknown: {cli_refusal_chirho}"
    );
    let (verify_ok_chirho, verified_chirho, verify_err_chirho) =
        r15_cli_chirho(&twin_chirho, &copy_chirho, &["oauth-verify"]);
    assert!(
        verify_ok_chirho,
        "R15's own verifier passes: {verify_err_chirho}"
    );
    assert!(
        verified_chirho.starts_with("verified 1 oauth client(s), "),
        "R15 sees one oauth client, the unopened app's: {verified_chirho}"
    );
    assert_eq!(
        connection_log_bytes_chirho(&copy_chirho.tenant_root_chirho),
        connection_bytes_chirho,
        "R15's run left the connection logs byte-identical"
    );

    // Roll forward on the copy R15 wrote.
    let [legacy_clients_chirho, _, _, connection_clients_chirho, connection_keys_chirho, connection_uses_chirho] =
        six_verifiers_chirho(&copy_chirho.tenant_root_chirho);
    assert_eq!(
        (
            legacy_clients_chirho,
            connection_clients_chirho,
            connection_keys_chirho,
            connection_uses_chirho
        ),
        (1, 1, 2, 1),
        "the successor reads R15's appended rows back, and the connection logs as they were"
    );
    with_successor_served_chirho(&copy_chirho.tenant_root_chirho, |addr_chirho| {
        let answer_chirho = |path_chirho: &str, token_chirho: &str| {
            probe_chirho(
                addr_chirho,
                "GET",
                path_chirho,
                &[("authorization", &bearer_chirho(token_chirho))],
                b"",
            )
            .0
        };
        assert_eq!(
            answer_chirho(
                &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
                &state_chirho.reset_connection_chirho
            ),
            403,
            "R15's credential reset ended user 0's connection"
        );
        assert_eq!(
            answer_chirho(
                &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
                &state_chirho.kept_connection_chirho
            ),
            200,
            "user 1's connection answers again after roll-forward"
        );
        for minted_chirho in [&json_minted_chirho, &cli_token_chirho] {
            assert_eq!(
                answer_chirho(CONTROL_VIEW_CHIRHO, minted_chirho),
                200,
                "a legacy key R15 minted for the unopened app answers on the successor"
            );
        }
    });
}

const DAY_MS_CHIRHO: u64 = identity_chirho::BROWSER_SESSION_LIFETIME_MS_CHIRHO;
const THIRTY_DAYS_MS_CHIRHO: u64 = identity_chirho::CONNECTION_SESSION_LIFETIME_MS_CHIRHO;

/// One session row's issue and expiry instants, as written, found by seq in the session log.
fn session_instants_chirho(root_chirho: &Path, seq_chirho: u64) -> (u64, u64) {
    let text_chirho =
        std::fs::read_to_string(root_chirho.join("identity-sessions-chirho.jsonl")).unwrap();
    let row_chirho = text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| serde_json::from_str::<serde_json::Value>(line_chirho).unwrap())
        .find(|row_chirho| row_chirho["seq_chirho"].as_u64() == Some(seq_chirho))
        .expect("the session row");
    (
        row_chirho["issued_ms_chirho"].as_u64().unwrap(),
        row_chirho["expires_ms_chirho"].as_u64().unwrap(),
    )
}

/// R15's own list of one principal's verified sessions, as the host runs `identity-sessions-list`: seq to its issue
/// instant, expiry instant and state.
fn r15_sessions_chirho(
    twin_chirho: &Path,
    copy_chirho: &RootCopyChirho,
    principal_chirho: &str,
) -> std::collections::BTreeMap<u64, (u64, u64, String)> {
    let (listed_chirho, out_chirho, err_chirho) = r15_cli_chirho(
        twin_chirho,
        copy_chirho,
        &["identity-sessions-list", principal_chirho],
    );
    assert!(listed_chirho, "R15 lists the sessions: {err_chirho}");
    out_chirho
        .lines()
        .filter_map(|line_chirho| {
            let fields_chirho: std::collections::BTreeMap<&str, &str> = line_chirho
                .split('\t')
                .filter_map(|field_chirho| field_chirho.split_once('='))
                .collect();
            Some((
                fields_chirho.get("seq")?.parse().ok()?,
                (
                    fields_chirho.get("issued_ms")?.parse().ok()?,
                    fields_chirho.get("expires_ms")?.parse().ok()?,
                    fields_chirho.get("state")?.to_string(),
                ),
            ))
        })
        .collect()
}

/// K4 PART 2, R15 SIDE (PFE #26779, #26787): R15 over the production carrier's real 30-day connection sessions, then
/// roll-forward. The connection's own road writes them: ordinary session rows with no new field.
///
/// - **As written.** Three connections (user 0's, which R15's recovery will reset; user 1's kept one; user 1's second,
///   which R15's operator will revoke) each come from a 30-day session, and each key carries its session's instants.
///   The six verifiers pass.
/// - **R15 parses, verifies and tolerates the rows.** Over a copy, every control of the carrier arm holds unchanged,
///   and every connection is refused. R15's own `identity-sessions-verify` passes. Its `identity-sessions-list` shows
///   user 1's kept connection session live with its 30-day expiry, and user 0's revoked after the recovery. A browser
///   sign-in on R15 still gets 24 hours.
/// - **R15 can end a connection through its session.** Its operator revokes user 1's second connection session by seq.
/// - **Roll forward.** The six verifiers read R15's rows back. The connection R15's recovery reset, and the one R15's
///   operator revoked, are refused; the kept connection answers, as do the legacy keys R15 minted.
///
/// MIGRATION PATH: R15 refusing to start, or `identity-sessions-verify` failing, means the 30-day row is an outage for
/// the predecessor and the carrier needs another shape; a kept connection refused after roll-forward means the row's
/// lifetime was not honoured.
#[test]
#[ignore = "runs R15's twin: set CAIRN_R15_TWIN_CHIRHO and pass --ignored"]
fn r15_over_thirty_day_connection_sessions_then_roll_forward_chirho() {
    let twin_chirho = r15_twin_chirho();
    let state_chirho = real_state_chirho("k4-thirty-day");
    let tenant_chirho = &state_chirho.tenant_chirho;
    let revoked_chirho =
        token_of_chirho(&tenant_chirho.limited_bearer_chirho(1, &[PAGE_READ_CHIRHO]));
    let (user0_chirho, _) = tenant_chirho.user_chirho(0);
    let (user1_chirho, _) = tenant_chirho.user_chirho(1);

    // As written: [user 0's to be reset, user 1's kept, user 1's to be revoked], each from a 30-day session.
    let keys_chirho =
        cairn_chirho::oauth_chirho::load_connection_tokens_chirho(&tenant_chirho.root_chirho)
            .unwrap();
    assert_eq!(
        keys_chirho
            .iter()
            .map(|key_chirho| key_chirho.principal_chirho.as_str())
            .collect::<Vec<_>>(),
        vec![user0_chirho, user1_chirho, user1_chirho]
    );
    for key_chirho in &keys_chirho {
        let (issued_chirho, expires_chirho) =
            session_instants_chirho(&tenant_chirho.root_chirho, key_chirho.session_seq_chirho);
        assert_eq!(
            expires_chirho - issued_chirho,
            THIRTY_DAYS_MS_CHIRHO,
            "session {}: 30 days",
            key_chirho.session_seq_chirho
        );
        assert_eq!(
            (key_chirho.issued_ms_chirho, key_chirho.expires_ms_chirho),
            (issued_chirho, expires_chirho),
            "the key carries its session's instants"
        );
    }
    assert_eq!(
        six_verifiers_chirho(&tenant_chirho.root_chirho),
        [1, 1, 1, 1, 3, 1]
    );
    identity_chirho::verify_sessions_chirho(&tenant_chirho.root_chirho)
        .expect("the successor verifies its own 30-day session rows");
    let [reset_seq_chirho, kept_seq_chirho, revoked_seq_chirho] =
        [0, 1, 2].map(|index_chirho: usize| keys_chirho[index_chirho].session_seq_chirho);

    // R15 over a copy: the carrier arm's row, with the three connections refused.
    let copy_chirho = RootCopyChirho::of_chirho(&tenant_chirho.root_chirho, "k4-thirty-day-r15");
    let connection_bytes_chirho = connection_log_bytes_chirho(&copy_chirho.tenant_root_chirho);
    let (row_chirho, json_minted_chirho) = r15_row_chirho(
        &twin_chirho,
        &copy_chirho,
        &state_chirho,
        &[
            &state_chirho.reset_connection_chirho,
            &state_chirho.kept_connection_chirho,
            &revoked_chirho,
        ],
    );
    assert_eq!(
        row_chirho,
        "legacy key 200; legacy mint 200, its use 200; sign-in 303, signed-in view 200; connection keys \
         [403, 403, 403]; mint for the connection's client 400; recovery 200, sign-in after it 303 (cookie set)",
        "R15 over 30-day connection sessions: every control holds, and every connection is refused"
    );

    // R15's own reading of the sessions, through its CLI as the host runs it.
    let (verified_chirho, _, verify_err_chirho) =
        r15_cli_chirho(&twin_chirho, &copy_chirho, &["identity-sessions-verify"]);
    assert!(
        verified_chirho,
        "R15 verifies every session row: {verify_err_chirho}"
    );
    let user1_sessions_chirho = r15_sessions_chirho(&twin_chirho, &copy_chirho, user1_chirho);
    let kept_chirho = user1_sessions_chirho
        .get(&kept_seq_chirho)
        .expect("R15 lists the kept connection's session")
        .clone();
    assert_eq!(
        (kept_chirho.1 - kept_chirho.0, kept_chirho.2.as_str()),
        (THIRTY_DAYS_MS_CHIRHO, "live"),
        "R15 shows the kept connection's session live, with its 30-day expiry"
    );
    let (browser_seq_chirho, browser_chirho) = user1_sessions_chirho
        .iter()
        .next_back()
        .expect("R15's own sign-in made a session");
    assert!(*browser_seq_chirho > revoked_seq_chirho);
    assert_eq!(
        browser_chirho.1 - browser_chirho.0,
        DAY_MS_CHIRHO,
        "a browser sign-in on R15 gets 24 hours"
    );
    let user0_sessions_chirho = r15_sessions_chirho(&twin_chirho, &copy_chirho, user0_chirho);
    assert_eq!(
        user0_sessions_chirho
            .get(&reset_seq_chirho)
            .map(|session_chirho| session_chirho.2.as_str()),
        Some("revoked"),
        "R15's recovery revoked user 0's connection session"
    );
    let revoked_seq_text_chirho = revoked_seq_chirho.to_string();
    let (revoked_ok_chirho, _, revoke_err_chirho) = r15_cli_chirho(
        &twin_chirho,
        &copy_chirho,
        &[
            "identity-session-revoke",
            user1_chirho,
            "--session-seq",
            &revoked_seq_text_chirho,
        ],
    );
    assert!(
        revoked_ok_chirho,
        "R15's operator revokes a connection's session: {revoke_err_chirho}"
    );
    assert_eq!(
        connection_log_bytes_chirho(&copy_chirho.tenant_root_chirho),
        connection_bytes_chirho,
        "R15's run left the connection logs byte-identical"
    );

    // Roll forward on the copy R15 wrote.
    let [_, _, _, connection_clients_chirho, connection_keys_chirho, connection_uses_chirho] =
        six_verifiers_chirho(&copy_chirho.tenant_root_chirho);
    assert_eq!(
        (
            connection_clients_chirho,
            connection_keys_chirho,
            connection_uses_chirho
        ),
        (1, 3, 1)
    );
    with_successor_served_chirho(&copy_chirho.tenant_root_chirho, |addr_chirho| {
        let answer_chirho = |path_chirho: &str, token_chirho: &str| {
            probe_chirho(
                addr_chirho,
                "GET",
                path_chirho,
                &[("authorization", &bearer_chirho(token_chirho))],
                b"",
            )
            .0
        };
        let view_chirho = keyed_path_chirho(VIEW_ROUTE_CHIRHO);
        assert_eq!(
            [
                answer_chirho(&view_chirho, &state_chirho.reset_connection_chirho),
                answer_chirho(&view_chirho, &revoked_chirho),
                answer_chirho(&view_chirho, &state_chirho.kept_connection_chirho),
                answer_chirho(CONTROL_VIEW_CHIRHO, &json_minted_chirho),
            ],
            [403, 403, 200, 200],
            "reset and revoked on R15: refused; kept: answers; R15's legacy key: answers"
        );
    });
    identity_chirho::verify_sessions_chirho(&copy_chirho.tenant_root_chirho)
        .expect("the successor verifies the session rows R15 appended");
    identity_chirho::verify_session_revocations_chirho(&copy_chirho.tenant_root_chirho)
        .expect("the successor verifies the revocations R15 appended");

    // The same-key control: the original root, which R15 never touched, answers all three connections, so the two
    // refusals above are what R15's recovery and R15's operator did.
    with_successor_served_chirho(&tenant_chirho.root_chirho, |addr_chirho| {
        let view_chirho = keyed_path_chirho(VIEW_ROUTE_CHIRHO);
        let answers_chirho = [
            &state_chirho.reset_connection_chirho,
            &revoked_chirho,
            &state_chirho.kept_connection_chirho,
        ]
        .map(|token_chirho| {
            probe_chirho(
                addr_chirho,
                "GET",
                &view_chirho,
                &[("authorization", &bearer_chirho(token_chirho))],
                b"",
            )
            .0
        });
        assert_eq!(
            answers_chirho,
            [200, 200, 200],
            "untouched by R15, all three connections answer"
        );
    });
}
