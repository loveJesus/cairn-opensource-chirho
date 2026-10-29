// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The shared JSONL loader brick's key and session arms: a token log or a session-revocations log the engine cannot
//! examine is never read as "no keys" or "no revocations". Measured cold and warm on the owner's key list, her revoke,
//! the owner's keys page (K3), and a revoked session.
//! Tasklist: `spec-chirho/tasklists-chirho/26-10-08_23-20-tasklist-jsonl_absence_cache_door-chirho.md`.

use super::own_keys_fixture_chirho::{
    AccountTenantChirho, ACCOUNT_APP_CHIRHO, ACCOUNT_ROUTE_CHIRHO,
};
use super::unexaminable_log_tests_chirho::{
    apply_fault_chirho, bounded_call_chirho, judge_cases_chirho, restore_chirho,
    status_and_body_chirho, unread_root_chirho, CaseChirho, FaultChirho, ANSWER_TIMEOUT_CHIRHO,
    DANGLING_TARGET_CHIRHO, ELSEWHERE_DIR_CHIRHO, FAULTS_CHIRHO,
};
use super::*;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) const SECRET_CHIRHO: &str = "unexaminable-key-secret";
pub(super) const TOKEN_LOG_CHIRHO: &str = "scoped-tokens-chirho.jsonl";
pub(super) const REVOCATIONS_LOG_CHIRHO: &str = "identity-session-revocations-chirho.jsonl";
const PAGE_CHIRHO: &str = "/app-chirho/accountapp/account";
/// Cold: a root path this process has never read, faulted before its first served read. Warm: answered once first.
pub(super) const TEMPERATURES_CHIRHO: [&str; 2] = ["cold", "warm"];

/// One whole answer from a real local server.
pub(super) struct AnswerChirho {
    pub(super) status_chirho: u16,
    pub(super) location_chirho: Option<String>,
    pub(super) cache_control_chirho: Option<String>,
    pub(super) body_chirho: String,
}

/// One request, bounded: `None` when no whole answer comes back in time, as when a reader is stuck on a pipe.
pub(super) fn bounded_request_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
    body_chirho: &[u8],
) -> Option<AnswerChirho> {
    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho).ok()?;
    stream_chirho
        .set_read_timeout(Some(ANSWER_TIMEOUT_CHIRHO))
        .ok()?;
    stream_chirho
        .set_write_timeout(Some(ANSWER_TIMEOUT_CHIRHO))
        .ok()?;
    let mut request_chirho = format!(
        "{method_chirho} {path_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\n"
    );
    for (name_chirho, value_chirho) in headers_chirho {
        request_chirho.push_str(&format!("{name_chirho}: {value_chirho}\r\n"));
    }
    request_chirho.push_str(&format!("content-length: {}\r\n\r\n", body_chirho.len()));
    stream_chirho.write_all(request_chirho.as_bytes()).ok()?;
    stream_chirho.write_all(body_chirho).ok()?;
    let mut answer_chirho = Vec::new();
    stream_chirho.read_to_end(&mut answer_chirho).ok()?;
    let text_chirho = String::from_utf8_lossy(&answer_chirho).to_string();
    let (head_chirho, body_chirho) = text_chirho.split_once("\r\n\r\n")?;
    let status_chirho = head_chirho
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let header_chirho = |wanted_chirho: &str| {
        head_chirho.lines().find_map(|line_chirho| {
            let (name_chirho, value_chirho) = line_chirho.split_once(':')?;
            name_chirho
                .trim()
                .eq_ignore_ascii_case(wanted_chirho)
                .then(|| value_chirho.trim().to_string())
        })
    };
    Some(AnswerChirho {
        status_chirho,
        location_chirho: header_chirho("location"),
        cache_control_chirho: header_chirho("cache-control"),
        body_chirho: body_chirho.to_string(),
    })
}

/// A signed-in browser session for `principal_chirho`: its cookie, and its token.
pub(super) fn browser_session_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> (String, String) {
    let login_chirho =
        identity_chirho::login_identity_chirho(root_chirho, principal_chirho).unwrap();
    (
        format!(
            "cairn_session_chirho={}:{}",
            login_chirho.session_chirho.principal_chirho, login_chirho.token_chirho
        ),
        login_chirho.token_chirho,
    )
}

/// Her JSON key list as "STATUS keys=N", or "STATUS <first body line>" when it is not a list, or "hung".
pub(super) fn key_list_chirho(addr_chirho: &str, cookie_chirho: &str) -> String {
    let Some(answer_chirho) = bounded_request_chirho(
        addr_chirho,
        "GET",
        "/auth-chirho/keys-chirho",
        &[("cookie", cookie_chirho)],
        b"",
    ) else {
        return "hung".to_string();
    };
    match serde_json::from_str::<serde_json::Value>(&answer_chirho.body_chirho)
        .ok()
        .and_then(|value_chirho| value_chirho["keys_chirho"].as_array().map(Vec::len))
    {
        Some(count_chirho) => format!("{} keys={count_chirho}", answer_chirho.status_chirho),
        None => format!(
            "{} {}",
            answer_chirho.status_chirho,
            answer_chirho.body_chirho.lines().next().unwrap_or_default()
        ),
    }
}

/// Her no-script form revoke of `key_id_chirho` from her page, as "STATUS location=...", or "hung".
fn form_revoke_chirho(addr_chirho: &str, cookie_chirho: &str, key_id_chirho: &str) -> String {
    let body_chirho = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("key_id_chirho", key_id_chirho)
        .append_pair("redirect_chirho", PAGE_CHIRHO)
        .finish();
    let Some(answer_chirho) = bounded_request_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/key-revoke-chirho",
        &[
            ("cookie", cookie_chirho),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        body_chirho.as_bytes(),
    ) else {
        return "hung".to_string();
    };
    format!(
        "{} location={}",
        answer_chirho.status_chirho,
        answer_chirho.location_chirho.unwrap_or_default()
    )
}

/// Whether the fault is still what sits at the log's path. A write that replaced it, as a rename over a link would, went
/// through the fault as surely as one that followed it.
fn fault_in_place_chirho(log_chirho: &Path, fault_chirho: FaultChirho) -> bool {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let Ok(metadata_chirho) = std::fs::symlink_metadata(log_chirho) else {
        return false;
    };
    let kind_chirho = metadata_chirho.file_type();
    match fault_chirho {
        FaultChirho::LoopChirho | FaultChirho::DanglingChirho | FaultChirho::ValidTargetChirho => {
            kind_chirho.is_symlink()
        }
        FaultChirho::DirectoryChirho => kind_chirho.is_dir(),
        FaultChirho::FifoChirho => kind_chirho.is_fifo(),
        FaultChirho::UnreadableChirho => {
            kind_chirho.is_file() && metadata_chirho.permissions().mode() & 0o777 == 0
        }
    }
}

/// Whether a write went through the fault instead of refusing: the fault replaced at the log's path, a file now at the
/// dangling link's target, a changed copy behind the valid link, or anything created inside the directory.
fn wrote_through_chirho(log_chirho: &Path, fault_chirho: FaultChirho, saved_chirho: &[u8]) -> bool {
    if !fault_in_place_chirho(log_chirho, fault_chirho) {
        return true;
    }
    let dir_chirho = log_chirho.parent().unwrap();
    match fault_chirho {
        FaultChirho::DanglingChirho => {
            std::fs::symlink_metadata(dir_chirho.join(DANGLING_TARGET_CHIRHO)).is_ok()
        }
        FaultChirho::ValidTargetChirho => match std::fs::read(
            dir_chirho
                .join(ELSEWHERE_DIR_CHIRHO)
                .join(log_chirho.file_name().unwrap()),
        ) {
            Ok(bytes_chirho) => bytes_chirho != saved_chirho,
            Err(_) => true,
        },
        FaultChirho::DirectoryChirho => match std::fs::read_dir(log_chirho) {
            Ok(mut entries_chirho) => entries_chirho.next().is_some(),
            Err(_) => false,
        },
        // Nothing a write could leave: a loop and a pipe hold no data, and a mode-000 file refuses its owner's write.
        FaultChirho::LoopChirho | FaultChirho::FifoChirho | FaultChirho::UnreadableChirho => false,
    }
}

/// Serve `root_chirho` on a fresh local port for `measure_chirho`, then stop. The runtime shuts down with a deadline,
/// so a request stuck on a pipe cannot hold the test open.
pub(super) fn with_server_chirho(root_chirho: &Path, measure_chirho: impl FnOnce(&str)) {
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.to_path_buf();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let server_chirho = runtime_chirho.spawn(async move {
        serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
    });
    wait_for_serve_health_chirho(&addr_chirho);
    measure_chirho(&addr_chirho);
    server_chirho.abort();
    runtime_chirho.shutdown_timeout(Duration::from_secs(2));
}

/// Her root for a temperature: a cold case moves it to a path this process has never read.
pub(super) fn root_at_chirho(root_chirho: &Path, temperature_chirho: &str) -> PathBuf {
    if temperature_chirho == "cold" {
        unread_root_chirho(root_chirho)
    } else {
        root_chirho.to_path_buf()
    }
}

/// A root where Alice, an owner, holds one key on client "alpha" and a signed-in browser session: (root, her cookie,
/// her key's id).
pub(super) fn key_root_chirho(label_chirho: &str) -> (PathBuf, String, String) {
    let root_chirho = temp_root_chirho(label_chirho);
    let alice_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let client_chirho =
        oauth_chirho::register_client_chirho(&root_chirho, "alpha", &alice_chirho).unwrap();
    let issue_chirho = oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &alice_chirho,
        SECRET_CHIRHO,
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    let (cookie_chirho, _) = browser_session_chirho(&root_chirho, &alice_chirho);
    (
        root_chirho,
        cookie_chirho,
        oauth_chirho::scoped_key_id_chirho(&issue_chirho.record_chirho.token_hash_chirho),
    )
}

/// MEASUREMENT, THEN THE PROPERTY: a token log the engine cannot examine is never read as "no keys". For every fault,
/// cold and warm: her JSON key list refuses rather than answering an empty list, and her form revoke answers
/// `#refusal-keys-failed-chirho`, never `no-such-key` or `key-ended`, and writes nothing through the fault. The
/// controls: her list shows her one key before the fault (warm) and again after the log is restored.
///
/// MIGRATION PATH: "200 keys=0" means an unexaminable log read as no keys. `no-such-key` tells her a key she holds is
/// not hers, and the key comes back when the fault clears. "[WROTE THROUGH]" means a write followed the fault (a link's
/// target, a directory) instead of refusing. "hung" means a reader opened a pipe. A control that fails after the
/// restore means the fixture is wrong, or that a faulted call changed her keys.
#[test]
fn a_token_log_the_engine_cannot_examine_never_reads_as_no_keys_chirho() {
    let mut cases_chirho: Vec<CaseChirho> = Vec::new();
    for fault_chirho in FAULTS_CHIRHO {
        for temperature_chirho in TEMPERATURES_CHIRHO {
            let mut record_chirho =
                |case_chirho: String, answer_chirho: String, acceptable_chirho: bool| {
                    cases_chirho.push(CaseChirho {
                        case_chirho,
                        answer_chirho,
                        acceptable_chirho,
                    })
                };
            let (root_chirho, cookie_chirho, key_id_chirho) = key_root_chirho(&format!(
                "unexaminable-tokens-{temperature_chirho}-{fault_chirho:?}"
            ));
            let root_chirho = root_at_chirho(&root_chirho, temperature_chirho);
            let log_chirho = root_chirho.join(TOKEN_LOG_CHIRHO);
            let saved_chirho = std::fs::read(&log_chirho).unwrap();
            with_server_chirho(&root_chirho, |addr_chirho| {
                if temperature_chirho == "warm" {
                    let answer_chirho = key_list_chirho(addr_chirho, &cookie_chirho);
                    let acceptable_chirho = answer_chirho == "200 keys=1";
                    record_chirho(
                        format!("tokens warm {fault_chirho:?}, before (control)"),
                        answer_chirho,
                        acceptable_chirho,
                    );
                }
                apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
                let answer_chirho = key_list_chirho(addr_chirho, &cookie_chirho);
                let acceptable_chirho = answer_chirho != "hung" && !answer_chirho.starts_with('2');
                record_chirho(
                    format!("tokens {temperature_chirho} {fault_chirho:?}: her key list"),
                    answer_chirho,
                    acceptable_chirho,
                );
                let answer_chirho = form_revoke_chirho(addr_chirho, &cookie_chirho, &key_id_chirho);
                let wrote_chirho = wrote_through_chirho(&log_chirho, fault_chirho, &saved_chirho);
                let acceptable_chirho = !wrote_chirho
                    && answer_chirho
                        == format!("303 location={PAGE_CHIRHO}#refusal-keys-failed-chirho");
                record_chirho(
                    format!("tokens {temperature_chirho} {fault_chirho:?}: her revoke"),
                    format!(
                        "{answer_chirho}{}",
                        if wrote_chirho { " [WROTE THROUGH]" } else { "" }
                    ),
                    acceptable_chirho,
                );
                restore_chirho(&log_chirho, fault_chirho, Some(&saved_chirho));
                let answer_chirho = key_list_chirho(addr_chirho, &cookie_chirho);
                let acceptable_chirho = answer_chirho == "200 keys=1";
                record_chirho(
                    format!("tokens {temperature_chirho} {fault_chirho:?}, restored (control)"),
                    answer_chirho,
                    acceptable_chirho,
                );
            });
            let _ = std::fs::remove_dir_all(&root_chirho);
        }
    }
    judge_cases_chirho(&cases_chirho);
}

/// Her account page's answer through the production GET handler: "STATUS STATE rows=N" for an owner's-keys answer, else
/// "STATUS <first body line>", or "hung". The second value says whether the page answered `available-chirho`.
fn account_page_chirho(
    runtime_chirho: &tokio::runtime::Runtime,
    state_chirho: &AppStateChirho,
    cookie_chirho: &HeaderMap,
) -> (String, bool) {
    let state_chirho = state_chirho.clone();
    let cookie_chirho = cookie_chirho.clone();
    let answer_chirho = bounded_call_chirho(runtime_chirho, move || async move {
        let uri_chirho = format!("/app-chirho/{ACCOUNT_APP_CHIRHO}/{ACCOUNT_ROUTE_CHIRHO}")
            .parse()
            .unwrap();
        status_and_body_chirho(
            app_route_get_chirho(
                State(state_chirho),
                None,
                cookie_chirho,
                AxPath((
                    ACCOUNT_APP_CHIRHO.to_string(),
                    ACCOUNT_ROUTE_CHIRHO.to_string(),
                )),
                axum::extract::OriginalUri(uri_chirho),
            )
            .await,
        )
        .await
    });
    let Some((status_chirho, body_chirho)) = answer_chirho else {
        return ("hung".to_string(), false);
    };
    let answer_chirho = serde_json::from_str::<serde_json::Value>(&body_chirho).ok();
    let state_name_chirho = answer_chirho
        .as_ref()
        .and_then(|value_chirho| value_chirho["state_chirho"].as_str().map(str::to_string));
    match state_name_chirho {
        Some(state_name_chirho) => {
            let rows_chirho = answer_chirho
                .as_ref()
                .and_then(|value_chirho| value_chirho["keys_chirho"].as_array().map(Vec::len))
                .unwrap_or(0);
            let available_chirho = state_name_chirho == "available-chirho";
            (
                format!("{status_chirho} {state_name_chirho} rows={rows_chirho}"),
                available_chirho,
            )
        }
        None => (
            format!(
                "{status_chirho} {}",
                body_chirho.lines().next().unwrap_or_default()
            ),
            false,
        ),
    }
}

/// The owner's keys page (K3) under the same faults, cold and warm: her account route never answers
/// `available-chirho` over a token log the engine cannot examine; it answers `unavailable-chirho`, or refuses. The
/// controls: her page lists her two keys before the fault (warm) and after the restore.
///
/// MIGRATION PATH: `available-chirho rows=0` is the failure shown as "none" that K3's record left open; any
/// `available-chirho` over a fault means the page read past a log it could not examine.
#[test]
fn the_owners_keys_page_never_shows_an_unexaminable_token_log_as_no_keys_chirho() {
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let mut cases_chirho: Vec<CaseChirho> = Vec::new();
    for fault_chirho in FAULTS_CHIRHO {
        for temperature_chirho in TEMPERATURES_CHIRHO {
            let tenant_chirho = AccountTenantChirho::new_chirho(
                &format!(
                    "unexaminable-page-{temperature_chirho}-{}",
                    format!("{fault_chirho:?}").to_lowercase()
                ),
                1,
            );
            tenant_chirho.legacy_key_chirho(0);
            tenant_chirho.legacy_key_chirho(0);
            let cookie_chirho = tenant_chirho.cookie_chirho(0);
            // The tenant root sits at <platform>/tenants-chirho/<tenant>; a cold case moves the whole platform root.
            let platform_chirho = tenant_chirho
                .root_chirho
                .parent()
                .and_then(Path::parent)
                .unwrap()
                .to_path_buf();
            let inside_chirho = tenant_chirho
                .root_chirho
                .strip_prefix(&platform_chirho)
                .unwrap()
                .to_path_buf();
            let platform_chirho = root_at_chirho(&platform_chirho, temperature_chirho);
            let tenant_root_chirho = platform_chirho.join(inside_chirho);
            let state_chirho =
                super::app_route_fixture_chirho::growth_state_chirho(&tenant_root_chirho);
            let log_chirho = tenant_root_chirho.join(TOKEN_LOG_CHIRHO);
            let saved_chirho = std::fs::read(&log_chirho).unwrap();
            let mut record_chirho =
                |case_chirho: String, answer_chirho: String, acceptable_chirho: bool| {
                    cases_chirho.push(CaseChirho {
                        case_chirho,
                        answer_chirho,
                        acceptable_chirho,
                    })
                };
            {
                if temperature_chirho == "warm" {
                    let (answer_chirho, _) =
                        account_page_chirho(&runtime_chirho, &state_chirho, &cookie_chirho);
                    let acceptable_chirho = answer_chirho == "200 available-chirho rows=2";
                    record_chirho(
                        format!("page warm {fault_chirho:?}, before (control)"),
                        answer_chirho,
                        acceptable_chirho,
                    );
                }
                apply_fault_chirho(
                    &tenant_root_chirho,
                    &log_chirho,
                    fault_chirho,
                    Some(&saved_chirho),
                );
                let (answer_chirho, available_chirho) =
                    account_page_chirho(&runtime_chirho, &state_chirho, &cookie_chirho);
                let acceptable_chirho = answer_chirho != "hung" && !available_chirho;
                record_chirho(
                    format!("page {temperature_chirho} {fault_chirho:?}"),
                    answer_chirho,
                    acceptable_chirho,
                );
                restore_chirho(&log_chirho, fault_chirho, Some(&saved_chirho));
                let (answer_chirho, _) =
                    account_page_chirho(&runtime_chirho, &state_chirho, &cookie_chirho);
                let acceptable_chirho = answer_chirho == "200 available-chirho rows=2";
                record_chirho(
                    format!("page {temperature_chirho} {fault_chirho:?}, restored (control)"),
                    answer_chirho,
                    acceptable_chirho,
                );
            }
            drop(tenant_chirho);
            let _ = std::fs::remove_dir_all(&platform_chirho);
        }
    }
    runtime_chirho.shutdown_timeout(Duration::from_secs(2));
    judge_cases_chirho(&cases_chirho);
}

/// MEASUREMENT, THEN THE PROPERTY: a session-revocations log the engine cannot examine never brings a revoked session
/// back. Alice holds two browser sessions and revokes the first. For every fault, cold and warm, the revoked session's
/// key list is refused. The live session's answer is recorded beside it, not judged: refusing it too is the
/// fail-closed answer. The controls: before the fault (warm) and after the restore, the revoked session is refused and
/// the live one answered.
///
/// MIGRATION PATH: a 2xx for the revoked session means an unexaminable revocations log read as "no revocations", which
/// brings back every session ever revoked on the root.
#[test]
fn a_revocations_log_the_engine_cannot_examine_never_revives_a_revoked_session_chirho() {
    let mut cases_chirho: Vec<CaseChirho> = Vec::new();
    for fault_chirho in FAULTS_CHIRHO {
        for temperature_chirho in TEMPERATURES_CHIRHO {
            let mut record_chirho =
                |case_chirho: String, answer_chirho: String, acceptable_chirho: bool| {
                    cases_chirho.push(CaseChirho {
                        case_chirho,
                        answer_chirho,
                        acceptable_chirho,
                    })
                };
            let root_chirho = temp_root_chirho(&format!(
                "unexaminable-revocations-{temperature_chirho}-{fault_chirho:?}"
            ));
            let alice_chirho = identity_chirho::register_identity_with_credential_chirho(
                &root_chirho,
                identity_chirho::PrincipalKindChirho::OwnerChirho,
                SECRET_CHIRHO,
            )
            .unwrap()
            .principal_chirho;
            let (revoked_cookie_chirho, revoked_token_chirho) =
                browser_session_chirho(&root_chirho, &alice_chirho);
            let (live_cookie_chirho, _) = browser_session_chirho(&root_chirho, &alice_chirho);
            identity_chirho::revoke_session_token_chirho(
                &root_chirho,
                &alice_chirho,
                &revoked_token_chirho,
                &alice_chirho,
                "measurement",
            )
            .unwrap();
            let root_chirho = root_at_chirho(&root_chirho, temperature_chirho);
            let log_chirho = root_chirho.join(REVOCATIONS_LOG_CHIRHO);
            let saved_chirho = std::fs::read(&log_chirho).unwrap();
            with_server_chirho(&root_chirho, |addr_chirho| {
                if temperature_chirho == "warm" {
                    let revoked_chirho = key_list_chirho(addr_chirho, &revoked_cookie_chirho);
                    let live_chirho = key_list_chirho(addr_chirho, &live_cookie_chirho);
                    let acceptable_chirho =
                        revoked_chirho.starts_with("401") && live_chirho == "200 keys=0";
                    record_chirho(
                        format!("revocations warm {fault_chirho:?}, before (control)"),
                        format!("revoked {revoked_chirho}; live {live_chirho}"),
                        acceptable_chirho,
                    );
                }
                apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
                let revoked_chirho = key_list_chirho(addr_chirho, &revoked_cookie_chirho);
                let acceptable_chirho =
                    revoked_chirho != "hung" && !revoked_chirho.starts_with('2');
                record_chirho(
                    format!(
                        "revocations {temperature_chirho} {fault_chirho:?}: the revoked session"
                    ),
                    revoked_chirho,
                    acceptable_chirho,
                );
                record_chirho(
                    format!("revocations {temperature_chirho} {fault_chirho:?}: the live session (recorded)"),
                    key_list_chirho(addr_chirho, &live_cookie_chirho),
                    true,
                );
                restore_chirho(&log_chirho, fault_chirho, Some(&saved_chirho));
                let revoked_chirho = key_list_chirho(addr_chirho, &revoked_cookie_chirho);
                let live_chirho = key_list_chirho(addr_chirho, &live_cookie_chirho);
                let acceptable_chirho =
                    revoked_chirho.starts_with("401") && live_chirho == "200 keys=0";
                record_chirho(
                    format!(
                        "revocations {temperature_chirho} {fault_chirho:?}, restored (control)"
                    ),
                    format!("revoked {revoked_chirho}; live {live_chirho}"),
                    acceptable_chirho,
                );
            });
            let _ = std::fs::remove_dir_all(&root_chirho);
        }
    }
    judge_cases_chirho(&cases_chirho);
}
