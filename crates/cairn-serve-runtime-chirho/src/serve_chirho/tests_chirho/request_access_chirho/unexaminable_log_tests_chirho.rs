// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The shared JSONL loader brick's served arms: an app control-plane log the engine cannot examine is never read as an
//! empty log, at either door: the load, or a cached view accepted before any load. Measured first where an empty read
//! costs the most: the request-access policy, whose absence means public.
//! Tasklist: `spec-chirho/tasklists-chirho/26-10-08_23-20-tasklist-jsonl_absence_cache_door-chirho.md`.

use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) const GUARDED_APP_CHIRHO: &str = "guarded-chirho";
const OPEN_APP_CHIRHO: &str = "open-chirho";
pub(super) const ROUTE_CHIRHO: &str = "change-chirho";
pub(super) const ACCESS_LOG_CHIRHO: &str = "app-request-access-policy-records-chirho.jsonl";
/// An answer that does not come back in this long is recorded as hung, never as a pass.
pub(super) const ANSWER_TIMEOUT_CHIRHO: Duration = Duration::from_secs(10);
const REFUSED_ANONYMOUS_CHIRHO: &str = "401 authentication required";

/// What is put at a log's path in place of the log.
#[derive(Clone, Copy, Debug)]
pub(super) enum FaultChirho {
    /// A symlink to itself: the metadata read fails.
    LoopChirho,
    /// A symlink to nothing.
    DanglingChirho,
    /// A symlink to a valid copy of the log.
    ValidTargetChirho,
    /// A directory.
    DirectoryChirho,
    /// A named pipe: opening it for reading waits for a writer.
    FifoChirho,
    /// The log present with mode 000: its metadata reads, and opening it is refused.
    UnreadableChirho,
}

/// Where a dangling link points, relative to the log's directory: nothing is there unless a write follows the link.
pub(super) const DANGLING_TARGET_CHIRHO: &str = "nothing-here-chirho.jsonl";
/// The directory, under the root, holding the copy a valid link points to.
pub(super) const ELSEWHERE_DIR_CHIRHO: &str = "elsewhere-chirho";

pub(super) const FAULTS_CHIRHO: [FaultChirho; 6] = [
    FaultChirho::LoopChirho,
    FaultChirho::DanglingChirho,
    FaultChirho::ValidTargetChirho,
    FaultChirho::DirectoryChirho,
    FaultChirho::FifoChirho,
    FaultChirho::UnreadableChirho,
];

/// A plain-input app with a pure guest route, signed-in only when `guarded_chirho`. A root where no app ever set a
/// policy has no access policy log at all: a genuine absence.
pub(super) fn deploy_app_chirho(root_chirho: &Path, app_chirho: &str, guarded_chirho: bool) {
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let root_dag_chirho = deploy_transform_app_for_owner_chirho(
        root_chirho,
        app_chirho,
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        root_chirho,
        app_chirho,
        ROUTE_CHIRHO,
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
    );
    for route_chirho in [None, Some(ROUTE_CHIRHO)] {
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            root_chirho,
            app_chirho,
            route_chirho,
            &owner_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
        )
        .unwrap();
    }
    if guarded_chirho {
        cairn_chirho::app_chirho::set_app_request_access_policy_chirho(
            root_chirho,
            app_chirho,
            &owner_chirho,
            root_dag_chirho,
            cairn_chirho::app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho,
        )
        .unwrap();
    }
}

/// Move a deployed root to a path this process has never read, so its next served read starts with nothing cached. The
/// verified-view cache is process-wide and keyed by root path, and deploying an app reads through it. A root holding a
/// directly deployed app cannot move: measured, its app selection then refuses ("head transition id does not match the
/// canonical unsigned operation tuple"), so those arms read cold in a child process instead (`cold_answer_chirho`).
pub(super) fn unread_root_chirho(root_chirho: &Path) -> PathBuf {
    let unread_chirho = root_chirho.with_file_name(format!(
        "{}-unread-chirho",
        root_chirho.file_name().unwrap().to_string_lossy()
    ));
    std::fs::rename(root_chirho, &unread_chirho).unwrap();
    unread_chirho
}

/// Remove whatever is at `path_chirho`, without following a symlink there.
fn clear_path_chirho(path_chirho: &Path) {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) if metadata_chirho.is_dir() => {
            std::fs::remove_dir_all(path_chirho).unwrap()
        }
        Ok(_) => std::fs::remove_file(path_chirho).unwrap(),
        Err(error_chirho) => assert_eq!(error_chirho.kind(), std::io::ErrorKind::NotFound),
    }
}

/// Put `fault_chirho` at the log's path. `saved_chirho` is the log's bytes when it had any.
pub(super) fn apply_fault_chirho(
    root_chirho: &Path,
    path_chirho: &Path,
    fault_chirho: FaultChirho,
    saved_chirho: Option<&[u8]>,
) {
    clear_path_chirho(path_chirho);
    match fault_chirho {
        FaultChirho::LoopChirho => {
            std::os::unix::fs::symlink(path_chirho.file_name().unwrap(), path_chirho).unwrap()
        }
        FaultChirho::DanglingChirho => {
            std::os::unix::fs::symlink(DANGLING_TARGET_CHIRHO, path_chirho).unwrap()
        }
        FaultChirho::ValidTargetChirho => {
            let elsewhere_chirho = root_chirho.join(ELSEWHERE_DIR_CHIRHO);
            std::fs::create_dir_all(&elsewhere_chirho).unwrap();
            let copy_chirho = elsewhere_chirho.join(path_chirho.file_name().unwrap());
            std::fs::write(&copy_chirho, saved_chirho.unwrap_or_default()).unwrap();
            std::os::unix::fs::symlink(&copy_chirho, path_chirho).unwrap()
        }
        FaultChirho::DirectoryChirho => std::fs::create_dir(path_chirho).unwrap(),
        FaultChirho::FifoChirho => assert!(std::process::Command::new("mkfifo")
            .arg(path_chirho)
            .status()
            .unwrap()
            .success()),
        FaultChirho::UnreadableChirho => {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(path_chirho, saved_chirho.unwrap_or_default()).unwrap();
            std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
            assert_eq!(
                std::fs::File::open(path_chirho).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied,
                "the unreadable fault must actually refuse an open"
            );
        }
    }
}

/// Undo the fault: release any reader stuck on a pipe, then put the log back as it was (its bytes, or absent).
pub(super) fn restore_chirho(
    path_chirho: &Path,
    fault_chirho: FaultChirho,
    saved_chirho: Option<&[u8]>,
) {
    if let FaultChirho::FifoChirho = fault_chirho {
        // A reader blocked opening the pipe is released when a writer opens it, and a writer when a reader does. Each
        // helper opens and closes one end; one left with no partner waits forever and holds nothing the test needs.
        for write_chirho in [true, false] {
            let pipe_chirho = path_chirho.to_path_buf();
            std::thread::spawn(move || {
                let _ = std::fs::OpenOptions::new()
                    .write(write_chirho)
                    .read(!write_chirho)
                    .open(pipe_chirho);
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    clear_path_chirho(path_chirho);
    if let Some(bytes_chirho) = saved_chirho {
        std::fs::write(path_chirho, bytes_chirho).unwrap();
    }
}

/// Drive one served call on its own thread, waiting at most the answer timeout: `None` when no answer came. A handler
/// stuck in a blocking open (a pipe) holds that thread, not the test. A timeout around the call on the test's own
/// thread does not bound it: measured, the access policy's cold pipe case held the test past eleven minutes.
pub(super) fn bounded_call_chirho<T, MakeChirho, CallChirho>(
    runtime_chirho: &tokio::runtime::Runtime,
    make_call_chirho: MakeChirho,
) -> Option<T>
where
    T: Send + 'static,
    MakeChirho: FnOnce() -> CallChirho + Send + 'static,
    CallChirho: std::future::Future<Output = T>,
{
    let handle_chirho = runtime_chirho.handle().clone();
    let (sender_chirho, receiver_chirho) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender_chirho.send(handle_chirho.block_on(make_call_chirho()));
    });
    receiver_chirho.recv_timeout(ANSWER_TIMEOUT_CHIRHO).ok()
}

/// A response's status and whole body.
pub(super) async fn status_and_body_chirho(
    response_chirho: axum::response::Response,
) -> (u16, String) {
    let status_chirho = response_chirho.status().as_u16();
    let bytes_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status_chirho,
        String::from_utf8_lossy(&bytes_chirho).to_string(),
    )
}

const COLD_ROOT_ENV_CHIRHO: &str = "CAIRN_UNEXAMINABLE_COLD_ROOT_CHIRHO";
const COLD_CALL_ENV_CHIRHO: &str = "CAIRN_UNEXAMINABLE_COLD_CALL_CHIRHO";
const COLD_ANSWER_MARK_CHIRHO: &str = "COLD-ANSWER-CHIRHO ";

/// The cold read: a no-op unless `cold_answer_chirho` runs it in a child of this test binary, a process that has read
/// nothing, so its process-wide caches start empty. It prints its one answer and leaves without waiting for a call
/// stuck on a pipe.
#[test]
fn cold_child_answer_chirho() {
    use std::io::Write;
    let Ok(root_chirho) = std::env::var(COLD_ROOT_ENV_CHIRHO) else {
        return;
    };
    let call_chirho = std::env::var(COLD_CALL_ENV_CHIRHO).unwrap();
    let root_chirho = PathBuf::from(root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let answer_chirho = match call_chirho.split_once(':') {
        Some(("get", app_chirho)) => {
            anonymous_get_chirho(&runtime_chirho, &state_chirho, app_chirho)
        }
        Some(("post", needle_chirho)) => {
            post_needle_chirho(&runtime_chirho, &root_chirho, &state_chirho, needle_chirho).0
        }
        _ => panic!("unknown cold call {call_chirho}"),
    };
    println!("{COLD_ANSWER_MARK_CHIRHO}{answer_chirho}");
    std::io::stdout().flush().unwrap();
    std::process::exit(0);
}

/// One served call (`get:<app>` or `post:<needle>`) in a child of this test binary, a process that has read nothing:
/// its answer, or "hung" when the child does not finish in time.
fn cold_answer_chirho(root_chirho: &Path, call_chirho: &str) -> String {
    use std::io::Read;
    let mut child_chirho = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("serve_chirho::tests_chirho::unexaminable_log_tests_chirho::cold_child_answer_chirho")
        .arg("--exact")
        .arg("--nocapture")
        .env(COLD_ROOT_ENV_CHIRHO, root_chirho)
        .env(COLD_CALL_ENV_CHIRHO, call_chirho)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // The child bounds its own call; this bounds the child.
    let deadline_chirho = std::time::Instant::now() + ANSWER_TIMEOUT_CHIRHO * 3;
    while child_chirho.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline_chirho {
            let _ = child_chirho.kill();
            let _ = child_chirho.wait();
            return "hung".to_string();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut output_chirho = String::new();
    child_chirho
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output_chirho)
        .unwrap();
    output_chirho
        .lines()
        .find_map(|line_chirho| line_chirho.strip_prefix(COLD_ANSWER_MARK_CHIRHO))
        .map(str::to_string)
        .unwrap_or_else(|| "no answer from the child".to_string())
}

/// Whether an input-arm answer kept the body private: neither echoed nor at rest, and not hung.
fn private_answer_chirho(answer_chirho: &str) -> bool {
    answer_chirho != "hung"
        && !answer_chirho.contains("[ECHOED PLAINTEXT]")
        && !answer_chirho.contains("[PLAINTEXT AT REST]")
}

/// An anonymous GET of the app's route through the production handler, as "STATUS first-line-of-body", or "hung".
fn anonymous_get_chirho(
    runtime_chirho: &tokio::runtime::Runtime,
    state_chirho: &AppStateChirho,
    app_chirho: &str,
) -> String {
    let state_chirho = state_chirho.clone();
    let app_chirho = app_chirho.to_string();
    let answer_chirho = bounded_call_chirho(runtime_chirho, move || async move {
        let uri_chirho = format!("/app-chirho/{app_chirho}/{ROUTE_CHIRHO}")
            .parse()
            .unwrap();
        status_and_body_chirho(
            app_http_chirho::app_route_get_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                AxPath((app_chirho, ROUTE_CHIRHO.to_string())),
                axum::extract::OriginalUri(uri_chirho),
            )
            .await,
        )
        .await
    });
    match answer_chirho {
        Some((status_chirho, body_chirho)) => format!(
            "{status_chirho} {}",
            body_chirho.lines().next().unwrap_or_default()
        ),
        None => "hung".to_string(),
    }
}

/// One measured case: what it is, what the engine answered, and whether that answer is acceptable.
pub(super) struct CaseChirho {
    pub(super) case_chirho: String,
    pub(super) answer_chirho: String,
    pub(super) acceptable_chirho: bool,
}

/// Print every case, then fail naming every unacceptable one: all outcomes are collected before anything is judged.
pub(super) fn judge_cases_chirho(cases_chirho: &[CaseChirho]) {
    for case_chirho in cases_chirho {
        eprintln!(
            "{} {}: {}",
            if case_chirho.acceptable_chirho {
                "ok  "
            } else {
                "FAIL"
            },
            case_chirho.case_chirho,
            case_chirho.answer_chirho
        );
    }
    let failing_chirho: Vec<&str> = cases_chirho
        .iter()
        .filter(|case_chirho| !case_chirho.acceptable_chirho)
        .map(|case_chirho| case_chirho.case_chirho.as_str())
        .collect();
    assert!(
        failing_chirho.is_empty(),
        "failing cases: {failing_chirho:?}"
    );
}

/// A fault's answer is acceptable only as a prompt refusal: never served, never hung.
fn refused_promptly_chirho(answer_chirho: &str) -> bool {
    answer_chirho != "hung" && !answer_chirho.starts_with('2')
}

/// MEASUREMENT, THEN THE PROPERTY. For every fault kind, three served cases on fresh roots:
/// - cold: the deployed root is moved to a path this process has never read, and the fault is in place before the first
///   served read, so nothing is cached;
/// - warm-present: a signed-in-only app's verified policy is cached (an anonymous visitor gets 401), then the fault;
/// - warm-absent: a root where no app ever set a policy (a genuine absence, so the app is public and answers 200) is
///   cached, then the fault at the absent log's path.
///
/// Each case runs its control before or after: the intact log answers 401, and a restored genuine absence answers 200
/// again. Every outcome is collected before anything is judged, so one run reports every failing case.
///
/// The property: a log the engine cannot examine is refused promptly. It is never served as "no policy", and it never
/// hangs the request.
///
/// MIGRATION PATH: a 2xx on a fault row means an unexaminable log read as "no policy", and no policy is public. On a
/// warm row, that can come from the cache accepting its view before any load. "hung" means the loader opened a pipe for
/// reading. A control row that fails means the fixture, not the engine, is wrong.
#[test]
fn an_access_policy_log_the_engine_cannot_examine_never_reads_as_no_policy_chirho() {
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let mut cases_chirho: Vec<CaseChirho> = Vec::new();
    {
        for fault_chirho in FAULTS_CHIRHO {
            let mut record_chirho =
                |case_chirho: String, answer_chirho: String, acceptable_chirho: bool| {
                    cases_chirho.push(CaseChirho {
                        case_chirho,
                        answer_chirho,
                        acceptable_chirho,
                    })
                };

            // Cold: each read happens in a child process that has read nothing.
            let root_chirho = temp_root_chirho(&format!("unexaminable-cold-{fault_chirho:?}"));
            deploy_app_chirho(&root_chirho, GUARDED_APP_CHIRHO, true);
            let log_chirho = root_chirho.join(ACCESS_LOG_CHIRHO);
            let saved_chirho = std::fs::read(&log_chirho).unwrap();
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
            let get_chirho = format!("get:{GUARDED_APP_CHIRHO}");
            let answer_chirho = cold_answer_chirho(&root_chirho, &get_chirho);
            let acceptable_chirho = refused_promptly_chirho(&answer_chirho);
            record_chirho(
                format!("cold {fault_chirho:?}"),
                answer_chirho,
                acceptable_chirho,
            );
            restore_chirho(&log_chirho, fault_chirho, Some(&saved_chirho));
            let answer_chirho = cold_answer_chirho(&root_chirho, &get_chirho);
            let acceptable_chirho = answer_chirho == REFUSED_ANONYMOUS_CHIRHO;
            record_chirho(
                format!("cold {fault_chirho:?}, restored (control)"),
                answer_chirho,
                acceptable_chirho,
            );
            let _ = std::fs::remove_dir_all(&root_chirho);

            // Warm with a verified-present policy, then the fault.
            let root_chirho = temp_root_chirho(&format!("unexaminable-present-{fault_chirho:?}"));
            deploy_app_chirho(&root_chirho, GUARDED_APP_CHIRHO, true);
            let log_chirho = root_chirho.join(ACCESS_LOG_CHIRHO);
            let saved_chirho = std::fs::read(&log_chirho).unwrap();
            let state_chirho = app_state_for_root_chirho(&root_chirho);
            let answer_chirho =
                anonymous_get_chirho(&runtime_chirho, &state_chirho, GUARDED_APP_CHIRHO);
            let acceptable_chirho = answer_chirho == REFUSED_ANONYMOUS_CHIRHO;
            record_chirho(
                format!("warm-present {fault_chirho:?}, before (control)"),
                answer_chirho,
                acceptable_chirho,
            );
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
            let answer_chirho =
                anonymous_get_chirho(&runtime_chirho, &state_chirho, GUARDED_APP_CHIRHO);
            let acceptable_chirho = refused_promptly_chirho(&answer_chirho);
            record_chirho(
                format!("warm-present {fault_chirho:?}"),
                answer_chirho,
                acceptable_chirho,
            );
            restore_chirho(&log_chirho, fault_chirho, Some(&saved_chirho));
            let answer_chirho =
                anonymous_get_chirho(&runtime_chirho, &state_chirho, GUARDED_APP_CHIRHO);
            let acceptable_chirho = answer_chirho == REFUSED_ANONYMOUS_CHIRHO;
            record_chirho(
                format!("warm-present {fault_chirho:?}, restored (control)"),
                answer_chirho,
                acceptable_chirho,
            );
            let _ = std::fs::remove_dir_all(&root_chirho);

            // Warm with a genuine absence, then the fault at the absent log's path.
            let root_chirho = temp_root_chirho(&format!("unexaminable-absent-{fault_chirho:?}"));
            deploy_app_chirho(&root_chirho, OPEN_APP_CHIRHO, false);
            let log_chirho = root_chirho.join(ACCESS_LOG_CHIRHO);
            assert_eq!(
                std::fs::symlink_metadata(&log_chirho).unwrap_err().kind(),
                std::io::ErrorKind::NotFound,
                "the fixture's absence is genuine"
            );
            let state_chirho = app_state_for_root_chirho(&root_chirho);
            let answer_chirho =
                anonymous_get_chirho(&runtime_chirho, &state_chirho, OPEN_APP_CHIRHO);
            let acceptable_chirho = answer_chirho.starts_with("200");
            record_chirho(
                format!("warm-absent {fault_chirho:?}, before (control)"),
                answer_chirho,
                acceptable_chirho,
            );
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, None);
            let answer_chirho =
                anonymous_get_chirho(&runtime_chirho, &state_chirho, OPEN_APP_CHIRHO);
            let acceptable_chirho = refused_promptly_chirho(&answer_chirho);
            record_chirho(
                format!("warm-absent {fault_chirho:?}"),
                answer_chirho,
                acceptable_chirho,
            );
            restore_chirho(&log_chirho, fault_chirho, None);
            let answer_chirho =
                anonymous_get_chirho(&runtime_chirho, &state_chirho, OPEN_APP_CHIRHO);
            let acceptable_chirho = answer_chirho.starts_with("200");
            record_chirho(
                format!("warm-absent {fault_chirho:?}, restored (control)"),
                answer_chirho,
                acceptable_chirho,
            );
            let _ = std::fs::remove_dir_all(&root_chirho);
        }
    }
    // A request stuck on a pipe must not hold the test open.
    runtime_chirho.shutdown_timeout(Duration::from_secs(2));
    judge_cases_chirho(&cases_chirho);
}

const PRIVATE_APP_CHIRHO: &str = "inbox-chirho";
const INPUT_LOG_CHIRHO: &str = "app-input-policy-records-chirho.jsonl";
/// The marker a private body's run answers with in place of the body.
const PRIVATE_REF_MARKER_CHIRHO: &str = "APP-PRIVATE-INPUT-REF-V1-CHIRHO";

/// A public app whose root takes private input (a fixed inbox subject), or no input policy at all when `private_chirho`
/// is false: a genuine absence of the input policy log on a fresh root.
fn deploy_inbox_chirho(root_chirho: &Path, private_chirho: bool) {
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        root_chirho,
        PRIVATE_APP_CHIRHO,
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    if private_chirho {
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            root_chirho,
            PRIVATE_APP_CHIRHO,
            None,
            &owner_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: format!("app/{PRIVATE_APP_CHIRHO}/inbox"),
                safe_metadata_chirho: Vec::new(),
            },
        )
        .unwrap();
    }
}

/// An anonymous POST of `needle_chirho` to the inbox root, judged for privacy alone: whether its plaintext reached the
/// answer (the upcase guest would echo it uppercased) or any file under the root. Token, admission and run records are
/// not this measure: a refused or private request may still leave them.
fn post_needle_chirho(
    runtime_chirho: &tokio::runtime::Runtime,
    root_chirho: &Path,
    state_chirho: &AppStateChirho,
    needle_chirho: &str,
) -> (String, bool) {
    let state_chirho = state_chirho.clone();
    let body_chirho = format!("{{\"message_chirho\":\"{needle_chirho}\"}}");
    let answer_chirho = bounded_call_chirho(runtime_chirho, move || async move {
        status_and_body_chirho(
            app_post_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                AxPath(PRIVATE_APP_CHIRHO.to_string()),
                Bytes::from(body_chirho),
            )
            .await,
        )
        .await
    });
    let Some((status_chirho, body_chirho)) = answer_chirho else {
        return ("hung".to_string(), false);
    };
    let echoed_chirho = body_chirho.contains(&needle_chirho.to_uppercase());
    let at_rest_chirho = !files_holding_chirho(root_chirho, needle_chirho.as_bytes()).is_empty();
    let shown_chirho = if body_chirho.contains(PRIVATE_REF_MARKER_CHIRHO) {
        "private ref".to_string()
    } else {
        body_chirho
            .lines()
            .next()
            .unwrap_or_default()
            .chars()
            .take(80)
            .collect()
    };
    (
        format!(
            "{status_chirho} {shown_chirho}{}{}",
            if echoed_chirho {
                " [ECHOED PLAINTEXT]"
            } else {
                ""
            },
            if at_rest_chirho {
                " [PLAINTEXT AT REST]"
            } else {
                ""
            }
        ),
        !echoed_chirho && !at_rest_chirho,
    )
}

/// Every file under `root_chirho` whose bytes contain `needle_chirho`, without following symlinks or opening pipes.
fn files_holding_chirho(root_chirho: &Path, needle_chirho: &[u8]) -> Vec<std::path::PathBuf> {
    let mut hits_chirho = Vec::new();
    let mut pending_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = pending_chirho.pop() {
        let Ok(entries_chirho) = std::fs::read_dir(&dir_chirho) else {
            continue;
        };
        for entry_chirho in entries_chirho.flatten() {
            let path_chirho = entry_chirho.path();
            let Ok(metadata_chirho) = std::fs::symlink_metadata(&path_chirho) else {
                continue;
            };
            if metadata_chirho.is_dir() {
                pending_chirho.push(path_chirho);
            } else if metadata_chirho.is_file()
                && std::fs::read(&path_chirho).is_ok_and(|bytes_chirho| {
                    bytes_chirho
                        .windows(needle_chirho.len())
                        .any(|window_chirho| window_chirho == needle_chirho)
                })
            {
                hits_chirho.push(path_chirho);
            }
        }
    }
    hits_chirho
}

/// MEASUREMENT, THEN THE PROPERTY: an input policy log the engine cannot examine never lets a private body be taken as
/// plain. For every fault kind, on fresh roots:
/// - cold: the deployed root is moved to a path this process has never read, and the fault is in place before the first
///   served read;
/// - warm-present: the private policy is verified and cached (a body answers with a private reference), then the fault;
/// - warm-absent: an app that never set an input policy, cached, then the fault at the absent log's path.
///
/// A fault's answer is acceptable only as a private one, refusal or not: never hung, and never with the body's plaintext
/// echoed or at rest. Every outcome is collected before anything is judged. The controls: the intact private policy answers
/// with a private reference, and the genuine absence's own answer is recorded beside its fault's.
///
/// MIGRATION PATH: "[ECHOED PLAINTEXT]" or "[PLAINTEXT AT REST]" on a fault row means an unexaminable input policy log
/// let a private body run as plain; "hung" means the loader opened a pipe for reading.
#[test]
fn an_input_policy_log_the_engine_cannot_examine_never_takes_a_private_body_as_plain_chirho() {
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let mut cases_chirho: Vec<CaseChirho> = Vec::new();
    {
        for fault_chirho in FAULTS_CHIRHO {
            let mut record_chirho =
                |case_chirho: String, answer_chirho: String, acceptable_chirho: bool| {
                    cases_chirho.push(CaseChirho {
                        case_chirho,
                        answer_chirho,
                        acceptable_chirho,
                    })
                };
            let fault_label_chirho = format!("{fault_chirho:?}").to_lowercase();

            // Cold: each read happens in a child process that has read nothing.
            let root_chirho =
                temp_root_chirho(&format!("unexaminable-input-cold-{fault_label_chirho}"));
            deploy_inbox_chirho(&root_chirho, true);
            let log_chirho = root_chirho.join(INPUT_LOG_CHIRHO);
            let saved_chirho = std::fs::read(&log_chirho).unwrap();
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
            let answer_chirho = cold_answer_chirho(
                &root_chirho,
                &format!("post:cold-{fault_label_chirho}-needle"),
            );
            let acceptable_chirho = private_answer_chirho(&answer_chirho);
            record_chirho(
                format!("input cold {fault_chirho:?}"),
                answer_chirho,
                acceptable_chirho,
            );
            restore_chirho(&log_chirho, fault_chirho, Some(&saved_chirho));
            let answer_chirho = cold_answer_chirho(
                &root_chirho,
                &format!("post:cold-control-{fault_label_chirho}-needle"),
            );
            let acceptable_chirho =
                private_answer_chirho(&answer_chirho) && answer_chirho.contains("private ref");
            record_chirho(
                format!("input cold {fault_chirho:?}, restored (control)"),
                answer_chirho,
                acceptable_chirho,
            );
            let _ = std::fs::remove_dir_all(&root_chirho);

            // Warm with the verified private policy, then the fault.
            let root_chirho =
                temp_root_chirho(&format!("unexaminable-input-present-{fault_label_chirho}"));
            deploy_inbox_chirho(&root_chirho, true);
            let log_chirho = root_chirho.join(INPUT_LOG_CHIRHO);
            let saved_chirho = std::fs::read(&log_chirho).unwrap();
            let state_chirho = app_state_for_root_chirho(&root_chirho);
            let (answer_chirho, private_chirho) = post_needle_chirho(
                &runtime_chirho,
                &root_chirho,
                &state_chirho,
                &format!("present-control-{fault_label_chirho}-needle"),
            );
            let acceptable_chirho = private_chirho && answer_chirho.contains("private ref");
            record_chirho(
                format!("input warm-present {fault_chirho:?}, before (control)"),
                answer_chirho,
                acceptable_chirho,
            );
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
            let (answer_chirho, private_chirho) = post_needle_chirho(
                &runtime_chirho,
                &root_chirho,
                &state_chirho,
                &format!("present-{fault_label_chirho}-needle"),
            );
            let acceptable_chirho = private_chirho && answer_chirho != "hung";
            record_chirho(
                format!("input warm-present {fault_chirho:?}"),
                answer_chirho,
                acceptable_chirho,
            );
            restore_chirho(&log_chirho, fault_chirho, Some(&saved_chirho));
            let _ = std::fs::remove_dir_all(&root_chirho);

            // Warm with a genuine absence of any input policy, then the fault.
            let root_chirho =
                temp_root_chirho(&format!("unexaminable-input-absent-{fault_label_chirho}"));
            deploy_inbox_chirho(&root_chirho, false);
            let log_chirho = root_chirho.join(INPUT_LOG_CHIRHO);
            assert_eq!(
                std::fs::symlink_metadata(&log_chirho).unwrap_err().kind(),
                std::io::ErrorKind::NotFound,
                "the fixture's absence is genuine"
            );
            let state_chirho = app_state_for_root_chirho(&root_chirho);
            let (answer_chirho, private_chirho) = post_needle_chirho(
                &runtime_chirho,
                &root_chirho,
                &state_chirho,
                &format!("absent-control-{fault_label_chirho}-needle"),
            );
            // Recorded, not judged: what a genuinely absent input policy does today is the baseline for its fault.
            record_chirho(
                format!("input warm-absent {fault_chirho:?}, before (control, recorded)"),
                format!(
                    "{answer_chirho}{}",
                    if private_chirho { "" } else { " (not private)" }
                ),
                true,
            );
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, None);
            let (answer_chirho, private_chirho) = post_needle_chirho(
                &runtime_chirho,
                &root_chirho,
                &state_chirho,
                &format!("absent-{fault_label_chirho}-needle"),
            );
            let acceptable_chirho = private_chirho && answer_chirho != "hung";
            record_chirho(
                format!("input warm-absent {fault_chirho:?}"),
                answer_chirho,
                acceptable_chirho,
            );
            restore_chirho(&log_chirho, fault_chirho, None);
            let _ = std::fs::remove_dir_all(&root_chirho);
        }
    }
    runtime_chirho.shutdown_timeout(Duration::from_secs(2));
    judge_cases_chirho(&cases_chirho);
}
