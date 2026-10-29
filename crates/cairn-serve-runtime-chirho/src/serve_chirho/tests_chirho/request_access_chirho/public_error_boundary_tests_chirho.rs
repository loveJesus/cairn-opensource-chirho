// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms at the real boundaries of the public error answers (PFE #26446, #26451): each runs in a child process that
//! lowers its own descriptor limit, causes a real failure where the road meets it, and checks the answer; the parent
//! checks the child's server log for the typed witness and for the absence of the bearer, the payload and any path.

use super::*;
use crate::serve_chirho::public_error_chirho::hold_points_chirho::{
    set_hold_chirho, HoldPointChirho,
};
use crate::serve_chirho::public_error_chirho::{
    execution_refusal_plain_body_chirho, fixed_execution_refusal_knowledge_chirho,
};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use cairn_chirho::dag_chirho::refusal_chirho::{
    DagExecutionAttemptOrdinalChirho as AttemptChirho,
    DagExecutionKnowledgeChirho as KnowledgeChirho,
};
use cairn_chirho::durable_chirho::io_error_is_resource_exhaustion_chirho;
use cairn_chirho::effect_chirho::postgres_reversible_chirho::{
    PostgresReversibleExecutionChirho, PostgresReversibleRuntimePortChirho,
};
use std::path::{Path, PathBuf};

const ARM_CHILD_ENV_CHIRHO: &str = "CAIRN_PUBLIC_ERROR_ARM_CHILD_CHIRHO";
const ARM_ROOT_ENV_CHIRHO: &str = "CAIRN_PUBLIC_ERROR_ARM_ROOT_CHIRHO";
const ARM_BEARER_ENV_CHIRHO: &str = "CAIRN_PUBLIC_ERROR_ARM_BEARER_CHIRHO";
const PAYLOAD_NEEDLE_CHIRHO: &str = "public_error_payload_needle_chirho";
const ENTRY_NEEDLE_CHIRHO: &str = "public_error_entry_needle_chirho";
const ANONYMOUS_APP_CHIRHO: &str = "error-arm";
const WITNESS_PREFIX_CHIRHO: &str = "CairnPublicErrorChirho:";

// ---- the child process -------------------------------------------------------------------------------------------

fn in_arm_child_chirho() -> bool {
    std::env::var_os(ARM_CHILD_ENV_CHIRHO).is_some()
}

fn arm_root_chirho() -> PathBuf {
    PathBuf::from(std::env::var_os(ARM_ROOT_ENV_CHIRHO).expect("the arm root"))
}

fn arm_bearer_headers_chirho() -> HeaderMap {
    let bearer_chirho = std::env::var(ARM_BEARER_ENV_CHIRHO).expect("the arm bearer");
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {bearer_chirho}").parse().unwrap(),
    );
    headers_chirho
}

/// Runs one arm of this module in a child whose own descriptor limit is lowered (never this process's, never the
/// system's), and returns the child's server log, its stderr. The child's assertions decide its exit status.
fn run_arm_in_child_chirho(
    arm_chirho: &str,
    root_chirho: &Path,
    bearer_chirho: Option<&str>,
) -> String {
    let module_chirho = module_path!().split_once("::").expect("crate prefix").1;
    let test_name_chirho = format!("{module_chirho}::{arm_chirho}");
    let mut command_chirho = std::process::Command::new("/bin/sh");
    command_chirho
        .arg("-c")
        .arg("ulimit -n 256 && exec \"$0\" \"$@\"")
        .arg(std::env::current_exe().unwrap())
        .args([
            test_name_chirho.as_str(),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ARM_CHILD_ENV_CHIRHO, "1")
        .env(ARM_ROOT_ENV_CHIRHO, root_chirho);
    if let Some(bearer_chirho) = bearer_chirho {
        command_chirho.env(ARM_BEARER_ENV_CHIRHO, bearer_chirho);
    }
    let output_chirho = command_chirho.output().unwrap();
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr).into_owned();
    assert!(
        output_chirho.status.success(),
        "the child arm failed:\n{stdout_chirho}\n{stderr_chirho}"
    );
    assert!(
        stdout_chirho.contains("1 passed"),
        "the child ran exactly the arm: {stdout_chirho}"
    );
    stderr_chirho
}

// ---- real descriptor exhaustion, inside the child ------------------------------------------------------------------

static HELD_DESCRIPTORS_CHIRHO: std::sync::Mutex<Vec<std::fs::File>> =
    std::sync::Mutex::new(Vec::new());

/// Opens /dev/null until the process is out of descriptors, holding every one; only an exhaustion may stop it.
fn exhaust_descriptors_chirho() {
    let mut held_chirho = HELD_DESCRIPTORS_CHIRHO.lock().unwrap();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file_chirho) => held_chirho.push(file_chirho),
            Err(error_chirho) => {
                assert!(
                    io_error_is_resource_exhaustion_chirho(&error_chirho),
                    "only an exhaustion may stop the fill: {error_chirho}"
                );
                break;
            }
        }
        assert!(
            held_chirho.len() < 4096,
            "the child's limit was not lowered"
        );
    }
}

fn release_descriptors_chirho() {
    HELD_DESCRIPTORS_CHIRHO.lock().unwrap().clear();
}

// ---- answers and logs ----------------------------------------------------------------------------------------------

struct ArmAnswerChirho {
    status_chirho: StatusCode,
    content_type_chirho: Option<String>,
    retry_after_chirho: bool,
    body_chirho: String,
}

async fn arm_answer_chirho(response_chirho: axum::response::Response) -> ArmAnswerChirho {
    let status_chirho = response_chirho.status();
    let content_type_chirho = response_chirho
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .map(str::to_string);
    let retry_after_chirho = response_chirho.headers().contains_key(RETRY_AFTER);
    let bytes_chirho = axum::body::to_bytes(response_chirho.into_body(), 64 * 1024)
        .await
        .unwrap();
    ArmAnswerChirho {
        status_chirho,
        content_type_chirho,
        retry_after_chirho,
        body_chirho: String::from_utf8_lossy(&bytes_chirho).into_owned(),
    }
}

/// Neither a body nor a log may carry a root, a tenant, a refs or lock name, OS text, the payload or the entry.
fn assert_free_of_detail_chirho(label_chirho: &str, text_chirho: &str, root_chirho: &Path) {
    let root_name_chirho = root_chirho
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    for needle_chirho in [
        root_chirho.to_string_lossy().as_ref(),
        root_name_chirho.as_str(),
        "refs-chirho.json",
        "tenants-chirho",
        "locks-chirho",
        "os error",
        "Too many open files",
        PAYLOAD_NEEDLE_CHIRHO,
        ENTRY_NEEDLE_CHIRHO,
    ] {
        assert!(
            !text_chirho.contains(needle_chirho),
            "{label_chirho} carries '{needle_chirho}': {text_chirho}"
        );
    }
}

fn witness_lines_chirho(log_chirho: &str) -> Vec<&str> {
    log_chirho
        .lines()
        .filter(|line_chirho| line_chirho.starts_with(WITNESS_PREFIX_CHIRHO))
        .collect()
}

/// A pre-run resource witness at `site_chirho`, whose OS code is itself a typed resource exhaustion.
fn assert_resource_witness_chirho(line_chirho: &str, site_chirho: &str) {
    let prefix_chirho = format!(
        "{WITNESS_PREFIX_CHIRHO}site_chirho={site_chirho}:class_chirho=pre-run-resource-chirho:os_code_chirho="
    );
    let code_chirho: i32 = line_chirho
        .strip_prefix(&prefix_chirho)
        .unwrap_or_else(|| panic!("not a resource witness at {site_chirho}: {line_chirho}"))
        .parse()
        .unwrap();
    assert!(io_error_is_resource_exhaustion_chirho(
        &std::io::Error::from_raw_os_error(code_chirho)
    ));
}

fn assert_no_runs_chirho(root_chirho: &Path) {
    let runs_chirho = root_chirho.join("runs-chirho");
    assert!(
        !runs_chirho.exists() || std::fs::read_dir(&runs_chirho).unwrap().next().is_none(),
        "a pre-run refusal records no run"
    );
}

// ---- fixtures ------------------------------------------------------------------------------------------------------

/// An anonymous app with plain input whose node's entry is `entry_chirho`.
fn anonymous_app_root_chirho(label_chirho: &str, entry_chirho: &str) -> PathBuf {
    let root_chirho = temp_root_chirho(label_chirho);
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        ANONYMOUS_APP_CHIRHO,
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        entry_chirho,
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        ANONYMOUS_APP_CHIRHO,
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    root_chirho
}

fn bearer_of_chirho(headers_chirho: &HeaderMap) -> String {
    headers_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_string()
}

async fn post_anonymous_app_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: HeaderMap,
) -> ArmAnswerChirho {
    arm_answer_chirho(
        app_post_chirho(
            State(state_chirho.clone()),
            None,
            headers_chirho,
            AxPath(ANONYMOUS_APP_CHIRHO.to_string()),
            Bytes::from_static(PAYLOAD_NEEDLE_CHIRHO.as_bytes()),
        )
        .await,
    )
    .await
}

// ---- pre-run: a real resource exhaustion at the refs read ----------------------------------------------------------

#[test]
fn a_refs_read_out_of_descriptors_is_a_pre_run_503_with_no_detail_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for json_chirho in [false, true] {
                set_hold_chirho(
                    HoldPointChirho::BeforeAppRefsReadChirho,
                    exhaust_descriptors_chirho,
                );
                let mut headers_chirho = HeaderMap::new();
                if json_chirho {
                    headers_chirho.insert(ACCEPT, "application/json".parse().unwrap());
                }
                let answer_chirho = post_anonymous_app_chirho(&state_chirho, headers_chirho).await;
                release_descriptors_chirho();
                assert_eq!(
                    answer_chirho.status_chirho,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "{}",
                    answer_chirho.body_chirho
                );
                assert!(
                    !answer_chirho.retry_after_chirho,
                    "no answer authorizes a retry"
                );
                assert_free_of_detail_chirho("the body", &answer_chirho.body_chirho, &root_chirho);
                if json_chirho {
                    assert_eq!(
                        answer_chirho.content_type_chirho.as_deref(),
                        Some("application/json")
                    );
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&answer_chirho.body_chirho)
                            .unwrap(),
                        serde_json::json!({
                            "ok_chirho": false,
                            "error_chirho": "served-request-pre-run-unavailable-chirho",
                            "boundary_chirho": "pre-run-chirho",
                        })
                    );
                } else {
                    assert!(answer_chirho
                        .body_chirho
                        .starts_with("error: served-request-pre-run-unavailable-chirho\n"));
                    assert!(answer_chirho.body_chirho.contains("DAG was not started"));
                }
            }
        });
        return;
    }
    let root_chirho = anonymous_app_root_chirho("pre-run-refs-arm", "upcase_chirho");
    let log_chirho = run_arm_in_child_chirho(
        "a_refs_read_out_of_descriptors_is_a_pre_run_503_with_no_detail_chirho",
        &root_chirho,
        None,
    );
    let witnesses_chirho = witness_lines_chirho(&log_chirho);
    assert_eq!(witnesses_chirho.len(), 2, "{log_chirho}");
    for witness_chirho in witnesses_chirho {
        assert_resource_witness_chirho(witness_chirho, "app-refs-load-chirho");
    }
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    assert_no_runs_chirho(&root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_refs_read_out_of_descriptors_with_a_bearer_keeps_its_token_use_chirho() {
    use super::scoped_token_metering_tests_chirho::{
        metered_route_fixture_chirho, scoped_token_uses_chirho, METERED_APP_CHIRHO,
        METERED_ROUTE_CHIRHO,
    };
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            set_hold_chirho(
                HoldPointChirho::BeforeAppRefsReadChirho,
                exhaust_descriptors_chirho,
            );
            let response_chirho = app_route_post_chirho(
                State(state_chirho.clone()),
                None,
                arm_bearer_headers_chirho(),
                AxPath((
                    METERED_APP_CHIRHO.to_string(),
                    METERED_ROUTE_CHIRHO.to_string(),
                )),
                Bytes::from_static(PAYLOAD_NEEDLE_CHIRHO.as_bytes()),
            )
            .await;
            release_descriptors_chirho();
            let answer_chirho = arm_answer_chirho(response_chirho).await;
            assert_eq!(
                answer_chirho.status_chirho,
                StatusCode::SERVICE_UNAVAILABLE,
                "{}",
                answer_chirho.body_chirho
            );
            assert!(answer_chirho
                .body_chirho
                .contains("a use of an access token, may already be kept"));
            assert_free_of_detail_chirho("the body", &answer_chirho.body_chirho, &root_chirho);
        });
        return;
    }
    let (root_chirho, headers_chirho) = metered_route_fixture_chirho("pre-run-bearer-arm", 5);
    let bearer_chirho = bearer_of_chirho(&headers_chirho);
    let uses_before_chirho = scoped_token_uses_chirho(&root_chirho);
    let log_chirho = run_arm_in_child_chirho(
        "a_refs_read_out_of_descriptors_with_a_bearer_keeps_its_token_use_chirho",
        &root_chirho,
        Some(&bearer_chirho),
    );
    // The guidance says a token use may already be kept: on this road the use is recorded before the refs read.
    assert_eq!(
        scoped_token_uses_chirho(&root_chirho),
        uses_before_chirho + 1
    );
    let witnesses_chirho = witness_lines_chirho(&log_chirho);
    assert_eq!(witnesses_chirho.len(), 1, "{log_chirho}");
    assert_resource_witness_chirho(witnesses_chirho[0], "app-refs-load-chirho");
    assert!(
        !log_chirho.contains(&bearer_chirho),
        "the log carries no bearer"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    assert_no_runs_chirho(&root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ---- non-resource redaction controls -------------------------------------------------------------------------------

#[test]
fn refs_replaced_by_a_directory_is_a_redacted_500_not_capacity_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        let refs_chirho = root_chirho.join("refs-chirho.json");
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            set_hold_chirho(HoldPointChirho::BeforeAppRefsReadChirho, move || {
                std::fs::remove_file(&refs_chirho).unwrap();
                std::fs::create_dir(&refs_chirho).unwrap();
            });
            let answer_chirho = post_anonymous_app_chirho(&state_chirho, HeaderMap::new()).await;
            assert_eq!(
                answer_chirho.status_chirho,
                StatusCode::INTERNAL_SERVER_ERROR
            );
            assert_eq!(
                answer_chirho.body_chirho,
                "error: served-request-internal-error-chirho\n"
            );
        });
        return;
    }
    let root_chirho = anonymous_app_root_chirho("refs-directory-arm", "upcase_chirho");
    let log_chirho = run_arm_in_child_chirho(
        "refs_replaced_by_a_directory_is_a_redacted_500_not_capacity_chirho",
        &root_chirho,
        None,
    );
    assert_eq!(
        witness_lines_chirho(&log_chirho),
        vec!["CairnPublicErrorChirho:site_chirho=app-refs-load-chirho:class_chirho=fixed-refusal-chirho:status_chirho=500:identity_chirho=served-request-internal-error-chirho"],
        "{log_chirho}"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_signing_lock_that_cannot_open_is_a_fixed_403_on_the_bearer_road_chirho() {
    use super::scoped_token_metering_tests_chirho::{
        metered_route_fixture_chirho, scoped_token_uses_chirho, METERED_APP_CHIRHO,
        METERED_ROUTE_CHIRHO,
    };
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let response_chirho = app_route_post_chirho(
                State(state_chirho.clone()),
                None,
                arm_bearer_headers_chirho(),
                AxPath((
                    METERED_APP_CHIRHO.to_string(),
                    METERED_ROUTE_CHIRHO.to_string(),
                )),
                Bytes::from_static(PAYLOAD_NEEDLE_CHIRHO.as_bytes()),
            )
            .await;
            let answer_chirho = arm_answer_chirho(response_chirho).await;
            assert_eq!(answer_chirho.status_chirho, StatusCode::FORBIDDEN);
            assert_eq!(
                answer_chirho.body_chirho,
                "error: request-not-authorized-chirho\n"
            );
        });
        return;
    }
    let (root_chirho, headers_chirho) = metered_route_fixture_chirho("signing-lock-arm", 5);
    let bearer_chirho = bearer_of_chirho(&headers_chirho);
    let uses_before_chirho = scoped_token_uses_chirho(&root_chirho);
    // The bearer's validation opens the instance signing key's lock first: a directory there cannot be opened.
    let lock_chirho = root_chirho.join("locks-chirho").join(format!(
        "{}.lock",
        blake3::hash(b"signing-key-chirho").to_hex()
    ));
    let _ = std::fs::remove_file(&lock_chirho);
    std::fs::create_dir_all(&lock_chirho).unwrap();
    let log_chirho = run_arm_in_child_chirho(
        "a_signing_lock_that_cannot_open_is_a_fixed_403_on_the_bearer_road_chirho",
        &root_chirho,
        Some(&bearer_chirho),
    );
    std::fs::remove_dir(&lock_chirho).unwrap();
    assert_eq!(
        scoped_token_uses_chirho(&root_chirho),
        uses_before_chirho,
        "the refusal precedes the token use"
    );
    assert_eq!(
        witness_lines_chirho(&log_chirho),
        vec!["CairnPublicErrorChirho:site_chirho=app-request-context-chirho:class_chirho=fixed-refusal-chirho:status_chirho=403:identity_chirho=request-not-authorized-chirho"],
        "{log_chirho}"
    );
    assert!(
        !log_chirho.contains(&bearer_chirho),
        "the log carries no bearer"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_unknown_app_is_a_404_that_does_not_echo_its_name_chirho() {
    const NAME_NEEDLE_CHIRHO: &str = "unknown-app-needle-chirho";
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let response_chirho = app_post_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                AxPath(NAME_NEEDLE_CHIRHO.to_string()),
                Bytes::from_static(PAYLOAD_NEEDLE_CHIRHO.as_bytes()),
            )
            .await;
            let answer_chirho = arm_answer_chirho(response_chirho).await;
            assert_eq!(
                answer_chirho.status_chirho,
                StatusCode::NOT_FOUND,
                "{}",
                answer_chirho.body_chirho
            );
            assert_eq!(answer_chirho.body_chirho, "error: app-not-found-chirho\n");
        });
        return;
    }
    // A server with an app deployed, asked for one it does not have. (A bare root refuses earlier, at the write
    // relay, with its own fixed identity; that is not this road.)
    let root_chirho = anonymous_app_root_chirho("unknown-app-arm", "upcase_chirho");
    let log_chirho = run_arm_in_child_chirho(
        "an_unknown_app_is_a_404_that_does_not_echo_its_name_chirho",
        &root_chirho,
        None,
    );
    assert_eq!(
        witness_lines_chirho(&log_chirho),
        vec!["CairnPublicErrorChirho:site_chirho=app-selection-chirho:class_chirho=fixed-refusal-chirho:status_chirho=404:identity_chirho=app-not-found-chirho"],
        "{log_chirho}"
    );
    assert!(
        !log_chirho.contains(NAME_NEEDLE_CHIRHO),
        "the log echoes no name"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_safe_metadata_refusal_names_itself_without_the_value_chirho() {
    const VALUE_NEEDLE_CHIRHO: &str = "johnsmithneedle_chirho";
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut headers_chirho = HeaderMap::new();
            headers_chirho.insert(
                CONTENT_TYPE,
                "application/x-www-form-urlencoded".parse().unwrap(),
            );
            let response_chirho = app_post_chirho(
                State(state_chirho),
                None,
                headers_chirho,
                AxPath(ANONYMOUS_APP_CHIRHO.to_string()),
                Bytes::from(format!(
                    "request_kind_chirho={VALUE_NEEDLE_CHIRHO}&prayer_chirho=Help"
                )),
            )
            .await;
            let answer_chirho = arm_answer_chirho(response_chirho).await;
            assert_eq!(answer_chirho.status_chirho, StatusCode::BAD_REQUEST);
            assert_eq!(
                answer_chirho.body_chirho,
                "error: safe-metadata-value-not-allowed-chirho\n"
            );
        });
        return;
    }
    let root_chirho = anonymous_app_root_chirho("safe-metadata-arm", "upcase_chirho");
    let owner_chirho =
        cairn_chirho::app_chirho::verified_app_owner_chirho(&root_chirho, ANONYMOUS_APP_CHIRHO)
            .unwrap()
            .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        ANONYMOUS_APP_CHIRHO,
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: format!("app/{ANONYMOUS_APP_CHIRHO}/private-input"),
            safe_metadata_chirho: vec![
                cairn_chirho::app_chirho::AppPrivateInputSafeMetadataChirho {
                    key_chirho:
                        cairn_chirho::app_chirho::APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO
                            .to_string(),
                    allowed_values_chirho: vec!["visit_chirho".to_string()],
                },
            ],
        },
    )
    .unwrap();
    let log_chirho = run_arm_in_child_chirho(
        "a_safe_metadata_refusal_names_itself_without_the_value_chirho",
        &root_chirho,
        None,
    );
    assert_eq!(
        witness_lines_chirho(&log_chirho),
        vec!["CairnPublicErrorChirho:site_chirho=app-input-chirho:class_chirho=fixed-refusal-chirho:status_chirho=400:identity_chirho=safe-metadata-value-not-allowed-chirho"],
        "{log_chirho}"
    );
    assert!(!log_chirho.contains("johnsmith"), "the log echoes no value");
    assert!(
        !root_chirho
            .join("privacy-blob-records-chirho.jsonl")
            .exists(),
        "a refused value seals no private blob"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ---- execution: the trusted observation, never a capacity answer ---------------------------------------------------

#[test]
fn a_pre_effect_refusal_says_its_effects_did_not_run_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let answer_chirho = post_anonymous_app_chirho(&state_chirho, HeaderMap::new()).await;
            assert_eq!(answer_chirho.status_chirho, StatusCode::BAD_REQUEST);
            assert_eq!(
                answer_chirho.body_chirho,
                execution_refusal_plain_body_chirho(
                    KnowledgeChirho::DefinitelyNotExecutedChirho,
                    AttemptChirho::FirstChirho,
                )
            );
        });
        return;
    }
    let root_chirho = anonymous_app_root_chirho("pre-effect-arm", ENTRY_NEEDLE_CHIRHO);
    let log_chirho = run_arm_in_child_chirho(
        "a_pre_effect_refusal_says_its_effects_did_not_run_chirho",
        &root_chirho,
        None,
    );
    assert_eq!(
        witness_lines_chirho(&log_chirho),
        vec!["CairnPublicErrorChirho:site_chirho=app-execution-chirho:class_chirho=execution-refusal-chirho:identity_chirho=DagPreEffectRefusedChirho:knowledge_chirho=definitely-not-executed-chirho:attempt_chirho=first-chirho"],
        "{log_chirho}"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_failed_attempt_sent_again_is_a_failed_replay_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let first_chirho = post_anonymous_app_chirho(&state_chirho, HeaderMap::new()).await;
            let again_chirho = post_anonymous_app_chirho(&state_chirho, HeaderMap::new()).await;
            assert_eq!(first_chirho.status_chirho, StatusCode::BAD_REQUEST);
            assert_eq!(again_chirho.status_chirho, StatusCode::BAD_REQUEST);
            // A failed replay is never flattened into a fresh attempt.
            assert_eq!(
                again_chirho.body_chirho,
                execution_refusal_plain_body_chirho(
                    KnowledgeChirho::PriorAttemptFailedChirho,
                    AttemptChirho::FailedReplayChirho,
                ),
                "first: {}",
                first_chirho.body_chirho
            );
        });
        return;
    }
    let root_chirho = anonymous_app_root_chirho("failed-replay-arm", ENTRY_NEEDLE_CHIRHO);
    let log_chirho = run_arm_in_child_chirho(
        "a_failed_attempt_sent_again_is_a_failed_replay_chirho",
        &root_chirho,
        None,
    );
    let witnesses_chirho = witness_lines_chirho(&log_chirho);
    assert_eq!(witnesses_chirho.len(), 2, "{log_chirho}");
    assert!(
        witnesses_chirho[1].ends_with(
            ":knowledge_chirho=prior-attempt-failed-chirho:attempt_chirho=failed-replay-chirho"
        ),
        "{log_chirho}"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// An effect provider whose own connection open meets a real descriptor exhaustion, after the effect began.
struct ExhaustedProviderChirho;

impl PostgresReversibleRuntimePortChirho for ExhaustedProviderChirho {
    fn execute_chirho(
        &mut self,
        _execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        exhaust_descriptors_chirho();
        let error_chirho = std::fs::File::open("/dev/null")
            .expect_err("the provider's open must meet the exhausted limit");
        release_descriptors_chirho();
        assert!(io_error_is_resource_exhaustion_chirho(&error_chirho));
        Err(anyhow::Error::new(error_chirho).context("arm provider could not open its connection"))
    }
}

#[test]
fn a_resource_failure_inside_an_effect_may_have_executed_and_is_never_503_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let provider_chirho =
            SharedLedgerHostPostgresEffectRuntimeChirho::from_runtime_for_test_chirho(Box::new(
                ExhaustedProviderChirho,
            ));
        let state_chirho =
            crate::serve_chirho::app_state_for_runtime_root_with_effect_runtime_chirho(
                &root_chirho,
                crate::serve_chirho::RuntimeAppStateOptionsChirho {
                    inflight_limit_chirho: 8,
                    auth_tokens_chirho: crate::serve_chirho::ServeAuthTokensChirho::default(),
                    domain_routing_enabled_chirho: false,
                    served_request_limits_chirho: ServedRequestAbuseLimitsChirho::default(),
                    projection_read_chirho: None,
                    postgres_effect_chirho: Some(provider_chirho),
                    llm_served_chirho: None,
                    write_dispatch_chirho: None,
                    local_read_authority_chirho: None,
                    write_destination_slot_chirho: None,
                },
            )
            .unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let response_chirho = app_post_chirho(
                State(state_chirho),
                None,
                arm_bearer_headers_chirho(),
                AxPath("blocking-dispatch-app-chirho".to_string()),
                Bytes::from_static(PAYLOAD_NEEDLE_CHIRHO.as_bytes()),
            )
            .await;
            let answer_chirho = arm_answer_chirho(response_chirho).await;
            assert_eq!(
                answer_chirho.status_chirho,
                StatusCode::BAD_REQUEST,
                "never 503 once the run began: {}",
                answer_chirho.body_chirho
            );
            assert_eq!(
                fixed_execution_refusal_knowledge_chirho(&answer_chirho.body_chirho),
                Some(KnowledgeChirho::MayHaveExecutedChirho),
                "{}",
                answer_chirho.body_chirho
            );
            assert_free_of_detail_chirho("the body", &answer_chirho.body_chirho, &root_chirho);
        });
        return;
    }
    let root_chirho = temp_root_chirho("effect-resource-arm");
    let (_dag_chirho, context_chirho, bearer_chirho) =
        super::ledger_host_runtime_tests_chirho::blocking_dispatch_fixture_with_bearer_chirho(
            &root_chirho,
        );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        &context_chirho.app_chirho,
        None,
        &context_chirho.owner_principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let log_chirho = run_arm_in_child_chirho(
        "a_resource_failure_inside_an_effect_may_have_executed_and_is_never_503_chirho",
        &root_chirho,
        Some(&bearer_chirho),
    );
    let witnesses_chirho = witness_lines_chirho(&log_chirho);
    assert_eq!(witnesses_chirho.len(), 1, "{log_chirho}");
    assert!(
        witnesses_chirho[0].starts_with(
            "CairnPublicErrorChirho:site_chirho=app-execution-chirho:class_chirho=execution-refusal-chirho:"
        ) && witnesses_chirho[0].contains(":knowledge_chirho=may-have-executed-chirho:"),
        "{log_chirho}"
    );
    assert!(
        !log_chirho.contains(&bearer_chirho),
        "the log carries no bearer"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_ssr_run_out_of_descriptors_is_an_execution_refusal_never_503_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            set_hold_chirho(
                HoldPointChirho::BeforeSsrRunChirho,
                exhaust_descriptors_chirho,
            );
            let response_chirho = crate::serve_chirho::ssr_web_chirho::ssr_get_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                AxPath(ANONYMOUS_APP_CHIRHO.to_string()),
            )
            .await;
            release_descriptors_chirho();
            let answer_chirho = arm_answer_chirho(response_chirho).await;
            assert_eq!(
                answer_chirho.status_chirho,
                StatusCode::BAD_REQUEST,
                "the run began, so never 503: {}",
                answer_chirho.body_chirho
            );
            assert!(
                fixed_execution_refusal_knowledge_chirho(&answer_chirho.body_chirho).is_some(),
                "{}",
                answer_chirho.body_chirho
            );
            assert_free_of_detail_chirho("the body", &answer_chirho.body_chirho, &root_chirho);
        });
        return;
    }
    let root_chirho = anonymous_app_root_chirho("ssr-run-arm", "upcase_chirho");
    let log_chirho = run_arm_in_child_chirho(
        "an_ssr_run_out_of_descriptors_is_an_execution_refusal_never_503_chirho",
        &root_chirho,
        None,
    );
    let witnesses_chirho = witness_lines_chirho(&log_chirho);
    assert_eq!(witnesses_chirho.len(), 1, "{log_chirho}");
    assert!(
        witnesses_chirho[0].starts_with(
            "CairnPublicErrorChirho:site_chirho=ssr-execution-chirho:class_chirho=execution-refusal-chirho:"
        ),
        "{log_chirho}"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ---- the request-access policy read (PFE #26466) -------------------------------------------------------------------

const PROTECTED_APP_CHIRHO: &str = "protected-chirho";
const PROTECTED_ROUTE_CHIRHO: &str = "change-chirho";
const ACCESS_RECORDS_FILE_CHIRHO: &str = "app-request-access-policy-records-chirho.jsonl";

/// An app whose route accepts a body, with a signed Authenticated request-access policy, so the policy read opens its
/// records file and the refusal must come before the body is read.
fn protected_route_root_chirho(label_chirho: &str) -> PathBuf {
    let root_chirho = temp_root_chirho(label_chirho);
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let wasm_chirho = include_str!("../../../../../../examples-chirho/upcase-chirho.wat");
    let root_dag_chirho = deploy_transform_app_for_owner_chirho(
        &root_chirho,
        PROTECTED_APP_CHIRHO,
        &owner_chirho,
        wasm_chirho,
        "upcase_chirho",
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        PROTECTED_APP_CHIRHO,
        PROTECTED_ROUTE_CHIRHO,
        &owner_chirho,
        wasm_chirho,
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
    );
    for route_chirho in [None, Some(PROTECTED_ROUTE_CHIRHO)] {
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            PROTECTED_APP_CHIRHO,
            route_chirho,
            &owner_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
        )
        .unwrap();
    }
    cairn_chirho::app_chirho::set_app_request_access_policy_chirho(
        &root_chirho,
        PROTECTED_APP_CHIRHO,
        &owner_chirho,
        root_dag_chirho,
        cairn_chirho::app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho,
    )
    .unwrap();
    root_chirho
}

/// The route POST a visitor makes, with a body that records whether it was ever read.
async fn post_protected_route_chirho(
    state_chirho: &AppStateChirho,
    polled_chirho: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> ArmAnswerChirho {
    arm_answer_chirho(
        app_route_post_request_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath((
                PROTECTED_APP_CHIRHO.to_string(),
                PROTECTED_ROUTE_CHIRHO.to_string(),
            )),
            super::request_access_policy_tests_chirho::observed_request_chirho(polled_chirho),
        )
        .await,
    )
    .await
}

#[test]
fn a_request_access_policy_read_out_of_descriptors_is_a_pre_run_503_before_the_body_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            set_hold_chirho(
                HoldPointChirho::BeforeRequestAccessPolicyReadChirho,
                exhaust_descriptors_chirho,
            );
            let polled_chirho = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let answer_chirho =
                post_protected_route_chirho(&state_chirho, polled_chirho.clone()).await;
            release_descriptors_chirho();
            assert_eq!(
                answer_chirho.status_chirho,
                StatusCode::SERVICE_UNAVAILABLE,
                "{}",
                answer_chirho.body_chirho
            );
            assert!(answer_chirho
                .body_chirho
                .starts_with("error: served-request-pre-run-unavailable-chirho\n"));
            assert!(
                !answer_chirho.retry_after_chirho,
                "no answer authorizes a retry"
            );
            assert!(
                !polled_chirho.load(std::sync::atomic::Ordering::SeqCst),
                "the policy refusal comes before the body is read"
            );
            assert_free_of_detail_chirho("the body", &answer_chirho.body_chirho, &root_chirho);
        });
        return;
    }
    let root_chirho = protected_route_root_chirho("access-policy-resource-arm");
    let log_chirho = run_arm_in_child_chirho(
        "a_request_access_policy_read_out_of_descriptors_is_a_pre_run_503_before_the_body_chirho",
        &root_chirho,
        None,
    );
    let witnesses_chirho = witness_lines_chirho(&log_chirho);
    assert_eq!(witnesses_chirho.len(), 1, "{log_chirho}");
    assert_resource_witness_chirho(witnesses_chirho[0], "app-request-access-chirho");
    assert!(
        !log_chirho.contains(ACCESS_RECORDS_FILE_CHIRHO),
        "no chain in the log: {log_chirho}"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    assert_no_runs_chirho(&root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_tampered_request_access_policy_is_a_fixed_500_before_the_body_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            // The route POST checks the policy before its body; the app POST checks it with its request context.
            let polled_chirho = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let route_chirho =
                post_protected_route_chirho(&state_chirho, polled_chirho.clone()).await;
            let app_chirho = arm_answer_chirho(
                app_post_chirho(
                    State(state_chirho.clone()),
                    None,
                    HeaderMap::new(),
                    AxPath(PROTECTED_APP_CHIRHO.to_string()),
                    Bytes::from_static(PAYLOAD_NEEDLE_CHIRHO.as_bytes()),
                )
                .await,
            )
            .await;
            for answer_chirho in [&route_chirho, &app_chirho] {
                assert_eq!(
                    answer_chirho.status_chirho,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an integrity failure is not capacity: {}",
                    answer_chirho.body_chirho
                );
                assert_eq!(
                    answer_chirho.body_chirho,
                    "error: served-request-internal-error-chirho\n"
                );
                assert!(!answer_chirho.retry_after_chirho);
            }
            assert!(
                !polled_chirho.load(std::sync::atomic::Ordering::SeqCst),
                "the policy refusal comes before the body is read"
            );
        });
        return;
    }
    let root_chirho = protected_route_root_chirho("access-policy-tamper-arm");
    // A signed field changed without re-signing: the verifier refuses the record.
    let records_path_chirho = root_chirho.join(ACCESS_RECORDS_FILE_CHIRHO);
    let mut records_chirho =
        cairn_chirho::app_chirho::load_app_request_access_policy_records_chirho(&root_chirho)
            .unwrap();
    records_chirho[0].at_ms_chirho = 1;
    write_jsonl_rows_chirho(&records_path_chirho, &records_chirho);
    assert_verifier_names_chirho(
        cairn_chirho::app_chirho::verify_app_request_access_policies_chirho(&root_chirho)
            .map(|_count_chirho| ()),
        "signature",
    );
    let log_chirho = run_arm_in_child_chirho(
        "a_tampered_request_access_policy_is_a_fixed_500_before_the_body_chirho",
        &root_chirho,
        None,
    );
    let witness_chirho = "CairnPublicErrorChirho:site_chirho=app-request-access-chirho:class_chirho=fixed-refusal-chirho:status_chirho=500:identity_chirho=served-request-internal-error-chirho";
    assert_eq!(
        witness_lines_chirho(&log_chirho),
        vec![witness_chirho, witness_chirho],
        "{log_chirho}"
    );
    for needle_chirho in [ACCESS_RECORDS_FILE_CHIRHO, "signature", "unavailable"] {
        assert!(
            !log_chirho.contains(needle_chirho),
            "the log carries '{needle_chirho}': {log_chirho}"
        );
    }
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_undeployed_app_with_a_leftover_access_policy_is_a_404_without_its_name_chirho() {
    if in_arm_child_chirho() {
        let root_chirho = arm_root_chirho();
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let polled_chirho = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let route_chirho =
                post_protected_route_chirho(&state_chirho, polled_chirho.clone()).await;
            let app_chirho = arm_answer_chirho(
                app_post_chirho(
                    State(state_chirho.clone()),
                    None,
                    HeaderMap::new(),
                    AxPath(PROTECTED_APP_CHIRHO.to_string()),
                    Bytes::from_static(PAYLOAD_NEEDLE_CHIRHO.as_bytes()),
                )
                .await,
            )
            .await;
            for answer_chirho in [&route_chirho, &app_chirho] {
                assert_eq!(
                    answer_chirho.status_chirho,
                    StatusCode::NOT_FOUND,
                    "{}",
                    answer_chirho.body_chirho
                );
                assert_eq!(answer_chirho.body_chirho, "error: app-not-found-chirho\n");
            }
            assert!(
                !polled_chirho.load(std::sync::atomic::Ordering::SeqCst),
                "the policy refusal comes before the body is read"
            );
        });
        return;
    }
    // The access-policy record outlives the deploy, so the policy read itself meets "no deployed app": the one road
    // where the policy failure's delegation to selection's 404 decides the answer.
    let root_chirho = protected_route_root_chirho("undeployed-access-arm");
    let owner_chirho =
        cairn_chirho::app_chirho::verified_app_owner_chirho(&root_chirho, PROTECTED_APP_CHIRHO)
            .unwrap()
            .unwrap();
    assert!(cairn_chirho::app_chirho::undeploy_app_chirho(
        &root_chirho,
        PROTECTED_APP_CHIRHO,
        &owner_chirho
    )
    .unwrap());
    let log_chirho = run_arm_in_child_chirho(
        "an_undeployed_app_with_a_leftover_access_policy_is_a_404_without_its_name_chirho",
        &root_chirho,
        None,
    );
    let witness_chirho = "CairnPublicErrorChirho:site_chirho=app-selection-chirho:class_chirho=fixed-refusal-chirho:status_chirho=404:identity_chirho=app-not-found-chirho";
    assert_eq!(
        witness_lines_chirho(&log_chirho),
        vec![witness_chirho, witness_chirho],
        "{log_chirho}"
    );
    assert!(
        !log_chirho.contains(PROTECTED_APP_CHIRHO),
        "the log echoes no name: {log_chirho}"
    );
    assert_free_of_detail_chirho("the server log", &log_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}
