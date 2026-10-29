// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3's one-time scope over a real process's output (PFE #26801): the served road runs in a child process (this
//! test binary, re-run as the configured road's server) whose stdout and stderr the operating system writes to files.
//! After a creation, a wrong password and an uncertain creation, neither the bearer nor either password is in the root,
//! the answer's headers, or that captured output; each scan sits beside a planted control it must find. That
//! establishes absence there only, not in OS buffers or anything outside the engine.
//!
//! The same file holds the browser run's fixture (PFE #26814): an ignored arm that serves the configured road for a
//! JavaScript-disabled browser harness outside this crate, and reports counts only.

use super::connection_new_http_tests_chirho::{
    attempt_rows_chirho, files_holding_chirho, form_body_chirho, form_target_chirho, lines_chirho,
    location_chirho, post_form_chirho, with_connection_road_chirho,
};
use super::limited_key_fixture_chirho::*;
use super::limited_key_rollback_tests_chirho::sign_in_chirho;
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

const CHILD_ROOT_ENV_CHIRHO: &str = "CAIRN_K4P3_CHILD_ROOT_CHIRHO";
const CHILD_PORT_ENV_CHIRHO: &str = "CAIRN_K4P3_CHILD_PORT_CHIRHO";
const CHILD_TEST_CHIRHO: &str = "serve_chirho::tests_chirho::connection_new_output_tests_chirho::connection_road_child_process_chirho";

/// The child process's whole job, when the scan arm starts it: serve the root it names through the configured road,
/// with the connection gate open, until it is killed. Run any other way, it returns at once.
#[test]
#[ignore = "the served road's child process: the scan arm below starts it"]
fn connection_road_child_process_chirho() {
    let (Ok(root_chirho), Ok(port_chirho)) = (
        std::env::var(CHILD_ROOT_ENV_CHIRHO),
        std::env::var(CHILD_PORT_ENV_CHIRHO),
    ) else {
        return;
    };
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho
        .block_on(serve_with_configured_ledger_host_chirho(
            Path::new(&root_chirho),
            port_chirho.parse().unwrap(),
            8,
            ServeAuthTokensChirho::new_chirho(String::new(), String::new())
                .with_connection_issuance_enabled_chirho(true),
            false,
            ServedRequestAbuseLimitsChirho {
                sign_in_principal_successes_per_hour_chirho: 100,
                ..ServedRequestAbuseLimitsChirho::default()
            },
            ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho(),
        ))
        .unwrap();
}

struct ChildChirho(Child);

impl Drop for ChildChirho {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn file_holds_chirho(path_chirho: &Path, needle_chirho: &str) -> bool {
    std::fs::read(path_chirho)
        .unwrap_or_default()
        .windows(needle_chirho.len())
        .any(|window_chirho| window_chirho == needle_chirho.as_bytes())
}

/// NEITHER THE BEARER NOR A PASSWORD REACHES THE ROOT, THE HEADERS OR THE PROCESS'S OUTPUT: a real child process serves
/// the road with its stdout and stderr in files. A creation shows its bearer once; a wrong password is refused; with
/// the attempt log read-only, a creation is uncertain, and the server logs its cause. Then the planted controls (a file
/// under the root, the server's listen banner on stdout, and that logged cause on stderr) are each found, and the
/// bearer, the password and the wrong password are found nowhere.
#[test]
fn the_secret_reaches_no_root_header_or_output_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4p3-output", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let wrong_chirho = "the-wrong-password-k4p3-chirho";
    let logs_chirho = super::app_route_fixture_chirho::tmp_dir_chirho("k4p3-output-logs");
    let stdout_path_chirho = logs_chirho.join("child-stdout.log");
    let stderr_path_chirho = logs_chirho.join("child-stderr.log");
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let mut child_chirho = ChildChirho(
        Command::new(std::env::current_exe().unwrap())
            .args([
                CHILD_TEST_CHIRHO,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ROOT_ENV_CHIRHO, &root_chirho)
            .env(CHILD_PORT_ENV_CHIRHO, port_chirho.to_string())
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout_path_chirho).unwrap())
            .stderr(std::fs::File::create(&stderr_path_chirho).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline_chirho = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !try_http_get_for_smoke_chirho(&addr_chirho, "/healthz-chirho")
        .map(|response_chirho| response_chirho.status_chirho == 200)
        .unwrap_or(false)
    {
        assert!(
            child_chirho.0.try_wait().unwrap().is_none(),
            "the child server exited"
        );
        assert!(
            std::time::Instant::now() < deadline_chirho,
            "the child server never answered"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let (status_chirho, cookie_chirho) =
        sign_in_chirho(&addr_chirho, principal_chirho, secret_chirho);
    let cookie_chirho =
        cookie_chirho.unwrap_or_else(|| panic!("no session cookie ({status_chirho})"));
    let created_chirho = post_form_chirho(
        &addr_chirho,
        Some(&cookie_chirho),
        &form_body_chirho(
            &tenant_chirho.client_id_chirho,
            &[PAGE_READ_CHIRHO],
            secret_chirho,
        ),
    );
    assert_eq!(created_chirho.status_chirho, 200);
    let page_chirho = http_body_text_chirho(&created_chirho);
    let start_chirho = page_chirho.find("<code>").unwrap() + "<code>".len();
    let bearer_chirho = page_chirho
        [start_chirho..start_chirho + page_chirho[start_chirho..].find("</code>").unwrap()]
        .to_string();
    for value_chirho in created_chirho.headers_chirho.values() {
        assert!(!value_chirho.contains(&bearer_chirho) && !value_chirho.contains(secret_chirho));
    }
    let refused_chirho = post_form_chirho(
        &addr_chirho,
        Some(&cookie_chirho),
        &form_body_chirho(
            &tenant_chirho.client_id_chirho,
            &[PAGE_READ_CHIRHO],
            wrong_chirho,
        ),
    );
    assert!(location_chirho(&refused_chirho).ends_with("#refusal-credential-mismatch-chirho"));
    assert!(!location_chirho(&refused_chirho).contains(wrong_chirho));

    let attempts_chirho = root_chirho.join("identity-auth-attempts-chirho.jsonl");
    std::fs::set_permissions(&attempts_chirho, std::fs::Permissions::from_mode(0o444)).unwrap();
    let uncertain_chirho = post_form_chirho(
        &addr_chirho,
        Some(&cookie_chirho),
        &form_body_chirho(
            &tenant_chirho.client_id_chirho,
            &[PAGE_READ_CHIRHO],
            secret_chirho,
        ),
    );
    std::fs::set_permissions(&attempts_chirho, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(uncertain_chirho.status_chirho, 500);
    drop(child_chirho);

    let planted_chirho = "planted-control-needle-k4p3-output-chirho";
    std::fs::write(
        root_chirho.join("planted-control-chirho.txt"),
        planted_chirho,
    )
    .unwrap();
    assert_eq!(
        files_holding_chirho(&root_chirho, planted_chirho).len(),
        1,
        "the root scan finds what is there"
    );
    assert!(
        file_holds_chirho(&stdout_path_chirho, "cairn-chirho serving on"),
        "the stdout scan finds the banner"
    );
    assert!(
        file_holds_chirho(&stderr_path_chirho, "a connection's creation is uncertain"),
        "the stderr scan finds the logged cause"
    );
    for needle_chirho in [bearer_chirho.as_str(), secret_chirho, wrong_chirho] {
        assert!(
            files_holding_chirho(&root_chirho, needle_chirho).is_empty(),
            "under the root"
        );
        assert!(
            !file_holds_chirho(&stdout_path_chirho, needle_chirho),
            "on stdout"
        );
        assert!(
            !file_holds_chirho(&stderr_path_chirho, needle_chirho),
            "on stderr"
        );
    }
    let _ = std::fs::remove_dir_all(&logs_chirho);
}

const BROWSER_DIR_ENV_CHIRHO: &str = "CAIRN_K4P3_BROWSER_DIR_CHIRHO";
/// How long the fixture waits for the browser harness to finish before it fails.
const BROWSER_DEADLINE_CHIRHO: std::time::Duration = std::time::Duration::from_secs(600);

/// THE BROWSER RUN'S FIXTURE (PFE #26814): started by a JavaScript-disabled browser harness outside this crate, it serves
/// the configured road over a keyed tenant with the gate open. It hands the harness the address, the form's path, the
/// app's canonical path with a return path (Account Create brick 1), the action to tick and the fixture's synthetic
/// credential in a 0600 file inside the private directory the harness names,
/// and waits for the harness's done file. Then it removes that file and writes counts only: the owner's live
/// connections, the connection key log's lines, the attempt rows, and how many files under the root hold the credential,
/// beside a planted control it must find. Its tenant is removed when it returns. Run any other way, it returns at once.
#[test]
#[ignore = "the browser run's fixture: the JavaScript-disabled harness starts it"]
fn browser_run_fixture_chirho() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let Ok(dir_chirho) = std::env::var(BROWSER_DIR_ENV_CHIRHO) else {
        return;
    };
    let dir_chirho = Path::new(&dir_chirho);
    assert_eq!(
        std::fs::metadata(dir_chirho).unwrap().permissions().mode() & 0o077,
        0,
        "the handoff directory is private to its owner"
    );
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4p3-browser", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = &tenant_chirho.root_chirho;
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let handoff_path_chirho = dir_chirho.join("fixture-handoff-chirho.json");
    with_connection_road_chirho(root_chirho, true, |addr_chirho| {
        let return_chirho = format!("/app-chirho/{KEYED_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}");
        let app_path_chirho = format!(
            "/auth-chirho/connection-new-chirho?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("app_chirho", KEYED_APP_CHIRHO)
                .append_pair("return_chirho", &return_chirho)
                .finish()
        );
        let handoff_chirho = serde_json::json!({
            "base_url_chirho": format!("http://{addr_chirho}"),
            "form_path_chirho": form_target_chirho(&tenant_chirho.client_id_chirho),
            "app_path_chirho": app_path_chirho,
            "return_chirho": return_chirho,
            "client_id_chirho": tenant_chirho.client_id_chirho,
            "action_chirho": PAGE_READ_CHIRHO,
            "principal_chirho": principal_chirho,
            "credential_chirho": secret_chirho,
        });
        let mut file_chirho = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&handoff_path_chirho)
            .unwrap();
        file_chirho
            .write_all(handoff_chirho.to_string().as_bytes())
            .unwrap();
        drop(file_chirho);
        let started_chirho = std::time::Instant::now();
        while !dir_chirho.join("browser-done-chirho").exists() {
            assert!(
                started_chirho.elapsed() < BROWSER_DEADLINE_CHIRHO,
                "the browser harness did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    });
    std::fs::remove_file(&handoff_path_chirho).unwrap();
    let control_chirho = format!("browser-control-{}-chirho", std::process::id());
    std::fs::write(
        root_chirho.join("browser-control-chirho.txt"),
        &control_chirho,
    )
    .unwrap();
    let live_chirho = oauth_chirho::list_own_keys_chirho(root_chirho, principal_chirho)
        .unwrap()
        .iter()
        .filter(|row_chirho| row_chirho.live_chirho)
        .count();
    let attempts_chirho: Vec<String> = attempt_rows_chirho(root_chirho)
        .into_iter()
        .map(|(endpoint_chirho, outcome_chirho)| format!("{endpoint_chirho} {outcome_chirho:?}"))
        .collect();
    let result_chirho = serde_json::json!({
        "live_connections_chirho": live_chirho,
        "connection_key_lines_chirho": lines_chirho(root_chirho, "connection-tokens-chirho.jsonl"),
        "attempt_rows_chirho": attempts_chirho,
        "credential_files_under_root_chirho": files_holding_chirho(root_chirho, secret_chirho).len(),
        "control_files_under_root_chirho": files_holding_chirho(root_chirho, &control_chirho).len(),
    });
    std::fs::write(
        dir_chirho.join("fixture-result-chirho.json"),
        result_chirho.to_string(),
    )
    .unwrap();
}
