// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3 at the production entry point: `cairn-chirho up` opens the connection road only when its TOML says
//! `connection_issuance_enabled_chirho = true`. Without the field the road answers its fixed 503; with it, a signed-out
//! visit to the form is sent to the login page with the form as its return target. Nothing here needs an app: the gate
//! is decided before the session or the client is read.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const FORM_CHIRHO: &str =
    "/auth-chirho/connection-new-chirho?client_id_chirho=client%2F0123456789abcdef";

struct ChildServerChirho {
    child_chirho: Option<Child>,
}

impl Drop for ChildServerChirho {
    fn drop(&mut self) {
        if let Some(mut child_chirho) = self.child_chirho.take() {
            let _ = child_chirho.kill();
            let _ = child_chirho.wait();
        }
    }
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "cairn-k4p3-up-{label_chirho}-{}-{}-chirho",
        std::process::id(),
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ))
}

/// `up` over a fresh root with `extra_toml_chirho` in its TOML; the form's answer to a signed-out GET.
fn signed_out_form_answer_chirho(
    label_chirho: &str,
    extra_toml_chirho: &str,
) -> (u16, String, String) {
    let root_chirho = temp_root_chirho(label_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    let port_chirho = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config_path_chirho = root_chirho.join("cairn-chirho.toml");
    std::fs::write(
        &config_path_chirho,
        format!(
            "root_chirho = {:?}\nport_chirho = {port_chirho}\n{extra_toml_chirho}",
            root_chirho.display().to_string()
        ),
    )
    .unwrap();
    let digest_chirho = cairn_ledger_regenesis_chirho::ledger_host_config_digest_chirho(
        &std::fs::read(&config_path_chirho).unwrap(),
    );
    let _server_chirho = ChildServerChirho {
        child_chirho: Some(
            Command::new(env!("CARGO_BIN_EXE_cairn-chirho"))
                .args([
                    "up",
                    "--config",
                    config_path_chirho.to_str().unwrap(),
                    "--expected-config-digest-chirho",
                    digest_chirho.as_str(),
                    "--allow-platform-root-chirho",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ),
    };
    let base_chirho = format!("http://127.0.0.1:{port_chirho}");
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .redirects(0)
        .build();
    let deadline_chirho = Instant::now() + Duration::from_secs(30);
    while agent_chirho
        .get(&format!("{base_chirho}/healthz-chirho"))
        .call()
        .is_err()
    {
        assert!(
            Instant::now() < deadline_chirho,
            "cairn up did not become healthy"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let answer_chirho = match agent_chirho
        .get(&format!("{base_chirho}{FORM_CHIRHO}"))
        .call()
    {
        Ok(response_chirho) | Err(ureq::Error::Status(_, response_chirho)) => response_chirho,
        Err(error_chirho) => panic!("the form did not answer: {error_chirho}"),
    };
    let status_chirho = answer_chirho.status();
    let location_chirho = answer_chirho
        .header("location")
        .unwrap_or_default()
        .to_string();
    let body_chirho = answer_chirho.into_string().unwrap_or_default();
    let _ = std::fs::remove_dir_all(&root_chirho);
    (status_chirho, location_chirho, body_chirho)
}

/// THE TOML OPENS THE ROAD, AND ONLY THE TOML: without the field, the form answers the fixed 503; with it set, a
/// signed-out GET is sent to the road's sign-in page carrying the form as its target (PFE unit 330).
#[test]
fn up_opens_the_connection_road_only_when_its_toml_says_so_chirho() {
    let (closed_status_chirho, _closed_location_chirho, closed_body_chirho) =
        signed_out_form_answer_chirho("closed", "");
    assert_eq!(closed_status_chirho, 503);
    assert!(closed_body_chirho.contains("id=\"connection-issuance-disabled-chirho\""));

    let (open_status_chirho, open_location_chirho, _open_body_chirho) =
        signed_out_form_answer_chirho("open", "connection_issuance_enabled_chirho = true\n");
    assert_eq!(open_status_chirho, 303);
    assert!(
        open_location_chirho.starts_with("/auth-chirho/connection-sign-in-chirho?redirect_chirho="),
        "{open_location_chirho}"
    );
}
