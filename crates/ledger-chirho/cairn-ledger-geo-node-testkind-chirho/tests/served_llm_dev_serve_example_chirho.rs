// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The dev served-LLM example, run as its own process on a bootstrapped test-kind root: it names its
//! build, refuses without the opt-in before touching the root, serves health and the HTTP login road,
//! stops when its stop file appears, and prints the verified balances before and after.
//!
//! What the card itself does under this serve entry (issued keys on the paid route's answer, one charge
//! per draft, the replay, the refusal card) is proven by `served_llm_card_http_e2e_chirho`, which drives
//! the same `serve_with_dev_llm_served_composition_until_chirho` in-process. This file proves the
//! example's own wiring around it, which that test cannot see.

use cairn_chirho::identity_chirho::{
    register_identity_with_credential_chirho, PrincipalKindChirho,
};
use cairn_served_llm_dev_bootstrap_chirho::{
    run_served_llm_dev_bootstrap_chirho, ServedLlmDevBootstrapRequestChirho,
};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const EXAMPLE_NAME_CHIRHO: &str = "served_llm_dev_serve_chirho";
const AMOUNT_CHIRHO: u64 = 137;
const BILLING_KIND_CHIRHO: &str = "llm-credit-chirho";
const SETTLEMENT_OWNER_CHIRHO: &str = "dev-settlement-owner-chirho";
const USER_CREDENTIAL_CHIRHO: &str = "dev-example-user-secret-chirho";
const APP_NAME_CHIRHO: &str = "served-llm-dev-example-app-chirho";
const PAID_ROUTE_CHIRHO: &str = "draft-chirho";
const OPT_IN_CHIRHO: &str = "CAIRN_DEV_LLM_SERVED_CHIRHO";

/// The example binary `cargo test` builds for this package: examples land in `<profile>/examples/`,
/// beside the `<profile>/deps/` directory this test binary runs from.
fn example_binary_chirho() -> PathBuf {
    let test_binary_chirho = std::env::current_exe().expect("this test binary's path");
    let profile_dir_chirho = test_binary_chirho
        .parent()
        .and_then(Path::parent)
        .expect("a test binary sits in <profile>/deps");
    let binary_chirho = profile_dir_chirho.join("examples").join(format!(
        "{EXAMPLE_NAME_CHIRHO}{}",
        std::env::consts::EXE_SUFFIX
    ));
    assert!(
        binary_chirho.is_file(),
        "{} is missing. `cargo test -p cairn-ledger-geo-node-testkind-chirho` builds the package's \
         examples; a `--test` filter alone does not, so build it first with \
         `cargo build -p cairn-ledger-geo-node-testkind-chirho --example {EXAMPLE_NAME_CHIRHO}`",
        binary_chirho.display()
    );
    binary_chirho
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-served-llm-dev-example-{label_chirho}-{}-{nanos_chirho}-chirho",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_chirho).expect("create the temp root");
    root_chirho
}

fn unused_loopback_port_chirho() -> u16 {
    let listener_chirho =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
    listener_chirho.local_addr().unwrap().port()
}

/// Every file under the root with its bytes, so an arm can show the root was not touched at all.
fn root_snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk_chirho(dir_chirho: &Path, out_chirho: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry_chirho in std::fs::read_dir(dir_chirho).expect("read a root directory") {
            let path_chirho = entry_chirho.expect("a root entry").path();
            if path_chirho.is_dir() {
                walk_chirho(&path_chirho, out_chirho);
            } else {
                out_chirho.insert(
                    path_chirho.clone(),
                    std::fs::read(&path_chirho).expect("read a root file"),
                );
            }
        }
    }
    let mut out_chirho = BTreeMap::new();
    walk_chirho(root_chirho, &mut out_chirho);
    out_chirho
}

/// A bootstrapped test-kind root with one payer who can sign in, funded with `AMOUNT_CHIRHO`.
fn bootstrapped_root_chirho(label_chirho: &str) -> (PathBuf, String) {
    let root_chirho = temp_root_chirho(label_chirho);
    let user_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        USER_CREDENTIAL_CHIRHO,
    )
    .expect("register the payer with a credential")
    .principal_chirho;
    run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: &user_chirho,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho: AMOUNT_CHIRHO,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    })
    .expect("the dev bootstrap funds the payer");
    (
        root_chirho.canonicalize().expect("canonical root"),
        user_chirho,
    )
}

fn serve_args_chirho(root_chirho: &Path, port_chirho: u16, stop_file_chirho: &Path) -> Vec<String> {
    vec![
        "--root-chirho".into(),
        root_chirho.display().to_string(),
        "--port-chirho".into(),
        port_chirho.to_string(),
        "--app-chirho".into(),
        APP_NAME_CHIRHO.into(),
        "--paid-route-chirho".into(),
        PAID_ROUTE_CHIRHO.into(),
        "--billing-kind-chirho".into(),
        BILLING_KIND_CHIRHO.into(),
        "--stop-file-chirho".into(),
        stop_file_chirho.display().to_string(),
    ]
}

/// One url-encoded form value: unreserved bytes stay, every other byte is `%XX`.
fn form_value_chirho(value_chirho: &str) -> String {
    value_chirho
        .bytes()
        .map(|byte_chirho| match byte_chirho {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte_chirho).to_string()
            }
            _ => format!("%{byte_chirho:02X}"),
        })
        .collect()
}

fn wait_for_health_chirho(base_chirho: &str) {
    let deadline_chirho = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline_chirho {
        let healthy_chirho = ureq::get(&format!("{base_chirho}/healthz-chirho"))
            .timeout(Duration::from_millis(500))
            .call()
            .map(|response_chirho| response_chirho.status() == 200)
            .unwrap_or(false);
        if healthy_chirho {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the example never became healthy on {base_chirho}");
}

/// The balances one phase printed: `(principal, kind) -> (net, held)`.
fn balances_chirho(
    stdout_chirho: &str,
    phase_chirho: &str,
) -> BTreeMap<(String, String), (u64, u64)> {
    let prefix_chirho = format!("served-llm-dev-balance-chirho phase_chirho={phase_chirho} ");
    stdout_chirho
        .lines()
        .filter_map(|line_chirho| line_chirho.strip_prefix(&prefix_chirho))
        .map(|rest_chirho| {
            let fields_chirho: BTreeMap<&str, &str> = rest_chirho
                .split(' ')
                .filter_map(|field_chirho| field_chirho.split_once('='))
                .collect();
            (
                (
                    fields_chirho["principal_chirho"].to_string(),
                    fields_chirho["kind_chirho"].to_string(),
                ),
                (
                    fields_chirho["net_chirho"].parse().expect("a net amount"),
                    fields_chirho["held_chirho"].parse().expect("a held amount"),
                ),
            )
        })
        .collect()
}

#[test]
fn the_example_names_its_build_and_refuses_without_the_opt_in_before_touching_the_root_chirho() {
    let binary_chirho = example_binary_chirho();
    let version_chirho = Command::new(&binary_chirho)
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(version_chirho.status.success());
    let version_line_chirho = String::from_utf8(version_chirho.stdout).expect("utf8 version");
    assert!(
        version_line_chirho.starts_with(&format!("{EXAMPLE_NAME_CHIRHO} "))
            && version_line_chirho.trim_end().ends_with(')'),
        "the version line names the example, its version and its source commit: {version_line_chirho:?}"
    );

    let (root_chirho, _user_chirho) = bootstrapped_root_chirho("no-opt-in");
    let before_chirho = root_snapshot_chirho(&root_chirho);
    let stop_file_chirho = root_chirho.with_extension("stop-chirho");
    let refused_chirho = Command::new(&binary_chirho)
        .args(serve_args_chirho(
            &root_chirho,
            unused_loopback_port_chirho(),
            &stop_file_chirho,
        ))
        .env_remove(OPT_IN_CHIRHO)
        .output()
        .expect("run the example without the opt-in");
    assert!(!refused_chirho.status.success());
    let refusal_text_chirho = String::from_utf8_lossy(&refused_chirho.stderr);
    // The example's OWN refusal, not the runtime's: both name the opt-in, and only this one fires
    // before the balances are read and the resident is opened.
    assert!(
        refusal_text_chirho.contains(&format!(
            "{EXAMPLE_NAME_CHIRHO} refused: set {OPT_IN_CHIRHO}=1"
        )),
        "{refusal_text_chirho}"
    );
    assert_eq!(
        root_snapshot_chirho(&root_chirho),
        before_chirho,
        "without the opt-in the example refuses before it reads balances or opens the resident"
    );
    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_example_serves_login_until_its_stop_file_and_prints_matching_balances_chirho() {
    let binary_chirho = example_binary_chirho();
    let (root_chirho, user_chirho) = bootstrapped_root_chirho("serve");
    let port_chirho = unused_loopback_port_chirho();
    let base_chirho = format!("http://127.0.0.1:{port_chirho}");
    let stop_file_chirho = root_chirho.with_extension("stop-chirho");
    let stdout_path_chirho = root_chirho.with_extension("stdout-chirho");
    let stderr_path_chirho = root_chirho.with_extension("stderr-chirho");
    let mut child_chirho = Command::new(&binary_chirho)
        .args(serve_args_chirho(
            &root_chirho,
            port_chirho,
            &stop_file_chirho,
        ))
        .env(OPT_IN_CHIRHO, "1")
        .stdout(Stdio::from(
            std::fs::File::create(&stdout_path_chirho).expect("stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr_path_chirho).expect("stderr file"),
        ))
        .spawn()
        .expect("start the example");
    wait_for_health_chirho(&base_chirho);

    // PFE's confirmation (a): the payer signs in over HTTP on the example's own root.
    let agent_chirho = ureq::AgentBuilder::new().redirects(0).build();
    let login_chirho = agent_chirho
        .post(&format!("{base_chirho}/auth-chirho/login-chirho"))
        .set("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration::from_secs(20))
        .send_string(&format!(
            "principal_chirho={}&credential_chirho={}",
            form_value_chirho(&user_chirho),
            form_value_chirho(USER_CREDENTIAL_CHIRHO)
        ));
    let (login_status_chirho, login_cookie_chirho) = match login_chirho {
        Ok(response_chirho) | Err(ureq::Error::Status(_, response_chirho)) => (
            response_chirho.status(),
            response_chirho
                .all("Set-Cookie")
                .iter()
                .any(|cookie_chirho| cookie_chirho.starts_with("cairn_session_chirho=")),
        ),
        Err(error_chirho) => panic!("the login POST did not reach the example: {error_chirho}"),
    };

    std::fs::write(&stop_file_chirho, b"stop").expect("write the stop file");
    let deadline_chirho = Instant::now() + Duration::from_secs(60);
    let status_chirho = loop {
        if let Some(status_chirho) = child_chirho.try_wait().expect("poll the example") {
            break status_chirho;
        }
        if Instant::now() > deadline_chirho {
            let _killed_chirho = child_chirho.kill();
            panic!("the example did not stop within 60 s of its stop file");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut stdout_chirho = String::new();
    std::fs::File::open(&stdout_path_chirho)
        .and_then(|mut file_chirho| file_chirho.read_to_string(&mut stdout_chirho))
        .expect("read the example's stdout");
    let stderr_chirho = std::fs::read_to_string(&stderr_path_chirho).unwrap_or_default();
    assert!(
        status_chirho.success(),
        "the example exits cleanly after its stop file: {status_chirho}\n{stderr_chirho}"
    );
    assert_eq!(
        (login_status_chirho, login_cookie_chirho),
        (303, true),
        "a form sign-in on the example's root answers 303 with the session cookie\n{stderr_chirho}"
    );
    let before_chirho = balances_chirho(&stdout_chirho, "before");
    let after_chirho = balances_chirho(&stdout_chirho, "after");
    let payer_key_chirho = (user_chirho.clone(), BILLING_KIND_CHIRHO.to_string());
    assert_eq!(
        before_chirho.get(&payer_key_chirho).copied(),
        Some((AMOUNT_CHIRHO, 0)),
        "the before read names the funded payer, with nothing held: {stdout_chirho}"
    );
    assert!(
        before_chirho
            .values()
            .all(|(_net_chirho, held_chirho)| *held_chirho == 0),
        "no draft ran, so no account holds anything: {stdout_chirho}"
    );
    assert_eq!(
        after_chirho, before_chirho,
        "nothing was drafted, so the after read matches the before read"
    );
    for leftover_chirho in [
        &stop_file_chirho,
        &stdout_path_chirho,
        &stderr_path_chirho,
        &root_chirho,
    ] {
        let _removed_chirho = std::fs::remove_dir_all(leftover_chirho)
            .or_else(|_| std::fs::remove_file(leftover_chirho));
    }
}
