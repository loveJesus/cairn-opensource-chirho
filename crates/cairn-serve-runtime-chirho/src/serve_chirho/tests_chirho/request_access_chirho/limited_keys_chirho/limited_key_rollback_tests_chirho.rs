// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K1's rollback arms: R15's exact executable (its macOS twin, pinned by digest) serves a copy of a root the successor
//! engine built, the successor's own router serves another copy, and both take the same raw HTTP probes.
//! - **A limited key is no key to R15.** Its stored hash is in another domain, so R15 answers it exactly as it answers a
//!   made-up bearer and writes nothing for it: no use, no usage, no sealed input, no run. R15 still starts on the root,
//!   with the key-authority log beside its logs and limited records in its token log, and the successor serves the key.
//! - **Retirement holds on both engines.** The legacy key issued before the app opened a route was retired at the
//!   opt-in through the session door R15 already honours, so each engine answers it as a made-up bearer. A legacy key
//!   on a separate app that opens nothing keeps working on both, and so do browser sessions.
//! - **The activation boundary.** R15's JSON road mints an unrestricted legacy key for any client of the opted-in app,
//!   and on R15 that key reads and saves there. Customer-key activation (K4) registers such a client, so before it the
//!   old road must be blocked independently (an ingress restriction or a floor). On roll-forward the successor refuses
//!   the minted key on every entry and issues no legacy key for that client.
//!
//! These arms run a binary from outside the repository, so they are ignored by default. Run them with
//! `CAIRN_R15_TWIN_CHIRHO=<R15's macOS twin> cargo test -p cairn-serve-runtime-chirho --lib limited_key_rollback -- --ignored`;
//! an unset or mismatched twin fails, never skips.
//! Workflow: limited-key authority (K1),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.

use super::app_route_fixture_chirho::{
    counted_road_runtime_chirho, deploy_growth_app_chirho, head_version_chirho, tmp_dir_chirho,
    write_request_chirho, GROWTH_APP_CHIRHO,
};
use super::limited_key_fixture_chirho::*;
use super::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const R15_TWIN_ENV_CHIRHO: &str = "CAIRN_R15_TWIN_CHIRHO";
/// blake3 of R15's macOS twin. Its sha256 is ac9f980991d60147…0b43a9c6, as its byte evidence records, and its
/// `--version` names e1c65ad7da25c1e81421741f26a9fcd4d4c33159.
const R15_TWIN_BLAKE3_CHIRHO: &str =
    "87b3e361e862cee732f15198fa7719f8d95d41ddd5e0648f35af7b22ef5ff507";
const PAGE_TEXT_CHIRHO: &str = "the page a limited key saved";
const MADE_UP_BEARER_CHIRHO: &str = "cairn-k1-rollback-made-up-bearer-chirho";
const ROUTE_NOT_OPEN_LINE_CHIRHO: &str = "error: key-route-not-open-chirho";

/// R15's twin, from the environment, checked against its digest.
pub(super) fn r15_twin_chirho() -> PathBuf {
    let path_chirho = std::env::var_os(R15_TWIN_ENV_CHIRHO)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "set {R15_TWIN_ENV_CHIRHO} to R15's macOS twin \
                 (gitignored-chirho/successor-artifacts-chirho/e1c65ad7-macos-arm64-chirho/cairn-chirho); \
                 these arms never skip"
            )
        });
    let bytes_chirho = std::fs::read(&path_chirho)
        .unwrap_or_else(|error_chirho| panic!("{}: {error_chirho}", path_chirho.display()));
    assert_eq!(
        blake3::hash(&bytes_chirho).to_hex().as_str(),
        R15_TWIN_BLAKE3_CHIRHO,
        "{} is not R15's twin",
        path_chirho.display()
    );
    path_chirho
}

pub(super) fn token_of_chirho(headers_chirho: &HeaderMap) -> String {
    headers_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_string()
}

fn encoded_chirho(text_chirho: &str) -> String {
    BASE64_CHIRHO.encode(text_chirho.as_bytes())
}

/// The successor's root: the keyed app opened for page-read and page-save with a page saved through a limited key,
/// and a separate app that opens nothing.
struct SuccessorChirho {
    tenant_chirho: KeyedTenantChirho,
    /// User 0's legacy key, issued before the app opened a route and retired by that deploy.
    retired_chirho: String,
    /// User 0's limited key holding page-read.
    read_chirho: String,
    /// User 0's limited key holding page-read and page-save.
    save_chirho: String,
    /// User 1's legacy key on the app that opens nothing.
    control_chirho: String,
    dirs_chirho: Vec<PathBuf>,
}

impl Drop for SuccessorChirho {
    fn drop(&mut self) {
        for dir_chirho in &self.dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

fn successor_chirho(label_chirho: &str) -> SuccessorChirho {
    let tenant_chirho = KeyedTenantChirho::new_chirho(label_chirho, OpeningsChirho::NONE_CHIRHO, 2);
    let retired_chirho = token_of_chirho(
        &tenant_chirho
            .try_legacy_bearer_chirho(0)
            .expect("an app that opens nothing issues legacy keys"),
    );
    // A K1-era root: a legacy client before the app's first opening, which K4 refuses (built through the seam).
    cairn_chirho::oauth_chirho::with_k1_era_opening_chirho(|| {
        tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |_| {})
    });
    let read_chirho = token_of_chirho(&tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]));
    let save_headers_chirho =
        tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO, PAGE_SAVE_CHIRHO]);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) = post_route_chirho(
            &state_chirho,
            &save_headers_chirho,
            SAVE_ROUTE_CHIRHO,
            write_request_chirho(None, PAGE_TEXT_CHIRHO),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    });
    let (dirs_chirho, control_chirho) = control_app_chirho(&tenant_chirho, label_chirho);
    SuccessorChirho {
        save_chirho: token_of_chirho(&save_headers_chirho),
        tenant_chirho,
        retired_chirho,
        read_chirho,
        control_chirho,
        dirs_chirho,
    }
}

/// CF7's shape beside the keyed app: an app that opens nothing keeps its legacy keys. Returns its fixture directories
/// and user 1's legacy key on it.
pub(super) fn control_app_chirho(
    tenant_chirho: &KeyedTenantChirho,
    label_chirho: &str,
) -> (Vec<PathBuf>, String) {
    let dirs_chirho = deploy_growth_app_chirho(
        &tenant_chirho.root_chirho,
        &tenant_chirho.owner_chirho,
        &format!("{label_chirho}-control"),
    );
    let control_client_chirho = oauth_chirho::register_client_chirho(
        &tenant_chirho.root_chirho,
        GROWTH_APP_CHIRHO,
        &tenant_chirho.owner_chirho,
    )
    .unwrap()
    .client_id_chirho;
    let (principal_chirho, credential_chirho) = tenant_chirho.user_chirho(1);
    let control_chirho = oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
        &tenant_chirho.root_chirho,
        principal_chirho,
        credential_chirho,
        &control_client_chirho,
        Vec::new(),
        Some(oauth_chirho::ScopedTokenRateLimitChirho {
            window_ms_chirho: 60_000,
            max_invokes_chirho: oauth_chirho::TOKEN_RATE_MAX_INVOKES_CEILING_CHIRHO,
            device_id_chirho: None,
        }),
    )
    .unwrap()
    .token_chirho;
    (dirs_chirho, control_chirho)
}

/// A copy of the successor's platform root, with the twin's log beside it.
pub(super) struct RootCopyChirho {
    pub(super) dir_chirho: PathBuf,
    pub(super) platform_chirho: PathBuf,
    tenant_chirho: String,
    pub(super) tenant_root_chirho: PathBuf,
}

impl RootCopyChirho {
    pub(super) fn of_chirho(tenant_root_chirho: &Path, label_chirho: &str) -> Self {
        let tenants_chirho = tenant_root_chirho.parent().unwrap();
        assert_eq!(tenants_chirho.file_name().unwrap(), "tenants-chirho");
        let platform_chirho = tenants_chirho.parent().unwrap();
        let tenant_chirho = tenant_root_chirho
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let dir_chirho = tmp_dir_chirho(&format!("{label_chirho}-copy"));
        let platform_copy_chirho = dir_chirho.join("platform-chirho");
        assert!(Command::new("cp")
            .arg("-Rp")
            .arg(platform_chirho)
            .arg(&platform_copy_chirho)
            .status()
            .unwrap()
            .success());
        let tenant_root_copy_chirho = platform_copy_chirho
            .join("tenants-chirho")
            .join(&tenant_chirho);
        assert!(tenant_root_copy_chirho.is_dir());
        Self {
            dir_chirho,
            platform_chirho: platform_copy_chirho,
            tenant_chirho,
            tenant_root_chirho: tenant_root_copy_chirho,
        }
    }

    pub(super) fn twin_log_chirho(&self) -> String {
        std::fs::read_to_string(self.dir_chirho.join("twin-chirho.log")).unwrap_or_default()
    }
}

impl Drop for RootCopyChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir_chirho);
    }
}

/// R15's twin serving a root copy, as the host would run it: `--root <platform> serve --port <p> --tenant <t>`.
pub(super) struct TwinServerChirho {
    child_chirho: Child,
    pub(super) addr_chirho: String,
}

impl TwinServerChirho {
    pub(super) fn start_chirho(twin_chirho: &Path, copy_chirho: &RootCopyChirho) -> Self {
        let port_chirho = unused_local_port_chirho();
        let log_chirho =
            std::fs::File::create(copy_chirho.dir_chirho.join("twin-chirho.log")).unwrap();
        let child_chirho = Command::new(twin_chirho)
            .arg("--root")
            .arg(&copy_chirho.platform_chirho)
            .arg("serve")
            .arg("--port")
            .arg(port_chirho.to_string())
            .arg("--tenant")
            .arg(&copy_chirho.tenant_chirho)
            .stdin(Stdio::null())
            .stdout(log_chirho.try_clone().unwrap())
            .stderr(log_chirho)
            .spawn()
            .unwrap();
        let mut server_chirho = Self {
            child_chirho,
            addr_chirho: format!("127.0.0.1:{port_chirho}"),
        };
        for _ in 0..300 {
            if let Some(status_chirho) = server_chirho.child_chirho.try_wait().unwrap() {
                panic!(
                    "R15 exited before serving the successor's root ({status_chirho}):\n{}",
                    copy_chirho.twin_log_chirho()
                );
            }
            if try_http_get_for_smoke_chirho(&server_chirho.addr_chirho, "/healthz-chirho")
                .map(|response_chirho| response_chirho.status_chirho == 200)
                .unwrap_or(false)
            {
                return server_chirho;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "R15 did not become healthy on the successor's root:\n{}",
            copy_chirho.twin_log_chirho()
        );
    }
}

impl Drop for TwinServerChirho {
    fn drop(&mut self) {
        let _ = self.child_chirho.kill();
        let _ = self.child_chirho.wait();
    }
}

pub(super) fn keyed_path_chirho(route_chirho: &str) -> String {
    format!("/app-chirho/{KEYED_APP_CHIRHO}/{route_chirho}")
}

fn form_encode_chirho(value_chirho: &str) -> String {
    value_chirho
        .bytes()
        .map(|byte_chirho| {
            if byte_chirho.is_ascii_alphanumeric() || b"-._~".contains(&byte_chirho) {
                char::from(byte_chirho).to_string()
            } else {
                format!("%{byte_chirho:02X}")
            }
        })
        .collect()
}

/// A browser sign-in through the engine's own form road: its status and the session cookie it set, if any.
pub(super) fn sign_in_chirho(
    addr_chirho: &str,
    principal_chirho: &str,
    credential_chirho: &str,
) -> (u16, Option<String>) {
    let body_chirho = format!(
        "principal_chirho={}&credential_chirho={}",
        form_encode_chirho(principal_chirho),
        form_encode_chirho(credential_chirho)
    );
    let response_chirho = http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/login-chirho",
        &[("content-type", "application/x-www-form-urlencoded")],
        body_chirho.as_bytes(),
    );
    let cookie_chirho = response_chirho
        .headers_chirho
        .get("set-cookie")
        .map(|value_chirho| value_chirho.split(';').next().unwrap().to_string());
    (response_chirho.status_chirho, cookie_chirho)
}

/// User `index_chirho`'s session cookie from this engine's own sign-in.
fn session_cookie_chirho(
    addr_chirho: &str,
    tenant_chirho: &KeyedTenantChirho,
    index_chirho: usize,
) -> String {
    let (principal_chirho, credential_chirho) = tenant_chirho.user_chirho(index_chirho);
    let (status_chirho, cookie_chirho) =
        sign_in_chirho(addr_chirho, principal_chirho, credential_chirho);
    cookie_chirho.unwrap_or_else(|| panic!("the sign-in set no session cookie ({status_chirho})"))
}

/// A snapshot of the copy once two readings a quarter second apart agree, so a background write cannot pass for a
/// request's.
fn quiet_snapshot_chirho(platform_chirho: &Path) -> BTreeMap<PathBuf, String> {
    let mut last_chirho = root_snapshot_chirho(platform_chirho);
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(250));
        let next_chirho = root_snapshot_chirho(platform_chirho);
        if next_chirho == last_chirho {
            return next_chirho;
        }
        last_chirho = next_chirho;
    }
    panic!("the served copy never went quiet");
}

#[test]
#[ignore = "runs R15's twin: set CAIRN_R15_TWIN_CHIRHO and pass --ignored"]
fn r15_answers_a_limited_key_as_no_key_and_writes_nothing_for_it_chirho() {
    let twin_chirho = r15_twin_chirho();
    let successor_chirho = successor_chirho("k1-rb-hash");
    let root_chirho = &successor_chirho.tenant_chirho.root_chirho;
    assert!(cairn_chirho::app_chirho::app_key_authority_record_chirho(
        root_chirho,
        KEYED_APP_CHIRHO
    )
    .unwrap()
    .is_some());
    let encoded_page_chirho = encoded_chirho(PAGE_TEXT_CHIRHO);

    // The successor serves the key: it is a real key with a real page behind it.
    let successor_copy_chirho = RootCopyChirho::of_chirho(root_chirho, "k1-rb-hash-successor");
    with_successor_served_chirho(&successor_copy_chirho.tenant_root_chirho, |addr_chirho| {
        let (status_chirho, page_chirho) = probe_chirho(
            addr_chirho,
            "GET",
            &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
            &[(
                "authorization",
                &bearer_chirho(&successor_chirho.read_chirho),
            )],
            b"",
        );
        assert_eq!(status_chirho, 200, "{page_chirho}");
        assert_eq!(head_version_chirho(&page_chirho), Some(1));
        assert!(page_chirho.contains(&encoded_page_chirho), "{page_chirho}");
    });

    // R15 starts on the root, the key-authority log and the limited token records included.
    let copy_chirho = RootCopyChirho::of_chirho(root_chirho, "k1-rb-hash-r15");
    let r15_chirho = TwinServerChirho::start_chirho(&twin_chirho, &copy_chirho);
    let addr_chirho = r15_chirho.addr_chirho.clone();
    let before_chirho = quiet_snapshot_chirho(&copy_chirho.platform_chirho);
    let made_up_chirho = bearer_chirho(MADE_UP_BEARER_CHIRHO);
    let save_body_chirho = write_request_chirho(Some(1), "a page R15 must never write");
    let probes_chirho: [(&str, String, &str, &[u8]); 4] = [
        (
            "GET",
            keyed_path_chirho(VIEW_ROUTE_CHIRHO),
            &successor_chirho.read_chirho,
            b"",
        ),
        (
            "GET",
            format!("/app-chirho/{KEYED_APP_CHIRHO}/"),
            &successor_chirho.read_chirho,
            b"",
        ),
        (
            "GET",
            keyed_path_chirho(VIEW_ROUTE_CHIRHO),
            &successor_chirho.save_chirho,
            b"",
        ),
        (
            "POST",
            keyed_path_chirho(SAVE_ROUTE_CHIRHO),
            &successor_chirho.save_chirho,
            save_body_chirho.as_bytes(),
        ),
    ];
    let mut answers_chirho = Vec::new();
    for (method_chirho, path_chirho, token_chirho, body_chirho) in &probes_chirho {
        let limited_chirho = probe_chirho(
            &addr_chirho,
            method_chirho,
            path_chirho,
            &[("authorization", &bearer_chirho(token_chirho))],
            body_chirho,
        );
        assert!(
            !limited_chirho.1.contains(&encoded_page_chirho),
            "R15 must not serve the page to a limited key: {limited_chirho:?}"
        );
        answers_chirho.push(((*method_chirho, path_chirho.clone()), limited_chirho));
    }
    // Nothing the limited key sent was recorded: no use, no usage, no sealed input, no run.
    assert_eq!(
        quiet_snapshot_chirho(&copy_chirho.platform_chirho),
        before_chirho,
        "R15 wrote for a key it cannot find"
    );
    // The attribution: R15 answers each limited request exactly as it answers a bearer that names no key.
    for ((method_chirho, path_chirho), limited_chirho) in &answers_chirho {
        let body_chirho = if *method_chirho == "POST" {
            save_body_chirho.as_bytes()
        } else {
            b""
        };
        let made_up_answer_chirho = probe_chirho(
            &addr_chirho,
            method_chirho,
            path_chirho,
            &[("authorization", &made_up_chirho)],
            body_chirho,
        );
        assert!(
            (400..500).contains(&limited_chirho.0),
            "{method_chirho} {path_chirho}: {limited_chirho:?}"
        );
        assert_eq!(
            limited_chirho, &made_up_answer_chirho,
            "{method_chirho} {path_chirho}: R15 tells the limited key from no key"
        );
        eprintln!(
            "R15 answers a limited key on {method_chirho} {path_chirho} with {} [{}], as it answers no key",
            limited_chirho.0,
            identity_line_chirho(&limited_chirho.1)
        );
    }
    // The snapshot's control: a wrong sign-in on the same twin and copy is recorded, so the snapshot sees R15's writes.
    let (principal_chirho, _) = successor_chirho.tenant_chirho.user_chirho(0);
    let (status_chirho, cookie_chirho) =
        sign_in_chirho(&addr_chirho, principal_chirho, "not-this-user-credential");
    assert!(
        cookie_chirho.is_none(),
        "a wrong credential signed in ({status_chirho})"
    );
    assert_ne!(
        quiet_snapshot_chirho(&copy_chirho.platform_chirho),
        before_chirho,
        "the control: R15 records a wrong sign-in, so a write by R15 would show"
    );
    drop(r15_chirho);
}

#[test]
#[ignore = "runs R15's twin: set CAIRN_R15_TWIN_CHIRHO and pass --ignored"]
fn retirement_holds_on_both_engines_while_the_unopened_apps_key_and_sessions_keep_working_chirho() {
    let twin_chirho = r15_twin_chirho();
    let successor_chirho = successor_chirho("k1-rb-retire");
    let root_chirho = &successor_chirho.tenant_chirho.root_chirho;
    let encoded_page_chirho = encoded_chirho(PAGE_TEXT_CHIRHO);
    let control_path_chirho = format!("/app-chirho/{GROWTH_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}");

    let check_engine_chirho = |engine_chirho: &str, addr_chirho: &str| {
        // The retired key is no key: the engine answers it as it answers a made-up bearer.
        let retired_chirho = probe_chirho(
            addr_chirho,
            "GET",
            &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
            &[(
                "authorization",
                &bearer_chirho(&successor_chirho.retired_chirho),
            )],
            b"",
        );
        let made_up_chirho = probe_chirho(
            addr_chirho,
            "GET",
            &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
            &[("authorization", &bearer_chirho(MADE_UP_BEARER_CHIRHO))],
            b"",
        );
        assert!(
            (400..500).contains(&retired_chirho.0),
            "{engine_chirho}: {retired_chirho:?}"
        );
        assert_eq!(
            retired_chirho, made_up_chirho,
            "{engine_chirho}: the retired key still counts"
        );
        // The legacy key on the app that opens nothing keeps working.
        let (status_chirho, page_chirho) = probe_chirho(
            addr_chirho,
            "GET",
            &control_path_chirho,
            &[(
                "authorization",
                &bearer_chirho(&successor_chirho.control_chirho),
            )],
            b"",
        );
        assert_eq!(status_chirho, 200, "{engine_chirho}: {page_chirho}");
        // A browser session reads the page the limited key saved.
        let cookie_chirho = session_cookie_chirho(addr_chirho, &successor_chirho.tenant_chirho, 0);
        let (status_chirho, page_chirho) = probe_chirho(
            addr_chirho,
            "GET",
            &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
            &[("cookie", &cookie_chirho)],
            b"",
        );
        assert_eq!(status_chirho, 200, "{engine_chirho}: {page_chirho}");
        assert_eq!(
            head_version_chirho(&page_chirho),
            Some(1),
            "{engine_chirho}"
        );
        assert!(
            page_chirho.contains(&encoded_page_chirho),
            "{engine_chirho}: {page_chirho}"
        );
        cookie_chirho
    };

    // R15 first: a mutant that breaks retirement meets the predecessor's half of the arm, which no in-process arm has.
    let copy_chirho = RootCopyChirho::of_chirho(root_chirho, "k1-rb-retire-r15");
    let r15_chirho = TwinServerChirho::start_chirho(&twin_chirho, &copy_chirho);
    let cookie_chirho = check_engine_chirho("R15", &r15_chirho.addr_chirho);
    // R15's own key list ends the retired key: of user 0's keys on the opened app, the legacy one is not live.
    let (status_chirho, list_chirho) = probe_chirho(
        &r15_chirho.addr_chirho,
        "GET",
        "/auth-chirho/keys-chirho",
        &[("cookie", &cookie_chirho)],
        b"",
    );
    assert_eq!(status_chirho, 200, "{list_chirho}");
    let list_chirho: serde_json::Value = serde_json::from_str(&list_chirho).unwrap();
    let rows_chirho: Vec<&serde_json::Value> = list_chirho["keys_chirho"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row_chirho| row_chirho["app_chirho"] == KEYED_APP_CHIRHO)
        .collect();
    let legacy_chirho: Vec<&&serde_json::Value> = rows_chirho
        .iter()
        .filter(|row_chirho| {
            !row_chirho["scopes_chirho"]
                .as_array()
                .unwrap()
                .iter()
                .any(|scope_chirho| {
                    scope_chirho
                        == cairn_chirho::capability_key_grant_chirho::LIMITED_KEY_SCOPE_MARKER_CHIRHO
                })
        })
        .collect();
    assert_eq!(legacy_chirho.len(), 1, "{rows_chirho:?}");
    assert_eq!(legacy_chirho[0]["live_chirho"], false, "{rows_chirho:?}");
    eprintln!(
        "R15's key list for user 0 on the opened app: {} rows, {} marked live (limited rows R15 lists but cannot find)",
        rows_chirho.len(),
        rows_chirho
            .iter()
            .filter(|row_chirho| row_chirho["live_chirho"] == true)
            .count()
    );
    drop(r15_chirho);

    let successor_copy_chirho = RootCopyChirho::of_chirho(root_chirho, "k1-rb-retire-successor");
    with_successor_served_chirho(&successor_copy_chirho.tenant_root_chirho, |addr_chirho| {
        check_engine_chirho("the successor", addr_chirho);
    });
}

#[test]
#[ignore = "runs R15's twin: set CAIRN_R15_TWIN_CHIRHO and pass --ignored"]
fn r15_mints_an_unrestricted_key_for_a_successor_registered_client_and_roll_forward_refuses_it_chirho(
) {
    let twin_chirho = r15_twin_chirho();
    let successor_chirho = successor_chirho("k1-rb-client");
    let tenant_chirho = &successor_chirho.tenant_chirho;
    let (principal_chirho, credential_chirho) = tenant_chirho.user_chirho(0);
    let token_request_chirho = serde_json::to_vec(&serde_json::json!({
        "principal_chirho": principal_chirho,
        "credential_chirho": credential_chirho,
        "client_id_chirho": tenant_chirho.client_id_chirho,
        "scopes_chirho": [],
    }))
    .unwrap();
    let json_chirho = [("content-type", "application/json")];

    let copy_chirho = RootCopyChirho::of_chirho(&tenant_chirho.root_chirho, "k1-rb-client-r15");
    let r15_chirho = TwinServerChirho::start_chirho(&twin_chirho, &copy_chirho);
    let addr_chirho = r15_chirho.addr_chirho.clone();
    // The hazard: R15's JSON road mints a legacy key for the client the successor registered BEFORE the app opened (a
    // K1-era root). K4 puts a client registered after an app opens in the connection store, which R15 never reads, so it
    // mints nothing for it: `connection_real_rollback_tests_chirho.rs`.
    let (status_chirho, minted_chirho) = probe_chirho(
        &addr_chirho,
        "POST",
        "/auth-chirho/token-chirho",
        &json_chirho,
        &token_request_chirho,
    );
    assert_eq!(status_chirho, 200, "{minted_chirho}");
    let minted_chirho: serde_json::Value = serde_json::from_str(&minted_chirho).unwrap();
    let minted_chirho = minted_chirho["token_chirho"].as_str().unwrap().to_string();
    // On R15 that key reads the page and saves over it: nothing there limits it.
    let (status_chirho, page_chirho) = probe_chirho(
        &addr_chirho,
        "GET",
        &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
        &[("authorization", &bearer_chirho(&minted_chirho))],
        b"",
    );
    assert_eq!(status_chirho, 200, "{page_chirho}");
    assert!(
        page_chirho.contains(&encoded_chirho(PAGE_TEXT_CHIRHO)),
        "{page_chirho}"
    );
    let overwrite_chirho = write_request_chirho(Some(1), "written through the minted key");
    let (status_chirho, saved_chirho) = probe_chirho(
        &addr_chirho,
        "POST",
        &keyed_path_chirho(SAVE_ROUTE_CHIRHO),
        &[("authorization", &bearer_chirho(&minted_chirho))],
        overwrite_chirho.as_bytes(),
    );
    assert_eq!(status_chirho, 200, "{saved_chirho}");
    drop(r15_chirho);

    // Roll forward on the copy R15 wrote: the successor verifies R15's token rows and refuses the minted key.
    cairn_chirho::oauth_chirho::verify_scoped_tokens_chirho(&copy_chirho.tenant_root_chirho)
        .unwrap();
    with_successor_served_chirho(&copy_chirho.tenant_root_chirho, |addr_chirho| {
        for (method_chirho, path_chirho, body_chirho) in [
            ("GET", keyed_path_chirho(VIEW_ROUTE_CHIRHO), b"".as_slice()),
            (
                "GET",
                format!("/app-chirho/{KEYED_APP_CHIRHO}/"),
                b"".as_slice(),
            ),
            (
                "POST",
                keyed_path_chirho(SAVE_ROUTE_CHIRHO),
                overwrite_chirho.as_bytes(),
            ),
        ] {
            let (status_chirho, body_chirho) = probe_chirho(
                addr_chirho,
                method_chirho,
                &path_chirho,
                &[("authorization", &bearer_chirho(&minted_chirho))],
                body_chirho,
            );
            assert_eq!(
                status_chirho, 403,
                "{method_chirho} {path_chirho}: {body_chirho}"
            );
            assert_eq!(
                identity_line_chirho(&body_chirho),
                ROUTE_NOT_OPEN_LINE_CHIRHO,
                "{method_chirho} {path_chirho}"
            );
        }
        // The limited key still reads the page, now at the version R15's write made.
        let (status_chirho, page_chirho) = probe_chirho(
            addr_chirho,
            "GET",
            &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
            &[(
                "authorization",
                &bearer_chirho(&successor_chirho.read_chirho),
            )],
            b"",
        );
        assert_eq!(status_chirho, 200, "{page_chirho}");
        assert_eq!(head_version_chirho(&page_chirho), Some(2));
        // And the successor issues no legacy key for that client, saying why.
        let (status_chirho, refusal_chirho) = probe_chirho(
            addr_chirho,
            "POST",
            "/auth-chirho/token-chirho",
            &json_chirho,
            &token_request_chirho,
        );
        assert_eq!(status_chirho, 400, "{refusal_chirho}");
        assert!(
            refusal_chirho.contains(&oauth_chirho::LegacyKeyForLimitedAppChirho.to_string()),
            "{refusal_chirho}"
        );
    });
}

/// On R15, the legacy key is answered exactly as a made-up bearer, and the unopened app's legacy key works.
fn assert_r15_honours_no_retired_key_chirho(
    twin_chirho: &Path,
    tenant_root_chirho: &Path,
    label_chirho: &str,
    legacy_chirho: &str,
    control_chirho: &str,
) {
    let copy_chirho = RootCopyChirho::of_chirho(tenant_root_chirho, label_chirho);
    let r15_chirho = TwinServerChirho::start_chirho(twin_chirho, &copy_chirho);
    let addr_chirho = r15_chirho.addr_chirho.clone();
    let legacy_answer_chirho = probe_chirho(
        &addr_chirho,
        "GET",
        &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
        &[("authorization", &bearer_chirho(legacy_chirho))],
        b"",
    );
    let made_up_chirho = probe_chirho(
        &addr_chirho,
        "GET",
        &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
        &[("authorization", &bearer_chirho(MADE_UP_BEARER_CHIRHO))],
        b"",
    );
    assert!(
        (400..500).contains(&legacy_answer_chirho.0),
        "{label_chirho}: {legacy_answer_chirho:?}"
    );
    assert_eq!(
        legacy_answer_chirho, made_up_chirho,
        "{label_chirho}: R15 honours the legacy key"
    );
    let (status_chirho, page_chirho) = probe_chirho(
        &addr_chirho,
        "GET",
        &format!("/app-chirho/{GROWTH_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}"),
        &[("authorization", &bearer_chirho(control_chirho))],
        b"",
    );
    assert_eq!(
        status_chirho, 200,
        "{label_chirho}: the control key: {page_chirho}"
    );
    drop(r15_chirho);
}

#[test]
#[ignore = "runs R15's twin: set CAIRN_R15_TWIN_CHIRHO and pass --ignored"]
fn an_interrupted_opt_in_leaves_nothing_r15_would_honour_chirho() {
    let twin_chirho = r15_twin_chirho();
    // The app opens nothing yet: user 0 holds a legacy key on it, and user 1 one on the app that never opens anything.
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k1-rb-interrupt", OpeningsChirho::NONE_CHIRHO, 2);
    let legacy_chirho = token_of_chirho(
        &tenant_chirho
            .try_legacy_bearer_chirho(0)
            .expect("an app that opens nothing issues legacy keys"),
    );
    let (dirs_chirho, control_chirho) = control_app_chirho(&tenant_chirho, "k1-rb-interrupt");
    // The opt-in stops inside its locked section, after its retirements and before its record, as a crash would.
    cairn_chirho::app_manifest_chirho::set_opt_in_hold_chirho(|| {
        anyhow::bail!("the process stops here")
    });
    // A K1-era root: a legacy client before the app's first opening, which K4 refuses (built through the seam).
    let failure_chirho = cairn_chirho::oauth_chirho::with_k1_era_opening_chirho(|| {
        tenant_chirho.try_deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |_| {})
    })
    .expect_err("the interrupted opt-in fails");
    assert!(
        format!("{failure_chirho:#}")
            .contains("were retired, but its opening to limited keys was not recorded"),
        "{failure_chirho:#}"
    );
    // That exact prefix, served by R15: no legacy key of the app is live, and the control still works.
    assert_r15_honours_no_retired_key_chirho(
        &twin_chirho,
        &tenant_chirho.root_chirho,
        "k1-rb-interrupt-r15",
        &legacy_chirho,
        &control_chirho,
    );
    // And no opening is on disk: the stop came before the record.
    assert!(cairn_chirho::app_chirho::app_key_authority_record_chirho(
        &tenant_chirho.root_chirho,
        KEYED_APP_CHIRHO
    )
    .unwrap()
    .is_none());
    // Deploying again finishes the opt-in, and R15 still honours no legacy key of the app.
    // A K1-era root: a legacy client before the app's first opening, which K4 refuses (built through the seam).
    cairn_chirho::oauth_chirho::with_k1_era_opening_chirho(|| {
        tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |_| {})
    });
    assert!(cairn_chirho::app_chirho::app_key_authority_record_chirho(
        &tenant_chirho.root_chirho,
        KEYED_APP_CHIRHO
    )
    .unwrap()
    .is_some());
    assert_r15_honours_no_retired_key_chirho(
        &twin_chirho,
        &tenant_chirho.root_chirho,
        "k1-rb-interrupt-done-r15",
        &legacy_chirho,
        &control_chirho,
    );
    for dir_chirho in dirs_chirho {
        let _ = std::fs::remove_dir_all(dir_chirho);
    }
}
