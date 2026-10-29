// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The publish route must refuse a non-owner BEFORE any durable write.
//!
//! MEASURED BEFORE THIS GATE, at d79da456 on a binary whose running digest was captured live: a
//! user-kind session publishing a VALID package received 400 "app owner must be an owner principal"
//! from `deploy_app_chirho` — with BOTH declared objects already durably in CAS and no rollback.
//! The authority check ran after the write.
//!
//! The load-bearing assertion here is the ZERO DURABLE DELTA, not the status code. A refusal with
//! objects written is exactly the pre-gate behaviour, so a status-only arm passes against the
//! unfixed code and proves nothing.

use cairn_chirho::{app_chirho, identity_chirho};
use cairn_serve_runtime_chirho::serve_quiet_with_registration_token_chirho;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
};

const REG_TOKEN_CHIRHO: &str = "publish-gate-reg-token-chirho";
const PUBLISH_TOKEN_CHIRHO: &str = "publish-gate-publish-token-chirho";
const CREDENTIAL_CHIRHO: &str = "PublishGateP4ssw0rd";

/// User-kind session: refused, and NOTHING durable is written. The arm this gate exists for.
#[test]
fn a_user_session_publish_is_refused_with_zero_durable_delta_chirho() {
    with_server_chirho("user-zero-delta", |root_chirho, addr_chirho| {
        let user_chirho = register_user_chirho(addr_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &user_chirho);
        let (dag_chirho, dag_hex_chirho) = dag_object_chirho();
        let marker_chirho = format!("PUBLISH-GATE-MARKER-{}-chirho", std::process::id());
        let (mark_chirho, mark_hex_chirho) = marker_object_chirho(&marker_chirho);

        let before_chirho = inventory_chirho(root_chirho);
        let response_chirho = publish_chirho(
            addr_chirho,
            &token_chirho,
            &package_chirho(
                &user_chirho,
                &dag_chirho,
                &dag_hex_chirho,
                &mark_chirho,
                &mark_hex_chirho,
            ),
        );
        let after_chirho = inventory_chirho(root_chirho);

        // Refusal CLASS, not a pinned code: the status is not the invariant and pinning 403 would
        // make this arm brittle to a reasonable refusal-shape change. Zero durable delta is the
        // invariant, and it is what discriminates the fixed code from the unfixed — the pre-gate
        // behaviour ALSO refused, at 400, after writing.
        assert!(
            (400..500).contains(&response_chirho.status_chirho),
            "a non-owner must be refused, got {}",
            response_chirho.status_chirho
        );
        // THE LOAD-BEARING ASSERTIONS. Status alone passes against the unfixed code.
        assert_eq!(
            after_chirho, before_chirho,
            "a refused non-owner publish must leave ZERO durable delta; before={before_chirho:?} after={after_chirho:?}"
        );
        assert!(
            !marker_present_chirho(root_chirho, &marker_chirho),
            "the caller's own bytes must not reach the store on a refused publish"
        );
    });
}

/// THE ARM THAT PROVES THE CHECK IS THE *VERIFIED* ONE.
///
/// A user's identity row is edited to `owner` WITHOUT RE-SIGNING. Session validation still succeeds
/// — it uses the unchanged identity public key — so the request reaches the gate carrying a row that
/// merely *claims* Owner.
///
/// A raw `find_identity_chirho` gate reads `load_identities_chirho`, which checks the schema string
/// only, would see "owner", ADMIT the write, and leave the refusal to the verified late gate — after
/// the CAS objects had landed. That is the ordering defect this gate exists to close, so an early
/// gate built on the raw read would pass every other arm here while failing exactly this one.
#[test]
fn a_kind_corrupted_without_resigning_is_refused_with_zero_durable_delta_chirho() {
    with_server_chirho("corrupt-kind", |root_chirho, addr_chirho| {
        let user_chirho = register_user_chirho(addr_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &user_chirho);

        // Tamper: claim Owner, leave the signature untouched.
        let log_chirho = root_chirho.join("identities-chirho.jsonl");
        let text_chirho = std::fs::read_to_string(&log_chirho).expect("identity log");
        // The enum serialises as its variant name verbatim — "UserChirho", not "user". The first
        // version of this tamper used "user" and matched nothing; the arming assertion below caught
        // it, which is the only reason this arm is not vacuous.
        let tampered_chirho = text_chirho.replace(
            "\"kind_chirho\":\"UserChirho\"",
            "\"kind_chirho\":\"OwnerChirho\"",
        );
        assert_ne!(
            tampered_chirho, text_chirho,
            "arming: the tamper must actually change the identity log, or this arm proves nothing"
        );
        std::fs::write(&log_chirho, &tampered_chirho).expect("write tampered log");

        let (dag_chirho, dag_hex_chirho) = dag_object_chirho();
        let marker_chirho = format!("CORRUPT-KIND-MARKER-{}-chirho", std::process::id());
        let (mark_chirho, mark_hex_chirho) = marker_object_chirho(&marker_chirho);

        let before_chirho = inventory_chirho(root_chirho);
        let response_chirho = publish_chirho(
            addr_chirho,
            &token_chirho,
            &package_chirho(
                &user_chirho,
                &dag_chirho,
                &dag_hex_chirho,
                &mark_chirho,
                &mark_hex_chirho,
            ),
        );
        let after_chirho = inventory_chirho(root_chirho);

        assert!(
            (400..500).contains(&response_chirho.status_chirho),
            "a row claiming Owner without a valid signature must be refused, got {}: {}",
            response_chirho.status_chirho,
            String::from_utf8_lossy(&response_chirho.body_chirho)
        );
        assert_eq!(
            after_chirho, before_chirho,
            "an unverifiable Owner claim must leave ZERO durable delta"
        );
        assert!(
            !marker_present_chirho(root_chirho, &marker_chirho),
            "the caller's bytes must not reach the store behind a forged kind"
        );
    });
}

/// Owner-kind session still publishes, and the app AUTHORITATIVELY exists. Without the second half
/// a gate that returned 200 while publishing nothing would pass.
#[test]
fn an_owner_session_publish_still_succeeds_chirho() {
    with_server_chirho("owner-live", |root_chirho, addr_chirho| {
        let owner_chirho = register_owner_chirho(root_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &owner_chirho);
        let (dag_chirho, dag_hex_chirho) = dag_object_chirho();
        let (mark_chirho, mark_hex_chirho) = marker_object_chirho("owner-arm-payload-chirho");

        let response_chirho = publish_chirho(
            addr_chirho,
            &token_chirho,
            &package_chirho(
                &owner_chirho,
                &dag_chirho,
                &dag_hex_chirho,
                &mark_chirho,
                &mark_hex_chirho,
            ),
        );
        assert_eq!(
            response_chirho.status_chirho,
            200,
            "owner publication must remain live: {}",
            String::from_utf8_lossy(&response_chirho.body_chirho)
        );
        assert_published_chirho(root_chirho, &dag_chirho, &mark_chirho, &owner_chirho);
    });
}

/// The configured publish-token branch returns before the new gate and must still PUBLISH.
///
/// A real OWNER package is used and 200 is required. `assert_ne!(403)` would be a false green: the
/// unfixed late refusal is 400, which also satisfies "not 403" while proving nothing about
/// publication succeeding.
#[test]
fn the_configured_publish_token_branch_still_publishes_chirho() {
    with_server_chirho("token-branch", |root_chirho, addr_chirho| {
        let owner_chirho = register_owner_chirho(root_chirho);
        let (dag_chirho, dag_hex_chirho) = dag_object_chirho();
        let (mark_chirho, mark_hex_chirho) = marker_object_chirho("token-arm-payload-chirho");

        let response_chirho = publish_chirho(
            addr_chirho,
            PUBLISH_TOKEN_CHIRHO,
            &package_chirho(
                &owner_chirho,
                &dag_chirho,
                &dag_hex_chirho,
                &mark_chirho,
                &mark_hex_chirho,
            ),
        );
        assert_eq!(
            response_chirho.status_chirho,
            200,
            "configured-token publication must remain LIVE: {}",
            String::from_utf8_lossy(&response_chirho.body_chirho)
        );
        assert_published_chirho(root_chirho, &dag_chirho, &mark_chirho, &owner_chirho);
    });
}

// ---------- harness ----------

fn with_server_chirho(tag_chirho: &str, body_chirho: impl FnOnce(&Path, &str)) {
    let root_chirho = temp_root_chirho(tag_chirho);
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_with_registration_token_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                PUBLISH_TOKEN_CHIRHO.to_string(),
                REG_TOKEN_CHIRHO.to_string(),
            )
            .await
        });
        wait_for_serve_chirho(&addr_chirho);
        body_chirho(&root_chirho, &addr_chirho);
        server_chirho.abort();
    });
}

fn register_user_chirho(addr_chirho: &str) -> String {
    let page_chirho = http_get_chirho(addr_chirho, "/auth-chirho/register-chirho");
    let html_chirho = String::from_utf8(page_chirho.body_chirho).unwrap();
    let token_chirho = between_chirho(
        &html_chirho,
        "name=\"human_check_token_chirho\" value=\"",
        "\"",
    );
    // The form carries THREE <label> elements — registration token, password, and the arithmetic
    // challenge. Taking the first one yields "registration token ..." and a silent answer of 0, so
    // select the label that actually parses as `<int> + <int>`.
    let answer_chirho: u32 = html_chirho
        .split("<label>")
        .filter_map(|segment_chirho| segment_chirho.split(" =").next())
        .find_map(|candidate_chirho| {
            let (left_chirho, right_chirho) = candidate_chirho.trim().split_once(" + ")?;
            Some(
                left_chirho.trim().parse::<u32>().ok()?
                    + right_chirho.trim().parse::<u32>().ok()?,
            )
        })
        .expect("the register page must present a solvable arithmetic challenge");
    let body_chirho = format!(
        "kind_chirho=user&registration_token_chirho={REG_TOKEN_CHIRHO}&credential_chirho={CREDENTIAL_CHIRHO}\
         &human_check_token_chirho={token_chirho}&human_check_chirho={answer_chirho}"
    );
    let response_chirho = http_post_chirho(
        addr_chirho,
        "/auth-chirho/register-chirho",
        "application/x-www-form-urlencoded",
        &body_chirho,
        None,
    );
    let text_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
    principal_in_chirho(&text_chirho, "user/").unwrap_or_else(|| {
        panic!(
            "registration must mint a user principal; status={} body={text_chirho}",
            response_chirho.status_chirho
        )
    })
}

fn register_owner_chirho(root_chirho: &Path) -> String {
    let record_chirho = identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        CREDENTIAL_CHIRHO,
    )
    .expect("owner registration");
    record_chirho.principal_chirho
}

fn login_token_chirho(addr_chirho: &str, principal_chirho: &str) -> String {
    let body_chirho =
        format!("principal_chirho={principal_chirho}&credential_chirho={CREDENTIAL_CHIRHO}");
    let response_chirho = http_post_chirho(
        addr_chirho,
        "/auth-chirho/login-chirho",
        "application/x-www-form-urlencoded",
        &body_chirho,
        None,
    );
    let cookie_chirho = response_chirho
        .headers_chirho
        .iter()
        .find(|line_chirho| line_chirho.to_ascii_lowercase().starts_with("set-cookie:"))
        .expect("login must set a session cookie");
    // The cookie is `principal:token`; validate_session_token_chirho hashes the TOKEN ALONE.
    let value_chirho = between_chirho(cookie_chirho, "cairn_session_chirho=", ";");
    value_chirho
        .split_once(':')
        .map(|(_, t_chirho)| t_chirho.to_string())
        .unwrap_or(value_chirho)
}

fn dag_object_chirho() -> (String, String) {
    let bytes_chirho = br#"{"nodes_chirho":[],"edges_chirho":[]}"#.to_vec();
    (
        blake3::hash(&bytes_chirho).to_hex().to_string(),
        hex_chirho(&bytes_chirho),
    )
}

fn marker_object_chirho(payload_chirho: &str) -> (String, String) {
    let bytes_chirho = payload_chirho.as_bytes().to_vec();
    (
        blake3::hash(&bytes_chirho).to_hex().to_string(),
        hex_chirho(&bytes_chirho),
    )
}

fn package_chirho(
    owner_chirho: &str,
    dag_chirho: &str,
    dag_hex_chirho: &str,
    mark_chirho: &str,
    mark_hex_chirho: &str,
) -> String {
    format!(
        "{{\"name_chirho\":\"gate-arm-chirho\",\"owner_chirho\":\"{owner_chirho}\",\
          \"dag_chirho\":\"{dag_chirho}\",\"objects_chirho\":[\
          {{\"hash_chirho\":\"{dag_chirho}\",\"bytes_hex_chirho\":\"{dag_hex_chirho}\"}},\
          {{\"hash_chirho\":\"{mark_chirho}\",\"bytes_hex_chirho\":\"{mark_hex_chirho}\"}}]}}"
    )
}

fn publish_chirho(
    addr_chirho: &str,
    bearer_chirho: &str,
    package_chirho: &str,
) -> HttpResponseChirho {
    http_post_chirho(
        addr_chirho,
        "/publish-chirho",
        "application/json",
        package_chirho,
        Some(bearer_chirho),
    )
}

/// Every file under the root as (relative path, CONTENT HASH).
///
/// A path-only inventory is a FALSE GREEN, and the first version of this arm was one: appending to
/// an existing jsonl or rewriting a ref in place leaves the path set identical, so "unchanged" would
/// be asserted over a root that had in fact been written to.
///
/// The read `expect`s rather than substituting a placeholder: a literal stand-in would make two
/// unreadable files compare EQUAL, which is a false green inside the fix for a false green. An
/// unreadable file makes the snapshot unprovable and must abort the arm.
fn inventory_chirho(root_chirho: &Path) -> Vec<(String, String)> {
    let mut paths_chirho = Vec::new();
    collect_chirho(root_chirho, &mut paths_chirho);
    paths_chirho.sort();
    let prefix_chirho = format!("{}/", root_chirho.display());
    paths_chirho
        .into_iter()
        .map(|path_chirho| {
            let relative_chirho = path_chirho
                .strip_prefix(&prefix_chirho)
                .unwrap_or(&path_chirho)
                .to_string();
            let bytes_chirho = std::fs::read(&path_chirho).unwrap_or_else(|error_chirho| {
                panic!("inventory must read {path_chirho}: {error_chirho}")
            });
            (
                relative_chirho,
                blake3::hash(&bytes_chirho).to_hex().to_string(),
            )
        })
        .collect()
}

/// A 200 is not publication, and neither is "the route did not 404".
///
/// Requires the AUTHORITATIVE control-plane state: the app is active, its DAG is exactly the one
/// published, and its owner is exactly the expected principal. `status != 404` would pass on 400,
/// 403 and 500, and binds nothing to the DAG or the owner.
fn assert_published_chirho(
    root_chirho: &Path,
    dag_chirho: &str,
    mark_chirho: &str,
    expected_owner_chirho: &str,
) {
    for hash_chirho in [dag_chirho, mark_chirho] {
        let object_chirho = root_chirho
            .join("objects-chirho")
            .join(&hash_chirho[..2])
            .join(&hash_chirho[2..]);
        assert!(
            object_chirho.is_file(),
            "published object {hash_chirho} must be in CAS"
        );
        let bytes_chirho = std::fs::read(&object_chirho).expect("read published object");
        assert_eq!(
            blake3::hash(&bytes_chirho).to_hex().to_string(),
            hash_chirho,
            "stored object must hash to the name it was published under"
        );
    }

    let status_chirho =
        app_chirho::app_status_chirho(root_chirho, "gate-arm-chirho").expect("app status");
    assert!(
        status_chirho.active_chirho,
        "the published app must be active"
    );
    assert_eq!(
        status_chirho
            .dag_chirho
            .as_ref()
            .map(|hash_chirho| hash_chirho.0.as_str()),
        Some(dag_chirho),
        "the app ref must bind the exact published DAG"
    );
    assert_eq!(
        status_chirho.owner_principal_chirho.as_deref(),
        Some(expected_owner_chirho),
        "the app must be owned by the publishing principal"
    );

    // NO HTTP SERVE PROBE HERE, and the reason is measured rather than assumed. A correctly
    // published minimal app returns 400 from the route, refused at its input site (the public body
    // is the fixed identity `app-input-refused-chirho`; the input-policy verifier's own answer is
    // "needs a signed input policy before request bodies can be handled") — a separate and correct
    // runtime gate. Requiring a success class would force this arm to also
    // deploy an input policy, which has nothing to do with the owner gate under test, and a
    // `!= 404` probe would pass on 400/403/500 and prove nothing.
    //
    // The control-plane assertions above are STRICTLY more authoritative than any status code: the
    // app is active, bound to the exact published DAG, and owned by the exact publishing principal.
}

/// Strict traversal. A silent return on `read_dir` failure, or `flatten()` swallowing entry errors,
/// would report a hidden subtree as ABSENCE — the same default-on-error bug as a placeholder hash,
/// and it would make both the zero-delta snapshot and the marker control silently incomplete.
fn collect_chirho(dir_chirho: &Path, out_chirho: &mut Vec<String>) {
    let entries_chirho = std::fs::read_dir(dir_chirho).unwrap_or_else(|error_chirho| {
        panic!(
            "traversal must read {}: {error_chirho}",
            dir_chirho.display()
        )
    });
    for entry_chirho in entries_chirho {
        let entry_chirho = entry_chirho.unwrap_or_else(|error_chirho| {
            panic!(
                "traversal entry under {}: {error_chirho}",
                dir_chirho.display()
            )
        });
        let path_chirho = entry_chirho.path();
        if path_chirho.is_dir() {
            collect_chirho(&path_chirho, out_chirho);
        } else {
            out_chirho.push(path_chirho.display().to_string());
        }
    }
}

/// The marker control, reading strictly. `unwrap_or(false)` would report an UNREADABLE file as
/// "marker absent", turning the control into a source of false reassurance.
fn marker_present_chirho(root_chirho: &Path, marker_chirho: &str) -> bool {
    let mut paths_chirho = Vec::new();
    collect_chirho(root_chirho, &mut paths_chirho);
    let needle_hex_chirho = hex_chirho(marker_chirho.as_bytes());
    paths_chirho.iter().any(|path_chirho| {
        let bytes_chirho = std::fs::read(path_chirho).unwrap_or_else(|error_chirho| {
            panic!("marker control must read {path_chirho}: {error_chirho}")
        });
        String::from_utf8_lossy(&bytes_chirho).contains(marker_chirho)
            || hex_chirho(&bytes_chirho).contains(&needle_hex_chirho)
    })
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn between_chirho(haystack_chirho: &str, start_chirho: &str, end_chirho: &str) -> String {
    let Some(rest_chirho) = haystack_chirho
        .split_once(start_chirho)
        .map(|(_, r_chirho)| r_chirho)
    else {
        return String::new();
    };
    rest_chirho
        .split_once(end_chirho)
        .map(|(v_chirho, _)| v_chirho.to_string())
        .unwrap_or_default()
}

fn principal_in_chirho(text_chirho: &str, prefix_chirho: &str) -> Option<String> {
    let start_chirho = text_chirho.find(prefix_chirho)?;
    let tail_chirho = &text_chirho[start_chirho..];
    let end_chirho = tail_chirho
        .char_indices()
        .find(|(i_chirho, c_chirho)| {
            *i_chirho > prefix_chirho.len() && !c_chirho.is_ascii_hexdigit()
        })
        .map(|(i_chirho, _)| i_chirho)
        .unwrap_or(tail_chirho.len());
    Some(tail_chirho[..end_chirho].to_string())
}

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-publish-gate-{tag_chirho}-{}-chirho",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    std::fs::create_dir_all(&dir_chirho).expect("temp root");
    dir_chirho
}

fn unused_local_port_chirho() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_serve_chirho(addr_chirho: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr_chirho).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("server did not start at {addr_chirho}");
}

fn http_get_chirho(addr_chirho: &str, path_chirho: &str) -> HttpResponseChirho {
    let mut stream_chirho = TcpStream::connect(addr_chirho).expect("connect");
    let request_chirho =
        format!("GET {path_chirho} HTTP/1.1\r\nHost: {addr_chirho}\r\nConnection: close\r\n\r\n");
    stream_chirho.write_all(request_chirho.as_bytes()).unwrap();
    read_response_chirho(stream_chirho)
}

fn http_post_chirho(
    addr_chirho: &str,
    path_chirho: &str,
    content_type_chirho: &str,
    body_chirho: &str,
    bearer_chirho: Option<&str>,
) -> HttpResponseChirho {
    let mut stream_chirho = TcpStream::connect(addr_chirho).expect("connect");
    let auth_chirho = bearer_chirho
        .map(|token_chirho| format!("Authorization: Bearer {token_chirho}\r\n"))
        .unwrap_or_default();
    let request_chirho = format!(
        "POST {path_chirho} HTTP/1.1\r\nHost: {addr_chirho}\r\nContent-Type: {content_type_chirho}\r\n\
         Content-Length: {}\r\n{auth_chirho}Connection: close\r\n\r\n{body_chirho}",
        body_chirho.len()
    );
    stream_chirho.write_all(request_chirho.as_bytes()).unwrap();
    read_response_chirho(stream_chirho)
}

fn read_response_chirho(mut stream_chirho: TcpStream) -> HttpResponseChirho {
    let mut bytes_chirho = Vec::new();
    let _ = stream_chirho.read_to_end(&mut bytes_chirho);
    let text_chirho = String::from_utf8_lossy(&bytes_chirho).to_string();
    let (head_chirho, body_chirho) = text_chirho
        .split_once("\r\n\r\n")
        .unwrap_or((&text_chirho, ""));
    let mut lines_chirho = head_chirho.lines();
    let status_chirho = lines_chirho
        .next()
        .and_then(|line_chirho| line_chirho.split_whitespace().nth(1))
        .and_then(|code_chirho| code_chirho.parse().ok())
        .unwrap_or(0);
    HttpResponseChirho {
        status_chirho,
        headers_chirho: lines_chirho.map(str::to_string).collect(),
        body_chirho: body_chirho.as_bytes().to_vec(),
    }
}

struct HttpResponseChirho {
    status_chirho: u16,
    headers_chirho: Vec<String>,
    body_chirho: Vec<u8>,
}
