// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4's full-state rollback MEASUREMENT (PFE #26751): R15's exact executable serves a root holding an actually issued
//! successor connection, beside an unopened app's legacy key, browser sign-in and an operator recovery code. The
//! connection is a limited key for an opened app, which it used to save a page.
//!
//! Three placements of the connection's records are measured, each on its own copy of one root:
//! - today: every record in the shared logs, as the successor writes them now;
//! - client only: the connection's client in a log R15 never reads (the K4 proposal's first draft);
//! - isolated: the connection's client, token and use rows all in logs R15 never reads.
//!
//! The isolated placements are SIMULATED, by moving the connection's rows into the files a K4 successor would write. In
//! the token and use logs those rows are the tail, so those logs stay contiguous. **The client log does NOT (PFE
//! #26764):** the keyed client is seq 0 and the control client seq 1, so an isolated copy keeps client seq 1 with no
//! seq 0. R15's request path never checks client sequences, so the HTTP rows stand, but those copies are not valid
//! roots (`verify_clients_chirho` refuses a seq gap). Valid-root evidence is CP7's real-write arm.
//!
//! This measures the carrier's placement; it is not a candidate's arm. Run:
//! `CAIRN_R15_TWIN_CHIRHO=<R15's macOS twin> cargo test -p cairn-serve-runtime-chirho --lib connection_rollback -- --ignored --nocapture`.

use super::app_route_fixture_chirho::{
    counted_road_runtime_chirho, write_request_chirho, GROWTH_APP_CHIRHO,
};
use super::limited_key_fixture_chirho::*;
use super::limited_key_rollback_tests_chirho::{
    control_app_chirho, keyed_path_chirho, r15_twin_chirho, sign_in_chirho, token_of_chirho,
    RootCopyChirho, TwinServerChirho,
};
use super::*;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

const PAGE_TEXT_CHIRHO: &str = "the page a connection saved";
const NEW_CREDENTIAL_CHIRHO: &str = "recovered-credential-value-chirho";
const CONTROL_VIEW_CHIRHO: &str = "/app-chirho/routegrowth/view";

#[derive(Clone, Copy, Debug)]
enum PlacementChirho {
    TodayChirho,
    ClientOnlyChirho,
    IsolatedChirho,
}

/// The successor's root: an unopened app with user 1's legacy key, used once, and then the connection: the keyed app
/// opened for its page routes, user 0's limited key, used to save a page. User 0 also holds an operator recovery code.
struct FullStateChirho {
    tenant_chirho: KeyedTenantChirho,
    control_key_chirho: String,
    control_client_chirho: String,
    connection_key_chirho: String,
    recovery_code_chirho: String,
    dirs_chirho: Vec<PathBuf>,
}

impl Drop for FullStateChirho {
    fn drop(&mut self) {
        for dir_chirho in &self.dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

fn full_state_chirho(label_chirho: &str) -> FullStateChirho {
    let tenant_chirho = KeyedTenantChirho::new_chirho(label_chirho, OpeningsChirho::NONE_CHIRHO, 2);
    // The unopened app and its legacy key first, so their rows lead every sequenced log.
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
    // The connection, after: the keyed app opens, user 0's limited key saves a page.
    // A K1-era root: a legacy client before the app's first opening, which K4 refuses (built through the seam).
    cairn_chirho::oauth_chirho::with_k1_era_opening_chirho(|| {
        tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |_| {})
    });
    let connection_headers_chirho =
        tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO, PAGE_SAVE_CHIRHO]);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) = post_route_chirho(
            &state_chirho,
            &connection_headers_chirho,
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
    FullStateChirho {
        connection_key_chirho: token_of_chirho(&connection_headers_chirho),
        tenant_chirho,
        control_key_chirho,
        control_client_chirho,
        recovery_code_chirho,
        dirs_chirho,
    }
}

/// Move every row naming `client_chirho` from `shared_chirho` to `own_chirho`. In a sequenced log (`tail_only_chirho`)
/// the moved rows must be the tail, so the rows that stay are contiguous; its head sidecar is removed with them.
fn move_client_rows_chirho(
    shared_chirho: &Path,
    own_chirho: &Path,
    client_chirho: &str,
    tail_only_chirho: bool,
) {
    let text_chirho = std::fs::read_to_string(shared_chirho).unwrap();
    let mut kept_chirho = String::new();
    let mut moved_chirho = String::new();
    for line_chirho in text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
    {
        let value_chirho: serde_json::Value = serde_json::from_str(line_chirho).unwrap();
        if value_chirho["client_id_chirho"].as_str() == Some(client_chirho) {
            moved_chirho.push_str(line_chirho);
            moved_chirho.push('\n');
        } else {
            assert!(
                !tail_only_chirho || moved_chirho.is_empty(),
                "{}: a kept row follows a moved one, so the simulation would leave a gap",
                shared_chirho.display()
            );
            kept_chirho.push_str(line_chirho);
            kept_chirho.push('\n');
        }
    }
    assert!(
        !moved_chirho.is_empty(),
        "{}: the connection has rows to move",
        shared_chirho.display()
    );
    std::fs::write(shared_chirho, kept_chirho).unwrap();
    std::fs::write(own_chirho, moved_chirho).unwrap();
    let _ = std::fs::remove_file(format!("{}.head-chirho", shared_chirho.display()));
}

fn place_connection_chirho(
    copy_chirho: &RootCopyChirho,
    client_chirho: &str,
    placement_chirho: PlacementChirho,
) {
    let root_chirho = &copy_chirho.tenant_root_chirho;
    let moves_chirho: &[(&str, &str, bool)] = match placement_chirho {
        PlacementChirho::TodayChirho => &[],
        PlacementChirho::ClientOnlyChirho => &[(
            "oauth-clients-chirho.jsonl",
            "oauth-connection-clients-chirho.jsonl",
            false,
        )],
        PlacementChirho::IsolatedChirho => &[
            (
                "oauth-clients-chirho.jsonl",
                "oauth-connection-clients-chirho.jsonl",
                false,
            ),
            (
                "scoped-tokens-chirho.jsonl",
                "connection-tokens-chirho.jsonl",
                true,
            ),
            (
                "scoped-token-uses-chirho.jsonl",
                "connection-token-uses-chirho.jsonl",
                true,
            ),
        ],
    };
    for (shared_chirho, own_chirho, tail_only_chirho) in moves_chirho {
        move_client_rows_chirho(
            &root_chirho.join(shared_chirho),
            &root_chirho.join(own_chirho),
            client_chirho,
            *tail_only_chirho,
        );
    }
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

/// R15 over one placement of the connection, in one row: every status the probes received.
fn r15_row_chirho(
    twin_chirho: &Path,
    full_chirho: &FullStateChirho,
    placement_chirho: PlacementChirho,
) -> String {
    let tenant_chirho = &full_chirho.tenant_chirho;
    let copy_chirho = RootCopyChirho::of_chirho(
        &tenant_chirho.root_chirho,
        &format!("k4-full-state-{placement_chirho:?}"),
    );
    place_connection_chirho(
        &copy_chirho,
        &tenant_chirho.client_id_chirho,
        placement_chirho,
    );
    let started_chirho = std::panic::catch_unwind(AssertUnwindSafe(|| {
        TwinServerChirho::start_chirho(twin_chirho, &copy_chirho)
    }));
    let Ok(server_chirho) = started_chirho else {
        let log_chirho = copy_chirho.twin_log_chirho();
        let tail_chirho: Vec<&str> = log_chirho.lines().rev().take(3).collect();
        return format!("{placement_chirho:?}: R15 did not start: {tail_chirho:?}");
    };
    let addr_chirho = server_chirho.addr_chirho.as_str();
    let json_chirho = [("content-type", "application/json")];
    let (user0_chirho, credential0_chirho) = tenant_chirho.user_chirho(0);
    let (user1_chirho, credential1_chirho) = tenant_chirho.user_chirho(1);

    let (legacy_chirho, _) = probe_chirho(
        addr_chirho,
        "GET",
        CONTROL_VIEW_CHIRHO,
        &[(
            "authorization",
            &bearer_chirho(&full_chirho.control_key_chirho),
        )],
        b"",
    );
    let (mint_chirho, minted_chirho) = probe_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/token-chirho",
        &json_chirho,
        &mint_request_chirho(
            user1_chirho,
            credential1_chirho,
            &full_chirho.control_client_chirho,
        ),
    );
    let minted_use_chirho = serde_json::from_str::<serde_json::Value>(&minted_chirho)
        .ok()
        .and_then(|value_chirho| value_chirho["token_chirho"].as_str().map(str::to_string))
        .map(|token_chirho| {
            probe_chirho(
                addr_chirho,
                "GET",
                CONTROL_VIEW_CHIRHO,
                &[("authorization", &bearer_chirho(&token_chirho))],
                b"",
            )
            .0
            .to_string()
        })
        .unwrap_or_else(|| "none".to_string());
    let (sign_in_status_chirho, cookie_chirho) =
        sign_in_chirho(addr_chirho, user1_chirho, credential1_chirho);
    let signed_in_view_chirho = cookie_chirho
        .as_deref()
        .map(|cookie_chirho| {
            probe_chirho(
                addr_chirho,
                "GET",
                CONTROL_VIEW_CHIRHO,
                &[("cookie", cookie_chirho)],
                b"",
            )
            .0
            .to_string()
        })
        .unwrap_or_else(|| "no cookie".to_string());
    let (connection_key_chirho, _) = probe_chirho(
        addr_chirho,
        "GET",
        &keyed_path_chirho(VIEW_ROUTE_CHIRHO),
        &[(
            "authorization",
            &bearer_chirho(&full_chirho.connection_key_chirho),
        )],
        b"",
    );
    let (connection_mint_chirho, _) = probe_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/token-chirho",
        &json_chirho,
        &mint_request_chirho(
            user0_chirho,
            credential0_chirho,
            &tenant_chirho.client_id_chirho,
        ),
    );
    let recover_body_chirho = serde_json::to_vec(&serde_json::json!({
        "principal_chirho": user0_chirho,
        "recovery_code_chirho": full_chirho.recovery_code_chirho,
        "new_credential_chirho": NEW_CREDENTIAL_CHIRHO,
    }))
    .unwrap();
    let (recovery_chirho, _) = probe_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/recover-chirho",
        &[
            ("content-type", "application/json"),
            ("x-forwarded-for", "203.0.113.9"),
        ],
        &recover_body_chirho,
    );
    let (after_recovery_chirho, after_cookie_chirho) =
        sign_in_chirho(addr_chirho, user0_chirho, NEW_CREDENTIAL_CHIRHO);
    format!(
        "{placement_chirho:?}: legacy key {legacy_chirho}; legacy mint {mint_chirho}, its use {minted_use_chirho}; \
         sign-in {sign_in_status_chirho}, signed-in view {signed_in_view_chirho}; connection key {connection_key_chirho}; \
         mint for the connection's client {connection_mint_chirho}; recovery {recovery_chirho}, sign-in after it \
         {after_recovery_chirho} ({})",
        if after_cookie_chirho.is_some() { "cookie set" } else { "no cookie" }
    )
}

/// THE MEASUREMENT, as first run on 2026-10-09 (PFE #26751), now pinned. R15 serves each placement of an actually
/// issued connection. One row per placement:
/// - **Today**, the hazard: R15 mints an unrestricted key for the connection's client (200).
/// - **Client only**, the K4 draft's first placement: an outage. R15's token view resolves every token's client, so
///   the connection's token, its client unknown, fails the whole view. The unrelated legacy key is refused (403), and
///   legacy minting fails (400).
/// - **Isolated**: the client, the token and its uses all out of R15's sight. Every legacy, browser and recovery control
///   works, and the connection's client mints nothing (400). Sessions stayed shared, and R15 tolerated them.
///
/// The isolated row is the shape the production carrier must reproduce with real successor writes, not this
/// simulation. A row that changes means R15's twin or the successor's records changed; read it, never wave it through.
#[test]
#[ignore = "runs R15's twin: set CAIRN_R15_TWIN_CHIRHO and pass --ignored"]
fn r15_over_each_placement_of_an_issued_connection_chirho() {
    let twin_chirho = r15_twin_chirho();
    let full_chirho = full_state_chirho("k4-full-state");
    let rows_chirho: Vec<String> = [
        PlacementChirho::TodayChirho,
        PlacementChirho::ClientOnlyChirho,
        PlacementChirho::IsolatedChirho,
    ]
    .into_iter()
    .map(|placement_chirho| r15_row_chirho(&twin_chirho, &full_chirho, placement_chirho))
    .collect();
    for row_chirho in &rows_chirho {
        eprintln!("K4 FULL STATE {row_chirho}");
    }
    let controls_chirho = "sign-in 303, signed-in view 200; connection key 403";
    let recovered_chirho = "recovery 200, sign-in after it 303 (cookie set)";
    assert_eq!(
        rows_chirho,
        vec![
            format!(
                "TodayChirho: legacy key 200; legacy mint 200, its use 200; {controls_chirho}; mint for the \
                 connection's client 200; {recovered_chirho}"
            ),
            format!(
                "ClientOnlyChirho: legacy key 403; legacy mint 400, its use none; {controls_chirho}; mint for the \
                 connection's client 400; {recovered_chirho}"
            ),
            format!(
                "IsolatedChirho: legacy key 200; legacy mint 200, its use 200; {controls_chirho}; mint for the \
                 connection's client 400; {recovered_chirho}"
            ),
        ],
        "R15 over the three placements: today mints for the connection, client-only isolation is an outage, and \
         full isolation keeps every control while refusing the connection's client"
    );
}
