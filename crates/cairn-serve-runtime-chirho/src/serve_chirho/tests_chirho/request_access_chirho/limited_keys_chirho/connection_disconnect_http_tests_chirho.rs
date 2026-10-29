// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 CP5's served arm: K3's Disconnect ends a CONNECTION over HTTP. The keyed tenant's app opens before its client
//! registers, so the client is a connection client and its user's limited key lives in the connection token log.
//! Workflows: the owner's keys page (K3), `spec-chirho/workflows-chirho/identity-auth-chirho/own-keys-page-chirho.md`;
//! the connection carrier (K4), `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md`.

use super::limited_key_fixture_chirho::*;
use super::*;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::HeaderName;
use std::path::Path;

const VIEW_PATH_CHIRHO: &str = "/app-chirho/keyedapp/view";

fn header_text_chirho(headers_chirho: &HeaderMap, name_chirho: HeaderName) -> String {
    headers_chirho
        .get(name_chirho)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn log_lines_chirho(root_chirho: &Path, name_chirho: &str) -> usize {
    std::fs::read_to_string(root_chirho.join(name_chirho))
        .map(|text_chirho| text_chirho.lines().count())
        .unwrap_or(0)
}

/// The owner's JSON key list over HTTP.
fn key_rows_chirho(addr_chirho: &str, cookie_chirho: &str) -> Vec<serde_json::Value> {
    let response_chirho = http_request_for_smoke_chirho(
        addr_chirho,
        "GET",
        "/auth-chirho/keys-chirho",
        &[("cookie", cookie_chirho)],
        b"",
    );
    assert_eq!(response_chirho.status_chirho, 200);
    let list_chirho: serde_json::Value =
        serde_json::from_str(&http_body_text_chirho(&response_chirho)).unwrap();
    list_chirho["keys_chirho"].as_array().unwrap().clone()
}

/// K3'S DISCONNECT ENDS A CONNECTION OVER HTTP: over a real local server, the connection answers its view; the owner's
/// key list shows it live; the no-script form ends it by the key id the list gave, answering 303 to the notice
/// fragment; the connection then refuses, and the list shows it ended. Nothing reaches the legacy token log.
///
/// MIGRATION PATH: a 200 after the Disconnect means the revoke missed the connection's session; a list without the
/// connection means K3's list reads only the legacy store.
#[test]
fn k3_disconnect_ends_a_connection_over_http_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4-disconnect", OpeningsChirho::PAGE_CHIRHO, 1);
    assert_eq!(
        oauth_chirho::find_client_in_store_chirho(
            &tenant_chirho.root_chirho,
            &tenant_chirho.client_id_chirho
        )
        .unwrap()
        .map(|(_client_chirho, store_chirho)| store_chirho),
        Some(oauth_chirho::KeyStoreChirho::ConnectionChirho)
    );
    let bearer_chirho = header_text_chirho(
        &tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]),
        AUTHORIZATION,
    );
    let cookie_chirho = header_text_chirho(&tenant_chirho.cookie_chirho(0), COOKIE);
    assert_eq!(
        (
            log_lines_chirho(&tenant_chirho.root_chirho, "scoped-tokens-chirho.jsonl"),
            log_lines_chirho(&tenant_chirho.root_chirho, "connection-tokens-chirho.jsonl")
        ),
        (0, 1)
    );
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = tenant_chirho.root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let view_status_chirho = || {
            http_request_for_smoke_chirho(
                &addr_chirho,
                "GET",
                VIEW_PATH_CHIRHO,
                &[("authorization", bearer_chirho.as_str())],
                b"",
            )
            .status_chirho
        };
        assert_eq!(view_status_chirho(), 200, "the connection answers its view");

        let rows_chirho = key_rows_chirho(&addr_chirho, &cookie_chirho);
        assert_eq!(rows_chirho.len(), 1, "{rows_chirho:?}");
        assert_eq!(rows_chirho[0]["live_chirho"], true);
        let key_id_chirho = rows_chirho[0]["key_id_chirho"]
            .as_str()
            .unwrap()
            .to_string();
        let mut form_chirho = url::form_urlencoded::Serializer::new(String::new());
        form_chirho.append_pair("key_id_chirho", &key_id_chirho);
        form_chirho.append_pair("redirect_chirho", VIEW_PATH_CHIRHO);
        let ended_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/key-revoke-chirho",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", cookie_chirho.as_str()),
            ],
            form_chirho.finish().as_bytes(),
        );
        assert_eq!(ended_chirho.status_chirho, 303);
        assert_eq!(
            ended_chirho
                .headers_chirho
                .get("location")
                .map(String::as_str),
            Some(format!("{VIEW_PATH_CHIRHO}#notice-key-ended-chirho").as_str())
        );

        assert_eq!(view_status_chirho(), 403, "the ended connection is refused");
        let rows_chirho = key_rows_chirho(&addr_chirho, &cookie_chirho);
        assert_eq!(
            (rows_chirho.len(), &rows_chirho[0]["live_chirho"]),
            (1, &serde_json::Value::Bool(false)),
            "the ended connection stays listed, as ended"
        );
        server_chirho.abort();
    });
    assert_eq!(
        log_lines_chirho(&tenant_chirho.root_chirho, "scoped-tokens-chirho.jsonl"),
        0,
        "nothing reached the legacy token log"
    );
}
