// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Served arms for brick 4b-2's owner key routes over a real local server: `GET /auth-chirho/keys-chirho` lists the
//! signed-in owner's own keys and nothing else, and `POST /auth-chirho/key-revoke-chirho` revokes one by its key id,
//! with one byte-identical refusal for every id that is not hers. A revoked key then refuses on the bearer road.

use super::*;

const SECRET_CHIRHO: &str = "owner-keys-served-secret";

fn cookie_chirho(login_chirho: &identity_chirho::IdentityLoginResultChirho) -> String {
    format!(
        "cairn_session_chirho={}:{}",
        login_chirho.session_chirho.principal_chirho, login_chirho.token_chirho
    )
}

fn keys_chirho(addr_chirho: &str, cookie_chirho: Option<&str>) -> HttpSmokeResponseChirho {
    let mut headers_chirho: Vec<(&str, &str)> = Vec::new();
    if let Some(cookie_chirho) = cookie_chirho {
        headers_chirho.push(("cookie", cookie_chirho));
    }
    http_request_for_smoke_chirho(
        addr_chirho,
        "GET",
        "/auth-chirho/keys-chirho",
        &headers_chirho,
        b"",
    )
}

fn revoke_chirho(
    addr_chirho: &str,
    cookie_chirho: Option<&str>,
    body_chirho: &[u8],
) -> HttpSmokeResponseChirho {
    let mut headers_chirho: Vec<(&str, &str)> = vec![("content-type", "application/json")];
    if let Some(cookie_chirho) = cookie_chirho {
        headers_chirho.push(("cookie", cookie_chirho));
    }
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/key-revoke-chirho",
        &headers_chirho,
        body_chirho,
    )
}

fn revoke_id_chirho(
    addr_chirho: &str,
    cookie_chirho: &str,
    key_id_chirho: &str,
) -> HttpSmokeResponseChirho {
    let body_chirho = serde_json::json!({ "key_id_chirho": key_id_chirho }).to_string();
    revoke_chirho(addr_chirho, Some(cookie_chirho), body_chirho.as_bytes())
}

/// Every answer of the owner key routes must forbid caching, from the engine itself (PFE #26030).
fn assert_no_store_chirho(response_chirho: &HttpSmokeResponseChirho, what_chirho: &str) {
    assert_eq!(
        response_chirho
            .headers_chirho
            .get("cache-control")
            .map(String::as_str),
        Some("private, no-store"),
        "{what_chirho}: the engine forbids storing it"
    );
}

fn listed_ids_chirho(response_chirho: &HttpSmokeResponseChirho) -> Vec<(String, bool)> {
    let body_chirho: serde_json::Value =
        serde_json::from_str(&http_body_text_chirho(response_chirho)).unwrap();
    body_chirho["keys_chirho"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row_chirho| {
            (
                row_chirho["key_id_chirho"].as_str().unwrap().to_string(),
                row_chirho["live_chirho"].as_bool().unwrap(),
            )
        })
        .collect()
}

/// THE SERVED OWNER KEYS. Alice's cookie lists exactly her two keys (never a key, a token hash, or Bob's key) and no
/// cookie lists nothing. Bob naming Alice's key id, an unknown id and a malformed id get one byte-identical 404. Alice
/// revokes a key by its id: the key then refuses on the bearer road while her other key and Bob's keep working, a
/// repeat answers the same, and her list marks it not live. A body that is not the request shape is refused as such.
///
/// MIGRATION PATH: Bob's refusal differing from the unknown id's is an existence oracle; Bob's key or any token in
/// Alice's list is a disclosure; the revoked key answering means the revoke missed its session.
#[test]
fn served_owner_keys_list_her_own_and_revoke_by_id_with_one_refusal_chirho() {
    let root_chirho = temp_root_chirho("served-owner-keys");
    let register_chirho = || {
        identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            SECRET_CHIRHO,
        )
        .unwrap()
        .principal_chirho
    };
    let alice_chirho = register_chirho();
    let bob_chirho = register_chirho();
    let client_chirho =
        oauth_chirho::register_client_chirho(&root_chirho, "alpha", &alice_chirho).unwrap();
    let issue_chirho = |principal_chirho: &str| {
        oauth_chirho::issue_scoped_token_chirho(
            &root_chirho,
            principal_chirho,
            SECRET_CHIRHO,
            &client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
        )
        .unwrap()
    };
    let alices_chirho = [issue_chirho(&alice_chirho), issue_chirho(&alice_chirho)];
    let bobs_chirho = issue_chirho(&bob_chirho);
    let alice_cookie_chirho = cookie_chirho(
        &identity_chirho::login_identity_chirho(&root_chirho, &alice_chirho).unwrap(),
    );
    let bob_cookie_chirho =
        cookie_chirho(&identity_chirho::login_identity_chirho(&root_chirho, &bob_chirho).unwrap());
    let key_id_chirho = |issue_chirho: &oauth_chirho::ScopedTokenIssueChirho| {
        oauth_chirho::scoped_key_id_chirho(&issue_chirho.record_chirho.token_hash_chirho)
    };
    let bearer_chirho = |issue_chirho: &oauth_chirho::ScopedTokenIssueChirho| {
        oauth_chirho::validate_scoped_token_for_app_chirho(
            &root_chirho,
            "alpha",
            &issue_chirho.token_chirho,
        )
        .unwrap()
        .is_some()
    };
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let listed_chirho = keys_chirho(&addr_chirho, Some(&alice_cookie_chirho));
        assert_eq!(listed_chirho.status_chirho, 200);
        assert_no_store_chirho(&listed_chirho, "the key list");
        assert_eq!(
            listed_ids_chirho(&listed_chirho),
            alices_chirho
                .iter()
                .map(|issue_chirho| (key_id_chirho(issue_chirho), true))
                .collect::<Vec<_>>(),
            "alice sees exactly her two keys, oldest first"
        );
        let listed_text_chirho = http_body_text_chirho(&listed_chirho);
        for issue_chirho in alices_chirho.iter().chain([&bobs_chirho]) {
            assert!(
                !listed_text_chirho.contains(&issue_chirho.token_chirho),
                "never a key"
            );
            assert!(
                !listed_text_chirho.contains(&issue_chirho.record_chirho.token_hash_chirho),
                "never a token hash"
            );
        }
        assert!(
            !listed_text_chirho.contains(&key_id_chirho(&bobs_chirho)),
            "never bob's key"
        );
        let anonymous_chirho = keys_chirho(&addr_chirho, None);
        assert_eq!(anonymous_chirho.status_chirho, 401);
        assert_no_store_chirho(&anonymous_chirho, "the no-session refusal");
        assert!(http_body_text_chirho(&anonymous_chirho).contains("no-session-chirho"));

        let cross_chirho = revoke_id_chirho(
            &addr_chirho,
            &bob_cookie_chirho,
            &key_id_chirho(&alices_chirho[0]),
        );
        let unknown_chirho = revoke_id_chirho(&addr_chirho, &bob_cookie_chirho, &"0".repeat(32));
        let malformed_chirho = revoke_id_chirho(&addr_chirho, &bob_cookie_chirho, "zz");
        assert_eq!(cross_chirho.status_chirho, 404);
        assert_no_store_chirho(&cross_chirho, "the one refusal");
        for other_chirho in [&unknown_chirho, &malformed_chirho] {
            assert_eq!(other_chirho.status_chirho, cross_chirho.status_chirho);
            assert_eq!(
                http_body_text_chirho(other_chirho),
                http_body_text_chirho(&cross_chirho),
                "one byte-identical refusal for every id that is not the viewer's own"
            );
        }
        assert!(
            bearer_chirho(&alices_chirho[0]),
            "bob's attempt revoked nothing"
        );

        let revoked_chirho = revoke_id_chirho(
            &addr_chirho,
            &alice_cookie_chirho,
            &key_id_chirho(&alices_chirho[0]),
        );
        assert_eq!(revoked_chirho.status_chirho, 200);
        assert_no_store_chirho(&revoked_chirho, "the revoke");
        assert!(
            !bearer_chirho(&alices_chirho[0]),
            "the revoked key refuses on the bearer road"
        );
        assert!(
            bearer_chirho(&alices_chirho[1]) && bearer_chirho(&bobs_chirho),
            "and no other key"
        );
        let repeat_chirho = revoke_id_chirho(
            &addr_chirho,
            &alice_cookie_chirho,
            &key_id_chirho(&alices_chirho[0]),
        );
        assert_eq!(repeat_chirho.status_chirho, 200);
        assert_eq!(
            http_body_text_chirho(&repeat_chirho),
            http_body_text_chirho(&revoked_chirho)
        );
        assert_eq!(
            listed_ids_chirho(&keys_chirho(&addr_chirho, Some(&alice_cookie_chirho))),
            vec![
                (key_id_chirho(&alices_chirho[0]), false),
                (key_id_chirho(&alices_chirho[1]), true)
            ],
            "the revoked key is listed, not live"
        );

        let bad_body_chirho = revoke_chirho(&addr_chirho, Some(&alice_cookie_chirho), b"not json");
        assert_eq!(bad_body_chirho.status_chirho, 400);
        assert!(http_body_text_chirho(&bad_body_chirho).contains("request-invalid-chirho"));
        assert_eq!(
            revoke_chirho(&addr_chirho, None, b"{}").status_chirho,
            401,
            "no session, no revoke"
        );
        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}
