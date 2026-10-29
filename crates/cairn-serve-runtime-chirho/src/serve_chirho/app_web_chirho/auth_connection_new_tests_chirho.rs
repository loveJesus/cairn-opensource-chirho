// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The connection road's own parsing (K4 Part 3): the strict form, the client id's shape against the ids the engine
//! mints, and the one target the sign-in page may carry (PFE unit 330). Account Create brick 1 (PFE #26824, #26837): the closed
//! query with its two selectors and its return path kept as received, the canonical target for an app, and the POST's
//! one return path.

use super::*;

const ID_CHIRHO: &str = "client/0123456789abcdef";
const APP_CHIRHO: &str = "perffection-workspace";
const RETURN_CHIRHO: &str = "/app-chirho/perffection-workspace/account-chirho";

fn encoded_chirho(pairs_chirho: &[(&str, &str)]) -> String {
    let mut form_chirho = url::form_urlencoded::Serializer::new(String::new());
    for (field_chirho, value_chirho) in pairs_chirho {
        form_chirho.append_pair(field_chirho, value_chirho);
    }
    form_chirho.finish()
}

/// THE FORM IS PARSED STRICTLY: one well-formed client id, one or more distinct bounded actions and one non-empty
/// credential pass; anything else refuses, carrying the client id back only when it was well formed.
#[test]
fn the_form_is_parsed_strictly_chirho() {
    let good_chirho = encoded_chirho(&[
        ("client_id_chirho", ID_CHIRHO),
        ("action_chirho", "page-read-chirho"),
        ("action_chirho", "page-save-chirho"),
        ("credential_chirho", "secret"),
    ]);
    let form_chirho = parse_form_chirho(good_chirho.as_bytes()).ok().unwrap();
    assert_eq!(form_chirho.client_id_chirho, ID_CHIRHO);
    assert_eq!(
        form_chirho.actions_chirho,
        ["page-read-chirho", "page-save-chirho"]
    );
    assert_eq!(form_chirho.credential_chirho, "secret");

    let long_action_chirho = "a".repeat(MAX_ACTION_BYTES_CHIRHO + 1);
    let many_chirho: Vec<(String, String)> = (0..=MAX_ACTIONS_CHIRHO)
        .map(|index_chirho| {
            (
                "action_chirho".to_string(),
                format!("action-{index_chirho}"),
            )
        })
        .collect();
    let mut too_many_chirho = vec![
        ("client_id_chirho", ID_CHIRHO),
        ("credential_chirho", "secret"),
    ];
    too_many_chirho.extend(
        many_chirho
            .iter()
            .map(|(field_chirho, value_chirho)| (field_chirho.as_str(), value_chirho.as_str())),
    );
    for (refused_chirho, client_back_chirho) in [
        (
            encoded_chirho(&[
                ("client_id_chirho", ID_CHIRHO),
                ("credential_chirho", "secret"),
            ]),
            Some(ID_CHIRHO),
        ),
        (
            encoded_chirho(&[
                ("client_id_chirho", ID_CHIRHO),
                ("action_chirho", "a"),
                ("credential_chirho", ""),
            ]),
            Some(ID_CHIRHO),
        ),
        (
            encoded_chirho(&[
                ("client_id_chirho", ID_CHIRHO),
                ("action_chirho", "a"),
                ("action_chirho", "a"),
                ("credential_chirho", "s"),
            ]),
            Some(ID_CHIRHO),
        ),
        (
            encoded_chirho(&[
                ("client_id_chirho", ID_CHIRHO),
                ("action_chirho", "a"),
                ("credential_chirho", "s"),
                ("credential_chirho", "t"),
            ]),
            Some(ID_CHIRHO),
        ),
        (
            encoded_chirho(&[
                ("client_id_chirho", ID_CHIRHO),
                ("client_id_chirho", ID_CHIRHO),
                ("action_chirho", "a"),
                ("credential_chirho", "s"),
            ]),
            Some(ID_CHIRHO),
        ),
        (
            encoded_chirho(&[
                ("client_id_chirho", ID_CHIRHO),
                ("action_chirho", "a"),
                ("credential_chirho", "s"),
                ("principal_chirho", "someone"),
            ]),
            Some(ID_CHIRHO),
        ),
        (
            encoded_chirho(&[
                ("client_id_chirho", ID_CHIRHO),
                ("action_chirho", &long_action_chirho),
                ("credential_chirho", "s"),
            ]),
            Some(ID_CHIRHO),
        ),
        (encoded_chirho(&too_many_chirho), Some(ID_CHIRHO)),
        (
            encoded_chirho(&[
                ("client_id_chirho", "client/XYZ"),
                ("action_chirho", "a"),
                ("credential_chirho", "s"),
            ]),
            None,
        ),
        (
            encoded_chirho(&[("action_chirho", "a"), ("credential_chirho", "s")]),
            None,
        ),
    ] {
        assert_eq!(
            parse_form_chirho(refused_chirho.as_bytes()).err(),
            Some(client_back_chirho.map(str::to_string)),
            "{refused_chirho}"
        );
    }
}

/// THE CLIENT ID'S SHAPE: `client/` and sixteen lowercase hex digits pass, and nothing else that could carry markup, a
/// path or a query does. That the engine mints ids of this shape is witnessed end to end: the served arms reach the form
/// with ids the engine minted (`connection_new_http_tests_chirho.rs`).
#[test]
fn the_client_id_shape_is_the_minted_one_chirho() {
    assert!(client_id_well_formed_chirho(ID_CHIRHO));
    for malformed_chirho in [
        "client/0123456789ABCDEF",
        "client/0123456789abcde",
        "client/0123456789abcdef0",
        "client/0123456789abcdeg",
        "client/../0123456789ab",
        "0123456789abcdef",
        "",
        "client/<b>456789abcdef",
    ] {
        assert!(
            !client_id_well_formed_chirho(malformed_chirho),
            "{malformed_chirho}"
        );
    }
}

/// THE SIGN-IN PAGE CARRIES ONE TARGET ONLY: this form's own URL for a well-formed client id, as the road builds it, and
/// nothing else the redirect check would let through.
#[test]
fn the_sign_in_page_accepts_only_the_forms_own_target_chirho() {
    let target_chirho = form_target_chirho(
        &ConnectionSelectorChirho::ClientChirho(ID_CHIRHO.to_string()),
        None,
    );
    assert_eq!(
        target_chirho,
        "/auth-chirho/connection-new-chirho?client_id_chirho=client%2F0123456789abcdef"
    );
    assert_eq!(
        accepted_return_target_chirho(&target_chirho),
        Some(target_chirho.clone())
    );
    for refused_chirho in [
        "/".to_string(),
        "/auth-chirho/keys-chirho".to_string(),
        "/auth-chirho/connection-new-chirho".to_string(),
        "/auth-chirho/connection-new-chirho?client_id_chirho=client/0123456789abcdef".to_string(),
        format!("{target_chirho}&client_id_chirho=client%2F0123456789abcdef"),
        format!("{target_chirho}#fragment"),
        "//evil.example/auth-chirho/connection-new-chirho?client_id_chirho=client%2F0123456789abcdef".to_string(),
        "https://evil.example/".to_string(),
        "/auth-chirho/connection-new-chirho?client_id_chirho=client%2F0123456789ABCDEF".to_string(),
    ] {
        assert_eq!(accepted_return_target_chirho(&refused_chirho), None, "{refused_chirho}");
    }
}

fn query_chirho(raw_chirho: &str) -> Option<(ConnectionSelectorChirho, Option<String>)> {
    connection_query_chirho(raw_chirho)
        .map(|query_chirho| (query_chirho.selector_chirho, query_chirho.return_chirho))
}

/// THE GET'S QUERY IS CLOSED, AND ITS RETURN PATH IS KEPT AS RECEIVED: exactly one well-formed selector, a client id or
/// an app, and at most one return path, which an app selector must name a route of (a client id's app is checked once
/// known). A missing, mixed, repeated, unknown or malformed field refuses; so does a return path the shared redirect
/// check would trim, a dot segment, a query, a fragment, an encoded character, a backslash or another origin, written
/// plainly or query-encoded (PFE #26837). The good path, query-encoded, decodes to itself and passes: the control.
#[test]
fn the_query_takes_one_selector_and_one_return_kept_as_received_chirho() {
    let app_chirho = ConnectionSelectorChirho::AppChirho(APP_CHIRHO.to_string());
    let client_chirho = ConnectionSelectorChirho::ClientChirho(ID_CHIRHO.to_string());
    let other_route_chirho = "/app-chirho/other-app/view";
    for (raw_chirho, expected_chirho) in [
        (
            encoded_chirho(&[("client_id_chirho", ID_CHIRHO)]),
            (client_chirho.clone(), None),
        ),
        (
            encoded_chirho(&[("app_chirho", APP_CHIRHO)]),
            (app_chirho.clone(), None),
        ),
        (
            encoded_chirho(&[("app_chirho", APP_CHIRHO), ("return_chirho", RETURN_CHIRHO)]),
            (app_chirho.clone(), Some(RETURN_CHIRHO.to_string())),
        ),
        (
            encoded_chirho(&[("return_chirho", RETURN_CHIRHO), ("app_chirho", APP_CHIRHO)]),
            (app_chirho.clone(), Some(RETURN_CHIRHO.to_string())),
        ),
        (
            encoded_chirho(&[("client_id_chirho", ID_CHIRHO), ("return_chirho", other_route_chirho)]),
            (client_chirho.clone(), Some(other_route_chirho.to_string())),
        ),
        (
            "app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fperffection-workspace%2Faccount-chirho"
                .to_string(),
            (app_chirho.clone(), Some(RETURN_CHIRHO.to_string())),
        ),
    ] {
        assert_eq!(query_chirho(&raw_chirho), Some(expected_chirho), "{raw_chirho}");
    }
    let long_app_chirho = "a".repeat(oauth_chirho::CONNECTION_APP_SELECTOR_MAX_BYTES_CHIRHO + 1);
    let with_return_chirho = |return_chirho: &str| {
        encoded_chirho(&[("app_chirho", APP_CHIRHO), ("return_chirho", return_chirho)])
    };
    for raw_chirho in [
        String::new(),
        encoded_chirho(&[("client_id_chirho", ID_CHIRHO), ("app_chirho", APP_CHIRHO)]),
        encoded_chirho(&[("app_chirho", APP_CHIRHO), ("app_chirho", APP_CHIRHO)]),
        encoded_chirho(&[
            ("app_chirho", APP_CHIRHO),
            ("return_chirho", RETURN_CHIRHO),
            ("return_chirho", RETURN_CHIRHO),
        ]),
        encoded_chirho(&[("app_chirho", APP_CHIRHO), ("other_chirho", "x")]),
        encoded_chirho(&[("app_chirho", "")]),
        encoded_chirho(&[("app_chirho", "a/b")]),
        encoded_chirho(&[("app_chirho", "a b")]),
        encoded_chirho(&[("app_chirho", &long_app_chirho)]),
        encoded_chirho(&[("client_id_chirho", "client/XYZ")]),
        encoded_chirho(&[("return_chirho", RETURN_CHIRHO)]),
        with_return_chirho("/app-chirho/other-app/account-chirho"),
        with_return_chirho("/app-chirho/perffection-workspace/.."),
        with_return_chirho("/app-chirho/perffection-workspace/."),
        encoded_chirho(&[
            ("client_id_chirho", ID_CHIRHO),
            ("return_chirho", "/app-chirho/../account-chirho"),
        ]),
        with_return_chirho(" /app-chirho/perffection-workspace/account-chirho"),
        with_return_chirho("/app-chirho/perffection-workspace/account-chirho "),
        with_return_chirho("/app-chirho/perffection-workspace/account-chirho?x=1"),
        with_return_chirho("/app-chirho/perffection-workspace/account-chirho#top"),
        with_return_chirho("//evil.example/app-chirho/perffection-workspace/account-chirho"),
        with_return_chirho("https://evil.example/"),
        with_return_chirho("/app-chirho/perffection-workspace/account\\chirho"),
        with_return_chirho("/app-chirho/perffection-workspace/"),
        "app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fperffection-workspace%2F%2E%2E"
            .to_string(),
        "app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fperffection-workspace%2F%252E%252E"
            .to_string(),
        "app_chirho=perffection-workspace&return_chirho=%20%2Fapp-chirho%2Fperffection-workspace%2Faccount-chirho"
            .to_string(),
        "app_chirho=perffection-workspace&return_chirho=+%2Fapp-chirho%2Fperffection-workspace%2Faccount-chirho"
            .to_string(),
        "app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fperffection-workspace%2Faccount-chirho%3Fx%3D1"
            .to_string(),
        "app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fperffection-workspace%2Faccount-chirho%23top"
            .to_string(),
        "app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fperffection-workspace%2Faccount%00chirho"
            .to_string(),
    ] {
        assert_eq!(query_chirho(&raw_chirho), None, "{raw_chirho}");
    }
}

/// THE SIGN-IN PAGE CARRIES AN APP'S CANONICAL TARGET, AND ONLY IT: the selector, then the return path, encoded by the
/// serializer, as the road builds them, for either selector. Another order, another encoding of the same values, a
/// repeat, another app's route or a dot segment are refused.
#[test]
fn the_sign_in_page_accepts_an_app_selectors_canonical_target_chirho() {
    let app_chirho = ConnectionSelectorChirho::AppChirho(APP_CHIRHO.to_string());
    let bare_chirho = form_target_chirho(&app_chirho, None);
    let with_return_chirho = form_target_chirho(&app_chirho, Some(RETURN_CHIRHO));
    assert_eq!(
        bare_chirho,
        "/auth-chirho/connection-new-chirho?app_chirho=perffection-workspace"
    );
    assert_eq!(
        with_return_chirho,
        "/auth-chirho/connection-new-chirho?app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fperffection-workspace%2Faccount-chirho"
    );
    let client_with_return_chirho = form_target_chirho(
        &ConnectionSelectorChirho::ClientChirho(ID_CHIRHO.to_string()),
        Some(RETURN_CHIRHO),
    );
    for target_chirho in [
        &bare_chirho,
        &with_return_chirho,
        &client_with_return_chirho,
    ] {
        assert_eq!(
            accepted_return_target_chirho(target_chirho),
            Some(target_chirho.clone())
        );
    }
    for refused_chirho in [
        "/auth-chirho/connection-new-chirho?return_chirho=%2Fapp-chirho%2Fperffection-workspace%2Faccount-chirho&app_chirho=perffection-workspace".to_string(),
        "/auth-chirho/connection-new-chirho?app_chirho=perffection%2Dworkspace".to_string(),
        "/auth-chirho/connection-new-chirho?app_chirho=perffection-workspace&return_chirho=/app-chirho/perffection-workspace/account-chirho".to_string(),
        format!("{with_return_chirho}&app_chirho=perffection-workspace"),
        format!("{with_return_chirho}#fragment"),
        "/auth-chirho/connection-new-chirho?app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fother-app%2Faccount-chirho".to_string(),
        "/auth-chirho/connection-new-chirho?app_chirho=perffection-workspace&return_chirho=%2Fapp-chirho%2Fperffection-workspace%2F..".to_string(),
        "/auth-chirho/connection-new-chirho?app_chirho=perffection-workspace&client_id_chirho=client%2F0123456789abcdef".to_string(),
    ] {
        assert_eq!(accepted_return_target_chirho(&refused_chirho), None, "{refused_chirho}");
    }
}

/// THE ACCEPTED TARGET IS NEVER REPAIRED (PFE #27196): the redirect check every auth road uses trims, so a canonical
/// target with whitespace or a whitespace control character before or after it would pass that check as the bare
/// target. The one validator the sign-in page and refusal retention share accepts a target only exactly as received, so
/// each such variant refuses, for both selectors. The bare canonical targets are the control.
#[test]
fn the_accepted_target_is_never_repaired_chirho() {
    for target_chirho in [
        form_target_chirho(
            &ConnectionSelectorChirho::ClientChirho(ID_CHIRHO.to_string()),
            None,
        ),
        form_target_chirho(
            &ConnectionSelectorChirho::AppChirho(APP_CHIRHO.to_string()),
            Some(RETURN_CHIRHO),
        ),
    ] {
        assert_eq!(
            accepted_return_target_chirho(&target_chirho),
            Some(target_chirho.clone()),
            "the control: {target_chirho}"
        );
        for edge_chirho in [
            " ", "\t", "\n", "\r", "\u{0b}", "\u{0c}", "\u{85}", "\u{a0}", "\u{2028}", "\u{3000}",
        ] {
            for varied_chirho in [
                format!("{edge_chirho}{target_chirho}"),
                format!("{target_chirho}{edge_chirho}"),
            ] {
                assert_eq!(
                    accepted_return_target_chirho(&varied_chirho),
                    None,
                    "{varied_chirho:?}"
                );
            }
        }
    }
}

/// THE POST TAKES ONE RETURN PATH, KEPT AS RECEIVED: a well-formed return passes the parse (the engine then checks it
/// against the client's app); a repeat, a value the shared check would trim, a dot segment, a query, another origin or
/// an empty value refuses, carrying the client id back.
#[test]
fn the_form_takes_one_return_kept_as_received_chirho() {
    let form_with_chirho = |returns_chirho: &[&str]| {
        let mut pairs_chirho = vec![
            ("client_id_chirho", ID_CHIRHO),
            ("action_chirho", "page-read-chirho"),
            ("credential_chirho", "secret"),
        ];
        pairs_chirho.extend(
            returns_chirho
                .iter()
                .map(|return_chirho| ("return_chirho", *return_chirho)),
        );
        encoded_chirho(&pairs_chirho)
    };
    let form_chirho = parse_form_chirho(form_with_chirho(&[RETURN_CHIRHO]).as_bytes())
        .ok()
        .unwrap();
    assert_eq!(form_chirho.return_chirho.as_deref(), Some(RETURN_CHIRHO));
    assert_eq!(
        parse_form_chirho(form_with_chirho(&[]).as_bytes())
            .ok()
            .unwrap()
            .return_chirho,
        None
    );
    for refused_chirho in [
        form_with_chirho(&[RETURN_CHIRHO, RETURN_CHIRHO]),
        form_with_chirho(&[" /app-chirho/perffection-workspace/account-chirho"]),
        form_with_chirho(&["/app-chirho/perffection-workspace/.."]),
        form_with_chirho(&["/app-chirho/perffection-workspace/account-chirho?x=1"]),
        form_with_chirho(&["//evil.example/app-chirho/perffection-workspace/account-chirho"]),
        form_with_chirho(&[""]),
    ] {
        assert_eq!(
            parse_form_chirho(refused_chirho.as_bytes()).err(),
            Some(Some(ID_CHIRHO.to_string())),
            "{refused_chirho}"
        );
    }
}
