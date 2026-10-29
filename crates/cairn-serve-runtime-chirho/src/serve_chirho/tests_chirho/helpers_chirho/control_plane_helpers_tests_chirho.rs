// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

pub(super) struct ContactControlPlaneHttpFixtureChirho {
    pub(super) root_chirho: std::path::PathBuf,
}

pub(super) fn contact_control_plane_http_fixture_chirho(
    label_chirho: &str,
) -> ContactControlPlaneHttpFixtureChirho {
    let platform_root_chirho = temp_root_chirho(label_chirho);
    let root_chirho = cairn_chirho::tenant_chirho::root_for_tenant_chirho(
        &platform_root_chirho,
        &cairn_chirho::tenant_chirho::TenantIdChirho::TenantChirho(format!(
            "{label_chirho}-tenant-chirho"
        )),
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let query_caller_chirho = "served-control-plane-query-caller";
    let contact_dag_chirho = store_contact_write_render_dag_chirho(&root_chirho);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact",
        contact_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "contact",
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact/inbox".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    let list_dag_chirho = store_contact_list_route_dag_chirho(&root_chirho, query_caller_chirho);
    cairn_chirho::app_chirho::deploy_app_route_chirho(
        &root_chirho,
        "contact",
        "contact-list",
        list_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "contact",
        Some("contact-list"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    ContactControlPlaneHttpFixtureChirho { root_chirho }
}

pub(super) fn post_contact_app_over_http_chirho(
    root_chirho: &std::path::Path,
    body_chirho: &[u8],
) -> HttpSmokeResponseChirho {
    post_contact_route_over_http_chirho(root_chirho, "/app-chirho/contact", body_chirho)
}

pub(super) fn post_contact_route_over_http_chirho(
    root_chirho: &std::path::Path,
    path_chirho: &str,
    body_chirho: &[u8],
) -> HttpSmokeResponseChirho {
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.to_path_buf();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            path_chirho,
            &[("content-type", "application/x-www-form-urlencoded")],
            body_chirho,
        );
        server_chirho.abort();
        response_chirho
    })
}

pub(super) fn post_invoke_over_http_chirho(
    root_chirho: &std::path::Path,
    target_chirho: &str,
    payload_chirho: &[u8],
    headers_chirho: &[(&str, &str)],
) -> HttpSmokeResponseChirho {
    let payload_text_chirho =
        std::str::from_utf8(payload_chirho).expect("wire invoke test payload must be UTF-8");
    let body_chirho = serde_json::to_vec(&serde_json::json!({
        "target_chirho": target_chirho,
        "payload_chirho": payload_text_chirho,
    }))
    .unwrap();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.to_path_buf();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let mut request_headers_chirho = vec![("content-type", "application/json")];
        request_headers_chirho.extend_from_slice(headers_chirho);
        let response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/invoke-chirho",
            &request_headers_chirho,
            &body_chirho,
        );
        server_chirho.abort();
        response_chirho
    })
}

pub(super) fn get_ssr_over_http_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    headers_chirho: &[(&str, &str)],
) -> HttpSmokeResponseChirho {
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.to_path_buf();
    let path_chirho = format!("/ssr-chirho/{app_chirho}");
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let response_chirho =
            http_request_for_smoke_chirho(&addr_chirho, "GET", &path_chirho, headers_chirho, b"");
        server_chirho.abort();
        response_chirho
    })
}

pub(super) fn assert_served_control_plane_attack_blocked_chirho(
    root_chirho: &std::path::Path,
    response_chirho: &HttpSmokeResponseChirho,
    submitted_body_chirho: &[u8],
    needles_chirho: &[&str],
    expected_status_chirho: u16,
    expected_identity_chirho: Option<&str>,
) {
    let body_text_chirho = String::from_utf8_lossy(&response_chirho.body_chirho);
    assert_eq!(
        response_chirho.status_chirho, expected_status_chirho,
        "unexpected served attack status/body: {body_text_chirho}"
    );
    // The body names the refusing gate by its fixed public identity and nothing else; the verifier's
    // own cause is the caller's to attribute, by calling that verifier directly (public-error-bodies).
    if let Some(expected_identity_chirho) = expected_identity_chirho {
        // Exactly the gate's fixed identity, plain or (on a JSON transport) its two bounded fields.
        let json_chirho = serde_json::from_str::<serde_json::Value>(&body_text_chirho).ok();
        assert!(
            body_text_chirho == format!("error: {expected_identity_chirho}\n")
                || json_chirho
                    == Some(serde_json::json!({
                        "ok_chirho": false,
                        "error_chirho": expected_identity_chirho,
                    })),
            "served attack response must be exactly its gate's fixed identity: {body_text_chirho}"
        );
    } else {
        assert!(
            body_text_chirho.is_empty(),
            "generic served route denial must not reveal route or policy details: {body_text_chirho}"
        );
    }
    assert_no_contact_pii_chirho(
        "served control-plane attack response",
        &response_chirho.body_chirho,
        needles_chirho,
    );

    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(submitted_body_chirho);
    assert!(
        cairn_chirho::cas_chirho::get_chirho(root_chirho, &raw_hash_chirho).is_err(),
        "served attack persisted the submitted request body as a CAS object"
    );
    assert_eq!(
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(root_chirho)
            .unwrap()
            .len(),
        0
    );
    assert_optional_dir_empty_chirho(&root_chirho.join("runs-chirho"), "runs-chirho");
    assert_optional_dir_empty_chirho(&root_chirho.join("effects-chirho"), "effects-chirho");
    assert_optional_file_empty_chirho(
        &root_chirho.join("volatile-effects-chirho.jsonl"),
        "volatile-effects-chirho.jsonl",
    );
    assert_optional_dir_empty_chirho(
        &root_chirho.join("privacy-keys-chirho"),
        "privacy-keys-chirho",
    );

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert!(store_chirho
        .get_chirho("contacts-chirho/latest")
        .unwrap()
        .is_none());
    assert!(store_chirho.current_entries_chirho().unwrap().is_empty());
    drop(store_chirho);
    assert!(
        cairn_chirho::query_chirho::query_prefix_chirho(root_chirho, "contacts-chirho", 50)
            .unwrap()
            .is_empty()
    );
    assert_contact_persisted_surfaces_no_pii_chirho(root_chirho, &[0], needles_chirho);
}

pub(super) fn assert_optional_file_empty_chirho(path_chirho: &std::path::Path, label_chirho: &str) {
    if !path_chirho.exists() {
        return;
    }
    assert!(
        std::fs::read(path_chirho).unwrap().is_empty(),
        "{label_chirho} should stay empty for served control-plane attack"
    );
}

pub(super) fn assert_optional_dir_empty_chirho(path_chirho: &std::path::Path, label_chirho: &str) {
    if !path_chirho.exists() {
        return;
    }
    let entries_chirho = std::fs::read_dir(path_chirho)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        entries_chirho.is_empty(),
        "{label_chirho} should stay empty for served control-plane attack"
    );
}

pub(super) fn write_jsonl_rows_chirho<T: serde::Serialize>(
    path_chirho: &std::path::Path,
    rows_chirho: &[T],
) {
    let mut text_chirho = String::new();
    for row_chirho in rows_chirho {
        text_chirho.push_str(&serde_json::to_string(row_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

pub(super) fn split_owner_principal_for_path_chirho(principal_chirho: &str) -> (String, String) {
    principal_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap()
}

pub(super) fn owner_bearer_headers_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    credential_chirho: &str,
) -> HeaderMap {
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        root_chirho,
        owner_chirho,
        credential_chirho,
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", login_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    headers_chirho
}

pub(super) fn app_build_request_form_body_chirho(
    idempotency_key_chirho: &str,
    owner_goal_chirho: &str,
    notes_chirho: &str,
    modules_chirho: &[&str],
) -> String {
    let mut body_chirho = format!(
        "idempotency_key_chirho={}&owner_goal_chirho={}&notes_chirho={}",
        encode_query_value_chirho(idempotency_key_chirho),
        encode_query_value_chirho(owner_goal_chirho),
        encode_query_value_chirho(notes_chirho),
    );
    for module_chirho in modules_chirho {
        body_chirho.push_str("&module_chirho=");
        body_chirho.push_str(&encode_query_value_chirho(module_chirho));
    }
    body_chirho
}

pub(super) fn write_jsonl_chirho<T: serde::Serialize>(
    path_chirho: &std::path::Path,
    records_chirho: &[T],
) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

pub(super) fn owner_path_parts_chirho(owner_chirho: &str) -> (&str, &str) {
    owner_chirho.split_once('/').unwrap()
}

pub(super) fn encode_query_value_chirho(value_chirho: &str) -> String {
    value_chirho
        .bytes()
        .flat_map(|byte_chirho| match byte_chirho {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                vec![byte_chirho as char]
            }
            b' ' => vec!['+'],
            other_chirho => format!("%{other_chirho:02X}").chars().collect(),
        })
        .collect()
}

pub(super) fn assert_text_excludes_needles_chirho(text_chirho: &str, needles_chirho: &[String]) {
    for needle_chirho in needles_chirho {
        assert!(
            !text_chirho.contains(needle_chirho),
            "response leaked forbidden needle: {needle_chirho}"
        );
    }
}

pub(super) fn temp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-serve-{label_chirho}-{}-{nanos_chirho}",
        std::process::id()
    ))
}

pub(super) fn tenant_root_for_test_chirho(label_chirho: &str) -> std::path::PathBuf {
    let platform_root_chirho = temp_root_chirho(label_chirho);
    cairn_chirho::tenant_chirho::root_for_tenant_chirho(
        &platform_root_chirho,
        &cairn_chirho::tenant_chirho::TenantIdChirho::TenantChirho(format!(
            "{label_chirho}-tenant-chirho"
        )),
    )
    .unwrap()
}

/// The public body names only the refusing gate, so a tamper arm attributes its cause by calling the
/// verifier itself: it must refuse, and name the tamper.
pub(super) fn assert_verifier_names_chirho(outcome_chirho: anyhow::Result<()>, cause_chirho: &str) {
    let error_chirho =
        outcome_chirho.expect_err("the tampered control plane must fail its verifier");
    assert!(
        format!("{error_chirho:#}").contains(cause_chirho),
        "the verifier must name the tamper '{cause_chirho}': {error_chirho:#}"
    );
}

/// The contact app's input mode, as the served road resolves it, under the app's signed owner.
pub(super) fn contact_input_mode_chirho(root_chirho: &std::path::Path) -> anyhow::Result<()> {
    let owner_chirho = cairn_chirho::app_chirho::verified_app_owner_chirho(root_chirho, "contact")?
        .expect("the fixture deploys a signed owner");
    cairn_chirho::app_chirho::app_input_mode_chirho(root_chirho, "contact", None, &owner_chirho)
        .map(|_mode_chirho| ())
}
