// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

fn effect_file_count_chirho(root_chirho: &std::path::Path) -> usize {
    std::fs::read_dir(root_chirho.join("effects-chirho"))
        .map(|entries_chirho| {
            entries_chirho
                .filter_map(|entry_chirho| entry_chirho.ok())
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn realtime_websocket_refuses_before_session_effect_or_ledger_work_chirho() {
    let root_chirho = temp_root_chirho("realtime-ws-legacy-money-refusal");
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "realtime-refusal-secret",
    )
    .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &user_chirho.principal_chirho,
        "realtime-refusal-secret",
    )
    .unwrap();
    let authorization_chirho = format!("Bearer {}", login_chirho.token_chirho);
    let headers_chirho = [("authorization", authorization_chirho.as_str())];

    let initial_ledger_rows_chirho =
        cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
            .unwrap()
            .len();
    let initial_sessions_chirho =
        cairn_chirho::realtime_legacy_evidence_chirho::load_realtime_sessions_chirho(&root_chirho)
            .unwrap()
            .len();
    let initial_volatile_rows_chirho =
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap()
            .len();
    let initial_effect_files_chirho = effect_file_count_chirho(&root_chirho);

    let route_chirho = format!(
        "/realtime-chirho/retired-session-chirho/ws-chirho?caller_chirho={}&app_chirho=voiceapp&payer_chirho=attacker%2Fpayer&provider_chirho=provider%2Fattacker&max_seconds_chirho=999&token_per_second_chirho=999",
        encode_query_value_chirho(&user_chirho.principal_chirho)
    );
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let unauthenticated_chirho =
            websocket_upgrade_for_smoke_chirho(&addr_chirho, &route_chirho, &[]);
        assert_eq!(unauthenticated_chirho.status_chirho, 401);

        let refusal_chirho =
            websocket_upgrade_for_smoke_chirho(&addr_chirho, &route_chirho, &headers_chirho);
        assert_eq!(refusal_chirho.status_chirho, 400);
        let refusal_text_chirho = String::from_utf8_lossy(&refusal_chirho.body_chirho);
        assert!(refusal_text_chirho.contains("legacy money road"));
        assert!(refusal_text_chirho.contains("RealtimeSessionChirho"));
        assert!(!refusal_text_chirho.contains("attacker/payer"));
        assert!(!refusal_text_chirho.contains("provider/attacker"));

        server_chirho.abort();
    });

    assert_eq!(
        cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
            .unwrap()
            .len(),
        initial_ledger_rows_chirho
    );
    assert_eq!(
        cairn_chirho::realtime_legacy_evidence_chirho::load_realtime_sessions_chirho(&root_chirho)
            .unwrap()
            .len(),
        initial_sessions_chirho
    );
    assert_eq!(
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        initial_volatile_rows_chirho
    );
    assert_eq!(
        effect_file_count_chirho(&root_chirho),
        initial_effect_files_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
