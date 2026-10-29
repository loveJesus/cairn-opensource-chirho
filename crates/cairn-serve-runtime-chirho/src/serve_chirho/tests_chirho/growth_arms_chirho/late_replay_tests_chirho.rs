// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The late exact replay arms: a save whose version has left the viewer-state window is still answered, for the
//! credential that made it, by its original receipt, with no new mutation record; under another credential of the same
//! viewer, the same bytes reach the door and get the stale-version conflict.
//!
//! Census CAIRN #26559; PFE's proof boundaries 1 and 2 (#26561). The door's own idempotency check searches only the
//! retained window, so a retired version's request that reaches the door can only conflict. Its original receipt can
//! come only from the replay carrier (the effect node's run cache, then the effect record), which is keyed by the
//! credential's token hash, as the run-intent admission is. Neither arm changes the replay or unknown-outcome law.
//! Tasklist: `spec-chirho/tasklists-chirho/26-10-09_04-00-tasklist-late_replay_arms-chirho.md`.

use super::app_route_fixture_chirho::*;
use super::*;
use std::path::Path;

/// The door's retained window: `VIEWER_STATE_HISTORY_LIMIT_CHIRHO`, private to the engine. Each arm asserts the view's
/// history holds exactly this many versions, so a changed window fails here by name.
const WINDOW_CHIRHO: u64 = 16;

/// THE save's value: the attempted value a conflict echoes back.
const RETIRED_VALUE_CHIRHO: &str = "the retired save's page";

/// The replay carrier's records (run results, run keys, run seals and effect records, by file) and the run-intent log
/// (by line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CarrierCountsChirho {
    runs_chirho: usize,
    run_keys_chirho: usize,
    run_seals_chirho: usize,
    effects_chirho: usize,
    run_intents_chirho: usize,
}

fn carrier_counts_chirho(root_chirho: &Path) -> CarrierCountsChirho {
    CarrierCountsChirho {
        runs_chirho: entries_chirho(&root_chirho.join("runs-chirho")),
        run_keys_chirho: entries_chirho(&root_chirho.join("runkeys-chirho")),
        run_seals_chirho: entries_chirho(&root_chirho.join("runseals-chirho")),
        effects_chirho: entries_chirho(&root_chirho.join("effects-chirho")),
        run_intents_chirho: run_intent_line_count_chirho(root_chirho),
    }
}

/// The versions a viewer-state response's history lists, newest first.
fn history_versions_chirho(page_chirho: &str) -> Vec<u64> {
    let value_chirho: serde_json::Value = serde_json::from_str(page_chirho)
        .unwrap_or_else(|_| panic!("the page is the viewer-state response: {page_chirho}"));
    value_chirho["history_chirho"]
        .as_array()
        .unwrap_or_else(|| panic!("the response lists its history: {page_chirho}"))
        .iter()
        .map(|version_chirho| version_chirho["version_chirho"].as_u64().unwrap())
        .collect()
}

fn restore_request_chirho(expected_chirho: u64, from_chirho: u64) -> String {
    serde_json::json!({
        "schema_chirho": "viewer-state-request-v1-chirho",
        "action_chirho": "restore-chirho",
        "key_chirho": STATE_KEY_CHIRHO,
        "expected_current_version_chirho": expected_chirho,
        "restore_from_version_chirho": from_chirho,
    })
    .to_string()
}

/// THE save under test, after it retired: its exact request bytes, its original page, its version and the head now.
struct RetiredSaveChirho {
    body_chirho: String,
    page_chirho: String,
    version_chirho: u64,
    head_chirho: u64,
}

/// v1, then THE save (at expected head 1, so v2), then saves until v2 has left the window.
async fn retire_a_save_chirho(
    state_chirho: &AppStateChirho,
    user_chirho: &HeaderMap,
) -> RetiredSaveChirho {
    let first_chirho = save_next_chirho(state_chirho, user_chirho, None, "the first page").await;
    let body_chirho = write_request_chirho(first_chirho, RETIRED_VALUE_CHIRHO);
    let (status_chirho, page_chirho) =
        save_chirho(state_chirho, user_chirho, body_chirho.clone()).await;
    assert_eq!(
        status_chirho,
        StatusCode::OK,
        "THE save is served: {page_chirho}"
    );
    let version_chirho = head_version_chirho(&page_chirho).expect("THE save names its version");
    let mut head_chirho = Some(version_chirho);
    while head_chirho.unwrap() < version_chirho + WINDOW_CHIRHO {
        let next_page_chirho = format!("a later page, version {}", head_chirho.unwrap() + 1);
        head_chirho =
            save_next_chirho(state_chirho, user_chirho, head_chirho, &next_page_chirho).await;
    }
    RetiredSaveChirho {
        body_chirho,
        page_chirho,
        version_chirho,
        head_chirho: head_chirho.unwrap(),
    }
}

/// A second legacy bearer for user `index_chirho`: the same principal, client and scopes as the first, under a token of
/// its own, so its runs and its admission are keyed apart from the first's.
fn second_bearer_chirho(tenant_chirho: &GrowthTenantChirho, index_chirho: usize) -> HeaderMap {
    let client_chirho = cairn_chirho::oauth_chirho::load_clients_chirho(&tenant_chirho.root_chirho)
        .unwrap()
        .remove(0);
    let (principal_chirho, secret_chirho) = &tenant_chirho.user_credentials_chirho[index_chirho];
    let token_chirho = cairn_chirho::oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
        &tenant_chirho.root_chirho,
        principal_chirho,
        secret_chirho,
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
        Some(cairn_chirho::oauth_chirho::ScopedTokenRateLimitChirho {
            window_ms_chirho: 60_000,
            max_invokes_chirho: cairn_chirho::oauth_chirho::TOKEN_RATE_MAX_INVOKES_CEILING_CHIRHO,
            device_id_chirho: Some(format!("late-replay-second-{index_chirho}-chirho")),
        }),
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", token_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    headers_chirho
}

/// BOUNDARY 1, THE SAME CREDENTIAL (PFE #26561): a late exact replay of a retired save answers its original receipt,
/// byte for byte, and appends no run, run key, run seal, effect or run-intent record; the head and history are unchanged,
/// and the replay is on the warm road (no whole-log read).
///
/// Retirement is witnessed three ways first: the view's history no longer lists THE save's version; a restore of it is
/// refused with a fixed public refusal and changes nothing; and the same restore shape, aimed at a version still
/// retained at that moment, restores (the positive control).
///
/// RECORDED, not asserted: what the replay adds outside the carrier (private values, blobs, key files, volatile effects
/// and token use). An allowed bearer request may record its own accounting; boundary 1 promises no new MUTATION record.
///
/// MIGRATION PATH: a conflict here means the replay reached the door, so the carrier no longer answers a retired save;
/// a new run-intent row means a completed replay records a terminal row again; a new run or effect means the replay
/// re-executed its write.
#[test]
fn a_late_exact_replay_of_a_retired_save_answers_its_original_receipt_chirho() {
    let tenant_chirho = growth_tenant_chirho("late-replay-same-credential");
    let state_chirho = growth_state_chirho(&tenant_chirho.root_chirho);
    let runtime_chirho = counted_road_runtime_chirho();
    runtime_chirho.block_on(async {
        let user_chirho = &tenant_chirho.users_chirho[0];
        let retired_chirho = retire_a_save_chirho(&state_chirho, user_chirho).await;

        let (status_chirho, view_page_chirho) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK, "{view_page_chirho}");
        let history_chirho = history_versions_chirho(&view_page_chirho);
        assert_eq!(
            history_chirho.len() as u64,
            WINDOW_CHIRHO,
            "the view's history is the full window: {history_chirho:?}"
        );
        assert!(
            !history_chirho.contains(&retired_chirho.version_chirho),
            "THE save's version {} has left the window: {history_chirho:?}",
            retired_chirho.version_chirho
        );
        let (status_chirho, refusal_chirho) = save_chirho(
            &state_chirho,
            user_chirho,
            restore_request_chirho(retired_chirho.head_chirho, retired_chirho.version_chirho),
        )
        .await;
        assert_ne!(status_chirho, StatusCode::OK, "a retired version cannot be restored");
        assert!(
            crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(
                &refusal_chirho
            )
            .is_some(),
            "the refusal is one fixed public answer: {refusal_chirho}"
        );
        let (_, after_refusal_chirho) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(
            after_refusal_chirho, view_page_chirho,
            "the refused restore changed nothing"
        );
        let (status_chirho, restored_chirho) = save_chirho(
            &state_chirho,
            user_chirho,
            restore_request_chirho(retired_chirho.head_chirho, retired_chirho.head_chirho - 1),
        )
        .await;
        assert_eq!(
            (status_chirho, head_version_chirho(&restored_chirho)),
            (StatusCode::OK, Some(retired_chirho.head_chirho + 1)),
            "the positive control: the same restore shape restores a retained version: {restored_chirho}"
        );

        let (_, before_page_chirho) = view_chirho(&state_chirho, user_chirho).await;
        let carrier_before_chirho = carrier_counts_chirho(&tenant_chirho.root_chirho);
        assert!(
            carrier_before_chirho.runs_chirho > 0
                && carrier_before_chirho.run_keys_chirho > 0
                && carrier_before_chirho.run_seals_chirho > 0
                && carrier_before_chirho.effects_chirho > 0
                && carrier_before_chirho.run_intents_chirho > 0,
            "every carrier counter sees the saves above, so an unchanged count is not an empty one: \
             {carrier_before_chirho:?}"
        );
        let footprint_before_chirho = footprint_chirho(&tenant_chirho.root_chirho);
        reset_road_chirho();
        let (status_chirho, replayed_chirho) =
            save_chirho(&state_chirho, user_chirho, retired_chirho.body_chirho.clone()).await;
        let replay_road_chirho = road_chirho();
        let accounting_chirho =
            footprint_delta_chirho(footprint_before_chirho, footprint_chirho(&tenant_chirho.root_chirho));
        assert_eq!(status_chirho, StatusCode::OK, "the late replay is served: {replayed_chirho}");
        assert_eq!(
            replayed_chirho, retired_chirho.page_chirho,
            "a late exact replay answers THE save's original receipt, byte for byte"
        );
        assert_eq!(
            carrier_counts_chirho(&tenant_chirho.root_chirho),
            carrier_before_chirho,
            "the replay appends no run, run key, run seal, effect or run-intent record"
        );
        assert_warm_road_chirho(&replay_road_chirho, "the late replay");
        let (_, after_page_chirho) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(
            after_page_chirho, before_page_chirho,
            "the head and the history are unchanged"
        );
        eprintln!(
            "late replay, same credential: request accounting outside the carrier {accounting_chirho:?} (recorded, \
             not asserted); road {replay_road_chirho:?}"
        );
    });
}

/// BOUNDARY 2, ANOTHER CREDENTIAL (PFE #26561): the same viewer under a second bearer (the same principal, client and
/// scopes) sends THE save's exact bytes after it retired. It is authorized (its view is served, and equals the first
/// bearer's), so it reaches the door, which answers the stale-version conflict: 200, the conflict schema, THE save's
/// expected version, the head, and the attempted value echoed. It is not the original receipt, and the current
/// document is intact. A fresh run-intent admission and a new effect record are its cache-miss witness. The conflict's
/// own exact replay answers the same conflict and records nothing (workflow invariant 11).
///
/// MIGRATION PATH: the original receipt here means the replay carrier no longer binds the credential; a refusal means
/// the second bearer never reached the door, so the arm no longer witnesses a cache miss.
#[test]
fn the_same_late_save_under_another_credential_gets_the_conflict_chirho() {
    let tenant_chirho = growth_tenant_chirho("late-replay-other-credential");
    let state_chirho = growth_state_chirho(&tenant_chirho.root_chirho);
    let runtime_chirho = counted_road_runtime_chirho();
    runtime_chirho.block_on(async {
        let user_chirho = &tenant_chirho.users_chirho[0];
        let retired_chirho = retire_a_save_chirho(&state_chirho, user_chirho).await;
        let second_chirho = second_bearer_chirho(&tenant_chirho, 0);

        let (status_chirho, second_view_chirho) = view_chirho(&state_chirho, &second_chirho).await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "the second credential is authorized: {second_view_chirho}"
        );
        let (_, first_view_chirho) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(
            second_view_chirho, first_view_chirho,
            "the same viewer, so the same state"
        );
        assert_eq!(
            history_versions_chirho(&first_view_chirho).len() as u64,
            WINDOW_CHIRHO,
            "the view's history is the full window"
        );

        let carrier_before_chirho = carrier_counts_chirho(&tenant_chirho.root_chirho);
        let (status_chirho, answer_chirho) =
            save_chirho(&state_chirho, &second_chirho, retired_chirho.body_chirho.clone()).await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "the door answers the conflict; it does not refuse: {answer_chirho}"
        );
        assert_ne!(
            answer_chirho, retired_chirho.page_chirho,
            "another credential never gets the original receipt"
        );
        let conflict_chirho: serde_json::Value = serde_json::from_str(&answer_chirho)
            .unwrap_or_else(|_| panic!("the answer is JSON: {answer_chirho}"));
        assert_eq!(
            (
                conflict_chirho["schema_chirho"].as_str(),
                conflict_chirho["expected_current_version_chirho"].as_u64(),
                conflict_chirho["current_version_chirho"].as_u64(),
                conflict_chirho["attempted_value_base64_chirho"].as_str(),
            ),
            (
                Some("viewer-state-conflict-v1-chirho"),
                Some(retired_chirho.version_chirho - 1),
                Some(retired_chirho.head_chirho),
                Some(BASE64_CHIRHO.encode(RETIRED_VALUE_CHIRHO.as_bytes()).as_str()),
            ),
            "the stale-version conflict: THE save's expected version, the head, and its value echoed: {answer_chirho}"
        );
        let carrier_after_chirho = carrier_counts_chirho(&tenant_chirho.root_chirho);
        assert!(
            carrier_after_chirho.run_intents_chirho > carrier_before_chirho.run_intents_chirho
                && carrier_after_chirho.effects_chirho > carrier_before_chirho.effects_chirho,
            "the cache-miss witness: a fresh admission and a new effect record: before {carrier_before_chirho:?}, \
             after {carrier_after_chirho:?}"
        );
        let (_, after_view_chirho) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(
            after_view_chirho, first_view_chirho,
            "the current document is intact"
        );

        let (status_chirho, again_chirho) =
            save_chirho(&state_chirho, &second_chirho, retired_chirho.body_chirho.clone()).await;
        assert_eq!(
            (status_chirho, again_chirho.as_str()),
            (StatusCode::OK, answer_chirho.as_str()),
            "the conflict's exact replay answers the same conflict"
        );
        assert_eq!(
            carrier_counts_chirho(&tenant_chirho.root_chirho),
            carrier_after_chirho,
            "and records nothing"
        );
    });
}
