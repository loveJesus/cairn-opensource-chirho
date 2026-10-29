// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Consumer arms for C2.1 brick 1b-0: through the served write relay, a fence that cannot be examined
//! refuses before any dispatch or local selection, while a valid fence still relays (gpt #29621).

use super::*;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, issue_elected_writer_fence_for_root_chirho,
    writer_fence_path_chirho,
};
use std::os::unix::fs::symlink;

const SPEND_URI_CHIRHO: &str = "/app-chirho/credits-demo-chirho/spend-chirho";

fn fence_path_chirho(root_chirho: &Path) -> PathBuf {
    let group_chirho = consistency_group_for_root_chirho(root_chirho).expect("consistency group");
    writer_fence_path_chirho(root_chirho, &group_chirho).expect("fence path")
}

fn spend_headers_chirho() -> HeaderMap {
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("follower-spend-operation-0001-chirho"),
    );
    headers_chirho
}

async fn spend_decision_before_selection_chirho(
    state_chirho: &AppStateChirho,
) -> ServedWriteBeforeSelectionChirho {
    dispatch_before_app_selection_chirho(
        state_chirho,
        &spend_headers_chirho(),
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        &Method::POST,
        &SPEND_URI_CHIRHO.parse().unwrap(),
        b"fence-read-consumer-body-chirho",
        None,
        None,
    )
    .await
}

/// The typed refusal a decision answered with, or `None` when it continues toward local selection.
fn refusal_identity_chirho(
    decision_chirho: &ServedWriteBeforeSelectionChirho,
) -> Option<RelayRefusalIdentityChirho> {
    match decision_chirho {
        ServedWriteBeforeSelectionChirho::RespondChirho(response_chirho) => Some(
            response_chirho
                .extensions()
                .get::<RelayHttpRefusalChirho>()
                .expect("every preselection answer here is a named relay refusal")
                .0,
        ),
        ServedWriteBeforeSelectionChirho::ContinueChirho(_) => None,
    }
}

/// One root, one request and one stub dispatch throughout; only the kind of entry at the fence path
/// changes. The valid fence reaches the relay port before and after, so the refusals in between come
/// from the entry's kind. A genuine absence still reads Local: see
/// `never_latched_requests_bypass_both_caller_key_and_dispatch_chirho`.
#[tokio::test]
async fn an_unexaminable_fence_refuses_before_dispatch_and_a_valid_one_still_relays_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("fence-read-consumer");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 7).expect("geo-latch tenant root");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::OwnerUnknownChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    let fence_chirho = fence_path_chirho(&root_chirho);
    let moved_chirho = root_chirho.join("moved-fence-chirho.json");

    let valid_chirho = spend_decision_before_selection_chirho(&state_chirho).await;
    assert_eq!(
        refusal_identity_chirho(&valid_chirho),
        Some(RelayRefusalIdentityChirho::RelayOwnerUnknownChirho),
        "control: a valid Elected fence must reach the relay port"
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 1);

    // The old `exists()` read a dangling link as no fence, so the era was Local and the request
    // continued toward local selection. A live link to this root's own valid fence was followed and
    // relayed, and so was a link at the fence directory to its own moved copy (gpt #29681).
    std::fs::rename(&fence_chirho, &moved_chirho).expect("move the valid fence aside");
    symlink(root_chirho.join("nowhere-chirho.json"), &fence_chirho).expect("dangling link");
    let dangling_chirho = spend_decision_before_selection_chirho(&state_chirho).await;
    std::fs::remove_file(&fence_chirho).expect("remove the dangling link");
    symlink(&moved_chirho, &fence_chirho).expect("live link to the valid fence");
    let live_link_chirho = spend_decision_before_selection_chirho(&state_chirho).await;
    std::fs::remove_file(&fence_chirho).expect("remove the live link");
    std::fs::rename(&moved_chirho, &fence_chirho).expect("restore the valid fence");
    let fence_dir_chirho = fence_chirho
        .parent()
        .expect("fence directory")
        .to_path_buf();
    let moved_dir_chirho = root_chirho.join("moved-fences-chirho");
    std::fs::rename(&fence_dir_chirho, &moved_dir_chirho).expect("move the fence directory aside");
    symlink(&moved_dir_chirho, &fence_dir_chirho).expect("link at the fence directory");
    let directory_link_chirho = spend_decision_before_selection_chirho(&state_chirho).await;
    for (case_chirho, decision_chirho) in [
        ("a dangling link", &dangling_chirho),
        ("a live link", &live_link_chirho),
        ("a directory link", &directory_link_chirho),
    ] {
        assert_eq!(
            refusal_identity_chirho(decision_chirho),
            Some(RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho),
            "{case_chirho} must refuse by its fixed identity, never continue locally"
        );
    }
    assert_eq!(
        dispatch_chirho.calls_chirho(),
        1,
        "an unexaminable fence must refuse before the relay port"
    );

    std::fs::remove_file(&fence_dir_chirho).expect("remove the directory link");
    std::fs::rename(&moved_dir_chirho, &fence_dir_chirho).expect("restore the fence directory");
    let restored_chirho = spend_decision_before_selection_chirho(&state_chirho).await;
    assert_eq!(
        refusal_identity_chirho(&restored_chirho),
        Some(RelayRefusalIdentityChirho::RelayOwnerUnknownChirho),
        "control: the restored fence must reach the relay port again"
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 2);
}

/// The whole served request, not only the decision: a dangling link at the fence path answers the fixed
/// 503 refusal and calls no relay port. The status and the identity carry the causal proof. The
/// unchanged snapshot is a non-attributing safety net on this fixture: with the old following read the
/// request took the local road and answered 405 without writing, because no app is deployed here.
#[tokio::test]
async fn a_dangling_fence_link_refuses_the_served_write_and_writes_nothing_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("fence-read-consumer-http");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 7).expect("geo-latch tenant root");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::OwnerUnknownChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    let fence_chirho = fence_path_chirho(&root_chirho);
    std::fs::rename(&fence_chirho, root_chirho.join("moved-fence-chirho.json"))
        .expect("move the valid fence aside");
    symlink(root_chirho.join("nowhere-chirho.json"), &fence_chirho).expect("dangling link");
    let before_chirho = snapshot_files_chirho(&root_chirho);

    let response_chirho = app_http_chirho::run_app_http_with_method_for_served_request_chirho(
        &state_chirho,
        Some("127.0.0.1:43121".parse().unwrap()),
        &spend_headers_chirho(),
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        Method::POST,
        b"must-not-run-locally-chirho".to_vec(),
    )
    .await;
    let (status_chirho, text_chirho) = response_text_chirho(response_chirho).await;

    assert_eq!(
        status_chirho,
        StatusCode::SERVICE_UNAVAILABLE,
        "{text_chirho}"
    );
    assert!(
        text_chirho.contains("RelayConsistencyGroupMismatchChirho"),
        "{text_chirho}"
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 0);
    assert_eq!(
        snapshot_files_chirho(&root_chirho),
        before_chirho,
        "a refused served write must leave every durable byte unchanged"
    );
}
