// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The app-route road under concurrency: saves by two principals at the same instant all land, a same-user race saves
//! once and answers the other racer by version, and a save whose projection refresh fails is still answered as saved.
//! A save that meets an outside holder of the viewer-state store is still recorded FAILED; its acceptance arm waits,
//! ignored, for the pre-effect brick.
//!
//! Before the store crate's in-process open lock (`open_lock_chirho`), about a quarter of simultaneous saves by two
//! principals collided on redb's file lock and were refused (PFE #25853).

use super::app_route_fixture_chirho::*;
use super::*;

const CONFLICT_SCHEMA_CHIRHO: &str = "viewer-state-conflict-v1-chirho";

fn concurrent_runtime_chirho() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// Two principals save at the same instant, 20 rounds: every save lands and advances its own head.
///
/// MIGRATION PATH: a refused save here means two requests on one tenant collided again on a store's file lock.
#[test]
fn simultaneous_saves_by_two_principals_all_land_chirho() {
    let tenant_chirho = growth_tenant_chirho("route-concurrency-principals");
    let state_chirho = growth_state_chirho(&tenant_chirho.root_chirho);
    concurrent_runtime_chirho().block_on(async {
        let mut heads_chirho = [None, None];
        for round_chirho in 0..20 {
            let mut tasks_chirho = Vec::new();
            for (user_chirho, headers_chirho) in tenant_chirho.users_chirho.iter().enumerate() {
                let state_chirho = state_chirho.clone();
                let headers_chirho = headers_chirho.clone();
                let body_chirho = write_request_chirho(
                    heads_chirho[user_chirho],
                    &format!("round {round_chirho} by user {user_chirho}"),
                );
                tasks_chirho.push(tokio::spawn(async move {
                    save_chirho(&state_chirho, &headers_chirho, body_chirho).await
                }));
            }
            for (user_chirho, task_chirho) in tasks_chirho.into_iter().enumerate() {
                let (status_chirho, page_chirho) = task_chirho.await.unwrap();
                assert_eq!(
                    status_chirho,
                    StatusCode::OK,
                    "round {round_chirho}, user {user_chirho}: {page_chirho}"
                );
                let next_chirho = head_version_chirho(&page_chirho);
                assert!(
                    next_chirho > heads_chirho[user_chirho],
                    "round {round_chirho}, user {user_chirho}: the save advanced the head: {page_chirho}"
                );
                heads_chirho[user_chirho] = next_chirho;
            }
        }
    });
}

/// One user races two saves at the same expected version, 6 rounds: exactly one saves, and the other is ANSWERED by
/// version (the conflict schema), never refused.
#[test]
fn a_same_user_race_saves_once_and_answers_the_other_by_version_chirho() {
    let tenant_chirho = growth_tenant_chirho("route-concurrency-same-user");
    let state_chirho = growth_state_chirho(&tenant_chirho.root_chirho);
    concurrent_runtime_chirho().block_on(async {
        let headers_chirho = &tenant_chirho.users_chirho[0];
        let mut head_chirho =
            save_next_chirho(&state_chirho, headers_chirho, None, "the race's first page").await;
        for round_chirho in 0..6 {
            let tasks_chirho: Vec<_> = (0..2)
                .map(|racer_chirho| {
                    let state_chirho = state_chirho.clone();
                    let headers_chirho = headers_chirho.clone();
                    let body_chirho = write_request_chirho(
                        head_chirho,
                        &format!("round {round_chirho}, racer {racer_chirho}"),
                    );
                    tokio::spawn(async move {
                        save_chirho(&state_chirho, &headers_chirho, body_chirho).await
                    })
                })
                .collect();
            let (mut saved_chirho, mut answered_chirho) = (0, 0);
            for task_chirho in tasks_chirho {
                let (status_chirho, page_chirho) = task_chirho.await.unwrap();
                assert_eq!(
                    status_chirho,
                    StatusCode::OK,
                    "round {round_chirho}: a racer is saved or answered, never refused: {page_chirho}"
                );
                if page_chirho.contains(CONFLICT_SCHEMA_CHIRHO) {
                    answered_chirho += 1;
                } else {
                    saved_chirho += 1;
                    head_chirho = head_version_chirho(&page_chirho);
                }
            }
            assert_eq!(
                (saved_chirho, answered_chirho),
                (1, 1),
                "round {round_chirho}: exactly one racer saves and the other is answered by version"
            );
        }
    });
}

/// Hold a store file's lock from outside the server, as another process (an operator command) would, run `act`, then
/// let go.
async fn with_outside_holder_chirho<T>(
    store_path_chirho: &std::path::Path,
    act_chirho: impl std::future::Future<Output = T>,
) -> T {
    let holder_chirho = std::fs::File::open(store_path_chirho).unwrap();
    holder_chirho.lock().unwrap();
    let result_chirho = act_chirho.await;
    drop(holder_chirho);
    result_chirho
}

/// A save that meets an outside holder of the VERSIONED store (the query projection's source) lands, its projection
/// refresh fails, and it is answered as SAVED: the saved page, 200 (PFE #25858). An editor save is a viewer-state
/// write, so the projection has nothing to catch up here; the contact write arm
/// (`a_write_whose_projection_refresh_fails_is_saved_and_the_projection_catches_up_chirho`) has the catch-up. The
/// identical retry, after the holder lets go, is a replay: the same page, the head unmoved, no run-intent record.
///
/// MIGRATION PATH: a 500 here means a landed write is answered as failed again. A changed retry page, a moved head,
/// or a new run-intent record means the retry ran again instead of replaying. On this road the versioned store's file
/// exists only because the post-write refresh opens it (measured: with the refresh skipped, the holder's open is
/// NotFound). So when the capacity lever lands (no refresh after a run that wrote no versioned-store row), this arm's
/// premise is gone: an editor save can no longer meet a refresh failure. Retire it then, with that reason.
#[test]
fn a_save_whose_projection_refresh_fails_is_answered_as_saved_chirho() {
    let tenant_chirho = growth_tenant_chirho("route-collision-projection");
    let state_chirho = growth_state_chirho(&tenant_chirho.root_chirho);
    concurrent_runtime_chirho().block_on(async {
        let headers_chirho = &tenant_chirho.users_chirho[0];
        let head_chirho =
            save_next_chirho(&state_chirho, headers_chirho, None, "before the collision").await;
        let body_chirho = write_request_chirho(head_chirho, "the collided save");
        let (status_chirho, page_chirho) = with_outside_holder_chirho(
            &tenant_chirho.root_chirho.join("versioned-chirho.redb"),
            save_chirho(&state_chirho, headers_chirho, body_chirho.clone()),
        )
        .await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "a landed save is answered as saved: {page_chirho}"
        );
        let saved_head_chirho = head_version_chirho(&page_chirho);
        assert!(
            saved_head_chirho > head_chirho,
            "the answer is the saved page: {page_chirho}"
        );
        let run_intents_chirho = run_intent_line_count_chirho(&tenant_chirho.root_chirho);
        let (status_chirho, retry_page_chirho) =
            save_chirho(&state_chirho, headers_chirho, body_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK, "{retry_page_chirho}");
        assert_eq!(
            retry_page_chirho, page_chirho,
            "the identical retry replays the saved page"
        );
        assert_eq!(
            run_intent_line_count_chirho(&tenant_chirho.root_chirho),
            run_intents_chirho,
            "a replay appends no run-intent record"
        );
        let (status_chirho, view_page_chirho) = view_chirho(&state_chirho, headers_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK, "{view_page_chirho}");
        assert_eq!(
            head_version_chirho(&view_page_chirho),
            saved_head_chirho,
            "the save landed exactly once"
        );
    });
}

/// An outside holder of the VIEWER-STATE store meets the save INSIDE its run, before the write. Today the run is
/// recorded FAILED and every identical retry is refused for manual review (measured, CAIRN #25859). agy's ruling
/// (#25855): a failure provably before any side effect must not be terminal. This is that follow-up brick's
/// acceptance arm: an identical retry, after the holder lets go, must SAVE.
#[test]
#[ignore = "acceptance arm of the pre-effect failure brick (agy #25855): a store-open refusal inside a run is still recorded FAILED"]
fn an_outside_holder_of_the_viewer_state_store_never_poisons_the_save_chirho() {
    let tenant_chirho = growth_tenant_chirho("route-collision-viewer-state");
    let state_chirho = growth_state_chirho(&tenant_chirho.root_chirho);
    concurrent_runtime_chirho().block_on(async {
        let headers_chirho = &tenant_chirho.users_chirho[0];
        let head_chirho =
            save_next_chirho(&state_chirho, headers_chirho, None, "before the collision").await;
        let body_chirho = write_request_chirho(head_chirho, "the collided save");
        let (status_chirho, _) = with_outside_holder_chirho(
            &tenant_chirho.root_chirho.join("viewer-state-chirho.redb"),
            save_chirho(&state_chirho, headers_chirho, body_chirho.clone()),
        )
        .await;
        assert_ne!(
            status_chirho,
            StatusCode::OK,
            "the collided save is refused"
        );
        let (status_chirho, page_chirho) =
            save_chirho(&state_chirho, headers_chirho, body_chirho).await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "the identical retry after the holder lets go must save: {page_chirho}"
        );
    });
}
