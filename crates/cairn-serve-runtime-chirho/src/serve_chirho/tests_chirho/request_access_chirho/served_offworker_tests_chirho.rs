// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Served-overload (ii): every served road executes its run off the async workers, and the work that executes owns the
//! request's admission (and invoke's mailbox) until it ends. Each arm parks, fails or panics the work at a test-only
//! hold point, on a runtime with ONE async worker, and waits with deadlines so a deadlock fails instead of hanging.
//!
//! Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.

use super::*;
use crate::serve_chirho::invoke_transport_chirho::{
    process_invoke_json_with_headers_chirho, WireRequestChirho,
};
use crate::serve_chirho::runtime_ports_chirho::served_run_hold_chirho::{
    arm_chirho, ArmedHoldChirho, HoldModeChirho, HoldSiteChirho,
};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, Method};
use axum::Json;
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

pub(super) const OFFWORKER_APP_CHIRHO: &str = "offworker-upcase";
/// Long enough for a quiet or a loaded machine to answer work that is free to run.
pub(super) const PROMPT_CHIRHO: Duration = Duration::from_secs(3);
/// How long work that was released has to finish.
pub(super) const SETTLE_CHIRHO: Duration = Duration::from_secs(10);
/// How long an arm watches for something that must NOT happen.
const QUIET_CHIRHO: Duration = Duration::from_secs(2);

/// One served road, entered by calling its handler directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoadChirho {
    AppChirho,
    SsrChirho,
    InvokeChirho,
    InvokeMessageChirho,
    RunChirho,
    PreviewChirho,
}

pub(super) const ALL_ROADS_CHIRHO: [RoadChirho; 6] = [
    RoadChirho::AppChirho,
    RoadChirho::SsrChirho,
    RoadChirho::InvokeChirho,
    RoadChirho::InvokeMessageChirho,
    RoadChirho::RunChirho,
    RoadChirho::PreviewChirho,
];

/// A root with one deployed pure upcase app; its DAG also serves `/run-chirho` and preview.
pub(super) struct OffworkerFixtureChirho {
    pub(super) root_chirho: std::path::PathBuf,
    pub(super) dag_hex_chirho: String,
}

impl Drop for OffworkerFixtureChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_chirho);
    }
}

pub(super) fn offworker_fixture_chirho(label_chirho: &str) -> OffworkerFixtureChirho {
    let root_chirho = temp_root_chirho(label_chirho);
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let dag_chirho = deploy_transform_app_for_owner_chirho(
        &root_chirho,
        OFFWORKER_APP_CHIRHO,
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(&root_chirho, OFFWORKER_APP_CHIRHO, &owner_chirho);
    OffworkerFixtureChirho {
        root_chirho,
        dag_hex_chirho: dag_chirho.0,
    }
}

/// ONE async worker: any served work that blocks it stops every other request, which is what the arms detect.
pub(super) fn one_worker_runtime_chirho(
    max_blocking_threads_chirho: usize,
) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(max_blocking_threads_chirho)
        .enable_all()
        .build()
        .unwrap()
}

pub(super) fn capped_state_chirho(
    root_chirho: &std::path::Path,
    cap_chirho: usize,
) -> AppStateChirho {
    AppStateChirho {
        inflight_chirho: Arc::new(tokio::sync::Semaphore::new(cap_chirho)),
        ..app_state_for_root_chirho(root_chirho)
    }
}

/// A road's answer as an HTTP status; the WebSocket message's JSON answer maps onto the same three outcomes.
async fn road_status_chirho(
    state_chirho: AppStateChirho,
    dag_hex_chirho: String,
    road_chirho: RoadChirho,
) -> u16 {
    let invoke_request_chirho = || WireRequestChirho {
        target_chirho: OFFWORKER_APP_CHIRHO.to_string(),
        payload_chirho: "x".to_string(),
        base_version_chirho: None,
    };
    let response_chirho = match road_chirho {
        RoadChirho::AppChirho => {
            app_post_request_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                AxPath(OFFWORKER_APP_CHIRHO.to_string()),
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/app-chirho/{OFFWORKER_APP_CHIRHO}"))
                    .body(Body::from("x"))
                    .unwrap(),
            )
            .await
        }
        RoadChirho::SsrChirho => {
            ssr_get_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                AxPath(OFFWORKER_APP_CHIRHO.to_string()),
            )
            .await
        }
        RoadChirho::InvokeChirho => {
            invoke_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                Json(invoke_request_chirho()),
            )
            .await
        }
        RoadChirho::InvokeMessageChirho => {
            let text_chirho =
                format!(r#"{{"target_chirho":"{OFFWORKER_APP_CHIRHO}","payload_chirho":"x"}}"#);
            let answer_chirho =
                process_invoke_json_with_headers_chirho(&state_chirho, &text_chirho, None, None)
                    .await;
            let parsed_chirho: serde_json::Value = serde_json::from_str(&answer_chirho).unwrap();
            return if parsed_chirho["ok_chirho"] == true {
                200
            } else if parsed_chirho["payload_chirho"] == "served request unavailable" {
                429
            } else {
                400
            };
        }
        RoadChirho::RunChirho => {
            run_post_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                AxPath(dag_hex_chirho),
                Bytes::from_static(b"x"),
            )
            .await
        }
        RoadChirho::PreviewChirho => {
            preview_post_chirho(
                State(state_chirho),
                None,
                HeaderMap::new(),
                AxPath(dag_hex_chirho),
                Bytes::from_static(b"x"),
            )
            .await
        }
    };
    response_chirho.status().as_u16()
}

/// A request in flight on the test runtime: its task, and the channel its status arrives on.
pub(super) struct InFlightChirho {
    pub(super) task_chirho: tokio::task::JoinHandle<()>,
    pub(super) status_chirho: Receiver<u16>,
}

pub(super) fn spawn_road_chirho(
    runtime_chirho: &tokio::runtime::Runtime,
    state_chirho: &AppStateChirho,
    fixture_chirho: &OffworkerFixtureChirho,
    road_chirho: RoadChirho,
) -> InFlightChirho {
    let (sender_chirho, receiver_chirho) = channel();
    let state_chirho = state_chirho.clone();
    let dag_hex_chirho = fixture_chirho.dag_hex_chirho.clone();
    let task_chirho = runtime_chirho.spawn(async move {
        let status_chirho = road_status_chirho(state_chirho, dag_hex_chirho, road_chirho).await;
        let _ = sender_chirho.send(status_chirho);
    });
    InFlightChirho {
        task_chirho,
        status_chirho: receiver_chirho,
    }
}

/// True when the runtime's async worker polls a fresh health request within `PROMPT_CHIRHO`.
pub(super) fn health_answers_chirho(runtime_chirho: &tokio::runtime::Runtime) -> bool {
    let (sender_chirho, receiver_chirho) = channel();
    runtime_chirho.spawn(async move {
        let _ = sender_chirho.send(healthz_chirho().await);
    });
    receiver_chirho.recv_timeout(PROMPT_CHIRHO).is_ok()
}

/// Abort a request's handler task and wait until the runtime has dropped its future.
pub(super) fn abort_handler_chirho(in_flight_chirho: &InFlightChirho, case_chirho: &str) {
    in_flight_chirho.task_chirho.abort();
    let deadline_chirho = Instant::now() + PROMPT_CHIRHO;
    while !in_flight_chirho.task_chirho.is_finished() {
        assert!(
            Instant::now() < deadline_chirho,
            "{case_chirho}: the aborted handler's future was never dropped (is it blocking the worker?)"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub(super) fn wait_permits_chirho(
    state_chirho: &AppStateChirho,
    expected_chirho: usize,
    case_chirho: &str,
) {
    let deadline_chirho = Instant::now() + SETTLE_CHIRHO;
    while state_chirho.inflight_chirho.available_permits() != expected_chirho {
        assert!(
            Instant::now() < deadline_chirho,
            "{case_chirho}: expected {expected_chirho} available permits, have {}",
            state_chirho.inflight_chirho.available_permits()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn parked_chirho(hold_chirho: &ArmedHoldChirho, count_chirho: usize, case_chirho: &str) {
    assert!(
        hold_chirho.wait_entered_chirho(count_chirho, SETTLE_CHIRHO),
        "{case_chirho}: {count_chirho} piece(s) of work never reached the hold"
    );
}

/// Every road, with its run parked: the one async worker still answers health, and a second request is refused at the
/// door by the in-flight cap, promptly, instead of queueing behind the parked run.
///
/// MIGRATION PATH: a health timeout means a run executes on the async worker again (the facade's fast path, or a
/// synchronous handler). A second request that is NOT refused means the run no longer holds the permit it was admitted
/// with. A first request that does not answer 200 after release means the release or the run itself broke.
#[test]
fn every_served_road_runs_off_the_worker_and_sheds_at_the_door_chirho() {
    for road_chirho in ALL_ROADS_CHIRHO {
        let case_chirho = format!("{road_chirho:?}");
        let runtime_chirho = one_worker_runtime_chirho(8);
        let fixture_chirho = offworker_fixture_chirho("offworker-door");
        let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 1);
        let hold_chirho = arm_chirho(
            &fixture_chirho.root_chirho,
            HoldSiteChirho::RunChirho,
            HoldModeChirho::ParkChirho,
        );
        let first_chirho =
            spawn_road_chirho(&runtime_chirho, &state_chirho, &fixture_chirho, road_chirho);
        parked_chirho(&hold_chirho, 1, &case_chirho);
        assert!(
            health_answers_chirho(&runtime_chirho),
            "{case_chirho}: health must answer while the run is parked"
        );
        let second_chirho =
            spawn_road_chirho(&runtime_chirho, &state_chirho, &fixture_chirho, road_chirho);
        assert_eq!(
            second_chirho.status_chirho.recv_timeout(PROMPT_CHIRHO),
            Ok(429),
            "{case_chirho}: the second request is refused at the door"
        );
        hold_chirho.release_chirho();
        assert_eq!(
            first_chirho.status_chirho.recv_timeout(SETTLE_CHIRHO),
            Ok(200),
            "{case_chirho}: the parked request completes after release"
        );
        wait_permits_chirho(&state_chirho, 1, &case_chirho);
        assert_eq!(hold_chirho.timed_out_chirho(), 0, "{case_chirho}");
    }
}

/// Every road: abort the handler while its run is parked. The work keeps the admission, so the permit stays taken and a
/// new request is refused, until the work ends and the permit returns.
///
/// MIGRATION PATH: a permit that returns while the run is still parked means the admission is owned by the handler's
/// future again (or dropped before the work), so a cancelled request frees capacity its work still uses.
#[test]
fn a_cancelled_handler_cannot_release_the_permit_its_work_still_uses_chirho() {
    for road_chirho in ALL_ROADS_CHIRHO {
        let case_chirho = format!("{road_chirho:?}");
        let runtime_chirho = one_worker_runtime_chirho(8);
        let fixture_chirho = offworker_fixture_chirho("offworker-custody");
        let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 1);
        let hold_chirho = arm_chirho(
            &fixture_chirho.root_chirho,
            HoldSiteChirho::RunChirho,
            HoldModeChirho::ParkChirho,
        );
        let first_chirho =
            spawn_road_chirho(&runtime_chirho, &state_chirho, &fixture_chirho, road_chirho);
        parked_chirho(&hold_chirho, 1, &case_chirho);
        abort_handler_chirho(&first_chirho, &case_chirho);
        assert_eq!(
            state_chirho.inflight_chirho.available_permits(),
            0,
            "{case_chirho}: the parked work still owns its permit"
        );
        let second_chirho =
            spawn_road_chirho(&runtime_chirho, &state_chirho, &fixture_chirho, road_chirho);
        assert_eq!(
            second_chirho.status_chirho.recv_timeout(PROMPT_CHIRHO),
            Ok(429),
            "{case_chirho}: no new request is admitted while the work runs"
        );
        hold_chirho.release_chirho();
        wait_permits_chirho(&state_chirho, 1, &case_chirho);
        assert_eq!(hold_chirho.timed_out_chirho(), 0, "{case_chirho}");
    }
}

/// Both invoke transports: park the first section AFTER its run and BEFORE its final version observation, then cancel
/// its handler. A second invoke is admitted but cannot enter the mailbox until that whole section ends.
///
/// MIGRATION PATH: a second invoke that reaches the hold while the first is parked means the mailbox is released before
/// the section ends: owned by a cancelled handler, or dropped right after the run.
#[test]
fn the_invoke_mailbox_spans_the_whole_section_through_a_cancelled_handler_chirho() {
    for road_chirho in [RoadChirho::InvokeChirho, RoadChirho::InvokeMessageChirho] {
        let case_chirho = format!("{road_chirho:?}");
        let runtime_chirho = one_worker_runtime_chirho(8);
        let fixture_chirho = offworker_fixture_chirho("offworker-mailbox");
        let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 2);
        let hold_chirho = arm_chirho(
            &fixture_chirho.root_chirho,
            HoldSiteChirho::InvokeAfterRunChirho,
            HoldModeChirho::ParkChirho,
        );
        let first_chirho =
            spawn_road_chirho(&runtime_chirho, &state_chirho, &fixture_chirho, road_chirho);
        parked_chirho(&hold_chirho, 1, &case_chirho);
        abort_handler_chirho(&first_chirho, &case_chirho);
        let second_chirho =
            spawn_road_chirho(&runtime_chirho, &state_chirho, &fixture_chirho, road_chirho);
        assert!(
            !hold_chirho.wait_entered_chirho(2, QUIET_CHIRHO),
            "{case_chirho}: the second invoke entered the mailbox while the first section was unfinished"
        );
        assert_eq!(
            state_chirho.inflight_chirho.available_permits(),
            0,
            "{case_chirho}: both invokes hold their permits, one in the section and one at the mailbox"
        );
        assert!(health_answers_chirho(&runtime_chirho), "{case_chirho}");
        hold_chirho.release_chirho();
        assert_eq!(
            second_chirho.status_chirho.recv_timeout(SETTLE_CHIRHO),
            Ok(200),
            "{case_chirho}: the second invoke runs once the first section ends"
        );
        wait_permits_chirho(&state_chirho, 2, &case_chirho);
        assert_eq!(hold_chirho.timed_out_chirho(), 0, "{case_chirho}");
    }
}

/// The named app route's after-write refresh runs inside the admission: with the refresh parked and the handler
/// cancelled, the permit stays taken until the refresh ends.
///
/// MIGRATION PATH: a permit that returns while the refresh is parked means the admission ends before the refresh.
#[test]
fn the_after_write_refresh_runs_inside_the_admission_chirho() {
    let runtime_chirho = one_worker_runtime_chirho(8);
    let fixture_chirho = offworker_fixture_chirho("offworker-refresh");
    let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 1);
    let hold_chirho = arm_chirho(
        &fixture_chirho.root_chirho,
        HoldSiteChirho::RefreshChirho,
        HoldModeChirho::ParkChirho,
    );
    let first_chirho = spawn_road_chirho(
        &runtime_chirho,
        &state_chirho,
        &fixture_chirho,
        RoadChirho::AppChirho,
    );
    parked_chirho(&hold_chirho, 1, "refresh");
    assert!(
        health_answers_chirho(&runtime_chirho),
        "the refresh runs off the worker"
    );
    abort_handler_chirho(&first_chirho, "refresh");
    assert_eq!(state_chirho.inflight_chirho.available_permits(), 0);
    let second_chirho = spawn_road_chirho(
        &runtime_chirho,
        &state_chirho,
        &fixture_chirho,
        RoadChirho::AppChirho,
    );
    assert_eq!(
        second_chirho.status_chirho.recv_timeout(PROMPT_CHIRHO),
        Ok(429)
    );
    hold_chirho.release_chirho();
    wait_permits_chirho(&state_chirho, 1, "refresh");
    assert_eq!(hold_chirho.timed_out_chirho(), 0);
}

/// A refresh that fails, or panics, after the run returned Ok does not turn the saved result into a failure: the
/// request answers 200 with the run's output, and the permit returns. The real-failure arms with an exact replayed
/// retry are `a_save_whose_projection_refresh_fails_is_answered_as_saved_chirho` and
/// `a_write_whose_projection_refresh_fails_is_saved_and_the_projection_catches_up_chirho`.
///
/// MIGRATION PATH: a non-200 here means a refresh failure is propagated over a landed result again.
#[test]
fn a_failed_or_panicking_refresh_keeps_the_saved_result_chirho() {
    for mode_chirho in [HoldModeChirho::FailChirho, HoldModeChirho::PanicChirho] {
        let case_chirho = format!("{mode_chirho:?}");
        let runtime_chirho = one_worker_runtime_chirho(8);
        let fixture_chirho = offworker_fixture_chirho("offworker-refresh-failure");
        let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 1);
        let hold_chirho = arm_chirho(
            &fixture_chirho.root_chirho,
            HoldSiteChirho::RefreshChirho,
            mode_chirho,
        );
        let (sender_chirho, receiver_chirho) = channel();
        let request_state_chirho = state_chirho.clone();
        runtime_chirho.spawn(async move {
            let response_chirho = app_post_request_chirho(
                State(request_state_chirho),
                None,
                HeaderMap::new(),
                AxPath(OFFWORKER_APP_CHIRHO.to_string()),
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/app-chirho/{OFFWORKER_APP_CHIRHO}"))
                    .body(Body::from("x"))
                    .unwrap(),
            )
            .await;
            let status_chirho = response_chirho.status().as_u16();
            let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
                .await
                .unwrap();
            let _ = sender_chirho.send((status_chirho, body_chirho.to_vec()));
        });
        assert_eq!(
            receiver_chirho.recv_timeout(SETTLE_CHIRHO),
            Ok((200, b"X".to_vec())),
            "{case_chirho}: the saved result is the answer"
        );
        assert_eq!(
            hold_chirho.entered_chirho(),
            1,
            "{case_chirho}: the refresh ran"
        );
        wait_permits_chirho(&state_chirho, 1, &case_chirho);
    }
}

/// Every road: a panic in the run unwinds the request (no answer claims a refused or effect-free run), and its permit,
/// and invoke's mailbox, are released: the same road then answers 200.
///
/// MIGRATION PATH: a request that answers instead of unwinding means a join failure is mapped to a response again; a
/// permit that never returns, or a follow-up that is refused or hangs, means the cleanup broke.
#[test]
fn a_panicking_run_unwinds_its_request_and_releases_its_permit_chirho() {
    for road_chirho in ALL_ROADS_CHIRHO {
        let case_chirho = format!("{road_chirho:?}");
        let runtime_chirho = one_worker_runtime_chirho(8);
        let fixture_chirho = offworker_fixture_chirho("offworker-panic");
        let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 1);
        let hold_chirho = arm_chirho(
            &fixture_chirho.root_chirho,
            HoldSiteChirho::RunChirho,
            HoldModeChirho::PanicChirho,
        );
        let first_chirho =
            spawn_road_chirho(&runtime_chirho, &state_chirho, &fixture_chirho, road_chirho);
        let joined_chirho = runtime_chirho
            .block_on(async { tokio::time::timeout(SETTLE_CHIRHO, first_chirho.task_chirho).await })
            .expect("the panicking request ends");
        assert!(
            joined_chirho.is_err_and(|error_chirho| error_chirho.is_panic()),
            "{case_chirho}: the run's panic unwinds the request"
        );
        assert!(
            first_chirho.status_chirho.try_recv().is_err(),
            "{case_chirho}: no answer"
        );
        wait_permits_chirho(&state_chirho, 1, &case_chirho);
        drop(hold_chirho);
        let follow_up_chirho =
            spawn_road_chirho(&runtime_chirho, &state_chirho, &fixture_chirho, road_chirho);
        assert_eq!(
            follow_up_chirho.status_chirho.recv_timeout(SETTLE_CHIRHO),
            Ok(200),
            "{case_chirho}: the road serves again"
        );
    }
}

/// The in-flight cap bounds QUEUED work as well as running work. With one blocking thread, a parked run occupies it, a
/// second admitted run waits in the blocking queue without starting, and a third request is refused at the door; health
/// stays live throughout, and the queued run starts once the first ends.
///
/// MIGRATION PATH: a third request that is admitted means admission no longer precedes scheduling, so the blocking queue
/// can grow without bound.
#[test]
fn the_in_flight_cap_bounds_queued_and_running_work_together_chirho() {
    let runtime_chirho = one_worker_runtime_chirho(1);
    let fixture_chirho = offworker_fixture_chirho("offworker-queue");
    let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 2);
    let hold_chirho = arm_chirho(
        &fixture_chirho.root_chirho,
        HoldSiteChirho::RunChirho,
        HoldModeChirho::ParkChirho,
    );
    let running_chirho = spawn_road_chirho(
        &runtime_chirho,
        &state_chirho,
        &fixture_chirho,
        RoadChirho::RunChirho,
    );
    parked_chirho(&hold_chirho, 1, "queue");
    let queued_chirho = spawn_road_chirho(
        &runtime_chirho,
        &state_chirho,
        &fixture_chirho,
        RoadChirho::RunChirho,
    );
    assert!(
        !hold_chirho.wait_entered_chirho(2, QUIET_CHIRHO),
        "the second run must wait in the blocking queue, not start"
    );
    assert_eq!(state_chirho.inflight_chirho.available_permits(), 0);
    assert!(
        health_answers_chirho(&runtime_chirho),
        "a full blocking pool leaves the worker free"
    );
    let refused_chirho = spawn_road_chirho(
        &runtime_chirho,
        &state_chirho,
        &fixture_chirho,
        RoadChirho::RunChirho,
    );
    assert_eq!(
        refused_chirho.status_chirho.recv_timeout(PROMPT_CHIRHO),
        Ok(429)
    );
    hold_chirho.release_chirho();
    assert_eq!(
        running_chirho.status_chirho.recv_timeout(SETTLE_CHIRHO),
        Ok(200)
    );
    assert_eq!(
        queued_chirho.status_chirho.recv_timeout(SETTLE_CHIRHO),
        Ok(200)
    );
    wait_permits_chirho(&state_chirho, 2, "queue");
    assert_eq!(hold_chirho.timed_out_chirho(), 0);
}
