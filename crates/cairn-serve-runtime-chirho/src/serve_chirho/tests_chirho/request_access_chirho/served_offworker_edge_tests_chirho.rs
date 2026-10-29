// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Served-overload (ii), the edges: preview takes admission yet persists nothing, a REAL closed connection leaves its
//! work's permit taken, and a runtime shutdown is the one place the detached custody ends before a started run does.
//!
//! Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.

use super::served_offworker_tests_chirho::*;
use super::*;
use crate::serve_chirho::runtime_ports_chirho::served_run_hold_chirho::{
    arm_chirho, HoldModeChirho, HoldSiteChirho,
};
use axum::http::HeaderMap;
use cairn_app_preview_chirho::PREVIEW_UNREVIEWED_HEADER_CHIRHO;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

/// Preview is admitted like a served run, but its executor persists nothing: the root is byte-identical after a preview.
/// The positive control runs the same DAG and input through `/run-chirho`, whose run intent and cached result the same
/// snapshot must see, or the snapshot proves nothing about preview.
///
/// MIGRATION PATH: a changed root after preview means preview gained a durable write; it must stay pure. A control that
/// shows no change means `/run-chirho` stopped persisting or the snapshot stopped seeing writes: fix the instrument.
#[test]
fn preview_takes_admission_but_persists_nothing_chirho() {
    let runtime_chirho = one_worker_runtime_chirho(8);
    let fixture_chirho = offworker_fixture_chirho("offworker-preview-persist");
    let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 1);
    let before_chirho = runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho);
    let (status_chirho, labelled_chirho, body_chirho) = runtime_chirho.block_on(async {
        let response_chirho = preview_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(fixture_chirho.dag_hex_chirho.clone()),
            Bytes::from_static(b"x"),
        )
        .await;
        let status_chirho = response_chirho.status().as_u16();
        let labelled_chirho = response_chirho
            .headers()
            .contains_key(PREVIEW_UNREVIEWED_HEADER_CHIRHO);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        (status_chirho, labelled_chirho, body_chirho.to_vec())
    });
    assert_eq!(
        (status_chirho, body_chirho.as_slice()),
        (200, b"X".as_slice())
    );
    assert!(labelled_chirho, "preview output keeps its unreviewed label");
    assert_eq!(
        runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho),
        before_chirho,
        "preview must not persist anything"
    );
    wait_permits_chirho(&state_chirho, 1, "preview");
    let run_status_chirho = runtime_chirho.block_on(async {
        run_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(fixture_chirho.dag_hex_chirho.clone()),
            Bytes::from_static(b"x"),
        )
        .await
        .status()
        .as_u16()
    });
    assert_eq!(run_status_chirho, 200);
    assert_ne!(
        runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho),
        before_chirho,
        "the control: the snapshot must see /run-chirho's writes"
    );
}

/// One HTTP/1.1 request over a fresh connection, read until the server closes it. `None` when no status line arrives
/// within `read_timeout_chirho`.
fn raw_post_status_chirho(
    addr_chirho: &str,
    path_chirho: &str,
    read_timeout_chirho: Duration,
) -> Option<u16> {
    let mut stream_chirho = TcpStream::connect(addr_chirho).ok()?;
    stream_chirho
        .set_read_timeout(Some(read_timeout_chirho))
        .ok()?;
    write_post_chirho(&mut stream_chirho, addr_chirho, path_chirho);
    let mut answer_chirho = Vec::new();
    let _ = stream_chirho.read_to_end(&mut answer_chirho);
    let head_chirho = String::from_utf8_lossy(&answer_chirho);
    head_chirho
        .strip_prefix("HTTP/1.1 ")?
        .get(..3)?
        .parse()
        .ok()
}

fn write_post_chirho(stream_chirho: &mut TcpStream, addr_chirho: &str, path_chirho: &str) {
    write!(
        stream_chirho,
        "POST {path_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\ncontent-length: 1\r\nconnection: close\r\n\r\nx"
    )
    .unwrap();
    stream_chirho.flush().unwrap();
}

/// The real server, with an in-flight cap of one. A client sends a request, its run parks, and the client CLOSES the
/// connection. Whether or not the server then cancels that handler (this arm does not claim either), the work keeps its
/// permit: a second client is refused until the work ends, and then served.
///
/// MIGRATION PATH: a second client served while the first run is parked means a closed connection released a permit
/// its work still uses.
#[test]
fn a_closed_connection_leaves_its_works_permit_taken_until_the_work_ends_chirho() {
    let fixture_chirho = offworker_fixture_chirho("offworker-connection-close");
    let app_path_chirho = format!("/app-chirho/{OFFWORKER_APP_CHIRHO}");
    let run_path_chirho = format!("/run-chirho/{}", fixture_chirho.dag_hex_chirho);
    for path_chirho in [app_path_chirho, run_path_chirho] {
        let port_chirho = unused_local_port_chirho();
        let addr_chirho = format!("127.0.0.1:{port_chirho}");
        let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
        let root_for_server_chirho = fixture_chirho.root_chirho.clone();
        let server_chirho = runtime_chirho.spawn(async move {
            serve_with_configured_request_limits_chirho(
                &root_for_server_chirho,
                port_chirho,
                1,
                String::new(),
                String::new(),
                false,
                ServedRequestAbuseLimitsChirho::default(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let hold_chirho = arm_chirho(
            &fixture_chirho.root_chirho,
            HoldSiteChirho::RunChirho,
            HoldModeChirho::ParkChirho,
        );
        let mut closing_chirho = TcpStream::connect(&addr_chirho).unwrap();
        write_post_chirho(&mut closing_chirho, &addr_chirho, &path_chirho);
        assert!(
            hold_chirho.wait_entered_chirho(1, SETTLE_CHIRHO),
            "{path_chirho}: the first run reached the hold"
        );
        closing_chirho.shutdown(Shutdown::Both).unwrap();
        drop(closing_chirho);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            raw_post_status_chirho(&addr_chirho, &path_chirho, PROMPT_CHIRHO),
            Some(429),
            "{path_chirho}: the closed connection's work still owns the only permit"
        );
        hold_chirho.release_chirho();
        let deadline_chirho = Instant::now() + SETTLE_CHIRHO;
        loop {
            if raw_post_status_chirho(&addr_chirho, &path_chirho, PROMPT_CHIRHO) == Some(200) {
                break;
            }
            assert!(
                Instant::now() < deadline_chirho,
                "{path_chirho}: the permit never returned after the work ended"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(hold_chirho.timed_out_chirho(), 0, "{path_chirho}");
        drop(hold_chirho);
        server_chirho.abort();
        drop(runtime_chirho);
    }
}

/// The documented limit of detached custody (tokio 1.52.3, `spawn_blocking`): a runtime shutdown drops every async task,
/// the custody task included, so the request's permit is released while a STARTED blocking run keeps running until it
/// ends. No request task runs after that point, so nothing new is admitted, but the permit object is gone before the
/// work is. This arm records that, so the boundary is measured rather than asserted.
///
/// MIGRATION PATH: a permit that stays taken until the run ends means custody moved into the blocking work itself; this
/// arm then documents a stronger property and should say so.
#[test]
fn runtime_shutdown_ends_detached_custody_before_a_started_run_chirho() {
    let runtime_chirho = one_worker_runtime_chirho(8);
    let fixture_chirho = offworker_fixture_chirho("offworker-shutdown");
    let state_chirho = capped_state_chirho(&fixture_chirho.root_chirho, 1);
    let hold_chirho = arm_chirho(
        &fixture_chirho.root_chirho,
        HoldSiteChirho::RunChirho,
        HoldModeChirho::ParkChirho,
    );
    let in_flight_chirho = spawn_road_chirho(
        &runtime_chirho,
        &state_chirho,
        &fixture_chirho,
        RoadChirho::AppChirho,
    );
    assert!(hold_chirho.wait_entered_chirho(1, SETTLE_CHIRHO));
    let observed_chirho = std::thread::scope(|scope_chirho| {
        let observer_chirho = scope_chirho.spawn(|| {
            let deadline_chirho = Instant::now() + SETTLE_CHIRHO;
            while state_chirho.inflight_chirho.available_permits() != 1 {
                if Instant::now() >= deadline_chirho {
                    hold_chirho.release_chirho();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let still_running_chirho =
                hold_chirho.left_chirho() == 0 && hold_chirho.timed_out_chirho() == 0;
            hold_chirho.release_chirho();
            Some(still_running_chirho)
        });
        runtime_chirho.shutdown_timeout(SETTLE_CHIRHO);
        observer_chirho.join().unwrap()
    });
    assert_eq!(
        observed_chirho,
        Some(true),
        "shutdown releases the permit while the started run is still parked"
    );
    assert_eq!(
        hold_chirho.left_chirho(),
        1,
        "the started run then finished on its own"
    );
    assert!(
        in_flight_chirho.status_chirho.try_recv().is_err(),
        "the request never answered"
    );
}
