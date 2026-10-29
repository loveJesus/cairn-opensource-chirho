// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Proves sign-in work runs off the async workers, a few at a time, with its errors intact, and that the auth
//! handlers route every synchronous sign-in call through a helper; and that a waiter dropped mid-work, as when a client
//! hangs up, leaves the permit with the running work, so a burst at one principal stays serial (R11.1), and leaves
//! the source's charge with it too (R12).

use super::super::auth_blocking_chirho::{
    run_blocking_auth_chirho, run_blocking_auth_with_permits_chirho,
    run_blocking_public_auth_with_permits_chirho, SignInWorkIncompleteChirho,
};
use super::super::served_request_limits_chirho::ServedRequestAbuseLimitsChirho;
use super::super::sign_in_gate_chirho::{SignInChargesChirho, SignInGateChirho};
use axum::http::HeaderMap;
use cairn_chirho::identity_chirho::PublicAuthRefusalChirho;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// On a SINGLE-threaded runtime, a quick task must finish while slow sign-in work is in flight. If the helper ran
/// the work inline (the pre-fix shape) the one thread would be blocked and the quick task would wait it out.
#[tokio::test(flavor = "current_thread")]
async fn a_concurrent_task_completes_while_sign_in_work_runs_chirho() {
    let permits_chirho = Arc::new(Semaphore::new(1));
    let slow_permits_chirho = Arc::clone(&permits_chirho);
    let started_chirho = Instant::now();
    let slow_chirho = tokio::spawn(async move {
        run_blocking_auth_with_permits_chirho(&slow_permits_chirho, || {
            std::thread::sleep(Duration::from_millis(600));
            Ok(())
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let quick_elapsed_chirho = started_chirho.elapsed();
    assert!(
        quick_elapsed_chirho < Duration::from_millis(300),
        "a concurrent task waited {quick_elapsed_chirho:?} behind sign-in work; the work is running on the async worker"
    );
    assert!(
        !slow_chirho.is_finished(),
        "control: the slow sign-in work must still be in flight"
    );
    slow_chirho.await.expect("join").expect("slow task result");
}

/// No more than the permit count of sign-ins compute at once; the rest wait asynchronously.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_in_work_runs_at_most_the_permit_count_at_once_chirho() {
    let permits_chirho = Arc::new(Semaphore::new(1));
    let running_chirho = Arc::new(AtomicUsize::new(0));
    let peak_chirho = Arc::new(AtomicUsize::new(0));
    let mut handles_chirho = Vec::new();
    for _ in 0..3 {
        let permits_chirho = Arc::clone(&permits_chirho);
        let running_chirho = Arc::clone(&running_chirho);
        let peak_chirho = Arc::clone(&peak_chirho);
        handles_chirho.push(tokio::spawn(async move {
            run_blocking_auth_with_permits_chirho(&permits_chirho, move || {
                let now_chirho = running_chirho.fetch_add(1, Ordering::SeqCst) + 1;
                peak_chirho.fetch_max(now_chirho, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(80));
                running_chirho.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            })
            .await
        }));
    }
    for handle_chirho in handles_chirho {
        handle_chirho.await.expect("join").expect("task result");
    }
    assert_eq!(
        peak_chirho.load(Ordering::SeqCst),
        1,
        "more sign-ins computed at once than the permit count"
    );
}

#[derive(Debug)]
struct TypedRefusalChirho;
impl std::fmt::Display for TypedRefusalChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "typed refusal")
    }
}
impl std::error::Error for TypedRefusalChirho {}

/// The refusal mapping downcasts the error type (the rate-limit refusal decides the page token, status and sentence),
/// so the error must cross the blocking pool unchanged, through the production entry point too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_typed_refusal_crosses_the_blocking_pool_intact_chirho() {
    let error_chirho =
        run_blocking_auth_chirho(|| -> anyhow::Result<()> { Err(TypedRefusalChirho.into()) })
            .await
            .expect_err("the task's refusal must come back as an error");
    assert!(
        error_chirho.downcast_ref::<TypedRefusalChirho>().is_some(),
        "the refusal lost its type: {error_chirho:#}"
    );
}

/// Every synchronous sign-in call in the auth handlers goes through a blocking helper: `run_blocking_auth_chirho`, or
/// for the public roads R12's `run_blocking_public_auth_chirho`, whose charge runs in the same task. Each call must
/// exist (the positive control: a renamed call would otherwise pass vacuously) and open the helper's work closure.
#[test]
fn auth_handlers_route_sign_in_work_through_the_blocking_helper_chirho() {
    let sources_chirho = [
        (
            "auth_wallet_chirho.rs",
            include_str!("../auth_wallet_chirho.rs"),
            "identity_chirho::login_identity_with_public_auth_limit_outcome_chirho(",
        ),
        (
            "auth_wallet_chirho.rs",
            include_str!("../auth_wallet_chirho.rs"),
            "oauth_chirho::issue_scoped_token_with_public_auth_limit_outcome_chirho(",
        ),
        (
            "auth_recover_chirho.rs",
            include_str!("../app_web_chirho/auth_recover_chirho.rs"),
            "identity_chirho::redeem_recovery_code_with_public_limit_outcome_chirho(",
        ),
        (
            "auth_credential_change_chirho.rs",
            include_str!("../app_web_chirho/auth_credential_change_chirho.rs"),
            "identity_chirho::change_identity_credential_for_session_chirho(",
        ),
        // K4 Part 3: the connection road's form choices and its issuance.
        (
            "auth_connection_new_chirho.rs",
            include_str!("../app_web_chirho/auth_connection_new_chirho.rs"),
            "oauth_chirho::connection_form_choices_chirho(",
        ),
        (
            "auth_connection_new_chirho.rs",
            include_str!("../app_web_chirho/auth_connection_new_chirho.rs"),
            "oauth_chirho::issue_connection_key_served_chirho(",
        ),
    ];
    for (file_chirho, source_chirho, call_chirho) in sources_chirho {
        let positions_chirho: Vec<usize> = source_chirho
            .match_indices(call_chirho)
            .map(|(i, _)| i)
            .collect();
        assert!(
            !positions_chirho.is_empty(),
            "{file_chirho}: {call_chirho} not found; the guard would be vacuous"
        );
        let unwrapped_chirho = unwrapped_sign_in_calls_chirho(source_chirho, call_chirho);
        assert!(
            unwrapped_chirho.is_empty(),
            "{file_chirho}: {call_chirho} at bytes {unwrapped_chirho:?} is not the first thing inside a blocking helper's work closure"
        );
    }
}

/// A TASK THAT DOES NOT COMPLETE IS TYPED, AND CLOSED PERMITS ARE NOT (PFE #26813): a task that panics comes back as the
/// typed not-completed error, with the text it always had, so every road but the connection road answers as before;
/// closed permits, where no work ran, come back as their own untyped error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_that_does_not_complete_is_typed_and_closed_permits_are_not_chirho() {
    let permits_chirho = Arc::new(Semaphore::new(1));
    let incomplete_chirho =
        run_blocking_auth_with_permits_chirho(&permits_chirho, || -> anyhow::Result<()> {
            panic!("a sign-in task that does not complete")
        })
        .await
        .unwrap_err();
    assert!(incomplete_chirho
        .downcast_ref::<SignInWorkIncompleteChirho>()
        .is_some());
    assert_eq!(
        incomplete_chirho.to_string(),
        "sign-in work did not complete"
    );
    let closed_chirho = Arc::new(Semaphore::new(1));
    closed_chirho.close();
    let refused_chirho = run_blocking_auth_with_permits_chirho(&closed_chirho, || Ok(()))
        .await
        .unwrap_err();
    assert!(refused_chirho
        .downcast_ref::<SignInWorkIncompleteChirho>()
        .is_none());
    assert_eq!(
        refused_chirho.to_string(),
        "sign-in work permits are closed"
    );
}

/// The helpers' work-closure openings, with whitespace collapsed to single spaces: the plain helper's, and R12's public
/// helper's, whose work closure follows the gate's meter.
const OPENINGS_CHIRHO: [&str; 2] = [
    "run_blocking_auth_chirho(move || {",
    "run_blocking_public_auth_chirho(meter_chirho, move || {",
];

/// The byte positions of `call_chirho` that are NOT immediately preceded (whitespace aside) by a helper's opening.
/// Anchoring on the closure boundary, not on a distance window, means a second, unwrapped call placed just after a
/// wrapped one is still caught (claude2 #25619: a window is a false-accept risk).
fn unwrapped_sign_in_calls_chirho(source_chirho: &str, call_chirho: &str) -> Vec<usize> {
    source_chirho
        .match_indices(call_chirho)
        .map(|(position_chirho, _)| position_chirho)
        .filter(|&position_chirho| {
            let before_chirho = source_chirho[..position_chirho]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            !OPENINGS_CHIRHO
                .iter()
                .any(|opening_chirho| before_chirho.ends_with(opening_chirho))
        })
        .collect()
}

/// The guard's own negative and positive fixtures: an unwrapped call right AFTER a wrapped one must be reported (the
/// false-accept direction a distance window missed), and a wrapped-only source must report nothing.
#[test]
fn the_routing_guard_rejects_an_unwrapped_call_beside_a_wrapped_one_chirho() {
    let call_chirho = "identity_chirho::login_identity_with_public_auth_limit_chirho(";
    let wrapped_chirho = "match run_blocking_auth_chirho(move || {\n        identity_chirho::login_identity_with_public_auth_limit_chirho(&r, &p, &c)\n    })\n    .await\n    {\n";
    let unwrapped_after_chirho = format!(
        "{wrapped_chirho}        Ok(x) => {{ let _ = identity_chirho::login_identity_with_public_auth_limit_chirho(&r, &p, &c); }}\n"
    );
    assert_eq!(
        unwrapped_sign_in_calls_chirho(wrapped_chirho, call_chirho),
        Vec::<usize>::new()
    );
    let public_wrapped_chirho = "match run_blocking_public_auth_chirho(meter_chirho, move || {\n        identity_chirho::login_identity_with_public_auth_limit_chirho(&r, &p, &c)\n    })\n";
    assert_eq!(
        unwrapped_sign_in_calls_chirho(public_wrapped_chirho, call_chirho),
        Vec::<usize>::new(),
        "R12's public helper opens a work closure too"
    );
    let reported_chirho = unwrapped_sign_in_calls_chirho(&unwrapped_after_chirho, call_chirho);
    assert_eq!(
        reported_chirho.len(),
        1,
        "the unwrapped call beside a wrapped one was not reported"
    );
    // Fixture control: the OLD guard (helper text anywhere in the 240 characters before the call) would have
    // accepted this unwrapped call, so the fixture really exercises the false-accept direction.
    let helper_start_chirho = wrapped_chirho
        .find("run_blocking_auth_chirho(move ||")
        .expect("fixture has the helper");
    assert!(
        reported_chirho[0].saturating_sub(240) <= helper_start_chirho,
        "fixture control: the unwrapped call must sit inside the old 240-character window"
    );
}

/// The serve path warms the sign-in attempt view before its listener accepts traffic, so no sign-in pays the first
/// load of the whole log (brick 2b, the bounded-auth-history charter's property 1).
#[test]
fn the_serve_path_warms_the_sign_in_view_before_it_listens_chirho() {
    let source_chirho = include_str!("../runtime_lifecycle_chirho/startup_chirho.rs");
    let warm_chirho = source_chirho
        .find("auth_blocking_chirho::warm_sign_in_view_chirho(root_chirho).await")
        .expect("the serve path must warm the sign-in view");
    let bind_chirho = source_chirho
        .find("tokio::net::TcpListener::bind(")
        .expect("control: the serve path binds a listener");
    assert!(
        warm_chirho < bind_chirho,
        "the warm-up must run before the listener accepts traffic"
    );
    assert_eq!(
        source_chirho.matches("TcpListener::bind(").count(),
        1,
        "a second listener would need its own warm-up"
    );
}

/// Poll until the semaphore has its one permit back, for at most five seconds.
async fn permit_returns_chirho(permits_chirho: &Semaphore) -> bool {
    for _ in 0..500 {
        if permits_chirho.available_permits() == 1 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// R11.1, HOLD AND RELEASE (PFE #26081): a waiter dropped while its work runs (a client that hangs up mid-request)
/// leaves the permit with the work until the work is done, so the permit cap bounds the work running, not the requests
/// still waiting.
///
/// MIGRATION PATH: a permit back the moment its waiter is dropped means the handler holds it again, and a client that
/// hangs up mid-request frees a slot while its Argon2id still computes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_waiter_leaves_the_permit_with_the_running_work_chirho() {
    let permits_chirho = Arc::new(Semaphore::new(1));
    let (started_tx_chirho, started_rx_chirho) = tokio::sync::oneshot::channel::<()>();
    let (release_tx_chirho, release_rx_chirho) = std::sync::mpsc::channel::<()>();
    let waiter_permits_chirho = Arc::clone(&permits_chirho);
    let waiter_chirho = tokio::spawn(async move {
        run_blocking_auth_with_permits_chirho(&waiter_permits_chirho, move || {
            let _ = started_tx_chirho.send(());
            let _ = release_rx_chirho.recv();
            Ok(())
        })
        .await
    });
    started_rx_chirho.await.expect("the work started");
    waiter_chirho.abort();
    assert!(
        waiter_chirho
            .await
            .expect_err("the waiter was dropped")
            .is_cancelled(),
        "control: the waiter was dropped, not finished"
    );
    assert_eq!(
        permits_chirho.available_permits(),
        0,
        "the running work keeps its permit after its waiter is dropped"
    );
    release_tx_chirho.send(()).expect("release the work");
    assert!(
        permit_returns_chirho(&permits_chirho).await,
        "the permit returns when the work is done"
    );
}

/// A gate whose failure budget holds ONE slot, and a source from a fixed public peer, checked by the handler's call.
fn one_slot_gate_chirho() -> (Arc<SignInGateChirho>, std::net::SocketAddr) {
    let gate_chirho = Arc::new(SignInGateChirho::new_chirho(
        &ServedRequestAbuseLimitsChirho {
            sign_in_source_failures_per_window_chirho: 1,
            ..ServedRequestAbuseLimitsChirho::default()
        },
    ));
    (gate_chirho, "198.51.100.9:443".parse().unwrap())
}

fn source_passes_chirho(gate_chirho: &SignInGateChirho, peer_chirho: std::net::SocketAddr) -> bool {
    gate_chirho
        .check_source_chirho(
            Some(peer_chirho),
            &HeaderMap::new(),
            cairn_chirho::identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
        )
        .is_ok()
}

/// R12, HOLD AND RELEASE: a public road is metered in its blocking task. Its slot is reserved BEFORE the work, so while
/// the work is held the source is already full; and the slot is settled AFTER the work even when the waiter was dropped
/// mid-work (a client that hangs up), so a refusal that recorded nothing frees it again.
///
/// MIGRATION PATH: a source still full after the release means the settling moved back after the await, where a client
/// that hangs up skips it; a source free while the work is held means the reservation moved after the work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_meter_reserves_before_the_work_and_settles_after_it_even_when_dropped_chirho() {
    let (gate_chirho, peer_chirho) = one_slot_gate_chirho();
    let source_chirho = gate_chirho
        .check_source_chirho(
            Some(peer_chirho),
            &HeaderMap::new(),
            cairn_chirho::identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
        )
        .expect("an empty source passes the handler's check");
    let meter_chirho = gate_chirho.meter_chirho(
        source_chirho,
        cairn_chirho::identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
        SignInChargesChirho::SuccessesAndFailuresChirho,
    );
    let permits_chirho = Arc::new(Semaphore::new(1));
    let (started_tx_chirho, started_rx_chirho) = tokio::sync::oneshot::channel::<()>();
    let (release_tx_chirho, release_rx_chirho) = std::sync::mpsc::channel::<()>();
    let waiter_permits_chirho = Arc::clone(&permits_chirho);
    let waiter_chirho = tokio::spawn(async move {
        run_blocking_public_auth_with_permits_chirho(
            &waiter_permits_chirho,
            meter_chirho,
            move || -> Result<(), PublicAuthRefusalChirho> {
                let _ = started_tx_chirho.send(());
                let _ = release_rx_chirho.recv();
                Err(PublicAuthRefusalChirho::not_recorded_chirho(
                    anyhow::anyhow!("a refusal that recorded nothing"),
                ))
            },
        )
        .await
    });
    started_rx_chirho.await.expect("the work started");
    assert!(
        !source_passes_chirho(&gate_chirho, peer_chirho),
        "the work's slot was reserved before the work ran"
    );
    waiter_chirho.abort();
    assert!(
        waiter_chirho
            .await
            .expect_err("the waiter was dropped")
            .is_cancelled(),
        "control: the waiter was dropped, not finished"
    );
    release_tx_chirho.send(()).expect("release the work");
    let mut freed_chirho = false;
    for _ in 0..500 {
        if source_passes_chirho(&gate_chirho, peer_chirho) {
            freed_chirho = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        freed_chirho,
        "the settling ran after the work and released the unearned slot, though nothing awaited it"
    );
}

/// R12: the admission inside the task is the authoritative check. An attempt that passed the handler's check before
/// another attempt from its source reserved the last slot (a burst queued behind the permit) is refused in its task,
/// runs no work, and records nothing.
///
/// MIGRATION PATH: the work running means the task trusts the handler's earlier check, and a queued burst overruns
/// the source's limit by its whole queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_attempt_is_refused_in_its_task_when_the_source_filled_meanwhile_chirho() {
    let (gate_chirho, peer_chirho) = one_slot_gate_chirho();
    let check_chirho = || {
        gate_chirho
            .check_source_chirho(
                Some(peer_chirho),
                &HeaderMap::new(),
                cairn_chirho::identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
            )
            .expect("an empty source passes the handler's check")
    };
    let first_chirho = gate_chirho.meter_chirho(
        check_chirho(),
        cairn_chirho::identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
        SignInChargesChirho::SuccessesAndFailuresChirho,
    );
    let queued_chirho = gate_chirho.meter_chirho(
        check_chirho(),
        cairn_chirho::identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
        SignInChargesChirho::SuccessesAndFailuresChirho,
    );
    let _held_chirho = first_chirho
        .admit_chirho()
        .expect("the first attempt takes the only slot");
    let ran_chirho = Arc::new(AtomicUsize::new(0));
    let ran_in_task_chirho = Arc::clone(&ran_chirho);
    let refusal_chirho = run_blocking_public_auth_with_permits_chirho(
        &Arc::new(Semaphore::new(1)),
        queued_chirho,
        move || -> Result<(), PublicAuthRefusalChirho> {
            ran_in_task_chirho.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .await
    .expect_err("the queued attempt is refused in its task");
    assert_eq!(ran_chirho.load(Ordering::SeqCst), 0, "no work ran");
    assert!(
        !refusal_chirho.failure_recorded_chirho,
        "nothing was recorded"
    );
    assert!(
        cairn_chirho::identity_chirho::is_auth_rate_limit_error_chirho(
            &refusal_chirho.error_chirho
        ),
        "the one rate refusal: {:#}",
        refusal_chirho.error_chirho
    );
}

/// R11.1, THE BURST (PFE #26081): twenty wrong-password sign-ins at ONE principal, each waiter dropped as soon as its
/// work starts (a client that hangs up), run at most five hashes at one permit. Each task holds its permit until its
/// work is done, so the principal's limiter, checked inside the task, sees every earlier failure: five failed rows,
/// and fifteen refused before any hash.
///
/// MIGRATION PATH: more than five failed rows means a dropped waiter freed its permit while its hash still ran, so
/// later tasks passed the limiter before the earlier failures were recorded (race (ii) riding race (i)).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_dropped_sign_ins_at_one_principal_runs_at_most_five_hashes_chirho() {
    use cairn_chirho::identity_chirho;
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-burst-chirho-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let principal_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "burst-arm-secret-value",
    )
    .unwrap()
    .principal_chirho;
    let permits_chirho = Arc::new(Semaphore::new(1));
    let velocity_chirho = identity_chirho::SignInVelocityChirho {
        principal_successes_per_hour_chirho: 10,
    };
    let (started_tx_chirho, mut started_rx_chirho) =
        tokio::sync::mpsc::unbounded_channel::<usize>();
    let (done_tx_chirho, mut done_rx_chirho) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut waiters_chirho = Vec::new();
    for index_chirho in 0..20 {
        let permits_chirho = Arc::clone(&permits_chirho);
        let root_chirho = root_chirho.clone();
        let principal_chirho = principal_chirho.clone();
        let started_tx_chirho = started_tx_chirho.clone();
        let done_tx_chirho = done_tx_chirho.clone();
        waiters_chirho.push(tokio::spawn(async move {
            run_blocking_auth_with_permits_chirho(&permits_chirho, move || {
                let _ = started_tx_chirho.send(index_chirho);
                let outcome_chirho = identity_chirho::login_identity_with_public_auth_limit_chirho(
                    &root_chirho,
                    &principal_chirho,
                    "burst-arm-wrong-value",
                    &velocity_chirho,
                );
                let _ = done_tx_chirho.send(());
                outcome_chirho
            })
            .await
        }));
    }
    drop((started_tx_chirho, done_tx_chirho));
    for _ in 0..20 {
        let index_chirho = tokio::time::timeout(Duration::from_secs(120), started_rx_chirho.recv())
            .await
            .expect("a sign-in's work never started")
            .expect("every sign-in's work starts");
        waiters_chirho[index_chirho].abort();
    }
    for _ in 0..20 {
        tokio::time::timeout(Duration::from_secs(120), done_rx_chirho.recv())
            .await
            .expect("a sign-in's work never finished")
            .expect("every sign-in's work finishes");
    }
    let failed_rows_chirho = identity_chirho::load_auth_attempts_chirho(&root_chirho)
        .unwrap()
        .iter()
        .filter(|row_chirho| {
            row_chirho.outcome_chirho
                == identity_chirho::IdentityAuthAttemptOutcomeChirho::FailureChirho
        })
        .count();
    assert_eq!(
        failed_rows_chirho, 5,
        "twenty dropped sign-ins at one principal ran {failed_rows_chirho} hashes; the limiter allows five"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
