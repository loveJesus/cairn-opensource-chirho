// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Count-based scaling guards proving a warm served-route request re-verifies nothing regardless of deploy history.

use super::super::verified_view_cache_chirho::test_metrics_chirho as metrics_chirho;
use super::*;

fn register_owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho
}

/// Deploy one app + route + Plain input policy; returns (owner, active route DAG).
fn setup_hot_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
) -> (String, HashChirho) {
    let owner_chirho = register_owner_chirho(root_chirho);
    let app_dag_chirho = fake_dag_chirho(root_chirho, format!("{app_chirho}-dag").as_bytes());
    let route_dag_chirho = fake_dag_chirho(
        root_chirho,
        format!("{app_chirho}-{route_chirho}").as_bytes(),
    );
    deploy_app_chirho(root_chirho, app_chirho, app_dag_chirho, &owner_chirho).unwrap();
    deploy_app_route_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        route_dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        root_chirho,
        app_chirho,
        Some(route_chirho),
        &owner_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    (owner_chirho, route_dag_chirho)
}

/// The leaf loaders one authenticated GET /app-chirho/<app>/<route> drives, including the serve
/// path's threefold route re-resolution — every call routes through the verified-view cache.
fn drive_route_request_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_chirho: &str,
    route_dag_chirho: &HashChirho,
) {
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho).unwrap();
    for _ in 0..3 {
        verified_selected_app_route_record_chirho(
            root_chirho,
            &refs_chirho,
            app_chirho,
            route_chirho,
            owner_chirho,
        )
        .unwrap();
    }
    app_input_mode_chirho(root_chirho, app_chirho, Some(route_chirho), owner_chirho).unwrap();
    app_route_response_content_type_chirho(root_chirho, app_chirho, route_chirho, owner_chirho)
        .unwrap();
    app_params_chirho(root_chirho, app_chirho, Some(route_chirho), owner_chirho).unwrap();
    verified_app_route_request_body_policy_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        owner_chirho,
        route_dag_chirho,
    )
    .unwrap();
}

#[test]
fn warm_route_request_reverifies_nothing_chirho() {
    let root_chirho = tmp_root_chirho();
    let (owner_chirho, route_dag_chirho) = setup_hot_app_chirho(&root_chirho, "hot", "lite");

    // First request after the deploy writes is cold: it must do real load + verify work.
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let cold_chirho = metrics_chirho::snapshot_chirho();
    assert!(
        cold_chirho.misses_chirho > 0,
        "cold request must populate the cache"
    );
    assert!(
        cold_chirho.ed25519_verifies_chirho > 0,
        "cold request must actually verify signatures"
    );
    assert!(
        cold_chirho.full_log_loads_chirho > 0,
        "cold request must read logs"
    );

    // Second, warm request over unchanged logs: zero re-verification, zero re-reads, zero misses.
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let warm_chirho = metrics_chirho::snapshot_chirho();
    assert_eq!(
        warm_chirho.misses_chirho, 0,
        "warm request must not rebuild any cache entry"
    );
    assert_eq!(
        warm_chirho.full_log_loads_chirho, 0,
        "warm request must not re-read any log"
    );
    assert_eq!(
        warm_chirho.ed25519_verifies_chirho, 0,
        "warm request must not re-verify"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn warm_counts_after_extra_app_deploys_chirho(
    n_extra_chirho: usize,
) -> (
    metrics_chirho::MetricsSnapshotChirho,
    metrics_chirho::MetricsSnapshotChirho,
    u64,
) {
    let root_chirho = tmp_root_chirho();
    let (owner_chirho, route_dag_chirho) = setup_hot_app_chirho(&root_chirho, "hot", "lite");

    // Warm the baseline, then measure a warm request.
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let baseline_warm_chirho = metrics_chirho::snapshot_chirho();

    // Append N unrelated app deploy records — the log the served path re-verifies ~13x and the axis
    // the O(R*M) owner amplifier multiplied by. (Route-log growth is covered separately.)
    for i_chirho in 0..n_extra_chirho {
        let app_chirho = format!("extra-{i_chirho}");
        let app_dag_chirho =
            fake_dag_chirho(&root_chirho, format!("extra-dag-{i_chirho}").as_bytes());
        deploy_app_chirho(&root_chirho, &app_chirho, app_dag_chirho, &owner_chirho).unwrap();
    }

    // The first request after those writes is cold again; capture its verify count to prove cold
    // work scales with history, then warm the cache.
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let cold_after_extra_chirho = metrics_chirho::snapshot_chirho().ed25519_verifies_chirho;

    // Measure a warm request again: it must be identical to the baseline warm request.
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let after_warm_chirho = metrics_chirho::snapshot_chirho();

    let _ = std::fs::remove_dir_all(&root_chirho);
    (
        baseline_warm_chirho,
        after_warm_chirho,
        cold_after_extra_chirho,
    )
}

#[test]
fn warm_counts_are_independent_of_deploy_history_chirho() {
    for n_extra_chirho in [50usize, 500usize] {
        let (baseline_chirho, after_chirho, cold_after_extra_chirho) =
            warm_counts_after_extra_app_deploys_chirho(n_extra_chirho);
        assert_eq!(baseline_chirho.misses_chirho, 0);
        assert_eq!(baseline_chirho.full_log_loads_chirho, 0);
        assert_eq!(baseline_chirho.ed25519_verifies_chirho, 0);
        // The invariant: warm per-request counts do not change after +N unrelated deploys.
        assert_eq!(
            after_chirho.misses_chirho, baseline_chirho.misses_chirho,
            "warm misses grew with {n_extra_chirho} extra deploys"
        );
        assert_eq!(
            after_chirho.full_log_loads_chirho, baseline_chirho.full_log_loads_chirho,
            "warm log reads grew with {n_extra_chirho} extra deploys"
        );
        assert_eq!(
            after_chirho.ed25519_verifies_chirho, baseline_chirho.ed25519_verifies_chirho,
            "warm verifies grew with {n_extra_chirho} extra deploys"
        );
        // Sanity: without the cache a cold request's verify work does scale with history, so the
        // cache is genuinely load-bearing (it is not that nothing verifies at all).
        assert!(
            cold_after_extra_chirho >= n_extra_chirho as u64,
            "cold verify count {cold_after_extra_chirho} should grow with {n_extra_chirho} deploys"
        );
    }
}

#[test]
fn warm_counts_stable_across_route_log_growth_chirho() {
    let root_chirho = tmp_root_chirho();
    let (owner_chirho, _route_dag_chirho) = setup_hot_app_chirho(&root_chirho, "hot", "lite");

    // Grow the route log by redeploying the hot route with fresh DAGs; the active route is the last.
    let mut active_dag_chirho = _route_dag_chirho;
    for i_chirho in 0..40usize {
        active_dag_chirho =
            fake_dag_chirho(&root_chirho, format!("hot-lite-v{i_chirho}").as_bytes());
        deploy_app_route_chirho(
            &root_chirho,
            "hot",
            "lite",
            active_dag_chirho.clone(),
            &owner_chirho,
        )
        .unwrap();
    }

    // Warm, then a warm request re-verifies nothing despite the now-long route log.
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &active_dag_chirho,
    );
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &active_dag_chirho,
    );
    let warm_chirho = metrics_chirho::snapshot_chirho();
    assert_eq!(warm_chirho.misses_chirho, 0);
    assert_eq!(warm_chirho.full_log_loads_chirho, 0);
    assert_eq!(warm_chirho.ed25519_verifies_chirho, 0);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn appending_one_deploy_reverifies_and_serves_new_state_chirho() {
    let root_chirho = tmp_root_chirho();
    let (owner_chirho, route_dag_chirho) = setup_hot_app_chirho(&root_chirho, "hot", "lite");

    // Warm the cache and confirm it serves the original active route DAG.
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let warm_record_chirho = verified_selected_app_route_record_chirho(
        &root_chirho,
        &refs_chirho,
        "hot",
        "lite",
        &owner_chirho,
    )
    .unwrap();
    assert_eq!(
        warm_record_chirho.dag_chirho.as_ref(),
        Some(&route_dag_chirho)
    );

    // Redeploy the same route with a NEW DAG: one more append to the route log.
    let new_route_dag_chirho = fake_dag_chirho(&root_chirho, b"hot-lite-v2");
    deploy_app_route_chirho(
        &root_chirho,
        "hot",
        "lite",
        new_route_dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();

    // The next request must re-verify (fingerprint changed) and serve the NEW state.
    metrics_chirho::reset_chirho();
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let updated_record_chirho = verified_selected_app_route_record_chirho(
        &root_chirho,
        &refs_chirho,
        "hot",
        "lite",
        &owner_chirho,
    )
    .unwrap();
    let after_change_chirho = metrics_chirho::snapshot_chirho();
    assert!(
        after_change_chirho.misses_chirho > 0,
        "an appended deploy must invalidate the cache"
    );
    assert_eq!(
        updated_record_chirho.dag_chirho.as_ref(),
        Some(&new_route_dag_chirho),
        "the re-verified request must serve the newly deployed DAG"
    );
    assert_ne!(
        updated_record_chirho.dag_chirho.as_ref(),
        Some(&route_dag_chirho)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn two_roots_do_not_bleed_chirho() {
    let root_a_chirho = tmp_root_chirho();
    let root_b_chirho = tmp_root_chirho();
    let (owner_a_chirho, route_dag_a_chirho) = setup_hot_app_chirho(&root_a_chirho, "hot", "lite");
    let (owner_b_chirho, route_dag_b_chirho) = setup_hot_app_chirho(&root_b_chirho, "cold", "dark");

    // Warm both roots.
    drive_route_request_chirho(
        &root_a_chirho,
        "hot",
        "lite",
        &owner_a_chirho,
        &route_dag_a_chirho,
    );
    drive_route_request_chirho(
        &root_b_chirho,
        "cold",
        "dark",
        &owner_b_chirho,
        &route_dag_b_chirho,
    );

    // Mutating root A must not disturb root B's warm cache.
    let extra_dag_chirho = fake_dag_chirho(&root_a_chirho, b"a-extra");
    deploy_app_chirho(&root_a_chirho, "extra", extra_dag_chirho, &owner_a_chirho).unwrap();

    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_b_chirho,
        "cold",
        "dark",
        &owner_b_chirho,
        &route_dag_b_chirho,
    );
    let warm_b_chirho = metrics_chirho::snapshot_chirho();
    assert_eq!(
        warm_b_chirho.misses_chirho, 0,
        "root A's change must not evict root B"
    );
    assert_eq!(warm_b_chirho.ed25519_verifies_chirho, 0);
    assert_eq!(warm_b_chirho.full_log_loads_chirho, 0);

    // No cross-root record bleed: each root resolves its own app.
    let refs_b_chirho = refs_chirho::load_refs_chirho(&root_b_chirho).unwrap();
    let record_b_chirho = verified_selected_app_route_record_chirho(
        &root_b_chirho,
        &refs_b_chirho,
        "cold",
        "dark",
        &owner_b_chirho,
    )
    .unwrap();
    assert_eq!(record_b_chirho.app_chirho, "cold");
    assert_eq!(
        record_b_chirho.dag_chirho.as_ref(),
        Some(&route_dag_b_chirho)
    );
    assert!(
        verified_selected_app_route_record_chirho(
            &root_b_chirho,
            &refs_b_chirho,
            "hot",
            "lite",
            &owner_b_chirho
        )
        .is_err(),
        "root B must not resolve root A's app"
    );

    let _ = std::fs::remove_dir_all(&root_a_chirho);
    let _ = std::fs::remove_dir_all(&root_b_chirho);
}

#[test]
fn warm_owner_gate_never_rereads_identity_log_chirho() {
    let root_chirho = tmp_root_chirho();
    let (owner_chirho, route_dag_chirho) = setup_hot_app_chirho(&root_chirho, "hot", "lite");

    // Direct proof the leaf counter is wired to the identity log: one raw load counts exactly once,
    // so the served path's warm "zero full reads" guard is no longer blind to the owner gate.
    metrics_chirho::reset_chirho();
    identity_chirho::load_identities_chirho(&root_chirho).unwrap();
    assert_eq!(
        metrics_chirho::snapshot_chirho().full_log_loads_chirho,
        1,
        "load_identities_chirho must count as a full-log load so the guard covers it"
    );

    // Warm the served path, then a warm owner-principal gate must re-read no log — identity included.
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    metrics_chirho::reset_chirho();
    ensure_owner_principal_chirho(&root_chirho, &owner_chirho).unwrap();
    app_input_mode_chirho(&root_chirho, "hot", Some("lite"), &owner_chirho).unwrap();
    let warm_chirho = metrics_chirho::snapshot_chirho();
    assert_eq!(
        warm_chirho.full_log_loads_chirho, 0,
        "the warm owner gate must not re-read the identity log"
    );
    assert_eq!(warm_chirho.misses_chirho, 0);
    assert_eq!(warm_chirho.ed25519_verifies_chirho, 0);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn warm_counts_after_extra_principal_registrations_chirho(
    n_extra_chirho: usize,
) -> (
    metrics_chirho::MetricsSnapshotChirho,
    metrics_chirho::MetricsSnapshotChirho,
    u64,
) {
    let root_chirho = tmp_root_chirho();
    let (owner_chirho, route_dag_chirho) = setup_hot_app_chirho(&root_chirho, "hot", "lite");

    // Warm the baseline, then measure a warm request.
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let baseline_warm_chirho = metrics_chirho::snapshot_chirho();

    // Grow the identity log by N unrelated principals — the axis the served owner-principal gate used
    // to re-read (a full parse of every registered principal) on every warm request.
    for _ in 0..n_extra_chirho {
        register_owner_chirho(&root_chirho);
    }

    // The identity append changed the fingerprint, so the next request is cold again and DOES read
    // the now-larger identity log; capture its full-log loads to prove the cache is load-bearing.
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let cold_after_extra_chirho = metrics_chirho::snapshot_chirho().full_log_loads_chirho;

    // Measure a warm request again: it must be identical to the baseline warm request.
    metrics_chirho::reset_chirho();
    drive_route_request_chirho(
        &root_chirho,
        "hot",
        "lite",
        &owner_chirho,
        &route_dag_chirho,
    );
    let after_warm_chirho = metrics_chirho::snapshot_chirho();

    let _ = std::fs::remove_dir_all(&root_chirho);
    (
        baseline_warm_chirho,
        after_warm_chirho,
        cold_after_extra_chirho,
    )
}

#[test]
fn warm_counts_independent_of_registered_principal_growth_chirho() {
    for n_extra_chirho in [50usize, 500usize] {
        let (baseline_chirho, after_chirho, cold_after_extra_chirho) =
            warm_counts_after_extra_principal_registrations_chirho(n_extra_chirho);
        assert_eq!(baseline_chirho.misses_chirho, 0);
        assert_eq!(baseline_chirho.full_log_loads_chirho, 0);
        assert_eq!(baseline_chirho.ed25519_verifies_chirho, 0);
        // The invariant: warm per-request counts do not change after +N registered principals, and
        // the identity leaf is now inside `full_log_loads_chirho`, so an owner-gate re-read would trip
        // this assertion.
        assert_eq!(
            after_chirho.full_log_loads_chirho, baseline_chirho.full_log_loads_chirho,
            "warm log reads grew with {n_extra_chirho} extra principals"
        );
        assert_eq!(
            after_chirho.misses_chirho, baseline_chirho.misses_chirho,
            "warm misses grew with {n_extra_chirho} extra principals"
        );
        assert_eq!(
            after_chirho.ed25519_verifies_chirho, baseline_chirho.ed25519_verifies_chirho,
            "warm verifies grew with {n_extra_chirho} extra principals"
        );
        // Sanity: a cold request genuinely reads logs (identity leaf included), so warm-zero is a real
        // skip, not a case where nothing reads at all.
        assert!(
            cold_after_extra_chirho > 0,
            "cold request after +{n_extra_chirho} principals must read logs"
        );
    }
}
