// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The app-route road's growth arm: a warm private GET view and a warm private POST save, through the real app-route
//! handlers, load no control-plane log, read no reflog, and do no history-sized work on the blob and value roads.
//!
//! The road the agent API and the workspace share (`/app-chirho/:name/:route`, GET and POST). The fixture is shaped
//! like the product's roads, as PFE measured them (#25824, #25829): a viewer-state app built the way the product's
//! apps are, an app tree emitted by the tree builder with its guests swapped for WAT, as the beta host packet does.
//! Two routes, every edge private to the requesting user: a GET view (build a read request, read the viewer's state,
//! render) and a POST save (build a write request with expected_version, write, render). Two principals on scoped
//! bearers save N times each, at N = 1, 10 and 100 (agy #25834).
//!
//! Asserted on warm requests: no control-plane log load and no reflog read (so the app-route control-plane rows are
//! Covered); blob, value and run-intent roads that read no whole log and fold only the request's own delta (S1, S2,
//! S3); and no growth with the tenant's history at all past the viewer-state window. Recorded beside PFE's profile,
//! not asserted, because each is another brick's axis: viewer-state unseals (S4), and the private values, blobs, key
//! files and volatile effects a request adds (S5).

use super::app_route_fixture_chirho::*;
use super::*;

/// THE APP-ROUTE ROAD ARM. At N = 1, 10, 20 and 100 saves by each of two users, a warm private view and a warm private
/// save load no app control-plane log, read no reflog, and read no whole blob, value or run-intent log; every value
/// lookup copies out exactly one claim; the records each request folds are the same at every N; and the run-intent
/// road's counts (view reads, records folded, fresh re-verifies) are identical at every N.
///
/// Past the viewer-state window (16 versions; full at N = 20), NOTHING grows with the tenant's history: from N = 20 to
/// N = 100 (2 users x 80 saves = 160 added private runs) each request's blob lookups, key-file reads, value lookups
/// and claim copies are unchanged. Before S3 they grew by exactly one each per added run (160), because the run-intent
/// admission re-verified every private run on every request; the admission view (S3) folds each record once and
/// re-verifies only the admitted run (agy #25851, option (a)).
///
/// BOUNDED PER OPERATION (PFE #26561, growth boundary 3): what each warm view and each warm save leaves retained (runs,
/// effects, run intents and private values) is the same at every N, and every one of those counters sees each save's
/// records, so an equal count is never an empty one. The totals still grow with the tenant's history, one save's worth
/// per save, by the retention law ("effects are forever"); that growth, startup and rebuild, the integrity pass and GC
/// are explicitly outside this warm bound. Nothing here sets a storage SLA or pins an incidental count: the arm asserts
/// equality across N, never a number.
///
/// RECORDED, not asserted, each another brick's axis:
/// - the identity log's whole loads per request (census identity-auth row 1, wave 1 item 2): 0 per warm view and save
///   since brick 4a-2a's token view, where they were 5 and 6; the control arm pins the view's;
/// - what each request adds to the tenant's blobs, key files and volatile effects, beside PFE's measured profile
///   (#25829): S5's axis;
/// - the window's per-version work itself, which stops at 16 versions: S4's axis.
///
/// MIGRATION PATH: an app control-plane load or a reflog read means a warm app-route request re-verifies the control
/// plane again; a whole blob or value log read means a private lookup is back on a full-scan road; more than one copy
/// per value lookup means claims are copied out wholesale again; folds that grow with N mean a request folds the
/// history again. A nonzero N = 20 to N = 100 difference, a growing run-intent fold or a whole run-intent log read on a
/// warm request means the admission re-verifies the history again: S3 undone. Retained runs, effects, run intents or
/// private values that differ between N mean a request's accumulation now depends on the history.
#[test]
fn a_warm_private_view_and_save_do_no_history_sized_work_on_the_app_route_road_chirho() {
    let mut per_n_chirho = Vec::new();
    let mut footprints_chirho = Vec::new();
    for saves_chirho in [1_usize, 10, 20, 100] {
        let (view_road_chirho, save_road_chirho, view_footprint_chirho, save_footprint_chirho) =
            warm_requests_at_chirho(saves_chirho);
        for (road_chirho, request_chirho) in
            [(&view_road_chirho, "view"), (&save_road_chirho, "save")]
        {
            let context_chirho = format!("{request_chirho} after {saves_chirho} saves each");
            assert_warm_road_chirho(road_chirho, &context_chirho);
            assert_eq!(
                road_chirho.value_chirho.claims_copied_chirho,
                road_chirho.value_chirho.lookups_chirho,
                "{context_chirho}: each value lookup copies out exactly one claim: {road_chirho:?}"
            );
        }
        eprintln!(
            "app-route road at N={saves_chirho}: view loads the identity log {} times, save {} times (auth's axis); \
             view {view_road_chirho:?} adds {view_footprint_chirho:?}; save {save_road_chirho:?} adds \
             {save_footprint_chirho:?} (PFE's profile: a replayed view adds 1 value, 1 blob, 1 key file, 1 volatile \
             effect, 0 intents; a save about 5 values, 6 blobs, 11 key files, 3 intents)",
            view_road_chirho.identity_loads_chirho(),
            save_road_chirho.identity_loads_chirho()
        );
        per_n_chirho.push((saves_chirho, view_road_chirho, save_road_chirho));
        footprints_chirho.push((saves_chirho, view_footprint_chirho, save_footprint_chirho));
    }
    let (_, first_view_footprint_chirho, first_save_footprint_chirho) = footprints_chirho[0];
    for (saves_chirho, view_footprint_chirho, save_footprint_chirho) in &footprints_chirho {
        assert!(
            save_footprint_chirho
                .retained_chirho()
                .iter()
                .all(|count_chirho| *count_chirho >= 1),
            "at N={saves_chirho}, every retained counter sees the save's records: {save_footprint_chirho:?}"
        );
        assert_eq!(
            view_footprint_chirho.retained_chirho(),
            first_view_footprint_chirho.retained_chirho(),
            "the view retains the same runs, effects, run intents and private values at N={saves_chirho} as at N=1: \
             {view_footprint_chirho:?} against {first_view_footprint_chirho:?}"
        );
        assert_eq!(
            save_footprint_chirho.retained_chirho(),
            first_save_footprint_chirho.retained_chirho(),
            "the save retains the same runs, effects, run intents and private values at N={saves_chirho} as at N=1: \
             {save_footprint_chirho:?} against {first_save_footprint_chirho:?}"
        );
    }
    let folds_chirho = |road_chirho: &RoadCountsChirho| {
        (
            road_chirho.blob_chirho.records_folded_chirho,
            road_chirho.value_chirho.records_folded_chirho,
            road_chirho.run_intent_chirho,
        )
    };
    let (_, first_view_chirho, first_save_chirho) = per_n_chirho[0].clone();
    for (saves_chirho, view_road_chirho, save_road_chirho) in &per_n_chirho {
        assert_eq!(
            folds_chirho(view_road_chirho),
            folds_chirho(&first_view_chirho),
            "the view folds the same records, and does the same run-intent work, at N={saves_chirho} as at N=1"
        );
        assert_eq!(
            folds_chirho(save_road_chirho),
            folds_chirho(&first_save_chirho),
            "the save folds the same records, and does the same run-intent work, at N={saves_chirho} as at N=1"
        );
    }
    let window_work_chirho = |road_chirho: &RoadCountsChirho| {
        [
            road_chirho.blob_chirho.lookups_chirho,
            road_chirho.blob_chirho.key_file_reads_chirho,
            road_chirho.value_chirho.lookups_chirho,
            road_chirho.value_chirho.claims_copied_chirho,
        ]
    };
    let full_window_chirho: Vec<&(usize, RoadCountsChirho, RoadCountsChirho)> = per_n_chirho
        .iter()
        .filter(|(saves_chirho, _, _)| *saves_chirho >= 20)
        .collect();
    assert_eq!(
        full_window_chirho.len(),
        2,
        "two points past the 16-version window"
    );
    let (low_n_chirho, low_view_chirho, low_save_chirho) = full_window_chirho[0];
    let (high_n_chirho, high_view_chirho, high_save_chirho) = full_window_chirho[1];
    // Each save is one private-request run, and both users save, so the tenant gains two runs per unit of N.
    let added_runs_chirho = 2 * (high_n_chirho - low_n_chirho);
    for (request_chirho, low_chirho, high_chirho) in [
        ("view", low_view_chirho, high_view_chirho),
        ("save", low_save_chirho, high_save_chirho),
    ] {
        let growth_chirho: Vec<u64> = window_work_chirho(high_chirho)
            .iter()
            .zip(window_work_chirho(low_chirho))
            .map(|(high_chirho, low_chirho)| high_chirho - low_chirho)
            .collect();
        assert_eq!(
            growth_chirho,
            vec![0; 4],
            "{request_chirho}: from N={low_n_chirho} to N={high_n_chirho} ({added_runs_chirho} added private runs), no \
             blob lookup, key-file read, value lookup or claim copy grows with the history (it grew by one each per \
             added run before S3); N={low_n_chirho} {low_chirho:?}, N={high_n_chirho} {high_chirho:?}"
        );
    }
}

/// THE CONTROLS: every counter the arm asserts on is LIVE on this road, on this thread. Without them, a counter that
/// sees nothing (work moved to another thread, or a dead hook) would let the arm pass for nothing.
/// - A stylesheet release changes the control plane, so the next view re-verifies it: control-plane loads and reflog
///   reads are at least 1, and the view after it is warm again.
/// - A new inode under the value, blob and run-intent logs makes the next view rebuild all three views: one whole-log
///   read each.
/// - A token issued off the road is folded by the next view's token view, which loads the identity log (brick 4a-2a:
///   a warm bearer view loads it no more, which this control also pins).
#[test]
fn the_app_route_road_counters_see_this_road_chirho() {
    let tenant_chirho = growth_tenant_chirho("route-growth-control");
    let state_chirho = growth_state_chirho(&tenant_chirho.root_chirho);
    let runtime_chirho = counted_road_runtime_chirho();
    runtime_chirho.block_on(async {
        let user_chirho = &tenant_chirho.users_chirho[0];
        save_next_chirho(&state_chirho, user_chirho, None, "the control's save").await;
        let (status_chirho, page_chirho) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK, "the warming view is served: {page_chirho}");

        cairn_chirho::app_chirho::set_app_static_asset_bytes_chirho(
            &tenant_chirho.root_chirho,
            GROWTH_APP_CHIRHO,
            &tenant_chirho.owner_chirho,
            "style-chirho.css",
            "text/css",
            b".release-chirho { color: green; }",
        )
        .unwrap();
        reset_road_chirho();
        let (status_chirho, _) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK);
        let released_chirho = road_chirho();
        // The identity log loads on every authenticated request, so the control counts the APP control plane only;
        // otherwise identity loads alone would satisfy it with the app counting dead.
        assert!(
            released_chirho.app_control_loads_chirho() >= 1 && released_chirho.reflog_reads_chirho >= 1,
            "after a release, the next view must re-verify the app control plane: {released_chirho:?}"
        );
        reset_road_chirho();
        let (status_chirho, _) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK);
        let warm_chirho = road_chirho();
        assert_eq!(
            (warm_chirho.app_control_loads_chirho(), warm_chirho.reflog_reads_chirho),
            (0, 0),
            "and the view after that is warm again: {warm_chirho:?}"
        );
        // Brick 4a-2a: a warm bearer request reads the token view, so it no longer loads the identity log at all.
        assert_eq!(
            warm_chirho.identity_loads_chirho(),
            0,
            "a warm bearer view loads the identity log no more; one load here means the per-request token check is \
             back: {warm_chirho:?}"
        );
        // The identity log's counter is still LIVE on this road: a token issued off the road is folded by the next
        // request's token view, whose per-record check loads the identity log.
        let client_chirho = cairn_chirho::oauth_chirho::load_clients_chirho(&tenant_chirho.root_chirho)
            .unwrap()
            .remove(0);
        let controller_chirho = cairn_chirho::identity_chirho::register_identity_with_credential_chirho(
            &tenant_chirho.root_chirho,
            cairn_chirho::identity_chirho::PrincipalKindChirho::UserChirho,
            "route-growth-control-secret-chirho",
        )
        .unwrap();
        cairn_chirho::oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
            &tenant_chirho.root_chirho,
            &controller_chirho.principal_chirho,
            "route-growth-control-secret-chirho",
            &client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
            Some(cairn_chirho::oauth_chirho::ScopedTokenRateLimitChirho {
                window_ms_chirho: 60_000,
                max_invokes_chirho: 5,
                device_id_chirho: None,
            }),
        )
        .unwrap();
        reset_road_chirho();
        let (status_chirho, _) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK);
        let folded_chirho = road_chirho();
        assert!(
            folded_chirho.identity_loads_chirho() >= 1,
            "a new token's fold loads the identity log on this road, so the arm's record of it is live: \
             {folded_chirho:?}"
        );

        swap_inode_chirho(&tenant_chirho.root_chirho.join("private-dag-values-chirho.jsonl"));
        swap_inode_chirho(&tenant_chirho.root_chirho.join("privacy-blob-records-chirho.jsonl"));
        swap_inode_chirho(&tenant_chirho.root_chirho.join("run-intents-chirho.jsonl"));
        reset_road_chirho();
        let (status_chirho, _) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK);
        let rebuilt_chirho = road_chirho();
        assert!(
            rebuilt_chirho.value_chirho.full_log_loads_chirho >= 1
                && rebuilt_chirho.blob_chirho.full_log_loads_chirho >= 1
                && rebuilt_chirho.run_intent_chirho.full_log_loads_chirho >= 1,
            "a new inode under all three logs must make the next view rebuild all three views: {rebuilt_chirho:?}"
        );
    });
}
