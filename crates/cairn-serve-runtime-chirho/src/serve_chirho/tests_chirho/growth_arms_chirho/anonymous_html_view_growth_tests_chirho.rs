// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The anonymous public HTML view's growth arm: a warm view does no history-proportional work.
//!
//! This is the publishing product's main traffic path. perffection.com redirects to the app root,
//! and published sites live at `/app-chirho/<slug>/`, so the arm drives an anonymous GET through
//! the real app-root handler (PFE #25745, agy #25746). History grows at 1, 10 and 100 units on two
//! axes at once: asset releases (the asset log) and other apps deployed on the same root (the
//! reflog and the app-record log, as published sites accumulate on the platform root).
//!
//! A warm view must load NO control-plane log (apps, routes, policies, params, identities, assets)
//! and read NO reflog. The axes, and the brick that owns each:
//! - A2, assets (620fcfeb): the CSP reads the cached verified asset view.
//! - A1, the reflog (HERE): the app-record selection is cached the way route selection is. The app
//!   carries an explicit PUBLIC access record, so the access check, which selects the app record
//!   again, is on the measured road too.
//! - A3, the public descriptor (HERE): it reads the cached verified app records.
//! - private runs: the replay admission still verifies the whole run-intent log under the root
//!   append lock. The execution checkpoint brick adds that axis here.

use super::*;
use cairn_chirho::app_chirho::control_log_load_metrics_chirho as control_loads_chirho;
use cairn_core_chirho::refs_chirho::reflog_read_metrics_chirho as reflog_reads_chirho;

const VIEW_APP_CHIRHO: &str = "anonview";

/// The viewed HTML app, with an explicit PUBLIC access record and `history_chirho` units of history
/// on each axis: stylesheet releases, and other apps deployed on the same root.
fn html_app_with_history_chirho(
    label_chirho: &str,
    history_chirho: usize,
) -> (std::path::PathBuf, String) {
    let root_chirho = temp_root_chirho(label_chirho);
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let root_dag_chirho = deploy_transform_app_for_owner_chirho(
        &root_chirho,
        VIEW_APP_CHIRHO,
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(&root_chirho, VIEW_APP_CHIRHO, &owner_chirho);
    cairn_chirho::app_chirho::set_app_response_policy_chirho(
        &root_chirho,
        VIEW_APP_CHIRHO,
        &owner_chirho,
        "text/html",
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_request_access_policy_chirho(
        &root_chirho,
        VIEW_APP_CHIRHO,
        &owner_chirho,
        root_dag_chirho,
        cairn_chirho::app_chirho::AppRequestAccessPolicyChirho::PublicChirho,
    )
    .unwrap();
    for unit_chirho in 0..history_chirho {
        release_stylesheet_chirho(&root_chirho, &owner_chirho, unit_chirho);
        deploy_transform_app_for_owner_chirho(
            &root_chirho,
            &format!("other{unit_chirho}"),
            &owner_chirho,
            include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
            "upcase_chirho",
        );
    }
    (root_chirho, owner_chirho)
}

fn release_stylesheet_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    release_chirho: usize,
) {
    cairn_chirho::app_chirho::set_app_static_asset_bytes_chirho(
        root_chirho,
        VIEW_APP_CHIRHO,
        owner_chirho,
        "style-chirho.css",
        "text/css",
        format!(".release-{release_chirho}-chirho {{ color: green; }}").as_bytes(),
    )
    .unwrap();
}

/// One anonymous GET of the app root, the road a public page view takes: (status, CSP header).
async fn anonymous_view_chirho(state_chirho: &AppStateChirho) -> (StatusCode, String) {
    let response_chirho = app_get_chirho(
        State(state_chirho.clone()),
        None,
        HeaderMap::new(),
        format!("/app-chirho/{VIEW_APP_CHIRHO}/").parse().unwrap(),
        AxPath(VIEW_APP_CHIRHO.to_string()),
    )
    .await;
    let csp_chirho = response_chirho
        .headers()
        .get("content-security-policy")
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (response_chirho.status(), csp_chirho)
}

/// One anonymous GET of the public descriptor route.
async fn anonymous_descriptor_chirho(state_chirho: &AppStateChirho) -> StatusCode {
    app_descriptor_get_chirho(
        State(state_chirho.clone()),
        AxPath(VIEW_APP_CHIRHO.to_string()),
    )
    .await
    .status()
}

fn reset_counts_chirho() {
    control_loads_chirho::reset_chirho();
    reflog_reads_chirho::reset_chirho();
}

/// (control-plane log loads, reflog reads) on this thread since the last reset.
fn counts_chirho() -> (u64, u64) {
    (
        control_loads_chirho::count_chirho(),
        reflog_reads_chirho::count_chirho(),
    )
}

/// (control-plane log loads, reflog reads) across five warm views at `history_chirho` units.
fn warm_view_counts_chirho(history_chirho: usize) -> (u64, u64) {
    let (root_chirho, _owner_chirho) =
        html_app_with_history_chirho(&format!("anon-view-{history_chirho}"), history_chirho);
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let counts_now_chirho = runtime_chirho.block_on(async {
        let (status_chirho, csp_chirho) = anonymous_view_chirho(&state_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK, "the warming view is served");
        assert!(
            csp_chirho.contains("style-src 'self'") && !csp_chirho.contains("'unsafe-inline'"),
            "the CSP still comes from the verified asset records: {csp_chirho}"
        );
        reset_counts_chirho();
        for _ in 0..5 {
            let (status_chirho, _) = anonymous_view_chirho(&state_chirho).await;
            assert_eq!(status_chirho, StatusCode::OK);
        }
        counts_chirho()
    });
    let _ = std::fs::remove_dir_all(root_chirho);
    counts_now_chirho
}

#[test]
fn a_warm_anonymous_view_loads_no_control_log_and_reads_no_reflog_at_any_history_chirho() {
    for history_chirho in [1, 10, 100] {
        assert_eq!(
            warm_view_counts_chirho(history_chirho),
            (0, 0),
            "{history_chirho} units of history: (control-plane log loads, reflog reads) per 5 warm views"
        );
    }
}

/// The control: both counters are LIVE on this road. A release changes the control plane, so the
/// next view must re-verify (loading logs, and reading the reflog to re-select the app record), and
/// the view after that is warm again. Without this, dead counters would let the arms pass for nothing.
#[test]
fn a_release_makes_the_next_view_reverify_once_then_warm_again_chirho() {
    let (root_chirho, owner_chirho) = html_app_with_history_chirho("anon-view-control", 1);
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let (status_chirho, _) = anonymous_view_chirho(&state_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK);
        release_stylesheet_chirho(&root_chirho, &owner_chirho, 1);
        reset_counts_chirho();
        let (status_chirho, _) = anonymous_view_chirho(&state_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK);
        let (loads_chirho, reflog_chirho) = counts_chirho();
        assert!(
            loads_chirho >= 1 && reflog_chirho >= 1,
            "after a release, the next view must re-verify: loads {loads_chirho}, reflog reads {reflog_chirho}"
        );
        let (status_chirho, _) = anonymous_view_chirho(&state_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK);
        assert_eq!(
            counts_chirho(),
            (loads_chirho, reflog_chirho),
            "and the view after that is warm again"
        );
    });
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// A3: the public descriptor route, anonymous, warm, at every history size.
#[test]
fn a_warm_public_descriptor_loads_no_control_log_and_reads_no_reflog_chirho() {
    for history_chirho in [1, 10, 100] {
        let (root_chirho, _owner_chirho) = html_app_with_history_chirho(
            &format!("anon-descriptor-{history_chirho}"),
            history_chirho,
        );
        let state_chirho = app_state_for_root_chirho(&root_chirho);
        let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
        let counts_now_chirho = runtime_chirho.block_on(async {
            assert_eq!(
                anonymous_descriptor_chirho(&state_chirho).await,
                StatusCode::OK
            );
            reset_counts_chirho();
            for _ in 0..5 {
                assert_eq!(
                    anonymous_descriptor_chirho(&state_chirho).await,
                    StatusCode::OK
                );
            }
            counts_chirho()
        });
        let _ = std::fs::remove_dir_all(root_chirho);
        assert_eq!(
            counts_now_chirho,
            (0, 0),
            "{history_chirho} units of history: (control-plane log loads, reflog reads) per 5 warm descriptor GETs"
        );
    }
}
