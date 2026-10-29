// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Re-promotion over a LIVE reviewed app, through the owner's review-promote route (PFE #25681, CAIRN #25683):
//! a changed asset under an unchanged name must install, and a failed install must leave the prior version live.

use super::super::*;

const ASSET_NAME_CHIRHO: &str = "reviewed-source-chirho.css";
const ASSET_V1_CHIRHO: &[u8] = b".reviewed-source-chirho{color:#123456}\n";
const ASSET_V2_CHIRHO: &[u8] = b".reviewed-source-chirho{color:#654321}\n";

/// Disarms the thread-local install fault on drop, so a failed assertion cannot leave it armed.
struct InstallFaultGuardChirho;

impl InstallFaultGuardChirho {
    fn arm_chirho(fail_after_chirho: usize) -> Self {
        app_source_manifest_chirho::set_reviewed_asset_install_fail_after_for_test_chirho(Some(
            fail_after_chirho,
        ));
        InstallFaultGuardChirho
    }
}

impl Drop for InstallFaultGuardChirho {
    fn drop(&mut self) {
        app_source_manifest_chirho::set_reviewed_asset_install_fail_after_for_test_chirho(None);
    }
}

struct RepromoteFixtureChirho {
    root_chirho: std::path::PathBuf,
    owner_chirho: String,
    kind_chirho: String,
    id_chirho: String,
    headers_chirho: HeaderMap,
    app_chirho: &'static str,
    route_chirho: &'static str,
    subject_chirho: String,
}

impl RepromoteFixtureChirho {
    fn new_chirho(label_chirho: &str, app_chirho: &'static str) -> Self {
        let root_chirho = temp_root_chirho(label_chirho);
        let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            "owner-repromote-secret",
        )
        .unwrap();
        let (kind_chirho, id_chirho) =
            split_owner_principal_for_path_chirho(&owner_chirho.principal_chirho);
        let headers_chirho = owner_bearer_headers_chirho(
            &root_chirho,
            &owner_chirho.principal_chirho,
            "owner-repromote-secret",
        );
        RepromoteFixtureChirho {
            subject_chirho: format!("app/{app_chirho}/input"),
            root_chirho,
            owner_chirho: owner_chirho.principal_chirho,
            kind_chirho,
            id_chirho,
            headers_chirho,
            app_chirho,
            route_chirho: "preview-chirho",
        }
    }

    /// A stored review of the app with `asset_bytes` under ASSET_NAME, taken against whatever is live NOW.
    fn review_chirho(
        &self,
        asset_bytes_chirho: &[u8],
    ) -> (
        HashChirho,
        HashChirho,
        app_source_manifest_chirho::AppSourceReviewReportChirho,
    ) {
        build_private_review_report_for_owner_with_asset_chirho(
            &self.root_chirho,
            self.app_chirho,
            self.route_chirho,
            &self.owner_chirho,
            &self.subject_chirho,
            asset_bytes_chirho,
        )
    }

    /// The owner's review-promote route, the entry point a real caller uses. Returns (status, body).
    fn promote_chirho(
        &self,
        candidate_chirho: &HashChirho,
        report_chirho: &HashChirho,
    ) -> (StatusCode, String) {
        let state_chirho = app_state_for_root_chirho(&self.root_chirho);
        let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
        runtime_chirho.block_on(async {
            let response_chirho = app_review_promote_post_chirho(
                State(state_chirho),
                self.headers_chirho.clone(),
                AxPath((
                    self.kind_chirho.clone(),
                    self.id_chirho.clone(),
                    self.app_chirho.to_string(),
                )),
                Form(AppReviewPromoteRequestChirho {
                    candidate_chirho: candidate_chirho.0.clone(),
                    source_review_report_chirho: report_chirho.0.clone(),
                    accept_capability_escalation_chirho: false,
                    accept_cost_increase_chirho: false,
                }),
            )
            .await;
            let status_chirho = response_chirho.status();
            let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status_chirho,
                String::from_utf8(body_chirho.to_vec()).unwrap(),
            )
        })
    }

    fn served_asset_bytes_chirho(&self) -> Option<Vec<u8>> {
        self.served_named_asset_bytes_chirho(ASSET_NAME_CHIRHO)
    }

    fn served_named_asset_bytes_chirho(&self, name_chirho: &str) -> Option<Vec<u8>> {
        app_chirho::app_static_asset_by_name_chirho(&self.root_chirho, self.app_chirho, name_chirho)
            .unwrap()
            .map(|selection_chirho| {
                app_chirho::app_static_asset_bytes_chirho(&self.root_chirho, &selection_chirho)
                    .unwrap()
            })
    }

    fn review_variant_chirho(
        &self,
        variant_chirho: &ReviewFixtureVariantChirho,
    ) -> (
        HashChirho,
        HashChirho,
        app_source_manifest_chirho::AppSourceReviewReportChirho,
    ) {
        build_private_review_report_variant_chirho(
            &self.root_chirho,
            self.app_chirho,
            self.route_chirho,
            &self.owner_chirho,
            &self.subject_chirho,
            variant_chirho,
        )
    }

    /// The prior version is live: its root, its route, and its reviewed surface is current.
    fn assert_live_version_chirho(
        &self,
        candidate_chirho: &HashChirho,
        review_chirho: &app_source_manifest_chirho::AppSourceReviewReportChirho,
    ) {
        let status_chirho =
            app_chirho::app_status_chirho(&self.root_chirho, self.app_chirho).unwrap();
        assert!(status_chirho.active_chirho, "the app must stay live");
        assert_eq!(status_chirho.dag_chirho.as_ref(), Some(candidate_chirho));
        assert_eq!(
            status_chirho.routes_chirho.get(self.route_chirho),
            Some(candidate_chirho)
        );
        assert!(
            app_source_manifest_chirho::reviewed_app_source_install_report_current_chirho(
                &self.root_chirho,
                review_chirho,
            )
            .unwrap()
            .is_some(),
            "the prior version's reviewed surface must be current"
        );
    }
}

fn two_asset_variant_chirho(a_chirho: &[u8], b_chirho: &[u8]) -> ReviewFixtureVariantChirho {
    ReviewFixtureVariantChirho {
        assets_chirho: vec![
            ("a-chirho.css", a_chirho.to_vec()),
            ("b-chirho.css", b_chirho.to_vec()),
        ],
        ..ReviewFixtureVariantChirho::one_asset_chirho(b"")
    }
}

impl Drop for RepromoteFixtureChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_chirho);
    }
}

#[test]
fn a_repromotion_that_changes_an_asset_under_the_same_name_installs_the_new_bytes_chirho() {
    let fixture_chirho = RepromoteFixtureChirho::new_chirho(
        "review-repromote-same-name-asset",
        "review-repromote-asset-app-chirho",
    );
    let (report_v1_chirho, candidate_chirho, _) = fixture_chirho.review_chirho(ASSET_V1_CHIRHO);
    let (status_chirho, body_chirho) =
        fixture_chirho.promote_chirho(&candidate_chirho, &report_v1_chirho);
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    assert_eq!(
        fixture_chirho.served_asset_bytes_chirho().as_deref(),
        Some(ASSET_V1_CHIRHO)
    );

    // Taken against the LIVE v1, as a re-promotion's review must be.
    let (report_v2_chirho, candidate_v2_chirho, v2_chirho) =
        fixture_chirho.review_chirho(ASSET_V2_CHIRHO);
    // Preconditions, proven before measuring: the root is unchanged, and only the asset's bytes differ.
    assert_eq!(candidate_v2_chirho, candidate_chirho);
    assert_eq!(v2_chirho.candidate_chirho.assets_chirho.len(), 1);
    assert_eq!(
        v2_chirho.candidate_chirho.assets_chirho[0].name_chirho,
        ASSET_NAME_CHIRHO
    );
    assert_ne!(report_v2_chirho, report_v1_chirho);

    let (status_chirho, body_chirho) =
        fixture_chirho.promote_chirho(&candidate_chirho, &report_v2_chirho);
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    let status_after_chirho =
        app_chirho::app_status_chirho(&fixture_chirho.root_chirho, fixture_chirho.app_chirho)
            .unwrap();
    assert!(status_after_chirho.active_chirho);
    assert_eq!(
        status_after_chirho.dag_chirho,
        Some(candidate_chirho.clone())
    );
    assert_eq!(
        status_after_chirho
            .routes_chirho
            .get(fixture_chirho.route_chirho),
        Some(&candidate_chirho)
    );
    assert_eq!(
        fixture_chirho.served_asset_bytes_chirho().as_deref(),
        Some(ASSET_V2_CHIRHO)
    );
    assert!(
        app_source_manifest_chirho::reviewed_app_source_install_report_current_chirho(
            &fixture_chirho.root_chirho,
            &v2_chirho,
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn a_failed_repromotion_install_leaves_the_prior_version_live_chirho() {
    let fixture_chirho = RepromoteFixtureChirho::new_chirho(
        "review-repromote-failed-install",
        "review-repromote-fail-app-chirho",
    );
    let (report_v1_chirho, candidate_chirho, v1_chirho) =
        fixture_chirho.review_chirho(ASSET_V1_CHIRHO);
    let (status_chirho, body_chirho) =
        fixture_chirho.promote_chirho(&candidate_chirho, &report_v1_chirho);
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");

    let (report_v2_chirho, _, _) = fixture_chirho.review_chirho(ASSET_V2_CHIRHO);
    let (status_chirho, _) = {
        let _armed_chirho = InstallFaultGuardChirho::arm_chirho(0);
        fixture_chirho.promote_chirho(&candidate_chirho, &report_v2_chirho)
    };
    assert_ne!(
        status_chirho,
        StatusCode::OK,
        "the injected install fault must fail the promote"
    );

    // The prior version is LIVE: its root, its route and its asset bytes, and its reviewed surface is current.
    let status_after_chirho =
        app_chirho::app_status_chirho(&fixture_chirho.root_chirho, fixture_chirho.app_chirho)
            .unwrap();
    assert!(
        status_after_chirho.active_chirho,
        "a failed re-promotion must not darken the app"
    );
    assert_eq!(
        status_after_chirho.dag_chirho,
        Some(candidate_chirho.clone())
    );
    assert_eq!(
        status_after_chirho
            .routes_chirho
            .get(fixture_chirho.route_chirho),
        Some(&candidate_chirho)
    );
    assert_eq!(
        fixture_chirho.served_asset_bytes_chirho().as_deref(),
        Some(ASSET_V1_CHIRHO)
    );
    assert!(
        app_source_manifest_chirho::reviewed_app_source_install_report_current_chirho(
            &fixture_chirho.root_chirho,
            &v1_chirho,
        )
        .unwrap()
        .is_some()
    );
}

/// Only the INSTALL's own restore can undo this: the install is called directly, so no promotion wraps it, and its
/// fault fires after it has already replaced the first of two assets.
#[test]
fn a_failed_install_over_a_live_version_puts_back_an_asset_it_had_already_changed_chirho() {
    let fixture_chirho = RepromoteFixtureChirho::new_chirho(
        "review-repromote-partial-assets",
        "review-repromote-partial-app-chirho",
    );
    let (report_v1_chirho, candidate_chirho, v1_chirho) = fixture_chirho.review_variant_chirho(
        &two_asset_variant_chirho(b".a{color:#111}\n", b".b{color:#111}\n"),
    );
    let (status_chirho, body_chirho) =
        fixture_chirho.promote_chirho(&candidate_chirho, &report_v1_chirho);
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    let (_, candidate_v2_chirho, v2_chirho) = fixture_chirho.review_variant_chirho(
        &two_asset_variant_chirho(b".a{color:#222}\n", b".b{color:#222}\n"),
    );
    assert_eq!(
        candidate_v2_chirho, candidate_chirho,
        "precondition: only the assets differ"
    );

    let failure_chirho = {
        let _armed_chirho = InstallFaultGuardChirho::arm_chirho(1);
        app_source_manifest_chirho::install_reviewed_app_source_report_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            &v2_chirho,
        )
        .expect_err("the injected fault must fail the install")
    };
    let message_chirho = format!("{failure_chirho:#}");
    assert!(
        message_chirho.contains("injected reviewed asset install failure"),
        "{message_chirho}"
    );
    assert!(
        message_chirho.contains("the surface this install found was put back and verified"),
        "the first asset WAS replaced, so the install must report putting it back: {message_chirho}"
    );

    fixture_chirho.assert_live_version_chirho(&candidate_chirho, &v1_chirho);
    assert_eq!(
        fixture_chirho
            .served_named_asset_bytes_chirho("a-chirho.css")
            .as_deref(),
        Some(&b".a{color:#111}\n"[..])
    );
    assert_eq!(
        fixture_chirho
            .served_named_asset_bytes_chirho("b-chirho.css")
            .as_deref(),
        Some(&b".b{color:#111}\n"[..])
    );
}

/// Only the PROMOTION's restore can undo this: the promotion moves the root to v2 before the install runs, so the
/// surface the install found already has v2's root.
#[test]
fn a_failed_repromotion_that_moved_the_root_puts_the_prior_root_back_chirho() {
    let fixture_chirho = RepromoteFixtureChirho::new_chirho(
        "review-repromote-moved-root",
        "review-repromote-root-app-chirho",
    );
    let (report_v1_chirho, candidate_chirho, v1_chirho) = fixture_chirho.review_variant_chirho(
        &ReviewFixtureVariantChirho::one_asset_chirho(ASSET_V1_CHIRHO),
    );
    let (status_chirho, body_chirho) =
        fixture_chirho.promote_chirho(&candidate_chirho, &report_v1_chirho);
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    // Less fuel: a different node, so a different root, and never a cost increase.
    let (report_v2_chirho, candidate_v2_chirho, _) =
        fixture_chirho.review_variant_chirho(&ReviewFixtureVariantChirho {
            node_fuel_chirho: 999_999,
            ..ReviewFixtureVariantChirho::one_asset_chirho(ASSET_V1_CHIRHO)
        });
    assert_ne!(
        candidate_v2_chirho, candidate_chirho,
        "precondition: v2 moves the root"
    );

    let (status_chirho, body_chirho) = {
        let _armed_chirho = InstallFaultGuardChirho::arm_chirho(0);
        fixture_chirho.promote_chirho(&candidate_v2_chirho, &report_v2_chirho)
    };
    assert_eq!(status_chirho, StatusCode::BAD_REQUEST, "{body_chirho}");
    assert!(
        body_chirho.contains("injected reviewed asset install failure"),
        "{body_chirho}"
    );
    assert!(
        body_chirho.contains("from before the promotion was put back and verified"),
        "the root moved, so the promotion must report putting it back: {body_chirho}"
    );
    fixture_chirho.assert_live_version_chirho(&candidate_chirho, &v1_chirho);
    assert_eq!(
        fixture_chirho.served_asset_bytes_chirho().as_deref(),
        Some(ASSET_V1_CHIRHO)
    );
}

/// A part that cannot be put back is NAMED in the error, never discarded: v1 had no root response type, v2 sets one,
/// and the response-policy log has no "unset" record. Everything restorable is still restored.
#[test]
fn a_failed_repromotion_names_what_it_could_not_put_back_chirho() {
    let fixture_chirho = RepromoteFixtureChirho::new_chirho(
        "review-repromote-unrestorable",
        "review-repromote-named-app-chirho",
    );
    let (report_v1_chirho, candidate_chirho, v1_chirho) = fixture_chirho.review_variant_chirho(
        &ReviewFixtureVariantChirho::one_asset_chirho(ASSET_V1_CHIRHO),
    );
    let (status_chirho, body_chirho) =
        fixture_chirho.promote_chirho(&candidate_chirho, &report_v1_chirho);
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    let (report_v2_chirho, candidate_v2_chirho, _) =
        fixture_chirho.review_variant_chirho(&ReviewFixtureVariantChirho {
            root_response_content_type_chirho: Some("text/plain"),
            ..ReviewFixtureVariantChirho::one_asset_chirho(ASSET_V2_CHIRHO)
        });
    assert_eq!(
        candidate_v2_chirho, candidate_chirho,
        "precondition: the root does not move"
    );

    let (status_chirho, body_chirho) = {
        let _armed_chirho = InstallFaultGuardChirho::arm_chirho(0);
        fixture_chirho.promote_chirho(&candidate_chirho, &report_v2_chirho)
    };
    assert_eq!(status_chirho, StatusCode::BAD_REQUEST, "{body_chirho}");
    assert!(
        body_chirho.contains("injected reviewed asset install failure"),
        "{body_chirho}"
    );
    assert!(
        body_chirho.contains("PUTTING BACK"),
        "a failed restore must be reported: {body_chirho}"
    );
    assert!(
        body_chirho.contains("the root response type"),
        "and the part named: {body_chirho}"
    );
    fixture_chirho.assert_live_version_chirho(&candidate_chirho, &v1_chirho);
    assert_eq!(
        fixture_chirho.served_asset_bytes_chirho().as_deref(),
        Some(ASSET_V1_CHIRHO)
    );
}
