// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Continuation behavior through the three landed elected doors, including external reviewed-input
//! custody, one-time coordinate migration, named authority refusals, and idempotence.

use super::*;
use cairn_chirho::{app_source_manifest_chirho, cas_chirho, identity_chirho};
use cairn_durable_chirho::cas_lifecycle_chirho::migrate_cas_lifecycle_offline_chirho;
use cairn_writer_head_chirho::head_transition_authority_chirho::{
    with_elected_head_transition_scope_chirho, HeadTransitionCommitActionChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    issue_elected_writer_fence_for_root_chirho, ConsistencyGroupIdChirho,
};
use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const NAMESPACE_CHIRHO: &str = "ledger-substrate-chirho";

fn scratch_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-s4p-{tag_chirho}-{nanos_chirho}-{n_chirho}-chirho"
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// Mark the root consumed the same way `setup_chirho` observes it: the substrate namespace exists.
fn consume_root_chirho(root_chirho: &Path) {
    std::fs::create_dir_all(root_chirho.join(NAMESPACE_CHIRHO)).unwrap();
    std::fs::create_dir_all(root_chirho.join(constants_chirho::REVIEWED_INPUTS_DIR_CHIRHO))
        .unwrap();
}

fn empty_external_reviewed_inputs_dir_chirho(label_chirho: &str) -> PathBuf {
    let dir_chirho = scratch_root_chirho(&format!("{label_chirho}-external-reviewed-inputs"));
    std::fs::set_permissions(&dir_chirho, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir_chirho
}

fn externalize_reviewed_inputs_chirho(root_chirho: &Path, label_chirho: &str) -> PathBuf {
    let external_dir_chirho = empty_external_reviewed_inputs_dir_chirho(label_chirho);
    let source_chirho = reviewed_candidate_pointer_path_chirho(root_chirho);
    let target_chirho =
        external_dir_chirho.join(constants_chirho::REVIEWED_CANDIDATE_POINTER_FILE_CHIRHO);
    std::fs::copy(&source_chirho, &target_chirho).unwrap();
    std::fs::set_permissions(&target_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    external_dir_chirho
}

struct LiveContinuationAuthorityChirho {
    group_chirho: ConsistencyGroupIdChirho,
    term_chirho: u64,
    calls_chirho: Cell<usize>,
}

impl HeadTransitionAuthorityPortChirho for LiveContinuationAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        self.calls_chirho
            .set(self.calls_chirho.get().saturating_add(1));
        with_elected_head_transition_scope_chirho(
            root_chirho,
            &self.group_chirho,
            self.term_chirho,
            None,
            |scope_chirho| action_chirho.call_chirho(scope_chirho),
        )
        .into_result_chirho()
    }
}

struct RefusingContinuationAuthorityChirho {
    refusal_chirho: &'static str,
}

impl HeadTransitionAuthorityPortChirho for RefusingContinuationAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        _root_chirho: &Path,
        _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        Err(anyhow::anyhow!(self.refusal_chirho))
    }
}

struct ObservedOnlyContinuationAuthorityChirho {
    called_chirho: Cell<bool>,
}

impl HeadTransitionAuthorityPortChirho for ObservedOnlyContinuationAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        _root_chirho: &Path,
        _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        self.called_chirho.set(true);
        Err(anyhow::anyhow!(
            "NeverLatchedContinuationMustNotReachElectedAuthorityChirho"
        ))
    }
}

fn build_review_report_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> (
    String,
    HashChirho,
    app_source_manifest_chirho::AppSourceReviewReportChirho,
) {
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let artifact_path_chirho = PathBuf::from("credits-demo-node-chirho.wat");
    let artifact_chirho = root_chirho.join(&artifact_path_chirho);
    std::fs::write(
        &artifact_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let manifest_chirho = app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_owned(),
        app_chirho: app_chirho.to_owned(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho: vec![app_source_manifest_chirho::AppSourceNodeManifestChirho {
            id_chirho: "credits_demo_node_chirho".to_owned(),
            name_chirho: "credits_demo_node_chirho".to_owned(),
            entry_chirho: Some("upcase_chirho".to_owned()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: Vec::new(),
            source_chirho: app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_path_chirho,
            },
        }],
        dags_chirho: vec![app_source_manifest_chirho::AppSourceDagManifestChirho {
            id_chirho: "credits_demo_dag_chirho".to_owned(),
            nodes_chirho: vec!["credits_demo_node_chirho".to_owned()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: vec![app_source_manifest_chirho::AppSourceModuleManifestChirho {
            id_chirho: "credits_demo_module_chirho".to_owned(),
            dag_chirho: "credits_demo_dag_chirho".to_owned(),
            name_chirho: "credits_demo_module_chirho".to_owned(),
            version_chirho: "v1".to_owned(),
            previous_module_chirho: None,
            input_bindings_chirho: vec![
                app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "request_chirho".to_owned(),
                    node_chirho: "credits_demo_node_chirho".to_owned(),
                    node_port_chirho: "in".to_owned(),
                },
            ],
            output_bindings_chirho: vec![
                app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "response_chirho".to_owned(),
                    node_chirho: "credits_demo_node_chirho".to_owned(),
                    node_port_chirho: "out".to_owned(),
                },
            ],
            route_labels_chirho: vec![constants_chirho::SPEND_ROUTE_CHIRHO.to_owned()],
            metadata_chirho: BTreeMap::new(),
            subscription_views_chirho: Vec::new(),
        }],
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "credits_demo_module_chirho".to_owned(),
                },
            ),
            input_mode_chirho: None,
            response_content_type_chirho: Some("text/html".to_owned()),
            params_chirho: None,
            routes_chirho: vec![
                app_source_manifest_chirho::AppSourceDeployRouteManifestChirho {
                    route_chirho: constants_chirho::SPEND_ROUTE_CHIRHO.to_owned(),
                    source_chirho:
                        app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                            id_chirho: "credits_demo_module_chirho".to_owned(),
                        },
                    input_mode_chirho: None,
                    request_body_policy_chirho: None,
                    response_content_type_chirho: Some("text/html".to_owned()),
                    params_chirho: None,
                    key_access_chirho: None,
                },
            ],
            runtime_packages_chirho: Vec::new(),
            target_chirho:
                app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let manifest_bytes_chirho = serde_json::to_vec(&manifest_chirho).unwrap();
    let prepared_chirho = app_source_manifest_chirho::preflight_app_source_manifest_inputs_chirho(
        root_chirho,
        &manifest_bytes_chirho,
    )
    .unwrap();
    let report_chirho =
        app_source_manifest_chirho::build_app_source_review_from_prepared_bytes_for_owner_chirho(
            root_chirho,
            &manifest_bytes_chirho,
            root_chirho,
            &owner_chirho,
            &prepared_chirho,
        )
        .unwrap();
    let report_hash_chirho = report_chirho.source_review_report_chirho.clone().unwrap();
    (owner_chirho, report_hash_chirho, report_chirho)
}

fn prepare_reviewed_root_chirho(
    label_chirho: &str,
    geo_latched_chirho: bool,
) -> (
    PathBuf,
    PathBuf,
    app_source_manifest_chirho::AppSourceReviewReportChirho,
    Option<LiveContinuationAuthorityChirho>,
) {
    let root_chirho = scratch_root_chirho(label_chirho);
    consume_root_chirho(&root_chirho);
    let (_owner_chirho, report_hash_chirho, report_chirho) =
        build_review_report_chirho(&root_chirho, constants_chirho::APP_CHIRHO);
    persist_reviewed_candidate_pointer_chirho(&root_chirho, &report_hash_chirho).unwrap();
    let reviewed_inputs_dir_chirho = externalize_reviewed_inputs_chirho(&root_chirho, label_chirho);
    if !geo_latched_chirho {
        return (root_chirho, reviewed_inputs_dir_chirho, report_chirho, None);
    }
    migrate_cas_lifecycle_offline_chirho(&root_chirho).unwrap();
    let fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 7).unwrap();
    let authority_chirho = LiveContinuationAuthorityChirho {
        group_chirho: fence_chirho.group_chirho,
        term_chirho: 7,
        calls_chirho: Cell::new(0),
    };
    (
        root_chirho,
        reviewed_inputs_dir_chirho,
        report_chirho,
        Some(authority_chirho),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContinuationDurableCountsChirho {
    app_records_chirho: usize,
    route_records_chirho: usize,
    price_records_chirho: usize,
    selected_refs_chirho: usize,
    reflog_entries_chirho: usize,
}

fn durable_counts_chirho(root_chirho: &Path) -> ContinuationDurableCountsChirho {
    ContinuationDurableCountsChirho {
        app_records_chirho: cairn_chirho::app_chirho::verified_app_records_chirho(root_chirho)
            .unwrap()
            .len(),
        route_records_chirho: cairn_chirho::app_chirho::verified_app_route_records_chirho(
            root_chirho,
        )
        .unwrap()
        .len(),
        price_records_chirho:
            cairn_chirho::effect_pricing_chirho::verified_price_book_records_chirho(root_chirho)
                .unwrap()
                .len(),
        selected_refs_chirho: refs_chirho::load_refs_chirho(root_chirho)
            .unwrap()
            .branches_chirho
            .len(),
        reflog_entries_chirho: refs_chirho::reflog_chirho(root_chirho).unwrap().len(),
    }
}

fn put_branch_chirho(root_chirho: &Path, name_chirho: &str, payload_chirho: &[u8]) -> HashChirho {
    let head_chirho = cas_chirho::add_chirho(root_chirho, payload_chirho).unwrap();
    refs_chirho::set_branch_chirho(root_chirho, name_chirho, head_chirho.clone()).unwrap();
    head_chirho
}

fn app_branch_name_chirho() -> String {
    cairn_chirho::app_chirho::app_branch_ref_name_chirho(constants_chirho::APP_CHIRHO)
}

const ROUTE_CHIRHO: &str = constants_chirho::SPEND_ROUTE_CHIRHO;

/// FIXTURE ONLY. A test has to PLANT a full branch name, but production must not spell one — the
/// module reads routes through the typed enumerator now, and the app-control-plane centralization
/// guard scans production lines. So the raw form lives here, in `cfg(test)`, and nowhere else.
fn route_branch_name_chirho(route_chirho: &str) -> String {
    format!("app-route/{}/{route_chirho}", constants_chirho::APP_CHIRHO)
}

/// A FRESH root is refused BY NAME, and the refusal names the reason rather than failing later on a
/// missing coordinate. This is the mirror of `setup_chirho`'s non-fresh refusal.
#[test]
fn continuation_refuses_a_fresh_root_by_name_chirho() {
    let root_chirho = scratch_root_chirho("fresh");
    let reviewed_inputs_dir_chirho = empty_external_reviewed_inputs_dir_chirho("fresh");
    // Deliberately NOT consumed.
    let error_chirho = run_credits_demo_continuation_chirho(
        &root_chirho,
        &reviewed_inputs_dir_chirho,
        &"00".repeat(32),
        NAMESPACE_CHIRHO,
    )
    .expect_err("a fresh root must be refused, never silently continued");
    assert!(
        format!("{error_chirho:#}").contains(CONTINUATION_FRESH_ROOT_REFUSAL_CHIRHO),
        "refusal must be the NAMED fresh-root refusal, not an incidental failure: {error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(reviewed_inputs_dir_chirho);
}

/// Every coordinate is READ from the root. Nothing is hardcoded: a root with no heads inventories as
/// empty, and the same root gains exactly the heads it is given.
#[test]
fn inventory_reads_coordinates_from_the_root_rather_than_assuming_them_chirho() {
    let root_chirho = scratch_root_chirho("inventory");
    consume_root_chirho(&root_chirho);

    let empty_chirho = inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO).unwrap();
    assert!(empty_chirho.ledger_substrate_present_chirho);
    assert_eq!(empty_chirho.app_head_chirho, None);
    assert!(empty_chirho.route_heads_chirho.is_empty());
    assert!(!empty_chirho.end_state_reached_chirho());

    let app_head_chirho = put_branch_chirho(&root_chirho, &app_branch_name_chirho(), b"app-head");
    let route_name_chirho = ROUTE_CHIRHO.to_string();
    let route_branch_chirho = route_branch_name_chirho(ROUTE_CHIRHO);
    let route_head_chirho = put_branch_chirho(&root_chirho, &route_branch_chirho, b"route-head");
    // A route belonging to a DIFFERENT app must not be counted as this app's.
    let foreign_chirho = "app-route/other-app-chirho/demo-chirho".to_string();
    put_branch_chirho(&root_chirho, &foreign_chirho, b"foreign-route-head");

    let filled_chirho = inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO).unwrap();
    assert_eq!(filled_chirho.app_head_chirho, Some(app_head_chirho));
    assert_eq!(
        filled_chirho.route_heads_chirho,
        vec![(route_name_chirho, route_head_chirho)],
        "only this app's route heads may be inventoried"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// Completed phases are SKIPPED: the entry point moves forward as coordinates appear, and it never
/// re-enters a phase whose head already exists.
#[test]
fn completed_phases_are_skipped_and_never_re_entered_chirho() {
    let root_chirho = scratch_root_chirho("skip");
    consume_root_chirho(&root_chirho);

    let bare_chirho = inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO).unwrap();
    assert_eq!(
        next_phase_chirho(&bare_chirho),
        ContinuationPhaseChirho::AppPromotionChirho,
        "with no app head the only entry point is app promotion"
    );

    put_branch_chirho(&root_chirho, &app_branch_name_chirho(), b"app-head");
    let with_app_chirho = inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO).unwrap();
    assert_eq!(
        next_phase_chirho(&with_app_chirho),
        ContinuationPhaseChirho::RouteDeployChirho,
        "an existing app head must be skipped, not promoted again"
    );

    let route_branch_chirho = route_branch_name_chirho(ROUTE_CHIRHO);
    put_branch_chirho(&root_chirho, &route_branch_chirho, b"route-head");
    let with_route_chirho = inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO).unwrap();
    assert_eq!(
        next_phase_chirho(&with_route_chirho),
        ContinuationPhaseChirho::PriceBookChirho,
        "an existing route head must be skipped too"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// The former door-seam arm is retargeted to the migration seam: a pre-pointer consumed root
/// refuses by the pointer's identity and never reaches authority.
#[test]
fn a_pre_pointer_consumed_root_refuses_before_authority_chirho() {
    let root_chirho = scratch_root_chirho("pre-pointer");
    consume_root_chirho(&root_chirho);
    let reviewed_inputs_dir_chirho = empty_external_reviewed_inputs_dir_chirho("pre-pointer");
    let authority_chirho = ObservedOnlyContinuationAuthorityChirho {
        called_chirho: Cell::new(false),
    };
    let error_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
        &root_chirho,
        &reviewed_inputs_dir_chirho,
        NAMESPACE_CHIRHO,
        &authority_chirho,
    )
    .expect_err("a consumed root without the bounded pointer must refuse");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains(REVIEWED_CANDIDATE_POINTER_MISSING_REFUSAL_CHIRHO),
        "the refusal must identify the one-time coordinate migration: {text_chirho}"
    );
    assert!(
        !text_chirho.contains(CONTINUATION_FRESH_ROOT_REFUSAL_CHIRHO),
        "a consumed root must not be refused as fresh: {text_chirho}"
    );
    assert!(
        !authority_chirho.called_chirho.get(),
        "pointer validation must precede every authority call"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(reviewed_inputs_dir_chirho);
}

/// Location separation is structural on this road: supplying the old root-relative directory must
/// refuse before authority even when that directory contains a fully valid reviewed pointer.
#[test]
fn continuation_refuses_root_local_reviewed_inputs_without_fallback_chirho() {
    let (root_chirho, external_dir_chirho, _review_chirho, _live_chirho) =
        prepare_reviewed_root_chirho("root-local-refusal", true);
    let root_local_dir_chirho = root_chirho.join(constants_chirho::REVIEWED_INPUTS_DIR_CHIRHO);
    let authority_chirho = ObservedOnlyContinuationAuthorityChirho {
        called_chirho: Cell::new(false),
    };
    let before_chirho = durable_counts_chirho(&root_chirho);

    let error_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
        &root_chirho,
        &root_local_dir_chirho,
        NAMESPACE_CHIRHO,
        &authority_chirho,
    )
    .expect_err("the continuation road must have no root-relative reviewed-input fallback");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains(REVIEWED_INPUTS_NOT_EXTERNAL_REFUSAL_CHIRHO),
        "the refusal must name location separation: {text_chirho}"
    );
    assert!(
        !text_chirho.contains(REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO),
        "the root-local fixture must reach containment, not the transplant gate: {text_chirho}"
    );
    assert!(!authority_chirho.called_chirho.get());
    assert_eq!(durable_counts_chirho(&root_chirho), before_chirho);

    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(external_dir_chirho);
}

/// Moving reviewed inputs outside the root grants no transplant authority. A bundle from root A is
/// re-resolved against root B's own CAS and refuses before any elected mutation.
#[test]
fn external_reviewed_inputs_cannot_be_transplanted_between_roots_chirho() {
    let (root_a_chirho, external_a_chirho, _review_a_chirho, _authority_a_chirho) =
        prepare_reviewed_root_chirho("transplant-a", false);
    let (root_b_chirho, external_b_chirho, _review_b_chirho, _authority_b_chirho) =
        prepare_reviewed_root_chirho("transplant-b", false);
    let authority_chirho = ObservedOnlyContinuationAuthorityChirho {
        called_chirho: Cell::new(false),
    };
    let before_chirho = durable_counts_chirho(&root_b_chirho);

    let error_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
        &root_b_chirho,
        &external_a_chirho,
        NAMESPACE_CHIRHO,
        &authority_chirho,
    )
    .expect_err("root A's external locator must not authorize root B");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains(REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO),
        "the locator must fail while resolving against the selected root: {text_chirho}"
    );
    assert!(
        !text_chirho.contains(REVIEWED_INPUTS_NOT_EXTERNAL_REFUSAL_CHIRHO),
        "the external location is valid; the ROOT binding must be what refuses: {text_chirho}"
    );
    assert!(!authority_chirho.called_chirho.get());
    assert_eq!(durable_counts_chirho(&root_b_chirho), before_chirho);

    let _ = std::fs::remove_dir_all(root_a_chirho);
    let _ = std::fs::remove_dir_all(external_a_chirho);
    let _ = std::fs::remove_dir_all(root_b_chirho);
    let _ = std::fs::remove_dir_all(external_b_chirho);
}

/// The price-book ref name, mirroring `effect_pricing_chirho.rs:60` (`pricebook_ref_chirho` is
/// private). FIXTURE ONLY, like `route_branch_name_chirho`: a test must plant one, production must
/// not spell one. **Unlike the route case there is no public accessor to switch to** — I checked,
/// having just been wrong in the other direction about exactly that.
fn pricebook_ref_name_chirho() -> String {
    format!("pricebook/{}", constants_chirho::APP_CHIRHO)
}

/// **A price-book read ERROR must REFUSE, never read as "no price book".**
///
/// Reviewer-chosen arm (claude2_chirho): the inventory previously did `.unwrap_or(None)` on a read
/// that GATES a mutation decision. `next_phase_chirho` routes an absent price head to
/// `PriceBookChirho` — so error-as-absence sends the continuation to MINT a price book over a root
/// whose price ref exists but does not verify.
///
/// The fixture violates the property rather than merely differing from a good root: it sets a
/// `pricebook/<app>` head that selects no verified signed history, which is the real `Err` at
/// `effect_pricing_chirho.rs:245` — not a synthetic IO failure.
///
/// **Identity is asserted because `is_err()` alone would be vacuous here**: under the bug the run
/// can ALSO fail at a later pre-mutation guard after already selecting `PriceBookChirho`. Both
/// states are `Err`; only the reason distinguishes a read refusal from a wrong decision that got
/// lucky.
#[test]
fn a_price_book_read_error_refuses_rather_than_reading_as_absence_chirho() {
    let root_chirho = scratch_root_chirho("price-read-error");
    consume_root_chirho(&root_chirho);
    let reviewed_inputs_dir_chirho = empty_external_reviewed_inputs_dir_chirho("price-read-error");
    put_branch_chirho(&root_chirho, &app_branch_name_chirho(), b"app-head");
    let route_branch_chirho = route_branch_name_chirho(ROUTE_CHIRHO);
    put_branch_chirho(&root_chirho, &route_branch_chirho, b"route-head");

    // NON-VACUITY CONTROL: without the bogus price ref this same root inventories cleanly, so the
    // failure below is caused by the price ref and by nothing else in the fixture.
    let control_chirho = inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO)
        .expect("control: the fixture root must inventory cleanly before the price ref is planted");
    assert_eq!(
        control_chirho.price_book_head_chirho, None,
        "control: a genuinely absent price book is Ok(None) — the arm below must not be measuring \
         mere absence"
    );

    // A price head that exists and selects NO verified signed history.
    put_branch_chirho(
        &root_chirho,
        &pricebook_ref_name_chirho(),
        b"unverifiable-price-head",
    );

    let inventory_error_chirho = inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO)
        .expect_err("an unverifiable price head must fail the inventory, never inventory as None");
    let inventory_text_chirho = format!("{inventory_error_chirho:#}");
    assert!(
        inventory_text_chirho.contains("price book"),
        "the refusal must name the price-book read as the cause: {inventory_text_chirho}"
    );

    let before_chirho = durable_counts_chirho(&root_chirho);
    let authority_chirho = ObservedOnlyContinuationAuthorityChirho {
        called_chirho: Cell::new(false),
    };
    let run_error_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
        &root_chirho,
        &reviewed_inputs_dir_chirho,
        NAMESPACE_CHIRHO,
        &authority_chirho,
    )
    .expect_err("the continuation must refuse rather than route to a mutation phase");
    let run_text_chirho = format!("{run_error_chirho:#}");
    assert!(
        run_text_chirho.contains("price book"),
        "the run must refuse for the READ failure: {run_text_chirho}"
    );
    assert!(
        !authority_chirho.called_chirho.get(),
        "price-read refusal must precede elected authority; a call proves the error was treated as \
         absence and PriceBookChirho was selected"
    );
    assert_eq!(
        durable_counts_chirho(&root_chirho),
        before_chirho,
        "price-read refusal must preserve every durable row, ref, and reflog count"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(reviewed_inputs_dir_chirho);
}

/// One invocation crosses all three real elected doors. Each family gains exactly one row, ref, and
/// receipt; the second invocation observes Complete and changes no durable count.
#[test]
fn one_run_reaches_the_real_end_state_and_the_second_mutates_nothing_chirho() {
    let (root_chirho, reviewed_inputs_dir_chirho, _review_chirho, authority_chirho) =
        prepare_reviewed_root_chirho("elected-end-state", true);
    let authority_chirho = authority_chirho.unwrap();
    let before_chirho = durable_counts_chirho(&root_chirho);

    let first_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
        &root_chirho,
        &reviewed_inputs_dir_chirho,
        NAMESPACE_CHIRHO,
        &authority_chirho,
    )
    .expect("one live elected invocation reaches the end state");
    assert_eq!(
        first_chirho.entered_phase_chirho,
        ContinuationPhaseChirho::AppPromotionChirho
    );
    assert_eq!(first_chirho.mutations_attempted_chirho, 3);
    assert_eq!(authority_chirho.calls_chirho.get(), 3);
    let after_first_chirho = durable_counts_chirho(&root_chirho);
    assert_eq!(
        after_first_chirho.app_records_chirho,
        before_chirho.app_records_chirho + 1
    );
    assert_eq!(
        after_first_chirho.route_records_chirho,
        before_chirho.route_records_chirho + 1
    );
    assert_eq!(
        after_first_chirho.price_records_chirho,
        before_chirho.price_records_chirho + 1
    );
    assert_eq!(
        after_first_chirho.selected_refs_chirho,
        before_chirho.selected_refs_chirho + 3
    );
    assert_eq!(
        after_first_chirho.reflog_entries_chirho,
        before_chirho.reflog_entries_chirho + 3
    );
    assert!(
        inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO)
            .unwrap()
            .end_state_reached_chirho(),
        "non-vacuity: the first invocation must reach the actual three-head end state"
    );

    let second_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
        &root_chirho,
        &reviewed_inputs_dir_chirho,
        NAMESPACE_CHIRHO,
        &authority_chirho,
    )
    .expect("a complete root is an idempotent success");
    assert_eq!(
        second_chirho.entered_phase_chirho,
        ContinuationPhaseChirho::CompleteChirho
    );
    assert_eq!(second_chirho.mutations_attempted_chirho, 0);
    assert_eq!(
        authority_chirho.calls_chirho.get(),
        3,
        "the complete retry must not enter any elected authority scope"
    );
    assert_eq!(durable_counts_chirho(&root_chirho), after_first_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(reviewed_inputs_dir_chirho);
}

/// A never-latched root consumes the same continuation arguments but all three landed dispatchers
/// retain their pre-geo local paths; the supplied elected port is never observed.
#[test]
fn never_latched_continuation_never_enters_elected_authority_chirho() {
    let (root_chirho, reviewed_inputs_dir_chirho, _review_chirho, _authority_chirho) =
        prepare_reviewed_root_chirho("never-latched", false);
    let authority_chirho = ObservedOnlyContinuationAuthorityChirho {
        called_chirho: Cell::new(false),
    };
    let report_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
        &root_chirho,
        &reviewed_inputs_dir_chirho,
        NAMESPACE_CHIRHO,
        &authority_chirho,
    )
    .expect("never-latched continuation preserves all three local paths");
    assert_eq!(report_chirho.mutations_attempted_chirho, 3);
    assert!(
        !authority_chirho.called_chirho.get(),
        "never-latched dispatch must remain byte-compatible by avoiding the elected port"
    );
    assert!(
        inventory_consumed_root_chirho(&root_chirho, NAMESPACE_CHIRHO)
            .unwrap()
            .end_state_reached_chirho()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(reviewed_inputs_dir_chirho);
}

/// The continuation adds no error wrapper that erases the elected adapter's refusal identity.
/// Neighbor assertions distinguish each failure from a generic authority rejection.
#[test]
fn elected_refusal_identities_surface_before_any_durable_output_chirho() {
    let cases_chirho = [
        (
            "ElectedAuthorityDeposedChirho",
            "ElectedAuthorityLeaseExpiredChirho",
        ),
        (
            "ElectedAuthorityLeaseExpiredChirho",
            "ElectedAuthorityDeposedChirho",
        ),
        (
            "ElectedAuthorityWrongRootChirho",
            "ElectedAuthorityWrongGroupChirho",
        ),
        (
            "ElectedAuthorityWrongGroupChirho",
            "ElectedAuthorityWrongRootChirho",
        ),
    ];
    for (index_chirho, (refusal_chirho, neighbor_chirho)) in cases_chirho.into_iter().enumerate() {
        let (root_chirho, reviewed_inputs_dir_chirho, _review_chirho, _live_chirho) =
            prepare_reviewed_root_chirho(&format!("refusal-{index_chirho}"), true);
        let before_chirho = durable_counts_chirho(&root_chirho);
        let authority_chirho = RefusingContinuationAuthorityChirho { refusal_chirho };
        let error_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
            &root_chirho,
            &reviewed_inputs_dir_chirho,
            NAMESPACE_CHIRHO,
            &authority_chirho,
        )
        .expect_err("named elected refusal must stop the continuation");
        let text_chirho = format!("{error_chirho:#}");
        assert!(
            text_chirho.contains(refusal_chirho),
            "refusal identity must survive the continuation: {text_chirho}"
        );
        assert!(
            !text_chirho.contains(neighbor_chirho),
            "neighbor refusal must remain unreachable: {text_chirho}"
        );
        assert_eq!(
            durable_counts_chirho(&root_chirho),
            before_chirho,
            "authority refusal must happen before any app/route/price row, ref, or receipt"
        );
        let _ = std::fs::remove_dir_all(root_chirho);
        let _ = std::fs::remove_dir_all(reviewed_inputs_dir_chirho);
    }
}

/// The migration command validates before write and preserves the route non-uniqueness refusal.
#[test]
fn coordinate_pin_refuses_invalid_and_duplicate_review_coordinates_without_writing_chirho() {
    let root_chirho = scratch_root_chirho("pin-refusal");
    consume_root_chirho(&root_chirho);
    let invalid_chirho = pin_reviewed_candidate_coordinates_chirho(&root_chirho, &"A".repeat(64))
        .expect_err("uppercase review hashes are non-canonical");
    assert!(
        format!("{invalid_chirho:#}").contains(REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO)
    );
    assert!(!reviewed_candidate_pointer_path_chirho(&root_chirho).exists());

    let (_owner_chirho, _report_hash_chirho, report_chirho) =
        build_review_report_chirho(&root_chirho, constants_chirho::APP_CHIRHO);
    let mut duplicate_chirho = report_chirho.clone();
    duplicate_chirho
        .candidate_chirho
        .routes_chirho
        .push(duplicate_chirho.candidate_chirho.routes_chirho[0].clone());
    let duplicate_hash_chirho = app_source_manifest_chirho::put_app_source_review_report_chirho(
        &root_chirho,
        &duplicate_chirho,
    )
    .unwrap();
    let duplicate_error_chirho =
        pin_reviewed_candidate_coordinates_chirho(&root_chirho, &duplicate_hash_chirho.0)
            .expect_err("duplicate review-bound spend routes must refuse");
    assert!(format!("{duplicate_error_chirho:#}")
        .contains(REVIEWED_CANDIDATE_ROUTE_DUPLICATE_REFUSAL_CHIRHO));
    assert!(!reviewed_candidate_pointer_path_chirho(&root_chirho).exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// The explicit operator coordinate is accepted only after full review validation, and the
/// migration cannot replace even an identical existing pointer.
#[test]
fn explicit_coordinate_pin_writes_one_verified_locator_without_overwrite_chirho() {
    let root_chirho = scratch_root_chirho("pin-success");
    consume_root_chirho(&root_chirho);
    let (owner_chirho, report_hash_chirho, report_chirho) =
        build_review_report_chirho(&root_chirho, constants_chirho::APP_CHIRHO);

    let pointer_chirho =
        pin_reviewed_candidate_coordinates_chirho(&root_chirho, &report_hash_chirho.0)
            .expect("a canonical fully verified review coordinate must pin once");
    assert_eq!(pointer_chirho.app_chirho, constants_chirho::APP_CHIRHO);
    assert_eq!(pointer_chirho.owner_chirho, owner_chirho);
    assert_eq!(
        pointer_chirho.source_review_report_chirho,
        report_hash_chirho
    );
    assert_eq!(
        pointer_chirho.candidate_root_dag_chirho,
        report_chirho.candidate_chirho.root_dag_chirho
    );
    let pointer_path_chirho = reviewed_candidate_pointer_path_chirho(&root_chirho);
    let original_bytes_chirho = std::fs::read(&pointer_path_chirho).unwrap();

    let repeat_error_chirho =
        pin_reviewed_candidate_coordinates_chirho(&root_chirho, &report_hash_chirho.0)
            .expect_err("the one-time migration must never replace an existing pointer");
    assert!(
        format!("{repeat_error_chirho:#}")
            .contains(REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO),
        "the refusal must preserve the pointer-write identity: {repeat_error_chirho:#}"
    );
    assert_eq!(
        std::fs::read(&pointer_path_chirho).unwrap(),
        original_bytes_chirho,
        "a repeated pin must leave the existing locator byte-identical"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// Fresh setup calls the same bounded-pointer writer as the migration and does so before promotion.
/// This is a source-order arm because the full setup requires the sanctioned local PostgreSQL
/// fixture; the continuation behavior tests above exercise the writer and locator at runtime.
#[test]
fn fresh_setup_persists_the_bounded_locator_before_promotion_chirho() {
    let source_chirho = include_str!("setup_chirho.rs");
    let pointer_anchors_chirho: Vec<usize> = source_chirho
        .match_indices("continuation_chirho::persist_reviewed_candidate_pointer_chirho(")
        .map(|(index_chirho, _match_chirho)| index_chirho)
        .collect();
    assert_eq!(
        pointer_anchors_chirho.len(),
        1,
        "fresh setup must have one pointer-persistence anchor; zero loses migration parity and more \
         than one risks replacement"
    );
    let promotion_anchor_chirho = source_chirho
        .find(
            "review_chirho::\
             promote_candidate_with_review_evidence_and_head_transition_authority_chirho(",
        )
        .expect("fresh setup must retain its elected reviewed promotion");
    assert!(
        pointer_anchors_chirho[0] < promotion_anchor_chirho,
        "pointer persistence must precede promotion so a post-review setup interruption remains \
         continuable without a CAS scan"
    );
}

/// The pointer is only a locator: changing any copied coordinate cannot redirect authority because
/// the report is reloaded and the pointer is compared back to its verified coordinates.
#[test]
fn pointer_coordinate_tamper_refuses_before_authority_chirho() {
    let (root_chirho, reviewed_inputs_dir_chirho, _review_chirho, _live_chirho) =
        prepare_reviewed_root_chirho("pointer-tamper", true);
    let pointer_path_chirho =
        reviewed_inputs_dir_chirho.join(constants_chirho::REVIEWED_CANDIDATE_POINTER_FILE_CHIRHO);
    let mut pointer_chirho: CreditsDemoReviewedCandidatePointerChirho =
        serde_json::from_slice(&std::fs::read(&pointer_path_chirho).unwrap()).unwrap();
    pointer_chirho.candidate_root_dag_chirho = HashChirho("0".repeat(64));
    std::fs::write(
        &pointer_path_chirho,
        serde_json::to_vec(&pointer_chirho).unwrap(),
    )
    .unwrap();
    let authority_chirho = ObservedOnlyContinuationAuthorityChirho {
        called_chirho: Cell::new(false),
    };
    let error_chirho = run_credits_demo_continuation_with_head_transition_authority_chirho(
        &root_chirho,
        &reviewed_inputs_dir_chirho,
        NAMESPACE_CHIRHO,
        &authority_chirho,
    )
    .expect_err("pointer coordinate substitution must refuse");
    assert!(format!("{error_chirho:#}").contains(REVIEWED_CANDIDATE_POINTER_INVALID_REFUSAL_CHIRHO));
    assert!(!authority_chirho.called_chirho.get());
    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(reviewed_inputs_dir_chirho);
}
