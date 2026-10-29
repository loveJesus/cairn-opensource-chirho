// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_durable_chirho::cas_lifecycle_chirho::{
    migrate_cas_lifecycle_offline_chirho, CasLifecycleRootChirho,
};
use cairn_writer_head_chirho::head_transition_authority_chirho::{
    with_elected_head_transition_scope_chirho, HeadTransitionAuthorityPortChirho,
    HeadTransitionCommitActionChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    issue_elected_writer_fence_for_root_chirho, ConsistencyGroupIdChirho,
};
use std::cell::Cell;
use std::fs::{FileTimes, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy)]
enum TestRouteAuthorityModeChirho {
    LiveChirho,
    AdvanceLifecycleChirho,
    RewriteRouteTailPreservingStatChirho,
}

struct TestRouteElectedAuthorityChirho {
    group_chirho: ConsistencyGroupIdChirho,
    term_chirho: u64,
    mode_chirho: TestRouteAuthorityModeChirho,
    mutation_applied_chirho: Cell<bool>,
}

impl HeadTransitionAuthorityPortChirho for TestRouteElectedAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        if matches!(
            self.mode_chirho,
            TestRouteAuthorityModeChirho::AdvanceLifecycleChirho
        ) {
            let lifecycle_chirho =
                CasLifecycleRootChirho::open_chirho(root_chirho).map_err(anyhow::Error::new)?;
            let mut exclusive_chirho = lifecycle_chirho
                .try_exclusive_chirho()
                .map_err(anyhow::Error::new)?;
            exclusive_chirho
                .advance_generation_before_roots_chirho()
                .map_err(anyhow::Error::new)?;
            drop(exclusive_chirho);
        }
        if matches!(
            self.mode_chirho,
            TestRouteAuthorityModeChirho::RewriteRouteTailPreservingStatChirho
        ) {
            let route_records_path_chirho = root_chirho.join("app-route-records-chirho.jsonl");
            let mut file_chirho = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&route_records_path_chirho)
                .expect("open app-route record log for the planted tail mutation");
            let before_chirho = file_chirho
                .metadata()
                .expect("stat app-route record log before mutation");
            let accessed_chirho = before_chirho
                .accessed()
                .expect("read app-route record access time before mutation");
            let modified_chirho = before_chirho
                .modified()
                .expect("read app-route record modification time before mutation");
            assert!(
                before_chirho.len() > 0,
                "mutation fixture must contain a prior app-route record"
            );
            file_chirho
                .seek(SeekFrom::End(-1))
                .expect("seek to final app-route record newline");
            let mut final_byte_chirho = [0u8; 1];
            std::io::Read::read_exact(&mut file_chirho, &mut final_byte_chirho)
                .expect("read final app-route record byte");
            assert_eq!(
                final_byte_chirho[0], b'\n',
                "mutation anchor must be the unique final JSONL newline"
            );
            file_chirho
                .seek(SeekFrom::End(-1))
                .expect("reseek to final app-route record newline");
            file_chirho
                .write_all(b" ")
                .expect("replace final newline without changing length");
            file_chirho
                .sync_all()
                .expect("persist planted app-route record tail mutation");
            file_chirho
                .set_times(
                    FileTimes::new()
                        .set_accessed(accessed_chirho)
                        .set_modified(modified_chirho),
                )
                .expect("restore timestamps used by the prior stat-only witness");
            let after_chirho = file_chirho
                .metadata()
                .expect("stat app-route record log after mutation");
            assert_eq!(after_chirho.dev(), before_chirho.dev());
            assert_eq!(after_chirho.ino(), before_chirho.ino());
            assert_eq!(after_chirho.len(), before_chirho.len());
            assert_eq!(after_chirho.mtime(), before_chirho.mtime());
            assert_eq!(after_chirho.mtime_nsec(), before_chirho.mtime_nsec());
            let mutated_chirho =
                std::fs::read(&route_records_path_chirho).expect("reread planted tail mutation");
            assert_eq!(
                mutated_chirho.last(),
                Some(&b' '),
                "mutation must apply before the commit-state comparison runs"
            );
            self.mutation_applied_chirho.set(true);
        }
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

struct RefusingRouteAuthorityChirho {
    refusal_chirho: &'static str,
}

impl HeadTransitionAuthorityPortChirho for RefusingRouteAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        _root_chirho: &Path,
        _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        Err(anyhow::anyhow!(self.refusal_chirho))
    }
}

struct ObservedOnlyRouteAuthorityChirho {
    called_chirho: Cell<bool>,
}

impl HeadTransitionAuthorityPortChirho for ObservedOnlyRouteAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        _root_chirho: &Path,
        _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        self.called_chirho.set(true);
        Err(anyhow::anyhow!(
            "NeverLatchedRouteMustNotReachElectedAuthorityChirho"
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AppRouteDeployDurableCountsChirho {
    records_chirho: usize,
    selected_chirho: bool,
    receipts_chirho: usize,
}

fn route_branch_chirho(app_chirho: &str, route_chirho: &str) -> String {
    format!("app-route/{app_chirho}/{route_chirho}")
}

fn route_durable_counts_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
) -> AppRouteDeployDurableCountsChirho {
    let branch_chirho = route_branch_chirho(app_chirho, route_chirho);
    AppRouteDeployDurableCountsChirho {
        records_chirho: verified_app_route_records_chirho(root_chirho)
            .expect("load verified app-route records")
            .len(),
        selected_chirho: refs_chirho::load_refs_chirho(root_chirho)
            .expect("load refs")
            .branches_chirho
            .contains_key(&branch_chirho),
        receipts_chirho: refs_chirho::reflog_chirho(root_chirho)
            .expect("load reflog")
            .into_iter()
            .filter(|entry_chirho| entry_chirho.branch_chirho == branch_chirho)
            .count(),
    }
}

fn route_owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .expect("register owner")
    .principal_chirho
}

fn exact_route_dag_chirho(root_chirho: &Path, label_chirho: &str) -> HashChirho {
    let schema_chirho =
        crate::cas_chirho::add_chirho(root_chirho, format!("{label_chirho}-schema").as_bytes())
            .expect("store port schema");
    let node_chirho = crate::model_chirho::builtin_phi_node_def_chirho(
        &format!("{label_chirho}-phi-chirho"),
        &["input-chirho".to_string()],
        "output-chirho",
        schema_chirho,
    );
    let node_hash_chirho =
        store_chirho::put_object_chirho(root_chirho, &node_chirho).expect("store exact node");
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .expect("store exact route DAG")
}

fn geo_latched_route_fixture_chirho(
    label_chirho: &str,
) -> (PathBuf, String, HashChirho, TestRouteElectedAuthorityChirho) {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    let app_dag_chirho = exact_route_dag_chirho(&root_chirho, &format!("{label_chirho}-app"));
    deploy_app_chirho(
        &root_chirho,
        &format!("{label_chirho}app"),
        app_dag_chirho,
        &owner_chirho,
    )
    .expect("seed the route's selected parent app");
    let route_dag_chirho = exact_route_dag_chirho(&root_chirho, label_chirho);
    migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("offline lifecycle migration before elected serving");
    let initial_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 7)
        .expect("latch elected writer era");
    let authority_chirho = TestRouteElectedAuthorityChirho {
        group_chirho: initial_fence_chirho.group_chirho,
        term_chirho: 7,
        mode_chirho: TestRouteAuthorityModeChirho::LiveChirho,
        mutation_applied_chirho: Cell::new(false),
    };
    (
        root_chirho,
        owner_chirho,
        route_dag_chirho,
        authority_chirho,
    )
}

#[test]
fn never_latched_route_deploy_stays_on_the_existing_local_path_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    let app_dag_chirho = fake_dag_chirho(&root_chirho, b"never latched route parent app");
    deploy_app_chirho(&root_chirho, "localrouteapp", app_dag_chirho, &owner_chirho)
        .expect("seed local parent app");
    let route_dag_chirho = fake_dag_chirho(&root_chirho, b"never latched route DAG");
    let authority_chirho = ObservedOnlyRouteAuthorityChirho {
        called_chirho: Cell::new(false),
    };

    let record_chirho = deploy_app_route_with_head_transition_authority_chirho(
        &root_chirho,
        "localrouteapp",
        "submit",
        route_dag_chirho.clone(),
        &owner_chirho,
        &authority_chirho,
    )
    .expect("never-latched route deploy preserves the local path");

    assert_eq!(record_chirho.dag_chirho, Some(route_dag_chirho));
    assert!(
        !authority_chirho.called_chirho.get(),
        "a never-latched root must remain byte-identical by never entering the elected adapter"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn elected_fresh_route_deploy_publishes_exactly_one_row_ref_and_receipt_chirho() {
    let (root_chirho, owner_chirho, route_dag_chirho, authority_chirho) =
        geo_latched_route_fixture_chirho("freshroute");
    let before_chirho = route_durable_counts_chirho(&root_chirho, "freshrouteapp", "submit");

    let record_chirho = deploy_app_route_with_head_transition_authority_chirho(
        &root_chirho,
        "freshrouteapp",
        "submit",
        route_dag_chirho.clone(),
        &owner_chirho,
        &authority_chirho,
    )
    .expect("live same-root elected authority commits one route deploy");

    assert_eq!(
        before_chirho,
        AppRouteDeployDurableCountsChirho {
            records_chirho: 0,
            selected_chirho: false,
            receipts_chirho: 0,
        }
    );
    assert_eq!(record_chirho.dag_chirho, Some(route_dag_chirho));
    assert_eq!(
        route_durable_counts_chirho(&root_chirho, "freshrouteapp", "submit"),
        AppRouteDeployDurableCountsChirho {
            records_chirho: 1,
            selected_chirho: true,
            receipts_chirho: 1,
        }
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn elected_authority_refusals_precede_every_route_durable_output_chirho() {
    let cases_chirho = [
        (
            "deposedroute",
            "ElectedAuthorityDeposedChirho",
            "ElectedAuthorityLeaseExpiredChirho",
        ),
        (
            "expiredroute",
            "ElectedAuthorityLeaseExpiredChirho",
            "ElectedAuthorityDeposedChirho",
        ),
        (
            "wrongrootroute",
            "ElectedAuthorityWrongRootChirho",
            "ElectedAuthorityWrongGroupChirho",
        ),
        (
            "wronggrouproute",
            "ElectedAuthorityWrongGroupChirho",
            "ElectedAuthorityWrongRootChirho",
        ),
    ];
    for (label_chirho, expected_chirho, neighbor_chirho) in cases_chirho {
        let (root_chirho, owner_chirho, route_dag_chirho, _live_chirho) =
            geo_latched_route_fixture_chirho(label_chirho);
        let authority_chirho = RefusingRouteAuthorityChirho {
            refusal_chirho: expected_chirho,
        };
        let app_chirho = format!("{label_chirho}app");
        let before_chirho = route_durable_counts_chirho(&root_chirho, &app_chirho, "submit");

        let error_chirho = deploy_app_route_with_head_transition_authority_chirho(
            &root_chirho,
            &app_chirho,
            "submit",
            route_dag_chirho,
            &owner_chirho,
            &authority_chirho,
        )
        .expect_err("unsafe elected authority must refuse before route output")
        .to_string();

        assert!(error_chirho.contains(expected_chirho), "{error_chirho}");
        assert!(
            !error_chirho.contains(neighbor_chirho),
            "failure means the refusal identities collapsed; preserve the named authority cause: {error_chirho}"
        );
        assert_eq!(
            route_durable_counts_chirho(&root_chirho, &app_chirho, "submit"),
            before_chirho,
            "failure means a refusal wrote an app-route row, ref, or receipt; keep all mutations behind the elected callback"
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

#[test]
fn route_lifecycle_generation_drift_refuses_before_row_ref_or_receipt_chirho() {
    let (root_chirho, owner_chirho, route_dag_chirho, mut authority_chirho) =
        geo_latched_route_fixture_chirho("routelifecycle");
    authority_chirho.mode_chirho = TestRouteAuthorityModeChirho::AdvanceLifecycleChirho;
    let before_chirho = route_durable_counts_chirho(&root_chirho, "routelifecycleapp", "submit");

    let error_chirho = deploy_app_route_with_head_transition_authority_chirho(
        &root_chirho,
        "routelifecycleapp",
        "submit",
        route_dag_chirho,
        &owner_chirho,
        &authority_chirho,
    )
    .expect_err("generation drift must fail route F4 promotion");
    let chain_chirho = format!("{error_chirho:#}");

    assert!(
        chain_chirho.contains("AppRouteDeployCasLifecyclePromotionRefusedChirho"),
        "{chain_chirho}"
    );
    assert!(
        chain_chirho.contains("CasLifecycleStaleChirho"),
        "{chain_chirho}"
    );
    assert_eq!(
        route_durable_counts_chirho(&root_chirho, "routelifecycleapp", "submit"),
        before_chirho,
        "failure means lifecycle promotion moved behind a durable route output"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn route_same_stat_tail_rewrite_refuses_before_row_ref_or_receipt_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    let app_dag_chirho = exact_route_dag_chirho(&root_chirho, "route-tail-parent");
    deploy_app_chirho(&root_chirho, "routetailapp", app_dag_chirho, &owner_chirho)
        .expect("seed parent app");
    let prior_route_dag_chirho = exact_route_dag_chirho(&root_chirho, "route-tail-prior");
    deploy_app_route_chirho(
        &root_chirho,
        "routetailapp",
        "prior",
        prior_route_dag_chirho,
        &owner_chirho,
    )
    .expect("seed one signed route record before the elected era");
    let target_route_dag_chirho = exact_route_dag_chirho(&root_chirho, "route-tail-target");
    migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("offline lifecycle migration before elected serving");
    let initial_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 13)
        .expect("latch elected writer era");
    let authority_chirho = TestRouteElectedAuthorityChirho {
        group_chirho: initial_fence_chirho.group_chirho,
        term_chirho: 13,
        mode_chirho: TestRouteAuthorityModeChirho::RewriteRouteTailPreservingStatChirho,
        mutation_applied_chirho: Cell::new(false),
    };
    let before_chirho = route_durable_counts_chirho(&root_chirho, "routetailapp", "target");

    let error_chirho = deploy_app_route_with_head_transition_authority_chirho(
        &root_chirho,
        "routetailapp",
        "target",
        target_route_dag_chirho,
        &owner_chirho,
        &authority_chirho,
    )
    .expect_err("a changed terminal route line must invalidate the prepared evidence")
    .to_string();

    assert!(
        authority_chirho.mutation_applied_chirho.get(),
        "failure means the mutation did not run; keep the planted same-stat rewrite ahead of COMMIT"
    );
    assert!(
        error_chirho.contains("AppRouteDeployPreparedStateChangedChirho"),
        "{error_chirho}"
    );
    assert!(
        !error_chirho.contains("AppRouteDeployCasLifecyclePromotionRefusedChirho"),
        "failure means the route-tail witness lost its refusal identity: {error_chirho}"
    );
    assert_eq!(
        route_durable_counts_chirho(&root_chirho, "routetailapp", "target"),
        before_chirho,
        "failure means the tail-evidence refusal appended the target row, ref, or receipt"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pending_route_transition_named_refuses_without_prepare_recovery_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    let app_dag_chirho = exact_route_dag_chirho(&root_chirho, "pending-route-parent");
    deploy_app_chirho(
        &root_chirho,
        "pendingrouteapp",
        app_dag_chirho,
        &owner_chirho,
    )
    .expect("seed parent app");
    let route_dag_chirho = exact_route_dag_chirho(&root_chirho, "pending-route");
    let state_chirho = AppRouteAuthorityStateChirho {
        schema_chirho: APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO.to_string(),
        app_chirho: "pendingrouteapp".to_string(),
        route_chirho: "submit".to_string(),
        owner_principal_chirho: owner_chirho.clone(),
        dag_chirho: route_dag_chirho.clone(),
        action_chirho: AppRouteActionChirho::DeployRouteChirho,
        request_body_policy_chirho: None,
    };
    cairn_app_control_chirho::append_pending_app_route_for_test_chirho(
        &RootAppRouteAuthorityPortChirho,
        &root_chirho,
        &state_chirho,
        None,
    )
    .expect("seed one unreceipted route transition");
    migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("offline lifecycle migration before elected serving");
    let initial_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 17)
        .expect("latch elected writer era");
    let authority_chirho = TestRouteElectedAuthorityChirho {
        group_chirho: initial_fence_chirho.group_chirho,
        term_chirho: 17,
        mode_chirho: TestRouteAuthorityModeChirho::LiveChirho,
        mutation_applied_chirho: Cell::new(false),
    };
    let before_chirho = route_durable_counts_chirho(&root_chirho, "pendingrouteapp", "submit");
    assert!(
        before_chirho.records_chirho > 0
            && !before_chirho.selected_chirho
            && before_chirho.receipts_chirho == 0,
        "the pending fixture must start with a real unreceipted row; failure means this arm could \
         pass vacuously without exercising the elected refusal"
    );

    let error_chirho = deploy_app_route_with_head_transition_authority_chirho(
        &root_chirho,
        "pendingrouteapp",
        "submit",
        route_dag_chirho,
        &owner_chirho,
        &authority_chirho,
    )
    .expect_err("PREPARE must not repair an unreceipted route transition")
    .to_string();

    assert!(
        error_chirho.contains("AppRouteDeployPendingHeadTransitionChirho"),
        "{error_chirho}"
    );
    assert!(
        !error_chirho.contains("AppRouteDeployHeadRemovalSettlementRequiredChirho"),
        "failure means the pending positive-transition refusal lost its identity: {error_chirho}"
    );
    assert_eq!(
        route_durable_counts_chirho(&root_chirho, "pendingrouteapp", "submit"),
        before_chirho,
        "failure means PREPARE repaired or duplicated the pending route transition"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn prior_route_tombstone_named_refuses_without_placeholder_settlement_proof_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    let app_dag_chirho = exact_route_dag_chirho(&root_chirho, "removed-route-parent");
    deploy_app_chirho(
        &root_chirho,
        "removedrouteapp",
        app_dag_chirho,
        &owner_chirho,
    )
    .expect("seed parent app");
    let first_route_dag_chirho = exact_route_dag_chirho(&root_chirho, "removed-route-first");
    deploy_app_route_chirho(
        &root_chirho,
        "removedrouteapp",
        "submit",
        first_route_dag_chirho,
        &owner_chirho,
    )
    .expect("local-era first route deploy");
    assert!(
        undeploy_app_route_chirho(&root_chirho, "removedrouteapp", "submit", &owner_chirho,)
            .expect("local-era route removal")
    );
    let replacement_dag_chirho = exact_route_dag_chirho(&root_chirho, "removed-route-replacement");
    migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("offline lifecycle migration before elected serving");
    let initial_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 11)
        .expect("latch elected writer era");
    let authority_chirho = TestRouteElectedAuthorityChirho {
        group_chirho: initial_fence_chirho.group_chirho,
        term_chirho: 11,
        mode_chirho: TestRouteAuthorityModeChirho::LiveChirho,
        mutation_applied_chirho: Cell::new(false),
    };
    let before_chirho = route_durable_counts_chirho(&root_chirho, "removedrouteapp", "submit");

    let error_chirho = deploy_app_route_with_head_transition_authority_chirho(
        &root_chirho,
        "removedrouteapp",
        "submit",
        replacement_dag_chirho,
        &owner_chirho,
        &authority_chirho,
    )
    .expect_err("a prior route tombstone needs the real settlement-proof mint")
    .to_string();

    assert!(
        error_chirho.contains("AppRouteDeployHeadRemovalSettlementRequiredChirho"),
        "{error_chirho}"
    );
    assert!(
        !error_chirho.contains("AppRouteDeployPendingHeadTransitionChirho"),
        "failure means the route tombstone refusal lost its identity: {error_chirho}"
    );
    assert_eq!(
        route_durable_counts_chirho(&root_chirho, "removedrouteapp", "submit"),
        before_chirho,
        "failure means the route tombstone refusal appended a replacement row/ref/receipt"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// Raw bytes of a root-level family log, or `None` when absent. Byte-exact rather than a parsed
/// count, so ANY append or rewrite shows — including one that leaves the row count unchanged.
fn family_log_bytes_chirho(root_chirho: &Path, name_chirho: &str) -> Option<Vec<u8>> {
    std::fs::read(root_chirho.join(name_chirho)).ok()
}

/// **A refused route deploy must leave the APP and REMOVAL families untouched, not only the route
/// family.**
///
/// Reviewer-chosen arm (claude_chirho, S2 adversarial review — independent of the mover's pins).
///
/// `route_durable_counts_chirho` measures the ROUTE family only: verified route records, the route
/// branch, and reflog entries filtered to that branch. But the ZR-2b Z8 census established that the
/// route door also touches **`app-records-chirho.jsonl`** (through app head-removal recovery,
/// `app_head_removal_chirho.rs:27`) and **`head-removals-chirho.jsonl`**
/// (`head_removal_chirho.rs:58`) — and the door runs removal recovery on EVERY deploy, not only
/// when something is being removed.
///
/// S2's PREPARE is aware of both: `capture_mutable_state_chirho` fingerprints them. **What is not
/// pinned is the refusal path.** A refusal that appended to either family would leave every
/// route-scoped counter identical and the existing arms green — the mover's pins cannot reveal a
/// leak into a family the mover's counter does not read.
///
/// Bytes rather than counts, because a same-length rewrite is exactly the mutation a count misses;
/// this is the twin of the same-stat terminal-line case S1 and S2 both guard on the success path.
///
/// MIGRATION PATH: if this fails, a refusal wrote outside the route family. Do NOT widen the
/// expected bytes — find which surface moved and why it moved before authority was granted.
#[test]
fn refused_route_deploy_leaves_the_app_and_removal_families_byte_identical_chirho() {
    let (root_chirho, owner_chirho, route_dag_chirho, _live_chirho) =
        geo_latched_route_fixture_chirho("crossfamily");
    let app_chirho = "crossfamilyapp".to_string();

    let app_records_before_chirho =
        family_log_bytes_chirho(&root_chirho, "app-records-chirho.jsonl");
    let removals_before_chirho =
        family_log_bytes_chirho(&root_chirho, "head-removals-chirho.jsonl");
    // NON-VACUITY: the app family must be non-empty, or "unchanged" is a claim about nothing.
    assert!(
        app_records_before_chirho
            .as_ref()
            .is_some_and(|bytes_chirho| !bytes_chirho.is_empty()),
        "fixture precondition: the parent app deploy must have written app-records rows"
    );

    let authority_chirho = RefusingRouteAuthorityChirho {
        refusal_chirho: "ElectedAuthorityDeposedChirho",
    };
    let error_chirho = deploy_app_route_with_head_transition_authority_chirho(
        &root_chirho,
        &app_chirho,
        "submit",
        route_dag_chirho,
        &owner_chirho,
        &authority_chirho,
    )
    .expect_err("a deposed elected authority must refuse before any route output")
    .to_string();
    assert!(
        error_chirho.contains("ElectedAuthorityDeposedChirho"),
        "fixture precondition: the refusal must be the named authority refusal: {error_chirho}"
    );

    assert_eq!(
        family_log_bytes_chirho(&root_chirho, "app-records-chirho.jsonl"),
        app_records_before_chirho,
        "a refused ROUTE deploy wrote into the APP family; the route-scoped counters cannot see this"
    );
    assert_eq!(
        family_log_bytes_chirho(&root_chirho, "head-removals-chirho.jsonl"),
        removals_before_chirho,
        "a refused ROUTE deploy wrote into the REMOVAL family; removal recovery runs on every deploy, so this is reachable"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
