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
enum TestAuthorityModeChirho {
    LiveChirho,
    AdvanceLifecycleChirho,
    RewriteAppTailPreservingStatChirho,
}

struct TestElectedAuthorityChirho {
    group_chirho: ConsistencyGroupIdChirho,
    term_chirho: u64,
    mode_chirho: TestAuthorityModeChirho,
    mutation_applied_chirho: Cell<bool>,
}

impl HeadTransitionAuthorityPortChirho for TestElectedAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        if matches!(
            self.mode_chirho,
            TestAuthorityModeChirho::AdvanceLifecycleChirho
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
            TestAuthorityModeChirho::RewriteAppTailPreservingStatChirho
        ) {
            let app_records_path_chirho = app_records_path_chirho(root_chirho);
            let mut file_chirho = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&app_records_path_chirho)
                .expect("open app record log for the planted tail mutation");
            let before_chirho = file_chirho
                .metadata()
                .expect("stat app record log before mutation");
            let accessed_chirho = before_chirho
                .accessed()
                .expect("read app record access time before mutation");
            let modified_chirho = before_chirho
                .modified()
                .expect("read app record modification time before mutation");
            assert!(
                before_chirho.len() > 0,
                "mutation fixture must contain a prior app record"
            );
            file_chirho
                .seek(SeekFrom::End(-1))
                .expect("seek to final app record newline");
            let mut final_byte_chirho = [0u8; 1];
            std::io::Read::read_exact(&mut file_chirho, &mut final_byte_chirho)
                .expect("read final app record byte");
            assert_eq!(
                final_byte_chirho[0], b'\n',
                "mutation anchor must be the unique final JSONL newline"
            );
            file_chirho
                .seek(SeekFrom::End(-1))
                .expect("reseek to final app record newline");
            file_chirho
                .write_all(b" ")
                .expect("replace final newline without changing length");
            file_chirho
                .sync_all()
                .expect("persist planted app record tail mutation");
            file_chirho
                .set_times(
                    FileTimes::new()
                        .set_accessed(accessed_chirho)
                        .set_modified(modified_chirho),
                )
                .expect("restore timestamps used by the prior stat-only witness");
            let after_chirho = file_chirho
                .metadata()
                .expect("stat app record log after mutation");
            assert_eq!(after_chirho.dev(), before_chirho.dev());
            assert_eq!(after_chirho.ino(), before_chirho.ino());
            assert_eq!(after_chirho.len(), before_chirho.len());
            assert_eq!(after_chirho.mtime(), before_chirho.mtime());
            assert_eq!(after_chirho.mtime_nsec(), before_chirho.mtime_nsec());
            let mutated_chirho =
                std::fs::read(&app_records_path_chirho).expect("reread planted tail mutation");
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

struct RefusingAuthorityChirho {
    refusal_chirho: &'static str,
}

impl HeadTransitionAuthorityPortChirho for RefusingAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        _root_chirho: &Path,
        _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        Err(anyhow::anyhow!(self.refusal_chirho))
    }
}

struct ObservedOnlyAuthorityChirho {
    called_chirho: Cell<bool>,
}

impl HeadTransitionAuthorityPortChirho for ObservedOnlyAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        _root_chirho: &Path,
        _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        self.called_chirho.set(true);
        Err(anyhow::anyhow!(
            "NeverLatchedRootMustNotReachElectedAuthorityChirho"
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AppDeployDurableCountsChirho {
    records_chirho: usize,
    selected_chirho: bool,
    receipts_chirho: usize,
}

fn durable_counts_chirho(root_chirho: &Path, app_chirho: &str) -> AppDeployDurableCountsChirho {
    AppDeployDurableCountsChirho {
        records_chirho: verified_app_records_chirho(root_chirho)
            .expect("load verified app records")
            .len(),
        selected_chirho: refs_chirho::load_refs_chirho(root_chirho)
            .expect("load refs")
            .branches_chirho
            .contains_key(&app_branch_ref_name_chirho(app_chirho)),
        receipts_chirho: refs_chirho::reflog_chirho(root_chirho)
            .expect("load reflog")
            .into_iter()
            .filter(|entry_chirho| {
                entry_chirho.branch_chirho == app_branch_ref_name_chirho(app_chirho)
            })
            .count(),
    }
}

fn owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .expect("register owner")
    .principal_chirho
}

fn exact_dag_chirho(root_chirho: &Path, label_chirho: &str) -> HashChirho {
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
    .expect("store exact DAG")
}

fn geo_latched_fixture_chirho(
    label_chirho: &str,
) -> (PathBuf, String, HashChirho, TestElectedAuthorityChirho) {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = exact_dag_chirho(&root_chirho, label_chirho);
    migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("offline lifecycle migration before elected serving");
    let initial_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 7)
        .expect("latch elected writer era");
    let authority_chirho = TestElectedAuthorityChirho {
        group_chirho: initial_fence_chirho.group_chirho,
        term_chirho: 7,
        mode_chirho: TestAuthorityModeChirho::LiveChirho,
        mutation_applied_chirho: Cell::new(false),
    };
    (root_chirho, owner_chirho, dag_chirho, authority_chirho)
}

#[test]
fn never_latched_deploy_stays_on_the_existing_local_path_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"never latched local DAG");
    let authority_chirho = ObservedOnlyAuthorityChirho {
        called_chirho: Cell::new(false),
    };

    let record_chirho = deploy_app_with_head_transition_authority_chirho(
        &root_chirho,
        "localpath",
        dag_chirho.clone(),
        &owner_chirho,
        &authority_chirho,
    )
    .expect("never-latched deploy preserves the local path");

    assert_eq!(record_chirho.dag_chirho, Some(dag_chirho));
    assert!(
        !authority_chirho.called_chirho.get(),
        "a never-latched root must remain byte-identical by never entering the elected adapter"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn elected_fresh_deploy_publishes_exactly_one_row_ref_and_receipt_chirho() {
    let (root_chirho, owner_chirho, dag_chirho, authority_chirho) =
        geo_latched_fixture_chirho("fresh-elected");
    let before_chirho = durable_counts_chirho(&root_chirho, "freshgeo");

    let record_chirho = deploy_app_with_head_transition_authority_chirho(
        &root_chirho,
        "freshgeo",
        dag_chirho.clone(),
        &owner_chirho,
        &authority_chirho,
    )
    .expect("live same-root elected authority commits one deploy");

    assert_eq!(
        before_chirho,
        AppDeployDurableCountsChirho {
            records_chirho: 0,
            selected_chirho: false,
            receipts_chirho: 0,
        }
    );
    assert_eq!(record_chirho.dag_chirho, Some(dag_chirho));
    assert_eq!(
        durable_counts_chirho(&root_chirho, "freshgeo"),
        AppDeployDurableCountsChirho {
            records_chirho: 1,
            selected_chirho: true,
            receipts_chirho: 1,
        }
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn elected_authority_refusals_precede_every_app_durable_output_chirho() {
    let cases_chirho = [
        (
            "deposed",
            "ElectedAuthorityDeposedChirho",
            "ElectedAuthorityLeaseExpiredChirho",
        ),
        (
            "expired",
            "ElectedAuthorityLeaseExpiredChirho",
            "ElectedAuthorityDeposedChirho",
        ),
        (
            "wrongroot",
            "ElectedAuthorityWrongRootChirho",
            "ElectedAuthorityWrongGroupChirho",
        ),
        (
            "wronggroup",
            "ElectedAuthorityWrongGroupChirho",
            "ElectedAuthorityWrongRootChirho",
        ),
    ];
    for (label_chirho, expected_chirho, neighbor_chirho) in cases_chirho {
        let (root_chirho, owner_chirho, dag_chirho, _live_chirho) =
            geo_latched_fixture_chirho(label_chirho);
        let authority_chirho = RefusingAuthorityChirho {
            refusal_chirho: expected_chirho,
        };
        let before_chirho = durable_counts_chirho(&root_chirho, label_chirho);

        let error_chirho = deploy_app_with_head_transition_authority_chirho(
            &root_chirho,
            label_chirho,
            dag_chirho,
            &owner_chirho,
            &authority_chirho,
        )
        .expect_err("unsafe elected authority must refuse before app output")
        .to_string();

        assert!(error_chirho.contains(expected_chirho), "{error_chirho}");
        assert!(
            !error_chirho.contains(neighbor_chirho),
            "failure means the refusal identities collapsed; preserve the named authority cause: {error_chirho}"
        );
        assert_eq!(
            durable_counts_chirho(&root_chirho, label_chirho),
            before_chirho,
            "failure means a refusal wrote an app row, ref, or receipt; keep all mutations behind the elected callback"
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

#[test]
fn lifecycle_generation_drift_refuses_before_row_ref_or_receipt_chirho() {
    let (root_chirho, owner_chirho, dag_chirho, mut authority_chirho) =
        geo_latched_fixture_chirho("lifecycle-drift");
    authority_chirho.mode_chirho = TestAuthorityModeChirho::AdvanceLifecycleChirho;
    let before_chirho = durable_counts_chirho(&root_chirho, "lifecyclestale");

    let error_chirho = deploy_app_with_head_transition_authority_chirho(
        &root_chirho,
        "lifecyclestale",
        dag_chirho,
        &owner_chirho,
        &authority_chirho,
    )
    .expect_err("generation drift must fail F4 promotion");
    let chain_chirho = format!("{error_chirho:#}");

    assert!(
        chain_chirho.contains("AppDeployCasLifecyclePromotionRefusedChirho"),
        "{chain_chirho}"
    );
    assert!(
        chain_chirho.contains("CasLifecycleStaleChirho"),
        "{chain_chirho}"
    );
    assert_eq!(
        durable_counts_chirho(&root_chirho, "lifecyclestale"),
        before_chirho,
        "failure means lifecycle promotion moved behind a durable app output"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn same_stat_tail_rewrite_refuses_before_row_ref_or_receipt_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let prior_dag_chirho = exact_dag_chirho(&root_chirho, "tail-witness-prior");
    deploy_app_chirho(
        &root_chirho,
        "tailwitnessprior",
        prior_dag_chirho,
        &owner_chirho,
    )
    .expect("seed one signed app record before the elected era");
    let target_dag_chirho = exact_dag_chirho(&root_chirho, "tail-witness-target");
    migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("offline lifecycle migration before elected serving");
    let initial_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 13)
        .expect("latch elected writer era");
    let authority_chirho = TestElectedAuthorityChirho {
        group_chirho: initial_fence_chirho.group_chirho,
        term_chirho: 13,
        mode_chirho: TestAuthorityModeChirho::RewriteAppTailPreservingStatChirho,
        mutation_applied_chirho: Cell::new(false),
    };
    let before_chirho = durable_counts_chirho(&root_chirho, "tailwitnesstarget");

    let error_chirho = deploy_app_with_head_transition_authority_chirho(
        &root_chirho,
        "tailwitnesstarget",
        target_dag_chirho,
        &owner_chirho,
        &authority_chirho,
    )
    .expect_err("a changed terminal line must invalidate the prepared app evidence")
    .to_string();

    assert!(
        authority_chirho.mutation_applied_chirho.get(),
        "failure means the mutation did not run; keep the planted same-stat rewrite ahead of COMMIT"
    );
    assert!(
        error_chirho.contains("AppDeployPreparedStateChangedChirho"),
        "{error_chirho}"
    );
    assert!(
        !error_chirho.contains("AppDeployCasLifecyclePromotionRefusedChirho"),
        "failure means the tail witness lost its refusal identity: {error_chirho}"
    );
    assert_eq!(
        durable_counts_chirho(&root_chirho, "tailwitnesstarget"),
        before_chirho,
        "failure means the tail-evidence refusal appended the target row, ref, or receipt"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn prior_tombstone_named_refuses_without_placeholder_settlement_proof_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let first_dag_chirho = exact_dag_chirho(&root_chirho, "removed-first");
    deploy_app_chirho(&root_chirho, "removedapp", first_dag_chirho, &owner_chirho)
        .expect("local-era first deploy");
    assert!(
        undeploy_app_chirho(&root_chirho, "removedapp", &owner_chirho).expect("local-era removal")
    );
    let replacement_dag_chirho = exact_dag_chirho(&root_chirho, "removed-replacement");
    migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("offline lifecycle migration before elected serving");
    let initial_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 11)
        .expect("latch elected writer era");
    let authority_chirho = TestElectedAuthorityChirho {
        group_chirho: initial_fence_chirho.group_chirho,
        term_chirho: 11,
        mode_chirho: TestAuthorityModeChirho::LiveChirho,
        mutation_applied_chirho: Cell::new(false),
    };
    let before_chirho = durable_counts_chirho(&root_chirho, "removedapp");

    let error_chirho = deploy_app_with_head_transition_authority_chirho(
        &root_chirho,
        "removedapp",
        replacement_dag_chirho,
        &owner_chirho,
        &authority_chirho,
    )
    .expect_err("a prior tombstone needs the real settlement-proof mint")
    .to_string();

    assert!(
        error_chirho.contains("AppDeployHeadRemovalSettlementRequiredChirho"),
        "{error_chirho}"
    );
    assert!(
        !error_chirho.contains("AppDeployPendingHeadTransitionChirho"),
        "failure means the tombstone refusal lost its identity: {error_chirho}"
    );
    assert_eq!(
        durable_counts_chirho(&root_chirho, "removedapp"),
        before_chirho,
        "failure means the tombstone refusal appended a replacement row/ref/receipt"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
