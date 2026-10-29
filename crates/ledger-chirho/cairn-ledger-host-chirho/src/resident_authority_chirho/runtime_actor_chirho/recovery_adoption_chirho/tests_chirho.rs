// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::reconciliation_chirho::{
    gd7_winner_handoff_head_path_chirho, ExistingNodeGd7SignerChirho,
    Gd7WinnerHandoffStoreRefusalChirho,
};
use crate::resident_authority_chirho::runtime_actor_chirho::winner_handoff_chirho::ResidentGd7WinnerHandoffRefusalChirho;
use crate::tests_chirho::{
    resident_mint_request_chirho, warm_single_node_elector_chirho,
    with_bound_resident_fixture_chirho,
};
use crate::{
    FsLedgerStorageChirho, ResidentLedgerAppendPermitChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerLocalPortsChirho,
};
use cairn_ledger_log_chirho::append_mirror_chirho::LedgerAppendMirrorTailChirho;
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorPrefixSourceChirho, LedgerMirrorRecoveryCandidateInputChirho,
    LedgerMirrorRecoveryPortErrorChirho, RawCanonicalGroupIdDigestChirho,
};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityHandleChirho, LocalAppendHandoffControlHandleChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

const TEST_AUTHORITY_REVOKED_CHIRHO: &str = "LedgerMirrorRecoveryAuthorityRevokedForTestChirho";

struct TestRecoveryPortChirho {
    candidate_chirho: LedgerMirrorRecoveryCandidateChirho,
    records_chirho: BTreeMap<u64, Vec<u8>>,
    revalidation_count_chirho: AtomicUsize,
    deny_on_call_chirho: AtomicUsize,
}

impl TestRecoveryPortChirho {
    fn new_chirho(
        candidate_chirho: LedgerMirrorRecoveryCandidateChirho,
        records_chirho: BTreeMap<u64, Vec<u8>>,
    ) -> Self {
        Self {
            candidate_chirho,
            records_chirho,
            revalidation_count_chirho: AtomicUsize::new(0),
            deny_on_call_chirho: AtomicUsize::new(0),
        }
    }

    fn deny_on_revalidation_chirho(&self, call_chirho: usize) {
        self.revalidation_count_chirho.store(0, Ordering::SeqCst);
        self.deny_on_call_chirho
            .store(call_chirho, Ordering::SeqCst);
    }

    fn permit_revalidation_chirho(&self) {
        self.revalidation_count_chirho.store(0, Ordering::SeqCst);
        self.deny_on_call_chirho.store(0, Ordering::SeqCst);
    }

    /// Revalidations asked of this port since it was built or last reset. Each recovery revalidation
    /// attempt asks once before anything local, and once more if it acquires the local guard (A6-c).
    fn revalidation_calls_chirho(&self) -> usize {
        self.revalidation_count_chirho.load(Ordering::SeqCst)
    }
}

impl LedgerMirrorRecoveryPortChirho for TestRecoveryPortChirho {
    fn select_recovery_candidate_chirho(
        &self,
        _local_tail_chirho: &LedgerAppendMirrorTailChirho,
        _local_source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> std::result::Result<
        Option<LedgerMirrorRecoveryCandidateChirho>,
        LedgerMirrorRecoveryPortErrorChirho,
    > {
        Ok(Some(self.candidate_chirho.clone()))
    }

    fn revalidate_recovery_authority_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    ) -> std::result::Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        if candidate_chirho != &self.candidate_chirho {
            return Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorRecoveryTestCandidateChangedChirho",
            ));
        }
        let call_chirho = self
            .revalidation_count_chirho
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        if self.deny_on_call_chirho.load(Ordering::SeqCst) == call_chirho {
            return Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                TEST_AUTHORITY_REVOKED_CHIRHO,
            ));
        }
        Ok(())
    }

    fn read_recovery_record_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
        seq_chirho: u64,
        record_digest_chirho: &str,
    ) -> std::result::Result<Vec<u8>, LedgerMirrorRecoveryPortErrorChirho> {
        if candidate_chirho != &self.candidate_chirho {
            return Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorRecoveryTestCandidateChangedChirho",
            ));
        }
        let bytes_chirho = self.records_chirho.get(&seq_chirho).ok_or_else(|| {
            LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorRecoveryTestRecordMissingChirho",
            )
        })?;
        let line_chirho = std::str::from_utf8(bytes_chirho).map_err(|_| {
            LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorRecoveryTestRecordUtf8RefusedChirho",
            )
        })?;
        if stored_line_digest_chirho(line_chirho).0 != record_digest_chirho {
            return Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorRecoveryTestRecordDigestMismatchChirho",
            ));
        }
        Ok(bytes_chirho.clone())
    }

    fn ensure_verified_prefix_bootstrapped_chirho(
        &self,
        _source_tail_chirho: &LedgerAppendMirrorTailChirho,
        _source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> std::result::Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        Ok(())
    }
}

fn journal_ports_chirho(
    ports_chirho: ResidentLedgerLocalPortsChirho<'_>,
) -> JournalPortsChirho<'_> {
    JournalPortsChirho {
        storage_chirho: ports_chirho.storage_chirho,
        signer_chirho: ports_chirho.signer_chirho,
        clock_chirho: ports_chirho.clock_chirho,
        membership_chirho: ports_chirho.membership_chirho,
        kind_registry_chirho: ports_chirho.kind_registry_chirho,
        authority_chirho: ports_chirho.authority_chirho,
    }
}

fn candidate_with_group_digest_chirho(
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    consistency_group_digest_chirho: RawCanonicalGroupIdDigestChirho,
) -> LedgerMirrorRecoveryCandidateChirho {
    candidate_edited_chirho(candidate_chirho, |input_chirho| {
        input_chirho.consistency_group_digest_chirho = consistency_group_digest_chirho;
    })
}

/// Rebuild a candidate from its own port evidence with one edit applied.
fn candidate_edited_chirho(
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    edit_chirho: impl FnOnce(&mut LedgerMirrorRecoveryCandidateInputChirho),
) -> LedgerMirrorRecoveryCandidateChirho {
    let mut input_chirho = LedgerMirrorRecoveryCandidateInputChirho {
        consistency_group_digest_chirho: candidate_chirho.consistency_group_digest_chirho().clone(),
        assignment_digest_chirho: candidate_chirho.assignment_digest_chirho().to_string(),
        historical_leader_node_id_chirho: candidate_chirho
            .historical_leader_node_id_chirho()
            .to_string(),
        holder_node_ids_chirho: candidate_chirho.holder_node_ids_chirho().clone(),
        historical_term_chirho: candidate_chirho.historical_term_chirho(),
        historical_membership_view_digest_chirho: candidate_chirho
            .historical_membership_view_digest_chirho()
            .to_string(),
        cluster_id_chirho: candidate_chirho.cluster_id_chirho().to_string(),
        journal_genesis_digest_chirho: candidate_chirho.journal_genesis_digest_chirho().to_string(),
        tail_seq_chirho: candidate_chirho.tail_seq_chirho(),
        tail_record_digest_chirho: candidate_chirho.tail_record_digest_chirho().to_string(),
        tail_epoch_chirho: candidate_chirho.tail_epoch_chirho(),
        tail_hlc_chirho: candidate_chirho.tail_hlc_chirho().clone(),
        current_term_chirho: candidate_chirho.current_term_chirho(),
        current_membership_view_digest_chirho: candidate_chirho
            .current_membership_view_digest_chirho()
            .to_string(),
        holder_receipt_digests_chirho: candidate_chirho.holder_receipt_digests_chirho().clone(),
        holder_receipt_wires_chirho: candidate_chirho.holder_receipt_wires_chirho().clone(),
    };
    edit_chirho(&mut input_chirho);
    LedgerMirrorRecoveryCandidateChirho::from_port_evidence_chirho(input_chirho).unwrap()
}

/// Everything a recovery staging arm can reach, by name. `elector_chirho` is the elector the local
/// authority belongs to, so an arm can drive a real local transition against the authority that the
/// effect context revalidates.
struct StagingFixtureChirho<'fixture_chirho> {
    elector_chirho: &'fixture_chirho RaftWriterElectorChirho,
    storage_chirho: &'fixture_chirho FsLedgerStorageChirho,
    recovery_chirho: &'fixture_chirho TestRecoveryPortChirho,
    candidate_chirho: &'fixture_chirho LedgerMirrorRecoveryCandidateChirho,
    binding_digest_chirho: &'fixture_chirho str,
    gd7_store_chirho: &'fixture_chirho Gd7WinnerHandoffStoreChirho<'fixture_chirho>,
    handoff_control_chirho: &'fixture_chirho LocalAppendHandoffControlHandleChirho,
    local_authority_chirho: &'fixture_chirho LocalAppendAuthorityHandleChirho,
    journal_ports_chirho: JournalPortsChirho<'fixture_chirho>,
    cluster_chirho: &'fixture_chirho ClusterIdChirho,
    canonical_genesis_line_chirho: &'fixture_chirho str,
    source_path_chirho: &'fixture_chirho StoragePathChirho,
    original_journal_bytes_chirho: &'fixture_chirho [u8],
    group_chirho: &'fixture_chirho ConsistencyGroupIdChirho,
    tail_chirho: &'fixture_chirho LedgerAppendMirrorTailChirho,
}

/// The positional form the first staging arms were written against.
#[allow(clippy::too_many_arguments)]
fn with_staging_fixture_chirho(
    label_chirho: &str,
    action_chirho: impl FnOnce(
        &FsLedgerStorageChirho,
        &TestRecoveryPortChirho,
        &LedgerMirrorRecoveryCandidateChirho,
        &str,
        &Gd7WinnerHandoffStoreChirho<'_>,
        &LocalAppendHandoffControlHandleChirho,
        &LocalAppendAuthorityHandleChirho,
        JournalPortsChirho<'_>,
        &ClusterIdChirho,
        &str,
        &StoragePathChirho,
        &[u8],
        &ConsistencyGroupIdChirho,
        &LedgerAppendMirrorTailChirho,
    ),
) {
    with_staging_fixture_named_chirho(label_chirho, |fixture_chirho| {
        action_chirho(
            fixture_chirho.storage_chirho,
            fixture_chirho.recovery_chirho,
            fixture_chirho.candidate_chirho,
            fixture_chirho.binding_digest_chirho,
            fixture_chirho.gd7_store_chirho,
            fixture_chirho.handoff_control_chirho,
            fixture_chirho.local_authority_chirho,
            fixture_chirho.journal_ports_chirho,
            fixture_chirho.cluster_chirho,
            fixture_chirho.canonical_genesis_line_chirho,
            fixture_chirho.source_path_chirho,
            fixture_chirho.original_journal_bytes_chirho,
            fixture_chirho.group_chirho,
            fixture_chirho.tail_chirho,
        )
    });
}

/// A bound resident journal with two minted records, a warm single-node elector, and a recovery
/// candidate for that journal at the elector's current term.
fn with_staging_fixture_named_chirho(
    label_chirho: &str,
    action_chirho: impl FnOnce(StagingFixtureChirho<'_>),
) {
    with_bound_resident_fixture_chirho(
        label_chirho,
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            let handoff_control_chirho = local_authority_chirho.handoff_control_handle_chirho();
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_chirho.clone(),
                    0,
                    local_authority_chirho.clone(),
                )
                .unwrap();
            let permit_chirho = ResidentLedgerAppendPermitChirho::for_test_chirho();
            resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    resident_mint_request_chirho(5, "recovery-staging-one-chirho"),
                )
                .unwrap();
            resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    resident_mint_request_chirho(7, "recovery-staging-two-chirho"),
                )
                .unwrap();
            drop(resident_chirho);

            let original_journal_bytes_chirho = ports_chirho
                .storage_chirho
                .read_all_chirho(journal_path_chirho)
                .unwrap()
                .unwrap();
            let journal_ports_chirho = journal_ports_chirho(ports_chirho);
            let source_journal_chirho = LedgerJournalChirho::open_read_only_full_chirho(
                journal_ports_chirho,
                journal_path_chirho.clone(),
                cluster_chirho,
            )
            .unwrap();
            let tail_chirho = source_journal_chirho.verified_append_mirror_tail_chirho();
            let canonical_genesis_line_chirho =
                LedgerMirrorPrefixSourceChirho::canonical_genesis_line_chirho(
                    &source_journal_chirho,
                )
                .unwrap();
            let records_chirho = std::str::from_utf8(&original_journal_bytes_chirho)
                .unwrap()
                .lines()
                .skip(1)
                .map(|line_chirho| {
                    let record_chirho = parse_canonical_ledger_record_chirho(line_chirho).unwrap();
                    (record_chirho.seq_chirho, line_chirho.as_bytes().to_vec())
                })
                .collect::<BTreeMap<_, _>>();
            assert_eq!(records_chirho.len(), 2);
            // In production a candidate's CURRENT term comes from a fresh join of the same elector
            // the recovery guard reads, so the fixture takes that term from this elector instead of
            // inventing one. It used to be a constant 7, which no join can produce; revalidation now
            // binds the guard to the candidate's term, so a constant would refuse at that binding.
            let elected_term_chirho = local_authority_chirho
                .try_acquire_chirho()
                .expect("the warm single-node elector grants a guard")
                .published_raft_term_chirho();
            let candidate_chirho = LedgerMirrorRecoveryCandidateChirho::from_port_evidence_chirho(
                LedgerMirrorRecoveryCandidateInputChirho {
                    consistency_group_digest_chirho:
                        RawCanonicalGroupIdDigestChirho::from_canonical_group_id_chirho(
                            &group_chirho.canonical_id_chirho(),
                        ),
                    assignment_digest_chirho: "a".repeat(64),
                    historical_leader_node_id_chirho: "1".repeat(64),
                    holder_node_ids_chirho: ["2".repeat(64), "3".repeat(64)],
                    historical_term_chirho: 5,
                    historical_membership_view_digest_chirho: "b".repeat(64),
                    cluster_id_chirho: tail_chirho.cluster_id_chirho().0.clone(),
                    journal_genesis_digest_chirho: tail_chirho
                        .journal_genesis_digest_chirho()
                        .0
                        .clone(),
                    tail_seq_chirho: tail_chirho.tail_seq_chirho(),
                    tail_record_digest_chirho: tail_chirho.tail_record_digest_chirho().0.clone(),
                    tail_epoch_chirho: tail_chirho.current_epoch_chirho(),
                    tail_hlc_chirho: tail_chirho.tail_hlc_chirho().clone(),
                    current_term_chirho: elected_term_chirho,
                    current_membership_view_digest_chirho: "c".repeat(64),
                    holder_receipt_digests_chirho: ["d".repeat(64), "e".repeat(64)],
                    holder_receipt_wires_chirho: [
                        b"holder-a-chirho".to_vec(),
                        b"holder-b-chirho".to_vec(),
                    ],
                },
            )
            .unwrap();
            let binding_digest_chirho = candidate_chirho.binding_digest_chirho();
            let recovery_chirho =
                TestRecoveryPortChirho::new_chirho(candidate_chirho.clone(), records_chirho);
            let signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .unwrap();
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .unwrap();
            drop(source_journal_chirho);

            action_chirho(StagingFixtureChirho {
                elector_chirho: &elector_chirho,
                storage_chirho: ports_chirho.storage_chirho,
                recovery_chirho: &recovery_chirho,
                candidate_chirho: &candidate_chirho,
                binding_digest_chirho: &binding_digest_chirho,
                gd7_store_chirho: &gd7_store_chirho,
                handoff_control_chirho: &handoff_control_chirho,
                local_authority_chirho: &local_authority_chirho,
                journal_ports_chirho,
                cluster_chirho,
                canonical_genesis_line_chirho: &canonical_genesis_line_chirho,
                source_path_chirho: journal_path_chirho,
                original_journal_bytes_chirho: &original_journal_bytes_chirho,
                group_chirho,
                tail_chirho: &tail_chirho,
            });
        },
    );
}

#[test]
fn foreign_mirror_group_candidate_refuses_before_any_staging_byte_chirho() {
    with_staging_fixture_chirho(
        "recovery-foreign-group",
        |storage_chirho,
         _recovery_chirho,
         candidate_chirho,
         _binding_digest_chirho,
         _gd7_store_chirho,
         _handoff_control_chirho,
         _local_authority_chirho,
         _journal_ports_chirho,
         _cluster_chirho,
         _canonical_genesis_line_chirho,
         _source_path_chirho,
         _original_journal_bytes_chirho,
         group_chirho,
         tail_chirho| {
            let expected_mirror_digest_chirho =
                RawCanonicalGroupIdDigestChirho::from_canonical_group_id_chirho(
                    &group_chirho.canonical_id_chirho(),
                );
            assert_eq!(
                candidate_chirho.consistency_group_digest_chirho(),
                &expected_mirror_digest_chirho
            );
            assert_ne!(
                candidate_chirho
                    .consistency_group_digest_chirho()
                    .as_str_chirho(),
                consistency_group_digest_chirho(group_chirho).unwrap(),
                "mirror evidence and writer-fence/canary coordinates must remain distinct"
            );
            let foreign_group_chirho = ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: "foreign-recovery-tenant-chirho".to_string(),
            };
            let foreign_candidate_chirho = candidate_with_group_digest_chirho(
                candidate_chirho,
                RawCanonicalGroupIdDigestChirho::from_canonical_group_id_chirho(
                    &foreign_group_chirho.canonical_id_chirho(),
                ),
            );
            let refusal_chirho = verify_candidate_static_binding_chirho(
                &foreign_candidate_chirho,
                tail_chirho,
                group_chirho,
            )
            .unwrap_err();
            assert_eq!(
                refusal_chirho.to_string(),
                "LedgerMirrorRecoveryCandidateGroupBindingRefusedChirho"
            );
            assert_ne!(
                refusal_chirho.to_string(),
                "LedgerMirrorRecoveryCandidateLocalBindingRefusedChirho"
            );
            assert!(storage_chirho
                .list_chirho(&StoragePathChirho::new_chirho(format!(
                    "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_STAGING_DIR_CHIRHO}/"
                )))
                .unwrap()
                .is_empty());
        },
    );
}

#[test]
fn authority_loss_before_first_imported_byte_leaves_the_staging_namespace_empty_chirho() {
    with_staging_fixture_chirho(
        "recovery-authority-before-byte",
        |storage_chirho,
         recovery_chirho,
         candidate_chirho,
         binding_digest_chirho,
         gd7_store_chirho,
         handoff_control_chirho,
         local_authority_chirho,
         _journal_ports_chirho,
         _cluster_chirho,
         _canonical_genesis_line_chirho,
         source_path_chirho,
         original_journal_bytes_chirho,
         _group_chirho,
         _tail_chirho| {
            recovery_chirho.deny_on_revalidation_chirho(1);
            let effect_context_chirho = ResidentRecoveryEffectContextChirho {
                storage_chirho,
                gd7_store_chirho,
                migration_store_chirho: None,
                handoff_control_chirho,
                local_authority_chirho,
                contention_pause_chirho: &|| {},
            };
            let refusal_chirho = stage_candidate_records_chirho(
                &effect_context_chirho,
                recovery_chirho,
                candidate_chirho,
                binding_digest_chirho,
            )
            .unwrap_err();
            let detail_chirho = format!("{refusal_chirho:#}");
            assert!(detail_chirho.contains(TEST_AUTHORITY_REVOKED_CHIRHO));
            assert!(storage_chirho
                .list_chirho(&StoragePathChirho::new_chirho(format!(
                    "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_STAGING_DIR_CHIRHO}/{binding_digest_chirho}/"
                )))
                .unwrap()
                .is_empty());
            assert_eq!(
                storage_chirho.read_all_chirho(source_path_chirho).unwrap(),
                Some(original_journal_bytes_chirho.to_vec()),
                "authority loss before staging must not mutate the selected resident journal"
            );
        },
    );
}

#[test]
fn mid_import_authority_loss_leaves_only_inert_bytes_and_a_lawful_retry_replays_chirho() {
    with_staging_fixture_chirho(
        "recovery-authority-mid-import",
        |storage_chirho,
         recovery_chirho,
         candidate_chirho,
         binding_digest_chirho,
         gd7_store_chirho,
         handoff_control_chirho,
         local_authority_chirho,
         journal_ports_chirho,
         cluster_chirho,
         canonical_genesis_line_chirho,
         source_path_chirho,
         original_journal_bytes_chirho,
         _group_chirho,
         _tail_chirho| {
            // Call 2 is the first revalidation's check under its guard, so call 3 is the second
            // revalidation, after the first record is staged.
            recovery_chirho.deny_on_revalidation_chirho(3);
            let effect_context_chirho = ResidentRecoveryEffectContextChirho {
                storage_chirho,
                gd7_store_chirho,
                migration_store_chirho: None,
                handoff_control_chirho,
                local_authority_chirho,
                contention_pause_chirho: &|| {},
            };
            let refusal_chirho = stage_candidate_records_chirho(
                &effect_context_chirho,
                recovery_chirho,
                candidate_chirho,
                binding_digest_chirho,
            )
            .unwrap_err();
            assert!(format!("{refusal_chirho:#}").contains(TEST_AUTHORITY_REVOKED_CHIRHO));
            let staged_root_chirho = StoragePathChirho::new_chirho(format!(
                "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_STAGING_DIR_CHIRHO}/{binding_digest_chirho}/"
            ));
            assert_eq!(
                storage_chirho.list_chirho(&staged_root_chirho).unwrap().len(),
                1,
                "the first transferred record may be inert, but the revoked second write must not land"
            );
            assert_eq!(
                storage_chirho.read_all_chirho(source_path_chirho).unwrap(),
                Some(original_journal_bytes_chirho.to_vec()),
                "an interrupted import must not mutate the selected resident journal"
            );
            assert!(storage_chirho
                .read_all_chirho(&candidate_journal_path_chirho(binding_digest_chirho))
                .unwrap()
                .is_none());

            recovery_chirho.permit_revalidation_chirho();
            stage_candidate_records_chirho(
                &effect_context_chirho,
                recovery_chirho,
                candidate_chirho,
                binding_digest_chirho,
            )
            .unwrap();
            assert_eq!(
                storage_chirho
                    .list_chirho(&staged_root_chirho)
                    .unwrap()
                    .len(),
                2
            );
            let (candidate_path_chirho, _candidate_digest_chirho) =
                assemble_candidate_journal_chirho(
                    storage_chirho,
                    candidate_chirho,
                    binding_digest_chirho,
                    canonical_genesis_line_chirho,
                )
                .unwrap();
            assert_ne!(&candidate_path_chirho, source_path_chirho);
            let candidate_journal_chirho = LedgerJournalChirho::open_read_only_full_chirho(
                journal_ports_chirho,
                candidate_path_chirho,
                cluster_chirho,
            )
            .unwrap();
            verify_replayed_candidate_tail_chirho(&candidate_journal_chirho, candidate_chirho)
                .unwrap();
        },
    );
}

#[test]
fn unreadable_gd7_head_refuses_distinctly_from_an_absent_head_chirho() {
    with_bound_resident_fixture_chirho(
        "recovery-unreadable-gd7-head",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         _journal_path_chirho,
         _cluster_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            let handoff_control_chirho = local_authority_chirho.handoff_control_handle_chirho();
            let signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .unwrap();
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                group_digest_chirho.clone(),
                node_chirho.0.clone(),
            )
            .unwrap();
            require_recovery_adoption_slot_chirho(&gd7_store_chirho, None, &handoff_control_chirho)
                .expect("an absent GD7 head is not an active or unreadable owner");

            let head_path_chirho =
                gd7_winner_handoff_head_path_chirho(&group_digest_chirho, &node_chirho.0).unwrap();
            let physical_head_chirho = ports_chirho
                .storage_chirho
                .namespace_root_chirho()
                .join(head_path_chirho.key_chirho());
            fs::create_dir_all(&physical_head_chirho).unwrap();
            let refusal_chirho = require_recovery_adoption_slot_chirho(
                &gd7_store_chirho,
                None,
                &handoff_control_chirho,
            )
            .unwrap_err();
            assert!(matches!(
                refusal_chirho,
                ResidentAppendBarrierRefusalChirho::Gd7Chirho(
                    ResidentGd7WinnerHandoffRefusalChirho::StoreChirho(
                        Gd7WinnerHandoffStoreRefusalChirho::StorageChirho
                    )
                )
            ));
            assert!(physical_head_chirho.is_dir());
        },
    );
}

#[path = "recovery_contention_elector_tests_chirho.rs"]
mod recovery_contention_elector_tests_chirho;
