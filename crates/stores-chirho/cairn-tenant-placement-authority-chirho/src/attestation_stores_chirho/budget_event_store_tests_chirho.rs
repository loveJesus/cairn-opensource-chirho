// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Adversarial arms for the chained prepaid-budget store.

use super::*;
use cairn_placement_chirho::budget_chirho::budget_event_attestation_chirho::*;
use cairn_placement_chirho::budget_chirho::budget_funding_attestation_chirho::*;
use std::path::Path;
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

const KEY_CHIRHO: &str = "budget-authority-key-chirho";
const BUDGET_CHIRHO: &str = "budget-a-chirho";
const OTHER_BUDGET_CHIRHO: &str = "budget-b-chirho";
const CEILING_CHIRHO: u64 = 100_000;

#[derive(Clone, Copy)]
struct AuthorityChirho;

impl BudgetAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }

    fn verify_chirho(&self, message_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{message_chirho}")
    }
}

#[derive(Clone, Copy)]
struct OtherAuthorityChirho;

impl BudgetAuthorityPortChirho for OtherAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        "other-budget-authority-key-chirho".to_string()
    }

    fn verify_chirho(&self, message_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{message_chirho}")
    }
}

struct BudgetWorldChirho {
    evidence_root_chirho: tempfile::TempDir,
    authority_root_chirho: tempfile::TempDir,
}

impl BudgetWorldChirho {
    fn new_chirho() -> Self {
        let evidence_root_chirho = tempfile::tempdir().expect("evidence root");
        cairn_signer_chirho::signer_chirho::pubkey_hex_chirho(evidence_root_chirho.path())
            .expect("root key");
        Self {
            evidence_root_chirho,
            authority_root_chirho: tempfile::tempdir().expect("authority root"),
        }
    }

    fn evidence_chirho(&self) -> &Path {
        self.evidence_root_chirho.path()
    }

    fn authority_chirho(&self) -> &Path {
        self.authority_root_chirho.path()
    }

    fn fund_chirho(&self, budget_id_chirho: &str, ceiling_chirho: u64) -> String {
        let scope_chirho =
            budget_evidence_scope_chirho(self.evidence_chirho(), budget_id_chirho).expect("scope");
        let record_chirho = signed_funding_chirho(&scope_chirho, ceiling_chirho);
        let digest_chirho = budget_funding_record_digest_chirho(&record_chirho).expect("digest");
        publish_verified_budget_funding_chirho(
            self.evidence_chirho(),
            self.authority_chirho(),
            &record_chirho,
            &AuthorityChirho,
        )
        .expect("publish funding");
        digest_chirho
    }

    fn append_chirho(
        &self,
        record_chirho: &BudgetEventAttestationChirho,
    ) -> Result<(), BudgetStoreRefusalChirho> {
        append_verified_budget_event_chirho(
            self.evidence_chirho(),
            self.authority_chirho(),
            record_chirho,
            &AuthorityChirho,
        )
    }

    fn replay_chirho(
        &self,
        budget_id_chirho: &str,
    ) -> Result<InfrastructureBudgetChirho, BudgetStoreRefusalChirho> {
        replay_budget_chirho(
            self.evidence_chirho(),
            self.authority_chirho(),
            budget_id_chirho,
            &AuthorityChirho,
        )
    }
}

fn signed_funding_chirho(
    scope_chirho: &BudgetEvidenceScopeChirho,
    ceiling_chirho: u64,
) -> BudgetFundingAttestationChirho {
    let intent_chirho = BudgetFundingIntentChirho {
        schema_chirho: BUDGET_FUNDING_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        evidence_root_key_id_chirho: scope_chirho.evidence_root_key_id_chirho.clone(),
        tenant_id_chirho: scope_chirho.tenant_id_chirho.clone(),
        budget_id_chirho: scope_chirho.budget_id_chirho.clone(),
        prepaid_ceiling_micros_chirho: ceiling_chirho,
    };
    let mut record_chirho = BudgetFundingAttestationChirho {
        schema_chirho: BUDGET_FUNDING_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: BUDGET_FUNDING_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: budget_funding_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_budget_funding_message_chirho(&record_chirho)
    );
    record_chirho
}

fn signed_event_chirho(
    world_chirho: &BudgetWorldChirho,
    budget_id_chirho: &str,
    funding_digest_chirho: &str,
    reservation_id_chirho: &str,
    kind_chirho: BudgetEventKindChirho,
    event_seq_chirho: u64,
) -> BudgetEventAttestationChirho {
    let scope_chirho =
        budget_evidence_scope_chirho(world_chirho.evidence_chirho(), budget_id_chirho)
            .expect("scope");
    let intent_chirho = BudgetEventIntentChirho {
        schema_chirho: BUDGET_EVENT_INTENT_SCHEMA_V2_CHIRHO.to_string(),
        evidence_root_key_id_chirho: scope_chirho.evidence_root_key_id_chirho,
        tenant_id_chirho: scope_chirho.tenant_id_chirho,
        budget_id_chirho: budget_id_chirho.to_string(),
        funding_record_digest_chirho: funding_digest_chirho.to_string(),
        reservation_id_chirho: reservation_id_chirho.to_string(),
        kind_chirho,
        event_seq_chirho,
    };
    let mut record_chirho = BudgetEventAttestationChirho {
        schema_chirho: BUDGET_EVENT_ATTESTATION_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: BUDGET_EVENT_ATTESTATION_DOMAIN_V2_CHIRHO.to_string(),
        intent_digest_chirho: budget_event_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_budget_event_message_chirho(&record_chirho)
    );
    record_chirho
}

fn reserve_chirho(
    world_chirho: &BudgetWorldChirho,
    budget_id_chirho: &str,
    funding_digest_chirho: &str,
    reservation_id_chirho: &str,
    micros_chirho: u64,
    event_seq_chirho: u64,
) -> BudgetEventAttestationChirho {
    signed_event_chirho(
        world_chirho,
        budget_id_chirho,
        funding_digest_chirho,
        reservation_id_chirho,
        BudgetEventKindChirho::ReserveChirho {
            requested_micros_chirho: micros_chirho,
            deadline_millis_chirho: 10_000,
        },
        event_seq_chirho,
    )
}

fn settle_chirho(
    world_chirho: &BudgetWorldChirho,
    funding_digest_chirho: &str,
    reservation_id_chirho: &str,
    micros_chirho: u64,
    event_seq_chirho: u64,
) -> BudgetEventAttestationChirho {
    signed_event_chirho(
        world_chirho,
        BUDGET_CHIRHO,
        funding_digest_chirho,
        reservation_id_chirho,
        BudgetEventKindChirho::SettleChirho {
            settled_micros_chirho: micros_chirho,
        },
        event_seq_chirho,
    )
}

fn log_lines_chirho(world_chirho: &BudgetWorldChirho) -> Vec<String> {
    std::fs::read_to_string(world_chirho.evidence_chirho().join(BUDGET_EVENT_LOG_CHIRHO))
        .expect("log")
        .lines()
        .map(str::to_string)
        .collect()
}

fn write_lines_chirho(world_chirho: &BudgetWorldChirho, lines_chirho: &[String]) {
    let mut text_chirho = lines_chirho.join("\n");
    if !text_chirho.is_empty() {
        text_chirho.push('\n');
    }
    std::fs::write(
        world_chirho.evidence_chirho().join(BUDGET_EVENT_LOG_CHIRHO),
        text_chirho,
    )
    .expect("rewrite log");
}

#[test]
fn signed_funding_drives_replay_and_report_provenance_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            30_000,
            1,
        ))
        .expect("reserve");
    world_chirho
        .append_chirho(&settle_chirho(
            &world_chirho,
            &funding_chirho,
            "r1-chirho",
            12_000,
            2,
        ))
        .expect("settle");

    let budget_chirho = world_chirho.replay_chirho(BUDGET_CHIRHO).expect("replay");
    assert_eq!(budget_chirho.settled_micros_chirho(), 12_000);
    assert_eq!(budget_chirho.available_micros_chirho(), 88_000);
    let report_chirho = build_budget_report_chirho(
        world_chirho.evidence_chirho(),
        world_chirho.authority_chirho(),
        BUDGET_CHIRHO,
        9_000,
        &AuthorityChirho,
    )
    .expect("report");
    assert_eq!(report_chirho.schema_chirho, BUDGET_REPORT_SCHEMA_V2_CHIRHO);
    assert_eq!(report_chirho.prepaid_ceiling_micros_chirho, CEILING_CHIRHO);
    assert_eq!(
        report_chirho.ceiling_provenance_chirho,
        BudgetCeilingProvenanceChirho::AuthenticatedFundingChirho {
            funding_record_digest_chirho: funding_chirho,
            authority_key_id_chirho: KEY_CHIRHO.to_string(),
        }
    );
}

#[test]
fn immutable_funding_refuses_a_second_ceiling_for_one_budget_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    let scope_chirho =
        budget_evidence_scope_chirho(world_chirho.evidence_chirho(), BUDGET_CHIRHO).unwrap();
    let replacement_chirho = signed_funding_chirho(&scope_chirho, CEILING_CHIRHO * 2);
    assert!(matches!(
        publish_verified_budget_funding_chirho(
            world_chirho.evidence_chirho(),
            world_chirho.authority_chirho(),
            &replacement_chirho,
            &AuthorityChirho,
        ),
        Err(BudgetStoreRefusalChirho::FundingImmutableConflictChirho { .. })
    ));
}

#[test]
fn reserve_beyond_signed_ceiling_refuses_without_appending_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    let refusal_chirho = world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            CEILING_CHIRHO + 1,
            1,
        ))
        .expect_err("over ceiling");
    assert!(matches!(
        refusal_chirho,
        BudgetStoreRefusalChirho::RuleChirho { .. }
    ));
    assert!(!world_chirho
        .evidence_chirho()
        .join(BUDGET_EVENT_LOG_CHIRHO)
        .exists());
}

#[test]
fn event_bound_to_another_funding_record_refuses_by_binding_identity_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    let event_chirho = reserve_chirho(
        &world_chirho,
        BUDGET_CHIRHO,
        "wrong-funding-record-digest-chirho",
        "r1-chirho",
        10_000,
        1,
    );
    assert!(matches!(
        world_chirho.append_chirho(&event_chirho),
        Err(BudgetStoreRefusalChirho::EventBindingMismatchChirho {
            refusal_chirho: BudgetEventRefusalChirho::FundingDigestMismatchChirho { .. },
        })
    ));
    assert!(
        !world_chirho
            .evidence_chirho()
            .join(BUDGET_EVENT_LOG_CHIRHO)
            .exists(),
        "a funding-binding refusal must not create the event log"
    );
}

#[test]
fn same_business_sequence_is_refused_by_name_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    let event_chirho = reserve_chirho(
        &world_chirho,
        BUDGET_CHIRHO,
        &funding_chirho,
        "r1-chirho",
        10_000,
        1,
    );
    world_chirho.append_chirho(&event_chirho).expect("first");
    assert!(matches!(
        world_chirho.append_chirho(&event_chirho),
        Err(BudgetStoreRefusalChirho::ReplayedEventSeqChirho { .. })
    ));
}

#[test]
fn middle_deletion_refuses_as_a_dense_gap_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            20_000,
            1,
        ))
        .unwrap();
    world_chirho
        .append_chirho(&settle_chirho(
            &world_chirho,
            &funding_chirho,
            "r1-chirho",
            10_000,
            2,
        ))
        .unwrap();
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r2-chirho",
            5_000,
            3,
        ))
        .unwrap();
    let lines_chirho = log_lines_chirho(&world_chirho);
    write_lines_chirho(
        &world_chirho,
        &[lines_chirho[0].clone(), lines_chirho[2].clone()],
    );
    assert!(matches!(
        world_chirho.replay_chirho(BUDGET_CHIRHO),
        Err(BudgetStoreRefusalChirho::GapChainSeqChirho {
            expected_chirho: 1,
            found_chirho: 2,
        })
    ));
}

#[test]
fn tail_deletion_is_read_only_refused_then_operator_repaired_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            20_000,
            1,
        ))
        .unwrap();
    world_chirho
        .append_chirho(&settle_chirho(
            &world_chirho,
            &funding_chirho,
            "r1-chirho",
            8_000,
            2,
        ))
        .unwrap();
    let lines_chirho = log_lines_chirho(&world_chirho);
    write_lines_chirho(&world_chirho, &lines_chirho[..1]);
    let before_chirho =
        std::fs::read(world_chirho.evidence_chirho().join(BUDGET_EVENT_LOG_CHIRHO)).unwrap();
    assert!(matches!(
        world_chirho.replay_chirho(BUDGET_CHIRHO),
        Err(BudgetStoreRefusalChirho::CheckpointAheadOrAppendInFlightChirho { .. })
    ));
    assert_eq!(
        std::fs::read(world_chirho.evidence_chirho().join(BUDGET_EVENT_LOG_CHIRHO)).unwrap(),
        before_chirho,
        "a read must not repair"
    );
    assert!(matches!(
        repair_budget_log_chirho(
            world_chirho.evidence_chirho(),
            world_chirho.authority_chirho(),
            &AuthorityChirho,
        ),
        Ok(
            BudgetRepairOutcomeChirho::RecoveredAbandonedCheckpointChirho {
                chain_seq_chirho: 1,
            }
        )
    ));
    assert_eq!(
        world_chirho
            .replay_chirho(BUDGET_CHIRHO)
            .unwrap()
            .settled_micros_chirho(),
        8_000
    );
}

#[test]
fn delete_all_beyond_one_retained_tail_refuses_without_repair_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            20_000,
            1,
        ))
        .unwrap();
    world_chirho
        .append_chirho(&settle_chirho(
            &world_chirho,
            &funding_chirho,
            "r1-chirho",
            8_000,
            2,
        ))
        .unwrap();
    std::fs::write(
        world_chirho.evidence_chirho().join(BUDGET_EVENT_LOG_CHIRHO),
        b"",
    )
    .unwrap();
    assert!(matches!(
        repair_budget_log_chirho(
            world_chirho.evidence_chirho(),
            world_chirho.authority_chirho(),
            &AuthorityChirho,
        ),
        Err(BudgetStoreRefusalChirho::CheckpointTooFarAheadChirho {
            local_count_chirho: 0,
            checkpoint_count_chirho: 2,
        })
    ));
}

#[test]
fn whole_log_copy_to_another_root_refuses_at_the_anchor_chirho() {
    let source_chirho = BudgetWorldChirho::new_chirho();
    let source_funding_chirho = source_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    source_chirho
        .append_chirho(&reserve_chirho(
            &source_chirho,
            BUDGET_CHIRHO,
            &source_funding_chirho,
            "r1-chirho",
            10_000,
            1,
        ))
        .unwrap();
    let target_chirho = BudgetWorldChirho::new_chirho();
    target_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    std::fs::copy(
        source_chirho
            .evidence_chirho()
            .join(BUDGET_EVENT_LOG_CHIRHO),
        target_chirho
            .evidence_chirho()
            .join(BUDGET_EVENT_LOG_CHIRHO),
    )
    .unwrap();
    assert!(matches!(
        target_chirho.replay_chirho(BUDGET_CHIRHO),
        Err(BudgetStoreRefusalChirho::PreviousLineBindingMismatchChirho { seq_chirho: 0 })
    ));
}

#[test]
fn corrupted_signed_terminal_row_refuses_before_checkpoint_comparison_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            20_000,
            1,
        ))
        .unwrap();
    world_chirho
        .append_chirho(&settle_chirho(
            &world_chirho,
            &funding_chirho,
            "r1-chirho",
            8_000,
            2,
        ))
        .unwrap();
    let mut lines_chirho = log_lines_chirho(&world_chirho);
    lines_chirho[1] = lines_chirho[1].replacen("sig-over:", "sig-wrong", 1);
    write_lines_chirho(&world_chirho, &lines_chirho);
    assert!(matches!(
        world_chirho.replay_chirho(BUDGET_CHIRHO),
        Err(BudgetStoreRefusalChirho::EventSignatureInvalidChirho { .. })
    ));
}

#[test]
fn rewritten_budget_id_refuses_before_funding_routing_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            10_000,
            1,
        ))
        .unwrap();
    let mut lines_chirho = log_lines_chirho(&world_chirho);
    lines_chirho[0] =
        lines_chirho[0].replacen(BUDGET_CHIRHO, "budget-with-no-funding-record-chirho", 1);
    write_lines_chirho(&world_chirho, &lines_chirho);
    assert!(matches!(
        world_chirho.replay_chirho(BUDGET_CHIRHO),
        Err(BudgetStoreRefusalChirho::EventSignatureInvalidChirho {
            refusal_chirho: BudgetEventRefusalChirho::IntentDigestMismatchChirho { .. },
        })
    ));
}

#[test]
fn checkpoint_genesis_refuses_a_substituted_authority_key_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    assert_eq!(
        replay_budget_chirho(
            world_chirho.evidence_chirho(),
            world_chirho.authority_chirho(),
            BUDGET_CHIRHO,
            &OtherAuthorityChirho,
        ),
        Err(
            BudgetStoreRefusalChirho::CheckpointAuthorityMismatchChirho {
                expected_chirho: KEY_CHIRHO.to_string(),
                found_chirho: "other-budget-authority-key-chirho".to_string(),
            }
        )
    );
}

#[test]
fn concurrent_same_sequence_commits_exactly_one_row_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    let evidence_chirho = world_chirho.evidence_chirho().to_path_buf();
    let authority_root_chirho = world_chirho.authority_chirho().to_path_buf();
    let first_chirho = reserve_chirho(
        &world_chirho,
        BUDGET_CHIRHO,
        &funding_chirho,
        "r1-chirho",
        10_000,
        1,
    );
    let second_chirho = reserve_chirho(
        &world_chirho,
        BUDGET_CHIRHO,
        &funding_chirho,
        "r2-chirho",
        10_000,
        1,
    );
    let barrier_chirho = Arc::new(Barrier::new(3));
    let spawn_chirho = |record_chirho: BudgetEventAttestationChirho| {
        let evidence_chirho = evidence_chirho.clone();
        let authority_root_chirho = authority_root_chirho.clone();
        let barrier_chirho = Arc::clone(&barrier_chirho);
        std::thread::spawn(move || {
            barrier_chirho.wait();
            append_verified_budget_event_chirho(
                &evidence_chirho,
                &authority_root_chirho,
                &record_chirho,
                &AuthorityChirho,
            )
        })
    };
    let first_thread_chirho = spawn_chirho(first_chirho);
    let second_thread_chirho = spawn_chirho(second_chirho);
    barrier_chirho.wait();
    let outcomes_chirho = [
        first_thread_chirho.join().unwrap(),
        second_thread_chirho.join().unwrap(),
    ];
    assert_eq!(
        outcomes_chirho
            .iter()
            .filter(|result_chirho| result_chirho.is_ok())
            .count(),
        1
    );
    assert_eq!(
        outcomes_chirho
            .iter()
            .filter(|result_chirho| matches!(
                result_chirho,
                Err(BudgetStoreRefusalChirho::ReplayedEventSeqChirho { .. })
            ))
            .count(),
        1
    );
    assert_eq!(log_lines_chirho(&world_chirho).len(), 1);
}

#[test]
fn an_append_cannot_complete_while_the_root_and_authority_locks_are_held_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    let record_chirho = reserve_chirho(
        &world_chirho,
        BUDGET_CHIRHO,
        &funding_chirho,
        "r1-chirho",
        10_000,
        1,
    );
    let evidence_chirho = world_chirho.evidence_chirho().to_path_buf();
    let authority_root_chirho = world_chirho.authority_chirho().to_path_buf();
    let root_scope_chirho = derive_root_scope_chirho(world_chirho.evidence_chirho()).unwrap();
    let (started_tx_chirho, started_rx_chirho) = mpsc::channel();
    let (done_tx_chirho, done_rx_chirho) = mpsc::channel();
    let thread_chirho = with_budget_write_locks_chirho(
        world_chirho.evidence_chirho(),
        world_chirho.authority_chirho(),
        &root_scope_chirho,
        || {
            let thread_chirho = std::thread::spawn(move || {
                started_tx_chirho.send(()).unwrap();
                let result_chirho = append_verified_budget_event_chirho(
                    &evidence_chirho,
                    &authority_root_chirho,
                    &record_chirho,
                    &AuthorityChirho,
                );
                done_tx_chirho.send(()).unwrap();
                result_chirho
            });
            started_rx_chirho
                .recv_timeout(Duration::from_secs(1))
                .expect("append thread started");
            assert!(
                matches!(
                    done_rx_chirho.recv_timeout(Duration::from_millis(250)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "an append completed while another holder owned both production locks"
            );
            Ok(thread_chirho)
        },
    )
    .unwrap();
    assert!(thread_chirho.join().unwrap().is_ok());
    assert_eq!(log_lines_chirho(&world_chirho).len(), 1);
}

#[test]
fn concurrent_different_budgets_both_commit_under_the_root_lock_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let first_funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    let second_funding_chirho = world_chirho.fund_chirho(OTHER_BUDGET_CHIRHO, CEILING_CHIRHO);
    let evidence_chirho = world_chirho.evidence_chirho().to_path_buf();
    let authority_root_chirho = world_chirho.authority_chirho().to_path_buf();
    let first_chirho = reserve_chirho(
        &world_chirho,
        BUDGET_CHIRHO,
        &first_funding_chirho,
        "ra-chirho",
        10_000,
        1,
    );
    let second_chirho = reserve_chirho(
        &world_chirho,
        OTHER_BUDGET_CHIRHO,
        &second_funding_chirho,
        "rb-chirho",
        20_000,
        1,
    );
    let barrier_chirho = Arc::new(Barrier::new(3));
    let spawn_chirho = |record_chirho: BudgetEventAttestationChirho| {
        let evidence_chirho = evidence_chirho.clone();
        let authority_root_chirho = authority_root_chirho.clone();
        let barrier_chirho = Arc::clone(&barrier_chirho);
        std::thread::spawn(move || {
            barrier_chirho.wait();
            append_verified_budget_event_chirho(
                &evidence_chirho,
                &authority_root_chirho,
                &record_chirho,
                &AuthorityChirho,
            )
        })
    };
    let first_thread_chirho = spawn_chirho(first_chirho);
    let second_thread_chirho = spawn_chirho(second_chirho);
    barrier_chirho.wait();
    assert!(first_thread_chirho.join().unwrap().is_ok());
    assert!(second_thread_chirho.join().unwrap().is_ok());
    assert_eq!(log_lines_chirho(&world_chirho).len(), 2);
    assert_eq!(
        world_chirho
            .replay_chirho(BUDGET_CHIRHO)
            .unwrap()
            .outstanding_micros_chirho(),
        10_000
    );
    assert_eq!(
        world_chirho
            .replay_chirho(OTHER_BUDGET_CHIRHO)
            .unwrap()
            .outstanding_micros_chirho(),
        20_000
    );
}

#[test]
fn sibling_budget_append_repairs_pending_tail_before_new_admission_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let first_funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    let second_funding_chirho = world_chirho.fund_chirho(OTHER_BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &first_funding_chirho,
            "ra-chirho",
            10_000,
            1,
        ))
        .unwrap();
    write_lines_chirho(&world_chirho, &[]);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            OTHER_BUDGET_CHIRHO,
            &second_funding_chirho,
            "rb-chirho",
            20_000,
            1,
        ))
        .expect("repair A then append B");
    assert_eq!(log_lines_chirho(&world_chirho).len(), 2);
    assert_eq!(
        world_chirho
            .replay_chirho(BUDGET_CHIRHO)
            .unwrap()
            .outstanding_micros_chirho(),
        10_000
    );
    assert_eq!(
        world_chirho
            .replay_chirho(OTHER_BUDGET_CHIRHO)
            .unwrap()
            .outstanding_micros_chirho(),
        20_000
    );
}

#[test]
fn torn_pending_line_repairs_only_when_it_is_the_checkpoint_prefix_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            10_000,
            1,
        ))
        .unwrap();
    let path_chirho = world_chirho.evidence_chirho().join(BUDGET_EVENT_LOG_CHIRHO);
    let complete_chirho = std::fs::read(&path_chirho).unwrap();
    std::fs::write(&path_chirho, &complete_chirho[..complete_chirho.len() / 2]).unwrap();
    assert!(matches!(
        world_chirho.replay_chirho(BUDGET_CHIRHO),
        Err(BudgetStoreRefusalChirho::TornTailChirho)
    ));
    assert!(matches!(
        repair_budget_log_chirho(
            world_chirho.evidence_chirho(),
            world_chirho.authority_chirho(),
            &AuthorityChirho,
        ),
        Ok(BudgetRepairOutcomeChirho::RecoveredAbandonedCheckpointChirho { .. })
    ));
    assert_eq!(std::fs::read(path_chirho).unwrap(), complete_chirho);
}

#[test]
fn torn_tail_with_the_wrong_bytes_is_never_repaired_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            10_000,
            1,
        ))
        .unwrap();
    std::fs::write(
        world_chirho.evidence_chirho().join(BUDGET_EVENT_LOG_CHIRHO),
        b"not-the-checkpointed-prefix-chirho",
    )
    .unwrap();
    assert_eq!(
        repair_budget_log_chirho(
            world_chirho.evidence_chirho(),
            world_chirho.authority_chirho(),
            &AuthorityChirho,
        ),
        Err(BudgetStoreRefusalChirho::TornTailDoesNotMatchCheckpointChirho)
    );
}

#[test]
fn checkpointed_line_with_an_invalid_event_signature_is_never_repaired_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let funding_chirho = world_chirho.fund_chirho(BUDGET_CHIRHO, CEILING_CHIRHO);
    world_chirho
        .append_chirho(&reserve_chirho(
            &world_chirho,
            BUDGET_CHIRHO,
            &funding_chirho,
            "r1-chirho",
            10_000,
            1,
        ))
        .unwrap();
    let root_scope_chirho = derive_root_scope_chirho(world_chirho.evidence_chirho()).unwrap();
    let mut checkpoint_chirho =
        read_checkpoint_chirho(world_chirho.authority_chirho(), &root_scope_chirho).unwrap();
    let invalid_line_chirho = checkpoint_chirho
        .tail_line_chirho
        .as_ref()
        .unwrap()
        .replacen("sig-over:", "sig-wrong", 1);
    checkpoint_chirho.tail_digest_chirho = stored_line_digest_hex_chirho(&invalid_line_chirho);
    checkpoint_chirho.tail_line_chirho = Some(invalid_line_chirho);
    write_checkpoint_chirho(
        world_chirho.authority_chirho(),
        &root_scope_chirho,
        &checkpoint_chirho,
    )
    .unwrap();
    let log_path_chirho = world_chirho.evidence_chirho().join(BUDGET_EVENT_LOG_CHIRHO);
    std::fs::write(&log_path_chirho, b"").unwrap();
    assert!(matches!(
        repair_budget_log_chirho(
            world_chirho.evidence_chirho(),
            world_chirho.authority_chirho(),
            &AuthorityChirho,
        ),
        Err(BudgetStoreRefusalChirho::EventSignatureInvalidChirho { .. })
    ));
    assert_eq!(std::fs::read(log_path_chirho).unwrap(), b"");
}

#[test]
fn custody_root_must_be_separate_and_non_nested_chirho() {
    let world_chirho = BudgetWorldChirho::new_chirho();
    let scope_chirho =
        budget_evidence_scope_chirho(world_chirho.evidence_chirho(), BUDGET_CHIRHO).unwrap();
    let funding_chirho = signed_funding_chirho(&scope_chirho, CEILING_CHIRHO);
    assert_eq!(
        publish_verified_budget_funding_chirho(
            world_chirho.evidence_chirho(),
            world_chirho.evidence_chirho(),
            &funding_chirho,
            &AuthorityChirho,
        ),
        Err(BudgetStoreRefusalChirho::AuthorityRootOverlapsEvidenceRootChirho)
    );
}
