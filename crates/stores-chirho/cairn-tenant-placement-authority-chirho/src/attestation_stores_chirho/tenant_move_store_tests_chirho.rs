// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the durable tenant-root move log.
//!
//! The centrepiece is [`the_writer_moves_exactly_once_across_the_whole_move_chirho`]: CF8 clause 4's
//! *"preserves one writer"*, observed OFF DISK across every stage rather than asserted about a
//! variable. It walks the move and records who may write at each point, then checks the sequence has
//! exactly one transition — a check that fails both if the writer moves twice and if it never moves.

use super::super::move_control_store_chirho::{
    list_record_addresses_chirho, MOVE_CONTROL_STAGE_RECORDS_DIR_CHIRHO,
};
use super::*;
use cairn_tenant_chirho::move_chirho::move_attestation_chirho::*;
use cairn_tenant_chirho::move_chirho::move_stages_chirho::MoveStageChirho;
use cairn_tenant_chirho::surface_disposition_chirho::TENANT_MOVE_CONTROL_SURFACE_CHIRHO;

const KEY_CHIRHO: &str = "move-authority-key-chirho";
const MOVE_CHIRHO: &str = "move-a-chirho";

struct AuthorityChirho;

impl MoveAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

fn stage_record_chirho(
    stage_chirho: MoveStageChirho,
    seq_chirho: u64,
) -> MoveStageAttestationChirho {
    let post_handoff_record_digests_chirho = match stage_chirho {
        MoveStageChirho::WriterHandedOffChirho => vec![move_stage_record_digest_chirho(
            &stage_record_chirho(MoveStageChirho::SourceRetiredChirho, seq_chirho + 1),
        )
        .expect("terminal record digest")],
        _ => Vec::new(),
    };
    let intent_chirho = MoveStageIntentChirho {
        schema_chirho: MOVE_STAGE_INTENT_SCHEMA_V2_CHIRHO.to_string(),
        move_id_chirho: MOVE_CHIRHO.to_string(),
        source_root_chirho: "root-source-chirho".to_string(),
        target_root_chirho: "root-target-chirho".to_string(),
        stage_chirho,
        // Only the surfaces-carrying stage may name evidence; the fixture mirrors that rule so these
        // arms exercise the real records rather than a shape the verifier would reject.
        surfaces_evidence_chirho: match stage_chirho {
            MoveStageChirho::SurfacesCarriedChirho => Some("e".repeat(64)),
            _ => None,
        },
        post_handoff_record_digests_chirho,
        retirement_authorization_digest_chirho: match stage_chirho {
            MoveStageChirho::SourceRetiredChirho => Some("a".repeat(64)),
            _ => None,
        },
        stage_seq_chirho: seq_chirho,
    };
    let mut record_chirho = MoveStageAttestationChirho {
        schema_chirho: MOVE_STAGE_ATTESTATION_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: MOVE_STAGE_ATTESTATION_DOMAIN_V2_CHIRHO.to_string(),
        intent_digest_chirho: move_stage_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_move_stage_message_chirho(&record_chirho)
    );
    record_chirho
}

fn resign_record_chirho(record_chirho: &mut MoveStageAttestationChirho) {
    record_chirho.intent_digest_chirho =
        move_stage_intent_digest_chirho(&record_chirho.intent_chirho).expect("digest");
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_move_stage_message_chirho(record_chirho)
    );
}

fn write_record_direct_chirho(root_chirho: &Path, record_chirho: &MoveStageAttestationChirho) {
    let mut line_chirho = serde_json::to_vec(record_chirho).expect("encode");
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(
        &root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO),
        &line_chirho,
    )
    .expect("write the log directly, bypassing the append path");
}

fn verified_control_record_chirho(
    record_chirho: &MoveStageAttestationChirho,
) -> VerifiedMoveControlRecordChirho {
    verify_move_control_record_chirho(record_chirho, &AuthorityChirho, MOVE_CHIRHO)
        .expect("verified control record")
}

fn store_control_record_chirho(root_chirho: &Path, record_chirho: &MoveStageAttestationChirho) {
    store_verified_move_control_record_chirho(
        root_chirho,
        &verified_control_record_chirho(record_chirho),
    )
    .expect("store verified control record");
}

fn post_handoff_pair_chirho() -> (MoveStageAttestationChirho, MoveStageAttestationChirho) {
    (
        stage_record_chirho(MoveStageChirho::WriterHandedOffChirho, 4),
        stage_record_chirho(MoveStageChirho::SourceRetiredChirho, 5),
    )
}

fn prestore_post_handoff_pair_chirho(root_chirho: &Path) {
    let (handoff_chirho, terminal_chirho) = post_handoff_pair_chirho();
    prestore_post_handoff_move_records_chirho(
        root_chirho,
        &handoff_chirho,
        &terminal_chirho,
        &AuthorityChirho,
    )
    .expect("pre-store the exact post-handoff pair");
}

fn control_record_path_chirho(root_chirho: &Path, record_digest_chirho: &str) -> PathBuf {
    let move_digest_chirho = blake3::hash(MOVE_CHIRHO.as_bytes()).to_hex().to_string();
    root_chirho
        .join(TENANT_MOVE_CONTROL_SURFACE_CHIRHO)
        .join(&move_digest_chirho[..2])
        .join(&move_digest_chirho[2..])
        .join(MOVE_CONTROL_STAGE_RECORDS_DIR_CHIRHO)
        .join(record_digest_chirho)
}

fn append_chirho(
    root_chirho: &Path,
    stage_chirho: MoveStageChirho,
    seq_chirho: u64,
) -> Result<MoveStageChirho, TenantMoveStoreRefusalChirho> {
    append_verified_move_stage_chirho(
        root_chirho,
        &stage_record_chirho(stage_chirho, seq_chirho),
        &AuthorityChirho,
    )
}

fn writer_chirho(root_chirho: &Path) -> MoveWriterChirho {
    current_writer_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho).expect("writer")
}

fn append_through_custody_chirho(root_chirho: &Path) {
    for (stage_chirho, seq_chirho) in [
        (MoveStageChirho::PreparedChirho, 1),
        (MoveStageChirho::SurfacesCarriedChirho, 2),
        (MoveStageChirho::CustodyPlacedChirho, 3),
    ] {
        append_chirho(root_chirho, stage_chirho, seq_chirho).expect("stage through custody");
    }
}

#[test]
fn the_writer_moves_exactly_once_across_the_whole_move_chirho() {
    // CF8 clause 4's "preserves one writer", observed OFF DISK. The check fails both ways: a writer
    // that moved twice and a writer that never moved both break "exactly one transition", and asserting
    // only the final writer would pass for a move that handed over at the very first stage.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_chirho(root_chirho, MoveStageChirho::PreparedChirho, 1).expect("prepare");

    let mut observed_chirho = vec![writer_chirho(root_chirho)];
    for (stage_chirho, seq_chirho) in [
        (MoveStageChirho::SurfacesCarriedChirho, 2),
        (MoveStageChirho::CustodyPlacedChirho, 3),
    ] {
        append_chirho(root_chirho, stage_chirho, seq_chirho).expect("stage applies");
        observed_chirho.push(writer_chirho(root_chirho));
    }
    prestore_post_handoff_pair_chirho(root_chirho);
    let (handoff_chirho, terminal_chirho) = post_handoff_pair_chirho();
    for record_chirho in [handoff_chirho, terminal_chirho] {
        append_verified_move_stage_chirho(root_chirho, &record_chirho, &AuthorityChirho)
            .expect("pre-stored stage applies");
        observed_chirho.push(writer_chirho(root_chirho));
    }

    let transitions_chirho = observed_chirho
        .windows(2)
        .filter(|pair_chirho| pair_chirho[0] != pair_chirho[1])
        .count();
    assert_eq!(
        transitions_chirho, 1,
        "the writer must change exactly once across the move: {observed_chirho:?}"
    );
    assert_eq!(observed_chirho[0], MoveWriterChirho::SourceChirho);
    assert_eq!(
        *observed_chirho.last().expect("non-empty"),
        MoveWriterChirho::TargetChirho
    );
}

#[test]
fn handoff_refuses_until_the_exact_terminal_pair_is_pre_stored_chirho() {
    let temp_chirho = tempfile::tempdir().expect("root");
    let root_chirho = temp_chirho.path();
    append_through_custody_chirho(root_chirho);
    let (handoff_chirho, _terminal_chirho) = post_handoff_pair_chirho();
    let before_chirho =
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read log");

    assert!(matches!(
        append_verified_move_stage_chirho(root_chirho, &handoff_chirho, &AuthorityChirho)
            .expect_err("handoff cannot author its own future evidence"),
        TenantMoveStoreRefusalChirho::RequiredPrestoredControlRecordMissingChirho {
            logged_chirho: 3,
            stored_chirho: 3,
        }
    ));
    assert_eq!(
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read refused log"),
        before_chirho,
        "a missing terminal permit must refuse before the handoff row lands"
    );
}

#[test]
fn partial_prestore_resumes_then_handoff_freezes_the_control_set_chirho() {
    let temp_chirho = tempfile::tempdir().expect("root");
    let root_chirho = temp_chirho.path();
    append_through_custody_chirho(root_chirho);
    let (handoff_chirho, terminal_chirho) = post_handoff_pair_chirho();

    store_control_record_chirho(root_chirho, &handoff_chirho);
    assert!(matches!(
        replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho)
            .expect_err("one orphan future record is not a complete permit set"),
        TenantMoveStoreRefusalChirho::ControlRecordGrammarMismatchChirho {
            logged_chirho: 3,
            stored_chirho: 4,
        }
    ));
    prestore_post_handoff_move_records_chirho(
        root_chirho,
        &handoff_chirho,
        &terminal_chirho,
        &AuthorityChirho,
    )
    .expect("resume completes the exact pair");
    assert_eq!(
        list_record_addresses_chirho(root_chirho, MOVE_CHIRHO)
            .expect("list active shard")
            .len(),
        5
    );

    append_verified_move_stage_chirho(root_chirho, &handoff_chirho, &AuthorityChirho)
        .expect("append pre-stored handoff");
    let handoff_bytes_chirho =
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read handoff log");
    let mut conflicting_terminal_chirho = terminal_chirho.clone();
    conflicting_terminal_chirho
        .intent_chirho
        .retirement_authorization_digest_chirho = Some("b".repeat(64));
    resign_record_chirho(&mut conflicting_terminal_chirho);
    assert!(matches!(
        append_verified_move_stage_chirho(
            root_chirho,
            &conflicting_terminal_chirho,
            &AuthorityChirho,
        )
        .expect_err("handoff freezes the pre-authorized terminal bytes"),
        TenantMoveStoreRefusalChirho::RequiredPrestoredControlRecordMissingChirho {
            logged_chirho: 4,
            stored_chirho: 5,
        }
    ));
    assert_eq!(
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read refused log"),
        handoff_bytes_chirho
    );

    assert_eq!(
        prestore_post_handoff_move_records_chirho(
            root_chirho,
            &handoff_chirho,
            &terminal_chirho,
            &AuthorityChirho,
        )
        .expect_err("the future-record writer is unavailable after handoff"),
        TenantMoveStoreRefusalChirho::PrestoreRequiresCustodyPlacedChirho
    );
    append_verified_move_stage_chirho(root_chirho, &terminal_chirho, &AuthorityChirho)
        .expect("append exact terminal");
    assert_eq!(
        replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho)
            .expect("terminal replay"),
        MoveStageChirho::SourceRetiredChirho
    );
}

#[test]
fn append_refuses_an_unpermitted_control_record_under_its_own_identity_chirho() {
    let temp_chirho = tempfile::tempdir().expect("root");
    let root_chirho = temp_chirho.path();
    append_chirho(root_chirho, MoveStageChirho::PreparedChirho, 1).expect("prepare");
    let unpermitted_chirho = stage_record_chirho(MoveStageChirho::SourceRetiredChirho, 5);
    store_control_record_chirho(root_chirho, &unpermitted_chirho);
    let before_chirho =
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read log");

    assert_eq!(
        append_chirho(root_chirho, MoveStageChirho::SurfacesCarriedChirho, 2)
            .expect_err("a valid record outside the offered grammar must refuse"),
        TenantMoveStoreRefusalChirho::UnexpectedControlRecordChirho {
            allowed_chirho: 2,
            stored_chirho: 2,
        }
    );
    assert_eq!(
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read refused log"),
        before_chirho,
        "the unexpected-record refusal must fire before the offered stage is appended"
    );
}

#[test]
fn replay_refuses_when_a_logged_control_record_is_missing_chirho() {
    let temp_chirho = tempfile::tempdir().expect("root");
    let root_chirho = temp_chirho.path();
    let prepared_chirho = stage_record_chirho(MoveStageChirho::PreparedChirho, 1);
    append_verified_move_stage_chirho(root_chirho, &prepared_chirho, &AuthorityChirho)
        .expect("append prepared");
    let digest_chirho = move_stage_record_digest_chirho(&prepared_chirho).expect("record digest");
    std::fs::remove_file(control_record_path_chirho(root_chirho, &digest_chirho))
        .expect("remove control fixture");

    assert!(matches!(
        replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho)
            .expect_err("a stage row cannot outlive its signed control bytes"),
        TenantMoveStoreRefusalChirho::LoggedControlRecordMissingChirho {
            logged_chirho: 1,
            stored_chirho: 0,
        }
    ));
}

#[test]
fn post_handoff_sequence_overflow_cannot_alias_the_terminal_coordinate_chirho() {
    let retained_record_chirho = stage_record_chirho(MoveStageChirho::PreparedChirho, u64::MAX - 1);
    let retained_control_chirho = verified_control_record_chirho(&retained_record_chirho);
    let retained_chirho = VerifiedStoredMoveStageChirho {
        record_chirho: retained_record_chirho,
        verified_chirho: retained_control_chirho.verified_stage_chirho().clone(),
        record_digest_chirho: retained_control_chirho.record_digest_chirho().to_string(),
    };
    let terminal_record_chirho =
        stage_record_chirho(MoveStageChirho::SourceRetiredChirho, u64::MAX);
    let terminal_chirho = verified_control_record_chirho(&terminal_record_chirho);
    let mut handoff_record_chirho = stage_record_chirho(MoveStageChirho::WriterHandedOffChirho, 4);
    handoff_record_chirho.intent_chirho.stage_seq_chirho = u64::MAX;
    handoff_record_chirho
        .intent_chirho
        .post_handoff_record_digests_chirho =
        vec![terminal_chirho.record_digest_chirho().to_string()];
    resign_record_chirho(&mut handoff_record_chirho);
    let handoff_chirho = verified_control_record_chirho(&handoff_record_chirho);

    assert_eq!(
        validate_post_handoff_pair_chirho(
            &[retained_chirho],
            &handoff_chirho,
            &terminal_chirho,
            false,
        )
        .expect_err("u64::MAX has no next terminal coordinate"),
        TenantMoveStoreRefusalChirho::PostHandoffRecordSequenceMismatchChirho {
            handoff_chirho: u64::MAX,
            terminal_chirho: u64::MAX,
        }
    );
}

#[test]
fn a_handoff_offered_before_custody_is_refused_with_the_rules_own_reason_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_chirho(root_chirho, MoveStageChirho::PreparedChirho, 1).expect("prepare");
    append_chirho(root_chirho, MoveStageChirho::SurfacesCarriedChirho, 2).expect("carry");

    assert_eq!(
        append_chirho(root_chirho, MoveStageChirho::WriterHandedOffChirho, 3)
            .expect_err("handoff before custody"),
        TenantMoveStoreRefusalChirho::OrderingChirho {
            refusal_chirho: MoveAdvanceRefusalChirho::HandoffBeforeCustodyChirho,
        }
    );
    // And the writer did not move: the refusal happened before anything was appended.
    assert_eq!(writer_chirho(root_chirho), MoveWriterChirho::SourceChirho);
}

#[test]
fn retiring_the_source_before_handoff_is_refused_with_the_rules_own_reason_chirho() {
    // The opposite mistake, and it keeps its own identity through the store rather than becoming a
    // generic ordering error -- opposite mistakes have opposite fixes.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    for (stage_chirho, seq_chirho) in [
        (MoveStageChirho::PreparedChirho, 1),
        (MoveStageChirho::SurfacesCarriedChirho, 2),
        (MoveStageChirho::CustodyPlacedChirho, 3),
    ] {
        append_chirho(root_chirho, stage_chirho, seq_chirho).expect("stage");
    }
    assert_eq!(
        append_chirho(root_chirho, MoveStageChirho::SourceRetiredChirho, 4)
            .expect_err("retire before handoff"),
        TenantMoveStoreRefusalChirho::OrderingChirho {
            refusal_chirho: MoveAdvanceRefusalChirho::RetirementBeforeHandoffChirho,
        }
    );
}

#[test]
fn a_non_next_stage_sequence_is_refused_without_log_growth_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_chirho(root_chirho, MoveStageChirho::PreparedChirho, 1).expect("prepare");
    let before_chirho =
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read log");
    assert_eq!(
        append_chirho(root_chirho, MoveStageChirho::SurfacesCarriedChirho, 3)
            .expect_err("a fixed grammar cannot skip sequence two"),
        TenantMoveStoreRefusalChirho::StageSeqNotNextChirho {
            expected_chirho: 2,
            offered_chirho: 3,
        }
    );
    assert_eq!(
        replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho).expect("replay"),
        MoveStageChirho::PreparedChirho
    );
    assert_eq!(
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read refused log"),
        before_chirho
    );
}

#[test]
fn a_forged_stage_leaves_no_log_at_all_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let mut forged_chirho = stage_record_chirho(MoveStageChirho::PreparedChirho, 1);
    forged_chirho.sig_chirho = "sig-over:not-the-message-chirho".to_string();
    assert_eq!(
        append_verified_move_stage_chirho(root_chirho, &forged_chirho, &AuthorityChirho)
            .expect_err("forged"),
        TenantMoveStoreRefusalChirho::NotVerifiedChirho
    );
    assert!(!root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO).exists());
}

#[test]
fn a_move_with_no_stages_refuses_rather_than_reporting_prepared_chirho() {
    // Reporting PreparedChirho for a move nobody started would say "the source is the writer" about a
    // move that does not exist -- an answer that reads as authoritative and is about nothing.
    let temp_chirho = tempfile::tempdir().unwrap();
    assert!(matches!(
        replay_move_stage_chirho(
            temp_chirho.path(),
            "move-never-started-chirho",
            &AuthorityChirho
        )
        .expect_err("no such move"),
        TenantMoveStoreRefusalChirho::NoSuchMoveChirho { .. }
    ));
}

#[test]
fn every_later_stage_refuses_as_row_zero_on_append_and_replay_chirho() {
    for offered_chirho in [
        MoveStageChirho::SurfacesCarriedChirho,
        MoveStageChirho::CustodyPlacedChirho,
        MoveStageChirho::WriterHandedOffChirho,
        MoveStageChirho::SourceRetiredChirho,
    ] {
        let append_temp_chirho = tempfile::tempdir().unwrap();
        let append_root_chirho = append_temp_chirho.path();
        assert_eq!(
            append_chirho(append_root_chirho, offered_chirho, 1)
                .expect_err("a later stage cannot establish a move"),
            TenantMoveStoreRefusalChirho::OrderingChirho {
                refusal_chirho: MoveAdvanceRefusalChirho::FirstStageMustBePreparedChirho {
                    offered_chirho,
                },
            },
            "append path at {offered_chirho:?}"
        );
        assert!(
            !append_root_chirho
                .join(TENANT_MOVE_STAGE_LOG_CHIRHO)
                .exists(),
            "a refused first stage must not become durable"
        );

        let replay_temp_chirho = tempfile::tempdir().unwrap();
        let replay_root_chirho = replay_temp_chirho.path();
        write_record_direct_chirho(replay_root_chirho, &stage_record_chirho(offered_chirho, 1));
        assert_eq!(
            replay_move_stage_chirho(replay_root_chirho, MOVE_CHIRHO, &AuthorityChirho)
                .expect_err("a direct later row cannot self-establish"),
            TenantMoveStoreRefusalChirho::OrderingChirho {
                refusal_chirho: MoveAdvanceRefusalChirho::FirstStageMustBePreparedChirho {
                    offered_chirho,
                },
            },
            "replay path at {offered_chirho:?}"
        );
    }
}

#[test]
fn an_exact_signed_record_retry_is_a_no_op_even_after_later_progress_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let prepared_chirho = stage_record_chirho(MoveStageChirho::PreparedChirho, 1);
    append_verified_move_stage_chirho(root_chirho, &prepared_chirho, &AuthorityChirho)
        .expect("prepared");
    let prepared_bytes_chirho =
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read log");
    assert_eq!(
        append_verified_move_stage_chirho(root_chirho, &prepared_chirho, &AuthorityChirho)
            .expect("exact retry"),
        MoveStageChirho::PreparedChirho
    );
    assert_eq!(
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read log"),
        prepared_bytes_chirho,
        "an exact retry must append zero bytes"
    );

    append_chirho(root_chirho, MoveStageChirho::SurfacesCarriedChirho, 2).expect("carry");
    let carried_bytes_chirho =
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read log");
    assert_eq!(
        append_verified_move_stage_chirho(root_chirho, &prepared_chirho, &AuthorityChirho)
            .expect("retry an earlier exact record"),
        MoveStageChirho::SurfacesCarriedChirho,
        "retry returns the move's current stage rather than moving it backwards"
    );
    assert_eq!(
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read log"),
        carried_bytes_chirho,
        "retry after later progress must append zero bytes"
    );
}

#[test]
fn different_signed_records_at_one_sequence_refuse_as_conflict_not_retry_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_chirho(root_chirho, MoveStageChirho::PreparedChirho, 1).expect("prepare");
    let original_chirho = stage_record_chirho(MoveStageChirho::SurfacesCarriedChirho, 2);
    append_verified_move_stage_chirho(root_chirho, &original_chirho, &AuthorityChirho)
        .expect("first coordinate occupant");

    let mut conflicting_chirho = original_chirho.clone();
    conflicting_chirho.intent_chirho.surfaces_evidence_chirho = Some("f".repeat(64));
    resign_record_chirho(&mut conflicting_chirho);
    let refusal_chirho =
        append_verified_move_stage_chirho(root_chirho, &conflicting_chirho, &AuthorityChirho)
            .expect_err("different signed records at one sequence");
    assert_eq!(
        refusal_chirho,
        TenantMoveStoreRefusalChirho::ConflictingStageSeqChirho {
            move_id_chirho: MOVE_CHIRHO.to_string(),
            stage_seq_chirho: 2,
        }
    );
    assert!(!matches!(
        refusal_chirho,
        TenantMoveStoreRefusalChirho::ReplayedStageSeqChirho { .. }
    ));
    assert_eq!(read_records_chirho(root_chirho).unwrap().len(), 2);
}

#[test]
fn a_move_id_tamper_refuses_before_the_row_can_be_filtered_away_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let mut tampered_chirho = stage_record_chirho(MoveStageChirho::PreparedChirho, 1);
    tampered_chirho.intent_chirho.move_id_chirho = "move-b-chirho".to_string();
    write_record_direct_chirho(root_chirho, &tampered_chirho);

    let refusal_chirho = replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho)
        .expect_err("the unverified discriminator must not hide its row");
    assert_eq!(
        refusal_chirho,
        TenantMoveStoreRefusalChirho::NotVerifiedChirho
    );
    assert!(!matches!(
        refusal_chirho,
        TenantMoveStoreRefusalChirho::NoSuchMoveChirho { .. }
    ));
}

#[test]
fn one_move_cannot_change_source_or_target_coordinates_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_chirho(root_chirho, MoveStageChirho::PreparedChirho, 1).expect("prepare");
    let mut moved_target_chirho = stage_record_chirho(MoveStageChirho::SurfacesCarriedChirho, 2);
    moved_target_chirho.intent_chirho.target_root_chirho = "root-other-target-chirho".to_string();
    resign_record_chirho(&mut moved_target_chirho);
    assert_eq!(
        append_verified_move_stage_chirho(root_chirho, &moved_target_chirho, &AuthorityChirho)
            .expect_err("coordinates are immutable across a move"),
        TenantMoveStoreRefusalChirho::MoveCoordinatesChangedChirho {
            move_id_chirho: MOVE_CHIRHO.to_string(),
        }
    );
    assert_eq!(read_records_chirho(root_chirho).unwrap().len(), 1);

    write_record_direct_chirho(root_chirho, &moved_target_chirho);
    assert_eq!(
        replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho)
            .expect_err("replay pins the same coordinates"),
        TenantMoveStoreRefusalChirho::MoveCoordinatesChangedChirho {
            move_id_chirho: MOVE_CHIRHO.to_string(),
        }
    );
}

#[test]
fn the_complete_signed_record_resolves_outside_the_general_payload_cas_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let record_chirho = stage_record_chirho(MoveStageChirho::PreparedChirho, 1);
    let declared_chirho = move_stage_record_digest_chirho(&record_chirho).expect("record digest");
    append_verified_move_stage_chirho(root_chirho, &record_chirho, &AuthorityChirho)
        .expect("append");
    let retained_chirho =
        load_bounded_move_control_records_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho)
            .expect("load dedicated control shard");
    assert_eq!(retained_chirho.len(), 1);
    assert_eq!(retained_chirho[0].record_chirho(), &record_chirho);
    assert_eq!(retained_chirho[0].record_digest_chirho(), declared_chirho);
    assert!(
        !root_chirho.join("objects-chirho").exists(),
        "move authority evidence must never enter the carried payload CAS"
    );
}

#[test]
fn a_log_written_outside_the_append_path_refuses_on_replay_chirho() {
    // ADDED AFTER A SURVIVING MUTATION. Replacing replay's rule application with "take the last row"
    // killed nothing, because every log my other arms build goes through the APPEND path, which already
    // enforces ordering — so both readings agreed on every fixture I had. What replay-through-the-rule
    // actually defends is a log written OUTSIDE that path: hand-edited, or produced by a future writer
    // with a bug. Each row here is individually valid and correctly signed; only the SEQUENCE is
    // illegal, jumping from Prepared straight to retirement, which is the jump that erases a key.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    for (stage_chirho, seq_chirho) in [
        (MoveStageChirho::PreparedChirho, 1_u64),
        (MoveStageChirho::SourceRetiredChirho, 2_u64),
    ] {
        let record_chirho = stage_record_chirho(stage_chirho, seq_chirho);
        write_record_direct_chirho(root_chirho, &record_chirho);
    }

    assert_eq!(
        replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho)
            .expect_err("an illegal sequence must refuse on replay"),
        TenantMoveStoreRefusalChirho::OrderingChirho {
            refusal_chirho: MoveAdvanceRefusalChirho::RetirementBeforeHandoffChirho,
        }
    );
    // And the writer cannot be read either: a move whose log does not replay has no answer to "who may
    // write", and inventing one would be the worst possible response to a tampered log.
    assert!(current_writer_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho).is_err());
}

/// Write a four-row move log DIRECTLY, bypassing the append path, optionally tampering the handoff
/// row's signature. The append path verifies, so a row that fails verification can only be put on
/// disk this way — which is exactly the log a hand-edit or a buggy future writer would leave.
fn write_four_row_log_chirho(root_chirho: &Path, tamper_handoff_chirho: bool) {
    for (stage_chirho, seq_chirho) in [
        (MoveStageChirho::PreparedChirho, 1_u64),
        (MoveStageChirho::SurfacesCarriedChirho, 2_u64),
        (MoveStageChirho::CustodyPlacedChirho, 3_u64),
        (MoveStageChirho::WriterHandedOffChirho, 4_u64),
    ] {
        let record_chirho = stage_record_chirho(stage_chirho, seq_chirho);
        store_control_record_chirho(root_chirho, &record_chirho);
        if stage_chirho == MoveStageChirho::WriterHandedOffChirho {
            store_control_record_chirho(
                root_chirho,
                &stage_record_chirho(MoveStageChirho::SourceRetiredChirho, 5),
            );
        }
        let mut logged_record_chirho = record_chirho;
        if tamper_handoff_chirho && stage_chirho == MoveStageChirho::WriterHandedOffChirho {
            logged_record_chirho.sig_chirho = "sig-over:not-the-signed-message-chirho".to_string();
        }
        write_record_direct_chirho(root_chirho, &logged_record_chirho);
    }
}

#[test]
fn a_tampered_stage_row_refuses_rather_than_vanishing_and_moving_the_writer_backwards_chirho() {
    // ATTRIBUTING — this arm fails without the fix it guards. Replay used to
    // `.filter_map(|r| verify_move_stage_chirho(..).ok())`, which OMITTED a row that failed
    // verification instead of refusing it. Tampering the handoff row made that row VANISH, replay
    // stopped at CustodyPlaced, and `current_writer_chirho` then answered SourceChirho for a move
    // that had already handed off — the writer moving BACKWARDS on a tampered log, with no error.
    //
    // If this fails because NotVerifiedChirho is absent, the silent drop is back. If it fails
    // because the untampered control below also fails, the fixture stopped reaching the handoff
    // row — fix the fixture, not the assertion.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    write_four_row_log_chirho(root_chirho, true);

    let refusal_chirho = replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho)
        .expect_err("a row that fails verification must refuse, never be omitted");
    // Assert the IDENTITY, and assert it is NOT the neighbouring refusal: the other way this path
    // can refuse is the RULE's ordering complaint, and a fixture that tripped THAT would prove
    // nothing about verification while looking exactly as green.
    assert_eq!(
        refusal_chirho,
        TenantMoveStoreRefusalChirho::NotVerifiedChirho
    );
    assert!(!matches!(
        refusal_chirho,
        TenantMoveStoreRefusalChirho::OrderingChirho { .. }
    ));

    // The security consequence, asserted directly: a log that does not verify has no answer to
    // "who may write", and inventing one is the worst possible response.
    assert!(current_writer_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho).is_err());
}

#[test]
fn positive_control_the_untampered_four_row_log_reaches_handoff_chirho() {
    // NON-VACUITY for the arm above. Without this, a fixture that never reached the handoff row
    // would make that arm's refusal true for an uninteresting reason.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    write_four_row_log_chirho(root_chirho, false);

    assert_eq!(
        replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho).expect("replays"),
        MoveStageChirho::WriterHandedOffChirho
    );
    assert_eq!(writer_chirho(root_chirho), MoveWriterChirho::TargetChirho);
}

#[test]
fn concurrent_same_sequence_writers_add_exactly_one_row_chirho() {
    use std::sync::{Arc, Barrier};

    const WRITER_COUNT_CHIRHO: usize = 16;
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_chirho(root_chirho, MoveStageChirho::PreparedChirho, 1).expect("prepare");
    let barrier_chirho = Arc::new(Barrier::new(WRITER_COUNT_CHIRHO + 1));

    let results_chirho = std::thread::scope(|scope_chirho| {
        let handles_chirho = (0..WRITER_COUNT_CHIRHO)
            .map(|index_chirho| {
                let barrier_chirho = Arc::clone(&barrier_chirho);
                let mut record_chirho =
                    stage_record_chirho(MoveStageChirho::SurfacesCarriedChirho, 2);
                let digit_chirho = b"0123456789abcdef"[index_chirho] as char;
                record_chirho.intent_chirho.surfaces_evidence_chirho =
                    Some(digit_chirho.to_string().repeat(64));
                resign_record_chirho(&mut record_chirho);
                scope_chirho.spawn(move || {
                    barrier_chirho.wait();
                    append_verified_move_stage_chirho(root_chirho, &record_chirho, &AuthorityChirho)
                })
            })
            .collect::<Vec<_>>();
        barrier_chirho.wait();
        handles_chirho
            .into_iter()
            .map(|handle_chirho| handle_chirho.join().expect("writer thread"))
            .collect::<Vec<_>>()
    });

    assert_eq!(
        results_chirho
            .iter()
            .filter(|result_chirho| {
                matches!(result_chirho, Ok(MoveStageChirho::SurfacesCarriedChirho))
            })
            .count(),
        1,
        "one writer owns the sequence coordinate"
    );
    assert_eq!(
        results_chirho
            .iter()
            .filter(|result_chirho| {
                matches!(
                    result_chirho,
                    Err(TenantMoveStoreRefusalChirho::ConflictingStageSeqChirho {
                        stage_seq_chirho: 2,
                        ..
                    })
                )
            })
            .count(),
        WRITER_COUNT_CHIRHO - 1,
        "every losing writer receives the conflict identity"
    );
    assert_eq!(
        read_records_chirho(root_chirho).unwrap().len(),
        2,
        "prepared plus exactly one carried row"
    );
    assert_eq!(
        replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho).expect("replay"),
        MoveStageChirho::SurfacesCarriedChirho
    );
}

#[test]
fn an_unparseable_retained_row_refuses_instead_of_becoming_an_absent_coordinate_chirho() {
    // SCOPE/MIGRATION PATH. This pins the current single-source row decoder; it does NOT detect a
    // future stage-head sidecar because this fixture never makes a head disagree with its rows. If a
    // sidecar is introduced, add an explicit head-ahead/row-missing fixture before citing coverage of
    // that new two-source state. With no sidecar, a red here means a typed decode refusal collapsed.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_chirho(root_chirho, MoveStageChirho::PreparedChirho, 1).expect("prepare");
    cairn_durable_chirho::append_durable_line_chirho(
        &root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO),
        b"{\"truncated_chirho\":\n",
    )
    .expect("plant an unparseable retained row");
    let before_chirho =
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read planted log");

    let refusal_chirho = append_chirho(root_chirho, MoveStageChirho::SurfacesCarriedChirho, 2)
        .expect_err("decode failure must not become an absent sequence coordinate");
    assert_eq!(
        refusal_chirho,
        TenantMoveStoreRefusalChirho::DecodeChirho { line_chirho: 2 }
    );
    assert!(!matches!(
        refusal_chirho,
        TenantMoveStoreRefusalChirho::ConflictingStageSeqChirho { .. }
    ));
    assert_eq!(
        std::fs::read(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).expect("read refused log"),
        before_chirho,
        "an unreadable retained coordinate must not be replaced or extended"
    );
}

#[test]
fn an_unreadable_log_refuses_and_is_never_reported_as_no_such_move_chirho() {
    // ATTRIBUTING, and THREE cases rather than two. `Path::exists()` reports false BOTH for a
    // missing file and for one whose metadata call fails, so the old pre-check read an UNREADABLE
    // log as "no stage was ever recorded" — a failure signal converted into an absence, fail-OPEN.
    // Absent and unreadable must therefore carry DIFFERENT refusal identities, which is what the
    // two halves below pin.
    use std::os::unix::fs::PermissionsExt;

    // Case ABSENT keeps its own identity, on its own root.
    let absent_chirho = tempfile::tempdir().unwrap();
    assert_eq!(
        replay_move_stage_chirho(absent_chirho.path(), MOVE_CHIRHO, &AuthorityChirho)
            .expect_err("a root with no log at all"),
        TenantMoveStoreRefusalChirho::NoSuchMoveChirho {
            move_id_chirho: MOVE_CHIRHO.to_string(),
        }
    );

    // Case PRESENT-BUT-UNREADABLE: a real log, made unstattable.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    write_four_row_log_chirho(root_chirho, false);
    std::fs::set_permissions(root_chirho, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let stattable_chirho =
        std::fs::symlink_metadata(root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)).is_ok();
    let refusal_chirho = replay_move_stage_chirho(root_chirho, MOVE_CHIRHO, &AuthorityChirho).err();
    // Restore BEFORE asserting, so a red arm still leaves a deletable temp dir.
    std::fs::set_permissions(root_chirho, std::fs::Permissions::from_mode(0o700)).expect("restore");

    // The fixture must actually have produced the condition. Under a uid that bypasses mode bits
    // it would not have, and this arm would then pass while measuring nothing at all.
    assert!(
        !stattable_chirho,
        "fixture precondition failed: the log is still stattable under mode 000, so this arm \
         would be green-by-emptiness — it is running as a uid that bypasses permission bits"
    );
    assert_eq!(
        refusal_chirho,
        Some(TenantMoveStoreRefusalChirho::StoreUnavailableChirho)
    );
}
