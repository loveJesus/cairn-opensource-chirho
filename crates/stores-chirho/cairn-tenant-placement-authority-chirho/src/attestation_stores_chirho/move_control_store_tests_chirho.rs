// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_tenant_chirho::move_chirho::move_attestation_chirho::*;
use cairn_tenant_chirho::move_chirho::move_stages_chirho::MoveStageChirho;
use std::fs;

const KEY_CHIRHO: &str = "move-authority-key-chirho";
const MOVE_CHIRHO: &str = "move-control-store-test-chirho";

struct AuthorityChirho;

impl MoveAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }

    fn verify_chirho(&self, message_chirho: &str, signature_chirho: &str) -> bool {
        signature_chirho == format!("sig-over:{message_chirho}")
    }
}

fn signed_prepared_chirho(stage_seq_chirho: u64) -> MoveStageAttestationChirho {
    let intent_chirho = MoveStageIntentChirho {
        schema_chirho: MOVE_STAGE_INTENT_SCHEMA_V2_CHIRHO.to_string(),
        move_id_chirho: MOVE_CHIRHO.to_string(),
        source_root_chirho: "source-root-chirho".to_string(),
        target_root_chirho: "target-root-chirho".to_string(),
        stage_chirho: MoveStageChirho::PreparedChirho,
        surfaces_evidence_chirho: None,
        post_handoff_record_digests_chirho: Vec::new(),
        retirement_authorization_digest_chirho: None,
        stage_seq_chirho,
    };
    let mut record_chirho = MoveStageAttestationChirho {
        schema_chirho: MOVE_STAGE_ATTESTATION_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: MOVE_STAGE_ATTESTATION_DOMAIN_V2_CHIRHO.to_string(),
        intent_digest_chirho: move_stage_intent_digest_chirho(&intent_chirho)
            .expect("intent digest"),
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

fn verified_chirho(stage_seq_chirho: u64) -> VerifiedMoveControlRecordChirho {
    verify_move_control_record_chirho(
        &signed_prepared_chirho(stage_seq_chirho),
        &AuthorityChirho,
        MOVE_CHIRHO,
    )
    .expect("verified record")
}

fn stored_path_chirho(root_chirho: &Path, record_digest_chirho: &str) -> std::path::PathBuf {
    let move_digest_chirho = blake3::hash(MOVE_CHIRHO.as_bytes()).to_hex().to_string();
    root_chirho
        .join(TENANT_MOVE_CONTROL_SURFACE_CHIRHO)
        .join(&move_digest_chirho[..2])
        .join(&move_digest_chirho[2..])
        .join(MOVE_CONTROL_STAGE_RECORDS_DIR_CHIRHO)
        .join(record_digest_chirho)
}

#[test]
fn a_verified_record_round_trips_outside_the_general_payload_cas_chirho() {
    let temp_chirho = tempfile::tempdir().expect("root");
    let verified_chirho = verified_chirho(1);
    store_verified_move_control_record_chirho(temp_chirho.path(), &verified_chirho).expect("store");

    let resolved_chirho = resolve_move_control_record_chirho(
        temp_chirho.path(),
        MOVE_CHIRHO,
        verified_chirho.record_digest_chirho(),
        &AuthorityChirho,
    )
    .expect("resolve");
    assert_eq!(resolved_chirho, verified_chirho);
    assert!(
        !temp_chirho.path().join("objects-chirho").exists(),
        "move control must not enter the carried payload CAS"
    );
}

#[test]
fn the_closed_record_set_refuses_missing_or_extra_objects_chirho() {
    let temp_chirho = tempfile::tempdir().expect("root");
    let first_chirho = verified_chirho(1);
    store_verified_move_control_record_chirho(temp_chirho.path(), &first_chirho).expect("first");
    let expected_chirho = BTreeSet::from([first_chirho.record_digest_chirho().to_string()]);
    assert_eq!(
        verify_move_control_record_set_chirho(
            temp_chirho.path(),
            MOVE_CHIRHO,
            &expected_chirho,
            &AuthorityChirho,
        )
        .expect("exact set"),
        vec![first_chirho.clone()]
    );

    let second_chirho = verified_chirho(2);
    store_verified_move_control_record_chirho(temp_chirho.path(), &second_chirho).expect("extra");
    assert_eq!(
        verify_move_control_record_set_chirho(
            temp_chirho.path(),
            MOVE_CHIRHO,
            &expected_chirho,
            &AuthorityChirho,
        )
        .expect_err("extra record refuses"),
        MoveControlStoreRefusalChirho::RecordSetMismatchChirho {
            expected_count_chirho: 1,
            found_count_chirho: 2,
        }
    );
}

#[test]
fn the_five_stage_grammar_caps_growth_without_breaking_exact_retry_chirho() {
    let temp_chirho = tempfile::tempdir().expect("root");
    let records_chirho: Vec<VerifiedMoveControlRecordChirho> = (1
        ..=MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO as u64)
        .map(verified_chirho)
        .collect();
    for record_chirho in &records_chirho {
        store_verified_move_control_record_chirho(temp_chirho.path(), record_chirho)
            .expect("within cap");
    }
    store_verified_move_control_record_chirho(temp_chirho.path(), &records_chirho[0])
        .expect("exact retry at the cap");
    assert_eq!(
        store_verified_move_control_record_chirho(temp_chirho.path(), &verified_chirho(6))
            .expect_err("sixth distinct record refuses"),
        MoveControlStoreRefusalChirho::BoundExceededChirho
    );
    assert_eq!(
        list_record_addresses_chirho(temp_chirho.path(), MOVE_CHIRHO)
            .expect("bounded list")
            .len(),
        MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO
    );
}

#[test]
fn concurrent_distinct_writers_cannot_exceed_the_five_record_grammar_chirho() {
    use std::sync::{Arc, Barrier};

    const WRITER_COUNT_CHIRHO: usize = 16;
    let temp_chirho = tempfile::tempdir().expect("root");
    let root_chirho = temp_chirho.path();
    let barrier_chirho = Arc::new(Barrier::new(WRITER_COUNT_CHIRHO + 1));
    let results_chirho = std::thread::scope(|scope_chirho| {
        let handles_chirho = (1..=WRITER_COUNT_CHIRHO)
            .map(|index_chirho| {
                let barrier_chirho = Arc::clone(&barrier_chirho);
                let record_chirho = verified_chirho(index_chirho as u64);
                scope_chirho.spawn(move || {
                    barrier_chirho.wait();
                    store_verified_move_control_record_chirho(root_chirho, &record_chirho)
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
            .filter(|result_chirho| result_chirho.is_ok())
            .count(),
        MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO
    );
    assert_eq!(
        results_chirho
            .iter()
            .filter(|result_chirho| {
                matches!(
                    result_chirho,
                    Err(MoveControlStoreRefusalChirho::BoundExceededChirho)
                )
            })
            .count(),
        WRITER_COUNT_CHIRHO - MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO
    );
    assert_eq!(
        list_record_addresses_chirho(root_chirho, MOVE_CHIRHO)
            .expect("bounded shard")
            .len(),
        MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO
    );
}

#[test]
fn retained_record_tamper_refuses_before_deserialization_or_authority_use_chirho() {
    let temp_chirho = tempfile::tempdir().expect("root");
    let verified_chirho = verified_chirho(1);
    store_verified_move_control_record_chirho(temp_chirho.path(), &verified_chirho).expect("store");
    fs::write(
        stored_path_chirho(temp_chirho.path(), verified_chirho.record_digest_chirho()),
        b"{}",
    )
    .expect("tamper fixture");
    assert_eq!(
        resolve_move_control_record_chirho(
            temp_chirho.path(),
            MOVE_CHIRHO,
            verified_chirho.record_digest_chirho(),
            &AuthorityChirho,
        )
        .expect_err("tamper refuses"),
        MoveControlStoreRefusalChirho::CorruptObjectChirho
    );
}
