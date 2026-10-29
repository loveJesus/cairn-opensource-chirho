// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Rotation-era journal proofs (split from journal_tests per the file-cap signal): Byzantine
//! manifest plants against the pre-rotation layout, rotate-seal + rotated full-open recomposition,
//! forged seam refusals, the rotated checkpoint fast open, and the forged manifest-tail miss.

use crate::journal_chirho::{
    ExpectedGenesisOpenErrorChirho, ExpectedGenesisRefusalReasonChirho,
    ExpectedLedgerGenesisChirho, JournalErrorChirho, LedgerJournalChirho,
    MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO, MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO,
};
use crate::journal_tests_chirho::{
    account_chirho, mint_request_chirho, transfer_request_chirho, HarnessChirho, MONEY_KIND_CHIRHO,
};
use crate::ports_chirho::{LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho};
use crate::segment_adapter_chirho::{
    SegmentContinuityOverLedgerSignerPortChirho, SegmentStorageOverLedgerPortChirho,
};
use anyhow::Result;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_seqlog_chirho::segment_chirho::continuity_chirho::sign_manifest_entry_chirho;
use cairn_seqlog_chirho::segment_chirho::manifest_chirho::{
    append_signed_manifest_line_chirho, new_segment_manifest_entry_chirho,
};
use cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho;
use cairn_seqlog_chirho::segment_chirho::LogIdentityChirho;

#[derive(serde::Serialize)]
struct TestRotationIntentChirho {
    schema_chirho: String,
    log_identity_digest_chirho: String,
    generation_chirho: u64,
    first_seq_chirho: u64,
    last_seq_chirho: u64,
    byte_len_chirho: u64,
    segment_digest_chirho: String,
    final_line_digest_chirho: String,
}

fn create_with_expected_genesis_chirho(
    harness_chirho: &HarnessChirho,
) -> (LedgerJournalChirho<'_>, ExpectedLedgerGenesisChirho) {
    let prepared_chirho = LedgerJournalChirho::prepare_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    let expected_chirho = ExpectedLedgerGenesisChirho::from_verified_identity_chirho(
        prepared_chirho.canonical_line_chirho(),
        prepared_chirho.digest_chirho().clone(),
    )
    .unwrap();
    let engine_chirho = LedgerJournalChirho::create_prepared_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        prepared_chirho,
    )
    .unwrap();
    (engine_chirho, expected_chirho)
}

fn foreign_expected_genesis_chirho(harness_chirho: &HarnessChirho) -> ExpectedLedgerGenesisChirho {
    let prepared_chirho = LedgerJournalChirho::prepare_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.cluster_chirho(),
        2,
    )
    .unwrap();
    ExpectedLedgerGenesisChirho::from_verified_identity_chirho(
        prepared_chirho.canonical_line_chirho(),
        prepared_chirho.digest_chirho().clone(),
    )
    .unwrap()
}

fn pending_first_rotation_marker_chirho(
    harness_chirho: &HarnessChirho,
) -> (StoragePathChirho, Vec<u8>) {
    let active_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let segment_digest_chirho = blake3::hash(&active_chirho).to_hex().to_string();
    let identity_chirho = LogIdentityChirho::new_chirho(format!(
        "cairn-ledger:{}",
        harness_chirho.cluster_chirho().0
    ));
    let marker_chirho = serde_json::to_vec(&TestRotationIntentChirho {
        schema_chirho: "segment-rotation-intent-v1-chirho".to_owned(),
        log_identity_digest_chirho: identity_chirho.digest_chirho(),
        generation_chirho: 0,
        first_seq_chirho: 0,
        last_seq_chirho: 0,
        byte_len_chirho: active_chirho.len() as u64,
        segment_digest_chirho,
        final_line_digest_chirho: blake3::hash(&active_chirho).to_hex().to_string(),
    })
    .unwrap();
    let marker_path_chirho = StoragePathChirho::new_chirho(
        SegmentPathsChirho::new_chirho(harness_chirho.path_chirho().key_chirho())
            .rotation_marker_chirho()
            .as_str_chirho(),
    );
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&marker_path_chirho, &marker_chirho)
        .unwrap();
    (marker_path_chirho, marker_chirho)
}

/// A signer whose key is NOT the journal's — its manifest signatures never verify against the
/// journal's injected trust root, so a manifest it signs is a FORGED artifact under the
/// Byzantine-storage threat model.
struct WrongManifestSignerChirho;

impl LedgerSignerPortChirho for WrongManifestSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(format!(
            "wrong-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "wrong-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

/// Plant a base>0 segment manifest under `harness`'s journal storage, signed by
/// `manifest_signer_chirho` (the journal's own signer for the valid-but-premature case; a wrong key
/// for the forged case). No sealed segment FILE is written: base derivation verifies the manifest
/// CHAIN (signature + identity + count + prev-chain), not the segment bytes, so one signed entry
/// spanning seqs 0..=4 is enough to make the manifest claim base 5.
fn plant_base_positive_manifest_chirho(
    harness_chirho: &HarnessChirho,
    manifest_signer_chirho: &dyn LedgerSignerPortChirho,
) {
    let paths_chirho = SegmentPathsChirho::new_chirho(harness_chirho.path_chirho().key_chirho());
    let identity_chirho = LogIdentityChirho::new_chirho(format!(
        "cairn-ledger:{}",
        harness_chirho.cluster_chirho().0
    ));
    let storage_chirho =
        SegmentStorageOverLedgerPortChirho::new_chirho(&harness_chirho.storage_chirho);
    let continuity_chirho =
        SegmentContinuityOverLedgerSignerPortChirho::new_chirho(manifest_signer_chirho);
    let entry_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        0,
        0,
        4,
        128,
        blake3::hash(b"synthetic-segment-chirho")
            .to_hex()
            .to_string(),
        blake3::hash(b"synthetic-final-line-chirho")
            .to_hex()
            .to_string(),
        None,
    );
    let line_chirho = sign_manifest_entry_chirho(&continuity_chirho, &entry_chirho).unwrap();
    append_signed_manifest_line_chirho(&storage_chirho, &paths_chirho, &line_chirho).unwrap();
}

/// claude2 #4709 (Byzantine-storage, reachable TODAY — not brick-3-only): a VALIDLY-SIGNED base>0
/// manifest planted on the pre-rotation single-file layout. The active file still starts at genesis
/// while the (journal-key-signed) manifest claims sequences are already sealed. `full_open` must FAIL
/// CLOSED at the brick-2a layout guard rather than mint a shifted money base — rotated-journal open is
/// brick 3, and no manifest may move the base under a layout the rotated-open format has not defined.
#[test]
fn open_fails_closed_on_valid_signed_base_positive_manifest_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    // Signed by the JOURNAL's OWN key: the manifest is authentic — only its base is premature.
    plant_base_positive_manifest_chirho(&harness_chirho, &harness_chirho.signer_chirho);
    match LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("sealed segment walk failed"),
            "unexpected chain-error detail: {detail_chirho}"
        ),
        _ => panic!("a base>0 manifest with no sealed segments must fail the sealed walk closed"),
    }
}

/// claude2 #4709: a FORGED manifest (signed by a key that is NOT the journal's) planted under the
/// journal storage. Base derivation verifies every manifest line against the journal's INJECTED trust
/// root (never the embedded key id), so the wrong-key signature fails and `full_open` FAILS CLOSED —
/// a Byzantine store cannot mint a base the journal key never authorized.
#[test]
fn open_fails_closed_on_forged_wrong_key_manifest_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    // Signed by a WRONG key — a Byzantine-storage forgery presentable NOW.
    plant_base_positive_manifest_chirho(&harness_chirho, &WrongManifestSignerChirho);
    match LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("segment base-seq derivation failed"),
            "unexpected chain-error detail: {detail_chirho}"
        ),
        _ => panic!("a forged (wrong-key) manifest must fail base-seq derivation closed"),
    }
}

#[test]
fn rotate_seals_active_chains_next_append_and_open_fails_closed_chirho() {
    // B0 brick 3b-ii: the STAGED rotate — seal via the journal's own ports, money/chain state
    // unchanged, the next append chains across the seam, the sidecar is removed, and until the
    // rotated-open lands (3b-iii) any reopen of the rotated journal FAILS CLOSED on the 2a
    // layout guard (the safe-ordering pin).
    let harness_chirho = HarnessChirho::new_chirho();
    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-rot-mint"))
        .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            120,
            "idem-rot-t1",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    assert!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&sidecar_path_chirho)
            .unwrap()
            .is_some(),
        "checkpoint sidecar must exist before rotation for the removal assertion to bite"
    );
    let pre_tail_seq_chirho = engine_chirho.tail_chirho().0;
    let pre_tail_digest_chirho = engine_chirho.tail_chirho().1.clone();
    let pre_supply_chirho = engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into());
    let pre_issuer_chirho = engine_chirho
        .head_state_chirho(&account_chirho("issuer-chirho"))
        .cloned();

    engine_chirho.rotate_chirho().unwrap();

    // Storage layout: a signed manifest entry exists, and the fresh active is EMPTY.
    let manifest_path_chirho = StoragePathChirho(
        cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho::new_chirho(
            harness_chirho.path_chirho().key_chirho(),
        )
        .manifest_chirho()
        .as_str_chirho()
        .to_owned(),
    );
    let manifest_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&manifest_path_chirho)
        .unwrap();
    assert!(
        manifest_bytes_chirho.is_some_and(|bytes_chirho| !bytes_chirho.is_empty()),
        "rotation must leave a durable signed manifest entry"
    );
    let active_after_rotate_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap_or_default();
    assert!(
        active_after_rotate_chirho.is_empty(),
        "the fresh active must be empty right after rotation"
    );
    // The stale advisory sidecar REMAINS on disk (removing it would spend the ≤7 rotation write
    // budget on a guarantee that already holds): at base > 0 its genesis binding can never verify,
    // so the reopen below must DISCARD it structurally — must-miss without a durable call.
    assert!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&sidecar_path_chirho)
            .unwrap()
            .is_some(),
        "rotation leaves the stale sidecar in place (structural discard, not durable removal)"
    );
    // Money/chain state is UNCHANGED by the layout cut.
    assert_eq!(engine_chirho.tail_chirho().0, pre_tail_seq_chirho);
    assert_eq!(engine_chirho.tail_chirho().1, &pre_tail_digest_chirho);
    assert_eq!(
        engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into()),
        pre_supply_chirho
    );
    assert_eq!(
        engine_chirho
            .head_state_chirho(&account_chirho("issuer-chirho"))
            .cloned(),
        pre_issuer_chirho
    );

    // The next append CHAINS ACROSS THE SEAM: seq continues, and the fresh active's first (only)
    // line physically carries prev = the pre-rotation tail digest at seq = pre-tail + 1.
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let seam_receipt_chirho = engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            30,
            "idem-rot-t2",
        ))
        .unwrap();
    assert_eq!(seam_receipt_chirho.seq_chirho, pre_tail_seq_chirho + 1);
    let active_lines_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let active_text_chirho = std::str::from_utf8(&active_lines_chirho).unwrap();
    let seam_lines_chirho: Vec<&str> = active_text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .collect();
    assert_eq!(
        seam_lines_chirho.len(),
        1,
        "the fresh active must hold exactly the one post-rotation record"
    );
    let seam_record_chirho: serde_json::Value = serde_json::from_str(seam_lines_chirho[0]).unwrap();
    assert_eq!(
        seam_record_chirho["seq_chirho"].as_u64().unwrap(),
        pre_tail_seq_chirho + 1
    );
    assert_eq!(
        seam_record_chirho["prev_chirho"].as_str().unwrap(),
        pre_tail_digest_chirho.0.as_str()
    );

    // 3b-iii ROTATED-OPEN EQUIVALENCE (evolved from the staged fail-closed pin): reopening the
    // rotated journal runs the manifest-walk recomposition (genesis from segment 1 + the seam
    // record from the fresh active) and must agree EXACTLY with the live pre-drop state — the
    // recovery law across the rotation seam.
    let live_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    let live_genesis_chirho = engine_chirho.genesis_digest_chirho().clone();
    let live_supply_chirho = engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into());
    let live_issuer_chirho = engine_chirho
        .head_state_chirho(&account_chirho("issuer-chirho"))
        .cloned();
    let live_alice_chirho = engine_chirho
        .head_state_chirho(&account_chirho("alice-chirho"))
        .cloned();
    drop(engine_chirho);
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .expect("the rotated journal must open via the manifest-walk rotated-open");
    assert!(
        !reopened_chirho.last_open_was_fast_chirho(),
        "the STALE pre-rotation sidecar must be structurally discarded (never a fast open at \
         base > 0) — checkpoint-less recovery with the sidecar still present"
    );
    assert_eq!(
        (
            reopened_chirho.tail_chirho().0,
            reopened_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho,
        "rotated reopen must recover the exact live tail"
    );
    assert_eq!(
        reopened_chirho.genesis_digest_chirho(),
        &live_genesis_chirho
    );
    assert_eq!(
        reopened_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into()),
        live_supply_chirho
    );
    assert_eq!(
        reopened_chirho
            .head_state_chirho(&account_chirho("issuer-chirho"))
            .cloned(),
        live_issuer_chirho
    );
    assert_eq!(
        reopened_chirho
            .head_state_chirho(&account_chirho("alice-chirho"))
            .cloned(),
        live_alice_chirho
    );
    // A further append on the REOPENED journal chains cleanly (the seam recovery is appendable).
    drop(reopened_chirho);
    let mut reopened_writer_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_400);
    let post_reopen_receipt_chirho = reopened_writer_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            10,
            "idem-rot-t3",
        ))
        .unwrap();
    assert_eq!(
        post_reopen_receipt_chirho.seq_chirho,
        live_tail_chirho.0 + 1
    );
}

/// B1 seam law (read side): the active file's first record after rotation must chain the SEALED
/// history exactly — a forged seq (not last-sealed + 1) and a forged prev (not the manifest-bound
/// final sealed digest) both REFUSE at the rotated-open via the chain law itself.
#[test]
fn rotated_open_rejects_forged_seam_seq_and_prev_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-seam-mint"))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    let seam_receipt_chirho = engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            50,
            "idem-seam-t1",
        ))
        .unwrap();
    let seam_seq_chirho = seam_receipt_chirho.seq_chirho;
    drop(engine_chirho);
    let clean_active_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();

    // Forge 1: the seam record claims a HIGHER seq (a gap over the sealed history).
    let forged_seq_chirho = String::from_utf8(clean_active_chirho.clone())
        .unwrap()
        .replacen(
            &format!("\"seq_chirho\":{seam_seq_chirho}"),
            &format!("\"seq_chirho\":{}", seam_seq_chirho + 1),
            1,
        );
    assert_ne!(forged_seq_chirho.as_bytes(), clean_active_chirho.as_slice());
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), forged_seq_chirho.as_bytes())
        .unwrap();
    match LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("dense law"),
            "forged seam seq must fail the dense law: {detail_chirho}"
        ),
        _ => panic!("a forged seam seq must fail the rotated-open closed"),
    }

    // Forge 2: the seam record's prev does NOT bind the sealed chain's final digest.
    let text_chirho = String::from_utf8(clean_active_chirho.clone()).unwrap();
    let prev_start_chirho = text_chirho.find("\"prev_chirho\":\"").unwrap() + 15;
    let mut forged_prev_chirho = text_chirho.clone();
    forged_prev_chirho.replace_range(prev_start_chirho..prev_start_chirho + 8, "deadbeef");
    assert_ne!(forged_prev_chirho, text_chirho);
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), forged_prev_chirho.as_bytes())
        .unwrap();
    match LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("prev mismatch"),
            "forged seam prev must fail the prev binding: {detail_chirho}"
        ),
        _ => panic!("a forged seam prev must fail the rotated-open closed"),
    }
}

/// Fast-path over sealed history: a POST-rotation checkpoint fast-opens the rotated journal with
/// exact live state — both the seam-append case and the empty-active case (sealed-resident tail).
#[test]
fn rotated_checkpoint_enables_fast_open_with_exact_state_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let cluster_chirho = harness_chirho.cluster_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        cluster_chirho.clone(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-fp-mint"))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    // CASE A: empty-active checkpoint (sealed-resident covered tail).
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let live_tail_a_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    let live_supply_chirho = engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into());
    drop(engine_chirho);
    let exact_a_chirho = LedgerJournalChirho::open_read_only_exact_head_checkpoint_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &cluster_chirho,
    )
    .unwrap();
    assert_eq!(
        (
            exact_a_chirho.tail_chirho().0,
            exact_a_chirho.tail_chirho().1.clone()
        ),
        live_tail_a_chirho,
        "empty-active held startup rereads the authenticated sealed tail"
    );
    drop(exact_a_chirho);
    let reopened_a_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &cluster_chirho,
    )
    .unwrap();
    assert!(
        reopened_a_chirho.last_open_was_fast_chirho(),
        "a post-rotation checkpoint with an empty active must FAST-open via the binding pair"
    );
    assert_eq!(
        (
            reopened_a_chirho.tail_chirho().0,
            reopened_a_chirho.tail_chirho().1.clone()
        ),
        live_tail_a_chirho
    );
    assert_eq!(
        reopened_a_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into()),
        live_supply_chirho
    );
    drop(reopened_a_chirho);
    // CASE B: seam append + fresh checkpoint (active-resident covered tail), then fast reopen.
    let mut writer_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &cluster_chirho,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    writer_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            50,
            "idem-fp-t1",
        ))
        .unwrap();
    writer_chirho.write_head_checkpoint_chirho().unwrap();
    let live_tail_b_chirho = (
        writer_chirho.tail_chirho().0,
        writer_chirho.tail_chirho().1.clone(),
    );
    let live_alice_chirho = writer_chirho
        .head_state_chirho(&account_chirho("alice-chirho"))
        .cloned();
    drop(writer_chirho);
    let exact_b_chirho = LedgerJournalChirho::open_read_only_exact_head_checkpoint_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &cluster_chirho,
    )
    .unwrap();
    assert_eq!(
        (
            exact_b_chirho.tail_chirho().0,
            exact_b_chirho.tail_chirho().1.clone()
        ),
        live_tail_b_chirho,
        "active-resident held startup verifies the exact physical tail"
    );
    drop(exact_b_chirho);
    let mut reopened_b_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &cluster_chirho,
    )
    .unwrap();
    assert!(reopened_b_chirho.last_open_was_fast_chirho());
    assert_eq!(
        (
            reopened_b_chirho.tail_chirho().0,
            reopened_b_chirho.tail_chirho().1.clone()
        ),
        live_tail_b_chirho
    );
    assert_eq!(
        reopened_b_chirho
            .head_state_chirho(&account_chirho("alice-chirho"))
            .cloned(),
        live_alice_chirho
    );
    // And it stays appendable after the fast rotated open.
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let receipt_chirho = reopened_b_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            5,
            "idem-fp-t2",
        ))
        .unwrap();
    assert_eq!(receipt_chirho.seq_chirho, live_tail_b_chirho.0 + 1);
}

/// A STALE pre-rotation sidecar (no binding pair) must NEVER fast-open a rotated journal — it
/// misses structurally and the full manifest-walk serves the exact state.
#[test]
fn stale_prerotation_sidecar_never_fast_opens_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let cluster_chirho = harness_chirho.cluster_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        cluster_chirho.clone(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-stale-mint"))
        .unwrap();
    // Checkpoint BEFORE rotation: the sidecar carries NO binding pair.
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    engine_chirho.rotate_chirho().unwrap();
    let live_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    drop(engine_chirho);
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &cluster_chirho,
    )
    .unwrap();
    assert!(
        !reopened_chirho.last_open_was_fast_chirho(),
        "a base-less sidecar on a rotated journal must miss (cross-state replay)"
    );
    assert_eq!(
        (
            reopened_chirho.tail_chirho().0,
            reopened_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho
    );
}

/// A validly-SIGNED sidecar whose manifest-tail binding is FORGED must miss the fast path (the
/// binding, not just the signature, is load-bearing) — and the full walk still serves exact state.
#[test]
fn forged_manifest_tail_binding_misses_fast_open_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let cluster_chirho = harness_chirho.cluster_chirho();
    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        cluster_chirho.clone(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-forge-mint"))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let live_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    drop(engine_chirho);
    // Forge: parse the REAL sidecar, swap the manifest-tail binding, RE-SIGN with the journal key
    // (the harness signer signs anything) — the signature verifies but the binding must refuse.
    let sidecar_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&sidecar_path_chirho)
        .unwrap()
        .unwrap();
    let mut forged_chirho =
        crate::checkpoint_chirho::parse_head_checkpoint_chirho(&sidecar_bytes_chirho).unwrap();
    forged_chirho.manifest_tail_entry_digest_chirho = Some("forged-tail-digest-chirho".into());
    let signing_chirho =
        String::from_utf8(forged_chirho.signing_message_chirho().unwrap()).unwrap();
    forged_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&signing_chirho)
        .unwrap();
    let forged_bytes_chirho =
        crate::checkpoint_chirho::canonical_head_checkpoint_bytes_chirho(&forged_chirho).unwrap();
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&sidecar_path_chirho, &forged_bytes_chirho)
        .unwrap();
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &cluster_chirho,
    )
    .unwrap();
    assert!(
        !reopened_chirho.last_open_was_fast_chirho(),
        "a forged (even validly re-signed) manifest-tail binding must miss the fast path"
    );
    assert_eq!(
        (
            reopened_chirho.tail_chirho().0,
            reopened_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho
    );
}

#[test]
fn expected_genesis_constructor_refuses_unbounded_line_before_parsing_chirho() {
    let refused_chirho = ExpectedLedgerGenesisChirho::from_verified_identity_chirho(
        &"x".repeat(MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO + 1),
        DigestChirho("0".repeat(64)),
    )
    .unwrap_err();
    assert_eq!(
        refused_chirho,
        ExpectedGenesisRefusalReasonChirho::ExpectedGenesisLineTooLargeChirho {
            observed_at_least_chirho: MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO + 1,
            maximum_chirho: MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO,
        }
    );
}

#[test]
fn expected_genesis_allows_torn_tail_repair_only_after_exact_match_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (engine_chirho, expected_chirho) = create_with_expected_genesis_chirho(&harness_chirho);
    drop(engine_chirho);
    let clean_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let torn_chirho = b"{\"torn_chirho\":";
    harness_chirho
        .storage_chirho
        .append_durable_chirho(&harness_chirho.path_chirho(), torn_chirho)
        .unwrap();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let reopened_chirho = LedgerJournalChirho::open_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
    )
    .unwrap();

    assert!(!reopened_chirho.last_open_was_fast_chirho());
    assert_eq!(
        reopened_chirho.repaired_torn_tail_bytes_chirho(),
        Some(torn_chirho.len() as u64)
    );
    assert_eq!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&harness_chirho.path_chirho())
            .unwrap()
            .unwrap(),
        clean_chirho
    );
    let writes_after_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    assert_eq!(
        writes_after_chirho[3] - writes_before_chirho[3],
        1,
        "the exact expectation permits the later verified-prefix truncate"
    );
}

#[test]
fn expected_genesis_read_only_refuses_torn_tail_without_mutation_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (engine_chirho, expected_chirho) = create_with_expected_genesis_chirho(&harness_chirho);
    drop(engine_chirho);
    harness_chirho
        .storage_chirho
        .append_durable_chirho(
            &harness_chirho.path_chirho(),
            b"{\"read-only-torn-chirho\":",
        )
        .unwrap();
    let bytes_before_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let refused_chirho = LedgerJournalChirho::open_read_only_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
    )
    .err()
    .expect("torn read-only journal must be refused");

    assert_eq!(
        refused_chirho,
        ExpectedGenesisOpenErrorChirho::JournalChirho {
            error_chirho: JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
                reason_chirho: crate::journal_chirho::ReadOnlyRecoveryReasonChirho::TornTailChirho,
            },
        }
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho
    );
    assert_eq!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&harness_chirho.path_chirho())
            .unwrap()
            .unwrap(),
        bytes_before_chirho
    );
}

#[test]
fn expected_genesis_read_only_refuses_pending_rotation_without_mutation_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (engine_chirho, expected_chirho) = create_with_expected_genesis_chirho(&harness_chirho);
    drop(engine_chirho);
    let (marker_path_chirho, marker_before_chirho) =
        pending_first_rotation_marker_chirho(&harness_chirho);
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let refused_chirho = LedgerJournalChirho::open_read_only_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
    )
    .err()
    .expect("pending rotation must be refused without mutation");

    assert_eq!(
        refused_chirho,
        ExpectedGenesisOpenErrorChirho::JournalChirho {
            error_chirho: JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
                reason_chirho:
                    crate::journal_chirho::ReadOnlyRecoveryReasonChirho::PendingRotationChirho,
            },
        }
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho
    );
    assert_eq!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&marker_path_chirho)
            .unwrap()
            .unwrap(),
        marker_before_chirho
    );
}

#[test]
fn expected_genesis_read_only_uses_verified_checkpoint_without_writes_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (mut engine_chirho, expected_chirho) = create_with_expected_genesis_chirho(&harness_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_210);
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            300,
            "idem-expected-read-only-fast-chirho",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let expected_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    drop(engine_chirho);
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let reopened_chirho = LedgerJournalChirho::open_read_only_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
    )
    .unwrap();

    assert!(reopened_chirho.last_open_was_fast_chirho());
    assert_eq!(
        (
            reopened_chirho.tail_chirho().0,
            reopened_chirho.tail_chirho().1.clone(),
        ),
        expected_tail_chirho
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho
    );
}

#[test]
fn foreign_expected_genesis_refuses_before_torn_tail_mutation_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (engine_chirho, _expected_chirho) = create_with_expected_genesis_chirho(&harness_chirho);
    drop(engine_chirho);
    harness_chirho
        .storage_chirho
        .append_durable_chirho(
            &harness_chirho.path_chirho(),
            b"{\"foreign-must-not-truncate-chirho\":",
        )
        .unwrap();
    let foreign_chirho = foreign_expected_genesis_chirho(&harness_chirho);
    let bytes_before_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let refused_chirho = LedgerJournalChirho::open_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &foreign_chirho,
    )
    .err()
    .expect("foreign expected genesis must refuse the open");
    let reads_after_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();

    assert_eq!(
        refused_chirho,
        ExpectedGenesisOpenErrorChirho::ExpectationRefusedChirho {
            reason_chirho: ExpectedGenesisRefusalReasonChirho::AuthoritativeGenesisMismatchChirho,
        }
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "foreign genesis must refuse before any repair mutation"
    );
    assert_eq!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&harness_chirho.path_chirho())
            .unwrap()
            .unwrap(),
        bytes_before_chirho,
        "the torn forensic suffix remains byte-exact on identity refusal"
    );
    assert_eq!(
        [
            reads_after_chirho[0] - reads_before_chirho[0],
            reads_after_chirho[1] - reads_before_chirho[1],
            reads_after_chirho[2] - reads_before_chirho[2],
            reads_after_chirho[3] - reads_before_chirho[3],
            reads_after_chirho[4] - reads_before_chirho[4],
        ],
        [2, 1, 0, 0, 0],
        "unrotated refusal is two metadata reads plus one bounded range read, never a full scan"
    );
}

#[test]
fn foreign_expected_genesis_refuses_before_pending_rotation_recovery_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (engine_chirho, expected_chirho) = create_with_expected_genesis_chirho(&harness_chirho);
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    drop(engine_chirho);
    let (marker_path_chirho, marker_chirho) = pending_first_rotation_marker_chirho(&harness_chirho);
    let foreign_chirho = foreign_expected_genesis_chirho(&harness_chirho);
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let refused_chirho = LedgerJournalChirho::open_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &foreign_chirho,
    )
    .err()
    .expect("foreign expected genesis must refuse pending recovery");

    assert!(matches!(
        refused_chirho,
        ExpectedGenesisOpenErrorChirho::ExpectationRefusedChirho {
            reason_chirho: ExpectedGenesisRefusalReasonChirho::AuthoritativeGenesisMismatchChirho,
        }
    ));
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "identity refusal must precede seal, manifest append, active reset, and marker removal"
    );
    assert_eq!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&marker_path_chirho)
            .unwrap()
            .unwrap(),
        marker_chirho,
        "the pending marker remains byte-exact after foreign-genesis refusal"
    );

    let reopened_chirho = LedgerJournalChirho::open_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
    )
    .unwrap();
    assert_eq!(reopened_chirho.tail_chirho().0, 0);
    assert!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&marker_path_chirho)
            .unwrap()
            .is_none(),
        "the same valid marker is recoverable only after the exact expectation succeeds"
    );
}

#[test]
fn rotated_expected_genesis_preflight_is_bounded_and_fast_open_stays_exact_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (mut engine_chirho, expected_chirho) = create_with_expected_genesis_chirho(&harness_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            500,
            "idem-expected-fast-chirho",
        ))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let live_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    drop(engine_chirho);

    let foreign_chirho = foreign_expected_genesis_chirho(&harness_chirho);
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    let refused_chirho = LedgerJournalChirho::open_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &foreign_chirho,
    )
    .err()
    .expect("foreign expected genesis must refuse rotated open");
    assert!(matches!(
        refused_chirho,
        ExpectedGenesisOpenErrorChirho::ExpectationRefusedChirho {
            reason_chirho: ExpectedGenesisRefusalReasonChirho::AuthoritativeGenesisMismatchChirho,
        }
    ));
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho
    );
    let reads_after_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    assert_eq!(
        [
            reads_after_chirho[0] - reads_before_chirho[0],
            reads_after_chirho[1] - reads_before_chirho[1],
            reads_after_chirho[2] - reads_before_chirho[2],
            reads_after_chirho[3] - reads_before_chirho[3],
            reads_after_chirho[4] - reads_before_chirho[4],
        ],
        [2, 2, 0, 0, 0],
        "rotated refusal reads one capped manifest line and one capped sealed genesis only"
    );

    let reopened_chirho = LedgerJournalChirho::open_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
    )
    .unwrap();
    assert!(reopened_chirho.last_open_was_fast_chirho());
    assert_eq!(
        (
            reopened_chirho.tail_chirho().0,
            reopened_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho
    );
    assert_eq!(
        reopened_chirho.genesis_digest_chirho(),
        expected_chirho.digest_chirho()
    );
}

#[test]
fn oversized_first_manifest_line_refuses_without_history_fallback_or_mutation_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (engine_chirho, expected_chirho) = create_with_expected_genesis_chirho(&harness_chirho);
    drop(engine_chirho);
    let manifest_path_chirho = StoragePathChirho::new_chirho(
        SegmentPathsChirho::new_chirho(harness_chirho.path_chirho().key_chirho())
            .manifest_chirho()
            .as_str_chirho(),
    );
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(
            &manifest_path_chirho,
            &vec![b'x'; MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO + 1],
        )
        .unwrap();
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let refused_chirho = LedgerJournalChirho::open_with_expected_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
    )
    .err()
    .expect("oversized first manifest line must refuse");

    assert_eq!(
        refused_chirho,
        ExpectedGenesisOpenErrorChirho::ExpectationRefusedChirho {
            reason_chirho:
                ExpectedGenesisRefusalReasonChirho::ExpectedGenesisManifestLineTooLargeChirho {
                    observed_at_least_chirho: MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO + 1,
                    maximum_chirho: MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO,
                },
        }
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho
    );
    let reads_after_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    assert_eq!(
        [
            reads_after_chirho[0] - reads_before_chirho[0],
            reads_after_chirho[1] - reads_before_chirho[1],
            reads_after_chirho[2] - reads_before_chirho[2],
            reads_after_chirho[3] - reads_before_chirho[3],
            reads_after_chirho[4] - reads_before_chirho[4],
        ],
        [1, 1, 0, 0, 0],
        "cap refusal must not full-read, list, or inspect history"
    );
}
