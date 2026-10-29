// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! C5 B3-a1 and a2-ii: the elected erasure's sink sees an authenticated cut before any key is removed, a sink that refuses stops it with nothing removed or recorded, and the root classifies, binds and reconciles from its own authenticated erasure log.

use super::*;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

const ALICE_CHIRHO: &str = "user/alice";
const BOB_CHIRHO: &str = "user/bob";
/// Private text a sink's binding refusal carries. The public pending error must never echo it (gpt #29956).
const BINDING_SENTINEL_CHIRHO: &str = "private-sentinel-cause carol@example.com";

/// A sink that records each capture with how many of its key files still existed when it ran, the evidence
/// it was handed, and every binding. It reports the unbound seqs an arm gives it, and can fail its binding.
struct RecordingSinkChirho {
    root_chirho: PathBuf,
    refuse_chirho: bool,
    seen_chirho: RefCell<Vec<(ErasureCaptureChirho, usize)>>,
    unbound_chirho: RefCell<Vec<u64>>,
    earlier_seen_chirho: RefCell<Vec<BTreeMap<u64, EarlierErasureEvidenceChirho>>>,
    bindings_chirho: RefCell<Vec<(u64, String, String)>>,
    fail_binding_chirho: Cell<bool>,
}

impl RecordingSinkChirho {
    fn new_chirho(root_chirho: &Path, refuse_chirho: bool) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            refuse_chirho,
            seen_chirho: RefCell::new(Vec::new()),
            unbound_chirho: RefCell::new(Vec::new()),
            earlier_seen_chirho: RefCell::new(Vec::new()),
            bindings_chirho: RefCell::new(Vec::new()),
            fail_binding_chirho: Cell::new(false),
        }
    }

    fn seen_chirho(&self) -> Vec<(ErasureCaptureChirho, usize)> {
        self.seen_chirho.borrow().clone()
    }
}

impl ErasureRequirementSinkChirho for RecordingSinkChirho {
    fn unbound_requirement_seqs_chirho(&self, _subject_chirho: &str) -> Result<Vec<u64>> {
        Ok(self.unbound_chirho.borrow().clone())
    }

    fn record_requirement_chirho(
        &self,
        capture_chirho: &ErasureCaptureChirho,
        earlier_chirho: &BTreeMap<u64, EarlierErasureEvidenceChirho>,
    ) -> Result<()> {
        self.earlier_seen_chirho
            .borrow_mut()
            .push(earlier_chirho.clone());
        let present_chirho = capture_chirho
            .key_ids_chirho
            .iter()
            .filter(|key_id_chirho| key_path_chirho(&self.root_chirho, key_id_chirho).exists())
            .count();
        self.seen_chirho
            .borrow_mut()
            .push((capture_chirho.clone(), present_chirho));
        if self.refuse_chirho {
            bail!("test sink refuses");
        }
        Ok(())
    }

    fn record_binding_chirho(
        &self,
        erasure_seq_chirho: u64,
        subject_chirho: &str,
        erasure_record_digest_chirho: &str,
    ) -> Result<()> {
        if self.fail_binding_chirho.get() {
            bail!("test sink cannot bind: {BINDING_SENTINEL_CHIRHO}");
        }
        self.bindings_chirho.borrow_mut().push((
            erasure_seq_chirho,
            subject_chirho.to_string(),
            erasure_record_digest_chirho.to_string(),
        ));
        Ok(())
    }
}

fn store_chirho(root_chirho: &Path, subject_chirho: &str) -> String {
    store_private_blob_chirho(
        root_chirho,
        &PrivateBlobAttributionChirho::for_test_subject_chirho(subject_chirho),
        subject_chirho,
        b"b3-a1 capture fixture",
    )
    .unwrap()
    .key_id_chirho
}

fn erase_with_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    sink_chirho: &RecordingSinkChirho,
) -> Result<PrivacyErasureRecordChirho> {
    erase_subject_data_with_requirement_chirho(
        root_chirho,
        subject_chirho,
        "owner/admin",
        "gdpr-erasure",
        &BTreeSet::new(),
        sink_chirho,
    )
}

fn ids_chirho<const N_CHIRHO: usize>(ids_chirho: [&String; N_CHIRHO]) -> BTreeSet<String> {
    ids_chirho.into_iter().cloned().collect()
}

#[test]
fn the_sink_sees_an_authenticated_cut_before_any_key_is_removed_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_one_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let bob_chirho = store_chirho(&root_chirho, BOB_CHIRHO);
    let alice_two_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    let record_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap();

    let seen_chirho = sink_chirho.seen_chirho();
    assert_eq!(seen_chirho.len(), 1);
    let (capture_chirho, present_chirho) = &seen_chirho[0];
    assert_eq!(capture_chirho.erasure_seq_chirho, 0);
    assert_eq!(capture_chirho.subject_chirho, ALICE_CHIRHO);
    assert_eq!(
        capture_chirho.key_ids_chirho,
        ids_chirho([&alice_one_chirho, &alice_two_chirho])
    );
    // Bob's record sits between Alice's: the bound is the whole log's length, not her row count.
    assert_eq!(capture_chirho.erased_below_blob_seq_chirho, 3);
    assert_eq!(
        *present_chirho, 2,
        "the sink must run before any key is removed"
    );
    assert!(!key_path_chirho(&root_chirho, &alice_one_chirho).exists());
    assert!(!key_path_chirho(&root_chirho, &alice_two_chirho).exists());
    assert!(key_path_chirho(&root_chirho, &bob_chirho).exists());
    assert_eq!(record_chirho.seq_chirho, 0);
    assert_eq!(
        record_chirho.key_ids_chirho.iter().collect::<BTreeSet<_>>(),
        capture_chirho
            .key_ids_chirho
            .iter()
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn a_refusing_sink_stops_the_erasure_with_no_key_removed_and_no_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, true);

    let error_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap_err();

    assert!(
        format!("{error_chirho:#}").contains("test sink refuses"),
        "{error_chirho:#}"
    );
    assert_eq!(sink_chirho.seen_chirho().len(), 1);
    assert!(key_path_chirho(&root_chirho, &alice_chirho).exists());
    assert!(load_privacy_erasure_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());
}

#[test]
fn the_cut_is_the_union_of_the_signed_log_and_the_local_key_files_chirho() {
    let root_chirho = tmp_root_chirho();
    let logged_only_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let both_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    // An earlier attempt already unlinked this key; only the signed log still names it.
    std::fs::remove_file(key_path_chirho(&root_chirho, &logged_only_chirho)).unwrap();
    // A crash between a key file and its blob record leaves a key only the local scan finds.
    let local_only_chirho = "c0ffee00c0ffee00c0ffee00c0ffee00".to_string();
    let orphan_chirho = ShredKeyChirho {
        subject_chirho: ALICE_CHIRHO.to_string(),
        key_hex_chirho: "00".repeat(32),
    };
    write_private_key_file_chirho(
        &key_path_chirho(&root_chirho, &local_only_chirho),
        &serde_json::to_vec(&orphan_chirho).unwrap(),
    )
    .unwrap();
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    let record_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap();

    let (capture_chirho, present_chirho) = sink_chirho.seen_chirho().remove(0);
    assert_eq!(
        capture_chirho.key_ids_chirho,
        ids_chirho([&logged_only_chirho, &both_chirho, &local_only_chirho])
    );
    assert_eq!(present_chirho, 2);
    assert_eq!(capture_chirho.erased_below_blob_seq_chirho, 2);
    // The local record names only what this attempt unlinked; the cut keeps the logged-only key.
    assert_eq!(
        record_chirho
            .key_ids_chirho
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        ids_chirho([&both_chirho, &local_only_chirho])
    );
}

#[test]
fn an_unauthenticated_blob_log_refuses_before_the_sink_and_before_any_unlink_chirho() {
    // gpt #29699: a namespace check is not a signature check.
    let bad_signature_root_chirho = tmp_root_chirho();
    let first_chirho = store_chirho(&bad_signature_root_chirho, ALICE_CHIRHO);
    let second_chirho = store_chirho(&bad_signature_root_chirho, ALICE_CHIRHO);
    let mut records_chirho = load_privacy_blob_records_chirho(&bad_signature_root_chirho).unwrap();
    let last_chirho = records_chirho[1].sig_chirho.pop().unwrap();
    records_chirho[1]
        .sig_chirho
        .push(if last_chirho == '0' { '1' } else { '0' });
    write_jsonl_records_chirho(
        &privacy_blob_records_path_chirho(&bad_signature_root_chirho),
        &records_chirho,
    );
    // A seq gap, on a leader that has already lost its key files.
    let gap_root_chirho = tmp_root_chirho();
    let lost_one_chirho = store_chirho(&gap_root_chirho, ALICE_CHIRHO);
    let lost_two_chirho = store_chirho(&gap_root_chirho, ALICE_CHIRHO);
    let mut gap_records_chirho = load_privacy_blob_records_chirho(&gap_root_chirho).unwrap();
    gap_records_chirho[1].seq_chirho = 2;
    write_jsonl_records_chirho(
        &privacy_blob_records_path_chirho(&gap_root_chirho),
        &gap_records_chirho,
    );
    for key_id_chirho in [&lost_one_chirho, &lost_two_chirho] {
        std::fs::remove_file(key_path_chirho(&gap_root_chirho, key_id_chirho)).unwrap();
    }

    for (case_chirho, root_chirho, needle_chirho) in [
        (
            "a bad signature",
            &bad_signature_root_chirho,
            "signature invalid",
        ),
        ("a seq gap", &gap_root_chirho, "seq gap"),
    ] {
        let sink_chirho = RecordingSinkChirho::new_chirho(root_chirho, false);
        let error_chirho = erase_with_chirho(root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap_err();
        assert!(
            format!("{error_chirho:#}").contains(needle_chirho),
            "{case_chirho}: {error_chirho:#}"
        );
        assert!(
            sink_chirho.seen_chirho().is_empty(),
            "{case_chirho}: the sink must never see a cut from an unauthenticated log"
        );
        assert!(load_privacy_erasure_records_chirho(root_chirho)
            .unwrap()
            .is_empty());
    }
    assert!(key_path_chirho(&bad_signature_root_chirho, &first_chirho).exists());
    assert!(key_path_chirho(&bad_signature_root_chirho, &second_chirho).exists());
}

const SEED_FILE_CHIRHO: &str = "signing-key-chirho.bin";
const PUBLIC_FILE_CHIRHO: &str = "pubkey-chirho.hex";

/// Nothing was minted, nothing was cut or unlinked, and no erasure row was written.
fn assert_refused_untouched_chirho(
    root_chirho: &Path,
    sink_chirho: &RecordingSinkChirho,
    case_chirho: &str,
) {
    assert!(
        sink_chirho.seen_chirho().is_empty(),
        "{case_chirho}: the sink must not run"
    );
    assert!(
        !root_chirho.join(SEED_FILE_CHIRHO).exists(),
        "{case_chirho}: a signing seed was minted"
    );
    assert!(
        load_privacy_erasure_records_chirho(root_chirho)
            .unwrap()
            .is_empty(),
        "{case_chirho}: an erasure row was written"
    );
}

#[test]
fn losing_both_key_files_refuses_without_minting_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    for name_chirho in [SEED_FILE_CHIRHO, PUBLIC_FILE_CHIRHO] {
        std::fs::remove_file(root_chirho.join(name_chirho)).unwrap();
    }
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    assert!(erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).is_err());

    assert_refused_untouched_chirho(&root_chirho, &sink_chirho, "both key files lost");
    assert!(!root_chirho.join(PUBLIC_FILE_CHIRHO).exists());
    assert!(key_path_chirho(&root_chirho, &alice_chirho).exists());
}

#[test]
fn losing_only_the_signing_seed_refuses_before_any_cut_or_unlink_chirho() {
    // gpt #29719: the public key alone authenticates the log but proves no possession. A load-or-create
    // final sign would then mint a replacement key and overwrite the public key, orphaning old history.
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    std::fs::remove_file(root_chirho.join(SEED_FILE_CHIRHO)).unwrap();
    let public_before_chirho = std::fs::read(root_chirho.join(PUBLIC_FILE_CHIRHO)).unwrap();
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    assert!(erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).is_err());

    assert_refused_untouched_chirho(&root_chirho, &sink_chirho, "only the seed lost");
    assert_eq!(
        std::fs::read(root_chirho.join(PUBLIC_FILE_CHIRHO)).unwrap(),
        public_before_chirho
    );
    assert!(key_path_chirho(&root_chirho, &alice_chirho).exists());
}

#[test]
fn a_keyless_root_with_no_blobs_refuses_without_minting_chirho() {
    // An empty blob log and an empty hold log read no public key, so possession is the only check left.
    let root_chirho = tmp_root_chirho();
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    assert!(erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).is_err());

    assert_refused_untouched_chirho(&root_chirho, &sink_chirho, "a keyless empty root");
    assert!(!root_chirho.join(PUBLIC_FILE_CHIRHO).exists());
}

/// A sink that loses the signing seed while it runs: custody vanishing between the proof and the sign.
struct SeedDroppingSinkChirho {
    root_chirho: PathBuf,
    calls_chirho: RefCell<usize>,
}

impl ErasureRequirementSinkChirho for SeedDroppingSinkChirho {
    fn unbound_requirement_seqs_chirho(&self, _subject_chirho: &str) -> Result<Vec<u64>> {
        Ok(Vec::new())
    }

    fn record_binding_chirho(
        &self,
        _seq_chirho: u64,
        _subject_chirho: &str,
        _digest_chirho: &str,
    ) -> Result<()> {
        Ok(())
    }

    fn record_requirement_chirho(
        &self,
        _capture_chirho: &ErasureCaptureChirho,
        _earlier_chirho: &BTreeMap<u64, EarlierErasureEvidenceChirho>,
    ) -> Result<()> {
        *self.calls_chirho.borrow_mut() += 1;
        std::fs::remove_file(self.root_chirho.join(SEED_FILE_CHIRHO))?;
        Ok(())
    }
}

#[test]
fn custody_lost_after_the_sink_refuses_the_final_sign_without_minting_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let public_before_chirho = std::fs::read(root_chirho.join(PUBLIC_FILE_CHIRHO)).unwrap();
    let sink_chirho = SeedDroppingSinkChirho {
        root_chirho: root_chirho.clone(),
        calls_chirho: RefCell::new(0),
    };

    let result_chirho = erase_subject_data_with_requirement_chirho(
        &root_chirho,
        ALICE_CHIRHO,
        "owner/admin",
        "gdpr-erasure",
        &BTreeSet::new(),
        &sink_chirho,
    );

    assert!(result_chirho.is_err());
    assert_eq!(*sink_chirho.calls_chirho.borrow(), 1);
    assert!(
        !root_chirho.join(SEED_FILE_CHIRHO).exists(),
        "the final sign must refuse, never mint"
    );
    assert_eq!(
        std::fs::read(root_chirho.join(PUBLIC_FILE_CHIRHO)).unwrap(),
        public_before_chirho
    );
    assert!(load_privacy_erasure_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    // The keys were already unlinked, so the sink's durable requirement is what recovery works from.
    assert!(!key_path_chirho(&root_chirho, &alice_chirho).exists());
}

#[test]
fn another_subject_takes_the_same_seq_after_a_refused_attempt_chirho() {
    // Why the requirement store keys by seq AND subject: a refused attempt leaves the seq unclaimed.
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    store_chirho(&root_chirho, BOB_CHIRHO);
    let refusing_chirho = RecordingSinkChirho::new_chirho(&root_chirho, true);
    let accepting_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    erase_with_chirho(&root_chirho, ALICE_CHIRHO, &refusing_chirho).unwrap_err();
    let bob_record_chirho = erase_with_chirho(&root_chirho, BOB_CHIRHO, &accepting_chirho).unwrap();
    erase_with_chirho(&root_chirho, ALICE_CHIRHO, &accepting_chirho).unwrap();

    let refused_chirho = &refusing_chirho.seen_chirho()[0].0;
    let accepted_chirho = accepting_chirho.seen_chirho();
    assert_eq!(
        (
            refused_chirho.erasure_seq_chirho,
            refused_chirho.subject_chirho.as_str()
        ),
        (0, ALICE_CHIRHO)
    );
    assert_eq!(
        (
            accepted_chirho[0].0.erasure_seq_chirho,
            accepted_chirho[0].0.subject_chirho.as_str()
        ),
        (0, BOB_CHIRHO)
    );
    assert_eq!(bob_record_chirho.seq_chirho, 0);
    assert_eq!(
        (
            accepted_chirho[1].0.erasure_seq_chirho,
            accepted_chirho[1].0.subject_chirho.as_str()
        ),
        (1, ALICE_CHIRHO)
    );
    assert_eq!(
        accepted_chirho[1].0.key_ids_chirho,
        ids_chirho([&alice_chirho])
    );
}

#[test]
fn a_repeat_erasure_still_captures_the_logged_ids_after_the_local_files_are_gone_chirho() {
    // agy R-C5-3: a retry whose local files were already unlinked must not capture an empty cut.
    let root_chirho = tmp_root_chirho();
    let one_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let two_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap();
    let repeat_record_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap();

    let (repeat_capture_chirho, present_chirho) = sink_chirho.seen_chirho().remove(1);
    assert_eq!(repeat_capture_chirho.erasure_seq_chirho, 1);
    assert_eq!(
        repeat_capture_chirho.key_ids_chirho,
        ids_chirho([&one_chirho, &two_chirho])
    );
    assert_eq!(present_chirho, 0);
    assert!(
        repeat_record_chirho.key_ids_chirho.is_empty(),
        "the local record still names only what this attempt unlinked"
    );
}

// C5 B3-a2-ii: classification, binding and reconcile, against the root's own authenticated erasure log.

fn erase_requiring_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    required_chirho: &BTreeSet<String>,
    sink_chirho: &RecordingSinkChirho,
) -> Result<PrivacyErasureRecordChirho> {
    erase_subject_data_with_requirement_chirho(
        root_chirho,
        subject_chirho,
        "owner/admin",
        "gdpr-erasure",
        required_chirho,
        sink_chirho,
    )
}

fn digest_chirho(record_chirho: &PrivacyErasureRecordChirho) -> String {
    erasure_record_digest_hex_chirho(record_chirho).unwrap()
}

/// An erasure of `subject_chirho` whose record is appended but whose binding the sink loses.
fn recorded_unbound_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    sink_chirho: &RecordingSinkChirho,
) -> ErasureRecordedBindingPendingChirho {
    sink_chirho.fail_binding_chirho.set(true);
    let error_chirho = erase_with_chirho(root_chirho, subject_chirho, sink_chirho).unwrap_err();
    sink_chirho.fail_binding_chirho.set(false);
    error_chirho
        .downcast_ref::<ErasureRecordedBindingPendingChirho>()
        .expect("a binding lost after the append must be typed pending")
        .clone()
}

#[test]
fn the_elected_erasure_binds_its_requirement_to_the_appended_records_digest_chirho() {
    let root_chirho = tmp_root_chirho();
    store_chirho(&root_chirho, ALICE_CHIRHO);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    let record_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap();

    let loaded_chirho = load_privacy_erasure_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        *sink_chirho.bindings_chirho.borrow(),
        vec![(
            0,
            ALICE_CHIRHO.to_string(),
            digest_chirho(&loaded_chirho[0])
        )],
        "the in-lock digest is the authenticated row's"
    );
    // The digest is domain-tagged over the canonical record, signature included.
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"cairn-privacy-erasure-record-v1-chirho");
    hasher_chirho.update(&serde_json::to_vec(&record_chirho).unwrap());
    assert_eq!(
        digest_chirho(&record_chirho),
        hasher_chirho.finalize().to_hex().to_string()
    );
    let mut resigned_chirho = record_chirho.clone();
    resigned_chirho.sig_chirho.push('0');
    assert_ne!(
        digest_chirho(&resigned_chirho),
        digest_chirho(&record_chirho)
    );
}

#[test]
fn a_binding_lost_after_the_append_is_typed_pending_and_reconcile_binds_it_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);
    sink_chirho.fail_binding_chirho.set(true);

    let error_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap_err();

    // The public text is fixed: the sink's refusal, and the private text in it, never reach it.
    for text_chirho in [format!("{error_chirho:#}"), format!("{error_chirho:?}")] {
        assert!(
            text_chirho.contains("ErasureRecordedBindingPendingChirho"),
            "{text_chirho}"
        );
        assert!(
            !text_chirho.contains(BINDING_SENTINEL_CHIRHO) && !text_chirho.contains("cannot bind"),
            "the pending error echoed the sink's refusal"
        );
    }
    let pending_chirho = error_chirho
        .downcast_ref::<ErasureRecordedBindingPendingChirho>()
        .expect("a binding lost after the append must be typed pending")
        .clone();
    sink_chirho.fail_binding_chirho.set(false);

    let records_chirho = load_privacy_erasure_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 1, "the erasure is recorded");
    assert_eq!(pending_chirho.erasure_seq_chirho, 0);
    assert_eq!(
        pending_chirho.erasure_record_digest_chirho,
        digest_chirho(&records_chirho[0])
    );
    assert!(!key_path_chirho(&root_chirho, &alice_chirho).exists());
    assert!(sink_chirho.bindings_chirho.borrow().is_empty());

    sink_chirho.unbound_chirho.replace(vec![0]);
    let bound_chirho =
        reconcile_subject_erasure_bindings_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho)
            .unwrap();

    assert_eq!(bound_chirho, vec![0]);
    assert_eq!(
        *sink_chirho.bindings_chirho.borrow(),
        vec![(
            0,
            ALICE_CHIRHO.to_string(),
            pending_chirho.erasure_record_digest_chirho.clone()
        )]
    );
    assert_eq!(
        load_privacy_erasure_records_chirho(&root_chirho).unwrap(),
        records_chirho,
        "reconcile writes no record"
    );
    assert_eq!(
        sink_chirho.seen_chirho().len(),
        1,
        "reconcile records no requirement"
    );
}

#[test]
fn the_next_erasure_classifies_a_recorded_unbound_attempt_as_recorded_chirho() {
    let root_chirho = tmp_root_chirho();
    store_chirho(&root_chirho, ALICE_CHIRHO);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);
    let pending_chirho = recorded_unbound_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho);
    store_chirho(&root_chirho, ALICE_CHIRHO);
    sink_chirho.unbound_chirho.replace(vec![0]);

    let second_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap();

    assert_eq!(second_chirho.seq_chirho, 1);
    assert_eq!(
        sink_chirho.earlier_seen_chirho.borrow()[1],
        BTreeMap::from([(
            0,
            EarlierErasureEvidenceChirho::RecordedChirho {
                erasure_record_digest_chirho: pending_chirho.erasure_record_digest_chirho
            }
        )])
    );
}

#[test]
fn a_never_recorded_attempt_whose_seq_another_subject_took_is_carried_chirho() {
    let root_chirho = tmp_root_chirho();
    store_chirho(&root_chirho, ALICE_CHIRHO);
    store_chirho(&root_chirho, BOB_CHIRHO);
    // The refusing sink stands for a requirement made durable whose erasure then stopped unrecorded.
    let refusing_chirho = RecordingSinkChirho::new_chirho(&root_chirho, true);
    erase_with_chirho(&root_chirho, ALICE_CHIRHO, &refusing_chirho).unwrap_err();
    let accepting_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);
    erase_with_chirho(&root_chirho, BOB_CHIRHO, &accepting_chirho).unwrap();
    // Alice's seq 0 is unbound. Seq 1 is her in-flight retry and seq 7 is the store's to refuse as
    // rollback, so neither belongs in the evidence.
    accepting_chirho.unbound_chirho.replace(vec![0, 1, 7]);

    let record_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &accepting_chirho).unwrap();

    assert_eq!(record_chirho.seq_chirho, 1);
    assert_eq!(
        accepting_chirho.earlier_seen_chirho.borrow()[1],
        BTreeMap::from([(0, EarlierErasureEvidenceChirho::NeverRecordedChirho)])
    );
}

#[test]
fn required_ids_join_a_new_cut_without_a_key_file_or_a_blob_row_chirho() {
    // gpt #29850 (design item 10): the producer pins the requirement's contents, never the row's ids.
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    let unlinked_chirho = "ab".repeat(16);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);

    let record_chirho = erase_requiring_chirho(
        &root_chirho,
        ALICE_CHIRHO,
        &BTreeSet::from([unlinked_chirho.clone()]),
        &sink_chirho,
    )
    .unwrap();

    assert_eq!(
        sink_chirho.seen_chirho()[0].0.key_ids_chirho,
        BTreeSet::from([alice_chirho.clone(), unlinked_chirho])
    );
    assert_eq!(record_chirho.key_ids_chirho, vec![alice_chirho]);
}

#[test]
fn a_required_id_out_of_form_or_of_another_subject_refuses_before_any_unlink_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);
    // Bob's key named by the signed log, its file already gone.
    let logged_chirho = store_chirho(&root_chirho, BOB_CHIRHO);
    std::fs::remove_file(key_path_chirho(&root_chirho, &logged_chirho)).unwrap();
    // Bob's key file whose blob row is not in the log (the last row is dropped, so seqs stay dense).
    let filed_chirho = store_chirho(&root_chirho, BOB_CHIRHO);
    let mut blob_records_chirho = load_privacy_blob_records_chirho(&root_chirho).unwrap();
    blob_records_chirho.pop();
    write_jsonl_records_chirho(
        &privacy_blob_records_path_chirho(&root_chirho),
        &blob_records_chirho,
    );

    for (case_chirho, required_chirho, needle_chirho) in [
        (
            "logged to another subject",
            logged_chirho.clone(),
            "ErasureRequiredKeyNotTheSubjectsChirho",
        ),
        (
            "filed to another subject",
            filed_chirho.clone(),
            "ErasureRequiredKeyNotTheSubjectsChirho",
        ),
        (
            "out of form",
            "not-hex".to_string(),
            "key_id_chirho is invalid",
        ),
    ] {
        let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);
        let error_chirho = erase_requiring_chirho(
            &root_chirho,
            ALICE_CHIRHO,
            &BTreeSet::from([required_chirho.clone()]),
            &sink_chirho,
        )
        .unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(
            text_chirho.contains(needle_chirho),
            "{case_chirho}: {text_chirho}"
        );
        assert!(
            !text_chirho.contains(BOB_CHIRHO) && !text_chirho.contains(&required_chirho),
            "{case_chirho}: the refusal names neither the key nor the other subject"
        );
        assert!(sink_chirho.seen_chirho().is_empty(), "{case_chirho}");
        assert!(
            key_path_chirho(&root_chirho, &alice_chirho).exists(),
            "{case_chirho}"
        );
        assert!(load_privacy_erasure_records_chirho(&root_chirho)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn a_tampered_erasure_record_refuses_classification_and_reconcile_chirho() {
    let root_chirho = tmp_root_chirho();
    store_chirho(&root_chirho, ALICE_CHIRHO);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);
    recorded_unbound_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho);
    sink_chirho.unbound_chirho.replace(vec![0]);
    // Rewritten to Bob, the row would read "never recorded" and Alice's attempt would be carried.
    let mut records_chirho = load_privacy_erasure_records_chirho(&root_chirho).unwrap();
    records_chirho[0].subject_chirho = BOB_CHIRHO.to_string();
    write_jsonl_records_chirho(
        &privacy_erasure_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let alice_two_chirho = store_chirho(&root_chirho, ALICE_CHIRHO);

    let error_chirho = erase_with_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho).unwrap_err();

    assert!(
        format!("{error_chirho:#}").contains("signature invalid"),
        "{error_chirho:#}"
    );
    assert_eq!(
        sink_chirho.seen_chirho().len(),
        1,
        "no cut is classified from a tampered log"
    );
    assert!(key_path_chirho(&root_chirho, &alice_two_chirho).exists());
    assert_eq!(
        load_privacy_erasure_records_chirho(&root_chirho).unwrap(),
        records_chirho
    );

    let error_chirho =
        reconcile_subject_erasure_bindings_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho)
            .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("signature invalid"),
        "{error_chirho:#}"
    );
    assert!(sink_chirho.bindings_chirho.borrow().is_empty());
}

#[test]
fn reconcile_refuses_rollback_and_leaves_the_tip_and_anothers_record_pending_chirho() {
    let root_chirho = tmp_root_chirho();
    store_chirho(&root_chirho, ALICE_CHIRHO);
    store_chirho(&root_chirho, BOB_CHIRHO);
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);
    let pending_chirho = recorded_unbound_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho);
    erase_with_chirho(&root_chirho, BOB_CHIRHO, &sink_chirho).unwrap();
    let records_chirho = load_privacy_erasure_records_chirho(&root_chirho).unwrap();
    let bindings_before_chirho = sink_chirho.bindings_chirho.borrow().clone();

    // The log's length is 2. A seq beyond it refuses, and nothing is bound, not even seq 0.
    sink_chirho.unbound_chirho.replace(vec![0, 3]);
    let error_chirho =
        reconcile_subject_erasure_bindings_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho)
            .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ErasureRequirementSeqRollbackRefusedChirho"),
        "{error_chirho:#}"
    );
    assert_eq!(
        *sink_chirho.bindings_chirho.borrow(),
        bindings_before_chirho
    );

    // Seq 1 is Bob's record and seq 2 the in-flight tip: both stay pending. Only seq 0 is bound.
    sink_chirho.unbound_chirho.replace(vec![0, 1, 2]);
    let bound_chirho =
        reconcile_subject_erasure_bindings_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho)
            .unwrap();

    assert_eq!(bound_chirho, vec![0]);
    let mut expected_chirho = bindings_before_chirho;
    expected_chirho.push((
        0,
        ALICE_CHIRHO.to_string(),
        pending_chirho.erasure_record_digest_chirho,
    ));
    assert_eq!(*sink_chirho.bindings_chirho.borrow(), expected_chirho);
    assert_eq!(
        load_privacy_erasure_records_chirho(&root_chirho).unwrap(),
        records_chirho
    );
}

#[test]
fn reconcile_on_a_keyless_root_refuses_without_minting_chirho() {
    let root_chirho = tmp_root_chirho();
    let sink_chirho = RecordingSinkChirho::new_chirho(&root_chirho, false);
    sink_chirho.unbound_chirho.replace(vec![0]);

    assert!(
        reconcile_subject_erasure_bindings_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho)
            .is_err()
    );

    assert!(!root_chirho.join(SEED_FILE_CHIRHO).exists());
    assert!(!root_chirho.join(PUBLIC_FILE_CHIRHO).exists());
    assert!(sink_chirho.bindings_chirho.borrow().is_empty());
}

// gpt #29956: committed V1 vectors. Persisted bindings name these digests, so the canonical bytes and the digest
// are literals here, computed outside this code (b3sum over the domain tag and the bytes). A field reorder or a
// changed skip rule fails this arm, instead of moving both roads and their test together.
const V1_RECORD_LINE_CHIRHO: &str = concat!(
    r#"{"schema_chirho":"privacy-erasure-record-v1-chirho","seq_chirho":7,"subject_chirho":"user/vector","#,
    r#""requested_by_chirho":"owner/admin","reason_chirho":"gdpr-erasure","#,
    r#""key_ids_chirho":["0a1b2c3d4e5f60718293a4b5c6d7e8f9"],"removed_keys_chirho":1,"#,
    r#""at_ms_chirho":1793088000000,"sig_chirho":""#,
    "abababababababababababababababababababababababababababababababab",
    "abababababababababababababababababababababababababababababababab",
    r#""}"#
);
const LEGACY_RECORD_LINE_CHIRHO: &str = concat!(
    r#"{"seq_chirho":2,"subject_chirho":"user/legacy","requested_by_chirho":"owner/admin","#,
    r#""reason_chirho":"gdpr-erasure","key_ids_chirho":[],"removed_keys_chirho":0,"#,
    r#""at_ms_chirho":1700000000000,"sig_chirho":""#,
    "abababababababababababababababababababababababababababababababab",
    "abababababababababababababababababababababababababababababababab",
    r#""}"#
);

#[test]
fn the_v1_record_digest_matches_its_committed_vectors_chirho() {
    for (case_chirho, line_chirho, digest_hex_chirho) in [
        (
            "a schema-tagged row",
            V1_RECORD_LINE_CHIRHO,
            "dba5584a1dc01eb268f89b47d21dddc5da9c277df304c8b29f0ee29e37daacda",
        ),
        (
            "a legacy row with no schema",
            LEGACY_RECORD_LINE_CHIRHO,
            "44f4418a18450bff43536aacbb9cb2606c52de3ed33afad3ff863447eed048a2",
        ),
    ] {
        let record_chirho: PrivacyErasureRecordChirho = serde_json::from_str(line_chirho).unwrap();
        assert_eq!(
            serde_json::to_string(&record_chirho).unwrap(),
            line_chirho,
            "{case_chirho}: the canonical bytes"
        );
        assert_eq!(
            digest_chirho(&record_chirho),
            digest_hex_chirho,
            "{case_chirho}: the digest"
        );
    }
    let legacy_chirho: PrivacyErasureRecordChirho =
        serde_json::from_str(LEGACY_RECORD_LINE_CHIRHO).unwrap();
    assert!(
        legacy_chirho.schema_chirho.is_empty(),
        "a legacy row reads with an empty schema, which the log verifier accepts"
    );
}
