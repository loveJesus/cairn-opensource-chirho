// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Fail-closed arms for the contact smoke's effect-object PII scan — the surface that carried BOTH
//! defects at once.
//!
//! `assert_effect_cas_objects_no_contact_pii_chirho` is what lets this operator evidence say "no PII
//! on the persisted surfaces". It used to read the response object with `cas_chirho::get_chirho` and
//! catch EVERY failure in one `Err(_absent_chirho)` arm, then wave the surface through on a bare
//! existence check over the private-value log. Two consequences, and the first is the serious one:
//!
//!   1. A TAMPERED public object — bytes that are PRESENT and do not re-hash — took the absence
//!      branch, so **the PII needle check never ran on it at all**. The evidence reported a clean
//!      scan over content it had not looked at. Sealing makes that coincidence the NORMAL case
//!      rather than a rare one: a sealed response rests as a private DAG value, so a valid private
//!      record at the same hash is exactly what a live store holds.
//!   2. One appended line naming the response hash satisfied the fallback, with no ciphertext, no
//!      key and no signature behind it.
//!
//! FIVE OUTCOMES ARE KEPT APART HERE, because a two-case arm (present / absent) goes green on the
//! near-miss that rescues `Unreadable` alongside `Absent`:
//!   * VERIFIED, clean          — the needle check RUNS and passes.
//!   * VERIFIED, needle-bearing — the needle check RUNS and FIRES. (Probe-is-live control.)
//!   * ABSENT                   — the one outcome for which the private fallback is legitimate, and
//!     that fallback itself splits three ways (verified / nothing claims /
//!     claimed-but-unverifiable).
//!   * TAMPERED                 — present. Must refuse, and must NOT be rescued by a valid private
//!     record at the same hash.
//!   * UNREADABLE               — says nothing about whether the object is there. Must NOT be
//!     rescued either. This is the case a two-case arm cannot see.
//!
//! HONEST SCOPE on what the tamper arm proves. The shipped fix refuses at the tamper identity
//! BEFORE the needle check, so what is pinned is not "the needles are matched against tampered
//! bytes" — it is that a tampered object can no longer SKIP inspection silently, which is the
//! property the defect broke. That the needle probe itself is live and does fire is pinned
//! separately by `..._fires_on_a_verified_object_carrying_a_needle_chirho`, so the two together
//! close what one alone would leave open.

use super::*;
use cairn_chirho::model_chirho::{CapabilityChirho, HashChirho};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const CONTACT_NEEDLE_CHIRHO: &str = "ada@example.com";
const RESPONSE_SUBJECT_CHIRHO: &str = "user/contact-evidence-fail-closed-chirho";

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-contact-evidence-{nanos_chirho}-{n_chirho}"))
}

fn needles_chirho() -> Vec<&'static str> {
    vec![CONTACT_NEEDLE_CHIRHO]
}

fn cas_object_path_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&hash_chirho.0[0..2])
        .join(&hash_chirho.0[2..])
}

/// An effect whose REQUEST object is real, present and clean, so every refusal below can only have
/// come from the response branch under test.
fn effect_with_response_chirho(root_chirho: &Path, response_chirho: &HashChirho) -> EffectChirho {
    let request_chirho =
        cas_chirho::add_chirho(root_chirho, b"safe contact request payload chirho").unwrap();
    EffectChirho {
        seq_chirho: 0,
        idem_key_chirho: HashChirho("contact-evidence-idem-chirho".to_string()),
        capability_chirho: CapabilityChirho::ClockChirho,
        request_chirho,
        response_chirho: Some(response_chirho.clone()),
        sig_chirho: "test-sig-chirho".to_string(),
        at_chirho: "0".to_string(),
    }
}

fn assert_response_object_chirho(root_chirho: &Path, response_chirho: &HashChirho) -> Result<()> {
    let effect_chirho = effect_with_response_chirho(root_chirho, response_chirho);
    assert_effect_cas_objects_no_contact_pii_chirho(root_chirho, &effect_chirho, &needles_chirho())
}

/// Seals bytes as a private DAG value and returns the plaintext hash, which is NOT in public CAS —
/// the shape a live sealed response actually has.
fn seal_private_response_chirho(root_chirho: &Path, bytes_chirho: &[u8]) -> HashChirho {
    let hash_chirho = dag_private_value_chirho::store_private_dag_value_chirho(
        root_chirho,
        // The fixture's subject is that user's own principal, so only that user's account may own it.
        &cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho::account_owned_chirho(
            RESPONSE_SUBJECT_CHIRHO,
        )
        .unwrap(),
        RESPONSE_SUBJECT_CHIRHO,
        bytes_chirho,
        dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(root_chirho, &hash_chirho),
            cas_chirho::CasReadOutcomeChirho::AbsentChirho(_)
        ),
        "fixture: a sealed value's PLAINTEXT address must be absent from public CAS"
    );
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_chirho(
            root_chirho,
            &hash_chirho
        )
        .unwrap()
        .is_some(),
        "fixture: the sealed value must resolve to a VERIFIED private record"
    );
    hash_chirho
}

/// Appends ONE unsigned line claiming the hash, and PROVES the append landed.
fn forge_claiming_line_chirho(root_chirho: &Path, value_hash_chirho: &HashChirho) {
    let path_chirho = root_chirho.join("private-dag-values-chirho.jsonl");
    let before_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_default();
    let forged_chirho = serde_json::json!({
        "schema_chirho": dag_private_value_chirho::PRIVATE_DAG_VALUE_SCHEMA_CHIRHO,
        "seq_chirho": before_chirho.lines().count(),
        "subject_chirho": "user/contact-evidence-forged-claim-chirho",
        "value_hash_chirho": value_hash_chirho.0,
        "blob_chirho": {
            "alg_chirho": "xchacha20poly1305-chirho",
            "key_id_chirho": "forged-key-id-chirho",
            "nonce_chirho": "00".repeat(24),
            "mac_chirho": "00".repeat(32),
            "ciphertext_chirho": cas_chirho::hash_chirho(b"no such ciphertext chirho").0,
        },
        "bytes_chirho": 0,
        "at_ms_chirho": 0,
        "sig_chirho": "",
    });
    std::fs::create_dir_all(root_chirho).unwrap();
    std::fs::write(&path_chirho, format!("{before_chirho}{forged_chirho}\n")).unwrap();
    let after_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    assert_eq!(
        after_chirho.lines().count(),
        before_chirho.lines().count() + 1,
        "the forged line was not appended, so every assertion below would pass over an unmutated log"
    );
}

/// VERIFIED and clean — the ordinary path, and the control that says this probe reaches the object
/// at all rather than passing because it never looked.
#[test]
fn contact_evidence_admits_a_verified_response_object_without_needles_chirho() {
    let root_chirho = tmp_root_chirho();
    let response_chirho =
        cas_chirho::add_chirho(&root_chirho, b"safe contact response payload chirho").unwrap();
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &response_chirho),
            cas_chirho::CasReadOutcomeChirho::VerifiedChirho(_)
        ),
        "fixture: this object must VERIFY, or the arm exercises the wrong branch"
    );

    assert_response_object_chirho(&root_chirho, &response_chirho)
        .expect("a verified, needle-free response object must pass");

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// POSITIVE CONTROL FOR THE PROBE ITSELF. "No error was returned" is worthless unless the needle
/// check actually FIRES when the needle is there. Same call, same needles, one byte-string apart.
#[test]
fn contact_evidence_needle_check_fires_on_a_verified_object_carrying_a_needle_chirho() {
    let root_chirho = tmp_root_chirho();
    let leaky_bytes_chirho = format!("contact row email_chirho={CONTACT_NEEDLE_CHIRHO} chirho");
    let response_chirho =
        cas_chirho::add_chirho(&root_chirho, leaky_bytes_chirho.as_bytes()).unwrap();
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &response_chirho),
            cas_chirho::CasReadOutcomeChirho::VerifiedChirho(_)
        ),
        "fixture: the leaky object must VERIFY, so only the needle check can refuse it"
    );

    let error_chirho = assert_response_object_chirho(&root_chirho, &response_chirho)
        .expect_err("the needle check did not fire on a verified object carrying the needle");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("leaked contact PII needle"),
        "the probe must refuse by the needle identity, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains("effect response object"),
        "the refusal must name the surface it inspected, got: {text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// ABSENT plus a VERIFIED private record — the one fallback this surface legitimately allows, and
/// the normal shape of a sealed response.
#[test]
fn contact_evidence_admits_an_absent_response_backed_by_a_verified_private_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let response_chirho = seal_private_response_chirho(
        &root_chirho,
        format!("sealed contact body email_chirho={CONTACT_NEEDLE_CHIRHO} chirho").as_bytes(),
    );

    assert_response_object_chirho(&root_chirho, &response_chirho)
        .expect("a sealed response with a verified private record must pass");

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// ABSENT and nothing claims it — the surface keeps its own refusal identity.
#[test]
fn contact_evidence_refuses_an_absent_response_nothing_records_chirho() {
    let root_chirho = tmp_root_chirho();
    let response_chirho = cas_chirho::hash_chirho(b"a response nothing ever stored chirho");
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &response_chirho),
            cas_chirho::CasReadOutcomeChirho::AbsentChirho(_)
        ),
        "fixture: this hash must be ABSENT, or the arm exercises the wrong branch"
    );

    let error_chirho = assert_response_object_chirho(&root_chirho, &response_chirho)
        .expect_err("an unrecorded, absent response object passed the scan");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("neither in public CAS nor a verified private DAG value"),
        "absence must refuse by its own identity, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("re-hashes to"),
        "absence must NOT borrow the tamper identity, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("could not be read"),
        "absence must NOT borrow the unreadable identity, got: {text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// ABSENT and claimed only by an unverifiable line — the bare existence check let this stand in for
/// sealing evidence. One appended line was the whole attack.
///
/// MIGRATION PATH — if this goes red with `Ok`, the bare existence check is back. If it goes red on
/// a refusal naming something other than record verification, read the refusal first: the IDENTITY
/// is the pin, not the mere fact of an error.
#[test]
fn contact_evidence_refuses_an_absent_response_claimed_only_by_an_unverifiable_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let response_chirho = cas_chirho::hash_chirho(b"a response only a forged line claims chirho");
    forge_claiming_line_chirho(&root_chirho, &response_chirho);
    // Proof the fixture reproduces the defect: the signal that was REPLACED accepts this line.
    assert!(
        dag_private_value_chirho::private_dag_value_recorded_chirho(&root_chirho, &response_chirho)
            .unwrap(),
        "fixture: the bare existence check must ACCEPT this line, or the arm proves nothing about \
         the signal that was replaced"
    );

    let error_chirho = assert_response_object_chirho(&root_chirho, &response_chirho)
        .expect_err("one appended line stood in for sealing evidence");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("claimed only by records that do not verify"),
        "the scan refused for some other reason than record verification: {text_chirho}"
    );

    // DIFFERENTIAL: remove the forged line and the same hash is merely unrecorded again.
    std::fs::write(root_chirho.join("private-dag-values-chirho.jsonl"), "").unwrap();
    let after_chirho = assert_response_object_chirho(&root_chirho, &response_chirho)
        .expect_err("without the forged line the response is still unrecorded")
        .to_string();
    assert!(
        after_chirho.contains("neither in public CAS nor a verified private DAG value"),
        "removing the forged line must return the case to plain absence, got: {after_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE SERIOUS ONE. A TAMPERED public object carrying the PII needle, with a VALID private record at
/// the same hash — the exact coincidence sealing makes normal.
///
/// Under the old `Err(_absent_chirho)` arm this returned `Ok(())`: the tampered bytes took the
/// absence branch, the private record waved them through, and **the needle check never ran on the
/// leaking content**. The evidence then said "no PII on the persisted surfaces" about a surface it
/// had not inspected. It must now refuse, and refuse as TAMPER rather than as absence.
///
/// MIGRATION PATH — if this goes red with `Ok`, the fallback catches tamper again and this operator
/// evidence is once more capable of passing over content it never read. If it goes red naming the
/// needle instead of the re-hash, the fix has moved the needle check ahead of the tamper refusal:
/// that is a stronger posture, not a regression — retarget the identity assertion and keep the
/// `is_err` requirement.
#[test]
fn contact_evidence_refuses_a_tampered_response_object_even_with_a_valid_private_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let response_chirho = seal_private_response_chirho(
        &root_chirho,
        b"the sealed response body that the private record covers chirho",
    );
    // The tampered bytes CARRY the needle, so a scan that inspected them would fire on content.
    let tampered_bytes_chirho =
        format!("tampered public bytes email_chirho={CONTACT_NEEDLE_CHIRHO} chirho");
    let object_path_chirho = cas_object_path_chirho(&root_chirho, &response_chirho);
    std::fs::create_dir_all(object_path_chirho.parent().unwrap()).unwrap();
    std::fs::write(&object_path_chirho, tampered_bytes_chirho.as_bytes()).unwrap();
    // Fixture check BEFORE the assertion that depends on it.
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &response_chirho),
            cas_chirho::CasReadOutcomeChirho::TamperedChirho { .. }
        ),
        "fixture: the planted bytes must read as TAMPERED, or this arm exercises the wrong branch"
    );

    let error_chirho = assert_response_object_chirho(&root_chirho, &response_chirho).expect_err(
        "a TAMPERED response object was waved through by its private record — the scan passed over \
         content it never inspected",
    );
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("is present in public CAS and re-hashes to"),
        "tamper must refuse by its own identity, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains(&response_chirho.0),
        "the refusal must name the object it is about, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("neither in public CAS nor a verified private DAG value"),
        "tamper must NOT be reported as absence, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("could not be read"),
        "tamper must NOT borrow the unreadable identity, got: {text_chirho}"
    );

    // DIFFERENTIAL: remove the planted bytes and the same hash passes again on its private record —
    // proof the refusal came from the tamper and not from anything else this fixture did.
    std::fs::remove_file(&object_path_chirho).unwrap();
    assert_response_object_chirho(&root_chirho, &response_chirho)
        .expect("removing the planted bytes must restore the legitimate private fallback");

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE NEAR-MISS, and the reason this arm has more than two cases.
///
/// A fix that falls back on `Absent` **and** `Unreadable` passes every tamper assertion above while
/// leaving the door open one notch narrower: an object that is present but unreadable — permission,
/// a directory in its place, a failing device — still gets rescued by the private record, and the
/// needle check still never runs. A directory planted at the object path produces a non-`NotFound`
/// read failure without depending on file modes a root-running test would ignore.
///
/// MIGRATION PATH — if this goes red with `Ok`, `Unreadable` has been folded back in with `Absent`
/// and the fallback launders a broken store into a clean pass.
#[test]
fn contact_evidence_refuses_an_unreadable_response_object_even_with_a_valid_private_record_chirho()
{
    let root_chirho = tmp_root_chirho();
    let response_chirho = seal_private_response_chirho(
        &root_chirho,
        b"the sealed response body behind an unreadable object chirho",
    );
    let object_path_chirho = cas_object_path_chirho(&root_chirho, &response_chirho);
    std::fs::create_dir_all(&object_path_chirho).unwrap();
    // Fixture check BEFORE the assertion that depends on it: a directory reads as UNREADABLE, which
    // is a DIFFERENT outcome from both absence and tamper. If this ever became AbsentChirho the
    // assertion below would be testing the wrong branch and would still look green.
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &response_chirho),
            cas_chirho::CasReadOutcomeChirho::UnreadableChirho(_)
        ),
        "fixture: a directory at the object path must read as UNREADABLE, not absent"
    );

    let error_chirho = assert_response_object_chirho(&root_chirho, &response_chirho).expect_err(
        "an UNREADABLE response object was rescued by its private record — the near-miss the \
         three-case split exists to catch",
    );
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("is present but could not be read"),
        "unreadable must refuse by its own identity, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("neither in public CAS nor a verified private DAG value"),
        "unreadable must NOT be reported as absence, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("re-hashes to"),
        "unreadable must NOT borrow the tamper identity, got: {text_chirho}"
    );

    // DIFFERENTIAL: remove the planted directory and the same hash passes again on its private
    // record.
    std::fs::remove_dir(&object_path_chirho).unwrap();
    assert_response_object_chirho(&root_chirho, &response_chirho)
        .expect("removing the planted directory must restore the legitimate private fallback");

    let _ = std::fs::remove_dir_all(&root_chirho);
}
