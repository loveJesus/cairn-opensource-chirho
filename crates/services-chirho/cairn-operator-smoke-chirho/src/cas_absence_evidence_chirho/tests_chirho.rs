// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Three cases, not two: absent may be claimed, tampered and unreadable must refuse.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_root_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-cas-absence-evidence-{nanos_chirho}-{n_chirho}"
    ))
}

fn object_path_chirho(root_chirho: &std::path::Path, address_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&address_chirho.0[0..2])
        .join(&address_chirho.0[2..])
}

/// POSITIVE CONTROL for every absence claim below: the same probe DOES see the body when the body
/// is really there. Without this, "absent" is indistinguishable from a probe that never looked.
#[test]
fn the_absence_probe_sees_a_body_that_is_actually_present_chirho() {
    let root_chirho = tmp_root_chirho();
    let body_chirho = b"name_chirho=Alice+Example&email_chirho=alice%40example.com";
    let address_chirho = cas_chirho::add_chirho(&root_chirho, body_chirho).unwrap();

    assert!(
        !raw_body_absent_from_public_cas_chirho(&root_chirho, &address_chirho, "control").unwrap(),
        "the probe reported ABSENT for a body sitting verified in public CAS, so every absence \
         claim it makes is worthless"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_body_never_stored_is_genuinely_absent_chirho() {
    let root_chirho = tmp_root_chirho();
    let address_chirho = cas_chirho::hash_chirho(b"bytes that were never stored anywhere chirho");

    assert!(
        raw_body_absent_from_public_cas_chirho(&root_chirho, &address_chirho, "absent").unwrap(),
        "a hash nothing was ever stored under must read as ABSENT"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// PRESENT-BUT-UNREADABLE — the privacy false negative. A directory at the object path yields
/// EISDIR, which (unlike mode 000) no privileged test runner can ignore. The old `is_err()` shape
/// recorded this as ABSENT while the raw PII body may sit there intact.
///
/// MIGRATION PATH — if this goes red returning `Ok(true)`, the false negative is back and shipped
/// operator evidence can again say "absent" about a body it never read. If the refusal names a
/// TAMPER instead, the outcome is being misclassified, not laundered.
#[test]
fn an_unreadable_object_is_never_reported_as_absent_chirho() {
    let root_chirho = tmp_root_chirho();
    let body_chirho = b"name_chirho=Alice+Example&email_chirho=alice%40example.com";
    let address_chirho = cas_chirho::hash_chirho(body_chirho);
    let planted_chirho = object_path_chirho(&root_chirho, &address_chirho);
    std::fs::create_dir_all(&planted_chirho).unwrap();
    // Proof the plant applied before anything depends on it.
    assert!(
        planted_chirho.is_dir(),
        "the directory plant did not land, so the assertion below would pass over ABSENT"
    );

    let error_chirho =
        raw_body_absent_from_public_cas_chirho(&root_chirho, &address_chirho, "unreadable surface")
            .expect_err("an unreadable object was answered as an absence claim");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("could not be read"),
        "the refusal must say the read failed, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains(&address_chirho.0),
        "the refusal must name the object it is about, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains("unreadable surface"),
        "the refusal must name the calling surface, got: {text_chirho}"
    );
    // NEGATIVE IDENTITY: not the tamper refusal, which is a different store state.
    assert!(
        !text_chirho.contains("tampered bytes"),
        "an unreadable object was misclassified as tamper, got: {text_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// PRESENT-AND-TAMPERED — bytes that do not re-hash to this address genuinely are not the raw
/// body, but these smokes build their own fresh root, so nothing legitimate writes wrong-hash bytes
/// at exactly the private body's address. Evidence about an address is not produced from a store
/// visibly corrupt at that address.
#[test]
fn a_tampered_object_is_never_reported_as_absent_chirho() {
    let root_chirho = tmp_root_chirho();
    let body_chirho = b"name_chirho=Alice+Example&email_chirho=alice%40example.com";
    let address_chirho = cas_chirho::add_chirho(&root_chirho, body_chirho).unwrap();
    let tampered_bytes_chirho = b"tampered public bytes chirho";
    std::fs::write(
        object_path_chirho(&root_chirho, &address_chirho),
        tampered_bytes_chirho,
    )
    .unwrap();
    // Proof the tamper applied, and that it really violates the property under test: these bytes
    // must re-hash to a DIFFERENT address, or this arm is testing the verified path.
    let actual_chirho = cas_chirho::hash_chirho(tampered_bytes_chirho);
    assert_ne!(
        actual_chirho.0, address_chirho.0,
        "the tamper fixture did not change the content address, so nothing is being violated"
    );

    let error_chirho =
        raw_body_absent_from_public_cas_chirho(&root_chirho, &address_chirho, "tamper surface")
            .expect_err("a tampered object was answered as an absence claim");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("tampered bytes"),
        "the refusal must say the store holds tampered bytes, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains(&actual_chirho.0),
        "the refusal must name what the bytes actually hash to, got: {text_chirho}"
    );
    // NEGATIVE IDENTITY: not the unreadable refusal — the read succeeded, the bytes disagreed.
    assert!(
        !text_chirho.contains("could not be read"),
        "a tampered object was misclassified as unreadable, got: {text_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
