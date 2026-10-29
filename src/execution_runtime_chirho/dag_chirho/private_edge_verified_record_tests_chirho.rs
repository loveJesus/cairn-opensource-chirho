// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Fail-closed arms for the private-edge runtime gate: the record must VERIFY, never merely claim.
//!
//! `collect_edge_inputs_chirho` exists to prove a private edge's value was actually sealed. It used
//! to ask `private_dag_value_recorded_chirho`, which parses the private-value JSONL WITHOUT checking
//! schema, signature, subject or blob ownership — so ONE appended line naming the upstream hash
//! satisfied the gate, with no ciphertext, no key and no signature behind it. Append access to the
//! log was the whole attack.
//!
//! THE THREE OUTCOMES THIS SIGNAL HAS, kept apart deliberately, because a two-case arm (claimed /
//! not claimed) goes green on the near-miss that swallows an `Err` into a `None`:
//!   * `Ok(None)`    — NOTHING claims the hash. The one outcome for which the skipped-stone
//!     fallback is legitimate.
//!   * `Ok(Some(_))` — a record claims it AND verifies. The gate passes.
//!   * `Err(_)`      — a record claims it and does NOT verify. The loud case: fail closed, and
//!     fail closed EVEN WHEN the hash is the skipped stone.
//!
//! That last clause is the one behaviour change beyond the obvious, and it is a JUDGEMENT rather
//! than a mechanical consequence: before the fix, a hash that IS the skipped stone passed the gate
//! whatever the private log said, because `is_skipped_hash_chirho` short-circuited the bail. Now a
//! BROKEN record claiming the skipped stone propagates its `Err` through the `?` before the skip is
//! ever consulted. `private_edge_gate_refuses_a_broken_record_even_on_the_skipped_stone_chirho`
//! pins that, so the next reader inherits a proof instead of an opinion.

use super::*;
use crate::model_chirho::{
    EdgePrivacyChirho, EdgePrivacySubjectSourceChirho, PortChirho, SKIPPED_STONE_BYTES_CHIRHO,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PRIVATE_EDGE_SUBJECT_CHIRHO: &str = "user/private-edge-gate-chirho";

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-private-edge-gate-{nanos_chirho}-{n_chirho}"))
}

fn request_context_chirho() -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: PRIVATE_EDGE_SUBJECT_CHIRHO.to_string(),
        app_chirho: "private-edge-gate-app-chirho".to_string(),
        owner_principal_chirho: "owner/private-edge-gate-chirho".to_string(),
        client_id_chirho: "browser-session-chirho".to_string(),
        token_hash_chirho: "token-private-edge-gate-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn port_chirho(name_chirho: &str) -> PortChirho {
    PortChirho {
        name_chirho: name_chirho.to_string(),
        schema_chirho: HashChirho("schema-private-edge-gate-chirho".to_string()),
    }
}

fn node_def_chirho(name_chirho: &str) -> NodeDefChirho {
    NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: HashChirho(format!("impl-{name_chirho}")),
        entry_chirho: "never_runs_chirho".to_string(),
        inputs_chirho: vec![port_chirho("in")],
        outputs_chirho: vec![port_chirho("out")],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000,
        ..Default::default()
    }
}

/// Drives ONLY the gate: one private edge whose upstream output is the hash under test.
///
/// No wasm and no run — the point is to isolate the decision from everything that surrounds it, so
/// a refusal here can only have come from the private-record check or from the skip.
fn collect_private_edge_inputs_chirho(
    root_chirho: &Path,
    upstream_out_chirho: &HashChirho,
) -> Result<(
    BTreeMap<String, HashChirho>,
    dag_private_value_chirho::PrivateDagValueResolverChirho,
)> {
    let from_node_chirho = HashChirho("node-upstream-private-edge-gate-chirho".to_string());
    let to_def_chirho = node_def_chirho("downstream_chirho");
    let edge_chirho = EdgeChirho {
        from_node_chirho: from_node_chirho.clone(),
        from_port_chirho: "out".to_string(),
        to_node_chirho: HashChirho("node-downstream-private-edge-gate-chirho".to_string()),
        to_port_chirho: "in".to_string(),
        privacy_chirho: Some(EdgePrivacyChirho::PrivateBlobRefChirho {
            subject_source_chirho: EdgePrivacySubjectSourceChirho::RequestUserChirho,
        }),
    };
    let mut outputs_chirho = HashMap::new();
    outputs_chirho.insert(
        (from_node_chirho, "out".to_string()),
        upstream_out_chirho.clone(),
    );
    let run_of_chirho = HashMap::new();
    let context_chirho = request_context_chirho();
    let mut resolver_chirho = dag_private_value_chirho::PrivateDagValueResolverChirho::default();
    let (inputs_chirho, _parents_chirho) = collect_edge_inputs_chirho(
        &[&edge_chirho],
        &outputs_chirho,
        &run_of_chirho,
        &to_def_chirho,
        root_chirho,
        Some(&context_chirho),
        &mut resolver_chirho,
    )?;
    Ok((inputs_chirho, resolver_chirho))
}

fn private_dag_values_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("private-dag-values-chirho.jsonl")
}

/// Appends ONE unsigned line claiming `value_hash_chirho` — no object, no ciphertext, no key, no
/// signature behind it — and PROVES the append landed before any assertion can depend on it.
fn forge_claiming_line_chirho(root_chirho: &Path, value_hash_chirho: &HashChirho) {
    let path_chirho = private_dag_values_path_chirho(root_chirho);
    let before_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_default();
    let forged_chirho = serde_json::json!({
        "schema_chirho": dag_private_value_chirho::PRIVATE_DAG_VALUE_SCHEMA_CHIRHO,
        "seq_chirho": before_chirho.lines().count(),
        "subject_chirho": "user/private-edge-forged-claim-chirho",
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

/// Removes the planted line again — the differential that shows the case green without the forgery.
fn remove_forged_line_chirho(root_chirho: &Path) {
    let path_chirho = private_dag_values_path_chirho(root_chirho);
    let before_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let kept_chirho: Vec<&str> = before_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.contains("user/private-edge-forged-claim-chirho"))
        .collect();
    assert_eq!(
        kept_chirho.len(),
        before_chirho.lines().count() - 1,
        "the differential removed something other than exactly the one forged line"
    );
    let text_chirho = if kept_chirho.is_empty() {
        String::new()
    } else {
        format!("{}\n", kept_chirho.join("\n"))
    };
    std::fs::write(&path_chirho, text_chirho).unwrap();
}

/// POSITIVE CONTROL. "It refused" is cheap to obtain from a fixture that never reached the branch,
/// so prove the gate DOES admit a private edge whose value is really sealed. Every refusal below is
/// attributable only because this passes.
#[test]
fn private_edge_gate_admits_a_verified_private_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let sealed_hash_chirho = dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            PRIVATE_EDGE_SUBJECT_CHIRHO,
        ),
        PRIVATE_EDGE_SUBJECT_CHIRHO,
        b"sealed private edge value chirho",
        dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();
    // Fixture check before the assertion that depends on it.
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_chirho(
            &root_chirho,
            &sealed_hash_chirho
        )
        .unwrap()
        .is_some(),
        "fixture: the stored value must resolve to a VERIFIED record, or this control proves nothing"
    );

    let (inputs_chirho, resolver_chirho) =
        collect_private_edge_inputs_chirho(&root_chirho, &sealed_hash_chirho)
            .expect("the gate refused a private edge whose value is genuinely sealed");
    assert_eq!(inputs_chirho.get("in"), Some(&sealed_hash_chirho));
    assert_eq!(
        resolver_chirho
            .domain_for_hash_chirho(&sealed_hash_chirho)
            .unwrap()
            .map(|(subject_chirho, _owner_chirho)| subject_chirho)
            .as_deref(),
        Some(PRIVATE_EDGE_SUBJECT_CHIRHO),
        "an admitted private edge must bind its value to the request subject"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// ABSENCE — nothing claims the hash and it is not the skipped stone. The ordinary missing case,
/// and it must keep ITS OWN refusal identity, sharing no phrase with the verification refusal.
#[test]
fn private_edge_gate_refuses_a_hash_no_record_claims_chirho() {
    let root_chirho = tmp_root_chirho();
    let unclaimed_hash_chirho = cas_chirho::hash_chirho(b"bytes that were never sealed chirho");
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_chirho(
            &root_chirho,
            &unclaimed_hash_chirho
        )
        .unwrap()
        .is_none(),
        "fixture: no record may claim this hash, or this arm exercises the wrong branch"
    );
    assert!(
        !cache_chirho::is_skipped_hash_chirho(&root_chirho, &unclaimed_hash_chirho).unwrap(),
        "fixture: this hash must not be the skipped stone, or the bail is short-circuited"
    );

    let error_chirho = collect_private_edge_inputs_chirho(&root_chirho, &unclaimed_hash_chirho)
        .expect_err("the gate admitted a private edge whose value nothing records");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("without a private DAG value record"),
        "absence must refuse by its own identity, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("claimed only by records that do not verify"),
        "absence must NOT borrow the verification refusal's identity, got: {text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// ABSENCE plus the skip — the one fallback the gate legitimately allows. A skipped node produces
/// the canonical skipped stone, which no private record claims and none should.
#[test]
fn private_edge_gate_admits_the_skipped_stone_when_no_record_claims_it_chirho() {
    let root_chirho = tmp_root_chirho();
    let skipped_hash_chirho = cache_chirho::skipped_stone_hash_chirho(&root_chirho).unwrap();
    assert_eq!(
        skipped_hash_chirho,
        cas_chirho::hash_chirho(SKIPPED_STONE_BYTES_CHIRHO),
        "fixture: the skipped stone hash must be the canonical one"
    );
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_chirho(
            &root_chirho,
            &skipped_hash_chirho
        )
        .unwrap()
        .is_none(),
        "fixture: no record may claim the skipped stone yet, or this arm proves the wrong thing"
    );

    let (inputs_chirho, _resolver_chirho) =
        collect_private_edge_inputs_chirho(&root_chirho, &skipped_hash_chirho)
            .expect("a skipped private edge with no claiming record must pass on the skip");
    assert_eq!(inputs_chirho.get("in"), Some(&skipped_hash_chirho));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// CLAIMED-BUT-UNVERIFIABLE — one appended line, and the gate must fail CLOSED rather than count
/// the claim as sealing evidence.
///
/// MIGRATION PATH — if this goes red returning `Ok`, the bare existence check is back and one
/// appended line buys a private edge again. If it goes red on a refusal naming something other than
/// record verification, read the refusal before touching the assertion: the IDENTITY is what this
/// pins, not the mere fact of an error.
#[test]
fn private_edge_gate_refuses_a_hash_claimed_only_by_an_unverifiable_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let forged_hash_chirho = cas_chirho::hash_chirho(b"bytes nothing ever sealed chirho");
    forge_claiming_line_chirho(&root_chirho, &forged_hash_chirho);
    assert!(
        !cache_chirho::is_skipped_hash_chirho(&root_chirho, &forged_hash_chirho).unwrap(),
        "fixture: this hash must not be the skipped stone, so only the record check can decide"
    );

    let error_chirho = collect_private_edge_inputs_chirho(&root_chirho, &forged_hash_chirho)
        .expect_err("the gate accepted one appended line as sealing evidence");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("claimed only by records that do not verify"),
        "the gate refused for some other reason than record verification: {text_chirho}"
    );
    assert!(
        text_chirho.contains(&forged_hash_chirho.0),
        "the refusal must name the hash it is about: {text_chirho}"
    );
    // THE NEAR-MISS. A fix that swallowed the `Err` into a `None` would still refuse here — but with
    // ABSENCE's identity, because the gate would then fall through to its own bail. Two-case arms go
    // green on that mutation; this assertion does not.
    assert!(
        !text_chirho.contains("without a private DAG value record"),
        "a broken record was reported as an ABSENT one, which is the near-miss this arm exists for: \
         {text_chirho}"
    );

    // DIFFERENTIAL: remove the planted line and the same hash is merely absent again.
    remove_forged_line_chirho(&root_chirho);
    let after_chirho = collect_private_edge_inputs_chirho(&root_chirho, &forged_hash_chirho)
        .expect_err("without the forged line this hash is still unrecorded")
        .to_string();
    assert!(
        after_chirho.contains("without a private DAG value record"),
        "removing the forged line must return the case to plain absence, got: {after_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE JUDGEMENT, pinned. A hash that IS the skipped stone, whose private record exists and is
/// BROKEN, now fails CLOSED instead of passing on the skip.
///
/// Before the fix the skip short-circuited the bail, so the private log's contents could not change
/// the outcome for this hash at all. After it, the record check runs FIRST and its `Err` propagates
/// through the `?` — a store whose private-value log has been tampered with cannot launder a private
/// edge through the skipped stone. This is the only case whose outcome moved, and the reason to
/// choose fail-closed is that the alternative reads a BROKEN log as evidence of a legitimate skip.
///
/// MIGRATION PATH — if this ever goes red with `Ok`, someone has restored the skip short-circuit
/// ahead of the record check, and the decision recorded here has been reversed rather than fixed.
#[test]
fn private_edge_gate_refuses_a_broken_record_even_on_the_skipped_stone_chirho() {
    let root_chirho = tmp_root_chirho();
    let skipped_hash_chirho = cache_chirho::skipped_stone_hash_chirho(&root_chirho).unwrap();
    // Fixture checks BEFORE the assertion that depends on them: this hash really is the skipped
    // stone, and the forged line really landed. Either one false makes the refusal below mean
    // something other than what this arm claims.
    assert!(
        cache_chirho::is_skipped_hash_chirho(&root_chirho, &skipped_hash_chirho).unwrap(),
        "fixture: this arm is only meaningful on a hash the skip WOULD have rescued"
    );
    forge_claiming_line_chirho(&root_chirho, &skipped_hash_chirho);

    let error_chirho = collect_private_edge_inputs_chirho(&root_chirho, &skipped_hash_chirho)
        .expect_err(
            "a BROKEN private record on the skipped stone passed on the skip — the judgement this \
             arm pins has been reversed",
        );
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("claimed only by records that do not verify"),
        "the skipped-stone refusal must carry the verification identity, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("without a private DAG value record"),
        "the skipped stone refused as plain absence, so the record check did not decide it: \
         {text_chirho}"
    );

    // DIFFERENTIAL: with the planted line gone, the same skipped stone passes again — proof the
    // refusal came from the forgery and not from anything else this fixture did.
    remove_forged_line_chirho(&root_chirho);
    let (inputs_chirho, _resolver_chirho) =
        collect_private_edge_inputs_chirho(&root_chirho, &skipped_hash_chirho)
            .expect("removing the forged line must restore the legitimate skip");
    assert_eq!(inputs_chirho.get("in"), Some(&skipped_hash_chirho));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
