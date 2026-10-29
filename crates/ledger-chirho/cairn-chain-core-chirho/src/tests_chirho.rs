// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

/// A minimal test family: `seq|prev|payload|sigflag` lines. `sigflag != "ok"` refuses at the
/// family hook, so every core law is exercised without any real wire/signature machinery.
struct TestFamilyChirho;

#[derive(Debug, PartialEq, Eq)]
struct TestRecordChirho {
    seq_chirho: u64,
    prev_chirho: String,
    payload_chirho: String,
    sig_ok_chirho: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum TestErrorChirho {
    ParseChirho,
    SignatureChirho { seq_chirho: u64 },
}

impl ChainFamilyChirho for TestFamilyChirho {
    type RecordChirho = TestRecordChirho;
    type ErrorChirho = TestErrorChirho;

    fn parse_line_chirho(&self, line_chirho: &str) -> Result<TestRecordChirho, TestErrorChirho> {
        let parts_chirho: Vec<&str> = line_chirho.split('|').collect();
        if parts_chirho.len() != 4 {
            return Err(TestErrorChirho::ParseChirho);
        }
        Ok(TestRecordChirho {
            seq_chirho: parts_chirho[0]
                .parse()
                .map_err(|_| TestErrorChirho::ParseChirho)?,
            prev_chirho: parts_chirho[1].to_string(),
            payload_chirho: parts_chirho[2].to_string(),
            sig_ok_chirho: parts_chirho[3] == "ok",
        })
    }

    fn seq_chirho(&self, record_chirho: &TestRecordChirho) -> u64 {
        record_chirho.seq_chirho
    }

    fn prev_hex_chirho<'record_chirho>(
        &self,
        record_chirho: &'record_chirho TestRecordChirho,
    ) -> &'record_chirho str {
        &record_chirho.prev_chirho
    }

    fn verify_record_chirho(
        &self,
        record_chirho: &TestRecordChirho,
    ) -> Result<(), TestErrorChirho> {
        if record_chirho.sig_ok_chirho {
            Ok(())
        } else {
            Err(TestErrorChirho::SignatureChirho {
                seq_chirho: record_chirho.seq_chirho,
            })
        }
    }
}

const DOMAIN_CHIRHO: &str = "test-family-chirho";
const IDENTITY_CHIRHO: &str = "log-alpha-chirho";

fn build_chain_chirho(payloads_chirho: &[&str]) -> String {
    let anchor_chirho = chain_anchor_hex_chirho(DOMAIN_CHIRHO, IDENTITY_CHIRHO);
    let mut prev_chirho = anchor_chirho;
    let mut text_chirho = String::new();
    for (index_chirho, payload_chirho) in payloads_chirho.iter().enumerate() {
        let line_chirho = format!("{index_chirho}|{prev_chirho}|{payload_chirho}|ok");
        prev_chirho = stored_line_digest_hex_chirho(&line_chirho);
        text_chirho.push_str(&line_chirho);
        text_chirho.push('\n');
    }
    text_chirho
}

#[test]
fn empty_log_yields_the_anchor_tail_chirho() {
    let anchor_chirho = chain_anchor_hex_chirho(DOMAIN_CHIRHO, IDENTITY_CHIRHO);
    let (records_chirho, tail_chirho) =
        walk_verified_chain_chirho("", &anchor_chirho, &TestFamilyChirho).unwrap();
    assert!(records_chirho.is_empty());
    assert_eq!(tail_chirho, anchor_chirho);
}

#[test]
fn valid_chain_walks_and_tail_binds_the_last_line_chirho() {
    let text_chirho = build_chain_chirho(&["alpha", "beta", "gamma"]);
    let anchor_chirho = chain_anchor_hex_chirho(DOMAIN_CHIRHO, IDENTITY_CHIRHO);
    let (records_chirho, tail_chirho) =
        walk_verified_chain_chirho(&text_chirho, &anchor_chirho, &TestFamilyChirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(records_chirho[2].record_chirho.payload_chirho, "gamma");
    let last_line_chirho = text_chirho.lines().last().unwrap();
    assert_eq!(tail_chirho, stored_line_digest_hex_chirho(last_line_chirho));
    // Each verified line's digest is the NEXT record's prev (the binding law, verified end-to-end).
    assert_eq!(
        records_chirho[1].record_chirho.prev_chirho,
        records_chirho[0].line_digest_chirho
    );
}

#[test]
fn anchor_domain_separation_refuses_a_foreign_chain_chirho() {
    let text_chirho = build_chain_chirho(&["alpha"]);
    // Same identity, DIFFERENT domain: record 0's prev cannot bind the foreign anchor.
    let foreign_anchor_chirho = chain_anchor_hex_chirho("other-family-chirho", IDENTITY_CHIRHO);
    let error_chirho =
        walk_verified_chain_chirho(&text_chirho, &foreign_anchor_chirho, &TestFamilyChirho)
            .unwrap_err();
    assert_eq!(
        error_chirho,
        ChainWalkErrorChirho::PrevBindingChirho { seq_chirho: 0 }
    );
    // Same domain, different INSTANCE identity: refused the same way (no cross-log splice).
    let foreign_id_anchor_chirho = chain_anchor_hex_chirho(DOMAIN_CHIRHO, "log-beta-chirho");
    assert_eq!(
        walk_verified_chain_chirho(&text_chirho, &foreign_id_anchor_chirho, &TestFamilyChirho)
            .unwrap_err(),
        ChainWalkErrorChirho::PrevBindingChirho { seq_chirho: 0 }
    );
}

#[test]
fn dense_seq_gap_and_duplicate_refuse_chirho() {
    let anchor_chirho = chain_anchor_hex_chirho(DOMAIN_CHIRHO, IDENTITY_CHIRHO);
    // Gap: seq jumps to 1 at index 0.
    let gap_line_chirho = format!("1|{anchor_chirho}|alpha|ok");
    assert_eq!(
        walk_verified_chain_chirho(&gap_line_chirho, &anchor_chirho, &TestFamilyChirho)
            .unwrap_err(),
        ChainWalkErrorChirho::DenseSeqChirho {
            expected_chirho: 0,
            found_chirho: 1
        }
    );
    // Duplicate: a valid line 0 followed by a REPLAY of seq 0 (its prev even binds line 0's digest
    // — the dense law refuses before prev is consulted).
    let line0_chirho = format!("0|{anchor_chirho}|alpha|ok");
    let digest0_chirho = stored_line_digest_hex_chirho(&line0_chirho);
    let replay_chirho = format!("{line0_chirho}\n0|{digest0_chirho}|alpha|ok\n");
    assert_eq!(
        walk_verified_chain_chirho(&replay_chirho, &anchor_chirho, &TestFamilyChirho).unwrap_err(),
        ChainWalkErrorChirho::DenseSeqChirho {
            expected_chirho: 1,
            found_chirho: 0
        }
    );
}

#[test]
fn interior_tamper_ripples_to_a_prev_mismatch_chirho() {
    let text_chirho = build_chain_chirho(&["alpha", "beta", "gamma"]);
    let anchor_chirho = chain_anchor_hex_chirho(DOMAIN_CHIRHO, IDENTITY_CHIRHO);
    // Flip one payload byte in the MIDDLE line: its own parse still succeeds, but its stored-line
    // digest changes, so line 2's prev no longer binds — the tamper ripples forward.
    let tampered_chirho = text_chirho.replace("beta", "betA");
    assert_eq!(
        walk_verified_chain_chirho(&tampered_chirho, &anchor_chirho, &TestFamilyChirho)
            .unwrap_err(),
        ChainWalkErrorChirho::PrevBindingChirho { seq_chirho: 2 }
    );
}

#[test]
fn family_hook_refusal_aborts_fail_closed_chirho() {
    let text_chirho = build_chain_chirho(&["alpha", "beta"]);
    // Break line 1's signature flag WITHOUT changing what line 2 would bind (no line 2 here): the
    // family hook must abort the walk with ITS typed error carried verbatim.
    let bad_sig_chirho = {
        let mut lines_chirho: Vec<String> = text_chirho
            .lines()
            .map(|line_chirho| line_chirho.to_string())
            .collect();
        let last_chirho = lines_chirho.pop().unwrap();
        lines_chirho.push(last_chirho.replace("|ok", "|bad"));
        lines_chirho.join("\n")
    };
    // The tampered final line's prev still binds (we only changed ITS bytes, and nothing follows
    // it), so the failure lands exactly on the family signature hook.
    assert_eq!(
        walk_verified_chain_chirho(
            &bad_sig_chirho,
            &chain_anchor_hex_chirho(DOMAIN_CHIRHO, IDENTITY_CHIRHO),
            &TestFamilyChirho
        )
        .unwrap_err(),
        ChainWalkErrorChirho::FamilyChirho {
            error_chirho: TestErrorChirho::SignatureChirho { seq_chirho: 1 }
        }
    );
}

#[test]
fn kind_registry_law_equivalence_anchor_and_digest_chirho() {
    // The extraction-faithfulness pin: the core's anchor and line-digest must equal the landed
    // kind-registry law byte-for-byte (domain + ":" + id, blake3 hex; blake3 of the line bytes) so
    // the later re-base is byte-identical by construction.
    let anchor_chirho = chain_anchor_hex_chirho("kind-registry-chain-v1-chirho", "registry-a");
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"kind-registry-chain-v1-chirho");
    hasher_chirho.update(b":");
    hasher_chirho.update(b"registry-a");
    assert_eq!(anchor_chirho, hasher_chirho.finalize().to_hex().to_string());
    assert_eq!(
        stored_line_digest_hex_chirho("any-line"),
        blake3::hash(b"any-line").to_hex().to_string()
    );
}
