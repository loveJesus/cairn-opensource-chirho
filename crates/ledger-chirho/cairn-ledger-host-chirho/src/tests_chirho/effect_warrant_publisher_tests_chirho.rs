// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the resident effect-warrant publisher: what gets published, at which coordinate, and
//! what is refused without publishing anything.
//!
//! These pin the WARRANT contract, not the append: that a warrant is published at exactly the
//! coordinate the GD7 plan reducer recomputes, that its bytes are the canonical signed line and
//! nothing more, that an unverifiable line publishes nothing at all, and that a coordinate already
//! binding different bytes refuses by name instead of rewriting.

use crate::resident_authority_chirho::{
    publish_effect_intent_warrant_for_tests_chirho,
    publish_effect_terminal_warrant_for_tests_chirho, ResidentEffectWarrantRefusalChirho,
};
use anyhow::Result;
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, effect_intent_ref_chirho, sign_effect_intent_chirho,
    EffectIntentChirho, EffectIntentJournalCutChirho, EffectIntentSignerPortChirho,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_effect_commit_chirho::minimal_warrant_chirho::verify_minimal_warrant_line_chirho;
use cairn_effect_commit_chirho::terminal_chirho::{
    canonical_effect_terminal_outcome_line_chirho, effect_terminal_outcome_ref_chirho,
    sign_effect_terminal_outcome_chirho, EffectTerminalDispositionChirho,
    EffectTerminalOutcomeChirho, EffectTerminalSignerPortChirho,
    EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO,
};
use cairn_effect_commit_ledger_chirho::public_evidence_chirho::{
    public_effect_evidence_path_chirho, PublicEffectEvidenceKindChirho,
    RootPublicEffectEvidenceStoreChirho, MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, HlcChirho};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct WarrantSignerChirho {
    secret_chirho: [u8; 32],
}

impl WarrantSignerChirho {
    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(line_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl EffectIntentSignerPortChirho for WarrantSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        "warrant-intent-root-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

impl EffectTerminalSignerPortChirho for WarrantSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        "warrant-terminal-root-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

fn warrant_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let count_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-warrant-{label_chirho}-{nanos_chirho}-{count_chirho}"
    ));
    fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn digest_chirho(nibble_chirho: char) -> DigestChirho {
    DigestChirho(nibble_chirho.to_string().repeat(64))
}

fn signed_intent_warrant_chirho(
    signer_chirho: &WarrantSignerChirho,
    unique_chirho: char,
) -> (DigestChirho, String) {
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: EffectIntentJournalCutChirho {
                journal_genesis_digest_chirho: digest_chirho('1'),
                tail_seq_chirho: 4,
                tail_record_digest_chirho: digest_chirho('2'),
                tail_hlc_chirho: HlcChirho {
                    physical_ms_chirho: 4,
                    logical_chirho: 0,
                },
            },
            contract_set_digest_chirho: digest_chirho('6'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": digest_chirho('7').0,
                "capability_fingerprint_chirho": digest_chirho('8').0,
            }))
            .unwrap(),
            reversion_contract_digest_chirho: digest_chirho(unique_chirho),
            request_ref_chirho: digest_chirho(unique_chirho),
            request_context_ref_chirho: digest_chirho('9'),
            evidence_refs_chirho: vec![digest_chirho('a')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: AssetKindIdChirho("warrant-kind-chirho".to_owned()),
                kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho('b')),
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: AccountIdChirho {
                owner_chirho: "warrant-payer-chirho".to_owned(),
                kind_id_chirho: AssetKindIdChirho("warrant-kind-chirho".to_owned()),
            },
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::PlatformChirho,
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signer_chirho,
    )
    .unwrap();
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    (intent_ref_chirho, line_chirho)
}

fn signed_terminal_chirho(
    signer_chirho: &WarrantSignerChirho,
    intent_ref_chirho: &DigestChirho,
) -> (DigestChirho, String) {
    let outcome_chirho = sign_effect_terminal_outcome_chirho(
        EffectTerminalOutcomeChirho {
            schema_chirho: EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO.to_owned(),
            intent_ref_chirho: intent_ref_chirho.clone(),
            provider_evidence_ref_chirho: digest_chirho('c'),
            disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho {
                result_ref_chirho: digest_chirho('d'),
            },
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signer_chirho,
    )
    .unwrap();
    let outcome_ref_chirho = effect_terminal_outcome_ref_chirho(&outcome_chirho).unwrap();
    let line_chirho = canonical_effect_terminal_outcome_line_chirho(&outcome_chirho).unwrap();
    (outcome_ref_chirho, line_chirho)
}

fn loaded_warrant_chirho(
    root_chirho: &Path,
    kind_chirho: PublicEffectEvidenceKindChirho,
    coordinate_chirho: &DigestChirho,
) -> Option<Vec<u8>> {
    RootPublicEffectEvidenceStoreChirho::new_chirho(root_chirho)
        .load_bounded_chirho(
            kind_chirho,
            &coordinate_chirho.0,
            MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
        )
        .unwrap()
}

/// A2 + A6. The warrant lands at EXACTLY the coordinate the plan reducer recomputes, carrying the
/// canonical signed line byte for byte — no envelope, no added field, no second surface.
#[test]
fn published_intent_warrant_is_the_canonical_line_at_the_recomputed_ref_chirho() {
    let root_chirho = warrant_root_chirho("intent-happy");
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let (intent_ref_chirho, line_chirho) = signed_intent_warrant_chirho(&signer_chirho, '3');

    let published_ref_chirho =
        publish_effect_intent_warrant_for_tests_chirho(&root_chirho, &line_chirho, &signer_chirho)
            .expect("a verified intent line publishes its warrant");

    // The reducer recomputes effect_intent_ref_chirho over the verified content and demands
    // equality with the ref it was handed. Publishing anywhere else would refuse as Missing.
    assert_eq!(published_ref_chirho, intent_ref_chirho);
    let stored_chirho = loaded_warrant_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &intent_ref_chirho,
    )
    .expect("the warrant is retrievable at its own ref");
    // The published bytes are the MINIMAL WARRANT, not the intent line. Verifying them through the
    // same door the reducer uses proves the projection is consumable, and the inequality proves the
    // narrowing actually happened rather than being asserted in a comment.
    let text_chirho = String::from_utf8(stored_chirho.clone()).expect("warrant is utf-8");
    assert_ne!(
        stored_chirho,
        line_chirho.as_bytes(),
        "the projection must NOT hold the intent line -- that is the whole narrowing"
    );
    let verified_chirho = verify_minimal_warrant_line_chirho(&text_chirho, &signer_chirho)
        .expect("the published warrant verifies through the reducer's own door");
    assert_eq!(verified_chirho.intent_ref_chirho, intent_ref_chirho);
    assert_eq!(
        verified_chirho.payer_account_binding_chirho,
        AccountIdChirho {
            owner_chirho: "warrant-payer-chirho".to_owned(),
            kind_id_chirho: AssetKindIdChirho("warrant-kind-chirho".to_owned()),
        }
        .digest_chirho(),
        "the payer account is carried as its binding, recomputable from the record"
    );
    assert!(
        !text_chirho.contains("warrant-payer-chirho"),
        "the payer account OWNER must never appear in the projection"
    );
}

#[test]
fn full_intent_bytes_in_warrant_family_refuse_as_non_warrant_chirho() {
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let (_intent_ref_chirho, full_intent_line_chirho) =
        signed_intent_warrant_chirho(&signer_chirho, '4');

    let refusal_chirho =
        verify_minimal_warrant_line_chirho(&full_intent_line_chirho, &signer_chirho)
            .expect_err("a full intent must never satisfy the warrant reader");
    assert!(
        refusal_chirho.to_string().contains("schema")
            || refusal_chirho.to_string().contains("warrant"),
        "the strict reader must name the non-warrant refusal: {refusal_chirho}"
    );
}

/// A1. An unverifiable line publishes NOTHING. The refusal names the warrant, so a forged line is
/// never reported as a storage fault, and no orphan is left behind for it either.
#[test]
fn unverifiable_intent_warrant_publishes_nothing_chirho() {
    let root_chirho = warrant_root_chirho("intent-forged");
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let (intent_ref_chirho, line_chirho) = signed_intent_warrant_chirho(&signer_chirho, '3');
    let mut tampered_chirho: serde_json::Value = serde_json::from_str(&line_chirho).unwrap();
    tampered_chirho["request_ref_chirho"] = serde_json::json!("8".repeat(64));
    let tampered_line_chirho = serde_json::to_string(&tampered_chirho).unwrap();
    let tampered_ref_chirho = DigestChirho(
        blake3::hash(tampered_line_chirho.as_bytes())
            .to_hex()
            .to_string(),
    );

    let refusal_chirho = publish_effect_intent_warrant_for_tests_chirho(
        &root_chirho,
        &tampered_line_chirho,
        &signer_chirho,
    )
    .expect_err("a signature-invalid intent cannot become a warrant");

    assert_eq!(
        refusal_chirho,
        ResidentEffectWarrantRefusalChirho::InvalidIntentWarrantChirho
    );
    // Neither the original coordinate nor any coordinate derived from the tampered bytes exists.
    assert!(loaded_warrant_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &intent_ref_chirho
    )
    .is_none());
    assert!(!public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &tampered_ref_chirho.0
    )
    .unwrap()
    .exists());
}

/// A7. Republishing the identical warrant is idempotent, so a retried append re-warrants without a
/// second write. This is what lets the publisher sit ahead of an in-window same-K journal retry.
#[test]
fn republishing_the_identical_intent_warrant_is_idempotent_chirho() {
    let root_chirho = warrant_root_chirho("intent-retry");
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let (intent_ref_chirho, line_chirho) = signed_intent_warrant_chirho(&signer_chirho, '3');

    let first_chirho =
        publish_effect_intent_warrant_for_tests_chirho(&root_chirho, &line_chirho, &signer_chirho)
            .expect("first publish");
    let second_chirho =
        publish_effect_intent_warrant_for_tests_chirho(&root_chirho, &line_chirho, &signer_chirho)
            .expect("republishing identical bytes is idempotent");

    assert_eq!(first_chirho, second_chirho);
    assert_eq!(first_chirho, intent_ref_chirho);
    let stored_chirho = loaded_warrant_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &intent_ref_chirho,
    )
    .unwrap();
    assert_ne!(
        stored_chirho,
        line_chirho.as_bytes(),
        "the projection holds the warrant, never the intent line"
    );
    verify_minimal_warrant_line_chirho(
        std::str::from_utf8(&stored_chirho).unwrap(),
        &signer_chirho,
    )
    .expect("the republished warrant still verifies");
}

/// A4. A coordinate that already binds DIFFERENT bytes refuses by name. Warrants are immutable:
/// the publisher never rewrites, and the refusal is distinguishable from a missing or forged one.
#[test]
fn intent_warrant_coordinate_binding_other_bytes_refuses_by_name_chirho() {
    let root_chirho = warrant_root_chirho("intent-collision");
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let (intent_ref_chirho, line_chirho) = signed_intent_warrant_chirho(&signer_chirho, '3');
    // Plant foreign bytes at the coordinate this warrant would occupy.
    let planted_path_chirho = public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &intent_ref_chirho.0,
    )
    .unwrap();
    fs::create_dir_all(planted_path_chirho.parent().unwrap()).unwrap();
    fs::write(&planted_path_chirho, b"{\"foreign_chirho\":true}").unwrap();

    let refusal_chirho =
        publish_effect_intent_warrant_for_tests_chirho(&root_chirho, &line_chirho, &signer_chirho)
            .expect_err("a coordinate binding different bytes cannot be rewritten");

    assert_eq!(
        refusal_chirho,
        ResidentEffectWarrantRefusalChirho::ImmutableCollisionChirho
    );
    assert_eq!(
        fs::read(&planted_path_chirho).unwrap(),
        b"{\"foreign_chirho\":true}",
        "the planted bytes are left untouched; a warrant is never overwritten"
    );
}

/// Terminal twin of the happy path. The terminal side composes the SAME order and the same
/// coordinate discipline; it was measured to have the identical gap, so it gets the identical arm.
#[test]
fn published_terminal_warrant_is_the_canonical_line_at_its_outcome_ref_chirho() {
    let root_chirho = warrant_root_chirho("terminal-happy");
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let (intent_ref_chirho, _intent_line_chirho) =
        signed_intent_warrant_chirho(&signer_chirho, '3');
    let (outcome_ref_chirho, terminal_line_chirho) =
        signed_terminal_chirho(&signer_chirho, &intent_ref_chirho);

    let published_ref_chirho = publish_effect_terminal_warrant_for_tests_chirho(
        &root_chirho,
        &terminal_line_chirho,
        &signer_chirho,
    )
    .expect("a verified terminal outcome publishes its warrant");

    assert_eq!(published_ref_chirho, outcome_ref_chirho);
    assert_eq!(
        loaded_warrant_chirho(
            &root_chirho,
            PublicEffectEvidenceKindChirho::TerminalChirho,
            &outcome_ref_chirho
        )
        .expect("the terminal warrant is retrievable at its own ref"),
        terminal_line_chirho.as_bytes()
    );
    // The terminal warrant does not land in the intent family: the two kinds stay separate
    // coordinates, so a terminal can never satisfy a reducer lookup for an intent.
    assert!(loaded_warrant_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &outcome_ref_chirho
    )
    .is_none());
}

/// Terminal twin of A1.
#[test]
fn unverifiable_terminal_warrant_publishes_nothing_chirho() {
    let root_chirho = warrant_root_chirho("terminal-forged");
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let (intent_ref_chirho, _intent_line_chirho) =
        signed_intent_warrant_chirho(&signer_chirho, '3');
    let (outcome_ref_chirho, terminal_line_chirho) =
        signed_terminal_chirho(&signer_chirho, &intent_ref_chirho);
    let mut tampered_chirho: serde_json::Value =
        serde_json::from_str(&terminal_line_chirho).unwrap();
    tampered_chirho["provider_evidence_ref_chirho"] = serde_json::json!("8".repeat(64));
    let tampered_line_chirho = serde_json::to_string(&tampered_chirho).unwrap();

    let refusal_chirho = publish_effect_terminal_warrant_for_tests_chirho(
        &root_chirho,
        &tampered_line_chirho,
        &signer_chirho,
    )
    .expect_err("a signature-invalid terminal outcome cannot become a warrant");

    assert_eq!(
        refusal_chirho,
        ResidentEffectWarrantRefusalChirho::InvalidTerminalWarrantChirho
    );
    assert!(loaded_warrant_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::TerminalChirho,
        &outcome_ref_chirho
    )
    .is_none());
}

/// THE MIGRATION CONTROL, RETARGETED (second move). Its history is the point, so it is written down
/// rather than lost: it was first red-by-assertion while the full intent line was published, then
/// flipped to assert ABSENCE once the minimal warrant landed. It is now aimed one step deeper.
///
/// WHY IT MOVED AGAIN. The intent door now applies the money log's own bounded-identifier law, so
/// the arm's original fixture -- `john.smith@example.com` and `Jane Q Public` -- can no longer
/// become a signed intent at all. That is a STRONGER outcome than this arm asserted, and it is
/// pinned by `an_email_shaped_intent_never_becomes_a_signed_intent_or_a_warrant_chirho` below, which
/// inherits that exact fixture. Retargeting rather than deleting keeps both properties pinned.
///
/// WHAT THIS ARM NOW GUARDS, and why the narrowing is still load-bearing after the law: the law is a
/// SHAPE floor, exactly as `wire_chirho` says of itself -- it refuses control characters, whitespace
/// ("free-text shape") and `@` ("email shape"), and nothing more. `acct-jane-q-public-chirho` is
/// law-LEGAL and is still an identifier naming a person. If the narrowing were removed and only the
/// law kept, that string would sit permanently in an immutable projection with no privacy or GC
/// custody. So this fixture is deliberately law-legal: it can only be kept out of the warrant by the
/// digest binding, never by the law.
///
/// IF THIS GOES RED: the projection is carrying identifying content again. Do not relax the
/// needles -- find what widened the published bytes.
#[test]
fn pii_shaped_intent_fields_never_reach_the_warrant_on_disk_chirho() {
    let root_chirho = warrant_root_chirho("pii-boundary");
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let (intent_ref_chirho, line_chirho) = signed_intent_identifying_chirho(
        &signer_chirho,
        LAW_LEGAL_OWNER_CHIRHO,
        LAW_LEGAL_PRINCIPAL_CHIRHO,
    )
    .expect("a law-legal identifier signs -- the law bounds shape, it does not de-identify");

    // Positive control: the identifiers really are in the intent we are publishing from. Without
    // this, the absence assertions below would pass just as well against an empty fixture.
    assert!(
        line_chirho.contains(LAW_LEGAL_OWNER_CHIRHO)
            && line_chirho.contains(LAW_LEGAL_PRINCIPAL_CHIRHO),
        "the fixture intent must actually carry the identifying content this arm is about"
    );

    publish_effect_intent_warrant_for_tests_chirho(&root_chirho, &line_chirho, &signer_chirho)
        .expect("an intent with identifying fields still publishes -- as a narrowed warrant");

    let stored_chirho = loaded_warrant_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &intent_ref_chirho,
    )
    .expect("the warrant is on disk");
    let text_chirho = String::from_utf8(stored_chirho).expect("warrant is utf-8");
    assert!(
        !text_chirho.contains(LAW_LEGAL_OWNER_CHIRHO),
        "an identifying account owner reached the projection: {text_chirho}"
    );
    assert!(
        !text_chirho.contains(LAW_LEGAL_PRINCIPAL_CHIRHO),
        "an identifying causer principal reached the projection: {text_chirho}"
    );
    assert!(
        !text_chirho.contains('@'),
        "no '@' may appear anywhere in a published warrant: {text_chirho}"
    );

    // The bindings ARE present, so the reducer's equality checks still have something to compare.
    let verified_chirho = verify_minimal_warrant_line_chirho(&text_chirho, &signer_chirho)
        .expect("the warrant verifies");
    assert_eq!(
        verified_chirho.attribution_binding_chirho,
        AttributionChirho::CauserChirho {
            principal_chirho: LAW_LEGAL_PRINCIPAL_CHIRHO.to_owned(),
        }
        .binding_digest_chirho(),
        "the attribution is bound by digest, recomputable from the record"
    );
}

/// The original migration-control fixture, now pinning the STRONGER property it earned.
///
/// `john.smith@example.com` / `Jane Q Public` is exactly the content M-PRIV-2 measured reaching the
/// warrant on disk. It is now refused at the intent door -- the same
/// `validate_bounded_identifier_chirho` the money log has always applied to these very fields once
/// they become a record. Nothing is signed, so nothing is published, so the publish-first ordering
/// can no longer strand that content in an immutable store on behalf of an intent the ledger was
/// always going to reject.
#[test]
fn an_email_shaped_intent_never_becomes_a_signed_intent_or_a_warrant_chirho() {
    let signer_chirho = WarrantSignerChirho {
        secret_chirho: [7; 32],
    };
    let refusal_chirho =
        signed_intent_identifying_chirho(&signer_chirho, "john.smith@example.com", "Jane Q Public")
            .expect_err("an email-shaped payer owner must not become a signed intent");
    assert!(
        format!("{refusal_chirho:?}").contains("payer_account_chirho.owner_chirho"),
        "the refusal must name the field it refused: {refusal_chirho:?}"
    );
    assert!(
        format!("{refusal_chirho:?}").contains("email shape"),
        "the refusal must carry the REASON, not collapse it: {refusal_chirho:?}"
    );
}

/// A law-legal identifier that is nonetheless a person's name. Kept as a named constant because two
/// arms depend on it being law-legal AND identifying at the same time -- change it and the retarget
/// note above stops being true.
const LAW_LEGAL_OWNER_CHIRHO: &str = "acct-jane-q-public-chirho";
const LAW_LEGAL_PRINCIPAL_CHIRHO: &str = "jane-q-public-chirho";

fn signed_intent_identifying_chirho(
    signer_chirho: &WarrantSignerChirho,
    owner_chirho: &str,
    principal_chirho: &str,
) -> Result<
    (DigestChirho, String),
    cairn_effect_commit_chirho::intent_chirho::EffectIntentWireErrorChirho,
> {
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: EffectIntentJournalCutChirho {
                journal_genesis_digest_chirho: digest_chirho('1'),
                tail_seq_chirho: 4,
                tail_record_digest_chirho: digest_chirho('2'),
                tail_hlc_chirho: HlcChirho {
                    physical_ms_chirho: 4,
                    logical_chirho: 0,
                },
            },
            contract_set_digest_chirho: digest_chirho('6'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": digest_chirho('7').0,
                "capability_fingerprint_chirho": digest_chirho('8').0,
            }))
            .unwrap(),
            reversion_contract_digest_chirho: digest_chirho('3'),
            request_ref_chirho: digest_chirho('3'),
            request_context_ref_chirho: digest_chirho('9'),
            evidence_refs_chirho: vec![digest_chirho('a')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: AssetKindIdChirho("warrant-kind-chirho".to_owned()),
                kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho('b')),
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: AccountIdChirho {
                owner_chirho: owner_chirho.to_owned(),
                kind_id_chirho: AssetKindIdChirho("warrant-kind-chirho".to_owned()),
            },
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: principal_chirho.to_owned(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signer_chirho,
    )?;
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho)?;
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho)?;
    Ok((intent_ref_chirho, line_chirho))
}
