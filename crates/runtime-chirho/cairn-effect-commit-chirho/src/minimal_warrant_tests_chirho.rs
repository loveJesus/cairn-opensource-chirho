// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Arms for the identifier LAW on the two published CF3 objects: the minimal warrant's own
//! `kind_id_chirho`, and the intent door that both write sites share.
//!
//! # What these pin, and why the law is not the same thing as the narrowing
//!
//! The narrowing (a warrant carries digests, not values) answers "what leaves the journal". The LAW
//! answers "what may be in those strings at all", and it is the money log's own
//! `validate_bounded_identifier_chirho`: no control characters, no whitespace (free-text shape), no
//! `@` (email shape). Before this, an asset kind rode the warrant as an unvalidated `String` and the
//! judgement that "an asset kind is safe metadata" was PROSE. It is now bytes.
//!
//! The intent-door half is what closes the CF3 PostgreSQL write site. That store retains the FULL
//! canonical intent line on purpose — `reconcile_in_doubt_chirho` reloads it, re-verifies it, and
//! hands the rebuilt intent to the provider to close an in-doubt Hold — so a minimal projection
//! cannot substitute for it there. Applying the record law at the intent door instead means the
//! retained line can no longer carry a shape the money log itself refuses.
//!
//! NOTE ON SCOPE, so nothing here is read as more than it is: this law is a SHAPE floor, exactly as
//! `wire_chirho` says of itself. `owner_chirho: "bob-chirho"` passes it and is still an identifier.
//! That is precisely why the warrant narrowing still matters and is pinned separately — see
//! `pii_shaped_intent_fields_never_reach_the_warrant_on_disk_chirho` in the ledger-host publisher
//! arms, whose fixture is deliberately law-LEGAL.

use crate::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    EffectIntentJournalCutChirho, EffectIntentSignerPortChirho, EffectIntentWireErrorChirho,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use crate::minimal_warrant_chirho::{
    minimal_warrant_from_intent_chirho, parse_canonical_minimal_warrant_line_chirho,
    sign_minimal_warrant_chirho,
};
use anyhow::Result;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, HlcChirho};
use cairn_ledger_model_chirho::LogIdChirho;

const LEGAL_KIND_CHIRHO: &str = "billing-credit-chirho";

struct LawArmSignerChirho;

impl EffectIntentSignerPortChirho for LawArmSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(b"law-arm-root-chirho");
        hasher_chirho.update(signed_content_line_chirho.as_bytes());
        Ok(hasher_chirho.finalize().to_hex().to_string())
    }

    fn key_id_chirho(&self) -> String {
        "law-arm-root-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho).unwrap() == sig_chirho
    }
}

fn digest_chirho(nibble_chirho: char) -> DigestChirho {
    DigestChirho(nibble_chirho.to_string().repeat(64))
}

/// A law-legal intent. Every arm below mutates exactly ONE field of this, so a refusal can only be
/// attributed to that field.
fn lawful_intent_chirho() -> EffectIntentChirho {
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
        request_ref_chirho: digest_chirho('4'),
        request_context_ref_chirho: digest_chirho('9'),
        evidence_refs_chirho: vec![digest_chirho('a')],
        resolved_price_chirho: AssetOpChirho {
            amount_chirho: 10,
            kind_id_chirho: AssetKindIdChirho(LEGAL_KIND_CHIRHO.to_owned()),
            kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho('b')),
            rounding_chirho: RoundingChirho::ExactChirho,
        },
        payer_account_chirho: LogIdChirho::new_chirho("user-7-chirho", LEGAL_KIND_CHIRHO),
        effect_step_chirho: 1,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "user-7-chirho".to_owned(),
        },
        original_effect_key_chirho: None,
        sig_chirho: String::new(),
        key_id_chirho: String::new(),
    }
}

/// Set BOTH kind-id coordinates: the intent's own equality check compares them, and an arm about the
/// LAW must not be answered by the equality check firing first.
fn intent_with_kind_chirho(kind_chirho: &str) -> EffectIntentChirho {
    let mut intent_chirho = lawful_intent_chirho();
    intent_chirho.resolved_price_chirho.kind_id_chirho = AssetKindIdChirho(kind_chirho.to_owned());
    intent_chirho.payer_account_chirho.kind_id_chirho = AssetKindIdChirho(kind_chirho.to_owned());
    intent_chirho
}

fn refusal_chirho(error_chirho: &EffectIntentWireErrorChirho) -> (&'static str, String) {
    match error_chirho {
        EffectIntentWireErrorChirho::UnboundedIdentifierChirho {
            field_chirho,
            reason_chirho,
        } => (field_chirho, reason_chirho.clone()),
        other_chirho => {
            panic!("expected the bounded-identifier law to refuse, got {other_chirho:?}")
        }
    }
}

/// POSITIVE CONTROL for every refusal arm below. A bounded, single-token asset kind narrows to a
/// warrant and the kind rides through in the clear — without this, the refusals could be passing
/// because the constructor refuses everything.
#[test]
fn a_bounded_asset_kind_still_narrows_to_a_warrant_and_stays_readable_chirho() {
    let warrant_chirho =
        minimal_warrant_from_intent_chirho(&intent_with_kind_chirho(LEGAL_KIND_CHIRHO))
            .expect("a bounded asset kind is exactly what this coordinate is for");
    assert_eq!(
        warrant_chirho.kind_id_chirho.0, LEGAL_KIND_CHIRHO,
        "the asset kind stays in the clear: it is the audit-readable coordinate the terminal \
         record-law check compares against leg.account.kind_id_chirho"
    );
}

/// ITEM 0. An email-shaped asset kind is refused AT THE NARROWING POINT, by name.
///
/// The field name in the refusal is what proves WHICH law fired: `kind_id_chirho` is the warrant's
/// own check, deliberately placed before the ref computation. If this ever reports
/// `payer_account_chirho.kind_id_chirho` or `resolved_price_chirho.kind_id_chirho`, the intent
/// door answered instead and the warrant's own gate is no longer being exercised — retarget by
/// restoring the ordering in `minimal_warrant_from_intent_chirho`, do not relax the assertion.
#[test]
fn an_email_shaped_asset_kind_refuses_at_the_warrant_narrowing_point_by_name_chirho() {
    let error_chirho =
        minimal_warrant_from_intent_chirho(&intent_with_kind_chirho("billing@example.com"))
            .expect_err("an email-shaped asset kind must not reach the projection");
    let (field_chirho, reason_chirho) = refusal_chirho(&error_chirho);
    assert_eq!(field_chirho, "kind_id_chirho");
    assert_eq!(reason_chirho, "'@' (email shape)");
}

/// ITEM 0, the other denylisted shape: multi-word free text.
#[test]
fn a_free_text_asset_kind_refuses_at_the_warrant_narrowing_point_by_name_chirho() {
    let error_chirho =
        minimal_warrant_from_intent_chirho(&intent_with_kind_chirho("Jane Q Public"))
            .expect_err("a free-text asset kind must not reach the projection");
    let (field_chirho, reason_chirho) = refusal_chirho(&error_chirho);
    assert_eq!(field_chirho, "kind_id_chirho");
    assert_eq!(reason_chirho, "whitespace (free-text shape)");
}

/// The law also guards the READ direction, where no intent exists at all.
///
/// This is the arm that proves the warrant's body walk — not its constructor — carries the law: the
/// bytes are hand-mutated on the way back in, exactly as an adversarial or legacy line on disk would
/// arrive. Nothing about the intent path can satisfy it.
#[test]
fn a_warrant_line_off_disk_refuses_a_free_text_asset_kind_chirho() {
    let signer_chirho = LawArmSignerChirho;
    let warrant_chirho = sign_minimal_warrant_chirho(
        minimal_warrant_from_intent_chirho(&intent_with_kind_chirho(LEGAL_KIND_CHIRHO)).unwrap(),
        &signer_chirho,
    )
    .expect("the lawful warrant signs");
    let line_chirho =
        crate::minimal_warrant_chirho::canonical_minimal_warrant_line_chirho(&warrant_chirho)
            .unwrap();

    // Positive control: the coordinate this arm mutates really is in the line.
    assert!(
        line_chirho.contains(LEGAL_KIND_CHIRHO),
        "the fixture must carry the kind id this arm rewrites"
    );
    let tampered_chirho = line_chirho.replace(LEGAL_KIND_CHIRHO, "Jane Q Public");
    assert_ne!(
        tampered_chirho, line_chirho,
        "the mutation must have applied"
    );

    let error_chirho = parse_canonical_minimal_warrant_line_chirho(&tampered_chirho)
        .expect_err("a free-text asset kind must not load back out of the projection either");
    let (field_chirho, reason_chirho) = refusal_chirho(&error_chirho);
    assert_eq!(field_chirho, "kind_id_chirho");
    assert_eq!(reason_chirho, "whitespace (free-text shape)");
    // And the refusal is the LAW, not merely the canonical-bytes check that would also have caught
    // this. Asserting the reason is what keeps the arm from passing for the wrong reason.
    assert!(
        !matches!(
            error_chirho,
            EffectIntentWireErrorChirho::NonCanonicalBytesChirho
        ),
        "the identifier law must fire before the byte comparison"
    );
}

/// ITEM 2. The intent door refuses what the money log refuses — which is what closes the CF3
/// PostgreSQL site, where the FULL line is retained deliberately.
///
/// Before this, `sign_effect_intent_chirho` happily signed an email-shaped payer owner, and because
/// a warrant is published BEFORE the append it warrants, that value reached an immutable store on an
/// intent the ledger was always going to reject. Now it never becomes a signed intent at all.
#[test]
fn the_intent_door_refuses_an_email_shaped_payer_owner_by_name_chirho() {
    let mut intent_chirho = lawful_intent_chirho();
    intent_chirho.payer_account_chirho.owner_chirho = "john.smith@example.com".to_owned();

    let error_chirho = sign_effect_intent_chirho(intent_chirho.clone(), &LawArmSignerChirho)
        .expect_err("an email-shaped payer owner must not become a signed intent");
    let (field_chirho, reason_chirho) = refusal_chirho(&error_chirho);
    assert_eq!(field_chirho, "payer_account_chirho.owner_chirho");
    assert_eq!(reason_chirho, "'@' (email shape)");

    // The same refusal on the EMIT door, so an already-signed legacy value cannot be canonically
    // re-emitted into a store either.
    intent_chirho.sig_chirho = "deadbeef".to_owned();
    intent_chirho.key_id_chirho = "law-arm-root-key-chirho".to_owned();
    assert_eq!(
        refusal_chirho(&canonical_effect_intent_line_chirho(&intent_chirho).unwrap_err()).0,
        "payer_account_chirho.owner_chirho"
    );
}

/// ITEM 2, the attribution half — the other free `String` M-PRIV-2 measured.
#[test]
fn the_intent_door_refuses_a_free_text_causer_principal_by_name_chirho() {
    let mut intent_chirho = lawful_intent_chirho();
    intent_chirho.attribution_chirho = AttributionChirho::CauserChirho {
        principal_chirho: "Jane Q Public".to_owned(),
    };

    let error_chirho = sign_effect_intent_chirho(intent_chirho, &LawArmSignerChirho)
        .expect_err("a free-text causer principal must not become a signed intent");
    let (field_chirho, reason_chirho) = refusal_chirho(&error_chirho);
    assert_eq!(field_chirho, "attribution_chirho.principal_chirho");
    assert_eq!(reason_chirho, "whitespace (free-text shape)");
}

/// The law's floor is a SHAPE floor and this arm says so out loud, so no later reader mistakes it
/// for a PII filter. A bounded single-token owner is still an identifier and still passes — which is
/// exactly why the warrant narrowing is a separate, still-necessary mechanism.
#[test]
fn the_shape_law_still_admits_a_bounded_identifier_and_is_not_a_pii_filter_chirho() {
    let mut intent_chirho = lawful_intent_chirho();
    intent_chirho.payer_account_chirho.owner_chirho = "jane-q-public-chirho".to_owned();
    intent_chirho.attribution_chirho = AttributionChirho::CauserChirho {
        principal_chirho: "jane-q-public-chirho".to_owned(),
    };

    let signed_chirho = sign_effect_intent_chirho(intent_chirho, &LawArmSignerChirho)
        .expect("a bounded single-token identifier is law-legal");
    let line_chirho = canonical_effect_intent_line_chirho(&signed_chirho).unwrap();
    assert!(
        line_chirho.contains("jane-q-public-chirho"),
        "the identifier is still in the intent line -- the law bounds SHAPE, it does not \
         de-identify, and the warrant narrowing is what keeps it out of the projection"
    );
}
