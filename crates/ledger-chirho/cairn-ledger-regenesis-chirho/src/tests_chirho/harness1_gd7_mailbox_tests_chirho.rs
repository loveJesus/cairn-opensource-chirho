// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! HARNESS-1 piece 10, first half: a GD7 wire command driven through the REAL actor mailbox.
//!
//! # WHAT THIS IS, AND WHY IT IS ONLY HALF
//!
//! Before this module NOTHING drove the GD7 mailbox. The three wire methods on
//! `ResidentEffectJournalHandleChirho` had zero callers — production or test — measured two ways:
//! the three mailbox variants `AdvanceGd7SinkTermChirho` / `ReleaseConvergedGd7HoldChirho` /
//! `CompleteGd7CompensationChirho` are CONSTRUCTED only inside `gd7_wire_handle_chirho.rs`, and
//! nothing called the methods that construct them. So the mailbox hop, the dispatch arms, and the
//! reply channel were unexercised, while the B3c full-chain ladder drove the RESIDENT directly one
//! layer inward and said so in its own header.
//!
//! These arms close the REFUSAL half of that gap and no more. Each proves a real wire command
//! traverses: handle method -> `try_send` -> the actor's dispatch arm -> the resident -> the reply
//! channel -> the caller, carrying a refusal that names its own barrier. Every link is real: a real
//! custody-verified actor opened by the real opener on a real published regenesis world.
//!
//! ALL THREE wire commands are now traversed — but only the two REFUSAL traversals live here.
//! `advance_gd7_sink_term_chirho`'s first traversal is a SUCCESS, in the capstone arms
//! (`harness1_compensated_terminal_arms_chirho`), driven with the world's real authenticated
//! deposed-fork observation loaded through the public witness reader. (Corrected 2026-08-05: this
//! header used to say advance was untraversable without the parked remainder's world; the
//! returning-world ladder drive made that world reachable.)
//!
//! WHICH BARRIER FIRES IN EACH, stated exactly so neither arm is over-read:
//!   - release: the door re-authenticates the adopted checkpoint BEFORE examining the certificate,
//!     so the refusal is `MissingReferencedCheckpointChirho`. This proves the WIRE and the
//!     CHECKPOINT barrier. It does NOT reach the certificate-signature barrier and must not be
//!     cited for it — that one is proven at the resident tier in the D4 write-restoration suite.
//!   - completion: the leg resolves the obligation's processing state and refuses
//!     `NotProviderObservedChirho`, which is the deepest of the two — the command got all the way
//!     to obligation resolution before refusing.
//!
//! # WHAT IT DOES NOT PROVE — read this before citing it
//!
//! It does NOT prove a compensation reaching `CompletedChirho` through the mailbox — and as of
//! 2026-08-05 neither does anything else, for a sharper, MEASURED reason. The former parked
//! remainder partially landed in the capstone arms
//! (`harness1_compensated_terminal_arms_chirho`): a real minted obligation now reaches
//! `ProviderObservedChirho` through this same mailbox, the strand is lifted by the real lawful
//! advance, the hold is released, and the fenced append COMMITS — then the post-commit
//! winner-first-record evidence refuses, because the post-adoption RESUME step does not exist yet
//! (see that module's header for the full map). Until that design decision lands, the phrase
//! "live completed compensation path" still belongs to nobody, and neither this module's refusal
//! arms nor the capstone arms may be cited for it.
//!
//! A refusal arm is worth landing on its own because the wire is exactly where a silent break
//! hides: a command that never reached the resident, or a reply that never came back, would look
//! identical to a successful no-op from outside. Proving the REFUSAL travels proves the channel is
//! connected in both directions.
//!
//! # MIGRATION PATH
//!
//! - If this starts SUCCEEDING, the release door accepted a caller-named checkpoint that names
//!   nothing. That is a money-path defect, not a fixture drift — read it before "fixing" it.
//! - If the refusal NAME changes, retarget at the new name rather than loosening to `is_err()`:
//!   the whole point is distinguishing "the wire carried a real refusal" from "something, somewhere,
//!   returned an error".
//! - The parked remainder's first half landed (`harness1_compensated_terminal_arms_chirho`);
//!   these refusal arms now stand as the negative controls beside it, exactly as planned.

use super::{fixture_chirho, request_chirho};
use crate::run_ledger_regenesis_chirho;
use cairn_config_chirho::config_chirho::load_config_chirho;
use cairn_effect_commit_chirho::compensation_chirho::{
    authorize_effect_compensation_chirho, CompensationAuthorizationFactsChirho,
    CompensationAuthorizationViewChirho, CompensationAuthorizationViewErrorChirho,
    CompensationBreakerVerdictChirho, EffectCompensationAuthorizationOutcomeChirho,
};
use cairn_effect_commit_chirho::coordinator_chirho::EffectCommitJournalViewPortChirho;
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    VerifiedEffectIntentChirho, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::open_resident_effect_journal_handle_chirho;
use cairn_ledger_host_chirho::reconciliation_chirho::ConvergedReadReplicaChirho;
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, HostLedgerSignersChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_ledger_model_chirho::LogIdChirho;

/// A CALLER-BUILT convergence certificate: well-formed enough to deserialize, signed by nobody.
///
/// Built through serde rather than a constructor because `ConvergedReadReplicaChirho` keeps its
/// fields private. Since the guarded-release brick the release door verifies the certificate's
/// signature first, so this caller-built (non-custody key, placeholder signature) payload is exactly
/// what the release refuses — at the signature barrier, before the checkpoint re-authentication.
fn caller_built_certificate_chirho(
    adopted_checkpoint_ref_chirho: &str,
) -> ConvergedReadReplicaChirho {
    serde_json::from_value(serde_json::json!({
        "schema_chirho": "gd7-converged-read-replica-v2-chirho",
        "reconciliation_identity_digest_chirho": "1".repeat(64),
        "checkpoint_ref_chirho": adopted_checkpoint_ref_chirho,
        "sealed_plan_ref_chirho": "2".repeat(64),
        "winner_fork_witness_object_digest_chirho": "3".repeat(64),
        "winner_term_chirho": 1,
        "adopted_checkpoint_ref_chirho": adopted_checkpoint_ref_chirho,
        "losing_population_identity_chirho": "harness1-losing-population-chirho",
        "losing_population_digest_chirho": "4".repeat(64),
        "terminal_outcome_identity_chirho": "harness1-terminal-outcome-chirho",
        "terminal_outcome_digest_chirho": "5".repeat(64),
        "conservation_snapshot_digest_chirho": "6".repeat(64),
        "retained_refs_chirho": [],
        "population_count_chirho": 0,
        "completed_count_chirho": 0,
        "disposed_count_chirho": 0,
        "certificate_key_id_chirho": "harness1-not-a-custody-key-chirho",
        "certificate_sig_chirho": "7".repeat(128),
    }))
    .expect("the caller-built certificate must DESERIALIZE, or the arm never reaches the wire")
}

#[test]
fn the_real_mailbox_carries_a_gd7_release_refusal_end_to_end_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let ledger_config_chirho = load_config_chirho(&fixture_chirho.config_path_chirho)
        .expect("the fixture config loads")
        .ledger_host_chirho
        .expect("fixture config carries the ledger host");

    // The REAL opener, the REAL custody-verified world. A handle is obtainable no other way, which
    // is what makes possession of one already imply an admitted world.
    let actor_chirho = open_resident_effect_journal_handle_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        None,
    )
    .expect("the published world opens the real resident actor");

    // POSITIVE CONTROL that the actor is genuinely alive and answering BEFORE the wire call. A dead
    // actor would refuse the wire command too, for an entirely different reason, and this arm would
    // read green while proving nothing — the mailbox would never have been traversed at all.
    let cut_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the live actor answers a verified-view command before the wire command is sent");

    let adopted_checkpoint_ref_chirho = "8".repeat(64);
    let certificate_chirho = caller_built_certificate_chirho(&adopted_checkpoint_ref_chirho);

    // THE WIRE CALL. First time in the repository that a GD7 wire command crosses the real actor
    // mailbox. This world has no reconciliation hold, so the release door's checkpoint
    // re-authentication must refuse — and that refusal has to travel back across the reply channel.
    let refusal_chirho = actor_chirho
        .release_converged_gd7_hold_chirho(&adopted_checkpoint_ref_chirho, &certificate_chirho)
        .expect_err(
            "releasing on a caller-built certificate against a world with no hold must REFUSE; \
             a success here would mean the release door accepts caller-supplied evidence",
        );
    let refusal_text_chirho = format!("{refusal_chirho:?}");

    // ASSERT THE REFUSAL'S IDENTITY, and note WHICH barrier it is. Since the guarded-release brick,
    // the release door verifies the convergence certificate's SIGNATURE first — v2 schema, the held
    // verifier's own key id, a signature over the canonical bytes. This world's certificate is
    // caller-built (signed by nobody, keyed to a non-custody id), so the release refuses at that
    // signature barrier before it ever re-authenticates the caller-named checkpoint. The PURPOSE of
    // this arm is unchanged — it proves a release REFUSAL travels the real actor mailbox end to end;
    // only WHICH barrier fires moved earlier, because a fabricated certificate now cannot pass the
    // signature check. (Before the brick this refused at the checkpoint re-authentication barrier
    // with `MissingReferencedCheckpointChirho`, because the door consumed the certificate only
    // through its unauthenticated field getter.)
    assert!(
        refusal_text_chirho.contains("ConvergenceCertificateUnverifiedChirho"),
        "the refusal must name the certificate-verification barrier, so a green arm cannot come \
         from an unrelated refusal.\nrefusal: {refusal_text_chirho}"
    );

    // The actor must still be SERVING after refusing. A wire command that killed the actor loop
    // would ALSO produce a refusal, and this is the assertion that tells those two apart — without
    // it, a panicking dispatch arm would read as a clean policy refusal.
    let cut_after_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .unwrap_or_else(|error_chirho| {
            panic!(
            "the actor must keep serving after the wire command refuses; if this fails the refusal \
             above came from a DEAD actor, not from the release door.\nrefusal was: \
             {refusal_text_chirho}\nserving error: {error_chirho:?}"
        )
        });
    assert_eq!(
        cut_after_chirho.tail_seq_chirho, cut_chirho.tail_seq_chirho,
        "a refused release must not move the journal tail"
    );

    drop(actor_chirho);
}

// ---------------------------------------------------------------------------------------------
// The SECOND wire command. `release` above proves the mailbox carries a refusal; this proves the
// COMPLETED LEG's own dispatch arm does too, which is a different arm and a different refusal
// path. Two of the three wire commands are traversed after this; `advance` remains untraversed
// because its input is an opaque authenticated observation that only the real witness-verifier
// can mint, and building one needs the parked remainder's world.
// ---------------------------------------------------------------------------------------------

/// Must parse as a real effect-intent coordinate. A free-form string is refused UPSTREAM of the
/// mailbox, which would make this fixture prove nothing about the wire.
const HARNESS1_ORIGINAL_EFFECT_KEY_CHIRHO: &str = concat!(
    "cf3-intent-v1-chirho:",
    "7f",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
);

/// Permits every candidate on purpose. If authorization could also refuse, a green arm would not
/// say WHICH mechanism refused — and the one under test is the completed leg, past the mailbox.
struct PermittingCompensationViewChirho;

impl CompensationAuthorizationViewChirho for PermittingCompensationViewChirho {
    fn derive_chirho(
        &self,
        _candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            HARNESS1_ORIGINAL_EFFECT_KEY_CHIRHO.to_owned(),
            HARNESS1_ORIGINAL_EFFECT_KEY_CHIRHO.to_owned(),
            1,
            4,
            CompensationBreakerVerdictChirho::PermittedChirho,
        ))
    }
}

#[test]
fn the_real_mailbox_carries_a_gd7_completion_refusal_end_to_end_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let ledger_config_chirho = load_config_chirho(&fixture_chirho.config_path_chirho)
        .expect("the fixture config loads")
        .ledger_host_chirho
        .expect("fixture config carries the ledger host");
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&ledger_config_chirho.signer_secrets_chirho)
            .expect("the fixture config names its signer secrets");
    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &fixture_chirho.root_chirho,
        &signer_refs_chirho,
    )
    .expect("the published world carries all six runtime signers");
    let kind_id_chirho = AssetKindIdChirho(fixture_chirho.plan_chirho.kind_id_chirho.clone());

    let actor_chirho = open_resident_effect_journal_handle_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        None,
    )
    .expect("the published world opens the real resident actor");

    let cut_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the live actor answers a verified-view command before the wire command is sent");
    let continuation_chirho = actor_chirho
        .current_continuation_chirho(&kind_id_chirho)
        .expect("the resident answers its kind continuation")
        .expect("the published kind has a verified continuation");

    let digest_chirho =
        |character_chirho: char| DigestChirho(character_chirho.to_string().repeat(64));
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: cut_chirho.clone(),
            contract_set_digest_chirho: digest_chirho('a'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": "b".repeat(64),
                "capability_fingerprint_chirho": "c".repeat(64)
            }))
            .expect("the fixture door parses"),
            reversion_contract_digest_chirho: digest_chirho('d'),
            request_ref_chirho: digest_chirho('e'),
            request_context_ref_chirho: digest_chirho('f'),
            evidence_refs_chirho: vec![digest_chirho('9')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 1,
                kind_id_chirho: kind_id_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho(
                fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
                kind_id_chirho,
            ),
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
            },
            // Some(..) is what makes this a COMPENSATION candidate; None is refused before the
            // authorizer can issue, and the arm would never reach the mailbox.
            original_effect_key_chirho: Some(HARNESS1_ORIGINAL_EFFECT_KEY_CHIRHO.to_owned()),
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signers_chirho.effect_intent_signer_chirho(),
    )
    .expect("the compensation intent signs");
    let intent_line_chirho =
        canonical_effect_intent_line_chirho(&intent_chirho).expect("the intent line is canonical");

    let authorization_chirho = match authorize_effect_compensation_chirho(
        &intent_line_chirho,
        signers_chirho.effect_intent_signer_chirho(),
        &PermittingCompensationViewChirho,
    )
    .expect("the compensation authorization completes")
    {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(authorized_chirho) => {
            authorized_chirho
        }
        other_chirho => panic!(
            "this fixture must yield an AUTHORIZED capability, or the arm stops before the mailbox \
             and proves nothing about the wire: {other_chirho:?}"
        ),
    };

    // THE WIRE CALL. The obligation coordinates name nothing this world ever observed, so the
    // completed leg must refuse — across the mailbox and back through the reply channel.
    let refusal_chirho = actor_chirho
        .complete_gd7_compensation_chirho(
            &"6".repeat(64),
            &"7".repeat(64),
            &"8".repeat(64),
            &"9".repeat(64),
            "harness1-idempotency-key-chirho",
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect_err(
            "completing a compensation for an obligation this world never observed must REFUSE; \
             a success would mean the completed leg accepts caller-named obligation coordinates",
        );
    let refusal_text_chirho = format!("{refusal_chirho:?}");
    // ASSERT THE REFUSAL'S IDENTITY. `NotProviderObserved` is the completed leg's OWN barrier —
    // reaching it means the command crossed the mailbox, ran the dispatch arm, and got as far as
    // resolving the obligation's processing state before refusing. That is the whole wire.
    assert!(
        refusal_text_chirho.contains("NotProviderObservedChirho"),
        "the refusal must name the completed leg's provider-observation barrier, so a green arm \
         cannot come from an unrelated refusal.\nrefusal: {refusal_text_chirho}"
    );

    // A Provider/Unavailable refusal is the shape the WIRE ITSELF produces when the command never
    // lands (closed actor, full mailbox, dropped reply). Excluding it is what proves the hop
    // actually happened and the resident is what refused.
    assert!(
        !refusal_text_chirho.contains("UnavailableChirho"),
        "an Unavailable refusal means the command never crossed the mailbox — the wire, not the \
         obligation check, is what refused.\nrefusal: {refusal_text_chirho}"
    );

    let cut_after_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .unwrap_or_else(|error_chirho| {
            panic!(
            "the actor must keep serving after the wire command refuses; if this fails the refusal \
             above came from a DEAD actor, not from the completed leg.\nrefusal was: \
             {refusal_text_chirho}\nserving error: {error_chirho:?}"
        )
        });
    assert_eq!(
        cut_after_chirho.tail_seq_chirho, cut_chirho.tail_seq_chirho,
        "a refused completion must not move the journal tail"
    );

    drop(actor_chirho);
}
