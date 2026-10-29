// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Executable arms for `verify_post_cut_extension_class_and_anchor_chirho` — the winner's
//! restore-time walk over everything appended after a handoff's source cut.
//!
//! # WHAT THESE ARMS PIN, AND EXACTLY WHAT THEY DO NOT
//!
//! The subject verifies TWO things and no more: every post-cut record is compensation-CLASS, and
//! the traversal REACHED the cut anchor. These arms pin those two and nothing else.
//!
//! ANCHOR IDENTITY *is* pinned, and it is easy to confuse with the thing below that is not. A
//! forged anchor — real sequence, wrong digest — is refused, and BOTH reader paths are covered:
//! `AnchorDigestMismatchAtFrozenTailChirho` when the anchor is the live tail, and
//! `AnchorDigestMismatchChirho` when it is reached mid-traversal. One English sentence, two code
//! paths, two arms; there is no uncovered digest-mismatch branch.
//!
//! That is about the ANCHOR the caller supplies. It says nothing about the RECORDS the walk reads,
//! which is the next paragraph and a different property entirely.
//!
//! They do NOT pin that a record's idempotency key is a genuinely derived compensation coordinate.
//! That check is designed and privacy-gated, not built, and is recorded as a residual at the
//! subject's own definition. A fabricated compensation-lineage key passes the walk today and
//! therefore passes these arms — read a green here as class-plus-anchor coverage, never as
//! coordinate validity, and never as any statement about WHICH reconciliation a record belongs to
//! (that one is fork-impossible at this seam, also recorded at the definition).
//!
//! # WHAT TIER THESE ARMS RUN AT — they call the traversal, not its caller
//!
//! Every arm invokes `verify_post_cut_extension_class_and_anchor_chirho` DIRECTLY on a resident.
//! None goes through `verify_historical_readiness_chirho`, the production caller in
//! `winner_handoff_chirho`. So they prove the walk and prove NOTHING about the handoff dispatch,
//! the readiness snapshot that supplies the anchor, or the refusal mapping at that call site.
//!
//! One consequence is specific enough to be worth naming, because it is easy to over-read. The
//! production caller short-circuits: it compares EPOCH, seq, and digest against the source cut, and
//! when the tail is exactly the cut it never calls the traversal at all. The traversal's anchor is
//! only (seq, digest) — no epoch. So the empty-extension arm below pins the WALK's own behavior
//! when handed an anchor equal to its tail; it does not exercise production's no-drift path, which
//! is the short-circuit branch and is somebody else's arm. Read it as defensive coverage of the
//! walk, not as coverage of the no-drift case.
//!
//! # WHY THE LIVENESS ARM USES AN AGED FIXTURE
//!
//! Seven candidate designs died before this walk was built, and every one of them died in the
//! LIVENESS direction — each would have refused records that ought to be admitted, because each
//! derived admissibility from a membership set (a reconciliation's obligations, the effect-receipt
//! window, the active-hold set) rather than from the records themselves. **Every one of the seven
//! would have passed a fresh-fixture liveness arm**, where the verifying object is the same warm
//! object that just did the appending and every such set is still populated.
//!
//! So `compensation_class_extension_reaches_the_anchor_on_an_aged_fixture_chirho` appends with one
//! resident, DROPS it together with its elector, and verifies with a second resident opened from
//! disk.
//!
//! **The aging is realized BY CONSTRUCTION, not by an assertion**: the writing resident and its
//! elector live in an inner scope and are gone before the verifying resident exists, which the
//! compiler enforces and a comment could not. The two assertions in
//! `verify_on_an_aged_resident_chirho` do NOT establish aging; they pin the two things that could
//! silently make this arm meaningless — that the verifying resident's view is the committed
//! extension BY VALUE, and that no live reconciliation state exists at verification time.
//!
//! **WHICH MEMBERSHIP FAMILIES THIS FIXTURE ACTUALLY DEFEATS, stated exactly, because the honest
//! answer is "some of them".** A design deriving admissibility from a RECONCILIATION'S OBLIGATION
//! set would refuse here: no obligation state is ever created in this fixture and the group holds
//! no active reconciliation state, both checked. A design deriving it from the journal's
//! EFFECT-RECEIPT WINDOW would NOT be caught by this fixture: replay rebuilds that window on open.
//! That is MEASURED, not read off a comment — 2026-08-08, a temporary probe compared
//! `verified_effect_receipt_inventory_chirho` on the warm writing resident and on the aged
//! verifying resident and got the same two compensation sequences both times. Re-measure the same
//! way if it matters; do not re-derive it from the source. Aging that window needs bounded
//! retention plus resolved holds plus clock advance, which this arm deliberately does not build.
//! Do not read this green as coverage of the receipt-window family.
//!
//! MIGRATION PATH, because whoever meets a red here will not have this context:
//! - If the wrong-class arm starts RETURNING `Ok`, the class gate is gone — that is the defect
//!   this arm exists to catch, not a fixture problem.
//! - If it refuses with a DIFFERENT reason (traversal termination, a page bound, a classifier
//!   error), the fixture stopped reaching the class gate; repair the fixture, do not relax the
//!   assertion, because a refusal from another mechanism proves nothing about the class gate.
//! - If the aged liveness arm starts REFUSING, do not "fix" it by warming the fixture. A refusal
//!   here means the walk acquired a dependency on live in-process state, which is the exact failure
//!   mode the seven dead candidates shared.
//! - If the empty-extension arm fails on its ZERO, the reader started returning records for a range
//!   with no records in it; if it fails on its CONTROL (the two-record count), the reader stopped
//!   returning records it should. Those are opposite defects and the two assertions exist to tell
//!   them apart — read WHICH one went red before forming a theory. If instead it fails only at the
//!   final `Ok`, look at the anchor==frozen-tail short-circuit in the losing-suffix reader, which is
//!   the one branch this arm reaches and the other two do not.

use super::super::provision_signers_chirho;
use super::{
    resident_mint_request_chirho, warm_single_node_elector_chirho,
    with_unbound_resident_fixture_chirho,
};
use crate::reconciliation_chirho::gd7_reconciliation_group_has_any_active_hold_chirho;
use crate::{
    FsLedgerStorageChirho, HostLedgerSignersChirho, ResidentLedgerAppendPermitChirho,
    ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerAuthorityRefusalChirho, ResidentLedgerBirthPermitChirho,
    ResidentLedgerLocalPortsChirho,
};
use cairn_effect_commit_chirho::compensation_chirho::{
    authorize_effect_compensation_chirho, CompensationAuthorizationFactsChirho,
    CompensationAuthorizationViewChirho, CompensationAuthorizationViewErrorChirho,
    CompensationBreakerVerdictChirho, EffectCompensationAuthorizationOutcomeChirho,
    VerifiedEffectCompensationChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    EffectIntentSignerPortChirho, VerifiedEffectIntentChirho, EFFECT_INTENT_KEY_PREFIX_CHIRHO,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_kind_registry_chirho::chain_chirho::VerifiedRegistryChirho;
use cairn_kind_registry_chirho::record_chirho::IdempotencyWindowPolicyChirho;
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixCoordinateChirho, LosingSuffixJournalIdentityChirho, LosingSuffixPageRequestChirho,
    MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO, MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};

fn digest_chirho(seed_chirho: &str) -> DigestChirho {
    DigestChirho(seed_chirho.repeat(32))
}

/// A distinct original effect K per compensation. One compensation coordinate exists per original
/// K, so two extension records REQUIRE two originals — reusing one returns the first receipt and
/// appends nothing, which would silently shrink the extension this walk is supposed to traverse.
fn original_effect_key_chirho(seed_chirho: &str) -> String {
    format!(
        "{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}",
        seed_chirho.repeat(32)
    )
}

/// Permits every candidate, so nothing in the AUTHORIZATION layer can refuse the appends that build
/// these fixtures. A fixture whose records could be refused before they reach the journal would
/// leave the traversal with nothing to classify.
struct PermittingCompensationViewChirho {
    original_effect_key_chirho: String,
}

impl CompensationAuthorizationViewChirho for PermittingCompensationViewChirho {
    fn derive_chirho(
        &self,
        candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        if candidate_chirho
            .intent_chirho()
            .original_effect_key_chirho
            .as_deref()
            != Some(self.original_effect_key_chirho.as_str())
        {
            return Err(CompensationAuthorizationViewErrorChirho::RefusedChirho {
                detail_chirho: "candidate names a different original effect K".to_owned(),
            });
        }
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            self.original_effect_key_chirho.clone(),
            self.original_effect_key_chirho.clone(),
            1,
            4,
            CompensationBreakerVerdictChirho::PermittedChirho,
        ))
    }
}

/// A CF3-compliant registry, built locally rather than by editing the shared fixture.
///
/// The shared test registry leaves `idempotency_window_chirho` at `None`, which the journal reads
/// as RetainIndefinitely and refuses for any CF3 effect intent — so no compensation append can
/// complete anywhere in that fixture family. This declares a kind that HAS a bounded window, which
/// is what a real CF3 kind carries; it is not inventing a finite default for an absent policy. Same
/// move, same reason, as `strand_fence_liveness_tests_chirho`'s full-chain arm.
fn cf3_bounded_registry_chirho(base_chirho: &VerifiedRegistryChirho) -> VerifiedRegistryChirho {
    let mut kinds_chirho = base_chirho.kinds_chirho.clone();
    for projection_chirho in kinds_chirho.values_mut() {
        projection_chirho
            .current_policy_chirho
            .idempotency_window_chirho = Some(IdempotencyWindowPolicyChirho {
            idempotency_horizon_ms_chirho: 3_600_000,
            retry_finality_horizon_ms_chirho: 7_200_000,
        });
    }
    VerifiedRegistryChirho {
        records_chirho: Vec::new(),
        tail_digest_chirho: base_chirho.tail_digest_chirho.clone(),
        kinds_chirho,
    }
}

fn open_read_only_journal_chirho<'ports_chirho>(
    ports_chirho: &ResidentLedgerLocalPortsChirho<'ports_chirho>,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
) -> LedgerJournalChirho<'ports_chirho> {
    LedgerJournalChirho::open_read_only_chirho(
        JournalPortsChirho {
            storage_chirho: ports_chirho.storage_chirho,
            signer_chirho: ports_chirho.signer_chirho,
            clock_chirho: ports_chirho.clock_chirho,
            membership_chirho: ports_chirho.membership_chirho,
            kind_registry_chirho: ports_chirho.kind_registry_chirho,
            authority_chirho: ports_chirho.authority_chirho,
        },
        journal_path_chirho.clone(),
        cluster_id_chirho,
    )
    .expect("the fixture journal opens read-only for its current effect-intent cut")
}

/// Sign a compensation intent against the journal's CURRENT verified cut.
///
/// The cut is re-read per record on purpose: every append moves it, and an intent carrying a stale
/// cut is refused by the journal before it can become an extension record.
fn signed_compensation_intent_line_chirho(
    journal_chirho: &LedgerJournalChirho<'_>,
    signer_chirho: &dyn EffectIntentSignerPortChirho,
    original_effect_key_chirho: &str,
    request_seed_chirho: &str,
) -> String {
    let intent_chirho = EffectIntentChirho {
        schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        journal_cut_chirho: journal_chirho.effect_intent_cut_chirho(),
        contract_set_digest_chirho: digest_chirho("a1"),
        door_chirho: serde_json::from_value(serde_json::json!({
            "effect_node_chirho": "b2".repeat(32),
            "capability_fingerprint_chirho": "c3".repeat(32),
        }))
        .unwrap(),
        reversion_contract_digest_chirho: digest_chirho("d4"),
        request_ref_chirho: digest_chirho(request_seed_chirho),
        request_context_ref_chirho: digest_chirho("f6"),
        evidence_refs_chirho: vec![digest_chirho("a1")],
        resolved_price_chirho: AssetOpChirho {
            amount_chirho: 10,
            kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
            kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho("11")),
            rounding_chirho: RoundingChirho::ExactChirho,
        },
        payer_account_chirho: AccountIdChirho {
            owner_chirho: "resident-authority-user-chirho".to_owned(),
            kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
        },
        effect_step_chirho: 7,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "resident-authority-user-chirho".to_owned(),
        },
        original_effect_key_chirho: Some(original_effect_key_chirho.to_owned()),
        sig_chirho: String::new(),
        key_id_chirho: String::new(),
    };
    let signed_chirho = sign_effect_intent_chirho(intent_chirho, signer_chirho).unwrap();
    canonical_effect_intent_line_chirho(&signed_chirho).unwrap()
}

fn authorized_compensation_chirho(
    line_chirho: &str,
    signer_chirho: &dyn EffectIntentSignerPortChirho,
    original_effect_key_chirho: &str,
) -> VerifiedEffectCompensationChirho {
    let view_chirho = PermittingCompensationViewChirho {
        original_effect_key_chirho: original_effect_key_chirho.to_owned(),
    };
    match authorize_effect_compensation_chirho(line_chirho, signer_chirho, &view_chirho).unwrap() {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(token_chirho) => {
            token_chirho
        }
        EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(pending_chirho) => {
            panic!("the permitting view must authorize: {pending_chirho:?}")
        }
    }
}

/// Append one REAL compensation-class hold through the resident's own production door.
///
/// Nothing here is hand-forged: the record is minted by `record_effect_compensation_hold_chirho`
/// from a signed intent and an authorization token that binds it, so what the traversal later
/// classifies is a record the journal actually admitted.
fn append_real_compensation_hold_chirho(
    resident_chirho: &mut ResidentLedgerAuthorityChirho<'_>,
    ports_chirho: &ResidentLedgerLocalPortsChirho<'_>,
    signers_chirho: &HostLedgerSignersChirho,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    original_seed_chirho: &str,
    request_seed_chirho: &str,
) -> ResidentLedgerAppendReceiptChirho {
    let original_effect_key_chirho = original_effect_key_chirho(original_seed_chirho);
    let line_chirho = {
        let journal_chirho =
            open_read_only_journal_chirho(ports_chirho, journal_path_chirho, cluster_id_chirho);
        signed_compensation_intent_line_chirho(
            &journal_chirho,
            &signers_chirho.effect_intent_chirho,
            &original_effect_key_chirho,
            request_seed_chirho,
        )
    };
    let token_chirho = authorized_compensation_chirho(
        &line_chirho,
        &signers_chirho.effect_intent_chirho,
        &original_effect_key_chirho,
    );
    resident_chirho
        .record_effect_compensation_hold_chirho(
            &line_chirho,
            &signers_chirho.effect_intent_chirho,
            &token_chirho,
        )
        .expect("the compensation hold must commit; the extension needs a real admitted record")
}

/// The committed coordinate of the record a receipt describes, cross-checked against the journal's
/// own verified tail.
///
/// Two independent instruments for one coordinate: the receipt the append returned, and the tail
/// accessor the traversal itself uses to find its starting point. If they ever disagree, the anchor
/// handed to the walk is not the coordinate the walk compares against, and every result below would
/// be about the wrong record.
fn anchor_from_receipt_chirho(
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
    ports_chirho: &ResidentLedgerLocalPortsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
) -> (u64, String) {
    let journal_chirho =
        open_read_only_journal_chirho(ports_chirho, journal_path_chirho, cluster_id_chirho);
    let tail_chirho = journal_chirho.verified_losing_tail_chirho();
    assert_eq!(
        tail_chirho.coordinate_chirho().seq_chirho(),
        receipt_chirho.append_chirho.seq_chirho,
        "the anchor receipt must describe the journal's current committed tail",
    );
    assert_eq!(
        tail_chirho.coordinate_chirho().record_digest_chirho(),
        &receipt_chirho.append_chirho.record_digest_chirho,
        "receipt digest and verified-tail digest must name one record, or the anchor is fiction",
    );
    (
        receipt_chirho.append_chirho.seq_chirho,
        receipt_chirho.append_chirho.record_digest_chirho.0.clone(),
    )
}

/// What the walk's own reader returns for one anchor: `(records in the page, reached the anchor)`.
///
/// This asks the SAME question the traversal asks — same journal identity, same start (the verified
/// losing tail), same anchor — so a count here is a count of the records the traversal would have
/// classified. The page-size arguments are the reader's public maxima rather than the traversal's
/// private ones; that substitution cannot change either value being asserted, because an empty
/// range returns zero records at any page size and a two-record range fits in every size on offer.
fn page_records_and_anchor_reach_chirho(
    ports_chirho: &ResidentLedgerLocalPortsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    anchor_chirho: &(u64, String),
) -> (usize, bool) {
    let journal_chirho =
        open_read_only_journal_chirho(ports_chirho, journal_path_chirho, cluster_id_chirho);
    let tail_chirho = journal_chirho.verified_losing_tail_chirho();
    let request_chirho = LosingSuffixPageRequestChirho::new_chirho(
        LosingSuffixJournalIdentityChirho::new_chirho(
            journal_chirho.genesis_digest_chirho().clone(),
        ),
        tail_chirho.coordinate_chirho().clone(),
        LosingSuffixCoordinateChirho::new_chirho(
            anchor_chirho.0,
            DigestChirho(anchor_chirho.1.clone()),
        ),
        MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    );
    let page_chirho = journal_chirho
        .read_verified_losing_suffix_page_chirho(&request_chirho)
        .expect("the fixture's own suffix page reads");
    (
        page_chirho.records_newest_first_chirho().len(),
        page_chirho.reached_anchor_chirho(),
    )
}

/// Open a second resident from disk and run the walk on it.
///
/// AGING IS THE CALLER'S CONSTRUCTION, NOT THIS FUNCTION'S ASSERTION: callers drop the writing
/// resident and its elector in an inner scope before calling, so the object verifying here shares
/// nothing with the object that appended. What this function checks is narrower and worth being
/// exact about — that the verifying resident's replayed view is the committed extension BY VALUE,
/// and that the group holds no active reconciliation state that could serve as a membership set.
/// Neither check would fail on a fresh fixture, so neither is evidence OF aging; they exist so that
/// a fixture which silently drifted cannot pass as one that did not.
/// A WELL-FORMED digest that is not this one.
///
/// The substitution changes only the VALUE, never the shape: still 64 lowercase hex, so the only
/// thing the reader can object to is that it does not match the record at that sequence. A
/// malformed digest would refuse for a different reason and the arm would be green while proving
/// something else — the same trap as a tamper fixture that violates the wrong property.
fn substituted_digest_chirho(digest_chirho: &str) -> String {
    assert_eq!(
        digest_chirho.len(),
        64,
        "the fixture's anchor digest must be a 64-hex digest before substitution: {digest_chirho}"
    );
    let first_chirho = if digest_chirho.starts_with('0') {
        '1'
    } else {
        '0'
    };
    let substituted_chirho = format!("{first_chirho}{}", &digest_chirho[1..]);
    assert_ne!(
        substituted_chirho, digest_chirho,
        "the substitution must actually change the digest, or the arm asserts nothing"
    );
    substituted_chirho
}

/// Build the fixture both digest-substitution arms share: fund, then two real compensation holds.
///
/// Hands back BOTH anchors, because the two arms differ only in which one they forge — the funding
/// record (reached mid-traversal) and the last compensation (which IS the live tail). Those two
/// positions take DIFFERENT code paths in the reader, which is the entire reason there are two arms.
fn with_two_compensation_extension_chirho(
    label_chirho: &str,
    action_chirho: impl FnOnce(
        &std::path::Path,
        &ConsistencyGroupIdChirho,
        &cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho,
        ResidentLedgerLocalPortsChirho<'_>,
        &StoragePathChirho,
        &ClusterIdChirho,
        (u64, String),
        (u64, String),
    ),
) {
    with_unbound_resident_fixture_chirho(
        label_chirho,
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let cf3_registry_chirho =
                cf3_bounded_registry_chirho(ports_chirho.kind_registry_chirho);
            let ports_chirho = ResidentLedgerLocalPortsChirho {
                kind_registry_chirho: &cf3_registry_chirho,
                ..ports_chirho
            };
            let refs_chirho = provision_signers_chirho(root_chirho);
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &refs_chirho).unwrap();

            let funding_anchor_chirho;
            let tail_anchor_chirho;
            {
                let writing_elector_chirho =
                    warm_single_node_elector_chirho(local_node_chirho, group_chirho);
                drop(
                    ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                        ResidentLedgerBirthPermitChirho::for_test_chirho(
                            root_chirho,
                            journal_path_chirho.clone(),
                            cluster_id_chirho.clone(),
                            0,
                        ),
                        ports_chirho,
                        writing_elector_chirho.local_append_authority_handle_chirho(),
                    )
                    .expect("bound resident is born"),
                );
                let mut writing_resident_chirho =
                    ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                        root_chirho,
                        ports_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                        writing_elector_chirho.local_append_authority_handle_chirho(),
                    )
                    .expect("bound resident opens at its birth term");

                let funding_receipt_chirho = writing_resident_chirho
                    .append_preactivation_chirho(
                        &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                        resident_mint_request_chirho(900, "post-cut-substitution-funding-chirho"),
                    )
                    .expect("fund the compensation payer");
                funding_anchor_chirho = anchor_from_receipt_chirho(
                    &funding_receipt_chirho,
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                );
                append_real_compensation_hold_chirho(
                    &mut writing_resident_chirho,
                    &ports_chirho,
                    &signers_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    "3c",
                    "e5",
                );
                let last_chirho = append_real_compensation_hold_chirho(
                    &mut writing_resident_chirho,
                    &ports_chirho,
                    &signers_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    "4d",
                    "e6",
                );
                tail_anchor_chirho = anchor_from_receipt_chirho(
                    &last_chirho,
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                );
                assert_eq!(
                    tail_anchor_chirho.0,
                    funding_anchor_chirho.0 + 2,
                    "the two anchors must sit two records apart, or the arms are not testing the \
                     two positions they claim to"
                );
            }

            action_chirho(
                root_chirho,
                group_chirho,
                local_node_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                funding_anchor_chirho,
                tail_anchor_chirho,
            );
        },
    );
}

/// Assert a substituted-anchor refusal names the variant it should, and NOT the other three.
///
/// The negatives matter as much as the positive here: a class refusal or a termination refusal
/// would make the arm green while proving nothing about anchor identity, and naming the OTHER
/// mismatch variant would mean the fixture hit the wrong code path — which is exactly the
/// distinction these two arms exist to keep separate.
fn assert_anchor_digest_refusal_chirho(
    refusal_chirho: &ResidentLedgerAuthorityRefusalChirho,
    expected_variant_chirho: &str,
    forbidden_variant_chirho: &str,
) {
    let ResidentLedgerAuthorityRefusalChirho::Gd7PostCutExtensionRefusedChirho { detail_chirho } =
        refusal_chirho
    else {
        panic!(
            "expected Gd7PostCutExtensionRefusedChirho, got {refusal_chirho:?}; a refusal from \
             another mechanism says nothing about anchor identity"
        );
    };
    assert!(
        detail_chirho.contains(expected_variant_chirho),
        "the refusal must name {expected_variant_chirho}, got: {detail_chirho}"
    );
    assert!(
        !detail_chirho.contains(forbidden_variant_chirho),
        "this fixture must reach the {expected_variant_chirho} path, not {forbidden_variant_chirho} \
         — a swap here means the arm is testing the other position, got: {detail_chirho}"
    );
    assert!(
        !detail_chirho.contains("not a compensation hold"),
        "a CLASS refusal here would make this arm green while proving nothing about the anchor, \
         got: {detail_chirho}"
    );
    assert!(
        !detail_chirho.contains("before reaching the cut anchor")
            && !detail_chirho.contains("exceeded its page bound"),
        "this must be an anchor-identity refusal, not a traversal-termination one, got: \
         {detail_chirho}"
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixture verifies one complete aged-resident authority coordinate"
)]
fn verify_on_an_aged_resident_chirho(
    root_chirho: &std::path::Path,
    group_chirho: &ConsistencyGroupIdChirho,
    ports_chirho: ResidentLedgerLocalPortsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    local_node_chirho: &cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho,
    expected_tail_seq_chirho: u64,
    anchor_chirho: (u64, String),
) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(root_chirho).expect("open the resident root");
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &storage_chirho,
            &consistency_group_digest_chirho(group_chirho).unwrap(),
        )
        .expect("probe the reconciliation hold"),
        "the aged fixture must hold NO active reconciliation state: a walk that only passes while \
         a live obligation/hold set names these records is one of the seven designs that died",
    );

    // A SECOND elector instance as well as a second resident: the handle that authorized the
    // appends is gone with its elector, so nothing warm from the writing life is reachable here.
    let verifying_elector_chirho = warm_single_node_elector_chirho(local_node_chirho, group_chirho);
    let verifying_resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
        root_chirho,
        ports_chirho,
        journal_path_chirho.clone(),
        cluster_id_chirho.clone(),
        0,
        verifying_elector_chirho.local_append_authority_handle_chirho(),
    )
    .expect("a fresh resident opens the committed journal from disk");

    assert_eq!(
        verifying_resident_chirho
            .probe_chirho()
            .expect("the aged resident probes")
            .journal_tail_seq_chirho,
        expected_tail_seq_chirho,
        "the aged resident's tail must come from REPLAY of the committed extension, by value; a \
         mismatch means this arm is verifying a different journal state than it built",
    );

    verifying_resident_chirho
        .verify_post_cut_extension_class_and_anchor_chirho(anchor_chirho.0, &anchor_chirho.1)
}

#[test]
fn wrong_class_record_in_the_post_cut_extension_refuses_by_class_chirho() {
    with_unbound_resident_fixture_chirho(
        "post-cut-extension-wrong-class",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let cf3_registry_chirho =
                cf3_bounded_registry_chirho(ports_chirho.kind_registry_chirho);
            let ports_chirho = ResidentLedgerLocalPortsChirho {
                kind_registry_chirho: &cf3_registry_chirho,
                ..ports_chirho
            };
            let refs_chirho = provision_signers_chirho(root_chirho);
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &refs_chirho).unwrap();

            let anchor_chirho;
            let extension_tail_seq_chirho;
            {
                let writing_elector_chirho =
                    warm_single_node_elector_chirho(local_node_chirho, group_chirho);
                drop(
                    ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                        ResidentLedgerBirthPermitChirho::for_test_chirho(
                            root_chirho,
                            journal_path_chirho.clone(),
                            cluster_id_chirho.clone(),
                            0,
                        ),
                        ports_chirho,
                        writing_elector_chirho.local_append_authority_handle_chirho(),
                    )
                    .expect("bound resident is born"),
                );
                let mut writing_resident_chirho =
                    ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                        root_chirho,
                        ports_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                        writing_elector_chirho.local_append_authority_handle_chirho(),
                    )
                    .expect("bound resident opens at its birth term");

                // THE ANCHOR: the funding mint. Everything after it is the post-cut extension.
                let anchor_receipt_chirho = writing_resident_chirho
                    .append_preactivation_chirho(
                        &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                        // 900 of the kind's 1_000 supply cap, leaving headroom for the ordinary
                        // record below. The two arms are funded identically so they differ ONLY in
                        // what the extension contains.
                        resident_mint_request_chirho(900, "post-cut-wrong-class-funding-chirho"),
                    )
                    .expect("fund the compensation payer");
                anchor_chirho = anchor_from_receipt_chirho(
                    &anchor_receipt_chirho,
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                );

                // A REAL compensation first, so the refusal below cannot be explained by a fixture
                // that is simply unable to produce any admissible extension record.
                append_real_compensation_hold_chirho(
                    &mut writing_resident_chirho,
                    &ports_chirho,
                    &signers_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    "3c",
                    "e5",
                );

                // THE WRONG-CLASS RECORD, newest in the extension: an ordinary ledger mint.
                let wrong_class_receipt_chirho = writing_resident_chirho
                    .append_preactivation_chirho(
                        &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                        resident_mint_request_chirho(1, "post-cut-wrong-class-intruder-chirho"),
                    )
                    .expect("append the ordinary record the walk must refuse");
                extension_tail_seq_chirho = wrong_class_receipt_chirho.append_chirho.seq_chirho;
                assert!(
                    extension_tail_seq_chirho > anchor_chirho.0,
                    "the extension must be non-empty, or the walk would reach the anchor without \
                     ever classifying a record",
                );
            }

            let refusal_chirho = verify_on_an_aged_resident_chirho(
                root_chirho,
                group_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
                extension_tail_seq_chirho,
                anchor_chirho,
            )
            .expect_err("a non-compensation record in the post-cut extension must refuse");

            // ASSERT THE REASON, not merely the refusal — and assert the negative, so a refusal
            // arriving from any other mechanism fails this arm instead of passing it.
            let ResidentLedgerAuthorityRefusalChirho::Gd7PostCutExtensionRefusedChirho {
                detail_chirho,
            } = &refusal_chirho
            else {
                panic!(
                    "expected Gd7PostCutExtensionRefusedChirho, got {refusal_chirho:?}; a refusal \
                     from another mechanism says nothing about the class gate"
                );
            };
            assert!(
                detail_chirho.contains("post-cut record is not a compensation hold"),
                "the refusal must name the CLASS gate, got: {detail_chirho}"
            );
            assert!(
                detail_chirho.contains("LedgerOnlyChirho"),
                "the refusal must name the class it actually saw, got: {detail_chirho}"
            );
            assert!(
                !detail_chirho.contains("before reaching the cut anchor")
                    && !detail_chirho.contains("exceeded its page bound"),
                "this must be the class refusal, not a traversal-termination refusal, got: \
                 {detail_chirho}"
            );
        },
    );
}

#[test]
fn compensation_class_extension_reaches_the_anchor_on_an_aged_fixture_chirho() {
    with_unbound_resident_fixture_chirho(
        "post-cut-extension-aged-liveness",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let cf3_registry_chirho =
                cf3_bounded_registry_chirho(ports_chirho.kind_registry_chirho);
            let ports_chirho = ResidentLedgerLocalPortsChirho {
                kind_registry_chirho: &cf3_registry_chirho,
                ..ports_chirho
            };
            let refs_chirho = provision_signers_chirho(root_chirho);
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &refs_chirho).unwrap();

            let anchor_chirho;
            let extension_tail_seq_chirho;
            {
                let writing_elector_chirho =
                    warm_single_node_elector_chirho(local_node_chirho, group_chirho);
                drop(
                    ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                        ResidentLedgerBirthPermitChirho::for_test_chirho(
                            root_chirho,
                            journal_path_chirho.clone(),
                            cluster_id_chirho.clone(),
                            0,
                        ),
                        ports_chirho,
                        writing_elector_chirho.local_append_authority_handle_chirho(),
                    )
                    .expect("bound resident is born"),
                );
                let mut writing_resident_chirho =
                    ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                        root_chirho,
                        ports_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                        writing_elector_chirho.local_append_authority_handle_chirho(),
                    )
                    .expect("bound resident opens at its birth term");

                let anchor_receipt_chirho = writing_resident_chirho
                    .append_preactivation_chirho(
                        &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                        // Identical funding to the wrong-class arm: the two fixtures differ ONLY in
                        // the class of what follows the anchor.
                        resident_mint_request_chirho(900, "post-cut-aged-funding-chirho"),
                    )
                    .expect("fund the compensation payer");
                anchor_chirho = anchor_from_receipt_chirho(
                    &anchor_receipt_chirho,
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                );

                // TWO records, not one. A one-record extension cannot distinguish "classified every
                // record" from "classified the first and stopped", and two distinct original Ks are
                // required because the coordinate is one-per-original-K.
                let first_chirho = append_real_compensation_hold_chirho(
                    &mut writing_resident_chirho,
                    &ports_chirho,
                    &signers_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    "3c",
                    "e5",
                );
                let second_chirho = append_real_compensation_hold_chirho(
                    &mut writing_resident_chirho,
                    &ports_chirho,
                    &signers_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    "4d",
                    "e6",
                );
                assert_eq!(
                    second_chirho.append_chirho.seq_chirho,
                    first_chirho.append_chirho.seq_chirho + 1,
                    "both compensations must have committed as SEPARATE records; an idempotent \
                     second append would silently leave a one-record extension",
                );
                extension_tail_seq_chirho = second_chirho.append_chirho.seq_chirho;
                assert_eq!(
                    extension_tail_seq_chirho,
                    anchor_chirho.0 + 2,
                    "the extension is exactly the two compensation records after the anchor",
                );
            }

            // THE Ok BELOW MUST NOT BE GREEN-BY-EMPTINESS. Asked of the walk's own reader with the
            // walk's own anchor, this range holds TWO records — so the success that follows is a
            // success that classified two, not a walk that read nothing and found nothing wrong.
            assert_eq!(
                page_records_and_anchor_reach_chirho(
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    &anchor_chirho,
                ),
                (2, true),
                "the extension the walk is about to classify must contain exactly two records and \
                 reach the anchor in one page",
            );

            verify_on_an_aged_resident_chirho(
                root_chirho,
                group_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
                extension_tail_seq_chirho,
                anchor_chirho,
            )
            .expect(
                "a compensation-class extension must REACH THE ANCHOR and return Ok on an aged \
                 fixture. If this refuses, the walk has acquired a dependency on live in-process \
                 state — do not warm the fixture to make it pass; that is the failure mode every \
                 one of the seven dead candidates shared",
            );
        },
    );
}

/// The NO-DRIFT case, and the boundary that separates it from its dangerous twin.
///
/// When the live tail already equals the cut anchor there is no extension, and the walk returns Ok
/// having classified nothing. That is correct — but "classified nothing because nothing is there"
/// and "read nothing while records existed" produce the SAME `Ok`, and the second is the
/// green-by-emptiness failure this suite's own header warns about. So the zero is asserted, and it
/// is asserted against a positive control on the same fixture, same reader, same journal: move the
/// anchor back to the funding record and the identical query returns TWO records. The zero is
/// therefore a property of where the anchor sits, not of a reader that cannot see anything.
#[test]
fn empty_post_cut_extension_reaches_the_anchor_having_classified_nothing_chirho() {
    with_unbound_resident_fixture_chirho(
        "post-cut-extension-empty",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let cf3_registry_chirho =
                cf3_bounded_registry_chirho(ports_chirho.kind_registry_chirho);
            let ports_chirho = ResidentLedgerLocalPortsChirho {
                kind_registry_chirho: &cf3_registry_chirho,
                ..ports_chirho
            };
            let refs_chirho = provision_signers_chirho(root_chirho);
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &refs_chirho).unwrap();

            let funding_anchor_chirho;
            let tail_anchor_chirho;
            {
                let writing_elector_chirho =
                    warm_single_node_elector_chirho(local_node_chirho, group_chirho);
                drop(
                    ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                        ResidentLedgerBirthPermitChirho::for_test_chirho(
                            root_chirho,
                            journal_path_chirho.clone(),
                            cluster_id_chirho.clone(),
                            0,
                        ),
                        ports_chirho,
                        writing_elector_chirho.local_append_authority_handle_chirho(),
                    )
                    .expect("bound resident is born"),
                );
                let mut writing_resident_chirho =
                    ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                        root_chirho,
                        ports_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                        writing_elector_chirho.local_append_authority_handle_chirho(),
                    )
                    .expect("bound resident opens at its birth term");

                let funding_receipt_chirho = writing_resident_chirho
                    .append_preactivation_chirho(
                        &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                        resident_mint_request_chirho(900, "post-cut-empty-funding-chirho"),
                    )
                    .expect("fund the compensation payer");
                funding_anchor_chirho = anchor_from_receipt_chirho(
                    &funding_receipt_chirho,
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                );

                // The journal is deliberately NOT empty: two real compensation records sit below
                // the anchor this arm uses. A fixture with an empty journal would make the zero
                // true for the wrong reason.
                append_real_compensation_hold_chirho(
                    &mut writing_resident_chirho,
                    &ports_chirho,
                    &signers_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    "3c",
                    "e5",
                );
                let last_chirho = append_real_compensation_hold_chirho(
                    &mut writing_resident_chirho,
                    &ports_chirho,
                    &signers_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    "4d",
                    "e6",
                );

                // THE ANCHOR IS THE LIVE TAIL. `anchor_from_receipt_chirho` re-reads the journal's
                // verified tail and asserts it equals this receipt, so "anchor == tail" is checked
                // rather than assumed.
                tail_anchor_chirho = anchor_from_receipt_chirho(
                    &last_chirho,
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                );
                assert_eq!(
                    tail_anchor_chirho.0,
                    funding_anchor_chirho.0 + 2,
                    "the two compensation records must exist below the anchor",
                );
            }

            assert_eq!(
                page_records_and_anchor_reach_chirho(
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    &tail_anchor_chirho,
                ),
                (0, true),
                "with the anchor AT the live tail the walk must reach the anchor having classified \
                 ZERO records",
            );

            // POSITIVE CONTROL for that zero: same fixture, same reader, anchor moved back.
            assert_eq!(
                page_records_and_anchor_reach_chirho(
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    &funding_anchor_chirho,
                ),
                (2, true),
                "the reader CAN surface records on this journal; a zero from the control would mean \
                 the empty-extension assertion above proves nothing",
            );

            verify_on_an_aged_resident_chirho(
                root_chirho,
                group_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
                tail_anchor_chirho.0,
                tail_anchor_chirho,
            )
            .expect("an empty post-cut extension is the no-drift case and must return Ok");
        },
    );
}

/// A FORGED ANCHOR AT THE LIVE TAIL IS REFUSED — right sequence, wrong digest.
///
/// PROVENANCE, because it changes how this arm should be read: the property was found and specified
/// by gpt as a review probe against the three arms above (#12170 / #12180 / #12187), and landed here
/// by the mover. The probe ran once in an isolated copy; an arm is what keeps it from being
/// proven-once and pinned-nowhere.
///
/// The anchor's SEQUENCE is real and only its digest is forged, so nothing upstream can refuse this
/// for being malformed — the walk must refuse it for not being the record that lives there. Reaching
/// the anchor is what ends the traversal successfully, so an anchor the walk cannot authenticate is
/// the difference between "I arrived" and "I arrived somewhere".
///
/// # MIGRATION PATH
/// - If this ADMITS, a caller can hand the walk any digest at a real sequence and be told the
///   extension checks out. That is the defect this arm exists to catch.
/// - If it refuses naming `AnchorDigestMismatchChirho` instead, the fixture stopped putting the
///   anchor at the live tail and is now exercising the sibling arm's path.
#[test]
fn forged_anchor_digest_at_the_live_tail_refuses_by_variant_chirho() {
    with_two_compensation_extension_chirho(
        "post-cut-forged-anchor-tail",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         _funding_anchor_chirho,
         tail_anchor_chirho| {
            let forged_chirho = (
                tail_anchor_chirho.0,
                substituted_digest_chirho(&tail_anchor_chirho.1),
            );
            let refusal_chirho = verify_on_an_aged_resident_chirho(
                root_chirho,
                group_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
                tail_anchor_chirho.0,
                forged_chirho,
            )
            .expect_err("a forged anchor digest at the live tail must refuse");
            assert_anchor_digest_refusal_chirho(
                &refusal_chirho,
                "AnchorDigestMismatchAtFrozenTailChirho",
                "AnchorDigestMismatchChirho",
            );
        },
    );
}

/// A FORGED ANCHOR REACHED MID-TRAVERSAL IS REFUSED — the sibling path, and it is a different one.
///
/// PROVENANCE: the branch fork was found by claude while sharpening gpt's probe spec (#12186); the
/// EXPANSION to cover it was ruled by the coordinator (#12189), so the widening is on the record
/// rather than silent. gpt's probe exercised the live-tail path only, and measured this one
/// UNPROVEN.
///
/// WHY THIS IS NOT A DUPLICATE, and it is the whole point: "substituted digest must refuse" is one
/// English sentence over TWO code paths. When the anchor IS the frozen tail the reader
/// short-circuits and refuses `AnchorDigestMismatchAtFrozenTailChirho`; when the anchor is reached
/// after reading records it refuses `AnchorDigestMismatchChirho`. An arm on one of them reads as
/// though it covered the property. Here the anchor is the funding record with two compensation
/// records above it, so the walk must actually traverse before it can discover the forgery.
///
/// # MIGRATION PATH
/// - If this ADMITS, a forged anchor survives a real traversal — strictly worse than the tail case,
///   because records were read and classified against a coordinate that does not exist.
/// - If it refuses naming `AnchorDigestMismatchAtFrozenTailChirho` instead, the fixture collapsed to
///   an empty extension and is now exercising the sibling arm's path.
#[test]
fn forged_anchor_digest_reached_mid_traversal_refuses_by_variant_chirho() {
    with_two_compensation_extension_chirho(
        "post-cut-forged-anchor-midwalk",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         funding_anchor_chirho,
         tail_anchor_chirho| {
            // The HONEST anchor at this position admits two records — asserted here so the refusal
            // below is known to be caused by the substitution and not by a fixture that could never
            // have traversed at all.
            assert_eq!(
                page_records_and_anchor_reach_chirho(
                    &ports_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    &funding_anchor_chirho,
                ),
                (2, true),
                "the honest anchor at this position must traverse two records and reach"
            );
            let forged_chirho = (
                funding_anchor_chirho.0,
                substituted_digest_chirho(&funding_anchor_chirho.1),
            );
            let refusal_chirho = verify_on_an_aged_resident_chirho(
                root_chirho,
                group_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
                tail_anchor_chirho.0,
                forged_chirho,
            )
            .expect_err("a forged anchor digest reached mid-traversal must refuse");
            assert_anchor_digest_refusal_chirho(
                &refusal_chirho,
                "AnchorDigestMismatchChirho",
                "AnchorDigestMismatchAtFrozenTailChirho",
            );
        },
    );
}
