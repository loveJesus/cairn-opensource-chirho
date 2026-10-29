// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::authority_chirho::{
    enumerate_gd7_sealed_plan_obligations_chirho,
    verify_gd7_sealed_plan_obligation_at_checkpoint_chirho,
};
use super::super::contract_chirho::{
    Gd7PlanPageFactCountsChirho, Gd7ReconciliationPlanPageChirho,
    GD7_RECONCILIATION_PLAN_PAGE_SCHEMA_V1_CHIRHO,
};
use super::super::reducer_chirho::reduce_record_inputs_chirho;
use super::super::tests_chirho::{
    digest_chirho, effect_proof_ports_chirho, forward_hold_record_chirho, identity_chirho,
    signed_intent_warrant_at_tail_chirho, signed_intent_warrant_chirho, temp_storage_chirho,
    FakeIntentSignerChirho, FakePlanSignerChirho, FakeTerminalSignerChirho,
    MemoryEffectEvidenceChirho, VerifierOnlyPlanVerifierChirho,
};
use super::*;
use crate::reconciliation_chirho::{
    gd7_losing_manifest_page_path_chirho, gd7_reconciliation_checkpoint_path_chirho,
    gd7_reconciliation_identity_digest_chirho, gd7_reconciliation_plan_page_path_chirho,
    load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho, Gd7EffectProofPortsChirho,
    Gd7LedgerRecordVerifierPortChirho, Gd7LosingManifestPageChirho,
    Gd7ReconciliationCheckpointChirho, Gd7ReconciliationCheckpointStateChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, GD7_LOSING_MANIFEST_PAGE_SCHEMA_V1_CHIRHO,
    GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho, LedgerRecordChirho,
    LegDeltaChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    stored_line_digest_chirho, LEDGER_FORMAT_VERSION_V1_CHIRHO, LEDGER_RECORD_SCHEMA_V1_CHIRHO,
};
use std::collections::BTreeMap;
use std::fs;

pub(super) struct FakeLosingRecordVerifierChirho {
    secret_chirho: [u8; 32],
}

impl FakeLosingRecordVerifierChirho {
    fn signature_chirho(&self, signed_content_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(signed_content_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }

    pub(super) fn sign_record_chirho(
        &self,
        mut record_chirho: LedgerRecordChirho,
    ) -> LedgerRecordChirho {
        record_chirho.key_id_chirho = self.key_id_chirho();
        record_chirho.sig_chirho.clear();
        let signed_content_chirho = ledger_record_signed_content_line_chirho(&record_chirho)
            .expect("fixture record has canonical signed content");
        record_chirho.sig_chirho = self.signature_chirho(&signed_content_chirho);
        record_chirho
    }
}

impl Gd7LedgerRecordVerifierPortChirho for FakeLosingRecordVerifierChirho {
    fn key_id_chirho(&self) -> String {
        "journal-chirho:gd7-obligation-mint-fixture-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

pub(super) struct ObligationMintFixtureChirho {
    pub(super) root_chirho: std::path::PathBuf,
    pub(super) storage_chirho: crate::FsLedgerStorageChirho,
    pub(super) held_signer_chirho: FakePlanSignerChirho,
    pub(super) intent_signer_chirho: FakeIntentSignerChirho,
    pub(super) terminal_signer_chirho: FakeTerminalSignerChirho,
    pub(super) losing_record_verifier_chirho: FakeLosingRecordVerifierChirho,
    pub(super) evidence_chirho: MemoryEffectEvidenceChirho,
    pub(super) identity_chirho: Gd7ReconciliationIdentityChirho,
    pub(super) identity_digest_chirho: String,
    pub(super) production_checkpoint_ref_chirho: String,
    pub(super) production_checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
    pub(super) production_plan_ref_chirho: String,
    pub(super) alternate_checkpoint_ref_chirho: String,
    pub(super) alternate_checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
    pub(super) alternate_obligation_plan_ref_chirho: String,
    /// A complete ONE-page chain whose cumulative obligation count is 0, under its own identity
    /// (a page-0 manifest's newest record must be the frozen tail, so the zero-obligation suffix
    /// cannot share the main identity's hold-then-ledger tail).
    pub(super) empty_checkpoint_ref_chirho: String,
    pub(super) empty_checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
    pub(super) empty_plan_ref_chirho: String,
    pub(super) empty_identity_digest_chirho: String,
    /// A two-page chain whose ONLY obligation is on the page the walk reaches SECOND.
    pub(super) subset_checkpoint_ref_chirho: String,
    pub(super) subset_checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
    pub(super) subset_plan_ref_chirho: String,
    pub(super) subset_identity_digest_chirho: String,
    pub(super) subset_evidence_chirho: MemoryEffectEvidenceChirho,
    pub(super) obligation_chirho: Gd7EffectPlanObligationChirho,
    pub(super) source_object_bytes_chirho: BTreeMap<String, Vec<u8>>,
}

impl Drop for ObligationMintFixtureChirho {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root_chirho).expect("remove obligation mint fixture root");
    }
}

#[test]
fn exact_sealed_plan_obligation_mints_once_and_retry_reports_awaiting_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("exact-once");
    let selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        fixture_chirho.production_plan_ref_chirho.clone(),
        0,
    )
    .expect("select the production plan obligation");
    let verified_chirho = fixture_chirho.verify_production_obligation_chirho(&selector_chirho);
    let minted_chirho = claim_verified_gd7_losing_effect_obligation_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &digest_chirho('e').0,
        &fixture_chirho.production_checkpoint_ref_chirho,
        &fixture_chirho.production_plan_ref_chirho,
        &fixture_chirho.identity_digest_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
        verified_chirho,
    )
    .expect("the exact adopted sealed-plan obligation mints once");
    assert_eq!(
        minted_chirho.obligation_chirho(),
        &fixture_chirho.obligation_chirho
    );
    assert_eq!(
        minted_chirho.historical_winner_term_chirho(),
        fixture_chirho.identity_chirho.winner_term_chirho
    );
    assert_eq!(
        minted_chirho.plan_checkpoint_ref_chirho(),
        fixture_chirho.production_checkpoint_ref_chirho
    );
    let receipt_path_chirho = gd7_losing_effect_obligation_mint_receipt_path_chirho(
        minted_chirho.mint_identity_digest_chirho(),
    )
    .expect("derive the semantic receipt path");
    let receipt_before_chirho = fixture_chirho
        .storage_chirho
        .read_all_chirho(&receipt_path_chirho)
        .expect("read minted receipt")
        .expect("minted receipt exists");
    let receipt_json_chirho: serde_json::Value =
        serde_json::from_slice(&receipt_before_chirho).expect("receipt is canonical JSON");
    assert_eq!(
        receipt_json_chirho["state_chirho"],
        "minted_awaiting_consumption_chirho"
    );
    assert!(receipt_json_chirho.get("obligation_chirho").is_none());
    assert!(receipt_json_chirho.get("intent_ref_chirho").is_none());

    let retry_verified_chirho =
        fixture_chirho.verify_production_obligation_chirho(&selector_chirho);
    let retry_refusal_chirho = expect_mint_refusal_chirho(
        claim_verified_gd7_losing_effect_obligation_chirho(
            &fixture_chirho.storage_chirho,
            &fixture_chirho.held_signer_chirho,
            &digest_chirho('e').0,
            &fixture_chirho.production_checkpoint_ref_chirho,
            &fixture_chirho.production_plan_ref_chirho,
            &fixture_chirho.identity_digest_chirho,
            fixture_chirho.identity_chirho.winner_term_chirho,
            retry_verified_chirho,
        ),
        "the same semantic obligation cannot mint a second runtime value",
    );
    assert_eq!(
        retry_refusal_chirho,
        Gd7LosingEffectObligationMintRefusalChirho::MintedAwaitingConsumptionChirho {
            receipt_ref_chirho: minted_chirho.receipt_ref_chirho().to_owned(),
        }
    );
    let rendered_chirho = retry_refusal_chirho.to_string();
    assert!(rendered_chirho.contains("awaiting verified item-5b consumption"));
    assert!(!rendered_chirho.contains("collided"));
    assert!(!rendered_chirho.contains("signature is invalid"));
    assert_eq!(
        fixture_chirho
            .storage_chirho
            .read_all_chirho(&receipt_path_chirho)
            .expect("re-read minted receipt")
            .expect("minted receipt remains"),
        receipt_before_chirho,
        "retry must not create or rewrite a second receipt"
    );
    fixture_chirho.assert_source_objects_unchanged_chirho();
}

#[test]
fn duplicated_semantic_obligation_at_a_second_verified_position_collides_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("duplicate-verified-position");
    let selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        fixture_chirho.production_plan_ref_chirho.clone(),
        0,
    )
    .expect("select the production plan obligation");
    let first_verified_chirho =
        fixture_chirho.verify_production_obligation_chirho(&selector_chirho);
    let mut duplicated_verified_chirho = first_verified_chirho.clone();
    duplicated_verified_chirho.plan_page_ref_chirho = digest_chirho('0').0;
    duplicated_verified_chirho.plan_page_index_chirho += 1;
    duplicated_verified_chirho.obligation_index_chirho += 1;
    assert_ne!(
        (
            duplicated_verified_chirho.plan_page_ref_chirho.as_str(),
            duplicated_verified_chirho.plan_page_index_chirho,
            duplicated_verified_chirho.obligation_index_chirho,
        ),
        (
            first_verified_chirho.plan_page_ref_chirho.as_str(),
            first_verified_chirho.plan_page_index_chirho,
            first_verified_chirho.obligation_index_chirho,
        ),
        "the hostile arm must move the real verifier output to a second trusted-boundary position"
    );
    assert_eq!(
        duplicated_verified_chirho.obligation_chirho, first_verified_chirho.obligation_chirho,
        "the hostile arm must duplicate semantic content rather than create another obligation"
    );
    let first_chirho = claim_verified_gd7_losing_effect_obligation_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &digest_chirho('e').0,
        &fixture_chirho.production_checkpoint_ref_chirho,
        &fixture_chirho.production_plan_ref_chirho,
        &fixture_chirho.identity_digest_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
        first_verified_chirho,
    )
    .expect("mint the real verifier's semantic obligation once");
    let receipt_path_chirho = gd7_losing_effect_obligation_mint_receipt_path_chirho(
        first_chirho.mint_identity_digest_chirho(),
    )
    .expect("derive the semantic receipt path");
    let receipt_before_chirho = fixture_chirho
        .storage_chirho
        .read_all_chirho(&receipt_path_chirho)
        .expect("read the first receipt")
        .expect("the first receipt exists");

    let duplicate_refusal_chirho = expect_mint_refusal_chirho(
        claim_verified_gd7_losing_effect_obligation_chirho(
            &fixture_chirho.storage_chirho,
            &fixture_chirho.held_signer_chirho,
            &digest_chirho('e').0,
            &fixture_chirho.production_checkpoint_ref_chirho,
            &fixture_chirho.production_plan_ref_chirho,
            &fixture_chirho.identity_digest_chirho,
            fixture_chirho.identity_chirho.winner_term_chirho,
            duplicated_verified_chirho,
        ),
        "a verifier duplication must collide at the existing semantic receipt path",
    );
    assert_eq!(
        duplicate_refusal_chirho,
        Gd7LosingEffectObligationMintRefusalChirho::MintReceiptCollisionChirho
    );
    let rendered_chirho = duplicate_refusal_chirho.to_string();
    assert!(rendered_chirho.contains("collided"));
    assert!(!rendered_chirho.contains("awaiting verified"));
    assert!(!rendered_chirho.contains("signature is invalid"));
    assert_eq!(
        fixture_chirho
            .storage_chirho
            .read_all_chirho(&receipt_path_chirho)
            .expect("re-read the semantic receipt path")
            .expect("the original receipt remains"),
        receipt_before_chirho,
        "a duplicated semantic obligation must not create or rewrite a second receipt"
    );
    fixture_chirho.assert_source_objects_unchanged_chirho();
}

#[test]
fn verifier_only_compile_witness_walks_complete_manifest_and_rejects_head_only_subset_chirho() {
    // The selected obligation lives on the newer page of a two-page chain. A
    // head-only traversal would inspect only the older head and falsely miss it.
    let fixture_chirho = obligation_mint_fixture_chirho("alternate-chain");
    let selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        fixture_chirho.alternate_obligation_plan_ref_chirho.clone(),
        0,
    )
    .expect("select the genuine alternate-chain obligation");
    let effect_ports_chirho = fixture_chirho.effect_ports_chirho();
    let verifier_only_chirho =
        VerifierOnlyPlanVerifierChirho::new_chirho(&fixture_chirho.held_signer_chirho);
    let enumerated_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &verifier_only_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
    )
    .expect("a verifier-only capability walks the complete two-page manifest chain");
    assert_eq!(enumerated_chirho.len(), 1);
    assert!(enumerated_chirho.iter().any(|obligation_chirho| {
        obligation_chirho.plan_page_ref_chirho()
            == fixture_chirho.alternate_obligation_plan_ref_chirho
    }));
    let alternate_verified_chirho = verify_gd7_sealed_plan_obligation_at_checkpoint_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.alternate_checkpoint_ref_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
        &selector_chirho,
    )
    .expect("the alternate page is genuine inside its own complete sealed chain");
    assert_eq!(
        alternate_verified_chirho.obligation_chirho,
        fixture_chirho.obligation_chirho
    );

    let refusal_chirho = verify_gd7_sealed_plan_obligation_at_checkpoint_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.production_checkpoint_ref_chirho,
        &fixture_chirho.production_checkpoint_chirho,
        &selector_chirho,
    )
    .expect_err("a genuine page outside the adopted chain must not mint an obligation");
    assert_eq!(
        refusal_chirho,
        Gd7PlanRefusalChirho::ObligationNotInSealedPlanChirho
    );
    let rendered_chirho = refusal_chirho.to_string();
    assert!(rendered_chirho.contains("not in the exact sealed plan"));
    assert!(!rendered_chirho.contains("object digest"));
    assert!(!rendered_chirho.contains("page shape"));
}

#[test]
fn every_semantic_binding_coordinate_is_independently_load_bearing_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("binding-coordinates");
    let selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        fixture_chirho.production_plan_ref_chirho.clone(),
        0,
    )
    .expect("select the production plan obligation");
    for mutation_chirho in ObligationBindingMutationChirho::ALL_CHIRHO {
        let verified_chirho = fixture_chirho.verify_production_obligation_chirho(&selector_chirho);
        let refusal_chirho = expect_mint_refusal_chirho(
            claim_verified_gd7_losing_effect_obligation_with_binding_transform_chirho(
                &fixture_chirho.storage_chirho,
                &fixture_chirho.held_signer_chirho,
                &digest_chirho('e').0,
                &fixture_chirho.production_checkpoint_ref_chirho,
                &fixture_chirho.production_plan_ref_chirho,
                &fixture_chirho.identity_digest_chirho,
                fixture_chirho.identity_chirho.winner_term_chirho,
                verified_chirho,
                |binding_chirho| mutation_chirho.apply_chirho(binding_chirho),
            ),
            "every changed semantic coordinate must refuse before receipt creation",
        );
        assert_eq!(
            refusal_chirho,
            Gd7LosingEffectObligationMintRefusalChirho::ObligationBindingMismatchChirho,
            "mutation {mutation_chirho:?} must own the exact binding refusal"
        );
    }
}

#[test]
fn validly_resigned_wrong_receipt_collides_while_signature_tamper_stays_distinct_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("receipt-boundary");
    let selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        fixture_chirho.production_plan_ref_chirho.clone(),
        0,
    )
    .expect("select the production plan obligation");
    let minted_chirho = claim_verified_gd7_losing_effect_obligation_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &digest_chirho('e').0,
        &fixture_chirho.production_checkpoint_ref_chirho,
        &fixture_chirho.production_plan_ref_chirho,
        &fixture_chirho.identity_digest_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
        fixture_chirho.verify_production_obligation_chirho(&selector_chirho),
    )
    .expect("mint the control receipt");
    let receipt_path_chirho = gd7_losing_effect_obligation_mint_receipt_path_chirho(
        minted_chirho.mint_identity_digest_chirho(),
    )
    .expect("derive the control receipt path");
    let original_bytes_chirho = fixture_chirho
        .storage_chirho
        .read_all_chirho(&receipt_path_chirho)
        .expect("read control receipt")
        .expect("control receipt exists");
    let mut signature_tamper_chirho: Gd7LosingEffectObligationMintReceiptChirho =
        serde_json::from_slice(&original_bytes_chirho).expect("parse control receipt");
    let replacement_chirho = if signature_tamper_chirho.sig_chirho.starts_with('z') {
        "y"
    } else {
        "z"
    };
    let signature_before_chirho = signature_tamper_chirho.sig_chirho.clone();
    signature_tamper_chirho
        .sig_chirho
        .replace_range(0..1, replacement_chirho);
    assert_ne!(signature_tamper_chirho.sig_chirho, signature_before_chirho);
    let signature_tamper_bytes_chirho =
        canonical_json_chirho(&signature_tamper_chirho).expect("encode signature tamper");
    fixture_chirho
        .storage_chirho
        .atomic_write_chirho(&receipt_path_chirho, &signature_tamper_bytes_chirho)
        .expect("plant signature-only tamper");
    let signature_refusal_chirho = expect_mint_refusal_chirho(
        claim_verified_gd7_losing_effect_obligation_chirho(
            &fixture_chirho.storage_chirho,
            &fixture_chirho.held_signer_chirho,
            &digest_chirho('e').0,
            &fixture_chirho.production_checkpoint_ref_chirho,
            &fixture_chirho.production_plan_ref_chirho,
            &fixture_chirho.identity_digest_chirho,
            fixture_chirho.identity_chirho.winner_term_chirho,
            fixture_chirho.verify_production_obligation_chirho(&selector_chirho),
        ),
        "signature-only receipt tamper must refuse before identity comparison",
    );
    assert_eq!(
        signature_refusal_chirho,
        Gd7LosingEffectObligationMintRefusalChirho::InvalidMintReceiptSignatureChirho
    );

    let mut collision_chirho: Gd7LosingEffectObligationMintReceiptChirho =
        serde_json::from_slice(&original_bytes_chirho).expect("parse receipt for collision arm");
    collision_chirho.adopted_checkpoint_ref_chirho = digest_chirho('f').0;
    collision_chirho.sig_chirho.clear();
    let unsigned_collision_chirho =
        canonical_json_chirho(&collision_chirho).expect("encode unsigned collision receipt");
    collision_chirho.sig_chirho = fixture_chirho
        .held_signer_chirho
        .sign_chirho(
            std::str::from_utf8(&unsigned_collision_chirho)
                .expect("collision receipt remains UTF-8"),
        )
        .expect("validly sign the wrong receipt identity");
    let collision_bytes_chirho =
        canonical_json_chirho(&collision_chirho).expect("encode signed collision receipt");
    fixture_chirho
        .storage_chirho
        .atomic_write_chirho(&receipt_path_chirho, &collision_bytes_chirho)
        .expect("plant separately valid wrong receipt");
    let collision_refusal_chirho = expect_mint_refusal_chirho(
        claim_verified_gd7_losing_effect_obligation_chirho(
            &fixture_chirho.storage_chirho,
            &fixture_chirho.held_signer_chirho,
            &digest_chirho('e').0,
            &fixture_chirho.production_checkpoint_ref_chirho,
            &fixture_chirho.production_plan_ref_chirho,
            &fixture_chirho.identity_digest_chirho,
            fixture_chirho.identity_chirho.winner_term_chirho,
            fixture_chirho.verify_production_obligation_chirho(&selector_chirho),
        ),
        "a valid receipt for the wrong adoption identity must collide",
    );
    assert_eq!(
        collision_refusal_chirho,
        Gd7LosingEffectObligationMintRefusalChirho::MintReceiptCollisionChirho
    );
    let rendered_chirho = collision_refusal_chirho.to_string();
    assert!(rendered_chirho.contains("collided"));
    assert!(!rendered_chirho.contains("signature is invalid"));
    assert!(!rendered_chirho.contains("awaiting verified"));
}

impl ObligationMintFixtureChirho {
    pub(super) fn effect_ports_chirho(&self) -> Gd7EffectProofPortsChirho<'_> {
        effect_proof_ports_chirho(
            &self.evidence_chirho,
            &self.intent_signer_chirho,
            &self.terminal_signer_chirho,
        )
    }

    /// Effect ports carrying the subset-trap chain's own intent evidence.
    pub(super) fn subset_effect_ports_chirho(&self) -> Gd7EffectProofPortsChirho<'_> {
        effect_proof_ports_chirho(
            &self.subset_evidence_chirho,
            &self.intent_signer_chirho,
            &self.terminal_signer_chirho,
        )
    }

    fn verify_production_obligation_chirho(
        &self,
        selector_chirho: &Gd7LosingEffectObligationSelectorChirho,
    ) -> VerifiedGd7SealedPlanObligationChirho {
        verify_gd7_sealed_plan_obligation_at_checkpoint_chirho(
            &self.storage_chirho,
            &self.held_signer_chirho,
            &self.losing_record_verifier_chirho,
            &self.effect_ports_chirho(),
            &self.production_checkpoint_ref_chirho,
            &self.production_checkpoint_chirho,
            selector_chirho,
        )
        .expect("reverify the production sealed-plan obligation")
    }

    pub(super) fn assert_source_objects_unchanged_chirho(&self) {
        for (path_chirho, expected_bytes_chirho) in &self.source_object_bytes_chirho {
            assert_eq!(
                self.storage_chirho
                    .read_all_chirho(&StoragePathChirho::new_chirho(path_chirho))
                    .expect("re-read immutable source object")
                    .expect("immutable source object remains"),
                *expected_bytes_chirho,
                "mint must not rewrite plan or manifest object {path_chirho}"
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
enum ObligationBindingMutationChirho {
    SchemaChirho,
    IdentityChirho,
    AdoptedCheckpointChirho,
    PlanCheckpointChirho,
    SealedPlanChirho,
    PlanPageChirho,
    PlanPageIndexChirho,
    ObligationIndexChirho,
    HistoricalTermChirho,
    KindChirho,
    LineageChirho,
    OriginalEffectKeyChirho,
    TerminalStateChirho,
    TerminalMarkerChirho,
    SourceSequenceChirho,
    SourceDigestChirho,
    CanonicalObligationDigestChirho,
}

impl ObligationBindingMutationChirho {
    const ALL_CHIRHO: [Self; 17] = [
        Self::SchemaChirho,
        Self::IdentityChirho,
        Self::AdoptedCheckpointChirho,
        Self::PlanCheckpointChirho,
        Self::SealedPlanChirho,
        Self::PlanPageChirho,
        Self::PlanPageIndexChirho,
        Self::ObligationIndexChirho,
        Self::HistoricalTermChirho,
        Self::KindChirho,
        Self::LineageChirho,
        Self::OriginalEffectKeyChirho,
        Self::TerminalStateChirho,
        Self::TerminalMarkerChirho,
        Self::SourceSequenceChirho,
        Self::SourceDigestChirho,
        Self::CanonicalObligationDigestChirho,
    ];

    fn apply_chirho(self, binding_chirho: &mut Gd7LosingEffectObligationBindingChirho) {
        let before_chirho = binding_chirho.clone();
        match self {
            Self::SchemaChirho => binding_chirho.schema_chirho.push_str("-changed-chirho"),
            Self::IdentityChirho => {
                binding_chirho.reconciliation_identity_digest_chirho = digest_chirho('1').0
            }
            Self::AdoptedCheckpointChirho => {
                binding_chirho.adopted_checkpoint_ref_chirho = digest_chirho('2').0
            }
            Self::PlanCheckpointChirho => {
                binding_chirho.plan_checkpoint_ref_chirho = digest_chirho('3').0
            }
            Self::SealedPlanChirho => binding_chirho.sealed_plan_ref_chirho = digest_chirho('4').0,
            Self::PlanPageChirho => binding_chirho.plan_page_ref_chirho = digest_chirho('5').0,
            Self::PlanPageIndexChirho => binding_chirho.plan_page_index_chirho += 1,
            Self::ObligationIndexChirho => binding_chirho.obligation_index_chirho += 1,
            Self::HistoricalTermChirho => binding_chirho.historical_winner_term_chirho += 1,
            Self::KindChirho => {
                binding_chirho.kind_chirho =
                    Gd7EffectPlanObligationKindChirho::CommittedOnLosingForkChirho
            }
            Self::LineageChirho => {
                binding_chirho.lineage_chirho = Gd7EffectLineageChirho::CompensationChirho
            }
            Self::OriginalEffectKeyChirho => {
                binding_chirho.original_effect_key_chirho =
                    Some("changed-effect-key-chirho".to_owned())
            }
            Self::TerminalStateChirho => {
                binding_chirho.terminal_state_chirho =
                    Gd7LosingEffectObligationTerminalStateChirho::CommittedFinalizeChirho
            }
            Self::TerminalMarkerChirho => {
                binding_chirho.terminal_marker_object_digest_chirho = Some(digest_chirho('6').0)
            }
            Self::SourceSequenceChirho => binding_chirho.source_seq_chirho += 1,
            Self::SourceDigestChirho => {
                binding_chirho.source_record_digest_chirho = digest_chirho('7').0
            }
            Self::CanonicalObligationDigestChirho => {
                binding_chirho.canonical_obligation_digest_chirho = digest_chirho('8').0
            }
        }
        assert_ne!(
            binding_chirho, &before_chirho,
            "mutation {self:?} must alter exactly one planted binding coordinate"
        );
    }
}

pub(super) fn obligation_mint_fixture_chirho(label_chirho: &str) -> ObligationMintFixtureChirho {
    let (root_chirho, storage_chirho) = temp_storage_chirho(label_chirho);
    let held_signer_chirho = FakePlanSignerChirho {
        key_id_chirho: digest_chirho('b').0,
        secret_chirho: [0x41; 32],
    };
    let intent_signer_chirho = FakeIntentSignerChirho {
        secret_chirho: [0x51; 32],
    };
    let terminal_signer_chirho = FakeTerminalSignerChirho {
        secret_chirho: [0x61; 32],
    };
    let losing_record_verifier_chirho = FakeLosingRecordVerifierChirho {
        secret_chirho: [0x71; 32],
    };
    let mut identity_chirho = identity_chirho();
    identity_chirho.fork_chirho.seq_chirho = 5;
    identity_chirho.fork_chirho.record_digest_chirho = digest_chirho('d').0;
    let (intent_ref_chirho, intent_line_chirho) =
        signed_intent_warrant_chirho(&intent_signer_chirho, &identity_chirho, '1', 6, None);
    let hold_record_chirho = losing_record_verifier_chirho
        .sign_record_chirho(forward_hold_record_chirho(6, &intent_ref_chirho));
    let hold_digest_chirho = ledger_record_digest_chirho(&hold_record_chirho);
    let ledger_record_chirho = losing_record_verifier_chirho.sign_record_chirho(
        ledger_only_record_chirho(7, &hold_digest_chirho, hold_record_chirho.epoch_chirho),
    );
    let ledger_digest_chirho = ledger_record_digest_chirho(&ledger_record_chirho);
    identity_chirho.losing_journal_tail_chirho.epoch_chirho = ledger_record_chirho.epoch_chirho;
    identity_chirho.losing_journal_tail_chirho.seq_chirho = ledger_record_chirho.seq_chirho;
    identity_chirho
        .losing_journal_tail_chirho
        .record_digest_chirho = ledger_digest_chirho.clone();
    let identity_digest_chirho = gd7_reconciliation_identity_digest_chirho(&identity_chirho)
        .expect("digest obligation mint identity");
    let evidence_chirho = MemoryEffectEvidenceChirho {
        lines_chirho: [(intent_ref_chirho.0.clone(), intent_line_chirho.clone())]
            .into_iter()
            .collect(),
        terminal_lines_chirho: BTreeMap::new(),
    };
    let effect_ports_chirho = effect_proof_ports_chirho(
        &evidence_chirho,
        &intent_signer_chirho,
        &terminal_signer_chirho,
    );

    let production_manifest_ref_chirho = persist_manifest_page_chirho(
        &storage_chirho,
        &identity_chirho,
        &identity_digest_chirho,
        ManifestPageFixtureInputChirho {
            page_index_chirho: 0,
            newer_manifest_page_ref_chirho: None,
            records_newest_first_chirho: vec![
                (ledger_digest_chirho.clone(), ledger_record_chirho.clone()),
                (hold_digest_chirho.clone(), hold_record_chirho.clone()),
            ],
            next_cursor_object_ref_chirho: None,
            reached_anchor_chirho: true,
        },
    );
    let production_reduction_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &effect_ports_chirho,
        &identity_chirho,
        &identity_digest_chirho,
        [
            (ledger_digest_chirho.as_str(), &ledger_record_chirho),
            (hold_digest_chirho.as_str(), &hold_record_chirho),
        ],
    )
    .expect("reduce the production manifest page");
    let obligation_chirho = production_reduction_chirho.obligations_newest_first_chirho[0].clone();
    let production_plan_ref_chirho = persist_plan_page_chirho(
        &storage_chirho,
        &identity_digest_chirho,
        0,
        &production_manifest_ref_chirho,
        None,
        2,
        production_reduction_chirho.fact_counts_chirho,
        production_reduction_chirho.obligations_newest_first_chirho,
        production_reduction_chirho.terminal_marker_object_digests_newest_first_chirho,
        1,
        2,
        1,
        true,
    );
    let (production_checkpoint_ref_chirho, production_checkpoint_chirho) =
        persist_plan_checkpoint_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &identity_chirho,
            &production_manifest_ref_chirho,
            &production_plan_ref_chirho,
            1,
            2,
            1,
        );

    let alternate_newer_manifest_ref_chirho = persist_manifest_page_chirho(
        &storage_chirho,
        &identity_chirho,
        &identity_digest_chirho,
        ManifestPageFixtureInputChirho {
            page_index_chirho: 0,
            newer_manifest_page_ref_chirho: None,
            records_newest_first_chirho: vec![(
                ledger_digest_chirho.clone(),
                ledger_record_chirho.clone(),
            )],
            next_cursor_object_ref_chirho: Some(digest_chirho('c').0),
            reached_anchor_chirho: false,
        },
    );
    let alternate_newer_reduction_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &effect_ports_chirho,
        &identity_chirho,
        &identity_digest_chirho,
        [(ledger_digest_chirho.as_str(), &ledger_record_chirho)],
    )
    .expect("reduce alternate newer manifest page");
    let alternate_newer_plan_ref_chirho = persist_plan_page_chirho(
        &storage_chirho,
        &identity_digest_chirho,
        0,
        &alternate_newer_manifest_ref_chirho,
        None,
        1,
        alternate_newer_reduction_chirho.fact_counts_chirho,
        alternate_newer_reduction_chirho.obligations_newest_first_chirho,
        alternate_newer_reduction_chirho.terminal_marker_object_digests_newest_first_chirho,
        1,
        1,
        0,
        false,
    );
    let alternate_older_manifest_ref_chirho = persist_manifest_page_chirho(
        &storage_chirho,
        &identity_chirho,
        &identity_digest_chirho,
        ManifestPageFixtureInputChirho {
            page_index_chirho: 1,
            newer_manifest_page_ref_chirho: Some(alternate_newer_manifest_ref_chirho.clone()),
            records_newest_first_chirho: vec![(
                hold_digest_chirho.clone(),
                hold_record_chirho.clone(),
            )],
            next_cursor_object_ref_chirho: None,
            reached_anchor_chirho: true,
        },
    );
    let alternate_older_reduction_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &effect_ports_chirho,
        &identity_chirho,
        &identity_digest_chirho,
        [(hold_digest_chirho.as_str(), &hold_record_chirho)],
    )
    .expect("reduce alternate older manifest page");
    let alternate_obligation_plan_ref_chirho = persist_plan_page_chirho(
        &storage_chirho,
        &identity_digest_chirho,
        1,
        &alternate_older_manifest_ref_chirho,
        Some(alternate_newer_plan_ref_chirho.clone()),
        1,
        alternate_older_reduction_chirho.fact_counts_chirho,
        alternate_older_reduction_chirho.obligations_newest_first_chirho,
        alternate_older_reduction_chirho.terminal_marker_object_digests_newest_first_chirho,
        2,
        2,
        1,
        true,
    );
    let (alternate_checkpoint_ref_chirho, alternate_checkpoint_chirho) =
        persist_plan_checkpoint_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &identity_chirho,
            &alternate_older_manifest_ref_chirho,
            &alternate_obligation_plan_ref_chirho,
            2,
            2,
            1,
        );

    // A COMPLETE one-page chain carrying ZERO obligations.
    //
    // The enumerator refuses `page_count == 0`, so an honestly empty population is not an empty
    // chain — it is a real walked page whose cumulative obligation count is 0.
    //
    // It needs its OWN identity, and the reason is a real invariant rather than fixture
    // convenience: a page-0 manifest's newest record must BE the frozen losing tail, and an
    // anchored page's oldest record must sit exactly one seq above the fork. The main identity's
    // tail is the ledger record whose predecessor is the forward-hold — the very record that mints
    // the obligation. So under that identity, no complete chain can have zero obligations. This
    // identity's whole losing suffix is one ledger-only record instead.
    let mut empty_identity_chirho = identity_chirho.clone();
    let empty_record_chirho = losing_record_verifier_chirho.sign_record_chirho(
        ledger_only_record_chirho(6, &digest_chirho('d').0, ledger_record_chirho.epoch_chirho),
    );
    let empty_record_digest_chirho = ledger_record_digest_chirho(&empty_record_chirho);
    empty_identity_chirho
        .losing_journal_tail_chirho
        .epoch_chirho = empty_record_chirho.epoch_chirho;
    empty_identity_chirho.losing_journal_tail_chirho.seq_chirho = empty_record_chirho.seq_chirho;
    empty_identity_chirho
        .losing_journal_tail_chirho
        .record_digest_chirho = empty_record_digest_chirho.clone();
    let empty_identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&empty_identity_chirho)
            .expect("digest the zero-obligation identity");
    let empty_manifest_ref_chirho = persist_manifest_page_chirho(
        &storage_chirho,
        &empty_identity_chirho,
        &empty_identity_digest_chirho,
        ManifestPageFixtureInputChirho {
            page_index_chirho: 0,
            newer_manifest_page_ref_chirho: None,
            records_newest_first_chirho: vec![(
                empty_record_digest_chirho.clone(),
                empty_record_chirho.clone(),
            )],
            next_cursor_object_ref_chirho: None,
            reached_anchor_chirho: true,
        },
    );
    let empty_reduction_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &effect_ports_chirho,
        &empty_identity_chirho,
        &empty_identity_digest_chirho,
        [(empty_record_digest_chirho.as_str(), &empty_record_chirho)],
    )
    .expect("reduce the zero-obligation manifest page");
    assert!(
        empty_reduction_chirho
            .obligations_newest_first_chirho
            .is_empty(),
        "the zero-obligation fixture must reduce to no obligations, or it is not the case under test"
    );
    let empty_plan_ref_chirho = persist_plan_page_chirho(
        &storage_chirho,
        &empty_identity_digest_chirho,
        0,
        &empty_manifest_ref_chirho,
        None,
        1,
        empty_reduction_chirho.fact_counts_chirho,
        empty_reduction_chirho.obligations_newest_first_chirho,
        empty_reduction_chirho.terminal_marker_object_digests_newest_first_chirho,
        1,
        1,
        0,
        true,
    );
    let (empty_checkpoint_ref_chirho, empty_checkpoint_chirho) = persist_plan_checkpoint_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &empty_identity_chirho,
        &empty_manifest_ref_chirho,
        &empty_plan_ref_chirho,
        1,
        1,
        0,
    );

    // THE SUBSET TRAP: a two-page chain whose ONLY obligation sits on the page the walk reaches
    // SECOND. The walk enters at the highest page index (the oldest page), so putting the sole
    // obligation on page 0 means a converger that stopped after its entry page would measure a
    // population of ZERO and certify — releasing past an obligation it never saw. That is the money
    // hazard this chain exists to catch, and it is the mirror of the zero-obligation chain above:
    // measured-nonzero-across-pages versus measured-zero.
    //
    // Order is forced: page 0 is the NEWER page, so the holding record must carry the higher seq,
    // which means its intent's journal cut must name the seq-6 record rather than the fork.
    let mut subset_identity_chirho = identity_chirho.clone();
    let subset_older_record_chirho = losing_record_verifier_chirho.sign_record_chirho(
        ledger_only_record_chirho(6, &digest_chirho('d').0, ledger_record_chirho.epoch_chirho),
    );
    let subset_older_digest_chirho = ledger_record_digest_chirho(&subset_older_record_chirho);
    let (subset_intent_ref_chirho, subset_intent_line_chirho) =
        signed_intent_warrant_at_tail_chirho(
            &intent_signer_chirho,
            &identity_chirho,
            '2',
            7,
            None,
            DigestChirho(subset_older_digest_chirho.clone()),
        );
    let mut subset_hold_record_chirho = forward_hold_record_chirho(7, &subset_intent_ref_chirho);
    subset_hold_record_chirho.prev_chirho = DigestChirho(subset_older_digest_chirho.clone());
    let subset_hold_record_chirho =
        losing_record_verifier_chirho.sign_record_chirho(subset_hold_record_chirho);
    let subset_hold_digest_chirho = ledger_record_digest_chirho(&subset_hold_record_chirho);
    subset_identity_chirho
        .losing_journal_tail_chirho
        .epoch_chirho = subset_hold_record_chirho.epoch_chirho;
    subset_identity_chirho.losing_journal_tail_chirho.seq_chirho =
        subset_hold_record_chirho.seq_chirho;
    subset_identity_chirho
        .losing_journal_tail_chirho
        .record_digest_chirho = subset_hold_digest_chirho.clone();
    let subset_identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&subset_identity_chirho)
            .expect("digest the subset-trap identity");
    let subset_evidence_chirho = MemoryEffectEvidenceChirho {
        lines_chirho: [
            (intent_ref_chirho.0.clone(), intent_line_chirho.clone()),
            (
                subset_intent_ref_chirho.0.clone(),
                subset_intent_line_chirho,
            ),
        ]
        .into_iter()
        .collect(),
        terminal_lines_chirho: BTreeMap::new(),
    };
    let subset_effect_ports_chirho = effect_proof_ports_chirho(
        &subset_evidence_chirho,
        &intent_signer_chirho,
        &terminal_signer_chirho,
    );
    // Page 0 (newer, reached SECOND): carries the sole obligation and the frozen tail.
    let subset_newer_manifest_ref_chirho = persist_manifest_page_chirho(
        &storage_chirho,
        &subset_identity_chirho,
        &subset_identity_digest_chirho,
        ManifestPageFixtureInputChirho {
            page_index_chirho: 0,
            newer_manifest_page_ref_chirho: None,
            records_newest_first_chirho: vec![(
                subset_hold_digest_chirho.clone(),
                subset_hold_record_chirho.clone(),
            )],
            next_cursor_object_ref_chirho: Some(digest_chirho('c').0),
            reached_anchor_chirho: false,
        },
    );
    let subset_newer_reduction_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &subset_effect_ports_chirho,
        &subset_identity_chirho,
        &subset_identity_digest_chirho,
        [(
            subset_hold_digest_chirho.as_str(),
            &subset_hold_record_chirho,
        )],
    )
    .expect("reduce the subset-trap newer page");
    assert_eq!(
        subset_newer_reduction_chirho
            .obligations_newest_first_chirho
            .len(),
        1,
        "the subset trap's sole obligation must live on the page the walk reaches SECOND"
    );
    let subset_newer_plan_ref_chirho = persist_plan_page_chirho(
        &storage_chirho,
        &subset_identity_digest_chirho,
        0,
        &subset_newer_manifest_ref_chirho,
        None,
        1,
        subset_newer_reduction_chirho.fact_counts_chirho,
        subset_newer_reduction_chirho.obligations_newest_first_chirho,
        subset_newer_reduction_chirho.terminal_marker_object_digests_newest_first_chirho,
        1,
        1,
        1,
        false,
    );
    // Page 1 (older, the ENTRY page): anchored at the fork, and deliberately obligation-FREE.
    let subset_older_manifest_ref_chirho = persist_manifest_page_chirho(
        &storage_chirho,
        &subset_identity_chirho,
        &subset_identity_digest_chirho,
        ManifestPageFixtureInputChirho {
            page_index_chirho: 1,
            newer_manifest_page_ref_chirho: Some(subset_newer_manifest_ref_chirho.clone()),
            records_newest_first_chirho: vec![(
                subset_older_digest_chirho.clone(),
                subset_older_record_chirho.clone(),
            )],
            next_cursor_object_ref_chirho: None,
            reached_anchor_chirho: true,
        },
    );
    let subset_older_reduction_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &subset_effect_ports_chirho,
        &subset_identity_chirho,
        &subset_identity_digest_chirho,
        [(
            subset_older_digest_chirho.as_str(),
            &subset_older_record_chirho,
        )],
    )
    .expect("reduce the subset-trap older page");
    assert!(
        subset_older_reduction_chirho
            .obligations_newest_first_chirho
            .is_empty(),
        "the ENTRY page must carry no obligation, or the trap does not trap anything"
    );
    let subset_plan_ref_chirho = persist_plan_page_chirho(
        &storage_chirho,
        &subset_identity_digest_chirho,
        1,
        &subset_older_manifest_ref_chirho,
        Some(subset_newer_plan_ref_chirho.clone()),
        1,
        subset_older_reduction_chirho.fact_counts_chirho,
        subset_older_reduction_chirho.obligations_newest_first_chirho,
        subset_older_reduction_chirho.terminal_marker_object_digests_newest_first_chirho,
        2,
        2,
        1,
        true,
    );
    let (subset_checkpoint_ref_chirho, subset_checkpoint_chirho) = persist_plan_checkpoint_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &subset_identity_chirho,
        &subset_older_manifest_ref_chirho,
        &subset_plan_ref_chirho,
        2,
        2,
        1,
    );
    assert_eq!(
        load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &alternate_checkpoint_ref_chirho,
        )
        .expect("authenticate the genuine alternate checkpoint"),
        alternate_checkpoint_chirho
    );

    let source_object_bytes_chirho = [
        gd7_losing_manifest_page_path_chirho(&production_manifest_ref_chirho)
            .expect("derive production manifest path"),
        gd7_reconciliation_plan_page_path_chirho(&production_plan_ref_chirho)
            .expect("derive production plan path"),
        gd7_losing_manifest_page_path_chirho(&alternate_newer_manifest_ref_chirho)
            .expect("derive alternate newer manifest path"),
        gd7_losing_manifest_page_path_chirho(&alternate_older_manifest_ref_chirho)
            .expect("derive alternate older manifest path"),
        gd7_reconciliation_plan_page_path_chirho(&alternate_obligation_plan_ref_chirho)
            .expect("derive alternate obligation plan path"),
        gd7_reconciliation_plan_page_path_chirho(&alternate_newer_plan_ref_chirho)
            .expect("derive alternate newer plan path"),
        gd7_losing_manifest_page_path_chirho(&empty_manifest_ref_chirho)
            .expect("derive zero-obligation manifest path"),
        gd7_reconciliation_plan_page_path_chirho(&empty_plan_ref_chirho)
            .expect("derive zero-obligation plan path"),
    ]
    .into_iter()
    .map(|path_chirho| {
        let bytes_chirho = storage_chirho
            .read_all_chirho(&path_chirho)
            .expect("read immutable fixture object")
            .expect("immutable fixture object exists");
        (path_chirho.key_chirho().to_owned(), bytes_chirho)
    })
    .collect();

    ObligationMintFixtureChirho {
        root_chirho,
        storage_chirho,
        held_signer_chirho,
        intent_signer_chirho,
        terminal_signer_chirho,
        losing_record_verifier_chirho,
        evidence_chirho,
        identity_chirho,
        identity_digest_chirho,
        production_checkpoint_ref_chirho,
        production_checkpoint_chirho,
        production_plan_ref_chirho,
        alternate_checkpoint_ref_chirho,
        alternate_checkpoint_chirho,
        alternate_obligation_plan_ref_chirho,
        empty_checkpoint_ref_chirho,
        empty_checkpoint_chirho,
        empty_plan_ref_chirho,
        empty_identity_digest_chirho,
        subset_checkpoint_ref_chirho,
        subset_checkpoint_chirho,
        subset_plan_ref_chirho,
        subset_identity_digest_chirho,
        subset_evidence_chirho,
        obligation_chirho,
        source_object_bytes_chirho,
    }
}

struct ManifestPageFixtureInputChirho {
    page_index_chirho: u64,
    newer_manifest_page_ref_chirho: Option<String>,
    records_newest_first_chirho: Vec<(String, LedgerRecordChirho)>,
    next_cursor_object_ref_chirho: Option<String>,
    reached_anchor_chirho: bool,
}

fn persist_manifest_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    identity_digest_chirho: &str,
    input_chirho: ManifestPageFixtureInputChirho,
) -> String {
    let page_chirho: Gd7LosingManifestPageChirho = serde_json::from_value(serde_json::json!({
        "schema_chirho": GD7_LOSING_MANIFEST_PAGE_SCHEMA_V1_CHIRHO,
        "reconciliation_identity_digest_chirho": identity_digest_chirho,
        "page_index_chirho": input_chirho.page_index_chirho,
        "newer_manifest_page_ref_chirho": input_chirho.newer_manifest_page_ref_chirho,
        "frozen_losing_tail_chirho": identity_chirho.losing_journal_tail_chirho.clone(),
        "exact_fork_anchor_chirho": identity_chirho.fork_chirho.clone(),
        "records_newest_first_chirho": input_chirho.records_newest_first_chirho
            .into_iter()
            .map(|(record_digest_chirho, record_chirho)| serde_json::json!({
                "record_digest_chirho": record_digest_chirho,
                "record_chirho": record_chirho,
            }))
            .collect::<Vec<_>>(),
        "next_cursor_object_ref_chirho": input_chirho.next_cursor_object_ref_chirho,
        "reached_anchor_chirho": input_chirho.reached_anchor_chirho,
    }))
    .expect("build canonical manifest page fixture");
    let bytes_chirho = serde_json::to_vec(&page_chirho).expect("encode manifest page fixture");
    let digest_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
    persist_exact_bytes_chirho(
        storage_chirho,
        &gd7_losing_manifest_page_path_chirho(&digest_chirho).expect("derive manifest page path"),
        &bytes_chirho,
    );
    digest_chirho
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixture spells every cumulative page coordinate so a swapped count cannot hide"
)]
pub(super) fn persist_plan_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    identity_digest_chirho: &str,
    page_index_chirho: u64,
    manifest_page_ref_chirho: &str,
    newer_plan_page_ref_chirho: Option<String>,
    manifest_record_count_chirho: u64,
    fact_counts_chirho: Gd7PlanPageFactCountsChirho,
    obligations_newest_first_chirho: Vec<Gd7EffectPlanObligationChirho>,
    terminal_markers_chirho: Vec<String>,
    cumulative_page_count_chirho: u64,
    cumulative_record_count_chirho: u64,
    cumulative_obligation_count_chirho: u64,
    reached_anchor_chirho: bool,
) -> String {
    let page_chirho = Gd7ReconciliationPlanPageChirho {
        schema_chirho: GD7_RECONCILIATION_PLAN_PAGE_SCHEMA_V1_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: identity_digest_chirho.to_owned(),
        page_index_chirho,
        manifest_page_ref_chirho: manifest_page_ref_chirho.to_owned(),
        newer_plan_page_ref_chirho,
        manifest_record_count_chirho,
        local_fact_counts_chirho: fact_counts_chirho,
        obligations_newest_first_chirho,
        terminal_marker_object_digests_newest_first_chirho: terminal_markers_chirho,
        cumulative_manifest_page_count_chirho: cumulative_page_count_chirho,
        cumulative_manifest_record_count_chirho: cumulative_record_count_chirho,
        cumulative_effect_obligation_count_chirho: cumulative_obligation_count_chirho,
        reached_anchor_chirho,
    };
    let bytes_chirho = serde_json::to_vec(&page_chirho).expect("encode plan page fixture");
    let digest_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
    persist_exact_bytes_chirho(
        storage_chirho,
        &super::super::gd7_reconciliation_plan_page_path_chirho(&digest_chirho)
            .expect("derive plan page path"),
        &bytes_chirho,
    );
    digest_chirho
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixture spells every signed checkpoint count instead of deriving a second state"
)]
pub(super) fn persist_plan_checkpoint_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    manifest_head_ref_chirho: &str,
    plan_head_ref_chirho: &str,
    page_count_chirho: u64,
    record_count_chirho: u64,
    obligation_count_chirho: u64,
) -> (String, Gd7ReconciliationCheckpointChirho) {
    let mut checkpoint_chirho = Gd7ReconciliationCheckpointChirho {
        schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho: identity_chirho.clone(),
        winner_fork_witness_object_digest_chirho: digest_chirho('8').0,
        state_chirho: Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
            transition_seq_chirho: 4,
            previous_checkpoint_ref_chirho: Some(digest_chirho('9').0),
            manifest_head_ref_chirho: Some(manifest_head_ref_chirho.to_owned()),
            manifest_page_count_chirho: page_count_chirho,
            manifest_record_count_chirho: record_count_chirho,
            plan_head_ref_chirho: Some(plan_head_ref_chirho.to_owned()),
            plan_page_count_chirho: page_count_chirho,
            sealed_plan_ref_chirho: Some(plan_head_ref_chirho.to_owned()),
            effect_obligation_count_chirho: obligation_count_chirho,
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: None,
        },
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    let unsigned_chirho =
        serde_json::to_vec(&checkpoint_chirho).expect("encode unsigned PlanSealed checkpoint");
    checkpoint_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(std::str::from_utf8(&unsigned_chirho).expect("checkpoint JSON remains UTF-8"))
        .expect("sign PlanSealed checkpoint");
    let bytes_chirho =
        serde_json::to_vec(&checkpoint_chirho).expect("encode signed PlanSealed checkpoint");
    let checkpoint_ref_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
    persist_exact_bytes_chirho(
        storage_chirho,
        &gd7_reconciliation_checkpoint_path_chirho(&checkpoint_ref_chirho)
            .expect("derive checkpoint path"),
        &bytes_chirho,
    );
    (checkpoint_ref_chirho, checkpoint_chirho)
}

pub(super) fn persist_exact_bytes_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
) {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .expect("persist immutable fixture bytes")
    {
        CreateDurableOutcomeChirho::CreatedChirho => {}
        CreateDurableOutcomeChirho::AlreadyExistsChirho => assert_eq!(
            storage_chirho
                .read_all_chirho(path_chirho)
                .expect("read existing immutable fixture bytes")
                .expect("existing immutable fixture object remains"),
            bytes_chirho
        ),
    }
}

fn ledger_record_digest_chirho(record_chirho: &LedgerRecordChirho) -> String {
    let canonical_chirho = canonical_ledger_record_line_chirho(record_chirho)
        .expect("encode canonical fixture record");
    stored_line_digest_chirho(&canonical_chirho).0
}

fn expect_mint_refusal_chirho(
    result_chirho: std::result::Result<
        MintedGd7LosingEffectObligationChirho,
        Gd7LosingEffectObligationMintRefusalChirho,
    >,
    message_chirho: &str,
) -> Gd7LosingEffectObligationMintRefusalChirho {
    match result_chirho {
        Ok(_minted_chirho) => panic!("{message_chirho}"),
        Err(refusal_chirho) => refusal_chirho,
    }
}

fn ledger_only_record_chirho(
    seq_chirho: u64,
    previous_digest_chirho: &str,
    epoch_chirho: u64,
) -> LedgerRecordChirho {
    LedgerRecordChirho {
        schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        format_version_chirho: LEDGER_FORMAT_VERSION_V1_CHIRHO,
        seq_chirho,
        prev_chirho: DigestChirho(previous_digest_chirho.to_owned()),
        epoch_chirho,
        hlc_chirho: HlcChirho {
            physical_ms_chirho: seq_chirho,
            logical_chirho: 0,
        },
        legs_chirho: vec![LedgerLegChirho {
            account_chirho: super::super::tests_chirho::plan_payer_account_chirho(),
            kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho('c')),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 1,
            post_chirho: LegPostStateChirho {
                credits_total_chirho: 1,
                debits_total_chirho: 0,
                held_chirho: 0,
            },
            counterpart_chirho: None,
        }],
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: digest_chirho('7'),
        },
        idempotency_key_chirho: "gd7-obligation-ledger-only-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
        anchor_chirho: None,
        sig_chirho: String::new(),
        key_id_chirho: String::new(),
    }
}
