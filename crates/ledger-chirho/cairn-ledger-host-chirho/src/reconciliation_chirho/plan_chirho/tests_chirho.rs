// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::marker_chirho::gd7_terminal_marker_path_chirho;
use super::reducer_chirho::{
    reduce_record_inputs_chirho, reverify_record_inputs_read_only_chirho, Gd7EffectProofPortsChirho,
};
use super::RootGd7EffectEvidenceReaderChirho;
use super::{
    Gd7EffectEvidenceReaderPortChirho, Gd7EffectPlanObligationKindChirho, Gd7PlanRefusalChirho,
    Gd7TerminalMarkerChirho,
};
use crate::reconciliation_chirho::{
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho,
};
use crate::FsLedgerStorageChirho;
use anyhow::Result;
use cairn_effect_commit_chirho::intent_chirho::{
    effect_intent_ref_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    EffectIntentJournalCutChirho, EffectIntentSignerPortChirho, EFFECT_INTENT_KEY_PREFIX_CHIRHO,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_effect_commit_chirho::minimal_warrant_chirho::{
    canonical_minimal_warrant_line_chirho, minimal_warrant_from_intent_chirho,
    sign_minimal_warrant_chirho,
};
use cairn_effect_commit_chirho::terminal_chirho::{
    canonical_effect_terminal_outcome_line_chirho, effect_terminal_outcome_ref_chirho,
    sign_effect_terminal_outcome_chirho, EffectTerminalDispositionChirho,
    EffectTerminalOutcomeChirho, EffectTerminalSignerPortChirho, EFFECT_TERMINAL_KEY_PREFIX_CHIRHO,
    EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO,
};
use cairn_effect_commit_ledger_chirho::public_evidence_chirho::{
    PublicEffectEvidenceKindChirho, RootPublicEffectEvidenceStoreChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, EscrowControlChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho,
    LedgerRecordChirho, LegDeltaChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, stored_line_digest_chirho,
    LEDGER_FORMAT_VERSION_V1_CHIRHO, LEDGER_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub(super) struct MemoryEffectEvidenceChirho {
    pub(super) lines_chirho: BTreeMap<String, String>,
    pub(super) terminal_lines_chirho: BTreeMap<String, String>,
}

impl Gd7EffectEvidenceReaderPortChirho for MemoryEffectEvidenceChirho {
    fn load_intent_line_bounded_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
        maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>> {
        let line_chirho = self.lines_chirho.get(&intent_ref_chirho.0);
        if line_chirho.is_some_and(|line_chirho| line_chirho.len() > maximum_bytes_chirho) {
            anyhow::bail!("intent evidence exceeds the caller's byte ceiling");
        }
        Ok(line_chirho.map(|line_chirho| line_chirho.as_bytes().to_vec()))
    }

    fn load_terminal_line_bounded_chirho(
        &self,
        outcome_ref_chirho: &DigestChirho,
        maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>> {
        let line_chirho = self.terminal_lines_chirho.get(&outcome_ref_chirho.0);
        if line_chirho.is_some_and(|line_chirho| line_chirho.len() > maximum_bytes_chirho) {
            anyhow::bail!("terminal evidence exceeds the caller's byte ceiling");
        }
        Ok(line_chirho.map(|line_chirho| line_chirho.as_bytes().to_vec()))
    }
}

pub(super) struct FakePlanSignerChirho {
    pub(super) key_id_chirho: String,
    pub(super) secret_chirho: [u8; 32],
}

impl FakePlanSignerChirho {
    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(line_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl Gd7ReconciliationVerifierPortChirho for FakePlanSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(canonical_unsigned_chirho) == sig_chirho
    }
}

impl Gd7ReconciliationSignerPortChirho for FakePlanSignerChirho {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(canonical_unsigned_chirho))
    }
}

pub(super) struct VerifierOnlyPlanVerifierChirho<'a> {
    verifier_chirho: &'a dyn Gd7ReconciliationVerifierPortChirho,
}

impl<'a> VerifierOnlyPlanVerifierChirho<'a> {
    pub(super) fn new_chirho(verifier_chirho: &'a dyn Gd7ReconciliationVerifierPortChirho) -> Self {
        Self { verifier_chirho }
    }
}

impl Gd7ReconciliationVerifierPortChirho for VerifierOnlyPlanVerifierChirho<'_> {
    fn key_id_chirho(&self) -> String {
        self.verifier_chirho.key_id_chirho()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verifier_chirho
            .verify_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

struct CountingPlanSignerChirho<'a> {
    signer_chirho: &'a dyn Gd7ReconciliationSignerPortChirho,
    sign_count_chirho: AtomicU64,
}

impl<'a> CountingPlanSignerChirho<'a> {
    fn new_chirho(signer_chirho: &'a dyn Gd7ReconciliationSignerPortChirho) -> Self {
        Self {
            signer_chirho,
            sign_count_chirho: AtomicU64::new(0),
        }
    }

    fn sign_count_chirho(&self) -> u64 {
        self.sign_count_chirho.load(Ordering::Relaxed)
    }
}

impl Gd7ReconciliationVerifierPortChirho for CountingPlanSignerChirho<'_> {
    fn key_id_chirho(&self) -> String {
        self.signer_chirho.key_id_chirho()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.signer_chirho
            .verify_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

impl Gd7ReconciliationSignerPortChirho for CountingPlanSignerChirho<'_> {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> Result<String> {
        self.sign_count_chirho.fetch_add(1, Ordering::Relaxed);
        self.signer_chirho.sign_chirho(canonical_unsigned_chirho)
    }
}

pub(super) struct FakeIntentSignerChirho {
    pub(super) secret_chirho: [u8; 32],
}

impl FakeIntentSignerChirho {
    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(line_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl EffectIntentSignerPortChirho for FakeIntentSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        "gd7-effect-intent-root-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

pub(super) struct FakeTerminalSignerChirho {
    pub(super) secret_chirho: [u8; 32],
}

impl FakeTerminalSignerChirho {
    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(line_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl EffectTerminalSignerPortChirho for FakeTerminalSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        "gd7-effect-terminal-root-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

pub(super) fn effect_proof_ports_chirho<'ports_chirho>(
    evidence_chirho: &'ports_chirho dyn Gd7EffectEvidenceReaderPortChirho,
    intent_verifier_chirho: &'ports_chirho dyn EffectIntentSignerPortChirho,
    terminal_verifier_chirho: &'ports_chirho dyn EffectTerminalSignerPortChirho,
) -> Gd7EffectProofPortsChirho<'ports_chirho> {
    Gd7EffectProofPortsChirho::new_chirho(
        evidence_chirho,
        intent_verifier_chirho,
        terminal_verifier_chirho,
    )
}

pub(super) fn digest_chirho(nibble_chirho: char) -> DigestChirho {
    DigestChirho(std::iter::repeat_n(nibble_chirho, 64).collect())
}

pub(super) fn identity_chirho() -> Gd7ReconciliationIdentityChirho {
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "gd7-plan-reducer-tenant-chirho".to_owned(),
    };
    Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        winner_node_chirho: digest_chirho('a').0,
        held_node_chirho: digest_chirho('b').0,
        winner_term_chirho: 9,
        losing_term_chirho: 8,
        winner_journal_genesis_digest_chirho: digest_chirho('2').0.clone(),
        winner_journal_tail_chirho: super::super::Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(9, 0).unwrap(),
            seq_chirho: 20,
            record_digest_chirho: digest_chirho('3').0,
        },
        fork_chirho: super::super::Gd7ForkCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(8, 0).unwrap(),
            seq_chirho: 5,
            record_digest_chirho: digest_chirho('4').0,
        },
        losing_journal_genesis_digest_chirho: digest_chirho('2').0,
        losing_journal_tail_chirho: super::super::Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(8, 0).unwrap(),
            seq_chirho: 15,
            record_digest_chirho: digest_chirho('5').0,
        },
    }
}

pub(super) fn temp_storage_chirho(
    label_chirho: &str,
) -> (std::path::PathBuf, FsLedgerStorageChirho) {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let count_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-gd7-plan-{label_chirho}-{nanos_chirho}-{count_chirho}"
    ));
    fs::create_dir_all(&root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();
    (root_chirho, storage_chirho)
}

pub(super) fn signed_intent_warrant_chirho(
    signer_chirho: &FakeIntentSignerChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    unique_chirho: char,
    hold_seq_chirho: u64,
    original_effect_key_chirho: Option<String>,
) -> (DigestChirho, String) {
    // The overwhelming majority of fixtures hold directly at the fork, so that stays the default.
    signed_intent_warrant_at_tail_chirho(
        signer_chirho,
        identity_chirho,
        unique_chirho,
        hold_seq_chirho,
        original_effect_key_chirho,
        digest_chirho('d'),
    )
}

/// Sign an intent whose journal cut names an EXPLICIT predecessor digest.
///
/// `reducer_chirho` binds `intent.journal_cut.tail_record_digest` to the holding record's `prev`
/// (reducer_chirho.rs:679), so a hold that sits anywhere other than immediately after the fork
/// needs its intent cut moved with it. Added rather than changing
/// [`signed_intent_warrant_chirho`]'s signature: that helper has 29 call sites, and none of them are
/// asking this question.
pub(super) fn signed_intent_warrant_at_tail_chirho(
    signer_chirho: &FakeIntentSignerChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    unique_chirho: char,
    hold_seq_chirho: u64,
    original_effect_key_chirho: Option<String>,
    tail_record_digest_chirho: DigestChirho,
) -> (DigestChirho, String) {
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: EffectIntentJournalCutChirho {
                journal_genesis_digest_chirho: DigestChirho(
                    identity_chirho.losing_journal_genesis_digest_chirho.clone(),
                ),
                tail_seq_chirho: hold_seq_chirho.checked_sub(1).unwrap(),
                tail_record_digest_chirho,
                tail_hlc_chirho: HlcChirho {
                    physical_ms_chirho: hold_seq_chirho.checked_sub(1).unwrap(),
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
                kind_id_chirho: plan_kind_id_chirho(),
                kind_policy_ref_chirho: plan_kind_policy_ref_chirho(),
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: plan_payer_account_chirho(),
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::PlatformChirho,
            original_effect_key_chirho,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signer_chirho,
    )
    .unwrap();
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
    // The projection holds the MINIMAL WARRANT, never the intent line. The intent is still what is
    // signed and journaled; this helper hands back the bytes that legitimately go on the public
    // side, so a fixture cannot accidentally seed the projection with an intent again.
    let warrant_chirho = sign_minimal_warrant_chirho(
        minimal_warrant_from_intent_chirho(&intent_chirho).unwrap(),
        signer_chirho,
    )
    .unwrap();
    let line_chirho = canonical_minimal_warrant_line_chirho(&warrant_chirho).unwrap();
    (intent_ref_chirho, line_chirho)
}

fn signed_terminal_chirho(
    signer_chirho: &FakeTerminalSignerChirho,
    intent_ref_chirho: &DigestChirho,
    unique_chirho: char,
    committed_chirho: bool,
) -> (DigestChirho, String) {
    let outcome_chirho = sign_effect_terminal_outcome_chirho(
        EffectTerminalOutcomeChirho {
            schema_chirho: EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO.to_owned(),
            intent_ref_chirho: intent_ref_chirho.clone(),
            provider_evidence_ref_chirho: digest_chirho(unique_chirho),
            disposition_chirho: if committed_chirho {
                EffectTerminalDispositionChirho::CommittedChirho {
                    result_ref_chirho: digest_chirho(unique_chirho),
                }
            } else {
                EffectTerminalDispositionChirho::DefiniteNoEffectChirho
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

fn plan_kind_id_chirho() -> AssetKindIdChirho {
    AssetKindIdChirho("gd7-plan-kind-chirho".to_owned())
}

fn plan_kind_policy_ref_chirho() -> AssetKindRefChirho {
    AssetKindRefChirho(digest_chirho('c'))
}

pub(super) fn plan_payer_account_chirho() -> AccountIdChirho {
    AccountIdChirho {
        owner_chirho: "gd7-plan-payer-chirho".to_owned(),
        kind_id_chirho: plan_kind_id_chirho(),
    }
}

fn plan_leg_chirho(
    account_chirho: AccountIdChirho,
    delta_chirho: LegDeltaChirho,
) -> LedgerLegChirho {
    LedgerLegChirho {
        account_chirho,
        kind_policy_ref_chirho: plan_kind_policy_ref_chirho(),
        delta_chirho,
        amount_chirho: 10,
        post_chirho: LegPostStateChirho {
            credits_total_chirho: 10,
            debits_total_chirho: 0,
            held_chirho: 0,
        },
        counterpart_chirho: None,
    }
}

fn control_chirho(saga_id_chirho: DigestChirho) -> EscrowControlChirho {
    EscrowControlChirho {
        saga_id_chirho,
        step_chirho: 1,
    }
}

fn record_chirho(
    seq_chirho: u64,
    legs_chirho: Vec<LedgerLegChirho>,
    op_chirho: LedgerOpChirho,
    idempotency_key_chirho: String,
    provenance_chirho: Option<DigestChirho>,
) -> LedgerRecordChirho {
    LedgerRecordChirho {
        schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        format_version_chirho: LEDGER_FORMAT_VERSION_V1_CHIRHO,
        seq_chirho,
        prev_chirho: digest_chirho('d'),
        epoch_chirho: compose_writer_epoch_chirho(8, 0).unwrap(),
        hlc_chirho: HlcChirho {
            physical_ms_chirho: seq_chirho,
            logical_chirho: 0,
        },
        legs_chirho,
        op_chirho,
        idempotency_key_chirho,
        provenance_chirho,
        attribution_chirho: AttributionChirho::PlatformChirho,
        anchor_chirho: None,
        sig_chirho: "record-signature-chirho".to_owned(),
        key_id_chirho: "record-key-chirho".to_owned(),
    }
}

fn record_digest_chirho(record_chirho: &LedgerRecordChirho) -> String {
    let line_chirho = canonical_ledger_record_line_chirho(record_chirho).unwrap();
    stored_line_digest_chirho(&line_chirho).0
}

fn terminal_record_chirho(
    seq_chirho: u64,
    intent_ref_chirho: &DigestChirho,
    control_chirho: EscrowControlChirho,
    outcome_ref_chirho: DigestChirho,
    committed_chirho: bool,
) -> LedgerRecordChirho {
    let legs_chirho = if committed_chirho {
        vec![
            plan_leg_chirho(plan_payer_account_chirho(), LegDeltaChirho::FinalizeChirho),
            plan_leg_chirho(
                AccountIdChirho {
                    owner_chirho: "gd7-plan-settlement-chirho".to_owned(),
                    kind_id_chirho: plan_kind_id_chirho(),
                },
                LegDeltaChirho::CreditChirho,
            ),
        ]
    } else {
        vec![plan_leg_chirho(
            plan_payer_account_chirho(),
            LegDeltaChirho::ReleaseChirho,
        )]
    };
    record_chirho(
        seq_chirho,
        legs_chirho,
        if committed_chirho {
            LedgerOpChirho::EscrowFinalizeChirho { control_chirho }
        } else {
            LedgerOpChirho::EscrowReleaseChirho { control_chirho }
        },
        format!("{EFFECT_TERMINAL_KEY_PREFIX_CHIRHO}{}", intent_ref_chirho.0),
        Some(outcome_ref_chirho),
    )
}

pub(super) fn forward_hold_record_chirho(
    seq_chirho: u64,
    intent_ref_chirho: &DigestChirho,
) -> LedgerRecordChirho {
    record_chirho(
        seq_chirho,
        vec![plan_leg_chirho(
            plan_payer_account_chirho(),
            LegDeltaChirho::HoldChirho,
        )],
        LedgerOpChirho::EscrowHoldChirho {
            control_chirho: control_chirho(intent_ref_chirho.clone()),
        },
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}", intent_ref_chirho.0),
        Some(intent_ref_chirho.clone()),
    )
}

#[test]
fn newest_first_markers_resolve_cross_page_holds_without_an_open_hold_map_chirho() {
    let (root_chirho, storage_chirho) = temp_storage_chirho("newest-first");
    let identity_chirho = identity_chirho();
    let identity_digest_chirho =
        crate::reconciliation_chirho::gd7_reconciliation_identity_digest_chirho(&identity_chirho)
            .unwrap();
    let held_signer_chirho = FakePlanSignerChirho {
        key_id_chirho: identity_chirho.held_node_chirho.clone(),
        secret_chirho: [0x41; 32],
    };
    let intent_signer_chirho = FakeIntentSignerChirho {
        secret_chirho: [0x51; 32],
    };
    let terminal_signer_chirho = FakeTerminalSignerChirho {
        secret_chirho: [0x61; 32],
    };
    let evidence_store_chirho = RootPublicEffectEvidenceStoreChirho::new_chirho(&root_chirho);
    let (committed_ref_chirho, committed_line_chirho) =
        signed_intent_warrant_chirho(&intent_signer_chirho, &identity_chirho, '1', 13, None);
    let (released_ref_chirho, released_line_chirho) =
        signed_intent_warrant_chirho(&intent_signer_chirho, &identity_chirho, '2', 12, None);
    let (unresolved_ref_chirho, unresolved_line_chirho) =
        signed_intent_warrant_chirho(&intent_signer_chirho, &identity_chirho, '3', 11, None);
    for (intent_ref_chirho, line_chirho) in [
        (&committed_ref_chirho, committed_line_chirho),
        (&released_ref_chirho, released_line_chirho),
        (&unresolved_ref_chirho, unresolved_line_chirho),
    ] {
        evidence_store_chirho
            .store_line_chirho(
                PublicEffectEvidenceKindChirho::WarrantChirho,
                &intent_ref_chirho.0,
                line_chirho.as_bytes(),
            )
            .unwrap();
    }
    let (committed_outcome_ref_chirho, committed_outcome_line_chirho) =
        signed_terminal_chirho(&terminal_signer_chirho, &committed_ref_chirho, 'e', true);
    let (released_outcome_ref_chirho, released_outcome_line_chirho) =
        signed_terminal_chirho(&terminal_signer_chirho, &released_ref_chirho, 'f', false);
    for (outcome_ref_chirho, line_chirho) in [
        (&committed_outcome_ref_chirho, committed_outcome_line_chirho),
        (&released_outcome_ref_chirho, released_outcome_line_chirho),
    ] {
        evidence_store_chirho
            .store_line_chirho(
                PublicEffectEvidenceKindChirho::TerminalChirho,
                &outcome_ref_chirho.0,
                line_chirho.as_bytes(),
            )
            .unwrap();
    }
    let evidence_chirho = RootGd7EffectEvidenceReaderChirho::new_chirho(&root_chirho);

    let committed_terminal_chirho = terminal_record_chirho(
        15,
        &committed_ref_chirho,
        control_chirho(committed_ref_chirho.clone()),
        committed_outcome_ref_chirho,
        true,
    );
    let released_terminal_chirho = terminal_record_chirho(
        14,
        &released_ref_chirho,
        control_chirho(released_ref_chirho.clone()),
        released_outcome_ref_chirho,
        false,
    );
    let terminal_records_chirho = [
        (
            record_digest_chirho(&committed_terminal_chirho),
            committed_terminal_chirho,
        ),
        (
            record_digest_chirho(&released_terminal_chirho),
            released_terminal_chirho,
        ),
    ];
    let reduced_terminals_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &effect_proof_ports_chirho(
            &evidence_chirho,
            &intent_signer_chirho,
            &terminal_signer_chirho,
        ),
        &identity_chirho,
        &identity_digest_chirho,
        terminal_records_chirho
            .iter()
            .map(|(digest_chirho, record_chirho)| (digest_chirho.as_str(), record_chirho)),
    )
    .unwrap();
    assert_eq!(
        reduced_terminals_chirho
            .fact_counts_chirho
            .committed_terminal_count_chirho,
        1
    );
    assert_eq!(
        reduced_terminals_chirho
            .fact_counts_chirho
            .definite_no_effect_terminal_count_chirho,
        1
    );
    assert_eq!(
        reduced_terminals_chirho
            .obligations_newest_first_chirho
            .len(),
        1
    );
    assert_eq!(
        reduced_terminals_chirho.obligations_newest_first_chirho[0].kind_chirho,
        Gd7EffectPlanObligationKindChirho::CommittedOnLosingForkChirho
    );
    assert_eq!(
        reduced_terminals_chirho
            .terminal_marker_object_digests_newest_first_chirho
            .len(),
        2
    );

    let committed_hold_chirho = forward_hold_record_chirho(13, &committed_ref_chirho);
    let released_hold_chirho = forward_hold_record_chirho(12, &released_ref_chirho);
    let unresolved_hold_chirho = forward_hold_record_chirho(11, &unresolved_ref_chirho);
    let hold_records_chirho = [
        (
            record_digest_chirho(&committed_hold_chirho),
            committed_hold_chirho,
        ),
        (
            record_digest_chirho(&released_hold_chirho),
            released_hold_chirho,
        ),
        (
            record_digest_chirho(&unresolved_hold_chirho),
            unresolved_hold_chirho,
        ),
    ];
    let reduced_holds_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &effect_proof_ports_chirho(
            &evidence_chirho,
            &intent_signer_chirho,
            &terminal_signer_chirho,
        ),
        &identity_chirho,
        &identity_digest_chirho,
        hold_records_chirho
            .iter()
            .map(|(digest_chirho, record_chirho)| (digest_chirho.as_str(), record_chirho)),
    )
    .unwrap();
    assert_eq!(
        reduced_holds_chirho
            .fact_counts_chirho
            .resolved_hold_count_chirho,
        2
    );
    assert_eq!(
        reduced_holds_chirho
            .fact_counts_chirho
            .unresolved_hold_count_chirho,
        1
    );
    assert_eq!(
        reduced_holds_chirho.obligations_newest_first_chirho.len(),
        1
    );
    assert_eq!(
        reduced_holds_chirho.obligations_newest_first_chirho[0].kind_chirho,
        Gd7EffectPlanObligationKindChirho::InDoubtHoldOnLosingForkChirho
    );
    assert_eq!(
        reduced_holds_chirho.obligations_newest_first_chirho[0].intent_ref_chirho,
        unresolved_ref_chirho
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn persisting_marker_signs_once_retry_reuses_and_tamper_fails_chirho() {
    let (root_chirho, storage_chirho) = temp_storage_chirho("marker-tamper");
    let identity_chirho = identity_chirho();
    let identity_digest_chirho =
        crate::reconciliation_chirho::gd7_reconciliation_identity_digest_chirho(&identity_chirho)
            .unwrap();
    let base_held_signer_chirho = FakePlanSignerChirho {
        key_id_chirho: identity_chirho.held_node_chirho.clone(),
        secret_chirho: [0x42; 32],
    };
    let held_signer_chirho = CountingPlanSignerChirho::new_chirho(&base_held_signer_chirho);
    let intent_signer_chirho = FakeIntentSignerChirho {
        secret_chirho: [0x52; 32],
    };
    let terminal_signer_chirho = FakeTerminalSignerChirho {
        secret_chirho: [0x62; 32],
    };
    let (intent_ref_chirho, intent_line_chirho) =
        signed_intent_warrant_chirho(&intent_signer_chirho, &identity_chirho, '1', 14, None);
    let (outcome_ref_chirho, outcome_line_chirho) =
        signed_terminal_chirho(&terminal_signer_chirho, &intent_ref_chirho, 'e', true);
    let evidence_chirho = MemoryEffectEvidenceChirho {
        lines_chirho: [(intent_ref_chirho.0.clone(), intent_line_chirho)]
            .into_iter()
            .collect(),
        terminal_lines_chirho: [(outcome_ref_chirho.0.clone(), outcome_line_chirho)]
            .into_iter()
            .collect(),
    };
    let terminal_chirho = terminal_record_chirho(
        15,
        &intent_ref_chirho,
        control_chirho(intent_ref_chirho.clone()),
        outcome_ref_chirho,
        true,
    );
    let terminal_digest_chirho = record_digest_chirho(&terminal_chirho);
    let marker_path_chirho =
        gd7_terminal_marker_path_chirho(&identity_digest_chirho, &intent_ref_chirho).unwrap();
    assert_eq!(
        reverify_record_inputs_read_only_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &effect_proof_ports_chirho(
                &evidence_chirho,
                &intent_signer_chirho,
                &terminal_signer_chirho,
            ),
            &identity_chirho,
            &identity_digest_chirho,
            [(terminal_digest_chirho.as_str(), &terminal_chirho)],
        )
        .unwrap_err(),
        Gd7PlanRefusalChirho::MissingTerminalMarkerChirho
    );
    assert_eq!(
        storage_chirho
            .object_len_chirho(&marker_path_chirho)
            .unwrap(),
        None,
        "read-only plan verification must not recreate a missing terminal marker"
    );
    assert_eq!(
        held_signer_chirho.sign_count_chirho(),
        0,
        "the verifier-only read path must not call the sign method"
    );
    let reduce_terminal_chirho = || {
        reduce_record_inputs_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &effect_proof_ports_chirho(
                &evidence_chirho,
                &intent_signer_chirho,
                &terminal_signer_chirho,
            ),
            &identity_chirho,
            &identity_digest_chirho,
            [(terminal_digest_chirho.as_str(), &terminal_chirho)],
        )
        .unwrap()
    };
    let first_chirho = reduce_terminal_chirho();
    assert_eq!(
        held_signer_chirho.sign_count_chirho(),
        1,
        "the persisting path must sign the newly durable terminal marker exactly once"
    );
    let retry_chirho = reduce_terminal_chirho();
    assert_eq!(retry_chirho, first_chirho);
    assert_eq!(
        held_signer_chirho.sign_count_chirho(),
        1,
        "retry must verify and reuse the durable marker without signing a replacement"
    );

    let marker_bytes_chirho = storage_chirho
        .read_all_chirho(&marker_path_chirho)
        .unwrap()
        .unwrap();
    let mut marker_chirho: Gd7TerminalMarkerChirho =
        serde_json::from_slice(&marker_bytes_chirho).unwrap();
    marker_chirho.sig_chirho.replace_range(0..1, "z");
    storage_chirho
        .atomic_write_chirho(
            &marker_path_chirho,
            &serde_json::to_vec(&marker_chirho).unwrap(),
        )
        .unwrap();
    let hold_chirho = forward_hold_record_chirho(14, &intent_ref_chirho);
    let hold_digest_chirho = record_digest_chirho(&hold_chirho);
    assert_eq!(
        reduce_record_inputs_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &effect_proof_ports_chirho(
                &evidence_chirho,
                &intent_signer_chirho,
                &terminal_signer_chirho,
            ),
            &identity_chirho,
            &identity_digest_chirho,
            [(hold_digest_chirho.as_str(), &hold_chirho)],
        )
        .unwrap_err(),
        Gd7PlanRefusalChirho::InvalidTerminalMarkerSignatureChirho
    );
    assert_eq!(
        held_signer_chirho.sign_count_chirho(),
        1,
        "tampered durable state must fail verification before any replacement signature"
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn intent_evidence_is_required_and_lineage_mismatch_fails_closed_chirho() {
    let (root_chirho, storage_chirho) = temp_storage_chirho("intent-binding");
    let identity_chirho = identity_chirho();
    let identity_digest_chirho =
        crate::reconciliation_chirho::gd7_reconciliation_identity_digest_chirho(&identity_chirho)
            .unwrap();
    let held_signer_chirho = FakePlanSignerChirho {
        key_id_chirho: identity_chirho.held_node_chirho.clone(),
        secret_chirho: [0x43; 32],
    };
    let intent_signer_chirho = FakeIntentSignerChirho {
        secret_chirho: [0x53; 32],
    };
    let terminal_signer_chirho = FakeTerminalSignerChirho {
        secret_chirho: [0x63; 32],
    };
    let original_effect_key_chirho =
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}", digest_chirho('e').0);
    let (compensation_ref_chirho, compensation_line_chirho) = signed_intent_warrant_chirho(
        &intent_signer_chirho,
        &identity_chirho,
        '1',
        14,
        Some(original_effect_key_chirho.clone()),
    );
    let forged_forward_hold_chirho = record_chirho(
        14,
        vec![plan_leg_chirho(
            plan_payer_account_chirho(),
            LegDeltaChirho::HoldChirho,
        )],
        LedgerOpChirho::EscrowHoldChirho {
            control_chirho: control_chirho(compensation_ref_chirho.clone()),
        },
        format!(
            "{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}",
            compensation_ref_chirho.0
        ),
        Some(compensation_ref_chirho.clone()),
    );
    let forged_digest_chirho = record_digest_chirho(&forged_forward_hold_chirho);
    assert_eq!(
        reduce_record_inputs_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &effect_proof_ports_chirho(
                &MemoryEffectEvidenceChirho::default(),
                &intent_signer_chirho,
                &terminal_signer_chirho,
            ),
            &identity_chirho,
            &identity_digest_chirho,
            [(forged_digest_chirho.as_str(), &forged_forward_hold_chirho)],
        )
        .unwrap_err(),
        Gd7PlanRefusalChirho::MissingIntentEvidenceChirho
    );
    let evidence_chirho = MemoryEffectEvidenceChirho {
        lines_chirho: [(compensation_ref_chirho.0.clone(), compensation_line_chirho)]
            .into_iter()
            .collect(),
        terminal_lines_chirho: BTreeMap::new(),
    };
    assert_eq!(
        reduce_record_inputs_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &effect_proof_ports_chirho(
                &evidence_chirho,
                &intent_signer_chirho,
                &terminal_signer_chirho,
            ),
            &identity_chirho,
            &identity_digest_chirho,
            [(forged_digest_chirho.as_str(), &forged_forward_hold_chirho)],
        )
        .unwrap_err(),
        Gd7PlanRefusalChirho::EffectLineageMismatchChirho
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn intent_economics_and_terminal_authority_mismatches_fail_closed_chirho() {
    let (root_chirho, storage_chirho) = temp_storage_chirho("effect-authority-binding");
    let identity_chirho = identity_chirho();
    let identity_digest_chirho =
        crate::reconciliation_chirho::gd7_reconciliation_identity_digest_chirho(&identity_chirho)
            .unwrap();
    let held_signer_chirho = FakePlanSignerChirho {
        key_id_chirho: identity_chirho.held_node_chirho.clone(),
        secret_chirho: [0x44; 32],
    };
    let intent_signer_chirho = FakeIntentSignerChirho {
        secret_chirho: [0x54; 32],
    };
    let terminal_signer_chirho = FakeTerminalSignerChirho {
        secret_chirho: [0x64; 32],
    };
    let (intent_ref_chirho, intent_line_chirho) =
        signed_intent_warrant_chirho(&intent_signer_chirho, &identity_chirho, '1', 14, None);

    let mut wrong_hold_chirho = forward_hold_record_chirho(14, &intent_ref_chirho);
    wrong_hold_chirho.legs_chirho[0].amount_chirho = 11;
    let wrong_hold_digest_chirho = record_digest_chirho(&wrong_hold_chirho);
    let intent_only_evidence_chirho = MemoryEffectEvidenceChirho {
        lines_chirho: [(intent_ref_chirho.0.clone(), intent_line_chirho.clone())]
            .into_iter()
            .collect(),
        terminal_lines_chirho: BTreeMap::new(),
    };
    assert_eq!(
        reduce_record_inputs_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &effect_proof_ports_chirho(
                &intent_only_evidence_chirho,
                &intent_signer_chirho,
                &terminal_signer_chirho,
            ),
            &identity_chirho,
            &identity_digest_chirho,
            [(wrong_hold_digest_chirho.as_str(), &wrong_hold_chirho)],
        )
        .unwrap_err(),
        Gd7PlanRefusalChirho::IntentEvidenceMismatchChirho
    );

    let (committed_outcome_ref_chirho, committed_outcome_line_chirho) =
        signed_terminal_chirho(&terminal_signer_chirho, &intent_ref_chirho, 'e', true);
    let committed_terminal_chirho = terminal_record_chirho(
        15,
        &intent_ref_chirho,
        control_chirho(intent_ref_chirho.clone()),
        committed_outcome_ref_chirho.clone(),
        true,
    );
    let committed_terminal_digest_chirho = record_digest_chirho(&committed_terminal_chirho);
    assert_eq!(
        reduce_record_inputs_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &effect_proof_ports_chirho(
                &intent_only_evidence_chirho,
                &intent_signer_chirho,
                &terminal_signer_chirho,
            ),
            &identity_chirho,
            &identity_digest_chirho,
            [(
                committed_terminal_digest_chirho.as_str(),
                &committed_terminal_chirho,
            )],
        )
        .unwrap_err(),
        Gd7PlanRefusalChirho::MissingTerminalEvidenceChirho
    );

    let (release_outcome_ref_chirho, release_outcome_line_chirho) =
        signed_terminal_chirho(&terminal_signer_chirho, &intent_ref_chirho, 'f', false);
    let mismatched_terminal_chirho = terminal_record_chirho(
        15,
        &intent_ref_chirho,
        control_chirho(intent_ref_chirho.clone()),
        release_outcome_ref_chirho.clone(),
        true,
    );
    let mismatched_terminal_digest_chirho = record_digest_chirho(&mismatched_terminal_chirho);
    let mismatched_evidence_chirho = MemoryEffectEvidenceChirho {
        lines_chirho: [(intent_ref_chirho.0.clone(), intent_line_chirho)]
            .into_iter()
            .collect(),
        terminal_lines_chirho: [
            (
                committed_outcome_ref_chirho.0,
                committed_outcome_line_chirho,
            ),
            (release_outcome_ref_chirho.0, release_outcome_line_chirho),
        ]
        .into_iter()
        .collect(),
    };
    assert_eq!(
        reduce_record_inputs_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &effect_proof_ports_chirho(
                &mismatched_evidence_chirho,
                &intent_signer_chirho,
                &terminal_signer_chirho,
            ),
            &identity_chirho,
            &identity_digest_chirho,
            [(
                mismatched_terminal_digest_chirho.as_str(),
                &mismatched_terminal_chirho,
            )],
        )
        .unwrap_err(),
        Gd7PlanRefusalChirho::TerminalEvidenceMismatchChirho
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

/// A load-counting evidence reader. The COUNT is the instrument: an orphan is not merely "ignored",
/// it is never asked for, and only a counter can tell those two apart.
struct CountingEffectEvidenceChirho {
    inner_chirho: MemoryEffectEvidenceChirho,
    intent_loads_chirho: AtomicU64,
}

impl Gd7EffectEvidenceReaderPortChirho for CountingEffectEvidenceChirho {
    fn load_intent_line_bounded_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
        maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.intent_loads_chirho.fetch_add(1, Ordering::Relaxed);
        self.inner_chirho
            .load_intent_line_bounded_chirho(intent_ref_chirho, maximum_bytes_chirho)
    }

    fn load_terminal_line_bounded_chirho(
        &self,
        outcome_ref_chirho: &DigestChirho,
        maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.inner_chirho
            .load_terminal_line_bounded_chirho(outcome_ref_chirho, maximum_bytes_chirho)
    }
}

/// AN ORPHAN WARRANT IS NOT A REVEAL PATH, and not a commitment claim.
///
/// # The hazard this exists for
///
/// A warrant is published BEFORE the money append it warrants, so a crash between the two leaves a
/// warrant on disk with no journal record — deliberately, because the reverse residue (a settled
/// record with no warrant) cannot be reconciled at all. The store's consumption contract says that
/// residue is safe for exactly one structural reason: **every reader resolves a warrant by a ref it
/// already took from a record it found in the journal.** An orphan is therefore unreachable rather
/// than merely ignored, and this arm is what stops that sentence from being prose.
///
/// # What is asserted, and why each assertion is not vacuous
///
/// The warrant really is on disk (positive control — without it every claim below would hold
/// against an empty store). Reduced against NO records, the reducer yields nothing, and the evidence
/// reader is **never called even once** — the orphan is not filtered out downstream, it is never
/// reached. Reduced against an UNRELATED record, the reducer resolves that record's own coordinate
/// and still produces no obligation naming the orphan: a present-but-unclaimed warrant does not
/// attach itself to whatever else is being reconciled.
///
/// IF THIS GOES RED with a nonzero load count on the no-records case, something has started
/// ENUMERATING the projection rather than point-reading it by a record's ref. That is the exact
/// move the store's consumption contract forbids, and it would turn every inert orphan into a
/// commitment claim. Do not relax the count — find the new enumeration.
#[test]
fn an_orphan_warrant_is_unreachable_and_reveals_nothing_chirho() {
    let (root_chirho, storage_chirho) = temp_storage_chirho("orphan-warrant");
    let identity_chirho = identity_chirho();
    let identity_digest_chirho =
        crate::reconciliation_chirho::gd7_reconciliation_identity_digest_chirho(&identity_chirho)
            .unwrap();
    let held_signer_chirho = FakePlanSignerChirho {
        key_id_chirho: identity_chirho.held_node_chirho.clone(),
        secret_chirho: [0x43; 32],
    };
    let intent_signer_chirho = FakeIntentSignerChirho {
        secret_chirho: [0x53; 32],
    };
    let terminal_signer_chirho = FakeTerminalSignerChirho {
        secret_chirho: [0x63; 32],
    };

    // The orphan: a real, verifiable warrant whose append never happened.
    let (orphan_ref_chirho, orphan_line_chirho) =
        signed_intent_warrant_chirho(&intent_signer_chirho, &identity_chirho, '5', 21, None);
    let evidence_chirho = CountingEffectEvidenceChirho {
        inner_chirho: MemoryEffectEvidenceChirho {
            lines_chirho: [(orphan_ref_chirho.0.clone(), orphan_line_chirho.clone())]
                .into_iter()
                .collect(),
            terminal_lines_chirho: BTreeMap::new(),
        },
        intent_loads_chirho: AtomicU64::new(0),
    };

    // POSITIVE CONTROL: the orphan is genuinely present and genuinely loadable BY REF. Every
    // absence assertion below would pass just as well against an empty store without this.
    assert_eq!(
        evidence_chirho
            .inner_chirho
            .load_intent_line_bounded_chirho(&orphan_ref_chirho, 64 * 1024)
            .unwrap()
            .map(|bytes_chirho| String::from_utf8(bytes_chirho).unwrap()),
        Some(orphan_line_chirho.clone()),
        "the fixture must actually have an orphan warrant on the evidence surface"
    );

    // NO RECORDS: nothing reduces, and the projection is never even consulted.
    let empty_reduction_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &effect_proof_ports_chirho(
            &evidence_chirho,
            &intent_signer_chirho,
            &terminal_signer_chirho,
        ),
        &identity_chirho,
        &identity_digest_chirho,
        [],
    )
    .expect("an empty page reduces without error");
    assert!(
        empty_reduction_chirho
            .obligations_newest_first_chirho
            .is_empty(),
        "an orphan warrant must not mint an obligation"
    );
    assert_eq!(
        evidence_chirho.intent_loads_chirho.load(Ordering::Relaxed),
        0,
        "the orphan was ASKED FOR -- a reader is reaching the projection without a record's ref"
    );

    // AN UNRELATED RECORD: its own coordinate resolves, the orphan still does not attach.
    let (other_ref_chirho, other_line_chirho) =
        signed_intent_warrant_chirho(&intent_signer_chirho, &identity_chirho, '6', 22, None);
    assert_ne!(
        other_ref_chirho, orphan_ref_chirho,
        "the two fixtures must be distinct coordinates or this arm proves nothing"
    );
    let paired_evidence_chirho = CountingEffectEvidenceChirho {
        inner_chirho: MemoryEffectEvidenceChirho {
            lines_chirho: [
                (orphan_ref_chirho.0.clone(), orphan_line_chirho.clone()),
                (other_ref_chirho.0.clone(), other_line_chirho),
            ]
            .into_iter()
            .collect(),
            terminal_lines_chirho: BTreeMap::new(),
        },
        intent_loads_chirho: AtomicU64::new(0),
    };
    let unrelated_hold_chirho = record_chirho(
        22,
        vec![plan_leg_chirho(
            plan_payer_account_chirho(),
            LegDeltaChirho::HoldChirho,
        )],
        LedgerOpChirho::EscrowHoldChirho {
            control_chirho: control_chirho(other_ref_chirho.clone()),
        },
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}", other_ref_chirho.0),
        Some(other_ref_chirho.clone()),
    );
    let unrelated_digest_chirho = record_digest_chirho(&unrelated_hold_chirho);
    let reduction_chirho = reduce_record_inputs_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &effect_proof_ports_chirho(
            &paired_evidence_chirho,
            &intent_signer_chirho,
            &terminal_signer_chirho,
        ),
        &identity_chirho,
        &identity_digest_chirho,
        [(unrelated_digest_chirho.as_str(), &unrelated_hold_chirho)],
    )
    .expect("the unrelated hold reduces on its own coordinate");
    assert!(
        !format!("{reduction_chirho:?}").contains(&orphan_ref_chirho.0),
        "the orphan's coordinate appeared in a reduction it has no record for: {reduction_chirho:?}"
    );
    // POSITIVE CONTROL ON THE INSTRUMENT ITSELF. A counter that can never increment would make the
    // `== 0` assertion above true no matter what the reducer did. This proves the same counter, on
    // the same port, does move when a record legitimately resolves its own coordinate — so the zero
    // is a measurement rather than a property of the fake.
    assert!(
        paired_evidence_chirho
            .intent_loads_chirho
            .load(Ordering::Relaxed)
            > 0,
        "the load counter never incremented even for a record that HAS a warrant -- the counter is \
         not measuring anything, so the zero-load assertion above proves nothing"
    );

    fs::remove_dir_all(root_chirho).unwrap();
}
