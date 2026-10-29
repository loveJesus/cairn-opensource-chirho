// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::temp_root_chirho;
use crate::reconciliation_chirho::{
    gd7_reconciliation_identity_digest_chirho, winner_first_record_path_chirho,
    winner_fork_witness_path_chirho, Gd7ForkCoordinateChirho, Gd7JournalTailCoordinateChirho,
    Gd7LedgerRecordVerifierPortChirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    Gd7WinnerFirstRecordIndexChirho, Gd7WinnerForkWitnessChirho, Gd7WinnerWitnessReaderChirho,
    Gd7WinnerWitnessRefusalChirho, Gd7WinnerWitnessStoreChirho,
    PinnedGd7LedgerRecordVerifierChirho, MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO,
};
use crate::{FsLedgerStorageChirho, SystemLedgerClockChirho};
use anyhow::Result;
use cairn_effect_commit_chirho::intent_chirho::EffectIntentSignerPortChirho;
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::epoch_first_record_chirho::EpochFirstRecordEvidenceChirho;
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::VerifiedLosingJournalTailChirho;
use cairn_ledger_log_chirho::ports_chirho::{LedgerSignerPortChirho, LedgerStoragePortChirho};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, CrossZoneAnchorChirho, HlcChirho, LedgerOpChirho, LedgerRecordChirho,
    LegDeltaChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    LEDGER_FORMAT_VERSION_V1_CHIRHO, LEDGER_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;

pub(super) struct FakeGd7ControlSignerChirho {
    key_id_chirho: String,
    secret_chirho: [u8; 32],
}

impl FakeGd7ControlSignerChirho {
    pub(super) fn new_chirho(key_id_chirho: String, secret_chirho: u8) -> Self {
        Self {
            key_id_chirho,
            secret_chirho: [secret_chirho; 32],
        }
    }

    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(line_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl Gd7ReconciliationVerifierPortChirho for FakeGd7ControlSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(canonical_unsigned_chirho) == sig_chirho
    }
}

impl Gd7ReconciliationSignerPortChirho for FakeGd7ControlSignerChirho {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(canonical_unsigned_chirho))
    }
}

pub(super) struct ClosedGd7IntentVerifierChirho;

impl EffectIntentSignerPortChirho for ClosedGd7IntentVerifierChirho {
    fn sign_chirho(&self, _signed_content_line_chirho: &str) -> Result<String> {
        anyhow::bail!("the read-only plan reducer must not sign effect intents")
    }

    fn key_id_chirho(&self) -> String {
        "closed-gd7-intent-verifier-chirho".to_owned()
    }

    fn verify_chirho(&self, _signed_content_line_chirho: &str, _sig_chirho: &str) -> bool {
        false
    }
}

pub(super) struct ClosedGd7TerminalVerifierChirho;

impl EffectTerminalSignerPortChirho for ClosedGd7TerminalVerifierChirho {
    fn sign_chirho(&self, _signed_content_line_chirho: &str) -> Result<String> {
        anyhow::bail!("the read-only plan reducer must not sign effect terminals")
    }

    fn key_id_chirho(&self) -> String {
        "closed-gd7-terminal-verifier-chirho".to_owned()
    }

    fn verify_chirho(&self, _signed_content_line_chirho: &str, _sig_chirho: &str) -> bool {
        false
    }
}

pub(crate) struct FakeWinnerLedgerSignerChirho {
    secret_chirho: [u8; 32],
}

impl FakeWinnerLedgerSignerChirho {
    pub(crate) fn new_chirho(secret_chirho: u8) -> Self {
        Self {
            secret_chirho: [secret_chirho; 32],
        }
    }

    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(line_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl LedgerSignerPortChirho for FakeWinnerLedgerSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        "winner-ledger-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

impl Gd7LedgerRecordVerifierPortChirho for FakeWinnerLedgerSignerChirho {
    fn key_id_chirho(&self) -> String {
        LedgerSignerPortChirho::key_id_chirho(self)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        LedgerSignerPortChirho::verify_chirho(self, signed_content_line_chirho, sig_chirho)
    }
}

pub(super) struct FakeWinnerLedgerVerifierOnlyChirho {
    key_id_chirho: String,
    secret_chirho: [u8; 32],
}

impl FakeWinnerLedgerVerifierOnlyChirho {
    pub(super) fn new_chirho(key_id_chirho: &str, secret_chirho: u8) -> Self {
        Self {
            key_id_chirho: key_id_chirho.to_owned(),
            secret_chirho: [secret_chirho; 32],
        }
    }

    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(line_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl Gd7LedgerRecordVerifierPortChirho for FakeWinnerLedgerVerifierOnlyChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

#[test]
fn pinned_winner_ledger_verifier_never_requires_the_remote_signing_key_chirho() {
    let signing_key_chirho = SigningKey::from_bytes(&[0x5a; 32]);
    let public_key_hex_chirho = signing_key_chirho
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect();
    let verifier_chirho = PinnedGd7LedgerRecordVerifierChirho::new_chirho(
        "winner-journal-key-chirho".to_owned(),
        public_key_hex_chirho,
    )
    .unwrap();
    let signed_content_chirho = "{\"schema_chirho\":\"ledger-record-v1-chirho\"}";
    let signature_chirho = signing_key_chirho
        .sign(signed_content_chirho.as_bytes())
        .to_bytes()
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect::<String>();

    assert_eq!(
        Gd7LedgerRecordVerifierPortChirho::key_id_chirho(&verifier_chirho),
        "winner-journal-key-chirho"
    );
    assert!(Gd7LedgerRecordVerifierPortChirho::verify_chirho(
        &verifier_chirho,
        signed_content_chirho,
        &signature_chirho,
    ));
    assert!(!Gd7LedgerRecordVerifierPortChirho::verify_chirho(
        &verifier_chirho,
        "{\"schema_chirho\":\"ledger-record-v1-chirho\",\"tampered_chirho\":true}",
        &signature_chirho,
    ));
}

pub(crate) struct ObservedTailMembershipChirho;

impl MembershipViewChirho for ObservedTailMembershipChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

pub(crate) struct ObservedTailKindRegistryChirho;

impl KindRegistryViewChirho for ObservedTailKindRegistryChirho {
    fn resolve_chirho(&self, _policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        KindResolutionChirho::CurrentChirho(KindPolicyViewChirho {
            kind_id_chirho: AssetKindIdChirho("gd7-observed-kind-chirho".to_owned()),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(1_000),
            },
            rounding_chirho: RoundingChirho::ExactChirho,
            settlement_owner_chirho: None,
            idempotency_window_chirho: None,
        })
    }
}

pub(crate) struct ObservedTailAuthorityChirho;

impl AuthorityVerifierViewChirho for ObservedTailAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::VerifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::VerifiedChirho
    }
}

pub(crate) fn digest_chirho(nibble_chirho: char) -> String {
    std::iter::repeat_n(nibble_chirho, 64).collect()
}

fn reconciliation_identity_chirho() -> Gd7ReconciliationIdentityChirho {
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "gd7-winner-witness-tenant-chirho".to_owned(),
    };
    Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        winner_node_chirho: digest_chirho('a'),
        held_node_chirho: digest_chirho('b'),
        winner_term_chirho: 9,
        losing_term_chirho: 8,
        winner_journal_genesis_digest_chirho: digest_chirho('2'),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(9, 2).unwrap(),
            seq_chirho: 12,
            record_digest_chirho: digest_chirho('3'),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(8, 0).unwrap(),
            seq_chirho: 5,
            record_digest_chirho: digest_chirho('4'),
        },
        losing_journal_genesis_digest_chirho: digest_chirho('2'),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(8, 3).unwrap(),
            seq_chirho: 10,
            record_digest_chirho: digest_chirho('6'),
        },
    }
}

pub(super) fn epoch_first_evidence_chirho(
    ledger_signer_chirho: &dyn LedgerSignerPortChirho,
    term_chirho: u64,
    local_generation_chirho: u64,
    inherited_term_chirho: u64,
    inherited_local_generation_chirho: u64,
    inherited_seq_chirho: u64,
    inherited_digest_chirho: &str,
) -> EpochFirstRecordEvidenceChirho {
    let mut record_chirho = LedgerRecordChirho {
        schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        format_version_chirho: LEDGER_FORMAT_VERSION_V1_CHIRHO,
        seq_chirho: inherited_seq_chirho + 1,
        prev_chirho: DigestChirho(inherited_digest_chirho.to_owned()),
        epoch_chirho: compose_writer_epoch_chirho(term_chirho, local_generation_chirho).unwrap(),
        hlc_chirho: HlcChirho {
            physical_ms_chirho: 10_000,
            logical_chirho: 0,
        },
        legs_chirho: Vec::new(),
        op_chirho: LedgerOpChirho::TransferChirho,
        idempotency_key_chirho: format!(
            "gd7-winner-first-{term_chirho}-{local_generation_chirho}-chirho"
        ),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
        anchor_chirho: Some(CrossZoneAnchorChirho {
            inherited_epoch_chirho: compose_writer_epoch_chirho(
                inherited_term_chirho,
                inherited_local_generation_chirho,
            )
            .unwrap(),
            inherited_seq_chirho,
            inherited_digest_chirho: DigestChirho(inherited_digest_chirho.to_owned()),
        }),
        sig_chirho: String::new(),
        key_id_chirho: ledger_signer_chirho.key_id_chirho(),
    };
    let signed_content_chirho = ledger_record_signed_content_line_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho = ledger_signer_chirho
        .sign_chirho(&signed_content_chirho)
        .unwrap();
    let canonical_line_chirho = canonical_ledger_record_line_chirho(&record_chirho).unwrap();
    EpochFirstRecordEvidenceChirho::from_canonical_record_line_chirho(
        canonical_line_chirho,
        ledger_signer_chirho,
    )
    .unwrap()
}

pub(super) fn open_storage_chirho(
    label_chirho: &str,
) -> (std::path::PathBuf, FsLedgerStorageChirho) {
    let root_chirho = temp_root_chirho(label_chirho);
    fs::create_dir_all(&root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();
    (root_chirho, storage_chirho)
}

pub(super) fn empty_verified_losing_tail_chirho(
    storage_chirho: &FsLedgerStorageChirho,
    ledger_signer_chirho: &FakeWinnerLedgerSignerChirho,
    label_chirho: &str,
) -> VerifiedLosingJournalTailChirho {
    let clock_chirho = SystemLedgerClockChirho;
    let membership_chirho = ObservedTailMembershipChirho;
    let kind_registry_chirho = ObservedTailKindRegistryChirho;
    let authority_chirho = ObservedTailAuthorityChirho;
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        JournalPortsChirho {
            storage_chirho,
            signer_chirho: ledger_signer_chirho,
            clock_chirho: &clock_chirho,
            membership_chirho: &membership_chirho,
            kind_registry_chirho: &kind_registry_chirho,
            authority_chirho: &authority_chirho,
        },
        cairn_ledger_log_chirho::ports_chirho::StoragePathChirho::new_chirho(format!(
            "journals-chirho/{label_chirho}.jsonl"
        )),
        ClusterIdChirho(format!("gd7-held-import-{label_chirho}-chirho")),
        0,
    )
    .unwrap();
    journal_chirho
        .append_chirho(AppendRequestChirho {
            op_chirho: LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho(digest_chirho('7')),
            },
            legs_chirho: vec![AppendLegRequestChirho {
                account_chirho: LogIdChirho::new_chirho(
                    "gd7-held-import-owner-chirho",
                    "gd7-observed-kind-chirho",
                ),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(digest_chirho('8'))),
                delta_chirho: LegDeltaChirho::CreditChirho,
                amount_chirho: 1,
                counterpart_chirho: None,
            }],
            idempotency_key_chirho: format!("gd7-held-import-{label_chirho}-chirho"),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
        })
        .unwrap();
    journal_chirho.verified_losing_tail_chirho()
}

pub(super) struct HeldWinnerImportFixtureChirho {
    pub(super) identity_chirho: Gd7ReconciliationIdentityChirho,
    pub(super) index_bytes_chirho: Vec<u8>,
    pub(super) witness_bytes_chirho: Vec<u8>,
}

/// The original entry point: one fixed tenant group, winner term 1.
///
/// Kept as a delegating wrapper so its existing callers are behaviourally byte-identical. The
/// constants it supplies were the ONLY shape available until the full-chain arm needed a witness
/// that matches a live resident's group and its bumped mesh term — see
/// [`held_winner_import_fixture_for_group_and_term_chirho`].
pub(super) fn held_winner_import_fixture_chirho(
    source_storage_chirho: &FsLedgerStorageChirho,
    control_signer_chirho: &FakeGd7ControlSignerChirho,
    ledger_signer_chirho: &FakeWinnerLedgerSignerChirho,
    verified_losing_tail_chirho: &VerifiedLosingJournalTailChirho,
) -> HeldWinnerImportFixtureChirho {
    held_winner_import_fixture_for_group_and_term_chirho(
        source_storage_chirho,
        control_signer_chirho,
        ledger_signer_chirho,
        verified_losing_tail_chirho,
        &ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "gd7-held-winner-import-tenant-chirho".to_owned(),
        },
        1,
    )
}

/// Seal a genuine winner-fork witness for an ARBITRARY group and winner term.
///
/// # WHY THE TERM AND GROUP HAD TO BECOME PARAMETERS
///
/// The lawful advance binds an EQUALITY between the witness's winner term and the resident's own
/// published Raft term, and it refuses a witness naming a different consistency group. A witness
/// pinned to term 1 and to its own tenant can therefore never authorize an advance on a live
/// resident, whose cell is born at its mesh term and bumped by a real election. That is exactly why
/// the full chain was unreachable: not a missing assertion, a missing fixture.
///
/// The losing side stays at term 0 by construction (`fork` epoch 0, and the losing tail is whatever
/// `verified_losing_tail_chirho` sealed), so `validate_identity_chirho`'s geo-term equalities hold
/// for any `winner_term_chirho >= 1`.
pub(super) fn held_winner_import_fixture_for_group_and_term_chirho(
    source_storage_chirho: &FsLedgerStorageChirho,
    control_signer_chirho: &FakeGd7ControlSignerChirho,
    ledger_signer_chirho: &FakeWinnerLedgerSignerChirho,
    verified_losing_tail_chirho: &VerifiedLosingJournalTailChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    winner_term_chirho: u64,
) -> HeldWinnerImportFixtureChirho {
    assert!(
        winner_term_chirho > 0,
        "the winner term must exceed the losing term 0, or validate_identity_chirho refuses the \
         identity before anything is sealed"
    );
    let losing_genesis_chirho = verified_losing_tail_chirho
        .identity_chirho()
        .genesis_digest_chirho()
        .0
        .clone();
    let mut identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(group_chirho).unwrap(),
        winner_node_chirho: control_signer_chirho.key_id_chirho(),
        held_node_chirho: digest_chirho('b'),
        winner_term_chirho,
        losing_term_chirho: 0,
        winner_journal_genesis_digest_chirho: losing_genesis_chirho.clone(),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(winner_term_chirho, 0).unwrap(),
            seq_chirho: 1,
            record_digest_chirho: digest_chirho('3'),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: 0,
            seq_chirho: 0,
            record_digest_chirho: losing_genesis_chirho.clone(),
        },
        losing_journal_genesis_digest_chirho: losing_genesis_chirho.clone(),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: verified_losing_tail_chirho.record_epoch_chirho(),
            seq_chirho: verified_losing_tail_chirho.coordinate_chirho().seq_chirho(),
            record_digest_chirho: verified_losing_tail_chirho
                .coordinate_chirho()
                .record_digest_chirho()
                .0
                .clone(),
        },
    };
    let evidence_chirho = epoch_first_evidence_chirho(
        ledger_signer_chirho,
        winner_term_chirho,
        0,
        0,
        0,
        0,
        &losing_genesis_chirho,
    );
    let source_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        source_storage_chirho,
        control_signer_chirho,
        ledger_signer_chirho,
    );
    let index_chirho = source_store_chirho
        .ensure_winner_first_record_chirho(
            &identity_chirho.consistency_group_digest_chirho,
            &identity_chirho.winner_node_chirho,
            identity_chirho.winner_term_chirho,
            &identity_chirho.winner_journal_genesis_digest_chirho,
            &evidence_chirho,
        )
        .unwrap();
    identity_chirho.winner_journal_tail_chirho = Gd7JournalTailCoordinateChirho {
        epoch_chirho: index_chirho.index_chirho().first_record_chirho.epoch_chirho,
        seq_chirho: index_chirho.index_chirho().first_record_chirho.seq_chirho,
        record_digest_chirho: index_chirho
            .index_chirho()
            .first_record_digest_chirho
            .clone(),
    };
    source_store_chirho
        .seal_winner_fork_witness_chirho(identity_chirho.clone(), &index_chirho)
        .unwrap();
    let index_path_chirho = winner_first_record_path_chirho(
        &identity_chirho.consistency_group_digest_chirho,
        identity_chirho.winner_term_chirho,
        &identity_chirho.winner_journal_genesis_digest_chirho,
    )
    .unwrap();
    let identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&identity_chirho).unwrap();
    let witness_path_chirho = winner_fork_witness_path_chirho(&identity_digest_chirho).unwrap();
    HeldWinnerImportFixtureChirho {
        identity_chirho,
        index_bytes_chirho: source_storage_chirho
            .read_all_chirho(&index_path_chirho)
            .unwrap()
            .unwrap(),
        witness_bytes_chirho: source_storage_chirho
            .read_all_chirho(&witness_path_chirho)
            .unwrap()
            .unwrap(),
    }
}

#[test]
fn held_import_persists_reloads_and_replays_exact_winner_observation_chirho() {
    let (source_root_chirho, source_storage_chirho) =
        open_storage_chirho("gd7-held-import-source-chirho");
    let (held_root_chirho, held_storage_chirho) =
        open_storage_chirho("gd7-held-import-destination-chirho");
    let control_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(digest_chirho('a'), 0x31);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x32);
    let losing_tail_chirho = empty_verified_losing_tail_chirho(
        &held_storage_chirho,
        &ledger_signer_chirho,
        "valid-chirho",
    );
    let fixture_chirho = held_winner_import_fixture_chirho(
        &source_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
        &losing_tail_chirho,
    );
    let reader_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &held_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );

    let imported_chirho = reader_chirho
        .import_authenticated_deposed_fork_observation_chirho(
            &fixture_chirho.identity_chirho,
            &fixture_chirho.index_bytes_chirho,
            &fixture_chirho.witness_bytes_chirho,
            &losing_tail_chirho,
        )
        .unwrap();
    let replayed_chirho = reader_chirho
        .import_authenticated_deposed_fork_observation_chirho(
            &fixture_chirho.identity_chirho,
            &fixture_chirho.index_bytes_chirho,
            &fixture_chirho.witness_bytes_chirho,
            &losing_tail_chirho,
        )
        .unwrap();

    assert_eq!(replayed_chirho, imported_chirho);
    assert_eq!(
        imported_chirho.identity_chirho(),
        &fixture_chirho.identity_chirho
    );
    assert_eq!(
        reader_chirho
            .load_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &losing_tail_chirho,
            )
            .unwrap(),
        imported_chirho
    );
    fs::remove_dir_all(source_root_chirho).unwrap();
    fs::remove_dir_all(held_root_chirho).unwrap();
}

#[test]
fn held_import_rejects_tampered_or_oversized_network_evidence_before_write_chirho() {
    let (source_root_chirho, source_storage_chirho) =
        open_storage_chirho("gd7-held-import-tamper-source-chirho");
    let (held_root_chirho, held_storage_chirho) =
        open_storage_chirho("gd7-held-import-tamper-destination-chirho");
    let control_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(digest_chirho('a'), 0x33);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x34);
    let losing_tail_chirho = empty_verified_losing_tail_chirho(
        &held_storage_chirho,
        &ledger_signer_chirho,
        "tamper-chirho",
    );
    let fixture_chirho = held_winner_import_fixture_chirho(
        &source_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
        &losing_tail_chirho,
    );
    let reader_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &held_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );
    let mut tampered_index_chirho: Gd7WinnerFirstRecordIndexChirho =
        serde_json::from_slice(&fixture_chirho.index_bytes_chirho).unwrap();
    tampered_index_chirho.sig_chirho = digest_chirho('e');
    assert_eq!(
        reader_chirho
            .import_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &serde_json::to_vec(&tampered_index_chirho).unwrap(),
                &fixture_chirho.witness_bytes_chirho,
                &losing_tail_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::InvalidIndexSignatureChirho
    );
    let mut tampered_witness_chirho: Gd7WinnerForkWitnessChirho =
        serde_json::from_slice(&fixture_chirho.witness_bytes_chirho).unwrap();
    tampered_witness_chirho.sig_chirho = digest_chirho('f');
    assert_eq!(
        reader_chirho
            .import_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &fixture_chirho.index_bytes_chirho,
                &serde_json::to_vec(&tampered_witness_chirho).unwrap(),
                &losing_tail_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::InvalidWitnessSignatureChirho
    );
    assert_eq!(
        reader_chirho
            .import_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &vec![b'x'; MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO + 1],
                &fixture_chirho.witness_bytes_chirho,
                &losing_tail_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::OversizedIndexChirho
    );
    assert_eq!(
        reader_chirho
            .import_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &fixture_chirho.index_bytes_chirho,
                &vec![
                    b'x';
                    crate::reconciliation_chirho::MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO + 1
                ],
                &losing_tail_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::OversizedWitnessChirho
    );
    let index_path_chirho = winner_first_record_path_chirho(
        &fixture_chirho
            .identity_chirho
            .consistency_group_digest_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
        &fixture_chirho
            .identity_chirho
            .winner_journal_genesis_digest_chirho,
    )
    .unwrap();
    assert!(held_storage_chirho
        .read_all_chirho(&index_path_chirho)
        .unwrap()
        .is_none());
    fs::remove_dir_all(source_root_chirho).unwrap();
    fs::remove_dir_all(held_root_chirho).unwrap();
}

#[test]
fn held_import_rejects_wrong_local_tail_and_immutable_collisions_chirho() {
    let (source_root_chirho, source_storage_chirho) =
        open_storage_chirho("gd7-held-import-collision-source-chirho");
    let (held_root_chirho, held_storage_chirho) =
        open_storage_chirho("gd7-held-import-collision-destination-chirho");
    let (wrong_root_chirho, wrong_storage_chirho) =
        open_storage_chirho("gd7-held-import-wrong-tail-chirho");
    let control_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(digest_chirho('a'), 0x35);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x36);
    let losing_tail_chirho = empty_verified_losing_tail_chirho(
        &held_storage_chirho,
        &ledger_signer_chirho,
        "collision-chirho",
    );
    let wrong_tail_chirho = empty_verified_losing_tail_chirho(
        &wrong_storage_chirho,
        &ledger_signer_chirho,
        "wrong-chirho",
    );
    let fixture_chirho = held_winner_import_fixture_chirho(
        &source_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
        &losing_tail_chirho,
    );
    let reader_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &held_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );
    assert_eq!(
        reader_chirho
            .import_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &fixture_chirho.index_bytes_chirho,
                &fixture_chirho.witness_bytes_chirho,
                &wrong_tail_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::WrongLosingTailChirho
    );

    let index_path_chirho = winner_first_record_path_chirho(
        &fixture_chirho
            .identity_chirho
            .consistency_group_digest_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
        &fixture_chirho
            .identity_chirho
            .winner_journal_genesis_digest_chirho,
    )
    .unwrap();
    held_storage_chirho
        .create_durable_chirho(&index_path_chirho, b"immutable-collision-chirho")
        .unwrap();
    assert_eq!(
        reader_chirho
            .import_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &fixture_chirho.index_bytes_chirho,
                &fixture_chirho.witness_bytes_chirho,
                &losing_tail_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::ImmutableCollisionChirho
    );
    let identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&fixture_chirho.identity_chirho).unwrap();
    let witness_path_chirho = winner_fork_witness_path_chirho(&identity_digest_chirho).unwrap();
    assert!(held_storage_chirho
        .read_all_chirho(&witness_path_chirho)
        .unwrap()
        .is_none());
    fs::remove_dir_all(source_root_chirho).unwrap();
    fs::remove_dir_all(held_root_chirho).unwrap();
    fs::remove_dir_all(wrong_root_chirho).unwrap();
}

#[test]
fn winner_first_record_and_fork_witness_retry_by_exact_coordinate_chirho() {
    let (root_chirho, storage_chirho) =
        open_storage_chirho("gd7-winner-witness-deterministic-chirho");
    let identity_chirho = reconciliation_identity_chirho();
    let control_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.winner_node_chirho.clone(), 0x41);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x51);
    let evidence_chirho = epoch_first_evidence_chirho(
        &ledger_signer_chirho,
        9,
        0,
        8,
        0,
        identity_chirho.fork_chirho.seq_chirho,
        &identity_chirho.fork_chirho.record_digest_chirho,
    );
    let store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );

    let index_chirho = store_chirho
        .ensure_winner_first_record_chirho(
            &identity_chirho.consistency_group_digest_chirho,
            &identity_chirho.winner_node_chirho,
            identity_chirho.winner_term_chirho,
            &identity_chirho.winner_journal_genesis_digest_chirho,
            &evidence_chirho,
        )
        .unwrap();
    let retried_index_chirho = store_chirho
        .ensure_winner_first_record_chirho(
            &identity_chirho.consistency_group_digest_chirho,
            &identity_chirho.winner_node_chirho,
            identity_chirho.winner_term_chirho,
            &identity_chirho.winner_journal_genesis_digest_chirho,
            &evidence_chirho,
        )
        .unwrap();
    assert_eq!(retried_index_chirho, index_chirho);
    assert_eq!(
        store_chirho
            .load_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                identity_chirho.winner_term_chirho,
                &identity_chirho.winner_journal_genesis_digest_chirho,
            )
            .unwrap(),
        Some(index_chirho.clone())
    );

    let witness_chirho = store_chirho
        .seal_winner_fork_witness_chirho(identity_chirho.clone(), &index_chirho)
        .unwrap();
    let retried_witness_chirho = store_chirho
        .seal_winner_fork_witness_chirho(identity_chirho.clone(), &index_chirho)
        .unwrap();
    assert_eq!(retried_witness_chirho, witness_chirho);
    assert_eq!(
        store_chirho
            .load_winner_fork_witness_chirho(&identity_chirho, &index_chirho)
            .unwrap(),
        Some(witness_chirho)
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn winner_observation_slot_bounds_losing_tail_identity_across_restart_chirho() {
    let (root_chirho, storage_chirho) =
        open_storage_chirho("gd7-winner-observation-slot-bounded-chirho");
    let identity_chirho = reconciliation_identity_chirho();
    let control_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.winner_node_chirho.clone(), 0x61);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x71);
    let evidence_chirho = epoch_first_evidence_chirho(
        &ledger_signer_chirho,
        identity_chirho.winner_term_chirho,
        0,
        identity_chirho.losing_term_chirho,
        0,
        identity_chirho.fork_chirho.seq_chirho,
        &identity_chirho.fork_chirho.record_digest_chirho,
    );
    let (index_chirho, first_witness_chirho) = {
        let store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
            &storage_chirho,
            &control_signer_chirho,
            &ledger_signer_chirho,
        );
        let index_chirho = store_chirho
            .ensure_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                identity_chirho.winner_term_chirho,
                &identity_chirho.winner_journal_genesis_digest_chirho,
                &evidence_chirho,
            )
            .unwrap();
        let first_witness_chirho = store_chirho
            .seal_winner_fork_witness_chirho(identity_chirho.clone(), &index_chirho)
            .unwrap();
        (index_chirho, first_witness_chirho)
    };

    let restarted_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );
    let mut distinct_tail_identity_chirho = identity_chirho.clone();
    distinct_tail_identity_chirho
        .losing_journal_tail_chirho
        .seq_chirho += 1;
    distinct_tail_identity_chirho
        .losing_journal_tail_chirho
        .record_digest_chirho = digest_chirho('7');
    assert_eq!(
        restarted_store_chirho
            .reserve_deposed_fork_observation_slot_chirho(&distinct_tail_identity_chirho)
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::ObservationSlotCollisionChirho
    );
    assert_eq!(
        restarted_store_chirho
            .seal_winner_fork_witness_chirho(distinct_tail_identity_chirho.clone(), &index_chirho,)
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::ObservationSlotCollisionChirho
    );

    restarted_store_chirho
        .reserve_deposed_fork_observation_slot_chirho(&identity_chirho)
        .unwrap();
    assert_eq!(
        restarted_store_chirho
            .seal_winner_fork_witness_chirho(identity_chirho.clone(), &index_chirho)
            .unwrap(),
        first_witness_chirho
    );

    let first_identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&identity_chirho).unwrap();
    let first_witness_path_chirho =
        winner_fork_witness_path_chirho(&first_identity_digest_chirho).unwrap();
    assert!(storage_chirho
        .read_all_chirho(&first_witness_path_chirho)
        .unwrap()
        .is_some());
    let distinct_identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&distinct_tail_identity_chirho).unwrap();
    let distinct_witness_path_chirho =
        winner_fork_witness_path_chirho(&distinct_identity_digest_chirho).unwrap();
    assert!(storage_chirho
        .read_all_chirho(&distinct_witness_path_chirho)
        .unwrap()
        .is_none());
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn same_term_regrant_reuses_but_cannot_create_the_term_index_chirho() {
    let identity_chirho = reconciliation_identity_chirho();
    let control_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.winner_node_chirho.clone(), 0x42);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x52);
    let crossing_chirho = epoch_first_evidence_chirho(
        &ledger_signer_chirho,
        9,
        0,
        8,
        0,
        identity_chirho.fork_chirho.seq_chirho,
        &identity_chirho.fork_chirho.record_digest_chirho,
    );
    let regrant_chirho =
        epoch_first_evidence_chirho(&ledger_signer_chirho, 9, 1, 9, 0, 6, &digest_chirho('5'));

    let (present_root_chirho, present_storage_chirho) =
        open_storage_chirho("gd7-winner-witness-regrant-present-chirho");
    let present_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &present_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );
    let first_chirho = present_store_chirho
        .ensure_winner_first_record_chirho(
            &identity_chirho.consistency_group_digest_chirho,
            &identity_chirho.winner_node_chirho,
            9,
            &identity_chirho.winner_journal_genesis_digest_chirho,
            &crossing_chirho,
        )
        .unwrap();
    assert_eq!(
        present_store_chirho
            .ensure_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                9,
                &identity_chirho.winner_journal_genesis_digest_chirho,
                &regrant_chirho,
            )
            .unwrap(),
        first_chirho
    );

    let (absent_root_chirho, absent_storage_chirho) =
        open_storage_chirho("gd7-winner-witness-regrant-absent-chirho");
    let absent_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &absent_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );
    assert_eq!(
        absent_store_chirho
            .ensure_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                9,
                &identity_chirho.winner_journal_genesis_digest_chirho,
                &regrant_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::SameTermAnchorWithoutIndexChirho
    );
    fs::remove_dir_all(present_root_chirho).unwrap();
    fs::remove_dir_all(absent_root_chirho).unwrap();
}

#[test]
fn winner_evidence_signatures_identity_and_bounds_fail_closed_chirho() {
    let (root_chirho, storage_chirho) =
        open_storage_chirho("gd7-winner-witness-fail-closed-chirho");
    let identity_chirho = reconciliation_identity_chirho();
    let control_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.winner_node_chirho.clone(), 0x43);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x53);
    let evidence_chirho = epoch_first_evidence_chirho(
        &ledger_signer_chirho,
        9,
        0,
        8,
        0,
        identity_chirho.fork_chirho.seq_chirho,
        &identity_chirho.fork_chirho.record_digest_chirho,
    );
    let store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );
    let index_chirho = store_chirho
        .ensure_winner_first_record_chirho(
            &identity_chirho.consistency_group_digest_chirho,
            &identity_chirho.winner_node_chirho,
            9,
            &identity_chirho.winner_journal_genesis_digest_chirho,
            &evidence_chirho,
        )
        .unwrap();

    let wrong_ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x54);
    let wrong_ledger_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &storage_chirho,
        &control_signer_chirho,
        &wrong_ledger_signer_chirho,
    );
    assert_eq!(
        wrong_ledger_store_chirho
            .load_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                9,
                &identity_chirho.winner_journal_genesis_digest_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::InvalidLedgerSignatureChirho
    );

    let mut wrong_fork_identity_chirho = identity_chirho.clone();
    wrong_fork_identity_chirho.fork_chirho.record_digest_chirho = digest_chirho('7');
    assert_eq!(
        store_chirho
            .seal_winner_fork_witness_chirho(wrong_fork_identity_chirho, &index_chirho)
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::ForkAnchorMismatchChirho
    );

    let witness_chirho = store_chirho
        .seal_winner_fork_witness_chirho(identity_chirho.clone(), &index_chirho)
        .unwrap();
    let identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&identity_chirho).unwrap();
    let witness_path_chirho = winner_fork_witness_path_chirho(&identity_digest_chirho).unwrap();
    let witness_bytes_chirho = storage_chirho
        .read_all_chirho(&witness_path_chirho)
        .unwrap()
        .unwrap();
    let mut witness_value_chirho: Gd7WinnerForkWitnessChirho =
        serde_json::from_slice(&witness_bytes_chirho).unwrap();
    witness_value_chirho.sig_chirho = digest_chirho('f');
    storage_chirho
        .atomic_write_chirho(
            &witness_path_chirho,
            &serde_json::to_vec(&witness_value_chirho).unwrap(),
        )
        .unwrap();
    assert_eq!(
        store_chirho
            .load_winner_fork_witness_chirho(&identity_chirho, &index_chirho)
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::InvalidWitnessSignatureChirho
    );

    let index_path_chirho = winner_first_record_path_chirho(
        &identity_chirho.consistency_group_digest_chirho,
        identity_chirho.winner_term_chirho,
        &identity_chirho.winner_journal_genesis_digest_chirho,
    )
    .unwrap();
    storage_chirho
        .atomic_write_chirho(
            &index_path_chirho,
            &vec![b'x'; MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO + 1],
        )
        .unwrap();
    assert_eq!(
        store_chirho
            .load_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                9,
                &identity_chirho.winner_journal_genesis_digest_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::OversizedIndexChirho
    );
    assert_eq!(
        witness_chirho
            .witness_chirho()
            .winner_first_record_digest_chirho,
        index_chirho.index_chirho().first_record_digest_chirho
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn tampered_control_signature_is_rejected_before_index_use_chirho() {
    let (root_chirho, storage_chirho) =
        open_storage_chirho("gd7-winner-index-control-signature-chirho");
    let identity_chirho = reconciliation_identity_chirho();
    let control_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.winner_node_chirho.clone(), 0x44);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x55);
    let evidence_chirho = epoch_first_evidence_chirho(
        &ledger_signer_chirho,
        9,
        0,
        8,
        0,
        identity_chirho.fork_chirho.seq_chirho,
        &identity_chirho.fork_chirho.record_digest_chirho,
    );
    let store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );
    store_chirho
        .ensure_winner_first_record_chirho(
            &identity_chirho.consistency_group_digest_chirho,
            &identity_chirho.winner_node_chirho,
            9,
            &identity_chirho.winner_journal_genesis_digest_chirho,
            &evidence_chirho,
        )
        .unwrap();
    let path_chirho = winner_first_record_path_chirho(
        &identity_chirho.consistency_group_digest_chirho,
        9,
        &identity_chirho.winner_journal_genesis_digest_chirho,
    )
    .unwrap();
    let bytes_chirho = storage_chirho
        .read_all_chirho(&path_chirho)
        .unwrap()
        .unwrap();
    let mut index_chirho: Gd7WinnerFirstRecordIndexChirho =
        serde_json::from_slice(&bytes_chirho).unwrap();
    index_chirho.sig_chirho = digest_chirho('e');
    storage_chirho
        .atomic_write_chirho(&path_chirho, &serde_json::to_vec(&index_chirho).unwrap())
        .unwrap();
    assert_eq!(
        store_chirho
            .load_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                9,
                &identity_chirho.winner_journal_genesis_digest_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::InvalidIndexSignatureChirho
    );
    fs::remove_dir_all(root_chirho).unwrap();
}
