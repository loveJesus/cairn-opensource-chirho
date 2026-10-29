// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! B-2 slice 1: the single cluster-journal ENGINE over the ledger ports — genesis creation via the
//! A3 codec, fail-closed full-verify open (router + chain law + fold verify), and the token-gated
//! append path: build → sign → FULL admission → canonical emit → one durable append → live-state
//! update. `&mut self` IS the single-writer append lock (F2: one serialized journal per cluster);
//! the live in-memory head-index is updated inside that borrow (§11.4, O(0) steady-state, no extra
//! sync — the ONE durable sync per op is the signed journal append). Only an
//! [`AdmittedRecordChirho`](crate::admission_chirho::AdmittedRecordChirho) ever reaches storage
//! (the B1 law in the engine). Torn-tail REPAIR is
//! in: open drops an unacknowledged partial final line by durable truncate ONLY after the clean
//! prefix fully verifies (a torn GENESIS stays fail-closed — no prefix to keep). Still slice 2+:
//! the advisory durable head-checkpoint sidecar, epoch advance + anchor emission, hydrate/passivate
//! O(active) memory, and W-window idempotency pruning; those fail CLOSED here.

mod append_execution_chirho;
pub mod append_mirror_chirho;
mod append_request_bounds_chirho;
mod epoch_first_record_tail_chirho;
mod open_contract_chirho;
pub use crate::journal_fastopen_chirho::{
    ExpectedGenesisOpenErrorChirho, ExpectedGenesisRefusalReasonChirho,
    ExpectedLedgerGenesisChirho, MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO,
    MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO,
};
pub use append_request_bounds_chirho::{
    AppendRequestBoundDimensionChirho, MAX_APPEND_REQUEST_BYTES_CHIRHO,
    MAX_APPEND_REQUEST_LEGS_CHIRHO,
};
use open_contract_chirho::JournalOpenPostureChirho;
pub(crate) use open_contract_chirho::{storage_error_chirho, verify_tail_signature_chirho};
pub use open_contract_chirho::{JournalErrorChirho, ReadOnlyRecoveryReasonChirho};

use crate::admission_chirho::{
    fold_leg_post_chirho, AuthorityVerifierViewChirho, CurrentContinuationPolicyChirho,
    KindRegistryViewChirho, MembershipViewChirho,
};
use crate::append_mirror_chirho::LedgerAppendMirrorPortChirho;
use crate::checkpoint_chirho::EffectReceiptWindowEntryChirho;
use crate::epoch_first_record_chirho::EpochFirstRecordEvidenceChirho;
use crate::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerClockPortChirho, LedgerSignerPortChirho,
    LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_effect_commit_chirho::intent_chirho::EffectIntentJournalCutChirho;
use cairn_ledger_model_chirho::counterpart_chirho::CounterpartClaimChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, HlcChirho, LedgerGenesisRecordChirho, LedgerOpChirho, LedgerRecordChirho,
    LegDeltaChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_genesis_line_chirho, ledger_genesis_signed_content_line_chirho,
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
    LEDGER_FORMAT_VERSION_V1_CHIRHO, LEDGER_GENESIS_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::ShardEpochChirho;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One requested leg — the SEMANTIC content; the engine computes the post-state under the lock
/// (Pr1) and admission re-verifies it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AppendLegRequestChirho {
    pub account_chirho: AccountIdChirho,
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    pub delta_chirho: LegDeltaChirho,
    pub amount_chirho: u64,
    pub counterpart_chirho: Option<CounterpartClaimChirho>,
}

/// One append request: what the caller wants recorded; seq/prev/epoch/HLC/posts/sig are the
/// ENGINE's to derive (never caller-chosen).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AppendRequestChirho {
    pub op_chirho: LedgerOpChirho,
    pub legs_chirho: Vec<AppendLegRequestChirho>,
    pub idempotency_key_chirho: String,
    pub provenance_chirho: Option<DigestChirho>,
    pub attribution_chirho: AttributionChirho,
}

/// What an accepted append proves back to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendReceiptChirho {
    pub seq_chirho: u64,
    pub record_digest_chirho: DigestChirho,
    pub hlc_chirho: HlcChirho,
    pub epoch_first_record_chirho: Option<EpochFirstRecordEvidenceChirho>,
}

/// One fully signed and canonical journal birth record prepared before any storage mutation.
///
/// The resident-writer identity commits this exact line and digest while it owns the provisioning
/// lease. Fields stay private so callers cannot manufacture a partially checked birth record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLedgerGenesisChirho {
    canonical_line_chirho: String,
    digest_chirho: DigestChirho,
    cluster_id_chirho: ClusterIdChirho,
    opening_epoch_chirho: ShardEpochChirho,
    opening_hlc_chirho: HlcChirho,
}

impl PreparedLedgerGenesisChirho {
    pub fn canonical_line_chirho(&self) -> &str {
        &self.canonical_line_chirho
    }

    pub fn digest_chirho(&self) -> &DigestChirho {
        &self.digest_chirho
    }

    pub fn cluster_id_chirho(&self) -> &ClusterIdChirho {
        &self.cluster_id_chirho
    }

    pub fn opening_epoch_chirho(&self) -> ShardEpochChirho {
        self.opening_epoch_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppendIdempotencyClassChirho {
    LegacyUnprunedChirho,
    VerifiedEffectIntentChirho {
        intent_ref_chirho: DigestChirho,
    },
    VerifiedEffectTerminalChirho {
        intent_ref_chirho: DigestChirho,
        outcome_ref_chirho: DigestChirho,
    },
}

/// The single cluster-journal engine (one instance = one journal = one writer).
pub struct LedgerJournalChirho<'ports_chirho> {
    pub(crate) storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub(crate) signer_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
    pub(crate) clock_chirho: &'ports_chirho dyn LedgerClockPortChirho,
    pub(crate) membership_chirho: &'ports_chirho dyn MembershipViewChirho,
    pub(crate) kind_registry_chirho: &'ports_chirho dyn KindRegistryViewChirho,
    pub(crate) authority_chirho: &'ports_chirho dyn AuthorityVerifierViewChirho,
    /// Optional F1 mirror gate installed by the geo resident composition. Local/non-geo journals
    /// retain the historical single-durable-append posture unless explicitly composed.
    pub(crate) append_mirror_chirho: Option<Arc<dyn LedgerAppendMirrorPortChirho>>,
    pub(crate) path_chirho: StoragePathChirho,
    pub(crate) cluster_id_chirho: ClusterIdChirho,
    /// The LEASE epoch appends run under (§11.5; advanced by the lease holder via
    /// [`Self::advance_epoch_chirho`]).
    pub(crate) current_epoch_chirho: ShardEpochChirho,
    /// The epoch of the tail RECORD (or genesis). When it lags `current_epoch`, the next append is
    /// the new epoch's FIRST record and must carry the binding anchor.
    pub(crate) last_recorded_epoch_chirho: ShardEpochChirho,
    pub(crate) tail_seq_chirho: u64,
    pub(crate) tail_digest_chirho: DigestChirho,
    pub(crate) tail_hlc_chirho: HlcChirho,
    pub(crate) genesis_digest_chirho: DigestChirho,
    /// Exact canonical signed genesis retained by every verified open. Recovery transfer needs the
    /// bytes to build an inert complete candidate without raw-reading the journal namespace.
    pub(crate) canonical_genesis_line_chirho: Option<String>,
    /// The LIVE in-memory head-index (§11.4): account → last post-state. Slice 1 holds every
    /// touched account (O(total-touched)); hydrate/passivate bounds it to O(active) in slice 2.
    pub(crate) head_states_chirho: BTreeMap<AccountIdChirho, LegPostStateChirho>,
    /// Net supply per stable kind (minted − burned) — the R2.3 durable aggregate's live view.
    pub(crate) supply_by_kind_chirho: BTreeMap<AssetKindIdChirho, u64>,
    /// All idempotency keys seen (slice 1 = unbounded; the W-law window prunes in slice 2).
    pub(crate) idempotency_keys_chirho: BTreeSet<String>,
    /// Bounded CF3 effect receipts, keyed by the reserved K. Every value is rebuildable from the
    /// signed journal record; live pruning consults only the registry's retention-scoped view.
    pub(crate) effect_receipt_window_chirho: BTreeMap<String, EffectReceiptWindowEntryChirho>,
    /// The UNCONSUMED escrow holds (CF2): exact (account, saga, step) -> held amount. Maintained
    /// by the ONE transition coding on append AND replay (P2); O(active-holds).
    pub(crate) active_holds_chirho: BTreeMap<crate::admission_chirho::EscrowHoldKeyChirho, u64>,
    /// CONSUMED counterpart nullifiers (F3a law ii) — replay-rebuilt, checkpoint-carried,
    /// conservative default unpruned (#5040 c2: prune is a CF3 W-law coordinate).
    pub(crate) consumed_nullifiers_chirho:
        BTreeSet<cairn_ledger_model_chirho::counterpart_chirho::CounterpartNullifierChirho>,
    /// The x-cluster admission composition (law v): None keeps the counterpart row Unsupported.
    pub(crate) finality_chirho:
        Option<crate::admission_chirho::FinalityAdmissionViewsChirho<'ports_chirho>>,
    /// Set when THIS open repaired a torn tail: how many unacknowledged bytes were dropped. The
    /// repair is lawful because an un-fsynced suffix was never acknowledged (no receipt exists on
    /// it) and only runs AFTER the clean prefix fully verified.
    pub(crate) repaired_torn_tail_bytes_chirho: Option<u64>,
    /// Total durable journal bytes (every line INCLUDING its LF) — the next append's line offset.
    pub(crate) tail_byte_len_chirho: u64,
    /// Physical active-object length observed for this cut. Normally equal to `tail_byte_len_chirho`;
    /// a held-only reader may retain a bounded unacknowledged torn suffix beyond the clean cut.
    pub(crate) tail_physical_byte_len_chirho: u64,
    /// The tail line's BODY offset + length (the checkpoint's covered-cut locator).
    pub(crate) tail_line_offset_chirho: u64,
    pub(crate) tail_line_len_chirho: u64,
    /// Byte length of the genesis line BODY (locates line 0 for the sidecar binding check).
    pub(crate) genesis_line_len_chirho: u64,
    /// The segment base at open/last-rotation (0 = never rotated), and the VERIFIED manifest
    /// tail-entry digest at that moment — the rotated-journal checkpoint binding pair.
    pub(crate) base_seq_chirho: u64,
    pub(crate) manifest_tail_entry_digest_chirho: Option<String>,
    /// Per-account byte locators for each account's last-touching signed leg (§11.4: WHERE to
    /// read; the sidecar persists these so reopen + rehydration are range-reads, never full scans).
    pub(crate) head_locators_chirho:
        BTreeMap<AccountIdChirho, crate::checkpoint_chirho::HeadLocatorChirho>,
    /// Did THIS open take the verified fast path (sidecar + suffix replay) instead of a full scan?
    pub(crate) last_open_was_fast_chirho: bool,
}

/// The ports + views bundle for building an engine (borrowed; the composition root owns them).
#[derive(Clone, Copy)]
pub struct JournalPortsChirho<'ports_chirho> {
    pub storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub signer_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
    pub clock_chirho: &'ports_chirho dyn LedgerClockPortChirho,
    pub membership_chirho: &'ports_chirho dyn MembershipViewChirho,
    pub kind_registry_chirho: &'ports_chirho dyn KindRegistryViewChirho,
    pub authority_chirho: &'ports_chirho dyn AuthorityVerifierViewChirho,
}

impl<'ports_chirho> LedgerJournalChirho<'ports_chirho> {
    /// Prepare the exact signed genesis before a resident identity or storage object is written.
    pub fn prepare_genesis_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        cluster_id_chirho: ClusterIdChirho,
        opening_epoch_chirho: ShardEpochChirho,
    ) -> Result<PreparedLedgerGenesisChirho, JournalErrorChirho> {
        let opening_hlc_chirho = HlcChirho {
            physical_ms_chirho: ports_chirho.clock_chirho.physical_now_ms_chirho(),
            logical_chirho: 0,
        };
        let mut genesis_chirho = LedgerGenesisRecordChirho {
            schema_chirho: LEDGER_GENESIS_SCHEMA_V1_CHIRHO.into(),
            format_version_chirho: LEDGER_FORMAT_VERSION_V1_CHIRHO,
            cluster_id_chirho: cluster_id_chirho.clone(),
            epoch_chirho: opening_epoch_chirho,
            hlc_chirho: opening_hlc_chirho.clone(),
            sig_chirho: String::new(),
            key_id_chirho: ports_chirho.signer_chirho.key_id_chirho(),
        };
        let signed_content_chirho = ledger_genesis_signed_content_line_chirho(&genesis_chirho)?;
        genesis_chirho.sig_chirho = ports_chirho
            .signer_chirho
            .sign_chirho(&signed_content_chirho)
            .map_err(|error_chirho| JournalErrorChirho::SignerChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
        let line_chirho = canonical_ledger_genesis_line_chirho(&genesis_chirho)?;
        let genesis_digest_chirho = stored_line_digest_chirho(&line_chirho);
        Self::verify_prepared_genesis_chirho(
            ports_chirho,
            &line_chirho,
            &cluster_id_chirho,
            opening_epoch_chirho,
            &genesis_digest_chirho,
        )
    }

    /// Reconstruct a prepared birth record from exact canonical bytes committed by a resident
    /// Pending identity. The injected journal signer, cluster, epoch, and digest are all checked.
    pub fn verify_prepared_genesis_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        canonical_line_chirho: &str,
        expected_cluster_chirho: &ClusterIdChirho,
        expected_opening_epoch_chirho: ShardEpochChirho,
        expected_digest_chirho: &DigestChirho,
    ) -> Result<PreparedLedgerGenesisChirho, JournalErrorChirho> {
        let genesis_chirho =
            match parse_canonical_ledger_journal_line_chirho(canonical_line_chirho)? {
                LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => genesis_chirho,
                LedgerJournalLineChirho::RecordChirho(_) => {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: "prepared journal birth line is not genesis".to_owned(),
                    });
                }
            };
        if genesis_chirho.cluster_id_chirho != *expected_cluster_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "prepared genesis names a different cluster".to_owned(),
            });
        }
        if genesis_chirho.epoch_chirho != expected_opening_epoch_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "prepared genesis names a different opening epoch".to_owned(),
            });
        }
        if genesis_chirho.key_id_chirho != ports_chirho.signer_chirho.key_id_chirho() {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho:
                    "prepared genesis signer label differs from the injected journal signer"
                        .to_owned(),
            });
        }
        verify_tail_signature_chirho(
            ports_chirho.signer_chirho,
            &LedgerJournalLineChirho::GenesisChirho(genesis_chirho.clone()),
        )?;
        let actual_digest_chirho = stored_line_digest_chirho(canonical_line_chirho);
        if actual_digest_chirho != *expected_digest_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "prepared genesis digest commitment mismatch".to_owned(),
            });
        }
        Ok(PreparedLedgerGenesisChirho {
            canonical_line_chirho: canonical_line_chirho.to_owned(),
            digest_chirho: actual_digest_chirho,
            cluster_id_chirho: genesis_chirho.cluster_id_chirho,
            opening_epoch_chirho: genesis_chirho.epoch_chirho,
            opening_hlc_chirho: genesis_chirho.hlc_chirho,
        })
    }

    /// Atomically create a NEW journal from one verified prepared genesis. A concurrent creator
    /// wins or loses the create-only storage claim; preexisting bytes are never appended to.
    pub fn create_prepared_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        prepared_chirho: PreparedLedgerGenesisChirho,
    ) -> Result<Self, JournalErrorChirho> {
        let prepared_chirho = Self::verify_prepared_genesis_chirho(
            ports_chirho,
            prepared_chirho.canonical_line_chirho(),
            prepared_chirho.cluster_id_chirho(),
            prepared_chirho.opening_epoch_chirho(),
            prepared_chirho.digest_chirho(),
        )?;
        let mut bytes_chirho = prepared_chirho.canonical_line_chirho.clone().into_bytes();
        bytes_chirho.push(b'\n');
        match ports_chirho
            .storage_chirho
            .create_durable_chirho(&path_chirho, &bytes_chirho)
            .map_err(storage_error_chirho)?
        {
            CreateDurableOutcomeChirho::CreatedChirho => {}
            CreateDurableOutcomeChirho::AlreadyExistsChirho => {
                return Err(JournalErrorChirho::ChainChirho {
                    detail_chirho: "journal path already exists (a journal is born once)"
                        .to_owned(),
                });
            }
        }
        let line_len_chirho = prepared_chirho.canonical_line_chirho.len() as u64;
        let genesis_digest_chirho = prepared_chirho.digest_chirho;
        let canonical_genesis_line_chirho = prepared_chirho.canonical_line_chirho.clone();
        Ok(Self {
            storage_chirho: ports_chirho.storage_chirho,
            signer_chirho: ports_chirho.signer_chirho,
            clock_chirho: ports_chirho.clock_chirho,
            membership_chirho: ports_chirho.membership_chirho,
            kind_registry_chirho: ports_chirho.kind_registry_chirho,
            authority_chirho: ports_chirho.authority_chirho,
            append_mirror_chirho: None,
            path_chirho,
            cluster_id_chirho: prepared_chirho.cluster_id_chirho,
            current_epoch_chirho: prepared_chirho.opening_epoch_chirho,
            last_recorded_epoch_chirho: prepared_chirho.opening_epoch_chirho,
            tail_seq_chirho: 0,
            tail_digest_chirho: genesis_digest_chirho.clone(),
            tail_hlc_chirho: prepared_chirho.opening_hlc_chirho,
            genesis_digest_chirho,
            canonical_genesis_line_chirho: Some(canonical_genesis_line_chirho),
            head_states_chirho: BTreeMap::new(),
            supply_by_kind_chirho: BTreeMap::new(),
            idempotency_keys_chirho: BTreeSet::new(),
            effect_receipt_window_chirho: BTreeMap::new(),
            active_holds_chirho: BTreeMap::new(),
            consumed_nullifiers_chirho: BTreeSet::new(),
            finality_chirho: None,
            repaired_torn_tail_bytes_chirho: None,
            tail_byte_len_chirho: line_len_chirho + 1,
            tail_physical_byte_len_chirho: line_len_chirho + 1,
            tail_line_offset_chirho: 0,
            tail_line_len_chirho: line_len_chirho,
            genesis_line_len_chirho: line_len_chirho,
            base_seq_chirho: 0,
            manifest_tail_entry_digest_chirho: None,
            head_locators_chirho: BTreeMap::new(),
            last_open_was_fast_chirho: false,
        })
    }

    /// Create a NEW journal by preparing then atomically claiming its path.
    pub fn create_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        cluster_id_chirho: ClusterIdChirho,
        opening_epoch_chirho: ShardEpochChirho,
    ) -> Result<Self, JournalErrorChirho> {
        let prepared_chirho =
            Self::prepare_genesis_chirho(ports_chirho, cluster_id_chirho, opening_epoch_chirho)?;
        Self::create_prepared_chirho(ports_chirho, path_chirho, prepared_chirho)
    }

    /// Open an EXISTING journal. Tries the VERIFIED FAST PATH first (§11.4: advisory sidecar →
    /// authenticate the covered cut by range-reads → parse checkpoint state and replay only the
    /// suffix, O(checkpoint state + delta) and independent of total history); ANY verification miss
    /// silently discards the sidecar and falls back to the full rebuild — the sidecar is never
    /// authority and never an error source.
    pub fn open_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
    ) -> Result<Self, JournalErrorChirho> {
        if let Some(engine_chirho) =
            Self::try_fast_open_chirho(ports_chirho, &path_chirho, expected_cluster_chirho)
        {
            return Ok(engine_chirho);
        }
        Self::full_open_chirho(
            ports_chirho,
            path_chirho,
            expected_cluster_chirho,
            JournalOpenPostureChirho::RepairingChirho,
        )
    }

    pub(crate) fn ensure_read_only_rotation_clear_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: &StoragePathChirho,
    ) -> Result<(), JournalErrorChirho> {
        let segment_storage_chirho =
            crate::segment_adapter_chirho::SegmentStorageOverLedgerPortChirho::new_chirho(
                ports_chirho.storage_chirho,
            );
        let segment_paths_chirho =
            cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho::new_chirho(
                path_chirho.key_chirho(),
            );
        let marker_exists_chirho =
            cairn_seqlog_chirho::segment_chirho::storage_chirho::SegmentStorageChirho::exists_chirho(
                &segment_storage_chirho,
                &segment_paths_chirho.rotation_marker_chirho(),
            )
            .map_err(|error_chirho| JournalErrorChirho::StorageChirho {
                detail_chirho: format!(
                    "read-only rotation-marker inspection failed: {error_chirho}"
                ),
            })?;
        if marker_exists_chirho {
            return Err(JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
                reason_chirho: ReadOnlyRecoveryReasonChirho::PendingRotationChirho,
            });
        }
        Ok(())
    }

    /// Open and verify an existing journal without repair authority.
    ///
    /// Unlike [`Self::open_chirho`], this constructor never completes a pending rotation or
    /// truncates a torn suffix. It first attempts the signed-checkpoint O(checkpoint state + delta)
    /// path without repair authority, independent of total history, then falls back to the
    /// O(history) full verifier on an advisory-sidecar miss. A pending rotation or torn suffix
    /// returns a typed recovery requirement and mutates no journal record, segment, or tail.
    ///
    /// NOT byte-inert, and the difference matters to anyone reasoning about concurrency: on an
    /// advisory-head miss `derive_base_seq_chirho` re-seeds the manifest-head sidecar through
    /// `write_durable_chirho`. That write is advisory and behind-never-ahead, so it costs only a
    /// rescan if it fails — but "read-only" here means NO REPAIR AUTHORITY, not zero writes. An
    /// earlier revision of this comment promised every storage byte untouched; that was false
    /// whenever the head fast path misses, which is the ordinary cold path on a rotated journal.
    /// Served reads
    /// and projection observers use this door; deep auditors use
    /// [`Self::open_read_only_full_chirho`], and a writer/operator must run the ordinary open before
    /// reads resume.
    pub fn open_read_only_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
    ) -> Result<Self, JournalErrorChirho> {
        Self::ensure_read_only_rotation_clear_chirho(ports_chirho, &path_chirho)?;
        if let Some(engine_chirho) = Self::try_fast_open_read_only_chirho(
            ports_chirho,
            &path_chirho,
            expected_cluster_chirho,
        )? {
            // Recheck after range reads. The resident lease is the primary serialization boundary;
            // this second observation also refuses a marker that appeared during the fast attempt.
            Self::ensure_read_only_rotation_clear_chirho(ports_chirho, &path_chirho)?;
            return Ok(engine_chirho);
        }
        Self::open_read_only_full_chirho(ports_chirho, path_chirho, expected_cluster_chirho)
    }

    /// Open only when the signed head checkpoint describes the exact current physical tail.
    ///
    /// Held geo followers use this bounded door. It never falls back to an O(history) rebuild,
    /// never repairs, and never replays a suffix beyond the checkpoint. Rotated state must resolve
    /// through the authenticated manifest-head fast path. Before returning, the current physical
    /// tail is independently reread under the losing-suffix byte cap and its signature, sequence,
    /// epoch, digest, seal state, and active length are revalidated.
    pub fn open_read_only_exact_head_checkpoint_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
    ) -> Result<Self, JournalErrorChirho> {
        Self::ensure_read_only_rotation_clear_chirho(ports_chirho, &path_chirho)?;
        let engine_chirho = Self::try_fast_open_read_only_exact_checkpoint_chirho(
            ports_chirho,
            &path_chirho,
            expected_cluster_chirho,
        )?
        .ok_or(JournalErrorChirho::ReadOnlyExactCheckpointRequiredChirho)?;
        engine_chirho
            .revalidate_current_losing_tail_chirho()
            .map_err(|error_chirho| {
                JournalErrorChirho::ReadOnlyExactCheckpointTailRefusedChirho {
                    detail_chirho: format!("{error_chirho:?}"),
                }
            })?;
        Self::ensure_read_only_rotation_clear_chirho(ports_chirho, &path_chirho)?;
        Ok(engine_chirho)
    }

    /// Perform the no-repair O(history) verifier deliberately.
    ///
    /// Deep audits use this door when every covered record must be reread rather than relying on the
    /// signed checkpoint's covered-prefix aggregates. It has the same no-repair guarantees as
    /// [`Self::open_read_only_chirho`] — and the same limit on them: it mutates no record, segment
    /// or tail, but it is NOT byte-inert. `derive_base_seq_chirho` runs OUTSIDE the
    /// `RepairingChirho` posture guard, so an advisory-head miss re-seeds the manifest-head sidecar
    /// here too. Do not build a concurrency argument on this door being write-free; build it on the
    /// tail-revalidation refusals, which fail closed on any byte of growth.
    pub fn open_read_only_full_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
    ) -> Result<Self, JournalErrorChirho> {
        Self::full_open_chirho(
            ports_chirho,
            path_chirho,
            expected_cluster_chirho,
            JournalOpenPostureChirho::ReadOnlyChirho,
        )
    }

    pub(crate) fn full_repair_open_with_expected_preflight_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        preflight_chirho: &crate::journal_fastopen_chirho::VerifiedExpectedGenesisPreflightChirho<
            '_,
        >,
    ) -> Result<Self, JournalErrorChirho> {
        Self::full_open_chirho(
            ports_chirho,
            preflight_chirho.path_chirho().clone(),
            preflight_chirho.expected_cluster_chirho(),
            JournalOpenPostureChirho::RepairingChirho,
        )
    }

    /// The full verified rebuild: every line through the ONE router, the chain law at every step,
    /// every leg's post fold-verified from the running heads (§11.3 chain verify), supply +
    /// idempotency rebuilt.
    fn full_open_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
        posture_chirho: JournalOpenPostureChirho,
    ) -> Result<Self, JournalErrorChirho> {
        if posture_chirho == JournalOpenPostureChirho::ReadOnlyChirho {
            Self::ensure_read_only_rotation_clear_chirho(ports_chirho, &path_chirho)?;
        }
        // B0 bricks 2a + 3b-iii: derive the base sequence from the signed segment manifest FIRST,
        // driven through the journal's OWN ports (storage + signer) via the segment adapter — one
        // code path drives the real filesystem in production and the fault-injectable sim store in
        // the crash matrix. base == 0 (no manifest) ⇒ the legacy single-file path, byte-identical
        // to the pre-segment journal. base > 0 ⇒ the ROTATED-OPEN: the verified sealed raw lines
        // (genesis lives in the FIRST sealed segment) are recomposed with the journal's own
        // clean-prefix active lines and replayed as ONE unsplit log — the chain law itself (dense
        // seq + prev binding) verifies the seam; no checkpoint is consulted (always-available,
        // tamper-evident, O(history) — the checkpoint fast path over sealed history is a separate
        // later increment).
        let (base_seq_chirho, sealed_lines_chirho, manifest_tail_entry_digest_chirho) = {
            let segment_storage_chirho =
                crate::segment_adapter_chirho::SegmentStorageOverLedgerPortChirho::new_chirho(
                    ports_chirho.storage_chirho,
                );
            let segment_continuity_chirho =
                crate::segment_adapter_chirho::SegmentContinuityOverLedgerSignerPortChirho::new_chirho(
                    ports_chirho.signer_chirho,
                );
            let segment_paths_chirho =
                cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho::new_chirho(
                    path_chirho.key_chirho(),
                );
            let log_identity_chirho =
                cairn_seqlog_chirho::segment_chirho::LogIdentityChirho::new_chirho(format!(
                    "cairn-ledger:{}",
                    expected_cluster_chirho.0
                ));
            if posture_chirho == JournalOpenPostureChirho::RepairingChirho {
                // A crash mid-rotation leaves the intent marker; the WRITE-lane open finishes or
                // refuses it before deriving a sequence. The read-only lane already performed its
                // non-mutating marker check above.
                cairn_seqlog_chirho::segment_chirho::rotation_chirho::recover_pending_rotation_chirho(
                        &segment_storage_chirho,
                        &segment_continuity_chirho,
                        &segment_paths_chirho,
                        &log_identity_chirho,
                    )
                    .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
                        detail_chirho: format!("rotation recovery failed: {error_chirho}"),
                    })?;
            }
            let base_chirho =
                cairn_seqlog_chirho::segment_chirho::manifest_chirho::derive_base_seq_chirho(
                    &segment_storage_chirho,
                    &segment_continuity_chirho,
                    &segment_paths_chirho,
                    &log_identity_chirho.digest_chirho(),
                )
                .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
                    detail_chirho: format!("segment base-seq derivation failed: {error_chirho}"),
                })?;
            if base_chirho.base_seq_chirho == 0 {
                (0, Vec::new(), None)
            } else {
                let sealed_chirho =
                    cairn_seqlog_chirho::segment_chirho::reader_chirho::load_sealed_raw_jsonl_lines_chirho(
                        &segment_storage_chirho,
                        &segment_continuity_chirho,
                        &segment_paths_chirho,
                        &log_identity_chirho.digest_chirho(),
                    )
                    .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
                        detail_chirho: format!("sealed segment walk failed: {error_chirho}"),
                    })?;
                if sealed_chirho.len() as u64 != base_chirho.base_seq_chirho {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "sealed walk returned {} lines but the manifest base seq is {} — \
                             refusing divergent sealed history",
                            sealed_chirho.len(),
                            base_chirho.base_seq_chirho
                        ),
                    });
                }
                (
                    base_chirho.base_seq_chirho,
                    sealed_chirho,
                    base_chirho.last_entry_digest_chirho.clone(),
                )
            }
        };
        // The active file is read ONLY NOW — after rotation recovery, which may have completed a
        // crashed rotation and RESET the active (reading earlier would recompose a stale
        // pre-recovery active: a doubled history — the rotation crash matrix caught exactly that).
        let bytes_chirho = ports_chirho
            .storage_chirho
            .read_all_chirho(&path_chirho)
            .map_err(storage_error_chirho)?
            .ok_or_else(|| JournalErrorChirho::StorageChirho {
                detail_chirho: "journal object missing".to_owned(),
            })?;
        // Torn-tail law: a crash mid-append leaves a partial FINAL line — an un-fsynced suffix no
        // caller ever received a receipt for. The clean prefix ends at the last LF; the torn
        // suffix is repaired (durably truncated) ONLY after the whole prefix verifies.
        let clean_len_chirho = bytes_chirho
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
            .map(|index_chirho| index_chirho + 1)
            .unwrap_or(0);
        let torn_len_chirho = (bytes_chirho.len() - clean_len_chirho) as u64;
        let text_chirho = std::str::from_utf8(&bytes_chirho[..clean_len_chirho]).map_err(|_| {
            JournalErrorChirho::ChainChirho {
                detail_chirho: "journal prefix is not UTF-8".to_owned(),
            }
        })?;
        // Empty/torn-genesis guards are BASE-DEPENDENT: at base == 0 the active file must open with
        // genesis (empty ⇒ no genesis; wholly-torn ⇒ the genesis append itself tore — no verified
        // prefix to keep, fail closed). At base > 0 the verified prefix INCLUDES the sealed
        // history, so an empty fresh active is the legal post-rotation state and a wholly-torn
        // active is an ordinary repairable torn suffix.
        if base_seq_chirho == 0 {
            if bytes_chirho.is_empty() {
                return Err(JournalErrorChirho::ChainChirho {
                    detail_chirho: "journal is empty (no genesis)".to_owned(),
                });
            }
            if clean_len_chirho == 0 {
                if posture_chirho == JournalOpenPostureChirho::ReadOnlyChirho {
                    return Err(JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
                        reason_chirho: ReadOnlyRecoveryReasonChirho::TornTailChirho,
                    });
                }
                return Err(JournalErrorChirho::TornTailChirho);
            }
        }
        // Recompose the ONE unsplit log: sealed lines (all of history through the last seal), then
        // the clean-prefix active lines. Line 0 is ALWAYS the genesis — from the active file at
        // base == 0, from the first sealed segment at base > 0.
        let mut recomposed_chirho = sealed_lines_chirho.iter().map(String::as_str).chain(
            text_chirho
                .lines()
                .filter(|line_chirho| !line_chirho.trim().is_empty()),
        );
        let genesis_line_chirho =
            recomposed_chirho
                .next()
                .ok_or(JournalErrorChirho::ChainChirho {
                    detail_chirho: "journal has no lines".to_owned(),
                })?;
        let genesis_chirho = match parse_canonical_ledger_journal_line_chirho(genesis_line_chirho)?
        {
            LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => genesis_chirho,
            LedgerJournalLineChirho::RecordChirho(_) => {
                return Err(JournalErrorChirho::ChainChirho {
                    detail_chirho: "line 0 is not a genesis record".to_owned(),
                })
            }
        };
        if genesis_chirho.cluster_id_chirho != *expected_cluster_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "genesis names a different cluster".to_owned(),
            });
        }
        let genesis_digest_chirho = stored_line_digest_chirho(genesis_line_chirho);
        // Post-genesis recomposed lines = sealed records (base > 0 only), then active records.
        let sealed_record_count_chirho = sealed_lines_chirho.len().saturating_sub(1);
        let mut engine_chirho = Self {
            storage_chirho: ports_chirho.storage_chirho,
            signer_chirho: ports_chirho.signer_chirho,
            clock_chirho: ports_chirho.clock_chirho,
            membership_chirho: ports_chirho.membership_chirho,
            kind_registry_chirho: ports_chirho.kind_registry_chirho,
            authority_chirho: ports_chirho.authority_chirho,
            append_mirror_chirho: None,
            path_chirho,
            cluster_id_chirho: genesis_chirho.cluster_id_chirho.clone(),
            current_epoch_chirho: genesis_chirho.epoch_chirho,
            last_recorded_epoch_chirho: genesis_chirho.epoch_chirho,
            tail_seq_chirho: 0,
            tail_digest_chirho: genesis_digest_chirho.clone(),
            tail_hlc_chirho: genesis_chirho.hlc_chirho.clone(),
            genesis_digest_chirho,
            canonical_genesis_line_chirho: Some(genesis_line_chirho.to_string()),
            head_states_chirho: BTreeMap::new(),
            supply_by_kind_chirho: BTreeMap::new(),
            idempotency_keys_chirho: BTreeSet::new(),
            effect_receipt_window_chirho: BTreeMap::new(),
            active_holds_chirho: BTreeMap::new(),
            consumed_nullifiers_chirho: BTreeSet::new(),
            finality_chirho: None,
            repaired_torn_tail_bytes_chirho: None,
            tail_byte_len_chirho: if base_seq_chirho == 0 {
                genesis_line_chirho.len() as u64 + 1
            } else {
                0
            },
            tail_physical_byte_len_chirho: if base_seq_chirho == 0 {
                genesis_line_chirho.len() as u64 + 1
            } else {
                0
            },
            tail_line_offset_chirho: 0,
            // At base > 0 the genesis is sealed-resident: the empty fresh active has no tail line
            // (the 3b-ii empty anchors); `genesis_line_len` keeps the sealed genesis LINE length
            // (its active-file-locator meaning does not apply at base > 0 — see
            // `write_head_checkpoint_chirho`).
            tail_line_len_chirho: if base_seq_chirho == 0 {
                genesis_line_chirho.len() as u64
            } else {
                0
            },
            genesis_line_len_chirho: genesis_line_chirho.len() as u64,
            base_seq_chirho,
            manifest_tail_entry_digest_chirho,
            head_locators_chirho: BTreeMap::new(),
            last_open_was_fast_chirho: false,
        };
        if base_seq_chirho > 0 && sealed_record_count_chirho == 0 {
            // Rotated with only the genesis sealed: the derive ↔ replay bind still must hold.
            if engine_chirho.tail_seq_chirho + 1 != base_seq_chirho {
                return Err(JournalErrorChirho::ChainChirho {
                    detail_chirho: format!(
                        "manifest base seq {} does not bind the sealed genesis (next seq 1)",
                        base_seq_chirho
                    ),
                });
            }
        }
        let mut position_chirho = if base_seq_chirho == 0 {
            genesis_line_chirho.len() as u64 + 1
        } else {
            0
        };
        let mut tail_line_chirho = LedgerJournalLineChirho::GenesisChirho(genesis_chirho);
        let mut replayed_chirho: usize = 0;
        for line_chirho in recomposed_chirho {
            let sealed_resident_chirho = replayed_chirho < sealed_record_count_chirho;
            let record_chirho = match parse_canonical_ledger_journal_line_chirho(line_chirho)? {
                LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho,
                LedgerJournalLineChirho::GenesisChirho(_) => {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: "second genesis line".to_owned(),
                    })
                }
            };
            let line_digest_chirho = stored_line_digest_chirho(line_chirho);
            if sealed_resident_chirho {
                // Sealed-resident records have NO active-file coordinates: replay with dummy
                // locator inputs (the whole locator map is cleared at the seal boundary below) and
                // leave the active tail anchors untouched.
                engine_chirho.replay_verified_chirho(&record_chirho, 0, 0, &line_digest_chirho)?;
                engine_chirho.tail_digest_chirho = line_digest_chirho;
            } else {
                engine_chirho.replay_verified_chirho(
                    &record_chirho,
                    position_chirho,
                    line_chirho.len() as u64,
                    &line_digest_chirho,
                )?;
                engine_chirho.tail_digest_chirho = line_digest_chirho;
                engine_chirho.tail_line_offset_chirho = position_chirho;
                engine_chirho.tail_line_len_chirho = line_chirho.len() as u64;
                position_chirho += line_chirho.len() as u64 + 1;
            }
            tail_line_chirho = LedgerJournalLineChirho::RecordChirho(record_chirho);
            replayed_chirho += 1;
            if sealed_resident_chirho && replayed_chirho == sealed_record_count_chirho {
                // Derive ↔ replay BIND: after the last sealed record, the next seq IS the manifest
                // base — a manifest whose base diverges from the sealed record chain fails closed.
                if engine_chirho.tail_seq_chirho + 1 != base_seq_chirho {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "manifest base seq {} does not bind the sealed chain (next seq {})",
                            base_seq_chirho,
                            engine_chirho.tail_seq_chirho + 1
                        ),
                    });
                }
                // Sealed-resident heads get NO active-file locator: absence forces the full path
                // (fail-closed), never a coordinate into bytes that live in a sealed segment.
                // Active replays below re-insert real active-file locators.
                engine_chirho.head_locators_chirho.clear();
            }
        }
        engine_chirho.tail_byte_len_chirho = clean_len_chirho as u64;
        engine_chirho.tail_physical_byte_len_chirho = clean_len_chirho as u64;
        // The successor-less tail line's signature is the ONE anchor the digest chain cannot bind;
        // verifying it makes the whole recovered journal tamper-evident (claude2 #4533/#4535).
        verify_tail_signature_chirho(engine_chirho.signer_chirho, &tail_line_chirho)?;
        // Repair the torn suffix ONLY now — the whole clean prefix verified. A crash between here
        // and the truncate re-runs the same repair on the next open (idempotent); a bad prefix
        // never mutates the object (forensic evidence stays intact).
        if torn_len_chirho > 0 {
            match posture_chirho {
                JournalOpenPostureChirho::RepairingChirho => {
                    engine_chirho
                        .storage_chirho
                        .truncate_durable_chirho(
                            &engine_chirho.path_chirho,
                            clean_len_chirho as u64,
                        )
                        .map_err(storage_error_chirho)?;
                    engine_chirho.repaired_torn_tail_bytes_chirho = Some(torn_len_chirho);
                }
                JournalOpenPostureChirho::ReadOnlyChirho => {
                    return Err(JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
                        reason_chirho: ReadOnlyRecoveryReasonChirho::TornTailChirho,
                    });
                }
            }
        }
        Ok(engine_chirho)
    }

    /// How many torn (unacknowledged) tail bytes THIS open dropped, if any.
    pub fn repaired_torn_tail_bytes_chirho(&self) -> Option<u64> {
        self.repaired_torn_tail_bytes_chirho
    }

    /// Did THIS open take the verified fast path (sidecar state + suffix replay, independent of
    /// total history)?
    /// Compose the x-cluster finality views (law v): WITHOUT this call the counterpart Transfer
    /// row stays ExplicitlyUnsupported. Consumes and returns the engine (builder style) so the
    /// composition is explicit at the composition root, never ambient.
    pub fn with_finality_views_chirho(
        mut self,
        views_chirho: crate::admission_chirho::FinalityAdmissionViewsChirho<'ports_chirho>,
    ) -> Self {
        self.finality_chirho = Some(views_chirho);
        self
    }

    /// Install the transport-neutral F1 gate before this journal enters a production resident actor.
    pub fn with_append_mirror_chirho(
        mut self,
        append_mirror_chirho: Arc<dyn LedgerAppendMirrorPortChirho>,
    ) -> Self {
        self.append_mirror_chirho = Some(append_mirror_chirho);
        self
    }

    pub fn last_open_was_fast_chirho(&self) -> bool {
        self.last_open_was_fast_chirho
    }

    /// The verified tail seq (read-only — a projection feeder's source-cut coordinate).
    pub fn tail_seq_chirho(&self) -> u64 {
        self.tail_seq_chirho
    }

    /// The verified tail HLC (read-only — the staleness watermark's source side).
    pub fn tail_hlc_chirho(&self) -> &HlcChirho {
        &self.tail_hlc_chirho
    }

    /// The exact engine-issued age/instance cut a CF3 signed intent binds. Read-only; it grants no
    /// append authority and becomes useful only after the dedicated door verifies the signed
    /// intent against its separately injected root.
    pub fn effect_intent_cut_chirho(&self) -> EffectIntentJournalCutChirho {
        EffectIntentJournalCutChirho {
            journal_genesis_digest_chirho: self.genesis_digest_chirho.clone(),
            tail_seq_chirho: self.tail_seq_chirho,
            tail_record_digest_chirho: self.tail_digest_chirho.clone(),
            tail_hlc_chirho: self.tail_hlc_chirho.clone(),
        }
    }

    /// The verified per-account head post-states (read-only — the state a STATE-DERIVED
    /// projection folds; granting a reader this view grants no write or admission capability).
    pub fn head_states_chirho(&self) -> &BTreeMap<AccountIdChirho, LegPostStateChirho> {
        &self.head_states_chirho
    }

    /// The verified net supply per stable kind (read-only — the conservation monitor's and the
    /// balance-class projections' source view).
    pub fn supply_by_kind_chirho(&self) -> &BTreeMap<AssetKindIdChirho, u64> {
        &self.supply_by_kind_chirho
    }

    /// Read-only view of the UNCONSUMED escrow holds (exact-triple key → held amount). The CF2
    /// coordinator consults this as EVIDENCE when a retried settle/release refuses ambiguously
    /// (the builder-fold Arithmetic mask) — reading it never gates money; admission still does.
    pub fn active_holds_chirho(
        &self,
    ) -> &BTreeMap<crate::admission_chirho::EscrowHoldKeyChirho, u64> {
        &self.active_holds_chirho
    }

    /// Resolve the registry's current continuation policy for a stable kind. This read-only client
    /// seam delegates to the same one-model question used by the CF3 terminal door.
    pub fn current_continuation_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Option<CurrentContinuationPolicyChirho> {
        self.kind_registry_chirho
            .resolve_current_continuation_by_kind_chirho(kind_id_chirho)
    }

    /// Chain-law + fold verification of ONE stored record during open, then state update. This is
    /// STRUCTURAL verification (the record was fully admitted when appended); authority views are
    /// not re-consulted — but posts, conservation-relevant folds, seq, prev, epoch/anchor, and HLC
    /// must all re-verify or the journal is refused.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub(crate) fn replay_verified_chirho(
        &mut self,
        record_chirho: &LedgerRecordChirho,
        line_offset_chirho: u64,
        line_len_chirho: u64,
        line_digest_chirho: &DigestChirho,
    ) -> Result<(), JournalErrorChirho> {
        let expected_seq_chirho = self.tail_seq_chirho + 1;
        if record_chirho.seq_chirho != expected_seq_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: format!(
                    "seq {} where {} expected (dense law)",
                    record_chirho.seq_chirho, expected_seq_chirho
                ),
            });
        }
        if record_chirho.prev_chirho != self.tail_digest_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: format!("prev mismatch at seq {}", record_chirho.seq_chirho),
            });
        }
        match record_chirho
            .epoch_chirho
            .cmp(&self.last_recorded_epoch_chirho)
        {
            std::cmp::Ordering::Less => {
                return Err(JournalErrorChirho::ChainChirho {
                    detail_chirho: format!("epoch regressed at seq {}", record_chirho.seq_chirho),
                })
            }
            std::cmp::Ordering::Equal => {
                if record_chirho.anchor_chirho.is_some() {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "steady-state record at seq {} carries an anchor",
                            record_chirho.seq_chirho
                        ),
                    });
                }
            }
            std::cmp::Ordering::Greater => {
                // First record of a NEW epoch must anchor the handoff point (§11.5).
                let anchor_chirho = record_chirho.anchor_chirho.as_ref().ok_or_else(|| {
                    JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "epoch bump at seq {} without an anchor",
                            record_chirho.seq_chirho
                        ),
                    }
                })?;
                let binds_chirho = anchor_chirho.inherited_epoch_chirho
                    == self.last_recorded_epoch_chirho
                    && anchor_chirho.inherited_seq_chirho == self.tail_seq_chirho
                    && anchor_chirho.inherited_digest_chirho == self.tail_digest_chirho;
                if !binds_chirho {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "anchor at seq {} does not bind the prior tail",
                            record_chirho.seq_chirho
                        ),
                    });
                }
                self.last_recorded_epoch_chirho = record_chirho.epoch_chirho;
                self.current_epoch_chirho = record_chirho.epoch_chirho;
            }
        }
        if record_chirho.hlc_chirho <= self.tail_hlc_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: format!("HLC not monotone at seq {}", record_chirho.seq_chirho),
            });
        }
        // Classify and duplicate-check BEFORE the fold. The shared transition preview names a
        // conflicting terminal outcome before arithmetic can mask it against an already-consumed
        // Hold; append and replay later apply the exact same state mutation.
        let effect_receipt_transition_chirho =
            self.effect_receipt_transition_for_replay_chirho(record_chirho)?;
        // Fold verify every leg from the running heads (F4 chain verify) and apply.
        for leg_chirho in &record_chirho.legs_chirho {
            let state_chirho = self
                .head_states_chirho
                .entry(leg_chirho.account_chirho.clone())
                .or_insert(LegPostStateChirho {
                    credits_total_chirho: 0,
                    debits_total_chirho: 0,
                    held_chirho: 0,
                });
            fold_leg_post_chirho(
                state_chirho,
                &leg_chirho.delta_chirho,
                leg_chirho.amount_chirho,
            )
            .map_err(|_| JournalErrorChirho::ChainChirho {
                detail_chirho: format!("stored fold overflows at seq {}", record_chirho.seq_chirho),
            })?;
            if *state_chirho != leg_chirho.post_chirho {
                return Err(JournalErrorChirho::ChainChirho {
                    detail_chirho: format!(
                        "stored post diverges from the recomputed fold at seq {}",
                        record_chirho.seq_chirho
                    ),
                });
            }
        }
        // Locators: each touched account's LAST leg in this record, at this stored line (§11.4 —
        // WHERE its balance-authority signed leg lives).
        for (leg_index_chirho, leg_chirho) in record_chirho.legs_chirho.iter().enumerate() {
            self.head_locators_chirho.insert(
                leg_chirho.account_chirho.clone(),
                crate::checkpoint_chirho::HeadLocatorChirho {
                    seq_chirho: record_chirho.seq_chirho,
                    leg_index_chirho: leg_index_chirho as u32,
                    line_offset_chirho,
                    line_len_chirho,
                    line_digest_chirho: line_digest_chirho.clone(),
                    post_chirho: leg_chirho.post_chirho.clone(),
                },
            );
        }
        self.apply_supply_chirho(record_chirho)?;
        self.apply_escrow_transition_chirho(record_chirho)?;
        // Replay resolves no authority: it applies only the receipt coordinates structurally bound
        // above. This is the SAME mutation live append uses after full admission.
        self.apply_effect_receipt_transition_chirho(
            record_chirho,
            line_digest_chirho,
            effect_receipt_transition_chirho,
        )?;
        self.tail_seq_chirho = record_chirho.seq_chirho;
        self.tail_hlc_chirho = record_chirho.hlc_chirho.clone();
        // tail_digest is set by the caller (it owns the stored line bytes).
        Ok(())
    }

    pub(crate) fn apply_supply_chirho(
        &mut self,
        record_chirho: &LedgerRecordChirho,
    ) -> Result<(), JournalErrorChirho> {
        match &record_chirho.op_chirho {
            LedgerOpChirho::MintChirho { .. } => {
                let leg_chirho = &record_chirho.legs_chirho[0];
                let kind_id_chirho = leg_chirho.account_chirho.kind_id_chirho.clone();
                let entry_chirho = self
                    .supply_by_kind_chirho
                    .entry(kind_id_chirho)
                    .or_insert(0);
                *entry_chirho = entry_chirho.checked_add(leg_chirho.amount_chirho).ok_or(
                    JournalErrorChirho::ChainChirho {
                        detail_chirho: "supply aggregate overflow".to_owned(),
                    },
                )?;
            }
            LedgerOpChirho::BurnChirho { .. } => {
                let leg_chirho = &record_chirho.legs_chirho[0];
                let entry_chirho = self
                    .supply_by_kind_chirho
                    .entry(leg_chirho.account_chirho.kind_id_chirho.clone())
                    .or_insert(0);
                *entry_chirho = entry_chirho.checked_sub(leg_chirho.amount_chirho).ok_or(
                    JournalErrorChirho::ChainChirho {
                        detail_chirho: "supply aggregate underflow (burn exceeds net supply)"
                            .to_owned(),
                    },
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Derive the next HLC (§11.1): physical = max(clock, tail.physical); logical bumps on a tie
    /// (the monotone guard lives HERE, not in the clock port — a regressing clock cannot regress
    /// the journal).
    fn next_hlc_chirho(&self) -> HlcChirho {
        let now_chirho = self.clock_chirho.physical_now_ms_chirho();
        if now_chirho > self.tail_hlc_chirho.physical_ms_chirho {
            HlcChirho {
                physical_ms_chirho: now_chirho,
                logical_chirho: 0,
            }
        } else {
            HlcChirho {
                physical_ms_chirho: self.tail_hlc_chirho.physical_ms_chirho,
                logical_chirho: self.tail_hlc_chirho.logical_chirho + 1,
            }
        }
    }

    /// The append path: build the record under the lock (posts folded from the LIVE heads, Pr1),
    /// sign its content, pass FULL admission, emit the canonical line, ONE durable append, then
    /// update the live state. Any refusal leaves journal + live state untouched.
    /// Rotate the active file into a sealed segment (B0 brick 3b-ii; STAGED — no production caller
    /// yet, and full_open keeps every rotated journal FAIL-CLOSED at open until the rotated-open
    /// lands in 3b-iii: the genesis-at-line-0 check fires on a non-empty rotated active, and the
    /// 2a base≠0 layout guard backs it for the empty-active case). The Model B-SEQ intent-first cut runs on the seqlog
    /// machinery through the journal's OWN ports (seal → durable signed manifest entry → fresh
    /// active → clear pending), so one code path drives production fs and the crash-matrix sim.
    /// In-memory chain/money state (tail seq/digest/hlc, epochs, heads, supply, idempotency) is
    /// UNCHANGED — rotation is a storage-layout cut, not a state change; the next append chains
    /// prev = tail_digest at seq = tail_seq + 1 across the seam. The active-file byte anchors reset
    /// to the empty fresh active, and the advisory head-checkpoint sidecar is REMOVED: its covered
    /// cut points into the pre-rotation active, and a stale advisory snapshot must MISS, never
    /// mislead (the sidecar is never authority; a checkpoint fast path over sealed history is a
    /// separate later increment).
    pub fn rotate_chirho(&mut self) -> Result<(), JournalErrorChirho> {
        let segment_storage_chirho =
            crate::segment_adapter_chirho::SegmentStorageOverLedgerPortChirho::new_chirho(
                self.storage_chirho,
            );
        let segment_continuity_chirho =
            crate::segment_adapter_chirho::SegmentContinuityOverLedgerSignerPortChirho::new_chirho(
                self.signer_chirho,
            );
        let segment_paths_chirho =
            cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho::new_chirho(
                self.path_chirho.key_chirho(),
            );
        let log_identity_chirho =
            cairn_seqlog_chirho::segment_chirho::LogIdentityChirho::new_chirho(format!(
                "cairn-ledger:{}",
                self.cluster_id_chirho.0
            ));
        cairn_seqlog_chirho::segment_chirho::rotation_chirho::rotate_segment_chirho(
            &segment_storage_chirho,
            &segment_continuity_chirho,
            &segment_paths_chirho,
            &log_identity_chirho,
        )
        .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
            detail_chirho: format!("segment rotation failed: {error_chirho}"),
        })?;
        // The journal's advisory head-checkpoint sidecar is deliberately NOT removed here: a
        // stale pre-rotation sidecar fails the base/manifest-tail binding (and, before that
        // binding existed, the genesis-line check) at the next fast open — must-miss holds
        // STRUCTURALLY without spending a durable call, keeping rotation within the ≤7
        // durability-call boundary budget (clause 3 / RC.5; measured exactly 7 in the sim).
        // Refresh the rotated-checkpoint binding pair from the freshly-sealed manifest (a warm
        // O(1) mhead read; no durable write).
        let refreshed_chirho =
            cairn_seqlog_chirho::segment_chirho::manifest_chirho::derive_base_seq_chirho(
                &segment_storage_chirho,
                &segment_continuity_chirho,
                &segment_paths_chirho,
                &log_identity_chirho.digest_chirho(),
            )
            .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
                detail_chirho: format!("post-rotation base refresh failed: {error_chirho}"),
            })?;
        self.base_seq_chirho = refreshed_chirho.base_seq_chirho;
        self.manifest_tail_entry_digest_chirho = refreshed_chirho.last_entry_digest_chirho;
        self.tail_byte_len_chirho = 0;
        self.tail_physical_byte_len_chirho = 0;
        self.tail_line_offset_chirho = 0;
        self.tail_line_len_chirho = 0;
        Ok(())
    }

    /// Apply one record's escrow-holds transition — the ONE coding shared by append and replay
    /// (CF2 P2): a stored history carrying a duplicate hold or an unmatched release/finalize
    /// FAILS CLOSED at load exactly as a live one refuses at admission.
    pub(crate) fn apply_escrow_transition_chirho(
        &mut self,
        record_chirho: &LedgerRecordChirho,
    ) -> Result<(), JournalErrorChirho> {
        match &record_chirho.op_chirho {
            LedgerOpChirho::EscrowHoldChirho { control_chirho } => {
                let leg_chirho = &record_chirho.legs_chirho[0];
                let key_chirho = crate::admission_chirho::EscrowHoldKeyChirho {
                    account_chirho: leg_chirho.account_chirho.clone(),
                    saga_id_chirho: control_chirho.saga_id_chirho.clone(),
                    step_chirho: control_chirho.step_chirho,
                };
                if self
                    .active_holds_chirho
                    .insert(key_chirho, leg_chirho.amount_chirho)
                    .is_some()
                {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "duplicate escrow hold at seq {} (exact-triple uniqueness)",
                            record_chirho.seq_chirho
                        ),
                    });
                }
            }
            LedgerOpChirho::EscrowReleaseChirho { control_chirho }
            | LedgerOpChirho::EscrowFinalizeChirho { control_chirho } => {
                let leg_chirho = &record_chirho.legs_chirho[0];
                let key_chirho = crate::admission_chirho::EscrowHoldKeyChirho {
                    account_chirho: leg_chirho.account_chirho.clone(),
                    saga_id_chirho: control_chirho.saga_id_chirho.clone(),
                    step_chirho: control_chirho.step_chirho,
                };
                match self.active_holds_chirho.remove(&key_chirho) {
                    Some(held_chirho) if held_chirho == leg_chirho.amount_chirho => {}
                    _ => {
                        return Err(JournalErrorChirho::ChainChirho {
                            detail_chirho: format!(
                                "release/finalize at seq {} names no matching unconsumed hold",
                                record_chirho.seq_chirho
                            ),
                        })
                    }
                }
            }
            LedgerOpChirho::TransferChirho => {
                // F3a law ii's STATE half: consume the claim's nullifier (first claim wins; a
                // replayed line with a consumed nullifier fails the LOAD closed — admission
                // already refused it live, so a chain carrying it is forged or corrupt).
                for leg_chirho in &record_chirho.legs_chirho {
                    if let Some(claim_chirho) = &leg_chirho.counterpart_chirho {
                        if !self
                            .consumed_nullifiers_chirho
                            .insert(claim_chirho.nullifier_chirho.clone())
                        {
                            return Err(JournalErrorChirho::ChainChirho {
                                detail_chirho: format!(
                                    "counterpart nullifier at seq {} was already consumed",
                                    record_chirho.seq_chirho
                                ),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Advance the shard-lease epoch (§11.5 — granted by the lease authority: Model A's fence
    /// today, the A6 Raft term later; the ENGINE only enforces monotonicity and the anchor law).
    /// The next successful append becomes the new epoch's FIRST record and automatically carries
    /// the anchor binding the pre-advance tail. Reopen resumes the lease at the last RECORDED
    /// epoch — a never-used advance does not survive a restart (the authority re-grants).
    pub fn advance_epoch_chirho(
        &mut self,
        new_epoch_chirho: ShardEpochChirho,
    ) -> Result<(), JournalErrorChirho> {
        if new_epoch_chirho <= self.current_epoch_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: format!(
                    "epoch advance must be monotone ({} -> {})",
                    self.current_epoch_chirho, new_epoch_chirho
                ),
            });
        }
        self.current_epoch_chirho = new_epoch_chirho;
        Ok(())
    }

    /// The lease epoch appends currently run under.
    pub fn current_epoch_chirho(&self) -> ShardEpochChirho {
        self.current_epoch_chirho
    }

    /// The journal instance identity (the genesis stored-line digest, §11.6).
    pub fn genesis_digest_chirho(&self) -> &DigestChirho {
        &self.genesis_digest_chirho
    }

    /// The verified TAIL stored-line digest (read-only). Because prev-binding is dense, this one
    /// digest commits the entire verified prefix — it is the signed-prefix coordinate a follow
    /// receipt binds so a fork at the same seq/HLC cannot impersonate this history.
    pub fn tail_line_digest_chirho(&self) -> &DigestChirho {
        &self.tail_digest_chirho
    }

    /// The cluster this journal serves.
    pub fn cluster_id_chirho(&self) -> &ClusterIdChirho {
        &self.cluster_id_chirho
    }

    /// Current tail (seq, digest) — the chain head.
    pub fn tail_chirho(&self) -> (u64, &DigestChirho) {
        (self.tail_seq_chirho, &self.tail_digest_chirho)
    }

    #[cfg(test)]
    pub(crate) fn manifest_tail_entry_digest_for_test_chirho(&self) -> Option<&str> {
        self.manifest_tail_entry_digest_chirho.as_deref()
    }

    /// The live head post-state for an account (None = never touched ⇒ zero baseline).
    pub fn head_state_chirho(
        &self,
        account_chirho: &AccountIdChirho,
    ) -> Option<&LegPostStateChirho> {
        self.head_states_chirho.get(account_chirho)
    }

    /// Net supply for a stable kind.
    pub fn supply_chirho(&self, kind_id_chirho: &AssetKindIdChirho) -> u64 {
        self.supply_by_kind_chirho
            .get(kind_id_chirho)
            .copied()
            .unwrap_or(0)
    }
}
