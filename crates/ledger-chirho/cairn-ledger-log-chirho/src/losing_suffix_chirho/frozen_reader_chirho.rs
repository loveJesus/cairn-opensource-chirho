// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Held-only authenticated journal-cut derivation without aggregate replay or checkpoint trust.
//!
//! The reader verifies the exact resident genesis, direct authenticated manifest tail/index,
//! fixed-size signed canary floor, and final complete signed physical line under the caller's writer
//! lock. A bounded unacknowledged torn suffix is retained byte-exact but excluded from the clean
//! cut. Every subsequent operation re-derives the same physical snapshot before and after use. No
//! aggregate balance, mutation, or repair API is exposed. Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::{
    load_index_entry_chirho, storage_error_chirho, validate_manifest_digest_chirho,
    LosingSuffixCursorChirho, LosingSuffixPageRequestChirho, LosingSuffixReadErrorChirho,
    LosingSuffixReaderChirho, VerifiedLosingJournalTailChirho, VerifiedLosingSuffixPageChirho,
    INITIAL_REVERSE_READ_BYTES_CHIRHO, MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO,
};
use crate::journal_chirho::{
    verify_tail_signature_chirho, ExpectedLedgerGenesisChirho, JournalPortsChirho,
    LedgerJournalChirho,
};
use crate::segment_adapter_chirho::{
    SegmentContinuityOverLedgerSignerPortChirho, SegmentStorageOverLedgerPortChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::{CrossZoneAnchorChirho, HlcChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_seqlog_chirho::segment_chirho::manifest_chirho::{
    new_segment_manifest_entry_chirho, BaseSeqChirho, SegmentManifestEntryChirho,
};
use cairn_seqlog_chirho::segment_chirho::manifest_head_chirho::{
    inspect_manifest_tail_for_held_cut_read_only_chirho, AuthenticatedManifestTailSnapshotChirho,
    EntirelyTornManifestTailSnapshotChirho, ReadOnlyManifestTailSnapshotChirho,
};
use cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho;
use cairn_seqlog_chirho::segment_chirho::predecessor_index_chirho::load_predecessor_index_entry_chirho;
use cairn_seqlog_chirho::segment_chirho::rotation_chirho::{
    inspect_rotation_intent_read_only_chirho, ReadOnlyRotationIntentChirho,
};
use cairn_seqlog_chirho::segment_chirho::storage_chirho::SegmentStorageChirho;
use cairn_seqlog_chirho::segment_chirho::LogIdentityChirho;
use std::collections::{BTreeMap, BTreeSet};

const MAX_FROZEN_TORN_SUFFIX_BYTES_CHIRHO: usize = MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO;
const MAX_FROZEN_ACTIVE_TAIL_WINDOW_BYTES_CHIRHO: usize =
    (MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO * 2) + 3;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FrozenTailObservationChirho {
    seq_chirho: u64,
    digest_chirho: DigestChirho,
    epoch_chirho: u64,
    hlc_chirho: HlcChirho,
    line_offset_chirho: u64,
    line_len_chirho: u64,
    is_genesis_chirho: bool,
    previous_digest_chirho: Option<DigestChirho>,
    anchor_chirho: Option<CrossZoneAnchorChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FrozenPhysicalSnapshotChirho {
    base_chirho: BaseSeqChirho,
    manifest_chirho: Option<ReadOnlyManifestTailSnapshotChirho>,
    rotation_chirho: Option<ReadOnlyRotationIntentChirho>,
    active_physical_len_chirho: u64,
    active_clean_len_chirho: u64,
    active_torn_len_chirho: u64,
    active_torn_digest_chirho: Option<String>,
    tail_chirho: FrozenTailObservationChirho,
}

struct DerivedFrozenCutChirho {
    snapshot_chirho: FrozenPhysicalSnapshotChirho,
    floor_relation_chirho: VerifiedLosingTailFloorRelationChirho,
}

struct ActiveTailCutChirho {
    physical_len_chirho: u64,
    clean_len_chirho: u64,
    torn_len_chirho: u64,
    torn_digest_chirho: Option<String>,
    physical_line_digest_chirho: Option<String>,
    body_chirho: Option<Vec<u8>>,
    line_offset_chirho: u64,
}

/// The latest fixed-size canary cut that an activated production resident acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedLosingTailFloorChirho {
    seq_chirho: u64,
    record_digest_chirho: DigestChirho,
    hlc_chirho: HlcChirho,
    recorded_epoch_chirho: u64,
}

impl ExpectedLosingTailFloorChirho {
    pub fn new_chirho(
        seq_chirho: u64,
        record_digest_chirho: DigestChirho,
        hlc_chirho: HlcChirho,
        recorded_epoch_chirho: u64,
    ) -> Self {
        Self {
            seq_chirho,
            record_digest_chirho,
            hlc_chirho,
            recorded_epoch_chirho,
        }
    }
}

/// How the physical tail relates to the last authority-observed fixed-size canary cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedLosingTailFloorRelationChirho {
    ExactCanaryChirho,
    OneCommittedRecordAheadChirho,
}

/// A held-only reader whose clean cut is derived from bounded authenticated journal metadata.
pub struct FrozenLosingJournalReaderChirho<'ports_chirho> {
    journal_chirho: LedgerJournalChirho<'ports_chirho>,
    expected_genesis_chirho: ExpectedLedgerGenesisChirho,
    snapshot_chirho: FrozenPhysicalSnapshotChirho,
    floor_chirho: ExpectedLosingTailFloorChirho,
    floor_relation_chirho: VerifiedLosingTailFloorRelationChirho,
}

impl<'ports_chirho> FrozenLosingJournalReaderChirho<'ports_chirho> {
    /// Derive and freeze the exact current losing cut without reading a head checkpoint or replaying
    /// aggregate state. The caller must retain the single-writer lock for this reader's lifetime.
    pub fn open_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: crate::ports_chirho::StoragePathChirho,
        expected_genesis_chirho: &ExpectedLedgerGenesisChirho,
        floor_chirho: &ExpectedLosingTailFloorChirho,
    ) -> Result<Self, LosingSuffixReadErrorChirho> {
        let derived_chirho = derive_frozen_cut_chirho(
            ports_chirho,
            &path_chirho,
            expected_genesis_chirho,
            floor_chirho,
        )?;
        let tail_chirho = &derived_chirho.snapshot_chirho.tail_chirho;
        let base_chirho = &derived_chirho.snapshot_chirho.base_chirho;
        let journal_chirho = LedgerJournalChirho {
            storage_chirho: ports_chirho.storage_chirho,
            signer_chirho: ports_chirho.signer_chirho,
            clock_chirho: ports_chirho.clock_chirho,
            membership_chirho: ports_chirho.membership_chirho,
            kind_registry_chirho: ports_chirho.kind_registry_chirho,
            authority_chirho: ports_chirho.authority_chirho,
            append_mirror_chirho: None,
            path_chirho,
            cluster_id_chirho: expected_genesis_chirho.cluster_id_chirho().clone(),
            current_epoch_chirho: tail_chirho.epoch_chirho,
            last_recorded_epoch_chirho: tail_chirho.epoch_chirho,
            tail_seq_chirho: tail_chirho.seq_chirho,
            tail_digest_chirho: tail_chirho.digest_chirho.clone(),
            tail_hlc_chirho: tail_chirho.hlc_chirho.clone(),
            genesis_digest_chirho: expected_genesis_chirho.digest_chirho().clone(),
            canonical_genesis_line_chirho: Some(
                expected_genesis_chirho.canonical_line_chirho().to_string(),
            ),
            head_states_chirho: BTreeMap::new(),
            supply_by_kind_chirho: BTreeMap::new(),
            idempotency_keys_chirho: BTreeSet::new(),
            effect_receipt_window_chirho: BTreeMap::new(),
            active_holds_chirho: BTreeMap::new(),
            consumed_nullifiers_chirho: BTreeSet::new(),
            finality_chirho: None,
            repaired_torn_tail_bytes_chirho: None,
            tail_byte_len_chirho: derived_chirho.snapshot_chirho.active_clean_len_chirho,
            tail_physical_byte_len_chirho: derived_chirho
                .snapshot_chirho
                .active_physical_len_chirho,
            tail_line_offset_chirho: tail_chirho.line_offset_chirho,
            tail_line_len_chirho: tail_chirho.line_len_chirho,
            genesis_line_len_chirho: expected_genesis_chirho.canonical_line_chirho().len() as u64,
            base_seq_chirho: base_chirho.base_seq_chirho,
            manifest_tail_entry_digest_chirho: base_chirho.last_entry_digest_chirho.clone(),
            head_locators_chirho: BTreeMap::new(),
            last_open_was_fast_chirho: false,
        };
        let reader_chirho = Self {
            journal_chirho,
            expected_genesis_chirho: expected_genesis_chirho.clone(),
            snapshot_chirho: derived_chirho.snapshot_chirho,
            floor_chirho: floor_chirho.clone(),
            floor_relation_chirho: derived_chirho.floor_relation_chirho,
        };
        reader_chirho.verify_frozen_snapshot_chirho()?;
        Ok(reader_chirho)
    }

    pub fn verified_losing_tail_chirho(&self) -> VerifiedLosingJournalTailChirho {
        self.journal_chirho.verified_losing_tail_chirho()
    }

    pub fn floor_relation_chirho(&self) -> VerifiedLosingTailFloorRelationChirho {
        self.floor_relation_chirho
    }

    fn ports_chirho(&self) -> JournalPortsChirho<'_> {
        JournalPortsChirho {
            storage_chirho: self.journal_chirho.storage_chirho,
            signer_chirho: self.journal_chirho.signer_chirho,
            clock_chirho: self.journal_chirho.clock_chirho,
            membership_chirho: self.journal_chirho.membership_chirho,
            kind_registry_chirho: self.journal_chirho.kind_registry_chirho,
            authority_chirho: self.journal_chirho.authority_chirho,
        }
    }

    fn verify_frozen_snapshot_chirho(
        &self,
    ) -> Result<VerifiedLosingJournalTailChirho, LosingSuffixReadErrorChirho> {
        let observed_chirho = derive_frozen_cut_chirho(
            self.ports_chirho(),
            &self.journal_chirho.path_chirho,
            &self.expected_genesis_chirho,
            &self.floor_chirho,
        )?;
        if observed_chirho.snapshot_chirho != self.snapshot_chirho
            || observed_chirho.floor_relation_chirho != self.floor_relation_chirho
        {
            return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho: "held journal physical cut changed after it was frozen".to_owned(),
            });
        }
        Ok(self.verified_losing_tail_chirho())
    }
}

impl LosingSuffixReaderChirho for FrozenLosingJournalReaderChirho<'_> {
    fn injected_journal_key_id_chirho(&self) -> String {
        self.journal_chirho.signer_chirho.key_id_chirho()
    }

    fn revalidate_current_losing_tail_chirho(
        &self,
    ) -> Result<VerifiedLosingJournalTailChirho, LosingSuffixReadErrorChirho> {
        self.verify_frozen_snapshot_chirho()
    }

    fn decode_verified_losing_suffix_cursor_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<LosingSuffixCursorChirho, LosingSuffixReadErrorChirho> {
        self.verify_frozen_snapshot_chirho()?;
        let cursor_chirho = self
            .journal_chirho
            .decode_verified_losing_suffix_cursor_chirho(bytes_chirho)?;
        self.verify_frozen_snapshot_chirho()?;
        Ok(cursor_chirho)
    }

    fn read_verified_losing_suffix_page_chirho(
        &self,
        request_chirho: &LosingSuffixPageRequestChirho,
    ) -> Result<VerifiedLosingSuffixPageChirho, LosingSuffixReadErrorChirho> {
        self.verify_frozen_snapshot_chirho()?;
        let page_chirho = self
            .journal_chirho
            .read_verified_losing_suffix_page_chirho(request_chirho)?;
        self.verify_frozen_snapshot_chirho()?;
        Ok(page_chirho)
    }
}

fn derive_frozen_cut_chirho(
    ports_chirho: JournalPortsChirho<'_>,
    path_chirho: &crate::ports_chirho::StoragePathChirho,
    expected_genesis_chirho: &ExpectedLedgerGenesisChirho,
    floor_chirho: &ExpectedLosingTailFloorChirho,
) -> Result<DerivedFrozenCutChirho, LosingSuffixReadErrorChirho> {
    let storage_chirho =
        SegmentStorageOverLedgerPortChirho::new_chirho(ports_chirho.storage_chirho);
    let continuity_chirho =
        SegmentContinuityOverLedgerSignerPortChirho::new_chirho(ports_chirho.signer_chirho);
    let paths_chirho = SegmentPathsChirho::new_chirho(path_chirho.key_chirho());
    let identity_chirho = LogIdentityChirho::new_chirho(format!(
        "cairn-ledger:{}",
        expected_genesis_chirho.cluster_id_chirho().0
    ));
    let identity_digest_chirho = identity_chirho.digest_chirho();
    let manifest_chirho = inspect_manifest_tail_for_held_cut_read_only_chirho(
        &storage_chirho,
        &continuity_chirho,
        &paths_chirho,
        &identity_digest_chirho,
    )
    .map_err(
        |error_chirho| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: format!(
                "bounded authenticated manifest-tail inspection refused: {error_chirho:#}"
            ),
        },
    )?;
    let rotation_chirho = inspect_rotation_intent_read_only_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_digest_chirho,
    )
    .map_err(
        |error_chirho| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: format!(
                "bounded read-only rotation-marker inspection refused: {error_chirho:#}"
            ),
        },
    )?;
    match manifest_chirho.as_ref() {
        Some(ReadOnlyManifestTailSnapshotChirho::EntirelyTornChirho(_)) => {
            LedgerJournalChirho::preflight_expected_genesis_from_active_chirho(
                ports_chirho,
                path_chirho,
                expected_genesis_chirho,
            )
        }
        _ => LedgerJournalChirho::preflight_expected_genesis_chirho(
            ports_chirho,
            path_chirho.clone(),
            expected_genesis_chirho,
        )
        .map(|_preflight_chirho| ()),
    }
    .map_err(
        |error_chirho| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: format!(
                "held journal exact resident genesis preflight refused: {error_chirho:?}"
            ),
        },
    )?;
    let authenticated_manifest_chirho =
        manifest_chirho
            .as_ref()
            .and_then(|manifest_chirho| match manifest_chirho {
                ReadOnlyManifestTailSnapshotChirho::AuthenticatedChirho(manifest_chirho) => {
                    Some(manifest_chirho)
                }
                ReadOnlyManifestTailSnapshotChirho::EntirelyTornChirho(_) => None,
            });
    if let Some(ReadOnlyManifestTailSnapshotChirho::EntirelyTornChirho(torn_manifest_chirho)) =
        manifest_chirho.as_ref()
    {
        verify_entirely_torn_first_manifest_append_chirho(
            &storage_chirho,
            &continuity_chirho,
            &paths_chirho,
            &identity_chirho,
            rotation_chirho.as_ref(),
            torn_manifest_chirho,
        )?;
    }
    let (base_chirho, sealed_tail_entry_chirho) = derive_authenticated_seal_state_chirho(
        &storage_chirho,
        &continuity_chirho,
        &paths_chirho,
        &identity_digest_chirho,
        authenticated_manifest_chirho,
    )?;
    let active_chirho = read_active_tail_cut_chirho(
        ports_chirho.storage_chirho,
        path_chirho,
        base_chirho.base_seq_chirho,
    )?;
    let active_tail_chirho = active_chirho
        .body_chirho
        .as_deref()
        .map(|body_chirho| {
            verify_tail_body_chirho(
                body_chirho,
                active_chirho.line_offset_chirho,
                ports_chirho.signer_chirho,
                expected_genesis_chirho,
            )
        })
        .transpose()?;
    let (effective_active_clean_len_chirho, tail_chirho) = classify_frozen_cut_chirho(
        &storage_chirho,
        &paths_chirho,
        ports_chirho.signer_chirho,
        expected_genesis_chirho,
        &base_chirho,
        authenticated_manifest_chirho,
        rotation_chirho.as_ref(),
        sealed_tail_entry_chirho.as_ref(),
        &active_chirho,
        active_tail_chirho.as_ref(),
    )?;
    if tail_chirho.seq_chirho == 0 && !tail_chirho.is_genesis_chirho {
        return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
            detail_chirho: "sequence zero must be the exact resident genesis".to_owned(),
        });
    }
    let floor_relation_chirho = verify_tail_floor_chirho(&tail_chirho, floor_chirho)?;
    Ok(DerivedFrozenCutChirho {
        snapshot_chirho: FrozenPhysicalSnapshotChirho {
            base_chirho,
            manifest_chirho,
            rotation_chirho,
            active_physical_len_chirho: active_chirho.physical_len_chirho,
            active_clean_len_chirho: effective_active_clean_len_chirho,
            active_torn_len_chirho: active_chirho.torn_len_chirho,
            active_torn_digest_chirho: active_chirho.torn_digest_chirho,
            tail_chirho,
        },
        floor_relation_chirho,
    })
}

fn verify_entirely_torn_first_manifest_append_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    continuity_chirho: &SegmentContinuityOverLedgerSignerPortChirho<'_>,
    paths_chirho: &SegmentPathsChirho,
    identity_chirho: &LogIdentityChirho,
    rotation_chirho: Option<&ReadOnlyRotationIntentChirho>,
    torn_manifest_chirho: &EntirelyTornManifestTailSnapshotChirho,
) -> Result<(), LosingSuffixReadErrorChirho> {
    let rotation_chirho =
        rotation_chirho.ok_or_else(|| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: "entirely torn first manifest append has no retained rotation marker"
                .to_owned(),
        })?;
    if rotation_chirho.generation_chirho != 0
        || rotation_chirho.first_seq_chirho != 0
        || rotation_chirho.last_seq_chirho.checked_add(1).is_none()
        || torn_manifest_chirho.manifest_physical_len_chirho
            != torn_manifest_chirho.bytes_chirho.len() as u64
        || torn_manifest_chirho.bytes_digest_chirho
            != blake3::hash(&torn_manifest_chirho.bytes_chirho)
                .to_hex()
                .to_string()
    {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "entirely torn manifest does not satisfy the generation-zero physical contract"
                    .to_owned(),
        });
    }
    let expected_entry_chirho = new_segment_manifest_entry_chirho(
        identity_chirho,
        rotation_chirho.generation_chirho,
        rotation_chirho.first_seq_chirho,
        rotation_chirho.last_seq_chirho,
        rotation_chirho.byte_len_chirho,
        rotation_chirho.segment_digest_chirho.clone(),
        rotation_chirho.final_line_digest_chirho.clone(),
        None,
    );
    let expected_digest_chirho =
        expected_entry_chirho
            .entry_digest_chirho()
            .map_err(
                |error_chirho| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                    detail_chirho: format!(
                        "derive generation-zero manifest entry digest: {error_chirho:#}"
                    ),
                },
            )?;
    let signed_line_chirho = load_predecessor_index_entry_chirho(
        storage_chirho,
        continuity_chirho,
        paths_chirho,
        &expected_digest_chirho,
        &identity_chirho.digest_chirho(),
    )
    .map_err(
        |error_chirho| LosingSuffixReadErrorChirho::PredecessorIndexChirho {
            digest_chirho: expected_digest_chirho,
            detail_chirho: format!("{error_chirho:#}"),
        },
    )?;
    if signed_line_chirho.entry_chirho != expected_entry_chirho {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: "generation-zero predecessor index disagrees with the rotation marker"
                .to_owned(),
        });
    }
    let mut expected_physical_line_chirho =
        serde_json::to_vec(&signed_line_chirho).map_err(|error_chirho| {
            LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho: format!(
                    "encode generation-zero signed manifest line: {error_chirho}"
                ),
            }
        })?;
    expected_physical_line_chirho.push(b'\n');
    if torn_manifest_chirho.bytes_chirho.is_empty()
        || torn_manifest_chirho.bytes_chirho.len() >= expected_physical_line_chirho.len()
        || !expected_physical_line_chirho.starts_with(&torn_manifest_chirho.bytes_chirho)
    {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "entirely torn manifest is not an exact prefix of its authenticated first line"
                    .to_owned(),
        });
    }
    Ok(())
}

fn derive_authenticated_seal_state_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    continuity_chirho: &SegmentContinuityOverLedgerSignerPortChirho<'_>,
    paths_chirho: &SegmentPathsChirho,
    identity_digest_chirho: &str,
    manifest_chirho: Option<&AuthenticatedManifestTailSnapshotChirho>,
) -> Result<(BaseSeqChirho, Option<SegmentManifestEntryChirho>), LosingSuffixReadErrorChirho> {
    let Some(manifest_chirho) = manifest_chirho else {
        return Ok((
            BaseSeqChirho {
                base_seq_chirho: 0,
                sealed_segment_count_chirho: 0,
                last_entry_digest_chirho: None,
            },
            None,
        ));
    };
    let digest_chirho = manifest_chirho
        .base_chirho
        .last_entry_digest_chirho
        .as_deref()
        .ok_or_else(|| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: "authenticated manifest tail omits its final entry digest".to_owned(),
        })?;
    validate_manifest_digest_chirho(digest_chirho)?;
    let entry_chirho = load_index_entry_chirho(
        storage_chirho,
        continuity_chirho,
        paths_chirho,
        identity_digest_chirho,
        digest_chirho,
    )?;
    if entry_chirho != manifest_chirho.entry_chirho
        || entry_chirho.next_first_seq_chirho != manifest_chirho.base_chirho.base_seq_chirho
        || entry_chirho.generation_chirho.checked_add(1)
            != Some(manifest_chirho.base_chirho.sealed_segment_count_chirho)
    {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "authenticated manifest tail and predecessor index disagree on the sealed tail"
                    .to_owned(),
        });
    }
    Ok((manifest_chirho.base_chirho.clone(), Some(entry_chirho)))
}

#[allow(clippy::too_many_arguments)]
fn classify_frozen_cut_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    signer_chirho: &dyn crate::ports_chirho::LedgerSignerPortChirho,
    expected_genesis_chirho: &ExpectedLedgerGenesisChirho,
    base_chirho: &BaseSeqChirho,
    manifest_chirho: Option<&AuthenticatedManifestTailSnapshotChirho>,
    rotation_chirho: Option<&ReadOnlyRotationIntentChirho>,
    sealed_entry_chirho: Option<&SegmentManifestEntryChirho>,
    active_chirho: &ActiveTailCutChirho,
    active_tail_chirho: Option<&FrozenTailObservationChirho>,
) -> Result<(u64, FrozenTailObservationChirho), LosingSuffixReadErrorChirho> {
    if let Some(rotation_chirho) = rotation_chirho {
        if manifest_chirho.is_some_and(|manifest_chirho| {
            manifest_chirho.entry_chirho.generation_chirho == rotation_chirho.generation_chirho
        }) {
            return classify_post_manifest_rotation_chirho(
                storage_chirho,
                paths_chirho,
                signer_chirho,
                expected_genesis_chirho,
                manifest_chirho.expect("checked Some"),
                rotation_chirho,
                sealed_entry_chirho.expect("manifest tail has an indexed entry"),
                active_chirho,
                active_tail_chirho,
            );
        }
        let sealed_count_chirho = manifest_chirho
            .map(|manifest_chirho| manifest_chirho.base_chirho.sealed_segment_count_chirho)
            .unwrap_or(0);
        if sealed_count_chirho == rotation_chirho.generation_chirho {
            return classify_pre_manifest_rotation_chirho(
                base_chirho,
                rotation_chirho,
                active_chirho,
                active_tail_chirho,
            );
        }
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "rotation marker generation is neither immediately before nor at the authenticated manifest tail"
                    .to_owned(),
        });
    }

    if manifest_chirho.is_some_and(|manifest_chirho| manifest_chirho.torn_suffix_len_chirho != 0) {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "manifest has a torn suffix without the rotation marker that would classify it"
                    .to_owned(),
        });
    }
    if let Some(active_tail_chirho) = active_tail_chirho {
        verify_active_tail_after_base_chirho(active_tail_chirho, base_chirho)?;
        return Ok((active_chirho.clean_len_chirho, active_tail_chirho.clone()));
    }
    let sealed_entry_chirho = sealed_entry_chirho.ok_or_else(|| {
        LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
            detail_chirho:
                "journal has neither a complete active line nor an authenticated sealed tail"
                    .to_owned(),
        }
    })?;
    let sealed_tail_chirho = read_verified_sealed_tail_chirho(
        storage_chirho,
        paths_chirho,
        signer_chirho,
        expected_genesis_chirho,
        base_chirho,
        sealed_entry_chirho,
    )?;
    Ok((0, sealed_tail_chirho))
}

fn classify_pre_manifest_rotation_chirho(
    base_chirho: &BaseSeqChirho,
    rotation_chirho: &ReadOnlyRotationIntentChirho,
    active_chirho: &ActiveTailCutChirho,
    active_tail_chirho: Option<&FrozenTailObservationChirho>,
) -> Result<(u64, FrozenTailObservationChirho), LosingSuffixReadErrorChirho> {
    let active_tail_chirho =
        active_tail_chirho.ok_or_else(|| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: "pre-manifest rotation marker has no complete active tail".to_owned(),
        })?;
    verify_active_tail_after_base_chirho(active_tail_chirho, base_chirho)?;
    if rotation_chirho.first_seq_chirho != base_chirho.base_seq_chirho
        || rotation_chirho.last_seq_chirho != active_tail_chirho.seq_chirho
        || active_chirho.physical_len_chirho != rotation_chirho.byte_len_chirho
        || active_chirho.clean_len_chirho != active_chirho.physical_len_chirho
        || active_chirho.torn_len_chirho != 0
        || active_chirho.physical_line_digest_chirho.as_deref()
            != Some(rotation_chirho.final_line_digest_chirho.as_str())
    {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: "pre-manifest rotation marker disagrees with the bounded active cut"
                .to_owned(),
        });
    }
    Ok((active_chirho.clean_len_chirho, active_tail_chirho.clone()))
}

#[allow(clippy::too_many_arguments)]
fn classify_post_manifest_rotation_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    signer_chirho: &dyn crate::ports_chirho::LedgerSignerPortChirho,
    expected_genesis_chirho: &ExpectedLedgerGenesisChirho,
    manifest_chirho: &AuthenticatedManifestTailSnapshotChirho,
    rotation_chirho: &ReadOnlyRotationIntentChirho,
    sealed_entry_chirho: &SegmentManifestEntryChirho,
    active_chirho: &ActiveTailCutChirho,
    active_tail_chirho: Option<&FrozenTailObservationChirho>,
) -> Result<(u64, FrozenTailObservationChirho), LosingSuffixReadErrorChirho> {
    let entry_chirho = &manifest_chirho.entry_chirho;
    if entry_chirho.first_seq_chirho != rotation_chirho.first_seq_chirho
        || entry_chirho.last_seq_chirho != rotation_chirho.last_seq_chirho
        || entry_chirho.byte_len_chirho != rotation_chirho.byte_len_chirho
        || entry_chirho.segment_digest_chirho != rotation_chirho.segment_digest_chirho
        || entry_chirho.final_line_digest_chirho != rotation_chirho.final_line_digest_chirho
    {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "post-manifest rotation marker disagrees with the authenticated manifest entry"
                    .to_owned(),
        });
    }
    let sealed_tail_chirho = read_verified_sealed_tail_chirho(
        storage_chirho,
        paths_chirho,
        signer_chirho,
        expected_genesis_chirho,
        &manifest_chirho.base_chirho,
        sealed_entry_chirho,
    )?;
    if active_chirho.physical_len_chirho == 0 {
        return Ok((0, sealed_tail_chirho));
    }
    let active_tail_chirho =
        active_tail_chirho.ok_or_else(|| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "post-manifest rotation active file is neither empty nor a complete duplicate"
                    .to_owned(),
        })?;
    if active_chirho.physical_len_chirho != rotation_chirho.byte_len_chirho
        || active_chirho.clean_len_chirho != active_chirho.physical_len_chirho
        || active_chirho.torn_len_chirho != 0
        || active_chirho.physical_line_digest_chirho.as_deref()
            != Some(rotation_chirho.final_line_digest_chirho.as_str())
        || !same_tail_record_chirho(active_tail_chirho, &sealed_tail_chirho)
    {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "post-manifest rotation active duplicate disagrees with sealed authority".to_owned(),
        });
    }
    Ok((0, sealed_tail_chirho))
}

fn read_verified_sealed_tail_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    signer_chirho: &dyn crate::ports_chirho::LedgerSignerPortChirho,
    expected_genesis_chirho: &ExpectedLedgerGenesisChirho,
    base_chirho: &BaseSeqChirho,
    entry_chirho: &SegmentManifestEntryChirho,
) -> Result<FrozenTailObservationChirho, LosingSuffixReadErrorChirho> {
    let body_chirho = read_sealed_tail_body_chirho(storage_chirho, paths_chirho, entry_chirho)?;
    let tail_chirho =
        verify_tail_body_chirho(&body_chirho, 0, signer_chirho, expected_genesis_chirho)?;
    if tail_chirho.seq_chirho != entry_chirho.last_seq_chirho
        || entry_chirho.next_first_seq_chirho != base_chirho.base_seq_chirho
    {
        return Err(LosingSuffixReadErrorChirho::RecordSequenceMismatchChirho {
            expected_chirho: entry_chirho.last_seq_chirho,
            observed_chirho: tail_chirho.seq_chirho,
        });
    }
    Ok(tail_chirho)
}

fn verify_active_tail_after_base_chirho(
    tail_chirho: &FrozenTailObservationChirho,
    base_chirho: &BaseSeqChirho,
) -> Result<(), LosingSuffixReadErrorChirho> {
    if base_chirho.base_seq_chirho > 0
        && (tail_chirho.is_genesis_chirho || tail_chirho.seq_chirho < base_chirho.base_seq_chirho)
    {
        return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
            detail_chirho: "active tail does not follow the authenticated sealed-segment base"
                .to_owned(),
        });
    }
    Ok(())
}

fn same_tail_record_chirho(
    left_chirho: &FrozenTailObservationChirho,
    right_chirho: &FrozenTailObservationChirho,
) -> bool {
    left_chirho.seq_chirho == right_chirho.seq_chirho
        && left_chirho.digest_chirho == right_chirho.digest_chirho
        && left_chirho.epoch_chirho == right_chirho.epoch_chirho
        && left_chirho.hlc_chirho == right_chirho.hlc_chirho
        && left_chirho.is_genesis_chirho == right_chirho.is_genesis_chirho
        && left_chirho.previous_digest_chirho == right_chirho.previous_digest_chirho
        && left_chirho.anchor_chirho == right_chirho.anchor_chirho
}

fn verify_tail_floor_chirho(
    tail_chirho: &FrozenTailObservationChirho,
    floor_chirho: &ExpectedLosingTailFloorChirho,
) -> Result<VerifiedLosingTailFloorRelationChirho, LosingSuffixReadErrorChirho> {
    if tail_chirho.seq_chirho == floor_chirho.seq_chirho
        && tail_chirho.digest_chirho == floor_chirho.record_digest_chirho
        && tail_chirho.hlc_chirho == floor_chirho.hlc_chirho
        && tail_chirho.epoch_chirho == floor_chirho.recorded_epoch_chirho
    {
        return Ok(VerifiedLosingTailFloorRelationChirho::ExactCanaryChirho);
    }
    let Some(one_ahead_seq_chirho) = floor_chirho.seq_chirho.checked_add(1) else {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho: "canary sequence cannot advance beyond u64::MAX".to_owned(),
        });
    };
    if tail_chirho.seq_chirho != one_ahead_seq_chirho
        || tail_chirho.is_genesis_chirho
        || tail_chirho.previous_digest_chirho.as_ref() != Some(&floor_chirho.record_digest_chirho)
        || tail_chirho.hlc_chirho <= floor_chirho.hlc_chirho
        || tail_chirho.epoch_chirho < floor_chirho.recorded_epoch_chirho
    {
        return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "authenticated journal tail is neither the canary cut nor its one-record crash gap"
                    .to_owned(),
        });
    }
    if tail_chirho.epoch_chirho == floor_chirho.recorded_epoch_chirho {
        if tail_chirho.anchor_chirho.is_some() {
            return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho:
                    "same-epoch one-record crash gap unexpectedly carries a cross-zone anchor"
                        .to_owned(),
            });
        }
    } else {
        let anchor_chirho = tail_chirho.anchor_chirho.as_ref().ok_or_else(|| {
            LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho:
                    "epoch-advancing one-record crash gap omits its exact inherited anchor"
                        .to_owned(),
            }
        })?;
        if anchor_chirho.inherited_epoch_chirho != floor_chirho.recorded_epoch_chirho
            || anchor_chirho.inherited_seq_chirho != floor_chirho.seq_chirho
            || anchor_chirho.inherited_digest_chirho != floor_chirho.record_digest_chirho
        {
            return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho:
                    "epoch-advancing one-record crash gap anchor disagrees with the canary cut"
                        .to_owned(),
            });
        }
    }
    Ok(VerifiedLosingTailFloorRelationChirho::OneCommittedRecordAheadChirho)
}

fn read_active_tail_cut_chirho(
    storage_chirho: &dyn crate::ports_chirho::LedgerStoragePortChirho,
    path_chirho: &crate::ports_chirho::StoragePathChirho,
    base_seq_chirho: u64,
) -> Result<ActiveTailCutChirho, LosingSuffixReadErrorChirho> {
    let physical_len_chirho = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(storage_error_chirho)?
        .ok_or(LosingSuffixReadErrorChirho::ActiveLengthMismatchChirho {
            expected_chirho: 0,
            observed_chirho: None,
        })?;
    if physical_len_chirho == 0 {
        return Ok(ActiveTailCutChirho {
            physical_len_chirho,
            clean_len_chirho: 0,
            torn_len_chirho: 0,
            torn_digest_chirho: None,
            physical_line_digest_chirho: None,
            body_chirho: None,
            line_offset_chirho: 0,
        });
    }
    let mut requested_chirho =
        INITIAL_REVERSE_READ_BYTES_CHIRHO.min(MAX_FROZEN_ACTIVE_TAIL_WINDOW_BYTES_CHIRHO);
    loop {
        let read_len_chirho = physical_len_chirho.min(requested_chirho as u64);
        let start_chirho = physical_len_chirho - read_len_chirho;
        let bytes_chirho = storage_chirho
            .read_exact_range_chirho(path_chirho, start_chirho, read_len_chirho)
            .map_err(storage_error_chirho)?;
        let Some(last_lf_chirho) = bytes_chirho
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
        else {
            if start_chirho == 0 && base_seq_chirho > 0 {
                if bytes_chirho.len() > MAX_FROZEN_TORN_SUFFIX_BYTES_CHIRHO {
                    return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
                        observed_chirho: bytes_chirho.len() as u64,
                        maximum_chirho: MAX_FROZEN_TORN_SUFFIX_BYTES_CHIRHO,
                    });
                }
                return Ok(ActiveTailCutChirho {
                    physical_len_chirho,
                    clean_len_chirho: 0,
                    torn_len_chirho: physical_len_chirho,
                    torn_digest_chirho: Some(blake3::hash(&bytes_chirho).to_hex().to_string()),
                    physical_line_digest_chirho: None,
                    body_chirho: None,
                    line_offset_chirho: 0,
                });
            }
            if requested_chirho == MAX_FROZEN_ACTIVE_TAIL_WINDOW_BYTES_CHIRHO {
                return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
                    observed_chirho: read_len_chirho,
                    maximum_chirho: MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO,
                });
            }
            requested_chirho = requested_chirho
                .saturating_mul(2)
                .min(MAX_FROZEN_ACTIVE_TAIL_WINDOW_BYTES_CHIRHO);
            continue;
        };
        let torn_chirho = &bytes_chirho[last_lf_chirho + 1..];
        if torn_chirho.len() > MAX_FROZEN_TORN_SUFFIX_BYTES_CHIRHO {
            return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
                observed_chirho: torn_chirho.len() as u64,
                maximum_chirho: MAX_FROZEN_TORN_SUFFIX_BYTES_CHIRHO,
            });
        }
        let body_start_chirho = bytes_chirho[..last_lf_chirho]
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
            .map(|position_chirho| position_chirho + 1);
        let body_start_chirho = match body_start_chirho {
            Some(body_start_chirho) => body_start_chirho,
            None if start_chirho == 0 => 0,
            None if requested_chirho == MAX_FROZEN_ACTIVE_TAIL_WINDOW_BYTES_CHIRHO => {
                return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
                    observed_chirho: read_len_chirho,
                    maximum_chirho: MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO,
                });
            }
            None => {
                requested_chirho = requested_chirho
                    .saturating_mul(2)
                    .min(MAX_FROZEN_ACTIVE_TAIL_WINDOW_BYTES_CHIRHO);
                continue;
            }
        };
        let body_chirho = bytes_chirho[body_start_chirho..last_lf_chirho].to_vec();
        if body_chirho.is_empty() || body_chirho.len() > MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO {
            return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
                observed_chirho: body_chirho.len() as u64,
                maximum_chirho: MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO,
            });
        }
        return Ok(ActiveTailCutChirho {
            physical_len_chirho,
            clean_len_chirho: start_chirho + last_lf_chirho as u64 + 1,
            torn_len_chirho: torn_chirho.len() as u64,
            torn_digest_chirho: (!torn_chirho.is_empty())
                .then(|| blake3::hash(torn_chirho).to_hex().to_string()),
            physical_line_digest_chirho: Some(
                blake3::hash(&bytes_chirho[body_start_chirho..=last_lf_chirho])
                    .to_hex()
                    .to_string(),
            ),
            body_chirho: Some(body_chirho),
            line_offset_chirho: start_chirho + body_start_chirho as u64,
        });
    }
}

fn read_sealed_tail_body_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    entry_chirho: &SegmentManifestEntryChirho,
) -> Result<Vec<u8>, LosingSuffixReadErrorChirho> {
    validate_manifest_digest_chirho(&entry_chirho.segment_digest_chirho)?;
    validate_manifest_digest_chirho(&entry_chirho.final_line_digest_chirho)?;
    let path_chirho = paths_chirho.sealed_segment_chirho(&entry_chirho.segment_digest_chirho);
    let observed_len_chirho = storage_chirho
        .object_len_chirho(&path_chirho)
        .map_err(storage_error_chirho)?;
    if observed_len_chirho != Some(entry_chirho.byte_len_chirho) {
        return Err(LosingSuffixReadErrorChirho::SegmentLengthMismatchChirho {
            digest_chirho: entry_chirho.segment_digest_chirho.clone(),
            expected_chirho: entry_chirho.byte_len_chirho,
            observed_chirho: observed_len_chirho,
        });
    }
    let maximum_window_chirho = MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO + 2;
    let read_len_chirho = entry_chirho
        .byte_len_chirho
        .min(maximum_window_chirho as u64);
    let start_chirho = entry_chirho.byte_len_chirho - read_len_chirho;
    let bytes_chirho = storage_chirho
        .read_range_chirho(&path_chirho, start_chirho, read_len_chirho)
        .map_err(storage_error_chirho)?;
    if bytes_chirho.last() != Some(&b'\n') {
        return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
            detail_chirho: "sealed tail is not LF-terminated".to_owned(),
        });
    }
    let body_end_chirho = bytes_chirho.len() - 1;
    let body_start_chirho = bytes_chirho[..body_end_chirho]
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map(|position_chirho| position_chirho + 1)
        .unwrap_or(0);
    if start_chirho > 0 && body_start_chirho == 0 {
        return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
            observed_chirho: read_len_chirho,
            maximum_chirho: MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO,
        });
    }
    let physical_line_chirho = &bytes_chirho[body_start_chirho..];
    if blake3::hash(physical_line_chirho).to_hex().to_string()
        != entry_chirho.final_line_digest_chirho
    {
        return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
            detail_chirho: "sealed tail physical-line digest mismatches its index".to_owned(),
        });
    }
    Ok(bytes_chirho[body_start_chirho..body_end_chirho].to_vec())
}

fn verify_tail_body_chirho(
    body_chirho: &[u8],
    line_offset_chirho: u64,
    signer_chirho: &dyn crate::ports_chirho::LedgerSignerPortChirho,
    expected_genesis_chirho: &ExpectedLedgerGenesisChirho,
) -> Result<FrozenTailObservationChirho, LosingSuffixReadErrorChirho> {
    let text_chirho = std::str::from_utf8(body_chirho).map_err(|error_chirho| {
        LosingSuffixReadErrorChirho::RecordEncodingChirho {
            expected_seq_chirho: 0,
            detail_chirho: error_chirho.to_string(),
        }
    })?;
    let digest_chirho = stored_line_digest_chirho(text_chirho);
    let line_chirho =
        parse_canonical_ledger_journal_line_chirho(text_chirho).map_err(|error_chirho| {
            LosingSuffixReadErrorChirho::RecordEncodingChirho {
                expected_seq_chirho: 0,
                detail_chirho: format!("{error_chirho:?}"),
            }
        })?;
    verify_tail_signature_chirho(signer_chirho, &line_chirho).map_err(|_error_chirho| {
        LosingSuffixReadErrorChirho::RecordSignatureInvalidChirho {
            seq_chirho: match &line_chirho {
                LedgerJournalLineChirho::GenesisChirho(_) => 0,
                LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho.seq_chirho,
            },
        }
    })?;
    let (
        seq_chirho,
        epoch_chirho,
        hlc_chirho,
        is_genesis_chirho,
        previous_digest_chirho,
        anchor_chirho,
    ) = match &line_chirho {
        LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => {
            if text_chirho != expected_genesis_chirho.canonical_line_chirho()
                || digest_chirho != *expected_genesis_chirho.digest_chirho()
                || genesis_chirho.cluster_id_chirho != *expected_genesis_chirho.cluster_id_chirho()
            {
                return Err(LosingSuffixReadErrorChirho::JournalIdentityMismatchChirho);
            }
            (
                0,
                genesis_chirho.epoch_chirho,
                genesis_chirho.hlc_chirho.clone(),
                true,
                None,
                None,
            )
        }
        LedgerJournalLineChirho::RecordChirho(record_chirho) => (
            record_chirho.seq_chirho,
            record_chirho.epoch_chirho,
            record_chirho.hlc_chirho.clone(),
            false,
            Some(record_chirho.prev_chirho.clone()),
            record_chirho.anchor_chirho.clone(),
        ),
    };
    Ok(FrozenTailObservationChirho {
        seq_chirho,
        digest_chirho,
        epoch_chirho,
        hlc_chirho,
        line_offset_chirho,
        line_len_chirho: body_chirho.len() as u64,
        is_genesis_chirho,
        previous_digest_chirho,
        anchor_chirho,
    })
}
