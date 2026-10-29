// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The head-checkpoint sidecar ops (split from journal_chirho per the file-cap signal): the
//! sidecar path, the signed checkpoint WRITE, and the FAST OPEN that verifies the binding pair
//! and replays only the suffix — advisory both directions, behind-never-ahead (§11.4).

use crate::admission_chirho::RecordedRetentionWindowChirho;
use crate::checkpoint_chirho::{
    EffectReceiptWindowEntryChirho, EffectTerminalReceiptCoordinatesChirho,
};
use crate::journal_chirho::{storage_error_chirho, verify_tail_signature_chirho};
use crate::journal_chirho::{
    AppendReceiptChirho, JournalErrorChirho, JournalPortsChirho, LedgerJournalChirho,
    ReadOnlyRecoveryReasonChirho,
};
use crate::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_effect_commit_chirho::intent_chirho::is_reserved_effect_intent_key_chirho;
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::LedgerGenesisRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::stored_line_digest_chirho;
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, LedgerJournalLineChirho,
};
use cairn_seqlog_chirho::segment_chirho::continuity_chirho::{
    verify_manifest_line_chirho, SignedSegmentManifestLineChirho,
};
use cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho;
use cairn_seqlog_chirho::segment_chirho::LogIdentityChirho;

/// The maximum exact canonical genesis line accepted from a signed resident identity.
///
/// Every ledger-genesis field already has a substantially smaller wire bound. This outer cap makes
/// the trust-boundary parser and the authoritative range read fixed-cost even if a future wire field
/// is added without a corresponding aggregate-size calculation.
pub const MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO: usize = 4 * 1024;

/// The maximum first signed segment-manifest line read while locating sealed-resident genesis.
///
/// The preflight reads at most this body plus one LF. It never scans the manifest or sealed history.
pub const MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FastOpenPostureChirho {
    RepairingChirho,
    ReadOnlyChirho,
    ReadOnlyExactCheckpointChirho,
}

impl FastOpenPostureChirho {
    fn may_repair_chirho(self) -> bool {
        self == Self::RepairingChirho
    }

    fn requires_exact_checkpoint_chirho(self) -> bool {
        self == Self::ReadOnlyExactCheckpointChirho
    }
}

enum FastOpenAttemptChirho<'ports_chirho> {
    MissChirho,
    OpenedChirho(Box<LedgerJournalChirho<'ports_chirho>>),
    RecoveryRequiredChirho(ReadOnlyRecoveryReasonChirho),
}

/// The exact canonical genesis commitment copied from a verified resident identity.
///
/// Construction is bounded and proves that `digest_chirho` commits the supplied canonical genesis
/// line. The resident open additionally verifies the line's signature against the injected journal
/// signer before it touches any recovery or checkpoint path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedLedgerGenesisChirho {
    canonical_line_chirho: String,
    digest_chirho: DigestChirho,
    genesis_chirho: LedgerGenesisRecordChirho,
}

impl ExpectedLedgerGenesisChirho {
    pub fn from_verified_identity_chirho(
        canonical_line_chirho: &str,
        digest_chirho: DigestChirho,
    ) -> Result<Self, ExpectedGenesisRefusalReasonChirho> {
        if canonical_line_chirho.len() > MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO {
            return Err(
                ExpectedGenesisRefusalReasonChirho::ExpectedGenesisLineTooLargeChirho {
                    observed_at_least_chirho: canonical_line_chirho.len(),
                    maximum_chirho: MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO,
                },
            );
        }
        if digest_chirho.0.len() != 64
            || !digest_chirho.0.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho)
            })
        {
            return Err(ExpectedGenesisRefusalReasonChirho::ExpectedGenesisDigestInvalidChirho);
        }
        let genesis_chirho = match parse_canonical_ledger_journal_line_chirho(canonical_line_chirho)
        {
            Ok(LedgerJournalLineChirho::GenesisChirho(genesis_chirho)) => genesis_chirho,
            Ok(LedgerJournalLineChirho::RecordChirho(_)) | Err(_) => {
                return Err(ExpectedGenesisRefusalReasonChirho::ExpectedGenesisLineInvalidChirho);
            }
        };
        if stored_line_digest_chirho(canonical_line_chirho) != digest_chirho {
            return Err(ExpectedGenesisRefusalReasonChirho::ExpectedGenesisDigestMismatchChirho);
        }
        Ok(Self {
            canonical_line_chirho: canonical_line_chirho.to_owned(),
            digest_chirho,
            genesis_chirho,
        })
    }

    pub fn canonical_line_chirho(&self) -> &str {
        &self.canonical_line_chirho
    }

    pub fn digest_chirho(&self) -> &DigestChirho {
        &self.digest_chirho
    }

    pub fn cluster_id_chirho(&self) -> &ClusterIdChirho {
        &self.genesis_chirho.cluster_id_chirho
    }
}

/// A typed external-genesis refusal. These variants distinguish an identity mismatch from ordinary
/// journal corruption or storage failure without granting repair authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedGenesisRefusalReasonChirho {
    ExpectedGenesisLineTooLargeChirho {
        observed_at_least_chirho: usize,
        maximum_chirho: usize,
    },
    ExpectedGenesisManifestLineTooLargeChirho {
        observed_at_least_chirho: usize,
        maximum_chirho: usize,
    },
    ExpectedGenesisLineInvalidChirho,
    ExpectedGenesisDigestInvalidChirho,
    ExpectedGenesisDigestMismatchChirho,
    ExpectedGenesisSignerIdentityMismatchChirho,
    ExpectedGenesisSignatureInvalidChirho,
    AuthoritativeGenesisMismatchChirho,
}

/// The resident-facing open error keeps external-identity refusal separate from ordinary journal
/// verification, storage, and recovery errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedGenesisOpenErrorChirho {
    ExpectationRefusedChirho {
        reason_chirho: ExpectedGenesisRefusalReasonChirho,
    },
    JournalChirho {
        error_chirho: JournalErrorChirho,
    },
}

impl From<ExpectedGenesisRefusalReasonChirho> for ExpectedGenesisOpenErrorChirho {
    fn from(reason_chirho: ExpectedGenesisRefusalReasonChirho) -> Self {
        Self::ExpectationRefusedChirho { reason_chirho }
    }
}

impl From<JournalErrorChirho> for ExpectedGenesisOpenErrorChirho {
    fn from(error_chirho: JournalErrorChirho) -> Self {
        Self::JournalChirho { error_chirho }
    }
}

/// Non-forgeable evidence that the exact expected genesis was read from this path before recovery.
pub(crate) struct VerifiedExpectedGenesisPreflightChirho<'expected_chirho> {
    path_chirho: StoragePathChirho,
    expected_chirho: &'expected_chirho ExpectedLedgerGenesisChirho,
}

impl VerifiedExpectedGenesisPreflightChirho<'_> {
    pub(crate) fn path_chirho(&self) -> &StoragePathChirho {
        &self.path_chirho
    }

    pub(crate) fn expected_cluster_chirho(&self) -> &ClusterIdChirho {
        self.expected_chirho.cluster_id_chirho()
    }

    fn expected_digest_chirho(&self) -> &DigestChirho {
        self.expected_chirho.digest_chirho()
    }

    fn expected_line_len_chirho(&self) -> u64 {
        self.expected_chirho.canonical_line_chirho().len() as u64
    }
}

fn expected_storage_error_chirho(error_chirho: anyhow::Error) -> ExpectedGenesisOpenErrorChirho {
    ExpectedGenesisOpenErrorChirho::JournalChirho {
        error_chirho: storage_error_chirho(error_chirho),
    }
}

fn expected_chain_error_chirho(detail_chirho: impl Into<String>) -> ExpectedGenesisOpenErrorChirho {
    ExpectedGenesisOpenErrorChirho::JournalChirho {
        error_chirho: JournalErrorChirho::ChainChirho {
            detail_chirho: detail_chirho.into(),
        },
    }
}

fn expected_refusal_chirho(
    reason_chirho: ExpectedGenesisRefusalReasonChirho,
) -> ExpectedGenesisOpenErrorChirho {
    ExpectedGenesisOpenErrorChirho::ExpectationRefusedChirho { reason_chirho }
}

fn segment_storage_path_chirho(
    path_chirho: &cairn_seqlog_chirho::segment_chirho::storage_chirho::SegmentPathChirho,
) -> StoragePathChirho {
    StoragePathChirho::new_chirho(path_chirho.as_str_chirho())
}

fn verify_exact_stored_genesis_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    expected_chirho: &ExpectedLedgerGenesisChirho,
) -> Result<(), ExpectedGenesisOpenErrorChirho> {
    let mut expected_physical_line_chirho =
        Vec::with_capacity(expected_chirho.canonical_line_chirho().len() + 1);
    expected_physical_line_chirho
        .extend_from_slice(expected_chirho.canonical_line_chirho().as_bytes());
    expected_physical_line_chirho.push(b'\n');
    let Some(object_len_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(expected_storage_error_chirho)?
    else {
        return Err(expected_refusal_chirho(
            ExpectedGenesisRefusalReasonChirho::AuthoritativeGenesisMismatchChirho,
        ));
    };
    if object_len_chirho < expected_physical_line_chirho.len() as u64 {
        return Err(expected_refusal_chirho(
            ExpectedGenesisRefusalReasonChirho::AuthoritativeGenesisMismatchChirho,
        ));
    }
    let stored_chirho = storage_chirho
        .read_exact_range_chirho(path_chirho, 0, expected_physical_line_chirho.len() as u64)
        .map_err(expected_storage_error_chirho)?;
    if stored_chirho != expected_physical_line_chirho {
        return Err(expected_refusal_chirho(
            ExpectedGenesisRefusalReasonChirho::AuthoritativeGenesisMismatchChirho,
        ));
    }
    Ok(())
}

fn verify_expected_genesis_claim_chirho(
    signer_chirho: &dyn crate::ports_chirho::LedgerSignerPortChirho,
    expected_chirho: &ExpectedLedgerGenesisChirho,
) -> Result<(), ExpectedGenesisOpenErrorChirho> {
    if expected_chirho.genesis_chirho.key_id_chirho != signer_chirho.key_id_chirho() {
        return Err(expected_refusal_chirho(
            ExpectedGenesisRefusalReasonChirho::ExpectedGenesisSignerIdentityMismatchChirho,
        ));
    }
    verify_tail_signature_chirho(
        signer_chirho,
        &LedgerJournalLineChirho::GenesisChirho(expected_chirho.genesis_chirho.clone()),
    )
    .map_err(|_error_chirho| {
        expected_refusal_chirho(
            ExpectedGenesisRefusalReasonChirho::ExpectedGenesisSignatureInvalidChirho,
        )
    })
}

impl<'ports_chirho> LedgerJournalChirho<'ports_chirho> {
    /// Open an existing resident journal only after its exact signed identity genesis commitment is
    /// found at authoritative line zero.
    ///
    /// The preflight performs a fixed number of metadata/range reads under fixed byte caps and has
    /// no storage mutation capability. For an unrotated journal it compares active line zero; once a
    /// manifest has a first entry it verifies that signed generation-zero entry and compares the
    /// first sealed segment's line zero. Only the resulting private token can enter the expected
    /// fast/full repair branches. A fast-path miss may run the ordinary O(history) full rebuild, but
    /// never before the external identity check. The caller must hold the resident single-writer
    /// lease and a stable namespace snapshot across this call.
    pub fn open_with_expected_genesis_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_chirho: &ExpectedLedgerGenesisChirho,
    ) -> Result<Self, ExpectedGenesisOpenErrorChirho> {
        let preflight_chirho =
            Self::preflight_expected_genesis_chirho(ports_chirho, path_chirho, expected_chirho)?;
        if let Some(engine_chirho) =
            Self::try_fast_open_with_expected_genesis_chirho(ports_chirho, &preflight_chirho)
        {
            return Ok(engine_chirho);
        }
        Self::full_repair_open_with_expected_preflight_chirho(ports_chirho, &preflight_chirho)
            .map_err(ExpectedGenesisOpenErrorChirho::from)
    }

    /// Open an existing resident journal against its exact signed genesis without repair authority.
    ///
    /// This is the preactivation/readiness counterpart to
    /// [`Self::open_with_expected_genesis_chirho`]. A pending rotation or torn tail returns a typed
    /// recovery requirement and remains byte-for-byte untouched. The expected genesis is checked
    /// before the fast/full verifier and again after it, while the caller retains the resident lease
    /// and stable namespace snapshot. The fast path is O(checkpoint state + suffix delta); an advisory
    /// miss deliberately falls back to the non-mutating O(history) verifier.
    pub fn open_read_only_with_expected_genesis_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_chirho: &ExpectedLedgerGenesisChirho,
    ) -> Result<Self, ExpectedGenesisOpenErrorChirho> {
        let preflight_chirho =
            Self::preflight_expected_genesis_chirho(ports_chirho, path_chirho, expected_chirho)?;
        Self::ensure_read_only_rotation_clear_chirho(ports_chirho, preflight_chirho.path_chirho())?;
        let opened_chirho = match Self::try_fast_open_read_only_with_expected_genesis_chirho(
            ports_chirho,
            &preflight_chirho,
        )? {
            Some(engine_chirho) => engine_chirho,
            None => Self::open_read_only_full_chirho(
                ports_chirho,
                preflight_chirho.path_chirho().clone(),
                preflight_chirho.expected_cluster_chirho(),
            )?,
        };
        Self::ensure_read_only_rotation_clear_chirho(ports_chirho, preflight_chirho.path_chirho())?;
        Self::preflight_expected_genesis_chirho(
            ports_chirho,
            preflight_chirho.path_chirho().clone(),
            expected_chirho,
        )?;
        if opened_chirho.genesis_digest_chirho() != expected_chirho.digest_chirho() {
            return Err(expected_refusal_chirho(
                ExpectedGenesisRefusalReasonChirho::AuthoritativeGenesisMismatchChirho,
            ));
        }
        Ok(opened_chirho)
    }

    pub(crate) fn preflight_expected_genesis_chirho<'expected_chirho>(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_chirho: &'expected_chirho ExpectedLedgerGenesisChirho,
    ) -> Result<
        VerifiedExpectedGenesisPreflightChirho<'expected_chirho>,
        ExpectedGenesisOpenErrorChirho,
    > {
        verify_expected_genesis_claim_chirho(ports_chirho.signer_chirho, expected_chirho)?;

        let segment_paths_chirho = SegmentPathsChirho::new_chirho(path_chirho.key_chirho());
        let manifest_path_chirho =
            segment_storage_path_chirho(&segment_paths_chirho.manifest_chirho());
        let manifest_len_chirho = ports_chirho
            .storage_chirho
            .object_len_chirho(&manifest_path_chirho)
            .map_err(expected_storage_error_chirho)?
            .unwrap_or(0);
        if manifest_len_chirho == 0 {
            verify_exact_stored_genesis_chirho(
                ports_chirho.storage_chirho,
                &path_chirho,
                expected_chirho,
            )?;
            return Ok(VerifiedExpectedGenesisPreflightChirho {
                path_chirho,
                expected_chirho,
            });
        }

        let manifest_read_limit_chirho =
            (MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO as u64) + 1;
        let manifest_read_len_chirho = manifest_len_chirho.min(manifest_read_limit_chirho);
        let manifest_prefix_chirho = ports_chirho
            .storage_chirho
            .read_exact_range_chirho(&manifest_path_chirho, 0, manifest_read_len_chirho)
            .map_err(expected_storage_error_chirho)?;
        let Some(first_lf_chirho) = manifest_prefix_chirho
            .iter()
            .position(|byte_chirho| *byte_chirho == b'\n')
        else {
            if manifest_len_chirho > MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO as u64 {
                return Err(expected_refusal_chirho(
                    ExpectedGenesisRefusalReasonChirho::ExpectedGenesisManifestLineTooLargeChirho {
                        observed_at_least_chirho: MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO
                            + 1,
                        maximum_chirho: MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO,
                    },
                ));
            }
            return Err(expected_chain_error_chirho(
                "first segment manifest line is not LF-terminated",
            ));
        };
        if first_lf_chirho > MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO {
            return Err(expected_refusal_chirho(
                ExpectedGenesisRefusalReasonChirho::ExpectedGenesisManifestLineTooLargeChirho {
                    observed_at_least_chirho: first_lf_chirho,
                    maximum_chirho: MAX_EXPECTED_GENESIS_MANIFEST_LINE_BYTES_CHIRHO,
                },
            ));
        }
        let first_manifest_text_chirho = std::str::from_utf8(
            &manifest_prefix_chirho[..first_lf_chirho],
        )
        .map_err(|_error_chirho| {
            expected_chain_error_chirho("first segment manifest line is not UTF-8")
        })?;
        let first_manifest_line_chirho: SignedSegmentManifestLineChirho =
            serde_json::from_str(first_manifest_text_chirho).map_err(|error_chirho| {
                expected_chain_error_chirho(format!(
                    "first segment manifest line refused: {error_chirho}"
                ))
            })?;
        let continuity_chirho =
            crate::segment_adapter_chirho::SegmentContinuityOverLedgerSignerPortChirho::new_chirho(
                ports_chirho.signer_chirho,
            );
        let verified_manifest_chirho =
            verify_manifest_line_chirho(&continuity_chirho, &first_manifest_line_chirho).map_err(
                |error_chirho| {
                    expected_chain_error_chirho(format!(
                        "first segment manifest signature refused: {error_chirho}"
                    ))
                },
            )?;
        let first_entry_chirho = verified_manifest_chirho.entry_chirho();
        first_entry_chirho
            .check_intrinsic_chirho()
            .map_err(|error_chirho| {
                expected_chain_error_chirho(format!(
                    "first segment manifest entry refused: {error_chirho}"
                ))
            })?;
        if first_entry_chirho.generation_chirho != 0 {
            return Err(expected_chain_error_chirho(
                "first segment manifest line is not generation zero",
            ));
        }
        let log_identity_chirho = LogIdentityChirho::new_chirho(format!(
            "cairn-ledger:{}",
            expected_chirho.cluster_id_chirho().0
        ));
        if first_entry_chirho.log_identity_digest_chirho != log_identity_chirho.digest_chirho() {
            return Err(expected_refusal_chirho(
                ExpectedGenesisRefusalReasonChirho::AuthoritativeGenesisMismatchChirho,
            ));
        }
        let sealed_path_chirho = segment_storage_path_chirho(
            &segment_paths_chirho.sealed_segment_chirho(&first_entry_chirho.segment_digest_chirho),
        );
        verify_exact_stored_genesis_chirho(
            ports_chirho.storage_chirho,
            &sealed_path_chirho,
            expected_chirho,
        )?;
        Ok(VerifiedExpectedGenesisPreflightChirho {
            path_chirho,
            expected_chirho,
        })
    }

    /// Verify the expected genesis directly from the still-intact active file.
    ///
    /// This is used only for a writer-locked held cut when the first manifest append tore before its
    /// LF. The caller must separately prove that crash state against the rotation marker and
    /// authenticated predecessor index; this helper only preserves the exact resident-genesis check.
    pub(crate) fn preflight_expected_genesis_from_active_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: &StoragePathChirho,
        expected_chirho: &ExpectedLedgerGenesisChirho,
    ) -> Result<(), ExpectedGenesisOpenErrorChirho> {
        verify_expected_genesis_claim_chirho(ports_chirho.signer_chirho, expected_chirho)?;
        verify_exact_stored_genesis_chirho(
            ports_chirho.storage_chirho,
            path_chirho,
            expected_chirho,
        )
    }

    pub(crate) fn hold_receipt_from_window_entry_chirho(
        entry_chirho: &EffectReceiptWindowEntryChirho,
    ) -> AppendReceiptChirho {
        AppendReceiptChirho {
            seq_chirho: entry_chirho.committed_seq_chirho,
            record_digest_chirho: entry_chirho.stored_record_digest_chirho.clone(),
            hlc_chirho: entry_chirho.committed_hlc_chirho.clone(),
            epoch_first_record_chirho: None,
        }
    }

    pub(crate) fn terminal_receipt_from_window_entry_chirho(
        entry_chirho: &EffectReceiptWindowEntryChirho,
    ) -> Option<AppendReceiptChirho> {
        entry_chirho.terminal_receipt_chirho.as_ref().map(
            |receipt_chirho: &EffectTerminalReceiptCoordinatesChirho| AppendReceiptChirho {
                seq_chirho: receipt_chirho.seq_chirho,
                record_digest_chirho: receipt_chirho.stored_record_digest_chirho.clone(),
                hlc_chirho: receipt_chirho.hlc_chirho.clone(),
                epoch_first_record_chirho: None,
            },
        )
    }

    /// Drop only receipts STRICTLY older than every touched kind's CURRENT monotone window. The
    /// registry seam is retention-only: replay never calls it, and admission keeps refusing
    /// superseded refs through its distinct strict resolver. Unknown/legacy policy retains.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub(crate) fn prune_effect_receipt_window_chirho(&mut self) {
        let tail_physical_ms_chirho = self.tail_hlc_chirho.physical_ms_chirho;
        let registry_chirho = self.kind_registry_chirho;
        // Pruning is for RESOLVED work only. Forward and compensation receipts both remain visible
        // while their effective escrow control owns a live Hold; precompute once so retention stays
        // O(H log H + R log H), never an O(H*R) nested scan.
        let live_hold_control_refs_chirho = self
            .active_holds_chirho
            .keys()
            .map(|key_chirho| key_chirho.saga_id_chirho.clone())
            .collect::<std::collections::BTreeSet<_>>();
        self.effect_receipt_window_chirho
            .retain(|_key_chirho, entry_chirho| {
                if live_hold_control_refs_chirho
                    .contains(entry_chirho.effective_control_saga_id_chirho())
                {
                    return true;
                }
                if entry_chirho.policy_refs_chirho.is_empty() {
                    return true;
                }
                let mut effective_horizon_ms_chirho = 0_u64;
                for policy_ref_chirho in &entry_chirho.policy_refs_chirho {
                    match registry_chirho
                        .resolve_recorded_ref_retention_window_chirho(policy_ref_chirho)
                    {
                        RecordedRetentionWindowChirho::BoundedChirho(window_chirho) => {
                            effective_horizon_ms_chirho = effective_horizon_ms_chirho
                                .max(window_chirho.idempotency_horizon_ms_chirho);
                        }
                        RecordedRetentionWindowChirho::RetainIndefinitelyChirho => return true,
                    }
                }
                let age_ms_chirho = tail_physical_ms_chirho
                    .saturating_sub(entry_chirho.committed_hlc_chirho.physical_ms_chirho);
                age_ms_chirho <= effective_horizon_ms_chirho
            });
    }

    /// The sidecar object's path for a journal path.
    fn sidecar_path_chirho(path_chirho: &StoragePathChirho) -> StoragePathChirho {
        StoragePathChirho(format!("{}.head-checkpoint-chirho", path_chirho.0))
    }

    /// Write the ADVISORY durable head-checkpoint sidecar (§11.4): atomic, OFF the money path —
    /// never counted against the ≤1-sync/op budget (the caller/actor layer schedules it; it is an
    /// explicit separate operation). A torn/lost sidecar costs a full rebuild, never money.
    /// On a ROTATED journal (base > 0) the checkpoint carries the BINDING PAIR (segment base +
    /// verified manifest tail-entry digest) instead of relying on the active-file genesis line:
    /// the fast open requires both to equal the freshly-derived seal state, so a rotated journal
    /// warm-opens in O(checkpoint state + suffix window), with no sealed-segment reads, while any
    /// cross-seal-state or forged-binding sidecar misses to the full manifest walk.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub fn write_head_checkpoint_chirho(&self) -> Result<(), JournalErrorChirho> {
        let mut checkpoint_chirho = crate::checkpoint_chirho::HeadCheckpointChirho {
            schema_chirho: crate::checkpoint_chirho::HEAD_CHECKPOINT_SCHEMA_V1_CHIRHO.into(),
            genesis_digest_chirho: self.genesis_digest_chirho.clone(),
            genesis_line_len_chirho: self.genesis_line_len_chirho,
            covered_byte_len_chirho: self.tail_byte_len_chirho,
            covered_tail_offset_chirho: self.tail_line_offset_chirho,
            covered_tail_len_chirho: self.tail_line_len_chirho,
            covered_tail_digest_chirho: self.tail_digest_chirho.clone(),
            covered_seq_chirho: self.tail_seq_chirho,
            covered_epoch_chirho: self.last_recorded_epoch_chirho,
            covered_hlc_chirho: self.tail_hlc_chirho.clone(),
            base_seq_chirho: (self.base_seq_chirho > 0).then_some(self.base_seq_chirho),
            manifest_tail_entry_digest_chirho: if self.base_seq_chirho > 0 {
                self.manifest_tail_entry_digest_chirho.clone()
            } else {
                None
            },
            active_holds_chirho: self
                .active_holds_chirho
                .iter()
                .map(|(key_chirho, amount_chirho)| (key_chirho.clone(), *amount_chirho))
                .collect(),
            consumed_nullifiers_chirho: self.consumed_nullifiers_chirho.iter().cloned().collect(),
            head_locators_chirho: self
                .head_locators_chirho
                .iter()
                .map(|(account_chirho, locator_chirho)| {
                    crate::checkpoint_chirho::HeadLocatorEntryChirho {
                        account_chirho: account_chirho.clone(),
                        locator_chirho: locator_chirho.clone(),
                    }
                })
                .collect(),
            supply_by_kind_chirho: self.supply_by_kind_chirho.clone(),
            idempotency_window_chirho: self.idempotency_keys_chirho.clone(),
            effect_receipt_window_chirho: self.effect_receipt_window_chirho.clone(),
            sig_chirho: String::new(),
        };
        // Sign the sidecar so its trusted-on-faith aggregate balances are trust-root-vouched.
        let signing_message_chirho =
            checkpoint_chirho.signing_message_chirho().ok_or_else(|| {
                JournalErrorChirho::ChainChirho {
                    detail_chirho: "checkpoint signing message refused".to_owned(),
                }
            })?;
        let signing_line_chirho = String::from_utf8(signing_message_chirho).map_err(|_| {
            JournalErrorChirho::ChainChirho {
                detail_chirho: "checkpoint signing message not UTF-8".to_owned(),
            }
        })?;
        checkpoint_chirho.sig_chirho = self
            .signer_chirho
            .sign_chirho(&signing_line_chirho)
            .map_err(|error_chirho| JournalErrorChirho::SignerChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
        let bytes_chirho =
            crate::checkpoint_chirho::canonical_head_checkpoint_bytes_chirho(&checkpoint_chirho)
                .ok_or_else(|| JournalErrorChirho::ChainChirho {
                    detail_chirho: "checkpoint serialization refused".to_owned(),
                })?;
        self.storage_chirho
            .atomic_write_chirho(&Self::sidecar_path_chirho(&self.path_chirho), &bytes_chirho)
            .map_err(storage_error_chirho)
    }

    /// The verified fast open (§11.4, the RC4 pattern): sidecar → strict parse → SIDECAR-SIG verify →
    /// behind-never-ahead → genesis binding (range-read line 0, digest + router + cluster) →
    /// covered-cut authenticity (range-read the named tail line, digest + router + seq) → engine from
    /// the checkpoint → suffix replay under the full chain law + tail-sig (torn suffix repairs as in
    /// the full path). Cost is O(checkpoint state + delta), independent of total history. ANY miss
    /// returns None — the caller falls back to the full rebuild. The journal object is NEVER
    /// full-read on this path. The sidecar is length-inspected before allocation and cannot exceed
    /// [`crate::checkpoint_chirho::MAX_HEAD_CHECKPOINT_BYTES_CHIRHO`]; an oversized advisory object
    /// misses to the full verifier.
    ///
    /// **Covered-prefix trust (self-audit finding #2).** Records `1..covered_seq` are NOT re-read;
    /// their integrity rests on the SIDECAR SIGNATURE (which vouches the aggregate balances) plus the
    /// covered-tail digest/sig — NOT the journal chain. So an interior covered-record tamper is
    /// tolerated here (the honest sidecar-vouched balance is served) and surfaces only at the next
    /// FULL open as a fail-closed `prev` mismatch. No mis-stated money is served (the sidecar sig
    /// gates the aggregates; tampered bytes are never read). The RC4-R2 money-decision re-read closes
    /// interior detection at read time (deferred, per-account passivate slice).
    pub(crate) fn try_fast_open_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: &StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
    ) -> Option<Self> {
        match Self::try_fast_open_inner_chirho(
            ports_chirho,
            path_chirho,
            expected_cluster_chirho,
            None,
            FastOpenPostureChirho::RepairingChirho,
        ) {
            FastOpenAttemptChirho::OpenedChirho(engine_chirho) => Some(*engine_chirho),
            FastOpenAttemptChirho::MissChirho
            | FastOpenAttemptChirho::RecoveryRequiredChirho(_) => None,
        }
    }

    fn try_fast_open_with_expected_genesis_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        preflight_chirho: &VerifiedExpectedGenesisPreflightChirho<'_>,
    ) -> Option<Self> {
        match Self::try_fast_open_inner_chirho(
            ports_chirho,
            preflight_chirho.path_chirho(),
            preflight_chirho.expected_cluster_chirho(),
            Some(preflight_chirho),
            FastOpenPostureChirho::RepairingChirho,
        ) {
            FastOpenAttemptChirho::OpenedChirho(engine_chirho) => Some(*engine_chirho),
            FastOpenAttemptChirho::MissChirho
            | FastOpenAttemptChirho::RecoveryRequiredChirho(_) => None,
        }
    }

    fn try_fast_open_read_only_with_expected_genesis_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        preflight_chirho: &VerifiedExpectedGenesisPreflightChirho<'_>,
    ) -> Result<Option<Self>, JournalErrorChirho> {
        match Self::try_fast_open_inner_chirho(
            ports_chirho,
            preflight_chirho.path_chirho(),
            preflight_chirho.expected_cluster_chirho(),
            Some(preflight_chirho),
            FastOpenPostureChirho::ReadOnlyChirho,
        ) {
            FastOpenAttemptChirho::MissChirho => Ok(None),
            FastOpenAttemptChirho::OpenedChirho(engine_chirho) => Ok(Some(*engine_chirho)),
            FastOpenAttemptChirho::RecoveryRequiredChirho(reason_chirho) => {
                Err(JournalErrorChirho::ReadOnlyRecoveryRequiredChirho { reason_chirho })
            }
        }
    }

    pub(crate) fn try_fast_open_read_only_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: &StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
    ) -> Result<Option<Self>, JournalErrorChirho> {
        match Self::try_fast_open_inner_chirho(
            ports_chirho,
            path_chirho,
            expected_cluster_chirho,
            None,
            FastOpenPostureChirho::ReadOnlyChirho,
        ) {
            FastOpenAttemptChirho::MissChirho => Ok(None),
            FastOpenAttemptChirho::OpenedChirho(engine_chirho) => Ok(Some(*engine_chirho)),
            FastOpenAttemptChirho::RecoveryRequiredChirho(reason_chirho) => {
                Err(JournalErrorChirho::ReadOnlyRecoveryRequiredChirho { reason_chirho })
            }
        }
    }

    pub(crate) fn try_fast_open_read_only_exact_checkpoint_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: &StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
    ) -> Result<Option<Self>, JournalErrorChirho> {
        match Self::try_fast_open_inner_chirho(
            ports_chirho,
            path_chirho,
            expected_cluster_chirho,
            None,
            FastOpenPostureChirho::ReadOnlyExactCheckpointChirho,
        ) {
            FastOpenAttemptChirho::MissChirho => Ok(None),
            FastOpenAttemptChirho::OpenedChirho(engine_chirho) => Ok(Some(*engine_chirho)),
            FastOpenAttemptChirho::RecoveryRequiredChirho(reason_chirho) => {
                Err(JournalErrorChirho::ReadOnlyRecoveryRequiredChirho { reason_chirho })
            }
        }
    }

    fn try_fast_open_inner_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_chirho: &StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
        expected_preflight_chirho: Option<&VerifiedExpectedGenesisPreflightChirho<'_>>,
        posture_chirho: FastOpenPostureChirho,
    ) -> FastOpenAttemptChirho<'ports_chirho> {
        let attempt_chirho = (|| -> Option<FastOpenAttemptChirho<'ports_chirho>> {
            let segment_storage_chirho =
                crate::segment_adapter_chirho::SegmentStorageOverLedgerPortChirho::new_chirho(
                    ports_chirho.storage_chirho,
                );
            let segment_paths_chirho = SegmentPathsChirho::new_chirho(path_chirho.key_chirho());
            let marker_exists_chirho =
                cairn_seqlog_chirho::segment_chirho::storage_chirho::SegmentStorageChirho::exists_chirho(
                    &segment_storage_chirho,
                    &segment_paths_chirho.rotation_marker_chirho(),
                )
                .ok()?;
            if marker_exists_chirho {
                return if posture_chirho.may_repair_chirho() {
                    None
                } else {
                    Some(FastOpenAttemptChirho::RecoveryRequiredChirho(
                        ReadOnlyRecoveryReasonChirho::PendingRotationChirho,
                    ))
                };
            }
            let sidecar_path_chirho = Self::sidecar_path_chirho(path_chirho);
            let sidecar_len_chirho = ports_chirho
                .storage_chirho
                .object_len_chirho(&sidecar_path_chirho)
                .ok()??;
            if sidecar_len_chirho
                > crate::checkpoint_chirho::MAX_HEAD_CHECKPOINT_BYTES_CHIRHO as u64
            {
                return None;
            }
            let sidecar_bytes_chirho = ports_chirho
                .storage_chirho
                .read_exact_range_chirho(&sidecar_path_chirho, 0, sidecar_len_chirho)
                .ok()?;
            let checkpoint_chirho =
                crate::checkpoint_chirho::parse_head_checkpoint_chirho(&sidecar_bytes_chirho)
                    .ok()?;
            if let Some(preflight_chirho) = expected_preflight_chirho {
                if checkpoint_chirho.genesis_digest_chirho
                    != *preflight_chirho.expected_digest_chirho()
                    || checkpoint_chirho.genesis_line_len_chirho
                        != preflight_chirho.expected_line_len_chirho()
                {
                    return None;
                }
            }
            // The sidecar's aggregate balances are trusted on faith on this path, so its trust-root
            // signature MUST verify first — a Byzantine tamper of the sidecar (fabricated balances)
            // breaks the sig and discards to the full rebuild. Staleness is handled by suffix replay.
            let signing_line_chirho =
                String::from_utf8(checkpoint_chirho.signing_message_chirho()?).ok()?;
            if !ports_chirho
                .signer_chirho
                .verify_chirho(&signing_line_chirho, &checkpoint_chirho.sig_chirho)
            {
                return None;
            }
            // Pre-window sidecars carried every key in ONE legacy set and therefore lack the original
            // receipt coordinates for a reserved K. Such a sidecar self-identifies by prefix and is
            // discarded to the structural full replay exactly once; no half-trusted migration occurs.
            if checkpoint_chirho
                .idempotency_window_chirho
                .iter()
                .any(|key_chirho| is_reserved_effect_intent_key_chirho(key_chirho))
            {
                return None;
            }
            // A pre-dual-receipt terminalized sidecar carried the terminal coordinates in the Hold
            // slot. Its absent terminal slot therefore means "recompute from the verified walk", not
            // "trust this as unterminated". Any partial terminal state follows the same fail-safe path.
            if checkpoint_chirho
                .effect_receipt_window_chirho
                .values()
                .any(|entry_chirho| {
                    entry_chirho.terminal_outcome_ref_chirho.is_some()
                        != entry_chirho.terminal_receipt_chirho.is_some()
                        || entry_chirho.terminal_receipt_chirho.as_ref().is_some_and(
                            |receipt_chirho| {
                                receipt_chirho.seq_chirho <= entry_chirho.committed_seq_chirho
                            },
                        )
                })
            {
                return None;
            }
            let object_len_chirho = ports_chirho
                .storage_chirho
                .object_len_chirho(path_chirho)
                .ok()??;
            // Exact held opens may not fall back to a manifest scan. Their signed checkpoint names
            // the expected seal state, and a rotated checkpoint must bind through the verified
            // identity-bound manifest head. Ordinary opens retain the existing advisory fallback.
            let base_chirho = {
                let segment_continuity_chirho =
                crate::segment_adapter_chirho::SegmentContinuityOverLedgerSignerPortChirho::new_chirho(
                    ports_chirho.signer_chirho,
                );
                let log_identity_chirho =
                    cairn_seqlog_chirho::segment_chirho::LogIdentityChirho::new_chirho(format!(
                        "cairn-ledger:{}",
                        expected_cluster_chirho.0
                    ));
                if posture_chirho.requires_exact_checkpoint_chirho() {
                    if checkpoint_chirho.base_seq_chirho.unwrap_or(0) == 0 {
                        let manifest_len_chirho = cairn_seqlog_chirho::segment_chirho::storage_chirho::SegmentStorageChirho::object_len_chirho(
                            &segment_storage_chirho,
                            &segment_paths_chirho.manifest_chirho(),
                        )
                        .ok()?;
                        if manifest_len_chirho.is_some_and(|length_chirho| length_chirho != 0) {
                            return None;
                        }
                        cairn_seqlog_chirho::segment_chirho::manifest_chirho::BaseSeqChirho {
                            base_seq_chirho: 0,
                            sealed_segment_count_chirho: 0,
                            last_entry_digest_chirho: None,
                        }
                    } else {
                        cairn_seqlog_chirho::segment_chirho::manifest_head_chirho::try_manifest_head_fast_path_chirho(
                            &segment_storage_chirho,
                            &segment_continuity_chirho,
                            &segment_paths_chirho,
                            &log_identity_chirho.digest_chirho(),
                        )
                        .ok()??
                    }
                } else {
                    cairn_seqlog_chirho::segment_chirho::manifest_chirho::derive_base_seq_chirho(
                        &segment_storage_chirho,
                        &segment_continuity_chirho,
                        &segment_paths_chirho,
                        &log_identity_chirho.digest_chirho(),
                    )
                    .ok()?
                }
            };
            // A checkpoint from the OTHER seal state never fast-opens (a base>0 sidecar on an
            // unrotated log, or vice versa, is cross-state replay — discard to the full path).
            let genesis_for_tail_chirho = if base_chirho.base_seq_chirho == 0 {
                if checkpoint_chirho.base_seq_chirho.unwrap_or(0) != 0 {
                    return None;
                }
                // Behind-never-ahead: a sidecar claiming more than the object holds is
                // stale-vs-truncated state — discard.
                if checkpoint_chirho.covered_byte_len_chirho > object_len_chirho
                    || checkpoint_chirho.covered_byte_len_chirho
                        < checkpoint_chirho.genesis_line_len_chirho + 1
                {
                    return None;
                }
                // Genesis binding: the sidecar serves THIS journal instance and cluster.
                let genesis_bytes_chirho = ports_chirho
                    .storage_chirho
                    .read_exact_range_chirho(
                        path_chirho,
                        0,
                        checkpoint_chirho.genesis_line_len_chirho,
                    )
                    .ok()?;
                let genesis_line_chirho = String::from_utf8(genesis_bytes_chirho).ok()?;
                if stored_line_digest_chirho(&genesis_line_chirho)
                    != checkpoint_chirho.genesis_digest_chirho
                {
                    return None;
                }
                let genesis_chirho =
                    match parse_canonical_ledger_journal_line_chirho(&genesis_line_chirho).ok()? {
                        LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => genesis_chirho,
                        LedgerJournalLineChirho::RecordChirho(_) => return None,
                    };
                if genesis_chirho.cluster_id_chirho != *expected_cluster_chirho {
                    return None;
                }
                Some(genesis_chirho)
            } else {
                // ROTATED journal: the genesis lives in segment 1, so the binding pair replaces the
                // genesis-line read — the checkpoint must name EXACTLY this base and the VERIFIED
                // manifest tail-entry digest (identity-bound via the derive above). The active file is
                // fresh-since-rotation: offsets are active-relative and an empty active is legal.
                if checkpoint_chirho.base_seq_chirho != Some(base_chirho.base_seq_chirho) {
                    return None;
                }
                if checkpoint_chirho
                    .manifest_tail_entry_digest_chirho
                    .is_none()
                    || checkpoint_chirho.manifest_tail_entry_digest_chirho
                        != base_chirho.last_entry_digest_chirho
                {
                    return None;
                }
                // The checkpoint must cover at least the sealed history (last sealed seq = base - 1).
                if checkpoint_chirho.covered_seq_chirho + 1 < base_chirho.base_seq_chirho {
                    return None;
                }
                if checkpoint_chirho.covered_byte_len_chirho > object_len_chirho {
                    return None;
                }
                None
            };
            if posture_chirho.requires_exact_checkpoint_chirho()
                && checkpoint_chirho.covered_byte_len_chirho != object_len_chirho
            {
                return None;
            }
            // Covered-cut authenticity: the named tail line re-reads, re-hashes, re-parses (RC4-R2 —
            // the checkpoint says WHERE; the SIGNED line is what we trust). The covered tail record is
            // the fast-path tail line UNLESS the suffix replay adds later records.
            let mut tail_line_chirho = genesis_for_tail_chirho
                .clone()
                .map(LedgerJournalLineChirho::GenesisChirho);
            if checkpoint_chirho.covered_seq_chirho > 0
                && checkpoint_chirho.covered_tail_len_chirho > 0
            {
                let tail_bytes_chirho = ports_chirho
                    .storage_chirho
                    .read_exact_range_chirho(
                        path_chirho,
                        checkpoint_chirho.covered_tail_offset_chirho,
                        checkpoint_chirho.covered_tail_len_chirho,
                    )
                    .ok()?;
                let tail_text_chirho = String::from_utf8(tail_bytes_chirho).ok()?;
                if stored_line_digest_chirho(&tail_text_chirho)
                    != checkpoint_chirho.covered_tail_digest_chirho
                {
                    return None;
                }
                match parse_canonical_ledger_journal_line_chirho(&tail_text_chirho).ok()? {
                    LedgerJournalLineChirho::RecordChirho(record_chirho)
                        if record_chirho.seq_chirho == checkpoint_chirho.covered_seq_chirho =>
                    {
                        tail_line_chirho =
                            Some(LedgerJournalLineChirho::RecordChirho(record_chirho));
                    }
                    _ => return None,
                }
            } else if checkpoint_chirho.covered_tail_len_chirho == 0
                && checkpoint_chirho.base_seq_chirho.is_some()
            {
                // Sealed-resident covered tail (empty-active checkpoint on a rotated journal): there
                // is no active line to re-read; the sidecar SIG + the base/manifest-tail binding carry
                // it — the same covered-prefix trust doctrine as the interior records, with the full
                // open remaining the deep verifier.
            } else if checkpoint_chirho.covered_tail_digest_chirho
                != checkpoint_chirho.genesis_digest_chirho
            {
                return None;
            }
            let mut engine_chirho = Self {
                storage_chirho: ports_chirho.storage_chirho,
                signer_chirho: ports_chirho.signer_chirho,
                clock_chirho: ports_chirho.clock_chirho,
                membership_chirho: ports_chirho.membership_chirho,
                kind_registry_chirho: ports_chirho.kind_registry_chirho,
                authority_chirho: ports_chirho.authority_chirho,
                append_mirror_chirho: None,
                path_chirho: path_chirho.clone(),
                cluster_id_chirho: expected_cluster_chirho.clone(),
                current_epoch_chirho: checkpoint_chirho.covered_epoch_chirho,
                last_recorded_epoch_chirho: checkpoint_chirho.covered_epoch_chirho,
                tail_seq_chirho: checkpoint_chirho.covered_seq_chirho,
                tail_digest_chirho: checkpoint_chirho.covered_tail_digest_chirho.clone(),
                tail_hlc_chirho: checkpoint_chirho.covered_hlc_chirho.clone(),
                genesis_digest_chirho: checkpoint_chirho.genesis_digest_chirho.clone(),
                canonical_genesis_line_chirho: None,
                head_states_chirho: checkpoint_chirho
                    .head_locators_chirho
                    .iter()
                    .map(|entry_chirho| {
                        (
                            entry_chirho.account_chirho.clone(),
                            entry_chirho.locator_chirho.post_chirho.clone(),
                        )
                    })
                    .collect(),
                supply_by_kind_chirho: checkpoint_chirho.supply_by_kind_chirho.clone(),
                idempotency_keys_chirho: checkpoint_chirho.idempotency_window_chirho.clone(),
                effect_receipt_window_chirho: checkpoint_chirho
                    .effect_receipt_window_chirho
                    .clone(),
                active_holds_chirho: checkpoint_chirho
                    .active_holds_chirho
                    .iter()
                    .cloned()
                    .collect(),
                consumed_nullifiers_chirho: checkpoint_chirho
                    .consumed_nullifiers_chirho
                    .iter()
                    .cloned()
                    .collect(),
                finality_chirho: None,
                repaired_torn_tail_bytes_chirho: None,
                tail_byte_len_chirho: checkpoint_chirho.covered_byte_len_chirho,
                tail_physical_byte_len_chirho: checkpoint_chirho.covered_byte_len_chirho,
                tail_line_offset_chirho: checkpoint_chirho.covered_tail_offset_chirho,
                tail_line_len_chirho: checkpoint_chirho.covered_tail_len_chirho,
                genesis_line_len_chirho: checkpoint_chirho.genesis_line_len_chirho,
                base_seq_chirho: checkpoint_chirho.base_seq_chirho.unwrap_or(0),
                manifest_tail_entry_digest_chirho: checkpoint_chirho
                    .manifest_tail_entry_digest_chirho
                    .clone(),
                head_locators_chirho: checkpoint_chirho
                    .head_locators_chirho
                    .into_iter()
                    .map(|entry_chirho| (entry_chirho.account_chirho, entry_chirho.locator_chirho))
                    .collect(),
                last_open_was_fast_chirho: true,
            };
            // Replay only the suffix under the FULL chain law; cost is O(checkpoint state + delta),
            // independent of total history. A torn suffix repairs exactly as in the full path
            // (verify-then-truncate).
            if object_len_chirho > engine_chirho.tail_byte_len_chirho {
                let suffix_chirho = ports_chirho
                    .storage_chirho
                    .read_exact_range_chirho(
                        path_chirho,
                        engine_chirho.tail_byte_len_chirho,
                        object_len_chirho - engine_chirho.tail_byte_len_chirho,
                    )
                    .ok()?;
                let clean_len_chirho = suffix_chirho
                    .iter()
                    .rposition(|byte_chirho| *byte_chirho == b'\n')
                    .map(|index_chirho| index_chirho + 1)
                    .unwrap_or(0);
                let torn_len_chirho = (suffix_chirho.len() - clean_len_chirho) as u64;
                let text_chirho = std::str::from_utf8(&suffix_chirho[..clean_len_chirho]).ok()?;
                let mut position_chirho = engine_chirho.tail_byte_len_chirho;
                for line_chirho in text_chirho.lines() {
                    let record_chirho =
                        match parse_canonical_ledger_journal_line_chirho(line_chirho).ok()? {
                            LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho,
                            LedgerJournalLineChirho::GenesisChirho(_) => return None,
                        };
                    let line_digest_chirho = stored_line_digest_chirho(line_chirho);
                    engine_chirho
                        .replay_verified_chirho(
                            &record_chirho,
                            position_chirho,
                            line_chirho.len() as u64,
                            &line_digest_chirho,
                        )
                        .ok()?;
                    engine_chirho.tail_digest_chirho = line_digest_chirho;
                    engine_chirho.tail_line_offset_chirho = position_chirho;
                    engine_chirho.tail_line_len_chirho = line_chirho.len() as u64;
                    position_chirho += line_chirho.len() as u64 + 1;
                    tail_line_chirho = Some(LedgerJournalLineChirho::RecordChirho(record_chirho));
                }
                engine_chirho.tail_byte_len_chirho += clean_len_chirho as u64;
                engine_chirho.tail_physical_byte_len_chirho = engine_chirho.tail_byte_len_chirho;
                if torn_len_chirho > 0 {
                    if !posture_chirho.may_repair_chirho() {
                        return Some(FastOpenAttemptChirho::RecoveryRequiredChirho(
                            ReadOnlyRecoveryReasonChirho::TornTailChirho,
                        ));
                    }
                    ports_chirho
                        .storage_chirho
                        .truncate_durable_chirho(path_chirho, engine_chirho.tail_byte_len_chirho)
                        .ok()?;
                    engine_chirho.repaired_torn_tail_bytes_chirho = Some(torn_len_chirho);
                }
            }
            // The successor-less tail line's sig — the same O(1) whole-journal tamper-evidence anchor as
            // the full path. A miss discards to the full rebuild, which re-reads the whole journal and
            // refuses via its OWN tail-sig check (so the caller still gets the typed refusal).
            match &tail_line_chirho {
                Some(line_chirho) => {
                    if verify_tail_signature_chirho(engine_chirho.signer_chirho, line_chirho)
                        .is_err()
                    {
                        return None;
                    }
                }
                None => {
                    // Only reachable at base > 0 with an empty active and empty suffix: the tail line
                    // is sealed-resident and the sidecar SIG + binding pair vouch it (covered-prefix
                    // doctrine; the full open re-verifies everything).
                }
            }
            Some(FastOpenAttemptChirho::OpenedChirho(Box::new(engine_chirho)))
        })();
        attempt_chirho.unwrap_or(FastOpenAttemptChirho::MissChirho)
    }
}
