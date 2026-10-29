// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Synchronous CF3 provider coordination and fsck recovery.
//!
//! The coordinator owns ordering, not authority: canonical roots, the content-addressed evidence
//! store, provider, and journal are all injected. Its journal port is intentionally dumb and
//! narrow so the fake and real adapters cannot acquire a second copy of these laws.

use crate::compensation_chirho::VerifiedEffectCompensationChirho;
use crate::intent_chirho::{
    effect_compensation_key_chirho, effect_intent_ref_chirho, parse_effect_compensation_key_chirho,
    verify_effect_intent_line_chirho, EffectIntentJournalCutChirho, EffectIntentSignerPortChirho,
    VerifiedEffectIntentChirho,
};
use crate::terminal_chirho::{
    canonical_effect_terminal_outcome_line_chirho, effect_terminal_outcome_ref_chirho,
    sign_effect_terminal_outcome_chirho, EffectTerminalDispositionChirho,
    EffectTerminalOutcomeChirho, EffectTerminalSignerPortChirho,
    EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::HlcChirho;

const EFFECT_PROVIDER_EVIDENCE_REF_DOMAIN_CHIRHO: &[u8] =
    b"cairn-effect-provider-evidence-ref-v1-chirho";
const MAX_EFFECT_PROVIDER_EVIDENCE_BYTES_CHIRHO: usize = 16 * 1024 * 1024;
pub const MAX_EFFECT_COMMIT_RECEIPT_INVENTORY_CHIRHO: usize = 4_096;

/// Potentially private provider evidence. Debug output is redacted and drop overwrites the owned
/// buffer. Public records carry only its content-addressed ref.
#[derive(PartialEq, Eq)]
pub struct EffectProviderEvidenceBytesChirho(Vec<u8>);

impl EffectProviderEvidenceBytesChirho {
    pub fn new_chirho(
        bytes_chirho: Vec<u8>,
    ) -> Result<Self, EffectProviderEvidenceShapeErrorChirho> {
        if bytes_chirho.is_empty() {
            return Err(EffectProviderEvidenceShapeErrorChirho::EmptyChirho);
        }
        if bytes_chirho.len() > MAX_EFFECT_PROVIDER_EVIDENCE_BYTES_CHIRHO {
            return Err(EffectProviderEvidenceShapeErrorChirho::TooLargeChirho {
                actual_bytes_chirho: bytes_chirho.len(),
                max_bytes_chirho: MAX_EFFECT_PROVIDER_EVIDENCE_BYTES_CHIRHO,
            });
        }
        Ok(Self(bytes_chirho))
    }

    pub fn as_slice_chirho(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for EffectProviderEvidenceBytesChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str("EffectProviderEvidenceBytesChirho([REDACTED])")
    }
}

impl Drop for EffectProviderEvidenceBytesChirho {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectProviderEvidenceShapeErrorChirho {
    EmptyChirho,
    TooLargeChirho {
        actual_bytes_chirho: usize,
        max_bytes_chirho: usize,
    },
}

impl std::fmt::Display for EffectProviderEvidenceShapeErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChirho => formatter_chirho.write_str("provider evidence is empty"),
            Self::TooLargeChirho {
                actual_bytes_chirho,
                max_bytes_chirho,
            } => write!(
                formatter_chirho,
                "provider evidence is {actual_bytes_chirho} bytes, above {max_bytes_chirho}"
            ),
        }
    }
}

impl std::error::Error for EffectProviderEvidenceShapeErrorChirho {}

/// Untrusted cache evidence offered to the injected cache verifier. Construction validates only
/// the private-byte bound; it grants no authority and cannot enter the coordinator directly.
pub struct EffectCacheHitCandidateChirho {
    result_ref_chirho: DigestChirho,
    evidence_chirho: EffectProviderEvidenceBytesChirho,
}

impl EffectCacheHitCandidateChirho {
    pub fn new_chirho(
        result_ref_chirho: DigestChirho,
        evidence_bytes_chirho: Vec<u8>,
    ) -> Result<Self, EffectProviderEvidenceShapeErrorChirho> {
        Ok(Self {
            result_ref_chirho,
            evidence_chirho: EffectProviderEvidenceBytesChirho::new_chirho(evidence_bytes_chirho)?,
        })
    }

    pub fn result_ref_chirho(&self) -> &DigestChirho {
        &self.result_ref_chirho
    }

    pub fn evidence_bytes_chirho(&self) -> &[u8] {
        self.evidence_chirho.as_slice_chirho()
    }
}

impl std::fmt::Debug for EffectCacheHitCandidateChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho
            .debug_struct("EffectCacheHitCandidateChirho")
            .field("result_ref_chirho", &self.result_ref_chirho)
            .field("evidence_chirho", &"[REDACTED]")
            .finish()
    }
}

/// Cache authority verifies that these private evidence bytes bind this exact signed intent and
/// result. A caller-created candidate is powerless until this injected predicate accepts it.
pub trait EffectCacheHitVerifierPortChirho {
    fn verify_chirho(
        &self,
        intent_chirho: &VerifiedEffectIntentChirho,
        result_ref_chirho: &DigestChirho,
        evidence_bytes_chirho: &[u8],
    ) -> bool;
}

/// Opaque capability proving one cache result is bound to one signed effect intent. Fields and
/// construction stay private so no app/caller can select the cache path with a boolean or payload.
pub struct VerifiedEffectCacheHitChirho {
    intent_ref_chirho: DigestChirho,
    result_ref_chirho: DigestChirho,
    evidence_chirho: EffectProviderEvidenceBytesChirho,
}

/// Mint the opaque cache capability only after the signed intent and injected cache evidence both
/// verify. The coordinator independently re-verifies the intent before any Hold append.
pub fn verify_effect_cache_hit_chirho(
    canonical_intent_line_chirho: &str,
    intent_verifier_chirho: &dyn EffectIntentSignerPortChirho,
    candidate_chirho: EffectCacheHitCandidateChirho,
    cache_verifier_chirho: &dyn EffectCacheHitVerifierPortChirho,
) -> Result<VerifiedEffectCacheHitChirho, EffectCommitCoordinatorErrorChirho> {
    let verified_intent_chirho =
        verify_effect_intent_line_chirho(canonical_intent_line_chirho, intent_verifier_chirho)
            .map_err(
                |error_chirho| EffectCommitCoordinatorErrorChirho::CacheChirho {
                    detail_chirho: format!(
                        "cache candidate intent does not verify: {error_chirho}"
                    ),
                },
            )?;
    if !cache_verifier_chirho.verify_chirho(
        &verified_intent_chirho,
        candidate_chirho.result_ref_chirho(),
        candidate_chirho.evidence_bytes_chirho(),
    ) {
        return Err(EffectCommitCoordinatorErrorChirho::CacheChirho {
            detail_chirho: "cache evidence does not bind the verified intent and result".to_owned(),
        });
    }
    let intent_ref_chirho = effect_intent_ref_chirho(verified_intent_chirho.intent_chirho())
        .map_err(
            |error_chirho| EffectCommitCoordinatorErrorChirho::CacheChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
    Ok(VerifiedEffectCacheHitChirho {
        intent_ref_chirho,
        result_ref_chirho: candidate_chirho.result_ref_chirho,
        evidence_chirho: candidate_chirho.evidence_chirho,
    })
}

/// The only provider observations the coordinator understands. An ambiguous observation has no
/// terminal evidence and can never release money.
#[derive(Debug, PartialEq, Eq)]
pub enum EffectProviderObservationChirho {
    CommittedChirho {
        result_ref_chirho: DigestChirho,
        evidence_chirho: EffectProviderEvidenceBytesChirho,
    },
    DefiniteNoEffectChirho {
        evidence_chirho: EffectProviderEvidenceBytesChirho,
    },
    InDoubtChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectProviderPortErrorChirho {
    UnavailableChirho { detail_chirho: String },
    InvalidResponseChirho { detail_chirho: String },
}

impl std::fmt::Display for EffectProviderPortErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnavailableChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect provider unavailable: {detail_chirho}"
                )
            }
            Self::InvalidResponseChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect provider response invalid: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for EffectProviderPortErrorChirho {}

/// A blessed provider must execute-or-replay and query by the exact signed-intent K. An execute
/// error is resolved only by that query authority; an unresolved query stays in doubt, so no raw
/// transport failure can become definite no-effect.
pub trait BlessedEffectProviderPortChirho {
    fn execute_or_replay_chirho(
        &mut self,
        intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho>;

    fn query_by_key_chirho(
        &mut self,
        intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectEvidencePortErrorChirho {
    MissingChirho,
    ConflictChirho { detail_chirho: String },
    UnavailableChirho { detail_chirho: String },
}

impl std::fmt::Display for EffectEvidencePortErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingChirho => formatter_chirho.write_str("effect evidence is missing"),
            Self::ConflictChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect evidence conflicts: {detail_chirho}"
                )
            }
            Self::UnavailableChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect evidence unavailable: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for EffectEvidencePortErrorChirho {}

/// The evidence boundary. Content refs remain immutable, while compensation intents additionally
/// bind one deterministic original-effect coordinate to the same exact canonical bytes.
pub trait EffectCommitEvidencePortChirho {
    fn store_intent_line_chirho(
        &mut self,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<(), EffectEvidencePortErrorChirho>;

    fn load_intent_line_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<Option<String>, EffectEvidencePortErrorChirho>;

    /// Atomically bind one deterministic compensation K and its content-addressed intent ref to
    /// the exact canonical line. Same bytes load idempotently; either binding already naming
    /// different bytes refuses. A successful call must make the line available through
    /// `load_intent_line_chirho` so fsck needs no second authority or replay index.
    fn create_or_load_compensation_intent_line_chirho(
        &mut self,
        compensation_key_chirho: &str,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<String, EffectEvidencePortErrorChirho>;

    fn store_provider_evidence_chirho(
        &mut self,
        evidence_ref_chirho: &DigestChirho,
        evidence_bytes_chirho: &[u8],
    ) -> Result<(), EffectEvidencePortErrorChirho>;

    fn store_terminal_outcome_line_chirho(
        &mut self,
        outcome_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<(), EffectEvidencePortErrorChirho>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectCommitJournalReceiptChirho {
    pub seq_chirho: u64,
    pub record_digest_chirho: DigestChirho,
    pub hlc_chirho: HlcChirho,
}

/// Rebuildable journal state for one intent. `receipt_chirho` is the latest durable receipt: the
/// Hold while unresolved, then the terminal record after the shared append/replay transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectIntentJournalStateChirho {
    pub intent_ref_chirho: DigestChirho,
    pub receipt_chirho: EffectCommitJournalReceiptChirho,
    pub terminal_outcome_ref_chirho: Option<DigestChirho>,
}

/// Receipt coordinates rebuilt from verified journal state. The composition port refuses rather
/// than materializing more than [`MAX_EFFECT_COMMIT_RECEIPT_INVENTORY_CHIRHO`] entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEffectReceiptInventoryEntryChirho {
    pub intent_ref_chirho: DigestChirho,
    pub control_saga_id_chirho: Option<DigestChirho>,
    pub hold_receipt_chirho: EffectCommitJournalReceiptChirho,
    pub terminal_outcome_ref_chirho: Option<DigestChirho>,
    pub terminal_receipt_chirho: Option<EffectCommitJournalReceiptChirho>,
}

/// The only registry continuation coordinates Descriptor-D needs before it authors an intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectCommitContinuationViewChirho {
    pub kind_id_chirho: AssetKindIdChirho,
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    pub settlement_owner_present_chirho: bool,
}

/// Which MIRROR condition refused a commit, as a closed set.
///
/// These three used to fall into the generic `RefusedChirho` arm together with thirteen unrelated
/// journal errors, so every one of them surfaced on the Clause 14 loss-witness as the single token
/// `current-envelope-refused-chirho`. Measured 2026-08-17: that made the node-loss and region-loss
/// drills undiagnosable -- both reported a bare envelope refusal with no observed witness outcome,
/// and the detail separating "the mirror lawfully refused to prepare" from "a stale intent or an
/// invalid tail signature" was discarded at the mapping.
///
/// A closed set rather than the existing `detail_chirho` string because drill reports, packets and
/// notifications may not carry unbounded fields; that constraint is why the cause was dropped in the
/// first place, so the fix has to widen the TYPE rather than pass text through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectCommitJournalMirrorRefusalIdentityChirho {
    PrepareRefusedChirho,
    ReconciliationRefusedChirho,
    CommittedEvidencePendingChirho,
}

impl EffectCommitJournalMirrorRefusalIdentityChirho {
    pub const ALL_CHIRHO: &'static [Self] = &[
        Self::PrepareRefusedChirho,
        Self::ReconciliationRefusedChirho,
        Self::CommittedEvidencePendingChirho,
    ];

    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::PrepareRefusedChirho => "MirrorPrepareRefusedChirho",
            Self::ReconciliationRefusedChirho => "MirrorReconciliationRefusedChirho",
            Self::CommittedEvidencePendingChirho => "MirrorCommittedEvidencePendingChirho",
        }
    }
}

/// Which RESIDENT-PATH condition refused a commit, as a closed set.
///
/// Measured 2026-08-17 across three hosted windows: node loss and region loss both fail at the
/// witness's FIRST step, `prepare_resident_mutation_chirho`, and the refusal is built directly by the
/// resident path's own `refused_chirho(detail)` rather than by the adapter's journal-error mapping.
/// Everything there collapsed into the plain `RefusedChirho`, so both drills reported one
/// unattributable envelope refusal with no observed witness outcome.
///
/// Groups rather than one-per-variant because roughly thirty authority-refusal variants share that
/// fallthrough and a loss drill only needs to know WHICH KIND of condition refused.
/// `AuthorityCompositionOtherChirho` is a deliberate, named residual: if it fires, the cause is none
/// of the named groups, which is itself a usable answer rather than a silent catch-all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectCommitJournalResidentRefusalIdentityChirho {
    ReadinessCanaryAlignmentChirho,
    /// The canary alignment narrowed to WHICH coordinate moved. Window 4 showed node loss and region
    /// loss both refusing at the unnarrowed identity above, and the four coordinates answer different
    /// questions: seq/digest mean the journal TAIL advanced past its canary evidence, while
    /// epoch/group mean the DOMAIN changed underneath it. Values never travel, only the field name.
    CanaryTailSeqChirho,
    CanaryTailDigestChirho,
    CanaryConsistencyGroupChirho,
    Gd7HoldOrWithheldChirho,
    TestkindExemptLaneChirho,
    TenantMigrationFenceChirho,
    FenceOrContinuityChirho,
    InventoryBoundChirho,
    /// A mirror PREPARE or RECONCILIATION refused on the resident path.
    ///
    /// Split out of the residual on 2026-08-18 for the same reason the 2026-08-17 groups were: the
    /// loss drills reach `prepare_resident_mutation_chirho`, and a missing current holder is one of
    /// the conditions they most need to name. `MirrorRefusedChirho` already carries this distinction
    /// for refusals that pass through the adapter's journal-error mapping; these never do, so the
    /// resident set has to name it too or the cause is unattributable on exactly the path that
    /// observes it.
    MirrorPrepareOrReconciliationChirho,
    AuthorityCompositionOtherChirho,
}

impl EffectCommitJournalResidentRefusalIdentityChirho {
    pub const ALL_CHIRHO: &'static [Self] = &[
        Self::ReadinessCanaryAlignmentChirho,
        Self::CanaryTailSeqChirho,
        Self::CanaryTailDigestChirho,
        Self::CanaryConsistencyGroupChirho,
        Self::Gd7HoldOrWithheldChirho,
        Self::TestkindExemptLaneChirho,
        Self::TenantMigrationFenceChirho,
        Self::FenceOrContinuityChirho,
        Self::InventoryBoundChirho,
        Self::MirrorPrepareOrReconciliationChirho,
        Self::AuthorityCompositionOtherChirho,
    ];

    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::ReadinessCanaryAlignmentChirho => "ReadinessCanaryAlignmentChirho",
            Self::CanaryTailSeqChirho => "CanaryTailSeqChirho",
            Self::CanaryTailDigestChirho => "CanaryTailDigestChirho",
            Self::CanaryConsistencyGroupChirho => "CanaryConsistencyGroupChirho",
            Self::Gd7HoldOrWithheldChirho => "Gd7HoldOrWithheldChirho",
            Self::TestkindExemptLaneChirho => "TestkindExemptLaneChirho",
            Self::TenantMigrationFenceChirho => "TenantMigrationFenceChirho",
            Self::FenceOrContinuityChirho => "FenceOrContinuityChirho",
            Self::InventoryBoundChirho => "InventoryBoundChirho",
            Self::MirrorPrepareOrReconciliationChirho => "MirrorPrepareOrReconciliationChirho",
            Self::AuthorityCompositionOtherChirho => "AuthorityCompositionOtherChirho",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectCommitJournalAuthorityRefusalIdentityChirho {
    SinkTermNoAcceptedWinnerChirho,
    SinkTermStaleWinnerChirho,
    SinkTermUnseenWinnerChirho,
    OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho,
    OrdinaryElectionSinkTermAcceptanceChirho,
}

macro_rules! effect_commit_journal_committed_evidence_identities_chirho {
    ($( $identity_chirho:ident ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum EffectCommitJournalCommittedEvidenceIdentityChirho {
            $( $identity_chirho, )+
        }

        impl EffectCommitJournalCommittedEvidenceIdentityChirho {
            pub const ALL_CHIRHO: &'static [Self] = &[
                $( Self::$identity_chirho, )+
            ];

            pub const fn as_str_chirho(self) -> &'static str {
                match self {
                    $( Self::$identity_chirho => stringify!($identity_chirho), )+
                }
            }
        }
    };
}

effect_commit_journal_committed_evidence_identities_chirho!(
    MirrorAppendEvidencePendingChirho,
    WinnerTermIndexEvidencePendingChirho,
    JournalPostAppendReprobeEvidencePendingChirho,
    JournalPostAppendAuthorityChangedEvidencePendingChirho,
    JournalReplayBeyondTailEvidencePendingChirho,
    JournalSequenceExhaustedEvidencePendingChirho,
    JournalDenseTailTransitionEvidencePendingChirho,
    CanaryCutConstructionEvidencePendingChirho,
    CanaryCutDomainEvidencePendingChirho,
    CanaryLeaseAuthorityEvidencePendingChirho,
    CanaryPersistenceEvidencePendingChirho,
    TestkindDeposedSinkAdmissionEvidencePendingChirho,
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCommitJournalPortErrorChirho {
    RefusedChirho {
        detail_chirho: String,
    },
    /// A mirror-family refusal, carrying WHICH one as a closed set. Split out of `RefusedChirho`
    /// because collapsing it there made two Clause 14 drills report an unattributable envelope
    /// refusal; see `EffectCommitJournalMirrorRefusalIdentityChirho`.
    MirrorRefusedChirho {
        identity_chirho: EffectCommitJournalMirrorRefusalIdentityChirho,
        detail_chirho: String,
    },
    /// A resident-path refusal, carrying WHICH KIND as a closed set. This is the one the loss drills
    /// actually reach: they fail at `prepare_resident_mutation_chirho`, whose refusals are built
    /// directly in the resident path and never pass through the adapter's journal-error mapping.
    ResidentRefusedChirho {
        identity_chirho: EffectCommitJournalResidentRefusalIdentityChirho,
        detail_chirho: String,
    },
    ConflictChirho {
        detail_chirho: String,
    },
    UnavailableChirho {
        detail_chirho: String,
    },
    CommittedEvidencePendingChirho {
        receipt_chirho: EffectCommitJournalReceiptChirho,
        identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho,
        detail_chirho: String,
    },
    AuthorityRefusedChirho {
        identity_chirho: EffectCommitJournalAuthorityRefusalIdentityChirho,
        detail_chirho: String,
    },
}

impl std::fmt::Display for EffectCommitJournalPortErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RefusedChirho { detail_chirho } => {
                write!(formatter_chirho, "effect journal refused: {detail_chirho}")
            }
            Self::MirrorRefusedChirho {
                identity_chirho,
                detail_chirho,
            } => write!(
                formatter_chirho,
                "effect journal mirror refused ({}): {detail_chirho}",
                identity_chirho.as_str_chirho()
            ),
            Self::ResidentRefusedChirho {
                identity_chirho,
                detail_chirho,
            } => write!(
                formatter_chirho,
                "effect journal resident refused ({}): {detail_chirho}",
                identity_chirho.as_str_chirho()
            ),
            Self::ConflictChirho { detail_chirho } => {
                write!(formatter_chirho, "effect journal conflict: {detail_chirho}")
            }
            Self::UnavailableChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect journal unavailable: {detail_chirho}"
                )
            }
            Self::CommittedEvidencePendingChirho {
                receipt_chirho,
                identity_chirho,
                detail_chirho,
            } => write!(
                formatter_chirho,
                "effect journal committed seq {} but authority evidence remains pending ({identity_chirho:?}): {detail_chirho}",
                receipt_chirho.seq_chirho,
            ),
            Self::AuthorityRefusedChirho {
                identity_chirho,
                detail_chirho,
            } => write!(
                formatter_chirho,
                "effect journal authority refused ({identity_chirho:?}): {detail_chirho}"
            ),
        }
    }
}

impl std::error::Error for EffectCommitJournalPortErrorChirho {}

/// Dumb write-integration boundary. It has no default logic and owns no provider or ordering law.
pub trait EffectCommitJournalPortChirho {
    fn append_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho>;

    fn append_compensation_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho>;

    fn append_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        canonical_terminal_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho>;

    fn active_hold_intent_refs_chirho(
        &self,
    ) -> Result<Vec<DigestChirho>, EffectCommitJournalPortErrorChirho>;

    fn receipt_by_intent_ref_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<Option<EffectIntentJournalStateChirho>, EffectCommitJournalPortErrorChirho>;
}

/// Bounded read side of the same verified journal state used by the effect coordinator. It grants
/// no append authority and exposes neither raw journal bytes nor a storage path.
pub trait EffectCommitJournalViewPortChirho {
    fn effect_intent_cut_chirho(
        &self,
    ) -> Result<EffectIntentJournalCutChirho, EffectCommitJournalPortErrorChirho>;

    fn current_continuation_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Result<Option<EffectCommitContinuationViewChirho>, EffectCommitJournalPortErrorChirho>;

    fn verified_effect_receipt_inventory_chirho(
        &self,
    ) -> Result<Vec<VerifiedEffectReceiptInventoryEntryChirho>, EffectCommitJournalPortErrorChirho>;
}

/// One injected journal surface for Descriptor-D. Implementers must supply both the existing
/// coordinator writes and the bounded verified views; no concrete ledger engine crosses this seam.
pub trait EffectCommitJournalCompositionPortChirho:
    EffectCommitJournalPortChirho + EffectCommitJournalViewPortChirho
{
}

impl<PortChirho> EffectCommitJournalCompositionPortChirho for PortChirho where
    PortChirho: EffectCommitJournalPortChirho + EffectCommitJournalViewPortChirho + ?Sized
{
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCommitRunResultChirho {
    InDoubtChirho {
        intent_ref_chirho: DigestChirho,
        hold_receipt_chirho: EffectCommitJournalReceiptChirho,
    },
    TerminalChirho {
        intent_ref_chirho: DigestChirho,
        hold_receipt_chirho: EffectCommitJournalReceiptChirho,
        terminal_receipt_chirho: EffectCommitJournalReceiptChirho,
        outcome_ref_chirho: DigestChirho,
        disposition_chirho: EffectTerminalDispositionChirho,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCommitCoordinatorErrorChirho {
    IntentChirho {
        detail_chirho: String,
    },
    CompensationChirho {
        detail_chirho: String,
    },
    TerminalChirho {
        detail_chirho: String,
    },
    EvidenceChirho {
        detail_chirho: String,
    },
    JournalChirho {
        detail_chirho: String,
    },
    JournalCommittedEvidencePendingChirho {
        receipt_chirho: EffectCommitJournalReceiptChirho,
        identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho,
        detail_chirho: String,
    },
    JournalAuthorityRefusedChirho {
        identity_chirho: EffectCommitJournalAuthorityRefusalIdentityChirho,
        detail_chirho: String,
    },
    CacheChirho {
        detail_chirho: String,
    },
    MissingIntentEvidenceChirho {
        intent_ref_chirho: DigestChirho,
    },
    IntentEvidenceMismatchChirho {
        intent_ref_chirho: DigestChirho,
    },
    CompensationIntentEvidenceConflictChirho {
        compensation_key_chirho: String,
    },
    MissingJournalReceiptChirho {
        intent_ref_chirho: DigestChirho,
    },
    TerminalStateStillActiveChirho {
        intent_ref_chirho: DigestChirho,
    },
}

impl std::fmt::Display for EffectCommitCoordinatorErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntentChirho { detail_chirho } => {
                write!(formatter_chirho, "effect intent refused: {detail_chirho}")
            }
            Self::CompensationChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect compensation refused: {detail_chirho}"
                )
            }
            Self::TerminalChirho { detail_chirho } => {
                write!(formatter_chirho, "effect terminal refused: {detail_chirho}")
            }
            Self::EvidenceChirho { detail_chirho } => {
                write!(formatter_chirho, "effect evidence failed: {detail_chirho}")
            }
            Self::JournalChirho { detail_chirho } => {
                write!(formatter_chirho, "effect journal failed: {detail_chirho}")
            }
            Self::JournalCommittedEvidencePendingChirho {
                receipt_chirho,
                identity_chirho,
                detail_chirho,
            } => write!(
                formatter_chirho,
                "effect journal committed seq {} but authority evidence remains pending ({identity_chirho:?}): {detail_chirho}",
                receipt_chirho.seq_chirho,
            ),
            Self::JournalAuthorityRefusedChirho {
                identity_chirho,
                detail_chirho,
            } => write!(
                formatter_chirho,
                "effect journal authority refused ({identity_chirho:?}): {detail_chirho}"
            ),
            Self::CacheChirho { detail_chirho } => {
                write!(formatter_chirho, "effect cache refused: {detail_chirho}")
            }
            Self::MissingIntentEvidenceChirho { intent_ref_chirho } => write!(
                formatter_chirho,
                "effect intent evidence is missing for {}",
                intent_ref_chirho.0
            ),
            Self::IntentEvidenceMismatchChirho { intent_ref_chirho } => write!(
                formatter_chirho,
                "effect intent evidence does not bind {}",
                intent_ref_chirho.0
            ),
            Self::CompensationIntentEvidenceConflictChirho {
                compensation_key_chirho,
            } => write!(
                formatter_chirho,
                "compensation intent evidence conflicts at {compensation_key_chirho}"
            ),
            Self::MissingJournalReceiptChirho { intent_ref_chirho } => write!(
                formatter_chirho,
                "effect journal receipt is missing for {}",
                intent_ref_chirho.0
            ),
            Self::TerminalStateStillActiveChirho { intent_ref_chirho } => write!(
                formatter_chirho,
                "terminal effect state is still listed active for {}",
                intent_ref_chirho.0
            ),
        }
    }
}

impl std::error::Error for EffectCommitCoordinatorErrorChirho {}

/// The synchronous coordinator. The composition root may put an async pump around this core; that
/// adapter adds scheduling only and no authority.
pub struct EffectCommitCoordinatorChirho<'ports_chirho> {
    provider_chirho: &'ports_chirho mut dyn BlessedEffectProviderPortChirho,
    evidence_chirho: &'ports_chirho mut dyn EffectCommitEvidencePortChirho,
    journal_chirho: &'ports_chirho mut dyn EffectCommitJournalPortChirho,
    intent_verifier_chirho: &'ports_chirho dyn EffectIntentSignerPortChirho,
    terminal_signer_chirho: &'ports_chirho dyn EffectTerminalSignerPortChirho,
}

impl<'ports_chirho> EffectCommitCoordinatorChirho<'ports_chirho> {
    pub fn new_chirho(
        provider_chirho: &'ports_chirho mut dyn BlessedEffectProviderPortChirho,
        evidence_chirho: &'ports_chirho mut dyn EffectCommitEvidencePortChirho,
        journal_chirho: &'ports_chirho mut dyn EffectCommitJournalPortChirho,
        intent_verifier_chirho: &'ports_chirho dyn EffectIntentSignerPortChirho,
        terminal_signer_chirho: &'ports_chirho dyn EffectTerminalSignerPortChirho,
    ) -> Self {
        Self {
            provider_chirho,
            evidence_chirho,
            journal_chirho,
            intent_verifier_chirho,
            terminal_signer_chirho,
        }
    }

    /// Persist intent evidence, append the Hold, then and only then invoke the provider.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub fn execute_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> Result<EffectCommitRunResultChirho, EffectCommitCoordinatorErrorChirho> {
        let (verified_intent_chirho, intent_ref_chirho) =
            self.verify_execution_intent_chirho(canonical_intent_line_chirho)?;
        let hold_receipt_chirho =
            self.persist_intent_and_hold_chirho(canonical_intent_line_chirho, &intent_ref_chirho)?;
        let observation_chirho = self.execute_or_query_observation_chirho(&verified_intent_chirho);
        self.close_observation_chirho(
            canonical_intent_line_chirho,
            intent_ref_chirho,
            hold_receipt_chirho,
            observation_chirho,
        )
    }

    /// Meter a cache hit through the exact provider-commit money path while skipping provider I/O.
    /// The opaque token is intent-bound by an injected verifier; no caller-selectable cache flag
    /// reaches this method. Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub fn execute_verified_cache_hit_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        cache_hit_chirho: VerifiedEffectCacheHitChirho,
    ) -> Result<EffectCommitRunResultChirho, EffectCommitCoordinatorErrorChirho> {
        let (_verified_intent_chirho, intent_ref_chirho) =
            self.verify_execution_intent_chirho(canonical_intent_line_chirho)?;
        if intent_ref_chirho != cache_hit_chirho.intent_ref_chirho {
            return Err(EffectCommitCoordinatorErrorChirho::CacheChirho {
                detail_chirho: "verified cache token names a different signed intent".to_owned(),
            });
        }
        let hold_receipt_chirho =
            self.persist_intent_and_hold_chirho(canonical_intent_line_chirho, &intent_ref_chirho)?;
        self.close_observation_chirho(
            canonical_intent_line_chirho,
            intent_ref_chirho,
            hold_receipt_chirho,
            EffectProviderObservationChirho::CommittedChirho {
                result_ref_chirho: cache_hit_chirho.result_ref_chirho,
                evidence_chirho: cache_hit_chirho.evidence_chirho,
            },
        )
    }

    /// Create-or-load the one authoritative compensation intent before its Hold, then use the
    /// exact provider/terminal spine as a forward effect. Different rollback events for one
    /// original K collide at the evidence boundary before provider or money work.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub fn execute_compensation_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        authorization_chirho: VerifiedEffectCompensationChirho,
    ) -> Result<EffectCommitRunResultChirho, EffectCommitCoordinatorErrorChirho> {
        let (verified_intent_chirho, intent_ref_chirho) =
            self.verify_execution_intent_chirho(canonical_intent_line_chirho)?;
        let original_effect_key_chirho = verified_intent_chirho
            .intent_chirho()
            .original_effect_key_chirho
            .as_deref()
            .ok_or_else(|| EffectCommitCoordinatorErrorChirho::CompensationChirho {
                detail_chirho: "compensation intent lacks its original effect K".to_owned(),
            })?;
        let compensation_key_chirho = effect_compensation_key_chirho(original_effect_key_chirho)
            .map_err(
                |error_chirho| EffectCommitCoordinatorErrorChirho::CompensationChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        let control_saga_id_chirho = parse_effect_compensation_key_chirho(&compensation_key_chirho)
            .map_err(
                |error_chirho| EffectCommitCoordinatorErrorChirho::CompensationChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        if authorization_chirho.intent_ref_chirho() != &intent_ref_chirho
            || authorization_chirho.compensation_key_chirho() != compensation_key_chirho
            || authorization_chirho.control_saga_id_chirho() != &control_saga_id_chirho
            || authorization_chirho.original_effect_key_chirho() != original_effect_key_chirho
            || authorization_chirho.next_depth_chirho() == 0
            || authorization_chirho.max_depth_chirho() == 0
            || authorization_chirho.next_depth_chirho() > authorization_chirho.max_depth_chirho()
        {
            return Err(EffectCommitCoordinatorErrorChirho::CompensationChirho {
                detail_chirho:
                    "compensation authorization token does not bind this signed intent and depth"
                        .to_owned(),
            });
        }

        let stored_line_chirho = self
            .evidence_chirho
            .create_or_load_compensation_intent_line_chirho(
                &compensation_key_chirho,
                &intent_ref_chirho,
                canonical_intent_line_chirho,
            )
            .map_err(|error_chirho| match error_chirho {
                EffectEvidencePortErrorChirho::ConflictChirho { .. } => {
                    EffectCommitCoordinatorErrorChirho::CompensationIntentEvidenceConflictChirho {
                        compensation_key_chirho: compensation_key_chirho.clone(),
                    }
                }
                other_chirho => evidence_error_chirho(other_chirho),
            })?;
        if stored_line_chirho != canonical_intent_line_chirho {
            return Err(
                EffectCommitCoordinatorErrorChirho::CompensationIntentEvidenceConflictChirho {
                    compensation_key_chirho,
                },
            );
        }
        let hold_receipt_chirho = self
            .journal_chirho
            .append_compensation_hold_chirho(canonical_intent_line_chirho, &authorization_chirho)
            .map_err(journal_error_chirho)?;
        let observation_chirho = self.execute_or_query_observation_chirho(&verified_intent_chirho);
        self.close_observation_chirho(
            canonical_intent_line_chirho,
            intent_ref_chirho,
            hold_receipt_chirho,
            observation_chirho,
        )
    }

    fn verify_execution_intent_chirho(
        &self,
        canonical_intent_line_chirho: &str,
    ) -> Result<(VerifiedEffectIntentChirho, DigestChirho), EffectCommitCoordinatorErrorChirho>
    {
        let verified_intent_chirho = verify_effect_intent_line_chirho(
            canonical_intent_line_chirho,
            self.intent_verifier_chirho,
        )
        .map_err(
            |error_chirho| EffectCommitCoordinatorErrorChirho::IntentChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
        let intent_ref_chirho = effect_intent_ref_chirho(verified_intent_chirho.intent_chirho())
            .map_err(
                |error_chirho| EffectCommitCoordinatorErrorChirho::IntentChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        Ok((verified_intent_chirho, intent_ref_chirho))
    }

    fn execute_or_query_observation_chirho(
        &mut self,
        verified_intent_chirho: &VerifiedEffectIntentChirho,
    ) -> EffectProviderObservationChirho {
        match self
            .provider_chirho
            .execute_or_replay_chirho(verified_intent_chirho)
        {
            Ok(observation_chirho) => observation_chirho,
            Err(_) => self
                .provider_chirho
                .query_by_key_chirho(verified_intent_chirho)
                .unwrap_or(EffectProviderObservationChirho::InDoubtChirho),
        }
    }

    fn persist_intent_and_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitCoordinatorErrorChirho> {
        self.evidence_chirho
            .store_intent_line_chirho(intent_ref_chirho, canonical_intent_line_chirho)
            .map_err(evidence_error_chirho)?;
        self.journal_chirho
            .append_hold_chirho(canonical_intent_line_chirho)
            .map_err(journal_error_chirho)
    }

    /// Reconcile every active CF3 Hold from retained, signed intent evidence and provider query K.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub fn reconcile_all_in_doubt_chirho(
        &mut self,
    ) -> Result<Vec<EffectCommitRunResultChirho>, EffectCommitCoordinatorErrorChirho> {
        let intent_refs_chirho = self
            .journal_chirho
            .active_hold_intent_refs_chirho()
            .map_err(journal_error_chirho)?;
        let mut results_chirho = Vec::with_capacity(intent_refs_chirho.len());
        for intent_ref_chirho in intent_refs_chirho {
            results_chirho.push(self.reconcile_in_doubt_chirho(intent_ref_chirho)?);
        }
        Ok(results_chirho)
    }

    /// Close one named active Hold through the provider's read-by-K contract. Operator porcelain
    /// uses this targeted door after a crash; host construction remains strictly write-free.
    pub fn reconcile_in_doubt_chirho(
        &mut self,
        intent_ref_chirho: DigestChirho,
    ) -> Result<EffectCommitRunResultChirho, EffectCommitCoordinatorErrorChirho> {
        let state_chirho = self
            .journal_chirho
            .receipt_by_intent_ref_chirho(&intent_ref_chirho)
            .map_err(journal_error_chirho)?
            .ok_or_else(
                || EffectCommitCoordinatorErrorChirho::MissingJournalReceiptChirho {
                    intent_ref_chirho: intent_ref_chirho.clone(),
                },
            )?;
        if state_chirho.intent_ref_chirho != intent_ref_chirho {
            return Err(
                EffectCommitCoordinatorErrorChirho::IntentEvidenceMismatchChirho {
                    intent_ref_chirho,
                },
            );
        }
        if state_chirho.terminal_outcome_ref_chirho.is_some() {
            return Err(
                EffectCommitCoordinatorErrorChirho::TerminalStateStillActiveChirho {
                    intent_ref_chirho,
                },
            );
        }
        let canonical_intent_line_chirho = self
            .evidence_chirho
            .load_intent_line_chirho(&intent_ref_chirho)
            .map_err(evidence_error_chirho)?
            .ok_or_else(
                || EffectCommitCoordinatorErrorChirho::MissingIntentEvidenceChirho {
                    intent_ref_chirho: intent_ref_chirho.clone(),
                },
            )?;
        let verified_intent_chirho = verify_effect_intent_line_chirho(
            &canonical_intent_line_chirho,
            self.intent_verifier_chirho,
        )
        .map_err(
            |error_chirho| EffectCommitCoordinatorErrorChirho::IntentChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
        if effect_intent_ref_chirho(verified_intent_chirho.intent_chirho()).map_err(
            |error_chirho| EffectCommitCoordinatorErrorChirho::IntentChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )? != intent_ref_chirho
        {
            return Err(
                EffectCommitCoordinatorErrorChirho::IntentEvidenceMismatchChirho {
                    intent_ref_chirho,
                },
            );
        }
        let observation_chirho = match self
            .provider_chirho
            .query_by_key_chirho(&verified_intent_chirho)
        {
            Ok(observation_chirho) => observation_chirho,
            Err(_) => EffectProviderObservationChirho::InDoubtChirho,
        };
        self.close_observation_chirho(
            &canonical_intent_line_chirho,
            intent_ref_chirho,
            state_chirho.receipt_chirho,
            observation_chirho,
        )
    }

    fn close_observation_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        intent_ref_chirho: DigestChirho,
        hold_receipt_chirho: EffectCommitJournalReceiptChirho,
        observation_chirho: EffectProviderObservationChirho,
    ) -> Result<EffectCommitRunResultChirho, EffectCommitCoordinatorErrorChirho> {
        let (disposition_chirho, evidence_chirho) = match observation_chirho {
            EffectProviderObservationChirho::CommittedChirho {
                result_ref_chirho,
                evidence_chirho,
            } => (
                EffectTerminalDispositionChirho::CommittedChirho { result_ref_chirho },
                evidence_chirho,
            ),
            EffectProviderObservationChirho::DefiniteNoEffectChirho { evidence_chirho } => (
                EffectTerminalDispositionChirho::DefiniteNoEffectChirho,
                evidence_chirho,
            ),
            EffectProviderObservationChirho::InDoubtChirho => {
                return Ok(EffectCommitRunResultChirho::InDoubtChirho {
                    intent_ref_chirho,
                    hold_receipt_chirho,
                });
            }
        };

        // Provider evidence lands before the signed outcome and before the terminal money append.
        // A crash at either boundary leaves an orphaned evidence object plus a live Hold, never a
        // settlement without its warrant.
        let provider_evidence_ref_chirho =
            effect_provider_evidence_ref_chirho(evidence_chirho.as_slice_chirho());
        self.evidence_chirho
            .store_provider_evidence_chirho(
                &provider_evidence_ref_chirho,
                evidence_chirho.as_slice_chirho(),
            )
            .map_err(evidence_error_chirho)?;
        let outcome_chirho = sign_effect_terminal_outcome_chirho(
            EffectTerminalOutcomeChirho {
                schema_chirho: EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO.to_owned(),
                intent_ref_chirho: intent_ref_chirho.clone(),
                provider_evidence_ref_chirho,
                disposition_chirho: disposition_chirho.clone(),
                sig_chirho: String::new(),
                key_id_chirho: String::new(),
            },
            self.terminal_signer_chirho,
        )
        .map_err(
            |error_chirho| EffectCommitCoordinatorErrorChirho::TerminalChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
        let canonical_terminal_line_chirho =
            canonical_effect_terminal_outcome_line_chirho(&outcome_chirho).map_err(
                |error_chirho| EffectCommitCoordinatorErrorChirho::TerminalChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        let outcome_ref_chirho =
            effect_terminal_outcome_ref_chirho(&outcome_chirho).map_err(|error_chirho| {
                EffectCommitCoordinatorErrorChirho::TerminalChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?;
        self.evidence_chirho
            .store_terminal_outcome_line_chirho(
                &outcome_ref_chirho,
                &canonical_terminal_line_chirho,
            )
            .map_err(evidence_error_chirho)?;
        let terminal_receipt_chirho = self
            .journal_chirho
            .append_terminal_chirho(
                canonical_intent_line_chirho,
                &canonical_terminal_line_chirho,
            )
            .map_err(journal_error_chirho)?;
        Ok(EffectCommitRunResultChirho::TerminalChirho {
            intent_ref_chirho,
            hold_receipt_chirho,
            terminal_receipt_chirho,
            outcome_ref_chirho,
            disposition_chirho,
        })
    }
}

pub fn effect_provider_evidence_ref_chirho(evidence_bytes_chirho: &[u8]) -> DigestChirho {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(EFFECT_PROVIDER_EVIDENCE_REF_DOMAIN_CHIRHO);
    hasher_chirho.update(&(evidence_bytes_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(evidence_bytes_chirho);
    DigestChirho(hasher_chirho.finalize().to_hex().to_string())
}

fn evidence_error_chirho(
    error_chirho: EffectEvidencePortErrorChirho,
) -> EffectCommitCoordinatorErrorChirho {
    EffectCommitCoordinatorErrorChirho::EvidenceChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

fn journal_error_chirho(
    error_chirho: EffectCommitJournalPortErrorChirho,
) -> EffectCommitCoordinatorErrorChirho {
    match error_chirho {
        EffectCommitJournalPortErrorChirho::CommittedEvidencePendingChirho {
            receipt_chirho,
            identity_chirho,
            detail_chirho,
        } => EffectCommitCoordinatorErrorChirho::JournalCommittedEvidencePendingChirho {
            receipt_chirho,
            identity_chirho,
            detail_chirho,
        },
        EffectCommitJournalPortErrorChirho::AuthorityRefusedChirho {
            identity_chirho,
            detail_chirho,
        } => EffectCommitCoordinatorErrorChirho::JournalAuthorityRefusedChirho {
            identity_chirho,
            detail_chirho,
        },
        error_chirho => EffectCommitCoordinatorErrorChirho::JournalChirho {
            detail_chirho: error_chirho.to_string(),
        },
    }
}
