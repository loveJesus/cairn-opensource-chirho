// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Durable prepaid-budget evidence with one fail-closed authority boundary.
//!
//! The physical event log remains one bounded file per evidence root. Every line is a canonical
//! store-authored chain wrapper around an externally signed event: the wrapper owns dense file order
//! and previous-line binding, while the signed event owns per-budget semantic order. A separately
//! custodied checkpoint commits the exact current line before it is appended. Readers never repair;
//! append and the explicit operator repair road take the root lock and recover one committed line.
//!
//! Funding is an immutable signed scalar per budget identity. No append, replay, report, or adapter
//! receives a caller-supplied ceiling. Changing a ceiling requires a new budget id; production-money
//! supersession and transfer remain outside this test-credit mechanism.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/budget-integrity-chirho/`
//! `budget-admission-and-repair-chirho.md`.

use cairn_chain_core_chirho::{
    chain_anchor_hex_chirho, stored_line_digest_hex_chirho, walk_verified_chain_chirho,
    ChainFamilyChirho, ChainWalkErrorChirho,
};
use cairn_core_chirho::store_chirho::put_object_chirho;
use cairn_durable_chirho::CreateFileDurableOutcomeChirho;
use cairn_placement_chirho::budget_chirho::budget_event_attestation_chirho::{
    authenticate_budget_event_chirho, bind_authenticated_budget_event_chirho,
    BudgetAuthorityPortChirho, BudgetEventAttestationChirho, BudgetEventKindChirho,
    BudgetEventRefusalChirho, VerifiedBudgetEventChirho,
};
use cairn_placement_chirho::budget_chirho::budget_funding_attestation_chirho::{
    verify_budget_funding_chirho, BudgetEvidenceScopeChirho, BudgetFundingAttestationChirho,
    BudgetFundingRefusalChirho, VerifiedBudgetFundingChirho,
};
use cairn_placement_chirho::budget_chirho::infrastructure_budget_chirho::{
    BudgetRefusalChirho, InfrastructureBudgetChirho,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

pub const BUDGET_EVENT_LOG_CHIRHO: &str = "infrastructure-budget-events-chirho.jsonl";
pub const BUDGET_EVENT_LOG_MAX_BYTES_CHIRHO: u64 = 8 * 1024 * 1024;
pub const BUDGET_EVENT_LINE_MAX_BYTES_CHIRHO: usize = 16 * 1024;
pub const BUDGET_FUNDING_RECORD_MAX_BYTES_CHIRHO: u64 = 8 * 1024;
pub const BUDGET_CHECKPOINT_MAX_BYTES_CHIRHO: u64 = 48 * 1024;
pub const BUDGET_FUNDING_MAX_RECORDS_PER_ROOT_CHIRHO: usize = 4_096;
pub const BUDGET_EVENT_LINE_SCHEMA_V1_CHIRHO: &str = "cairn.budget-event-line.v1.chirho";
pub const BUDGET_LOG_CHECKPOINT_SCHEMA_V1_CHIRHO: &str = "cairn.budget-log-checkpoint.v1.chirho";
pub const BUDGET_REPORT_SCHEMA_V2_CHIRHO: &str = "infrastructure-budget-report-v2-chirho";

const BUDGET_CHAIN_DOMAIN_V1_CHIRHO: &str = "cairn.budget-event-chain.v1.chirho";
const BUDGET_ROOT_WRITE_LOCK_CHIRHO: &str = "infrastructure-budget-root-write-chirho";
const BUDGET_AUTHORITY_LOCK_PREFIX_CHIRHO: &str = "infrastructure-budget-authority-write-chirho";
const BUDGET_AUTHORITY_DIR_CHIRHO: &str = "budget-authority-chirho";
const BUDGET_FUNDING_DIR_CHIRHO: &str = "funding-chirho";
const BUDGET_CHECKPOINT_DIR_CHIRHO: &str = "checkpoints-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetStoreRefusalChirho {
    StoreUnavailableChirho,
    StoreIdentityUnstableChirho,
    AuthorityRootUnavailableChirho,
    AuthorityRootOverlapsEvidenceRootChirho,
    RootIdentityUnavailableChirho,
    DecodeChirho {
        line_chirho: u64,
    },
    NonCanonicalLineChirho {
        line_chirho: u64,
    },
    TornTailChirho,
    TornTailDoesNotMatchCheckpointChirho,
    BoundExceededChirho,
    FundingPopulationBoundExceededChirho,
    LegacyLogRequiresRegenesisChirho,
    FundingNotFoundChirho {
        budget_id_chirho: String,
    },
    FundingImmutableConflictChirho {
        budget_id_chirho: String,
    },
    FundingSignatureInvalidChirho {
        refusal_chirho: BudgetFundingRefusalChirho,
    },
    FundingBindingMismatchChirho {
        refusal_chirho: BudgetFundingRefusalChirho,
    },
    FundingMalformedChirho {
        refusal_chirho: BudgetFundingRefusalChirho,
    },
    CheckpointNotFoundChirho,
    CheckpointMalformedChirho,
    CheckpointScopeMismatchChirho,
    CheckpointAuthorityMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
    CheckpointTailLineMissingChirho,
    CheckpointTailLineMismatchChirho,
    CheckpointAheadOrAppendInFlightChirho {
        local_count_chirho: u64,
        checkpoint_count_chirho: u64,
    },
    CheckpointTooFarAheadChirho {
        local_count_chirho: u64,
        checkpoint_count_chirho: u64,
    },
    LocalLogAheadOfCheckpointChirho {
        local_count_chirho: u64,
        checkpoint_count_chirho: u64,
    },
    CheckpointTailMismatchChirho,
    CheckpointAdvanceConflictChirho,
    DuplicateChainSeqChirho {
        expected_chirho: u64,
        found_chirho: u64,
    },
    GapChainSeqChirho {
        expected_chirho: u64,
        found_chirho: u64,
    },
    PreviousLineBindingMismatchChirho {
        seq_chirho: u64,
    },
    ReplayedEventSeqChirho {
        budget_id_chirho: String,
        highest_recorded_chirho: u64,
        offered_chirho: u64,
    },
    IntentNotStoredChirho,
    IntentDigestNotItsCasAddressChirho {
        declared_chirho: String,
        stored_at_chirho: String,
    },
    RuleChirho {
        refusal_chirho: BudgetRefusalChirho,
    },
    EventSignatureInvalidChirho {
        refusal_chirho: BudgetEventRefusalChirho,
    },
    EventBindingMismatchChirho {
        refusal_chirho: BudgetEventRefusalChirho,
    },
    EventMalformedChirho {
        refusal_chirho: BudgetEventRefusalChirho,
    },
    ConservationViolatedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEventLineChirho {
    pub schema_chirho: String,
    pub chain_seq_chirho: u64,
    pub previous_line_digest_chirho: String,
    pub record_chirho: BudgetEventAttestationChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BudgetLogCheckpointChirho {
    schema_chirho: String,
    evidence_root_key_id_chirho: String,
    tenant_id_chirho: String,
    authority_key_id_chirho: String,
    record_count_chirho: u64,
    tail_digest_chirho: String,
    tail_line_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetRepairOutcomeChirho {
    AlreadySynchronizedAfterWaitChirho,
    RecoveredAbandonedCheckpointChirho { chain_seq_chirho: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetCeilingProvenanceChirho {
    AuthenticatedFundingChirho {
        funding_record_digest_chirho: String,
        authority_key_id_chirho: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReportChirho {
    pub schema_chirho: String,
    pub budget_id_chirho: String,
    pub prepaid_ceiling_micros_chirho: u64,
    pub ceiling_provenance_chirho: BudgetCeilingProvenanceChirho,
    pub settled_micros_chirho: u64,
    pub outstanding_micros_chirho: u64,
    pub available_micros_chirho: u64,
    pub conservation_holds_chirho: bool,
    pub awaiting_release_chirho: Vec<String>,
}

#[derive(Clone, Debug)]
struct BudgetRootScopeChirho {
    evidence_root_key_id_chirho: String,
    tenant_id_chirho: String,
}

struct VerifiedBudgetLogChirho {
    events_chirho: Vec<VerifiedBudgetEventChirho>,
    record_count_chirho: u64,
    tail_digest_chirho: String,
}

fn log_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(BUDGET_EVENT_LOG_CHIRHO)
}

fn root_storage_key_chirho(scope_chirho: &BudgetRootScopeChirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(scope_chirho.evidence_root_key_id_chirho.as_bytes());
    hasher_chirho.update(b"\0");
    hasher_chirho.update(scope_chirho.tenant_id_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

fn funding_storage_key_chirho(scope_chirho: &BudgetEvidenceScopeChirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(scope_chirho.evidence_root_key_id_chirho.as_bytes());
    hasher_chirho.update(b"\0");
    hasher_chirho.update(scope_chirho.tenant_id_chirho.as_bytes());
    hasher_chirho.update(b"\0");
    hasher_chirho.update(scope_chirho.budget_id_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

fn funding_root_dir_chirho(
    authority_root_chirho: &Path,
    root_scope_chirho: &BudgetRootScopeChirho,
) -> PathBuf {
    authority_root_chirho
        .join(BUDGET_AUTHORITY_DIR_CHIRHO)
        .join(BUDGET_FUNDING_DIR_CHIRHO)
        .join(root_storage_key_chirho(root_scope_chirho))
}

fn funding_path_chirho(
    authority_root_chirho: &Path,
    scope_chirho: &BudgetEvidenceScopeChirho,
) -> PathBuf {
    let key_chirho = funding_storage_key_chirho(scope_chirho);
    let root_scope_chirho = BudgetRootScopeChirho {
        evidence_root_key_id_chirho: scope_chirho.evidence_root_key_id_chirho.clone(),
        tenant_id_chirho: scope_chirho.tenant_id_chirho.clone(),
    };
    funding_root_dir_chirho(authority_root_chirho, &root_scope_chirho)
        .join(&key_chirho[..2])
        .join(format!("{key_chirho}.json"))
}

fn checkpoint_path_chirho(
    authority_root_chirho: &Path,
    scope_chirho: &BudgetRootScopeChirho,
) -> PathBuf {
    let key_chirho = root_storage_key_chirho(scope_chirho);
    authority_root_chirho
        .join(BUDGET_AUTHORITY_DIR_CHIRHO)
        .join(BUDGET_CHECKPOINT_DIR_CHIRHO)
        .join(&key_chirho[..2])
        .join(format!("{key_chirho}.json"))
}

fn derive_root_scope_chirho(
    evidence_root_chirho: &Path,
) -> Result<BudgetRootScopeChirho, BudgetStoreRefusalChirho> {
    let evidence_root_key_id_chirho =
        cairn_signer_chirho::signer_chirho::existing_pubkey_hex_chirho(evidence_root_chirho)
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::RootIdentityUnavailableChirho)?;
    let tenant_id_chirho =
        cairn_tenant_chirho::tenant_chirho::tenant_id_for_root_chirho(evidence_root_chirho)
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::RootIdentityUnavailableChirho)?
            .to_string();
    Ok(BudgetRootScopeChirho {
        evidence_root_key_id_chirho,
        tenant_id_chirho,
    })
}

pub fn budget_evidence_scope_chirho(
    evidence_root_chirho: &Path,
    budget_id_chirho: &str,
) -> Result<BudgetEvidenceScopeChirho, BudgetStoreRefusalChirho> {
    let root_scope_chirho = derive_root_scope_chirho(evidence_root_chirho)?;
    Ok(BudgetEvidenceScopeChirho {
        evidence_root_key_id_chirho: root_scope_chirho.evidence_root_key_id_chirho,
        tenant_id_chirho: root_scope_chirho.tenant_id_chirho,
        budget_id_chirho: budget_id_chirho.to_string(),
    })
}

fn validate_custody_roots_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
) -> Result<(), BudgetStoreRefusalChirho> {
    let evidence_chirho = fs::canonicalize(evidence_root_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::StoreUnavailableChirho)?;
    let authority_chirho = fs::canonicalize(authority_root_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)?;
    if evidence_chirho == authority_chirho
        || evidence_chirho.starts_with(&authority_chirho)
        || authority_chirho.starts_with(&evidence_chirho)
    {
        return Err(BudgetStoreRefusalChirho::AuthorityRootOverlapsEvidenceRootChirho);
    }
    Ok(())
}

fn chain_anchor_for_scope_chirho(scope_chirho: &BudgetRootScopeChirho) -> String {
    chain_anchor_hex_chirho(
        BUDGET_CHAIN_DOMAIN_V1_CHIRHO,
        &format!(
            "{}|{}",
            scope_chirho.evidence_root_key_id_chirho, scope_chirho.tenant_id_chirho
        ),
    )
}

fn read_log_bytes_chirho(root_chirho: &Path) -> Result<Vec<u8>, BudgetStoreRefusalChirho> {
    match cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &log_path_chirho(root_chirho),
        BUDGET_EVENT_LOG_MAX_BYTES_CHIRHO,
    ) {
        Ok(bytes_chirho) => Ok(bytes_chirho),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::InvalidData => {
            Err(BudgetStoreRefusalChirho::StoreIdentityUnstableChirho)
        }
        Err(_error_chirho) => Err(BudgetStoreRefusalChirho::StoreUnavailableChirho),
    }
}

fn complete_log_text_chirho(bytes_chirho: &[u8]) -> Result<&str, BudgetStoreRefusalChirho> {
    if !bytes_chirho.is_empty() && !bytes_chirho.ends_with(b"\n") {
        return Err(BudgetStoreRefusalChirho::TornTailChirho);
    }
    let text_chirho = std::str::from_utf8(bytes_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::DecodeChirho { line_chirho: 0 })?;
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            return Err(BudgetStoreRefusalChirho::NonCanonicalLineChirho {
                line_chirho: index_chirho as u64 + 1,
            });
        }
    }
    Ok(text_chirho)
}

fn classify_event_verification_refusal_chirho(
    refusal_chirho: BudgetEventRefusalChirho,
) -> BudgetStoreRefusalChirho {
    match refusal_chirho {
        BudgetEventRefusalChirho::BadSignatureChirho
        | BudgetEventRefusalChirho::IntentDigestMismatchChirho { .. } => {
            BudgetStoreRefusalChirho::EventSignatureInvalidChirho { refusal_chirho }
        }
        BudgetEventRefusalChirho::UnknownAuthorityKeyChirho { .. }
        | BudgetEventRefusalChirho::BudgetMismatchChirho { .. }
        | BudgetEventRefusalChirho::EvidenceRootMismatchChirho { .. }
        | BudgetEventRefusalChirho::TenantMismatchChirho { .. }
        | BudgetEventRefusalChirho::FundingDigestMismatchChirho { .. }
        | BudgetEventRefusalChirho::SignatureDomainMismatchChirho { .. } => {
            BudgetStoreRefusalChirho::EventBindingMismatchChirho { refusal_chirho }
        }
        BudgetEventRefusalChirho::RecordSchemaMismatchChirho { .. }
        | BudgetEventRefusalChirho::IntentSchemaMismatchChirho { .. }
        | BudgetEventRefusalChirho::FieldTooLongChirho { .. }
        | BudgetEventRefusalChirho::ZeroReservationChirho => {
            BudgetStoreRefusalChirho::EventMalformedChirho { refusal_chirho }
        }
    }
}

fn classify_funding_verification_refusal_chirho(
    refusal_chirho: BudgetFundingRefusalChirho,
) -> BudgetStoreRefusalChirho {
    match refusal_chirho {
        BudgetFundingRefusalChirho::BadSignatureChirho
        | BudgetFundingRefusalChirho::IntentDigestMismatchChirho { .. } => {
            BudgetStoreRefusalChirho::FundingSignatureInvalidChirho { refusal_chirho }
        }
        BudgetFundingRefusalChirho::UnknownAuthorityKeyChirho { .. }
        | BudgetFundingRefusalChirho::EvidenceRootMismatchChirho { .. }
        | BudgetFundingRefusalChirho::TenantMismatchChirho { .. }
        | BudgetFundingRefusalChirho::BudgetMismatchChirho { .. }
        | BudgetFundingRefusalChirho::SignatureDomainMismatchChirho { .. } => {
            BudgetStoreRefusalChirho::FundingBindingMismatchChirho { refusal_chirho }
        }
        BudgetFundingRefusalChirho::RecordSchemaMismatchChirho { .. }
        | BudgetFundingRefusalChirho::IntentSchemaMismatchChirho { .. }
        | BudgetFundingRefusalChirho::FieldTooLongChirho { .. } => {
            BudgetStoreRefusalChirho::FundingMalformedChirho { refusal_chirho }
        }
    }
}

fn load_verified_funding_chirho(
    authority_root_chirho: &Path,
    scope_chirho: &BudgetEvidenceScopeChirho,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<VerifiedBudgetFundingChirho, BudgetStoreRefusalChirho> {
    let path_chirho = funding_path_chirho(authority_root_chirho, scope_chirho);
    let bytes_chirho = match cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        BUDGET_FUNDING_RECORD_MAX_BYTES_CHIRHO,
    ) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Err(BudgetStoreRefusalChirho::FundingNotFoundChirho {
                budget_id_chirho: scope_chirho.budget_id_chirho.clone(),
            });
        }
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::InvalidData => {
            return Err(BudgetStoreRefusalChirho::StoreIdentityUnstableChirho);
        }
        Err(_error_chirho) => {
            return Err(BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho);
        }
    };
    let record_chirho: BudgetFundingAttestationChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(
            |_error_chirho| BudgetStoreRefusalChirho::FundingMalformedChirho {
                refusal_chirho: BudgetFundingRefusalChirho::RecordSchemaMismatchChirho {
                    found_chirho: "undecodable-chirho".to_string(),
                },
            },
        )?;
    let canonical_chirho = serde_json::to_vec(&record_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)?;
    if canonical_chirho != bytes_chirho {
        return Err(BudgetStoreRefusalChirho::FundingMalformedChirho {
            refusal_chirho: BudgetFundingRefusalChirho::RecordSchemaMismatchChirho {
                found_chirho: "non-canonical-chirho".to_string(),
            },
        });
    }
    verify_budget_funding_chirho(&record_chirho, authority_chirho, scope_chirho)
        .map_err(classify_funding_verification_refusal_chirho)
}

struct BudgetChainFamilyChirho<'a> {
    authority_root_chirho: &'a Path,
    authority_chirho: &'a dyn BudgetAuthorityPortChirho,
    root_scope_chirho: &'a BudgetRootScopeChirho,
    verified_events_chirho: RefCell<Vec<VerifiedBudgetEventChirho>>,
}

impl ChainFamilyChirho for BudgetChainFamilyChirho<'_> {
    type RecordChirho = BudgetEventLineChirho;
    type ErrorChirho = BudgetStoreRefusalChirho;

    fn parse_line_chirho(
        &self,
        line_chirho: &str,
    ) -> Result<Self::RecordChirho, Self::ErrorChirho> {
        if line_chirho.len() > BUDGET_EVENT_LINE_MAX_BYTES_CHIRHO {
            return Err(BudgetStoreRefusalChirho::BoundExceededChirho);
        }
        let parsed_chirho: BudgetEventLineChirho = serde_json::from_str(line_chirho)
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::DecodeChirho { line_chirho: 0 })?;
        let canonical_chirho = serde_json::to_string(&parsed_chirho)
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::StoreUnavailableChirho)?;
        if canonical_chirho != line_chirho {
            return Err(BudgetStoreRefusalChirho::NonCanonicalLineChirho { line_chirho: 0 });
        }
        if parsed_chirho.schema_chirho != BUDGET_EVENT_LINE_SCHEMA_V1_CHIRHO {
            return Err(BudgetStoreRefusalChirho::DecodeChirho { line_chirho: 0 });
        }
        Ok(parsed_chirho)
    }

    fn seq_chirho(&self, record_chirho: &Self::RecordChirho) -> u64 {
        record_chirho.chain_seq_chirho
    }

    fn prev_hex_chirho<'record_chirho>(
        &self,
        record_chirho: &'record_chirho Self::RecordChirho,
    ) -> &'record_chirho str {
        &record_chirho.previous_line_digest_chirho
    }

    fn verify_record_chirho(
        &self,
        record_chirho: &Self::RecordChirho,
    ) -> Result<(), Self::ErrorChirho> {
        let authenticated_chirho =
            authenticate_budget_event_chirho(&record_chirho.record_chirho, self.authority_chirho)
                .map_err(classify_event_verification_refusal_chirho)?;
        let scope_chirho = BudgetEvidenceScopeChirho {
            evidence_root_key_id_chirho: self.root_scope_chirho.evidence_root_key_id_chirho.clone(),
            tenant_id_chirho: self.root_scope_chirho.tenant_id_chirho.clone(),
            budget_id_chirho: authenticated_chirho.budget_id_chirho().to_string(),
        };
        let funding_chirho = load_verified_funding_chirho(
            self.authority_root_chirho,
            &scope_chirho,
            self.authority_chirho,
        )?;
        let verified_chirho = bind_authenticated_budget_event_chirho(
            authenticated_chirho,
            &scope_chirho,
            funding_chirho.record_digest_chirho(),
        )
        .map_err(classify_event_verification_refusal_chirho)?;
        self.verified_events_chirho
            .borrow_mut()
            .push(verified_chirho);
        Ok(())
    }
}

fn map_chain_error_chirho(
    error_chirho: ChainWalkErrorChirho<BudgetStoreRefusalChirho>,
) -> BudgetStoreRefusalChirho {
    match error_chirho {
        ChainWalkErrorChirho::DenseSeqChirho {
            expected_chirho,
            found_chirho,
        } if found_chirho < expected_chirho => BudgetStoreRefusalChirho::DuplicateChainSeqChirho {
            expected_chirho,
            found_chirho,
        },
        ChainWalkErrorChirho::DenseSeqChirho {
            expected_chirho,
            found_chirho,
        } => BudgetStoreRefusalChirho::GapChainSeqChirho {
            expected_chirho,
            found_chirho,
        },
        ChainWalkErrorChirho::PrevBindingChirho { seq_chirho } => {
            BudgetStoreRefusalChirho::PreviousLineBindingMismatchChirho { seq_chirho }
        }
        ChainWalkErrorChirho::FamilyChirho { error_chirho } => error_chirho,
    }
}

fn load_verified_log_from_text_chirho(
    text_chirho: &str,
    authority_root_chirho: &Path,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
    root_scope_chirho: &BudgetRootScopeChirho,
) -> Result<VerifiedBudgetLogChirho, BudgetStoreRefusalChirho> {
    let family_chirho = BudgetChainFamilyChirho {
        authority_root_chirho,
        authority_chirho,
        root_scope_chirho,
        verified_events_chirho: RefCell::new(Vec::new()),
    };
    let anchor_chirho = chain_anchor_for_scope_chirho(root_scope_chirho);
    let (lines_chirho, tail_digest_chirho) =
        walk_verified_chain_chirho(text_chirho, &anchor_chirho, &family_chirho)
            .map_err(map_chain_error_chirho)?;
    let events_chirho = family_chirho.verified_events_chirho.into_inner();
    if events_chirho.len() != lines_chirho.len() {
        return Err(BudgetStoreRefusalChirho::StoreUnavailableChirho);
    }
    Ok(VerifiedBudgetLogChirho {
        events_chirho,
        record_count_chirho: lines_chirho.len() as u64,
        tail_digest_chirho,
    })
}

fn load_verified_log_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
    root_scope_chirho: &BudgetRootScopeChirho,
) -> Result<VerifiedBudgetLogChirho, BudgetStoreRefusalChirho> {
    let bytes_chirho = read_log_bytes_chirho(evidence_root_chirho)?;
    let text_chirho = complete_log_text_chirho(&bytes_chirho)?;
    load_verified_log_from_text_chirho(
        text_chirho,
        authority_root_chirho,
        authority_chirho,
        root_scope_chirho,
    )
}

fn read_checkpoint_chirho(
    authority_root_chirho: &Path,
    scope_chirho: &BudgetRootScopeChirho,
) -> Result<BudgetLogCheckpointChirho, BudgetStoreRefusalChirho> {
    let path_chirho = checkpoint_path_chirho(authority_root_chirho, scope_chirho);
    let bytes_chirho = match cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        BUDGET_CHECKPOINT_MAX_BYTES_CHIRHO,
    ) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Err(BudgetStoreRefusalChirho::CheckpointNotFoundChirho);
        }
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::InvalidData => {
            return Err(BudgetStoreRefusalChirho::StoreIdentityUnstableChirho);
        }
        Err(_error_chirho) => {
            return Err(BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho);
        }
    };
    let checkpoint_chirho: BudgetLogCheckpointChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::CheckpointMalformedChirho)?;
    let canonical_chirho = serde_json::to_vec(&checkpoint_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::CheckpointMalformedChirho)?;
    if canonical_chirho != bytes_chirho
        || checkpoint_chirho.schema_chirho != BUDGET_LOG_CHECKPOINT_SCHEMA_V1_CHIRHO
    {
        return Err(BudgetStoreRefusalChirho::CheckpointMalformedChirho);
    }
    if checkpoint_chirho.evidence_root_key_id_chirho != scope_chirho.evidence_root_key_id_chirho
        || checkpoint_chirho.tenant_id_chirho != scope_chirho.tenant_id_chirho
    {
        return Err(BudgetStoreRefusalChirho::CheckpointScopeMismatchChirho);
    }
    Ok(checkpoint_chirho)
}

fn ensure_checkpoint_authority_chirho(
    checkpoint_chirho: &BudgetLogCheckpointChirho,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<(), BudgetStoreRefusalChirho> {
    let found_chirho = authority_chirho.authority_key_id_chirho();
    if checkpoint_chirho.authority_key_id_chirho != found_chirho {
        return Err(
            BudgetStoreRefusalChirho::CheckpointAuthorityMismatchChirho {
                expected_chirho: checkpoint_chirho.authority_key_id_chirho.clone(),
                found_chirho,
            },
        );
    }
    Ok(())
}

fn validate_checkpoint_tail_chirho(
    checkpoint_chirho: &BudgetLogCheckpointChirho,
) -> Result<(), BudgetStoreRefusalChirho> {
    if checkpoint_chirho.record_count_chirho == 0 {
        if checkpoint_chirho.tail_line_chirho.is_some() {
            return Err(BudgetStoreRefusalChirho::CheckpointTailLineMismatchChirho);
        }
        return Ok(());
    }
    let line_chirho = checkpoint_chirho
        .tail_line_chirho
        .as_deref()
        .ok_or(BudgetStoreRefusalChirho::CheckpointTailLineMissingChirho)?;
    if line_chirho.len() > BUDGET_EVENT_LINE_MAX_BYTES_CHIRHO
        || stored_line_digest_hex_chirho(line_chirho) != checkpoint_chirho.tail_digest_chirho
    {
        return Err(BudgetStoreRefusalChirho::CheckpointTailLineMismatchChirho);
    }
    let wrapper_chirho: BudgetEventLineChirho = serde_json::from_str(line_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::CheckpointTailLineMismatchChirho)?;
    if serde_json::to_string(&wrapper_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::CheckpointMalformedChirho)?
        != line_chirho
        || wrapper_chirho.schema_chirho != BUDGET_EVENT_LINE_SCHEMA_V1_CHIRHO
        || wrapper_chirho.chain_seq_chirho.checked_add(1)
            != Some(checkpoint_chirho.record_count_chirho)
    {
        return Err(BudgetStoreRefusalChirho::CheckpointTailLineMismatchChirho);
    }
    Ok(())
}

fn ensure_log_matches_checkpoint_chirho(
    log_chirho: &VerifiedBudgetLogChirho,
    checkpoint_chirho: &BudgetLogCheckpointChirho,
) -> Result<(), BudgetStoreRefusalChirho> {
    validate_checkpoint_tail_chirho(checkpoint_chirho)?;
    if log_chirho.record_count_chirho == checkpoint_chirho.record_count_chirho {
        if log_chirho.tail_digest_chirho == checkpoint_chirho.tail_digest_chirho {
            return Ok(());
        }
        return Err(BudgetStoreRefusalChirho::CheckpointTailMismatchChirho);
    }
    if checkpoint_chirho.record_count_chirho == log_chirho.record_count_chirho + 1 {
        return Err(
            BudgetStoreRefusalChirho::CheckpointAheadOrAppendInFlightChirho {
                local_count_chirho: log_chirho.record_count_chirho,
                checkpoint_count_chirho: checkpoint_chirho.record_count_chirho,
            },
        );
    }
    if checkpoint_chirho.record_count_chirho > log_chirho.record_count_chirho + 1 {
        return Err(BudgetStoreRefusalChirho::CheckpointTooFarAheadChirho {
            local_count_chirho: log_chirho.record_count_chirho,
            checkpoint_count_chirho: checkpoint_chirho.record_count_chirho,
        });
    }
    Err(BudgetStoreRefusalChirho::LocalLogAheadOfCheckpointChirho {
        local_count_chirho: log_chirho.record_count_chirho,
        checkpoint_count_chirho: checkpoint_chirho.record_count_chirho,
    })
}

fn checkpoint_tail_line_for_recovery_chirho<'a>(
    log_chirho: &VerifiedBudgetLogChirho,
    checkpoint_chirho: &'a BudgetLogCheckpointChirho,
) -> Result<&'a str, BudgetStoreRefusalChirho> {
    validate_checkpoint_tail_chirho(checkpoint_chirho)?;
    if checkpoint_chirho.record_count_chirho != log_chirho.record_count_chirho + 1 {
        ensure_log_matches_checkpoint_chirho(log_chirho, checkpoint_chirho)?;
        return Err(BudgetStoreRefusalChirho::CheckpointAdvanceConflictChirho);
    }
    let line_chirho = checkpoint_chirho
        .tail_line_chirho
        .as_deref()
        .ok_or(BudgetStoreRefusalChirho::CheckpointTailLineMissingChirho)?;
    let wrapper_chirho: BudgetEventLineChirho = serde_json::from_str(line_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::CheckpointTailLineMismatchChirho)?;
    if wrapper_chirho.chain_seq_chirho != log_chirho.record_count_chirho
        || wrapper_chirho.previous_line_digest_chirho != log_chirho.tail_digest_chirho
    {
        return Err(BudgetStoreRefusalChirho::CheckpointTailLineMismatchChirho);
    }
    Ok(line_chirho)
}

fn verified_checkpoint_tail_line_for_recovery_chirho<'a>(
    existing_text_chirho: &str,
    existing_log_chirho: &VerifiedBudgetLogChirho,
    authority_root_chirho: &Path,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
    root_scope_chirho: &BudgetRootScopeChirho,
    checkpoint_chirho: &'a BudgetLogCheckpointChirho,
) -> Result<&'a str, BudgetStoreRefusalChirho> {
    let line_chirho =
        checkpoint_tail_line_for_recovery_chirho(existing_log_chirho, checkpoint_chirho)?;
    let mut candidate_chirho = String::with_capacity(
        existing_text_chirho
            .len()
            .saturating_add(line_chirho.len() + 1),
    );
    candidate_chirho.push_str(existing_text_chirho);
    candidate_chirho.push_str(line_chirho);
    candidate_chirho.push('\n');
    let candidate_log_chirho = load_verified_log_from_text_chirho(
        &candidate_chirho,
        authority_root_chirho,
        authority_chirho,
        root_scope_chirho,
    )?;
    ensure_log_matches_checkpoint_chirho(&candidate_log_chirho, checkpoint_chirho)?;
    Ok(line_chirho)
}

fn write_checkpoint_chirho(
    authority_root_chirho: &Path,
    scope_chirho: &BudgetRootScopeChirho,
    checkpoint_chirho: &BudgetLogCheckpointChirho,
) -> Result<(), BudgetStoreRefusalChirho> {
    let bytes_chirho = serde_json::to_vec(checkpoint_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::CheckpointMalformedChirho)?;
    if bytes_chirho.len() as u64 > BUDGET_CHECKPOINT_MAX_BYTES_CHIRHO {
        return Err(BudgetStoreRefusalChirho::BoundExceededChirho);
    }
    cairn_durable_chirho::write_file_durable_with_mode_chirho(
        &checkpoint_path_chirho(authority_root_chirho, scope_chirho),
        &bytes_chirho,
        0o600,
    )
    .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)
}

fn create_genesis_checkpoint_chirho(
    authority_root_chirho: &Path,
    scope_chirho: &BudgetRootScopeChirho,
    authority_key_id_chirho: &str,
) -> Result<(), BudgetStoreRefusalChirho> {
    let checkpoint_chirho = BudgetLogCheckpointChirho {
        schema_chirho: BUDGET_LOG_CHECKPOINT_SCHEMA_V1_CHIRHO.to_string(),
        evidence_root_key_id_chirho: scope_chirho.evidence_root_key_id_chirho.clone(),
        tenant_id_chirho: scope_chirho.tenant_id_chirho.clone(),
        authority_key_id_chirho: authority_key_id_chirho.to_string(),
        record_count_chirho: 0,
        tail_digest_chirho: chain_anchor_for_scope_chirho(scope_chirho),
        tail_line_chirho: None,
    };
    let bytes_chirho = serde_json::to_vec(&checkpoint_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::CheckpointMalformedChirho)?;
    match cairn_durable_chirho::create_complete_file_durable_with_mode_chirho(
        &checkpoint_path_chirho(authority_root_chirho, scope_chirho),
        &bytes_chirho,
        0o600,
    )
    .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)?
    {
        CreateFileDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_checkpoint_chirho(authority_root_chirho, scope_chirho)?;
            if existing_chirho == checkpoint_chirho {
                Ok(())
            } else {
                Err(BudgetStoreRefusalChirho::CheckpointAdvanceConflictChirho)
            }
        }
    }
}

/// Resolve the authority key bound at funding genesis. Later production roads use this trusted
/// coordinate instead of accepting a replacement key through ordinary request or command input.
pub fn budget_authority_key_id_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
) -> Result<String, BudgetStoreRefusalChirho> {
    validate_custody_roots_chirho(evidence_root_chirho, authority_root_chirho)?;
    let root_scope_chirho = derive_root_scope_chirho(evidence_root_chirho)?;
    read_checkpoint_chirho(authority_root_chirho, &root_scope_chirho)
        .map(|checkpoint_chirho| checkpoint_chirho.authority_key_id_chirho)
}

fn funding_record_count_chirho(path_chirho: &Path) -> Result<usize, BudgetStoreRefusalChirho> {
    if !path_chirho.exists() {
        return Ok(0);
    }
    let mut count_chirho = 0usize;
    for shard_chirho in fs::read_dir(path_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)?
    {
        let shard_chirho = shard_chirho
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)?;
        let metadata_chirho = shard_chirho
            .file_type()
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)?;
        if !metadata_chirho.is_dir() || metadata_chirho.is_symlink() {
            return Err(BudgetStoreRefusalChirho::StoreIdentityUnstableChirho);
        }
        for record_chirho in fs::read_dir(shard_chirho.path())
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)?
        {
            let record_chirho = record_chirho.map_err(|_error_chirho| {
                BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho
            })?;
            let metadata_chirho = record_chirho.file_type().map_err(|_error_chirho| {
                BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho
            })?;
            if !metadata_chirho.is_file() || metadata_chirho.is_symlink() {
                return Err(BudgetStoreRefusalChirho::StoreIdentityUnstableChirho);
            }
            count_chirho = count_chirho.saturating_add(1);
            if count_chirho > BUDGET_FUNDING_MAX_RECORDS_PER_ROOT_CHIRHO {
                return Err(BudgetStoreRefusalChirho::FundingPopulationBoundExceededChirho);
            }
        }
    }
    Ok(count_chirho)
}

fn with_budget_write_locks_chirho<T>(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    root_scope_chirho: &BudgetRootScopeChirho,
    action_chirho: impl FnOnce() -> Result<T, BudgetStoreRefusalChirho>,
) -> Result<T, BudgetStoreRefusalChirho> {
    let authority_lock_chirho = format!(
        "{BUDGET_AUTHORITY_LOCK_PREFIX_CHIRHO}-{}",
        root_storage_key_chirho(root_scope_chirho)
    );
    cairn_seqlog_chirho::seqlog_chirho::with_named_lock_chirho(
        evidence_root_chirho,
        BUDGET_ROOT_WRITE_LOCK_CHIRHO,
        || {
            let result_chirho = cairn_seqlog_chirho::seqlog_chirho::with_named_lock_chirho(
                authority_root_chirho,
                &authority_lock_chirho,
                || Ok(action_chirho()),
            )?;
            Ok(result_chirho)
        },
    )
    .map_err(|_error_chirho| BudgetStoreRefusalChirho::StoreUnavailableChirho)?
}

/// Publish one immutable signed scalar funding record and initialize the root checkpoint if needed.
/// See the budget admission and repair workflow named in this module's header.
pub fn publish_verified_budget_funding_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    record_chirho: &BudgetFundingAttestationChirho,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<(), BudgetStoreRefusalChirho> {
    validate_custody_roots_chirho(evidence_root_chirho, authority_root_chirho)?;
    let root_scope_chirho = derive_root_scope_chirho(evidence_root_chirho)?;
    let scope_chirho = BudgetEvidenceScopeChirho {
        evidence_root_key_id_chirho: root_scope_chirho.evidence_root_key_id_chirho.clone(),
        tenant_id_chirho: root_scope_chirho.tenant_id_chirho.clone(),
        budget_id_chirho: record_chirho.intent_chirho.budget_id_chirho.clone(),
    };
    verify_budget_funding_chirho(record_chirho, authority_chirho, &scope_chirho)
        .map_err(classify_funding_verification_refusal_chirho)?;
    with_budget_write_locks_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        &root_scope_chirho,
        || {
            let log_bytes_chirho = read_log_bytes_chirho(evidence_root_chirho)?;
            match read_checkpoint_chirho(authority_root_chirho, &root_scope_chirho) {
                Ok(checkpoint_chirho) => {
                    ensure_checkpoint_authority_chirho(&checkpoint_chirho, authority_chirho)?;
                }
                Err(BudgetStoreRefusalChirho::CheckpointNotFoundChirho)
                    if log_bytes_chirho.is_empty() =>
                {
                    create_genesis_checkpoint_chirho(
                        authority_root_chirho,
                        &root_scope_chirho,
                        &record_chirho.authority_key_id_chirho,
                    )?;
                }
                Err(BudgetStoreRefusalChirho::CheckpointNotFoundChirho) => {
                    return Err(BudgetStoreRefusalChirho::LegacyLogRequiresRegenesisChirho);
                }
                Err(refusal_chirho) => return Err(refusal_chirho),
            }
            let path_chirho = funding_path_chirho(authority_root_chirho, &scope_chirho);
            let bytes_chirho = serde_json::to_vec(record_chirho).map_err(|_error_chirho| {
                BudgetStoreRefusalChirho::FundingMalformedChirho {
                    refusal_chirho: BudgetFundingRefusalChirho::RecordSchemaMismatchChirho {
                        found_chirho: "unencodable-chirho".to_string(),
                    },
                }
            })?;
            if path_chirho.exists() {
                let existing_chirho =
                    cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
                        &path_chirho,
                        BUDGET_FUNDING_RECORD_MAX_BYTES_CHIRHO,
                    )
                    .map_err(|_error_chirho| {
                        BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho
                    })?;
                return if existing_chirho == bytes_chirho {
                    Ok(())
                } else {
                    Err(BudgetStoreRefusalChirho::FundingImmutableConflictChirho {
                        budget_id_chirho: scope_chirho.budget_id_chirho.clone(),
                    })
                };
            }
            if funding_record_count_chirho(&funding_root_dir_chirho(
                authority_root_chirho,
                &root_scope_chirho,
            ))? >= BUDGET_FUNDING_MAX_RECORDS_PER_ROOT_CHIRHO
            {
                return Err(BudgetStoreRefusalChirho::FundingPopulationBoundExceededChirho);
            }
            match cairn_durable_chirho::create_complete_file_durable_with_mode_chirho(
                &path_chirho,
                &bytes_chirho,
                0o600,
            )
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::AuthorityRootUnavailableChirho)?
            {
                CreateFileDurableOutcomeChirho::CreatedChirho => Ok(()),
                CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
                    Err(BudgetStoreRefusalChirho::FundingImmutableConflictChirho {
                        budget_id_chirho: scope_chirho.budget_id_chirho.clone(),
                    })
                }
            }
        },
    )
}

fn repair_checkpoint_ahead_unlocked_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
    root_scope_chirho: &BudgetRootScopeChirho,
) -> Result<BudgetRepairOutcomeChirho, BudgetStoreRefusalChirho> {
    let checkpoint_chirho = read_checkpoint_chirho(authority_root_chirho, root_scope_chirho)?;
    ensure_checkpoint_authority_chirho(&checkpoint_chirho, authority_chirho)?;
    let raw_chirho = read_log_bytes_chirho(evidence_root_chirho)?;
    if !raw_chirho.is_empty() && !raw_chirho.ends_with(b"\n") {
        let last_lf_chirho = raw_chirho
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n');
        let split_chirho = last_lf_chirho.map_or(0, |index_chirho| index_chirho + 1);
        let clean_chirho = &raw_chirho[..split_chirho];
        let torn_chirho = &raw_chirho[split_chirho..];
        let clean_text_chirho = complete_log_text_chirho(clean_chirho)?;
        let clean_log_chirho = load_verified_log_from_text_chirho(
            clean_text_chirho,
            authority_root_chirho,
            authority_chirho,
            root_scope_chirho,
        )?;
        let line_chirho = verified_checkpoint_tail_line_for_recovery_chirho(
            clean_text_chirho,
            &clean_log_chirho,
            authority_root_chirho,
            authority_chirho,
            root_scope_chirho,
            &checkpoint_chirho,
        )?;
        let mut expected_suffix_chirho = line_chirho.as_bytes().to_vec();
        expected_suffix_chirho.push(b'\n');
        if !expected_suffix_chirho.starts_with(torn_chirho) {
            return Err(BudgetStoreRefusalChirho::TornTailDoesNotMatchCheckpointChirho);
        }
        let mut repaired_chirho = clean_chirho.to_vec();
        repaired_chirho.extend_from_slice(&expected_suffix_chirho);
        if repaired_chirho.len() as u64 > BUDGET_EVENT_LOG_MAX_BYTES_CHIRHO {
            return Err(BudgetStoreRefusalChirho::BoundExceededChirho);
        }
        cairn_durable_chirho::write_file_durable_chirho(
            &log_path_chirho(evidence_root_chirho),
            &repaired_chirho,
        )
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::StoreUnavailableChirho)?;
        return Ok(
            BudgetRepairOutcomeChirho::RecoveredAbandonedCheckpointChirho {
                chain_seq_chirho: checkpoint_chirho.record_count_chirho - 1,
            },
        );
    }
    let log_chirho = load_verified_log_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        authority_chirho,
        root_scope_chirho,
    )?;
    match ensure_log_matches_checkpoint_chirho(&log_chirho, &checkpoint_chirho) {
        Ok(()) => Ok(BudgetRepairOutcomeChirho::AlreadySynchronizedAfterWaitChirho),
        Err(BudgetStoreRefusalChirho::CheckpointAheadOrAppendInFlightChirho { .. }) => {
            let text_chirho = complete_log_text_chirho(&raw_chirho)?;
            let line_chirho = verified_checkpoint_tail_line_for_recovery_chirho(
                text_chirho,
                &log_chirho,
                authority_root_chirho,
                authority_chirho,
                root_scope_chirho,
                &checkpoint_chirho,
            )?;
            let required_chirho = raw_chirho.len().saturating_add(line_chirho.len() + 1);
            if required_chirho as u64 > BUDGET_EVENT_LOG_MAX_BYTES_CHIRHO {
                return Err(BudgetStoreRefusalChirho::BoundExceededChirho);
            }
            let mut bytes_chirho = line_chirho.as_bytes().to_vec();
            bytes_chirho.push(b'\n');
            cairn_durable_chirho::append_durable_line_chirho(
                &log_path_chirho(evidence_root_chirho),
                &bytes_chirho,
            )
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::StoreUnavailableChirho)?;
            Ok(
                BudgetRepairOutcomeChirho::RecoveredAbandonedCheckpointChirho {
                    chain_seq_chirho: checkpoint_chirho.record_count_chirho - 1,
                },
            )
        }
        Err(refusal_chirho) => Err(refusal_chirho),
    }
}

/// Explicit WRITE-authority recovery. It blocks on the root lock and re-reads inside the critical
/// section; a report or verify caller cannot invoke this as a read option.
/// See the budget admission and repair workflow named in this module's header.
pub fn repair_budget_log_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<BudgetRepairOutcomeChirho, BudgetStoreRefusalChirho> {
    validate_custody_roots_chirho(evidence_root_chirho, authority_root_chirho)?;
    let root_scope_chirho = derive_root_scope_chirho(evidence_root_chirho)?;
    with_budget_write_locks_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        &root_scope_chirho,
        || {
            repair_checkpoint_ahead_unlocked_chirho(
                evidence_root_chirho,
                authority_root_chirho,
                authority_chirho,
                &root_scope_chirho,
            )
        },
    )
}

fn verified_state_for_read_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<(BudgetRootScopeChirho, VerifiedBudgetLogChirho), BudgetStoreRefusalChirho> {
    validate_custody_roots_chirho(evidence_root_chirho, authority_root_chirho)?;
    let root_scope_chirho = derive_root_scope_chirho(evidence_root_chirho)?;
    let checkpoint_chirho = read_checkpoint_chirho(authority_root_chirho, &root_scope_chirho)?;
    ensure_checkpoint_authority_chirho(&checkpoint_chirho, authority_chirho)?;
    let log_chirho = load_verified_log_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        authority_chirho,
        &root_scope_chirho,
    )?;
    ensure_log_matches_checkpoint_chirho(&log_chirho, &checkpoint_chirho)?;
    Ok((root_scope_chirho, log_chirho))
}

fn events_for_budget_chirho<'a>(
    log_chirho: &'a VerifiedBudgetLogChirho,
    budget_id_chirho: &str,
) -> Vec<&'a VerifiedBudgetEventChirho> {
    let mut events_chirho = log_chirho
        .events_chirho
        .iter()
        .filter(|event_chirho| event_chirho.budget_id_chirho() == budget_id_chirho)
        .collect::<Vec<_>>();
    events_chirho.sort_by_key(|event_chirho| event_chirho.event_seq_chirho());
    events_chirho
}

pub fn highest_recorded_event_seq_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    budget_id_chirho: &str,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<Option<u64>, BudgetStoreRefusalChirho> {
    let (_scope_chirho, log_chirho) = verified_state_for_read_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        authority_chirho,
    )?;
    Ok(events_for_budget_chirho(&log_chirho, budget_id_chirho)
        .last()
        .map(|event_chirho| event_chirho.event_seq_chirho()))
}

fn apply_event_chirho(
    budget_chirho: &mut InfrastructureBudgetChirho,
    event_chirho: &VerifiedBudgetEventChirho,
) -> Result<(), BudgetRefusalChirho> {
    match event_chirho.kind_chirho() {
        BudgetEventKindChirho::ReserveChirho {
            requested_micros_chirho,
            deadline_millis_chirho,
        } => budget_chirho.reserve_chirho(
            event_chirho.reservation_id_chirho(),
            requested_micros_chirho,
            deadline_millis_chirho,
        ),
        BudgetEventKindChirho::SettleChirho {
            settled_micros_chirho,
        } => budget_chirho
            .settle_chirho(event_chirho.reservation_id_chirho(), settled_micros_chirho)
            .map(|_outcome_chirho| ()),
        BudgetEventKindChirho::ReleaseChirho => budget_chirho
            .release_chirho(event_chirho.reservation_id_chirho())
            .map(|_outcome_chirho| ()),
    }
}

fn fold_budget_chirho(
    log_chirho: &VerifiedBudgetLogChirho,
    budget_id_chirho: &str,
    ceiling_chirho: u64,
) -> Result<InfrastructureBudgetChirho, BudgetStoreRefusalChirho> {
    let mut budget_chirho = InfrastructureBudgetChirho::new_chirho(ceiling_chirho);
    for event_chirho in events_for_budget_chirho(log_chirho, budget_id_chirho) {
        apply_event_chirho(&mut budget_chirho, event_chirho)
            .map_err(|refusal_chirho| BudgetStoreRefusalChirho::RuleChirho { refusal_chirho })?;
    }
    if !budget_chirho.conservation_holds_chirho() {
        return Err(BudgetStoreRefusalChirho::ConservationViolatedChirho);
    }
    Ok(budget_chirho)
}

pub fn replay_budget_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    budget_id_chirho: &str,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<InfrastructureBudgetChirho, BudgetStoreRefusalChirho> {
    let (root_scope_chirho, log_chirho) = verified_state_for_read_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        authority_chirho,
    )?;
    let scope_chirho = BudgetEvidenceScopeChirho {
        evidence_root_key_id_chirho: root_scope_chirho.evidence_root_key_id_chirho,
        tenant_id_chirho: root_scope_chirho.tenant_id_chirho,
        budget_id_chirho: budget_id_chirho.to_string(),
    };
    let funding_chirho =
        load_verified_funding_chirho(authority_root_chirho, &scope_chirho, authority_chirho)?;
    fold_budget_chirho(
        &log_chirho,
        budget_id_chirho,
        funding_chirho.prepaid_ceiling_micros_chirho(),
    )
}

fn advance_checkpoint_chirho(
    authority_root_chirho: &Path,
    root_scope_chirho: &BudgetRootScopeChirho,
    expected_chirho: &BudgetLogCheckpointChirho,
    next_chirho: &BudgetLogCheckpointChirho,
) -> Result<(), BudgetStoreRefusalChirho> {
    let current_chirho = read_checkpoint_chirho(authority_root_chirho, root_scope_chirho)?;
    if current_chirho != *expected_chirho {
        return Err(BudgetStoreRefusalChirho::CheckpointAdvanceConflictChirho);
    }
    write_checkpoint_chirho(authority_root_chirho, root_scope_chirho, next_chirho)
}

/// Verify, replay, check, checkpoint, and append as one root-wide serialized operation.
/// See the budget admission and repair workflow named in this module's header.
pub fn append_verified_budget_event_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    record_chirho: &BudgetEventAttestationChirho,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<(), BudgetStoreRefusalChirho> {
    validate_custody_roots_chirho(evidence_root_chirho, authority_root_chirho)?;
    let root_scope_chirho = derive_root_scope_chirho(evidence_root_chirho)?;
    with_budget_write_locks_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        &root_scope_chirho,
        || {
            repair_checkpoint_ahead_unlocked_chirho(
                evidence_root_chirho,
                authority_root_chirho,
                authority_chirho,
                &root_scope_chirho,
            )?;
            let log_chirho = load_verified_log_chirho(
                evidence_root_chirho,
                authority_root_chirho,
                authority_chirho,
                &root_scope_chirho,
            )?;
            let checkpoint_chirho =
                read_checkpoint_chirho(authority_root_chirho, &root_scope_chirho)?;
            ensure_checkpoint_authority_chirho(&checkpoint_chirho, authority_chirho)?;
            ensure_log_matches_checkpoint_chirho(&log_chirho, &checkpoint_chirho)?;
            let authenticated_chirho =
                authenticate_budget_event_chirho(record_chirho, authority_chirho)
                    .map_err(classify_event_verification_refusal_chirho)?;
            let budget_id_chirho = authenticated_chirho.budget_id_chirho().to_string();
            let scope_chirho = BudgetEvidenceScopeChirho {
                evidence_root_key_id_chirho: root_scope_chirho.evidence_root_key_id_chirho.clone(),
                tenant_id_chirho: root_scope_chirho.tenant_id_chirho.clone(),
                budget_id_chirho: budget_id_chirho.clone(),
            };
            let funding_chirho = load_verified_funding_chirho(
                authority_root_chirho,
                &scope_chirho,
                authority_chirho,
            )?;
            let verified_chirho = bind_authenticated_budget_event_chirho(
                authenticated_chirho,
                &scope_chirho,
                funding_chirho.record_digest_chirho(),
            )
            .map_err(classify_event_verification_refusal_chirho)?;
            if let Some(highest_chirho) = events_for_budget_chirho(&log_chirho, &budget_id_chirho)
                .last()
                .map(|event_chirho| event_chirho.event_seq_chirho())
            {
                if verified_chirho.event_seq_chirho() <= highest_chirho {
                    return Err(BudgetStoreRefusalChirho::ReplayedEventSeqChirho {
                        budget_id_chirho,
                        highest_recorded_chirho: highest_chirho,
                        offered_chirho: verified_chirho.event_seq_chirho(),
                    });
                }
            }
            let mut budget_chirho = fold_budget_chirho(
                &log_chirho,
                &scope_chirho.budget_id_chirho,
                funding_chirho.prepaid_ceiling_micros_chirho(),
            )?;
            apply_event_chirho(&mut budget_chirho, &verified_chirho).map_err(|refusal_chirho| {
                BudgetStoreRefusalChirho::RuleChirho { refusal_chirho }
            })?;

            let stored_chirho =
                put_object_chirho(evidence_root_chirho, &record_chirho.intent_chirho)
                    .map_err(|_error_chirho| BudgetStoreRefusalChirho::IntentNotStoredChirho)?;
            if stored_chirho.0 != record_chirho.intent_digest_chirho {
                return Err(
                    BudgetStoreRefusalChirho::IntentDigestNotItsCasAddressChirho {
                        declared_chirho: record_chirho.intent_digest_chirho.clone(),
                        stored_at_chirho: stored_chirho.0,
                    },
                );
            }
            let wrapper_chirho = BudgetEventLineChirho {
                schema_chirho: BUDGET_EVENT_LINE_SCHEMA_V1_CHIRHO.to_string(),
                chain_seq_chirho: log_chirho.record_count_chirho,
                previous_line_digest_chirho: log_chirho.tail_digest_chirho.clone(),
                record_chirho: record_chirho.clone(),
            };
            let line_chirho = serde_json::to_string(&wrapper_chirho)
                .map_err(|_error_chirho| BudgetStoreRefusalChirho::StoreUnavailableChirho)?;
            if line_chirho.len() > BUDGET_EVENT_LINE_MAX_BYTES_CHIRHO {
                return Err(BudgetStoreRefusalChirho::BoundExceededChirho);
            }
            let current_bytes_chirho = read_log_bytes_chirho(evidence_root_chirho)?;
            if current_bytes_chirho
                .len()
                .saturating_add(line_chirho.len() + 1) as u64
                > BUDGET_EVENT_LOG_MAX_BYTES_CHIRHO
            {
                return Err(BudgetStoreRefusalChirho::BoundExceededChirho);
            }
            let next_checkpoint_chirho = BudgetLogCheckpointChirho {
                schema_chirho: BUDGET_LOG_CHECKPOINT_SCHEMA_V1_CHIRHO.to_string(),
                evidence_root_key_id_chirho: root_scope_chirho.evidence_root_key_id_chirho.clone(),
                tenant_id_chirho: root_scope_chirho.tenant_id_chirho.clone(),
                authority_key_id_chirho: checkpoint_chirho.authority_key_id_chirho.clone(),
                record_count_chirho: log_chirho.record_count_chirho + 1,
                tail_digest_chirho: stored_line_digest_hex_chirho(&line_chirho),
                tail_line_chirho: Some(line_chirho.clone()),
            };
            advance_checkpoint_chirho(
                authority_root_chirho,
                &root_scope_chirho,
                &checkpoint_chirho,
                &next_checkpoint_chirho,
            )?;
            let mut line_bytes_chirho = line_chirho.into_bytes();
            line_bytes_chirho.push(b'\n');
            cairn_durable_chirho::append_durable_line_chirho(
                &log_path_chirho(evidence_root_chirho),
                &line_bytes_chirho,
            )
            .map_err(|_error_chirho| BudgetStoreRefusalChirho::StoreUnavailableChirho)
        },
    )
}

pub fn reservations_awaiting_release_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    budget_id_chirho: &str,
    now_millis_chirho: u64,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<Vec<String>, BudgetStoreRefusalChirho> {
    let mut budget_chirho = replay_budget_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        budget_id_chirho,
        authority_chirho,
    )?;
    Ok(budget_chirho.release_expired_chirho(now_millis_chirho))
}

pub fn build_budget_report_chirho(
    evidence_root_chirho: &Path,
    authority_root_chirho: &Path,
    budget_id_chirho: &str,
    now_millis_chirho: u64,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<BudgetReportChirho, BudgetStoreRefusalChirho> {
    let (root_scope_chirho, log_chirho) = verified_state_for_read_chirho(
        evidence_root_chirho,
        authority_root_chirho,
        authority_chirho,
    )?;
    let scope_chirho = BudgetEvidenceScopeChirho {
        evidence_root_key_id_chirho: root_scope_chirho.evidence_root_key_id_chirho,
        tenant_id_chirho: root_scope_chirho.tenant_id_chirho,
        budget_id_chirho: budget_id_chirho.to_string(),
    };
    let funding_chirho =
        load_verified_funding_chirho(authority_root_chirho, &scope_chirho, authority_chirho)?;
    let budget_chirho = fold_budget_chirho(
        &log_chirho,
        budget_id_chirho,
        funding_chirho.prepaid_ceiling_micros_chirho(),
    )?;
    let mut probe_chirho = budget_chirho.clone();
    let awaiting_chirho = probe_chirho.release_expired_chirho(now_millis_chirho);
    Ok(BudgetReportChirho {
        schema_chirho: BUDGET_REPORT_SCHEMA_V2_CHIRHO.to_string(),
        budget_id_chirho: budget_id_chirho.to_string(),
        prepaid_ceiling_micros_chirho: funding_chirho.prepaid_ceiling_micros_chirho(),
        ceiling_provenance_chirho: BudgetCeilingProvenanceChirho::AuthenticatedFundingChirho {
            funding_record_digest_chirho: funding_chirho.record_digest_chirho().to_string(),
            authority_key_id_chirho: funding_chirho.authority_key_id_chirho().to_string(),
        },
        settled_micros_chirho: budget_chirho.settled_micros_chirho(),
        outstanding_micros_chirho: budget_chirho.outstanding_micros_chirho(),
        available_micros_chirho: budget_chirho.available_micros_chirho(),
        conservation_holds_chirho: budget_chirho.conservation_holds_chirho(),
        awaiting_release_chirho: awaiting_chirho,
    })
}

pub fn render_budget_report_chirho(
    report_chirho: &BudgetReportChirho,
) -> Result<String, BudgetStoreRefusalChirho> {
    serde_json::to_string(report_chirho)
        .map_err(|_error_chirho| BudgetStoreRefusalChirho::StoreUnavailableChirho)
}

#[cfg(test)]
#[path = "budget_event_store_tests_chirho.rs"]
mod budget_event_store_tests_chirho;
