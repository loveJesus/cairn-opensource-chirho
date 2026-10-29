// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Narrow dependency-inverted ports for private evidence and serializable database transactions.

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveBytesChirho(Vec<u8>);

impl SensitiveBytesChirho {
    pub fn new_chirho(bytes_chirho: Vec<u8>) -> Self {
        Self(bytes_chirho)
    }

    pub fn as_slice_chirho(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveBytesChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str("SensitiveBytesChirho([REDACTED])")
    }
}

impl Drop for SensitiveBytesChirho {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateEvidencePortErrorChirho {
    SubjectMismatchChirho,
    UnavailableChirho { detail_chirho: String },
}

impl std::fmt::Display for PrivateEvidencePortErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubjectMismatchChirho => {
                formatter_chirho.write_str("private evidence subject mismatch")
            }
            Self::UnavailableChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "private evidence unavailable: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for PrivateEvidencePortErrorChirho {}

/// Root-owned private storage implements this port; the leaf never reads a Cairn root directly.
pub trait PostgresPrivateEvidencePortChirho {
    fn load_subject_blob_chirho(
        &self,
        subject_chirho: &HashChirho,
        blob_ref_chirho: &PrivateBlobRefChirho,
    ) -> Result<SensitiveBytesChirho, PrivateEvidencePortErrorChirho>;

    fn store_subject_blob_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> Result<PrivateBlobRefChirho, PrivateEvidencePortErrorChirho>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DatabasePortErrorChirho {
    RetryableConflictChirho { detail_chirho: String },
    PermanentChirho { detail_chirho: String },
}

impl std::fmt::Display for DatabasePortErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RetryableConflictChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "retryable database conflict: {detail_chirho}"
                )
            }
            Self::PermanentChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "database operation failed: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for DatabasePortErrorChirho {}

#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseValueChirho {
    pub value_chirho: SensitiveBytesChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostgresForwardDecisionKindChirho {
    CommittedChirho,
    DefiniteNoEffectChirho,
}

/// One database-enforced terminal decision for an exact signed-intent K. The decision bytes carry
/// their own canonical authentication; the kind is only the indexed dispatch label and is checked
/// against the parsed body before either door trusts it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedForwardDecisionRowChirho {
    pub effect_idem_key_chirho: HashChirho,
    pub decision_kind_chirho: PostgresForwardDecisionKindChirho,
    pub decision_bytes_chirho: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedCompensationReceiptRowChirho {
    pub original_effect_idem_key_chirho: HashChirho,
    pub receipt_bytes_chirho: Vec<u8>,
    pub receipt_mac_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOriginalPostgresEffectChirho {
    pub original_effect_idem_key_chirho: HashChirho,
    pub request_bytes_chirho: Vec<u8>,
    pub forward_receipt_bytes_chirho: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginalEffectEvidenceErrorChirho {
    MissingChirho,
    InvalidChirho { detail_chirho: String },
    UnavailableChirho { detail_chirho: String },
}

impl std::fmt::Display for OriginalEffectEvidenceErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingChirho => {
                formatter_chirho.write_str("verified original PostgreSQL effect is missing")
            }
            Self::InvalidChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "verified original PostgreSQL effect is invalid: {detail_chirho}"
                )
            }
            Self::UnavailableChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "original-effect evidence unavailable: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for OriginalEffectEvidenceErrorChirho {}

/// Root verifies the signed append-only effect before returning this evidence to the leaf.
pub trait PostgresOriginalEffectEvidencePortChirho {
    fn load_verified_original_effect_chirho(
        &self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<VerifiedOriginalPostgresEffectChirho, OriginalEffectEvidenceErrorChirho>;
}

/// One active SERIALIZABLE transaction. Dropping without `commit_chirho` rolls it back.
pub trait ReversiblePostgresTransactionPortChirho: Sized {
    fn lock_forward_idempotency_key_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
    ) -> Result<(), DatabasePortErrorChirho>;

    fn lock_compensation_idempotency_key_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho>;

    fn lock_original_effect_compensation_chirho(
        &mut self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho>;

    fn lock_row_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho>;

    fn load_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho>;

    fn load_forward_decision_by_idem_key_chirho(
        &mut self,
        effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho>;

    fn load_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho>;

    fn load_compensation_receipt_by_original_effect_chirho(
        &mut self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho>;

    fn load_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<Option<DatabaseValueChirho>, DatabasePortErrorChirho>;

    fn upsert_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
        value_chirho: &[u8],
    ) -> Result<(), DatabasePortErrorChirho>;

    fn delete_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho>;

    fn insert_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
        row_chirho: &AuthenticatedForwardDecisionRowChirho,
    ) -> Result<(), DatabasePortErrorChirho>;

    fn insert_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
        row_chirho: &AuthenticatedCompensationReceiptRowChirho,
    ) -> Result<(), DatabasePortErrorChirho>;

    fn commit_chirho(self) -> Result<(), DatabasePortErrorChirho>;
}

pub trait ReversiblePostgresDatabasePortChirho {
    type TransactionChirho<'a>: ReversiblePostgresTransactionPortChirho
    where
        Self: 'a;

    /// Verifies the operator-installed schema, including the database-enforced one-decision floor.
    /// This is a read-only bootstrap preflight; implementations must never install or amend schema.
    fn verify_schema_ready_chirho(&mut self) -> Result<(), DatabasePortErrorChirho>;

    fn begin_serializable_transaction_chirho(
        &mut self,
    ) -> Result<Self::TransactionChirho<'_>, DatabasePortErrorChirho>;
}
