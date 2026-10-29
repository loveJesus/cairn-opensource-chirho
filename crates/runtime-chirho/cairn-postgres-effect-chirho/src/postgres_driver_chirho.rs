// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Synchronous PostgreSQL driver for the dormant reversible-effect transaction law.

use crate::ports_chirho::{
    AuthenticatedCompensationReceiptRowChirho, AuthenticatedForwardDecisionRowChirho,
    DatabasePortErrorChirho, DatabaseValueChirho, PostgresForwardDecisionKindChirho,
    ReversiblePostgresDatabasePortChirho, ReversiblePostgresTransactionPortChirho,
    SensitiveBytesChirho,
};
use cairn_core_chirho::model_chirho::HashChirho;
use postgres::error::SqlState;
use postgres::{Client, IsolationLevel, Transaction};

pub(crate) const INSTALL_SCHEMA_SQL_CHIRHO: &str = r#"
CREATE TABLE IF NOT EXISTS cairn_reversible_values_chirho (
    subject_chirho TEXT NOT NULL,
    row_key_chirho TEXT NOT NULL,
    value_chirho BYTEA NOT NULL,
    CONSTRAINT reversible_values_pk_chirho PRIMARY KEY (subject_chirho, row_key_chirho),
    CONSTRAINT reversible_values_subject_ck_chirho
        CHECK (subject_chirho ~ '^[0-9a-f]{64}$'),
    CONSTRAINT reversible_values_row_key_ck_chirho
        CHECK (row_key_chirho ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS cairn_reversible_forward_decisions_chirho (
    effect_intent_key_chirho TEXT NOT NULL,
    effect_idem_key_chirho TEXT NOT NULL,
    decision_kind_chirho TEXT NOT NULL,
    decision_bytes_chirho BYTEA NOT NULL,
    CONSTRAINT reversible_forward_decisions_pk_chirho PRIMARY KEY (effect_intent_key_chirho),
    CONSTRAINT reversible_forward_decisions_idem_uq_chirho UNIQUE (effect_idem_key_chirho),
    CONSTRAINT reversible_forward_intent_key_ck_chirho
        CHECK (effect_intent_key_chirho ~ '^cf3-intent-v1-chirho:[0-9a-f]{64}$'),
    CONSTRAINT reversible_forward_idem_key_ck_chirho
        CHECK (effect_idem_key_chirho ~ '^[0-9a-f]{64}$'),
    CONSTRAINT reversible_forward_decision_kind_ck_chirho
        CHECK (decision_kind_chirho IN ('committed-chirho', 'definite-no-effect-chirho'))
);

CREATE TABLE IF NOT EXISTS cairn_reversible_comp_receipts_chirho (
    compensation_idem_key_chirho TEXT NOT NULL,
    original_effect_idem_key_chirho TEXT NOT NULL,
    receipt_bytes_chirho BYTEA NOT NULL,
    receipt_mac_chirho TEXT NOT NULL,
    CONSTRAINT reversible_comp_receipts_pk_chirho PRIMARY KEY (compensation_idem_key_chirho),
    CONSTRAINT reversible_comp_original_uq_chirho UNIQUE (original_effect_idem_key_chirho),
    CONSTRAINT reversible_comp_key_ck_chirho
        CHECK (compensation_idem_key_chirho ~ '^[0-9a-f]{64}$'),
    CONSTRAINT reversible_comp_original_ck_chirho
        CHECK (original_effect_idem_key_chirho ~ '^[0-9a-f]{64}$'),
    CONSTRAINT reversible_comp_mac_ck_chirho
        CHECK (receipt_mac_chirho ~ '^[0-9a-f]{64}$')
);
"#;

const LOAD_FORWARD_DECISION_SQL_CHIRHO: &str = r#"
SELECT effect_idem_key_chirho, decision_kind_chirho, decision_bytes_chirho
FROM cairn_reversible_forward_decisions_chirho
WHERE effect_intent_key_chirho = $1
"#;

const LOAD_FORWARD_DECISION_BY_IDEM_SQL_CHIRHO: &str = r#"
SELECT effect_idem_key_chirho, decision_kind_chirho, decision_bytes_chirho
FROM cairn_reversible_forward_decisions_chirho
WHERE effect_idem_key_chirho = $1
"#;

const LOAD_COMPENSATION_SQL_CHIRHO: &str = r#"
SELECT original_effect_idem_key_chirho, receipt_bytes_chirho, receipt_mac_chirho
FROM cairn_reversible_comp_receipts_chirho
WHERE compensation_idem_key_chirho = $1
"#;

const LOAD_COMPENSATION_BY_ORIGINAL_SQL_CHIRHO: &str = r#"
SELECT original_effect_idem_key_chirho, receipt_bytes_chirho, receipt_mac_chirho
FROM cairn_reversible_comp_receipts_chirho
WHERE original_effect_idem_key_chirho = $1
"#;

const LOAD_VALUE_SQL_CHIRHO: &str = r#"
SELECT value_chirho
FROM cairn_reversible_values_chirho
WHERE subject_chirho = $1 AND row_key_chirho = $2
FOR UPDATE
"#;

const UPSERT_VALUE_SQL_CHIRHO: &str = r#"
INSERT INTO cairn_reversible_values_chirho (subject_chirho, row_key_chirho, value_chirho)
VALUES ($1, $2, $3)
ON CONFLICT (subject_chirho, row_key_chirho)
DO UPDATE SET value_chirho = EXCLUDED.value_chirho
"#;

const DELETE_VALUE_SQL_CHIRHO: &str = r#"
DELETE FROM cairn_reversible_values_chirho
WHERE subject_chirho = $1 AND row_key_chirho = $2
"#;

const INSERT_FORWARD_DECISION_SQL_CHIRHO: &str = r#"
INSERT INTO cairn_reversible_forward_decisions_chirho (
    effect_intent_key_chirho,
    effect_idem_key_chirho,
    decision_kind_chirho,
    decision_bytes_chirho
)
VALUES ($1, $2, $3, $4)
"#;

const INSERT_COMPENSATION_SQL_CHIRHO: &str = r#"
INSERT INTO cairn_reversible_comp_receipts_chirho (
    compensation_idem_key_chirho,
    original_effect_idem_key_chirho,
    receipt_bytes_chirho,
    receipt_mac_chirho
)
VALUES ($1, $2, $3, $4)
"#;

const ADVISORY_LOCK_SQL_CHIRHO: &str = "SELECT pg_advisory_xact_lock($1)";
const VERIFY_SCHEMA_COLUMNS_SQL_CHIRHO: &str = r#"
SELECT subject_chirho, row_key_chirho, value_chirho
FROM cairn_reversible_values_chirho LIMIT 0;
SELECT effect_intent_key_chirho, effect_idem_key_chirho, decision_kind_chirho,
       decision_bytes_chirho
FROM cairn_reversible_forward_decisions_chirho LIMIT 0;
SELECT compensation_idem_key_chirho, original_effect_idem_key_chirho,
       receipt_bytes_chirho, receipt_mac_chirho
FROM cairn_reversible_comp_receipts_chirho LIMIT 0;
"#;
const VERIFY_DECISION_CONSTRAINTS_SQL_CHIRHO: &str = r#"
WITH decision_table_chirho AS (
    SELECT to_regclass('cairn_reversible_forward_decisions_chirho') AS oid_chirho
), intent_column_chirho AS (
    SELECT attnum AS attnum_chirho
    FROM pg_attribute, decision_table_chirho
    WHERE attrelid = oid_chirho
      AND attname = 'effect_intent_key_chirho'
      AND NOT attisdropped
), idem_column_chirho AS (
    SELECT attnum AS attnum_chirho
    FROM pg_attribute, decision_table_chirho
    WHERE attrelid = oid_chirho
      AND attname = 'effect_idem_key_chirho'
      AND NOT attisdropped
)
SELECT
    EXISTS (
        SELECT 1
        FROM pg_constraint, decision_table_chirho, intent_column_chirho
        WHERE conrelid = oid_chirho
          AND conname = 'reversible_forward_decisions_pk_chirho'
          AND contype = 'p'
          AND conkey = ARRAY[intent_column_chirho.attnum_chirho]::smallint[]
    )
    AND EXISTS (
        SELECT 1
        FROM pg_constraint, decision_table_chirho, idem_column_chirho
        WHERE conrelid = oid_chirho
          AND conname = 'reversible_forward_decisions_idem_uq_chirho'
          AND contype = 'u'
          AND conkey = ARRAY[idem_column_chirho.attnum_chirho]::smallint[]
    )
    AND EXISTS (
        SELECT 1
        FROM pg_constraint, decision_table_chirho
        WHERE conrelid = oid_chirho
          AND conname = 'reversible_forward_decision_kind_ck_chirho'
          AND contype = 'c'
          AND pg_get_expr(conbin, conrelid) =
              '(decision_kind_chirho = ANY (ARRAY[''committed-chirho''::text, ''definite-no-effect-chirho''::text]))'
    ) AS ready_chirho
"#;
const FORWARD_LOCK_DOMAIN_CHIRHO: &str = "cairn-reversible-postgres-forward-idem-v1-chirho";
const COMPENSATION_LOCK_DOMAIN_CHIRHO: &str =
    "cairn-reversible-postgres-compensation-idem-v1-chirho";
const ORIGINAL_LOCK_DOMAIN_CHIRHO: &str = "cairn-reversible-postgres-original-effect-v1-chirho";
const ROW_LOCK_DOMAIN_CHIRHO: &str = "cairn-reversible-postgres-row-v1-chirho";

/// Explicit operator/test setup. The effect path never installs or alters database schema.
pub fn install_reversible_postgres_schema_chirho(
    client_chirho: &mut Client,
) -> Result<(), DatabasePortErrorChirho> {
    client_chirho
        .batch_execute(INSTALL_SCHEMA_SQL_CHIRHO)
        .map_err(database_error_chirho)
}

/// An already-configured client keeps connection, TLS, and credential policy host-owned.
pub struct PostgresDatabaseChirho {
    client_chirho: Client,
}

impl PostgresDatabaseChirho {
    pub fn from_client_chirho(client_chirho: Client) -> Self {
        Self { client_chirho }
    }

    pub fn into_client_chirho(self) -> Client {
        self.client_chirho
    }
}

pub struct PostgresTransactionChirho<'client_chirho> {
    transaction_chirho: Transaction<'client_chirho>,
}

impl ReversiblePostgresDatabasePortChirho for PostgresDatabaseChirho {
    type TransactionChirho<'client_chirho>
        = PostgresTransactionChirho<'client_chirho>
    where
        Self: 'client_chirho;

    fn verify_schema_ready_chirho(&mut self) -> Result<(), DatabasePortErrorChirho> {
        self.client_chirho
            .batch_execute(VERIFY_SCHEMA_COLUMNS_SQL_CHIRHO)
            .map_err(database_error_chirho)?;
        let ready_chirho: bool = self
            .client_chirho
            .query_one(VERIFY_DECISION_CONSTRAINTS_SQL_CHIRHO, &[])
            .map_err(database_error_chirho)?
            .try_get("ready_chirho")
            .map_err(database_error_chirho)?;
        if !ready_chirho {
            return Err(DatabasePortErrorChirho::PermanentChirho {
                detail_chirho: "operator-installed reversible PostgreSQL schema lacks the decision constraint floor"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn begin_serializable_transaction_chirho(
        &mut self,
    ) -> Result<Self::TransactionChirho<'_>, DatabasePortErrorChirho> {
        let transaction_chirho = self
            .client_chirho
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error_chirho)?;
        Ok(PostgresTransactionChirho { transaction_chirho })
    }
}

impl ReversiblePostgresTransactionPortChirho for PostgresTransactionChirho<'_> {
    fn lock_forward_idempotency_key_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.lock_advisory_chirho(advisory_key_chirho(
            FORWARD_LOCK_DOMAIN_CHIRHO,
            &[effect_intent_key_chirho],
        ))
    }

    fn lock_compensation_idempotency_key_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.lock_advisory_chirho(advisory_key_chirho(
            COMPENSATION_LOCK_DOMAIN_CHIRHO,
            &[compensation_idem_key_chirho.0.as_str()],
        ))
    }

    fn lock_original_effect_compensation_chirho(
        &mut self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.lock_advisory_chirho(advisory_key_chirho(
            ORIGINAL_LOCK_DOMAIN_CHIRHO,
            &[original_effect_idem_key_chirho.0.as_str()],
        ))
    }

    fn lock_row_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.lock_advisory_chirho(advisory_key_chirho(
            ROW_LOCK_DOMAIN_CHIRHO,
            &[subject_chirho.0.as_str(), row_key_chirho.0.as_str()],
        ))
    }

    fn load_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho> {
        let row_chirho = self
            .transaction_chirho
            .query_opt(
                LOAD_FORWARD_DECISION_SQL_CHIRHO,
                &[&effect_intent_key_chirho],
            )
            .map_err(database_error_chirho)?;
        row_chirho.map(forward_decision_row_chirho).transpose()
    }

    fn load_forward_decision_by_idem_key_chirho(
        &mut self,
        effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho> {
        let row_chirho = self
            .transaction_chirho
            .query_opt(
                LOAD_FORWARD_DECISION_BY_IDEM_SQL_CHIRHO,
                &[&effect_idem_key_chirho.0],
            )
            .map_err(database_error_chirho)?;
        row_chirho.map(forward_decision_row_chirho).transpose()
    }

    fn load_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho> {
        let row_chirho = self
            .transaction_chirho
            .query_opt(
                LOAD_COMPENSATION_SQL_CHIRHO,
                &[&compensation_idem_key_chirho.0],
            )
            .map_err(database_error_chirho)?;
        row_chirho.map(compensation_row_chirho).transpose()
    }

    fn load_compensation_receipt_by_original_effect_chirho(
        &mut self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho> {
        let row_chirho = self
            .transaction_chirho
            .query_opt(
                LOAD_COMPENSATION_BY_ORIGINAL_SQL_CHIRHO,
                &[&original_effect_idem_key_chirho.0],
            )
            .map_err(database_error_chirho)?;
        row_chirho.map(compensation_row_chirho).transpose()
    }

    fn load_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<Option<DatabaseValueChirho>, DatabasePortErrorChirho> {
        let row_chirho = self
            .transaction_chirho
            .query_opt(
                LOAD_VALUE_SQL_CHIRHO,
                &[&subject_chirho.0, &row_key_chirho.0],
            )
            .map_err(database_error_chirho)?;
        row_chirho
            .map(|row_chirho| {
                let value_chirho = row_chirho
                    .try_get("value_chirho")
                    .map_err(database_error_chirho)?;
                Ok(DatabaseValueChirho {
                    value_chirho: SensitiveBytesChirho::new_chirho(value_chirho),
                })
            })
            .transpose()
    }

    fn upsert_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
        value_chirho: &[u8],
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .execute(
                UPSERT_VALUE_SQL_CHIRHO,
                &[&subject_chirho.0, &row_key_chirho.0, &value_chirho],
            )
            .map_err(database_error_chirho)?;
        Ok(())
    }

    fn delete_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .execute(
                DELETE_VALUE_SQL_CHIRHO,
                &[&subject_chirho.0, &row_key_chirho.0],
            )
            .map_err(database_error_chirho)?;
        Ok(())
    }

    fn insert_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
        row_chirho: &AuthenticatedForwardDecisionRowChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .execute(
                INSERT_FORWARD_DECISION_SQL_CHIRHO,
                &[
                    &effect_intent_key_chirho,
                    &row_chirho.effect_idem_key_chirho.0,
                    &forward_decision_kind_text_chirho(row_chirho.decision_kind_chirho),
                    &row_chirho.decision_bytes_chirho,
                ],
            )
            .map_err(database_error_chirho)?;
        Ok(())
    }

    fn insert_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
        row_chirho: &AuthenticatedCompensationReceiptRowChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .execute(
                INSERT_COMPENSATION_SQL_CHIRHO,
                &[
                    &compensation_idem_key_chirho.0,
                    &row_chirho.original_effect_idem_key_chirho.0,
                    &row_chirho.receipt_bytes_chirho,
                    &row_chirho.receipt_mac_chirho.0,
                ],
            )
            .map_err(database_error_chirho)?;
        Ok(())
    }

    fn commit_chirho(self) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .commit()
            .map_err(database_error_chirho)
    }
}

impl PostgresTransactionChirho<'_> {
    fn lock_advisory_chirho(
        &mut self,
        advisory_key_chirho: i64,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .query_one(ADVISORY_LOCK_SQL_CHIRHO, &[&advisory_key_chirho])
            .map_err(database_error_chirho)?;
        Ok(())
    }
}

fn compensation_row_chirho(
    row_chirho: postgres::Row,
) -> Result<AuthenticatedCompensationReceiptRowChirho, DatabasePortErrorChirho> {
    Ok(AuthenticatedCompensationReceiptRowChirho {
        original_effect_idem_key_chirho: HashChirho(
            row_chirho
                .try_get("original_effect_idem_key_chirho")
                .map_err(database_error_chirho)?,
        ),
        receipt_bytes_chirho: row_chirho
            .try_get("receipt_bytes_chirho")
            .map_err(database_error_chirho)?,
        receipt_mac_chirho: HashChirho(
            row_chirho
                .try_get("receipt_mac_chirho")
                .map_err(database_error_chirho)?,
        ),
    })
}

fn forward_decision_row_chirho(
    row_chirho: postgres::Row,
) -> Result<AuthenticatedForwardDecisionRowChirho, DatabasePortErrorChirho> {
    let decision_kind_chirho: String = row_chirho
        .try_get("decision_kind_chirho")
        .map_err(database_error_chirho)?;
    let decision_kind_chirho = match decision_kind_chirho.as_str() {
        "committed-chirho" => PostgresForwardDecisionKindChirho::CommittedChirho,
        "definite-no-effect-chirho" => PostgresForwardDecisionKindChirho::DefiniteNoEffectChirho,
        _ => {
            return Err(DatabasePortErrorChirho::PermanentChirho {
                detail_chirho: "stored forward decision has an unknown kind".to_string(),
            });
        }
    };
    Ok(AuthenticatedForwardDecisionRowChirho {
        effect_idem_key_chirho: HashChirho(
            row_chirho
                .try_get("effect_idem_key_chirho")
                .map_err(database_error_chirho)?,
        ),
        decision_kind_chirho,
        decision_bytes_chirho: row_chirho
            .try_get("decision_bytes_chirho")
            .map_err(database_error_chirho)?,
    })
}

fn forward_decision_kind_text_chirho(
    kind_chirho: PostgresForwardDecisionKindChirho,
) -> &'static str {
    match kind_chirho {
        PostgresForwardDecisionKindChirho::CommittedChirho => "committed-chirho",
        PostgresForwardDecisionKindChirho::DefiniteNoEffectChirho => "definite-no-effect-chirho",
    }
}

fn advisory_key_chirho(domain_chirho: &str, coordinates_chirho: &[&str]) -> i64 {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(&(domain_chirho.len() as u64).to_be_bytes());
    hasher_chirho.update(domain_chirho.as_bytes());
    for coordinate_chirho in coordinates_chirho {
        hasher_chirho.update(&(coordinate_chirho.len() as u64).to_be_bytes());
        hasher_chirho.update(coordinate_chirho.as_bytes());
    }
    let digest_chirho = hasher_chirho.finalize();
    let mut lock_bytes_chirho = [0_u8; 8];
    lock_bytes_chirho.copy_from_slice(&digest_chirho.as_bytes()[..8]);
    i64::from_be_bytes(lock_bytes_chirho)
}

fn database_error_chirho(error_chirho: postgres::Error) -> DatabasePortErrorChirho {
    let retryable_chirho = matches!(
        error_chirho.code(),
        Some(code_chirho)
            if *code_chirho == SqlState::T_R_SERIALIZATION_FAILURE
                || *code_chirho == SqlState::T_R_DEADLOCK_DETECTED
    );
    let detail_chirho = error_chirho.to_string();
    if retryable_chirho {
        DatabasePortErrorChirho::RetryableConflictChirho { detail_chirho }
    } else {
        DatabasePortErrorChirho::PermanentChirho { detail_chirho }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn hash_chirho(marker_chirho: char) -> HashChirho {
        HashChirho(marker_chirho.to_string().repeat(64))
    }

    #[test]
    fn advisory_lock_keys_bind_domain_and_coordinates_chirho() {
        let first_chirho = hash_chirho('a');
        let second_chirho = hash_chirho('b');
        assert_eq!(
            advisory_key_chirho(
                ROW_LOCK_DOMAIN_CHIRHO,
                &[first_chirho.0.as_str(), second_chirho.0.as_str()]
            ),
            advisory_key_chirho(
                ROW_LOCK_DOMAIN_CHIRHO,
                &[first_chirho.0.as_str(), second_chirho.0.as_str()]
            )
        );
        assert_ne!(
            advisory_key_chirho(
                ROW_LOCK_DOMAIN_CHIRHO,
                &[first_chirho.0.as_str(), second_chirho.0.as_str()]
            ),
            advisory_key_chirho(
                ROW_LOCK_DOMAIN_CHIRHO,
                &[second_chirho.0.as_str(), first_chirho.0.as_str()]
            )
        );
        assert_ne!(
            advisory_key_chirho(ROW_LOCK_DOMAIN_CHIRHO, &[first_chirho.0.as_str()]),
            advisory_key_chirho(FORWARD_LOCK_DOMAIN_CHIRHO, &[first_chirho.0.as_str()])
        );
    }
}
