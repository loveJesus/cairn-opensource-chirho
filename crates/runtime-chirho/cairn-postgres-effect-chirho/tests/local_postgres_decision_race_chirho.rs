// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
use cairn_postgres_effect_chirho::ports_chirho::{
    AuthenticatedCompensationReceiptRowChirho, AuthenticatedForwardDecisionRowChirho,
    DatabasePortErrorChirho, DatabaseValueChirho, PostgresPrivateEvidencePortChirho,
    PrivateEvidencePortErrorChirho, ReversiblePostgresDatabasePortChirho,
    ReversiblePostgresTransactionPortChirho, SensitiveBytesChirho,
};
use cairn_postgres_effect_chirho::{
    apply_reversible_postgres_chirho, canonical_request_bytes_chirho,
    install_reversible_postgres_schema_chirho, query_reversible_postgres_by_key_chirho,
    AdapterEvidenceKeyChirho, DesiredPostgresStateChirho, ExpectedPostgresStateChirho,
    PostgresDatabaseChirho, PostgresForwardQueryResultChirho, PostgresTransactionChirho,
    ReversiblePostgresEffectCoordinateChirho, ReversiblePostgresErrorChirho,
    ReversiblePostgresRequestChirho,
};
use postgres::{Client, NoTls};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

const REQUEST_SCHEMA_CHIRHO: &str = "reversible-postgres-request-v1-chirho";
const DEFAULT_TEST_CONFIG_CHIRHO: &str = "host=/tmp port=5432 dbname=postgres";

struct DisposableSchemaChirho {
    connection_config_chirho: String,
    schema_chirho: String,
}

impl Drop for DisposableSchemaChirho {
    fn drop(&mut self) {
        if let Ok(mut client_chirho) = connect_chirho(&self.connection_config_chirho) {
            let _ = client_chirho.batch_execute(&format!(
                "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
                self.schema_chirho
            ));
        }
    }
}

#[derive(Clone)]
struct ForwardLockGateChirho {
    before_lock_chirho: Option<Arc<Barrier>>,
    locked_chirho: Option<Arc<Barrier>>,
    release_chirho: Option<Arc<Barrier>>,
}

impl ForwardLockGateChirho {
    fn winner_chirho(locked_chirho: Arc<Barrier>, release_chirho: Arc<Barrier>) -> Self {
        Self {
            before_lock_chirho: None,
            locked_chirho: Some(locked_chirho),
            release_chirho: Some(release_chirho),
        }
    }

    fn contender_chirho(before_lock_chirho: Arc<Barrier>) -> Self {
        Self {
            before_lock_chirho: Some(before_lock_chirho),
            locked_chirho: None,
            release_chirho: None,
        }
    }
}

struct GatedPostgresDatabaseChirho {
    database_chirho: PostgresDatabaseChirho,
    gate_chirho: ForwardLockGateChirho,
}

struct GatedPostgresTransactionChirho<'client_chirho> {
    transaction_chirho: PostgresTransactionChirho<'client_chirho>,
    gate_chirho: ForwardLockGateChirho,
}

impl ReversiblePostgresDatabasePortChirho for GatedPostgresDatabaseChirho {
    type TransactionChirho<'client_chirho>
        = GatedPostgresTransactionChirho<'client_chirho>
    where
        Self: 'client_chirho;

    fn verify_schema_ready_chirho(&mut self) -> Result<(), DatabasePortErrorChirho> {
        self.database_chirho.verify_schema_ready_chirho()
    }

    fn begin_serializable_transaction_chirho(
        &mut self,
    ) -> Result<Self::TransactionChirho<'_>, DatabasePortErrorChirho> {
        Ok(GatedPostgresTransactionChirho {
            transaction_chirho: self
                .database_chirho
                .begin_serializable_transaction_chirho()?,
            gate_chirho: self.gate_chirho.clone(),
        })
    }
}

impl ReversiblePostgresTransactionPortChirho for GatedPostgresTransactionChirho<'_> {
    fn lock_forward_idempotency_key_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
    ) -> Result<(), DatabasePortErrorChirho> {
        if let Some(before_lock_chirho) = &self.gate_chirho.before_lock_chirho {
            before_lock_chirho.wait();
        }
        self.transaction_chirho
            .lock_forward_idempotency_key_chirho(effect_intent_key_chirho)?;
        if let Some(locked_chirho) = &self.gate_chirho.locked_chirho {
            locked_chirho.wait();
        }
        if let Some(release_chirho) = &self.gate_chirho.release_chirho {
            release_chirho.wait();
        }
        Ok(())
    }

    fn lock_compensation_idempotency_key_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .lock_compensation_idempotency_key_chirho(compensation_idem_key_chirho)
    }

    fn lock_original_effect_compensation_chirho(
        &mut self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .lock_original_effect_compensation_chirho(original_effect_idem_key_chirho)
    }

    fn lock_row_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .lock_row_chirho(subject_chirho, row_key_chirho)
    }

    fn load_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho> {
        self.transaction_chirho
            .load_forward_decision_chirho(effect_intent_key_chirho)
    }

    fn load_forward_decision_by_idem_key_chirho(
        &mut self,
        effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho> {
        self.transaction_chirho
            .load_forward_decision_by_idem_key_chirho(effect_idem_key_chirho)
    }

    fn load_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho> {
        self.transaction_chirho
            .load_compensation_receipt_chirho(compensation_idem_key_chirho)
    }

    fn load_compensation_receipt_by_original_effect_chirho(
        &mut self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho> {
        self.transaction_chirho
            .load_compensation_receipt_by_original_effect_chirho(original_effect_idem_key_chirho)
    }

    fn load_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<Option<DatabaseValueChirho>, DatabasePortErrorChirho> {
        self.transaction_chirho
            .load_value_chirho(subject_chirho, row_key_chirho)
    }

    fn upsert_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
        value_chirho: &[u8],
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .upsert_value_chirho(subject_chirho, row_key_chirho, value_chirho)
    }

    fn delete_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .delete_value_chirho(subject_chirho, row_key_chirho)
    }

    fn insert_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
        row_chirho: &AuthenticatedForwardDecisionRowChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .insert_forward_decision_chirho(effect_intent_key_chirho, row_chirho)
    }

    fn insert_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
        row_chirho: &AuthenticatedCompensationReceiptRowChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho
            .insert_compensation_receipt_chirho(compensation_idem_key_chirho, row_chirho)
    }

    fn commit_chirho(self) -> Result<(), DatabasePortErrorChirho> {
        self.transaction_chirho.commit_chirho()
    }
}

#[derive(Default)]
struct LocalPrivateEvidenceChirho {
    blobs_chirho: BTreeMap<String, (HashChirho, Vec<u8>)>,
}

impl LocalPrivateEvidenceChirho {
    fn insert_blob_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> PrivateBlobRefChirho {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(subject_chirho.0.as_bytes());
        hasher_chirho.update(bytes_chirho);
        let ciphertext_chirho = HashChirho(hasher_chirho.finalize().to_hex().to_string());
        self.blobs_chirho.insert(
            ciphertext_chirho.0.clone(),
            (subject_chirho.clone(), bytes_chirho.to_vec()),
        );
        PrivateBlobRefChirho {
            ciphertext_chirho,
            key_id_chirho: "race-private-key-chirho".to_string(),
            nonce_chirho: "race-private-nonce-chirho".to_string(),
            mac_chirho: "race-private-mac-chirho".to_string(),
            alg_chirho: "race-private-v1-chirho".to_string(),
        }
    }
}

impl PostgresPrivateEvidencePortChirho for LocalPrivateEvidenceChirho {
    fn load_subject_blob_chirho(
        &self,
        subject_chirho: &HashChirho,
        blob_ref_chirho: &PrivateBlobRefChirho,
    ) -> Result<SensitiveBytesChirho, PrivateEvidencePortErrorChirho> {
        let (stored_subject_chirho, bytes_chirho) = self
            .blobs_chirho
            .get(&blob_ref_chirho.ciphertext_chirho.0)
            .ok_or_else(|| PrivateEvidencePortErrorChirho::UnavailableChirho {
                detail_chirho: "race private blob is missing".to_string(),
            })?;
        if stored_subject_chirho != subject_chirho {
            return Err(PrivateEvidencePortErrorChirho::SubjectMismatchChirho);
        }
        Ok(SensitiveBytesChirho::new_chirho(bytes_chirho.clone()))
    }

    fn store_subject_blob_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> Result<PrivateBlobRefChirho, PrivateEvidencePortErrorChirho> {
        Ok(self.insert_blob_chirho(subject_chirho, bytes_chirho))
    }
}

fn hash_chirho(marker_chirho: char) -> HashChirho {
    HashChirho(marker_chirho.to_string().repeat(64))
}

fn evidence_key_chirho() -> AdapterEvidenceKeyChirho {
    AdapterEvidenceKeyChirho::new_chirho([7; 32]).unwrap()
}

fn effect_coordinate_chirho(
    effect_idem_key_chirho: &HashChirho,
) -> ReversiblePostgresEffectCoordinateChirho {
    ReversiblePostgresEffectCoordinateChirho::new_chirho(
        format!("cf3-intent-v1-chirho:{}", effect_idem_key_chirho.0),
        hash_chirho('c'),
        hash_chirho('d'),
    )
    .unwrap()
}

fn build_request_bytes_chirho(
    private_chirho: &mut LocalPrivateEvidenceChirho,
    subject_chirho: &HashChirho,
    row_key_chirho: &HashChirho,
    value_chirho: &[u8],
) -> Vec<u8> {
    let value_ref_chirho = private_chirho.insert_blob_chirho(subject_chirho, value_chirho);
    canonical_request_bytes_chirho(&ReversiblePostgresRequestChirho {
        schema_chirho: REQUEST_SCHEMA_CHIRHO.to_string(),
        subject_chirho: subject_chirho.clone(),
        row_key_chirho: row_key_chirho.clone(),
        expected_before_chirho: ExpectedPostgresStateChirho::AbsentChirho,
        desired_chirho: DesiredPostgresStateChirho::PresentChirho { value_ref_chirho },
    })
    .unwrap()
}

fn connection_config_chirho() -> String {
    std::env::var("CAIRN_POSTGRES_TEST_CONFIG_CHIRHO")
        .unwrap_or_else(|_| DEFAULT_TEST_CONFIG_CHIRHO.to_string())
}

fn connect_chirho(connection_config_chirho: &str) -> Result<Client, postgres::Error> {
    Client::connect(connection_config_chirho, NoTls)
}

fn connect_in_schema_chirho(connection_config_chirho: &str, schema_chirho: &str) -> Client {
    let mut client_chirho = connect_chirho(connection_config_chirho).unwrap();
    client_chirho
        .batch_execute(&format!("SET search_path TO \"{schema_chirho}\""))
        .unwrap();
    client_chirho
}

fn gated_database_chirho(
    connection_config_chirho: &str,
    schema_chirho: &str,
    gate_chirho: ForwardLockGateChirho,
) -> GatedPostgresDatabaseChirho {
    GatedPostgresDatabaseChirho {
        database_chirho: PostgresDatabaseChirho::from_client_chirho(connect_in_schema_chirho(
            connection_config_chirho,
            schema_chirho,
        )),
        gate_chirho,
    }
}

fn read_value_chirho(
    client_chirho: &mut Client,
    subject_chirho: &HashChirho,
    row_key_chirho: &HashChirho,
) -> Option<Vec<u8>> {
    client_chirho
        .query_opt(
            "SELECT value_chirho FROM cairn_reversible_values_chirho WHERE subject_chirho = $1 AND row_key_chirho = $2",
            &[&subject_chirho.0, &row_key_chirho.0],
        )
        .unwrap()
        .map(|row_chirho| row_chirho.get("value_chirho"))
}

#[test]
#[ignore = "requires the explicitly sanctioned local Homebrew PostgreSQL server"]
fn schema_preflight_requires_the_database_decision_constraint_floor_chirho() {
    let connection_config_chirho = connection_config_chirho();
    let schema_chirho = format!(
        "cairn_postgres_schema_preflight_{}_chirho",
        std::process::id()
    );
    let mut setup_chirho = connect_chirho(&connection_config_chirho).unwrap();
    setup_chirho
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS \"{schema_chirho}\" CASCADE; CREATE SCHEMA \"{schema_chirho}\"; SET search_path TO \"{schema_chirho}\""
        ))
        .unwrap();
    install_reversible_postgres_schema_chirho(&mut setup_chirho).unwrap();
    drop(setup_chirho);
    let _schema_guard_chirho = DisposableSchemaChirho {
        connection_config_chirho: connection_config_chirho.clone(),
        schema_chirho: schema_chirho.clone(),
    };

    let mut ready_chirho = PostgresDatabaseChirho::from_client_chirho(connect_in_schema_chirho(
        &connection_config_chirho,
        &schema_chirho,
    ));
    ready_chirho.verify_schema_ready_chirho().unwrap();
    let mut strip_chirho = connect_in_schema_chirho(&connection_config_chirho, &schema_chirho);
    strip_chirho
        .batch_execute(
            "ALTER TABLE cairn_reversible_forward_decisions_chirho DROP CONSTRAINT reversible_forward_decisions_idem_uq_chirho",
        )
        .unwrap();
    let error_chirho = ready_chirho.verify_schema_ready_chirho().unwrap_err();
    assert!(matches!(
        error_chirho,
        DatabasePortErrorChirho::PermanentChirho { detail_chirho }
            if detail_chirho.contains("decision constraint floor")
    ));

    let mut widen_chirho = connect_in_schema_chirho(&connection_config_chirho, &schema_chirho);
    widen_chirho
        .batch_execute(
            "ALTER TABLE cairn_reversible_forward_decisions_chirho
                 ADD CONSTRAINT reversible_forward_decisions_idem_uq_chirho
                 UNIQUE (effect_idem_key_chirho);
             ALTER TABLE cairn_reversible_forward_decisions_chirho
                 DROP CONSTRAINT reversible_forward_decision_kind_ck_chirho;
             ALTER TABLE cairn_reversible_forward_decisions_chirho
                 ADD CONSTRAINT reversible_forward_decision_kind_ck_chirho
                 CHECK (decision_kind_chirho IN
                     ('committed-chirho', 'definite-no-effect-chirho', 'unreviewed-third-terminal-chirho'));",
        )
        .unwrap();
    let widened_error_chirho = ready_chirho.verify_schema_ready_chirho().unwrap_err();
    assert!(matches!(
        widened_error_chirho,
        DatabasePortErrorChirho::PermanentChirho { detail_chirho }
            if detail_chirho.contains("decision constraint floor")
    ));
}

#[test]
#[ignore = "requires the explicitly sanctioned local Homebrew PostgreSQL server"]
fn query_and_execute_share_one_durable_decision_in_both_winner_orders_chirho() {
    let connection_config_chirho = connection_config_chirho();
    let schema_chirho = format!("cairn_postgres_decision_race_{}_chirho", std::process::id());
    let mut setup_chirho = connect_chirho(&connection_config_chirho).unwrap();
    setup_chirho
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS \"{schema_chirho}\" CASCADE; CREATE SCHEMA \"{schema_chirho}\"; SET search_path TO \"{schema_chirho}\""
        ))
        .unwrap();
    install_reversible_postgres_schema_chirho(&mut setup_chirho).unwrap();
    drop(setup_chirho);
    let _schema_guard_chirho = DisposableSchemaChirho {
        connection_config_chirho: connection_config_chirho.clone(),
        schema_chirho: schema_chirho.clone(),
    };

    query_first_closes_before_execute_chirho(&connection_config_chirho, &schema_chirho);
    execute_first_commits_before_query_chirho(&connection_config_chirho, &schema_chirho);
}

fn query_first_closes_before_execute_chirho(connection_config_chirho: &str, schema_chirho: &str) {
    let coordinate_chirho = effect_coordinate_chirho(&hash_chirho('1'));
    let subject_chirho = hash_chirho('a');
    let row_key_chirho = hash_chirho('b');
    let mut private_chirho = LocalPrivateEvidenceChirho::default();
    let request_bytes_chirho = build_request_bytes_chirho(
        &mut private_chirho,
        &subject_chirho,
        &row_key_chirho,
        b"query-lost-race-chirho",
    );
    let locked_chirho = Arc::new(Barrier::new(2));
    let release_chirho = Arc::new(Barrier::new(2));
    let query_coordinate_chirho = coordinate_chirho.clone();
    let query_connection_chirho = connection_config_chirho.to_string();
    let query_schema_chirho = schema_chirho.to_string();
    let query_locked_chirho = locked_chirho.clone();
    let query_release_chirho = release_chirho.clone();
    let query_handle_chirho = std::thread::spawn(move || {
        let mut database_chirho = gated_database_chirho(
            &query_connection_chirho,
            &query_schema_chirho,
            ForwardLockGateChirho::winner_chirho(query_locked_chirho, query_release_chirho),
        );
        query_reversible_postgres_by_key_chirho(
            &mut database_chirho,
            &evidence_key_chirho(),
            &query_coordinate_chirho,
        )
    });
    locked_chirho.wait();

    let attempting_chirho = Arc::new(Barrier::new(2));
    let execute_coordinate_chirho = coordinate_chirho.clone();
    let execute_connection_chirho = connection_config_chirho.to_string();
    let execute_schema_chirho = schema_chirho.to_string();
    let execute_attempting_chirho = attempting_chirho.clone();
    let execute_request_bytes_chirho = request_bytes_chirho.clone();
    let execute_handle_chirho = std::thread::spawn(move || {
        let mut database_chirho = gated_database_chirho(
            &execute_connection_chirho,
            &execute_schema_chirho,
            ForwardLockGateChirho::contender_chirho(execute_attempting_chirho),
        );
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &evidence_key_chirho(),
            &execute_coordinate_chirho,
            &execute_request_bytes_chirho,
        )
    });
    attempting_chirho.wait();
    release_chirho.wait();

    assert!(matches!(
        query_handle_chirho.join().unwrap().unwrap(),
        PostgresForwardQueryResultChirho::DefiniteNoEffectChirho {
            replayed_chirho: false,
            ..
        }
    ));
    let execute_race_chirho = execute_handle_chirho.join().unwrap();
    assert!(matches!(
        execute_race_chirho,
        Err(ReversiblePostgresErrorChirho::EffectAlreadyDecidedAbsentChirho)
            | Err(ReversiblePostgresErrorChirho::DatabaseChirho(
                DatabasePortErrorChirho::RetryableConflictChirho { .. }
            ))
    ));
    let mut retry_database_chirho = PostgresDatabaseChirho::from_client_chirho(
        connect_in_schema_chirho(connection_config_chirho, schema_chirho),
    );
    let mut retry_private_chirho = LocalPrivateEvidenceChirho::default();
    let retry_request_bytes_chirho = build_request_bytes_chirho(
        &mut retry_private_chirho,
        &subject_chirho,
        &row_key_chirho,
        b"query-lost-race-chirho",
    );
    assert_eq!(retry_request_bytes_chirho, request_bytes_chirho);
    assert_eq!(
        apply_reversible_postgres_chirho(
            &mut retry_database_chirho,
            &mut retry_private_chirho,
            &evidence_key_chirho(),
            &coordinate_chirho,
            &retry_request_bytes_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::EffectAlreadyDecidedAbsentChirho)
    );
    let mut observer_chirho = connect_in_schema_chirho(connection_config_chirho, schema_chirho);
    assert_eq!(
        read_value_chirho(&mut observer_chirho, &subject_chirho, &row_key_chirho),
        None
    );
}

fn execute_first_commits_before_query_chirho(connection_config_chirho: &str, schema_chirho: &str) {
    let coordinate_chirho = effect_coordinate_chirho(&hash_chirho('2'));
    let subject_chirho = hash_chirho('e');
    let row_key_chirho = hash_chirho('f');
    let mut private_chirho = LocalPrivateEvidenceChirho::default();
    let request_bytes_chirho = build_request_bytes_chirho(
        &mut private_chirho,
        &subject_chirho,
        &row_key_chirho,
        b"execute-won-race-chirho",
    );
    let locked_chirho = Arc::new(Barrier::new(2));
    let release_chirho = Arc::new(Barrier::new(2));
    let execute_coordinate_chirho = coordinate_chirho.clone();
    let execute_connection_chirho = connection_config_chirho.to_string();
    let execute_schema_chirho = schema_chirho.to_string();
    let execute_locked_chirho = locked_chirho.clone();
    let execute_release_chirho = release_chirho.clone();
    let execute_handle_chirho = std::thread::spawn(move || {
        let mut database_chirho = gated_database_chirho(
            &execute_connection_chirho,
            &execute_schema_chirho,
            ForwardLockGateChirho::winner_chirho(execute_locked_chirho, execute_release_chirho),
        );
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &evidence_key_chirho(),
            &execute_coordinate_chirho,
            &request_bytes_chirho,
        )
    });
    locked_chirho.wait();

    let attempting_chirho = Arc::new(Barrier::new(2));
    let query_coordinate_chirho = coordinate_chirho.clone();
    let query_connection_chirho = connection_config_chirho.to_string();
    let query_schema_chirho = schema_chirho.to_string();
    let query_attempting_chirho = attempting_chirho.clone();
    let query_handle_chirho = std::thread::spawn(move || {
        let mut database_chirho = gated_database_chirho(
            &query_connection_chirho,
            &query_schema_chirho,
            ForwardLockGateChirho::contender_chirho(query_attempting_chirho),
        );
        query_reversible_postgres_by_key_chirho(
            &mut database_chirho,
            &evidence_key_chirho(),
            &query_coordinate_chirho,
        )
    });
    attempting_chirho.wait();
    release_chirho.wait();

    let committed_chirho = execute_handle_chirho.join().unwrap().unwrap();
    assert!(!committed_chirho.replayed_chirho);
    let query_race_chirho = query_handle_chirho.join().unwrap();
    assert!(
        matches!(
            &query_race_chirho,
            Ok(PostgresForwardQueryResultChirho::CommittedChirho {
                decision_bytes_chirho,
                ..
            }) if decision_bytes_chirho == &committed_chirho.decision_bytes_chirho
        ) || matches!(
            &query_race_chirho,
            Err(ReversiblePostgresErrorChirho::DatabaseChirho(
                DatabasePortErrorChirho::RetryableConflictChirho { .. }
            ))
        )
    );
    let mut retry_database_chirho = PostgresDatabaseChirho::from_client_chirho(
        connect_in_schema_chirho(connection_config_chirho, schema_chirho),
    );
    assert!(matches!(
        query_reversible_postgres_by_key_chirho(
            &mut retry_database_chirho,
            &evidence_key_chirho(),
            &coordinate_chirho,
        )
        .unwrap(),
        PostgresForwardQueryResultChirho::CommittedChirho {
            decision_bytes_chirho,
            ..
        } if decision_bytes_chirho == committed_chirho.decision_bytes_chirho
    ));
    let mut observer_chirho = connect_in_schema_chirho(connection_config_chirho, schema_chirho);
    assert_eq!(
        read_value_chirho(&mut observer_chirho, &subject_chirho, &row_key_chirho),
        Some(b"execute-won-race-chirho".to_vec())
    );
}
