// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
use cairn_postgres_effect_chirho::ports_chirho::{
    OriginalEffectEvidenceErrorChirho, PostgresOriginalEffectEvidencePortChirho,
    PostgresPrivateEvidencePortChirho, PrivateEvidencePortErrorChirho, SensitiveBytesChirho,
    VerifiedOriginalPostgresEffectChirho,
};
use cairn_postgres_effect_chirho::{
    apply_reversible_postgres_chirho as apply_reversible_postgres_coordinate_chirho,
    canonical_committed_decision_bytes_chirho, canonical_request_bytes_chirho,
    compensate_reversible_postgres_chirho, install_reversible_postgres_schema_chirho,
    parse_canonical_committed_decision_chirho, AdapterEvidenceKeyChirho,
    DesiredPostgresStateChirho, ExpectedPostgresStateChirho, PostgresCompensationOutcomeChirho,
    PostgresDatabaseChirho, PostgresForwardResultChirho, ReversiblePostgresEffectCoordinateChirho,
    ReversiblePostgresErrorChirho, ReversiblePostgresRequestChirho,
};
use postgres::{Client, NoTls};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

const REQUEST_SCHEMA_CHIRHO: &str = "reversible-postgres-request-v1-chirho";
const DEFAULT_TEST_CONFIG_CHIRHO: &str = "host=/tmp port=5432 dbname=postgres";

struct PrivateBlobFixtureChirho {
    subject_chirho: HashChirho,
    bytes_chirho: Vec<u8>,
}

#[derive(Default)]
struct LocalPrivateEvidenceChirho {
    blobs_chirho: BTreeMap<String, PrivateBlobFixtureChirho>,
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
            PrivateBlobFixtureChirho {
                subject_chirho: subject_chirho.clone(),
                bytes_chirho: bytes_chirho.to_vec(),
            },
        );
        PrivateBlobRefChirho {
            ciphertext_chirho,
            key_id_chirho: "local-postgres-test-key-chirho".to_string(),
            nonce_chirho: "local-postgres-test-nonce-chirho".to_string(),
            mac_chirho: "local-postgres-test-mac-chirho".to_string(),
            alg_chirho: "local-postgres-test-private-v1-chirho".to_string(),
        }
    }
}

impl PostgresPrivateEvidencePortChirho for LocalPrivateEvidenceChirho {
    fn load_subject_blob_chirho(
        &self,
        subject_chirho: &HashChirho,
        blob_ref_chirho: &PrivateBlobRefChirho,
    ) -> Result<SensitiveBytesChirho, PrivateEvidencePortErrorChirho> {
        let fixture_chirho = self
            .blobs_chirho
            .get(&blob_ref_chirho.ciphertext_chirho.0)
            .ok_or_else(|| PrivateEvidencePortErrorChirho::UnavailableChirho {
                detail_chirho: "local test blob is missing".to_string(),
            })?;
        if fixture_chirho.subject_chirho != *subject_chirho {
            return Err(PrivateEvidencePortErrorChirho::SubjectMismatchChirho);
        }
        Ok(SensitiveBytesChirho::new_chirho(
            fixture_chirho.bytes_chirho.clone(),
        ))
    }

    fn store_subject_blob_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> Result<PrivateBlobRefChirho, PrivateEvidencePortErrorChirho> {
        Ok(self.insert_blob_chirho(subject_chirho, bytes_chirho))
    }
}

#[derive(Default)]
struct LocalOriginalEffectsChirho {
    effects_chirho: BTreeMap<HashChirho, VerifiedOriginalPostgresEffectChirho>,
}

impl PostgresOriginalEffectEvidencePortChirho for LocalOriginalEffectsChirho {
    fn load_verified_original_effect_chirho(
        &self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<VerifiedOriginalPostgresEffectChirho, OriginalEffectEvidenceErrorChirho> {
        self.effects_chirho
            .get(original_effect_idem_key_chirho)
            .cloned()
            .ok_or(OriginalEffectEvidenceErrorChirho::MissingChirho)
    }
}

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

fn apply_reversible_postgres_chirho(
    database_chirho: &mut PostgresDatabaseChirho,
    private_evidence_chirho: &mut LocalPrivateEvidenceChirho,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    effect_idem_key_chirho: &HashChirho,
    request_bytes_chirho: &[u8],
) -> Result<PostgresForwardResultChirho, ReversiblePostgresErrorChirho> {
    apply_reversible_postgres_coordinate_chirho(
        database_chirho,
        private_evidence_chirho,
        evidence_key_chirho,
        &effect_coordinate_chirho(effect_idem_key_chirho),
        request_bytes_chirho,
    )
}

fn request_chirho(
    subject_chirho: HashChirho,
    row_key_chirho: HashChirho,
    expected_before_chirho: ExpectedPostgresStateChirho,
    desired_chirho: DesiredPostgresStateChirho,
) -> ReversiblePostgresRequestChirho {
    ReversiblePostgresRequestChirho {
        schema_chirho: REQUEST_SCHEMA_CHIRHO.to_string(),
        subject_chirho,
        row_key_chirho,
        expected_before_chirho,
        desired_chirho,
    }
}

fn original_effects_chirho(
    effect_idem_key_chirho: &HashChirho,
    request_bytes_chirho: &[u8],
    receipt_bytes_chirho: &[u8],
) -> LocalOriginalEffectsChirho {
    LocalOriginalEffectsChirho {
        effects_chirho: [(
            effect_idem_key_chirho.clone(),
            VerifiedOriginalPostgresEffectChirho {
                original_effect_idem_key_chirho: effect_idem_key_chirho.clone(),
                request_bytes_chirho: request_bytes_chirho.to_vec(),
                forward_receipt_bytes_chirho: receipt_bytes_chirho.to_vec(),
            },
        )]
        .into_iter()
        .collect(),
    }
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

fn read_row_chirho(
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

fn set_row_chirho(
    client_chirho: &mut Client,
    subject_chirho: &HashChirho,
    row_key_chirho: &HashChirho,
    value_chirho: &[u8],
) {
    client_chirho
        .execute(
            "INSERT INTO cairn_reversible_values_chirho (subject_chirho, row_key_chirho, value_chirho) VALUES ($1, $2, $3) ON CONFLICT (subject_chirho, row_key_chirho) DO UPDATE SET value_chirho = EXCLUDED.value_chirho",
            &[&subject_chirho.0, &row_key_chirho.0, &value_chirho],
        )
        .unwrap();
}

#[test]
#[ignore = "requires the explicitly sanctioned local Homebrew PostgreSQL server"]
fn local_postgres_reversible_effect_matrix_chirho() {
    let connection_config_chirho = connection_config_chirho();
    let schema_chirho = format!("cairn_postgres_effect_test_{}_chirho", std::process::id());
    assert!(schema_chirho
        .chars()
        .all(|character_chirho| character_chirho.is_ascii_lowercase()
            || character_chirho.is_ascii_digit()
            || character_chirho == '_'));
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

    let client_chirho = connect_in_schema_chirho(&connection_config_chirho, &schema_chirho);
    let mut database_chirho = PostgresDatabaseChirho::from_client_chirho(client_chirho);
    let mut observer_chirho = connect_in_schema_chirho(&connection_config_chirho, &schema_chirho);
    let key_chirho = evidence_key_chirho();

    // Commit ambiguity, exact replay, same-idem mismatch, parameterized injection bytes, and
    // subject-bound private input all run through the real driver.
    let mut private_chirho = LocalPrivateEvidenceChirho::default();
    let subject_chirho = hash_chirho('a');
    let row_key_chirho = hash_chirho('b');
    let effect_key_chirho = hash_chirho('c');
    let injection_value_chirho = b"'); DROP TABLE cairn_reversible_values_chirho; --";
    let value_ref_chirho =
        private_chirho.insert_blob_chirho(&subject_chirho, injection_value_chirho);
    let create_request_chirho = request_chirho(
        subject_chirho.clone(),
        row_key_chirho.clone(),
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho { value_ref_chirho },
    );
    let create_bytes_chirho = canonical_request_bytes_chirho(&create_request_chirho).unwrap();
    let first_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &create_bytes_chirho,
    )
    .unwrap();
    assert_eq!(
        read_row_chirho(&mut observer_chirho, &subject_chirho, &row_key_chirho),
        Some(injection_value_chirho.to_vec())
    );
    assert!(!first_chirho
        .receipt_bytes_chirho
        .windows(injection_value_chirho.len())
        .any(|window_chirho| window_chirho == injection_value_chirho));
    let replay_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &create_bytes_chirho,
    )
    .unwrap();
    assert!(replay_chirho.replayed_chirho);
    assert_eq!(
        replay_chirho.receipt_bytes_chirho,
        first_chirho.receipt_bytes_chirho
    );
    let mismatch_chirho = request_chirho(
        subject_chirho.clone(),
        row_key_chirho.clone(),
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::AbsentChirho,
    );
    assert_eq!(
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &key_chirho,
            &effect_key_chirho,
            &canonical_request_bytes_chirho(&mismatch_chirho).unwrap(),
        ),
        Err(ReversiblePostgresErrorChirho::IdempotencyConflictChirho)
    );

    let wrong_subject_ref_chirho =
        private_chirho.insert_blob_chirho(&hash_chirho('d'), b"wrong-subject");
    let wrong_subject_chirho = request_chirho(
        subject_chirho.clone(),
        hash_chirho('d'),
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: wrong_subject_ref_chirho,
        },
    );
    assert!(matches!(
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &key_chirho,
            &hash_chirho('d'),
            &canonical_request_bytes_chirho(&wrong_subject_chirho).unwrap(),
        ),
        Err(ReversiblePostgresErrorChirho::PrivateEvidenceChirho(
            PrivateEvidencePortErrorChirho::SubjectMismatchChirho
        ))
    ));

    // Update compensation restores the private before-image, replays identically, and refuses a
    // second compensation identity for the original effect.
    let update_subject_chirho = hash_chirho('e');
    let update_row_chirho = hash_chirho('f');
    let initial_ref_chirho = private_chirho.insert_blob_chirho(&update_subject_chirho, b"initial");
    let initial_request_chirho = request_chirho(
        update_subject_chirho.clone(),
        update_row_chirho.clone(),
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: initial_ref_chirho,
        },
    );
    let tamper_forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &hash_chirho('e'),
        &canonical_request_bytes_chirho(&initial_request_chirho).unwrap(),
    )
    .unwrap();
    let update_ref_chirho = private_chirho.insert_blob_chirho(&update_subject_chirho, b"updated");
    let update_request_chirho = request_chirho(
        update_subject_chirho.clone(),
        update_row_chirho.clone(),
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: cairn_postgres_effect_chirho::crypto_chirho::row_fingerprint_chirho(
                &key_chirho,
                &update_subject_chirho,
                &update_row_chirho,
                b"initial",
            ),
        },
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: update_ref_chirho,
        },
    );
    let update_bytes_chirho = canonical_request_bytes_chirho(&update_request_chirho).unwrap();
    let update_key_chirho = hash_chirho('f');
    let update_forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &update_key_chirho,
        &update_bytes_chirho,
    )
    .unwrap();
    let update_originals_chirho = original_effects_chirho(
        &update_key_chirho,
        &update_bytes_chirho,
        &update_forward_chirho.receipt_bytes_chirho,
    );
    let update_comp_key_chirho = hash_chirho('1');
    let restored_chirho = compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &update_originals_chirho,
        &key_chirho,
        &update_comp_key_chirho,
        &update_key_chirho,
    )
    .unwrap();
    assert!(matches!(
        restored_chirho.receipt_chirho.outcome_chirho,
        PostgresCompensationOutcomeChirho::RestoredChirho { .. }
    ));
    assert_eq!(
        read_row_chirho(
            &mut observer_chirho,
            &update_subject_chirho,
            &update_row_chirho
        ),
        Some(b"initial".to_vec())
    );
    let restored_replay_chirho = compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &update_originals_chirho,
        &key_chirho,
        &update_comp_key_chirho,
        &update_key_chirho,
    )
    .unwrap();
    assert!(restored_replay_chirho.replayed_chirho);
    assert_eq!(
        restored_replay_chirho.receipt_bytes_chirho,
        restored_chirho.receipt_bytes_chirho
    );
    assert_eq!(
        compensate_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &update_originals_chirho,
            &key_chirho,
            &hash_chirho('2'),
            &update_key_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::CompensationAlreadyRecordedChirho)
    );

    // Delete restore and create compensation cover both absence transitions.
    let delete_subject_chirho = hash_chirho('2');
    let delete_row_chirho = hash_chirho('3');
    set_row_chirho(
        &mut observer_chirho,
        &delete_subject_chirho,
        &delete_row_chirho,
        b"delete-me",
    );
    let delete_request_chirho = request_chirho(
        delete_subject_chirho.clone(),
        delete_row_chirho.clone(),
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: cairn_postgres_effect_chirho::crypto_chirho::row_fingerprint_chirho(
                &key_chirho,
                &delete_subject_chirho,
                &delete_row_chirho,
                b"delete-me",
            ),
        },
        DesiredPostgresStateChirho::AbsentChirho,
    );
    let delete_bytes_chirho = canonical_request_bytes_chirho(&delete_request_chirho).unwrap();
    let delete_key_chirho = hash_chirho('3');
    let delete_forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &delete_key_chirho,
        &delete_bytes_chirho,
    )
    .unwrap();
    assert_eq!(
        read_row_chirho(
            &mut observer_chirho,
            &delete_subject_chirho,
            &delete_row_chirho
        ),
        None
    );
    compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &original_effects_chirho(
            &delete_key_chirho,
            &delete_bytes_chirho,
            &delete_forward_chirho.receipt_bytes_chirho,
        ),
        &key_chirho,
        &hash_chirho('4'),
        &delete_key_chirho,
    )
    .unwrap();
    assert_eq!(
        read_row_chirho(
            &mut observer_chirho,
            &delete_subject_chirho,
            &delete_row_chirho
        ),
        Some(b"delete-me".to_vec())
    );

    let created_subject_chirho = hash_chirho('4');
    let created_row_chirho = hash_chirho('5');
    let created_ref_chirho = private_chirho.insert_blob_chirho(&created_subject_chirho, b"created");
    let created_request_chirho = request_chirho(
        created_subject_chirho.clone(),
        created_row_chirho.clone(),
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: created_ref_chirho,
        },
    );
    let created_bytes_chirho = canonical_request_bytes_chirho(&created_request_chirho).unwrap();
    let created_key_chirho = hash_chirho('5');
    let created_forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &created_key_chirho,
        &created_bytes_chirho,
    )
    .unwrap();
    compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &original_effects_chirho(
            &created_key_chirho,
            &created_bytes_chirho,
            &created_forward_chirho.receipt_bytes_chirho,
        ),
        &key_chirho,
        &hash_chirho('6'),
        &created_key_chirho,
    )
    .unwrap();
    assert_eq!(
        read_row_chirho(
            &mut observer_chirho,
            &created_subject_chirho,
            &created_row_chirho
        ),
        None
    );

    // A later world-state write turns compensation into a durable superseded result.
    let superseded_subject_chirho = hash_chirho('6');
    let superseded_row_chirho = hash_chirho('7');
    set_row_chirho(
        &mut observer_chirho,
        &superseded_subject_chirho,
        &superseded_row_chirho,
        b"before",
    );
    let superseded_ref_chirho =
        private_chirho.insert_blob_chirho(&superseded_subject_chirho, b"post");
    let superseded_request_chirho = request_chirho(
        superseded_subject_chirho.clone(),
        superseded_row_chirho.clone(),
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: cairn_postgres_effect_chirho::crypto_chirho::row_fingerprint_chirho(
                &key_chirho,
                &superseded_subject_chirho,
                &superseded_row_chirho,
                b"before",
            ),
        },
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: superseded_ref_chirho,
        },
    );
    let superseded_bytes_chirho =
        canonical_request_bytes_chirho(&superseded_request_chirho).unwrap();
    let superseded_key_chirho = hash_chirho('7');
    let superseded_forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &superseded_key_chirho,
        &superseded_bytes_chirho,
    )
    .unwrap();
    set_row_chirho(
        &mut observer_chirho,
        &superseded_subject_chirho,
        &superseded_row_chirho,
        b"later-world-state",
    );
    let superseded_chirho = compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &original_effects_chirho(
            &superseded_key_chirho,
            &superseded_bytes_chirho,
            &superseded_forward_chirho.receipt_bytes_chirho,
        ),
        &key_chirho,
        &hash_chirho('8'),
        &superseded_key_chirho,
    )
    .unwrap();
    assert!(matches!(
        superseded_chirho.receipt_chirho.outcome_chirho,
        PostgresCompensationOutcomeChirho::SupersededChirho { .. }
    ));
    assert_eq!(
        read_row_chirho(
            &mut observer_chirho,
            &superseded_subject_chirho,
            &superseded_row_chirho
        ),
        Some(b"later-world-state".to_vec())
    );

    // An authenticated receipt is mandatory recovery evidence.
    let tamper_subject_chirho = hash_chirho('8');
    let tamper_row_chirho = hash_chirho('9');
    let tamper_ref_chirho = private_chirho.insert_blob_chirho(&tamper_subject_chirho, b"tamper");
    let tamper_request_chirho = request_chirho(
        tamper_subject_chirho,
        tamper_row_chirho,
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: tamper_ref_chirho,
        },
    );
    let tamper_bytes_chirho = canonical_request_bytes_chirho(&tamper_request_chirho).unwrap();
    let tamper_key_chirho = hash_chirho('9');
    apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &tamper_key_chirho,
        &tamper_bytes_chirho,
    )
    .unwrap();
    let mut tamper_decision_chirho =
        parse_canonical_committed_decision_chirho(&tamper_forward_chirho.decision_bytes_chirho)
            .unwrap();
    tamper_decision_chirho.receipt_mac_chirho = hash_chirho('0');
    let tampered_decision_bytes_chirho =
        canonical_committed_decision_bytes_chirho(&tamper_decision_chirho).unwrap();
    let tamper_coordinate_chirho = effect_coordinate_chirho(&tamper_key_chirho);
    observer_chirho
        .execute(
            "UPDATE cairn_reversible_forward_decisions_chirho SET decision_bytes_chirho = $1 WHERE effect_intent_key_chirho = $2",
            &[
                &tampered_decision_bytes_chirho,
                &tamper_coordinate_chirho.effect_intent_key_chirho(),
            ],
        )
        .unwrap();
    assert!(matches!(
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &key_chirho,
            &tamper_key_chirho,
            &tamper_bytes_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::StoredEvidenceInvalidChirho { .. })
    ));

    // Barrier synchronization drives two absent-state writers at the same row without sleeps.
    let race_subject_chirho = hash_chirho('a');
    let race_row_chirho = hash_chirho('1');
    let barrier_chirho = Arc::new(Barrier::new(3));
    let mut handles_chirho = Vec::new();
    for (marker_chirho, value_chirho) in [('a', b"race-a".as_slice()), ('b', b"race-b".as_slice())]
    {
        let connection_config_chirho = connection_config_chirho.clone();
        let schema_chirho = schema_chirho.clone();
        let barrier_chirho = barrier_chirho.clone();
        let race_subject_chirho = race_subject_chirho.clone();
        let race_row_chirho = race_row_chirho.clone();
        handles_chirho.push(std::thread::spawn(move || {
            let client_chirho = connect_in_schema_chirho(&connection_config_chirho, &schema_chirho);
            let mut database_chirho = PostgresDatabaseChirho::from_client_chirho(client_chirho);
            let mut private_chirho = LocalPrivateEvidenceChirho::default();
            let value_ref_chirho =
                private_chirho.insert_blob_chirho(&race_subject_chirho, value_chirho);
            let request_chirho = request_chirho(
                race_subject_chirho,
                race_row_chirho,
                ExpectedPostgresStateChirho::AbsentChirho,
                DesiredPostgresStateChirho::PresentChirho { value_ref_chirho },
            );
            barrier_chirho.wait();
            apply_reversible_postgres_chirho(
                &mut database_chirho,
                &mut private_chirho,
                &evidence_key_chirho(),
                &hash_chirho(marker_chirho),
                &canonical_request_bytes_chirho(&request_chirho).unwrap(),
            )
        }));
    }
    barrier_chirho.wait();
    let race_results_chirho: Vec<_> = handles_chirho
        .into_iter()
        .map(|handle_chirho| handle_chirho.join().unwrap())
        .collect();
    assert_eq!(
        race_results_chirho
            .iter()
            .filter(|result_chirho| result_chirho.is_ok())
            .count(),
        1
    );
    assert_eq!(
        race_results_chirho
            .iter()
            .filter(|result_chirho| {
                matches!(
                    result_chirho,
                    Err(ReversiblePostgresErrorChirho::ExpectedBeforeMismatchChirho { .. })
                        | Err(ReversiblePostgresErrorChirho::DatabaseChirho(
                            cairn_postgres_effect_chirho::ports_chirho::DatabasePortErrorChirho::RetryableConflictChirho { .. }
                        ))
                )
            })
            .count(),
        1
    );
}
