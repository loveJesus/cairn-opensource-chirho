// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use crate::engine_tests_chirho::{
    build_request_chirho, evidence_key_chirho, FakeDatabaseChirho, FakePrivateEvidenceChirho,
};
use crate::model_chirho::{
    canonical_request_bytes_chirho, DesiredPostgresStateChirho, ExpectedPostgresStateChirho,
};
use crate::provider_chirho::{
    PostgresRequestEvidenceErrorChirho, PostgresRequestEvidencePortChirho,
    ReversiblePostgresProviderChirho,
};
use cairn_effect_commit_chirho::coordinator_chirho::{
    BlessedEffectProviderPortChirho, EffectProviderObservationChirho, EffectProviderPortErrorChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho,
    verify_effect_intent_line_chirho, EffectIntentChirho, EffectIntentJournalCutChirho,
    EffectIntentSignerPortChirho, VerifiedEffectIntentChirho, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, HlcChirho};
use cairn_ledger_model_chirho::LogIdChirho;

const DIGEST_A_CHIRHO: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B_CHIRHO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C_CHIRHO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D_CHIRHO: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const DIGEST_E_CHIRHO: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const DIGEST_F_CHIRHO: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

struct FakeIntentRootChirho;

impl EffectIntentSignerPortChirho for FakeIntentRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        Ok(intent_signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        "provider-intent-root-chirho".to_string()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == intent_signature_chirho(signed_content_line_chirho)
    }
}

fn intent_signature_chirho(content_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"provider-intent-root-chirho");
    hasher_chirho.update(content_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

struct FakeRequestEvidenceChirho {
    request_ref_chirho: DigestChirho,
    request_bytes_chirho: Vec<u8>,
}

impl PostgresRequestEvidencePortChirho for FakeRequestEvidenceChirho {
    fn load_request_bytes_chirho(
        &self,
        request_ref_chirho: &DigestChirho,
    ) -> Result<Vec<u8>, PostgresRequestEvidenceErrorChirho> {
        if request_ref_chirho != &self.request_ref_chirho {
            return Err(PostgresRequestEvidenceErrorChirho::MissingChirho);
        }
        Ok(self.request_bytes_chirho.clone())
    }
}

fn digest_chirho(value_chirho: &str) -> DigestChirho {
    DigestChirho(value_chirho.to_string())
}

fn request_ref_chirho(request_bytes_chirho: &[u8]) -> DigestChirho {
    DigestChirho(blake3::hash(request_bytes_chirho).to_hex().to_string())
}

fn verified_intent_chirho(request_bytes_chirho: &[u8]) -> VerifiedEffectIntentChirho {
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
            journal_cut_chirho: EffectIntentJournalCutChirho {
                journal_genesis_digest_chirho: digest_chirho(DIGEST_A_CHIRHO),
                tail_seq_chirho: 41,
                tail_record_digest_chirho: digest_chirho(DIGEST_B_CHIRHO),
                tail_hlc_chirho: HlcChirho {
                    physical_ms_chirho: 1_750_000_000_000,
                    logical_chirho: 7,
                },
            },
            contract_set_digest_chirho: digest_chirho(DIGEST_C_CHIRHO),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": DIGEST_D_CHIRHO,
                "capability_fingerprint_chirho": DIGEST_E_CHIRHO,
            }))
            .unwrap(),
            reversion_contract_digest_chirho: digest_chirho(DIGEST_F_CHIRHO),
            request_ref_chirho: request_ref_chirho(request_bytes_chirho),
            request_context_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
            evidence_refs_chirho: vec![
                digest_chirho(DIGEST_C_CHIRHO),
                digest_chirho(DIGEST_D_CHIRHO),
            ],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 125,
                kind_id_chirho: AssetKindIdChirho("billing-credit-chirho".to_string()),
                kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho(DIGEST_E_CHIRHO)),
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho("user-7-chirho", "billing-credit-chirho"),
            effect_step_chirho: 3,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: "user-7-chirho".to_string(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        &FakeIntentRootChirho,
    )
    .unwrap();
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    verify_effect_intent_line_chirho(&line_chirho, &FakeIntentRootChirho).unwrap()
}

fn request_bytes_chirho() -> Vec<u8> {
    canonical_request_bytes_chirho(&build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::AbsentChirho,
    ))
    .unwrap()
}

#[test]
fn provider_execute_replays_and_query_returns_the_exact_committed_decision_chirho() {
    let request_bytes_chirho = request_bytes_chirho();
    let verified_intent_chirho = verified_intent_chirho(&request_bytes_chirho);
    let request_evidence_chirho = FakeRequestEvidenceChirho {
        request_ref_chirho: verified_intent_chirho
            .intent_chirho()
            .request_ref_chirho
            .clone(),
        request_bytes_chirho,
    };
    let mut database_chirho = FakeDatabaseChirho::new_quiet_chirho();
    let mut private_chirho = FakePrivateEvidenceChirho::new_quiet_chirho();
    let evidence_key_chirho = evidence_key_chirho();
    {
        let mut provider_chirho = ReversiblePostgresProviderChirho::new_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &request_evidence_chirho,
            &evidence_key_chirho,
        );

        let first_chirho = provider_chirho
            .execute_or_replay_chirho(&verified_intent_chirho)
            .unwrap();
        let (first_result_ref_chirho, first_evidence_chirho) = committed_parts_chirho(first_chirho);
        let second_chirho = provider_chirho
            .execute_or_replay_chirho(&verified_intent_chirho)
            .unwrap();
        let queried_chirho = provider_chirho
            .query_by_key_chirho(&verified_intent_chirho)
            .unwrap();
        assert_eq!(
            committed_parts_chirho(second_chirho),
            (
                first_result_ref_chirho.clone(),
                first_evidence_chirho.clone()
            )
        );
        assert_eq!(
            committed_parts_chirho(queried_chirho),
            (first_result_ref_chirho, first_evidence_chirho)
        );
    }
    assert_eq!(database_chirho.forward_decision_count_chirho(), 1);
}

#[test]
fn provider_negative_query_closes_the_coordinate_before_execute_chirho() {
    let request_bytes_chirho = request_bytes_chirho();
    let verified_intent_chirho = verified_intent_chirho(&request_bytes_chirho);
    let request_evidence_chirho = FakeRequestEvidenceChirho {
        request_ref_chirho: verified_intent_chirho
            .intent_chirho()
            .request_ref_chirho
            .clone(),
        request_bytes_chirho,
    };
    let mut database_chirho = FakeDatabaseChirho::new_quiet_chirho();
    let mut private_chirho = FakePrivateEvidenceChirho::new_quiet_chirho();
    let evidence_key_chirho = evidence_key_chirho();
    {
        let mut provider_chirho = ReversiblePostgresProviderChirho::new_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &request_evidence_chirho,
            &evidence_key_chirho,
        );

        assert!(matches!(
            provider_chirho.query_by_key_chirho(&verified_intent_chirho),
            Ok(EffectProviderObservationChirho::DefiniteNoEffectChirho { .. })
        ));
        assert!(matches!(
            provider_chirho.execute_or_replay_chirho(&verified_intent_chirho),
            Err(EffectProviderPortErrorChirho::InvalidResponseChirho { .. })
        ));
    }
    assert_eq!(database_chirho.forward_decision_count_chirho(), 1);
    assert_eq!(database_chirho.row_count_chirho(), 0);
}

#[test]
fn provider_refuses_request_bytes_that_cannot_wear_the_signed_ref_chirho() {
    let signed_request_bytes_chirho = request_bytes_chirho();
    let verified_intent_chirho = verified_intent_chirho(&signed_request_bytes_chirho);
    let request_evidence_chirho = FakeRequestEvidenceChirho {
        request_ref_chirho: verified_intent_chirho
            .intent_chirho()
            .request_ref_chirho
            .clone(),
        request_bytes_chirho: b"different-request-bytes-chirho".to_vec(),
    };
    let mut database_chirho = FakeDatabaseChirho::new_quiet_chirho();
    let mut private_chirho = FakePrivateEvidenceChirho::new_quiet_chirho();
    let evidence_key_chirho = evidence_key_chirho();
    {
        let mut provider_chirho = ReversiblePostgresProviderChirho::new_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &request_evidence_chirho,
            &evidence_key_chirho,
        );

        assert!(matches!(
            provider_chirho.execute_or_replay_chirho(&verified_intent_chirho),
            Err(EffectProviderPortErrorChirho::InvalidResponseChirho { .. })
        ));
    }
    assert_eq!(database_chirho.forward_decision_count_chirho(), 0);
    assert_eq!(database_chirho.row_count_chirho(), 0);
}

fn committed_parts_chirho(
    observation_chirho: EffectProviderObservationChirho,
) -> (DigestChirho, Vec<u8>) {
    match observation_chirho {
        EffectProviderObservationChirho::CommittedChirho {
            result_ref_chirho,
            evidence_chirho,
        } => (
            result_ref_chirho,
            evidence_chirho.as_slice_chirho().to_vec(),
        ),
        other_chirho => panic!("expected committed provider observation, got {other_chirho:?}"),
    }
}
