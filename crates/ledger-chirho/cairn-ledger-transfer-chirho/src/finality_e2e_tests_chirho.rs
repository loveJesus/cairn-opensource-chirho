// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! F3a destination admission over a real journal and a canonical test-only finality-proof fixture:
//! claim-credit through the composed views, then the consume-once law at every level (live replay,
//! full reopen, fast open, and the forged-line load twin). Production source issuance deliberately
//! remains absent until one verified snapshot can bind the exact burn and retained-cut witnesses.

use crate::coordinator_tests_chirho::{JournalFixtureChirho, SharedClockChirho};
use cairn_ledger_log_chirho::admission_chirho::{
    AdmissionRejectChirho, FinalityAdmissionViewsChirho, FinalityProofBytesViewChirho,
    SettlementAuthorizationViewChirho, SourceRootVerifyViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalErrorChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerSignerPortChirho, LedgerStoragePortChirho};
use cairn_ledger_model_chirho::counterpart_chirho::{
    CounterpartClaimChirho, CounterpartNullifierChirho, FinalBurnRefChirho,
};
use cairn_ledger_model_chirho::finality_chirho::{
    canonical_finality_proof_line_chirho, derive_finality_proof_ref_chirho,
    finality_proof_signed_content_chirho, FinalityProofChirho, RetainedCutChirho,
    FINALITY_PROOF_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho, MoneyGroupIdChirho,
    SettlementChannelIdChirho, TransferIdChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::LogIdChirho;
use std::cell::Cell;
use std::collections::BTreeMap;

struct SourceRootChirho;

impl LedgerSignerPortChirho for SourceRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        Ok(format!(
            "mg-root-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "mg-root-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

#[derive(Default)]
struct ProofStoreChirho {
    proofs_chirho: BTreeMap<DigestChirho, Vec<u8>>,
}

impl FinalityProofBytesViewChirho for ProofStoreChirho {
    fn resolve_chirho(&self, proof_ref_chirho: &DigestChirho) -> Option<Vec<u8>> {
        self.proofs_chirho.get(proof_ref_chirho).cloned()
    }
}

struct SourceRootsViewChirho;

impl SourceRootVerifyViewChirho for SourceRootsViewChirho {
    fn verify_chirho(
        &self,
        money_group_chirho: &MoneyGroupIdChirho,
        signed_content_chirho: &str,
        sig_chirho: &str,
    ) -> bool {
        money_group_chirho.0 == "mg-1-chirho"
            && SourceRootChirho.verify_chirho(signed_content_chirho, sig_chirho)
    }
}

struct AllowlistAuthChirho {
    transfer_chirho: String,
}

impl SettlementAuthorizationViewChirho for AllowlistAuthChirho {
    fn verify_chirho(
        &self,
        transfer_id_chirho: &TransferIdChirho,
        channel_chirho: &SettlementChannelIdChirho,
        settlement_account_chirho: &AccountIdChirho,
    ) -> bool {
        transfer_id_chirho.0 == self.transfer_chirho
            && channel_chirho.0 == "chan-1-chirho"
            && settlement_account_chirho.owner_chirho == "settlement-b-chirho"
    }
}

#[derive(Clone, Debug)]
struct IssuedFinalityProofFixtureChirho {
    proof_chirho: FinalityProofChirho,
    proof_ref_chirho: DigestChirho,
}

/// Build destination-admission evidence from source-journal receipts without exposing a production
/// issuer. This fixture exercises canonical proof signing and destination verification only; it does
/// not claim to implement the future source-side ancestry witness.
fn issued_from_source_fixture_chirho(
    fixture_chirho: &JournalFixtureChirho,
    clock_chirho: &SharedClockChirho,
) -> IssuedFinalityProofFixtureChirho {
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        fixture_chirho.ports_chirho(clock_chirho),
        fixture_chirho.path_chirho(),
        fixture_chirho.cluster_chirho.clone(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(fixture_chirho.mint_chirho(500, "idem-e2e-mint"))
        .unwrap();
    engine_chirho
        .append_chirho(fixture_chirho.transfer_chirho(
            "issuer-chirho",
            "alice-chirho",
            100,
            "idem-e2e-fund",
        ))
        .unwrap();
    let burn_chirho = engine_chirho
        .append_chirho(fixture_chirho.transfer_chirho(
            "alice-chirho",
            "settlement-1-chirho",
            40,
            "idem-e2e-burn",
        ))
        .unwrap();
    let cut_chirho = engine_chirho
        .append_chirho(fixture_chirho.transfer_chirho(
            "issuer-chirho",
            "alice-chirho",
            1,
            "idem-e2e-cut",
        ))
        .unwrap();
    drop(engine_chirho);
    let mut proof_chirho = FinalityProofChirho {
        schema_chirho: FINALITY_PROOF_SCHEMA_V1_CHIRHO.to_owned(),
        source_money_group_chirho: MoneyGroupIdChirho("mg-1-chirho".into()),
        source_cluster_chirho: fixture_chirho.cluster_chirho.clone(),
        source_epoch_chirho: 1,
        source_seq_chirho: burn_chirho.seq_chirho,
        source_record_digest_chirho: burn_chirho.record_digest_chirho,
        cut_chirho: RetainedCutChirho {
            cut_epoch_chirho: 1,
            cut_seq_chirho: cut_chirho.seq_chirho,
            cut_record_digest_chirho: cut_chirho.record_digest_chirho,
        },
        burn_amount_chirho: 40,
        burn_kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
            fixture_chirho.policy_ref_chirho.clone(),
        )),
        burn_src_chirho: LogIdChirho::new_chirho("alice-chirho", "money-chirho"),
        burn_dst_money_group_chirho: MoneyGroupIdChirho("mg-1-chirho".into()),
        burn_dst_cluster_chirho: ClusterIdChirho("cluster-b-chirho".into()),
        burn_dst_chirho: LogIdChirho::new_chirho("bob-chirho", "money-chirho"),
        burn_channel_chirho: SettlementChannelIdChirho("chan-1-chirho".into()),
        root_sig_chirho: String::new(),
    };
    let signed_content_chirho = finality_proof_signed_content_chirho(&proof_chirho).unwrap();
    proof_chirho.root_sig_chirho = SourceRootChirho
        .sign_chirho(&signed_content_chirho)
        .unwrap();
    canonical_finality_proof_line_chirho(&proof_chirho).unwrap();
    let proof_ref_chirho = derive_finality_proof_ref_chirho(&proof_chirho).unwrap();
    IssuedFinalityProofFixtureChirho {
        proof_chirho,
        proof_ref_chirho,
    }
}

fn claim_for_proof_fixture_chirho(
    issued_chirho: &IssuedFinalityProofFixtureChirho,
    transfer_id_chirho: TransferIdChirho,
) -> CounterpartClaimChirho {
    let proof_chirho = &issued_chirho.proof_chirho;
    CounterpartClaimChirho {
        transfer_id_chirho,
        burn_chirho: FinalBurnRefChirho {
            source_money_group_chirho: proof_chirho.source_money_group_chirho.clone(),
            source_cluster_chirho: proof_chirho.source_cluster_chirho.clone(),
            source_epoch_chirho: proof_chirho.source_epoch_chirho,
            source_seq_chirho: proof_chirho.source_seq_chirho,
            source_record_digest_chirho: proof_chirho.source_record_digest_chirho.clone(),
            finality_proof_ref_chirho: issued_chirho.proof_ref_chirho.clone(),
        },
        amount_chirho: proof_chirho.burn_amount_chirho,
        kind_policy_ref_chirho: proof_chirho.burn_kind_policy_ref_chirho.clone(),
        src_chirho: proof_chirho.burn_src_chirho.clone(),
        dst_money_group_chirho: proof_chirho.burn_dst_money_group_chirho.clone(),
        dst_cluster_chirho: proof_chirho.burn_dst_cluster_chirho.clone(),
        dst_chirho: proof_chirho.burn_dst_chirho.clone(),
        channel_chirho: proof_chirho.burn_channel_chirho.clone(),
        nullifier_chirho: CounterpartNullifierChirho::derive_chirho(
            &proof_chirho.source_money_group_chirho,
            &proof_chirho.source_cluster_chirho,
            proof_chirho.source_epoch_chirho,
            proof_chirho.source_seq_chirho,
            &proof_chirho.source_record_digest_chirho,
            &proof_chirho.burn_dst_money_group_chirho,
            &proof_chirho.burn_dst_cluster_chirho,
            &proof_chirho.burn_dst_chirho,
            &proof_chirho.burn_channel_chirho,
        ),
    }
}

/// The destination claim-credit request: [Debit settlement-b, Credit bob + the claim].
fn claim_credit_request_chirho(
    fixture_chirho: &JournalFixtureChirho,
    issued_chirho: &IssuedFinalityProofFixtureChirho,
    idem_chirho: &str,
) -> AppendRequestChirho {
    let claim_chirho =
        claim_for_proof_fixture_chirho(issued_chirho, TransferIdChirho("t-e2e-chirho".into()));
    let leg_chirho = |owner_chirho: &str, delta_chirho| AppendLegRequestChirho {
        account_chirho: LogIdChirho::new_chirho(owner_chirho, "money-chirho"),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
            fixture_chirho.policy_ref_chirho.clone(),
        )),
        delta_chirho,
        amount_chirho: 40,
        counterpart_chirho: None,
    };
    let mut credit_chirho = leg_chirho("bob-chirho", LegDeltaChirho::CreditChirho);
    credit_chirho.counterpart_chirho = Some(claim_chirho);
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::TransferChirho,
        legs_chirho: vec![
            leg_chirho("settlement-b-chirho", LegDeltaChirho::DebitChirho),
            credit_chirho,
        ],
        idempotency_key_chirho: idem_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

#[test]
fn cross_cluster_claim_credits_once_and_only_once_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let source_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let issued_chirho = issued_from_source_fixture_chirho(&source_chirho, &clock_chirho);
    // Destination journal B, funded settlement account, COMPOSED with the three views.
    let destination_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "money-chirho", "platform-b-chirho");
    let mut proof_store_chirho = ProofStoreChirho::default();
    proof_store_chirho.proofs_chirho.insert(
        issued_chirho.proof_ref_chirho.clone(),
        cairn_ledger_model_chirho::finality_chirho::canonical_finality_proof_line_chirho(
            &issued_chirho.proof_chirho,
        )
        .unwrap()
        .into_bytes(),
    );
    let roots_chirho = SourceRootsViewChirho;
    let auth_chirho = AllowlistAuthChirho {
        transfer_chirho: "t-e2e-chirho".into(),
    };
    let views_chirho = FinalityAdmissionViewsChirho {
        proofs_chirho: &proof_store_chirho,
        source_roots_chirho: &roots_chirho,
        settlement_authorizations_chirho: &auth_chirho,
    };
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        destination_chirho.ports_chirho(&clock_chirho),
        destination_chirho.path_chirho(),
        destination_chirho.cluster_chirho.clone(),
        1,
    )
    .unwrap()
    .with_finality_views_chirho(views_chirho);
    engine_chirho
        .append_chirho(destination_chirho.mint_chirho(500, "idem-e2e-b-mint"))
        .unwrap();
    engine_chirho
        .append_chirho(destination_chirho.transfer_chirho(
            "issuer-chirho",
            "settlement-b-chirho",
            100,
            "idem-e2e-b-fund",
        ))
        .unwrap();
    // WITHOUT composition the same claim refuses Unsupported (law v) — proven on a twin engine
    // over a separate path before the composed engine admits.
    {
        let bare_fixture_chirho = JournalFixtureChirho::new_chirho(
            "cluster-b-chirho",
            "money-chirho",
            "platform-b-chirho",
        );
        let mut bare_chirho = LedgerJournalChirho::create_chirho(
            bare_fixture_chirho.ports_chirho(&clock_chirho),
            bare_fixture_chirho.path_chirho(),
            bare_fixture_chirho.cluster_chirho.clone(),
            1,
        )
        .unwrap();
        bare_chirho
            .append_chirho(bare_fixture_chirho.mint_chirho(500, "idem-e2e-bare-mint"))
            .unwrap();
        bare_chirho
            .append_chirho(bare_fixture_chirho.transfer_chirho(
                "issuer-chirho",
                "settlement-b-chirho",
                100,
                "idem-e2e-bare-fund",
            ))
            .unwrap();
        assert!(matches!(
            bare_chirho.append_chirho(claim_credit_request_chirho(
                &bare_fixture_chirho,
                &issued_chirho,
                "idem-e2e-bare-claim",
            )),
            Err(JournalErrorChirho::AdmissionChirho {
                reject_chirho: AdmissionRejectChirho::UnsupportedOperationChirho
            })
        ));
    }
    // THE CREDIT: admits exactly once...
    engine_chirho
        .append_chirho(claim_credit_request_chirho(
            &destination_chirho,
            &issued_chirho,
            "idem-e2e-claim",
        ))
        .expect("the fully-evidenced cross-cluster credit admits");
    // ...and the SAME claim under a FRESH idempotency key refuses on the CONSUMED nullifier.
    assert!(matches!(
        engine_chirho.append_chirho(claim_credit_request_chirho(
            &destination_chirho,
            &issued_chirho,
            "idem-e2e-claim-2",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::CounterpartNullifierConsumedChirho
        })
    ));
    let nets_chirho: BTreeMap<String, i128> = engine_chirho
        .head_states_chirho()
        .iter()
        .map(|(account_chirho, post_chirho)| {
            (
                account_chirho.owner_chirho.clone(),
                i128::from(post_chirho.credits_total_chirho)
                    - i128::from(post_chirho.debits_total_chirho),
            )
        })
        .collect();
    assert_eq!(nets_chirho["bob-chirho"], 40, "credited exactly once");
    assert_eq!(nets_chirho["settlement-b-chirho"], 60);
    drop(engine_chirho);
    // FULL REOPEN rebuilds the consumed set (replay's twin): the claim still refuses.
    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        destination_chirho.ports_chirho(&clock_chirho),
        destination_chirho.path_chirho(),
        &destination_chirho.cluster_chirho,
    )
    .unwrap()
    .with_finality_views_chirho(FinalityAdmissionViewsChirho {
        proofs_chirho: &proof_store_chirho,
        source_roots_chirho: &roots_chirho,
        settlement_authorizations_chirho: &auth_chirho,
    });
    assert!(matches!(
        reopened_chirho.append_chirho(claim_credit_request_chirho(
            &destination_chirho,
            &issued_chirho,
            "idem-e2e-claim-3",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::CounterpartNullifierConsumedChirho
        })
    ));
    // CHECKPOINT + FAST OPEN restores the consumed set without replay.
    reopened_chirho.write_head_checkpoint_chirho().unwrap();
    drop(reopened_chirho);
    let mut fast_chirho = LedgerJournalChirho::open_chirho(
        destination_chirho.ports_chirho(&clock_chirho),
        destination_chirho.path_chirho(),
        &destination_chirho.cluster_chirho,
    )
    .unwrap()
    .with_finality_views_chirho(FinalityAdmissionViewsChirho {
        proofs_chirho: &proof_store_chirho,
        source_roots_chirho: &roots_chirho,
        settlement_authorizations_chirho: &auth_chirho,
    });
    assert!(
        fast_chirho.last_open_was_fast_chirho(),
        "the twin binds the FAST path"
    );
    assert!(matches!(
        fast_chirho.append_chirho(claim_credit_request_chirho(
            &destination_chirho,
            &issued_chirho,
            "idem-e2e-claim-4",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::CounterpartNullifierConsumedChirho
        })
    ));
    drop(fast_chirho);
    // THE FORGED-LINE LOAD TWIN: a colluding-signer duplicate of the claim record (chain-valid,
    // sig-valid, fold-true because the settlement account still covers it) dies at LOAD on the
    // consumed-nullifier transition — the P2 pattern, third application.
    let log_bytes_chirho = destination_chirho
        .storage_chirho
        .read_all_chirho(&destination_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let log_text_chirho = String::from_utf8(log_bytes_chirho).unwrap();
    let claim_line_chirho = log_text_chirho
        .lines()
        .find(|line_chirho| {
            line_chirho.contains("counterpart_chirho") && line_chirho.contains("t-e2e-chirho")
        })
        .unwrap()
        .to_owned();
    let tail_line_chirho = log_text_chirho.lines().last().unwrap().to_owned();
    let template_chirho: cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho =
        serde_json::from_str(&claim_line_chirho).unwrap();
    let tail_chirho: cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho =
        serde_json::from_str(&tail_line_chirho).unwrap();
    let mut forged_chirho = template_chirho.clone();
    forged_chirho.seq_chirho = tail_chirho.seq_chirho + 1;
    forged_chirho.prev_chirho =
        cairn_ledger_model_chirho::wire_chirho::stored_line_digest_chirho(&tail_line_chirho);
    forged_chirho.hlc_chirho = tail_chirho.hlc_chirho.clone();
    forged_chirho.hlc_chirho.logical_chirho += 1;
    forged_chirho.idempotency_key_chirho = "idem-e2e-forged".to_owned();
    // Fold-true posts continuing from the live heads (settlement 60 -> 20 debited; bob 40 -> 80).
    forged_chirho.legs_chirho[0].post_chirho.debits_total_chirho = 80;
    forged_chirho.legs_chirho[1]
        .post_chirho
        .credits_total_chirho = 80;
    forged_chirho.sig_chirho = String::new();
    let signed_content_chirho =
        cairn_ledger_model_chirho::wire_chirho::ledger_record_signed_content_line_chirho(
            &forged_chirho,
        )
        .unwrap();
    forged_chirho.sig_chirho = destination_chirho
        .signer_chirho
        .sign_chirho(&signed_content_chirho)
        .unwrap();
    let forged_line_chirho =
        cairn_ledger_model_chirho::wire_chirho::canonical_ledger_record_line_chirho(&forged_chirho)
            .unwrap();
    destination_chirho
        .storage_chirho
        .append_durable_chirho(
            &destination_chirho.path_chirho(),
            format!("{forged_line_chirho}\n").as_bytes(),
        )
        .unwrap();
    // The sidecar must not mask the forged suffix: remove it so the open replays the full log.
    let _ = destination_chirho.storage_chirho.remove_chirho(
        &cairn_ledger_log_chirho::ports_chirho::StoragePathChirho(format!(
            "{}.head-checkpoint-chirho",
            destination_chirho.path_chirho().0
        )),
    );
    match LedgerJournalChirho::open_chirho(
        destination_chirho.ports_chirho(&clock_chirho),
        destination_chirho.path_chirho(),
        &destination_chirho.cluster_chirho,
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("nullifier"),
            "the forged duplicate claim must die at the consumed-nullifier transition: {detail_chirho}"
        ),
        other_chirho => panic!("a forged duplicate claim must fail the load closed: {:?}", other_chirho.map(|_| ())),
    }
}
