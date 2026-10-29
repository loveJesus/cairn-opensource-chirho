// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_chain_core_chirho::stored_line_digest_hex_chirho;
use cairn_ledger_conservation_monitor_chirho::checker_chirho::{
    run_conservation_monitor_once_chirho, ConservationMonitorFailureChirho,
};
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, FinalityProofBytesViewChirho,
    KindPolicyViewChirho, KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho,
    MembershipViewChirho, MintAuthorityPolicyChirho, SettlementAuthorizationViewChirho,
    SourceRootVerifyViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalErrorChirho, ReadOnlyRecoveryReasonChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerClockPortChirho, LedgerStoragePortChirho};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::counterpart_chirho::{
    CounterpartClaimChirho, CounterpartNullifierChirho, FinalBurnRefChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, MoneyGroupIdChirho,
    SettlementChannelIdChirho, TransferIdChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_read_model_chirho::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_read_model_chirho::feeder_chirho::VerifiedSourceStateChirho;
use cairn_ledger_read_model_chirho::follower_chirho::ProjectionReadOutcomeChirho;
use cairn_ledger_read_model_chirho::serving_chirho::journal_source_family_id_chirho;
use cairn_ledger_read_model_chirho::source_registry_chirho::SourceDeclarationChirho;
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

#[derive(Default)]
struct MemStorageChirho {
    objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl LedgerStoragePortChirho for MemStorageChirho {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<cairn_ledger_log_chirho::ports_chirho::CreateDurableOutcomeChirho> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        match objects_chirho.entry(path_chirho.0.clone()) {
            std::collections::btree_map::Entry::Vacant(entry_chirho) => {
                entry_chirho.insert(bytes_chirho.to_vec());
                Ok(
                    cairn_ledger_log_chirho::ports_chirho::CreateDurableOutcomeChirho::CreatedChirho,
                )
            }
            std::collections::btree_map::Entry::Occupied(_) => Ok(
                cairn_ledger_log_chirho::ports_chirho::CreateDurableOutcomeChirho::AlreadyExistsChirho,
            ),
        }
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<()> {
        self.objects_chirho
            .borrow_mut()
            .entry(path_chirho.0.clone())
            .or_default()
            .extend_from_slice(bytes_chirho);
        Ok(())
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.objects_chirho.borrow().get(&path_chirho.0).cloned())
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<Option<u64>> {
        Ok(self
            .objects_chirho
            .borrow()
            .get(&path_chirho.0)
            .map(|bytes_chirho| bytes_chirho.len() as u64))
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let objects_chirho = self.objects_chirho.borrow();
        let bytes_chirho = objects_chirho
            .get(&path_chirho.0)
            .ok_or_else(|| anyhow::anyhow!("missing object"))?;
        let start_chirho = offset_chirho as usize;
        let end_chirho = start_chirho + len_chirho as usize;
        if end_chirho > bytes_chirho.len() {
            anyhow::bail!("short read");
        }
        Ok(bytes_chirho[start_chirho..end_chirho].to_vec())
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<()> {
        self.objects_chirho
            .borrow_mut()
            .insert(path_chirho.0.clone(), bytes_chirho.to_vec());
        Ok(())
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        len_chirho: u64,
    ) -> anyhow::Result<()> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .get_mut(&path_chirho.0)
            .ok_or_else(|| anyhow::anyhow!("missing object"))?;
        bytes_chirho.truncate(len_chirho as usize);
        Ok(())
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> anyhow::Result<()> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .remove(&from_chirho.0)
            .ok_or_else(|| anyhow::anyhow!("missing source"))?;
        objects_chirho.insert(to_chirho.0.clone(), bytes_chirho);
        Ok(())
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<()> {
        self.objects_chirho.borrow_mut().remove(&path_chirho.0);
        Ok(())
    }

    fn list_chirho(
        &self,
        prefix_chirho: &StoragePathChirho,
    ) -> anyhow::Result<Vec<StoragePathChirho>> {
        Ok(self
            .objects_chirho
            .borrow()
            .keys()
            .filter(|key_chirho| key_chirho.starts_with(&prefix_chirho.0))
            .map(|key_chirho| StoragePathChirho(key_chirho.clone()))
            .collect())
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<bool> {
        Ok(self.objects_chirho.borrow().contains_key(&path_chirho.0))
    }
}

struct TestSignerChirho {
    name_chirho: &'static str,
}

impl LedgerSignerPortChirho for TestSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        Ok(format!(
            "{}::{}",
            self.name_chirho,
            stored_line_digest_hex_chirho(signed_content_line_chirho)
        ))
    }

    fn key_id_chirho(&self) -> String {
        self.name_chirho.to_string()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

struct StepClockChirho {
    now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for StepClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.set(self.now_ms_chirho.get() + 10);
        self.now_ms_chirho.get()
    }
}

struct AllMembersChirho;

impl MembershipViewChirho for AllMembersChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: u64,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

struct OpenKindsChirho;

impl KindRegistryViewChirho for OpenKindsChirho {
    fn resolve_chirho(&self, _policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        KindResolutionChirho::CurrentChirho(KindPolicyViewChirho {
            kind_id_chirho: AssetKindIdChirho("credits-chirho".to_string()),
            mint_authority_chirho: MintAuthorityPolicyChirho::ProviderReceiptChirho,
            rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
            settlement_owner_chirho: Some("settlement-owner-chirho".to_string()),
            idempotency_window_chirho: None,
        })
    }
}

struct OpenAuthorityChirho;

impl AuthorityVerifierViewChirho for OpenAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::VerifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::VerifiedChirho
    }
}

/// A proof view that resolves nothing — the WIRED-but-empty finality composition.
struct EmptyProofsChirho;

impl FinalityProofBytesViewChirho for EmptyProofsChirho {
    fn resolve_chirho(&self, _proof_ref_chirho: &DigestChirho) -> Option<Vec<u8>> {
        None
    }
}

/// The fifth key identity: the SOURCE money-group root behind the verify predicate.
struct SourceRootsOverSignerChirho<'signer_chirho> {
    signer_chirho: &'signer_chirho dyn LedgerSignerPortChirho,
}

impl SourceRootVerifyViewChirho for SourceRootsOverSignerChirho<'_> {
    fn verify_chirho(
        &self,
        _money_group_chirho: &MoneyGroupIdChirho,
        signed_content_chirho: &str,
        sig_chirho: &str,
    ) -> bool {
        self.signer_chirho
            .verify_chirho(signed_content_chirho, sig_chirho)
    }
}

struct AllowAllSettlementChirho;

impl SettlementAuthorizationViewChirho for AllowAllSettlementChirho {
    fn verify_chirho(
        &self,
        _transfer_id_chirho: &TransferIdChirho,
        _channel_chirho: &SettlementChannelIdChirho,
        _settlement_account_chirho: &AccountIdChirho,
    ) -> bool {
        true
    }
}

/// The balances fold (composition-local copy of the canonical test fold).
struct BalancesFoldChirho;

impl cairn_ledger_read_model_chirho::feeder_chirho::ProjectionFoldPortChirho
    for BalancesFoldChirho
{
    fn fold_chirho(&self, source_chirho: &VerifiedSourceStateChirho<'_>) -> Result<Vec<u8>> {
        let balances_chirho: BTreeMap<String, i128> = source_chirho
            .journal_chirho
            .head_states_chirho()
            .iter()
            .map(|(account_chirho, post_chirho)| {
                (
                    format!(
                        "{}:{}",
                        account_chirho.owner_chirho, account_chirho.kind_id_chirho.0
                    ),
                    i128::from(post_chirho.credits_total_chirho)
                        - i128::from(post_chirho.debits_total_chirho)
                        - i128::from(post_chirho.held_chirho),
                )
            })
            .collect();
        serde_json::to_vec(&balances_chirho).context("encode balances view")
    }
}

fn mint_request_chirho(
    owner_chirho: &str,
    amount_chirho: u64,
    idem_chirho: &str,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho("ee".repeat(32)),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: AccountIdChirho {
                owner_chirho: owner_chirho.to_string(),
                kind_id_chirho: AssetKindIdChirho("credits-chirho".to_string()),
            },
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("dd".repeat(32))),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: idem_chirho.to_string(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "composition-test-chirho".to_string(),
        },
    }
}

/// A claim-bearing x-cluster settlement request: [Debit settlement bare, Credit dst + ONE claim].
/// Every claim field is a dummy — laws v (absence) and i (proof resolution) refuse BEFORE any
/// binding equality runs, which is exactly what these seam tests pin.
fn claim_transfer_request_chirho(cluster_chirho: &ClusterIdChirho) -> AppendRequestChirho {
    let dst_chirho = AccountIdChirho {
        owner_chirho: "bob-chirho".to_string(),
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_string()),
    };
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::TransferChirho,
        legs_chirho: vec![
            AppendLegRequestChirho {
                account_chirho: AccountIdChirho {
                    owner_chirho: "settlement-chirho".to_string(),
                    kind_id_chirho: AssetKindIdChirho("credits-chirho".to_string()),
                },
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("dd".repeat(32))),
                delta_chirho: LegDeltaChirho::DebitChirho,
                amount_chirho: 40,
                counterpart_chirho: None,
            },
            AppendLegRequestChirho {
                account_chirho: dst_chirho.clone(),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("dd".repeat(32))),
                delta_chirho: LegDeltaChirho::CreditChirho,
                amount_chirho: 40,
                counterpart_chirho: Some(CounterpartClaimChirho {
                    transfer_id_chirho: TransferIdChirho("t-seam-chirho".to_string()),
                    burn_chirho: FinalBurnRefChirho {
                        source_money_group_chirho: MoneyGroupIdChirho("mg-src-chirho".to_string()),
                        source_cluster_chirho: ClusterIdChirho("cl-src-chirho".to_string()),
                        source_epoch_chirho: 1,
                        source_seq_chirho: 1,
                        source_record_digest_chirho: DigestChirho("ab".repeat(32)),
                        finality_proof_ref_chirho: DigestChirho("ac".repeat(32)),
                    },
                    amount_chirho: 40,
                    kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("dd".repeat(32))),
                    src_chirho: AccountIdChirho {
                        owner_chirho: "carol-chirho".to_string(),
                        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_string()),
                    },
                    dst_money_group_chirho: MoneyGroupIdChirho("mg-dst-chirho".to_string()),
                    dst_cluster_chirho: cluster_chirho.clone(),
                    dst_chirho,
                    channel_chirho: SettlementChannelIdChirho("chan-chirho".to_string()),
                    nullifier_chirho: CounterpartNullifierChirho(DigestChirho("ad".repeat(32))),
                }),
            },
        ],
        idempotency_key_chirho: "idem-seam-chirho".to_string(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "composition-test-chirho".to_string(),
        },
    }
}

struct HarnessChirho {
    storage_chirho: MemStorageChirho,
    journal_root_chirho: TestSignerChirho,
    config_root_chirho: TestSignerChirho,
    feeder_root_chirho: TestSignerChirho,
    finality_source_root_chirho: TestSignerChirho,
    clock_chirho: StepClockChirho,
    membership_chirho: AllMembersChirho,
    kinds_chirho: OpenKindsChirho,
    authority_chirho: OpenAuthorityChirho,
}

impl HarnessChirho {
    fn new_chirho() -> Self {
        HarnessChirho {
            storage_chirho: MemStorageChirho::default(),
            journal_root_chirho: TestSignerChirho {
                name_chirho: "journal-root-chirho",
            },
            config_root_chirho: TestSignerChirho {
                name_chirho: "config-root-chirho",
            },
            feeder_root_chirho: TestSignerChirho {
                name_chirho: "feeder-root-chirho",
            },
            finality_source_root_chirho: TestSignerChirho {
                name_chirho: "finality-source-root-chirho",
            },
            clock_chirho: StepClockChirho {
                now_ms_chirho: Cell::new(1_000),
            },
            membership_chirho: AllMembersChirho,
            kinds_chirho: OpenKindsChirho,
            authority_chirho: OpenAuthorityChirho,
        }
    }

    fn journal_ports_chirho(&self) -> JournalPortsChirho<'_> {
        JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: &self.journal_root_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.kinds_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }

    fn read_composition_chirho(&self) -> LedgerReadCompositionChirho<'_> {
        LedgerReadCompositionChirho {
            journal_ports_chirho: self.journal_ports_chirho(),
            config_root_chirho: &self.config_root_chirho,
            feeder_root_chirho: &self.feeder_root_chirho,
            projection_registry_path_chirho: StoragePathChirho(
                "registries/projections-chirho.jsonl".to_string(),
            ),
            projection_registry_id_chirho: "compose-projections-chirho".to_string(),
            source_registry_path_chirho: StoragePathChirho(
                "registries/sources-chirho.jsonl".to_string(),
            ),
            source_registry_id_chirho: "compose-sources-chirho".to_string(),
        }
    }
}

fn cluster_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-compose-chirho".to_string())
}

fn journal_path_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/compose-chirho.jsonl".to_string())
}

fn head_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/heads-chirho/balances-chirho".to_string())
}

#[test]
fn distinct_key_identities_hold_and_a_shared_key_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    assert_distinct_key_identities_chirho(&[
        ("journal-root-chirho", &harness_chirho.journal_root_chirho),
        ("config-root-chirho", &harness_chirho.config_root_chirho),
        ("feeder-root-chirho", &harness_chirho.feeder_root_chirho),
        (
            "finality-source-root-chirho",
            &harness_chirho.finality_source_root_chirho,
        ),
    ])
    .unwrap();
    // A COPIED key wearing two role names is the composition defect this check exists for.
    let copied_chirho = TestSignerChirho {
        name_chirho: "journal-root-chirho",
    };
    let error_chirho = assert_distinct_key_identities_chirho(&[
        ("journal-root-chirho", &harness_chirho.journal_root_chirho),
        ("feeder-root-chirho", &copied_chirho),
    ])
    .unwrap_err();
    assert!(error_chirho.to_string().contains("never share keys"));
}

#[test]
fn end_to_end_compose_feed_publish_load_serve_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let write_chirho = LedgerWriteCompositionChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        finality_chirho: None,
    };
    let mut journal_chirho = write_chirho
        .create_journal_chirho(&journal_path_chirho(), cluster_chirho(), 1)
        .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-comp-1"))
        .unwrap();
    drop(journal_chirho);
    let read_chirho = harness_chirho.read_composition_chirho();
    // Register the SOURCE, resolve evidence FROM the chain, and build the descriptor from it.
    let family_chirho = journal_source_family_id_chirho(&cluster_chirho());
    read_chirho
        .append_source_op_chirho(
            cairn_ledger_read_model_chirho::source_registry_chirho::SourceRegistryOpChirho::RegisterSourceChirho {
                declaration_chirho: SourceDeclarationChirho {
                    family_id_chirho: family_chirho.clone(),
                    schema_ref_chirho: DigestChirho("aa".repeat(32)),
                    privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
                    privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
                },
            },
        )
        .unwrap();
    let sources_chirho = vec![
        cairn_ledger_read_model_chirho::descriptor_chirho::VerifiedProjectionSourceChirho {
            binding_chirho: ProjectionSourceBindingChirho {
                family_id_chirho: family_chirho.clone(),
                source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
            },
            privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
            privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
        },
    ];
    let evidence_chirho = derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: "balances-chirho".to_string(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
        fold_fn_ref_chirho: DigestChirho("bb".repeat(32)),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: 5_000,
            read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_floor_evidence_ref_chirho: evidence_chirho,
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    };
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    read_chirho
        .append_projection_op_chirho(ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho,
        })
        .unwrap();
    // Feed + publish, then load + serve — the whole loop through the composition surface.
    let journal_path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    let source_chirho = ProjectionSourceChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        journal_path_chirho: &journal_path_local_chirho,
        cluster_chirho: &cluster_local_chirho,
    };
    read_chirho
        .feed_and_publish_chirho(
            "balances-chirho",
            &digest_chirho,
            &BalancesFoldChirho,
            source_chirho,
            &head_path_chirho(),
        )
        .unwrap();
    let composed_read_chirho = read_chirho
        .load_named_and_serve_with_view_chirho(
            "balances-chirho",
            &head_path_chirho(),
            source_chirho,
        )
        .unwrap();
    assert_eq!(
        read_chirho
            .load_named_and_serve_with_view_chirho(
                "foreign-projection-chirho",
                &head_path_chirho(),
                source_chirho,
            )
            .unwrap_err()
            .to_string(),
        "configured projection route does not match the published head receipt"
    );
    assert_eq!(
        composed_read_chirho.verified_cost_class_chirho,
        Some(ProjectionCostClassChirho::StandingWriteRateChirho)
    );
    let expected_view_chirho = serde_json::to_vec(&BTreeMap::from([(
        "alice-chirho:credits-chirho".to_string(),
        700_i128,
    )]))
    .unwrap();
    assert_eq!(
        composed_read_chirho.view_bytes_chirho.as_deref(),
        Some(expected_view_chirho.as_slice())
    );
    match composed_read_chirho.outcome_chirho {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho {
            lag_ms_chirho,
            ..
        }) => assert_eq!(lag_ms_chirho, 0),
        other_chirho => panic!("expected a fresh composed read, got {other_chirho:?}"),
    }
}

#[test]
fn finality_seam_absence_refuses_and_wiring_changes_the_refusal_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    // Fund the settlement account so the build fold cannot mask the admission refusal.
    let unwired_chirho = LedgerWriteCompositionChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        finality_chirho: None,
    };
    let mut journal_chirho = unwired_chirho
        .create_journal_chirho(&journal_path_chirho(), cluster_chirho(), 1)
        .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("settlement-chirho", 100, "idem-seam-0"))
        .unwrap();
    // LAW V THROUGH THE COMPOSITION: an un-wired composition refuses the counterpart row as
    // UNSUPPORTED — infrastructure absence never default-opens.
    let error_chirho = journal_chirho
        .append_chirho(claim_transfer_request_chirho(&cluster_chirho()))
        .unwrap_err();
    assert!(
        format!("{error_chirho:?}").contains("Unsupported"),
        "absence must refuse Unsupported, got {error_chirho:?}"
    );
    drop(journal_chirho);
    // THE SEAM WIRES: with composed views the SAME request now refuses at proof RESOLUTION —
    // the refusal CHANGES (Unsupported -> proof missing), proving the seam actually carries.
    let proofs_chirho = EmptyProofsChirho;
    let source_roots_chirho = SourceRootsOverSignerChirho {
        signer_chirho: &harness_chirho.finality_source_root_chirho,
    };
    let settlement_chirho = AllowAllSettlementChirho;
    let wired_chirho = LedgerWriteCompositionChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        finality_chirho: Some(FinalityAdmissionViewsChirho {
            proofs_chirho: &proofs_chirho,
            source_roots_chirho: &source_roots_chirho,
            settlement_authorizations_chirho: &settlement_chirho,
        }),
    };
    let mut journal_chirho = wired_chirho
        .open_journal_chirho(&journal_path_chirho(), &cluster_chirho())
        .unwrap();
    let error_chirho = journal_chirho
        .append_chirho(claim_transfer_request_chirho(&cluster_chirho()))
        .unwrap_err();
    assert!(
        format!("{error_chirho:?}").contains("ProofMissing"),
        "a wired seam must reach proof resolution, got {error_chirho:?}"
    );
}

#[test]
fn canary_and_heal_clean_refreshed_and_divergence_paths_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let write_chirho = LedgerWriteCompositionChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        finality_chirho: None,
    };
    let mut journal_chirho = write_chirho
        .create_journal_chirho(&journal_path_chirho(), cluster_chirho(), 1)
        .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-canary-1"))
        .unwrap();
    drop(journal_chirho);
    let read_chirho = harness_chirho.read_composition_chirho();
    let family_chirho = journal_source_family_id_chirho(&cluster_chirho());
    read_chirho
        .append_source_op_chirho(
            cairn_ledger_read_model_chirho::source_registry_chirho::SourceRegistryOpChirho::RegisterSourceChirho {
                declaration_chirho: SourceDeclarationChirho {
                    family_id_chirho: family_chirho.clone(),
                    schema_ref_chirho: DigestChirho("aa".repeat(32)),
                    privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
                    privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
                },
            },
        )
        .unwrap();
    let sources_chirho = vec![
        cairn_ledger_read_model_chirho::descriptor_chirho::VerifiedProjectionSourceChirho {
            binding_chirho: ProjectionSourceBindingChirho {
                family_id_chirho: family_chirho.clone(),
                source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
            },
            privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
            privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
        },
    ];
    let evidence_chirho = derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: "balances-chirho".to_string(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
        fold_fn_ref_chirho: DigestChirho("bb".repeat(32)),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: 5_000,
            read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_floor_evidence_ref_chirho: evidence_chirho,
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    };
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    read_chirho
        .append_projection_op_chirho(ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho,
        })
        .unwrap();
    let journal_path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    let source_chirho = ProjectionSourceChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        journal_path_chirho: &journal_path_local_chirho,
        cluster_chirho: &cluster_local_chirho,
    };
    let run_chirho = || {
        read_chirho.canary_and_heal_chirho(
            "balances-chirho",
            &digest_chirho,
            &BalancesFoldChirho,
            source_chirho,
            &head_path_chirho(),
        )
    };
    // First publication = Refreshed; a second run at the same cut = Clean.
    assert_eq!(
        run_chirho().unwrap(),
        CanaryOutcomeChirho::RefreshedChirho {
            published_seq_chirho: 1
        }
    );
    assert_eq!(run_chirho().unwrap(), CanaryOutcomeChirho::CleanChirho);
    // The source moves: Refreshed at the new cut.
    let mut journal_chirho = write_chirho
        .open_journal_chirho(&journal_path_chirho(), &cluster_chirho())
        .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("bob-chirho", 60, "idem-canary-2"))
        .unwrap();
    drop(journal_chirho);
    assert_eq!(
        run_chirho().unwrap(),
        CanaryOutcomeChirho::RefreshedChirho {
            published_seq_chirho: 2
        }
    );
    // DIVERGENCE: publish a doctored view at the SAME cut (validly re-signed by the honest
    // feeder root — every receipt law passes). The canary must heal it and report both digests.
    let honest_chirho =
        cairn_ledger_read_model_chirho::publication_chirho::load_published_projection_chirho(
            &harness_chirho.storage_chirho,
            &head_path_chirho(),
            &harness_chirho.feeder_root_chirho,
        )
        .unwrap();
    let mut doctored_chirho =
        cairn_ledger_read_model_chirho::feeder_chirho::MaterializedProjectionChirho {
            view_bytes_chirho: honest_chirho.view_bytes_chirho.clone(),
            receipt_chirho: honest_chirho.receipt_chirho.clone(),
        };
    doctored_chirho.view_bytes_chirho[2] ^= 1;
    doctored_chirho.receipt_chirho.view_digest_hex_chirho =
        cairn_ledger_read_model_chirho::feeder_chirho::view_bytes_digest_hex_chirho(
            &doctored_chirho.view_bytes_chirho,
        );
    doctored_chirho.receipt_chirho.feeder_sig_chirho = String::new();
    let content_chirho =
        cairn_ledger_read_model_chirho::feeder_chirho::follow_receipt_signed_content_chirho(
            &doctored_chirho.receipt_chirho,
        )
        .unwrap();
    doctored_chirho.receipt_chirho.feeder_sig_chirho = harness_chirho
        .feeder_root_chirho
        .sign_chirho(&content_chirho)
        .unwrap();
    cairn_ledger_read_model_chirho::publication_chirho::publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &doctored_chirho,
        &head_path_chirho(),
    )
    .unwrap();
    match run_chirho().unwrap() {
        CanaryOutcomeChirho::HealedDivergenceChirho {
            divergent_view_digest_chirho,
            healed_view_digest_chirho,
            at_seq_chirho,
        } => {
            assert_eq!(at_seq_chirho, 2);
            assert_eq!(
                divergent_view_digest_chirho,
                doctored_chirho.receipt_chirho.view_digest_hex_chirho
            );
            assert_eq!(
                healed_view_digest_chirho,
                honest_chirho.receipt_chirho.view_digest_hex_chirho
            );
        }
        other_chirho => panic!("expected a healed divergence, got {other_chirho:?}"),
    }
    // The head now serves the HONEST bytes again.
    let healed_chirho =
        cairn_ledger_read_model_chirho::publication_chirho::load_published_projection_chirho(
            &harness_chirho.storage_chirho,
            &head_path_chirho(),
            &harness_chirho.feeder_root_chirho,
        )
        .unwrap();
    assert_eq!(
        healed_chirho.view_bytes_chirho,
        honest_chirho.view_bytes_chirho
    );
}

/// The CF6 rehearsal Phase A whole-arc test: ONE fresh root carries genesis → admitted money →
/// registries → feed/publish → serve AND the conservation monitor — the previously untested seam
/// (#5294), wired composition-side per the #5298 split (audit derives, the monitor checks, this
/// crate only wires). No pre-seeded state, distinct injected identities per role, no sleeps.
#[test]
fn whole_arc_genesis_serve_and_conservation_monitor_green_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let write_chirho = LedgerWriteCompositionChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        finality_chirho: None,
    };
    let mut journal_chirho = write_chirho
        .create_journal_chirho(&journal_path_chirho(), cluster_chirho(), 1)
        .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-arc-1"))
        .unwrap();
    drop(journal_chirho);

    let read_chirho = harness_chirho.read_composition_chirho();
    let family_chirho = journal_source_family_id_chirho(&cluster_chirho());
    read_chirho
        .append_source_op_chirho(
            cairn_ledger_read_model_chirho::source_registry_chirho::SourceRegistryOpChirho::RegisterSourceChirho {
                declaration_chirho: SourceDeclarationChirho {
                    family_id_chirho: family_chirho.clone(),
                    schema_ref_chirho: DigestChirho("aa".repeat(32)),
                    privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
                    privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
                },
            },
        )
        .unwrap();
    let sources_chirho = vec![
        cairn_ledger_read_model_chirho::descriptor_chirho::VerifiedProjectionSourceChirho {
            binding_chirho: ProjectionSourceBindingChirho {
                family_id_chirho: family_chirho.clone(),
                source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
            },
            privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
            privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
        },
    ];
    let evidence_ref_chirho =
        derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: "arc-balances-chirho".to_string(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
        fold_fn_ref_chirho: DigestChirho("bb".repeat(32)),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: 5_000,
            read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_floor_evidence_ref_chirho: evidence_ref_chirho,
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    };
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    read_chirho
        .append_projection_op_chirho(ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho,
        })
        .unwrap();
    let journal_path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    read_chirho
        .feed_and_publish_chirho(
            "arc-balances-chirho",
            &digest_chirho,
            &BalancesFoldChirho,
            ProjectionSourceChirho {
                journal_ports_chirho: harness_chirho.journal_ports_chirho(),
                journal_path_chirho: &journal_path_local_chirho,
                cluster_chirho: &cluster_local_chirho,
            },
            &head_path_chirho(),
        )
        .unwrap();
    let outcome_chirho = read_chirho
        .load_and_serve_chirho(
            &head_path_chirho(),
            ProjectionSourceChirho {
                journal_ports_chirho: harness_chirho.journal_ports_chirho(),
                journal_path_chirho: &journal_path_local_chirho,
                cluster_chirho: &cluster_local_chirho,
            },
        )
        .unwrap();
    match outcome_chirho {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho {
            ..
        }) => {}
        other_chirho => panic!("expected a fresh composed read, got {other_chirho:?}"),
    }

    // THE MONITOR LEG — the seam this test exists for: the same fresh root, checked GREEN.
    let monitor_source_chirho = JournalConservationSourceChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        journal_path_chirho: journal_path_chirho(),
        cluster_chirho: cluster_chirho(),
        money_group_chirho: MoneyGroupIdChirho("mg-arc-chirho".to_string()),
    };
    let evidence_chirho = run_conservation_monitor_once_chirho(&monitor_source_chirho).unwrap();
    assert_eq!(evidence_chirho.domain_kind_rollups_checked_chirho, 1);
    assert_eq!(evidence_chirho.global_supplies_checked_chirho, 1);
    assert_eq!(evidence_chirho.head_chirho.covered_record_count_chirho, 1);

    // Fail-closed: a wrong cluster identity cannot produce a snapshot — the verified open
    // refuses and the monitor reports VerifiedSnapshotUnavailable, never a verdict.
    let wrong_source_chirho = JournalConservationSourceChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        journal_path_chirho: journal_path_chirho(),
        cluster_chirho: ClusterIdChirho("wrong-cluster-chirho".to_string()),
        money_group_chirho: MoneyGroupIdChirho("mg-arc-chirho".to_string()),
    };
    assert!(matches!(
        run_conservation_monitor_once_chirho(&wrong_source_chirho),
        Err(ConservationMonitorFailureChirho::VerifiedSnapshotUnavailableChirho(_))
    ));
}

#[test]
fn conservation_source_refuses_torn_journal_without_repairing_storage_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let write_chirho = LedgerWriteCompositionChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        finality_chirho: None,
    };
    let mut journal_chirho = write_chirho
        .create_journal_chirho(&journal_path_chirho(), cluster_chirho(), 1)
        .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho(
            "alice-chirho",
            700,
            "idem-torn-monitor-chirho",
        ))
        .unwrap();
    drop(journal_chirho);
    harness_chirho
        .storage_chirho
        .append_durable_chirho(
            &journal_path_chirho(),
            br#"{"schema_chirho":"torn-monitor-chirho"#,
        )
        .unwrap();
    let before_monitor_chirho = harness_chirho
        .storage_chirho
        .objects_chirho
        .borrow()
        .clone();
    let monitor_source_chirho = JournalConservationSourceChirho {
        journal_ports_chirho: harness_chirho.journal_ports_chirho(),
        journal_path_chirho: journal_path_chirho(),
        cluster_chirho: cluster_chirho(),
        money_group_chirho: MoneyGroupIdChirho("mg-torn-monitor-chirho".to_string()),
    };

    assert_eq!(
        run_conservation_monitor_once_chirho(&monitor_source_chirho),
        Err(
            ConservationMonitorFailureChirho::VerifiedSnapshotUnavailableChirho(
                JournalConservationSourceErrorChirho::JournalOpenChirho(
                    JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
                        reason_chirho: ReadOnlyRecoveryReasonChirho::TornTailChirho,
                    }
                )
            )
        )
    );
    assert_eq!(
        *harness_chirho.storage_chirho.objects_chirho.borrow(),
        before_monitor_chirho,
        "the conservation consumer must not truncate the torn journal it audits"
    );
}
