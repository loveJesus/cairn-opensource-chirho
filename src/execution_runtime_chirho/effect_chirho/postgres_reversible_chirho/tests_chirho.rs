// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::model_chirho::{DagChirho, HashChirho, NodeDefChirho, PortChirho};
use cairn_effect_commit_chirho::intent_chirho::EffectIntentSignerPortChirho;
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, CurrentContinuationPolicyChirho,
    IdempotencyWindowPolicyViewChirho, KindPolicyViewChirho, KindRegistryViewChirho,
    KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho, MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, AssetKindRefChirho, ClusterIdChirho};
use cairn_ledger_model_chirho::record_chirho::{LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::ShardEpochChirho;
use cairn_postgres_effect_chirho::ports_chirho::{
    AuthenticatedCompensationReceiptRowChirho, AuthenticatedForwardDecisionRowChirho,
    DatabasePortErrorChirho, DatabaseValueChirho, ReversiblePostgresTransactionPortChirho,
    SensitiveBytesChirho,
};
use cairn_postgres_effect_chirho::{
    canonical_request_bytes_chirho, install_reversible_postgres_schema_chirho,
    DesiredPostgresStateChirho, ExpectedPostgresStateChirho, PostgresDatabaseChirho,
    ReversiblePostgresRequestChirho,
};
use postgres::{Client, NoTls};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const MONEY_KIND_CHIRHO: &str = "money-chirho";
const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const MINT_EVIDENCE_CHIRHO: &str = "mint-authority-v1-chirho";
pub(super) const SETTLEMENT_OWNER_CHIRHO: &str = "platform-chirho";
const DEFAULT_POSTGRES_TEST_CONFIG_CHIRHO: &str = "host=/tmp port=5432 dbname=postgres";
pub(super) static APP_PRICE_POLICY_CHIRHO: AppPriceBookUserPaysPolicyChirho =
    AppPriceBookUserPaysPolicyChirho;

struct LocalPostgresSchemaGuardChirho {
    connection_config_chirho: String,
    schema_chirho: String,
}

impl Drop for LocalPostgresSchemaGuardChirho {
    fn drop(&mut self) {
        if let Ok(mut client_chirho) = Client::connect(&self.connection_config_chirho, NoTls) {
            let _ = client_chirho.batch_execute(&format!(
                "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
                self.schema_chirho
            ));
        }
    }
}

#[derive(Default)]
pub(super) struct MemoryLedgerStorageChirho {
    objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl MemoryLedgerStorageChirho {
    pub(super) fn snapshot_chirho(&self) -> BTreeMap<String, Vec<u8>> {
        self.objects_chirho.borrow().clone()
    }
}

impl LedgerStoragePortChirho for MemoryLedgerStorageChirho {
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
            .ok_or_else(|| anyhow::anyhow!("missing ledger object"))?;
        let end_chirho = offset_chirho
            .checked_add(len_chirho)
            .ok_or_else(|| anyhow::anyhow!("ledger range overflow"))?;
        if end_chirho > bytes_chirho.len() as u64 {
            anyhow::bail!("ledger range exceeds object");
        }
        Ok(bytes_chirho[offset_chirho as usize..end_chirho as usize].to_vec())
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
        new_len_chirho: u64,
    ) -> anyhow::Result<()> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .get_mut(&path_chirho.0)
            .ok_or_else(|| anyhow::anyhow!("missing ledger object"))?;
        if new_len_chirho > bytes_chirho.len() as u64 {
            anyhow::bail!("ledger truncate can only shorten");
        }
        bytes_chirho.truncate(new_len_chirho as usize);
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
            .ok_or_else(|| anyhow::anyhow!("missing ledger rename source"))?;
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

struct TestClockChirho {
    now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for TestClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.get()
    }
}

pub(super) struct TestRootChirho {
    name_chirho: &'static str,
}

impl TestRootChirho {
    fn signature_chirho(&self, content_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(self.name_chirho.as_bytes());
        hasher_chirho.update(content_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

macro_rules! impl_test_signer_chirho {
    ($trait_chirho:path) => {
        impl $trait_chirho for TestRootChirho {
            fn sign_chirho(&self, content_chirho: &str) -> anyhow::Result<String> {
                Ok(self.signature_chirho(content_chirho))
            }

            fn key_id_chirho(&self) -> String {
                format!("{}-key-chirho", self.name_chirho)
            }

            fn verify_chirho(&self, content_chirho: &str, sig_chirho: &str) -> bool {
                sig_chirho == self.signature_chirho(content_chirho)
            }
        }
    };
}

impl_test_signer_chirho!(LedgerSignerPortChirho);
impl_test_signer_chirho!(EffectIntentSignerPortChirho);
impl_test_signer_chirho!(EffectTerminalSignerPortChirho);

struct TestMembershipChirho {
    owners_chirho: BTreeSet<String>,
}

impl MembershipViewChirho for TestMembershipChirho {
    fn status_chirho(
        &self,
        account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        if self.owners_chirho.contains(&account_chirho.owner_chirho) {
            MembershipStatusChirho::MemberChirho
        } else {
            MembershipStatusChirho::NonMemberChirho
        }
    }
}

struct TestKindRegistryChirho;

impl TestKindRegistryChirho {
    fn policy_chirho(&self) -> KindPolicyViewChirho {
        KindPolicyViewChirho {
            kind_id_chirho: MONEY_KIND_CHIRHO.into(),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(1_000),
            },
            rounding_chirho: RoundingChirho::ExactChirho,
            settlement_owner_chirho: Some(SETTLEMENT_OWNER_CHIRHO.to_owned()),
            idempotency_window_chirho: Some(IdempotencyWindowPolicyViewChirho {
                idempotency_horizon_ms_chirho: 10_000,
                retry_finality_horizon_ms_chirho: 5_000,
            }),
        }
    }
}

impl KindRegistryViewChirho for TestKindRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        if policy_ref_chirho.0 .0 == MONEY_POLICY_REF_CHIRHO {
            KindResolutionChirho::CurrentChirho(self.policy_chirho())
        } else {
            KindResolutionChirho::UnknownChirho
        }
    }

    fn resolve_current_continuation_by_kind_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Option<CurrentContinuationPolicyChirho> {
        (kind_id_chirho.0 == MONEY_KIND_CHIRHO).then(|| CurrentContinuationPolicyChirho {
            kind_policy_ref_chirho: policy_ref_chirho(),
            policy_chirho: self.policy_chirho(),
        })
    }
}

struct TestAuthorityChirho;

impl AuthorityVerifierViewChirho for TestAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        if evidence_chirho.0 == MINT_EVIDENCE_CHIRHO && kind_id_chirho.0 == MONEY_KIND_CHIRHO {
            AuthorityVerdictChirho::VerifiedChirho
        } else {
            AuthorityVerdictChirho::UnverifiedChirho
        }
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

pub(super) struct JournalHarnessChirho {
    pub(super) storage_chirho: MemoryLedgerStorageChirho,
    clock_chirho: TestClockChirho,
    ledger_root_chirho: TestRootChirho,
    pub(super) intent_root_chirho: TestRootChirho,
    pub(super) terminal_root_chirho: TestRootChirho,
    membership_chirho: TestMembershipChirho,
    registry_chirho: TestKindRegistryChirho,
    authority_chirho: TestAuthorityChirho,
}

impl JournalHarnessChirho {
    pub(super) fn new_chirho(payer_chirho: &str) -> Self {
        Self {
            storage_chirho: MemoryLedgerStorageChirho::default(),
            clock_chirho: TestClockChirho {
                now_ms_chirho: Cell::new(1_000),
            },
            ledger_root_chirho: TestRootChirho {
                name_chirho: "ledger-root-chirho",
            },
            intent_root_chirho: TestRootChirho {
                name_chirho: "intent-root-chirho",
            },
            terminal_root_chirho: TestRootChirho {
                name_chirho: "terminal-root-chirho",
            },
            membership_chirho: TestMembershipChirho {
                owners_chirho: [
                    "issuer-chirho".to_owned(),
                    payer_chirho.to_owned(),
                    SETTLEMENT_OWNER_CHIRHO.to_owned(),
                ]
                .into_iter()
                .collect(),
            },
            registry_chirho: TestKindRegistryChirho,
            authority_chirho: TestAuthorityChirho,
        }
    }

    fn ports_chirho(&self) -> JournalPortsChirho<'_> {
        JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: &self.ledger_root_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }

    pub(super) fn funded_journal_chirho(&self, payer_chirho: &str) -> LedgerJournalChirho<'_> {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            self.ports_chirho(),
            StoragePathChirho::new_chirho("journals/descriptor-d-chirho.jsonl"),
            ClusterIdChirho("cluster-descriptor-d-chirho".to_owned()),
            1,
        )
        .unwrap();
        self.clock_chirho.now_ms_chirho.set(1_100);
        journal_chirho.append_chirho(mint_request_chirho()).unwrap();
        self.clock_chirho.now_ms_chirho.set(1_200);
        journal_chirho
            .append_chirho(fund_request_chirho(payer_chirho))
            .unwrap();
        journal_chirho
    }
}

fn policy_ref_chirho() -> AssetKindRefChirho {
    AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.to_owned()))
}

fn account_chirho(owner_chirho: &str) -> AccountIdChirho {
    LogIdChirho::new_chirho(owner_chirho, MONEY_KIND_CHIRHO)
}

fn mint_request_chirho() -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(MINT_EVIDENCE_CHIRHO.to_owned()),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: account_chirho("issuer-chirho"),
            kind_policy_ref_chirho: policy_ref_chirho(),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 500,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: "descriptor-d-mint-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

fn fund_request_chirho(payer_chirho: &str) -> AppendRequestChirho {
    let leg_chirho = |owner_chirho: &str, delta_chirho: LegDeltaChirho| AppendLegRequestChirho {
        account_chirho: account_chirho(owner_chirho),
        kind_policy_ref_chirho: policy_ref_chirho(),
        delta_chirho,
        amount_chirho: 100,
        counterpart_chirho: None,
    };
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::TransferChirho,
        legs_chirho: vec![
            leg_chirho("issuer-chirho", LegDeltaChirho::DebitChirho),
            leg_chirho(payer_chirho, LegDeltaChirho::CreditChirho),
        ],
        idempotency_key_chirho: "descriptor-d-fund-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct MemoryPostgresDatabaseChirho {
    schema_ready_chirho: bool,
    rows_chirho: BTreeMap<(HashChirho, HashChirho), Vec<u8>>,
    decisions_chirho: BTreeMap<String, AuthenticatedForwardDecisionRowChirho>,
    compensations_chirho: BTreeMap<HashChirho, AuthenticatedCompensationReceiptRowChirho>,
    compensation_by_original_chirho: BTreeMap<HashChirho, HashChirho>,
    committed_transactions_chirho: usize,
    fail_next_begin_chirho: bool,
    lose_next_commit_ack_chirho: bool,
}

impl MemoryPostgresDatabaseChirho {
    pub(super) fn ready_chirho() -> Self {
        Self {
            schema_ready_chirho: true,
            ..Self::default()
        }
    }

    pub(super) fn set_row_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) {
        self.rows_chirho.insert(
            (subject_chirho.clone(), row_key_chirho.clone()),
            bytes_chirho.to_vec(),
        );
    }

    pub(super) fn row_bytes_chirho(
        &self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Option<&[u8]> {
        self.rows_chirho
            .get(&(subject_chirho.clone(), row_key_chirho.clone()))
            .map(Vec::as_slice)
    }

    pub(super) fn compensation_count_chirho(&self) -> usize {
        self.compensations_chirho.len()
    }

    pub(super) fn lose_next_commit_ack_chirho(&mut self) {
        self.lose_next_commit_ack_chirho = true;
    }
}

pub(super) struct MemoryPostgresTransactionChirho<'database_chirho> {
    database_chirho: &'database_chirho mut MemoryPostgresDatabaseChirho,
    rows_chirho: BTreeMap<(HashChirho, HashChirho), Vec<u8>>,
    decisions_chirho: BTreeMap<String, AuthenticatedForwardDecisionRowChirho>,
    compensations_chirho: BTreeMap<HashChirho, AuthenticatedCompensationReceiptRowChirho>,
    compensation_by_original_chirho: BTreeMap<HashChirho, HashChirho>,
}

impl ReversiblePostgresDatabasePortChirho for MemoryPostgresDatabaseChirho {
    type TransactionChirho<'database_chirho>
        = MemoryPostgresTransactionChirho<'database_chirho>
    where
        Self: 'database_chirho;

    fn verify_schema_ready_chirho(&mut self) -> Result<(), DatabasePortErrorChirho> {
        if self.schema_ready_chirho {
            Ok(())
        } else {
            Err(DatabasePortErrorChirho::PermanentChirho {
                detail_chirho: "decision constraint floor is unavailable".to_owned(),
            })
        }
    }

    fn begin_serializable_transaction_chirho(
        &mut self,
    ) -> Result<Self::TransactionChirho<'_>, DatabasePortErrorChirho> {
        if self.fail_next_begin_chirho {
            self.fail_next_begin_chirho = false;
            return Err(DatabasePortErrorChirho::PermanentChirho {
                detail_chirho: "transport failed before transaction begin".to_owned(),
            });
        }
        Ok(MemoryPostgresTransactionChirho {
            rows_chirho: self.rows_chirho.clone(),
            decisions_chirho: self.decisions_chirho.clone(),
            compensations_chirho: self.compensations_chirho.clone(),
            compensation_by_original_chirho: self.compensation_by_original_chirho.clone(),
            database_chirho: self,
        })
    }
}

impl ReversiblePostgresTransactionPortChirho for MemoryPostgresTransactionChirho<'_> {
    fn lock_forward_idempotency_key_chirho(
        &mut self,
        _effect_intent_key_chirho: &str,
    ) -> Result<(), DatabasePortErrorChirho> {
        Ok(())
    }

    fn lock_compensation_idempotency_key_chirho(
        &mut self,
        _compensation_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        Ok(())
    }

    fn lock_original_effect_compensation_chirho(
        &mut self,
        _original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        Ok(())
    }

    fn lock_row_chirho(
        &mut self,
        _subject_chirho: &HashChirho,
        _row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        Ok(())
    }

    fn load_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho> {
        Ok(self.decisions_chirho.get(effect_intent_key_chirho).cloned())
    }

    fn load_forward_decision_by_idem_key_chirho(
        &mut self,
        effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho> {
        Ok(self
            .decisions_chirho
            .values()
            .find(|row_chirho| row_chirho.effect_idem_key_chirho == *effect_idem_key_chirho)
            .cloned())
    }

    fn load_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho> {
        Ok(self
            .compensations_chirho
            .get(compensation_idem_key_chirho)
            .cloned())
    }

    fn load_compensation_receipt_by_original_effect_chirho(
        &mut self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho> {
        Ok(self
            .compensation_by_original_chirho
            .get(original_effect_idem_key_chirho)
            .and_then(|key_chirho| self.compensations_chirho.get(key_chirho))
            .cloned())
    }

    fn load_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<Option<DatabaseValueChirho>, DatabasePortErrorChirho> {
        Ok(self
            .rows_chirho
            .get(&(subject_chirho.clone(), row_key_chirho.clone()))
            .cloned()
            .map(|bytes_chirho| DatabaseValueChirho {
                value_chirho: SensitiveBytesChirho::new_chirho(bytes_chirho),
            }))
    }

    fn upsert_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
        value_chirho: &[u8],
    ) -> Result<(), DatabasePortErrorChirho> {
        self.rows_chirho.insert(
            (subject_chirho.clone(), row_key_chirho.clone()),
            value_chirho.to_vec(),
        );
        Ok(())
    }

    fn delete_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        self.rows_chirho
            .remove(&(subject_chirho.clone(), row_key_chirho.clone()));
        Ok(())
    }

    fn insert_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
        row_chirho: &AuthenticatedForwardDecisionRowChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        if self.decisions_chirho.contains_key(effect_intent_key_chirho)
            || self.decisions_chirho.values().any(|existing_chirho| {
                existing_chirho.effect_idem_key_chirho == row_chirho.effect_idem_key_chirho
            })
        {
            return Err(DatabasePortErrorChirho::PermanentChirho {
                detail_chirho: "duplicate forward decision coordinate".to_owned(),
            });
        }
        self.decisions_chirho
            .insert(effect_intent_key_chirho.to_owned(), row_chirho.clone());
        Ok(())
    }

    fn insert_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
        row_chirho: &AuthenticatedCompensationReceiptRowChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        if self
            .compensations_chirho
            .contains_key(compensation_idem_key_chirho)
            || self
                .compensation_by_original_chirho
                .contains_key(&row_chirho.original_effect_idem_key_chirho)
        {
            return Err(DatabasePortErrorChirho::PermanentChirho {
                detail_chirho: "duplicate compensation coordinate".to_owned(),
            });
        }
        self.compensation_by_original_chirho.insert(
            row_chirho.original_effect_idem_key_chirho.clone(),
            compensation_idem_key_chirho.clone(),
        );
        self.compensations_chirho
            .insert(compensation_idem_key_chirho.clone(), row_chirho.clone());
        Ok(())
    }

    fn commit_chirho(self) -> Result<(), DatabasePortErrorChirho> {
        let lose_ack_chirho = self.database_chirho.lose_next_commit_ack_chirho;
        self.database_chirho.rows_chirho = self.rows_chirho;
        self.database_chirho.decisions_chirho = self.decisions_chirho;
        self.database_chirho.compensations_chirho = self.compensations_chirho;
        self.database_chirho.compensation_by_original_chirho = self.compensation_by_original_chirho;
        self.database_chirho.committed_transactions_chirho += 1;
        self.database_chirho.lose_next_commit_ack_chirho = false;
        if lose_ack_chirho {
            Err(DatabasePortErrorChirho::PermanentChirho {
                detail_chirho: "commit acknowledgement lost after apply".to_owned(),
            })
        } else {
            Ok(())
        }
    }
}

pub(super) fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-descriptor-d-test-{nanos_chirho}-{counter_chirho}-chirho"
    ))
}

pub(super) fn setup_context_chirho(root_chirho: &Path) -> RequestContextChirho {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let user_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho = crate::cas_chirho::add_chirho(root_chirho, b"descriptor-d-node").unwrap();
    let dag_chirho = crate::store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        root_chirho,
        "descriptor-d-test-chirho",
        dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    let (price_book_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        root_chirho,
        "descriptor-d-test-chirho",
        &owner_chirho,
        None,
        BTreeMap::from([(POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_owned(), 17)]),
        0,
    )
    .unwrap();
    RequestContextChirho {
        user_principal_chirho: user_chirho,
        app_chirho: "descriptor-d-test-chirho".to_owned(),
        owner_principal_chirho: owner_chirho,
        client_id_chirho: "client-descriptor-d-chirho".to_owned(),
        token_hash_chirho: "token-descriptor-d-chirho".to_owned(),
        price_book_chirho: Some(price_book_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

pub(super) fn postgres_node_chirho() -> NodeDefChirho {
    NodeDefChirho {
        name_chirho: "descriptor-d-postgres-node-chirho".to_owned(),
        impl_wasm_chirho: HashChirho("builtin:descriptor-d-postgres-chirho".to_owned()),
        entry_chirho: "descriptor_d_postgres_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: HashChirho("bytes".to_owned()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: HashChirho("bytes".to_owned()),
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            caller_chirho: "descriptor-d-runtime-chirho".to_owned(),
        }],
        fuel_limit_chirho: 0,
        effect_contract_set_chirho: Some(
            crate::provider_test_support_chirho::current_effect_contract_set_chirho(),
        ),
        ..NodeDefChirho::default()
    }
}

pub(super) fn request_bytes_chirho(root_chirho: &Path) -> (Vec<u8>, HashChirho, HashChirho) {
    let subject_chirho = HashChirho("a".repeat(64));
    let row_key_chirho = HashChirho("b".repeat(64));
    let value_ref_chirho = crate::privacy_chirho::store_private_blob_chirho(
        root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            &subject_chirho.0,
        ),
        &subject_chirho.0,
        b"descriptor-d-new-value-chirho",
    )
    .unwrap();
    let bytes_chirho = canonical_request_bytes_chirho(&ReversiblePostgresRequestChirho {
        schema_chirho: "reversible-postgres-request-v1-chirho".to_owned(),
        subject_chirho: subject_chirho.clone(),
        row_key_chirho: row_key_chirho.clone(),
        expected_before_chirho: ExpectedPostgresStateChirho::AbsentChirho,
        desired_chirho: DesiredPostgresStateChirho::PresentChirho { value_ref_chirho },
    })
    .unwrap();
    (bytes_chirho, subject_chirho, row_key_chirho)
}

pub(super) struct ScopedPostgresNodeInputsChirho<'a> {
    pub(super) root_chirho: &'a Path,
    pub(super) node_chirho: &'a NodeDefChirho,
    pub(super) node_hash_chirho: &'a HashChirho,
    pub(super) input_hash_chirho: &'a HashChirho,
    pub(super) context_chirho: &'a RequestContextChirho,
    pub(super) run_chirho: &'a HashChirho,
}

pub(super) fn run_scoped_postgres_node_chirho(
    inputs_chirho: &ScopedPostgresNodeInputsChirho<'_>,
    replay_chirho: bool,
    runtime_chirho: &mut dyn PostgresReversibleRuntimePortChirho,
) -> anyhow::Result<(crate::model_chirho::RunResultChirho, bool)> {
    super::super::run_intent_chirho::with_run_intent_execution_chirho(
        inputs_chirho.run_chirho,
        replay_chirho,
        || {
            super::super::run_intent_chirho::with_run_intent_effect_invocation_chirho(
                inputs_chirho.node_hash_chirho,
                0,
                || {
                    crate::cache_chirho::run_effect_node_cached_with_context_and_postgres_runtime_chirho(
                        inputs_chirho.root_chirho,
                        inputs_chirho.node_chirho,
                        inputs_chirho.node_hash_chirho,
                        inputs_chirho.input_hash_chirho,
                        &[],
                        Some(inputs_chirho.context_chirho),
                        runtime_chirho,
                    )
                },
            )
        },
    )
}

#[test]
fn bootstrap_and_custody_refuse_typed_before_any_intent_chirho() {
    let root_chirho = tmp_root_chirho();
    let harness_chirho = JournalHarnessChirho::new_chirho("payer-chirho");
    let mut journal_chirho = harness_chirho.funded_journal_chirho("payer-chirho");
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let mut missing_schema_chirho = MemoryPostgresDatabaseChirho::default();
    let schema_error_chirho = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        match LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut missing_schema_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        ) {
            Ok(_) => panic!("missing decision constraint floor must refuse"),
            Err(error_chirho) => error_chirho,
        }
    };
    assert!(matches!(
        schema_error_chirho.downcast_ref::<PostgresReversibleActivationErrorChirho>(),
        Some(PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho { .. })
    ));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho);
    assert!(!root_chirho.join("effect-commit-evidence-chirho").exists());

    let mut missing_kind_chirho = MemoryPostgresDatabaseChirho::ready_chirho();
    let kind_error_chirho = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        match LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut missing_kind_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho("missing-billing-kind-chirho".to_owned()),
        ) {
            Ok(_) => panic!("missing billing kind must refuse"),
            Err(error_chirho) => error_chirho,
        }
    };
    assert!(matches!(
        kind_error_chirho.downcast_ref::<PostgresReversibleActivationErrorChirho>(),
        Some(PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho { .. })
    ));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho);
    assert!(!root_chirho.join("effect-commit-evidence-chirho").exists());

    let mut missing_key_chirho = MemoryPostgresDatabaseChirho::ready_chirho();
    let key_error_chirho = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        match LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut missing_key_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        ) {
            Ok(_) => panic!("missing evidence key must refuse"),
            Err(error_chirho) => error_chirho,
        }
    };
    assert!(matches!(
        key_error_chirho.downcast_ref::<PostgresReversibleActivationErrorChirho>(),
        Some(PostgresReversibleActivationErrorChirho::CustodyUnavailableChirho { .. })
    ));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho);
    assert!(!root_chirho.join("effect-commit-evidence-chirho").exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn first_caller_sources_one_evidence_key_without_ambient_authority_chirho() {
    let source_chirho = include_str!("../postgres_reversible_chirho.rs");
    for forbidden_chirho in [
        "std::env::",
        "env::var(",
        "env::var_os(",
        "set_secret_chirho(",
        "AdapterEvidenceKeyChirho {",
    ] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "Descriptor-D first caller gained ambient or self-minted key authority via {forbidden_chirho}"
        );
    }
    assert_eq!(
        source_chirho.matches("resolve_secret_ref_chirho(").count(),
        1,
        "the first caller must have exactly one secret-store evidence-key source"
    );
    assert_eq!(
        source_chirho
            .matches("AdapterEvidenceKeyChirho::new_chirho(")
            .count(),
        1,
        "the resolved 32-byte value enters exactly one redacted key wrapper"
    );
}

#[test]
fn postgres_coordinate_has_exactly_one_production_router_call_chirho() {
    let callers_chirho = crate::source_scan_chirho::production_source_lines_matching_chirho(
        "run_postgres_reversible_chirho(",
    );
    assert_eq!(
        callers_chirho.len(),
        2,
        "Descriptor-D must have one definition and one production router call: {callers_chirho:?}"
    );
    assert!(callers_chirho
        .iter()
        .any(|(path_chirho, _, line_chirho)| path_chirho
            == "src/execution_runtime_chirho/effect_chirho/postgres_reversible_chirho.rs"
            && line_chirho == "pub(crate) fn run_postgres_reversible_chirho("));
    assert!(callers_chirho
        .iter()
        .any(|(path_chirho, _, line_chirho)| path_chirho
            == "src/execution_runtime_chirho/effect_chirho.rs"
            && line_chirho == "postgres_reversible_chirho::run_postgres_reversible_chirho("));
}

#[test]
fn invocation_binding_converges_without_the_run_lock_chirho() {
    let root_chirho = tmp_root_chirho();
    let invocation_ref_chirho = HashChirho("7".repeat(64));
    let barrier_chirho = Arc::new(Barrier::new(3));
    let candidates_chirho = [
        "candidate-intent-a-chirho".to_owned(),
        "candidate-intent-b-chirho".to_owned(),
    ];
    let workers_chirho = candidates_chirho
        .clone()
        .into_iter()
        .map(|candidate_chirho| {
            let worker_root_chirho = root_chirho.clone();
            let worker_ref_chirho = invocation_ref_chirho.clone();
            let worker_barrier_chirho = barrier_chirho.clone();
            std::thread::spawn(move || {
                worker_barrier_chirho.wait();
                create_or_load_invocation_intent_line_chirho(
                    &worker_root_chirho,
                    &worker_ref_chirho,
                    &candidate_chirho,
                )
                .unwrap()
            })
        })
        .collect::<Vec<_>>();
    barrier_chirho.wait();
    let loaded_chirho = workers_chirho
        .into_iter()
        .map(|worker_chirho| worker_chirho.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(loaded_chirho[0], loaded_chirho[1]);
    assert!(candidates_chirho.contains(&loaded_chirho[0]));
    assert_eq!(
        std::fs::read_dir(root_chirho.join("effect-commit-evidence-chirho/invocations-chirho"))
            .unwrap()
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn same_invocation_executes_and_meters_once_over_real_journal_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let node_chirho = postgres_node_chirho();
    let node_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let (request_bytes_chirho, subject_chirho, row_key_chirho) = request_bytes_chirho(&root_chirho);
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let mut database_chirho = MemoryPostgresDatabaseChirho::ready_chirho();
    let run_chirho = HashChirho("9".repeat(64));

    let (first_chirho, first_cached_chirho, second_chirho, second_cached_chirho) = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut runtime_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut database_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        )
        .unwrap();
        let (first_chirho, first_cached_chirho) = run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            false,
            &mut runtime_chirho,
        )
        .unwrap();
        let (second_chirho, second_cached_chirho) = run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            true,
            &mut runtime_chirho,
        )
        .unwrap();
        (
            first_chirho,
            first_cached_chirho,
            second_chirho,
            second_cached_chirho,
        )
    };

    assert!(!first_cached_chirho);
    assert!(!second_cached_chirho);
    let first_response_chirho = crate::cas_chirho::get_chirho(
        &root_chirho,
        first_chirho.outputs_chirho.get("out").unwrap(),
    )
    .unwrap();
    let second_response_chirho = crate::cas_chirho::get_chirho(
        &root_chirho,
        second_chirho.outputs_chirho.get("out").unwrap(),
    )
    .unwrap();
    assert_eq!(
        first_response_chirho, second_response_chirho,
        "same invocation must return the original terminal response bytes"
    );
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert!(journal_chirho.active_holds_chirho().is_empty());
    let payer_state_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .unwrap();
    assert_eq!(payer_state_chirho.credits_total_chirho, 100);
    assert_eq!(payer_state_chirho.debits_total_chirho, 17);
    assert_eq!(payer_state_chirho.held_chirho, 0);
    let settlement_state_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
        .unwrap();
    assert_eq!(settlement_state_chirho.credits_total_chirho, 17);
    assert_eq!(database_chirho.decisions_chirho.len(), 1);
    assert_eq!(
        database_chirho
            .rows_chirho
            .get(&(subject_chirho, row_key_chirho))
            .map(Vec::as_slice),
        Some(b"descriptor-d-new-value-chirho".as_slice())
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(
        std::fs::read_dir(root_chirho.join("effects-chirho"))
            .unwrap()
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[path = "money_policy_tests_chirho.rs"]
mod money_policy_tests_chirho;

#[test]
fn commit_ack_loss_queries_by_k_immediately_and_meters_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let node_chirho = postgres_node_chirho();
    let node_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let (request_bytes_chirho, subject_chirho, row_key_chirho) = request_bytes_chirho(&root_chirho);
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let mut database_chirho = MemoryPostgresDatabaseChirho {
        lose_next_commit_ack_chirho: true,
        ..MemoryPostgresDatabaseChirho::ready_chirho()
    };
    let run_chirho = HashChirho("6".repeat(64));

    let first_chirho = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut runtime_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut database_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        )
        .unwrap();
        run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            false,
            &mut runtime_chirho,
        )
        .unwrap()
        .0
    };
    assert!(first_chirho.outputs_chirho.contains_key("out"));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert!(journal_chirho.active_holds_chirho().is_empty());
    assert_eq!(database_chirho.decisions_chirho.len(), 1);

    let replayed_chirho = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut runtime_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut database_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        )
        .unwrap();
        run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            true,
            &mut runtime_chirho,
        )
        .unwrap()
        .0
    };

    assert!(replayed_chirho.outputs_chirho.contains_key("out"));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert!(journal_chirho.active_holds_chirho().is_empty());
    assert_eq!(database_chirho.decisions_chirho.len(), 1);
    assert_eq!(
        database_chirho
            .rows_chirho
            .get(&(subject_chirho, row_key_chirho))
            .map(Vec::as_slice),
        Some(b"descriptor-d-new-value-chirho".as_slice())
    );
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .unwrap()
            .credits_total_chirho,
        17
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pre_mutation_ambiguity_queries_durable_absence_and_releases_unmetered_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let node_chirho = postgres_node_chirho();
    let node_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let (request_bytes_chirho, subject_chirho, row_key_chirho) = request_bytes_chirho(&root_chirho);
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let mut database_chirho = MemoryPostgresDatabaseChirho {
        fail_next_begin_chirho: true,
        ..MemoryPostgresDatabaseChirho::ready_chirho()
    };
    let run_chirho = HashChirho("5".repeat(64));

    let result_chirho = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut runtime_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut database_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        )
        .unwrap();
        run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            false,
            &mut runtime_chirho,
        )
        .unwrap()
        .0
    };
    assert!(result_chirho.outputs_chirho.contains_key("out"));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert!(journal_chirho.active_holds_chirho().is_empty());
    assert_eq!(database_chirho.decisions_chirho.len(), 1);
    assert!(!database_chirho
        .rows_chirho
        .contains_key(&(subject_chirho, row_key_chirho)));
    assert!(journal_chirho
        .head_states_chirho()
        .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
        .is_none());
    let payer_state_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .unwrap();
    assert_eq!(payer_state_chirho.debits_total_chirho, 0);
    assert_eq!(payer_state_chirho.held_chirho, 0);
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
#[ignore = "requires the explicitly sanctioned local Homebrew PostgreSQL server"]
fn local_postgres_composition_executes_and_meters_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let node_chirho = postgres_node_chirho();
    let node_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let (request_bytes_chirho, subject_chirho, row_key_chirho) = request_bytes_chirho(&root_chirho);
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let run_chirho = HashChirho("8".repeat(64));

    let connection_config_chirho = std::env::var("CAIRN_POSTGRES_TEST_CONFIG_CHIRHO")
        .unwrap_or_else(|_| DEFAULT_POSTGRES_TEST_CONFIG_CHIRHO.to_owned());
    let schema_chirho = format!(
        "cairn_descriptor_d_atom_{}_{}_chirho",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let mut setup_chirho = Client::connect(&connection_config_chirho, NoTls).unwrap();
    setup_chirho
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS \"{schema_chirho}\" CASCADE; CREATE SCHEMA \"{schema_chirho}\"; SET search_path TO \"{schema_chirho}\""
        ))
        .unwrap();
    install_reversible_postgres_schema_chirho(&mut setup_chirho).unwrap();
    drop(setup_chirho);
    let _schema_guard_chirho = LocalPostgresSchemaGuardChirho {
        connection_config_chirho: connection_config_chirho.clone(),
        schema_chirho: schema_chirho.clone(),
    };
    let mut provider_client_chirho = Client::connect(&connection_config_chirho, NoTls).unwrap();
    provider_client_chirho
        .batch_execute(&format!("SET search_path TO \"{schema_chirho}\""))
        .unwrap();
    let mut database_chirho = PostgresDatabaseChirho::from_client_chirho(provider_client_chirho);

    let (first_chirho, second_chirho) = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut runtime_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut database_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        )
        .unwrap();
        let first_chirho = run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            false,
            &mut runtime_chirho,
        )
        .unwrap()
        .0;
        let second_chirho = run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            true,
            &mut runtime_chirho,
        )
        .unwrap()
        .0;
        (first_chirho, second_chirho)
    };

    assert_eq!(
        crate::cas_chirho::get_chirho(
            &root_chirho,
            first_chirho.outputs_chirho.get("out").unwrap()
        )
        .unwrap(),
        crate::cas_chirho::get_chirho(
            &root_chirho,
            second_chirho.outputs_chirho.get("out").unwrap()
        )
        .unwrap()
    );
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert!(journal_chirho.active_holds_chirho().is_empty());
    let mut inspect_chirho = Client::connect(&connection_config_chirho, NoTls).unwrap();
    inspect_chirho
        .batch_execute(&format!("SET search_path TO \"{schema_chirho}\""))
        .unwrap();
    let stored_value_chirho: Vec<u8> = inspect_chirho
        .query_one(
            "SELECT value_chirho FROM cairn_reversible_values_chirho WHERE subject_chirho = $1 AND row_key_chirho = $2",
            &[&subject_chirho.0, &row_key_chirho.0],
        )
        .unwrap()
        .get("value_chirho");
    let decision_count_chirho: i64 = inspect_chirho
        .query_one(
            "SELECT COUNT(*) FROM cairn_reversible_forward_decisions_chirho",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored_value_chirho, b"descriptor-d-new-value-chirho");
    assert_eq!(decision_count_chirho, 1);
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .unwrap()
            .credits_total_chirho,
        17
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
