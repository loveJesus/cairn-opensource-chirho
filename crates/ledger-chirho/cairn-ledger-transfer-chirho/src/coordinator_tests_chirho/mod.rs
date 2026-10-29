// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The CF2 acceptance spine (#4901 d): the saga-grain crash matrix over REAL two-journal
//! composition — crash at EVERY saga-log append boundary, resume, final state equals the
//! uncrashed golden; Σ(net per kind, counting held) constant at EVERY cut; TTL expiry
//! compensates; torn saga tails repair; foreign/tampered saga lines refuse. Event-based only.

use crate::coordinator_chirho::{
    net_units_by_kind_chirho, SagaCoordinatorChirho, SagaJournalRouterChirho,
};
use crate::log_chirho::load_saga_log_chirho;
use crate::record_chirho::{SagaOutcomeChirho, SagaStepPlanChirho};
use anyhow::{anyhow, Result};
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendReceiptChirho, AppendRequestChirho, JournalErrorChirho,
    JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::LogIdChirho;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

// ---- ports stubs ---------------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct MemoryStorageChirho {
    pub(crate) objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl LedgerStoragePortChirho for MemoryStorageChirho {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<cairn_ledger_log_chirho::ports_chirho::CreateDurableOutcomeChirho> {
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
    ) -> Result<()> {
        self.objects_chirho
            .borrow_mut()
            .entry(path_chirho.0.clone())
            .or_default()
            .extend_from_slice(bytes_chirho);
        Ok(())
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<Vec<u8>>> {
        Ok(self.objects_chirho.borrow().get(&path_chirho.0).cloned())
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>> {
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
    ) -> Result<Vec<u8>> {
        let objects_chirho = self.objects_chirho.borrow();
        let bytes_chirho = objects_chirho
            .get(&path_chirho.0)
            .ok_or_else(|| anyhow!("missing object"))?;
        let end_chirho = offset_chirho
            .checked_add(len_chirho)
            .ok_or_else(|| anyhow!("range overflow"))?;
        if end_chirho > bytes_chirho.len() as u64 {
            return Err(anyhow!("range past EOF"));
        }
        Ok(bytes_chirho[offset_chirho as usize..end_chirho as usize].to_vec())
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        self.objects_chirho
            .borrow_mut()
            .insert(path_chirho.0.clone(), bytes_chirho.to_vec());
        Ok(())
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        len_chirho: u64,
    ) -> Result<()> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .get_mut(&path_chirho.0)
            .ok_or_else(|| anyhow!("missing object"))?;
        bytes_chirho.truncate(len_chirho as usize);
        Ok(())
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> Result<()> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .remove(&from_chirho.0)
            .ok_or_else(|| anyhow!("missing object"))?;
        objects_chirho.insert(to_chirho.0.clone(), bytes_chirho);
        Ok(())
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()> {
        self.objects_chirho.borrow_mut().remove(&path_chirho.0);
        Ok(())
    }

    fn list_chirho(&self, prefix_chirho: &StoragePathChirho) -> Result<Vec<StoragePathChirho>> {
        Ok(self
            .objects_chirho
            .borrow()
            .keys()
            .filter(|key_chirho| key_chirho.starts_with(&prefix_chirho.0))
            .map(|key_chirho| StoragePathChirho(key_chirho.clone()))
            .collect())
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool> {
        Ok(self.objects_chirho.borrow().contains_key(&path_chirho.0))
    }
}

/// Wraps the saga-log storage and fails `append_durable` once the budget is spent — the crash cut.
struct CrashStorageChirho<'inner_chirho> {
    inner_chirho: &'inner_chirho MemoryStorageChirho,
    appends_left_chirho: Cell<Option<u32>>,
}

impl LedgerStoragePortChirho for CrashStorageChirho<'_> {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<cairn_ledger_log_chirho::ports_chirho::CreateDurableOutcomeChirho> {
        self.inner_chirho
            .create_durable_chirho(path_chirho, bytes_chirho)
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        if let Some(left_chirho) = self.appends_left_chirho.get() {
            if left_chirho == 0 {
                return Err(anyhow!("simulated crash at the saga-log append boundary"));
            }
            self.appends_left_chirho.set(Some(left_chirho - 1));
        }
        self.inner_chirho
            .append_durable_chirho(path_chirho, bytes_chirho)
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<Vec<u8>>> {
        self.inner_chirho.read_all_chirho(path_chirho)
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>> {
        self.inner_chirho.object_len_chirho(path_chirho)
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        self.inner_chirho
            .read_exact_range_chirho(path_chirho, offset_chirho, len_chirho)
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        self.inner_chirho
            .atomic_write_chirho(path_chirho, bytes_chirho)
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        len_chirho: u64,
    ) -> Result<()> {
        self.inner_chirho
            .truncate_durable_chirho(path_chirho, len_chirho)
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> Result<()> {
        self.inner_chirho.rename_chirho(from_chirho, to_chirho)
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()> {
        self.inner_chirho.remove_chirho(path_chirho)
    }

    fn list_chirho(&self, prefix_chirho: &StoragePathChirho) -> Result<Vec<StoragePathChirho>> {
        self.inner_chirho.list_chirho(prefix_chirho)
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool> {
        self.inner_chirho.exists_chirho(path_chirho)
    }
}

pub(crate) struct FakeJournalSignerChirho;

impl LedgerSignerPortChirho for FakeJournalSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(format!(
            "fake-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "journal-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

/// The coordinator's OWN root — a DIFFERENT scheme, so a journal-signed saga line can never verify.
pub(crate) struct SagaRootSignerChirho;

impl LedgerSignerPortChirho for SagaRootSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(format!(
            "saga-root-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "saga-root-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

pub(crate) struct SharedClockChirho {
    pub(crate) now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for SharedClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.get()
    }
}

struct OpenMembershipChirho;

impl MembershipViewChirho for OpenMembershipChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: cairn_ledger_model_chirho::ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

/// One kind per journal, settlement designated — the escrow-finalize shape.
struct OneKindRegistryChirho {
    /// A simulated mid-saga amend (#5127): Some((ref2, owner2)) makes the BASE ref resolve
    /// Superseded (the R1 that was current at hold time) while (ref2) resolves Current, and the
    /// continuation answers R2+owner2 — so a coordinator that reuses the plan's R1 ref strands.
    continuation_override_chirho: std::cell::RefCell<Option<(String, String)>>,
    kind_chirho: String,
    policy_ref_chirho: String,
    settlement_owner_chirho: String,
}

impl KindRegistryViewChirho for OneKindRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        let ref_chirho = &policy_ref_chirho.0 .0;
        let override_chirho = self.continuation_override_chirho.borrow();
        if let Some((amended_ref_chirho, amended_owner_chirho)) = override_chirho.as_ref() {
            if ref_chirho == &self.policy_ref_chirho {
                return KindResolutionChirho::SupersededChirho;
            }
            if ref_chirho == amended_ref_chirho {
                return KindResolutionChirho::CurrentChirho(
                    self.view_chirho(Some(amended_owner_chirho.clone())),
                );
            }
            return KindResolutionChirho::UnknownChirho;
        }
        if ref_chirho == &self.policy_ref_chirho {
            KindResolutionChirho::CurrentChirho(
                self.view_chirho(Some(self.settlement_owner_chirho.clone())),
            )
        } else {
            KindResolutionChirho::UnknownChirho
        }
    }

    fn resolve_current_continuation_by_kind_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Option<cairn_ledger_log_chirho::admission_chirho::CurrentContinuationPolicyChirho> {
        if kind_id_chirho.0 != self.kind_chirho {
            return None;
        }
        let (current_ref_chirho, current_owner_chirho) = self
            .continuation_override_chirho
            .borrow()
            .clone()
            .unwrap_or_else(|| {
                (
                    self.policy_ref_chirho.clone(),
                    self.settlement_owner_chirho.clone(),
                )
            });
        Some(
            cairn_ledger_log_chirho::admission_chirho::CurrentContinuationPolicyChirho {
                kind_policy_ref_chirho: AssetKindRefChirho(
                    cairn_ledger_model_chirho::ids_chirho::DigestChirho(current_ref_chirho),
                ),
                policy_chirho: self.view_chirho(Some(current_owner_chirho)),
            },
        )
    }
}

impl OneKindRegistryChirho {
    fn view_chirho(&self, settlement_owner_chirho: Option<String>) -> KindPolicyViewChirho {
        KindPolicyViewChirho {
            kind_id_chirho: AssetKindIdChirho(self.kind_chirho.clone()),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(100_000),
            },
            rounding_chirho: RoundingChirho::ExactChirho,
            settlement_owner_chirho,
            idempotency_window_chirho: None,
        }
    }
}

const MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";

struct MintAuthorityStubChirho {
    kind_chirho: String,
}

impl AuthorityVerifierViewChirho for MintAuthorityStubChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        if evidence_chirho.0 == MINT_EVIDENCE_CHIRHO && kind_id_chirho.0 == self.kind_chirho {
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

// ---- the two-journal fixture ---------------------------------------------------------------------

pub(crate) struct JournalFixtureChirho {
    pub(crate) storage_chirho: MemoryStorageChirho,
    pub(crate) signer_chirho: FakeJournalSignerChirho,
    membership_chirho: OpenMembershipChirho,
    registry_chirho: OneKindRegistryChirho,
    authority_chirho: MintAuthorityStubChirho,
    pub(crate) cluster_chirho: ClusterIdChirho,
    pub(crate) kind_chirho: String,
    pub(crate) policy_ref_chirho: String,
}

impl JournalFixtureChirho {
    pub(crate) fn new_chirho(
        cluster_chirho: &str,
        kind_chirho: &str,
        settlement_chirho: &str,
    ) -> Self {
        let policy_ref_chirho = format!("policy-{kind_chirho}");
        JournalFixtureChirho {
            storage_chirho: MemoryStorageChirho::default(),
            signer_chirho: FakeJournalSignerChirho,
            membership_chirho: OpenMembershipChirho,
            registry_chirho: OneKindRegistryChirho {
                kind_chirho: kind_chirho.to_owned(),
                policy_ref_chirho: policy_ref_chirho.clone(),
                settlement_owner_chirho: settlement_chirho.to_owned(),
                continuation_override_chirho: std::cell::RefCell::new(None),
            },
            authority_chirho: MintAuthorityStubChirho {
                kind_chirho: kind_chirho.to_owned(),
            },
            cluster_chirho: ClusterIdChirho(cluster_chirho.to_owned()),
            kind_chirho: kind_chirho.to_owned(),
            policy_ref_chirho,
        }
    }

    pub(crate) fn ports_chirho<'fixture_chirho>(
        &'fixture_chirho self,
        clock_chirho: &'fixture_chirho SharedClockChirho,
    ) -> JournalPortsChirho<'fixture_chirho> {
        JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: &self.signer_chirho,
            clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }

    /// Simulate a mid-saga amend R1 -> R2 (#5127): the base ref becomes Superseded and the
    /// continuation resolves to (ref2, owner2). A coordinator that reuses the plan's R1 strands.
    pub(crate) fn amend_continuation_chirho(&self, ref2_chirho: &str, owner2_chirho: &str) {
        *self
            .registry_chirho
            .continuation_override_chirho
            .borrow_mut() = Some((ref2_chirho.to_owned(), owner2_chirho.to_owned()));
    }

    pub(crate) fn path_chirho(&self) -> StoragePathChirho {
        StoragePathChirho(format!("journals/{}.jsonl", self.cluster_chirho.0))
    }

    pub(crate) fn mint_chirho(&self, amount_chirho: u64, idem_chirho: &str) -> AppendRequestChirho {
        AppendRequestChirho {
            op_chirho: LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho(MINT_EVIDENCE_CHIRHO.into()),
            },
            legs_chirho: vec![AppendLegRequestChirho {
                account_chirho: LogIdChirho::new_chirho("issuer-chirho", self.kind_chirho.as_str()),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    self.policy_ref_chirho.clone(),
                )),
                delta_chirho: LegDeltaChirho::CreditChirho,
                amount_chirho,
                counterpart_chirho: None,
            }],
            idempotency_key_chirho: idem_chirho.to_owned(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
        }
    }

    pub(crate) fn transfer_chirho(
        &self,
        from_chirho: &str,
        to_chirho: &str,
        amount_chirho: u64,
        idem_chirho: &str,
    ) -> AppendRequestChirho {
        let leg_chirho = |owner_chirho: &str, delta_chirho| AppendLegRequestChirho {
            account_chirho: LogIdChirho::new_chirho(owner_chirho, self.kind_chirho.as_str()),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                self.policy_ref_chirho.clone(),
            )),
            delta_chirho,
            amount_chirho,
            counterpart_chirho: None,
        };
        AppendRequestChirho {
            op_chirho: LedgerOpChirho::TransferChirho,
            legs_chirho: vec![
                leg_chirho(from_chirho, LegDeltaChirho::DebitChirho),
                leg_chirho(to_chirho, LegDeltaChirho::CreditChirho),
            ],
            idempotency_key_chirho: idem_chirho.to_owned(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: from_chirho.to_owned(),
            },
        }
    }
}

struct RouterChirho<'engines_chirho> {
    engines_chirho: BTreeMap<String, LedgerJournalChirho<'engines_chirho>>,
}

impl SagaJournalRouterChirho for RouterChirho<'_> {
    fn append_chirho(
        &mut self,
        cluster_chirho: &ClusterIdChirho,
        request_chirho: AppendRequestChirho,
    ) -> Result<AppendReceiptChirho, JournalErrorChirho> {
        let Some(engine_chirho) = self.engines_chirho.get_mut(&cluster_chirho.0) else {
            return Err(JournalErrorChirho::StorageChirho {
                detail_chirho: format!("unknown cluster {}", cluster_chirho.0),
            });
        };
        engine_chirho.append_chirho(request_chirho)
    }

    fn active_hold_chirho(
        &self,
        cluster_chirho: &ClusterIdChirho,
        key_chirho: &cairn_ledger_log_chirho::admission_chirho::EscrowHoldKeyChirho,
    ) -> Option<u64> {
        self.engines_chirho
            .get(&cluster_chirho.0)
            .and_then(|engine_chirho| engine_chirho.active_holds_chirho().get(key_chirho).copied())
    }

    fn current_continuation_chirho(
        &self,
        cluster_chirho: &ClusterIdChirho,
        kind_id_chirho: &cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho,
    ) -> Option<cairn_ledger_log_chirho::admission_chirho::CurrentContinuationPolicyChirho> {
        self.engines_chirho
            .get(&cluster_chirho.0)
            .and_then(|engine_chirho| engine_chirho.current_continuation_chirho(kind_id_chirho))
    }
}

// ---- scenario plumbing ---------------------------------------------------------------------------

const SAGA_LOG_ID_CHIRHO: &str = "saga-log-alpha-chirho";

fn saga_path_chirho() -> StoragePathChirho {
    StoragePathChirho("sagas/alpha.jsonl".into())
}

fn swap_steps_chirho(
    a_chirho: &JournalFixtureChirho,
    b_chirho: &JournalFixtureChirho,
) -> Vec<SagaStepPlanChirho> {
    vec![
        SagaStepPlanChirho {
            cluster_chirho: a_chirho.cluster_chirho.clone(),
            owner_chirho: "alice-chirho".into(),
            kind_chirho: a_chirho.kind_chirho.clone(),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                a_chirho.policy_ref_chirho.clone(),
            )),
            amount_chirho: 10,
            settlement_owner_chirho: "platform-a-chirho".into(),
        },
        SagaStepPlanChirho {
            cluster_chirho: b_chirho.cluster_chirho.clone(),
            owner_chirho: "bob-chirho".into(),
            kind_chirho: b_chirho.kind_chirho.clone(),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                b_chirho.policy_ref_chirho.clone(),
            )),
            amount_chirho: 5,
            settlement_owner_chirho: "platform-b-chirho".into(),
        },
    ]
}

/// Fund both journals and hand back the live engines (mint 500 to issuer; alice/bob get 100).
fn funded_router_chirho<'fixtures_chirho>(
    a_chirho: &'fixtures_chirho JournalFixtureChirho,
    b_chirho: &'fixtures_chirho JournalFixtureChirho,
    clock_chirho: &'fixtures_chirho SharedClockChirho,
) -> RouterChirho<'fixtures_chirho> {
    let mut engines_chirho = BTreeMap::new();
    for (fixture_chirho, funded_chirho) in [(a_chirho, "alice-chirho"), (b_chirho, "bob-chirho")] {
        let mut engine_chirho = LedgerJournalChirho::create_chirho(
            fixture_chirho.ports_chirho(clock_chirho),
            fixture_chirho.path_chirho(),
            fixture_chirho.cluster_chirho.clone(),
            1,
        )
        .unwrap();
        engine_chirho
            .append_chirho(fixture_chirho.mint_chirho(500, "idem-fund-mint"))
            .unwrap();
        engine_chirho
            .append_chirho(fixture_chirho.transfer_chirho(
                "issuer-chirho",
                funded_chirho,
                100,
                "idem-fund-transfer",
            ))
            .unwrap();
        engines_chirho.insert(fixture_chirho.cluster_chirho.0.clone(), engine_chirho);
    }
    RouterChirho { engines_chirho }
}

fn sigma_chirho(router_chirho: &RouterChirho<'_>) -> BTreeMap<String, i128> {
    let mut sums_chirho = BTreeMap::new();
    for engine_chirho in router_chirho.engines_chirho.values() {
        for (kind_chirho, net_chirho) in
            net_units_by_kind_chirho(engine_chirho.head_states_chirho())
        {
            *sums_chirho.entry(kind_chirho).or_insert(0_i128) += net_chirho;
        }
    }
    sums_chirho
}

fn held_total_chirho(router_chirho: &RouterChirho<'_>) -> u64 {
    router_chirho
        .engines_chirho
        .values()
        .flat_map(|engine_chirho| engine_chirho.head_states_chirho().values())
        .map(|post_chirho| post_chirho.held_chirho)
        .sum()
}

fn nets_snapshot_chirho(router_chirho: &RouterChirho<'_>) -> BTreeMap<String, i128> {
    let mut nets_chirho = BTreeMap::new();
    for engine_chirho in router_chirho.engines_chirho.values() {
        for (account_chirho, post_chirho) in engine_chirho.head_states_chirho() {
            nets_chirho.insert(
                format!(
                    "{}/{}",
                    account_chirho.owner_chirho, account_chirho.kind_id_chirho.0
                ),
                i128::from(post_chirho.credits_total_chirho)
                    - i128::from(post_chirho.debits_total_chirho),
            );
        }
    }
    nets_chirho
}

// ---- the tests -----------------------------------------------------------------------------------

/// The golden two-journal swap: both escrows finalize; value settles to each kind's designated
/// account; Σ per kind is untouched; no residual holds.
#[test]
fn golden_two_journal_swap_finalizes_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
    let sigma_before_chirho = sigma_chirho(&router_chirho);
    let saga_storage_chirho = MemoryStorageChirho::default();
    let saga_root_chirho = SagaRootSignerChirho;
    let coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    let report_chirho = coordinator_chirho
        .run_saga_chirho(
            &mut router_chirho,
            "token-golden-chirho",
            swap_steps_chirho(&a_chirho, &b_chirho),
            60_000,
        )
        .unwrap();
    assert_eq!(
        report_chirho.outcome_chirho,
        SagaOutcomeChirho::FinalizedChirho
    );
    assert_eq!(
        sigma_chirho(&router_chirho),
        sigma_before_chirho,
        "Σ per kind conserved"
    );
    assert_eq!(held_total_chirho(&router_chirho), 0, "no residual holds");
    let nets_chirho = nets_snapshot_chirho(&router_chirho);
    assert_eq!(nets_chirho["alice-chirho/money-chirho"], 90);
    assert_eq!(nets_chirho["platform-a-chirho/money-chirho"], 10);
    assert_eq!(nets_chirho["bob-chirho/points-chirho"], 95);
    assert_eq!(nets_chirho["platform-b-chirho/points-chirho"], 5);
    // A re-run of the SAME token is a resume of the closed saga — same outcome, no new effects.
    let rerun_chirho = coordinator_chirho
        .run_saga_chirho(
            &mut router_chirho,
            "token-golden-chirho",
            swap_steps_chirho(&a_chirho, &b_chirho),
            60_000,
        )
        .unwrap();
    assert_eq!(
        rerun_chirho.outcome_chirho,
        SagaOutcomeChirho::FinalizedChirho
    );
    assert_eq!(
        nets_snapshot_chirho(&router_chirho),
        nets_chirho,
        "idempotent re-entry"
    );
}

/// THE CRASH MATRIX: fail the saga log at EVERY append boundary (0..=6 of the 7 golden appends),
/// resume, and require the final state to equal the uncrashed golden — with Σ constant AT THE CUT
/// (before resume) and after. The saga-log crash cuts land exactly in the journal-effect gaps
/// (e.g. hold landed, StepHeld lost), so every resume path re-learns from the journals' own laws.
#[test]
fn crash_matrix_every_saga_append_boundary_chirho() {
    let golden_nets_chirho = {
        let clock_chirho = SharedClockChirho {
            now_ms_chirho: Cell::new(1_000),
        };
        let a_chirho = JournalFixtureChirho::new_chirho(
            "cluster-a-chirho",
            "money-chirho",
            "platform-a-chirho",
        );
        let b_chirho = JournalFixtureChirho::new_chirho(
            "cluster-b-chirho",
            "points-chirho",
            "platform-b-chirho",
        );
        let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
        let saga_storage_chirho = MemoryStorageChirho::default();
        let saga_root_chirho = SagaRootSignerChirho;
        let coordinator_chirho = SagaCoordinatorChirho {
            storage_chirho: &saga_storage_chirho,
            root_chirho: &saga_root_chirho,
            clock_chirho: &clock_chirho,
            path_chirho: saga_path_chirho(),
            saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
        };
        coordinator_chirho
            .run_saga_chirho(
                &mut router_chirho,
                "token-matrix-chirho",
                swap_steps_chirho(&a_chirho, &b_chirho),
                60_000,
            )
            .unwrap();
        nets_snapshot_chirho(&router_chirho)
    };
    // 7 golden saga appends: intent, held x2, decision, settled x2, closed.
    for crash_after_chirho in 0_u32..7 {
        let clock_chirho = SharedClockChirho {
            now_ms_chirho: Cell::new(1_000),
        };
        let a_chirho = JournalFixtureChirho::new_chirho(
            "cluster-a-chirho",
            "money-chirho",
            "platform-a-chirho",
        );
        let b_chirho = JournalFixtureChirho::new_chirho(
            "cluster-b-chirho",
            "points-chirho",
            "platform-b-chirho",
        );
        let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
        let sigma_funded_chirho = sigma_chirho(&router_chirho);
        let saga_storage_chirho = MemoryStorageChirho::default();
        let crash_storage_chirho = CrashStorageChirho {
            inner_chirho: &saga_storage_chirho,
            appends_left_chirho: Cell::new(Some(crash_after_chirho)),
        };
        let saga_root_chirho = SagaRootSignerChirho;
        let crashing_coordinator_chirho = SagaCoordinatorChirho {
            storage_chirho: &crash_storage_chirho,
            root_chirho: &saga_root_chirho,
            clock_chirho: &clock_chirho,
            path_chirho: saga_path_chirho(),
            saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
        };
        crashing_coordinator_chirho
            .run_saga_chirho(
                &mut router_chirho,
                "token-matrix-chirho",
                swap_steps_chirho(&a_chirho, &b_chirho),
                60_000,
            )
            .expect_err("the crash boundary must surface");
        // Σ AT THE CUT: escrow never creates or destroys — even mid-saga, per-kind nets hold.
        assert_eq!(
            sigma_chirho(&router_chirho),
            sigma_funded_chirho,
            "Σ constant at crash cut {crash_after_chirho}"
        );
        // RESUME on the durable state (budget lifted).
        let resumed_coordinator_chirho = SagaCoordinatorChirho {
            storage_chirho: &saga_storage_chirho,
            root_chirho: &saga_root_chirho,
            clock_chirho: &clock_chirho,
            path_chirho: saga_path_chirho(),
            saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
        };
        let mut reports_chirho = resumed_coordinator_chirho
            .resume_all_chirho(&mut router_chirho)
            .unwrap();
        if reports_chirho.is_empty() {
            // Crash before the intent was durable: nothing to resume — the idempotent re-run IS
            // the recovery (and must start clean because no journal effect preceded the intent).
            reports_chirho.push(
                resumed_coordinator_chirho
                    .run_saga_chirho(
                        &mut router_chirho,
                        "token-matrix-chirho",
                        swap_steps_chirho(&a_chirho, &b_chirho),
                        60_000,
                    )
                    .unwrap(),
            );
        }
        assert_eq!(reports_chirho.len(), 1);
        assert_eq!(
            reports_chirho[0].outcome_chirho,
            SagaOutcomeChirho::FinalizedChirho,
            "cut {crash_after_chirho} resumes to the golden outcome"
        );
        assert_eq!(
            nets_snapshot_chirho(&router_chirho),
            golden_nets_chirho,
            "cut {crash_after_chirho} converges to the golden final state"
        );
        assert_eq!(sigma_chirho(&router_chirho), sigma_funded_chirho);
        assert_eq!(held_total_chirho(&router_chirho), 0);
        // The journals REPLAY-VERIFY at this final state (drop + full reopen — P2's load law).
        for (cluster_chirho, fixture_chirho) in [
            ("cluster-a-chirho", &a_chirho),
            ("cluster-b-chirho", &b_chirho),
        ] {
            router_chirho.engines_chirho.remove(cluster_chirho);
            LedgerJournalChirho::open_chirho(
                fixture_chirho.ports_chirho(&clock_chirho),
                fixture_chirho.path_chirho(),
                &fixture_chirho.cluster_chirho,
            )
            .expect("journal replays clean after the resumed saga");
        }
    }
}

/// The durable TTL law: a saga crashed BEFORE its decision whose deadline has passed must
/// compensate on resume — every hold released, nets exactly as funded.
#[test]
fn ttl_expiry_before_decision_compensates_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
    let nets_funded_chirho = nets_snapshot_chirho(&router_chirho);
    let sigma_funded_chirho = sigma_chirho(&router_chirho);
    let saga_storage_chirho = MemoryStorageChirho::default();
    let crash_storage_chirho = CrashStorageChirho {
        inner_chirho: &saga_storage_chirho,
        appends_left_chirho: Cell::new(Some(3)), // intent + both helds; crash before the decision
    };
    let saga_root_chirho = SagaRootSignerChirho;
    let crashing_coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &crash_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    crashing_coordinator_chirho
        .run_saga_chirho(
            &mut router_chirho,
            "token-ttl-chirho",
            swap_steps_chirho(&a_chirho, &b_chirho),
            500,
        )
        .expect_err("crash before decision");
    assert!(
        held_total_chirho(&router_chirho) > 0,
        "holds live at the cut"
    );
    clock_chirho.now_ms_chirho.set(10_000); // past deadline 1_500
    let resumed_coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    let reports_chirho = resumed_coordinator_chirho
        .resume_all_chirho(&mut router_chirho)
        .unwrap();
    assert_eq!(reports_chirho.len(), 1);
    assert_eq!(
        reports_chirho[0].outcome_chirho,
        SagaOutcomeChirho::CompensatedChirho,
        "expired TTL must compensate, never finalize"
    );
    assert_eq!(
        nets_snapshot_chirho(&router_chirho),
        nets_funded_chirho,
        "nothing moved"
    );
    assert_eq!(sigma_chirho(&router_chirho), sigma_funded_chirho);
    assert_eq!(held_total_chirho(&router_chirho), 0, "every hold released");
}

/// A REAL hold refusal (overdraw) aborts the saga and releases the already-acquired prefix.
#[test]
fn hold_refusal_aborts_and_releases_the_prefix_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
    let nets_funded_chirho = nets_snapshot_chirho(&router_chirho);
    let saga_storage_chirho = MemoryStorageChirho::default();
    let saga_root_chirho = SagaRootSignerChirho;
    let coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    let mut steps_chirho = swap_steps_chirho(&a_chirho, &b_chirho);
    steps_chirho[1].amount_chirho = 1_000_000; // bob cannot cover this
    let report_chirho = coordinator_chirho
        .run_saga_chirho(
            &mut router_chirho,
            "token-refuse-chirho",
            steps_chirho,
            60_000,
        )
        .unwrap();
    assert_eq!(
        report_chirho.outcome_chirho,
        SagaOutcomeChirho::CompensatedChirho
    );
    assert_eq!(nets_snapshot_chirho(&router_chirho), nets_funded_chirho);
    assert_eq!(
        held_total_chirho(&router_chirho),
        0,
        "the acquired prefix was released"
    );
}

/// P3 at the composition level: two sagas over the SAME account coexist (distinct saga ids =
/// distinct hold keys) and both finalize.
#[test]
fn overlapping_sagas_on_one_account_both_finalize_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
    let saga_storage_chirho = MemoryStorageChirho::default();
    let saga_root_chirho = SagaRootSignerChirho;
    let coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    let alice_only_chirho = |amount_chirho: u64| {
        vec![SagaStepPlanChirho {
            cluster_chirho: a_chirho.cluster_chirho.clone(),
            owner_chirho: "alice-chirho".into(),
            kind_chirho: a_chirho.kind_chirho.clone(),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                a_chirho.policy_ref_chirho.clone(),
            )),
            amount_chirho,
            settlement_owner_chirho: "platform-a-chirho".into(),
        }]
    };
    for (token_chirho, amount_chirho) in [("token-x-chirho", 10_u64), ("token-y-chirho", 20)] {
        let report_chirho = coordinator_chirho
            .run_saga_chirho(
                &mut router_chirho,
                token_chirho,
                alice_only_chirho(amount_chirho),
                60_000,
            )
            .unwrap();
        assert_eq!(
            report_chirho.outcome_chirho,
            SagaOutcomeChirho::FinalizedChirho
        );
    }
    let nets_chirho = nets_snapshot_chirho(&router_chirho);
    assert_eq!(nets_chirho["alice-chirho/money-chirho"], 70);
    assert_eq!(nets_chirho["platform-a-chirho/money-chirho"], 30);
    assert_eq!(held_total_chirho(&router_chirho), 0);
}

/// The saga log's torn-tail posture: a torn suffix at a crash cut REPAIRS on load and the saga
/// still resumes to the golden outcome (resume-or-compensate, never fail-closed).
#[test]
fn torn_saga_tail_repairs_and_resumes_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
    let saga_storage_chirho = MemoryStorageChirho::default();
    let crash_storage_chirho = CrashStorageChirho {
        inner_chirho: &saga_storage_chirho,
        appends_left_chirho: Cell::new(Some(2)),
    };
    let saga_root_chirho = SagaRootSignerChirho;
    let crashing_coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &crash_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    crashing_coordinator_chirho
        .run_saga_chirho(
            &mut router_chirho,
            "token-torn-chirho",
            swap_steps_chirho(&a_chirho, &b_chirho),
            60_000,
        )
        .expect_err("crash");
    // The crash also tore a partial line into the tail.
    saga_storage_chirho
        .append_durable_chirho(&saga_path_chirho(), b"{\"schema_chirho\":\"ledger-saga-rec")
        .unwrap();
    let resumed_coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    let reports_chirho = resumed_coordinator_chirho
        .resume_all_chirho(&mut router_chirho)
        .unwrap();
    assert_eq!(reports_chirho.len(), 1);
    assert_eq!(
        reports_chirho[0].outcome_chirho,
        SagaOutcomeChirho::FinalizedChirho
    );
    // The repaired log walks clean end-to-end.
    load_saga_log_chirho(
        &saga_storage_chirho,
        &saga_root_chirho,
        &saga_path_chirho(),
        SAGA_LOG_ID_CHIRHO,
    )
    .unwrap();
}

/// Per-authority keys (#4901 b): a saga line tampered OR re-signed under the JOURNAL's key scheme
/// refuses the verified load — the saga root alone vouches saga records.
#[test]
fn tampered_or_journal_signed_saga_line_refuses_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
    let saga_storage_chirho = MemoryStorageChirho::default();
    let saga_root_chirho = SagaRootSignerChirho;
    let coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    coordinator_chirho
        .run_saga_chirho(
            &mut router_chirho,
            "token-tamper-chirho",
            swap_steps_chirho(&a_chirho, &b_chirho),
            60_000,
        )
        .unwrap();
    let clean_chirho = saga_storage_chirho
        .read_all_chirho(&saga_path_chirho())
        .unwrap()
        .unwrap();
    // Tamper: flip the recorded amount inside the intent.
    let tampered_chirho = String::from_utf8(clean_chirho.clone()).unwrap().replacen(
        "\"amount_chirho\":10",
        "\"amount_chirho\":11",
        1,
    );
    saga_storage_chirho
        .atomic_write_chirho(&saga_path_chirho(), tampered_chirho.as_bytes())
        .unwrap();
    assert!(
        load_saga_log_chirho(
            &saga_storage_chirho,
            &saga_root_chirho,
            &saga_path_chirho(),
            SAGA_LOG_ID_CHIRHO,
        )
        .is_err(),
        "a tampered saga line must refuse"
    );
    // Foreign authority: restore, then re-sign the first line under the JOURNAL scheme.
    let text_chirho = String::from_utf8(clean_chirho).unwrap();
    let first_line_chirho = text_chirho.lines().next().unwrap().to_owned();
    let mut record_chirho =
        crate::record_chirho::parse_canonical_saga_line_chirho(&first_line_chirho).unwrap();
    record_chirho.root_sig_chirho = String::new();
    let content_chirho =
        crate::record_chirho::saga_root_signed_content_chirho(&record_chirho).unwrap();
    record_chirho.root_sig_chirho = FakeJournalSignerChirho
        .sign_chirho(&content_chirho)
        .unwrap();
    let foreign_line_chirho =
        crate::record_chirho::canonical_saga_line_chirho(&record_chirho).unwrap();
    let forged_chirho = text_chirho.replacen(&first_line_chirho, &foreign_line_chirho, 1);
    saga_storage_chirho
        .atomic_write_chirho(&saga_path_chirho(), forged_chirho.as_bytes())
        .unwrap();
    let refusal_chirho = load_saga_log_chirho(
        &saga_storage_chirho,
        &saga_root_chirho,
        &saga_path_chirho(),
        SAGA_LOG_ID_CHIRHO,
    )
    .unwrap_err()
    .to_string();
    assert!(
        refusal_chirho.contains("signature"),
        "a journal-key-signed saga line must fail the SAGA root: {refusal_chirho}"
    );
}

/// The frozen lock-order law: the durable intent's plan is sorted by LOG-ID DIGEST ascending
/// (model_cf2_lockorder's coordinate), and the holds acquire in exactly that sequence.
#[test]
fn holds_acquire_in_log_id_digest_order_chirho() {
    use crate::coordinator_chirho::step_lock_digest_chirho;
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let mut router_chirho = {
        let mut engines_chirho = BTreeMap::new();
        let mut engine_chirho = LedgerJournalChirho::create_chirho(
            a_chirho.ports_chirho(&clock_chirho),
            a_chirho.path_chirho(),
            a_chirho.cluster_chirho.clone(),
            1,
        )
        .unwrap();
        engine_chirho
            .append_chirho(a_chirho.mint_chirho(500, "idem-lock-mint"))
            .unwrap();
        for owner_chirho in ["o1-chirho", "o2-chirho", "o3-chirho", "o4-chirho"] {
            engine_chirho
                .append_chirho(a_chirho.transfer_chirho(
                    "issuer-chirho",
                    owner_chirho,
                    50,
                    &format!("idem-lock-fund-{owner_chirho}"),
                ))
                .unwrap();
        }
        engines_chirho.insert(a_chirho.cluster_chirho.0.clone(), engine_chirho);
        RouterChirho { engines_chirho }
    };
    let saga_storage_chirho = MemoryStorageChirho::default();
    let saga_root_chirho = SagaRootSignerChirho;
    let coordinator_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    };
    let step_for_chirho = |owner_chirho: &str| SagaStepPlanChirho {
        cluster_chirho: a_chirho.cluster_chirho.clone(),
        owner_chirho: owner_chirho.to_owned(),
        kind_chirho: a_chirho.kind_chirho.clone(),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
            a_chirho.policy_ref_chirho.clone(),
        )),
        amount_chirho: 5,
        settlement_owner_chirho: "platform-a-chirho".into(),
    };
    // Deliberately submitted in LEXICAL owner order — the durable plan must come out DIGEST-sorted.
    let submitted_chirho: Vec<SagaStepPlanChirho> =
        ["o1-chirho", "o2-chirho", "o3-chirho", "o4-chirho"]
            .into_iter()
            .map(step_for_chirho)
            .collect();
    coordinator_chirho
        .run_saga_chirho(
            &mut router_chirho,
            "token-lock-chirho",
            submitted_chirho,
            60_000,
        )
        .unwrap();
    let loaded_chirho = load_saga_log_chirho(
        &saga_storage_chirho,
        &saga_root_chirho,
        &saga_path_chirho(),
        SAGA_LOG_ID_CHIRHO,
    )
    .unwrap();
    let crate::record_chirho::SagaOpChirho::IntentChirho { steps_chirho, .. } =
        &loaded_chirho.records_chirho[0].op_chirho
    else {
        panic!("record 0 is the intent");
    };
    let digests_chirho: Vec<String> = steps_chirho.iter().map(step_lock_digest_chirho).collect();
    let mut sorted_chirho = digests_chirho.clone();
    sorted_chirho.sort();
    assert_eq!(
        digests_chirho, sorted_chirho,
        "the durable plan is digest-ascending (§12)"
    );
    assert_ne!(
        steps_chirho
            .iter()
            .map(|step_chirho| step_chirho.owner_chirho.clone())
            .collect::<Vec<_>>(),
        ["o1-chirho", "o2-chirho", "o3-chirho", "o4-chirho"]
            .map(str::to_owned)
            .to_vec(),
        "the fixture must actually exercise a reorder (digest order differs from lexical)"
    );
}

/// N-way (three journals, three steps) with a mid-flight crash: the spine generalizes past two.
#[test]
fn three_journal_saga_finalizes_through_a_crash_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let c_chirho =
        JournalFixtureChirho::new_chirho("cluster-c-chirho", "miles-chirho", "platform-c-chirho");
    let mut engines_chirho = BTreeMap::new();
    for (fixture_chirho, funded_chirho) in [
        (&a_chirho, "alice-chirho"),
        (&b_chirho, "bob-chirho"),
        (&c_chirho, "carol-chirho"),
    ] {
        let mut engine_chirho = LedgerJournalChirho::create_chirho(
            fixture_chirho.ports_chirho(&clock_chirho),
            fixture_chirho.path_chirho(),
            fixture_chirho.cluster_chirho.clone(),
            1,
        )
        .unwrap();
        engine_chirho
            .append_chirho(fixture_chirho.mint_chirho(500, "idem-3way-mint"))
            .unwrap();
        engine_chirho
            .append_chirho(fixture_chirho.transfer_chirho(
                "issuer-chirho",
                funded_chirho,
                100,
                "idem-3way-fund",
            ))
            .unwrap();
        engines_chirho.insert(fixture_chirho.cluster_chirho.0.clone(), engine_chirho);
    }
    let mut router_chirho = RouterChirho { engines_chirho };
    let sigma_funded_chirho = sigma_chirho(&router_chirho);
    let steps_chirho = vec![
        (
            "cluster-a-chirho",
            "alice-chirho",
            &a_chirho,
            10_u64,
            "platform-a-chirho",
        ),
        (
            "cluster-b-chirho",
            "bob-chirho",
            &b_chirho,
            5,
            "platform-b-chirho",
        ),
        (
            "cluster-c-chirho",
            "carol-chirho",
            &c_chirho,
            7,
            "platform-c-chirho",
        ),
    ]
    .into_iter()
    .map(
        |(cluster_chirho, owner_chirho, fixture_chirho, amount_chirho, settlement_chirho)| {
            SagaStepPlanChirho {
                cluster_chirho: ClusterIdChirho(cluster_chirho.to_owned()),
                owner_chirho: owner_chirho.to_owned(),
                kind_chirho: fixture_chirho.kind_chirho.clone(),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    fixture_chirho.policy_ref_chirho.clone(),
                )),
                amount_chirho,
                settlement_owner_chirho: settlement_chirho.to_owned(),
            }
        },
    )
    .collect::<Vec<_>>();
    let saga_storage_chirho = MemoryStorageChirho::default();
    let crash_storage_chirho = CrashStorageChirho {
        inner_chirho: &saga_storage_chirho,
        appends_left_chirho: Cell::new(Some(5)), // dies mid-settle (intent + 3 helds + decision)
    };
    let saga_root_chirho = SagaRootSignerChirho;
    SagaCoordinatorChirho {
        storage_chirho: &crash_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    }
    .run_saga_chirho(
        &mut router_chirho,
        "token-3way-chirho",
        steps_chirho,
        60_000,
    )
    .expect_err("crash mid-settle");
    assert_eq!(sigma_chirho(&router_chirho), sigma_funded_chirho);
    let reports_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    }
    .resume_all_chirho(&mut router_chirho)
    .unwrap();
    assert_eq!(reports_chirho.len(), 1);
    assert_eq!(
        reports_chirho[0].outcome_chirho,
        SagaOutcomeChirho::FinalizedChirho
    );
    assert_eq!(sigma_chirho(&router_chirho), sigma_funded_chirho);
    assert_eq!(held_total_chirho(&router_chirho), 0);
    let nets_chirho = nets_snapshot_chirho(&router_chirho);
    assert_eq!(nets_chirho["alice-chirho/money-chirho"], 90);
    assert_eq!(nets_chirho["bob-chirho/points-chirho"], 95);
    assert_eq!(nets_chirho["carol-chirho/miles-chirho"], 93);
}

#[path = "interleaving_and_amendment_tests_chirho.rs"]
mod interleaving_and_amendment_tests_chirho;
