// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! S2d: the served-LLM CF3 money-conservation + privacy PROOF over a funded stub ledger.
//!
//! Each arm drives the real ladder — `admit_verified_node_effect_chirho` -> run-intent scope ->
//! `run_llm_served_chirho` -> [`LocalLlmServedCompositionChirho`] -> `EffectCommitCoordinatorChirho`
//! -> `LedgerEffectCommitAdapterChirho` — over a funded in-memory journal, and reads the ledger head
//! states before/after. The properties proven (boundary doc rulings 1 + 4):
//!   - a completed draft Finalizes EXACTLY the fixed price (payer debited it, settlement owner
//!     credited it, no Hold left) — this arm is also the POSITIVE CONTROL for the whole suite, so a
//!     never-charging stub could not pass the release/evidence arms vacuously;
//!   - a provider refusal maps to `DefiniteNoEffect` and Releases the whole Hold — nothing charged;
//!   - a same-intent-K retry charges ONCE (idempotency INHERITED from the coordinator + ledger
//!     adapter, not re-implemented here); the deterministic stub re-derives its completion on the
//!     retry, so the provider is called twice while the CHARGE stays one — the money invariant is
//!     one charge, never one provider call;
//!   - a completion whose provider evidence cannot be stored NEVER Finalizes (fail closed: the Hold
//!     stays, no debit, no settlement credit);
//!   - neither the prompt nor the completion text reaches any public surface (public CAS or the
//!     public effect-commit evidence store); the draft is sealed viewer-subject and the provider
//!     evidence carries counts/hashes only.
//!
//! `OverCeiling` / `InsufficientCredit` refusals defer with per-token metering (S2b resolution), so
//! they are deliberately NOT in this arm set.
//!
//! LOAN (recorded, repaid after S2 lands): the funded-ledger harness below duplicates
//! `postgres_reversible_chirho/tests_chirho.rs`'s `JournalHarnessChirho` (the ledger scaffolding, the
//! postgres DB mock dropped) rather than sharing it. Build-local was chosen over promote-first so the
//! postgres money proof is not disturbed while this proof is built, and so the later shared
//! extraction (postgres + llm effect-commit test support) is validated by BOTH proofs green rather
//! than by postgres alone. The same post-S2 refactor repays the evidence-adapter loan in
//! `llm_served_chirho.rs`.

use super::super::run_intent_chirho::{
    with_run_intent_effect_invocation_chirho, with_run_intent_execution_chirho,
};
use super::*;
use crate::model_chirho::{DagChirho, NodeDefChirho, PortChirho};
use cairn_effect_commit_ledger_chirho::LedgerEffectCommitAdapterChirho;
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
use cairn_llm_served_effect_chirho::{
    StubLlmProviderChirho, LLM_REQUEST_SCHEMA_CHIRHO, LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO,
};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

// The one shared adapter-evidence secret name (a shared-adapter contract, referenced not redefined).
use super::super::postgres_reversible_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO;

const MONEY_KIND_CHIRHO: &str = "money-chirho";
const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const MINT_EVIDENCE_CHIRHO: &str = "mint-authority-v1-chirho";
const SETTLEMENT_OWNER_CHIRHO: &str = "platform-chirho";
/// The fixed per-call llm price (a distinct value from any funded amount so conservation is crisp).
const LLM_PRICE_CHIRHO: u64 = 7;
/// Starting payer balance from the funded journal (mint 500 -> issuer, transfer 100 -> payer).
const PAYER_FUNDING_CHIRHO: u64 = 100;

// ---------------------------------------------------------------------------------------------------
// Funded-ledger harness (LOAN: duplicated from postgres_reversible_chirho/tests_chirho.rs; the
// postgres DB mock is not carried, since the served LLM effect has no decision table).
// ---------------------------------------------------------------------------------------------------

#[derive(Default)]
struct MemoryLedgerStorageChirho {
    objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
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
                Ok(cairn_ledger_log_chirho::ports_chirho::CreateDurableOutcomeChirho::CreatedChirho)
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

struct TestRootChirho {
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

struct JournalHarnessChirho {
    clock_chirho: TestClockChirho,
    ledger_root_chirho: TestRootChirho,
    intent_root_chirho: TestRootChirho,
    terminal_root_chirho: TestRootChirho,
    membership_chirho: TestMembershipChirho,
    registry_chirho: TestKindRegistryChirho,
    authority_chirho: TestAuthorityChirho,
    storage_chirho: MemoryLedgerStorageChirho,
}

impl JournalHarnessChirho {
    fn new_chirho(payer_chirho: &str) -> Self {
        Self {
            clock_chirho: TestClockChirho {
                now_ms_chirho: Cell::new(1_000),
            },
            ledger_root_chirho: TestRootChirho {
                name_chirho: "llm-ledger-root-chirho",
            },
            intent_root_chirho: TestRootChirho {
                name_chirho: "llm-intent-root-chirho",
            },
            terminal_root_chirho: TestRootChirho {
                name_chirho: "llm-terminal-root-chirho",
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
            storage_chirho: MemoryLedgerStorageChirho::default(),
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

    fn funded_journal_chirho(&self, payer_chirho: &str) -> LedgerJournalChirho<'_> {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            self.ports_chirho(),
            StoragePathChirho::new_chirho("journals/llm-served-chirho.jsonl"),
            ClusterIdChirho("cluster-llm-served-chirho".to_owned()),
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

    fn new_two_payers_chirho(payer_a_chirho: &str, payer_b_chirho: &str) -> Self {
        let mut harness_chirho = Self::new_chirho(payer_a_chirho);
        harness_chirho
            .membership_chirho
            .owners_chirho
            .insert(payer_b_chirho.to_owned());
        harness_chirho
    }

    fn funded_journal_two_payers_chirho(
        &self,
        payer_a_chirho: &str,
        payer_b_chirho: &str,
    ) -> LedgerJournalChirho<'_> {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            self.ports_chirho(),
            StoragePathChirho::new_chirho("journals/llm-served-chirho.jsonl"),
            ClusterIdChirho("cluster-llm-served-chirho".to_owned()),
            1,
        )
        .unwrap();
        self.clock_chirho.now_ms_chirho.set(1_100);
        journal_chirho.append_chirho(mint_request_chirho()).unwrap();
        self.clock_chirho.now_ms_chirho.set(1_200);
        journal_chirho
            .append_chirho(fund_request_keyed_chirho(
                payer_a_chirho,
                "llm-served-fund-a-chirho",
            ))
            .unwrap();
        self.clock_chirho.now_ms_chirho.set(1_250);
        journal_chirho
            .append_chirho(fund_request_keyed_chirho(
                payer_b_chirho,
                "llm-served-fund-b-chirho",
            ))
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
        idempotency_key_chirho: "llm-served-mint-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

fn fund_request_chirho(payer_chirho: &str) -> AppendRequestChirho {
    fund_request_keyed_chirho(payer_chirho, "llm-served-fund-chirho")
}

fn fund_request_keyed_chirho(
    payer_chirho: &str,
    idempotency_key_chirho: &str,
) -> AppendRequestChirho {
    let leg_chirho = |owner_chirho: &str, delta_chirho: LegDeltaChirho| AppendLegRequestChirho {
        account_chirho: account_chirho(owner_chirho),
        kind_policy_ref_chirho: policy_ref_chirho(),
        delta_chirho,
        amount_chirho: PAYER_FUNDING_CHIRHO,
        counterpart_chirho: None,
    };
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::TransferChirho,
        legs_chirho: vec![
            leg_chirho("issuer-chirho", LegDeltaChirho::DebitChirho),
            leg_chirho(payer_chirho, LegDeltaChirho::CreditChirho),
        ],
        idempotency_key_chirho: idempotency_key_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

// ---------------------------------------------------------------------------------------------------
// LLM-specific scaffolding: root, verified context + price book, the effect node, request bytes, and
// the two test providers the stub cannot itself be (a refuser and a call counter).
// ---------------------------------------------------------------------------------------------------

fn tmp_root_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-llm-served-s2d-{nanos_chirho}-{counter_chirho}-chirho"
    ))
}

fn setup_context_chirho(root_chirho: &Path) -> RequestContextChirho {
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
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
    let marker_chirho = crate::cas_chirho::add_chirho(root_chirho, b"llm-served-s2d-node").unwrap();
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
        "llm-served-s2d-chirho",
        dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    let (price_book_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        root_chirho,
        "llm-served-s2d-chirho",
        &owner_chirho,
        None,
        BTreeMap::from([(
            LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            LLM_PRICE_CHIRHO as i64,
        )]),
        0,
    )
    .unwrap();
    RequestContextChirho {
        user_principal_chirho: user_chirho,
        app_chirho: "llm-served-s2d-chirho".to_owned(),
        owner_principal_chirho: owner_chirho,
        client_id_chirho: "client-llm-served-s2d-chirho".to_owned(),
        token_hash_chirho: "token-llm-served-s2d-chirho".to_owned(),
        price_book_chirho: Some(price_book_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn llm_node_chirho() -> NodeDefChirho {
    NodeDefChirho {
        name_chirho: "llm-served-s2d-node-chirho".to_owned(),
        impl_wasm_chirho: HashChirho("builtin:llm-served-s2d-chirho".to_owned()),
        entry_chirho: "llm_served_s2d_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: HashChirho("bytes".to_owned()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: HashChirho("bytes".to_owned()),
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            caller_chirho: "llm-served-s2d-runtime-chirho".to_owned(),
        }],
        fuel_limit_chirho: 0,
        effect_contract_set_chirho: Some(
            crate::provider_test_support_chirho::current_effect_contract_set_chirho(),
        ),
        ..NodeDefChirho::default()
    }
}

/// A valid `llm-request-v1-chirho` guided brief. `business_name_chirho` rides both the prompt
/// (`user_chirho`) and the stub completion's `business_name`, so one needle proves neither leaks.
fn valid_request_bytes_chirho(business_name_chirho: &str) -> Vec<u8> {
    let request_chirho = LlmRequestChirho {
        schema_chirho: LLM_REQUEST_SCHEMA_CHIRHO.to_owned(),
        system_chirho: "You draft a small business landing page.".to_owned(),
        user_chirho: format!(
            "Business name: {business_name_chirho}\nServices to list: bread; cakes\nPhone (copy exactly): 555-0100\nEmail (copy exactly): hi@example.test\nHours or how to reach us: 9-5 daily"
        ),
        max_tokens_chirho: None,
        response_format_chirho: LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO.to_owned(),
    };
    serde_json::to_vec(&request_chirho).unwrap()
}

/// A provider that refuses every valid request with a fixed code — the stub never refuses a valid
/// request, so this is the only way to drive the `DefiniteNoEffect` -> Release leg.
struct RefusingLlmProviderChirho {
    code_chirho: LlmRefusalCodeChirho,
}

impl LlmProviderChirho for RefusingLlmProviderChirho {
    fn complete_chirho(&self, _request_chirho: &LlmRequestChirho) -> LlmProviderOutcomeChirho {
        LlmProviderOutcomeChirho::RefusedChirho(self.code_chirho)
    }
}

/// Wraps a provider and counts `complete_chirho` calls, so the retry arm can MEASURE the provider
/// call count (2 for the deterministic stub) rather than assume it, while the charge stays one.
struct CountingLlmProviderChirho<'inner_chirho> {
    inner_chirho: &'inner_chirho dyn LlmProviderChirho,
    calls_chirho: AtomicU64,
}

impl LlmProviderChirho for CountingLlmProviderChirho<'_> {
    fn complete_chirho(&self, request_chirho: &LlmRequestChirho) -> LlmProviderOutcomeChirho {
        self.calls_chirho.fetch_add(1, Ordering::Relaxed);
        self.inner_chirho.complete_chirho(request_chirho)
    }
}

/// Drive one served-LLM effect end to end over the funded journal, exactly as the paid-effect door
/// would: build the admission from the verified node, enter the run-intent scope, and dispatch. The
/// composition is opened fresh each call (idempotency lives in the journal, which persists), so a
/// retry passes the SAME `run_chirho` + node + request to reach the same intent K.
#[allow(clippy::too_many_arguments)]
fn run_one_llm_effect_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    harness_chirho: &JournalHarnessChirho,
    journal_chirho: &mut LedgerJournalChirho<'_>,
    provider_chirho: &dyn LlmProviderChirho,
    request_bytes_chirho: &[u8],
    run_chirho: &HashChirho,
    replay_chirho: bool,
) -> anyhow::Result<LlmServedEffectOutcomeChirho> {
    let node_chirho = llm_node_chirho();
    let node_hash_chirho = crate::store_chirho::hash_object_chirho(&node_chirho)?;
    let capability_chirho = node_chirho.capabilities_chirho[0].clone();
    let admission_chirho = crate::blessed_chirho::admit_verified_node_effect_chirho(
        &node_chirho,
        &node_hash_chirho,
        &capability_chirho,
    )?;
    let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
        journal_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    );
    let mut composition_chirho = LocalLlmServedCompositionChirho::open_chirho(
        root_chirho,
        &mut adapter_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
        &AppPriceBookUserPaysLlmPolicyChirho,
        provider_chirho,
        AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
    )?;
    with_run_intent_execution_chirho(run_chirho, replay_chirho, || {
        with_run_intent_effect_invocation_chirho(&node_hash_chirho, 0, || {
            run_llm_served_chirho(
                root_chirho,
                &admission_chirho,
                Some(context_chirho),
                request_bytes_chirho,
                Some(&mut composition_chirho),
            )
        })
    })
}

fn contains_subslice_chirho(haystack_chirho: &[u8], needle_chirho: &[u8]) -> bool {
    !needle_chirho.is_empty()
        && haystack_chirho.len() >= needle_chirho.len()
        && haystack_chirho
            .windows(needle_chirho.len())
            .any(|window_chirho| window_chirho == needle_chirho)
}

/// The outcome of scanning EVERY surface under the root for a plaintext needle. Distinguishing
/// `IncompleteChirho` from `CleanAndCompleteChirho` is the fail-CLOSED fix (claude2 #22601 + the S2d
/// post-commit hardening): the earlier walk read an unreadable dir/file as "needle absent", so a
/// surface the scan could not read passed as clean, and a whole-root walk WIDENED that to
/// mode-restricted key/secret surfaces. Now an unreadable surface — or a walk that read nothing at all
/// (the read-count floor) — is `IncompleteChirho`, which the privacy arm treats as a FAILURE, never as
/// proof of absence.
#[derive(Debug)]
enum RootSurfaceScanChirho {
    /// The plaintext needle rests on some surface under the root — privacy VIOLATED.
    NeedleFoundChirho,
    /// Every surface was read and the needle is on none of them — the property holds.
    CleanAndCompleteChirho,
    /// Some surface could not be read (or nothing was read at all), so absence cannot be proven.
    IncompleteChirho {
        unreadable_chirho: u64,
        read_count_chirho: u64,
    },
}

/// Walk the WHOLE root tree for `needle_chirho`, failing CLOSED. This walks the entire tree rather than
/// an allowlist of surfaces (claude2 #22601: the earlier scan covered 2 of the 21 surfaces the run
/// creates), and — unlike the earlier bool walk — an unreadable directory or file is COUNTED, so a
/// scan that could not read everything (or read nothing) can never report clean. The prompt rests only
/// as a sealed viewer-subject blob (ciphertext) and the completion rides the in-memory response, so
/// the plaintext needle must appear on NO surface — sealed stores included, because a seal holds
/// ciphertext, not the text.
fn scan_root_surfaces_chirho(root_chirho: &Path, needle_chirho: &[u8]) -> RootSurfaceScanChirho {
    fn walk_chirho(
        dir_chirho: &Path,
        needle_chirho: &[u8],
        unreadable_chirho: &mut u64,
        read_count_chirho: &mut u64,
    ) -> bool {
        match std::fs::read_dir(dir_chirho) {
            Err(_) => {
                *unreadable_chirho += 1;
                false
            }
            Ok(entries_chirho) => {
                for entry_chirho in entries_chirho {
                    let entry_chirho = match entry_chirho {
                        Ok(entry_chirho) => entry_chirho,
                        Err(_) => {
                            *unreadable_chirho += 1;
                            continue;
                        }
                    };
                    let path_chirho = entry_chirho.path();
                    if path_chirho.is_dir() {
                        if walk_chirho(
                            &path_chirho,
                            needle_chirho,
                            unreadable_chirho,
                            read_count_chirho,
                        ) {
                            return true;
                        }
                    } else {
                        match std::fs::read(&path_chirho) {
                            Ok(bytes_chirho) => {
                                *read_count_chirho += 1;
                                if contains_subslice_chirho(&bytes_chirho, needle_chirho) {
                                    return true;
                                }
                            }
                            Err(_) => *unreadable_chirho += 1,
                        }
                    }
                }
                false
            }
        }
    }
    let mut unreadable_chirho = 0;
    let mut read_count_chirho = 0;
    if walk_chirho(
        root_chirho,
        needle_chirho,
        &mut unreadable_chirho,
        &mut read_count_chirho,
    ) {
        return RootSurfaceScanChirho::NeedleFoundChirho;
    }
    if unreadable_chirho > 0 || read_count_chirho == 0 {
        return RootSurfaceScanChirho::IncompleteChirho {
            unreadable_chirho,
            read_count_chirho,
        };
    }
    RootSurfaceScanChirho::CleanAndCompleteChirho
}

// ---------------------------------------------------------------------------------------------------
// The arms.
// ---------------------------------------------------------------------------------------------------

/// POSITIVE CONTROL + arm 1: a completed draft Finalizes EXACTLY the fixed price. Because this arm
/// proves the ladder really charges, the release/evidence arms cannot pass on a never-charging stub.
#[test]
fn completion_finalizes_exactly_the_fixed_price_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let run_chirho = HashChirho("1".repeat(64));

    let outcome_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &StubLlmProviderChirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    )
    .expect("a valid completion must succeed");

    // The completion rides the response and is marked to seal to the requesting viewer.
    assert_eq!(
        outcome_chirho.private_subject_chirho.as_deref(),
        Some(context_chirho.user_principal_chirho.as_str()),
        "a completion must seal to the requesting viewer"
    );
    let response_chirho: LlmResponseChirho =
        serde_json::from_slice(&outcome_chirho.response_chirho)
            .expect("a completion response body");
    assert_eq!(response_chirho.schema_chirho, LLM_RESPONSE_SCHEMA_CHIRHO);
    assert!(
        response_chirho.completion_chirho.contains("Cedar Bakery"),
        "the completion carries the drafted business name"
    );

    // Money conservation: payer debited EXACTLY the price, settlement owner credited it, no Hold.
    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .cloned()
        .expect("payer head state");
    assert_eq!(payer_chirho.credits_total_chirho, PAYER_FUNDING_CHIRHO);
    assert_eq!(
        payer_chirho.debits_total_chirho, LLM_PRICE_CHIRHO,
        "payer is debited exactly the fixed price"
    );
    assert_eq!(
        payer_chirho.held_chirho, 0,
        "no Hold remains after Finalize"
    );
    let settlement_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
        .cloned()
        .expect("settlement head state");
    assert_eq!(
        settlement_chirho.credits_total_chirho, LLM_PRICE_CHIRHO,
        "settlement owner is credited exactly the fixed price"
    );
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert!(journal_chirho.active_holds_chirho().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Arm 2: a provider refusal maps to `DefiniteNoEffect` and Releases the whole Hold — nothing
/// charged. Asserts the refusal IDENTITY (the exact injected code), not merely "a refusal".
#[test]
fn provider_refusal_releases_the_whole_hold_unmetered_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let run_chirho = HashChirho("2".repeat(64));
    let provider_chirho = RefusingLlmProviderChirho {
        code_chirho: LlmRefusalCodeChirho::ProviderUnavailableChirho,
    };

    let outcome_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &provider_chirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    )
    .expect("a refusal is a typed body, not an error");

    // A refusal body carries no PII, so no seal subject; and it is the exact injected identity.
    assert!(
        outcome_chirho.private_subject_chirho.is_none(),
        "a refusal body has no viewer subject to seal"
    );
    let refusal_chirho: LlmRefusalChirho =
        serde_json::from_slice(&outcome_chirho.response_chirho).expect("a refusal response body");
    assert_eq!(
        refusal_chirho.refusal_code_chirho,
        LlmRefusalCodeChirho::ProviderUnavailableChirho,
        "the refusal identity is exactly the injected provider code"
    );

    // Money: nothing charged, the Hold released.
    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .cloned()
        .expect("payer head state");
    assert_eq!(payer_chirho.credits_total_chirho, PAYER_FUNDING_CHIRHO);
    assert_eq!(
        payer_chirho.debits_total_chirho, 0,
        "a refusal never debits the payer"
    );
    assert_eq!(payer_chirho.held_chirho, 0, "the Hold is released");
    assert!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .is_none(),
        "a refusal never credits the settlement owner"
    );
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert!(journal_chirho.active_holds_chirho().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Arm 3: a same-intent-K retry charges ONCE. Idempotency is INHERITED from the coordinator + ledger
/// adapter, so this arm VERIFIES it for the llm ladder rather than re-implementing it. The
/// deterministic stub re-derives its completion on the retry, so the provider is called twice — the
/// money invariant is one CHARGE, never one provider call.
#[test]
fn same_intent_retry_charges_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let run_chirho = HashChirho("3".repeat(64));
    let counting_chirho = CountingLlmProviderChirho {
        inner_chirho: &StubLlmProviderChirho,
        calls_chirho: AtomicU64::new(0),
    };

    // First attempt (fresh) then a retry of the SAME run + node + request => the SAME intent K.
    let first_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &counting_chirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    )
    .expect("first attempt completes");
    let retry_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &counting_chirho,
        &request_bytes_chirho,
        &run_chirho,
        true,
    )
    .expect("retry of the same intent completes idempotently");

    // Both attempts return the same sealed completion.
    assert_eq!(
        first_chirho.response_chirho, retry_chirho.response_chirho,
        "a same-K retry returns the original completion"
    );

    // ONE charge across both attempts: debited once, credited once, no new journal entries.
    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .cloned()
        .expect("payer head state");
    assert_eq!(
        payer_chirho.debits_total_chirho, LLM_PRICE_CHIRHO,
        "the payer is charged exactly once across the retry"
    );
    assert_eq!(payer_chirho.held_chirho, 0);
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .expect("settlement head state")
            .credits_total_chirho,
        LLM_PRICE_CHIRHO,
        "the settlement owner is credited exactly once across the retry"
    );
    assert_eq!(
        journal_chirho.tail_seq_chirho(),
        initial_tail_chirho + 2,
        "the retry appends no new Hold/Finalize"
    );
    assert!(journal_chirho.active_holds_chirho().is_empty());

    // The deterministic stub re-derives on the retry: two provider calls, one charge. This is the
    // provider-implementation detail, NOT the money property (a real provider's execute-or-replay
    // reads its own store by K and would not re-execute).
    assert_eq!(
        counting_chirho.calls_chirho.load(Ordering::Relaxed),
        2,
        "the deterministic stub is asked once per attempt while the charge stays one"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// SECOND-SEAT ARM (claude2, #22594): the NEGATIVE CONTROL for arm 3.
///
/// Arm 3 proves a same-K retry charges once. On its own that is consistent with TWO worlds: the
/// ledger deduplicates by intent K, or something else makes the charge one regardless of K. Arm 3
/// cannot tell them apart, because it only ever supplies ONE K.
///
/// This arm varies the suspected cause. Same request, same node, same payer -- a DIFFERENT run hash,
/// so a DIFFERENT intent K. If K-sameness is what collapses the charge, this MUST charge twice. If it
/// still charges once, the one-charge result in arm 3 is attributable to something other than the
/// ledger dedup, which is the finding claude asked me to look for.
#[test]
fn a_different_intent_key_charges_twice_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let counting_chirho = CountingLlmProviderChirho {
        inner_chirho: &StubLlmProviderChirho,
        calls_chirho: AtomicU64::new(0),
    };

    // Two attempts that differ ONLY in the run hash, so the intent K differs.
    let first_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &counting_chirho,
        &request_bytes_chirho,
        &HashChirho("3".repeat(64)),
        false,
    )
    .expect("first intent completes");
    let second_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &counting_chirho,
        &request_bytes_chirho,
        &HashChirho("4".repeat(64)),
        false,
    )
    .expect("a different intent completes");

    assert_eq!(
        first_chirho.response_chirho, second_chirho.response_chirho,
        "the deterministic stub returns the same completion for the same request -- so an equal \
         RESPONSE cannot be what makes a charge single; only the ledger can"
    );

    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .cloned()
        .expect("payer head state");
    assert_eq!(
        payer_chirho.debits_total_chirho,
        LLM_PRICE_CHIRHO * 2,
        "TWO distinct intents must be charged TWICE. One charge here would mean arm 3's single \
         charge is not attributable to intent-K dedup"
    );
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .expect("settlement head state")
            .credits_total_chirho,
        LLM_PRICE_CHIRHO * 2,
        "and the settlement owner credited twice"
    );
    assert_eq!(
        journal_chirho.tail_seq_chirho(),
        initial_tail_chirho + 4,
        "two Hold/Finalize pairs, not one"
    );
    assert!(journal_chirho.active_holds_chirho().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Arm 4: a completion whose provider evidence cannot be stored NEVER Finalizes (fail closed). The
/// tamper VIOLATES the property directly: a file is planted where the provider-evidence directory
/// must be created, so `store_provider_evidence_chirho` fails BEFORE the terminal money append. The
/// Hold stays, and no debit or settlement credit is recorded.
#[test]
fn missing_provider_evidence_never_finalizes_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let run_chirho = HashChirho("4".repeat(64));

    // Plant a FILE where the provider-evidence family directory must be, so its creation fails.
    let llm_evidence_dir_chirho = root_chirho
        .join(EFFECT_COMMIT_EVIDENCE_DIRECTORY_CHIRHO)
        .join("llm-served-chirho");
    std::fs::create_dir_all(&llm_evidence_dir_chirho).unwrap();
    std::fs::write(
        llm_evidence_dir_chirho.join("provider-chirho"),
        b"blocks the provider-evidence directory",
    )
    .unwrap();

    let result_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &StubLlmProviderChirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    );
    assert!(
        result_chirho.is_err(),
        "a completion whose provider evidence cannot be stored must fail closed"
    );

    // Fail closed: the Hold stays, nothing is charged, nothing is settled.
    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .cloned()
        .expect("payer head state");
    assert_eq!(
        payer_chirho.debits_total_chirho, 0,
        "no debit without stored provider evidence"
    );
    assert_eq!(
        payer_chirho.held_chirho, LLM_PRICE_CHIRHO,
        "the Hold stays open pending evidence (never a silent charge)"
    );
    assert!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .is_none(),
        "no settlement credit without stored provider evidence"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Arm 5 (privacy): neither the prompt nor the completion text reaches any public surface. The
/// business name rides both the prompt and the completion, so one needle proves both. A positive
/// control (a DIFFERENT needle, planted in the public CAS) proves the scanner can find a planted
/// needle, so the absence is a real measurement rather than an empty scan.
#[test]
fn neither_prompt_nor_completion_reaches_a_public_surface_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let pii_needle_chirho = "Zzyzx-S2D-Prompt-And-Completion-Needle-Chirho";
    let request_bytes_chirho = valid_request_bytes_chirho(pii_needle_chirho);
    let run_chirho = HashChirho("5".repeat(64));

    let outcome_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &StubLlmProviderChirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    )
    .expect("a valid completion must succeed");

    // The needle really is in both the prompt and the returned (in-memory) completion.
    assert!(contains_subslice_chirho(
        &request_bytes_chirho,
        pii_needle_chirho.as_bytes()
    ));
    let response_chirho: LlmResponseChirho =
        serde_json::from_slice(&outcome_chirho.response_chirho)
            .expect("a completion response body");
    assert!(
        response_chirho
            .completion_chirho
            .contains(pii_needle_chirho),
        "the drafted completion carries the business name (so the needle covers both surfaces)"
    );
    assert_eq!(
        outcome_chirho.private_subject_chirho.as_deref(),
        Some(context_chirho.user_principal_chirho.as_str()),
        "the completion is marked to seal viewer-subject"
    );

    // The real property: neither the prompt nor the completion text rests on ANY surface under the
    // root — sealed stores included (a seal holds ciphertext, not the text). The scan must be
    // CleanAndComplete: needle absent AND every surface actually read (fail closed — an unreadable
    // surface can never pass as clean).
    assert!(
        matches!(
            scan_root_surfaces_chirho(&root_chirho, pii_needle_chirho.as_bytes()),
            RootSurfaceScanChirho::CleanAndCompleteChirho
        ),
        "neither the prompt nor the completion text may rest on any surface under the root, and \
         every surface must have been readable (fail-closed scan)"
    );

    // Positive control (claude2 #22601): plant a needle at a root-level file the earlier 2-surface
    // scan would have MISSED, and require the walk to FIND it. A control that plants only where the
    // scan already looks cannot detect an uncovered surface — which is exactly the gap the whole-root
    // walk closes.
    let control_needle_chirho = b"S2D-Unscanned-Surface-Positive-Control-Needle-Chirho";
    std::fs::write(
        root_chirho.join("s2d-control-needle-chirho.txt"),
        control_needle_chirho,
    )
    .unwrap();
    assert!(
        matches!(
            scan_root_surfaces_chirho(&root_chirho, control_needle_chirho),
            RootSurfaceScanChirho::NeedleFoundChirho
        ),
        "the whole-root scan must find a needle in a surface the old 2-surface scan missed"
    );

    // Fail-closed control (S2d post-commit hardening): an UNREADABLE surface must make the scan report
    // `IncompleteChirho`, never `CleanAndCompleteChirho`. Plant a needle inside a directory, lock it to
    // mode 000, and require the scan to refuse to certify absence. Under the OLD fail-open walk this
    // hidden needle read as absent (clean); the fail-closed walk reports Incomplete. Skipped only if
    // the process can still read a 000 dir (e.g. running as root), where this path cannot be exercised.
    let locked_dir_chirho = root_chirho.join("s2d-locked-surface-chirho");
    std::fs::create_dir_all(&locked_dir_chirho).unwrap();
    let hidden_needle_chirho = b"S2D-Hidden-Behind-A-000-Mode-Dir-Needle-Chirho";
    std::fs::write(
        locked_dir_chirho.join("hidden-chirho.txt"),
        hidden_needle_chirho,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked_dir_chirho, std::fs::Permissions::from_mode(0o000))
            .unwrap();
        if std::fs::read_dir(&locked_dir_chirho).is_err() {
            match scan_root_surfaces_chirho(&root_chirho, hidden_needle_chirho) {
                RootSurfaceScanChirho::IncompleteChirho {
                    unreadable_chirho,
                    read_count_chirho,
                } => {
                    // The locked surface is counted, and the scan DID read other surfaces first (the
                    // read-count floor is exercised, not vacuously zero).
                    assert!(
                        unreadable_chirho >= 1,
                        "the mode-000 surface must be counted unreadable"
                    );
                    assert!(
                        read_count_chirho >= 1,
                        "the scan must have read other surfaces before the locked one"
                    );
                }
                other_chirho => panic!(
                    "an unreadable surface must fail the scan CLOSED (Incomplete), never pass as clean: {other_chirho:?}"
                ),
            }
        }
        // Restore read/exec so the arm's cleanup can remove the tree.
        std::fs::set_permissions(&locked_dir_chirho, std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// SECOND-SEAT GAP (claude2 #22597 + cairn-auditor F2): a second principal must not reuse another
/// payer's invocation coordinate. Two funded payers — A runs an invocation and is charged once; B
/// presents the SAME invocation coordinate and is REFUSED by identity as a different obligation, never
/// charged, never absorbed. This arm reddens when the invocation binding is dropped OR when
/// `same_invocation_obligation_chirho` is disabled, so the obligation GATE is load-bearing.
///
/// NOTE, measured (claude2's drop survived, the auditor explained why): the payer field ALONE is
/// redundant defense-in-depth — dropping only `payer_account_chirho` from the obligation SURVIVES,
/// because a different principal also mismatches on `request_context_ref_chirho` and
/// `attribution_chirho`, and even disabling the whole LLM gate leaves the inherited CF3
/// terminal-conflict backstop. So no single field is individually pinnable. The arm therefore asserts
/// the `InvocationObligationConflictChirho` IDENTITY — not merely `is_err` — so a bypass that a lower
/// backstop would still refuse (with a different identity) reddens this arm rather than passing.
///
/// INCOMPLETENESS, corrected (claude2 #22618/#22620): `request_context_ref_chirho` derives NOT only
/// from `user_principal` but from the WHOLE seven-field `RequestContextChirho` — including the
/// volatile `token_hash`/`client_id` and `price_book`/`billing_policy`. So this same identity ALSO
/// fires for the SAME payer whose session or pricing rotated between an attempt and a retry: a benign
/// dedupe wrongly surfacing as a CONFLICT, which this arm (asserting the shared identity) cannot tell
/// from the cross-payer attack it is named for. That is a KNOWN LADDER retry-dedup hypothesis (tracked
/// in the tasklist; the discriminator arm + the fix are cargo-pending) — NOT closed here.
#[test]
fn cross_payer_cannot_reuse_one_invocation_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_a_chirho = setup_context_chirho(&root_chirho);
    // A second principal in the same app and price book, but a different payer identity.
    let payer_b_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    let context_b_chirho = RequestContextChirho {
        user_principal_chirho: payer_b_chirho.clone(),
        app_chirho: context_a_chirho.app_chirho.clone(),
        owner_principal_chirho: context_a_chirho.owner_principal_chirho.clone(),
        client_id_chirho: context_a_chirho.client_id_chirho.clone(),
        token_hash_chirho: context_a_chirho.token_hash_chirho.clone(),
        price_book_chirho: context_a_chirho.price_book_chirho.clone(),
        billing_policy_chirho: context_a_chirho.billing_policy_chirho.clone(),
        key_limit_chirho: context_a_chirho.key_limit_chirho.clone(),
    };
    let harness_chirho = JournalHarnessChirho::new_two_payers_chirho(
        &context_a_chirho.user_principal_chirho,
        &payer_b_chirho,
    );
    let mut journal_chirho = harness_chirho
        .funded_journal_two_payers_chirho(&context_a_chirho.user_principal_chirho, &payer_b_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let run_chirho = HashChirho("6".repeat(64));

    // A runs the invocation -> charged exactly once.
    run_one_llm_effect_chirho(
        &root_chirho,
        &context_a_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &StubLlmProviderChirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    )
    .expect("A's draft completes");
    let tail_after_a_chirho = journal_chirho.tail_seq_chirho();

    // B presents the SAME invocation coordinate (same run + node + step) with a DIFFERENT payer, and
    // is driven through a COUNTING provider so we can prove B never reaches the provider at all — the
    // obligation gate refuses BEFORE the coordinator drives the provider.
    let b_provider_chirho = CountingLlmProviderChirho {
        inner_chirho: &StubLlmProviderChirho,
        calls_chirho: AtomicU64::new(0),
    };
    let b_result_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_b_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &b_provider_chirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    );
    // `expect_err` would require the Ok type to be Debug; a match keeps the money module untouched.
    let error_chirho = match b_result_chirho {
        Ok(_) => panic!("a second principal must not reuse another payer's invocation coordinate"),
        Err(error_chirho) => error_chirho,
    };
    assert!(
        matches!(
            error_chirho.downcast_ref::<LlmServedActivationErrorChirho>(),
            Some(LlmServedActivationErrorChirho::InvocationObligationConflictChirho)
        ),
        "the refusal identity must be the invocation-obligation conflict, not another error: {error_chirho}"
    );

    // B RECEIVES NO COMPLETION — the direct money-AUTHORITY property, proven by three ATTRIBUTING
    // facts (not the non-attributing `debits_b == 0` net below): the call returned Err with the
    // conflict identity (above — so B holds no `LlmServedEffectOutcomeChirho`, hence no draft); B
    // never reached the provider; and B appended nothing to the journal.
    assert_eq!(
        b_provider_chirho.calls_chirho.load(Ordering::Relaxed),
        0,
        "a refused reuse must never reach the provider (the gate precedes the coordinator)"
    );
    assert_eq!(
        journal_chirho.tail_seq_chirho(),
        tail_after_a_chirho,
        "a refused reuse appends nothing (no charge, no stranded Hold)"
    );

    // Money: A charged exactly once; B never charged and holds nothing; settlement credited once.
    // (`debits_b == 0` corroborates but does not attribute — the three facts above are the authority
    // proof; a bug that gave B a draft without charging would pass this line and fail those.)
    let payer_a_state_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_a_chirho.user_principal_chirho))
        .cloned()
        .expect("payer A head state");
    assert_eq!(
        payer_a_state_chirho.debits_total_chirho, LLM_PRICE_CHIRHO,
        "A is charged exactly once"
    );
    assert_eq!(payer_a_state_chirho.held_chirho, 0);
    let payer_b_state_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&payer_b_chirho))
        .cloned()
        .expect("payer B head state");
    assert_eq!(
        payer_b_state_chirho.debits_total_chirho, 0,
        "B is never charged for A's invocation"
    );
    assert_eq!(payer_b_state_chirho.held_chirho, 0, "B holds nothing");
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .expect("settlement head state")
            .credits_total_chirho,
        LLM_PRICE_CHIRHO,
        "settlement is credited once (A only)"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// FIX ARM (S2d ladder retry-dedup, claude2 #22618/#22620): a same-payer retry whose SESSION rotated
/// between attempts DEDUPLICATES to the one charge — it does not refuse as a conflict. Same user, app,
/// owner, request, and invocation coordinate; only `token_hash` + `client_id` differ (a session/client
/// refresh). Because the money-obligation identity (`request_identity_ref_chirho`) excludes that
/// volatile material, the retry is the SAME obligation and the coordinator dedupes it. Reddens if the
/// identity ref is widened to include token/client (mutation M8): the retry would then wrongly refuse
/// as `InvocationObligationConflictChirho`.
#[test]
fn session_rotation_deduplicates_the_charge_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let run_chirho = HashChirho("7".repeat(64));
    let counting_chirho = CountingLlmProviderChirho {
        inner_chirho: &StubLlmProviderChirho,
        calls_chirho: AtomicU64::new(0),
    };

    // First attempt with the original session.
    let first_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &counting_chirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    )
    .expect("first attempt completes");

    // Same payer/app/owner/request/coordinate — ONLY the session token and client id rotate.
    let rotated_context_chirho = RequestContextChirho {
        token_hash_chirho: "token-llm-served-s2d-ROTATED-chirho".to_owned(),
        client_id_chirho: "client-llm-served-s2d-ROTATED-chirho".to_owned(),
        ..context_chirho.clone()
    };
    let retry_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &rotated_context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &counting_chirho,
        &request_bytes_chirho,
        &run_chirho,
        true,
    )
    .expect("a session-rotated retry of the same obligation dedupes, it does not conflict");

    // Dedupe: the same completion, ONE charge, one settlement credit, no new journal entries.
    assert_eq!(
        first_chirho.response_chirho, retry_chirho.response_chirho,
        "a session-rotated retry returns the original completion"
    );
    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .cloned()
        .expect("payer head state");
    assert_eq!(
        payer_chirho.debits_total_chirho, LLM_PRICE_CHIRHO,
        "a session rotation must not double-charge, and must not refuse the retry"
    );
    assert_eq!(payer_chirho.held_chirho, 0);
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .expect("settlement head state")
            .credits_total_chirho,
        LLM_PRICE_CHIRHO,
        "settlement credited exactly once across the session-rotated retry"
    );
    assert_eq!(
        journal_chirho.tail_seq_chirho(),
        initial_tail_chirho + 2,
        "the rotated retry appends no new Hold/Finalize"
    );
    assert!(journal_chirho.active_holds_chirho().is_empty());
    // The stub re-derives on the retry (two provider calls) while the charge stays one.
    assert_eq!(counting_chirho.calls_chirho.load(Ordering::Relaxed), 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// FIX ARM ("narrow, don't drop" — claude2 #22629): `owner_principal` enters the money-obligation
/// identity ONLY through `request_identity_ref_chirho`, so a wholesale DROP of that ref (rather than
/// narrowing it) would leave a DIFFERENT owner able to reuse another party's invocation coordinate and
/// be ABSORBED onto its charge. Here A runs, then a request with the SAME payer, app, request, and
/// coordinate but a DIFFERENT `owner_principal` is REFUSED by the conflict identity — never absorbed,
/// never given A's completion. Reddens if `owner_principal` is dropped from the identity tuple
/// (mutation M9): the reuse would dedupe to A's charge and return A's draft.
#[test]
fn cross_owner_reuse_is_refused_by_identity_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_a_chirho = setup_context_chirho(&root_chirho);
    let other_owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    // Same payer, app, price book, request, coordinate — only the owner principal differs.
    let context_other_owner_chirho = RequestContextChirho {
        owner_principal_chirho: other_owner_chirho,
        ..context_a_chirho.clone()
    };
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_a_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_a_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let run_chirho = HashChirho("8".repeat(64));

    run_one_llm_effect_chirho(
        &root_chirho,
        &context_a_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &StubLlmProviderChirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    )
    .expect("A's draft completes");
    let tail_after_a_chirho = journal_chirho.tail_seq_chirho();

    let other_provider_chirho = CountingLlmProviderChirho {
        inner_chirho: &StubLlmProviderChirho,
        calls_chirho: AtomicU64::new(0),
    };
    let reuse_result_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &context_other_owner_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &other_provider_chirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    );
    let error_chirho = match reuse_result_chirho {
        Ok(_) => panic!("a different owner must not reuse another party's invocation coordinate"),
        Err(error_chirho) => error_chirho,
    };
    assert!(
        matches!(
            error_chirho.downcast_ref::<LlmServedActivationErrorChirho>(),
            Some(LlmServedActivationErrorChirho::InvocationObligationConflictChirho)
        ),
        "a different owner reusing the coordinate must be the conflict identity: {error_chirho}"
    );
    // Never absorbed: no completion, no provider call, nothing appended, and A's single charge stands.
    assert_eq!(
        other_provider_chirho.calls_chirho.load(Ordering::Relaxed),
        0,
        "a refused cross-owner reuse never reaches the provider"
    );
    assert_eq!(
        journal_chirho.tail_seq_chirho(),
        tail_after_a_chirho,
        "a refused cross-owner reuse appends nothing"
    );
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(&context_a_chirho.user_principal_chirho))
            .expect("payer head state")
            .debits_total_chirho,
        LLM_PRICE_CHIRHO,
        "only A's single charge stands"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// FIX ARM (distinct price identity): when the operator RE-VERSIONS the price book between the first
/// attempt and a retry of the SAME identity + request + coordinate, the retry is refused with its OWN
/// identity — `InvocationPriceChangedChirho`, a reconcilable version bump — NEVER the authority
/// `InvocationObligationConflictChirho`. The first attempt's charge is untouched; the retry appends
/// nothing and reaches no provider. Reddens if the price fields leave the obligation (retry would
/// dedupe to the stale price) or if a price mismatch is mapped to the conflict identity (M10).
#[test]
fn price_change_refuses_with_a_distinct_identity_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let request_bytes_chirho = valid_request_bytes_chirho("Cedar Bakery");
    let run_chirho = HashChirho("9".repeat(64));

    run_one_llm_effect_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &StubLlmProviderChirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
    )
    .expect("first attempt at the original price completes");
    let tail_after_first_chirho = journal_chirho.tail_seq_chirho();

    // The operator re-versions the price book (a new signed price row) -> a new price_book digest and
    // a new resolved price. Everything else about the retry is identical.
    let (new_price_book_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "llm-served-s2d-chirho",
        &context_chirho.owner_principal_chirho,
        None,
        BTreeMap::from([(
            LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            (LLM_PRICE_CHIRHO + 1) as i64,
        )]),
        0,
    )
    .unwrap();
    let repriced_context_chirho = RequestContextChirho {
        price_book_chirho: Some(new_price_book_chirho),
        ..context_chirho.clone()
    };
    let counting_chirho = CountingLlmProviderChirho {
        inner_chirho: &StubLlmProviderChirho,
        calls_chirho: AtomicU64::new(0),
    };
    let retry_result_chirho = run_one_llm_effect_chirho(
        &root_chirho,
        &repriced_context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &counting_chirho,
        &request_bytes_chirho,
        &run_chirho,
        true,
    );
    let error_chirho = match retry_result_chirho {
        Ok(_) => panic!("a retry after a price re-version must not reuse the stale price"),
        Err(error_chirho) => error_chirho,
    };
    assert!(
        matches!(
            error_chirho.downcast_ref::<LlmServedActivationErrorChirho>(),
            Some(LlmServedActivationErrorChirho::InvocationPriceChangedChirho)
        ),
        "a price re-version must refuse with its OWN identity, never the authority conflict: {error_chirho}"
    );
    // The first charge stands; the refused retry adds nothing and never reaches the provider.
    assert_eq!(
        counting_chirho.calls_chirho.load(Ordering::Relaxed),
        0,
        "a price-changed retry never reaches the provider"
    );
    assert_eq!(
        journal_chirho.tail_seq_chirho(),
        tail_after_first_chirho,
        "a price-changed retry appends nothing"
    );
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(&context_chirho.user_principal_chirho))
            .expect("payer head state")
            .debits_total_chirho,
        LLM_PRICE_CHIRHO,
        "only the first attempt's charge stands"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// F1 (cairn-auditor re-seat of 89bafcdf: Mut1 + Mut2 SURVIVED the flow arms). The money-obligation
/// identity ref is domain-separated AND length-prefixed on purpose, but no flow arm pins either — a
/// refactor could silently drop them and stay green. This arm pins both directly. Without
/// length-prefixing, two tuples whose fields concatenate to the same bytes collide; without the domain
/// tag, the ref equals a bare length-prefixed hash of the same fields. At a coordinate reachable across
/// apps/owners (the auditor left that reachability PLAUSIBLE, not constructed) a collision would absorb
/// one party's obligation onto another's — so this is a money-AUTHORITY collision-resistance claim, not
/// cosmetics. No live effect here (a cross-payer is double-guarded by payer_account + attribution).
#[test]
fn identity_ref_is_domain_separated_and_length_prefixed_chirho() {
    let ctx_chirho =
        |user_chirho: &str, app_chirho: &str, owner_chirho: &str| RequestContextChirho {
            user_principal_chirho: user_chirho.to_owned(),
            app_chirho: app_chirho.to_owned(),
            owner_principal_chirho: owner_chirho.to_owned(),
            client_id_chirho: "client-chirho".to_owned(),
            token_hash_chirho: "token-chirho".to_owned(),
            price_book_chirho: None,
            billing_policy_chirho: None,
            key_limit_chirho: None,
        };

    // Length-prefixing: same concatenation "abco", different field boundaries -> DIFFERENT refs.
    // (Reddens auditor Mut1, which deletes the length-prefix update.)
    assert_ne!(
        request_identity_ref_chirho(&ctx_chirho("ab", "c", "o")).0,
        request_identity_ref_chirho(&ctx_chirho("a", "bc", "o")).0,
        "a user/app field-boundary shift with equal concatenation must not collide"
    );
    assert_ne!(
        request_identity_ref_chirho(&ctx_chirho("u", "app", "x")).0,
        request_identity_ref_chirho(&ctx_chirho("u", "ap", "px")).0,
        "an app/owner field-boundary shift with equal concatenation must not collide"
    );

    // Domain separation: the ref must NOT equal the same length-prefixed digest computed WITHOUT the
    // domain tag. (Reddens auditor Mut2, which deletes the domain update.)
    let without_domain_chirho = {
        let mut hasher_chirho = blake3::Hasher::new();
        for field_chirho in ["u", "app", "x"] {
            hasher_chirho.update(&(field_chirho.len() as u64).to_be_bytes());
            hasher_chirho.update(field_chirho.as_bytes());
        }
        hasher_chirho.finalize().to_hex().to_string()
    };
    assert_ne!(
        request_identity_ref_chirho(&ctx_chirho("u", "app", "x")).0,
        without_domain_chirho,
        "the identity ref must apply the domain tag, not a bare length-prefixed hash"
    );

    // Sanity: the same identity tuple produces the same ref (the dedup property the flow arms rely on).
    assert_eq!(
        request_identity_ref_chirho(&ctx_chirho("u", "app", "x")).0,
        request_identity_ref_chirho(&ctx_chirho("u", "app", "x")).0,
        "the same identity tuple must produce the same ref"
    );
}

// ---------------------------------------------------------------------------------------------------
// S3: the served proof THROUGH THE DISPATCHER. S2d drove the ladder directly; S3 routes the effect
// through `run_admitted_effect_with_context_and_value_storage_chirho` (effect_chirho.rs), which
// applies the viewer SEAL (`sealed_value_subject = outcome.private_subject` at :742) the ladder never
// touched. The completion therefore rests as a PrivateBlobRef sealed to the requesting viewer, and is
// read back through the private DAG-value plane -- never public CAS.
// ---------------------------------------------------------------------------------------------------

/// Drive one served-LLM effect through the DISPATCHER (not the ladder directly), injecting the stub
/// composition via the run-options `llm_served` port. Returns the signed `EffectChirho`; the
/// completion (if any) rests sealed under the viewer subject the dispatcher applied.
#[allow(clippy::too_many_arguments)]
fn run_one_llm_effect_through_dispatcher_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    harness_chirho: &JournalHarnessChirho,
    journal_chirho: &mut LedgerJournalChirho<'_>,
    provider_chirho: &dyn LlmProviderChirho,
    request_bytes_chirho: &[u8],
    run_chirho: &HashChirho,
    replay_chirho: bool,
    seq_chirho: u64,
    idem_key_chirho: HashChirho,
) -> anyhow::Result<crate::model_chirho::EffectChirho> {
    let node_chirho = llm_node_chirho();
    let node_hash_chirho = crate::store_chirho::hash_object_chirho(&node_chirho)?;
    let capability_chirho = node_chirho.capabilities_chirho[0].clone();
    let admission_chirho = crate::blessed_chirho::admit_verified_node_effect_chirho(
        &node_chirho,
        &node_hash_chirho,
        &capability_chirho,
    )?;
    let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
        journal_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    );
    let mut composition_chirho = LocalLlmServedCompositionChirho::open_chirho(
        root_chirho,
        &mut adapter_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
        &AppPriceBookUserPaysLlmPolicyChirho,
        provider_chirho,
        AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
    )?;
    with_run_intent_execution_chirho(run_chirho, replay_chirho, || {
        with_run_intent_effect_invocation_chirho(&node_hash_chirho, 0, || {
            super::super::run_admitted_effect_with_context_and_value_storage_chirho(
                root_chirho,
                seq_chirho,
                idem_key_chirho.clone(),
                capability_chirho.clone(),
                request_bytes_chirho,
                super::super::run_options_chirho::AdmittedEffectRunOptionsChirho {
                    storage_chirho:
                        super::super::run_options_chirho::EffectValueStorageChirho::default(),
                    request_context_chirho: Some(context_chirho),
                    attribution_source_chirho:
                        crate::dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
                            Some(context_chirho),
                            None,
                        ),
                    admission_chirho: &admission_chirho,
                    postgres_reversible_chirho: None,
                    llm_served_chirho: Some(&mut composition_chirho),
                },
            )
        })
    })
}

/// S3 arm 1: a completed draft served THROUGH THE DISPATCHER charges the FLAT price and rests its
/// completion SEALED to the requesting viewer. The viewer can read the completion back through the
/// private DAG-value plane; the drafted business name (a PII needle) reaches NO public surface. This
/// exercises the S2c seal wiring the S2d ladder arms never reached.
#[test]
fn served_completion_charges_flat_price_and_seals_to_the_viewer_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let pii_needle_chirho = "Zzyzx-S3-Served-Completion-Needle-Chirho";
    let request_bytes_chirho = valid_request_bytes_chirho(pii_needle_chirho);
    let run_chirho = HashChirho("a".repeat(64));

    let effect_chirho = run_one_llm_effect_through_dispatcher_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &StubLlmProviderChirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
        0,
        HashChirho("s3-served-completion-idem-chirho".to_owned()),
    )
    .expect("a served completion succeeds through the dispatcher");

    // The completion rests SEALED to the requesting viewer, read back through the private plane.
    let response_hash_chirho = effect_chirho
        .response_chirho
        .expect("a completion has a response");
    let sealed_completion_bytes_chirho =
        crate::dag_private_value_chirho::load_private_dag_value_bytes_chirho(
            &root_chirho,
            &context_chirho.user_principal_chirho,
            &response_hash_chirho,
        )
        .expect("the viewer reads its own sealed completion");
    let response_chirho: LlmResponseChirho =
        serde_json::from_slice(&sealed_completion_bytes_chirho)
            .expect("a completion response body");
    assert!(
        response_chirho
            .completion_chirho
            .contains(pii_needle_chirho),
        "the viewer's sealed completion carries the drafted business name"
    );

    // The PII needle reaches NO public surface (the completion rests only as a sealed private blob).
    assert!(
        matches!(
            scan_root_surfaces_chirho(&root_chirho, pii_needle_chirho.as_bytes()),
            RootSurfaceScanChirho::CleanAndCompleteChirho
        ),
        "the completion text must not rest on any public surface under the root"
    );

    // Money: the payer is charged EXACTLY the flat price (not tokens_used x price), settlement
    // credited it, no Hold remains.
    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .cloned()
        .expect("payer head state");
    assert_eq!(
        payer_chirho.debits_total_chirho, LLM_PRICE_CHIRHO,
        "a served completion charges exactly the fixed per-call price"
    );
    assert_eq!(payer_chirho.held_chirho, 0);
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .expect("settlement head state")
            .credits_total_chirho,
        LLM_PRICE_CHIRHO,
        "settlement is credited exactly the fixed price"
    );
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// S3 arm 2: a REFUSED served draft returns a typed llm-refusal-v1 the product renders and charges
/// NOTHING -- no Hold, no provider. The refusal lever (PFE gpt's ask) is a request that fails
/// `LlmRequestChirho::validate_chirho`: a wrong schema tag or an unserved response_format ->
/// ResponseUnparseable, decided BEFORE the money ladder. The refusal BODY carries no PII and rests
/// in public CAS -- but the PROMPT (request) carries her free text and must rest SEALED to the
/// viewer even on a refusal (ruling 4 holds on BOTH outcomes). This arm pins that: it is the
/// coverage the S3 audit found missing, under which the malformed prompt had rested in public CAS.
#[test]
fn served_refusal_returns_typed_body_and_charges_nothing_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let pii_needle_chirho = "Zzyzx-S3-Served-Refusal-Needle-Chirho";
    // Valid JSON, but a response_format the port does not serve -> validate_chirho refuses. The
    // prompt still carries her free text (the needle), which must not leak on the refusal road.
    let malformed_chirho = serde_json::to_vec(&LlmRequestChirho {
        schema_chirho: LLM_REQUEST_SCHEMA_CHIRHO.to_owned(),
        system_chirho: "You draft a small business landing page.".to_owned(),
        user_chirho: format!("Business name: {pii_needle_chirho}"),
        max_tokens_chirho: None,
        response_format_chirho: "not-a-served-format-chirho".to_owned(),
    })
    .unwrap();
    let run_chirho = HashChirho("b".repeat(64));

    let effect_chirho = run_one_llm_effect_through_dispatcher_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &StubLlmProviderChirho,
        &malformed_chirho,
        &run_chirho,
        false,
        0,
        HashChirho("s3-served-refusal-idem-chirho".to_owned()),
    )
    .expect("a refusal is a typed body, not an error");

    // The response is a typed llm-refusal-v1 (ResponseUnparseable), in public CAS (no PII to seal).
    let response_hash_chirho = effect_chirho
        .response_chirho
        .expect("a refusal has a response");
    let refusal_bytes_chirho = crate::cas_chirho::get_chirho(&root_chirho, &response_hash_chirho)
        .expect("the refusal body rests in public CAS (no PII to seal)");
    let refusal_chirho: LlmRefusalChirho =
        serde_json::from_slice(&refusal_bytes_chirho).expect("a typed refusal body");
    assert_eq!(
        refusal_chirho.refusal_code_chirho,
        LlmRefusalCodeChirho::ResponseUnparseableChirho,
        "a malformed request refuses with the response-unparseable identity"
    );

    // Nothing charged: the refusal is decided before the Hold, so no debit, no settlement, no append.
    assert_eq!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(&context_chirho.user_principal_chirho))
            .map(|state_chirho| state_chirho.debits_total_chirho)
            .unwrap_or(0),
        0,
        "a refused draft charges nothing"
    );
    assert!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .is_none(),
        "a refused draft credits no settlement"
    );
    assert_eq!(
        journal_chirho.tail_seq_chirho(),
        initial_tail_chirho,
        "a refusal appends nothing to the money journal"
    );

    // Ruling 4 on the REFUSAL road: the PROMPT (request) carries her free text and must rest SEALED
    // to the viewer, NEVER in public CAS -- even though the refusal set no response seal subject.
    // Before the S3-audit fix the malformed prompt rested in public CAS here; this is that pin.
    assert!(
        matches!(
            scan_root_surfaces_chirho(&root_chirho, pii_needle_chirho.as_bytes()),
            RootSurfaceScanChirho::CleanAndCompleteChirho
        ),
        "the refused prompt must not rest on any public surface under the root"
    );
    let sealed_request_bytes_chirho =
        crate::dag_private_value_chirho::load_private_dag_value_bytes_chirho(
            &root_chirho,
            &context_chirho.user_principal_chirho,
            &effect_chirho.request_chirho,
        )
        .expect("the viewer reads its own sealed prompt back");
    assert!(
        sealed_request_bytes_chirho
            .windows(pii_needle_chirho.len())
            .any(|window_chirho| window_chirho == pii_needle_chirho.as_bytes()),
        "the refused prompt rests sealed under the viewer, carrying her free text"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// S3 arm 3: a PROVIDER refusal served THROUGH THE DISPATCHER returns the exact injected typed code,
/// Releases the whole Hold (nothing charged), and STILL rests the prompt SEALED to the viewer -- the
/// SECOND refusal road ruling 4 must hold on, and the one PFE's `CAIRN_LLM_STUB_REFUSE_CHIRHO` dev
/// knob drives through the real door + mapper. Unlike the ladder-direct provider-refusal arm, this
/// runs the dispatcher's request-copy forcing, where the S3-audit leak lived.
#[test]
fn served_provider_refusal_seals_the_prompt_and_charges_nothing_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let pii_needle_chirho = "Zzyzx-S3-Provider-Refusal-Needle-Chirho";
    let request_bytes_chirho = valid_request_bytes_chirho(pii_needle_chirho);
    let run_chirho = HashChirho("c".repeat(64));
    let provider_chirho = RefusingLlmProviderChirho {
        code_chirho: LlmRefusalCodeChirho::ProviderUnavailableChirho,
    };

    let effect_chirho = run_one_llm_effect_through_dispatcher_chirho(
        &root_chirho,
        &context_chirho,
        &harness_chirho,
        &mut journal_chirho,
        &provider_chirho,
        &request_bytes_chirho,
        &run_chirho,
        false,
        0,
        HashChirho("s3-served-provider-refusal-idem-chirho".to_owned()),
    )
    .expect("a provider refusal is a typed body, not an error");

    // The response is the EXACT injected typed code, in public CAS (a refusal body carries no PII).
    let response_hash_chirho = effect_chirho
        .response_chirho
        .expect("a refusal has a response");
    let refusal_bytes_chirho = crate::cas_chirho::get_chirho(&root_chirho, &response_hash_chirho)
        .expect("the refusal body rests in public CAS (no PII to seal)");
    let refusal_chirho: LlmRefusalChirho =
        serde_json::from_slice(&refusal_bytes_chirho).expect("a typed refusal body");
    assert_eq!(
        refusal_chirho.refusal_code_chirho,
        LlmRefusalCodeChirho::ProviderUnavailableChirho,
        "the refusal identity is exactly the injected provider code"
    );

    // Money: a provider refusal Releases the whole Hold -- nothing charged, no settlement credited
    // (Hold + Release is tail +2, net zero).
    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&account_chirho(&context_chirho.user_principal_chirho))
        .cloned()
        .expect("payer head state");
    assert_eq!(
        payer_chirho.debits_total_chirho, 0,
        "a provider refusal never debits the payer"
    );
    assert_eq!(payer_chirho.held_chirho, 0, "the Hold is released");
    assert!(
        journal_chirho
            .head_states_chirho()
            .get(&account_chirho(SETTLEMENT_OWNER_CHIRHO))
            .is_none(),
        "a provider refusal credits no settlement"
    );
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);

    // Ruling 4 on the provider-refusal road: the PROMPT rests SEALED to the viewer, NOT public.
    assert!(
        matches!(
            scan_root_surfaces_chirho(&root_chirho, pii_needle_chirho.as_bytes()),
            RootSurfaceScanChirho::CleanAndCompleteChirho
        ),
        "the refused prompt must not rest on any public surface under the root"
    );
    let sealed_request_bytes_chirho =
        crate::dag_private_value_chirho::load_private_dag_value_bytes_chirho(
            &root_chirho,
            &context_chirho.user_principal_chirho,
            &effect_chirho.request_chirho,
        )
        .expect("the viewer reads its own sealed prompt back");
    assert!(
        sealed_request_bytes_chirho
            .windows(pii_needle_chirho.len())
            .any(|window_chirho| window_chirho == pii_needle_chirho.as_bytes()),
        "the refused prompt rests sealed under the viewer, carrying her free text"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
