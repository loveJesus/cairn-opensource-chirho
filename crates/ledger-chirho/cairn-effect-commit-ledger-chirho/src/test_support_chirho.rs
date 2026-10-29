// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use anyhow::{anyhow, Result};
use cairn_effect_commit_chirho::compensation_chirho::{
    authorize_effect_compensation_chirho, CompensationAuthorizationFactsChirho,
    CompensationAuthorizationViewChirho, CompensationAuthorizationViewErrorChirho,
    CompensationBreakerVerdictChirho, EffectCompensationAuthorizationOutcomeChirho,
    VerifiedEffectCompensationChirho,
};
use cairn_effect_commit_chirho::coordinator_chirho::{
    BlessedEffectProviderPortChirho, EffectCommitEvidencePortChirho, EffectEvidencePortErrorChirho,
    EffectProviderEvidenceBytesChirho, EffectProviderObservationChirho,
    EffectProviderPortErrorChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    EffectIntentSignerPortChirho, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
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
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

pub const MONEY_KIND_CHIRHO: &str = "money-chirho";
pub const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
pub const GOOD_MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";
pub const DIGEST_A_CHIRHO: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const DIGEST_B_CHIRHO: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const DIGEST_C_CHIRHO: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
pub const DIGEST_D_CHIRHO: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
pub const DIGEST_E_CHIRHO: &str =
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
pub const DIGEST_F_CHIRHO: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[derive(Default)]
pub struct MemoryStorageChirho {
    objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
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
        new_len_chirho: u64,
    ) -> Result<()> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .get_mut(&path_chirho.0)
            .ok_or_else(|| anyhow!("missing object"))?;
        if new_len_chirho > bytes_chirho.len() as u64 {
            return Err(anyhow!("truncate can only shorten"));
        }
        bytes_chirho.truncate(new_len_chirho as usize);
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
            .ok_or_else(|| anyhow!("missing rename source"))?;
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

pub struct SettableClockChirho {
    pub now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for SettableClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.get()
    }
}

pub struct FakeRootChirho {
    pub root_chirho: &'static str,
}

impl FakeRootChirho {
    fn signature_chirho(&self, content_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(self.root_chirho.as_bytes());
        hasher_chirho.update(content_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl LedgerSignerPortChirho for FakeRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == self.signature_chirho(signed_content_line_chirho)
    }
}

impl EffectIntentSignerPortChirho for FakeRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == self.signature_chirho(signed_content_line_chirho)
    }
}

impl EffectTerminalSignerPortChirho for FakeRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == self.signature_chirho(signed_content_line_chirho)
    }
}

struct OpenMembershipChirho {
    members_chirho: BTreeSet<String>,
}

impl MembershipViewChirho for OpenMembershipChirho {
    fn status_chirho(
        &self,
        account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        if self.members_chirho.contains(&account_chirho.owner_chirho) {
            MembershipStatusChirho::MemberChirho
        } else {
            MembershipStatusChirho::NonMemberChirho
        }
    }
}

struct MoneyRegistryChirho;

impl MoneyRegistryChirho {
    fn policy_chirho(&self) -> KindPolicyViewChirho {
        KindPolicyViewChirho {
            kind_id_chirho: MONEY_KIND_CHIRHO.into(),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(1_000),
            },
            rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
            settlement_owner_chirho: Some("platform-chirho".to_owned()),
            idempotency_window_chirho: Some(IdempotencyWindowPolicyViewChirho {
                idempotency_horizon_ms_chirho: 1_000,
                retry_finality_horizon_ms_chirho: 500,
            }),
        }
    }
}

impl KindRegistryViewChirho for MoneyRegistryChirho {
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

struct EvidenceAuthorityChirho;

impl AuthorityVerifierViewChirho for EvidenceAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        if evidence_chirho.0 == GOOD_MINT_EVIDENCE_CHIRHO && kind_id_chirho.0 == MONEY_KIND_CHIRHO {
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

pub struct IntegrationHarnessChirho {
    pub storage_chirho: MemoryStorageChirho,
    pub clock_chirho: SettableClockChirho,
    pub ledger_root_chirho: FakeRootChirho,
    pub intent_root_chirho: FakeRootChirho,
    pub terminal_root_chirho: FakeRootChirho,
    membership_chirho: OpenMembershipChirho,
    registry_chirho: MoneyRegistryChirho,
    authority_chirho: EvidenceAuthorityChirho,
}

impl IntegrationHarnessChirho {
    pub fn new_chirho() -> Self {
        Self {
            storage_chirho: MemoryStorageChirho::default(),
            clock_chirho: SettableClockChirho {
                now_ms_chirho: Cell::new(1_000),
            },
            ledger_root_chirho: FakeRootChirho {
                root_chirho: "ledger-root-chirho",
            },
            intent_root_chirho: FakeRootChirho {
                root_chirho: "intent-root-chirho",
            },
            terminal_root_chirho: FakeRootChirho {
                root_chirho: "terminal-root-chirho",
            },
            membership_chirho: OpenMembershipChirho {
                members_chirho: ["issuer-chirho", "payer-chirho", "platform-chirho"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
            registry_chirho: MoneyRegistryChirho,
            authority_chirho: EvidenceAuthorityChirho,
        }
    }

    pub fn ports_chirho(&self) -> JournalPortsChirho<'_> {
        JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: &self.ledger_root_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }

    pub fn path_chirho(&self) -> StoragePathChirho {
        StoragePathChirho::new_chirho("journals/cf3-integration-chirho.jsonl")
    }

    pub fn cluster_chirho(&self) -> ClusterIdChirho {
        ClusterIdChirho("cluster-cf3-chirho".to_owned())
    }

    pub fn funded_journal_chirho(&self) -> LedgerJournalChirho<'_> {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            self.ports_chirho(),
            self.path_chirho(),
            self.cluster_chirho(),
            1,
        )
        .unwrap();
        self.clock_chirho.now_ms_chirho.set(1_100);
        journal_chirho.append_chirho(mint_request_chirho()).unwrap();
        self.clock_chirho.now_ms_chirho.set(1_200);
        journal_chirho.append_chirho(fund_request_chirho()).unwrap();
        journal_chirho
    }

    pub fn reopen_chirho(&self) -> LedgerJournalChirho<'_> {
        LedgerJournalChirho::open_chirho(
            self.ports_chirho(),
            self.path_chirho(),
            &self.cluster_chirho(),
        )
        .unwrap()
    }
}

pub fn signed_intent_line_chirho(
    journal_chirho: &LedgerJournalChirho<'_>,
    root_chirho: &FakeRootChirho,
) -> (EffectIntentChirho, String) {
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: journal_chirho.effect_intent_cut_chirho(),
            contract_set_digest_chirho: digest_chirho(DIGEST_A_CHIRHO),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": DIGEST_B_CHIRHO,
                "capability_fingerprint_chirho": DIGEST_C_CHIRHO,
            }))
            .unwrap(),
            reversion_contract_digest_chirho: digest_chirho(DIGEST_D_CHIRHO),
            request_ref_chirho: digest_chirho(DIGEST_E_CHIRHO),
            request_context_ref_chirho: digest_chirho(DIGEST_F_CHIRHO),
            evidence_refs_chirho: vec![digest_chirho(DIGEST_A_CHIRHO)],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
                kind_policy_ref_chirho: policy_ref_chirho(),
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: account_chirho("payer-chirho"),
            effect_step_chirho: 7,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: "payer-chirho".to_owned(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        root_chirho,
    )
    .unwrap();
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    (intent_chirho, line_chirho)
}

pub fn signed_compensation_intent_line_chirho(
    journal_chirho: &LedgerJournalChirho<'_>,
    root_chirho: &FakeRootChirho,
    original_effect_key_chirho: &str,
    request_ref_chirho: DigestChirho,
) -> (EffectIntentChirho, String) {
    let (mut intent_chirho, _) = signed_intent_line_chirho(journal_chirho, root_chirho);
    intent_chirho.original_effect_key_chirho = Some(original_effect_key_chirho.to_owned());
    intent_chirho.request_ref_chirho = request_ref_chirho;
    intent_chirho.sig_chirho.clear();
    intent_chirho.key_id_chirho.clear();
    let intent_chirho = sign_effect_intent_chirho(intent_chirho, root_chirho).unwrap();
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    (intent_chirho, line_chirho)
}

struct PermittingCompensationViewChirho;

impl CompensationAuthorizationViewChirho for PermittingCompensationViewChirho {
    fn derive_chirho(
        &self,
        candidate_chirho: &cairn_effect_commit_chirho::intent_chirho::VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        let original_effect_key_chirho = candidate_chirho
            .intent_chirho()
            .original_effect_key_chirho
            .clone()
            .ok_or_else(|| CompensationAuthorizationViewErrorChirho::RefusedChirho {
                detail_chirho: "candidate has no original effect K".to_owned(),
            })?;
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            original_effect_key_chirho.clone(),
            original_effect_key_chirho,
            1,
            4,
            CompensationBreakerVerdictChirho::PermittedChirho,
        ))
    }
}

pub fn authorized_compensation_chirho(
    canonical_intent_line_chirho: &str,
    root_chirho: &FakeRootChirho,
) -> VerifiedEffectCompensationChirho {
    match authorize_effect_compensation_chirho(
        canonical_intent_line_chirho,
        root_chirho,
        &PermittingCompensationViewChirho,
    )
    .unwrap()
    {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(token_chirho) => {
            token_chirho
        }
        EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(_) => {
            panic!("permitting compensation view unexpectedly returned pending/manual")
        }
    }
}

pub fn account_chirho(owner_chirho: &str) -> AccountIdChirho {
    LogIdChirho::new_chirho(owner_chirho, MONEY_KIND_CHIRHO)
}

fn policy_ref_chirho() -> AssetKindRefChirho {
    AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.to_owned()))
}

fn digest_chirho(value_chirho: &str) -> DigestChirho {
    DigestChirho(value_chirho.to_owned())
}

fn mint_request_chirho() -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(GOOD_MINT_EVIDENCE_CHIRHO.to_owned()),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: account_chirho("issuer-chirho"),
            kind_policy_ref_chirho: policy_ref_chirho(),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 500,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: "cf3-integration-mint-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

fn fund_request_chirho() -> AppendRequestChirho {
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
            leg_chirho("payer-chirho", LegDeltaChirho::CreditChirho),
        ],
        idempotency_key_chirho: "cf3-integration-fund-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

#[derive(Clone, Copy)]
pub struct ProviderReplyChirho {
    mode_chirho: u8,
}

impl ProviderReplyChirho {
    pub fn committed_chirho() -> Self {
        Self { mode_chirho: 1 }
    }

    pub fn definite_no_effect_chirho() -> Self {
        Self { mode_chirho: 2 }
    }

    pub fn transport_error_chirho() -> Self {
        Self { mode_chirho: 3 }
    }
}

pub struct ScriptedProviderChirho {
    pub execute_reply_chirho: ProviderReplyChirho,
    pub query_reply_chirho: ProviderReplyChirho,
    pub execute_calls_chirho: usize,
    pub query_calls_chirho: usize,
}

impl ScriptedProviderChirho {
    pub fn new_chirho(
        execute_reply_chirho: ProviderReplyChirho,
        query_reply_chirho: ProviderReplyChirho,
    ) -> Self {
        Self {
            execute_reply_chirho,
            query_reply_chirho,
            execute_calls_chirho: 0,
            query_calls_chirho: 0,
        }
    }
}

impl BlessedEffectProviderPortChirho for ScriptedProviderChirho {
    fn execute_or_replay_chirho(
        &mut self,
        _intent_chirho: &cairn_effect_commit_chirho::intent_chirho::VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        self.execute_calls_chirho += 1;
        observation_chirho(self.execute_reply_chirho)
    }

    fn query_by_key_chirho(
        &mut self,
        _intent_chirho: &cairn_effect_commit_chirho::intent_chirho::VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        self.query_calls_chirho += 1;
        observation_chirho(self.query_reply_chirho)
    }
}

fn observation_chirho(
    reply_chirho: ProviderReplyChirho,
) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
    match reply_chirho.mode_chirho {
        1 => Ok(EffectProviderObservationChirho::CommittedChirho {
            result_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
            evidence_chirho: EffectProviderEvidenceBytesChirho::new_chirho(
                b"provider-committed-evidence-chirho".to_vec(),
            )
            .unwrap(),
        }),
        2 => Ok(EffectProviderObservationChirho::DefiniteNoEffectChirho {
            evidence_chirho: EffectProviderEvidenceBytesChirho::new_chirho(
                b"provider-no-effect-evidence-chirho".to_vec(),
            )
            .unwrap(),
        }),
        3 => Err(EffectProviderPortErrorChirho::UnavailableChirho {
            detail_chirho: "injected transport ambiguity".to_owned(),
        }),
        _ => Ok(EffectProviderObservationChirho::InDoubtChirho),
    }
}

#[derive(Default)]
pub struct MemoryEvidenceChirho {
    pub intent_lines_chirho: BTreeMap<DigestChirho, String>,
    pub compensation_intent_lines_chirho: BTreeMap<String, String>,
    pub provider_bytes_chirho: BTreeMap<DigestChirho, Vec<u8>>,
    pub terminal_lines_chirho: BTreeMap<DigestChirho, String>,
    pub fail_compensation_create_once_chirho: bool,
    pub fail_provider_store_once_chirho: bool,
    pub fail_terminal_store_once_chirho: bool,
}

impl EffectCommitEvidencePortChirho for MemoryEvidenceChirho {
    fn store_intent_line_chirho(
        &mut self,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        store_same_chirho(
            &mut self.intent_lines_chirho,
            intent_ref_chirho,
            canonical_line_chirho.to_owned(),
        )
    }

    fn load_intent_line_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<Option<String>, EffectEvidencePortErrorChirho> {
        Ok(self.intent_lines_chirho.get(intent_ref_chirho).cloned())
    }

    fn create_or_load_compensation_intent_line_chirho(
        &mut self,
        compensation_key_chirho: &str,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<String, EffectEvidencePortErrorChirho> {
        if self.fail_compensation_create_once_chirho {
            self.fail_compensation_create_once_chirho = false;
            return Err(EffectEvidencePortErrorChirho::UnavailableChirho {
                detail_chirho: "injected compensation evidence create cut".to_owned(),
            });
        }
        if self
            .compensation_intent_lines_chirho
            .get(compensation_key_chirho)
            .is_some_and(|existing_chirho| existing_chirho != canonical_line_chirho)
            || self
                .intent_lines_chirho
                .get(intent_ref_chirho)
                .is_some_and(|existing_chirho| existing_chirho != canonical_line_chirho)
        {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "compensation K or intent ref already binds different evidence"
                    .to_owned(),
            });
        }
        self.compensation_intent_lines_chirho.insert(
            compensation_key_chirho.to_owned(),
            canonical_line_chirho.to_owned(),
        );
        self.intent_lines_chirho
            .insert(intent_ref_chirho.clone(), canonical_line_chirho.to_owned());
        Ok(canonical_line_chirho.to_owned())
    }

    fn store_provider_evidence_chirho(
        &mut self,
        evidence_ref_chirho: &DigestChirho,
        evidence_bytes_chirho: &[u8],
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        if self.fail_provider_store_once_chirho {
            self.fail_provider_store_once_chirho = false;
            return Err(EffectEvidencePortErrorChirho::UnavailableChirho {
                detail_chirho: "injected provider-evidence cut".to_owned(),
            });
        }
        store_same_chirho(
            &mut self.provider_bytes_chirho,
            evidence_ref_chirho,
            evidence_bytes_chirho.to_vec(),
        )
    }

    fn store_terminal_outcome_line_chirho(
        &mut self,
        outcome_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        if self.fail_terminal_store_once_chirho {
            self.fail_terminal_store_once_chirho = false;
            return Err(EffectEvidencePortErrorChirho::UnavailableChirho {
                detail_chirho: "injected terminal-evidence cut".to_owned(),
            });
        }
        store_same_chirho(
            &mut self.terminal_lines_chirho,
            outcome_ref_chirho,
            canonical_line_chirho.to_owned(),
        )
    }
}

fn store_same_chirho<ValueChirho: Clone + PartialEq>(
    map_chirho: &mut BTreeMap<DigestChirho, ValueChirho>,
    key_chirho: &DigestChirho,
    value_chirho: ValueChirho,
) -> Result<(), EffectEvidencePortErrorChirho> {
    if let Some(existing_chirho) = map_chirho.get(key_chirho) {
        if existing_chirho != &value_chirho {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "content ref already binds different evidence".to_owned(),
            });
        }
        return Ok(());
    }
    map_chirho.insert(key_chirho.clone(), value_chirho);
    Ok(())
}

pub fn assert_settled_once_chirho(journal_chirho: &LedgerJournalChirho<'_>) {
    let payer_chirho = journal_chirho
        .head_state_chirho(&account_chirho("payer-chirho"))
        .unwrap();
    assert_eq!(payer_chirho.credits_total_chirho, 100);
    assert_eq!(payer_chirho.debits_total_chirho, 10);
    assert_eq!(payer_chirho.held_chirho, 0);
    let platform_chirho = journal_chirho
        .head_state_chirho(&account_chirho("platform-chirho"))
        .unwrap();
    assert_eq!(platform_chirho.credits_total_chirho, 10);
    assert_eq!(platform_chirho.debits_total_chirho, 0);
    assert_eq!(platform_chirho.held_chirho, 0);
    assert_eq!(
        journal_chirho.supply_chirho(&AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned())),
        500
    );
}
