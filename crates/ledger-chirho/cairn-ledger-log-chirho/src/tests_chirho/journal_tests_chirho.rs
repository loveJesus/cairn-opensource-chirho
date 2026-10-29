// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! B-2 engine proofs: create→append→reopen recovery EQUIVALENCE (the live state and the
//! full-verify rebuild agree exactly), chain tamper-evidence (a flipped amount, a flipped sig, a
//! reordered line, a planted second genesis all refuse), torn-tail REPAIR (unacknowledged suffix
//! dropped after the prefix verifies; torn GENESIS stays fail-closed), the HLC monotone
//! guard under a stuck AND a regressing clock, and the admission gate wired into the append path.
//! (The full crash/fault matrix drives from `cairn-ledger-sim-chirho`, which injects faults at the
//! ports this engine speaks.)

use crate::admission_chirho::*;
use crate::journal_chirho::*;
use crate::ports_chirho::*;
use anyhow::{anyhow, Result};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::*;
use cairn_ledger_model_chirho::record_chirho::*;
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MONEY_KIND_CHIRHO: &str = "money-chirho";
pub(crate) const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
pub(crate) const GOOD_MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";

/// Plain in-memory storage honoring the port contract (incl. fail-closed exact-range semantics).
/// The FAULT-INJECTING twin lives in the sim crate; this one is for engine-law tests only.
#[derive(Default)]
pub(crate) struct MemoryStorageChirho {
    objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
    read_all_calls_chirho: Cell<usize>,
    object_len_calls_chirho: Cell<usize>,
    read_exact_range_calls_chirho: Cell<usize>,
    list_calls_chirho: Cell<usize>,
    exists_calls_chirho: Cell<usize>,
    create_durable_calls_chirho: Cell<usize>,
    append_durable_calls_chirho: Cell<usize>,
    atomic_write_calls_chirho: Cell<usize>,
    truncate_durable_calls_chirho: Cell<usize>,
    rename_calls_chirho: Cell<usize>,
    remove_calls_chirho: Cell<usize>,
}

impl MemoryStorageChirho {
    pub(crate) fn traversal_read_counts_chirho(&self) -> [usize; 5] {
        [
            self.object_len_calls_chirho.get(),
            self.read_exact_range_calls_chirho.get(),
            self.read_all_calls_chirho.get(),
            self.list_calls_chirho.get(),
            self.exists_calls_chirho.get(),
        ]
    }

    pub(crate) fn storage_write_counts_chirho(&self) -> [usize; 6] {
        [
            self.create_durable_calls_chirho.get(),
            self.append_durable_calls_chirho.get(),
            self.atomic_write_calls_chirho.get(),
            self.truncate_durable_calls_chirho.get(),
            self.rename_calls_chirho.get(),
            self.remove_calls_chirho.get(),
        ]
    }
}

impl LedgerStoragePortChirho for MemoryStorageChirho {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<CreateDurableOutcomeChirho> {
        self.create_durable_calls_chirho
            .set(self.create_durable_calls_chirho.get() + 1);
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        match objects_chirho.entry(path_chirho.0.clone()) {
            std::collections::btree_map::Entry::Vacant(entry_chirho) => {
                entry_chirho.insert(bytes_chirho.to_vec());
                Ok(CreateDurableOutcomeChirho::CreatedChirho)
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Ok(CreateDurableOutcomeChirho::AlreadyExistsChirho)
            }
        }
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        self.append_durable_calls_chirho
            .set(self.append_durable_calls_chirho.get() + 1);
        self.objects_chirho
            .borrow_mut()
            .entry(path_chirho.0.clone())
            .or_default()
            .extend_from_slice(bytes_chirho);
        Ok(())
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<Vec<u8>>> {
        self.read_all_calls_chirho
            .set(self.read_all_calls_chirho.get() + 1);
        Ok(self.objects_chirho.borrow().get(&path_chirho.0).cloned())
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>> {
        self.object_len_calls_chirho
            .set(self.object_len_calls_chirho.get() + 1);
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
        self.read_exact_range_calls_chirho
            .set(self.read_exact_range_calls_chirho.get() + 1);
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
        self.atomic_write_calls_chirho
            .set(self.atomic_write_calls_chirho.get() + 1);
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
        self.truncate_durable_calls_chirho
            .set(self.truncate_durable_calls_chirho.get() + 1);
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
        self.rename_calls_chirho
            .set(self.rename_calls_chirho.get() + 1);
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .remove(&from_chirho.0)
            .ok_or_else(|| anyhow!("missing rename source"))?;
        objects_chirho.insert(to_chirho.0.clone(), bytes_chirho);
        Ok(())
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()> {
        self.remove_calls_chirho
            .set(self.remove_calls_chirho.get() + 1);
        self.objects_chirho.borrow_mut().remove(&path_chirho.0);
        Ok(())
    }

    fn list_chirho(&self, prefix_chirho: &StoragePathChirho) -> Result<Vec<StoragePathChirho>> {
        self.list_calls_chirho.set(self.list_calls_chirho.get() + 1);
        Ok(self
            .objects_chirho
            .borrow()
            .keys()
            .filter(|key_chirho| key_chirho.starts_with(&prefix_chirho.0))
            .map(|key_chirho| StoragePathChirho(key_chirho.clone()))
            .collect())
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool> {
        self.exists_calls_chirho
            .set(self.exists_calls_chirho.get() + 1);
        Ok(self.objects_chirho.borrow().contains_key(&path_chirho.0))
    }
}

pub(crate) struct SettableClockChirho {
    pub(crate) now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for SettableClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.get()
    }
}

/// Deterministic signer: the sig is a labeled digest of the signed content (label-only, §11.1).
#[derive(Default)]
pub(crate) struct FakeSignerChirho {
    sign_calls_chirho: Cell<usize>,
}

impl FakeSignerChirho {
    pub(crate) fn sign_calls_chirho(&self) -> usize {
        self.sign_calls_chirho.get()
    }
}

impl LedgerSignerPortChirho for FakeSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        self.sign_calls_chirho.set(self.sign_calls_chirho.get() + 1);
        Ok(format!(
            "fake-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "test-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

pub(crate) struct OpenMembershipChirho {
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

pub(crate) struct MoneyRegistryChirho {
    pub(crate) settlement_owner_chirho: Option<String>,
}

impl KindRegistryViewChirho for MoneyRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        (policy_ref_chirho.0 .0 == MONEY_POLICY_REF_CHIRHO)
            .then(|| KindPolicyViewChirho {
                kind_id_chirho: MONEY_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: Some(1_000),
                },
                rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
                settlement_owner_chirho: self.settlement_owner_chirho.clone(),
                idempotency_window_chirho: Some(IdempotencyWindowPolicyViewChirho {
                    idempotency_horizon_ms_chirho: 1_000,
                    retry_finality_horizon_ms_chirho: 500,
                }),
            })
            .map_or(
                KindResolutionChirho::UnknownChirho,
                KindResolutionChirho::CurrentChirho,
            )
    }

    fn resolve_current_continuation_by_kind_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Option<CurrentContinuationPolicyChirho> {
        (kind_id_chirho.0 == MONEY_KIND_CHIRHO).then(|| CurrentContinuationPolicyChirho {
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                MONEY_POLICY_REF_CHIRHO.to_owned(),
            )),
            policy_chirho: KindPolicyViewChirho {
                kind_id_chirho: MONEY_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: Some(1_000),
                },
                rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
                settlement_owner_chirho: self.settlement_owner_chirho.clone(),
                idempotency_window_chirho: Some(IdempotencyWindowPolicyViewChirho {
                    idempotency_horizon_ms_chirho: 1_000,
                    retry_finality_horizon_ms_chirho: 500,
                }),
            },
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

pub(crate) struct HarnessChirho {
    pub(crate) storage_chirho: MemoryStorageChirho,
    pub(crate) clock_chirho: SettableClockChirho,
    pub(crate) signer_chirho: FakeSignerChirho,
    membership_chirho: OpenMembershipChirho,
    pub(crate) registry_chirho: MoneyRegistryChirho,
    authority_chirho: EvidenceAuthorityChirho,
}

impl HarnessChirho {
    pub(crate) fn new_chirho() -> Self {
        HarnessChirho {
            storage_chirho: MemoryStorageChirho::default(),
            clock_chirho: SettableClockChirho {
                now_ms_chirho: Cell::new(1_000),
            },
            signer_chirho: FakeSignerChirho::default(),
            membership_chirho: OpenMembershipChirho {
                members_chirho: ["issuer-chirho", "alice-chirho", "bob-chirho"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
            registry_chirho: MoneyRegistryChirho {
                settlement_owner_chirho: None,
            },
            authority_chirho: EvidenceAuthorityChirho,
        }
    }

    pub(crate) fn ports_chirho(&self) -> JournalPortsChirho<'_> {
        JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: &self.signer_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }

    pub(crate) fn path_chirho(&self) -> StoragePathChirho {
        StoragePathChirho::new_chirho("journals/cluster-alpha-chirho.jsonl")
    }

    pub(crate) fn cluster_chirho(&self) -> ClusterIdChirho {
        ClusterIdChirho("cluster-alpha-chirho".into())
    }

    fn tamper_chirho(&self, from_chirho: &str, to_chirho: &str) {
        let path_chirho = self.path_chirho();
        let mut objects_chirho = self.storage_chirho.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho.get_mut(&path_chirho.0).unwrap();
        let text_chirho = String::from_utf8(bytes_chirho.clone()).unwrap();
        assert!(
            text_chirho.contains(from_chirho),
            "tamper target must exist"
        );
        *bytes_chirho = text_chirho.replacen(from_chirho, to_chirho, 1).into_bytes();
    }
}

pub(crate) fn mint_request_chirho(
    owner_chirho: &str,
    amount_chirho: u64,
    idem_chirho: &str,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(GOOD_MINT_EVIDENCE_CHIRHO.into()),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: LogIdChirho::new_chirho(owner_chirho, MONEY_KIND_CHIRHO),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                MONEY_POLICY_REF_CHIRHO.into(),
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

pub(crate) fn transfer_request_chirho(
    from_chirho: &str,
    to_chirho: &str,
    amount_chirho: u64,
    idem_chirho: &str,
) -> AppendRequestChirho {
    let leg_chirho = |owner_chirho: &str, delta_chirho| AppendLegRequestChirho {
        account_chirho: LogIdChirho::new_chirho(owner_chirho, MONEY_KIND_CHIRHO),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.into())),
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

pub(crate) fn account_chirho(owner_chirho: &str) -> AccountIdChirho {
    LogIdChirho::new_chirho(owner_chirho, MONEY_KIND_CHIRHO)
}

#[test]
fn create_append_reopen_recovery_equivalence_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    let mint_receipt_chirho = engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-mint-1"))
        .unwrap();
    assert_eq!(mint_receipt_chirho.seq_chirho, 1);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    let transfer_receipt_chirho = engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            120,
            "idem-t-1",
        ))
        .unwrap();
    assert_eq!(transfer_receipt_chirho.seq_chirho, 2);
    // Snapshot the LIVE state.
    let live_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    let live_genesis_chirho = engine_chirho.genesis_digest_chirho().clone();
    let live_issuer_chirho = engine_chirho
        .head_state_chirho(&account_chirho("issuer-chirho"))
        .cloned();
    let live_alice_chirho = engine_chirho
        .head_state_chirho(&account_chirho("alice-chirho"))
        .cloned();
    let live_supply_chirho = engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into());
    drop(engine_chirho);
    // Reopen: the full-verify rebuild must agree EXACTLY with the live state (recovery law).
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert_eq!(
        (
            reopened_chirho.tail_chirho().0,
            reopened_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho
    );
    assert_eq!(
        reopened_chirho.genesis_digest_chirho(),
        &live_genesis_chirho
    );
    assert_eq!(
        reopened_chirho
            .head_state_chirho(&account_chirho("issuer-chirho"))
            .cloned(),
        live_issuer_chirho
    );
    assert_eq!(
        reopened_chirho
            .head_state_chirho(&account_chirho("alice-chirho"))
            .cloned(),
        live_alice_chirho
    );
    assert_eq!(
        reopened_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into()),
        live_supply_chirho
    );
    // Balances themselves: issuer 500−120, alice +120 (Pr1 posts).
    assert_eq!(
        live_issuer_chirho.unwrap(),
        LegPostStateChirho {
            credits_total_chirho: 500,
            debits_total_chirho: 120,
            held_chirho: 0
        }
    );
    assert_eq!(
        live_alice_chirho.unwrap(),
        LegPostStateChirho {
            credits_total_chirho: 120,
            debits_total_chirho: 0,
            held_chirho: 0
        }
    );
    assert_eq!(live_supply_chirho, 500);
}

#[test]
fn admission_gates_the_append_path_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 100, "idem-mint-1"))
        .unwrap();
    // Duplicate idempotency key refuses and appends nothing.
    let tail_before_chirho = engine_chirho.tail_chirho().0;
    let duplicate_chirho = engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 50, "idem-mint-1"))
        .unwrap_err();
    assert_eq!(
        duplicate_chirho,
        JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::IdempotencyDuplicateChirho
        }
    );
    assert_eq!(engine_chirho.tail_chirho().0, tail_before_chirho);
    // Overdraft refuses on the spendable floor.
    let overdraft_chirho = engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            500,
            "idem-t-over",
        ))
        .unwrap_err();
    assert!(matches!(
        overdraft_chirho,
        JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::SpendableFloorChirho { .. }
        }
    ));
    // Supply cap: 100 + 950 breaches the 1000 cap.
    let over_cap_chirho = engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 950, "idem-mint-2"))
        .unwrap_err();
    assert!(matches!(
        over_cap_chirho,
        JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::SupplyCapExceededChirho
        }
    ));
    // The refused appends left NO trace: reopen agrees with the live tail.
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert_eq!(
        reopened_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().0
    );
}

#[test]
fn hlc_monotone_guard_under_stuck_and_regressing_clock_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    // STUCK clock (same ms as genesis): logical bumps.
    let first_chirho = engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 10, "idem-1"))
        .unwrap();
    assert_eq!(
        first_chirho.hlc_chirho,
        HlcChirho {
            physical_ms_chirho: 1_000,
            logical_chirho: 1
        }
    );
    // REGRESSING clock: physical holds at the tail, logical bumps again — the journal never
    // regresses even when the clock does.
    harness_chirho.clock_chirho.now_ms_chirho.set(400);
    let second_chirho = engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 10, "idem-2"))
        .unwrap();
    assert_eq!(
        second_chirho.hlc_chirho,
        HlcChirho {
            physical_ms_chirho: 1_000,
            logical_chirho: 2
        }
    );
    // Healed clock: physical advances, logical resets.
    harness_chirho.clock_chirho.now_ms_chirho.set(2_000);
    let third_chirho = engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 10, "idem-3"))
        .unwrap();
    assert_eq!(
        third_chirho.hlc_chirho,
        HlcChirho {
            physical_ms_chirho: 2_000,
            logical_chirho: 0
        }
    );
}

#[test]
fn read_only_open_uses_the_signed_advisory_fast_path_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            500,
            "idem-read-only-full-walk-chirho",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    drop(engine_chirho);

    let fully_verified_chirho = LedgerJournalChirho::open_read_only_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(
        fully_verified_chirho.last_open_was_fast_chirho(),
        "the read-only/auditor door uses the signed checkpoint without repair authority"
    );
}

#[test]
fn fast_open_covered_prefix_trust_is_scoped_honestly_chirho() {
    // Self-audit finding #2 (pinned honestly): an interior COVERED-record tamper is NOT detected on
    // the fast path (records 1..covered_seq are not re-read; their integrity rests on the sidecar
    // signature), so the fast open serves the sidecar's HONEST cached balance — no mis-stated money.
    // The SAME tamper fails CLOSED on a full open (prev mismatch). This is the exact recovery-
    // equivalence gap; the RC4-R2 money-decision re-read closes interior detection at read time.
    let harness_chirho = HarnessChirho::new_chirho();
    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-mint-1"))
        .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            120,
            "idem-t-1",
        ))
        .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "bob-chirho",
            30,
            "idem-t-2",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap(); // covers seq 3 (bob), the tail
    drop(engine_chirho);
    let pristine_sidecar_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&sidecar_path_chirho)
        .unwrap()
        .unwrap();
    // Tamper an INTERIOR covered record's bytes SAME-LENGTH (seq 1's idempotency key) so downstream
    // byte offsets stay stable and the covered-TAIL (seq 3) digest still matches the sidecar.
    harness_chirho.tamper_chirho("\"idem-mint-1\"", "\"idem-mint-X\"");
    fn reopen_chirho(
        harness_chirho: &HarnessChirho,
    ) -> Result<LedgerJournalChirho<'_>, JournalErrorChirho> {
        LedgerJournalChirho::open_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &harness_chirho.cluster_chirho(),
        )
    }
    // FAST path: accepts (never reads seq 1), serving the sidecar's HONEST cached balances.
    let fast_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(
        fast_chirho.last_open_was_fast_chirho(),
        "the interior tamper is not on the fast path's read set"
    );
    assert_eq!(fast_chirho.tail_chirho().0, 3);
    assert_eq!(
        fast_chirho
            .head_state_chirho(&account_chirho("issuer-chirho"))
            .unwrap(),
        &LegPostStateChirho {
            credits_total_chirho: 500,
            debits_total_chirho: 150,
            held_chirho: 0
        },
        "no mis-stated money: the sidecar-vouched honest balance is served"
    );
    drop(fast_chirho);
    assert!(matches!(
        LedgerJournalChirho::open_read_only_full_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &harness_chirho.cluster_chirho(),
        ),
        Err(JournalErrorChirho::ChainChirho { .. })
    ));
    // FULL path (sidecar removed): the interior tamper fails CLOSED — seq 2's prev no longer binds
    // seq 1's (changed) digest.
    harness_chirho
        .storage_chirho
        .remove_chirho(&sidecar_path_chirho)
        .unwrap();
    assert!(matches!(
        reopen_chirho(&harness_chirho),
        Err(JournalErrorChirho::ChainChirho { .. })
    ));
    let _ = pristine_sidecar_chirho;
}

#[test]
fn byzantine_tail_and_sidecar_tamper_are_tamper_evident_chirho() {
    // claude2 #4533/#4535: on tamperable durable storage, the SUCCESSOR-LESS tail line's
    // idempotency_key is fold-excluded, successor-unbound, and (pre-fix) sig-unverified — a flip
    // would survive reopen and break exactly-once (a caller retry double-executes). The tail-sig
    // check closes it; because prev chains the stored-line digest, it makes the WHOLE journal
    // tamper-evident on recovery at O(1).
    let harness_chirho = HarnessChirho::new_chirho();
    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-mint-1"))
        .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            120,
            "idem-t-1",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    drop(engine_chirho);
    let pristine_journal_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let pristine_sidecar_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&sidecar_path_chirho)
        .unwrap()
        .unwrap();
    let restore_chirho = |harness_chirho: &HarnessChirho| {
        harness_chirho
            .storage_chirho
            .atomic_write_chirho(&harness_chirho.path_chirho(), &pristine_journal_chirho)
            .unwrap();
        harness_chirho
            .storage_chirho
            .atomic_write_chirho(&sidecar_path_chirho, &pristine_sidecar_chirho)
            .unwrap();
    };
    fn reopen_chirho(
        harness_chirho: &HarnessChirho,
    ) -> Result<LedgerJournalChirho<'_>, JournalErrorChirho> {
        LedgerJournalChirho::open_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &harness_chirho.cluster_chirho(),
        )
    }

    // A. THE VECTOR: flip the FINAL record's idempotency_key. Fold passes (key not folded), chain
    //    passes (nothing points at the tail), but the tail sig now fails -> refused. Without the
    //    fix this would have opened with the forged key -> exactly-once broken.
    restore_chirho(&harness_chirho);
    harness_chirho
        .storage_chirho
        .remove_chirho(&sidecar_path_chirho)
        .unwrap();
    harness_chirho.tamper_chirho("\"idem-t-1\"", "\"idem-HACKED-chirho\"");
    assert!(matches!(
        reopen_chirho(&harness_chirho),
        Err(JournalErrorChirho::TailSignatureInvalidChirho)
    ));

    // B. Flip ONLY the final record's sig -> refused (a forged sig cannot pass the trust root).
    restore_chirho(&harness_chirho);
    harness_chirho
        .storage_chirho
        .remove_chirho(&sidecar_path_chirho)
        .unwrap();
    // The seq-2 record's sig is the LAST "fake-sig-..." occurrence; flip its prefix.
    let text_chirho = String::from_utf8(pristine_journal_chirho.clone()).unwrap();
    let last_sig_chirho = text_chirho.rmatch_indices("fake-sig-").next().unwrap().0;
    let mut forged_chirho = pristine_journal_chirho.clone();
    forged_chirho[last_sig_chirho..last_sig_chirho + 9].copy_from_slice(b"fake-SIG-");
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &forged_chirho)
        .unwrap();
    assert!(matches!(
        reopen_chirho(&harness_chirho),
        Err(JournalErrorChirho::TailSignatureInvalidChirho)
    ));

    // C. A NON-final record's key flip is caught by the CHAIN (its successor's prev no longer
    //    binds) -> ChainChirho, NOT the tail-sig path. Proves the gap was EXACTLY the tail.
    restore_chirho(&harness_chirho);
    harness_chirho
        .storage_chirho
        .remove_chirho(&sidecar_path_chirho)
        .unwrap();
    harness_chirho.tamper_chirho("\"idem-mint-1\"", "\"idem-HACK1-chirho\"");
    assert!(matches!(
        reopen_chirho(&harness_chirho),
        Err(JournalErrorChirho::ChainChirho { .. })
    ));

    // D. Fabricated sidecar balance (inflate alice's post) fails the SIDECAR sig -> fast-open
    //    discards -> full rebuild yields alice's TRUE balance. A tampered sidecar can never seed a
    //    fabricated balance the engine trusts.
    restore_chirho(&harness_chirho);
    let sidecar_text_chirho = String::from_utf8(pristine_sidecar_chirho.clone()).unwrap();
    let fabricated_chirho = sidecar_text_chirho.replacen(
        "\"credits_total_chirho\":120",
        "\"credits_total_chirho\":999999",
        1,
    );
    assert_ne!(
        fabricated_chirho, sidecar_text_chirho,
        "the inflate must land"
    );
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&sidecar_path_chirho, fabricated_chirho.as_bytes())
        .unwrap();
    let recovered_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(
        !recovered_chirho.last_open_was_fast_chirho(),
        "a fabricated sidecar is discarded, not fast-trusted"
    );
    assert_eq!(
        recovered_chirho
            .head_state_chirho(&account_chirho("alice-chirho"))
            .unwrap()
            .credits_total_chirho,
        120
    );

    // E. Sanity: the untampered pristine journal + sidecar still fast-opens (the fix does not
    //    break the honest path).
    drop(recovered_chirho);
    restore_chirho(&harness_chirho);
    let honest_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(honest_chirho.last_open_was_fast_chirho());
    assert_eq!(honest_chirho.tail_chirho().0, 2);
}

#[test]
fn head_checkpoint_fast_open_agrees_with_full_rebuild_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-mint-1"))
        .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            120,
            "idem-t-1",
        ))
        .unwrap();
    // Checkpoint at seq 2, then one MORE append so the sidecar is honestly STALE (behind).
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "bob-chirho",
            30,
            "idem-t-2",
        ))
        .unwrap();
    let live_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    drop(engine_chirho);
    fn reopen_chirho(
        harness_chirho: &HarnessChirho,
    ) -> Result<LedgerJournalChirho<'_>, JournalErrorChirho> {
        LedgerJournalChirho::open_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &harness_chirho.cluster_chirho(),
        )
    }
    // 1. FAST open: sidecar verified + the post-checkpoint suffix replayed.
    let fast_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(fast_chirho.last_open_was_fast_chirho());
    assert_eq!(
        (
            fast_chirho.tail_chirho().0,
            fast_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho
    );
    assert_eq!(
        fast_chirho
            .head_state_chirho(&account_chirho("bob-chirho"))
            .unwrap()
            .credits_total_chirho,
        30
    );
    drop(fast_chirho);
    // 2. FULL-rebuild equivalence: remove the sidecar — same state, slow path.
    let sidecar_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&sidecar_path_chirho)
        .unwrap()
        .unwrap();
    harness_chirho
        .storage_chirho
        .remove_chirho(&sidecar_path_chirho)
        .unwrap();
    let full_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(!full_chirho.last_open_was_fast_chirho());
    assert_eq!(
        (
            full_chirho.tail_chirho().0,
            full_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho
    );
    drop(full_chirho);
    // 3. A TAMPERED sidecar silently discards to the full rebuild (advisory, never authority).
    let tampered_chirho = String::from_utf8(sidecar_bytes_chirho.clone())
        .unwrap()
        .replacen("\"covered_seq_chirho\":2", "\"covered_seq_chirho\":1", 1);
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&sidecar_path_chirho, tampered_chirho.as_bytes())
        .unwrap();
    let after_tamper_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(!after_tamper_chirho.last_open_was_fast_chirho());
    assert_eq!(after_tamper_chirho.tail_chirho().0, live_tail_chirho.0);
    drop(after_tamper_chirho);
    // 4. Restore the good sidecar; TORN TAIL + valid sidecar: fast path repairs the torn suffix.
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&sidecar_path_chirho, &sidecar_bytes_chirho)
        .unwrap();
    let journal_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let mut torn_chirho = journal_bytes_chirho.clone();
    torn_chirho.extend_from_slice(br#"{"schema_chirho":"ledger-rec"#);
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &torn_chirho)
        .unwrap();
    let repaired_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(repaired_chirho.last_open_was_fast_chirho());
    assert!(repaired_chirho.repaired_torn_tail_bytes_chirho().is_some());
    assert_eq!(repaired_chirho.tail_chirho().0, live_tail_chirho.0);
    drop(repaired_chirho);
    // 5. Sidecar AHEAD of a truncated journal (behind-never-ahead): discard, full rebuild of the
    //    shorter journal.
    let text_chirho = String::from_utf8(journal_bytes_chirho.clone()).unwrap();
    let two_lines_chirho: Vec<&str> = text_chirho.lines().take(2).collect();
    let mut short_chirho = two_lines_chirho.join("\n");
    short_chirho.push('\n');
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), short_chirho.as_bytes())
        .unwrap();
    let short_open_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(!short_open_chirho.last_open_was_fast_chirho());
    assert_eq!(short_open_chirho.tail_chirho().0, 1);
    drop(short_open_chirho);
    // 6. Restore; APPEND AFTER FAST OPEN chains correctly and a re-checkpoint fast-opens again —
    //    proving the fast path's byte-offset bookkeeping is exact.
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &journal_bytes_chirho)
        .unwrap();
    let mut continued_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(continued_chirho.last_open_was_fast_chirho());
    harness_chirho.clock_chirho.now_ms_chirho.set(2_000);
    continued_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "bob-chirho",
            10,
            "idem-t-3",
        ))
        .unwrap();
    continued_chirho.write_head_checkpoint_chirho().unwrap();
    let final_tail_chirho = continued_chirho.tail_chirho().0;
    drop(continued_chirho);
    let again_chirho = reopen_chirho(&harness_chirho).unwrap();
    assert!(again_chirho.last_open_was_fast_chirho());
    assert_eq!(again_chirho.tail_chirho().0, final_tail_chirho);
}

#[test]
fn epoch_advance_emits_the_binding_anchor_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    let initial_receipt_chirho = engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-mint-1"))
        .unwrap();
    assert!(initial_receipt_chirho.epoch_first_record_chirho.is_none());
    // A non-monotone advance refuses.
    assert!(matches!(
        engine_chirho.advance_epoch_chirho(1),
        Err(JournalErrorChirho::ChainChirho { .. })
    ));
    // Advance the lease TWICE before appending: the next record anchors the LAST RECORDED tail
    // (epoch 1), never the intermediate never-recorded lease value.
    engine_chirho.advance_epoch_chirho(2).unwrap();
    engine_chirho.advance_epoch_chirho(4).unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    let tail_before_chirho = engine_chirho.tail_chirho().1.clone();
    let epoch_first_receipt_chirho = engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            120,
            "idem-t-1",
        ))
        .unwrap();
    let epoch_first_evidence_chirho = epoch_first_receipt_chirho
        .epoch_first_record_chirho
        .as_ref()
        .expect("the first committed record after an epoch advance carries bounded evidence");
    assert_eq!(epoch_first_evidence_chirho.epoch_chirho(), 4);
    assert_eq!(
        epoch_first_evidence_chirho.seq_chirho(),
        epoch_first_receipt_chirho.seq_chirho
    );
    assert_eq!(
        epoch_first_evidence_chirho.record_digest_chirho(),
        &epoch_first_receipt_chirho.record_digest_chirho
    );
    let verified_epoch_first_chirho = epoch_first_evidence_chirho
        .verify_chirho(&harness_chirho.signer_chirho)
        .unwrap();
    let verified_anchor_chirho = verified_epoch_first_chirho
        .anchor_chirho
        .expect("epoch-first evidence retains the exact inherited anchor");
    assert_eq!(verified_anchor_chirho.inherited_epoch_chirho, 1);
    assert_eq!(verified_anchor_chirho.inherited_seq_chirho, 1);
    assert_eq!(
        verified_anchor_chirho.inherited_digest_chirho,
        tail_before_chirho
    );
    assert_eq!(
        engine_chirho
            .tail_epoch_first_record_evidence_chirho()
            .unwrap(),
        Some(epoch_first_evidence_chirho.clone())
    );
    // Steady state resumes: the NEXT record carries no anchor (proven by reopen verifying the
    // whole chain, whose replay law rejects a stray steady-state anchor).
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let steady_receipt_chirho = engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "bob-chirho",
            30,
            "idem-t-2",
        ))
        .unwrap();
    assert!(steady_receipt_chirho.epoch_first_record_chirho.is_none());
    assert!(engine_chirho
        .tail_epoch_first_record_evidence_chirho()
        .unwrap()
        .is_none());
    drop(engine_chirho);
    // The stored journal replays: the epoch-4 first record's anchor must bind (epoch 1, seq 1,
    // digest-of-record-1) — open's chain law verifies exactly that, and the lease resumes at the
    // last RECORDED epoch.
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert_eq!(reopened_chirho.current_epoch_chirho(), 4);
    assert_eq!(reopened_chirho.tail_chirho().0, 3);
    // The anchor in the stored bytes names the pre-advance tail digest.
    let stored_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let text_chirho = String::from_utf8(stored_chirho).unwrap();
    let epoch4_line_chirho = text_chirho.lines().nth(2).unwrap();
    assert!(epoch4_line_chirho.contains(&format!(
        r#""anchor_chirho":{{"inherited_epoch_chirho":1,"inherited_seq_chirho":1,"inherited_digest_chirho":"{}"}}"#,
        tail_before_chirho.0
    )));
    assert!(!text_chirho
        .lines()
        .nth(3)
        .unwrap()
        .contains("anchor_chirho"));
}

#[test]
fn open_refuses_tampered_reordered_torn_and_foreign_journals_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-mint-1"))
        .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            120,
            "idem-t-1",
        ))
        .unwrap();
    drop(engine_chirho);
    let pristine_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    fn reopen_chirho(
        harness_chirho: &HarnessChirho,
    ) -> Result<LedgerJournalChirho<'_>, JournalErrorChirho> {
        LedgerJournalChirho::open_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &harness_chirho.cluster_chirho(),
        )
    }
    // 1. A flipped AMOUNT inside a mid-journal record: still canonical JSON, but the fold no
    //    longer matches the stored posts (and the digest chain breaks) — refused.
    harness_chirho.tamper_chirho("\"amount_chirho\":500", "\"amount_chirho\":501");
    assert!(matches!(
        reopen_chirho(&harness_chirho),
        Err(JournalErrorChirho::ChainChirho { .. })
    ));
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &pristine_chirho)
        .unwrap();
    // 2. A flipped SIG on a NON-tail record: the stored-line digest changes, so the successor's
    //    prev no longer binds — prev binds signatures into the chain (§11.6), proven at the engine.
    harness_chirho.tamper_chirho("fake-sig-", "fake-SIG-");
    assert!(matches!(
        reopen_chirho(&harness_chirho),
        Err(JournalErrorChirho::ChainChirho { .. })
    ));
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &pristine_chirho)
        .unwrap();
    // 3. Reordered record lines: dense-seq/prev law refuses.
    {
        let text_chirho = String::from_utf8(pristine_chirho.clone()).unwrap();
        let mut lines_chirho: Vec<&str> = text_chirho.lines().collect();
        lines_chirho.swap(1, 2);
        let mut reordered_chirho = lines_chirho.join("\n");
        reordered_chirho.push('\n');
        harness_chirho
            .storage_chirho
            .atomic_write_chirho(&harness_chirho.path_chirho(), reordered_chirho.as_bytes())
            .unwrap();
        assert!(matches!(
            reopen_chirho(&harness_chirho),
            Err(JournalErrorChirho::ChainChirho { .. })
        ));
    }
    // 4. Torn tail (crash mid-append): the clean prefix verifies, the UNACKNOWLEDGED suffix is
    //    dropped by a durable truncate, and the journal continues from the repaired tail — the
    //    torn record left NO trace (its idempotency key is reusable).
    {
        let mut torn_chirho = pristine_chirho.clone();
        torn_chirho.truncate(torn_chirho.len() - 10);
        harness_chirho
            .storage_chirho
            .atomic_write_chirho(&harness_chirho.path_chirho(), &torn_chirho)
            .unwrap();
        let mut repaired_chirho = reopen_chirho(&harness_chirho).unwrap();
        assert!(repaired_chirho.repaired_torn_tail_bytes_chirho().is_some());
        assert_eq!(
            repaired_chirho.tail_chirho().0,
            1,
            "the torn transfer is gone"
        );
        assert!(repaired_chirho
            .head_state_chirho(&account_chirho("alice-chirho"))
            .is_none());
        assert_eq!(
            repaired_chirho
                .head_state_chirho(&account_chirho("issuer-chirho"))
                .cloned()
                .unwrap(),
            LegPostStateChirho {
                credits_total_chirho: 500,
                debits_total_chirho: 0,
                held_chirho: 0
            }
        );
        // The torn record's idempotency key was never admitted — reusing it SUCCEEDS.
        let retry_chirho = repaired_chirho
            .append_chirho(transfer_request_chirho(
                "issuer-chirho",
                "alice-chirho",
                120,
                "idem-t-1",
            ))
            .unwrap();
        assert_eq!(retry_chirho.seq_chirho, 2);
        // The repair is durable: a THIRD open is clean (no repair) and agrees with the live tail.
        let clean_chirho = reopen_chirho(&harness_chirho).unwrap();
        assert_eq!(clean_chirho.repaired_torn_tail_bytes_chirho(), None);
        assert_eq!(
            clean_chirho.tail_chirho().0,
            repaired_chirho.tail_chirho().0
        );
        assert_eq!(
            clean_chirho.tail_chirho().1,
            repaired_chirho.tail_chirho().1
        );
    }
    // 5. Wrong expected cluster: a journal cannot be mounted as another cluster's.
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &pristine_chirho)
        .unwrap();
    assert!(matches!(
        LedgerJournalChirho::open_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &ClusterIdChirho("cluster-OTHER-chirho".into()),
        ),
        Err(JournalErrorChirho::ChainChirho { .. })
    ));
    // 6. A planted second genesis line: refused.
    {
        let text_chirho = String::from_utf8(pristine_chirho.clone()).unwrap();
        let genesis_line_chirho = text_chirho.lines().next().unwrap().to_owned();
        let mut planted_chirho = text_chirho;
        planted_chirho.push_str(&genesis_line_chirho);
        planted_chirho.push('\n');
        harness_chirho
            .storage_chirho
            .atomic_write_chirho(&harness_chirho.path_chirho(), planted_chirho.as_bytes())
            .unwrap();
        assert!(matches!(
            reopen_chirho(&harness_chirho),
            Err(JournalErrorChirho::ChainChirho { .. })
        ));
    }
    // 7. A TORN GENESIS (crash during the very first append): no verified prefix exists to keep,
    //    so trim-repair is impossible — fail closed.
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(
            &harness_chirho.path_chirho(),
            br#"{"schema_chirho":"ledger-gen"#,
        )
        .unwrap();
    assert!(matches!(
        reopen_chirho(&harness_chirho),
        Err(JournalErrorChirho::TornTailChirho)
    ));
    // 8. A journal created twice: create refuses an existing path.
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &pristine_chirho)
        .unwrap();
    assert!(matches!(
        LedgerJournalChirho::create_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            harness_chirho.cluster_chirho(),
            1,
        ),
        Err(JournalErrorChirho::ChainChirho { .. })
    ));
}

#[test]
fn read_only_open_refuses_torn_tail_without_mutation_while_writer_open_repairs_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    journal_chirho.write_head_checkpoint_chirho().unwrap();
    drop(journal_chirho);
    let pristine_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let mut torn_chirho = pristine_chirho.clone();
    torn_chirho.extend_from_slice(br#"{"schema_chirho":"ledger-record-v1-chirho"#);
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &torn_chirho)
        .unwrap();

    let error_chirho = match LedgerJournalChirho::open_read_only_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(error_chirho) => error_chirho,
        Ok(_) => panic!("read-only open must not serve a torn journal"),
    };
    assert_eq!(
        error_chirho,
        JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
            reason_chirho: ReadOnlyRecoveryReasonChirho::TornTailChirho,
        }
    );
    assert_eq!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&harness_chirho.path_chirho())
            .unwrap(),
        Some(torn_chirho),
        "read-only open must preserve the exact forensic bytes"
    );

    let repaired_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(repaired_chirho.repaired_torn_tail_bytes_chirho().is_some());
    assert_eq!(
        harness_chirho
            .storage_chirho
            .read_all_chirho(&harness_chirho.path_chirho())
            .unwrap(),
        Some(pristine_chirho),
        "writer open retains the existing verified-prefix repair law"
    );
}

#[test]
fn read_only_open_refuses_pending_rotation_without_mutating_any_object_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    journal_chirho.write_head_checkpoint_chirho().unwrap();
    drop(journal_chirho);
    let segment_paths_chirho =
        cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho::new_chirho(
            harness_chirho.path_chirho().key_chirho(),
        );
    let marker_path_chirho = StoragePathChirho::new_chirho(
        segment_paths_chirho
            .rotation_marker_chirho()
            .as_str_chirho(),
    );
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&marker_path_chirho, b"pending-rotation-marker-chirho")
        .unwrap();
    let before_chirho = harness_chirho
        .storage_chirho
        .objects_chirho
        .borrow()
        .clone();

    let error_chirho = match LedgerJournalChirho::open_read_only_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(error_chirho) => error_chirho,
        Ok(_) => panic!("read-only open must not serve a pending rotation"),
    };
    assert_eq!(
        error_chirho,
        JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
            reason_chirho: ReadOnlyRecoveryReasonChirho::PendingRotationChirho,
        }
    );
    assert_eq!(
        *harness_chirho.storage_chirho.objects_chirho.borrow(),
        before_chirho,
        "read-only open must not finish, clear, or rewrite a pending rotation"
    );
}
