// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Shared TEST-ONLY port fakes for the read-model suites (feeder + serving): an in-memory ledger
//! storage, a deterministic content-bound signer, a stepping clock, open membership/kind/authority
//! views, and the balances-class fold. Compiled only under `cfg(test)` via `lib.rs`.

use crate::feeder_chirho::{ProjectionFoldPortChirho, VerifiedSourceStateChirho};
use anyhow::{Context, Result};
use cairn_chain_core_chirho::stored_line_digest_hex_chirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{AppendLegRequestChirho, AppendRequestChirho};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct MemStorageChirho {
    pub(crate) objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
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

pub(crate) struct TestSignerChirho {
    pub(crate) name_chirho: &'static str,
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

pub(crate) struct StepClockChirho {
    pub(crate) now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for StepClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.set(self.now_ms_chirho.get() + 10);
        self.now_ms_chirho.get()
    }
}

pub(crate) struct AllMembersChirho;

impl MembershipViewChirho for AllMembersChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: u64,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

pub(crate) struct OpenRegistryChirho;

impl KindRegistryViewChirho for OpenRegistryChirho {
    fn resolve_chirho(&self, _policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        KindResolutionChirho::CurrentChirho(KindPolicyViewChirho {
            kind_id_chirho: AssetKindIdChirho("credits-chirho".to_string()),
            mint_authority_chirho: MintAuthorityPolicyChirho::ProviderReceiptChirho,
            rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
            settlement_owner_chirho: None,
            idempotency_window_chirho: None,
        })
    }
}

pub(crate) struct OpenAuthorityChirho;

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

/// The balances-class fold: every account's spendable as canonical JSON — deterministic by
/// construction (BTreeMap order + one serializer).
pub(crate) struct BalancesFoldChirho;

impl ProjectionFoldPortChirho for BalancesFoldChirho {
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

pub(crate) fn mint_request_chirho(
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
            principal_chirho: "read-model-test-chirho".to_string(),
        },
    }
}
