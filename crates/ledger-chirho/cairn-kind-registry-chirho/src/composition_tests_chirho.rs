// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K5 — the composition capstone: the REAL signed registry log drives the REAL money journal's
//! admission end-to-end. Registration feeds a mint through the verified projection; an amend then
//! makes the old ref refuse DISTINCTLY (the policy-downgrade pin through the actual append path);
//! and the prospective-amend law holds — a cap lowered below existing supply refuses further mints
//! while the existing supply stands untouched (value destruction without a burn is not a thing).

use crate::chain_chirho::{
    append_registry_op_chirho, load_verified_registry_chirho, IssuerVerifyViewChirho,
    KindRegistryPortsChirho,
};
use crate::record_chirho::{KindPolicyBodyChirho, KindRegistryOpChirho, MintAuthorityRecordChirho};
use crate::wire_chirho::derive_policy_ref_chirho;
use anyhow::Result;
use cairn_ledger_log_chirho::admission_chirho::{
    AdmissionRejectChirho, AuthorityVerdictChirho, AuthorityVerifierViewChirho,
    MembershipStatusChirho, MembershipViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalErrorChirho, JournalPortsChirho,
    LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;

const MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";

// --- minimal ports (the registry crate's own storage stub + journal views) ---

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
            .ok_or_else(|| anyhow::anyhow!("missing object"))?;
        let end_chirho = offset_chirho + len_chirho;
        if end_chirho > bytes_chirho.len() as u64 {
            return Err(anyhow::anyhow!("range past EOF"));
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
            .ok_or_else(|| anyhow::anyhow!("missing object"))?;
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
            .ok_or_else(|| anyhow::anyhow!("missing rename source"))?;
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

struct NamedSignerChirho {
    name_chirho: &'static str,
}

impl LedgerSignerPortChirho for NamedSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(format!(
            "{}-sig-{}",
            self.name_chirho,
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.name_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

struct OneIssuerChirho {
    principal_chirho: &'static str,
    signer_chirho: NamedSignerChirho,
}

impl IssuerVerifyViewChirho for OneIssuerChirho {
    fn verify_issuer_chirho(
        &self,
        issuer_chirho: &str,
        signed_content_chirho: &str,
        sig_chirho: &str,
    ) -> bool {
        issuer_chirho == self.principal_chirho
            && self
                .signer_chirho
                .verify_chirho(signed_content_chirho, sig_chirho)
    }
}

struct StepClockChirho {
    now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for StepClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.get()
    }
}

struct AllMembersChirho;

impl MembershipViewChirho for AllMembersChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

struct OpenAuthorityChirho;

impl AuthorityVerifierViewChirho for OpenAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        if evidence_chirho.0 == MINT_EVIDENCE_CHIRHO {
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

// --- the composition ---

const REGISTRY_ID_CHIRHO: &str = "cairn-kind-registry:cluster-comp-chirho";
const KIND_CHIRHO: &str = "money-chirho";

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("registry/kinds-chirho.jsonl".to_owned())
}

fn journal_path_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/cluster-comp-chirho.jsonl".to_owned())
}

fn policy_chirho(max_supply_chirho: Option<u64>) -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: "usd-cent-chirho".to_owned(),
        precision_chirho: 2,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho,
        },
        rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        shard_attachment_chirho: "shard-a-chirho".to_owned(),
        settlement_owner_chirho: None,
        idempotency_window_chirho: None,
    }
}

fn mint_request_chirho(
    amount_chirho: u64,
    ref_chirho: &AssetKindRefChirho,
    idem_chirho: &str,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(MINT_EVIDENCE_CHIRHO.into()),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: LogIdChirho::new_chirho("issuer-chirho", KIND_CHIRHO),
            kind_policy_ref_chirho: ref_chirho.clone(),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: idem_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

#[test]
fn signed_registry_drives_journal_admission_end_to_end_chirho() {
    let storage_chirho = MemStorageChirho::default();
    let registry_root_chirho = NamedSignerChirho {
        name_chirho: "registry-root",
    };
    let issuer_signer_chirho = NamedSignerChirho {
        name_chirho: "issuer",
    };
    let issuer_view_chirho = OneIssuerChirho {
        principal_chirho: "issuer-alpha-chirho",
        signer_chirho: NamedSignerChirho {
            name_chirho: "issuer",
        },
    };
    let registry_ports_chirho = KindRegistryPortsChirho {
        storage_chirho: &storage_chirho,
        registry_root_chirho: &registry_root_chirho,
        issuer_verify_chirho: &issuer_view_chirho,
    };
    // 1. Register the kind (cap 1000) in the SIGNED registry.
    append_registry_op_chirho(
        registry_ports_chirho,
        &issuer_signer_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::RegisterKindChirho {
            kind_id_chirho: AssetKindIdChirho(KIND_CHIRHO.to_owned()),
            policy_chirho: policy_chirho(Some(1_000)),
        },
    )
    .unwrap();
    let view_v1_chirho = load_verified_registry_chirho(
        registry_ports_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    let ref_v1_chirho = derive_policy_ref_chirho(&policy_chirho(Some(1_000))).unwrap();

    // 2. The REAL journal admits a mint through the REAL verified registry view.
    let journal_signer_chirho = NamedSignerChirho {
        name_chirho: "journal",
    };
    let clock_chirho = StepClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let membership_chirho = AllMembersChirho;
    let authority_chirho = OpenAuthorityChirho;
    let ports_v1_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &journal_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &view_v1_chirho,
        authority_chirho: &authority_chirho,
    };
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        ports_v1_chirho,
        journal_path_chirho(),
        ClusterIdChirho("cluster-comp-chirho".into()),
        1,
    )
    .unwrap();
    clock_chirho.now_ms_chirho.set(1_100);
    journal_chirho
        .append_chirho(mint_request_chirho(600, &ref_v1_chirho, "idem-comp-mint-1"))
        .unwrap();
    drop(journal_chirho);

    // 3. AMEND: cap lowered to 500 — BELOW the existing 600 supply. Prospective law: the existing
    //    supply stands; further mints refuse.
    append_registry_op_chirho(
        registry_ports_chirho,
        &issuer_signer_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::AmendKindPolicyChirho {
            kind_id_chirho: AssetKindIdChirho(KIND_CHIRHO.to_owned()),
            supersedes_ref_chirho: ref_v1_chirho.clone(),
            policy_chirho: policy_chirho(Some(500)),
        },
    )
    .unwrap();
    let view_v2_chirho = load_verified_registry_chirho(
        registry_ports_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    let ref_v2_chirho = derive_policy_ref_chirho(&policy_chirho(Some(500))).unwrap();
    let ports_v2_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &journal_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &view_v2_chirho,
        authority_chirho: &authority_chirho,
    };
    // REOPEN under the amended registry: replay is STRUCTURAL (the old record carries its immutable
    // ref forever, R5b) — history verifies without consulting the registry.
    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        ports_v2_chirho,
        journal_path_chirho(),
        &ClusterIdChirho("cluster-comp-chirho".into()),
    )
    .unwrap();
    assert_eq!(
        reopened_chirho.supply_chirho(&AssetKindIdChirho(KIND_CHIRHO.to_owned())),
        600,
        "existing supply stands untouched by the prospective amend"
    );
    // 4. The OLD ref now refuses DISTINCTLY (the policy-downgrade pin, through the REAL append).
    clock_chirho.now_ms_chirho.set(1_200);
    match reopened_chirho.append_chirho(mint_request_chirho(10, &ref_v1_chirho, "idem-comp-old")) {
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::SupersededKindPolicyChirho,
        }) => {}
        other_chirho => panic!("the superseded ref must refuse distinctly, got {other_chirho:?}"),
    }
    // 5. The NEW ref refuses on the LOWERED CAP (supply 600 > cap 500): fail-closed forward,
    //    no clawback.
    clock_chirho.now_ms_chirho.set(1_300);
    assert!(matches!(
        reopened_chirho.append_chirho(mint_request_chirho(10, &ref_v2_chirho, "idem-comp-cap")),
        Err(JournalErrorChirho::AdmissionChirho { .. })
    ));
    assert_eq!(
        reopened_chirho.supply_chirho(&AssetKindIdChirho(KIND_CHIRHO.to_owned())),
        600,
        "no clawback: refused mints change nothing"
    );
}
