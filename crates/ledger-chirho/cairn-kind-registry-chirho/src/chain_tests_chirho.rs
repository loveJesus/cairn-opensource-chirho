// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Registry chain proofs: the register→amend happy chain with projection state, and the RED family
//! — tampered line, forged issuer sig, forged registry sig, re-register, amend off a superseded
//! ref (the monotone law), cross-registry replay, and the fail-closed torn tail (manifest posture:
//! configuration authority never self-heals).

use crate::chain_chirho::{
    append_registry_op_chirho, load_verified_registry_chirho, IssuerVerifyViewChirho,
    KindRegistryPortsChirho, RegistryChainErrorChirho,
};
use crate::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, KindRegistryOpChirho,
    MintAuthorityRecordChirho,
};
use crate::wire_chirho::{
    canonical_registry_line_chirho, derive_policy_ref_chirho, issuer_signed_content_chirho,
    parse_canonical_registry_line_chirho, registry_signed_content_chirho,
};
use anyhow::Result;
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// Minimal in-memory storage honoring the port contract (registry tests need read_all + append).
#[derive(Default)]
struct MemStorageChirho {
    objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl LedgerStoragePortChirho for MemStorageChirho {
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

/// Deterministic signer with a NAME baked into the sig (so root vs issuer sigs differ).
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

/// Issuer directory: exactly ONE known issuer principal, verified against its own named signer.
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

struct FixtureChirho {
    storage_chirho: MemStorageChirho,
    root_chirho: NamedSignerChirho,
    issuer_signer_chirho: NamedSignerChirho,
    issuer_view_chirho: OneIssuerChirho,
}

impl FixtureChirho {
    fn new_chirho() -> Self {
        FixtureChirho {
            storage_chirho: MemStorageChirho::default(),
            root_chirho: NamedSignerChirho {
                name_chirho: "registry-root",
            },
            issuer_signer_chirho: NamedSignerChirho {
                name_chirho: "issuer",
            },
            issuer_view_chirho: OneIssuerChirho {
                principal_chirho: "issuer-alpha-chirho",
                signer_chirho: NamedSignerChirho {
                    name_chirho: "issuer",
                },
            },
        }
    }

    fn ports_chirho(&self) -> KindRegistryPortsChirho<'_> {
        KindRegistryPortsChirho {
            storage_chirho: &self.storage_chirho,
            registry_root_chirho: &self.root_chirho,
            issuer_verify_chirho: &self.issuer_view_chirho,
        }
    }
}

const REGISTRY_ID_CHIRHO: &str = "cairn-kind-registry:cluster-alpha-chirho";

fn path_chirho() -> StoragePathChirho {
    StoragePathChirho("registry/kinds-chirho.jsonl".to_owned())
}

fn policy_v1_chirho() -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: "usd-cent-chirho".to_owned(),
        precision_chirho: 2,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho: Some(1_000_000),
        },
        rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        shard_attachment_chirho: "shard-a-chirho".to_owned(),
        settlement_owner_chirho: None,
        idempotency_window_chirho: None,
    }
}

fn policy_v2_chirho() -> KindPolicyBodyChirho {
    let mut policy_chirho = policy_v1_chirho();
    policy_chirho.mint_authority_chirho = MintAuthorityRecordChirho::PlatformPolicyChirho {
        max_supply_chirho: Some(500_000),
    };
    policy_chirho
}

fn bounded_policy_chirho(
    idempotency_horizon_ms_chirho: u64,
    retry_finality_horizon_ms_chirho: u64,
) -> KindPolicyBodyChirho {
    let mut policy_chirho = policy_v1_chirho();
    policy_chirho.idempotency_window_chirho = Some(IdempotencyWindowPolicyChirho {
        idempotency_horizon_ms_chirho,
        retry_finality_horizon_ms_chirho,
    });
    policy_chirho
}

fn kind_chirho() -> AssetKindIdChirho {
    AssetKindIdChirho("money-chirho".to_owned())
}

fn register_chirho(fixture_chirho: &FixtureChirho) {
    append_registry_op_chirho(
        fixture_chirho.ports_chirho(),
        &fixture_chirho.issuer_signer_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::RegisterKindChirho {
            kind_id_chirho: kind_chirho(),
            policy_chirho: policy_v1_chirho(),
        },
    )
    .unwrap();
}

#[test]
fn register_amend_chain_projects_current_and_superseded_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    register_chirho(&fixture_chirho);
    let ref_v1_chirho = derive_policy_ref_chirho(&policy_v1_chirho()).unwrap();
    append_registry_op_chirho(
        fixture_chirho.ports_chirho(),
        &fixture_chirho.issuer_signer_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::AmendKindPolicyChirho {
            kind_id_chirho: kind_chirho(),
            supersedes_ref_chirho: ref_v1_chirho.clone(),
            policy_chirho: policy_v2_chirho(),
        },
    )
    .unwrap();
    let verified_chirho = load_verified_registry_chirho(
        fixture_chirho.ports_chirho(),
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    assert_eq!(verified_chirho.records_chirho.len(), 2);
    let projection_chirho = verified_chirho.kinds_chirho.get(&kind_chirho()).unwrap();
    assert_eq!(projection_chirho.current_policy_chirho, policy_v2_chirho());
    assert_eq!(
        projection_chirho.current_ref_chirho,
        derive_policy_ref_chirho(&policy_v2_chirho()).unwrap()
    );
    assert!(projection_chirho
        .superseded_refs_chirho
        .contains(&ref_v1_chirho));
}

#[test]
fn invalid_idempotency_window_refuses_before_write_and_at_verified_load_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let invalid_policy_chirho = bounded_policy_chirho(3_599_999, 3_600_000);
    assert!(matches!(
        append_registry_op_chirho(
            fixture_chirho.ports_chirho(),
            &fixture_chirho.issuer_signer_chirho,
            &path_chirho(),
            REGISTRY_ID_CHIRHO,
            "issuer-alpha-chirho",
            KindRegistryOpChirho::RegisterKindChirho {
                kind_id_chirho: kind_chirho(),
                policy_chirho: invalid_policy_chirho.clone(),
            },
        ),
        Err(RegistryChainErrorChirho::InvalidIdempotencyWindowChirho {
            idempotency_horizon_ms_chirho: 3_599_999,
            retry_finality_horizon_ms_chirho: 3_600_000,
        })
    ));
    assert!(fixture_chirho
        .storage_chirho
        .read_all_chirho(&path_chirho())
        .unwrap()
        .is_none());

    // A colluding issuer+registry root can sign bytes, but cannot bypass the independently-folded
    // W-law at load. Mint one valid line, replace its body, and re-sign both layers honestly.
    append_registry_op_chirho(
        fixture_chirho.ports_chirho(),
        &fixture_chirho.issuer_signer_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::RegisterKindChirho {
            kind_id_chirho: kind_chirho(),
            policy_chirho: bounded_policy_chirho(7_200_000, 3_600_000),
        },
    )
    .unwrap();
    let bytes_chirho = fixture_chirho
        .storage_chirho
        .read_all_chirho(&path_chirho())
        .unwrap()
        .unwrap();
    let mut record_chirho = parse_canonical_registry_line_chirho(
        String::from_utf8(bytes_chirho)
            .unwrap()
            .trim_end_matches('\n'),
    )
    .unwrap();
    let KindRegistryOpChirho::RegisterKindChirho { policy_chirho, .. } =
        &mut record_chirho.op_chirho
    else {
        panic!("fixture is a register record")
    };
    *policy_chirho = invalid_policy_chirho;
    record_chirho.issuer_sig_chirho.clear();
    record_chirho.registry_sig_chirho.clear();
    let issuer_content_chirho = issuer_signed_content_chirho(&record_chirho).unwrap();
    record_chirho.issuer_sig_chirho = fixture_chirho
        .issuer_signer_chirho
        .sign_chirho(&issuer_content_chirho)
        .unwrap();
    let registry_content_chirho = registry_signed_content_chirho(&record_chirho).unwrap();
    record_chirho.registry_sig_chirho = fixture_chirho
        .root_chirho
        .sign_chirho(&registry_content_chirho)
        .unwrap();
    let forged_line_chirho = canonical_registry_line_chirho(&record_chirho).unwrap();
    fixture_chirho
        .storage_chirho
        .atomic_write_chirho(&path_chirho(), format!("{forged_line_chirho}\n").as_bytes())
        .unwrap();
    assert!(matches!(
        load_verified_registry_chirho(
            fixture_chirho.ports_chirho(),
            &path_chirho(),
            REGISTRY_ID_CHIRHO,
        ),
        Err(RegistryChainErrorChirho::InvalidIdempotencyWindowChirho { .. })
    ));
}

#[test]
fn idempotency_window_amendments_retain_longer_never_shorter_chirho() {
    use cairn_ledger_log_chirho::admission_chirho::{
        IdempotencyWindowPolicyViewChirho, KindRegistryViewChirho, KindResolutionChirho,
        RecordedRetentionWindowChirho,
    };
    let fixture_chirho = FixtureChirho::new_chirho();
    register_chirho(&fixture_chirho);
    let legacy_ref_chirho = derive_policy_ref_chirho(&policy_v1_chirho()).unwrap();
    let first_window_chirho = bounded_policy_chirho(7_200_000, 3_600_000);
    append_registry_op_chirho(
        fixture_chirho.ports_chirho(),
        &fixture_chirho.issuer_signer_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::AmendKindPolicyChirho {
            kind_id_chirho: kind_chirho(),
            supersedes_ref_chirho: legacy_ref_chirho,
            policy_chirho: first_window_chirho.clone(),
        },
    )
    .unwrap();
    let first_window_ref_chirho = derive_policy_ref_chirho(&first_window_chirho).unwrap();

    for downgraded_policy_chirho in [
        bounded_policy_chirho(7_199_999, 3_600_000),
        bounded_policy_chirho(7_200_000, 3_599_999),
        policy_v1_chirho(),
    ] {
        assert!(matches!(
            append_registry_op_chirho(
                fixture_chirho.ports_chirho(),
                &fixture_chirho.issuer_signer_chirho,
                &path_chirho(),
                REGISTRY_ID_CHIRHO,
                "issuer-alpha-chirho",
                KindRegistryOpChirho::AmendKindPolicyChirho {
                    kind_id_chirho: kind_chirho(),
                    supersedes_ref_chirho: first_window_ref_chirho.clone(),
                    policy_chirho: downgraded_policy_chirho,
                },
            ),
            Err(RegistryChainErrorChirho::IdempotencyWindowDowngradeChirho { .. })
        ));
    }

    let longer_window_chirho = bounded_policy_chirho(14_400_000, 7_200_000);
    append_registry_op_chirho(
        fixture_chirho.ports_chirho(),
        &fixture_chirho.issuer_signer_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::AmendKindPolicyChirho {
            kind_id_chirho: kind_chirho(),
            supersedes_ref_chirho: first_window_ref_chirho.clone(),
            policy_chirho: longer_window_chirho.clone(),
        },
    )
    .unwrap();
    let verified_chirho = load_verified_registry_chirho(
        fixture_chirho.ports_chirho(),
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        verified_chirho
            .kinds_chirho
            .get(&kind_chirho())
            .unwrap()
            .current_policy_chirho
            .idempotency_window_chirho,
        longer_window_chirho.idempotency_window_chirho,
    );
    let longer_ref_chirho = derive_policy_ref_chirho(&longer_window_chirho).unwrap();
    assert!(matches!(
        verified_chirho.resolve_chirho(&longer_ref_chirho),
        KindResolutionChirho::CurrentChirho(policy_chirho)
            if policy_chirho.idempotency_window_chirho
                == Some(IdempotencyWindowPolicyViewChirho {
                    idempotency_horizon_ms_chirho: 14_400_000,
                    retry_finality_horizon_ms_chirho: 7_200_000,
                })
    ));
    // Cross-law pin: a receipt admitted under the now-superseded R1 resolves ONLY for retention
    // to R2's longer CURRENT window. Admission above still refuses R1 as superseded, and the
    // downgrade attempts above prove this consumer can never observe a shorter current window.
    assert_eq!(
        verified_chirho.resolve_recorded_ref_retention_window_chirho(&first_window_ref_chirho),
        RecordedRetentionWindowChirho::BoundedChirho(IdempotencyWindowPolicyViewChirho {
            idempotency_horizon_ms_chirho: 14_400_000,
            retry_finality_horizon_ms_chirho: 7_200_000,
        })
    );
    let continuation_chirho = verified_chirho
        .resolve_current_continuation_by_kind_chirho(&kind_chirho())
        .expect("verified projection resolves its current continuation coordinate");
    assert_eq!(
        continuation_chirho.kind_policy_ref_chirho,
        longer_ref_chirho
    );
    assert_eq!(
        continuation_chirho.policy_chirho.kind_id_chirho,
        kind_chirho()
    );
    assert!(matches!(
        verified_chirho.resolve_chirho(&first_window_ref_chirho),
        KindResolutionChirho::SupersededChirho
    ));
}

#[test]
fn tampered_line_and_forged_signatures_fail_closed_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    register_chirho(&fixture_chirho);
    let clean_chirho = fixture_chirho
        .storage_chirho
        .read_all_chirho(&path_chirho())
        .unwrap()
        .unwrap();
    // Tamper the policy content (same length): the registry+issuer signatures both break.
    let tampered_chirho = String::from_utf8(clean_chirho.clone()).unwrap().replacen(
        "usd-cent-chirho",
        "usd-CENT-chirho",
        1,
    );
    fixture_chirho
        .storage_chirho
        .atomic_write_chirho(&path_chirho(), tampered_chirho.as_bytes())
        .unwrap();
    assert!(matches!(
        load_verified_registry_chirho(
            fixture_chirho.ports_chirho(),
            &path_chirho(),
            REGISTRY_ID_CHIRHO
        ),
        Err(RegistryChainErrorChirho::IssuerSignatureChirho { seq_chirho: 0 })
    ));
    // Forge ONLY the issuer sig field: the issuer check fails first (fail closed either way).
    let forged_chirho =
        String::from_utf8(clean_chirho)
            .unwrap()
            .replacen("issuer-sig-", "issuer-SIG-", 1);
    fixture_chirho
        .storage_chirho
        .atomic_write_chirho(&path_chirho(), forged_chirho.as_bytes())
        .unwrap();
    assert!(matches!(
        load_verified_registry_chirho(
            fixture_chirho.ports_chirho(),
            &path_chirho(),
            REGISTRY_ID_CHIRHO
        ),
        Err(RegistryChainErrorChirho::IssuerSignatureChirho { seq_chirho: 0 })
    ));
}

#[test]
fn reregister_and_stale_amend_refuse_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    register_chirho(&fixture_chirho);
    // Re-register: first registration wins.
    assert!(matches!(
        append_registry_op_chirho(
            fixture_chirho.ports_chirho(),
            &fixture_chirho.issuer_signer_chirho,
            &path_chirho(),
            REGISTRY_ID_CHIRHO,
            "issuer-alpha-chirho",
            KindRegistryOpChirho::RegisterKindChirho {
                kind_id_chirho: kind_chirho(),
                policy_chirho: policy_v2_chirho(),
            },
        ),
        Err(RegistryChainErrorChirho::ChainChirho { .. })
    ));
    // Amend to v2 legitimately, then a SECOND amend still naming the v1 ref: the monotone amend
    // law refuses (amending off a superseded ref is the registry-side downgrade class).
    let ref_v1_chirho = derive_policy_ref_chirho(&policy_v1_chirho()).unwrap();
    append_registry_op_chirho(
        fixture_chirho.ports_chirho(),
        &fixture_chirho.issuer_signer_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::AmendKindPolicyChirho {
            kind_id_chirho: kind_chirho(),
            supersedes_ref_chirho: ref_v1_chirho.clone(),
            policy_chirho: policy_v2_chirho(),
        },
    )
    .unwrap();
    let mut policy_v3_chirho = policy_v1_chirho();
    policy_v3_chirho.shard_attachment_chirho = "shard-b-chirho".to_owned();
    assert!(matches!(
        append_registry_op_chirho(
            fixture_chirho.ports_chirho(),
            &fixture_chirho.issuer_signer_chirho,
            &path_chirho(),
            REGISTRY_ID_CHIRHO,
            "issuer-alpha-chirho",
            KindRegistryOpChirho::AmendKindPolicyChirho {
                kind_id_chirho: kind_chirho(),
                supersedes_ref_chirho: ref_v1_chirho,
                policy_chirho: policy_v3_chirho,
            },
        ),
        Err(RegistryChainErrorChirho::ChainChirho { .. })
    ));
}

#[test]
fn cross_registry_replay_and_torn_tail_fail_closed_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    register_chirho(&fixture_chirho);
    // The SAME stored bytes under a DIFFERENT registry identity: the anchor and the record's bound
    // registry_id both refuse the splice (prev mismatch fires first — the anchor differs).
    assert!(matches!(
        load_verified_registry_chirho(
            fixture_chirho.ports_chirho(),
            &path_chirho(),
            "cairn-kind-registry:cluster-beta-chirho"
        ),
        Err(RegistryChainErrorChirho::ChainChirho { .. })
    ));
    // A torn tail (partial appended line, no LF): configuration authority FAILS CLOSED.
    fixture_chirho
        .storage_chirho
        .append_durable_chirho(&path_chirho(), b"{\"schema_chirho\":\"torn")
        .unwrap();
    assert!(matches!(
        load_verified_registry_chirho(
            fixture_chirho.ports_chirho(),
            &path_chirho(),
            REGISTRY_ID_CHIRHO
        ),
        Err(RegistryChainErrorChirho::TornTailChirho)
    ));
}

/// The production View over the verified projection: current ref resolves Current, the superseded
/// ref resolves Superseded (never Unknown — the downgrade refusal depends on the distinction).
#[test]
fn verified_registry_serves_the_three_state_view_chirho() {
    use cairn_ledger_log_chirho::admission_chirho::{KindRegistryViewChirho, KindResolutionChirho};
    let fixture_chirho = FixtureChirho::new_chirho();
    register_chirho(&fixture_chirho);
    let ref_v1_chirho = derive_policy_ref_chirho(&policy_v1_chirho()).unwrap();
    append_registry_op_chirho(
        fixture_chirho.ports_chirho(),
        &fixture_chirho.issuer_signer_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        "issuer-alpha-chirho",
        KindRegistryOpChirho::AmendKindPolicyChirho {
            kind_id_chirho: kind_chirho(),
            supersedes_ref_chirho: ref_v1_chirho.clone(),
            policy_chirho: policy_v2_chirho(),
        },
    )
    .unwrap();
    let verified_chirho = load_verified_registry_chirho(
        fixture_chirho.ports_chirho(),
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    let current_ref_chirho = derive_policy_ref_chirho(&policy_v2_chirho()).unwrap();
    match verified_chirho.resolve_chirho(&current_ref_chirho) {
        KindResolutionChirho::CurrentChirho(view_chirho) => {
            assert_eq!(view_chirho.kind_id_chirho, kind_chirho());
        }
        other_chirho => panic!("current ref must resolve Current, got {other_chirho:?}"),
    }
    assert!(matches!(
        verified_chirho.resolve_chirho(&ref_v1_chirho),
        KindResolutionChirho::SupersededChirho
    ));
    assert!(matches!(
        verified_chirho.resolve_chirho(&cairn_ledger_model_chirho::ids_chirho::AssetKindRefChirho(
            cairn_ledger_model_chirho::ids_chirho::DigestChirho("never-was-chirho".into())
        )),
        KindResolutionChirho::UnknownChirho
    ));
}
