// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    ProjectionCostClassChirho, ProjectionReadPolicyChirho, ProjectionRebuildLawChirho,
    ProjectionSourceBindingChirho, StalenessContractChirho, PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::RefCell;
use std::collections::BTreeMap;

const REGISTRY_ID_CHIRHO: &str = "projection-registry-test-chirho";

/// In-memory LedgerStoragePort: append + read_all are all the registry uses.
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

/// Deterministic test signer: sign = tag the content, verify = exact re-derive (injected root).
struct RootSignerChirho;

impl LedgerSignerPortChirho for RootSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        Ok(format!(
            "root-sig::{}",
            cairn_chain_core_chirho::stored_line_digest_hex_chirho(signed_content_line_chirho)
        ))
    }

    fn key_id_chirho(&self) -> String {
        "projection-registry-root-chirho".to_string()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

fn path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/registry-chirho.jsonl".to_string())
}

fn descriptor_chirho(name_chirho: &str, lag_ms_chirho: u64) -> ProjectionDescriptorChirho {
    ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: name_chirho.to_string(),
        source_families_chirho: vec![ProjectionSourceBindingChirho {
            family_id_chirho: "ledger-journal-cluster-a-chirho".to_string(),
            source_schema_ref_chirho: cairn_ledger_model_chirho::ids_chirho::DigestChirho(
                "aa".repeat(32),
            ),
        }],
        fold_fn_ref_chirho: cairn_ledger_model_chirho::ids_chirho::DigestChirho("bb".repeat(32)),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: lag_ms_chirho,
            read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_floor_evidence_ref_chirho: cairn_ledger_model_chirho::ids_chirho::DigestChirho(
            "cc".repeat(32),
        ),
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    }
}

#[test]
fn register_amend_retire_lifecycle_resolves_three_state_chirho() {
    let storage_chirho = MemStorageChirho::default();
    let root_chirho = RootSignerChirho;
    let descriptor_v1_chirho = descriptor_chirho("balances-chirho", 5_000);
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho: descriptor_v1_chirho.clone(),
        },
    )
    .unwrap();
    let digest_v1_chirho = projection_descriptor_digest_chirho(&descriptor_v1_chirho).unwrap();

    let loaded_chirho = load_verified_projection_registry_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    assert!(matches!(
        loaded_chirho.resolve_chirho("balances-chirho", &digest_v1_chirho),
        ProjectionResolutionChirho::CurrentChirho { .. }
    ));
    verify_descriptor_digest_binding_chirho(&descriptor_v1_chirho, &digest_v1_chirho).unwrap();

    // Amend to v2 (a tighter staleness contract): v1 becomes SUPERSEDED, v2 CURRENT.
    let descriptor_v2_chirho = descriptor_chirho("balances-chirho", 1_000);
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::AmendProjectionChirho {
            supersedes_digest_chirho: digest_v1_chirho.clone(),
            descriptor_chirho: descriptor_v2_chirho.clone(),
        },
    )
    .unwrap();
    let digest_v2_chirho = projection_descriptor_digest_chirho(&descriptor_v2_chirho).unwrap();
    let loaded_chirho = load_verified_projection_registry_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        loaded_chirho.resolve_chirho("balances-chirho", &digest_v1_chirho),
        ProjectionResolutionChirho::SupersededChirho
    );
    assert!(matches!(
        loaded_chirho.resolve_chirho("balances-chirho", &digest_v2_chirho),
        ProjectionResolutionChirho::CurrentChirho { .. }
    ));
    assert_eq!(
        loaded_chirho.resolve_chirho("balances-chirho", &DigestChirho("dd".repeat(32))),
        ProjectionResolutionChirho::UnknownChirho
    );
    assert_eq!(
        loaded_chirho.resolve_chirho("unknown-chirho", &digest_v2_chirho),
        ProjectionResolutionChirho::UnknownChirho
    );

    // Retire: EVERY digest refuses — retirement dominates currency and supersession.
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RetireProjectionChirho {
            name_chirho: "balances-chirho".to_string(),
        },
    )
    .unwrap();
    let loaded_chirho = load_verified_projection_registry_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        loaded_chirho.resolve_chirho("balances-chirho", &digest_v2_chirho),
        ProjectionResolutionChirho::RetiredChirho
    );
    assert_eq!(
        loaded_chirho.resolve_chirho("balances-chirho", &digest_v1_chirho),
        ProjectionResolutionChirho::RetiredChirho
    );
}

#[test]
fn amend_off_superseded_digest_refuses_the_downgrade_class_chirho() {
    let storage_chirho = MemStorageChirho::default();
    let root_chirho = RootSignerChirho;
    let descriptor_v1_chirho = descriptor_chirho("timeline-chirho", 5_000);
    let digest_v1_chirho = projection_descriptor_digest_chirho(&descriptor_v1_chirho).unwrap();
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho: descriptor_v1_chirho,
        },
    )
    .unwrap();
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::AmendProjectionChirho {
            supersedes_digest_chirho: digest_v1_chirho.clone(),
            descriptor_chirho: descriptor_chirho("timeline-chirho", 1_000),
        },
    )
    .unwrap();
    // A second amend naming the SUPERSEDED v1 digest is the downgrade class — refused.
    let error_chirho = append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::AmendProjectionChirho {
            supersedes_digest_chirho: digest_v1_chirho,
            descriptor_chirho: descriptor_chirho("timeline-chirho", 250),
        },
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("monotone amend law"));
    // Duplicate registration refuses too (first registration wins).
    let error_chirho = append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho: descriptor_chirho("timeline-chirho", 9_000),
        },
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("first registration wins"));
}

#[test]
fn tamper_torn_and_forged_sig_fail_closed_chirho() {
    let storage_chirho = MemStorageChirho::default();
    let root_chirho = RootSignerChirho;
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho: descriptor_chirho("balances-chirho", 5_000),
        },
    )
    .unwrap();
    let clean_chirho = storage_chirho
        .read_all_chirho(&path_chirho())
        .unwrap()
        .unwrap();

    // Torn tail: config authority fails closed, never repairs.
    let mut torn_chirho = clean_chirho.clone();
    torn_chirho.pop();
    storage_chirho
        .atomic_write_chirho(&path_chirho(), &torn_chirho)
        .unwrap();
    let error_chirho = load_verified_projection_registry_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("torn tail"));

    // Payload tamper: the root signature no longer verifies over the altered canonical content.
    let tampered_chirho = String::from_utf8(clean_chirho.clone())
        .unwrap()
        .replace("balances-chirho", "balancez-chirho");
    storage_chirho
        .atomic_write_chirho(&path_chirho(), tampered_chirho.as_bytes())
        .unwrap();
    let error_chirho = load_verified_projection_registry_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("root signature does not verify"));

    // Cross-registry replay of the whole log: the DOMAIN-SEPARATED ANCHOR net fires first (record
    // 0's prev cannot bind another registry's anchor).
    storage_chirho
        .atomic_write_chirho(&path_chirho(), &clean_chirho)
        .unwrap();
    let error_chirho = load_verified_projection_registry_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        "other-registry-chirho",
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("prev mismatch at seq 0"));

    // The IDENTITY net, exercised precisely: a validly-signed record whose prev binds the OTHER
    // registry's anchor but whose embedded registry id names the original — the second net fires.
    let mut forged_record_chirho = ProjectionRegistryRecordChirho {
        schema_chirho: PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        seq_chirho: 0,
        prev_chirho: chain_anchor_hex_chirho(
            PROJECTION_REGISTRY_CHAIN_DOMAIN_CHIRHO,
            "other-registry-chirho",
        ),
        registry_id_chirho: REGISTRY_ID_CHIRHO.to_string(),
        op_chirho: ProjectionRegistryOpChirho::RetireProjectionChirho {
            name_chirho: "balances-chirho".to_string(),
        },
        root_sig_chirho: String::new(),
    };
    forged_record_chirho.root_sig_chirho = root_chirho
        .sign_chirho(&registry_root_signed_content_chirho(&forged_record_chirho).unwrap())
        .unwrap();
    let forged_line_chirho =
        canonical_projection_registry_line_chirho(&forged_record_chirho).unwrap();
    storage_chirho
        .atomic_write_chirho(&path_chirho(), format!("{forged_line_chirho}\n").as_bytes())
        .unwrap();
    let error_chirho = load_verified_projection_registry_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        "other-registry-chirho",
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("cross-registry replay"));
}

#[test]
fn wire_goldens_and_malleability_refuse_chirho() {
    let record_chirho = ProjectionRegistryRecordChirho {
        schema_chirho: PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        seq_chirho: 0,
        prev_chirho: chain_anchor_hex_chirho(
            PROJECTION_REGISTRY_CHAIN_DOMAIN_CHIRHO,
            REGISTRY_ID_CHIRHO,
        ),
        registry_id_chirho: REGISTRY_ID_CHIRHO.to_string(),
        op_chirho: ProjectionRegistryOpChirho::RetireProjectionChirho {
            name_chirho: "balances-chirho".to_string(),
        },
        root_sig_chirho: "sig-chirho".to_string(),
    };
    let line_chirho = canonical_projection_registry_line_chirho(&record_chirho).unwrap();
    // Round-trip: strict parse accepts EXACTLY the canonical bytes.
    assert_eq!(
        parse_canonical_projection_registry_line_chirho(&line_chirho).unwrap(),
        record_chirho
    );
    // Reordered/whitespace/trailing/unknown-field forms all refuse.
    let reordered_chirho = line_chirho.replacen(r#"{"schema_chirho""#, r#"{ "schema_chirho""#, 1);
    assert!(parse_canonical_projection_registry_line_chirho(&reordered_chirho).is_err());
    assert!(parse_canonical_projection_registry_line_chirho(&format!("{line_chirho} ")).is_err());
    let unknown_field_chirho = line_chirho.replacen(
        r#""root_sig_chirho":"#,
        r#""extra_chirho":true,"root_sig_chirho":"#,
        1,
    );
    assert!(parse_canonical_projection_registry_line_chirho(&unknown_field_chirho).is_err());
    // Wrong schema refuses at the probe.
    let wrong_schema_chirho = line_chirho.replacen(
        PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO,
        "other-schema-v1-chirho",
        1,
    );
    assert!(parse_canonical_projection_registry_line_chirho(&wrong_schema_chirho).is_err());
}

#[test]
fn revert_amend_back_to_a_prior_descriptor_resolves_current_chirho() {
    // claude's #5005 pin: after A -> B -> back-to-A, A's digest sits in BOTH current and the
    // superseded set — ONLY the current-before-superseded check order makes it resolve Current.
    // This test makes that order load-bearing instead of accidental.
    let storage_chirho = MemStorageChirho::default();
    let root_chirho = RootSignerChirho;
    let descriptor_a_chirho = descriptor_chirho("revert-chirho", 5_000);
    let digest_a_chirho = projection_descriptor_digest_chirho(&descriptor_a_chirho).unwrap();
    let descriptor_b_chirho = descriptor_chirho("revert-chirho", 1_000);
    let digest_b_chirho = projection_descriptor_digest_chirho(&descriptor_b_chirho).unwrap();
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho: descriptor_a_chirho.clone(),
        },
    )
    .unwrap();
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::AmendProjectionChirho {
            supersedes_digest_chirho: digest_a_chirho.clone(),
            descriptor_chirho: descriptor_b_chirho,
        },
    )
    .unwrap();
    append_projection_registry_op_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::AmendProjectionChirho {
            supersedes_digest_chirho: digest_b_chirho.clone(),
            descriptor_chirho: descriptor_a_chirho,
        },
    )
    .unwrap();
    let loaded_chirho = load_verified_projection_registry_chirho(
        &storage_chirho,
        &root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    // A's digest is current AGAIN despite also being in the superseded set: Current wins.
    assert!(matches!(
        loaded_chirho.resolve_chirho("revert-chirho", &digest_a_chirho),
        ProjectionResolutionChirho::CurrentChirho { .. }
    ));
    assert_eq!(
        loaded_chirho.resolve_chirho("revert-chirho", &digest_b_chirho),
        ProjectionResolutionChirho::SupersededChirho
    );
}
