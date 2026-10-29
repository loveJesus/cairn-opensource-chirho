// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::attestation_stores_chirho::placement_record_store_chirho::tests_chirho::successor_chirho;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use std::path::PathBuf;
use tempfile::TempDir;

pub(crate) struct FixtureChirho {
    _temp_chirho: TempDir,
    pub(crate) record_chirho: TenantPlacementRecordChirho,
    pub(crate) placement_key_chirho: String,
    pub(crate) roster_key_chirho: String,
    pub(crate) plan_key_chirho: String,
    pub(crate) placement_root_chirho: PathBuf,
    pub(crate) serving_node_roots_chirho: Vec<PathBuf>,
    /// Exposed so a successor REVISION can be authored: every readiness receipt binds the intent
    /// digest, so a revision-1 record has to re-sign them all, held observer included.
    pub(crate) held_observer_root_chirho: PathBuf,
    plan_root_chirho: PathBuf,
}

pub(crate) fn fixture_chirho() -> FixtureChirho {
    let temp_chirho = tempfile::tempdir().expect("tempdir");
    let placement_root_chirho = temp_chirho.path().join("placement-key-chirho");
    let roster_root_chirho = temp_chirho.path().join("roster-key-chirho");
    let plan_root_chirho = temp_chirho.path().join("plan-key-chirho");
    sign_message_chirho(&placement_root_chirho, b"provision-placement-chirho").unwrap();
    sign_message_chirho(&roster_root_chirho, b"provision-roster-chirho").unwrap();
    sign_message_chirho(&plan_root_chirho, b"provision-plan-chirho").unwrap();
    let placement_key_chirho = pubkey_hex_chirho(&placement_root_chirho).unwrap();
    let roster_key_chirho = pubkey_hex_chirho(&roster_root_chirho).unwrap();
    let plan_key_chirho = pubkey_hex_chirho(&plan_root_chirho).unwrap();

    let mut node_roots_chirho = (0..4)
        .map(|index_chirho| {
            let root_chirho = temp_chirho
                .path()
                .join(format!("node-{index_chirho}-chirho"));
            sign_message_chirho(&root_chirho, b"provision-node-chirho").unwrap();
            let node_id_chirho = pubkey_hex_chirho(&root_chirho).unwrap();
            (node_id_chirho, root_chirho)
        })
        .collect::<Vec<_>>();
    node_roots_chirho.sort_by(|left_chirho, right_chirho| left_chirho.0.cmp(&right_chirho.0));
    let held_observer_root_chirho = node_roots_chirho.pop().unwrap();
    let serving_node_roots_chirho = node_roots_chirho
        .iter()
        .map(|(_node_id_chirho, root_chirho)| root_chirho.clone())
        .collect();
    let domains_chirho = [
        FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "de-fsn-chirho".to_string(),
        },
        FailureDomainChirho {
            provider_chirho: "ovh-chirho".to_string(),
            region_chirho: "fr-gra-chirho".to_string(),
        },
        FailureDomainChirho {
            provider_chirho: "ovh-chirho".to_string(),
            region_chirho: "fr-rbx-chirho".to_string(),
        },
    ];
    let assigned_nodes_chirho = node_roots_chirho
        .iter()
        .enumerate()
        .map(
            |(index_chirho, (node_id_chirho, _root_chirho))| TenantPlacementNodeBindingChirho {
                node_id_chirho: node_id_chirho.clone(),
                failure_domain_chirho: domains_chirho[index_chirho].clone(),
                expected_root_binding_chirho: format!(
                    "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
                    char::from(b'a' + u8::try_from(index_chirho).unwrap())
                        .to_string()
                        .repeat(64)
                ),
                expected_cluster_config_blake3_chirho: char::from(
                    b'd' + u8::try_from(index_chirho).unwrap(),
                )
                .to_string()
                .repeat(64),
            },
        )
        .collect::<Vec<_>>();
    let held_observer_node_chirho = TenantPlacementNodeBindingChirho {
        node_id_chirho: held_observer_root_chirho.0.clone(),
        failure_domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fi-hel-chirho".to_string(),
        },
        expected_root_binding_chirho: format!(
            "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
            "1".repeat(64)
        ),
        expected_cluster_config_blake3_chirho: "2".repeat(64),
    };
    let mut allowed_domains_chirho = domains_chirho.to_vec();
    allowed_domains_chirho.sort();
    let intent_chirho = TenantPlacementIntentChirho {
        schema_chirho: TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        digest_domain_chirho: TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO.to_string(),
        revision_chirho: 0,
        previous_assignment_digest_chirho: None,
        tenant_id_chirho: "credits-demo-chirho".to_string(),
        consistency_group_id_chirho: "tenant-chirho:credits-demo-chirho".to_string(),
        preferred_node_chirho: assigned_nodes_chirho[0].node_id_chirho.clone(),
        assigned_nodes_chirho,
        held_observer_node_chirho,
        demand_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 500,
            memory_bytes_chirho: 512 * 1024 * 1024,
            durable_bytes_chirho: 10 * 1024 * 1024 * 1024,
        },
        residency_chirho: TenantPlacementResidencyChirho {
            allowed_domains_chirho,
        },
        topology_plan_digest_chirho: "f".repeat(64),
    };
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(&intent_chirho).unwrap();
    let readiness_receipts_chirho = node_roots_chirho
        .iter()
        .zip(&intent_chirho.assigned_nodes_chirho)
        .enumerate()
        .map(
            |(index_chirho, ((node_id_chirho, root_chirho), assigned_chirho))| {
                let mut receipt_chirho = TenantPlacementNodeReadinessReceiptChirho {
                    schema_chirho: TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V2_CHIRHO.to_string(),
                    signature_domain_chirho: TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V2_CHIRHO
                        .to_string(),
                    intent_digest_chirho: intent_digest_chirho.clone(),
                    node_id_chirho: node_id_chirho.clone(),
                    failure_domain_chirho: assigned_chirho.failure_domain_chirho.clone(),
                    root_binding_chirho: assigned_chirho.expected_root_binding_chirho.clone(),
                    cluster_config_blake3_chirho: assigned_chirho
                        .expected_cluster_config_blake3_chirho
                        .clone(),
                    activation_anchor_digest_chirho: Some(
                        char::from(b'3' + u8::try_from(index_chirho).unwrap())
                            .to_string()
                            .repeat(64),
                    ),
                    prepared_at_ms_chirho: 1_786_542_000_000,
                    signer_key_id_chirho: node_id_chirho.clone(),
                    sig_chirho: String::new(),
                };
                let unsigned_chirho =
                    unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho).unwrap();
                receipt_chirho.sig_chirho =
                    sign_message_chirho(root_chirho, &unsigned_chirho).unwrap();
                receipt_chirho
            },
        )
        .collect::<Vec<_>>();
    let mut held_observer_readiness_receipt_chirho =
        TenantPlacementHeldObserverReadinessReceiptChirho {
            schema_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO.to_string(),
            signature_domain_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO
                .to_string(),
            intent_digest_chirho: intent_digest_chirho.clone(),
            node_id_chirho: held_observer_root_chirho.0.clone(),
            failure_domain_chirho: intent_chirho
                .held_observer_node_chirho
                .failure_domain_chirho
                .clone(),
            root_binding_chirho: intent_chirho
                .held_observer_node_chirho
                .expected_root_binding_chirho
                .clone(),
            cluster_config_blake3_chirho: intent_chirho
                .held_observer_node_chirho
                .expected_cluster_config_blake3_chirho
                .clone(),
            prepared_at_ms_chirho: 1_786_542_000_001,
            signer_key_id_chirho: held_observer_root_chirho.0.clone(),
            sig_chirho: String::new(),
        };
    let unsigned_chirho = unsigned_tenant_placement_held_observer_readiness_message_chirho(
        &held_observer_readiness_receipt_chirho,
    )
    .unwrap();
    held_observer_readiness_receipt_chirho.sig_chirho =
        sign_message_chirho(&held_observer_root_chirho.1, &unsigned_chirho).unwrap();
    let mut record_chirho = TenantPlacementRecordChirho {
        schema_chirho: TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_RECORD_DOMAIN_V2_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        serving_readiness_receipts_chirho: readiness_receipts_chirho,
        held_observer_readiness_receipt_chirho,
        placement_key_id_chirho: placement_key_chirho.clone(),
        sig_chirho: String::new(),
    };
    let unsigned_chirho = unsigned_tenant_placement_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        sign_message_chirho(&placement_root_chirho, &unsigned_chirho).unwrap();
    FixtureChirho {
        _temp_chirho: temp_chirho,
        record_chirho,
        placement_key_chirho,
        roster_key_chirho,
        plan_key_chirho,
        placement_root_chirho,
        serving_node_roots_chirho,
        held_observer_root_chirho: held_observer_root_chirho.1.clone(),
        plan_root_chirho,
    }
}

#[test]
fn exact_three_voters_and_one_held_observer_signed_placement_verifies_chirho() {
    let fixture_chirho = fixture_chirho();
    let verified_chirho = verify_tenant_placement_record_chirho(
        fixture_chirho.record_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    assert_eq!(verified_chirho.assigned_nodes_chirho().len(), 3);
    assert!(verified_chirho
        .assigned_nodes_chirho()
        .iter()
        .all(|node_chirho| {
            node_chirho.node_id_chirho != verified_chirho.held_observer_node_chirho().node_id_chirho
        }));
    assert_eq!(
        verified_chirho.preferred_node_chirho(),
        verified_chirho.assigned_nodes_chirho()[0].node_id_chirho
    );
    assert_eq!(verified_chirho.assignment_digest_chirho().len(), 64);
}

#[test]
fn missing_or_foreign_readiness_receipt_refuses_by_identity_chirho() {
    let primary_fixture_chirho = fixture_chirho();
    let mut missing_chirho = primary_fixture_chirho.record_chirho.clone();
    missing_chirho.serving_readiness_receipts_chirho.pop();
    assert_eq!(
        verify_tenant_placement_record_chirho(
            missing_chirho,
            &primary_fixture_chirho.placement_key_chirho,
            &primary_fixture_chirho.roster_key_chirho,
            &primary_fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::ReadinessPopulationChirho
    );

    let mut foreign_chirho = primary_fixture_chirho.record_chirho;
    foreign_chirho.serving_readiness_receipts_chirho[0].node_id_chirho = foreign_chirho
        .serving_readiness_receipts_chirho[1]
        .node_id_chirho
        .clone();
    assert_eq!(
        verify_tenant_placement_record_chirho(
            foreign_chirho,
            &primary_fixture_chirho.placement_key_chirho,
            &primary_fixture_chirho.roster_key_chirho,
            &primary_fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::ReadinessBindingChirho
    );

    let duplicate_fixture_chirho = fixture_chirho();
    let mut duplicate_chirho = duplicate_fixture_chirho.record_chirho;
    duplicate_chirho.serving_readiness_receipts_chirho[2] =
        duplicate_chirho.serving_readiness_receipts_chirho[0].clone();
    assert_eq!(
        verify_tenant_placement_record_chirho(
            duplicate_chirho,
            &duplicate_fixture_chirho.placement_key_chirho,
            &duplicate_fixture_chirho.roster_key_chirho,
            &duplicate_fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::ReadinessBindingChirho
    );
}

#[test]
fn readiness_signature_from_another_assigned_node_refuses_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut wrong_signer_chirho = fixture_chirho.record_chirho;
    wrong_signer_chirho.serving_readiness_receipts_chirho[0].sig_chirho = wrong_signer_chirho
        .serving_readiness_receipts_chirho[1]
        .sig_chirho
        .clone();
    assert_eq!(
        verify_tenant_placement_record_chirho(
            wrong_signer_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::ReadinessSignatureChirho
    );
}

#[test]
fn receipt_free_intent_digest_refuses_a_valid_looking_altered_decision_chirho() {
    let fixture_chirho = fixture_chirho();
    let intent_bytes_chirho =
        serde_json::to_vec(&fixture_chirho.record_chirho.intent_chirho).unwrap();
    assert!(!intent_bytes_chirho
        .windows(b"receipt".len())
        .any(|window_chirho| window_chirho == b"receipt"));

    let mut altered_chirho = fixture_chirho.record_chirho;
    altered_chirho.intent_chirho.preferred_node_chirho =
        altered_chirho.intent_chirho.assigned_nodes_chirho[1]
            .node_id_chirho
            .clone();
    assert_eq!(
        verify_tenant_placement_record_chirho(
            altered_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::IntentDigestChirho
    );
}

#[test]
fn serving_and_held_observer_receipts_cannot_cross_roles_chirho() {
    let fixture_chirho = fixture_chirho();
    let serving_chirho = &fixture_chirho
        .record_chirho
        .serving_readiness_receipts_chirho[0];
    let mut crossed_chirho = fixture_chirho.record_chirho.clone();
    crossed_chirho.held_observer_readiness_receipt_chirho =
        TenantPlacementHeldObserverReadinessReceiptChirho {
            schema_chirho: serving_chirho.schema_chirho.clone(),
            signature_domain_chirho: serving_chirho.signature_domain_chirho.clone(),
            intent_digest_chirho: serving_chirho.intent_digest_chirho.clone(),
            node_id_chirho: serving_chirho.node_id_chirho.clone(),
            failure_domain_chirho: serving_chirho.failure_domain_chirho.clone(),
            root_binding_chirho: serving_chirho.root_binding_chirho.clone(),
            cluster_config_blake3_chirho: serving_chirho.cluster_config_blake3_chirho.clone(),
            prepared_at_ms_chirho: serving_chirho.prepared_at_ms_chirho,
            signer_key_id_chirho: serving_chirho.signer_key_id_chirho.clone(),
            sig_chirho: serving_chirho.sig_chirho.clone(),
        };
    assert_eq!(
        verify_tenant_placement_record_chirho(
            crossed_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::HeldObserverReadinessSchemaChirho
    );
}

#[test]
fn held_observer_is_distinct_and_tenant_group_is_injective_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut duplicate_observer_chirho = fixture_chirho.record_chirho.intent_chirho.clone();
    duplicate_observer_chirho.held_observer_node_chirho =
        duplicate_observer_chirho.assigned_nodes_chirho[0].clone();
    assert_eq!(
        tenant_placement_intent_digest_chirho(&duplicate_observer_chirho).unwrap_err(),
        TenantPlacementRefusalChirho::HeldObserverIdentityChirho
    );

    let mut foreign_tenant_chirho = fixture_chirho.record_chirho.intent_chirho;
    foreign_tenant_chirho.tenant_id_chirho = "other-tenant-chirho".to_string();
    assert_eq!(
        tenant_placement_intent_digest_chirho(&foreign_tenant_chirho).unwrap_err(),
        TenantPlacementRefusalChirho::ConsistencyGroupIdentityChirho
    );
    // Migration note: if group ids become derived instead of stored, this fixture can no longer
    // violate the property; retire this arm only after moving the check to that construction tier.
}

#[test]
fn authority_keys_must_be_distinct_chirho() {
    let fixture_chirho = fixture_chirho();
    assert_eq!(
        verify_tenant_placement_record_chirho(
            fixture_chirho.record_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::AuthorityKeySeparationChirho
    );
}

#[test]
fn placement_and_geo_plan_keys_are_not_interchangeable_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut geo_signed_placement_chirho = fixture_chirho.record_chirho.clone();
    geo_signed_placement_chirho.sig_chirho.clear();
    let message_chirho =
        unsigned_tenant_placement_record_message_chirho(&geo_signed_placement_chirho).unwrap();
    geo_signed_placement_chirho.sig_chirho =
        sign_message_chirho(&fixture_chirho.plan_root_chirho, &message_chirho).unwrap();
    assert_eq!(
        verify_tenant_placement_record_chirho(
            geo_signed_placement_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::PlacementSignatureChirho
    );

    assert_eq!(
        verify_tenant_placement_record_chirho(
            fixture_chirho.record_chirho,
            &fixture_chirho.plan_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.placement_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::PlacementKeyChirho
    );
}

#[test]
fn preferred_node_and_spread_are_part_of_the_intent_digest_gate_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut wrong_preferred_chirho = fixture_chirho.record_chirho.intent_chirho.clone();
    wrong_preferred_chirho.preferred_node_chirho = "0".repeat(64);
    assert_eq!(
        tenant_placement_intent_digest_chirho(&wrong_preferred_chirho).unwrap_err(),
        TenantPlacementRefusalChirho::PreferredNodeChirho
    );

    let mut collapsed_chirho = fixture_chirho.record_chirho.intent_chirho;
    for (index_chirho, node_chirho) in collapsed_chirho
        .assigned_nodes_chirho
        .iter_mut()
        .enumerate()
    {
        node_chirho.failure_domain_chirho = FailureDomainChirho {
            provider_chirho: "one-provider-chirho".to_string(),
            region_chirho: format!("region-{index_chirho}-chirho"),
        };
    }
    assert_eq!(
        tenant_placement_intent_digest_chirho(&collapsed_chirho).unwrap_err(),
        TenantPlacementRefusalChirho::FailureDomainSpreadChirho
    );
}

#[test]
fn placement_store_refuses_oversize_and_symlink_entries_before_decode_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let oversized_chirho = temp_chirho.path().join("oversized-placement-chirho.json");
    std::fs::write(
        &oversized_chirho,
        vec![b' '; TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO as usize + 1],
    )
    .unwrap();
    assert_eq!(
        load_and_verify_tenant_placement_record_chirho(
            &oversized_chirho,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::StoreTooLargeChirho
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target_chirho = temp_chirho.path().join("target-placement-chirho.json");
        let link_chirho = temp_chirho.path().join("linked-placement-chirho.json");
        std::fs::write(&target_chirho, b"{}").unwrap();
        symlink(&target_chirho, &link_chirho).unwrap();
        assert_eq!(
            load_and_verify_tenant_placement_record_chirho(
                &link_chirho,
                &"a".repeat(64),
                &"b".repeat(64),
                &"c".repeat(64),
            )
            .unwrap_err(),
            TenantPlacementRefusalChirho::StoreEntryTypeChirho
        );
    }
}

#[test]
#[cfg(unix)]
fn a_hard_linked_placement_record_refuses_as_identity_unstable_not_as_entry_type_chirho() {
    // The hardening this arm exists for. A hard link is a REGULAR FILE and passes every pre-open
    // check the old local loader made -- file type, size, not-a-symlink -- so the previous
    // implementation read it happily. Another name for the same inode means anyone who can write
    // through the other name can change the record under the reader.
    //
    // It must refuse as StoreIdentityUnstable and NOT as StoreEntryType: "you handed me the wrong
    // kind of thing" and "the thing is reachable and mutable through another name" are different
    // operator problems, and folding them together is the conflation this repo keeps paying for.
    let temp_chirho = tempfile::tempdir().unwrap();
    let target_chirho = temp_chirho.path().join("target-placement-chirho.json");
    let hard_link_chirho = temp_chirho.path().join("hardlinked-placement-chirho.json");
    std::fs::write(&target_chirho, b"{}").unwrap();
    std::fs::hard_link(&target_chirho, &hard_link_chirho).unwrap();

    let refusal_chirho = load_and_verify_tenant_placement_record_chirho(
        &hard_link_chirho,
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        TenantPlacementRefusalChirho::StoreIdentityUnstableChirho
    );
    assert_ne!(
        refusal_chirho,
        TenantPlacementRefusalChirho::StoreEntryTypeChirho
    );

    // Positive control, and my first version of it was WRONG in a way worth keeping: I pointed it at
    // `target_chirho`, expecting the "original" name to still be single-link. It is not --
    // `hard_link` raises nlink on the SHARED INODE, so both names become multiply-linked and both
    // correctly refuse. The control caught my own misunderstanding of the fixture, which is exactly
    // what a control is for.
    //
    // So the control uses an INDEPENDENT single-link file with the same bytes: it must get past the
    // identity gate and fail later, on decode. Without it, the assertion above would pass equally
    // well against a loader that refused every path handed to it.
    let independent_chirho = temp_chirho.path().join("independent-placement-chirho.json");
    std::fs::write(&independent_chirho, b"{}").unwrap();
    assert_eq!(
        load_and_verify_tenant_placement_record_chirho(
            &independent_chirho,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::DecodeChirho
    );
}

// ---------------------------------------------------------------------------------------------
// MULTI-PARTY RECEIPT BINDING
//
// A placement record is only multi-party because each readiness receipt is signed by ITS OWN node
// and bound to THIS intent. That property is what makes a config-hash change require fresh receipts
// from every serving node and the held observer -- and it is what a reviewed expectation refresh
// leans on.
//
// Measured 2026-08-21 across 7 crates (49 result lines, 0 compile errors): deleting the serving
// signer check, the held-observer binding check, or the held-observer signer check left everything
// GREEN. The serving-node BINDING twin was pinned; its held-observer counterpart eleven lines away,
// checking the same six fields, was not. The guarded/unguarded split ran exactly along
// serving-vs-held-observer, which is the split the multi-party argument depends on.
// ---------------------------------------------------------------------------------------------

/// An authentic held-observer receipt from the PREVIOUS revision must not satisfy a new record.
///
/// This is the replay the binding check exists for, staged as the real thing rather than a synthetic
/// digest: revision 1 is authored properly by `successor_chirho`, then its held-observer receipt is
/// replaced with revision 0's -- correctly signed by the correct held observer, for the wrong intent
/// -- and the record is re-signed so the record signature cannot be what refuses.
///
/// The signature below the binding check verifies against the EXPECTED held-observer key, so a
/// receipt genuinely signed by that key verifies no matter which intent it names. The binding check
/// is the only thing standing between a stale receipt and a new revision.
#[test]
fn a_held_observer_receipt_from_the_previous_revision_refuses_by_binding_chirho() {
    let fixture_chirho = fixture_chirho();
    let revision_zero_chirho = fixture_chirho.record_chirho.clone();
    let revision_zero_digest_chirho =
        tenant_placement_assignment_digest_chirho(&revision_zero_chirho).unwrap();
    let revision_one_chirho = successor_chirho(
        &fixture_chirho,
        &revision_zero_chirho,
        1,
        Some(revision_zero_digest_chirho),
    );

    // POSITIVE CONTROL. Without this, a revision 1 broken for any unrelated reason would refuse and
    // the arm below would pass while proving nothing about the held observer.
    verify_tenant_placement_record_chirho(
        revision_one_chirho.clone(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .expect("the successor revision must VERIFY before its held-observer receipt is replayed");

    let mut replayed_chirho = revision_one_chirho;
    replayed_chirho.held_observer_readiness_receipt_chirho = revision_zero_chirho
        .held_observer_readiness_receipt_chirho
        .clone();
    replayed_chirho.sig_chirho = String::new();
    let unsigned_chirho =
        unsigned_tenant_placement_record_message_chirho(&replayed_chirho).unwrap();
    replayed_chirho.sig_chirho =
        sign_message_chirho(&fixture_chirho.placement_root_chirho, &unsigned_chirho).unwrap();

    assert_eq!(
        verify_tenant_placement_record_chirho(
            replayed_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::HeldObserverReadinessBindingChirho,
        "a stale held-observer receipt must refuse BY BINDING -- not by record signature, which this \
         fixture deliberately repairs, and not by the held-observer signature, which is genuine"
    );
}

/// The held observer's receipt must name the held observer as its signer.
///
/// Verification uses the EXPECTED `node_id_chirho` as the public key rather than the receipt's own
/// `signer_key_id_chirho`, so today a mismatch is also refused one line later by the signature
/// check. That makes this a coverage pin rather than a live hole -- and it is worth pinning
/// precisely because a future refactor that verified against the receipt's self-declared signer
/// would turn it into a real one with nothing firing. The tamper is re-signed so the identity under
/// test is the one that fires.
#[test]
fn a_held_observer_receipt_naming_another_signer_refuses_by_signer_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    let foreign_signer_chirho = fixture_chirho
        .record_chirho
        .serving_readiness_receipts_chirho[0]
        .node_id_chirho
        .clone();
    let mut wrong_signer_chirho = fixture_chirho.record_chirho.clone();
    assert_ne!(
        wrong_signer_chirho
            .held_observer_readiness_receipt_chirho
            .signer_key_id_chirho,
        foreign_signer_chirho,
        "fixture control: the substituted signer must actually differ"
    );
    wrong_signer_chirho
        .held_observer_readiness_receipt_chirho
        .signer_key_id_chirho = foreign_signer_chirho;
    wrong_signer_chirho
        .held_observer_readiness_receipt_chirho
        .sig_chirho = String::new();
    let unsigned_chirho = unsigned_tenant_placement_held_observer_readiness_message_chirho(
        &wrong_signer_chirho.held_observer_readiness_receipt_chirho,
    )
    .unwrap();
    wrong_signer_chirho
        .held_observer_readiness_receipt_chirho
        .sig_chirho =
        sign_message_chirho(&fixture_chirho.held_observer_root_chirho, &unsigned_chirho).unwrap();

    assert_eq!(
        verify_tenant_placement_record_chirho(
            wrong_signer_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::HeldObserverReadinessSignerChirho
    );
}

/// A serving receipt must name its own node as signer -- the serving twin of the arm above.
#[test]
fn a_serving_receipt_naming_another_signer_refuses_by_signer_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut wrong_signer_chirho = fixture_chirho.record_chirho.clone();
    let foreign_signer_chirho = wrong_signer_chirho.serving_readiness_receipts_chirho[1]
        .node_id_chirho
        .clone();
    assert_ne!(
        wrong_signer_chirho.serving_readiness_receipts_chirho[0].signer_key_id_chirho,
        foreign_signer_chirho,
        "fixture control: the substituted signer must actually differ"
    );
    wrong_signer_chirho.serving_readiness_receipts_chirho[0].signer_key_id_chirho =
        foreign_signer_chirho;
    wrong_signer_chirho.serving_readiness_receipts_chirho[0].sig_chirho = String::new();
    let unsigned_chirho = unsigned_tenant_placement_readiness_message_chirho(
        &wrong_signer_chirho.serving_readiness_receipts_chirho[0],
    )
    .unwrap();
    wrong_signer_chirho.serving_readiness_receipts_chirho[0].sig_chirho = sign_message_chirho(
        &fixture_chirho.serving_node_roots_chirho[0],
        &unsigned_chirho,
    )
    .unwrap();

    assert_eq!(
        verify_tenant_placement_record_chirho(
            wrong_signer_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::ReadinessSignerChirho
    );
}

/// The held observer's receipt must be signed BY the held observer.
///
/// This completes the serving-vs-held-observer asymmetry. Measured 2026-08-21 by identity-swap
/// mutation across every `TenantPlacementRefusalChirho` variant: the serving node had arms for
/// population, binding, signer AND signature; the held observer had none of binding, signer or
/// signature. This is the last of the four, and the only one of the ten unpinned identities in that
/// sweep that is an AUTHENTICITY check rather than a shape/validation refusal.
///
/// The forgery keeps `node_id_chirho` and `signer_key_id_chirho` correct so the binding and signer
/// checks both pass, leaving the ed25519 verification as the only thing that can refuse — otherwise
/// the arm would pass on a neighbour's identity and prove nothing about the signature.
#[test]
fn a_held_observer_receipt_signed_by_another_key_refuses_by_signature_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut forged_chirho = fixture_chirho.record_chirho.clone();
    forged_chirho
        .held_observer_readiness_receipt_chirho
        .sig_chirho = String::new();
    let unsigned_chirho = unsigned_tenant_placement_held_observer_readiness_message_chirho(
        &forged_chirho.held_observer_readiness_receipt_chirho,
    )
    .unwrap();
    // signed by a SERVING node root, not the held observer's
    forged_chirho
        .held_observer_readiness_receipt_chirho
        .sig_chirho = sign_message_chirho(
        &fixture_chirho.serving_node_roots_chirho[0],
        &unsigned_chirho,
    )
    .unwrap();

    assert_eq!(
        forged_chirho
            .held_observer_readiness_receipt_chirho
            .signer_key_id_chirho,
        fixture_chirho
            .record_chirho
            .intent_chirho
            .held_observer_node_chirho
            .node_id_chirho,
        "fixture control: the declared signer must still be correct, so the SIGNATURE check is what \
         refuses rather than the signer check one line above it"
    );
    assert_eq!(
        verify_tenant_placement_record_chirho(
            forged_chirho,
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementRefusalChirho::HeldObserverReadinessSignatureChirho
    );
}
