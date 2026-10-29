// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Tests for resource_chirho (split out to keep the module under the line cap).

use super::*;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-resource-test-{nanos_chirho}-{n_chirho}"))
}

fn deploy_owned_app_chirho(root_chirho: &Path, app_chirho: &str) -> String {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho = crate::cas_chirho::add_chirho(root_chirho, b"node marker").unwrap();
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(root_chirho, app_chirho, dag_chirho, &owner_chirho).unwrap();
    owner_chirho
}

fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn demo_policy_chirho() -> (Vec<ResourceMeterChirho>, Vec<ResourceActionPolicyChirho>) {
    (
        vec![
            ResourceMeterChirho {
                resource_chirho: "labs_credit_chirho".to_string(),
                unit_chirho: "credit".to_string(),
                stack_chirho: Some("google-labs".to_string()),
                per_user_limit_chirho: Some(3),
                app_limit_chirho: Some(5),
                window_ms_chirho: None,
                overage_chirho: ResourceOverageChirho::RouteChirho {
                    route_chirho: "labs-lite".to_string(),
                    forward_request_body_chirho: false,
                },
            },
            ResourceMeterChirho {
                resource_chirho: "storage_gb_chirho".to_string(),
                unit_chirho: "gb".to_string(),
                stack_chirho: Some("storage".to_string()),
                per_user_limit_chirho: None,
                app_limit_chirho: Some(10),
                window_ms_chirho: None,
                overage_chirho: ResourceOverageChirho::FailClosedChirho,
            },
        ],
        vec![ResourceActionPolicyChirho {
            section_chirho: "labs".to_string(),
            action_chirho: "generate".to_string(),
            effect_chirho: Some("llm_chirho".to_string()),
            allow_anonymous_chirho: false,
            charges_chirho: vec![
                ResourceChargeChirho {
                    resource_chirho: "labs_credit_chirho".to_string(),
                    amount_chirho: 2,
                },
                ResourceChargeChirho {
                    resource_chirho: "storage_gb_chirho".to_string(),
                    amount_chirho: 1,
                },
            ],
        }],
    )
}

fn resource_schema_fixture_chirho() -> (
    PathBuf,
    ResourcePolicyRecordChirho,
    ResourceUsageRecordChirho,
    ResourceUsageRecordChirho,
) {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "schemaresource");
    let (meters_chirho, actions_chirho) = demo_policy_chirho();
    let (_policy_hash_chirho, _policy_chirho, policy_record_chirho) = set_resource_policy_chirho(
        &root_chirho,
        "schemaresource",
        &owner_chirho,
        meters_chirho,
        actions_chirho,
    )
    .unwrap();
    let run_chirho = HashChirho("run-schema".to_string());
    let bridged_usage_chirho = record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "schemaresource".to_string(),
            user_chirho: "user/alice".to_string(),
            actor_chirho: None,
            section_chirho: "labs".to_string(),
            action_chirho: "generate".to_string(),
            effect_chirho: Some("llm_chirho".to_string()),
            run_chirho: Some(run_chirho),
            // The BILLING-BRIDGED variant retired with the billing writer at CF6 wave-1. A
            // dangling bridge is not a substitute: the runtime correctly REFUSES a bridge to a
            // row that does not exist, which is how this was found. Re-pin the bridged shape
            // when V2 billing lands (v2-rebuild-ledger).
            bridges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let plain_usage_chirho = record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "schemaresource".to_string(),
            user_chirho: "user/bob".to_string(),
            actor_chirho: None,
            section_chirho: "labs".to_string(),
            action_chirho: "generate".to_string(),
            effect_chirho: Some("llm_chirho".to_string()),
            run_chirho: None,
            bridges_chirho: Vec::new(),
        },
    )
    .unwrap();
    (
        root_chirho,
        policy_record_chirho,
        bridged_usage_chirho,
        plain_usage_chirho,
    )
}

#[test]
fn resource_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
    let (root_chirho, policy_chirho, bridged_usage_chirho, plain_usage_chirho) =
        resource_schema_fixture_chirho();

    assert_eq!(
        policy_chirho.schema_chirho,
        RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO
    );
    assert_eq!(
        bridged_usage_chirho.schema_chirho,
        RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(
        plain_usage_chirho.schema_chirho,
        RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(verify_resource_policies_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_resource_usage_chirho(&root_chirho).unwrap(), 2);
    let mut bad_charge_usage_chirho = bridged_usage_chirho.clone();
    bad_charge_usage_chirho.charges_chirho[0].amount_chirho += 1;
    bad_charge_usage_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &resource_usage_record_message_chirho(&bad_charge_usage_chirho).unwrap(),
    )
    .unwrap();
    write_jsonl_chirho(
        &usage_records_path_chirho(&root_chirho),
        &[bad_charge_usage_chirho, plain_usage_chirho.clone()],
    );
    let error_chirho = verify_resource_usage_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert_eq!(
        error_chirho,
        "resource usage record 0 charge vector does not match policy action"
    );
    write_jsonl_chirho(
        &usage_records_path_chirho(&root_chirho),
        &[bridged_usage_chirho.clone(), plain_usage_chirho.clone()],
    );
    let mut bad_policy_chirho = policy_chirho.clone();
    bad_policy_chirho.schema_chirho = "resource-policy-record-v9-chirho".to_string();
    write_jsonl_chirho(
        &policy_records_path_chirho(&root_chirho),
        &[bad_policy_chirho],
    );
    let error_chirho = load_resource_policy_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported schema"));
    assert!(verify_resource_policies_chirho(&root_chirho).is_err());
    write_jsonl_chirho(
        &policy_records_path_chirho(&root_chirho),
        std::slice::from_ref(&policy_chirho),
    );

    let mut bad_usage_chirho = bridged_usage_chirho.clone();
    bad_usage_chirho.schema_chirho = "resource-usage-record-v9-chirho".to_string();
    write_jsonl_chirho(
        &usage_records_path_chirho(&root_chirho),
        &[bad_usage_chirho, plain_usage_chirho.clone()],
    );
    let error_chirho = load_resource_usage_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported schema"));
    assert!(verify_resource_usage_chirho(&root_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resource_policy_unset_removes_ref_and_records_signed_tombstone_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "unsetresource");
    let other_owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let (meters_chirho, actions_chirho) = demo_policy_chirho();
    let (policy_hash_chirho, _policy_chirho, _policy_record_chirho) = set_resource_policy_chirho(
        &root_chirho,
        "unsetresource",
        &owner_chirho,
        meters_chirho,
        actions_chirho,
    )
    .unwrap();

    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "unsetresource")
            .unwrap()
            .is_some()
    );
    assert!(
        unset_resource_policy_chirho(&root_chirho, "unsetresource", &other_owner_chirho).is_err()
    );
    assert!(load_resource_policy_unset_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());

    let unset_record_chirho =
        unset_resource_policy_chirho(&root_chirho, "unsetresource", &owner_chirho)
            .unwrap()
            .expect("first unset should record a tombstone");
    assert_eq!(unset_record_chirho.previous_chirho, policy_hash_chirho);
    assert!(unset_record_chirho.sig_chirho.len() > 32);
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "unsetresource")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        load_resource_policy_unset_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(verify_resource_policies_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(
        verify_resource_policy_unsets_chirho(&root_chirho).unwrap(),
        1
    );
    assert!(
        crate::head_removal_chirho::load_head_removal_records_chirho(&root_chirho)
            .unwrap()
            .is_empty(),
        "v2 unsets must not mint legacy v1 removal rows"
    );
    let removal_values_chirho =
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap();
    assert_eq!(
        removal_values_chirho
            .iter()
            .map(|value_chirho| value_chirho["schema_chirho"].as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        vec![
            crate::head_removal_transition_chirho::HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO,
            crate::head_removal_transition_chirho::HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO,
        ],
        "an unset must settle as one Prepared row plus one Applied receipt"
    );
    assert_eq!(
        crate::head_removal_chirho::verify_head_removal_records_chirho(&root_chirho).unwrap(),
        1
    );
    assert_eq!(verify_resource_usage_chirho(&root_chirho).unwrap(), 0);
    assert!(
        unset_resource_policy_chirho(&root_chirho, "unsetresource", &owner_chirho)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        load_resource_policy_unset_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );

    let mut tampered_chirho = unset_record_chirho;
    tampered_chirho.previous_chirho = HashChirho("not-a-real-policy-hash".to_string());
    write_jsonl_chirho(
        &policy_unset_records_path_chirho(&root_chirho),
        &[tampered_chirho],
    );
    let tamper_error_chirho = verify_resource_policy_unsets_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        tamper_error_chirho.contains("unknown previous policy")
            || tamper_error_chirho.contains("signature invalid")
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resource_policy_unset_recovers_pending_head_removal_evidence_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "pendingresource");
    let (meters_chirho, actions_chirho) = demo_policy_chirho();
    set_resource_policy_chirho(
        &root_chirho,
        "pendingresource",
        &owner_chirho,
        meters_chirho,
        actions_chirho,
    )
    .unwrap();
    crate::head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        crate::head_removal_chirho::HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );

    assert!(
        unset_resource_policy_chirho(&root_chirho, "pendingresource", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "pendingresource")
            .unwrap_err()
            .to_string()
            .contains("does not match the verified latest set event"),
        "once the unset domain event is recorded it is the latest event, so the read fails closed \
         even though the branch removal has not yet settled"
    );
    assert_eq!(
        crate::head_removal_chirho::verify_head_removal_records_chirho(&root_chirho).unwrap(),
        1
    );

    let recovered_chirho =
        unset_resource_policy_chirho(&root_chirho, "pendingresource", &owner_chirho)
            .unwrap()
            .expect("pending evidence retry should finish removal and return the tombstone");
    assert_eq!(recovered_chirho.seq_chirho, 0);
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "pendingresource")
            .unwrap()
            .is_none()
    );
    assert!(
        crate::head_removal_chirho::load_head_removal_records_chirho(&root_chirho)
            .unwrap()
            .is_empty(),
        "recovery must settle the pending v2 removal without minting legacy rows"
    );
    assert_eq!(
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap()
        .len(),
        2,
        "the crashed unset retry must complete to exactly one Prepared plus one Applied"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_resource_records_without_schema_still_verify_chirho() {
    let (root_chirho, mut policy_chirho, mut bridged_usage_chirho, mut plain_usage_chirho) =
        resource_schema_fixture_chirho();

    policy_chirho.schema_chirho.clear();
    policy_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &resource_policy_record_message_chirho(&policy_chirho).unwrap(),
    )
    .unwrap();
    bridged_usage_chirho.schema_chirho.clear();
    bridged_usage_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &resource_usage_record_message_chirho(&bridged_usage_chirho).unwrap(),
    )
    .unwrap();
    plain_usage_chirho.schema_chirho.clear();
    plain_usage_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &resource_usage_record_message_chirho(&plain_usage_chirho).unwrap(),
    )
    .unwrap();

    write_jsonl_chirho(
        &policy_records_path_chirho(&root_chirho),
        std::slice::from_ref(&policy_chirho),
    );
    write_jsonl_chirho(
        &usage_records_path_chirho(&root_chirho),
        &[bridged_usage_chirho, plain_usage_chirho],
    );

    for path_chirho in [
        policy_records_path_chirho(&root_chirho),
        usage_records_path_chirho(&root_chirho),
    ] {
        let text_chirho = std::fs::read_to_string(path_chirho).unwrap();
        assert!(!text_chirho.contains("schema_chirho"));
    }
    assert_eq!(verify_resource_policies_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_resource_usage_chirho(&root_chirho).unwrap(), 2);
    assert!(load_resource_policy_records_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
    assert!(load_resource_usage_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_external_usage_resource_bridge_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let mut evidence_chirho = ResourceBridgeEvidenceChirho::default();
    let error_chirho = validate_resource_bridges_chirho(
        &root_chirho,
        "resourceapp",
        "user/alice",
        Some("llm_chirho"),
        None,
        &[ResourceBridgeRefChirho {
            kind_chirho: ResourceBridgeKindChirho::ExternalUsageChirho,
            seq_chirho: 0,
        }],
        &mut evidence_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("legacy external-usage resource bridges are unavailable"));
    assert!(!root_chirho.join("external-usage-chirho.jsonl").exists());
}

#[test]
fn app_resource_policy_records_usage_vectors_and_rollups_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceapp");
    let (meters_chirho, actions_chirho) = demo_policy_chirho();
    let (policy_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "resourceapp",
        &owner_chirho,
        meters_chirho,
        actions_chirho,
    )
    .unwrap();
    let run_chirho = HashChirho("run1".to_string());
    let first_chirho = record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "resourceapp".to_string(),
            user_chirho: "user/alice".to_string(),
            actor_chirho: None,
            section_chirho: "labs".to_string(),
            action_chirho: "generate".to_string(),
            effect_chirho: Some("llm_chirho".to_string()),
            run_chirho: Some(run_chirho),
            bridges_chirho: vec![ResourceBridgeRefChirho {
                kind_chirho: ResourceBridgeKindChirho::ProviderInvoiceChirho,
                seq_chirho: 0,
            }],
        },
    )
    .unwrap();
    assert_eq!(first_chirho.resource_policy_chirho, policy_hash_chirho);
    // One, not two: the BILLING bridge retired with the billing writer at wave-1.
    assert_eq!(first_chirho.bridges_chirho.len(), 1);
    assert_eq!(
        first_chirho.decision_chirho,
        ResourceDecisionChirho::AllowedChirho
    );
    assert!(record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "resourceapp".to_string(),
            user_chirho: "user/alice".to_string(),
            actor_chirho: None,
            section_chirho: "labs".to_string(),
            action_chirho: "generate".to_string(),
            effect_chirho: Some("llm_chirho".to_string()),
            run_chirho: None,
            bridges_chirho: vec![
                ResourceBridgeRefChirho {
                    kind_chirho: ResourceBridgeKindChirho::BillingUsageChirho,
                    // The billing WRITER died with the spine at CF6 wave-1. This bridge only ever
                    // carried a seq POINTER, and the schema under test is the resource
                    // usage record's -- so a literal pins the same shape without
                    // re-implementing a deleted writer to produce the row it points at.
                    seq_chirho: 0,
                },
                ResourceBridgeRefChirho {
                    kind_chirho: ResourceBridgeKindChirho::BillingUsageChirho,
                    // The billing WRITER died with the spine at CF6 wave-1. This bridge only ever
                    // carried a seq POINTER, and the schema under test is the resource
                    // usage record's -- so a literal pins the same shape without
                    // re-implementing a deleted writer to produce the row it points at.
                    seq_chirho: 0,
                },
            ],
        },
    )
    .is_err());
    assert!(record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "resourceapp".to_string(),
            user_chirho: "user/bob".to_string(),
            actor_chirho: None,
            section_chirho: "labs".to_string(),
            action_chirho: "generate".to_string(),
            effect_chirho: Some("llm_chirho".to_string()),
            run_chirho: None,
            bridges_chirho: vec![ResourceBridgeRefChirho {
                kind_chirho: ResourceBridgeKindChirho::BillingUsageChirho,
                // The billing WRITER died with the spine at CF6 wave-1. This bridge only ever
                // carried a seq POINTER, and the schema under test is the resource
                // usage record's -- so a literal pins the same shape without
                // re-implementing a deleted writer to produce the row it points at.
                seq_chirho: 0,
            }],
        },
    )
    .is_err());
    assert_eq!(load_resource_usage_chirho(&root_chirho).unwrap().len(), 1);

    let routed_chirho = record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "resourceapp".to_string(),
            user_chirho: "user/alice".to_string(),
            actor_chirho: Some("agent/support".to_string()),
            section_chirho: "labs".to_string(),
            action_chirho: "generate".to_string(),
            effect_chirho: Some("llm_chirho".to_string()),
            run_chirho: None,
            bridges_chirho: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(
        routed_chirho.decision_chirho,
        ResourceDecisionChirho::RoutedChirho {
            resource_chirho: "labs_credit_chirho".to_string(),
            route_chirho: "labs-lite".to_string(),
            forward_request_body_chirho: false,
            limit_chirho: 3,
            used_chirho: 2,
            attempted_chirho: 4,
        }
    );

    record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "resourceapp".to_string(),
            user_chirho: "user/bob".to_string(),
            actor_chirho: None,
            section_chirho: "labs".to_string(),
            action_chirho: "generate".to_string(),
            effect_chirho: Some("llm_chirho".to_string()),
            run_chirho: None,
            bridges_chirho: Vec::new(),
        },
    )
    .unwrap();

    assert_eq!(verify_resource_policies_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_resource_usage_chirho(&root_chirho).unwrap(), 3);

    let resource_rows_chirho = resource_rollup_chirho(
        &root_chirho,
        Some("resourceapp"),
        ResourceRollupAxisChirho::ResourceChirho,
    )
    .unwrap();
    assert!(resource_rows_chirho.iter().any(|row_chirho| {
        row_chirho.resource_chirho == "labs_credit_chirho"
            && row_chirho.amount_chirho == 4
            && row_chirho.usage_count_chirho == 2
    }));
    assert!(resource_rows_chirho.iter().any(|row_chirho| {
        row_chirho.resource_chirho == "storage_gb_chirho"
            && row_chirho.amount_chirho == 2
            && row_chirho.unit_chirho == "gb"
    }));

    let user_rollup_chirho = resource_rollup_chirho(
        &root_chirho,
        Some("resourceapp"),
        ResourceRollupAxisChirho::UserChirho,
    )
    .unwrap();
    assert!(user_rollup_chirho.iter().any(|row_chirho| {
        row_chirho.key_chirho == "user/alice"
            && row_chirho.resource_chirho == "labs_credit_chirho"
            && row_chirho.amount_chirho == 2
    }));
    assert!(!user_rollup_chirho.iter().any(|row_chirho| {
        row_chirho.key_chirho == "user/alice"
            && row_chirho.resource_chirho == "labs_credit_chirho"
            && row_chirho.amount_chirho == 4
    }));

    let status_chirho = resource_status_chirho(&root_chirho, Some("resourceapp"), None).unwrap();
    let app_labs_chirho = status_chirho
        .iter()
        .find(|row_chirho| {
            row_chirho.scope_chirho == ResourceBalanceScopeChirho::AppChirho
                && row_chirho.resource_chirho == "labs_credit_chirho"
        })
        .unwrap();
    assert_eq!(app_labs_chirho.limit_chirho, 5);
    assert_eq!(app_labs_chirho.used_chirho, 4);
    assert_eq!(app_labs_chirho.remaining_chirho, 1);
    assert_eq!(app_labs_chirho.routed_attempts_chirho, 1);
    assert_eq!(app_labs_chirho.routed_amount_chirho, 2);
    assert_eq!(app_labs_chirho.route_chirho.as_deref(), Some("labs-lite"));

    let app_storage_chirho = status_chirho
        .iter()
        .find(|row_chirho| {
            row_chirho.scope_chirho == ResourceBalanceScopeChirho::AppChirho
                && row_chirho.resource_chirho == "storage_gb_chirho"
        })
        .unwrap();
    assert_eq!(app_storage_chirho.used_chirho, 2);
    assert_eq!(app_storage_chirho.remaining_chirho, 8);
    assert_eq!(app_storage_chirho.routed_attempts_chirho, 0);

    let alice_labs_chirho = status_chirho
        .iter()
        .find(|row_chirho| {
            row_chirho.scope_chirho == ResourceBalanceScopeChirho::UserChirho
                && row_chirho.subject_chirho == "user/alice"
                && row_chirho.resource_chirho == "labs_credit_chirho"
        })
        .unwrap();
    assert_eq!(alice_labs_chirho.limit_chirho, 3);
    assert_eq!(alice_labs_chirho.used_chirho, 2);
    assert_eq!(alice_labs_chirho.remaining_chirho, 1);
    assert_eq!(alice_labs_chirho.routed_attempts_chirho, 1);

    let charlie_status_chirho =
        resource_status_chirho(&root_chirho, Some("resourceapp"), Some("user/charlie")).unwrap();
    assert!(charlie_status_chirho.iter().any(|row_chirho| {
        row_chirho.scope_chirho == ResourceBalanceScopeChirho::UserChirho
            && row_chirho.subject_chirho == "user/charlie"
            && row_chirho.resource_chirho == "labs_credit_chirho"
            && row_chirho.used_chirho == 0
            && row_chirho.remaining_chirho == 3
    }));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn windowed_resource_limit_recovers_after_window_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "windowresource");
    let window_ms_chirho = 2_000_u64;
    set_resource_policy_chirho(
        &root_chirho,
        "windowresource",
        &owner_chirho,
        vec![ResourceMeterChirho {
            resource_chirho: "public_write_chirho".to_string(),
            unit_chirho: "write".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: None,
            app_limit_chirho: Some(1),
            window_ms_chirho: Some(window_ms_chirho),
            overage_chirho: ResourceOverageChirho::FailClosedChirho,
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: "request_chirho".to_string(),
            action_chirho: "default_chirho".to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "public_write_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();

    let usage_input_chirho = || ResourceUsageInputChirho {
        app_chirho: "windowresource".to_string(),
        user_chirho: "anon/app/windowresource".to_string(),
        actor_chirho: None,
        section_chirho: "request_chirho".to_string(),
        action_chirho: "default_chirho".to_string(),
        effect_chirho: None,
        run_chirho: None,
        bridges_chirho: Vec::new(),
    };
    let first_chirho = record_resource_usage_chirho(&root_chirho, usage_input_chirho())
        .expect("first use should be allowed");
    assert_eq!(
        first_chirho.decision_chirho,
        ResourceDecisionChirho::AllowedChirho
    );
    assert!(record_resource_usage_chirho(&root_chirho, usage_input_chirho()).is_err());
    assert_eq!(load_resource_usage_chirho(&root_chirho).unwrap().len(), 1);

    let exhausted_status_chirho =
        resource_status_chirho(&root_chirho, Some("windowresource"), None).unwrap();
    let exhausted_app_chirho = exhausted_status_chirho
        .iter()
        .find(|row_chirho| {
            row_chirho.scope_chirho == ResourceBalanceScopeChirho::AppChirho
                && row_chirho.resource_chirho == "public_write_chirho"
        })
        .unwrap();
    assert_eq!(
        exhausted_app_chirho.window_ms_chirho,
        Some(window_ms_chirho)
    );
    assert_eq!(exhausted_app_chirho.used_chirho, 1);
    assert_eq!(exhausted_app_chirho.remaining_chirho, 0);

    std::thread::sleep(std::time::Duration::from_millis(
        window_ms_chirho.saturating_add(50),
    ));
    let recovered_status_chirho =
        resource_status_chirho(&root_chirho, Some("windowresource"), None).unwrap();
    let recovered_app_chirho = recovered_status_chirho
        .iter()
        .find(|row_chirho| {
            row_chirho.scope_chirho == ResourceBalanceScopeChirho::AppChirho
                && row_chirho.resource_chirho == "public_write_chirho"
        })
        .unwrap();
    assert_eq!(recovered_app_chirho.used_chirho, 0);
    assert_eq!(recovered_app_chirho.remaining_chirho, 1);

    std::fs::OpenOptions::new()
        .append(true)
        .open(usage_records_path_chirho(&root_chirho))
        .unwrap()
        .write_all(br#"{"seq_chirho":999,"app_chirho":"#)
        .unwrap();
    let second_chirho = record_resource_usage_chirho(&root_chirho, usage_input_chirho())
        .expect("use should recover after the window");
    assert_eq!(second_chirho.seq_chirho, 1);
    assert_eq!(
        second_chirho.decision_chirho,
        ResourceDecisionChirho::AllowedChirho
    );
    assert!(second_chirho.at_ms_chirho >= first_chirho.at_ms_chirho);
    assert_eq!(verify_resource_usage_chirho(&root_chirho).unwrap(), 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resource_policy_rejects_zero_window_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "zerowindow");
    let error_chirho = set_resource_policy_chirho(
        &root_chirho,
        "zerowindow",
        &owner_chirho,
        vec![ResourceMeterChirho {
            resource_chirho: "public_write_chirho".to_string(),
            unit_chirho: "write".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: None,
            app_limit_chirho: Some(1),
            window_ms_chirho: Some(0),
            overage_chirho: ResourceOverageChirho::FailClosedChirho,
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: "request_chirho".to_string(),
            action_chirho: "default_chirho".to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "public_write_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("window_ms_chirho must be positive"));
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "zerowindow")
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn fail_closed_resource_overage_refuses_without_usage_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "failresource");
    set_resource_policy_chirho(
        &root_chirho,
        "failresource",
        &owner_chirho,
        vec![ResourceMeterChirho {
            resource_chirho: "expensive_gb_chirho".to_string(),
            unit_chirho: "gb".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: None,
            app_limit_chirho: Some(1),
            window_ms_chirho: None,
            overage_chirho: ResourceOverageChirho::FailClosedChirho,
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: "storage".to_string(),
            action_chirho: "upload".to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "expensive_gb_chirho".to_string(),
                amount_chirho: 2,
            }],
        }],
    )
    .unwrap();

    assert!(record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "failresource".to_string(),
            user_chirho: "user/alice".to_string(),
            actor_chirho: None,
            section_chirho: "storage".to_string(),
            action_chirho: "upload".to_string(),
            effect_chirho: None,
            run_chirho: None,
            bridges_chirho: Vec::new(),
        },
    )
    .is_err());
    assert!(load_resource_usage_chirho(&root_chirho).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}
