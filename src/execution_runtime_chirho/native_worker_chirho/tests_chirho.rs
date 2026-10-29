// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-native-test-{nanos_chirho}-{n_chirho}"))
}

fn spec_from_bytes_chirho(
    root_chirho: &Path,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> (NativeProgramSpecChirho, HashChirho) {
    let executable_chirho = cas_chirho::add_chirho(root_chirho, b"not-executed").unwrap();
    let mut spec_chirho = NativeProgramSpecChirho {
        schema_chirho: NATIVE_PROGRAM_SCHEMA_CHIRHO.to_string(),
        name_chirho: "native-test-chirho".to_string(),
        executable_chirho,
        registered_by_chirho: "owner/platform-native-tier-chirho".to_string(),
        registered_pubkey_chirho: signer_chirho::pubkey_hex_chirho(root_chirho).unwrap(),
        sig_chirho: String::new(),
        argv_chirho: Vec::new(),
        abi_chirho: NATIVE_ABI_BYTES_STDIO_CHIRHO.to_string(),
        sandbox_mode_chirho: NativeSandboxModeChirho::BestEffortChirho,
        allowed_syscalls_chirho: default_native_syscalls_chirho(),
        capabilities_chirho: canonical_capabilities_chirho(&capabilities_chirho).unwrap(),
        timeout_ms_chirho: 1000,
        max_memory_bytes_chirho: 16 * 1024 * 1024,
        max_input_bytes_chirho: 1024,
        max_output_bytes_chirho: 1024,
        warm_pool_size_chirho: 1,
        scope_notes_chirho: Vec::new(),
    };
    let message_chirho = native_spec_message_chirho(&spec_chirho).unwrap();
    spec_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(root_chirho, &message_chirho).unwrap();
    let spec_hash_chirho = store_chirho::put_object_chirho(root_chirho, &spec_chirho).unwrap();
    (spec_chirho, spec_hash_chirho)
}

fn priced_app_context_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    caller_chirho: &str,
    effect_chirho: &str,
    price_chirho: i64,
) -> RequestContextChirho {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho = cas_chirho::add_chirho(root_chirho, b"native app marker").unwrap();
    let dag_hash_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(root_chirho, app_chirho, dag_hash_chirho, &owner_chirho)
        .unwrap();
    let mut effect_prices_chirho = BTreeMap::new();
    effect_prices_chirho.insert(effect_chirho.to_string(), price_chirho);
    let (book_hash_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        root_chirho,
        app_chirho,
        &owner_chirho,
        Some(1),
        effect_prices_chirho,
        0,
    )
    .unwrap();
    RequestContextChirho {
        user_principal_chirho: caller_chirho.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_chirho,
        client_id_chirho: format!("client/{app_chirho}"),
        token_hash_chirho: format!("token/{caller_chirho}"),
        price_book_chirho: Some(book_hash_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn current_effect_contract_set_chirho() -> HashChirho {
    cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho(
        &cairn_undo_plan_chirho::contract_chirho::canonical_authoring_reversion_contract_set_chirho(
        ),
    )
    .unwrap()
}

#[test]
fn native_program_verifies_materialized_executable_chirho() {
    let root_chirho = tmp_root_chirho();
    let (_spec_chirho, spec_hash_chirho) = spec_from_bytes_chirho(&root_chirho, Vec::new());
    let verification_chirho =
        verify_native_program_chirho(&root_chirho, &spec_hash_chirho).unwrap();
    assert_eq!(verification_chirho.spec_chirho, spec_hash_chirho);
    let warm_chirho = prewarm_native_program_chirho(&root_chirho, &spec_hash_chirho).unwrap();
    assert_eq!(warm_chirho.warm_slots_chirho, 1);
    assert!(Path::new(&warm_chirho.materialized_executable_chirho).exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn native_program_rejects_self_signed_foreign_admission_chirho() {
    let root_a_chirho = tmp_root_chirho();
    let root_b_chirho = tmp_root_chirho();
    let (spec_chirho, _spec_hash_chirho) = spec_from_bytes_chirho(&root_a_chirho, Vec::new());
    let foreign_hash_chirho =
        store_chirho::put_object_chirho(&root_b_chirho, &spec_chirho).unwrap();
    let error_chirho = load_native_program_chirho(&root_b_chirho, &foreign_hash_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("not admitted by this cairn instance"));
    let _ = std::fs::remove_dir_all(root_a_chirho);
    let _ = std::fs::remove_dir_all(root_b_chirho);
}

#[test]
fn native_program_rejects_nondeterministic_syscalls_chirho() {
    let root_chirho = tmp_root_chirho();
    let executable_path_chirho = root_chirho.join("native-worker-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(&executable_path_chirho, b"not-executed").unwrap();
    let error_chirho = build_native_program_chirho(
        &root_chirho,
        &executable_path_chirho,
        NativeProgramBuildRequestChirho {
            name_chirho: "native-bad-syscall-chirho".to_string(),
            argv_chirho: Vec::new(),
            sandbox_mode_chirho: NativeSandboxModeChirho::BestEffortChirho,
            allowed_syscalls_chirho: vec!["read".to_string(), "getrandom".to_string()],
            capabilities_chirho: Vec::new(),
            timeout_ms_chirho: 1000,
            max_memory_bytes_chirho: 16 * 1024 * 1024,
            max_input_bytes_chirho: 1024,
            max_output_bytes_chirho: 1024,
            warm_pool_size_chirho: 1,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("nondeterministic"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn native_effect_uses_same_signed_effect_and_run_result_shape_chirho() {
    let root_chirho = tmp_root_chirho();
    let (_spec_chirho, spec_hash_chirho) =
        spec_from_bytes_chirho(&root_chirho, vec![CapabilityChirho::ClockChirho]);
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"").unwrap();
    let (result_chirho, hit_chirho) =
        run_native_program_cached_chirho(&root_chirho, &spec_hash_chirho, &input_hash_chirho, &[])
            .unwrap();
    assert!(!hit_chirho);
    assert_eq!(result_chirho.effects_chirho.len(), 1);
    assert!(matches!(
        result_chirho.effects_chirho[0].capability_chirho,
        CapabilityChirho::ClockChirho
    ));
    let output_chirho = result_chirho.outputs_chirho.get("out").unwrap();
    assert!(
        cas_chirho::get_chirho(&root_chirho, output_chirho)
            .unwrap()
            .len()
            >= 8
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn native_reuse_policy_has_one_admission_owned_coding_chirho() {
    let source_chirho = include_str!("../native_worker_chirho.rs");
    assert_eq!(
        source_chirho
            .matches("EffectAdmissionChirho::may_reuse_generic_effect_result_chirho")
            .count(),
        1
    );
    assert!(!source_chirho.contains("bill_cached_native_paid_effect_chirho"));
}

#[test]
fn native_paid_effect_requires_identity_then_refuses_legacy_money_road_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = priced_app_context_chirho(
        &root_chirho,
        "nativepaidlegacyapp",
        "user/alice",
        "echo_paid_chirho",
        5,
    );
    let paid_capability_chirho = CapabilityChirho::PaidEffectChirho {
        effect_chirho: "echo_paid_chirho".to_string(),
        caller_chirho: "user/alice".to_string(),
    };
    let (_blocked_spec_chirho, blocked_spec_hash_chirho) =
        spec_from_bytes_chirho(&root_chirho, vec![paid_capability_chirho.clone()]);
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"native paid").unwrap();
    let error_chirho = run_native_program_cached_chirho(
        &root_chirho,
        &blocked_spec_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("requires verified RequestContextChirho"));

    let (_spec_chirho, spec_hash_chirho) = spec_from_bytes_chirho(
        &root_chirho,
        vec![
            paid_capability_chirho,
            CapabilityChirho::UserIdentityChirho {
                principal_chirho: "user/alice".to_string(),
                client_id_chirho: "native-cli".to_string(),
                token_hash_chirho: "token/native".to_string(),
            },
        ],
    );
    let refusal_chirho = run_native_program_cached_with_context_chirho(
        &root_chirho,
        &spec_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<effect_chirho::LegacyMoneyRoadRefusedChirho>(),
        Some(&effect_chirho::LegacyMoneyRoadRefusedChirho::new_chirho(
            effect_chirho::LegacyMoneyRoadChirho::PaidEffectChirho,
            "echo_paid_chirho",
        ))
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn native_context_rewrites_identity_then_uses_shared_legacy_refusal_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = priced_app_context_chirho(
        &root_chirho,
        "nativepaidapp",
        "ctx/alice",
        "echo_paid_chirho",
        17,
    );
    let (_spec_chirho, spec_hash_chirho) = spec_from_bytes_chirho(
        &root_chirho,
        vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "echo_paid_chirho".to_string(),
            caller_chirho: "ignored_until_context_chirho".to_string(),
        }],
    );
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"context paid").unwrap();

    let refusal_chirho = run_native_program_cached_with_context_chirho(
        &root_chirho,
        &spec_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<effect_chirho::LegacyMoneyRoadRefusedChirho>(),
        Some(&effect_chirho::LegacyMoneyRoadRefusedChirho::new_chirho(
            effect_chirho::LegacyMoneyRoadChirho::PaidEffectChirho,
            "echo_paid_chirho",
        ))
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn descriptor_v2_native_unknown_subtype_refuses_before_billing_or_execution_chirho() {
    let root_chirho = tmp_root_chirho();
    let effect_name_chirho = "unknown-native-paid-subtype-chirho";
    let caller_chirho = "user/native-v2-admission-chirho";
    let context_chirho = priced_app_context_chirho(
        &root_chirho,
        "nativev2admissionapp",
        caller_chirho,
        effect_name_chirho,
        7,
    );
    let (spec_chirho, spec_hash_chirho) = spec_from_bytes_chirho(
        &root_chirho,
        vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: effect_name_chirho.into(),
            caller_chirho: "declared-caller-chirho".into(),
        }],
    );
    let node_chirho = NodeDefChirho {
        name_chirho: "native-v2-admission-node-chirho".into(),
        impl_wasm_chirho: native_node_impl_hash_chirho(&spec_hash_chirho),
        entry_chirho: "native_chirho".into(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".into(),
            schema_chirho: HashChirho("bytes".into()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".into(),
            schema_chirho: HashChirho("bytes".into()),
        }],
        capabilities_chirho: spec_chirho.capabilities_chirho,
        effect_contract_set_chirho: Some(current_effect_contract_set_chirho()),
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"must not execute").unwrap();

    let error_chirho = run_verified_native_node_cached_with_context_chirho(
        &root_chirho,
        &spec_hash_chirho,
        &node_chirho,
        &node_hash_chirho,
        &input_hash_chirho,
        &[],
        crate::dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
            Some(&context_chirho),
            None,
        ),
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("not registered under blessed registry v2"));
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn native_query_effect_refuses_public_and_authenticated_roads_before_projection_chirho() {
    let root_chirho = tmp_root_chirho();
    let query_capability_chirho = CapabilityChirho::QueryChirho {
        prefix_chirho: "user".to_string(),
        caller_chirho: "user/alice".to_string(),
        max_rows_chirho: 10,
    };
    let (_blocked_spec_chirho, blocked_spec_hash_chirho) =
        spec_from_bytes_chirho(&root_chirho, vec![query_capability_chirho.clone()]);
    let request_chirho = effect_chirho::ScopedQueryRequestChirho {
        prefix_chirho: "user".to_string(),
        limit_chirho: Some(10),
    };
    let input_bytes_chirho = serde_json::to_vec(&request_chirho).unwrap();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, &input_bytes_chirho).unwrap();
    let error_chirho = run_native_program_cached_chirho(
        &root_chirho,
        &blocked_spec_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("requires matching UserIdentityChirho"));

    let (_spec_chirho, spec_hash_chirho) = spec_from_bytes_chirho(
        &root_chirho,
        vec![
            query_capability_chirho,
            CapabilityChirho::UserIdentityChirho {
                principal_chirho: "user/alice".to_string(),
                client_id_chirho: "native-cli".to_string(),
                token_hash_chirho: "token/native".to_string(),
            },
        ],
    );
    let public_error_chirho =
        run_native_program_cached_chirho(&root_chirho, &spec_hash_chirho, &input_hash_chirho, &[])
            .unwrap_err();
    assert_eq!(
        public_error_chirho.downcast_ref::<effect_chirho::LegacyMoneyRoadRefusedChirho>(),
        Some(&effect_chirho::LegacyMoneyRoadRefusedChirho::new_chirho(
            effect_chirho::LegacyMoneyRoadChirho::QueryEffectChirho,
            "query_chirho",
        ))
    );

    let context_chirho = priced_app_context_chirho(
        &root_chirho,
        "nativequeryapp",
        "ctx/query-alice",
        "query_chirho",
        2,
    );
    let (_context_spec_chirho, context_spec_hash_chirho) = spec_from_bytes_chirho(
        &root_chirho,
        vec![CapabilityChirho::QueryChirho {
            prefix_chirho: "user".to_string(),
            caller_chirho: "ignored_until_context_chirho".to_string(),
            max_rows_chirho: 10,
        }],
    );
    let authenticated_error_chirho = run_native_program_cached_with_context_chirho(
        &root_chirho,
        &context_spec_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
    )
    .unwrap_err();
    assert_eq!(
        authenticated_error_chirho.downcast_ref::<effect_chirho::LegacyMoneyRoadRefusedChirho>(),
        Some(&effect_chirho::LegacyMoneyRoadRefusedChirho::new_chirho(
            effect_chirho::LegacyMoneyRoadChirho::QueryEffectChirho,
            "query_chirho",
        ))
    );
    assert!(!root_chirho.join("readmodel-chirho.sqlite").exists());
    assert!(!root_chirho.join("effects-chirho").exists());
    assert!(!effect_chirho::volatile_effect_records_path_chirho(&root_chirho).exists());
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn required_seccomp_fails_closed_when_unavailable_chirho() {
    let root_chirho = tmp_root_chirho();
    let executable_chirho = cas_chirho::add_chirho(&root_chirho, b"not-executed").unwrap();
    let mut spec_chirho = NativeProgramSpecChirho {
        schema_chirho: NATIVE_PROGRAM_SCHEMA_CHIRHO.to_string(),
        name_chirho: "native-test-chirho".to_string(),
        executable_chirho,
        registered_by_chirho: "owner/platform-native-tier-chirho".to_string(),
        registered_pubkey_chirho: signer_chirho::pubkey_hex_chirho(&root_chirho).unwrap(),
        sig_chirho: String::new(),
        argv_chirho: Vec::new(),
        abi_chirho: NATIVE_ABI_BYTES_STDIO_CHIRHO.to_string(),
        sandbox_mode_chirho: NativeSandboxModeChirho::RequiredSeccompChirho,
        allowed_syscalls_chirho: default_native_syscalls_chirho(),
        capabilities_chirho: Vec::new(),
        timeout_ms_chirho: 1000,
        max_memory_bytes_chirho: 16 * 1024 * 1024,
        max_input_bytes_chirho: 1024,
        max_output_bytes_chirho: 1024,
        warm_pool_size_chirho: 1,
        scope_notes_chirho: Vec::new(),
    };
    let message_chirho = native_spec_message_chirho(&spec_chirho).unwrap();
    spec_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(&root_chirho, &message_chirho).unwrap();
    let status_chirho = sandbox_status_chirho(&spec_chirho);
    if !status_chirho.seccomp_enforced_chirho {
        let spec_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &spec_chirho).unwrap();
        let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"abc").unwrap();
        let error_chirho = run_native_program_cached_chirho(
            &root_chirho,
            &spec_hash_chirho,
            &input_hash_chirho,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("requires seccomp"));
    }
    let _ = std::fs::remove_dir_all(root_chirho);
}
