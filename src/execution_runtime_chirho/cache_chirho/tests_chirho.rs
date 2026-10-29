// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::model_chirho::{DagChirho, PortChirho};
use crate::provider_test_support_chirho::{
    current_effect_contract_set_chirho, llm_request_bytes_chirho,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const DOUBLE_WAT_CHIRHO: &str = r#"
    (module
      (func (export "double_chirho") (param i64) (result i64)
        local.get 0
        i64.const 2
        i64.mul))
"#;
const UPCASE_WAT_CHIRHO: &str = include_str!("../../../examples-chirho/upcase-chirho.wat");

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-cache-test-{nanos_chirho}-{n_chirho}"))
}

fn write_cache_json_chirho<T: serde::Serialize>(
    root_chirho: &Path,
    dir_chirho: &str,
    run_chirho: &HashChirho,
    value_chirho: &T,
) {
    let path_chirho = root_chirho.join(dir_chirho).join(&run_chirho.0);
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho).unwrap();
    }
    std::fs::write(
        path_chirho,
        serde_json::to_vec_pretty(value_chirho).unwrap(),
    )
    .unwrap();
}

#[test]
fn production_run_result_reads_stay_sealed_or_display_only_chirho() {
    // Workspace-aware: RunResultChirho bodies are read through this module's loader wherever
    // production modules live (root src/ or workspace crates).
    let raw_reads_chirho =
        crate::source_scan_chirho::production_source_lines_matching_chirho("load_result_chirho(");
    assert_eq!(
        raw_reads_chirho.len(),
        8,
        "raw RunResultChirho reads must stay sealed or display-only: {raw_reads_chirho:?}"
    );
    for (file_chirho, _line_chirho, text_chirho) in raw_reads_chirho {
        let allowed_chirho = match file_chirho.as_str() {
            "src/execution_runtime_chirho/cache_chirho.rs" => {
                text_chirho == "pub fn load_result_chirho("
                    || text_chirho
                        == "let Some(result_chirho) = load_result_chirho(root_chirho, run_hash_chirho)? else {"
            }
            "src/governance_flows_chirho/verify_chirho.rs" => {
                text_chirho
                    == "cache_chirho::load_result_chirho(root_chirho, &expected_run_chirho)?"
            }
            "src/governance_flows_chirho/audit_chirho.rs" => {
                text_chirho
                    == "if cache_chirho::load_result_chirho(root_chirho, run_hash_chirho)?.is_none() {"
                    || text_chirho
                        == "match cache_chirho::load_result_chirho(root_chirho, run_hash_chirho)? {"
            }
            "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/audit_cli_chirho.rs" => {
                text_chirho
                    == "match cache_chirho::load_result_chirho(root_chirho, &HashChirho(id_chirho.clone()))? {"
                    || text_chirho
                        == "match cache_chirho::load_result_chirho(root_chirho, &hash_chirho)? {"
            }
            _ => false,
        };
        assert!(
            allowed_chirho,
            "raw RunResultChirho read is not sealed/display-only: {file_chirho}: {text_chirho}"
        );
    }
}

fn scalar_node_chirho() -> (NodeDefChirho, HashChirho) {
    let node_chirho = NodeDefChirho {
        name_chirho: "double_chirho".to_string(),
        impl_wasm_chirho: HashChirho("wasm-placeholder".to_string()),
        entry_chirho: "double_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "x".to_string(),
            schema_chirho: HashChirho("i64".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("i64".to_string()),
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    (node_chirho, node_hash_chirho)
}

#[test]
fn miss_then_hit_then_distinct_input_chirho() {
    let root_chirho = tmp_root_chirho();
    let (node_chirho, node_hash_chirho) = scalar_node_chirho();
    let wasm_chirho = DOUBLE_WAT_CHIRHO.as_bytes();

    let (r1_chirho, hit1_chirho) = run_node_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        wasm_chirho,
        21,
    )
    .unwrap();
    assert!(!hit1_chirho);
    assert_eq!(r1_chirho.status_chirho, RunStatusChirho::OkChirho);
    assert!(r1_chirho.fuel_used_chirho > 0);
    let out_val_chirho: i64 =
        store_chirho::get_object_chirho(&root_chirho, r1_chirho.outputs_chirho.get("out").unwrap())
            .unwrap();
    assert_eq!(out_val_chirho, 42);

    let (r2_chirho, hit2_chirho) = run_node_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        wasm_chirho,
        21,
    )
    .unwrap();
    assert!(hit2_chirho);
    assert_eq!(r2_chirho.run_chirho, r1_chirho.run_chirho);

    let (r3_chirho, hit3_chirho) = run_node_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        wasm_chirho,
        5,
    )
    .unwrap();
    assert!(!hit3_chirho);
    assert_ne!(r3_chirho.run_chirho, r1_chirho.run_chirho);
    let out3_chirho: i64 =
        store_chirho::get_object_chirho(&root_chirho, r3_chirho.outputs_chirho.get("out").unwrap())
            .unwrap();
    assert_eq!(out3_chirho, 10);

    assert_eq!(
        run_key_hash_chirho(&node_chirho, &node_hash_chirho, 21).unwrap(),
        r1_chirho.run_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn bytes_cache_miss_then_hit_chirho() {
    let root_chirho = tmp_root_chirho();
    let node_chirho = NodeDefChirho {
        name_chirho: "upcase_chirho".to_string(),
        impl_wasm_chirho: HashChirho("wasm-placeholder".to_string()),
        entry_chirho: "upcase_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"hello").unwrap();

    let (r1_chirho, hit1_chirho) = run_node_bytes_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        UPCASE_WAT_CHIRHO.as_bytes(),
        &input_hash_chirho,
        &[],
    )
    .unwrap();
    assert!(!hit1_chirho);
    let out_bytes_chirho =
        cas_chirho::get_chirho(&root_chirho, r1_chirho.outputs_chirho.get("out").unwrap()).unwrap();
    assert_eq!(String::from_utf8(out_bytes_chirho).unwrap(), "HELLO");

    let (r2_chirho, hit2_chirho) = run_node_bytes_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        UPCASE_WAT_CHIRHO.as_bytes(),
        &input_hash_chirho,
        &[],
    )
    .unwrap();
    assert!(hit2_chirho);
    assert_eq!(r2_chirho.run_chirho, r1_chirho.run_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn bytes_cache_hit_requires_signed_run_result_seal_chirho() {
    let root_chirho = tmp_root_chirho();
    let node_chirho = NodeDefChirho {
        name_chirho: "upcase_chirho".to_string(),
        impl_wasm_chirho: HashChirho("wasm-placeholder".to_string()),
        entry_chirho: "upcase_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"hello").unwrap();

    let (result_chirho, hit_chirho) = run_node_bytes_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        UPCASE_WAT_CHIRHO.as_bytes(),
        &input_hash_chirho,
        &[],
    )
    .unwrap();
    assert!(!hit_chirho);

    let forged_output_chirho = cas_chirho::add_chirho(&root_chirho, b"FORGED").unwrap();
    let mut forged_result_chirho = result_chirho.clone();
    forged_result_chirho
        .outputs_chirho
        .insert("out".to_string(), forged_output_chirho);
    write_cache_json_chirho(
        &root_chirho,
        "runs-chirho",
        &result_chirho.run_chirho,
        &forged_result_chirho,
    );
    let error_chirho = run_node_bytes_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        UPCASE_WAT_CHIRHO.as_bytes(),
        &input_hash_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("run result seal hash mismatch"));

    write_cache_json_chirho(
        &root_chirho,
        "runs-chirho",
        &result_chirho.run_chirho,
        &result_chirho,
    );
    std::fs::remove_file(run_result_seal_path_chirho(
        &root_chirho,
        &result_chirho.run_chirho,
    ))
    .unwrap();
    let (resealed_chirho, resealed_hit_chirho) = run_node_bytes_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        UPCASE_WAT_CHIRHO.as_bytes(),
        &input_hash_chirho,
        &[],
    )
    .unwrap();
    assert!(!resealed_hit_chirho);
    assert_eq!(resealed_chirho.run_chirho, result_chirho.run_chirho);
    assert!(run_result_seal_path_chirho(&root_chirho, &result_chirho.run_chirho).exists());
    assert_eq!(
        cas_chirho::get_chirho(
            &root_chirho,
            resealed_chirho.outputs_chirho.get("out").unwrap()
        )
        .unwrap(),
        b"HELLO"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn paid_effect_node_chirho(capabilities_chirho: Vec<CapabilityChirho>) -> NodeDefChirho {
    NodeDefChirho {
        name_chirho: "paid_echo_chirho".to_string(),
        impl_wasm_chirho: HashChirho("builtin:paid_effect".to_string()),
        entry_chirho: "paid_effect_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        capabilities_chirho,
        fuel_limit_chirho: 0,
        ..Default::default()
    }
}

fn postgres_effect_node_chirho() -> NodeDefChirho {
    let mut node_chirho = paid_effect_node_chirho(vec![CapabilityChirho::PaidEffectChirho {
        effect_chirho:
            cairn_undo_plan_chirho::contract_chirho::POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO
                .to_owned(),
        caller_chirho: "descriptor-d-test-caller-chirho".to_owned(),
    }]);
    node_chirho.effect_contract_set_chirho = Some(current_effect_contract_set_chirho());
    node_chirho
}

#[derive(Default)]
struct CountingPostgresRuntimeChirho {
    calls_chirho: usize,
}

impl effect_chirho::postgres_reversible_chirho::PostgresReversibleRuntimePortChirho
    for CountingPostgresRuntimeChirho
{
    fn execute_chirho(
        &mut self,
        _execution_chirho: effect_chirho::postgres_reversible_chirho::PostgresReversibleExecutionChirho<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        self.calls_chirho += 1;
        Ok(b"descriptor-d-runtime-result-chirho".to_vec())
    }
}

#[test]
fn descriptor_v2_unknown_paid_subtype_refuses_before_cache_or_pricing_chirho() {
    let root_chirho = tmp_root_chirho();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"paid input").unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user/v2-admission-chirho".into(),
        app_chirho: "v2-admission-app-chirho".into(),
        owner_principal_chirho: "owner/v2-admission-chirho".into(),
        client_id_chirho: "client/v2-admission-chirho".into(),
        token_hash_chirho: "token/v2-admission-chirho".into(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let mut unknown_node_chirho =
        paid_effect_node_chirho(vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "unknown-v2-paid-subtype-chirho".into(),
            caller_chirho: "declared-caller-chirho".into(),
        }]);
    unknown_node_chirho.effect_contract_set_chirho = Some(current_effect_contract_set_chirho());
    let unknown_node_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &unknown_node_chirho).unwrap();

    let effective_node_chirho =
        contextual_node_def_chirho(&unknown_node_chirho, Some(&context_chirho));
    let cached_key_chirho = build_bytes_run_key_chirho(
        &effective_node_chirho,
        &unknown_node_hash_chirho,
        &input_hash_chirho,
    )
    .unwrap();
    let cached_run_chirho = store_chirho::hash_object_chirho(&cached_key_chirho).unwrap();
    store_run_key_chirho(&root_chirho, &cached_run_chirho, &cached_key_chirho).unwrap();
    let output_chirho = cas_chirho::add_chirho(&root_chirho, b"forged cached output").unwrap();
    let trace_chirho = cas_chirho::add_chirho(&root_chirho, b"cached trace").unwrap();
    store_result_chirho(
        &root_chirho,
        &RunResultChirho {
            run_chirho: cached_run_chirho.clone(),
            outputs_chirho: BTreeMap::from([("out".into(), output_chirho)]),
            effects_chirho: Vec::new(),
            fuel_used_chirho: 0,
            trace_chirho,
            status_chirho: RunStatusChirho::OkChirho,
            parents_chirho: Vec::new(),
        },
    )
    .unwrap();
    assert!(load_sealed_result_chirho(&root_chirho, &cached_run_chirho)
        .unwrap()
        .is_some());

    let unknown_error_chirho = run_effect_node_cached_with_context_chirho(
        &root_chirho,
        &unknown_node_chirho,
        &unknown_node_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    assert!(unknown_error_chirho.contains("not registered under blessed registry v2"));
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );

    let mut registered_node_chirho =
        paid_effect_node_chirho(vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".into(),
            caller_chirho: "declared-caller-chirho".into(),
        }]);
    registered_node_chirho.effect_contract_set_chirho = Some(current_effect_contract_set_chirho());
    let registered_node_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &registered_node_chirho).unwrap();
    let compatibility_error_chirho = run_effect_node_cached_with_context_chirho(
        &root_chirho,
        &registered_node_chirho,
        &registered_node_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    // llm_chirho passes v2 admission (it IS a blessed-v2 paid subtype), but with no served-LLM
    // composition injected on this cache path it refuses at the uninstalled composition -- the served
    // road's pre-effect refusal, not the legacy money road. Contrast with part 1, where an UNKNOWN
    // subtype fails v2 admission before any routing.
    assert!(
        compatibility_error_chirho
            .contains("served LLM provider composition is not installed"),
        "a registered served subtype refuses at the uninstalled composition: {compatibility_error_chirho}"
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn postgres_never_reuse_bypasses_forged_run_result_and_refuses_uncomposed_chirho() {
    let root_chirho = tmp_root_chirho();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"paid input").unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user/descriptor-d-chirho".into(),
        app_chirho: "descriptor-d-app-chirho".into(),
        owner_principal_chirho: "owner/descriptor-d-chirho".into(),
        client_id_chirho: "client/descriptor-d-chirho".into(),
        token_hash_chirho: "token/descriptor-d-chirho".into(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let node_chirho = postgres_effect_node_chirho();
    let node_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let effective_node_chirho = contextual_node_def_chirho(&node_chirho, Some(&context_chirho));
    let key_chirho = build_bytes_run_key_chirho(
        &effective_node_chirho,
        &node_hash_chirho,
        &input_hash_chirho,
    )
    .unwrap();
    let run_chirho = store_chirho::hash_object_chirho(&key_chirho).unwrap();
    store_run_key_chirho(&root_chirho, &run_chirho, &key_chirho).unwrap();
    let forged_output_chirho = cas_chirho::add_chirho(&root_chirho, b"forged result").unwrap();
    let trace_chirho = cas_chirho::add_chirho(&root_chirho, b"forged trace").unwrap();
    let forged_effect_chirho = effect_chirho::signed_skipped_effect_chirho(
        &root_chirho,
        run_chirho.clone(),
        node_chirho.capabilities_chirho[0].clone(),
        &input_hash_chirho,
        &forged_output_chirho,
    )
    .unwrap();
    store_result_chirho(
        &root_chirho,
        &RunResultChirho {
            run_chirho: run_chirho.clone(),
            outputs_chirho: BTreeMap::from([("out".into(), forged_output_chirho)]),
            effects_chirho: vec![forged_effect_chirho.clone()],
            fuel_used_chirho: 0,
            trace_chirho,
            status_chirho: RunStatusChirho::OkChirho,
            parents_chirho: Vec::new(),
        },
    )
    .unwrap();

    let error_chirho = run_effect_node_cached_with_context_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
    )
    .unwrap_err();
    assert!(matches!(
        error_chirho.downcast_ref::<
            effect_chirho::postgres_reversible_chirho::PostgresReversibleActivationErrorChirho,
        >(),
        Some(
            effect_chirho::postgres_reversible_chirho::PostgresReversibleActivationErrorChirho::CompositionUnavailableChirho
        )
    ));
    assert_eq!(
        effect_chirho::load_effect_chirho(&root_chirho, &run_chirho).unwrap(),
        Some(forged_effect_chirho),
        "NeverReuse bypasses rather than consuming or replacing the legacy Effect"
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn cached_paid_effects_share_one_typed_legacy_refusal_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user/descriptor-d-cache-backstop-chirho".into(),
        app_chirho: "descriptor-d-cache-backstop-chirho".into(),
        owner_principal_chirho: "owner/descriptor-d-cache-backstop-chirho".into(),
        client_id_chirho: "client/descriptor-d-cache-backstop-chirho".into(),
        token_hash_chirho: "token/descriptor-d-cache-backstop-chirho".into(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let reserved_chirho =
        cairn_undo_plan_chirho::contract_chirho::POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO;

    for effect_chirho in [
        "llm_chirho".to_owned(),
        reserved_chirho.to_owned(),
        format!("{reserved_chirho}-shadow"),
    ] {
        let error_chirho = bill_cached_paid_effect_chirho(
            &root_chirho,
            &CapabilityChirho::PaidEffectChirho {
                effect_chirho: effect_chirho.clone(),
                caller_chirho: context_chirho.user_principal_chirho.clone(),
            },
            &HashChirho("a".repeat(64)),
            Some(&context_chirho),
        )
        .unwrap_err();
        assert_eq!(
            error_chirho.downcast_ref::<effect_chirho::LegacyMoneyRoadRefusedChirho>(),
            Some(&effect_chirho::LegacyMoneyRoadRefusedChirho::new_chirho(
                effect_chirho::LegacyMoneyRoadChirho::CachedPaidEffectChirho,
                effect_chirho,
            ))
        );
    }
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn postgres_paid_door_refuses_without_invocation_scope_before_runtime_chirho() {
    let root_chirho = tmp_root_chirho();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"paid input").unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user/descriptor-d-chirho".into(),
        app_chirho: "descriptor-d-app-chirho".into(),
        owner_principal_chirho: "owner/descriptor-d-chirho".into(),
        client_id_chirho: "client/descriptor-d-chirho".into(),
        token_hash_chirho: "token/descriptor-d-chirho".into(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let node_chirho = postgres_effect_node_chirho();
    let node_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let mut runtime_chirho = CountingPostgresRuntimeChirho::default();

    let error_chirho = run_effect_node_cached_with_context_and_postgres_runtime_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
        &mut runtime_chirho,
    )
    .unwrap_err();
    assert!(matches!(
        error_chirho.downcast_ref::<
            effect_chirho::postgres_reversible_chirho::PostgresReversibleActivationErrorChirho,
        >(),
        Some(
            effect_chirho::postgres_reversible_chirho::PostgresReversibleActivationErrorChirho::InvocationScopeUnavailableChirho
        )
    ));
    assert_eq!(runtime_chirho.calls_chirho, 0);
    assert!(root_chirho.join("effects-chirho").read_dir().is_err());
    let _ = std::fs::remove_dir_all(root_chirho);
}

fn stored_upcase_node_chirho(root_chirho: &std::path::Path) -> (NodeDefChirho, HashChirho) {
    let wasm_hash_chirho = cas_chirho::add_chirho(root_chirho, UPCASE_WAT_CHIRHO.as_bytes())
        .expect("store upcase wasm");
    let node_chirho = NodeDefChirho {
        name_chirho: "upcase_chirho".to_string(),
        impl_wasm_chirho: wasm_hash_chirho,
        entry_chirho: "upcase_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho =
        store_chirho::put_object_chirho(root_chirho, &node_chirho).expect("store upcase node");
    (node_chirho, node_hash_chirho)
}

fn invoke_node_chirho(target_node_chirho: HashChirho) -> NodeDefChirho {
    NodeDefChirho {
        name_chirho: "invoke_chirho".to_string(),
        impl_wasm_chirho: HashChirho("builtin:invoke".to_string()),
        entry_chirho: "invoke_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        capabilities_chirho: vec![CapabilityChirho::InvokeChirho {
            node_chirho: target_node_chirho,
        }],
        fuel_limit_chirho: 0,
        ..Default::default()
    }
}

fn invoke_response_chirho(
    root_chirho: &std::path::Path,
    result_chirho: &RunResultChirho,
) -> effect_chirho::InvokeResponseChirho {
    let response_hash_chirho = result_chirho.effects_chirho[0]
        .response_chirho
        .as_ref()
        .expect("invoke response hash");
    let response_bytes_chirho =
        cas_chirho::get_chirho(root_chirho, response_hash_chirho).expect("invoke response");
    serde_json::from_slice(&response_bytes_chirho).expect("decode invoke response")
}

#[test]
fn invoke_effect_unwraps_pure_target_and_preserves_provenance_chirho() {
    let root_chirho = tmp_root_chirho();
    let (_target_chirho, target_hash_chirho) = stored_upcase_node_chirho(&root_chirho);
    let invoke_node_chirho = invoke_node_chirho(target_hash_chirho.clone());
    let invoke_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &invoke_node_chirho).unwrap();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"hello").unwrap();
    let parent_one_chirho = HashChirho("upstream-one-chirho".to_string());

    let (result_chirho, hit_chirho) = run_effect_node_cached_chirho(
        &root_chirho,
        &invoke_node_chirho,
        &invoke_hash_chirho,
        &input_hash_chirho,
        std::slice::from_ref(&parent_one_chirho),
    )
    .unwrap();
    assert!(!hit_chirho);
    let output_hash_chirho = result_chirho.outputs_chirho.get("out").unwrap();
    assert_eq!(
        cas_chirho::get_chirho(&root_chirho, output_hash_chirho).unwrap(),
        b"HELLO"
    );
    let response_chirho = invoke_response_chirho(&root_chirho, &result_chirho);
    assert_eq!(response_chirho.target_node_chirho, target_hash_chirho);
    assert_eq!(response_chirho.payload_hash_chirho, *output_hash_chirho);
    assert_eq!(
        result_chirho.parents_chirho,
        vec![
            parent_one_chirho.clone(),
            response_chirho.target_run_chirho.clone()
        ]
    );
    let target_run_chirho = load_result_chirho(&root_chirho, &response_chirho.target_run_chirho)
        .unwrap()
        .unwrap();
    assert_eq!(
        target_run_chirho.outputs_chirho.get("out").unwrap(),
        &response_chirho.payload_hash_chirho
    );

    let parent_two_chirho = HashChirho("upstream-two-chirho".to_string());
    let (cached_chirho, cached_hit_chirho) = run_effect_node_cached_chirho(
        &root_chirho,
        &invoke_node_chirho,
        &invoke_hash_chirho,
        &input_hash_chirho,
        std::slice::from_ref(&parent_two_chirho),
    )
    .unwrap();
    assert!(cached_hit_chirho);
    assert_eq!(cached_chirho.run_chirho, result_chirho.run_chirho);
    assert_eq!(
        cached_chirho.parents_chirho,
        vec![parent_two_chirho, response_chirho.target_run_chirho]
    );
    assert_eq!(
        cas_chirho::get_chirho(
            &root_chirho,
            cached_chirho.outputs_chirho.get("out").unwrap()
        )
        .unwrap(),
        b"HELLO"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn invoke_effect_propagates_context_then_refuses_legacy_paid_target_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho = cas_chirho::add_chirho(&root_chirho, b"invoke app marker").unwrap();
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(&root_chirho, "invokeapp", dag_hash_chirho, &owner_chirho)
        .unwrap();
    let mut effect_prices_chirho = BTreeMap::new();
    effect_prices_chirho.insert("llm_chirho".to_string(), 17);
    let (book_hash_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "invokeapp",
        &owner_chirho,
        Some(9),
        effect_prices_chirho,
        0,
    )
    .unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "alice".to_string(),
        app_chirho: "invokeapp".to_string(),
        owner_principal_chirho: owner_chirho.clone(),
        client_id_chirho: "client/invoke".to_string(),
        token_hash_chirho: "token/invoke".to_string(),
        price_book_chirho: Some(book_hash_chirho.clone()),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let mut target_node_chirho =
        paid_effect_node_chirho(vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".to_string(),
            caller_chirho: "ignored_until_contextualized_chirho".to_string(),
        }]);
    target_node_chirho.effect_contract_set_chirho = Some(current_effect_contract_set_chirho());
    let target_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &target_node_chirho).unwrap();
    let invoke_node_chirho = invoke_node_chirho(target_hash_chirho);
    let invoke_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &invoke_node_chirho).unwrap();
    let request_chirho = llm_request_bytes_chirho("paid hi");
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, &request_chirho).unwrap();

    let error_chirho = run_effect_node_cached_with_context_chirho(
        &root_chirho,
        &invoke_node_chirho,
        &invoke_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    // The invoke node's paid llm_chirho target passes v2 admission; with no served-LLM composition
    // injected it refuses at the uninstalled composition, and that typed refusal propagates through
    // the invoke node. (llm_chirho routes to the served ladder since S2b/S2c, not the legacy road.)
    assert!(
        error_chirho.contains("served LLM provider composition is not installed"),
        "the invoke node propagates the paid target's served composition refusal: {error_chirho}"
    );
    let unauth_invoke_error_chirho = run_effect_node_cached_chirho(
        &root_chirho,
        &invoke_node_chirho,
        &invoke_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(unauth_invoke_error_chirho.contains("requires verified RequestContextChirho"));
    assert_eq!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .len(),
        0
    );
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn invoke_effect_rejects_target_over_nested_fuel_budget_chirho() {
    let root_chirho = tmp_root_chirho();
    let (mut target_chirho, _) = stored_upcase_node_chirho(&root_chirho);
    target_chirho.fuel_limit_chirho = 50_000_001;
    let target_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &target_chirho).unwrap();
    let invoke_node_chirho = invoke_node_chirho(target_hash_chirho);
    let invoke_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &invoke_node_chirho).unwrap();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"hello").unwrap();

    let error_chirho = run_effect_node_cached_chirho(
        &root_chirho,
        &invoke_node_chirho,
        &invoke_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err();
    assert!(format!("{error_chirho:#}").contains("nested invoke budget"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn paid_effect_requires_verified_request_context_not_self_declared_identity_chirho() {
    let root_chirho = tmp_root_chirho();
    let request_chirho = llm_request_bytes_chirho("hi");
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, &request_chirho).unwrap();
    let paid_cap_chirho = CapabilityChirho::PaidEffectChirho {
        effect_chirho: "llm_chirho".to_string(),
        caller_chirho: "user/alice".to_string(),
    };
    let mut missing_identity_chirho = paid_effect_node_chirho(vec![paid_cap_chirho.clone()]);
    missing_identity_chirho.effect_contract_set_chirho = Some(current_effect_contract_set_chirho());
    let missing_hash_chirho = store_chirho::hash_object_chirho(&missing_identity_chirho).unwrap();
    let missing_error_chirho = run_effect_node_cached_chirho(
        &root_chirho,
        &missing_identity_chirho,
        &missing_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(missing_error_chirho.contains("requires verified RequestContextChirho"));

    let mut authorized_chirho = paid_effect_node_chirho(vec![
        paid_cap_chirho,
        CapabilityChirho::UserIdentityChirho {
            principal_chirho: "user/alice".to_string(),
            client_id_chirho: "client/alpha".to_string(),
            token_hash_chirho: "token-hash".to_string(),
        },
    ]);
    authorized_chirho.effect_contract_set_chirho = Some(current_effect_contract_set_chirho());
    let authorized_hash_chirho = store_chirho::hash_object_chirho(&authorized_chirho).unwrap();
    let self_declared_error_chirho = run_effect_node_cached_chirho(
        &root_chirho,
        &authorized_chirho,
        &authorized_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(self_declared_error_chirho.contains("requires verified RequestContextChirho"));

    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho = cas_chirho::add_chirho(&root_chirho, b"paid app marker").unwrap();
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        "paidctxapp",
        dag_hash_chirho,
        &owner_chirho,
    )
    .unwrap();
    let mut effect_prices_chirho = BTreeMap::new();
    effect_prices_chirho.insert("llm_chirho".to_string(), 5);
    let (book_hash_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "paidctxapp",
        &owner_chirho,
        Some(1),
        effect_prices_chirho,
        0,
    )
    .unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user/alice".to_string(),
        app_chirho: "paidctxapp".to_string(),
        owner_principal_chirho: owner_chirho,
        client_id_chirho: "client/alpha".to_string(),
        token_hash_chirho: "token-hash".to_string(),
        price_book_chirho: Some(book_hash_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };

    let refusal_chirho = run_effect_node_cached_with_context_chirho(
        &root_chirho,
        &authorized_chirho,
        &authorized_hash_chirho,
        &input_hash_chirho,
        &[],
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    // With verified context the paid llm_chirho effect passes v2 admission and reaches the served
    // road; uninjected, it refuses at the uninstalled composition (the served pre-effect refusal),
    // not the legacy money road. The verified-context refusals above are this test's primary intent.
    assert!(
        refusal_chirho.contains("served LLM provider composition is not installed"),
        "a verified-context paid llm effect refuses at the uninstalled composition: {refusal_chirho}"
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn query_effect_refuses_public_none_and_authenticated_some_before_projection_chirho() {
    let root_chirho = tmp_root_chirho();
    let request_chirho = serde_json::to_vec(&crate::effect_chirho::ScopedQueryRequestChirho {
        prefix_chirho: "contacts-chirho".to_string(),
        limit_chirho: Some(1),
    })
    .unwrap();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, &request_chirho).unwrap();
    let public_query_node_chirho = paid_effect_node_chirho(vec![
        CapabilityChirho::QueryChirho {
            prefix_chirho: "contacts-chirho".to_string(),
            caller_chirho: "user/query-victim".to_string(),
            max_rows_chirho: 10,
        },
        CapabilityChirho::UserIdentityChirho {
            principal_chirho: "user/query-victim".to_string(),
            client_id_chirho: "client/query-fake".to_string(),
            token_hash_chirho: "token/query-fake".to_string(),
        },
    ]);
    let public_query_hash_chirho =
        store_chirho::hash_object_chirho(&public_query_node_chirho).unwrap();
    let public_error_chirho = run_effect_node_cached_chirho(
        &root_chirho,
        &public_query_node_chirho,
        &public_query_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err();
    assert_eq!(
        public_error_chirho.downcast_ref::<effect_chirho::LegacyMoneyRoadRefusedChirho>(),
        Some(&effect_chirho::LegacyMoneyRoadRefusedChirho::new_chirho(
            effect_chirho::LegacyMoneyRoadChirho::QueryEffectChirho,
            "query_chirho",
        ))
    );

    let authenticated_query_node_chirho =
        paid_effect_node_chirho(vec![CapabilityChirho::QueryChirho {
            prefix_chirho: "contacts-chirho".to_string(),
            caller_chirho: "ignored-until-context-chirho".to_string(),
            max_rows_chirho: 10,
        }]);
    let authenticated_query_hash_chirho =
        store_chirho::hash_object_chirho(&authenticated_query_node_chirho).unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user/query-victim".to_string(),
        app_chirho: "public-query-app-chirho".to_string(),
        owner_principal_chirho: "owner/public-query-app-chirho".to_string(),
        client_id_chirho: "client/query-authenticated".to_string(),
        token_hash_chirho: "token/query-authenticated".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let authenticated_error_chirho = run_effect_node_cached_with_context_chirho(
        &root_chirho,
        &authenticated_query_node_chirho,
        &authenticated_query_hash_chirho,
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
    assert_eq!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .len(),
        0
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn cached_invoke_charge_bearing_target_requires_verified_context_chirho() {
    let root_chirho = tmp_root_chirho();
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"legacy paid payload").unwrap();
    let payload_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"legacy paid payload").unwrap();
    let trace_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"legacy trace").unwrap();
    let mut target_node_chirho = paid_effect_node_chirho(vec![
        CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".to_string(),
            caller_chirho: "user/cache-victim".to_string(),
        },
        CapabilityChirho::UserIdentityChirho {
            principal_chirho: "user/cache-victim".to_string(),
            client_id_chirho: "client/cache-fake".to_string(),
            token_hash_chirho: "token/cache-fake".to_string(),
        },
    ]);
    target_node_chirho.effect_contract_set_chirho = Some(current_effect_contract_set_chirho());
    let target_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &target_node_chirho).unwrap();
    let target_run_key_chirho =
        build_bytes_run_key_chirho(&target_node_chirho, &target_hash_chirho, &input_hash_chirho)
            .unwrap();
    let target_run_chirho = store_chirho::hash_object_chirho(&target_run_key_chirho).unwrap();
    store_run_key_chirho(&root_chirho, &target_run_chirho, &target_run_key_chirho).unwrap();
    let target_effect_chirho = crate::effect_chirho::signed_skipped_effect_chirho(
        &root_chirho,
        HashChirho("legacy-target-paid-effect-chirho".to_string()),
        CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".to_string(),
            caller_chirho: "user/cache-victim".to_string(),
        },
        &input_hash_chirho,
        &payload_hash_chirho,
    )
    .unwrap();
    let mut target_outputs_chirho = BTreeMap::new();
    target_outputs_chirho.insert("out".to_string(), payload_hash_chirho.clone());
    store_result_chirho(
        &root_chirho,
        &RunResultChirho {
            run_chirho: target_run_chirho.clone(),
            outputs_chirho: target_outputs_chirho,
            effects_chirho: vec![target_effect_chirho],
            fuel_used_chirho: 0,
            trace_chirho: trace_hash_chirho.clone(),
            status_chirho: RunStatusChirho::OkChirho,
            parents_chirho: vec![],
        },
    )
    .unwrap();

    let invoke_node_chirho = invoke_node_chirho(target_hash_chirho.clone());
    let invoke_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &invoke_node_chirho).unwrap();
    let invoke_run_key_chirho =
        build_bytes_run_key_chirho(&invoke_node_chirho, &invoke_hash_chirho, &input_hash_chirho)
            .unwrap();
    let invoke_run_chirho = store_chirho::hash_object_chirho(&invoke_run_key_chirho).unwrap();
    store_run_key_chirho(&root_chirho, &invoke_run_chirho, &invoke_run_key_chirho).unwrap();
    let invoke_response_chirho = crate::effect_chirho::InvokeResponseChirho {
        target_node_chirho: target_hash_chirho,
        target_run_chirho,
        payload_hash_chirho: payload_hash_chirho.clone(),
        cached_chirho: false,
    };
    let invoke_response_hash_chirho = cas_chirho::add_chirho(
        &root_chirho,
        &serde_json::to_vec(&invoke_response_chirho).unwrap(),
    )
    .unwrap();
    let invoke_effect_chirho = crate::effect_chirho::signed_skipped_effect_chirho(
        &root_chirho,
        HashChirho("legacy-outer-invoke-effect-chirho".to_string()),
        invoke_node_chirho.capabilities_chirho[0].clone(),
        &input_hash_chirho,
        &invoke_response_hash_chirho,
    )
    .unwrap();
    let mut invoke_outputs_chirho = BTreeMap::new();
    invoke_outputs_chirho.insert("out".to_string(), payload_hash_chirho);
    store_result_chirho(
        &root_chirho,
        &RunResultChirho {
            run_chirho: invoke_run_chirho,
            outputs_chirho: invoke_outputs_chirho,
            effects_chirho: vec![invoke_effect_chirho],
            fuel_used_chirho: 0,
            trace_chirho: trace_hash_chirho,
            status_chirho: RunStatusChirho::OkChirho,
            parents_chirho: vec![],
        },
    )
    .unwrap();

    let error_chirho = run_effect_node_cached_chirho(
        &root_chirho,
        &invoke_node_chirho,
        &invoke_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("cached charge-bearing PaidEffectChirho"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}
