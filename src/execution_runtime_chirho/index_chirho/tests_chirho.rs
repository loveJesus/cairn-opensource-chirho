// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::model_chirho::RunStatusChirho;
use std::collections::{BTreeMap, BTreeSet};
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
    std::env::temp_dir().join(format!("cairn-index-test-{nanos_chirho}-{n_chirho}"))
}

fn two_keys_with_different_first_nibbles_chirho() -> (String, String) {
    let first_chirho = "key-0".to_string();
    let first_slot_chirho = nibble_label_chirho(&key_hash_chirho(&first_chirho), 0).unwrap();
    for i_chirho in 1..10_000 {
        let candidate_chirho = format!("key-{i_chirho}");
        let candidate_slot_chirho =
            nibble_label_chirho(&key_hash_chirho(&candidate_chirho), 0).unwrap();
        if candidate_slot_chirho != first_slot_chirho {
            return (first_chirho, candidate_chirho);
        }
    }
    panic!("could not find two keys with different HAMT first nibbles");
}

fn write_run_result_chirho(root_chirho: &Path, result_chirho: &RunResultChirho) {
    cache_chirho::store_result_chirho(root_chirho, result_chirho).unwrap();
}

fn write_run_key_chirho(
    root_chirho: &Path,
    run_chirho: &HashChirho,
    node_chirho: HashChirho,
    input_chirho: HashChirho,
) {
    let path_chirho = root_chirho.join("runkeys-chirho").join(&run_chirho.0);
    std::fs::create_dir_all(path_chirho.parent().unwrap()).unwrap();
    let run_key_chirho = RunKeyChirho {
        node_chirho,
        inputs_chirho: BTreeMap::from([("in".to_string(), input_chirho)]),
        caps_chirho: cas_chirho::hash_chirho(b"caps"),
    };
    std::fs::write(
        &path_chirho,
        serde_json::to_vec_pretty(&run_key_chirho).unwrap(),
    )
    .unwrap();
}

fn run_result_chirho(
    root_chirho: &Path,
    label_chirho: &str,
    parents_chirho: Vec<HashChirho>,
    outputs_chirho: Vec<(&str, HashChirho)>,
    effects_chirho: Vec<EffectChirho>,
) -> RunResultChirho {
    let run_chirho = cas_chirho::hash_chirho(label_chirho.as_bytes());
    let trace_chirho =
        cas_chirho::add_chirho(root_chirho, format!("trace {label_chirho}").as_bytes()).unwrap();
    let result_chirho = RunResultChirho {
        run_chirho,
        outputs_chirho: outputs_chirho
            .into_iter()
            .map(|(port_chirho, hash_chirho)| (port_chirho.to_string(), hash_chirho))
            .collect::<BTreeMap<_, _>>(),
        effects_chirho,
        fuel_used_chirho: 0,
        trace_chirho,
        status_chirho: RunStatusChirho::OkChirho,
        parents_chirho,
    };
    write_run_result_chirho(root_chirho, &result_chirho);
    result_chirho
}

fn effect_chirho(seq_chirho: u64, request_chirho: HashChirho) -> EffectChirho {
    EffectChirho {
        seq_chirho,
        capability_chirho: CapabilityChirho::ClockChirho,
        request_chirho,
        idem_key_chirho: cas_chirho::hash_chirho(format!("idem-{seq_chirho}").as_bytes()),
        response_chirho: Some(cas_chirho::hash_chirho(
            format!("response-{seq_chirho}").as_bytes(),
        )),
        sig_chirho: format!("sig-{seq_chirho}"),
        at_chirho: "0".to_string(),
    }
}

#[test]
fn hamt_update_shares_untouched_nodes_and_keeps_old_roots_chirho() {
    let root_chirho = tmp_root_chirho();
    let (left_key_chirho, right_key_chirho) = two_keys_with_different_first_nibbles_chirho();
    let root1_chirho = put_hamt_entry_chirho(&root_chirho, None, &left_key_chirho, b"one").unwrap();
    let root2_chirho =
        put_hamt_entry_chirho(&root_chirho, Some(&root1_chirho), &right_key_chirho, b"two")
            .unwrap();
    let root3_chirho = put_hamt_entry_chirho(
        &root_chirho,
        Some(&root2_chirho),
        &left_key_chirho,
        b"one-updated",
    )
    .unwrap();

    let shared_chirho: BTreeSet<_> = reachable_hamt_nodes_chirho(&root_chirho, &root2_chirho)
        .unwrap()
        .intersection(&reachable_hamt_nodes_chirho(&root_chirho, &root3_chirho).unwrap())
        .cloned()
        .collect();
    assert!(!shared_chirho.is_empty());
    assert_eq!(
        lookup_value_hash_chirho(&root_chirho, &root1_chirho, &left_key_chirho)
            .unwrap()
            .map(|hash_chirho| cas_chirho::get_chirho(&root_chirho, &hash_chirho).unwrap()),
        Some(b"one".to_vec())
    );
    assert_eq!(
        lookup_value_hash_chirho(&root_chirho, &root3_chirho, &left_key_chirho)
            .unwrap()
            .map(|hash_chirho| cas_chirho::get_chirho(&root_chirho, &hash_chirho).unwrap()),
        Some(b"one-updated".to_vec())
    );
    assert_eq!(
        lookup_value_hash_chirho(&root_chirho, &root2_chirho, &right_key_chirho)
            .unwrap()
            .map(|hash_chirho| cas_chirho::get_chirho(&root_chirho, &hash_chirho).unwrap()),
        Some(b"two".to_vec())
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn index_projection_time_travels_and_rollback_repoints_chirho() {
    let root_chirho = tmp_root_chirho();
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    let v1_chirho = store_chirho.put_chirho("count", b"one").unwrap();
    let v2_chirho = store_chirho.put_chirho("count", b"two").unwrap();
    store_chirho.put_chirho("other", b"present").unwrap();
    drop(store_chirho);

    let old_projection_chirho = project_index_chirho(&root_chirho, Some(v1_chirho)).unwrap();
    let new_projection_chirho = project_index_chirho(&root_chirho, Some(v2_chirho)).unwrap();
    assert_eq!(
        get_index_value_chirho(
            &root_chirho,
            &old_projection_chirho.record_hash_chirho,
            "count"
        )
        .unwrap()
        .unwrap(),
        b"one".to_vec()
    );
    assert_eq!(
        get_index_value_chirho(
            &root_chirho,
            &new_projection_chirho.record_hash_chirho,
            "count"
        )
        .unwrap()
        .unwrap(),
        b"two".to_vec()
    );
    assert!(get_index_value_chirho(
        &root_chirho,
        &old_projection_chirho.record_hash_chirho,
        "other"
    )
    .unwrap()
    .is_none());

    let verification_chirho =
        verify_index_chirho(&root_chirho, &new_projection_chirho.record_hash_chirho).unwrap();
    assert_eq!(verification_chirho.rows_chirho, 1);
    let restored_chirho =
        rollback_index_ref_chirho(&root_chirho, &old_projection_chirho.record_hash_chirho).unwrap();
    assert_eq!(restored_chirho.view_chirho, v1_chirho);
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .get(INDEX_REF_CHIRHO),
        Some(&old_projection_chirho.record_hash_chirho)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn empty_index_projection_verifies_chirho() {
    let root_chirho = tmp_root_chirho();
    let projection_chirho = project_index_chirho(&root_chirho, None).unwrap();
    let verification_chirho =
        verify_index_chirho(&root_chirho, &projection_chirho.record_hash_chirho).unwrap();
    assert_eq!(verification_chirho.rows_chirho, 0);
    assert!(get_index_value_chirho(
        &root_chirho,
        &projection_chirho.record_hash_chirho,
        "missing"
    )
    .unwrap()
    .is_none());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn index_root_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
    let root_chirho = tmp_root_chirho();
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    store_chirho.put_chirho("count", b"one").unwrap();
    drop(store_chirho);
    let index_projection_chirho = project_index_chirho(&root_chirho, None).unwrap();
    let provenance_projection_chirho =
        project_inverted_provenance_index_chirho(&root_chirho).unwrap();
    assert_eq!(
        index_projection_chirho.record_chirho.schema_chirho,
        PERSISTENT_INDEX_ROOT_SCHEMA_CHIRHO
    );
    assert_eq!(
        provenance_projection_chirho.record_chirho.schema_chirho,
        INVERTED_PROVENANCE_ROOT_SCHEMA_CHIRHO
    );

    let mut bad_index_chirho = index_projection_chirho.record_chirho.clone();
    bad_index_chirho.schema_chirho = "persistent-index-root-v9-chirho".to_string();
    let bad_index_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &bad_index_chirho).unwrap();
    assert!(load_index_record_chirho(&root_chirho, &bad_index_hash_chirho).is_err());
    assert!(verify_index_chirho(&root_chirho, &bad_index_hash_chirho).is_err());
    let mut wrong_kind_index_chirho = index_projection_chirho.record_chirho.clone();
    wrong_kind_index_chirho.kind_chirho = INVERTED_PROVENANCE_KIND_CHIRHO.to_string();
    let wrong_kind_index_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &wrong_kind_index_chirho).unwrap();
    assert!(load_index_record_chirho(&root_chirho, &wrong_kind_index_hash_chirho).is_err());

    let mut bad_provenance_chirho = provenance_projection_chirho.record_chirho.clone();
    bad_provenance_chirho.schema_chirho = "inverted-provenance-root-v9-chirho".to_string();
    let bad_provenance_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &bad_provenance_chirho).unwrap();
    assert!(
        load_inverted_provenance_record_chirho(&root_chirho, &bad_provenance_hash_chirho).is_err()
    );
    assert!(
        verify_inverted_provenance_index_chirho(&root_chirho, &bad_provenance_hash_chirho).is_err()
    );
    let mut wrong_kind_provenance_chirho = provenance_projection_chirho.record_chirho.clone();
    wrong_kind_provenance_chirho.kind_chirho = PERSISTENT_INDEX_KIND_CHIRHO.to_string();
    let wrong_kind_provenance_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &wrong_kind_provenance_chirho).unwrap();
    assert!(load_inverted_provenance_record_chirho(
        &root_chirho,
        &wrong_kind_provenance_hash_chirho
    )
    .is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_index_roots_without_schema_still_verify_chirho() {
    let root_chirho = tmp_root_chirho();
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    store_chirho.put_chirho("count", b"one").unwrap();
    drop(store_chirho);
    let index_projection_chirho = project_index_chirho(&root_chirho, None).unwrap();
    let provenance_projection_chirho =
        project_inverted_provenance_index_chirho(&root_chirho).unwrap();
    let mut legacy_index_chirho = index_projection_chirho.record_chirho.clone();
    legacy_index_chirho.schema_chirho.clear();
    let legacy_index_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &legacy_index_chirho).unwrap();
    let legacy_index_json_chirho = serde_json::to_string(&legacy_index_chirho).unwrap();
    assert!(!legacy_index_json_chirho.contains("schema_chirho"));
    assert_eq!(
        load_index_record_chirho(&root_chirho, &legacy_index_hash_chirho)
            .unwrap()
            .schema_chirho,
        ""
    );
    verify_index_chirho(&root_chirho, &legacy_index_hash_chirho).unwrap();

    let mut legacy_provenance_chirho = provenance_projection_chirho.record_chirho.clone();
    legacy_provenance_chirho.schema_chirho.clear();
    let legacy_provenance_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &legacy_provenance_chirho).unwrap();
    let legacy_provenance_json_chirho = serde_json::to_string(&legacy_provenance_chirho).unwrap();
    assert!(!legacy_provenance_json_chirho.contains("schema_chirho"));
    assert_eq!(
        load_inverted_provenance_record_chirho(&root_chirho, &legacy_provenance_hash_chirho)
            .unwrap()
            .schema_chirho,
        ""
    );
    verify_inverted_provenance_index_chirho(&root_chirho, &legacy_provenance_hash_chirho).unwrap();

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn inverted_provenance_finds_transitive_dependent_effects_chirho() {
    let root_chirho = tmp_root_chirho();
    let state_chirho = cas_chirho::add_chirho(&root_chirho, b"state-v2").unwrap();
    let second_state_chirho = cas_chirho::add_chirho(&root_chirho, b"state-v3").unwrap();
    let direct_input_chirho = cas_chirho::add_chirho(&root_chirho, b"direct-input").unwrap();
    let direct_request_chirho = cas_chirho::add_chirho(&root_chirho, b"effect-request").unwrap();
    let producer_request_chirho =
        cas_chirho::add_chirho(&root_chirho, b"producer-effect-request").unwrap();
    let node_version_chirho = cas_chirho::hash_chirho(b"node-version");
    let producer_chirho = run_result_chirho(
        &root_chirho,
        "producer",
        vec![],
        vec![("out", state_chirho.clone())],
        vec![effect_chirho(0, producer_request_chirho)],
    );
    write_run_key_chirho(
        &root_chirho,
        &producer_chirho.run_chirho,
        cas_chirho::hash_chirho(b"producer-node"),
        cas_chirho::hash_chirho(b"producer-input"),
    );
    let first_effect_chirho = effect_chirho(0, direct_request_chirho.clone());
    let first_consumer_chirho = run_result_chirho(
        &root_chirho,
        "first-consumer",
        vec![producer_chirho.run_chirho.clone()],
        vec![("out", second_state_chirho.clone())],
        vec![first_effect_chirho],
    );
    write_run_key_chirho(
        &root_chirho,
        &first_consumer_chirho.run_chirho,
        node_version_chirho.clone(),
        direct_input_chirho.clone(),
    );
    let second_effect_chirho = effect_chirho(0, second_state_chirho.clone());
    let second_consumer_chirho = run_result_chirho(
        &root_chirho,
        "second-consumer",
        vec![first_consumer_chirho.run_chirho.clone()],
        vec![],
        vec![second_effect_chirho],
    );

    let projection_chirho = project_inverted_provenance_index_chirho(&root_chirho).unwrap();
    let verification_chirho = verify_inverted_provenance_index_chirho(
        &root_chirho,
        &projection_chirho.record_hash_chirho,
    )
    .unwrap();
    assert_eq!(verification_chirho.runs_indexed_chirho, 3);

    let dependents_chirho = find_dependent_effects_chirho(
        &root_chirho,
        &projection_chirho.record_hash_chirho,
        &state_chirho,
    )
    .unwrap();
    let dependent_runs_chirho: BTreeSet<_> = dependents_chirho
        .iter()
        .map(|effect_chirho| effect_chirho.run_chirho.clone())
        .collect();
    assert_eq!(
        dependent_runs_chirho,
        BTreeSet::from([
            first_consumer_chirho.run_chirho.clone(),
            second_consumer_chirho.run_chirho.clone()
        ])
    );

    let direct_dependents_chirho = find_dependent_effects_chirho(
        &root_chirho,
        &projection_chirho.record_hash_chirho,
        &direct_request_chirho,
    )
    .unwrap();
    assert_eq!(direct_dependents_chirho.len(), 2);
    assert!(direct_dependents_chirho
        .iter()
        .any(|effect_chirho| effect_chirho.run_chirho == first_consumer_chirho.run_chirho));

    let direct_input_dependents_chirho = find_dependent_effects_chirho(
        &root_chirho,
        &projection_chirho.record_hash_chirho,
        &direct_input_chirho,
    )
    .unwrap();
    assert_eq!(direct_input_dependents_chirho.len(), 2);

    let node_dependents_chirho = find_dependent_effects_chirho(
        &root_chirho,
        &projection_chirho.record_hash_chirho,
        &node_version_chirho,
    )
    .unwrap();
    assert_eq!(node_dependents_chirho.len(), 2);

    let producer_run_dependents_chirho = find_dependent_effects_chirho(
        &root_chirho,
        &projection_chirho.record_hash_chirho,
        &producer_chirho.run_chirho,
    )
    .unwrap();
    assert_eq!(producer_run_dependents_chirho.len(), 3);

    let missing_chirho = cas_chirho::hash_chirho(b"missing-state");
    assert!(find_dependent_effects_chirho(
        &root_chirho,
        &projection_chirho.record_hash_chirho,
        &missing_chirho
    )
    .unwrap()
    .is_empty());

    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .get(PROVENANCE_INDEX_REF_CHIRHO),
        Some(&projection_chirho.record_hash_chirho)
    );

    let _ = second_consumer_chirho;
    let _ = std::fs::remove_dir_all(&root_chirho);
}
