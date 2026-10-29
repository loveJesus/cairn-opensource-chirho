// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const OLD_PROJECTION_CHIRHO: &str = "version-pinning-old-chirho";
const NEW_PROJECTION_CHIRHO: &str = "version-pinning-new-chirho";

struct BlockingVersionProjectionPortChirho {
    entered_sender_chirho: mpsc::SyncSender<String>,
    release_receiver_chirho: Mutex<mpsc::Receiver<()>>,
    calls_chirho: Mutex<Vec<String>>,
}

impl BlockingVersionProjectionPortChirho {
    fn calls_chirho(&self) -> Vec<String> {
        self.calls_chirho.lock().unwrap().clone()
    }
}

impl PublishedProjectionReadPortChirho for BlockingVersionProjectionPortChirho {
    fn read_published_projection_chirho(
        &self,
        request_chirho: &PublishedProjectionReadRequestChirho<'_>,
    ) -> anyhow::Result<ComposedProjectionReadChirho> {
        let call_ordinal_chirho = {
            let mut calls_chirho = self.calls_chirho.lock().unwrap();
            calls_chirho.push(request_chirho.projection_name_chirho.to_string());
            calls_chirho.len()
        };
        if call_ordinal_chirho == 1 {
            self.entered_sender_chirho
                .send(request_chirho.projection_name_chirho.to_string())
                .map_err(|_| anyhow!("version-pinning entry receiver closed"))?;
            self.release_receiver_chirho
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error_chirho| {
                    anyhow!("version-pinning release timed out: {error_chirho}")
                })?;
        }

        let balance_chirho = match request_chirho.projection_name_chirho {
            OLD_PROJECTION_CHIRHO => 11,
            NEW_PROJECTION_CHIRHO => 22,
            unexpected_chirho => bail!("unexpected projection '{unexpected_chirho}'"),
        };
        Ok(fresh_projection_read_chirho(balance_chirho))
    }
}

fn store_versioned_query_dag_chirho(
    root_chirho: &Path,
    query_node_name_chirho: &str,
    projection_name_chirho: &str,
    sink_node_name_chirho: &str,
    sink_wasm_chirho: &[u8],
    sink_entry_chirho: &str,
) -> HashChirho {
    let (_query_node_chirho, query_node_hash_chirho) = store_effect_node_chirho(
        root_chirho,
        query_node_name_chirho,
        CapabilityChirho::QueryChirho {
            prefix_chirho: projection_name_chirho.to_string(),
            caller_chirho: "version-pinning-caller-string-grants-nothing-chirho".to_string(),
            max_rows_chirho: 25,
        },
    );
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let sink_node_chirho = NodeDefChirho {
        name_chirho: sink_node_name_chirho.to_string(),
        impl_wasm_chirho: cas_chirho::add_chirho(root_chirho, sink_wasm_chirho).unwrap(),
        entry_chirho: sink_entry_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let sink_node_hash_chirho =
        store_chirho::put_object_chirho(root_chirho, &sink_node_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![
                query_node_hash_chirho.clone(),
                sink_node_hash_chirho.clone(),
            ],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: query_node_hash_chirho,
                from_port_chirho: "out".to_string(),
                to_node_chirho: sink_node_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        },
    )
    .unwrap()
}

fn reversed_response_balance_chirho(report_chirho: &dag_chirho::DagRunReportChirho) -> u64 {
    let response_bytes_chirho = report_chirho
        .payload_chirho
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    let response_chirho: PublishedProjectionReadResponseChirho =
        serde_json::from_slice(&response_bytes_chirho).unwrap();
    response_chirho
        .view_chirho
        .as_ref()
        .and_then(|view_chirho| view_chirho.get("balance_chirho"))
        .and_then(serde_json::Value::as_u64)
        .unwrap()
}

#[test]
fn in_flight_dag_finishes_bound_version_then_next_admission_uses_new_ref_chirho() {
    let root_chirho = tmp_root_chirho();
    let old_dag_chirho = store_versioned_query_dag_chirho(
        &root_chirho,
        "version_pinning_old_query_chirho",
        OLD_PROJECTION_CHIRHO,
        "version_pinning_old_reverse_chirho",
        include_str!("../../../../examples-chirho/reverse-chirho.wat").as_bytes(),
        "reverse_chirho",
    );
    let new_dag_chirho = store_versioned_query_dag_chirho(
        &root_chirho,
        "version_pinning_new_query_chirho",
        NEW_PROJECTION_CHIRHO,
        "version_pinning_new_upcase_chirho",
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
        "upcase_chirho",
    );
    let context_chirho = verified_request_context_chirho(&root_chirho, &old_dag_chirho);
    let old_request_chirho = projection_request_bytes_chirho(OLD_PROJECTION_CHIRHO);
    let new_request_chirho = projection_request_bytes_chirho(NEW_PROJECTION_CHIRHO);
    let (entered_sender_chirho, entered_receiver_chirho) = mpsc::sync_channel(1);
    let (release_sender_chirho, release_receiver_chirho) = mpsc::sync_channel(1);
    let port_chirho = Arc::new(BlockingVersionProjectionPortChirho {
        entered_sender_chirho,
        release_receiver_chirho: Mutex::new(release_receiver_chirho),
        calls_chirho: Mutex::new(Vec::new()),
    });

    let worker_root_chirho = root_chirho.clone();
    let worker_context_chirho = context_chirho.clone();
    let worker_port_chirho = Arc::clone(&port_chirho);
    let worker_old_dag_chirho = old_dag_chirho.clone();
    let worker_chirho = std::thread::spawn(move || {
        let refs_chirho = crate::refs_chirho::load_refs_chirho(&worker_root_chirho).unwrap();
        let selected_chirho = crate::app_chirho::resolve_app_dag_chirho(
            &worker_root_chirho,
            &refs_chirho,
            "projection-resume-app-chirho",
        )
        .unwrap();
        assert_eq!(selected_chirho.dag_chirho, worker_old_dag_chirho);
        run_dag_with_intent_and_projection_read_chirho(
            &worker_root_chirho,
            &selected_chirho.dag_chirho,
            &old_request_chirho,
            Some(&worker_context_chirho),
            Some(worker_port_chirho.as_ref()),
        )
        .unwrap()
    });

    assert_eq!(
        entered_receiver_chirho
            .recv_timeout(Duration::from_secs(5))
            .unwrap(),
        OLD_PROJECTION_CHIRHO
    );
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        "projection-resume-app-chirho",
        new_dag_chirho.clone(),
        &context_chirho.owner_principal_chirho,
    )
    .unwrap();
    let updated_refs_chirho = crate::refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let next_selected_chirho = crate::app_chirho::resolve_app_dag_chirho(
        &root_chirho,
        &updated_refs_chirho,
        "projection-resume-app-chirho",
    )
    .unwrap();
    assert_eq!(next_selected_chirho.dag_chirho, new_dag_chirho);

    release_sender_chirho.send(()).unwrap();
    let old_report_chirho = worker_chirho.join().unwrap();
    assert_eq!(reversed_response_balance_chirho(&old_report_chirho), 11);
    assert_eq!(
        old_report_chirho
            .node_runs_chirho
            .iter()
            .map(|run_chirho| run_chirho.node_name_chirho.as_str())
            .collect::<Vec<_>>(),
        vec![
            "version_pinning_old_query_chirho",
            "version_pinning_old_reverse_chirho"
        ]
    );

    let new_report_chirho = run_dag_with_intent_and_projection_read_chirho(
        &root_chirho,
        &next_selected_chirho.dag_chirho,
        &new_request_chirho,
        Some(&context_chirho),
        Some(port_chirho.as_ref()),
    )
    .unwrap();
    assert!(String::from_utf8(new_report_chirho.payload_chirho.clone())
        .unwrap()
        .contains("\"BALANCE_CHIRHO\":22"));
    assert_eq!(
        new_report_chirho
            .node_runs_chirho
            .iter()
            .map(|run_chirho| run_chirho.node_name_chirho.as_str())
            .collect::<Vec<_>>(),
        vec![
            "version_pinning_new_query_chirho",
            "version_pinning_new_upcase_chirho"
        ]
    );
    assert_eq!(
        port_chirho.calls_chirho(),
        vec![
            OLD_PROJECTION_CHIRHO.to_string(),
            NEW_PROJECTION_CHIRHO.to_string()
        ]
    );
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        6
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 6);

    let _ = std::fs::remove_dir_all(root_chirho);
}
