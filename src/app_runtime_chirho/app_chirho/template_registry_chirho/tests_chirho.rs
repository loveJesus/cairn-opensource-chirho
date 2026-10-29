// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::DagChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-template-registry-test-{nanos_chirho}-{n_chirho}"
    ))
}

fn fake_dag_chirho(root_chirho: &std::path::Path) -> HashChirho {
    let dag_chirho = DagChirho {
        nodes_chirho: Vec::new(),
        edges_chirho: Vec::new(),
    };
    store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap()
}

#[test]
fn template_registry_signs_verifies_and_resolves_latest_target_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_one_chirho = fake_dag_chirho(&root_chirho);
    let dag_two_chirho = fake_dag_chirho(&root_chirho);

    register_template_app_template_chirho(
        &root_chirho,
        TemplateRegistryInputChirho {
            template_id_chirho: "tree-template-landing-chirho".to_string(),
            root_dag_chirho: dag_one_chirho,
            response_content_type_chirho: "text/html".to_string(),
        },
    )
    .unwrap();
    register_template_app_template_chirho(
        &root_chirho,
        TemplateRegistryInputChirho {
            template_id_chirho: "tree-template-landing-chirho".to_string(),
            root_dag_chirho: dag_two_chirho.clone(),
            response_content_type_chirho: "TEXT/HTML; charset=utf-8".to_string(),
        },
    )
    .unwrap();

    assert_eq!(verify_template_registry_chirho(&root_chirho).unwrap(), 2);
    let target_chirho =
        template_target_chirho(&root_chirho, "tree-template-landing-chirho").unwrap();
    assert_eq!(target_chirho.root_dag_chirho, dag_two_chirho);
    assert_eq!(
        target_chirho.response_content_type_chirho,
        "text/html; charset=utf-8"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn template_registry_fails_closed_on_missing_dag_and_tamper_chirho() {
    let root_chirho = tmp_root_chirho();
    let missing_dag_chirho = HashChirho("ab".repeat(32));
    let missing_error_chirho = register_template_app_template_chirho(
        &root_chirho,
        TemplateRegistryInputChirho {
            template_id_chirho: "bad-template-chirho".to_string(),
            root_dag_chirho: missing_dag_chirho,
            response_content_type_chirho: "text/html".to_string(),
        },
    )
    .unwrap_err()
    .to_string();
    assert!(missing_error_chirho.contains("not in the store"));

    let dag_chirho = fake_dag_chirho(&root_chirho);
    register_template_app_template_chirho(
        &root_chirho,
        TemplateRegistryInputChirho {
            template_id_chirho: "safe-template-chirho".to_string(),
            root_dag_chirho: dag_chirho,
            response_content_type_chirho: "text/html".to_string(),
        },
    )
    .unwrap();
    let path_chirho = template_registry_records_path_chirho(&root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    std::fs::write(
        &path_chirho,
        text_chirho.replace("safe-template-chirho", "unsafe-template-chirho"),
    )
    .unwrap();
    let tamper_error_chirho = verify_template_registry_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(tamper_error_chirho.contains("signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
