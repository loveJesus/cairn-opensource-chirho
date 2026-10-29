// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::gate1_anchor_chirho::{
    load_gate1_anchor_records_chirho, verify_gate1_anchor_head_replication_text_chirho,
};
use cairn_chirho::replication_source_export_chirho::prepare_replication_source_chirho;
use cairn_core_chirho::model_chirho::{HashChirho, RefsChirho};
use cairn_core_chirho::ports_chirho::ContentStoreChirho;
use cairn_core_chirho::refs_chirho::save_refs_chirho;
use cairn_replication_chirho::ref_snapshot_chirho::{
    read_verified_snapshot_heads_chirho, REF_SNAPSHOT_LOG_FILE_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nonce_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-source-export-{label_chirho}-{}-{nonce_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

#[test]
fn live_root_export_uses_real_zero_row_gate1_anchors_and_signed_snapshot_chirho() {
    let root_chirho = tmp_root_chirho("complete");
    let source_key_chirho = signer_chirho::pubkey_hex_chirho(&root_chirho).unwrap();
    let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
    let app_target_chirho = store_chirho.put_chirho(b"demo app target chirho").unwrap();
    let route_target_chirho = store_chirho
        .put_chirho(b"demo route target chirho")
        .unwrap();
    let mut branches_chirho = BTreeMap::new();
    branches_chirho.insert("app/demo-chirho".to_string(), app_target_chirho);
    branches_chirho.insert(
        "app-route/demo-chirho/root-chirho".to_string(),
        route_target_chirho,
    );
    branches_chirho.insert(
        "pricebook/demo-chirho".to_string(),
        HashChirho("a".repeat(64)),
    );
    save_refs_chirho(
        &root_chirho,
        &RefsChirho {
            branches_chirho,
            tags_chirho: BTreeMap::new(),
            head_chirho: "main".to_string(),
        },
    )
    .unwrap();

    let head_path_chirho = root_chirho
        .join("operator-output-chirho")
        .join("gate1-head-chirho.json");
    let report_chirho =
        prepare_replication_source_chirho(&root_chirho, &head_path_chirho, 1_234).unwrap();

    assert_eq!(report_chirho.gate1_anchor_records_appended_chirho, 8);
    assert_eq!(report_chirho.gate1_anchor_record_count_chirho, 8);
    assert_eq!(report_chirho.ref_snapshot_ref_count_chirho, 2);
    assert!(report_chirho.ref_snapshot_appended_chirho);
    assert_eq!(report_chirho.source_key_id_chirho, source_key_chirho);

    let anchors_chirho = load_gate1_anchor_records_chirho(&root_chirho).unwrap();
    assert_eq!(anchors_chirho.len(), 8);
    assert!(anchors_chirho
        .iter()
        .all(|anchor_chirho| anchor_chirho.line_count_chirho == 0));

    let head_text_chirho = std::fs::read_to_string(&head_path_chirho).unwrap();
    let verified_head_chirho =
        verify_gate1_anchor_head_replication_text_chirho(&root_chirho, &head_text_chirho).unwrap();
    assert_eq!(
        verified_head_chirho.record_chirho.key_id_chirho,
        source_key_chirho
    );
    let snapshot_log_chirho =
        std::fs::read(root_chirho.join(REF_SNAPSHOT_LOG_FILE_CHIRHO)).unwrap();
    let snapshot_heads_chirho =
        read_verified_snapshot_heads_chirho(&snapshot_log_chirho, &source_key_chirho).unwrap();
    assert_eq!(snapshot_heads_chirho.len(), 1);
    assert_eq!(snapshot_heads_chirho[0].ref_count_chirho, 2);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn source_export_refuses_to_mint_a_key_for_an_uninitialized_root_chirho() {
    let root_chirho = tmp_root_chirho("no-key");
    let message_chirho =
        prepare_replication_source_chirho(&root_chirho, &root_chirho.join("head-chirho.json"), 1)
            .expect_err("export must require an existing source key")
            .to_string();
    assert!(
        message_chirho.contains("ReplicationSourceExistingKeyRefusedChirho"),
        "{message_chirho}"
    );
    assert!(!root_chirho.join("signing-key-chirho.bin").exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}
