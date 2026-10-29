// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use cairn_chirho::cas_chirho;
use cairn_core_chirho::ports_chirho::{
    record_hash_chirho, AuditLogChirho, AuditRecordChirho, ContentReadChirho, ContentStoreChirho,
};
use cairn_store_fs_chirho::{FsAuditLogChirho, FsContentStoreChirho};
use std::fs;
use std::path::PathBuf;
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
    let root_chirho =
        std::env::temp_dir().join(format!("cairn-cross-impl-store-{nanos_chirho}-{n_chirho}"));
    let _ = fs::remove_dir_all(&root_chirho);
    fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

#[test]
fn prototype_cas_and_fs_adapter_share_objects_and_provenance_chirho() {
    let root_chirho = tmp_root_chirho();
    let fs_store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
    let fs_audit_chirho = FsAuditLogChirho::new_chirho(&root_chirho);

    let prototype_bytes_chirho =
        br#"{"schema_chirho":"prototype-cas-parity-v1-chirho","writer_chirho":"cas"}"#;
    let prototype_addr_chirho =
        cas_chirho::add_chirho(&root_chirho, prototype_bytes_chirho).unwrap();
    assert_eq!(
        prototype_addr_chirho,
        cas_chirho::hash_chirho(prototype_bytes_chirho)
    );
    assert_eq!(
        fs_store_chirho
            .get_chirho(&prototype_addr_chirho)
            .unwrap()
            .as_deref(),
        Some(&prototype_bytes_chirho[..])
    );

    let adapter_bytes_chirho =
        br#"{"schema_chirho":"prototype-cas-parity-v1-chirho","writer_chirho":"fs-adapter"}"#;
    let adapter_addr_chirho = fs_store_chirho.put_chirho(adapter_bytes_chirho).unwrap();
    assert_eq!(
        adapter_addr_chirho,
        cas_chirho::hash_chirho(adapter_bytes_chirho)
    );
    assert_eq!(
        cas_chirho::get_chirho(&root_chirho, &adapter_addr_chirho).unwrap(),
        adapter_bytes_chirho
    );
    assert_eq!(
        fs_store_chirho.put_chirho(prototype_bytes_chirho).unwrap(),
        prototype_addr_chirho
    );

    let payload_chirho = serde_json::json!({
        "schema_chirho": "cross-implementation-store-provenance-v1-chirho",
        "prototype_written_hash_chirho": prototype_addr_chirho.0,
        "adapter_written_hash_chirho": adapter_addr_chirho.0,
    })
    .to_string()
    .into_bytes();
    let writer_chirho = "cross-implementation-store-test-chirho";
    let audit_head_chirho = fs_audit_chirho
        .append_chirho(writer_chirho, &payload_chirho)
        .unwrap();
    let expected_record_chirho =
        AuditRecordChirho::new_chirho(writer_chirho, 0, None, payload_chirho);
    assert_eq!(
        audit_head_chirho,
        record_hash_chirho(&expected_record_chirho).unwrap()
    );
    assert_eq!(
        fs_audit_chirho.get_chirho(&audit_head_chirho).unwrap(),
        Some(expected_record_chirho)
    );
    assert_eq!(
        fs_audit_chirho.heads_chirho().unwrap(),
        vec![audit_head_chirho]
    );

    let _ = fs::remove_dir_all(&root_chirho);
}
