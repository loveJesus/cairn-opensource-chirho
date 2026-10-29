// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use std::path::PathBuf;

fn temp_root_chirho(name_chirho: &str) -> PathBuf {
    let stamp_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-ha1-appstate-{name_chirho}-{}-{stamp_chirho}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

#[test]
fn runtime_state_records_tenant_root_marker_chirho() {
    let platform_root_chirho = temp_root_chirho("tenant");
    let tenant_root_chirho = tenant_chirho::root_for_tenant_chirho(
        &platform_root_chirho,
        &tenant_chirho::TenantIdChirho::TenantChirho("ha1-tenant-chirho".to_string()),
    )
    .unwrap();
    let state_chirho = app_state_for_runtime_root_chirho(
        &tenant_root_chirho,
        3,
        String::new(),
        false,
        ServedRequestAbuseLimitsChirho::default(),
    )
    .unwrap();
    assert_eq!(
        state_chirho.tenant_chirho,
        tenant_chirho::TenantIdChirho::TenantChirho("ha1-tenant-chirho".to_string())
    );
    assert_eq!(
        state_chirho.runtime_chirho.root_path_chirho(),
        &tenant_root_chirho
    );

    let _ = std::fs::remove_dir_all(&platform_root_chirho);
}

#[test]
fn runtime_state_records_platform_root_when_marker_absent_chirho() {
    let root_chirho = temp_root_chirho("platform");
    let state_chirho = app_state_for_runtime_root_chirho(
        &root_chirho,
        3,
        String::new(),
        false,
        ServedRequestAbuseLimitsChirho::default(),
    )
    .unwrap();
    assert_eq!(
        state_chirho.tenant_chirho,
        tenant_chirho::TenantIdChirho::PlatformRootChirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn runtime_state_rejects_corrupt_tenant_marker_chirho() {
    let root_chirho = temp_root_chirho("corrupt");
    std::fs::write(
        root_chirho.join(tenant_chirho::TENANT_MARKER_CHIRHO),
        br#"{"tenant_id_chirho":"Tenant Bad"}"#,
    )
    .unwrap();
    let error_chirho = match app_state_for_runtime_root_chirho(
        &root_chirho,
        3,
        String::new(),
        false,
        ServedRequestAbuseLimitsChirho::default(),
    ) {
        Ok(_) => panic!("corrupt tenant marker unexpectedly built runtime state"),
        Err(error_chirho) => error_chirho,
    };
    assert!(error_chirho
        .to_string()
        .contains("tenant_chirho may contain only lowercase ASCII"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
