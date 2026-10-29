// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct KeyWriteRootChirho {
    pub(super) path_chirho: PathBuf,
    #[cfg(unix)]
    original_key_directory_permissions_chirho: Option<std::fs::Permissions>,
}

impl KeyWriteRootChirho {
    pub(super) fn new_chirho() -> Self {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let path_chirho = std::env::temp_dir().join(format!(
            "cairn-identity-key-write-{}-{nanos_chirho}-{counter_chirho}-chirho",
            std::process::id()
        ));
        std::fs::create_dir(&path_chirho).unwrap();
        Self {
            path_chirho,
            #[cfg(unix)]
            original_key_directory_permissions_chirho: None,
        }
    }

    #[cfg(unix)]
    pub(super) fn obstruct_key_directory_chirho(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let directory_chirho = identity_keys_dir_chirho(&self.path_chirho);
        self.original_key_directory_permissions_chirho =
            Some(std::fs::metadata(&directory_chirho).unwrap().permissions());
        std::fs::set_permissions(&directory_chirho, std::fs::Permissions::from_mode(0o500))
            .unwrap();
        let probe_chirho = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory_chirho.join("write-probe-chirho"))
            .expect_err(
                "this arm needs a non-root runner: the 0500 key directory allowed creation",
            );
        assert_eq!(probe_chirho.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    pub(super) fn restore_key_directory_chirho(&mut self) -> std::io::Result<()> {
        if let Some(permissions_chirho) = &self.original_key_directory_permissions_chirho {
            std::fs::set_permissions(
                identity_keys_dir_chirho(&self.path_chirho),
                permissions_chirho.clone(),
            )?;
            self.original_key_directory_permissions_chirho = None;
        }
        Ok(())
    }
}

impl Drop for KeyWriteRootChirho {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = self.restore_key_directory_chirho();
        let _ = std::fs::remove_dir_all(&self.path_chirho);
    }
}

#[cfg(unix)]
#[test]
fn credential_set_preserves_an_open_key_snapshot_and_the_signing_identity_chirho() {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let root_chirho = KeyWriteRootChirho::new_chirho();
    let root_chirho = &root_chirho.path_chirho;
    let identity_chirho =
        register_identity_chirho(root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let principal_chirho = &identity_chirho.principal_chirho;
    let path_chirho = identity_key_path_chirho(root_chirho, principal_chirho);
    assert_eq!(
        std::fs::metadata(&path_chirho)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let before_chirho = std::fs::read(&path_chirho).unwrap();
    let prior_record_chirho =
        load_identity_key_record_chirho(root_chirho, principal_chirho).unwrap();
    let mut reader_chirho = std::fs::File::open(&path_chirho).unwrap();

    set_identity_credential_chirho(root_chirho, principal_chirho, "set-secret-value").unwrap();

    let mut held_snapshot_chirho = Vec::new();
    reader_chirho
        .read_to_end(&mut held_snapshot_chirho)
        .unwrap();
    assert_eq!(
        held_snapshot_chirho, before_chirho,
        "an already-open key reader must retain the complete prior record"
    );
    let after_chirho = std::fs::read(&path_chirho).unwrap();
    assert_ne!(
        after_chirho, before_chirho,
        "credential set must replace the key state"
    );
    let settled_chirho: IdentityKeyChirho = serde_json::from_slice(&after_chirho).unwrap();
    assert_eq!(
        settled_chirho.principal_chirho,
        prior_record_chirho.principal_chirho
    );
    assert_eq!(
        settled_chirho.secret_key_chirho,
        prior_record_chirho.secret_key_chirho
    );
    assert!(settled_chirho.credential_hash_chirho.is_some());
    assert_eq!(verify_identities_chirho(root_chirho).unwrap(), 1);
    assert!(login_identity_with_credential_chirho(
        root_chirho,
        principal_chirho,
        "set-secret-value"
    )
    .is_ok());
}

#[cfg(unix)]
#[test]
fn credential_reset_replaces_a_read_only_key_with_private_permissions_chirho() {
    use std::os::unix::fs::PermissionsExt;

    let root_chirho = KeyWriteRootChirho::new_chirho();
    let root_chirho = &root_chirho.path_chirho;
    let identity_chirho = register_identity_with_credential_chirho(
        root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = &identity_chirho.principal_chirho;
    let prior_record_chirho =
        load_identity_key_record_chirho(root_chirho, principal_chirho).unwrap();
    let path_chirho = identity_key_path_chirho(root_chirho, principal_chirho);
    std::fs::set_permissions(&path_chirho, std::fs::Permissions::from_mode(0o444)).unwrap();

    reset_identity_credential_chirho(
        root_chirho,
        principal_chirho,
        "second-secret-value",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap();

    assert_eq!(
        std::fs::metadata(&path_chirho)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "replacement must not inherit the prior key's public read permissions"
    );
    let settled_chirho = load_identity_key_record_chirho(root_chirho, principal_chirho).unwrap();
    assert_eq!(
        settled_chirho.secret_key_chirho,
        prior_record_chirho.secret_key_chirho
    );
    assert!(login_identity_with_credential_chirho(
        root_chirho,
        principal_chirho,
        "first-secret-value"
    )
    .is_err());
    assert!(login_identity_with_credential_chirho(
        root_chirho,
        principal_chirho,
        "second-secret-value"
    )
    .is_ok());
    assert_eq!(verify_credential_resets_chirho(root_chirho).unwrap(), 1);
}
