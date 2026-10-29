// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Tenant roots keep one tenant's whole store outside another tenant's reach.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::CapabilityChirho;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const TENANTS_DIR_CHIRHO: &str = "tenants-chirho";
pub const TENANT_MARKER_CHIRHO: &str = "tenant-chirho.json";
const TENANT_MARKER_MAX_BYTES_CHIRHO: usize = 512;

/// The directory a geo genesis writes its immutable intent marker into, on the operator guard root and
/// on every member root, before any ledger mutation. Its presence marks a root as geo-born; it is the
/// control-plane law's evidence E2 (C2.1). Defined here, beside the other root markers, so the
/// writer-head evidence probe and the genesis crate name one constant.
pub const GEO_GENESIS_GUARD_DIR_CHIRHO: &str = "geo-genesis-guard-chirho";

/// The create-new record naming the control-plane role pin and the lineage a geo root signs under: the
/// control-plane law's evidence E3 (C2.1). The first lineage-law signing publishes it; a verification
/// never writes it.
pub const CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO: &str = "control-plane-law-chirho.json";

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantMarkerChirho {
    pub tenant_id_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", content = "id_chirho", rename_all = "kebab-case")]
pub enum TenantIdChirho {
    TenantChirho(String),
    PlatformRootChirho,
}

impl std::fmt::Display for TenantIdChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TenantChirho(id_chirho) => write!(f, "tenant:{}", id_chirho),
            Self::PlatformRootChirho => write!(f, "platform-root"),
        }
    }
}

impl TenantIdChirho {
    pub fn validate(&self) -> Result<Self> {
        match self {
            Self::TenantChirho(id_chirho) => {
                let validated_chirho = validate_tenant_id_chirho(id_chirho)?;
                Ok(Self::TenantChirho(validated_chirho))
            }
            Self::PlatformRootChirho => Ok(Self::PlatformRootChirho),
        }
    }

    pub fn as_tenant_id_chirho(&self) -> Option<&str> {
        match self {
            Self::TenantChirho(id_chirho) => Some(id_chirho),
            Self::PlatformRootChirho => None,
        }
    }

    pub fn into_tenant_id_chirho(self) -> Option<String> {
        match self {
            Self::TenantChirho(id_chirho) => Some(id_chirho),
            Self::PlatformRootChirho => None,
        }
    }

    pub fn is_platform_root_chirho(&self) -> bool {
        matches!(self, Self::PlatformRootChirho)
    }
}

pub fn tenant_id_from_optional_chirho(tenant_id_chirho: Option<&str>) -> Result<TenantIdChirho> {
    match tenant_id_chirho {
        Some(tenant_id_chirho) if !tenant_id_chirho.trim().is_empty() => Ok(
            TenantIdChirho::TenantChirho(validate_tenant_id_chirho(tenant_id_chirho)?),
        ),
        _ => Ok(TenantIdChirho::PlatformRootChirho),
    }
}

pub fn tenant_id_with_fallback_chirho(
    tenant_id_chirho: &TenantIdChirho,
    fallback_chirho: Option<&str>,
) -> Result<TenantIdChirho> {
    match tenant_id_chirho {
        TenantIdChirho::TenantChirho(_) => tenant_id_chirho.validate(),
        TenantIdChirho::PlatformRootChirho => tenant_id_from_optional_chirho(fallback_chirho),
    }
}

pub fn validate_tenant_id_chirho(tenant_id_chirho: &str) -> Result<String> {
    let tenant_id_chirho = tenant_id_chirho.trim();
    if tenant_id_chirho.is_empty() {
        bail!("tenant_chirho must not be empty");
    }
    if tenant_id_chirho.len() > 64 {
        bail!("tenant_chirho must be 64 bytes or less");
    }
    if tenant_id_chirho == "." || tenant_id_chirho == ".." {
        bail!("tenant_chirho must be a plain id, not a path segment");
    }
    if tenant_id_chirho.starts_with('-') || tenant_id_chirho.ends_with('-') {
        bail!("tenant_chirho must not start or end with '-'");
    }
    if !tenant_id_chirho.bytes().all(|b_chirho| {
        b_chirho.is_ascii_lowercase() || b_chirho.is_ascii_digit() || b_chirho == b'-'
    }) {
        bail!("tenant_chirho may contain only lowercase ASCII letters, digits, and '-'");
    }
    Ok(tenant_id_chirho.to_string())
}

pub fn tenant_root_chirho(platform_root_chirho: &Path, tenant_id_chirho: &str) -> Result<PathBuf> {
    let tenant_id_chirho = validate_tenant_id_chirho(tenant_id_chirho)?;
    Ok(platform_root_chirho
        .join(TENANTS_DIR_CHIRHO)
        .join(tenant_id_chirho))
}

pub fn prepare_tenant_root_chirho(
    platform_root_chirho: &Path,
    tenant_id_chirho: &str,
) -> Result<PathBuf> {
    let tenant_id_chirho = validate_tenant_id_chirho(tenant_id_chirho)?;
    let tenants_dir_chirho = platform_root_chirho.join(TENANTS_DIR_CHIRHO);
    std::fs::create_dir_all(&tenants_dir_chirho)
        .with_context(|| format!("create tenants dir {}", tenants_dir_chirho.display()))?;
    let tenants_dir_canon_chirho = tenants_dir_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize tenants dir {}", tenants_dir_chirho.display()))?;
    let root_chirho = tenant_root_chirho(platform_root_chirho, &tenant_id_chirho)?;
    std::fs::create_dir_all(&root_chirho)
        .with_context(|| format!("create tenant root {}", root_chirho.display()))?;
    let root_canon_chirho = root_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize tenant root {}", root_chirho.display()))?;
    if root_canon_chirho.parent() != Some(tenants_dir_canon_chirho.as_path())
        || root_canon_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
            != Some(tenant_id_chirho.as_str())
    {
        bail!(
            "tenant root {} escapes {}",
            root_canon_chirho.display(),
            tenants_dir_canon_chirho.display()
        );
    }
    let marker_path_chirho = tenant_marker_path_chirho(&root_chirho);
    if tenant_marker_entry_chirho(&marker_path_chirho)?.is_none() {
        let marker_chirho = TenantMarkerChirho {
            tenant_id_chirho: tenant_id_chirho.clone(),
        };
        let marker_bytes_chirho = serde_json::to_vec_pretty(&marker_chirho)?;
        if !create_tenant_marker_chirho(&marker_path_chirho, &marker_bytes_chirho)? {
            validate_tenant_marker_owner_chirho(&root_chirho, &tenant_id_chirho)?;
        }
    } else {
        validate_tenant_marker_owner_chirho(&root_chirho, &tenant_id_chirho)?;
    }
    Ok(root_chirho)
}

pub fn root_for_tenant_chirho(
    root_chirho: &Path,
    tenant_id_chirho: &TenantIdChirho,
) -> Result<PathBuf> {
    match tenant_id_chirho.validate()? {
        TenantIdChirho::TenantChirho(tenant_id_chirho) => {
            prepare_tenant_root_chirho(root_chirho, &tenant_id_chirho)
        }
        TenantIdChirho::PlatformRootChirho => Ok(root_chirho.to_path_buf()),
    }
}

pub fn tenant_id_for_root_chirho(root_chirho: &Path) -> Result<TenantIdChirho> {
    let marker_path_chirho = tenant_marker_path_chirho(root_chirho);
    if tenant_marker_entry_chirho(&marker_path_chirho)?.is_none() {
        return Ok(TenantIdChirho::PlatformRootChirho);
    }
    let marker_chirho: TenantMarkerChirho =
        serde_json::from_slice(&read_bounded_tenant_marker_chirho(&marker_path_chirho)?)
            .with_context(|| format!("decode tenant marker {}", marker_path_chirho.display()))?;
    let validated_chirho = validate_tenant_id_chirho(&marker_chirho.tenant_id_chirho)?;
    Ok(TenantIdChirho::TenantChirho(validated_chirho))
}

pub fn validated_store_key_for_root_chirho(root_chirho: &Path, key_chirho: &str) -> Result<String> {
    let key_chirho = validate_store_key_chirho(key_chirho)?;
    // Legacy roots have no marker; tenant roots fail closed if the marker is corrupt.
    tenant_id_for_root_chirho(root_chirho)?;
    Ok(key_chirho.to_string())
}

pub fn assert_capability_tenant_chirho(
    root_chirho: &Path,
    capability_chirho: &CapabilityChirho,
) -> Result<()> {
    match capability_chirho {
        CapabilityChirho::ReadStoreChirho { prefix_chirho }
        | CapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            validated_store_key_for_root_chirho(root_chirho, prefix_chirho)?;
        }
        _ => {}
    }
    Ok(())
}

fn tenant_marker_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(TENANT_MARKER_CHIRHO)
}

fn tenant_marker_entry_chirho(marker_path_chirho: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(marker_path_chirho) {
        Ok(metadata_chirho) => Ok(Some(metadata_chirho)),
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(None),
        Err(error_chirho) => Err(error_chirho)
            .with_context(|| format!("inspect tenant marker {}", marker_path_chirho.display())),
    }
}

fn validate_tenant_marker_owner_chirho(root_chirho: &Path, tenant_id_chirho: &str) -> Result<()> {
    match tenant_id_for_root_chirho(root_chirho)? {
        TenantIdChirho::TenantChirho(existing_id_chirho)
            if existing_id_chirho == tenant_id_chirho =>
        {
            Ok(())
        }
        TenantIdChirho::TenantChirho(existing_id_chirho) => bail!(
            "tenant root {} is marked for '{}' not '{}'",
            root_chirho.display(),
            existing_id_chirho,
            tenant_id_chirho
        ),
        TenantIdChirho::PlatformRootChirho => bail!(
            "tenant root {} has invalid/missing tenant ID marker",
            root_chirho.display()
        ),
    }
}

fn create_tenant_marker_chirho(marker_path_chirho: &Path, bytes_chirho: &[u8]) -> Result<bool> {
    let mut options_chirho = std::fs::OpenOptions::new();
    options_chirho.write(true).create_new(true);
    #[cfg(unix)]
    options_chirho.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut marker_file_chirho = match options_chirho.open(marker_path_chirho) {
        Ok(marker_file_chirho) => marker_file_chirho,
        Err(error_chirho) if error_chirho.kind() == ErrorKind::AlreadyExists => return Ok(false),
        Err(error_chirho) => {
            return Err(error_chirho)
                .with_context(|| format!("create tenant marker {}", marker_path_chirho.display()))
        }
    };
    marker_file_chirho
        .write_all(bytes_chirho)
        .with_context(|| format!("write tenant marker {}", marker_path_chirho.display()))?;
    marker_file_chirho
        .sync_all()
        .with_context(|| format!("sync tenant marker {}", marker_path_chirho.display()))?;
    Ok(true)
}

#[cfg(test)]
std::thread_local! {
    static TENANT_MARKER_PRE_OPEN_TEST_HOOK_CHIRHO:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
fn install_tenant_marker_pre_open_test_hook_chirho(hook_chirho: impl FnOnce() + 'static) {
    TENANT_MARKER_PRE_OPEN_TEST_HOOK_CHIRHO.with(|slot_chirho| {
        assert!(slot_chirho.borrow().is_none());
        *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho));
    });
}

#[cfg(test)]
fn run_tenant_marker_pre_open_test_hook_chirho() {
    let hook_chirho =
        TENANT_MARKER_PRE_OPEN_TEST_HOOK_CHIRHO.with(|slot_chirho| slot_chirho.borrow_mut().take());
    if let Some(hook_chirho) = hook_chirho {
        hook_chirho();
    }
}

fn read_bounded_tenant_marker_chirho(marker_path_chirho: &Path) -> Result<Vec<u8>> {
    let path_metadata_chirho = std::fs::symlink_metadata(marker_path_chirho)
        .with_context(|| format!("inspect tenant marker {}", marker_path_chirho.display()))?;
    if path_metadata_chirho.file_type().is_symlink() || !path_metadata_chirho.is_file() {
        bail!("tenant marker must be a regular non-symlink file");
    }
    #[cfg(test)]
    run_tenant_marker_pre_open_test_hook_chirho();
    let mut options_chirho = std::fs::OpenOptions::new();
    options_chirho.read(true);
    #[cfg(unix)]
    options_chirho.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let marker_file_chirho = options_chirho
        .open(marker_path_chirho)
        .with_context(|| format!("open tenant marker {}", marker_path_chirho.display()))?;
    let metadata_chirho = marker_file_chirho.metadata().with_context(|| {
        format!(
            "inspect opened tenant marker {}",
            marker_path_chirho.display()
        )
    })?;
    #[cfg(unix)]
    if path_metadata_chirho.dev() != metadata_chirho.dev()
        || path_metadata_chirho.ino() != metadata_chirho.ino()
        || metadata_chirho.nlink() != 1
    {
        bail!("tenant marker changed identity or has a filesystem alias");
    }
    if !metadata_chirho.is_file()
        || metadata_chirho.len() == 0
        || metadata_chirho.len() > TENANT_MARKER_MAX_BYTES_CHIRHO as u64
    {
        bail!("tenant marker exceeds its bounded encoding");
    }
    let mut bytes_chirho = Vec::with_capacity(metadata_chirho.len() as usize);
    marker_file_chirho
        .take((TENANT_MARKER_MAX_BYTES_CHIRHO + 1) as u64)
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read tenant marker {}", marker_path_chirho.display()))?;
    if bytes_chirho.len() > TENANT_MARKER_MAX_BYTES_CHIRHO {
        bail!("tenant marker exceeds its bounded encoding");
    }
    let final_path_metadata_chirho = std::fs::symlink_metadata(marker_path_chirho)
        .with_context(|| format!("reinspect tenant marker {}", marker_path_chirho.display()))?;
    if final_path_metadata_chirho.file_type().is_symlink() || !final_path_metadata_chirho.is_file()
    {
        bail!("tenant marker changed after its descriptor was opened");
    }
    #[cfg(unix)]
    if final_path_metadata_chirho.dev() != metadata_chirho.dev()
        || final_path_metadata_chirho.ino() != metadata_chirho.ino()
    {
        bail!("tenant marker pathname changed during its bounded read");
    }
    Ok(bytes_chirho)
}

fn validate_store_key_chirho(key_chirho: &str) -> Result<&str> {
    if key_chirho.is_empty() {
        bail!("store key must not be empty");
    }
    if key_chirho.as_bytes().contains(&0) {
        bail!("store key must not contain NUL");
    }
    if key_chirho.starts_with('/') || key_chirho.starts_with('\\') || key_chirho.contains('\\') {
        bail!("store key must be relative and use '/' separators");
    }
    if key_chirho
        .split('/')
        .any(|part_chirho| part_chirho.is_empty() || part_chirho == "." || part_chirho == "..")
    {
        bail!("store key must not contain empty, '.', or '..' path segments");
    }
    Ok(key_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let now_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d_chirho| d_chirho.as_millis())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("cairn-tenant-test-{n_chirho}-{now_chirho}"))
    }

    #[test]
    fn tenant_ids_are_plain_path_segments_chirho() {
        assert!(validate_tenant_id_chirho("tenant-a-chirho").is_ok());
        assert!(validate_tenant_id_chirho("").is_err());
        assert!(validate_tenant_id_chirho("../tenant").is_err());
        assert!(validate_tenant_id_chirho("..%2ftenant").is_err());
        assert!(validate_tenant_id_chirho("a/../../b").is_err());
        assert!(validate_tenant_id_chirho("/tenant").is_err());
        assert!(validate_tenant_id_chirho("Tenant-A-Chirho").is_err());
        assert!(validate_tenant_id_chirho("-tenant").is_err());
        assert!(validate_tenant_id_chirho("tenant.").is_err());
        assert!(validate_tenant_id_chirho("tenant space").is_err());
    }

    #[test]
    fn optional_tenant_text_becomes_explicit_scope_chirho() {
        assert_eq!(
            tenant_id_from_optional_chirho(None).unwrap(),
            TenantIdChirho::PlatformRootChirho
        );
        assert_eq!(
            tenant_id_from_optional_chirho(Some("   ")).unwrap(),
            TenantIdChirho::PlatformRootChirho
        );
        assert_eq!(
            tenant_id_from_optional_chirho(Some(" tenant-a-chirho ")).unwrap(),
            TenantIdChirho::TenantChirho("tenant-a-chirho".to_string())
        );
        assert!(tenant_id_from_optional_chirho(Some("Tenant-A-Chirho")).is_err());
    }

    #[test]
    fn root_for_tenant_validates_constructed_tenant_id_chirho() {
        let platform_root_chirho = tmp_root_chirho();
        assert_eq!(
            root_for_tenant_chirho(&platform_root_chirho, &TenantIdChirho::PlatformRootChirho)
                .unwrap(),
            platform_root_chirho
        );
        assert!(root_for_tenant_chirho(
            &platform_root_chirho,
            &TenantIdChirho::TenantChirho("bad/tenant".to_string())
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&platform_root_chirho);
    }

    #[test]
    fn tenant_store_keys_reject_path_traversal_chirho() {
        let platform_root_chirho = tmp_root_chirho();
        let root_a_chirho =
            prepare_tenant_root_chirho(&platform_root_chirho, "tenant-a-chirho").unwrap();
        assert_eq!(
            validated_store_key_for_root_chirho(&root_a_chirho, "app-data/msg").unwrap(),
            "app-data/msg"
        );
        assert!(validated_store_key_for_root_chirho(&root_a_chirho, "../msg").is_err());
        assert!(validated_store_key_for_root_chirho(&root_a_chirho, "app/../msg").is_err());
        assert!(validated_store_key_for_root_chirho(&root_a_chirho, "/msg").is_err());
        assert!(validated_store_key_for_root_chirho(&root_a_chirho, "app//msg").is_err());
        assert!(validated_store_key_for_root_chirho(&root_a_chirho, r"app\msg").is_err());
        let _ = std::fs::remove_dir_all(&platform_root_chirho);
    }

    #[test]
    fn tenant_marker_read_refuses_oversized_or_non_file_inputs_chirho() {
        let platform_root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&platform_root_chirho).unwrap();
        let marker_path_chirho = tenant_marker_path_chirho(&platform_root_chirho);
        std::fs::write(
            &marker_path_chirho,
            vec![b'x'; TENANT_MARKER_MAX_BYTES_CHIRHO + 1],
        )
        .unwrap();
        assert!(tenant_id_for_root_chirho(&platform_root_chirho).is_err());
        std::fs::remove_file(&marker_path_chirho).unwrap();
        std::fs::create_dir(&marker_path_chirho).unwrap();
        assert!(tenant_id_for_root_chirho(&platform_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(&platform_root_chirho);
    }

    #[cfg(unix)]
    #[test]
    fn tenant_marker_read_refuses_dangling_racing_and_hardlink_aliases_chirho() {
        use std::os::unix::fs::symlink;

        let platform_root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&platform_root_chirho).unwrap();
        let marker_path_chirho = tenant_marker_path_chirho(&platform_root_chirho);
        symlink("missing-tenant-marker-chirho", &marker_path_chirho).unwrap();
        assert!(tenant_id_for_root_chirho(&platform_root_chirho).is_err());
        std::fs::remove_file(&marker_path_chirho).unwrap();

        let valid_bytes_chirho = serde_json::to_vec(&TenantMarkerChirho {
            tenant_id_chirho: "tenant-a-chirho".to_owned(),
        })
        .unwrap();
        std::fs::write(&marker_path_chirho, &valid_bytes_chirho).unwrap();
        let hardlink_alias_chirho = platform_root_chirho.join("marker-hardlink-alias-chirho.json");
        std::fs::hard_link(&marker_path_chirho, &hardlink_alias_chirho).unwrap();
        assert!(tenant_id_for_root_chirho(&platform_root_chirho).is_err());
        std::fs::remove_file(hardlink_alias_chirho).unwrap();
        let replacement_chirho = platform_root_chirho.join("replacement-marker-chirho.json");
        std::fs::write(&replacement_chirho, valid_bytes_chirho).unwrap();
        let backup_chirho = platform_root_chirho.join("original-marker-chirho.json");
        let hook_marker_chirho = marker_path_chirho.clone();
        install_tenant_marker_pre_open_test_hook_chirho(move || {
            std::fs::rename(&hook_marker_chirho, backup_chirho).unwrap();
            symlink(replacement_chirho, hook_marker_chirho).unwrap();
        });
        assert!(tenant_id_for_root_chirho(&platform_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(&platform_root_chirho);
    }

    #[cfg(unix)]
    #[test]
    fn tenant_root_derivation_rejects_symlink_escape_chirho() {
        use std::os::unix::fs::symlink;

        let platform_root_chirho = tmp_root_chirho();
        let root_b_chirho =
            prepare_tenant_root_chirho(&platform_root_chirho, "tenant-b-chirho").unwrap();
        let tenant_a_path_chirho = platform_root_chirho
            .join(TENANTS_DIR_CHIRHO)
            .join("tenant-a-chirho");
        symlink(&root_b_chirho, &tenant_a_path_chirho).unwrap();
        assert!(prepare_tenant_root_chirho(&platform_root_chirho, "tenant-a-chirho").is_err());
        let _ = std::fs::remove_dir_all(&platform_root_chirho);
    }
}
