// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Private secret refs let host integrations resolve credentials without putting values in CAS or logs.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::CapabilityChirho;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SECRETS_DIR_CHIRHO: &str = "private-secrets-chirho";
const SECRET_SUFFIX_CHIRHO: &str = ".secret-chirho";

/// The refusal identity for a name whose SPELLING is not the name it RESOLVES.
///
/// This validator used to `trim()` the name and hand back the trimmed form, while every
/// distinctness law in the program compares the RAW string an operator supplied. A name differing
/// from an authority's name by one leading or trailing space therefore passed every "these refs
/// must be pairwise distinct" check and then resolved that authority's key — custody class
/// separation defeated by a space. Refusing surrounding whitespace outright is what makes those raw
/// comparisons sound, at the one place a name enters the system, rather than teaching every
/// comparison in the program to normalize.
pub const SECRET_NAME_SURROUNDING_WHITESPACE_REFUSAL_CHIRHO: &str =
    "secret name must not start or end with whitespace";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRefChirho {
    pub name_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInfoChirho {
    pub name_chirho: String,
    pub updated_ms_chirho: u64,
    pub bytes_chirho: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretValueChirho {
    bytes_chirho: Vec<u8>,
}

impl SecretValueChirho {
    pub fn as_bytes_chirho(&self) -> &[u8] {
        &self.bytes_chirho
    }

    pub fn into_string_chirho(mut self) -> Result<String> {
        Ok(String::from_utf8(std::mem::take(&mut self.bytes_chirho))?)
    }
}

impl Drop for SecretValueChirho {
    fn drop(&mut self) {
        self.bytes_chirho.fill(0);
    }
}

impl fmt::Debug for SecretValueChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        f_chirho.write_str("SecretValueChirho(<redacted>)")
    }
}

pub fn secret_ref_chirho(name_chirho: &str) -> Result<SecretRefChirho> {
    Ok(SecretRefChirho {
        name_chirho: validate_secret_name_chirho(name_chirho)?,
    })
}

pub fn secret_capability_chirho(name_chirho: &str) -> Result<CapabilityChirho> {
    Ok(CapabilityChirho::SecretRefChirho {
        name_chirho: validate_secret_name_chirho(name_chirho)?,
    })
}

pub fn set_secret_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    value_chirho: &[u8],
) -> Result<SecretRefChirho> {
    if value_chirho.is_empty() {
        bail!("secret value must not be empty");
    }
    let name_chirho = validate_secret_name_chirho(name_chirho)?;
    let dir_chirho = secrets_dir_chirho(root_chirho);
    create_private_dir_chirho(&dir_chirho)?;
    let path_chirho = secret_path_chirho(root_chirho, &name_chirho)?;
    write_private_secret_file_chirho(&path_chirho, value_chirho)?;
    Ok(SecretRefChirho { name_chirho })
}

pub fn resolve_secret_chirho(
    root_chirho: &Path,
    capability_chirho: &CapabilityChirho,
) -> Result<SecretValueChirho> {
    let CapabilityChirho::SecretRefChirho { name_chirho } = capability_chirho else {
        bail!("SecretRefChirho capability required to resolve a secret");
    };
    resolve_secret_ref_chirho(root_chirho, &secret_ref_chirho(name_chirho)?)
}

pub fn resolve_secret_ref_chirho(
    root_chirho: &Path,
    ref_chirho: &SecretRefChirho,
) -> Result<SecretValueChirho> {
    let name_chirho = validate_secret_name_chirho(&ref_chirho.name_chirho)?;
    let path_chirho = secret_path_chirho(root_chirho, &name_chirho)?;
    let bytes_chirho =
        std::fs::read(&path_chirho).with_context(|| format!("read secret {}", name_chirho))?;
    Ok(SecretValueChirho { bytes_chirho })
}

pub fn resolve_secret_string_chirho(root_chirho: &Path, name_chirho: &str) -> Result<String> {
    resolve_secret_chirho(root_chirho, &secret_capability_chirho(name_chirho)?)?
        .into_string_chirho()
}

pub fn list_secrets_chirho(root_chirho: &Path) -> Result<Vec<SecretInfoChirho>> {
    let dir_chirho = secrets_dir_chirho(root_chirho);
    if !dir_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut out_chirho = Vec::new();
    for entry_chirho in std::fs::read_dir(&dir_chirho)
        .with_context(|| format!("read secrets dir {}", dir_chirho.display()))?
    {
        let entry_chirho = entry_chirho?;
        let path_chirho = entry_chirho.path();
        if !path_chirho.is_file() {
            continue;
        }
        let Some(file_name_chirho) = path_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
        else {
            continue;
        };
        let Some(name_chirho) = file_name_chirho.strip_suffix(SECRET_SUFFIX_CHIRHO) else {
            continue;
        };
        let name_chirho = validate_secret_name_chirho(name_chirho)?;
        let meta_chirho = std::fs::metadata(&path_chirho)?;
        let updated_ms_chirho = meta_chirho
            .modified()
            .ok()
            .and_then(system_time_ms_chirho)
            .unwrap_or(0);
        out_chirho.push(SecretInfoChirho {
            name_chirho,
            updated_ms_chirho,
            bytes_chirho: meta_chirho.len(),
        });
    }
    out_chirho.sort_by(|a_chirho, b_chirho| a_chirho.name_chirho.cmp(&b_chirho.name_chirho));
    Ok(out_chirho)
}

fn secrets_dir_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(SECRETS_DIR_CHIRHO)
}

fn secret_path_chirho(root_chirho: &Path, name_chirho: &str) -> Result<PathBuf> {
    let name_chirho = validate_secret_name_chirho(name_chirho)?;
    Ok(secrets_dir_chirho(root_chirho).join(format!("{name_chirho}{SECRET_SUFFIX_CHIRHO}")))
}

fn validate_secret_name_chirho(name_chirho: &str) -> Result<String> {
    // FIRST, and never a trim: a name that is not already its own trimmed form would resolve a
    // DIFFERENT string than the caller supplied, and every distinctness law downstream compares the
    // supplied string. Refuse rather than normalize, so what a caller compares is what it resolves.
    if name_chirho != name_chirho.trim() {
        bail!("{SECRET_NAME_SURROUNDING_WHITESPACE_REFUSAL_CHIRHO}");
    }
    if name_chirho.is_empty() {
        bail!("secret name must not be empty");
    }
    if name_chirho.len() > 96 {
        bail!("secret name must be 96 bytes or less");
    }
    if name_chirho.starts_with('-') || name_chirho.ends_with('-') {
        bail!("secret name must not start or end with '-'");
    }
    if !name_chirho.bytes().all(|b_chirho| {
        b_chirho.is_ascii_lowercase() || b_chirho.is_ascii_digit() || b_chirho == b'-'
    }) {
        bail!("secret name may contain only lowercase ASCII letters, digits, and '-'");
    }
    Ok(name_chirho.to_string())
}

#[cfg(unix)]
fn create_private_dir_chirho(path_chirho: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path_chirho)?;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir_chirho(path_chirho: &Path) -> Result<()> {
    std::fs::create_dir_all(path_chirho)?;
    Ok(())
}

#[cfg(unix)]
fn write_private_secret_file_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    let mut file_chirho = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path_chirho)?;
    file_chirho.write_all(bytes_chirho)?;
    file_chirho.sync_all()?;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_secret_file_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> Result<()> {
    std::fs::write(path_chirho, bytes_chirho)?;
    Ok(())
}

fn system_time_ms_chirho(time_chirho: SystemTime) -> Option<u64> {
    time_chirho
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d_chirho| d_chirho.as_millis() as u64)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::cas_chirho;
    use cairn_tenant_chirho::tenant_chirho;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let now_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d_chirho| d_chirho.as_millis())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("cairn-secret-test-{n_chirho}-{now_chirho}"))
    }

    #[test]
    fn secret_ref_resolves_without_leaking_to_cas_or_logs_chirho() {
        let root_chirho = tmp_root_chirho();
        let secret_bytes_chirho = b"sk-test-secret-chirho";
        let ref_chirho =
            set_secret_chirho(&root_chirho, "openrouter-chirho", secret_bytes_chirho).unwrap();
        assert!(!serde_json::to_string(&ref_chirho)
            .unwrap()
            .contains("sk-test-secret-chirho"));
        cas_chirho::add_chirho(&root_chirho, b"ordinary object").unwrap();

        let value_chirho = resolve_secret_ref_chirho(&root_chirho, &ref_chirho).unwrap();
        assert_eq!(value_chirho.as_bytes_chirho(), secret_bytes_chirho);
        assert!(!non_secret_files_contain_chirho(&root_chirho, secret_bytes_chirho).unwrap());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn secret_resolution_requires_secret_ref_capability_chirho() {
        let root_chirho = tmp_root_chirho();
        set_secret_chirho(&root_chirho, "openrouter-chirho", b"sk-test").unwrap();
        let cap_chirho = secret_capability_chirho("openrouter-chirho").unwrap();
        assert_eq!(
            resolve_secret_chirho(&root_chirho, &cap_chirho)
                .unwrap()
                .as_bytes_chirho(),
            b"sk-test"
        );
        assert!(resolve_secret_chirho(&root_chirho, &CapabilityChirho::ClockChirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn tenant_roots_get_separate_secret_values_chirho() {
        let platform_root_chirho = tmp_root_chirho();
        let root_a_chirho =
            tenant_chirho::prepare_tenant_root_chirho(&platform_root_chirho, "tenant-a-chirho")
                .unwrap();
        let root_b_chirho =
            tenant_chirho::prepare_tenant_root_chirho(&platform_root_chirho, "tenant-b-chirho")
                .unwrap();
        set_secret_chirho(&root_a_chirho, "openrouter-chirho", b"secret-a").unwrap();
        set_secret_chirho(&root_b_chirho, "openrouter-chirho", b"secret-b").unwrap();

        assert_eq!(
            resolve_secret_string_chirho(&root_a_chirho, "openrouter-chirho").unwrap(),
            "secret-a"
        );
        assert_eq!(
            resolve_secret_string_chirho(&root_b_chirho, "openrouter-chirho").unwrap(),
            "secret-b"
        );
        let _ = std::fs::remove_dir_all(&platform_root_chirho);
    }

    /// A name differing from a live authority's name by ONE surrounding space must be REFUSED, not
    /// silently trimmed into that authority's key.
    ///
    /// The defect this pins: the validator used to `trim()`, so `" k-chirho"` and `"k-chirho"` were
    /// one key while every distinctness law in the program compares the RAW supplied strings and
    /// saw two different names. The fixture therefore violates the property directly — it tries to
    /// reach an already-provisioned authority key through a spelling no distinctness check can see.
    #[test]
    fn secret_names_refuse_surrounding_whitespace_instead_of_trimming_it_chirho() {
        let root_chirho = tmp_root_chirho();
        set_secret_chirho(&root_chirho, "authority-key-chirho", b"authority-value").unwrap();

        for hostile_chirho in [
            " authority-key-chirho",
            "authority-key-chirho ",
            "\tauthority-key-chirho",
            "authority-key-chirho\n",
        ] {
            let refusals_chirho = [
                secret_ref_chirho(hostile_chirho).err(),
                secret_capability_chirho(hostile_chirho).err(),
                set_secret_chirho(&root_chirho, hostile_chirho, b"attacker-value").err(),
                resolve_secret_string_chirho(&root_chirho, hostile_chirho).err(),
            ];
            for refusal_chirho in refusals_chirho {
                let message_chirho = refusal_chirho
                    .unwrap_or_else(|| {
                        panic!("{hostile_chirho:?} must be refused, never trimmed into a key")
                    })
                    .to_string();
                assert!(
                    message_chirho.contains(SECRET_NAME_SURROUNDING_WHITESPACE_REFUSAL_CHIRHO),
                    "{hostile_chirho:?} must fire the surrounding-whitespace law, got {message_chirho}"
                );
                // The whitespace law fired, and not one of its neighbors in the same validator.
                for neighbor_chirho in [
                    "secret name must not be empty",
                    "secret name must be 96 bytes or less",
                    "secret name must not start or end with '-'",
                    "secret name may contain only lowercase",
                ] {
                    assert!(
                        !message_chirho.contains(neighbor_chirho),
                        "the whitespace law was confused with {neighbor_chirho}: {message_chirho}"
                    );
                }
            }
        }

        // Positive control, and the money-shaped consequence: the same name WITHOUT the whitespace
        // still resolves, no hostile spelling overwrote it, and no second file was created.
        assert_eq!(
            resolve_secret_string_chirho(&root_chirho, "authority-key-chirho").unwrap(),
            "authority-value"
        );
        let listed_chirho = list_secrets_chirho(&root_chirho).unwrap();
        assert_eq!(listed_chirho.len(), 1);
        assert_eq!(listed_chirho[0].name_chirho, "authority-key-chirho");

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    /// INTERIOR whitespace was already invalid before the surrounding-whitespace law existed —
    /// measured here rather than assumed, and it must keep firing its OWN (charset) law, so the
    /// new law is proven to have taken over exactly the cases `trim()` used to swallow.
    #[test]
    fn secret_names_refuse_interior_whitespace_by_the_pre_existing_charset_law_chirho() {
        let message_chirho = secret_ref_chirho("authority key chirho")
            .unwrap_err()
            .to_string();
        assert!(
            message_chirho.contains("secret name may contain only lowercase"),
            "interior whitespace must fire the charset law, got {message_chirho}"
        );
        assert!(
            !message_chirho.contains(SECRET_NAME_SURROUNDING_WHITESPACE_REFUSAL_CHIRHO),
            "interior whitespace is not the surrounding-whitespace law: {message_chirho}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_private_chirho() {
        use std::os::unix::fs::PermissionsExt;

        let root_chirho = tmp_root_chirho();
        set_secret_chirho(&root_chirho, "openrouter-chirho", b"sk-test").unwrap();
        let dir_mode_chirho = std::fs::metadata(secrets_dir_chirho(&root_chirho))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode_chirho =
            std::fs::metadata(secret_path_chirho(&root_chirho, "openrouter-chirho").unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
        assert_eq!(dir_mode_chirho, 0o700);
        assert_eq!(file_mode_chirho, 0o600);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    fn non_secret_files_contain_chirho(root_chirho: &Path, needle_chirho: &[u8]) -> Result<bool> {
        let mut stack_chirho = vec![root_chirho.to_path_buf()];
        while let Some(path_chirho) = stack_chirho.pop() {
            if path_chirho
                .file_name()
                .and_then(|name_chirho| name_chirho.to_str())
                == Some(SECRETS_DIR_CHIRHO)
            {
                continue;
            }
            if path_chirho.is_dir() {
                for entry_chirho in std::fs::read_dir(&path_chirho)? {
                    stack_chirho.push(entry_chirho?.path());
                }
                continue;
            }
            if path_chirho.is_file() {
                let bytes_chirho = std::fs::read(&path_chirho)?;
                if bytes_chirho
                    .windows(needle_chirho.len())
                    .any(|window_chirho| window_chirho == needle_chirho)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
