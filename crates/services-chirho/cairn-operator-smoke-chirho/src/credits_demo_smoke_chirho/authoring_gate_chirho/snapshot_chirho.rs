// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Captures every local Cargo package in the guest's locked metadata closure into one sealed tree.

use super::command_chirho::{run_trusted_cargo_chirho, TrustedCargoChirho};
use anyhow::{bail, Context, Result};
use cairn_chirho::cas_chirho;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_SOURCE_FILE_BYTES_CHIRHO: u64 = 16 * 1024 * 1024;
const MAX_SOURCE_CLOSURE_BYTES_CHIRHO: u64 = 128 * 1024 * 1024;
static SNAPSHOT_SEQUENCE_CHIRHO: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SourceTreeFingerprintChirho {
    pub blake3_chirho: String,
    pub entry_count_chirho: usize,
}

#[derive(Debug)]
pub(super) struct SourceSnapshotChirho {
    container_root_chirho: PathBuf,
    root_chirho: PathBuf,
    target_dir_chirho: PathBuf,
    package_roots_chirho: Vec<PathBuf>,
    fingerprint_chirho: SourceTreeFingerprintChirho,
    pub local_package_count_chirho: usize,
}

impl SourceSnapshotChirho {
    pub fn root_chirho(&self) -> &Path {
        &self.root_chirho
    }

    pub fn target_dir_chirho(&self) -> &Path {
        &self.target_dir_chirho
    }

    pub fn fingerprint_chirho(&self) -> &SourceTreeFingerprintChirho {
        &self.fingerprint_chirho
    }

    pub fn assert_unchanged_chirho(&self, step_chirho: &str) -> Result<()> {
        let actual_chirho = capture_closure_chirho(
            &self.container_root_chirho.join("repository-chirho"),
            &self.package_roots_chirho,
        )?
        .fingerprint_chirho;
        if actual_chirho != self.fingerprint_chirho {
            bail!("credits-demo source snapshot changed during authoring step '{step_chirho}'");
        }
        Ok(())
    }
}

impl Drop for SourceSnapshotChirho {
    fn drop(&mut self) {
        let _result_chirho = std::fs::remove_dir_all(&self.container_root_chirho);
    }
}

pub(super) fn snapshot_source_closure_chirho(
    app_root_chirho: &Path,
    cargo_chirho: &TrustedCargoChirho,
) -> Result<SourceSnapshotChirho> {
    let app_metadata_chirho = std::fs::symlink_metadata(app_root_chirho)
        .with_context(|| format!("inspect app root {}", app_root_chirho.display()))?;
    if app_metadata_chirho.file_type().is_symlink() {
        bail!(
            "credits-demo app root {} is a symlink",
            app_root_chirho.display()
        );
    }
    if !app_metadata_chirho.is_dir() {
        bail!(
            "credits-demo app root {} is not a directory",
            app_root_chirho.display()
        );
    }
    let canonical_app_root_chirho = app_root_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize app root {}", app_root_chirho.display()))?;
    let source_anchor_chirho = find_source_anchor_chirho(&canonical_app_root_chirho)?;
    let packages_before_chirho = discover_local_packages_chirho(
        &canonical_app_root_chirho,
        &source_anchor_chirho,
        cargo_chirho,
    )?;
    let app_manifest_chirho = canonical_app_root_chirho.join("Cargo.toml");
    if !packages_before_chirho
        .iter()
        .any(|package_chirho| package_chirho.manifest_path_chirho == app_manifest_chirho)
    {
        bail!("Cargo metadata omitted the credits-demo root package");
    }

    let package_roots_before_chirho: Vec<PathBuf> = packages_before_chirho
        .iter()
        .map(|package_chirho| package_chirho.root_chirho.clone())
        .collect();
    let captured_chirho =
        capture_closure_chirho(&source_anchor_chirho, &package_roots_before_chirho)?;
    let packages_after_capture_chirho = discover_local_packages_chirho(
        &canonical_app_root_chirho,
        &source_anchor_chirho,
        cargo_chirho,
    )?;
    require_same_package_set_chirho(
        &packages_before_chirho,
        &packages_after_capture_chirho,
        "source closure changed while Cargo metadata was captured",
    )?;
    let recaptured_source_chirho =
        capture_closure_chirho(&source_anchor_chirho, &package_roots_before_chirho)?;
    if recaptured_source_chirho.fingerprint_chirho != captured_chirho.fingerprint_chirho {
        bail!("credits-demo local Cargo source closure changed while the snapshot was captured");
    }

    let container_root_chirho = create_snapshot_container_chirho()?;
    let repository_root_chirho = container_root_chirho.join("repository-chirho");
    std::fs::create_dir(&repository_root_chirho).with_context(|| {
        format!(
            "create authoring snapshot repository {}",
            repository_root_chirho.display()
        )
    })?;
    if let Err(error_chirho) =
        write_captured_closure_chirho(&repository_root_chirho, &captured_chirho)
    {
        let _result_chirho = std::fs::remove_dir_all(&container_root_chirho);
        return Err(error_chirho);
    }

    let relative_app_root_chirho = canonical_app_root_chirho
        .strip_prefix(&source_anchor_chirho)
        .context("app root escaped the source anchor")?;
    let snapshot_app_root_chirho = repository_root_chirho.join(relative_app_root_chirho);
    let snapshot_package_roots_chirho: Vec<PathBuf> = package_roots_before_chirho
        .iter()
        .map(|root_chirho| {
            root_chirho
                .strip_prefix(&source_anchor_chirho)
                .map(PathBuf::from)
                .context("local package root escaped the source anchor")
        })
        .collect::<Result<Vec<_>>>()?;
    let copied_chirho =
        capture_closure_chirho(&repository_root_chirho, &snapshot_package_roots_chirho)?;
    if copied_chirho.fingerprint_chirho != captured_chirho.fingerprint_chirho {
        let _result_chirho = std::fs::remove_dir_all(&container_root_chirho);
        bail!("credits-demo authoring snapshot did not reproduce the complete Cargo closure bytes");
    }

    let snapshot_packages_chirho = discover_local_packages_chirho(
        &snapshot_app_root_chirho,
        &repository_root_chirho,
        cargo_chirho,
    )?;
    require_same_relative_package_set_chirho(
        &packages_before_chirho,
        &source_anchor_chirho,
        &snapshot_packages_chirho,
        &repository_root_chirho,
    )?;
    let target_dir_chirho = container_root_chirho.join("target-chirho");
    std::fs::create_dir(&target_dir_chirho)
        .with_context(|| format!("create isolated target {}", target_dir_chirho.display()))?;

    Ok(SourceSnapshotChirho {
        container_root_chirho,
        root_chirho: snapshot_app_root_chirho,
        target_dir_chirho,
        package_roots_chirho: snapshot_package_roots_chirho,
        fingerprint_chirho: captured_chirho.fingerprint_chirho,
        local_package_count_chirho: packages_before_chirho.len(),
    })
}

#[derive(Debug, Deserialize)]
struct CargoMetadataChirho {
    #[serde(rename = "packages")]
    packages_chirho: Vec<CargoMetadataPackageChirho>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataPackageChirho {
    #[serde(rename = "name")]
    name_chirho: String,
    #[serde(rename = "source")]
    source_chirho: Option<String>,
    #[serde(rename = "manifest_path")]
    manifest_path_chirho: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalPackageChirho {
    name_chirho: String,
    manifest_path_chirho: PathBuf,
    root_chirho: PathBuf,
}

fn discover_local_packages_chirho(
    app_root_chirho: &Path,
    source_boundary_chirho: &Path,
    cargo_chirho: &TrustedCargoChirho,
) -> Result<Vec<LocalPackageChirho>> {
    let manifest_path_chirho = app_root_chirho.join("Cargo.toml");
    let manifest_text_chirho = manifest_path_chirho
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("app Cargo manifest path is not UTF-8"))?;
    let output_chirho = run_trusted_cargo_chirho(
        cargo_chirho,
        app_root_chirho,
        None,
        "cargo-metadata-chirho",
        &[
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--all-features",
            "--manifest-path",
            manifest_text_chirho,
        ],
    )?;
    let metadata_chirho: CargoMetadataChirho = serde_json::from_slice(&output_chirho.stdout_chirho)
        .context("parse trusted Cargo metadata output")?;
    let canonical_boundary_chirho = source_boundary_chirho.canonicalize().with_context(|| {
        format!(
            "canonicalize source boundary {}",
            source_boundary_chirho.display()
        )
    })?;
    let mut packages_chirho = Vec::new();
    let mut manifests_seen_chirho = BTreeSet::new();
    for package_chirho in metadata_chirho
        .packages_chirho
        .into_iter()
        .filter(|package_chirho| package_chirho.source_chirho.is_none())
    {
        let manifest_metadata_chirho =
            std::fs::symlink_metadata(&package_chirho.manifest_path_chirho).with_context(|| {
                format!(
                    "inspect local Cargo manifest {}",
                    package_chirho.manifest_path_chirho.display()
                )
            })?;
        if !manifest_metadata_chirho.is_file() || manifest_metadata_chirho.file_type().is_symlink()
        {
            bail!(
                "local Cargo manifest {} is not a regular non-symlink file",
                package_chirho.manifest_path_chirho.display()
            );
        }
        let manifest_path_chirho = package_chirho
            .manifest_path_chirho
            .canonicalize()
            .with_context(|| {
                format!(
                    "canonicalize local Cargo manifest {}",
                    package_chirho.manifest_path_chirho.display()
                )
            })?;
        if !manifest_path_chirho.starts_with(&canonical_boundary_chirho) {
            bail!(
                "local Cargo package '{}' escapes the snapshotted source boundary",
                package_chirho.name_chirho
            );
        }
        if !manifests_seen_chirho.insert(manifest_path_chirho.clone()) {
            bail!(
                "Cargo metadata repeated local manifest {}",
                manifest_path_chirho.display()
            );
        }
        let root_chirho = manifest_path_chirho
            .parent()
            .ok_or_else(|| anyhow::anyhow!("local Cargo manifest has no parent"))?
            .to_path_buf();
        packages_chirho.push(LocalPackageChirho {
            name_chirho: package_chirho.name_chirho,
            manifest_path_chirho,
            root_chirho,
        });
    }
    packages_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho
            .manifest_path_chirho
            .cmp(&right_chirho.manifest_path_chirho)
    });
    if packages_chirho.is_empty() {
        bail!("Cargo metadata returned no local packages for the credits-demo app");
    }
    Ok(packages_chirho)
}

fn require_same_package_set_chirho(
    expected_chirho: &[LocalPackageChirho],
    actual_chirho: &[LocalPackageChirho],
    message_chirho: &str,
) -> Result<()> {
    let expected_paths_chirho: Vec<&Path> = expected_chirho
        .iter()
        .map(|package_chirho| package_chirho.manifest_path_chirho.as_path())
        .collect();
    let actual_paths_chirho: Vec<&Path> = actual_chirho
        .iter()
        .map(|package_chirho| package_chirho.manifest_path_chirho.as_path())
        .collect();
    if expected_paths_chirho != actual_paths_chirho {
        bail!("{message_chirho}");
    }
    Ok(())
}

fn require_same_relative_package_set_chirho(
    source_chirho: &[LocalPackageChirho],
    source_root_chirho: &Path,
    snapshot_chirho: &[LocalPackageChirho],
    snapshot_root_chirho: &Path,
) -> Result<()> {
    let source_root_chirho = source_root_chirho.canonicalize().with_context(|| {
        format!(
            "canonicalize source closure root {}",
            source_root_chirho.display()
        )
    })?;
    let snapshot_root_chirho = snapshot_root_chirho.canonicalize().with_context(|| {
        format!(
            "canonicalize snapshot closure root {}",
            snapshot_root_chirho.display()
        )
    })?;
    let relative_set_chirho =
        |packages_chirho: &[LocalPackageChirho], root_chirho: &Path| -> Result<BTreeSet<PathBuf>> {
            packages_chirho
                .iter()
                .map(|package_chirho| {
                    package_chirho
                        .manifest_path_chirho
                        .strip_prefix(root_chirho)
                        .map(PathBuf::from)
                        .context("local Cargo manifest escaped its closure root")
                })
                .collect()
        };
    if relative_set_chirho(source_chirho, &source_root_chirho)?
        != relative_set_chirho(snapshot_chirho, &snapshot_root_chirho)?
    {
        bail!("snapshotted Cargo metadata resolved a different local package closure");
    }
    Ok(())
}

struct CapturedClosureChirho {
    package_roots_chirho: Vec<PathBuf>,
    directories_chirho: BTreeSet<PathBuf>,
    files_chirho: BTreeMap<PathBuf, CapturedFileChirho>,
    symlinks_chirho: BTreeMap<PathBuf, CapturedSymlinkChirho>,
    fingerprint_chirho: SourceTreeFingerprintChirho,
}

struct CapturedFileChirho {
    bytes_chirho: Vec<u8>,
    mode_chirho: u32,
}

struct CapturedSymlinkChirho {
    target_chirho: PathBuf,
    target_is_dir_chirho: bool,
}

fn capture_closure_chirho(
    source_root_chirho: &Path,
    package_roots_chirho: &[PathBuf],
) -> Result<CapturedClosureChirho> {
    let source_root_chirho = source_root_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize closure root {}", source_root_chirho.display()))?;
    let mut directories_chirho = BTreeSet::new();
    let mut files_chirho = BTreeMap::new();
    let mut symlinks_chirho = BTreeMap::new();
    let mut total_bytes_chirho = 0_u64;
    let mut relative_package_roots_chirho = Vec::with_capacity(package_roots_chirho.len());
    let mut absolute_package_roots_chirho = Vec::with_capacity(package_roots_chirho.len());
    for package_root_chirho in package_roots_chirho {
        let absolute_root_chirho = if package_root_chirho.is_absolute() {
            package_root_chirho.clone()
        } else {
            source_root_chirho.join(package_root_chirho)
        };
        let canonical_root_chirho = absolute_root_chirho.canonicalize().with_context(|| {
            format!(
                "canonicalize local package root {}",
                absolute_root_chirho.display()
            )
        })?;
        relative_package_roots_chirho.push(
            canonical_root_chirho
                .strip_prefix(&source_root_chirho)
                .with_context(|| {
                    format!(
                        "local package root {} escaped closure root {}",
                        canonical_root_chirho.display(),
                        source_root_chirho.display()
                    )
                })?
                .to_path_buf(),
        );
        absolute_package_roots_chirho.push(canonical_root_chirho);
    }
    for absolute_root_chirho in &absolute_package_roots_chirho {
        // The canonical closure root makes path rows stable across `/var` and
        // `/private/var` spellings on macOS.
        collect_package_entries_chirho(
            &source_root_chirho,
            absolute_root_chirho,
            &absolute_package_roots_chirho,
            &mut directories_chirho,
            &mut files_chirho,
            &mut symlinks_chirho,
            &mut total_bytes_chirho,
        )?;
    }
    let fingerprint_chirho = fingerprint_captured_closure_chirho(
        &relative_package_roots_chirho,
        &directories_chirho,
        &files_chirho,
        &symlinks_chirho,
    );
    Ok(CapturedClosureChirho {
        package_roots_chirho: relative_package_roots_chirho,
        directories_chirho,
        files_chirho,
        symlinks_chirho,
        fingerprint_chirho,
    })
}

fn collect_package_entries_chirho(
    source_root_chirho: &Path,
    directory_chirho: &Path,
    allowed_package_roots_chirho: &[PathBuf],
    directories_chirho: &mut BTreeSet<PathBuf>,
    files_chirho: &mut BTreeMap<PathBuf, CapturedFileChirho>,
    symlinks_chirho: &mut BTreeMap<PathBuf, CapturedSymlinkChirho>,
    total_bytes_chirho: &mut u64,
) -> Result<()> {
    let directory_metadata_chirho = std::fs::symlink_metadata(directory_chirho)
        .with_context(|| format!("inspect source directory {}", directory_chirho.display()))?;
    if directory_metadata_chirho.file_type().is_symlink() || !directory_metadata_chirho.is_dir() {
        bail!(
            "local Cargo source closure contains a symlink or non-directory package path {}",
            directory_chirho.display()
        );
    }
    let relative_directory_chirho = directory_chirho
        .strip_prefix(source_root_chirho)
        .with_context(|| {
            format!(
                "source directory {} escaped closure root {}",
                directory_chirho.display(),
                source_root_chirho.display()
            )
        })?
        .to_path_buf();
    directories_chirho.insert(relative_directory_chirho);
    let mut entries_chirho = std::fs::read_dir(directory_chirho)
        .with_context(|| format!("read source directory {}", directory_chirho.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("collect source directory {}", directory_chirho.display()))?;
    entries_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
    for entry_chirho in entries_chirho {
        let name_chirho = entry_chirho.file_name();
        if should_skip_source_entry_chirho(&name_chirho.to_string_lossy()) {
            continue;
        }
        let path_chirho = entry_chirho.path();
        let metadata_chirho = std::fs::symlink_metadata(&path_chirho)
            .with_context(|| format!("inspect source entry {}", path_chirho.display()))?;
        if metadata_chirho.file_type().is_symlink() {
            let target_chirho = std::fs::read_link(&path_chirho)
                .with_context(|| format!("read source symlink {}", path_chirho.display()))?;
            let canonical_target_chirho = path_chirho.canonicalize().with_context(|| {
                format!(
                    "canonicalize source symlink target {}",
                    path_chirho.display()
                )
            })?;
            if !allowed_package_roots_chirho
                .iter()
                .any(|root_chirho| canonical_target_chirho.starts_with(root_chirho))
            {
                bail!(
                    "local Cargo source closure contains symlink {} whose target escapes every \
                     snapshotted local package",
                    path_chirho.display()
                );
            }
            let target_metadata_chirho =
                std::fs::metadata(&canonical_target_chirho).with_context(|| {
                    format!(
                        "inspect source symlink target {}",
                        canonical_target_chirho.display()
                    )
                })?;
            if !target_metadata_chirho.is_file() && !target_metadata_chirho.is_dir() {
                bail!(
                    "local Cargo source symlink {} targets an unsupported filesystem entry",
                    path_chirho.display()
                );
            }
            let relative_chirho = path_chirho
                .strip_prefix(source_root_chirho)
                .context("source symlink escaped closure root")?
                .to_path_buf();
            if symlinks_chirho
                .insert(
                    relative_chirho.clone(),
                    CapturedSymlinkChirho {
                        target_chirho,
                        target_is_dir_chirho: target_metadata_chirho.is_dir(),
                    },
                )
                .is_some()
            {
                bail!(
                    "overlapping local package roots repeated symlink {}",
                    relative_chirho.display()
                );
            }
            continue;
        }
        if metadata_chirho.is_dir() {
            collect_package_entries_chirho(
                source_root_chirho,
                &path_chirho,
                allowed_package_roots_chirho,
                directories_chirho,
                files_chirho,
                symlinks_chirho,
                total_bytes_chirho,
            )?;
        } else if metadata_chirho.is_file() {
            let bytes_chirho =
                read_bounded_source_file_chirho(&path_chirho, MAX_SOURCE_FILE_BYTES_CHIRHO)?;
            let relative_chirho = path_chirho
                .strip_prefix(source_root_chirho)
                .context("source file escaped closure root")?
                .to_path_buf();
            let captured_chirho = CapturedFileChirho {
                bytes_chirho,
                mode_chirho: file_mode_chirho(&metadata_chirho),
            };
            if let Some(existing_chirho) = files_chirho.get(&relative_chirho) {
                if existing_chirho.bytes_chirho != captured_chirho.bytes_chirho
                    || existing_chirho.mode_chirho != captured_chirho.mode_chirho
                {
                    bail!(
                        "overlapping local package roots disagree for {}",
                        relative_chirho.display()
                    );
                }
            } else {
                *total_bytes_chirho = total_bytes_chirho
                    .checked_add(captured_chirho.bytes_chirho.len() as u64)
                    .ok_or_else(|| {
                        anyhow::anyhow!("local Cargo source closure byte count overflow")
                    })?;
                if *total_bytes_chirho > MAX_SOURCE_CLOSURE_BYTES_CHIRHO {
                    bail!(
                        "local Cargo source closure exceeds the {} byte limit",
                        MAX_SOURCE_CLOSURE_BYTES_CHIRHO
                    );
                }
                files_chirho.insert(relative_chirho, captured_chirho);
            }
        } else {
            bail!(
                "local Cargo source closure contains unsupported entry {}",
                path_chirho.display()
            );
        }
    }
    Ok(())
}

fn fingerprint_captured_closure_chirho(
    package_roots_chirho: &[PathBuf],
    directories_chirho: &BTreeSet<PathBuf>,
    files_chirho: &BTreeMap<PathBuf, CapturedFileChirho>,
    symlinks_chirho: &BTreeMap<PathBuf, CapturedSymlinkChirho>,
) -> SourceTreeFingerprintChirho {
    let mut rows_chirho = Vec::new();
    for root_chirho in package_roots_chirho {
        rows_chirho.push(format!(
            "package-root-chirho\t{}",
            path_text_chirho(root_chirho)
        ));
    }
    for directory_chirho in directories_chirho {
        rows_chirho.push(format!(
            "directory-chirho\t{}",
            path_text_chirho(directory_chirho)
        ));
    }
    for (path_chirho, file_chirho) in files_chirho {
        rows_chirho.push(format!(
            "file-chirho\t{}\t{}\t{}\t{}",
            path_text_chirho(path_chirho),
            file_chirho.mode_chirho,
            file_chirho.bytes_chirho.len(),
            cas_chirho::hash_chirho(&file_chirho.bytes_chirho).0
        ));
    }
    for (path_chirho, symlink_chirho) in symlinks_chirho {
        rows_chirho.push(format!(
            "symlink-chirho\t{}\t{}\t{}",
            path_text_chirho(path_chirho),
            path_text_chirho(&symlink_chirho.target_chirho),
            symlink_chirho.target_is_dir_chirho
        ));
    }
    rows_chirho.sort();
    let mut canonical_chirho = b"credits-demo-authoring-cargo-closure-v2-chirho\n".to_vec();
    for row_chirho in &rows_chirho {
        canonical_chirho.extend_from_slice(row_chirho.as_bytes());
        canonical_chirho.push(b'\n');
    }
    SourceTreeFingerprintChirho {
        blake3_chirho: cas_chirho::hash_chirho(&canonical_chirho).0,
        entry_count_chirho: rows_chirho.len(),
    }
}

fn write_captured_closure_chirho(
    repository_root_chirho: &Path,
    captured_chirho: &CapturedClosureChirho,
) -> Result<()> {
    for directory_chirho in &captured_chirho.directories_chirho {
        std::fs::create_dir_all(repository_root_chirho.join(directory_chirho)).with_context(
            || {
                format!(
                    "create snapshot source directory {}",
                    repository_root_chirho.join(directory_chirho).display()
                )
            },
        )?;
    }
    for (relative_chirho, file_chirho) in &captured_chirho.files_chirho {
        let destination_chirho = repository_root_chirho.join(relative_chirho);
        let mut output_chirho = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination_chirho)
            .with_context(|| format!("create snapshot source {}", destination_chirho.display()))?;
        output_chirho
            .write_all(&file_chirho.bytes_chirho)
            .with_context(|| format!("write snapshot source {}", destination_chirho.display()))?;
        set_file_mode_chirho(&destination_chirho, file_chirho.mode_chirho)?;
    }
    for (relative_chirho, symlink_chirho) in &captured_chirho.symlinks_chirho {
        let destination_chirho = repository_root_chirho.join(relative_chirho);
        create_symlink_chirho(
            &symlink_chirho.target_chirho,
            &destination_chirho,
            symlink_chirho.target_is_dir_chirho,
        )?;
        let canonical_target_chirho = destination_chirho.canonicalize().with_context(|| {
            format!(
                "canonicalize snapshotted symlink target {}",
                destination_chirho.display()
            )
        })?;
        let allowed_chirho = captured_chirho
            .package_roots_chirho
            .iter()
            .map(|root_chirho| repository_root_chirho.join(root_chirho).canonicalize())
            .collect::<std::io::Result<Vec<_>>>()
            .context("canonicalize snapshotted local-package roots")?;
        if !allowed_chirho
            .iter()
            .any(|root_chirho| canonical_target_chirho.starts_with(root_chirho))
        {
            bail!(
                "snapshotted symlink {} escaped the immutable local-package closure",
                destination_chirho.display()
            );
        }
    }
    Ok(())
}

fn create_snapshot_container_chirho() -> Result<PathBuf> {
    for _attempt_chirho in 0..100 {
        let sequence_chirho = SNAPSHOT_SEQUENCE_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let candidate_chirho = std::env::temp_dir().join(format!(
            "cairn-cf7-authoring-snapshot-{}-{sequence_chirho}-chirho",
            std::process::id()
        ));
        match std::fs::create_dir(&candidate_chirho) {
            Ok(()) => return Ok(candidate_chirho),
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error_chirho) => {
                return Err(error_chirho).with_context(|| {
                    format!("create authoring snapshot {}", candidate_chirho.display())
                })
            }
        }
    }
    bail!("could not allocate a unique credits-demo authoring snapshot directory")
}

fn find_source_anchor_chirho(app_root_chirho: &Path) -> Result<PathBuf> {
    for ancestor_chirho in app_root_chirho.ancestors() {
        if ancestor_chirho.join(".git").exists() {
            return ancestor_chirho.canonicalize().with_context(|| {
                format!("canonicalize source anchor {}", ancestor_chirho.display())
            });
        }
    }
    bail!(
        "credits-demo app root {} is not inside a Git worktree",
        app_root_chirho.display()
    )
}

fn read_bounded_source_file_chirho(path_chirho: &Path, max_chirho: u64) -> Result<Vec<u8>> {
    let file_chirho = std::fs::File::open(path_chirho)
        .with_context(|| format!("open source file {}", path_chirho.display()))?;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(max_chirho.saturating_add(1))
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read source file {}", path_chirho.display()))?;
    if bytes_chirho.len() as u64 > max_chirho {
        bail!(
            "source file {} exceeds the {} byte limit",
            path_chirho.display(),
            max_chirho
        );
    }
    Ok(bytes_chirho)
}

fn should_skip_source_entry_chirho(name_chirho: &str) -> bool {
    matches!(
        name_chirho,
        ".git" | "target" | "node_modules" | ".cairn-chirho" | ".DS_Store"
    )
}

fn path_text_chirho(path_chirho: &Path) -> String {
    path_chirho.to_string_lossy().replace('\\', "/")
}

#[cfg(unix)]
fn create_symlink_chirho(
    target_chirho: &Path,
    destination_chirho: &Path,
    _target_is_dir_chirho: bool,
) -> Result<()> {
    std::os::unix::fs::symlink(target_chirho, destination_chirho).with_context(|| {
        format!(
            "create snapshotted symlink {} -> {}",
            destination_chirho.display(),
            target_chirho.display()
        )
    })
}

#[cfg(windows)]
fn create_symlink_chirho(
    target_chirho: &Path,
    destination_chirho: &Path,
    target_is_dir_chirho: bool,
) -> Result<()> {
    let result_chirho = if target_is_dir_chirho {
        std::os::windows::fs::symlink_dir(target_chirho, destination_chirho)
    } else {
        std::os::windows::fs::symlink_file(target_chirho, destination_chirho)
    };
    result_chirho.with_context(|| {
        format!(
            "create snapshotted symlink {} -> {}",
            destination_chirho.display(),
            target_chirho.display()
        )
    })
}

#[cfg(not(any(unix, windows)))]
fn create_symlink_chirho(
    _target_chirho: &Path,
    destination_chirho: &Path,
    _target_is_dir_chirho: bool,
) -> Result<()> {
    bail!(
        "cannot preserve immutable source symlink {} on this platform",
        destination_chirho.display()
    )
}

#[cfg(unix)]
fn file_mode_chirho(metadata_chirho: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata_chirho.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode_chirho(metadata_chirho: &std::fs::Metadata) -> u32 {
    u32::from(metadata_chirho.permissions().readonly())
}

#[cfg(unix)]
fn set_file_mode_chirho(path_chirho: &Path, mode_chirho: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(mode_chirho))
        .with_context(|| format!("set snapshot source mode {}", path_chirho.display()))
}

#[cfg(not(unix))]
fn set_file_mode_chirho(path_chirho: &Path, mode_chirho: u32) -> Result<()> {
    let mut permissions_chirho = std::fs::metadata(path_chirho)?.permissions();
    permissions_chirho.set_readonly(mode_chirho != 0);
    std::fs::set_permissions(path_chirho, permissions_chirho)
        .with_context(|| format!("set snapshot source mode {}", path_chirho.display()))
}
