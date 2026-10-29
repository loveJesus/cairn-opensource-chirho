// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounded two-step operator tool for a fresh-root elected-writer activation.

use anyhow::{bail, Context, Result};
use cairn_ledger_geo_node_chirho::writer_era_activation_chirho::{
    inspect_writer_era_activation_candidate_chirho, sign_writer_era_activation_candidate_chirho,
    WriterEraActivationCandidateChirho, MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO,
};
use std::io::Read;
use std::path::{Path, PathBuf};

/// This binary's name PLUS the crate version PLUS the source commit that built these bytes.
///
/// This tool SIGNS a writer-era activation, so which bytes an operator ran is part of the record.
const VERSION_LINE_CHIRHO: &str =
    cairn_build_identity_chirho::version_line_chirho!("cairn-writer-era-activation-chirho");

fn main() -> Result<()> {
    let mut args_chirho = std::env::args_os();
    let _program_chirho = args_chirho.next();
    let mode_chirho = args_chirho
        .next()
        .and_then(|value_chirho| value_chirho.into_string().ok())
        .ok_or_else(usage_chirho)?;
    // BEFORE the mode match, which would otherwise answer a version request with the usage error.
    if cairn_build_identity_chirho::is_version_request_chirho(Some(mode_chirho.as_str())) {
        println!("{VERSION_LINE_CHIRHO}");
        return Ok(());
    }
    match mode_chirho.as_str() {
        "candidate-chirho" => {
            let root_chirho = next_path_chirho(&mut args_chirho)?;
            let cluster_config_chirho = next_path_chirho(&mut args_chirho)?;
            let output_chirho = next_path_chirho(&mut args_chirho)?;
            require_no_more_args_chirho(&mut args_chirho)?;
            let candidate_chirho = inspect_writer_era_activation_candidate_chirho(
                &root_chirho,
                &cluster_config_chirho,
            )?;
            write_new_private_json_chirho(&output_chirho, &candidate_chirho)?;
            println!(
                "writer-era activation candidate written: {}",
                output_chirho.display()
            );
        }
        "sign-chirho" => {
            let candidate_path_chirho = next_path_chirho(&mut args_chirho)?;
            let operator_sign_root_chirho = next_path_chirho(&mut args_chirho)?;
            let output_chirho = next_path_chirho(&mut args_chirho)?;
            require_no_more_args_chirho(&mut args_chirho)?;
            let candidate_chirho: WriterEraActivationCandidateChirho =
                read_bounded_json_chirho(&candidate_path_chirho)?;
            let authorization_chirho = sign_writer_era_activation_candidate_chirho(
                &candidate_chirho,
                &operator_sign_root_chirho,
            )?;
            write_new_private_json_chirho(&output_chirho, &authorization_chirho)?;
            println!(
                "writer-era activation authorization written: {}",
                output_chirho.display()
            );
        }
        _ => return Err(usage_chirho()),
    }
    Ok(())
}

fn next_path_chirho(args_chirho: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<PathBuf> {
    args_chirho
        .next()
        .map(PathBuf::from)
        .ok_or_else(usage_chirho)
}

fn require_no_more_args_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<()> {
    if args_chirho.next().is_some() {
        return Err(usage_chirho());
    }
    Ok(())
}

fn usage_chirho() -> anyhow::Error {
    anyhow::anyhow!(
        "usage: cairn-writer-era-activation-chirho candidate-chirho <selected-root> <cluster-config.json> <candidate-output.json> | sign-chirho <candidate.json> <operator-sign-root> <authorization-output.json>"
    )
}

fn read_bounded_json_chirho<ValueChirho>(path_chirho: &Path) -> Result<ValueChirho>
where
    ValueChirho: serde::de::DeserializeOwned,
{
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .with_context(|| format!("inspect activation input {}", path_chirho.display()))?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        bail!("activation input must be a regular non-symlink file");
    }
    if metadata_chirho.len() > MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO {
        bail!("activation input exceeds its bounded size");
    }
    let mut bytes_chirho = Vec::new();
    std::fs::File::open(path_chirho)?
        .take(MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)?;
    if bytes_chirho.len() as u64 > MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO {
        bail!("activation input exceeds its bounded read");
    }
    serde_json::from_slice(&bytes_chirho).context("parse activation input")
}

fn write_new_private_json_chirho<ValueChirho>(
    path_chirho: &Path,
    value_chirho: &ValueChirho,
) -> Result<()>
where
    ValueChirho: serde::Serialize,
{
    let mut bytes_chirho = serde_json::to_vec_pretty(value_chirho)?;
    bytes_chirho.push(b'\n');
    if bytes_chirho.len() as u64 > MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO {
        bail!("activation output exceeds its bounded size");
    }
    let parent_chirho = path_chirho
        .parent()
        .filter(|parent_chirho| !parent_chirho.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent_chirho)?;
    let mut options_chirho = std::fs::OpenOptions::new();
    options_chirho.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options_chirho.mode(0o600);
    }
    let mut file_chirho = options_chirho
        .open(path_chirho)
        .with_context(|| format!("create activation output {}", path_chirho.display()))?;
    use std::io::Write;
    file_chirho.write_all(&bytes_chirho)?;
    file_chirho.sync_all()?;
    Ok(())
}
