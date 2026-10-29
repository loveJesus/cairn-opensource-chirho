// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Credential-file helper functions for CLI commands.

use crate::args_chirho::CommandChirho;
use anyhow::Context;
use cairn_chirho::secret_chirho;
use std::path::{Path, PathBuf};

fn read_cli_credential_file_chirho(path_chirho: &Path) -> anyhow::Result<String> {
    let credential_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("failed to read credential file {}", path_chirho.display()))?;
    let credential_chirho = credential_chirho.trim_end_matches(['\r', '\n']).to_string();
    if credential_chirho.is_empty() {
        anyhow::bail!("credential file {} is empty", path_chirho.display());
    }
    Ok(credential_chirho)
}

pub(crate) fn read_cli_private_credential_file_chirho(
    path_chirho: &Path,
) -> anyhow::Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode_chirho = std::fs::metadata(path_chirho)
            .with_context(|| format!("stat credential file {}", path_chirho.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode_chirho != 0o600 {
            anyhow::bail!(
                "credential file {} must be mode 600, found {:o}",
                path_chirho.display(),
                mode_chirho
            );
        }
    }
    read_cli_credential_file_chirho(path_chirho)
}

pub(crate) fn resolve_cli_optional_credential_chirho(
    credential_chirho: Option<String>,
    credential_file_chirho: Option<PathBuf>,
) -> anyhow::Result<Option<String>> {
    match (credential_chirho, credential_file_chirho) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--credential and --credential-file cannot be used together")
        }
        (Some(credential_chirho), None) => Ok(Some(credential_chirho)),
        (None, Some(path_chirho)) => Ok(Some(read_cli_credential_file_chirho(&path_chirho)?)),
        (None, None) => Ok(None),
    }
}

pub(crate) fn resolve_cli_required_credential_chirho(
    credential_chirho: Option<String>,
    credential_file_chirho: Option<PathBuf>,
) -> anyhow::Result<String> {
    resolve_cli_optional_credential_chirho(credential_chirho, credential_file_chirho)?
        .ok_or_else(|| anyhow::anyhow!("--credential or --credential-file is required"))
}

pub(crate) fn handle_secret_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::SecretSetChirho(args_chirho) => {
            let crate::args_chirho::ops_args_chirho::SecretSetArgsChirho {
                name_chirho,
                file_chirho,
            } = args_chirho;
            let bytes_chirho = std::fs::read(file_chirho)?;
            let ref_chirho =
                secret_chirho::set_secret_chirho(root_chirho, name_chirho, &bytes_chirho)?;
            println!("{}", serde_json::to_string_pretty(&ref_chirho)?);
            Ok(true)
        }
        CommandChirho::SecretRefChirho(args_chirho) => {
            let crate::args_chirho::ops_args_chirho::SecretRefArgsChirho { name_chirho } =
                args_chirho;
            let ref_chirho = secret_chirho::secret_ref_chirho(name_chirho)?;
            println!("{}", serde_json::to_string_pretty(&ref_chirho)?);
            Ok(true)
        }
        CommandChirho::SecretListChirho => {
            for secret_chirho in secret_chirho::list_secrets_chirho(root_chirho)? {
                println!(
                    "{} bytes={} updated_ms={}",
                    secret_chirho.name_chirho,
                    secret_chirho.bytes_chirho,
                    secret_chirho.updated_ms_chirho
                );
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}
