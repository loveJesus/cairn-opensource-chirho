// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Applies generated source plans to a filesystem tree without allowing path escape.

use crate::model_chirho::{GeneratedFileChirho, GeneratedSourcePlanChirho};
use anyhow::{bail, Context, Result};
use cairn_tree_build_chirho::blessed_catalog_chirho::lookup_blessed_contract_chirho;
use cairn_tree_build_chirho::scaffold_chirho::new_app_chirho;
use std::path::{Component, Path, PathBuf};

pub fn apply_source_plan_chirho(
    plan_chirho: &GeneratedSourcePlanChirho,
    root_chirho: &Path,
) -> Result<()> {
    match plan_chirho {
        GeneratedSourcePlanChirho::ScaffoldContactChirho {
            hostile_capability_chirho,
        } => {
            new_app_chirho(root_chirho, "contact-form-chirho", "path", None)
                .map_err(anyhow::Error::msg)?;
            if *hostile_capability_chirho {
                add_hostile_blessed_role_chirho(root_chirho)?;
            }
            Ok(())
        }
        GeneratedSourcePlanChirho::FilesChirho { files_chirho } => {
            for file_chirho in files_chirho {
                write_generated_file_chirho(root_chirho, file_chirho)?;
            }
            Ok(())
        }
    }
}

pub fn count_source_files_chirho(root_chirho: &Path) -> Result<usize> {
    let mut count_chirho = 0usize;
    count_files_rec_chirho(root_chirho, &mut count_chirho)?;
    Ok(count_chirho)
}

fn write_generated_file_chirho(
    root_chirho: &Path,
    file_chirho: &GeneratedFileChirho,
) -> Result<()> {
    let path_chirho = safe_relative_path_chirho(&file_chirho.path_chirho)?;
    let out_chirho = root_chirho.join(path_chirho);
    if let Some(parent_chirho) = out_chirho.parent() {
        std::fs::create_dir_all(parent_chirho)
            .with_context(|| format!("create {}", parent_chirho.display()))?;
    }
    std::fs::write(&out_chirho, &file_chirho.content_chirho)
        .with_context(|| format!("write {}", out_chirho.display()))?;
    Ok(())
}

fn safe_relative_path_chirho(path_chirho: &str) -> Result<PathBuf> {
    if path_chirho.trim().is_empty() {
        bail!("generated file path must not be empty");
    }
    let path_chirho = Path::new(path_chirho);
    if path_chirho.is_absolute() {
        bail!("generated file path must be relative");
    }
    let mut out_chirho = PathBuf::new();
    for component_chirho in path_chirho.components() {
        match component_chirho {
            Component::Normal(segment_chirho) => out_chirho.push(segment_chirho),
            _ => bail!("generated file path must not contain '.', '..', or prefixes"),
        }
    }
    Ok(out_chirho)
}

fn add_hostile_blessed_role_chirho(root_chirho: &Path) -> Result<()> {
    let contract_chirho = lookup_blessed_contract_chirho("write-store")
        .ok_or_else(|| anyhow::anyhow!("write-store blessed contract missing"))?;
    let role_chirho = root_chirho
        .join("dags_chirho")
        .join("view_contact_chirho")
        .join("nodes_chirho")
        .join("save_contact_chirho");
    std::fs::create_dir_all(&role_chirho)
        .with_context(|| format!("create {}", role_chirho.display()))?;
    let card_chirho = format!(
        "# For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)\n\
schema_chirho = \"blessed-card-v2-chirho\"\n\
contract_chirho = \"write-store\"\n\
contract_hash_chirho = \"{}\"\n\
scope_chirho = \"g1-generated-store-chirho\"\n\
intent_chirho = \"Prompt-injected request to persist data.\"\n",
        contract_chirho.contract_hash_chirho()
    );
    std::fs::write(
        role_chirho.join("blessed-contract-chirho.toml"),
        card_chirho,
    )?;
    Ok(())
}

fn count_files_rec_chirho(root_chirho: &Path, count_chirho: &mut usize) -> Result<()> {
    if !root_chirho.exists() {
        return Ok(());
    }
    for entry_chirho in std::fs::read_dir(root_chirho)? {
        let entry_chirho = entry_chirho?;
        let path_chirho = entry_chirho.path();
        let meta_chirho = std::fs::symlink_metadata(&path_chirho)?;
        if meta_chirho.file_type().is_symlink() || meta_chirho.is_file() {
            *count_chirho += 1;
        } else if meta_chirho.is_dir() {
            count_files_rec_chirho(&path_chirho, count_chirho)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod source_plan_tests_chirho {
    use super::*;

    #[test]
    fn file_plan_rejects_path_escape_chirho() {
        let root_chirho =
            std::env::temp_dir().join(format!("g1-file-plan-escape-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root_chirho);
        std::fs::create_dir_all(&root_chirho).unwrap();
        let plan_chirho = GeneratedSourcePlanChirho::FilesChirho {
            files_chirho: vec![GeneratedFileChirho {
                path_chirho: "../escape-chirho.txt".to_string(),
                content_chirho: "bad".to_string(),
            }],
        };
        let error_chirho = apply_source_plan_chirho(&plan_chirho, &root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("must not contain"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
