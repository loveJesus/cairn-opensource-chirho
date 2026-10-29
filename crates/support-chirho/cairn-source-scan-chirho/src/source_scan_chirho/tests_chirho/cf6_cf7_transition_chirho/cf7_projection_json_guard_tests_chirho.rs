// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::workspace_root_chirho;
use std::path::{Path, PathBuf};

fn collect_manifests_chirho(dir_chirho: &Path, manifests_chirho: &mut Vec<PathBuf>) {
    let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if !path_chirho.is_dir() {
            if path_chirho
                .file_name()
                .and_then(|name_chirho| name_chirho.to_str())
                == Some("Cargo.toml")
            {
                manifests_chirho.push(path_chirho);
            }
            continue;
        }
        let name_chirho = entry_chirho.file_name();
        let name_chirho = name_chirho.to_string_lossy();
        if name_chirho.starts_with('.') || name_chirho == "target" {
            continue;
        }
        collect_manifests_chirho(&path_chirho, manifests_chirho);
    }
}

#[test]
fn projection_json_canonicalization_stays_single_coded_and_explicit_chirho() {
    let root_chirho = workspace_root_chirho();
    let codec_chirho = std::fs::read_to_string(
        root_chirho
            .join("crates/ledger-chirho/cairn-ledger-model-chirho/src/projection_json_chirho.rs"),
    )
    .unwrap();
    assert!(
        codec_chirho.contains("sorted_entries_chirho.sort_unstable_by"),
        "projection JSON must sort object keys explicitly"
    );
    assert!(codec_chirho.contains("serializer_chirho.serialize_map"));

    let producer_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/feed_group_chirho/account_net_chirho.rs",
    ))
    .unwrap();
    assert!(producer_chirho.contains("canonical_projection_json_bytes_chirho(view_chirho)"));
    assert!(producer_chirho.contains("parse_canonical_projection_json_value_chirho(bytes_chirho)"));
    assert!(!producer_chirho.contains("serde_json::to_vec(view_chirho)"));

    let consumer_chirho = std::fs::read_to_string(
        root_chirho.join("src/execution_runtime_chirho/effect_chirho/projection_read_chirho.rs"),
    )
    .unwrap();
    assert!(consumer_chirho
        .contains("parse_canonical_projection_json_value_chirho(&view_bytes_chirho)"));
    assert!(!consumer_chirho.contains("serde_json::to_vec(&value_chirho)"));

    let mut manifests_chirho = vec![root_chirho.join("Cargo.toml")];
    collect_manifests_chirho(&root_chirho.join("crates"), &mut manifests_chirho);
    for manifest_chirho in manifests_chirho {
        let text_chirho = std::fs::read_to_string(&manifest_chirho).unwrap();
        assert!(
            !text_chirho.contains("preserve_order"),
            "serde_json preserve_order would make projection ordering ambiguous: {}",
            manifest_chirho.display()
        );
    }
}
