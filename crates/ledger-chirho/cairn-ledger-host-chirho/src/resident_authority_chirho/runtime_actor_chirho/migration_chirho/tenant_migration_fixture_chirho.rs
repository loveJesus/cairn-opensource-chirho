// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use std::path::Path;

/// Give a fixture source one real, self-resolving log reference.
///
/// The self-containment half refuses a root over zero references because "nothing I was shown
/// dangles" over an empty list is not evidence. Fixtures that never wrote a log therefore get a
/// genuine object and a genuine reference rather than relaxing that anti-vacuity rule.
pub(crate) fn seed_migration_reference_chirho(root_chirho: &Path) {
    use cairn_tenant_chirho::migration_completeness_chirho::declared_log_surfaces_chirho;

    let bytes_chirho = b"seeded-migration-object-chirho";
    let hash_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    let shard_chirho = root_chirho.join("objects-chirho").join(&hash_chirho[..2]);
    std::fs::create_dir_all(&shard_chirho).expect("seed: create the CAS shard");
    std::fs::write(shard_chirho.join(&hash_chirho[2..]), bytes_chirho)
        .expect("seed: store one object in the source CAS");
    let log_chirho = declared_log_surfaces_chirho()
        .into_iter()
        .next()
        .expect("the log manifest is non-empty");
    let path_chirho = root_chirho.join(&log_chirho);
    let mut existing_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_default();
    existing_chirho.push_str(&format!("{{\"seeded_object_chirho\":\"{hash_chirho}\"}}\n"));
    std::fs::write(&path_chirho, existing_chirho).expect("seed: append one referencing line");
}

/// Give a fixture target the writer identity a completed adoption would leave it.
///
/// This bypasses the reviewed warrant ceremony only for tests whose subject is an already-bound
/// identity. Warrant tests must drive the real prepared/completed consumption path instead.
pub(crate) fn stage_adopted_writer_identity_chirho(target_root_chirho: &Path) {
    use cairn_writer_head_chirho::resident_writer_chirho::{
        reserve_resident_writer_chirho, ResidentWriterBindingChirho,
    };

    let metadata_chirho =
        std::fs::metadata(target_root_chirho).expect("stage: stat the target root");
    #[cfg(unix)]
    let (device_chirho, inode_chirho) = {
        use std::os::unix::fs::MetadataExt;
        (metadata_chirho.dev(), metadata_chirho.ino())
    };
    #[cfg(not(unix))]
    let (device_chirho, inode_chirho) = (0u64, 0u64);
    let canonical_chirho = serde_json::to_vec(&serde_json::json!({
        "schema_chirho": "resident-ledger-bound-identity-v4-chirho",
        "state_chirho": "bound_chirho",
        "coordinate_chirho": {
            "authority_root_device_chirho": device_chirho,
            "authority_root_inode_chirho": inode_chirho,
        },
    }))
    .expect("stage: encode the stand-in identity");
    let binding_chirho = ResidentWriterBindingChirho {
        root_chirho: target_root_chirho,
        identity_kind_chirho: "resident-ledger-bound-identity-v4-chirho",
        canonical_identity_chirho: &canonical_chirho,
    };
    let (lease_chirho, _outcome_chirho) =
        reserve_resident_writer_chirho(&binding_chirho).expect("stage: reserve the target writer");
    drop(lease_chirho);
}

/// Copy exactly the root surfaces that the disposition model says travel with a migration.
///
/// Deriving the population from the table keeps fixtures aligned with the production eligibility
/// model. Symlinks are deliberately skipped so the staged target cannot inherit a link outside its
/// own root.
pub(crate) fn stage_migration_target_surfaces_chirho(
    source_root_chirho: &Path,
    target_root_chirho: &Path,
) {
    use cairn_tenant_chirho::surface_disposition_chirho::{
        disposition_for_surface_chirho, surface_travels_with_the_root_chirho,
    };

    fn copy_tree_chirho(from_chirho: &Path, to_chirho: &Path) {
        let metadata_chirho = std::fs::symlink_metadata(from_chirho).expect("stage: stat source");
        if metadata_chirho.is_dir() {
            std::fs::create_dir_all(to_chirho).expect("stage: create target dir");
            for entry_chirho in std::fs::read_dir(from_chirho).expect("stage: read source dir") {
                let entry_chirho = entry_chirho.expect("stage: read source entry");
                copy_tree_chirho(
                    &entry_chirho.path(),
                    &to_chirho.join(entry_chirho.file_name()),
                );
            }
        } else if metadata_chirho.is_file() {
            std::fs::copy(from_chirho, to_chirho).expect("stage: copy file");
        }
    }

    for entry_chirho in std::fs::read_dir(source_root_chirho).expect("stage: read source root") {
        let entry_chirho = entry_chirho.expect("stage: read source root entry");
        let name_chirho = entry_chirho.file_name();
        let Some(name_chirho) = name_chirho.to_str() else {
            continue;
        };
        let travels_chirho = disposition_for_surface_chirho(name_chirho)
            .is_some_and(surface_travels_with_the_root_chirho);
        if travels_chirho {
            copy_tree_chirho(&entry_chirho.path(), &target_root_chirho.join(name_chirho));
        }
    }
}
