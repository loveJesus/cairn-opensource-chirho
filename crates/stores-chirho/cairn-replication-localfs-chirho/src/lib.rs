// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Local-filesystem adapter for the P3 `ReplicationSourceChirho` port. It reads a source root's
//! content-addressed objects (`objects-chirho/<ab>/<rest>`, the same sharding the fs content store
//! writes) and returns raw bytes WITHOUT verifying them — verification is the receiver's job, so a
//! corrupt or substituted source object flows through as-is and the receiver quarantines it. It also
//! provides a replica-root quarantine sink. This is the transport double that proves P3 with no CEPH
//! or Raft infrastructure; a network adapter implements the same port later.

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{StoreErrorChirho, StoreResultChirho};
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_replication_chirho::{
    is_replicable_log_name_chirho, QuarantineSinkChirho, ReplicationSourceChirho,
    REPLICATION_QUARANTINE_DIR_CHIRHO,
};
use std::path::{Path, PathBuf};

/// A read-only replication source over a local source root directory. Holds only a path; it can
/// read objects but has no ability to write to the source or touch any head.
pub struct LocalFsReplicationSourceChirho {
    source_root_chirho: PathBuf,
}

impl LocalFsReplicationSourceChirho {
    pub fn new_chirho(source_root_chirho: impl Into<PathBuf>) -> Self {
        Self {
            source_root_chirho: source_root_chirho.into(),
        }
    }

    fn objects_dir_chirho(&self) -> PathBuf {
        self.source_root_chirho.join("objects-chirho")
    }

    fn sharded_addr_path_chirho(&self, addr_chirho: &HashChirho) -> Option<PathBuf> {
        let hex_chirho = &addr_chirho.0;
        if hex_chirho.len() < 3 {
            return None;
        }
        Some(
            self.objects_dir_chirho()
                .join(&hex_chirho[0..2])
                .join(&hex_chirho[2..]),
        )
    }
}

impl ReplicationSourceChirho for LocalFsReplicationSourceChirho {
    fn list_object_addrs_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        let objects_dir_chirho = self.objects_dir_chirho();
        let mut addrs_chirho = Vec::new();
        let shard_iter_chirho = match std::fs::read_dir(&objects_dir_chirho) {
            Ok(iter_chirho) => iter_chirho,
            Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => {
                return Ok(addrs_chirho);
            }
            Err(e_chirho) => return Err(store_io_chirho(&objects_dir_chirho, e_chirho)),
        };
        for shard_chirho in shard_iter_chirho {
            let shard_chirho =
                shard_chirho.map_err(|e_chirho| store_io_chirho(&objects_dir_chirho, e_chirho))?;
            let shard_path_chirho = shard_chirho.path();
            if !shard_path_chirho.is_dir() {
                continue;
            }
            let Some(prefix_chirho) = shard_path_chirho
                .file_name()
                .and_then(|n_chirho| n_chirho.to_str())
            else {
                continue;
            };
            for entry_chirho in std::fs::read_dir(&shard_path_chirho)
                .map_err(|e_chirho| store_io_chirho(&shard_path_chirho, e_chirho))?
            {
                let entry_chirho = entry_chirho
                    .map_err(|e_chirho| store_io_chirho(&shard_path_chirho, e_chirho))?;
                if !entry_chirho.path().is_file() {
                    continue;
                }
                let Some(rest_chirho) = entry_chirho
                    .file_name()
                    .to_str()
                    .map(|s_chirho| s_chirho.to_string())
                else {
                    continue;
                };
                addrs_chirho.push(HashChirho(format!("{prefix_chirho}{rest_chirho}")));
            }
        }
        // Deterministic order so a pull is reproducible.
        addrs_chirho.sort_by(|a_chirho, b_chirho| a_chirho.0.cmp(&b_chirho.0));
        Ok(addrs_chirho)
    }

    fn fetch_object_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        let Some(path_chirho) = self.sharded_addr_path_chirho(addr_chirho) else {
            return Ok(None);
        };
        // A content-addressed object must resolve to a real file INSIDE objects-chirho — never a
        // symlink (or `..`) escaping the store to e.g. the signing key. Canonicalize and confirm
        // containment; anything that resolves outside is treated as absent and NEVER served. (The log
        // path enforces the analogous rule for named logs.)
        let canonical_chirho = match std::fs::canonicalize(&path_chirho) {
            Ok(canonical_chirho) => canonical_chirho,
            Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e_chirho) => return Err(store_io_chirho(&path_chirho, e_chirho)),
        };
        match std::fs::canonicalize(self.objects_dir_chirho()) {
            Ok(objects_dir_chirho) if canonical_chirho.starts_with(&objects_dir_chirho) => {}
            Ok(_) => return Ok(None),
            Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e_chirho) => return Err(store_io_chirho(&self.objects_dir_chirho(), e_chirho)),
        }
        match std::fs::read(&canonical_chirho) {
            Ok(bytes_chirho) => Ok(Some(bytes_chirho)),
            Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e_chirho) => Err(store_io_chirho(&canonical_chirho, e_chirho)),
        }
    }

    fn fetch_named_log_chirho(&self, name_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>> {
        // Allowlist: only the public Gate 1 anchor log and Ring-A family logs may leave the source.
        // This structurally refuses the signing key (`signing-key-chirho.bin`), refs, and any private
        // file by name — a path-traversal denylist would serve those plain names (invariant: keys and
        // plaintext never replicate).
        if !is_replicable_log_name_chirho(name_chirho) {
            return Err(StoreErrorChirho::invalid_chirho(format!(
                "replication log name is not an allowlisted public log: {name_chirho}"
            )));
        }
        let path_chirho = self.source_root_chirho.join(name_chirho);
        // An allowlisted name must be a real file in the source root, never a symlink pointing
        // elsewhere (defense-in-depth against a planted symlink named like a public log).
        if let Ok(meta_chirho) = std::fs::symlink_metadata(&path_chirho) {
            if meta_chirho.file_type().is_symlink() {
                return Err(StoreErrorChirho::invalid_chirho(format!(
                    "replication log name resolves to a symlink: {name_chirho}"
                )));
            }
        }
        match std::fs::read(&path_chirho) {
            Ok(bytes_chirho) => Ok(Some(bytes_chirho)),
            Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e_chirho) => Err(store_io_chirho(&path_chirho, e_chirho)),
        }
    }
}

/// A quarantine sink under a replica root. Failed objects are parked by their TRUE blake3 (the
/// address they were requested under is the forgery), so distinct corruptions never collide, and
/// nothing here is reachable from the replica's served store.
pub struct FsReplicaQuarantineChirho {
    replica_root_chirho: PathBuf,
}

impl FsReplicaQuarantineChirho {
    pub fn new_chirho(replica_root_chirho: impl Into<PathBuf>) -> Self {
        Self {
            replica_root_chirho: replica_root_chirho.into(),
        }
    }

    pub fn quarantine_dir_chirho(&self) -> PathBuf {
        self.replica_root_chirho
            .join(REPLICATION_QUARANTINE_DIR_CHIRHO)
    }
}

impl QuarantineSinkChirho for FsReplicaQuarantineChirho {
    fn quarantine_chirho(
        &self,
        _requested_chirho: &HashChirho,
        actual_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> StoreResultChirho<()> {
        let path_chirho = self.quarantine_dir_chirho().join(&actual_chirho.0);
        write_file_durable_chirho(&path_chirho, bytes_chirho)
            .map_err(|e_chirho| store_io_chirho(&path_chirho, e_chirho))
    }
}

fn store_io_chirho(path_chirho: &Path, error_chirho: std::io::Error) -> StoreErrorChirho {
    StoreErrorChirho::from(
        anyhow::Error::from(error_chirho)
            .context(format!("replication local-fs {}", path_chirho.display())),
    )
}
