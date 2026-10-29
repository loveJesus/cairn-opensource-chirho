// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The durable per-replica-root anti-rollback SYNC floor: the highest anchor-record count a
//! replica root has ever verified, read before and raised after every successful sync so a
//! stale-but-validly-signed shorter history fails closed across process restarts — and across
//! TRANSPORTS: the floor guards the root, so a replica that pulls over HTTP one day and from an
//! S3-compatible bucket the next keeps one continuous floor. (Distinct from the ref-snapshot
//! floor, `ref_snapshot_chirho::REF_SNAPSHOT_FLOOR_FILE_CHIRHO`, which guards the B2 snapshot
//! plane; the two floors are deliberately separate files so neither plane can mask the other's
//! rollback check.)

use anyhow::{bail, Context, Result};
use cairn_durable_chirho::write_file_durable_chirho;
use std::path::Path;

pub const SYNC_FLOOR_FILE_CHIRHO: &str = "replica-sync-floor-chirho.json";
pub const SYNC_FLOOR_SCHEMA_CHIRHO: &str = "replica-sync-floor-v1-chirho";

/// The durable anti-rollback floor: the highest anchor-record count this replica root has ever
/// verified. A later pull presenting a validly-signed but SHORTER history fails closed.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SyncFloorChirho {
    pub schema_chirho: String,
    pub min_anchor_record_count_chirho: u64,
}

pub fn read_sync_floor_chirho(replica_root_chirho: &Path) -> Result<Option<u64>> {
    let path_chirho = replica_root_chirho.join(SYNC_FLOOR_FILE_CHIRHO);
    if !path_chirho.exists() {
        return Ok(None);
    }
    let bytes_chirho = std::fs::read(&path_chirho)
        .with_context(|| format!("read sync floor {}", path_chirho.display()))?;
    let floor_chirho: SyncFloorChirho =
        serde_json::from_slice(&bytes_chirho).context("parse sync floor JSON")?;
    if floor_chirho.schema_chirho != SYNC_FLOOR_SCHEMA_CHIRHO {
        bail!(
            "sync floor schema {} is not {SYNC_FLOOR_SCHEMA_CHIRHO}",
            floor_chirho.schema_chirho
        );
    }
    Ok(Some(floor_chirho.min_anchor_record_count_chirho))
}

/// Persist the floor durably (temp + rename + fsync via `write_file_durable_chirho`), so a crash
/// mid-write can never leave a torn floor that would weaken the next pull's anti-rollback check.
pub fn write_sync_floor_chirho(replica_root_chirho: &Path, count_chirho: u64) -> Result<()> {
    let floor_chirho = SyncFloorChirho {
        schema_chirho: SYNC_FLOOR_SCHEMA_CHIRHO.to_string(),
        min_anchor_record_count_chirho: count_chirho,
    };
    let bytes_chirho = serde_json::to_vec_pretty(&floor_chirho).context("render sync floor")?;
    write_file_durable_chirho(
        &replica_root_chirho.join(SYNC_FLOOR_FILE_CHIRHO),
        &bytes_chirho,
    )
    .context("write sync floor")
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn tmp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-syncfloor-{label_chirho}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root_chirho);
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    #[test]
    fn floor_roundtrips_and_missing_reads_none_chirho() {
        let root_chirho = tmp_root_chirho("roundtrip");
        assert_eq!(read_sync_floor_chirho(&root_chirho).unwrap(), None);
        write_sync_floor_chirho(&root_chirho, 7).unwrap();
        assert_eq!(read_sync_floor_chirho(&root_chirho).unwrap(), Some(7));
        write_sync_floor_chirho(&root_chirho, 9).unwrap();
        assert_eq!(read_sync_floor_chirho(&root_chirho).unwrap(), Some(9));
    }

    #[test]
    fn floor_with_a_foreign_schema_fails_closed_chirho() {
        let root_chirho = tmp_root_chirho("schema");
        std::fs::write(
            root_chirho.join(SYNC_FLOOR_FILE_CHIRHO),
            br#"{"schema_chirho":"not-a-floor-chirho","min_anchor_record_count_chirho":1}"#,
        )
        .unwrap();
        let message_chirho = read_sync_floor_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(
            message_chirho.contains("is not replica-sync-floor-v1-chirho"),
            "{message_chirho}"
        );
    }

    #[test]
    fn torn_floor_bytes_fail_closed_not_default_chirho() {
        let root_chirho = tmp_root_chirho("torn");
        std::fs::write(root_chirho.join(SYNC_FLOOR_FILE_CHIRHO), b"{trunca").unwrap();
        assert!(read_sync_floor_chirho(&root_chirho).is_err());
    }
}
