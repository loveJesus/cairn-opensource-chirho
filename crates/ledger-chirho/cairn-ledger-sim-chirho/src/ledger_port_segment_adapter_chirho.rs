// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! B0 brick-1 differential over the PRODUCTION segment adapter.
//!
//! The `SegmentStorageOverLedgerPortChirho` bridge is now production code in `cairn-ledger-log-chirho`
//! (`segment_adapter_chirho`), driven by the journal's real `full_open` base-seq derivation. This
//! sim-scoped module keeps the brick-1 differential — op-by-op fidelity vs `FsSegmentStorageChirho`
//! and the money proof that `derive_base_seq_chirho` is IDENTICAL over the filesystem and the ledger
//! port — now exercising that exact production adapter over a fault-injectable `SimStorageChirho`.

use cairn_ledger_log_chirho::segment_adapter_chirho::SegmentStorageOverLedgerPortChirho;
use cairn_seqlog_chirho::segment_chirho::storage_chirho::{
    SegmentPathChirho, SegmentStorageChirho,
};

#[cfg(test)]
mod tests_chirho {
    use super::*;

    use cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho;
    use cairn_seqlog_chirho::segment_chirho::storage_chirho::FsSegmentStorageChirho;
    use cairn_seqlog_chirho::segment_chirho::LogIdentityChirho;

    use crate::fault_chirho::FaultPlanChirho;
    use crate::mem_segment_storage_tests_chirho::{
        run_derive_scenario_chirho, tmp_root_chirho, TestSegmentContinuityPortChirho,
    };
    use crate::storage_chirho::SimStorageChirho;

    /// The adapter over an in-memory ledger port mirrors `FsSegmentStorageChirho` op-by-op on the flat
    /// data ops the segment machinery uses. Both backends run the identical sequence over the identical
    /// keys and must observe identical results — the 1:1 delegation is faithful.
    #[test]
    fn adapter_over_ledger_port_mirrors_fs_flat_ops_chirho() {
        let root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&root_chirho).unwrap();
        let obj_chirho =
            SegmentPathChirho::from_path_chirho(&root_chirho.join("obj-chirho")).unwrap();
        let renamed_chirho =
            SegmentPathChirho::from_path_chirho(&root_chirho.join("renamed-chirho")).unwrap();
        let absent_chirho =
            SegmentPathChirho::from_path_chirho(&root_chirho.join("absent-chirho")).unwrap();

        let fs_chirho = FsSegmentStorageChirho;
        let sim_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let adapter_chirho = SegmentStorageOverLedgerPortChirho::new_chirho(&sim_chirho);

        // Fresh, independent stores (real files under `root` for fs; the sim's own map for the adapter),
        // keyed by the identical strings — so this is literally the same scenario on both.
        for storage_chirho in [&fs_chirho as &dyn SegmentStorageChirho, &adapter_chirho] {
            // Absent object: read None, len None, exists false.
            assert_eq!(
                storage_chirho.read_all_chirho(&absent_chirho).unwrap(),
                None
            );
            assert_eq!(
                storage_chirho.object_len_chirho(&absent_chirho).unwrap(),
                None
            );
            assert!(!storage_chirho.exists_chirho(&absent_chirho).unwrap());

            // write_durable is an atomic REPLACE; read/len/exists reflect it.
            storage_chirho
                .write_durable_chirho(&obj_chirho, b"abc")
                .unwrap();
            assert_eq!(
                storage_chirho
                    .read_all_chirho(&obj_chirho)
                    .unwrap()
                    .as_deref(),
                Some(b"abc".as_slice())
            );
            assert_eq!(
                storage_chirho.object_len_chirho(&obj_chirho).unwrap(),
                Some(3)
            );
            assert!(storage_chirho.exists_chirho(&obj_chirho).unwrap());
            storage_chirho
                .write_durable_chirho(&obj_chirho, b"wxyz")
                .unwrap();
            assert_eq!(
                storage_chirho
                    .read_all_chirho(&obj_chirho)
                    .unwrap()
                    .as_deref(),
                Some(b"wxyz".as_slice())
            );

            // append_durable EXTENDS the existing value (not a replace).
            storage_chirho
                .append_durable_chirho(&obj_chirho, b"!!")
                .unwrap();
            assert_eq!(
                storage_chirho
                    .read_all_chirho(&obj_chirho)
                    .unwrap()
                    .as_deref(),
                Some(b"wxyz!!".as_slice())
            );

            // read_range: exact window, and fail-closed past EOF / on an absent object.
            assert_eq!(
                storage_chirho.read_range_chirho(&obj_chirho, 0, 4).unwrap(),
                b"wxyz"
            );
            assert!(storage_chirho.read_range_chirho(&obj_chirho, 4, 5).is_err());
            assert!(storage_chirho
                .read_range_chirho(&absent_chirho, 0, 1)
                .is_err());

            // rename moves the value; the old key is then absent, the new key present.
            storage_chirho
                .rename_chirho(&obj_chirho, &renamed_chirho)
                .unwrap();
            assert_eq!(storage_chirho.read_all_chirho(&obj_chirho).unwrap(), None);
            assert_eq!(
                storage_chirho
                    .read_all_chirho(&renamed_chirho)
                    .unwrap()
                    .as_deref(),
                Some(b"wxyz!!".as_slice())
            );
            // renaming an absent source fails closed (fs ENOENT); remove is idempotent.
            assert!(storage_chirho
                .rename_chirho(&obj_chirho, &renamed_chirho)
                .is_err());
            storage_chirho.remove_chirho(&renamed_chirho).unwrap();
            assert!(!storage_chirho.exists_chirho(&renamed_chirho).unwrap());
            storage_chirho.remove_chirho(&renamed_chirho).unwrap();
        }

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    /// `list_dir_chirho` returns ONLY the direct child files of a dir (a nested descendant is excluded),
    /// identical over fs and the ledger-port adapter; `create_dir_all_chirho` is a no-op that invents no
    /// key; and — the exists-FILES-only invariant — a directory never "exists" as an object on the
    /// adapter, so the segment machinery must never `exists`-check a dir.
    #[test]
    fn adapter_list_dir_is_direct_child_files_only_and_dirs_are_implicit_chirho() {
        let root_chirho = tmp_root_chirho();
        let dir_path_chirho = root_chirho.join("seg-dir-chirho");
        let dir_chirho = SegmentPathChirho::from_path_chirho(&dir_path_chirho).unwrap();
        let child_a_chirho =
            SegmentPathChirho::from_path_chirho(&dir_path_chirho.join("a.seg-chirho")).unwrap();
        let child_b_chirho =
            SegmentPathChirho::from_path_chirho(&dir_path_chirho.join("b.seg-chirho")).unwrap();
        let deep_chirho = SegmentPathChirho::from_path_chirho(
            &dir_path_chirho.join("sub-chirho").join("deep-chirho"),
        )
        .unwrap();

        let fs_chirho = FsSegmentStorageChirho;
        let sim_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let adapter_chirho = SegmentStorageOverLedgerPortChirho::new_chirho(&sim_chirho);

        let sorted_children_chirho = |storage_chirho: &dyn SegmentStorageChirho| -> Vec<String> {
            let mut listed_chirho: Vec<String> = storage_chirho
                .list_dir_chirho(&dir_chirho)
                .unwrap()
                .into_iter()
                .map(|path_chirho| path_chirho.0)
                .collect();
            listed_chirho.sort();
            listed_chirho
        };

        // fs: real dirs/files, the deep file under a real sub-dir.
        std::fs::create_dir_all(&dir_path_chirho).unwrap();
        std::fs::create_dir_all(dir_path_chirho.join("sub-chirho")).unwrap();
        fs_chirho
            .write_durable_chirho(&child_a_chirho, b"a")
            .unwrap();
        fs_chirho
            .write_durable_chirho(&child_b_chirho, b"b")
            .unwrap();
        fs_chirho
            .write_durable_chirho(&deep_chirho, b"deep")
            .unwrap();
        // adapter: create_dir_all is a no-op; the identical keys land as flat blobs in the sim store.
        adapter_chirho.create_dir_all_chirho(&dir_chirho).unwrap();
        adapter_chirho
            .write_durable_chirho(&child_a_chirho, b"a")
            .unwrap();
        adapter_chirho
            .write_durable_chirho(&child_b_chirho, b"b")
            .unwrap();
        adapter_chirho
            .write_durable_chirho(&deep_chirho, b"deep")
            .unwrap();

        let expected_chirho = vec![child_a_chirho.0.clone(), child_b_chirho.0.clone()];
        // Only the two DIRECT child files (the sub-dir's deep file excluded), identical fs≡adapter.
        assert_eq!(sorted_children_chirho(&fs_chirho), expected_chirho);
        assert_eq!(sorted_children_chirho(&adapter_chirho), expected_chirho);

        // An absent directory yields an empty listing on both.
        let absent_dir_chirho =
            SegmentPathChirho::from_path_chirho(&root_chirho.join("absent-dir-chirho")).unwrap();
        assert!(fs_chirho
            .list_dir_chirho(&absent_dir_chirho)
            .unwrap()
            .is_empty());
        assert!(adapter_chirho
            .list_dir_chirho(&absent_dir_chirho)
            .unwrap()
            .is_empty());

        // exists-FILES-only: the dir key is not an object on the adapter (dirs are implicit), while its
        // files are — so the segment machinery must exists-check files, never this dir.
        assert!(adapter_chirho.exists_chirho(&child_a_chirho).unwrap());
        assert!(!adapter_chirho.exists_chirho(&dir_chirho).unwrap());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    /// THE B0 brick-1 money proof: the money-critical `derive_base_seq_chirho` derives the IDENTICAL
    /// `BaseSeqChirho` (cold AND warm) whether the segment machinery is driven by the filesystem or by
    /// the money journal's own `LedgerStoragePort` (through the adapter, over an in-memory sim store).
    /// This extends the fs≡mem proof (6226c953) from seqlog's OWN port to the LEDGER's port — so brick 2
    /// can wire the journal's recovery through segments and crash-test that seam entirely in the sim.
    #[test]
    fn derive_base_seq_through_ledger_port_equals_fs_cold_and_warm_chirho() {
        let root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&root_chirho).unwrap();
        let active_chirho = root_chirho.join("derive-ledger-port-diff-chirho.jsonl");
        // ONE path set for both backends: fs writes real files under `root`; the sim keys its map by the
        // identical strings. `BaseSeqChirho` is path-free (log identity is path-free), so identical keys
        // make the scenario literally the same on both.
        let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
        let port_chirho = TestSegmentContinuityPortChirho::new_chirho();
        let identity_chirho = LogIdentityChirho::new_chirho("ledger:adapter-derive-diff-chirho");

        let fs_storage_chirho = FsSegmentStorageChirho;
        let (fs_cold_chirho, fs_warm_chirho) = run_derive_scenario_chirho(
            &fs_storage_chirho,
            &paths_chirho,
            &port_chirho,
            &identity_chirho,
        );

        let sim_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let adapter_chirho = SegmentStorageOverLedgerPortChirho::new_chirho(&sim_chirho);
        let (port_cold_chirho, port_warm_chirho) = run_derive_scenario_chirho(
            &adapter_chirho,
            &paths_chirho,
            &port_chirho,
            &identity_chirho,
        );

        // Each backend is internally consistent: the warm O(1) head path agrees with the cold verify.
        assert_eq!(fs_cold_chirho, fs_warm_chirho);
        assert_eq!(port_cold_chirho, port_warm_chirho);
        // THE differential: base-seq derivation is identical over the filesystem and the ledger port.
        assert_eq!(
            fs_cold_chirho, port_cold_chirho,
            "cold derive must be identical fs ≡ ledger-port"
        );
        assert_eq!(
            fs_warm_chirho, port_warm_chirho,
            "warm derive must be identical fs ≡ ledger-port"
        );
        // …and the derived facts are exactly what the two sealed segments imply: base = 3 + 2 = 5.
        assert_eq!(port_cold_chirho.base_seq_chirho, 5);
        assert_eq!(port_cold_chirho.sealed_segment_count_chirho, 2);
        assert!(port_cold_chirho.last_entry_digest_chirho.is_some());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
