// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_core_chirho::model_chirho::{CapabilityChirho, NodeDefChirho, PortChirho};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

/// Each fixture's own number in this test process. The wall clock alone cannot name a root: macOS's realtime clock
/// ticks in whole microseconds, and this module's tests start together, so two fixtures once shared a root and one
/// test's tampered object reached another's snapshot.
static NEXT_FIXTURE_CHIRHO: AtomicU64 = AtomicU64::new(0);

struct ReadFixtureChirho {
    root_chirho: PathBuf,
    dag_chirho: HashChirho,
    wasm_chirho: HashChirho,
}

impl ReadFixtureChirho {
    fn new_chirho(capabilities_chirho: Vec<CapabilityChirho>) -> Self {
        let stamp_chirho = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture_chirho = NEXT_FIXTURE_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-pure-read-port-{}-{fixture_chirho}-{stamp_chirho}-chirho",
            std::process::id(),
        ));
        // A root that already exists is refused, never shared.
        std::fs::create_dir(&root_chirho).unwrap_or_else(|error_chirho| {
            panic!("the fixture's root must be its own: {error_chirho}")
        });
        let source_chirho = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples-chirho/upcase-chirho.wat"),
        )
        .unwrap();
        let wasm_chirho =
            cairn_chirho::cas_chirho::add_chirho(&root_chirho, &source_chirho).unwrap();
        let node_chirho = cairn_chirho::store_chirho::put_object_chirho(
            &root_chirho,
            &NodeDefChirho {
                name_chirho: "transient-read-chirho".to_string(),
                impl_wasm_chirho: wasm_chirho.clone(),
                entry_chirho: "upcase_chirho".to_string(),
                inputs_chirho: vec![PortChirho {
                    name_chirho: "in_chirho".into(),
                    schema_chirho: HashChirho("bytes-chirho".into()),
                }],
                outputs_chirho: vec![PortChirho {
                    name_chirho: "out_chirho".into(),
                    schema_chirho: HashChirho("bytes-chirho".into()),
                }],
                capabilities_chirho,
                fuel_limit_chirho: 1_000_000,
                ..Default::default()
            },
        )
        .unwrap();
        let dag_chirho = cairn_chirho::store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap();
        // A planted non-CAS file ensures the snapshot observes more than an empty tree.
        std::fs::write(
            root_chirho.join("sentinel-chirho"),
            b"retained evidence chirho",
        )
        .unwrap();
        Self {
            root_chirho,
            dag_chirho,
            wasm_chirho,
        }
    }

    fn runtime_chirho(&self) -> ServedRuntimeRootChirho {
        ServedRuntimeRootChirho::new_chirho(&self.root_chirho)
    }
}

impl Drop for ReadFixtureChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_chirho);
    }
}

type SnapshotChirho = BTreeMap<PathBuf, (u64, SystemTime, String)>;

fn snapshot_chirho(root_chirho: &Path) -> SnapshotChirho {
    fn walk_chirho(base_chirho: &Path, path_chirho: &Path, rows_chirho: &mut SnapshotChirho) {
        let metadata_chirho = std::fs::symlink_metadata(path_chirho).unwrap();
        let digest_chirho = if metadata_chirho.is_file() {
            blake3::hash(&std::fs::read(path_chirho).unwrap())
                .to_hex()
                .to_string()
        } else {
            String::new()
        };
        rows_chirho.insert(
            path_chirho.strip_prefix(base_chirho).unwrap().to_path_buf(),
            (
                metadata_chirho.len(),
                metadata_chirho.modified().unwrap(),
                digest_chirho,
            ),
        );
        if metadata_chirho.is_dir() {
            for entry_chirho in std::fs::read_dir(path_chirho).unwrap() {
                walk_chirho(base_chirho, &entry_chirho.unwrap().path(), rows_chirho);
            }
        }
    }
    let mut rows_chirho = BTreeMap::new();
    walk_chirho(root_chirho, root_chirho, &mut rows_chirho);
    rows_chirho
}

#[test]
fn pure_read_port_executes_wasm_without_cache_intent_or_input_writes_chirho() {
    let fixture_chirho = ReadFixtureChirho::new_chirho(Vec::new());
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    assert!(before_chirho.len() > 4);
    for _attempt_chirho in 0..2 {
        let outcome_chirho = fixture_chirho
            .runtime_chirho()
            .execute_pure_app_read_chirho(
                &fixture_chirho.dag_chirho,
                b"transient private input chirho",
            )
            .unwrap();
        let PureDagOutcomeChirho::PayloadChirho {
            bytes_chirho,
            node_runs_chirho,
            ..
        } = outcome_chirho
        else {
            panic!("pure WASM must execute");
        };
        assert_eq!(bytes_chirho, b"TRANSIENT PRIVATE INPUT CHIRHO");
        assert_eq!(node_runs_chirho.len(), 1);
        assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
    }
}

#[test]
fn pure_read_port_refuses_effects_without_a_durable_change_chirho() {
    let fixture_chirho = ReadFixtureChirho::new_chirho(vec![CapabilityChirho::WriteStoreChirho {
        prefix_chirho: "never-written-chirho".into(),
    }]);
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    assert!(matches!(
        fixture_chirho
            .runtime_chirho()
            .execute_pure_app_read_chirho(&fixture_chirho.dag_chirho, b"private chirho",)
            .unwrap(),
        PureDagOutcomeChirho::RefusedEffectfulChirho { .. }
    ));
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
}

#[test]
fn pure_read_port_rejects_tampered_code_before_execution_chirho() {
    let fixture_chirho = ReadFixtureChirho::new_chirho(Vec::new());
    std::fs::write(
        fixture_chirho
            .root_chirho
            .join("objects-chirho")
            .join(&fixture_chirho.wasm_chirho.0[..2])
            .join(&fixture_chirho.wasm_chirho.0[2..]),
        b"tampered code chirho",
    )
    .unwrap();
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    assert!(fixture_chirho
        .runtime_chirho()
        .execute_pure_app_read_chirho(&fixture_chirho.dag_chirho, b"private chirho",)
        .is_err());
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
}

#[test]
fn pure_read_port_bounds_object_reads_and_rejects_invalid_addresses_chirho() {
    let fixture_chirho = ReadFixtureChirho::new_chirho(Vec::new());
    let store_chirho = PureReadContentChirho(&fixture_chirho.root_chirho);
    assert!(store_chirho
        .get_chirho(&HashChirho("../../outside-chirho".into()))
        .is_err());
    let large_chirho = vec![b'x'; PURE_READ_OBJECT_MAX_BYTES_CHIRHO as usize + 1];
    let large_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(&fixture_chirho.root_chirho, &large_chirho).unwrap();
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    assert!(store_chirho.get_chirho(&large_hash_chirho).is_err());
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
}

/// THE FIXTURE'S OWN ROOT. Two fixtures alive at once hold two roots: their paths differ, and the first one's tampered
/// code object and sentinel never reach the second's snapshot. Both hold the same content-addressed objects at the same
/// relative paths, so a shared root would show the tamper there.
///
/// MIGRATION PATH: a panic "the fixture's root must be its own" means two fixtures were given one name, and the
/// exclusive create refused to share it; an unequal snapshot means the roots were shared anyway. Either brings back
/// the cross-test contamination this module's no-write snapshots cannot tell apart from a write by the port.
#[test]
fn two_live_fixtures_own_distinct_roots_chirho() {
    let first_chirho = ReadFixtureChirho::new_chirho(Vec::new());
    let second_chirho = ReadFixtureChirho::new_chirho(Vec::new());
    assert_ne!(first_chirho.root_chirho, second_chirho.root_chirho);
    assert_eq!(first_chirho.wasm_chirho, second_chirho.wasm_chirho);
    let second_before_chirho = snapshot_chirho(&second_chirho.root_chirho);
    std::fs::write(
        first_chirho
            .root_chirho
            .join("objects-chirho")
            .join(&first_chirho.wasm_chirho.0[..2])
            .join(&first_chirho.wasm_chirho.0[2..]),
        b"tampered code chirho",
    )
    .unwrap();
    std::fs::write(
        first_chirho.root_chirho.join("sentinel-chirho"),
        b"the first fixture's own chirho",
    )
    .unwrap();
    assert_eq!(
        snapshot_chirho(&second_chirho.root_chirho),
        second_before_chirho
    );
}
