// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! B2.2.1 pure executor over the REAL WASM runner: a pure chain runs and reproduces the
//! source-identical output hash; an effect or native node fails closed BY NAME with nothing run;
//! and every content read is verify-on-read (a tampered node def or WASM impl faults, never runs).

use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::{
    CapabilityChirho, DagChirho, EdgeChirho, HashChirho, NodeDefChirho, PortChirho,
    NATIVE_NODE_IMPL_PREFIX_CHIRHO,
};
use cairn_core_chirho::ports_chirho::{ContentReadChirho, ContentStoreChirho, StoreResultChirho};
use cairn_pure_executor_chirho::{run_pure_dag_chirho, PureDagOutcomeChirho};
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const UPCASE_WAT_CHIRHO: &str = r#"(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc_chirho") (param $len i32) (result i32)
    (local $p i32)
    global.get $heap local.set $p
    global.get $heap local.get $len i32.add global.set $heap
    local.get $p)
  (func (export "upcase_chirho") (param $ptr i32) (param $len i32) (result i64)
    (local $i i32) (local $c i32)
    (block $done (loop $loop
      local.get $i local.get $len i32.ge_u br_if $done
      local.get $ptr local.get $i i32.add i32.load8_u local.set $c
      (if (i32.and (i32.ge_u (local.get $c) (i32.const 97)) (i32.le_u (local.get $c) (i32.const 122)))
        (then local.get $ptr local.get $i i32.add local.get $c i32.const 32 i32.sub i32.store8))
      local.get $i i32.const 1 i32.add local.set $i br $loop))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32)) (i64.extend_i32_u (local.get $len)))))"#;

const REVERSE_WAT_CHIRHO: &str = r#"(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc_chirho") (param $len i32) (result i32)
    (local $p i32)
    global.get $heap local.set $p
    global.get $heap local.get $len i32.add global.set $heap
    local.get $p)
  (func (export "reverse_chirho") (param $ptr i32) (param $len i32) (result i64)
    (local $i i32) (local $j i32) (local $a i32) (local $b i32)
    local.get $ptr local.set $i
    local.get $ptr local.get $len i32.add i32.const 1 i32.sub local.set $j
    (block $done (loop $loop
      local.get $i local.get $j i32.ge_s br_if $done
      local.get $i i32.load8_u local.set $a
      local.get $j i32.load8_u local.set $b
      local.get $i local.get $b i32.store8
      local.get $j local.get $a i32.store8
      local.get $i i32.const 1 i32.add local.set $i
      local.get $j i32.const 1 i32.sub local.set $j br $loop))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32)) (i64.extend_i32_u (local.get $len)))))"#;

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-pureexec-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn object_path_chirho(root_chirho: &Path, addr_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&addr_chirho.0[..2])
        .join(&addr_chirho.0[2..])
}

/// Store an impl (WAT or a sentinel string) + a node def referencing it; return the def's hash.
fn store_node_chirho(
    store_chirho: &FsContentStoreChirho,
    name_chirho: &str,
    impl_bytes_chirho: &[u8],
    entry_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let impl_hash_chirho = store_chirho.put_chirho(impl_bytes_chirho).unwrap();
    store_node_with_impl_hash_chirho(
        store_chirho,
        name_chirho,
        impl_hash_chirho,
        entry_chirho,
        capabilities_chirho,
    )
}

/// Store a node def with an explicit impl hash (for native sentinels whose "impl" is a string, not
/// stored WASM).
fn store_node_with_impl_hash_chirho(
    store_chirho: &FsContentStoreChirho,
    name_chirho: &str,
    impl_hash_chirho: HashChirho,
    entry_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let schema_hash_chirho = store_chirho.put_chirho(b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: impl_hash_chirho,
        entry_chirho: entry_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho,
        fuel_limit_chirho: 5_000_000,
        ..Default::default()
    };
    store_chirho
        .put_chirho(&serde_json::to_vec(&node_chirho).unwrap())
        .unwrap()
}

fn edge_chirho(from_chirho: &HashChirho, to_chirho: &HashChirho) -> EdgeChirho {
    EdgeChirho {
        from_node_chirho: from_chirho.clone(),
        from_port_chirho: "out".to_string(),
        to_node_chirho: to_chirho.clone(),
        to_port_chirho: "in".to_string(),
        privacy_chirho: None,
    }
}

const CAP_CHIRHO: usize = 1024 * 1024;

#[test]
fn pure_chain_runs_and_reproduces_source_output_chirho() {
    let root_chirho = tmp_root_chirho("chain");
    let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
    let upcase_chirho = store_node_chirho(
        &store_chirho,
        "upcase",
        UPCASE_WAT_CHIRHO.as_bytes(),
        "upcase_chirho",
        vec![],
    );
    let reverse_chirho = store_node_chirho(
        &store_chirho,
        "reverse",
        REVERSE_WAT_CHIRHO.as_bytes(),
        "reverse_chirho",
        vec![],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![upcase_chirho.clone(), reverse_chirho.clone()],
        edges_chirho: vec![edge_chirho(&upcase_chirho, &reverse_chirho)],
    };

    let outcome_chirho =
        run_pure_dag_chirho(&store_chirho, &dag_chirho, b"hello", CAP_CHIRHO).unwrap();
    match outcome_chirho {
        PureDagOutcomeChirho::PayloadChirho {
            bytes_chirho,
            output_hash_chirho,
            node_runs_chirho,
        } => {
            // "hello" -> upcase "HELLO" -> reverse "OLLEH".
            assert_eq!(bytes_chirho, b"OLLEH");
            // The served payload's content address is exactly what the source would produce — the
            // §5 determinism bind checks against this.
            assert_eq!(output_hash_chirho, hash_chirho(b"OLLEH"));
            assert_eq!(node_runs_chirho.len(), 2);
            assert_eq!(
                node_runs_chirho[0].output_hash_chirho,
                hash_chirho(b"HELLO")
            );
            assert_eq!(
                node_runs_chirho[1].output_hash_chirho,
                hash_chirho(b"OLLEH")
            );
        }
        other_chirho => panic!("expected a payload, got {other_chirho:?}"),
    }
}

#[test]
fn effect_node_fails_closed_naming_the_node_chirho() {
    let root_chirho = tmp_root_chirho("effect");
    let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
    // The effect node's "impl" is deliberately NOT valid WASM: if the authority pre-pass were
    // bypassed and execution attempted, we'd get a WASM-compile Err — so a clean RefusedEffectful
    // proves the refusal happened BEFORE any run.
    let effect_chirho = store_node_chirho(
        &store_chirho,
        "effect",
        b"this is not wasm",
        "entry",
        vec![CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "demo/".to_string(),
        }],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![effect_chirho.clone()],
        edges_chirho: vec![],
    };
    match run_pure_dag_chirho(&store_chirho, &dag_chirho, b"x", CAP_CHIRHO).unwrap() {
        PureDagOutcomeChirho::RefusedEffectfulChirho { node_chirho } => {
            assert_eq!(node_chirho, effect_chirho)
        }
        other_chirho => panic!("expected a refusal naming the effect node, got {other_chirho:?}"),
    }
}

#[test]
fn native_node_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho("native");
    let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
    // A native node is marked by the impl-hash sentinel prefix; capabilities irrelevant.
    let native_impl_chirho = HashChirho(format!(
        "{NATIVE_NODE_IMPL_PREFIX_CHIRHO}{}",
        "a".repeat(64)
    ));
    let native_chirho = store_node_with_impl_hash_chirho(
        &store_chirho,
        "native",
        native_impl_chirho,
        "entry",
        vec![],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![native_chirho.clone()],
        edges_chirho: vec![],
    };
    match run_pure_dag_chirho(&store_chirho, &dag_chirho, b"x", CAP_CHIRHO).unwrap() {
        PureDagOutcomeChirho::RefusedNativeChirho { node_chirho } => {
            assert_eq!(node_chirho, native_chirho)
        }
        other_chirho => panic!("expected a native refusal, got {other_chirho:?}"),
    }
}

#[test]
fn no_partial_execution_before_refusal_chirho() {
    let root_chirho = tmp_root_chirho("no-partial");
    let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
    // A VALID pure node first, then an effect node whose impl is non-WASM. Nothing may run: the
    // whole DAG is refused at the pre-pass, so the pure node never executes and the non-WASM effect
    // impl never reaches the runner (which would Err instead of cleanly refusing).
    let upcase_chirho = store_node_chirho(
        &store_chirho,
        "upcase",
        UPCASE_WAT_CHIRHO.as_bytes(),
        "upcase_chirho",
        vec![],
    );
    let effect_chirho = store_node_chirho(
        &store_chirho,
        "effect",
        b"not wasm either",
        "entry",
        vec![CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "demo/".to_string(),
        }],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![upcase_chirho.clone(), effect_chirho.clone()],
        edges_chirho: vec![edge_chirho(&upcase_chirho, &effect_chirho)],
    };
    match run_pure_dag_chirho(&store_chirho, &dag_chirho, b"hello", CAP_CHIRHO).unwrap() {
        PureDagOutcomeChirho::RefusedEffectfulChirho { node_chirho } => {
            assert_eq!(
                node_chirho, effect_chirho,
                "the effect node is named, and nothing ran"
            )
        }
        other_chirho => panic!("a mixed DAG must refuse whole, got {other_chirho:?}"),
    }
}

#[test]
fn verify_on_read_holds_on_every_node_load_chirho() {
    // Tampering a stored node def: the def load re-hashes and faults before classification.
    let root_chirho = tmp_root_chirho("tamper-def");
    let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
    let upcase_chirho = store_node_chirho(
        &store_chirho,
        "upcase",
        UPCASE_WAT_CHIRHO.as_bytes(),
        "upcase_chirho",
        vec![],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![upcase_chirho.clone()],
        edges_chirho: vec![],
    };
    // Baseline: it runs.
    assert!(matches!(
        run_pure_dag_chirho(&store_chirho, &dag_chirho, b"hi", CAP_CHIRHO).unwrap(),
        PureDagOutcomeChirho::PayloadChirho { .. }
    ));
    // Overwrite the node-def object with different bytes: its address no longer matches.
    std::fs::write(
        object_path_chirho(&root_chirho, &upcase_chirho),
        b"tampered def bytes",
    )
    .unwrap();
    let error_chirho = run_pure_dag_chirho(&store_chirho, &dag_chirho, b"hi", CAP_CHIRHO)
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("verify-on-read")
            || error_chirho.contains("content address mismatch"),
        "{error_chirho}"
    );

    // Tampering the WASM impl object: the impl load re-hashes and faults before the runner sees it.
    let root2_chirho = tmp_root_chirho("tamper-wasm");
    let store2_chirho = FsContentStoreChirho::new_chirho(&root2_chirho);
    let impl_hash_chirho = store2_chirho
        .put_chirho(UPCASE_WAT_CHIRHO.as_bytes())
        .unwrap();
    let node2_chirho = store_node_with_impl_hash_chirho(
        &store2_chirho,
        "upcase",
        impl_hash_chirho.clone(),
        "upcase_chirho",
        vec![],
    );
    let dag2_chirho = DagChirho {
        nodes_chirho: vec![node2_chirho],
        edges_chirho: vec![],
    };
    std::fs::write(
        object_path_chirho(&root2_chirho, &impl_hash_chirho),
        b"tampered wasm bytes",
    )
    .unwrap();
    let error2_chirho = run_pure_dag_chirho(&store2_chirho, &dag2_chirho, b"hi", CAP_CHIRHO)
        .unwrap_err()
        .to_string();
    assert!(
        error2_chirho.contains("verify-on-read")
            || error2_chirho.contains("content address mismatch"),
        "{error2_chirho}"
    );
}

/// THE READ-PORT ARM. `ReadOnlyStoreChirho` implements `ContentReadChirho` and DELIBERATELY NOT
/// `ContentStoreChirho`, so it cannot be handed to anything that still demands the writer
/// supertrait. That it drives a full pure chain to a correct output is the proof that the executor's
/// signatures ask for reads and nothing more.
///
/// This arm is load-bearing, not decorative: widen `run_pure_dag_chirho`'s store parameter back to
/// `&dyn ContentStoreChirho` and this file stops COMPILING at this call — the fixture cannot satisfy
/// a trait it does not implement. A test that merely passed a real store would keep compiling and
/// would prove nothing about the port.
struct ReadOnlyStoreChirho {
    inner_chirho: FsContentStoreChirho,
}

impl ContentReadChirho for ReadOnlyStoreChirho {
    fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        self.inner_chirho.get_chirho(addr_chirho)
    }
}

#[test]
fn a_read_only_port_runs_the_whole_pure_chain_chirho() {
    let root_chirho = tmp_root_chirho("read-only-port");
    let seed_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
    let upcase_chirho = store_node_chirho(
        &seed_chirho,
        "upcase",
        UPCASE_WAT_CHIRHO.as_bytes(),
        "upcase_chirho",
        vec![],
    );
    let reverse_chirho = store_node_chirho(
        &seed_chirho,
        "reverse",
        REVERSE_WAT_CHIRHO.as_bytes(),
        "reverse_chirho",
        vec![],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![upcase_chirho.clone(), reverse_chirho.clone()],
        edges_chirho: vec![edge_chirho(&upcase_chirho, &reverse_chirho)],
    };

    // Seeding is done; from here the executor sees ONLY a read port.
    let read_only_chirho = ReadOnlyStoreChirho {
        inner_chirho: FsContentStoreChirho::new_chirho(&root_chirho),
    };
    let outcome_chirho =
        run_pure_dag_chirho(&read_only_chirho, &dag_chirho, b"hello", CAP_CHIRHO).unwrap();
    match outcome_chirho {
        PureDagOutcomeChirho::PayloadChirho {
            bytes_chirho,
            node_runs_chirho,
            ..
        } => {
            assert_eq!(bytes_chirho, b"OLLEH".to_vec());
            assert_eq!(node_runs_chirho.len(), 2);
        }
        other_chirho => panic!("a read-only port must run the pure chain, got {other_chirho:?}"),
    }
}
