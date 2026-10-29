// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! M5.4 — compile a DAG to a self-contained wasm artifact for the browser / JS host.
//!
//! v1 (step a): a single **pure**-node DAG compiles to that node's wasm, normalized to a binary
//! module (WAT -> wasm via `wat`) and content-addressed — the §8 compiled-module cache at DAG
//! granularity. The browser/JS host (`client-chirho/host-chirho.js`) loads the artifact and runs
//! it under the bytes ABI; the module's imports are its capabilities (enforced by the wasm
//! sandbox), so no cairn interpreter ships to the client.
//!
//! Staged: multi-node composition (link a pure-node chain into one module — needs a composable
//! shared-memory ABI + `walrus`); effect nodes -> wasm imports; DOM hydration + a browser test.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::{DagChirho, HashChirho, NodeDefChirho};
use cairn_core_chirho::{cas_chirho, store_chirho};
use std::path::Path;

/// Compile a DAG to a self-contained binary wasm artifact; returns its content hash.
pub fn compile_dag_chirho(root_chirho: &Path, dag_chirho: &DagChirho) -> Result<HashChirho> {
    if dag_chirho.nodes_chirho.len() != 1 {
        bail!(
            "v1 compiler handles a single pure-node DAG; multi-node composition is staged ({} nodes)",
            dag_chirho.nodes_chirho.len()
        );
    }
    let node_def_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(root_chirho, &dag_chirho.nodes_chirho[0])?;
    if !node_def_chirho.is_pure_chirho() {
        bail!("v1 compiler handles pure nodes only; effect-node imports are staged");
    }
    let impl_bytes_chirho = cas_chirho::get_chirho(root_chirho, &node_def_chirho.impl_wasm_chirho)?;
    // Normalize WAT (or pass-through binary) to a binary wasm module a browser can load.
    let wasm_binary_chirho = wat::parse_bytes(&impl_bytes_chirho)
        .map_err(|e_chirho| anyhow!("compile WAT->wasm: {e_chirho}"))?
        .into_owned();
    Ok(cas_chirho::add_chirho(root_chirho, &wasm_binary_chirho)?)
}

/// Compose composable step fragments (func bodies sharing one memory + `$alloc_chirho`) into one
/// self-contained wasm module exporting `run_chirho`, which runs the chain (each step's packed
/// output feeds the next). `import_decls_chirho` are the module's wasm imports — its effect
/// capabilities: a pure module passes none; an effectful one declares exactly the effects it uses,
/// which the JS host / wasmtime must supply. The novel multi-node composition: many nodes -> one
/// browser-ready wasm whose imports are its capabilities.
pub fn compose_app_chirho(
    import_decls_chirho: &[&str],
    fragments_chirho: &[&str],
) -> Result<Vec<u8>> {
    if fragments_chirho.is_empty() {
        bail!("compose needs at least one step");
    }
    let mut wat_chirho = String::new();
    wat_chirho.push_str("(module\n");
    for import_decl_chirho in import_decls_chirho {
        wat_chirho.push_str("  ");
        wat_chirho.push_str(import_decl_chirho);
        wat_chirho.push('\n');
    }
    wat_chirho.push_str("  (memory (export \"memory\") 1)\n");
    wat_chirho.push_str("  (global $heap_chirho (mut i32) (i32.const 1024))\n");
    wat_chirho.push_str(
        "  (func $alloc_chirho (export \"alloc_chirho\") (param $len i32) (result i32)\n    (local $p i32)\n    global.get $heap_chirho local.set $p\n    global.get $heap_chirho local.get $len i32.add global.set $heap_chirho local.get $p)\n",
    );
    for (i_chirho, frag_chirho) in fragments_chirho.iter().enumerate() {
        wat_chirho.push_str(&format!(
            "  (func $step_{i_chirho}_chirho (param $ptr i32) (param $len i32) (result i64)\n{frag_chirho}\n  )\n"
        ));
    }
    wat_chirho.push_str(
        "  (func (export \"run_chirho\") (param $ptr i32) (param $len i32) (result i64)\n    (local $packed_chirho i64)\n    local.get $ptr local.get $len call $step_0_chirho local.set $packed_chirho\n",
    );
    for i_chirho in 1..fragments_chirho.len() {
        wat_chirho.push_str(&format!(
            "    (i32.wrap_i64 (i64.shr_u (local.get $packed_chirho) (i64.const 32))) (i32.wrap_i64 (i64.and (local.get $packed_chirho) (i64.const 0xffffffff))) call $step_{i_chirho}_chirho local.set $packed_chirho\n"
        ));
    }
    wat_chirho.push_str("    local.get $packed_chirho)\n)\n");
    wat::parse_str(&wat_chirho).map_err(|e_chirho| anyhow!("compose WAT->wasm: {e_chirho}"))
}

/// Compose a pure chain (no effect imports). Thin wrapper over [`compose_app_chirho`].
pub fn compose_steps_chirho(fragments_chirho: &[&str]) -> Result<Vec<u8>> {
    compose_app_chirho(&[], fragments_chirho)
}

const UPCASE_STEP_CHIRHO: &str = include_str!("../../../../examples-chirho/upcase-step-chirho.wat");
const REVERSE_STEP_CHIRHO: &str =
    include_str!("../../../../examples-chirho/reverse-step-chirho.wat");
const EMIT_STEP_CHIRHO: &str = include_str!("../../../../examples-chirho/emit-step-chirho.wat");

/// The demo composed chain (upcase -> reverse) as one wasm — used by the CLI + the serve route.
pub fn demo_chain_wasm_chirho() -> Result<Vec<u8>> {
    compose_steps_chirho(&[UPCASE_STEP_CHIRHO, REVERSE_STEP_CHIRHO])
}

/// The demo EFFECTFUL chain (upcase -> dom_patch): the wasm imports the blessed `dom_patch_chirho`
/// browser effect and calls it with the transformed buffer. The import is the capability — a pure
/// module has none; this one declares exactly the effect it uses, which the host must supply.
pub fn demo_effect_chain_wasm_chirho() -> Result<Vec<u8>> {
    compose_app_chirho(
        &["(import \"cairn_chirho\" \"dom_patch_chirho\" (func $dom_patch_chirho (param i32 i32)))"],
        &[UPCASE_STEP_CHIRHO, EMIT_STEP_CHIRHO],
    )
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::model_chirho::PortChirho;
    use cairn_wasmtime_runner_chirho::runner_chirho;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-compile-test-{nanos_chirho}-{n_chirho}"))
    }

    #[test]
    fn compiles_single_node_to_runnable_wasm_chirho() {
        let root_chirho = tmp_root_chirho();
        let upcase_wat_chirho = include_str!("../../../../examples-chirho/upcase-chirho.wat");
        let impl_hash_chirho =
            cas_chirho::add_chirho(&root_chirho, upcase_wat_chirho.as_bytes()).unwrap();
        let schema_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"bytes").unwrap();
        let node_chirho = NodeDefChirho {
            name_chirho: "upcase_chirho".to_string(),
            impl_wasm_chirho: impl_hash_chirho,
            entry_chirho: "upcase_chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho,
            }],
            capabilities_chirho: vec![],
            effect_contract_set_chirho: None,
            fuel_limit_chirho: 1_000_000,
            max_output_bytes_chirho:
                cairn_core_chirho::model_chirho::DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
            max_memory_bytes_chirho:
                cairn_core_chirho::model_chirho::DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
        };
        let node_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
        let dag_chirho = DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        };

        let artifact_hash_chirho = compile_dag_chirho(&root_chirho, &dag_chirho).unwrap();
        let artifact_chirho = cas_chirho::get_chirho(&root_chirho, &artifact_hash_chirho).unwrap();
        // The artifact is a binary wasm module (the \0asm magic) ...
        assert_eq!(&artifact_chirho[0..4], b"\0asm");
        // ... and runs under the bytes ABI, producing the same output as the source.
        let outcome_chirho = runner_chirho::run_node_bytes_chirho(
            &artifact_chirho,
            "upcase_chirho",
            b"hello",
            1_000_000,
        )
        .unwrap();
        assert_eq!(outcome_chirho.output_chirho, b"HELLO");

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn composes_chain_to_runnable_wasm_chirho() {
        let upcase_step_chirho = include_str!("../../../../examples-chirho/upcase-step-chirho.wat");
        let reverse_step_chirho =
            include_str!("../../../../examples-chirho/reverse-step-chirho.wat");
        let wasm_chirho = compose_steps_chirho(&[upcase_step_chirho, reverse_step_chirho]).unwrap();
        assert_eq!(&wasm_chirho[0..4], b"\0asm");
        // One composed module runs the chain: upcase("hello") = "HELLO", then reverse = "OLLEH".
        let outcome_chirho =
            runner_chirho::run_node_bytes_chirho(&wasm_chirho, "run_chirho", b"hello", 1_000_000)
                .unwrap();
        assert_eq!(outcome_chirho.output_chirho, b"OLLEH");
    }

    #[test]
    fn composes_effectful_app_chirho() {
        // An effectful module imports dom_patch_chirho. wat::parse validates the WAT (the import
        // decl + the call), so a \0asm result means the effectful composition is well-formed.
        let wasm_chirho = demo_effect_chain_wasm_chirho().unwrap();
        assert_eq!(&wasm_chirho[0..4], b"\0asm");
    }
}
