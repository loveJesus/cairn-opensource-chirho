// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The execute-loop — run one WASM node under a fuel budget.
//!
//! Brick 1: a single `i64 -> i64` entry, fuel-metered. Typed ports, the result
//! cache, epoch-yield, and effects via blessed modules land in later bricks.
//! Fuel metering is here from the first brick on purpose — it is the unit we
//! will meter and monitor clients by.

use crate::module_cache_chirho::{cached_module_chirho, shared_engine_chirho};
use anyhow::{anyhow, bail, Result};
use wasmtime::{Instance, Memory, Store};

pub const DEFAULT_WASM_MAX_OUTPUT_BYTES_CHIRHO: usize = 10 * 1024 * 1024;
pub const DEFAULT_WASM_MAX_MEMORY_BYTES_CHIRHO: usize = 256 * 1024 * 1024;

/// The outcome of executing one node: its result and the fuel it consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcomeChirho {
    pub result_chirho: i64,
    pub fuel_used_chirho: u64,
}

/// Execute a WASM module's `entry` function (`i64 -> i64`) under a hard fuel cap.
/// The module may be WASM binary or WAT text. Out-of-fuel traps surface as an error.
pub fn run_node_chirho(
    wasm_chirho: &[u8],
    entry_chirho: &str,
    input_chirho: i64,
    fuel_limit_chirho: u64,
) -> Result<RunOutcomeChirho> {
    run_node_with_limits_chirho(
        wasm_chirho,
        entry_chirho,
        input_chirho,
        fuel_limit_chirho,
        DEFAULT_WASM_MAX_MEMORY_BYTES_CHIRHO,
    )
}

pub fn run_node_with_limits_chirho(
    wasm_chirho: &[u8],
    entry_chirho: &str,
    input_chirho: i64,
    fuel_limit_chirho: u64,
    max_memory_bytes_chirho: usize,
) -> Result<RunOutcomeChirho> {
    // One shared engine and one compile per distinct guest (`module_cache_chirho`); the Store below stays per call.
    let engine_chirho = shared_engine_chirho()?;
    let module_chirho = cached_module_chirho(wasm_chirho)?;

    struct StoreStateChirho {
        limits_chirho: wasmtime::StoreLimits,
    }
    let state_chirho = StoreStateChirho {
        limits_chirho: wasmtime::StoreLimitsBuilder::new()
            .memory_size(max_memory_bytes_chirho)
            .table_elements(10_000)
            .trap_on_grow_failure(true)
            .build(),
    };
    let mut store_chirho = Store::new(engine_chirho, state_chirho);
    store_chirho.limiter(|state_chirho| &mut state_chirho.limits_chirho);
    store_chirho.set_fuel(fuel_limit_chirho)?;

    let instance_chirho = Instance::new(&mut store_chirho, &module_chirho, &[])?;
    let func_chirho =
        instance_chirho.get_typed_func::<i64, i64>(&mut store_chirho, entry_chirho)?;
    let result_chirho = func_chirho.call(&mut store_chirho, input_chirho)?;

    let remaining_chirho = store_chirho.get_fuel()?;
    Ok(RunOutcomeChirho {
        result_chirho,
        fuel_used_chirho: fuel_limit_chirho.saturating_sub(remaining_chirho),
    })
}

/// The outcome of executing a byte-transform node: its output bytes and fuel consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesOutcomeChirho {
    pub output_chirho: Vec<u8>,
    pub fuel_used_chirho: u64,
}

/// Execute a node under the cairn **bytes ABI**, under a hard fuel cap.
///
/// The bytes ABI (v1) — the guest module exports:
///   * `memory` — its linear memory;
///   * `alloc_chirho(len: i32) -> i32` — reserve `len` bytes, return a pointer;
///   * `entry(ptr: i32, len: i32) -> i64` — read `len` input bytes at `ptr`, compute, write
///     output bytes into its memory, and return a packed `(out_ptr << 32) | out_len`.
///
/// The host allocates the input buffer in guest memory, writes the input, calls the entry,
/// and reads the output back. This is the boundary that lets real text/blob nodes run while
/// staying capability-sandboxed; `i64 -> i64` (`run_node_chirho`) remains for scalars.
pub fn run_node_bytes_chirho(
    wasm_chirho: &[u8],
    entry_chirho: &str,
    input_chirho: &[u8],
    fuel_limit_chirho: u64,
) -> Result<BytesOutcomeChirho> {
    run_node_bytes_with_limits_chirho(
        wasm_chirho,
        entry_chirho,
        input_chirho,
        fuel_limit_chirho,
        DEFAULT_WASM_MAX_OUTPUT_BYTES_CHIRHO,
        DEFAULT_WASM_MAX_MEMORY_BYTES_CHIRHO,
    )
}

pub fn run_node_bytes_with_limits_chirho(
    wasm_chirho: &[u8],
    entry_chirho: &str,
    input_chirho: &[u8],
    fuel_limit_chirho: u64,
    max_output_bytes_chirho: usize,
    max_memory_bytes_chirho: usize,
) -> Result<BytesOutcomeChirho> {
    // One shared engine and one compile per distinct guest (`module_cache_chirho`); the Store below stays per call.
    let engine_chirho = shared_engine_chirho()?;
    let module_chirho = cached_module_chirho(wasm_chirho)?;

    struct StoreStateChirho {
        limits_chirho: wasmtime::StoreLimits,
    }
    let state_chirho = StoreStateChirho {
        limits_chirho: wasmtime::StoreLimitsBuilder::new()
            .memory_size(max_memory_bytes_chirho)
            .table_elements(10_000)
            .trap_on_grow_failure(true)
            .build(),
    };
    let mut store_chirho = Store::new(engine_chirho, state_chirho);
    store_chirho.limiter(|state_chirho| &mut state_chirho.limits_chirho);
    store_chirho.set_fuel(fuel_limit_chirho)?;
    let instance_chirho = Instance::new(&mut store_chirho, &module_chirho, &[])?;

    let memory_chirho: Memory = instance_chirho
        .get_memory(&mut store_chirho, "memory")
        .ok_or_else(|| anyhow!("node exports no `memory` — required by the bytes ABI"))?;
    let alloc_chirho =
        instance_chirho.get_typed_func::<i32, i32>(&mut store_chirho, "alloc_chirho")?;
    let entry_fn_chirho =
        instance_chirho.get_typed_func::<(i32, i32), i64>(&mut store_chirho, entry_chirho)?;

    // Place the input in guest memory.
    let in_len_chirho = i32::try_from(input_chirho.len())
        .map_err(|_| anyhow!("input too large for the v1 bytes ABI"))?;
    let in_ptr_chirho = alloc_chirho.call(&mut store_chirho, in_len_chirho)?;
    memory_chirho.write(
        &mut store_chirho,
        in_ptr_chirho as u32 as usize,
        input_chirho,
    )?;

    // Run, then unpack (out_ptr << 32) | out_len.
    let packed_chirho = entry_fn_chirho.call(&mut store_chirho, (in_ptr_chirho, in_len_chirho))?;
    let out_ptr_chirho = ((packed_chirho >> 32) & 0xFFFF_FFFF) as usize;
    let out_len_chirho = (packed_chirho & 0xFFFF_FFFF) as usize;
    if out_len_chirho > max_output_bytes_chirho {
        bail!(
            "WASM node output has {} bytes, over max {}",
            out_len_chirho,
            max_output_bytes_chirho
        );
    }
    let out_end_chirho = out_ptr_chirho
        .checked_add(out_len_chirho)
        .ok_or_else(|| anyhow!("WASM node output range overflows host usize"))?;
    if out_end_chirho > memory_chirho.data_size(&store_chirho) {
        bail!(
            "WASM node output range {}..{} exceeds guest memory size {}",
            out_ptr_chirho,
            out_end_chirho,
            memory_chirho.data_size(&store_chirho)
        );
    }

    let mut output_chirho = vec![0u8; out_len_chirho];
    memory_chirho.read(&store_chirho, out_ptr_chirho, &mut output_chirho)?;

    let remaining_chirho = store_chirho.get_fuel()?;
    Ok(BytesOutcomeChirho {
        output_chirho,
        fuel_used_chirho: fuel_limit_chirho.saturating_sub(remaining_chirho),
    })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    const DOUBLE_WAT_CHIRHO: &str = r#"
        (module
          (func (export "double_chirho") (param i64) (result i64)
            local.get 0
            i64.const 2
            i64.mul))
    "#;

    #[test]
    fn runs_and_meters_fuel_chirho() {
        let outcome_chirho =
            run_node_chirho(DOUBLE_WAT_CHIRHO.as_bytes(), "double_chirho", 21, 10_000).unwrap();
        assert_eq!(outcome_chirho.result_chirho, 42);
        assert!(outcome_chirho.fuel_used_chirho > 0);
    }

    const UPCASE_WAT_CHIRHO: &str = include_str!("../../../../examples-chirho/upcase-chirho.wat");
    const REVERSE_WAT_CHIRHO: &str = include_str!("../../../../examples-chirho/reverse-chirho.wat");
    const DISHONEST_HUGE_OUTPUT_WAT_CHIRHO: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc_chirho") (param i32) (result i32)
            i32.const 0)
          (func (export "entry_chirho") (param i32 i32) (result i64)
            i64.const 4294967296
            i64.const 1024
            i64.or))
    "#;
    const GROWING_ALLOC_WAT_CHIRHO: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc_chirho") (param i32) (result i32)
            i32.const 2
            memory.grow
            drop
            i32.const 0)
          (func (export "entry_chirho") (param i32 i32) (result i64)
            i64.const 0))
    "#;

    #[test]
    fn upcase_bytes_under_fuel_chirho() {
        let outcome_chirho = run_node_bytes_chirho(
            UPCASE_WAT_CHIRHO.as_bytes(),
            "upcase_chirho",
            b"hello, world!",
            1_000_000,
        )
        .unwrap();
        assert_eq!(outcome_chirho.output_chirho, b"HELLO, WORLD!");
        assert!(outcome_chirho.fuel_used_chirho > 0);
    }

    #[test]
    fn rejects_oversized_output_chirho() {
        let result_chirho = run_node_bytes_with_limits_chirho(
            UPCASE_WAT_CHIRHO.as_bytes(),
            "upcase_chirho",
            b"hello, world!",
            1_000_000,
            5,
            64 * 1024 * 1024,
        );
        let err_chirho = result_chirho.unwrap_err().to_string();
        assert!(err_chirho.contains("over max 5"), "{err_chirho}");
    }

    #[test]
    fn rejects_guest_declared_oversized_output_before_host_allocation_chirho() {
        let result_chirho = run_node_bytes_with_limits_chirho(
            DISHONEST_HUGE_OUTPUT_WAT_CHIRHO.as_bytes(),
            "entry_chirho",
            b"x",
            1_000_000,
            8,
            64 * 1024 * 1024,
        );
        let err_chirho = result_chirho.unwrap_err().to_string();
        assert!(err_chirho.contains("over max 8"), "{err_chirho}");
    }

    #[test]
    fn store_limits_reject_guest_memory_growth_chirho() {
        let result_chirho = run_node_bytes_with_limits_chirho(
            GROWING_ALLOC_WAT_CHIRHO.as_bytes(),
            "entry_chirho",
            b"x",
            1_000_000,
            1024,
            64 * 1024,
        );
        let err_chirho = format!("{:#}", result_chirho.unwrap_err());
        assert!(err_chirho.contains("growing memory"), "{err_chirho}");
    }

    #[test]
    fn reverse_bytes_under_fuel_chirho() {
        let outcome_chirho = run_node_bytes_chirho(
            REVERSE_WAT_CHIRHO.as_bytes(),
            "reverse_chirho",
            b"abcde",
            1_000_000,
        )
        .unwrap();
        assert_eq!(outcome_chirho.output_chirho, b"edcba");
        assert!(outcome_chirho.fuel_used_chirho > 0);
    }
}
