// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The compiled-module cache: one compile per distinct guest with identical outcomes and fuel; bounded by count and by
//! compiled bytes, least recently used first; an oversize module never cached; concurrent calls safe; fuel and memory
//! limits still per call. Each arm's guests carry a unique comment, so parallel tests never share a cache key.

use super::module_compile_metrics_chirho::compiles_chirho;
use super::*;
use crate::runner_chirho::{
    run_node_bytes_chirho, run_node_bytes_with_limits_chirho, run_node_chirho,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

/// A tag unique to this call, so a guest's bytes (and so its cache key) are unique to the arm that uses it. The WAT
/// parser drops comments, so the compiled code is the same either way.
fn unique_tag_chirho(label_chirho: &str) -> String {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{label_chirho}-{nanos_chirho}-{}",
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
    )
}

/// A bytes-ABI guest that echoes its input.
fn echo_wat_chirho(tag_chirho: &str) -> String {
    format!(
        r#";; {tag_chirho}
(module
  (memory (export "memory") 1)
  (func (export "alloc_chirho") (param i32) (result i32) i32.const 0)
  (func (export "echo_chirho") (param i32 i32) (result i64)
    local.get 1
    i64.extend_i32_u))
"#
    )
}

/// A bytes-ABI guest that answers a fixed byte, whatever its input, through a DIFFERENT entry name.
fn fixed_wat_chirho(tag_chirho: &str) -> String {
    format!(
        r#";; {tag_chirho}
(module
  (memory (export "memory") 1)
  (data (i32.const 64) "F")
  (func (export "alloc_chirho") (param i32) (result i32) i32.const 0)
  (func (export "fixed_chirho") (param i32 i32) (result i64)
    i64.const 274877906945))
"#
    )
}

/// A scalar guest that loops `n` times, so its fuel use grows with `n`.
fn spin_wat_chirho(tag_chirho: &str) -> String {
    format!(
        r#";; {tag_chirho}
(module
  (func (export "spin_chirho") (param i64) (result i64)
    (local i64)
    (loop $again
      local.get 1
      i64.const 1
      i64.add
      local.set 1
      local.get 1
      local.get 0
      i64.lt_u
      br_if $again)
    local.get 1))
"#
    )
}

/// A bytes-ABI guest whose allocator grows memory by two pages.
fn growing_wat_chirho(tag_chirho: &str) -> String {
    format!(
        r#";; {tag_chirho}
(module
  (memory (export "memory") 1)
  (func (export "alloc_chirho") (param i32) (result i32)
    i32.const 2
    memory.grow
    drop
    i32.const 0)
  (func (export "entry_chirho") (param i32 i32) (result i64)
    i64.const 0))
"#
    )
}

/// A scalar guest with many exported functions, so it compiles to a larger image than the echo guest.
fn big_wat_chirho(tag_chirho: &str) -> String {
    let functions_chirho: String = (0..300)
        .map(|index_chirho| {
            format!(
                "  (func (export \"add_{index_chirho}_chirho\") (param i64) (result i64) local.get 0 i64.const \
                 {index_chirho} i64.add)\n"
            )
        })
        .collect();
    format!(";; {tag_chirho}\n(module\n{functions_chirho})\n")
}

fn compile_chirho(wat_chirho: &str) -> Module {
    Module::new(shared_engine_chirho().unwrap(), wat_chirho).unwrap()
}

fn key_chirho(wat_chirho: &str) -> [u8; 32] {
    *blake3::hash(wat_chirho.as_bytes()).as_bytes()
}

/// THE CACHE'S POINT: the same guest twice compiles ONCE, and the cached run's output and fuel equal the first's.
///
/// MIGRATION PATH: a second compile means every call compiles again (PFE measured that at 56.9% of the editor road);
/// a different output or fuel means a cached module changed an outcome.
#[test]
fn the_same_guest_compiles_once_and_answers_identically_chirho() {
    let wat_chirho = echo_wat_chirho(&unique_tag_chirho("same-guest"));
    let before_chirho = compiles_chirho();
    let first_chirho =
        run_node_bytes_chirho(wat_chirho.as_bytes(), "echo_chirho", b"hello", 1_000_000).unwrap();
    assert_eq!(
        compiles_chirho() - before_chirho,
        1,
        "the first call compiles"
    );
    let second_chirho =
        run_node_bytes_chirho(wat_chirho.as_bytes(), "echo_chirho", b"hello", 1_000_000).unwrap();
    assert_eq!(
        compiles_chirho() - before_chirho,
        1,
        "the second call compiles nothing"
    );
    assert_eq!(first_chirho.output_chirho, b"hello");
    assert_eq!(
        second_chirho, first_chirho,
        "the cached run's output and fuel equal the first's"
    );
}

/// Distinct guests compile once each, and each call runs ITS OWN guest: two guests with different entries and
/// different answers, each run twice.
///
/// MIGRATION PATH: one compile for two guests, or a "fixed" call answering like "echo", means the key no longer
/// separates guests: one guest's compiled code would run for another's bytes.
#[test]
fn distinct_guests_compile_once_each_and_each_runs_its_own_code_chirho() {
    let echo_chirho = echo_wat_chirho(&unique_tag_chirho("distinct-echo"));
    let fixed_chirho = fixed_wat_chirho(&unique_tag_chirho("distinct-fixed"));
    let before_chirho = compiles_chirho();
    for _round_chirho in 0..2 {
        let echoed_chirho =
            run_node_bytes_chirho(echo_chirho.as_bytes(), "echo_chirho", b"xyz", 1_000_000)
                .unwrap();
        assert_eq!(echoed_chirho.output_chirho, b"xyz");
        let fixed_output_chirho =
            run_node_bytes_chirho(fixed_chirho.as_bytes(), "fixed_chirho", b"xyz", 1_000_000)
                .unwrap();
        assert_eq!(fixed_output_chirho.output_chirho, b"F");
    }
    assert_eq!(
        compiles_chirho() - before_chirho,
        2,
        "one compile per distinct guest"
    );
}

/// Bounded by COUNT, least recently used first: three slots, four modules, the one used longest ago is evicted.
///
/// MIGRATION PATH: four entries means the cache grows without bound again.
#[test]
fn the_cache_is_bounded_by_count_least_recently_used_first_chirho() {
    let wats_chirho: Vec<String> = (0..4)
        .map(|index_chirho| echo_wat_chirho(&unique_tag_chirho(&format!("count-{index_chirho}"))))
        .collect();
    let mut cache_chirho = ModuleCacheChirho::new_chirho(3, usize::MAX);
    for wat_chirho in &wats_chirho[..3] {
        cache_chirho.insert_chirho(key_chirho(wat_chirho), compile_chirho(wat_chirho));
    }
    assert!(
        cache_chirho
            .get_chirho(&key_chirho(&wats_chirho[0]))
            .is_some(),
        "use the first, so the second is oldest"
    );
    cache_chirho.insert_chirho(key_chirho(&wats_chirho[3]), compile_chirho(&wats_chirho[3]));
    assert_eq!(cache_chirho.len_chirho(), 3);
    assert!(
        !cache_chirho.contains_chirho(&key_chirho(&wats_chirho[1])),
        "the least recently used is evicted"
    );
    for kept_chirho in [&wats_chirho[0], &wats_chirho[2], &wats_chirho[3]] {
        assert!(cache_chirho.contains_chirho(&key_chirho(kept_chirho)));
    }
}

/// Bounded by COMPILED BYTES (PFE #25894), least recently used first; and a module larger than the byte cap runs but
/// is never cached, so it cannot thrash the others.
///
/// MIGRATION PATH: a total over the cap means eviction ignores bytes; an oversize module in the cache means one huge
/// guest can push every other guest out.
#[test]
fn the_cache_is_bounded_by_bytes_and_never_keeps_an_oversize_module_chirho() {
    let wats_chirho: Vec<String> = (0..3)
        .map(|index_chirho| echo_wat_chirho(&unique_tag_chirho(&format!("bytes-{index_chirho}"))))
        .collect();
    let modules_chirho: Vec<Module> = wats_chirho
        .iter()
        .map(|wat_chirho| compile_chirho(wat_chirho))
        .collect();
    let size_chirho = compiled_bytes_chirho(&modules_chirho[0]);
    assert!(size_chirho > 0, "a compiled module has an image");
    // Room for two modules of this size, not three.
    let cap_chirho = 2 * size_chirho + size_chirho / 2;
    let mut cache_chirho = ModuleCacheChirho::new_chirho(usize::MAX, cap_chirho);
    for (wat_chirho, module_chirho) in wats_chirho.iter().zip(&modules_chirho) {
        cache_chirho.insert_chirho(key_chirho(wat_chirho), module_chirho.clone());
        assert!(
            cache_chirho.total_bytes_chirho() <= cap_chirho,
            "the byte bound holds after every insert"
        );
    }
    assert_eq!(cache_chirho.len_chirho(), 2);
    assert!(
        !cache_chirho.contains_chirho(&key_chirho(&wats_chirho[0])),
        "the least recently used is evicted"
    );

    // The oversize rule's real job: one huge guest must not flush the others. A cache holding one small module meets a
    // module bigger than its whole cap; the small one stays, and the huge one is not kept.
    let big_wat_chirho = big_wat_chirho(&unique_tag_chirho("bytes-big"));
    let big_chirho = compile_chirho(&big_wat_chirho);
    let big_size_chirho = compiled_bytes_chirho(&big_chirho);
    assert!(
        big_size_chirho > 2 * size_chirho,
        "fixture: the big guest compiles larger ({big_size_chirho} against {size_chirho})"
    );
    let mut guarded_chirho =
        ModuleCacheChirho::new_chirho(usize::MAX, size_chirho + size_chirho / 2);
    guarded_chirho.insert_chirho(key_chirho(&wats_chirho[0]), modules_chirho[0].clone());
    guarded_chirho.insert_chirho(key_chirho(&big_wat_chirho), big_chirho);
    assert!(
        guarded_chirho.contains_chirho(&key_chirho(&wats_chirho[0])),
        "the small module survives a module over the byte cap"
    );
    assert!(
        !guarded_chirho.contains_chirho(&key_chirho(&big_wat_chirho)),
        "a module over the byte cap is never cached"
    );
}

/// Eight threads run one guest at the same instant: all succeed with the same answer.
#[test]
fn concurrent_calls_of_one_guest_all_succeed_chirho() {
    let wat_chirho = Arc::new(echo_wat_chirho(&unique_tag_chirho("concurrent")));
    let start_chirho = Arc::new(Barrier::new(8));
    let handles_chirho: Vec<_> = (0..8)
        .map(|_thread_chirho| {
            let wat_chirho = Arc::clone(&wat_chirho);
            let start_chirho = Arc::clone(&start_chirho);
            std::thread::spawn(move || {
                start_chirho.wait();
                run_node_bytes_chirho(wat_chirho.as_bytes(), "echo_chirho", b"together", 1_000_000)
                    .map(|outcome_chirho| outcome_chirho.output_chirho)
                    .map_err(|error_chirho| format!("{error_chirho:#}"))
            })
        })
        .collect();
    for handle_chirho in handles_chirho {
        assert_eq!(handle_chirho.join().unwrap().unwrap(), b"together");
    }
}

/// Fuel and memory limits stay per call through a CACHED module: the second call of each guest compiles nothing, and
/// still runs out of fuel, or is still refused its memory growth, under its own tighter limit.
///
/// MIGRATION PATH: a call that succeeds under its tight limit means a limit leaked across calls with the module.
#[test]
fn limits_stay_per_call_through_a_cached_module_chirho() {
    let spin_chirho = spin_wat_chirho(&unique_tag_chirho("fuel"));
    let ample_chirho =
        run_node_chirho(spin_chirho.as_bytes(), "spin_chirho", 10, 1_000_000).unwrap();
    assert_eq!(ample_chirho.result_chirho, 10);
    let before_chirho = compiles_chirho();
    let starved_chirho = run_node_chirho(spin_chirho.as_bytes(), "spin_chirho", 100_000, 50);
    assert_eq!(
        compiles_chirho(),
        before_chirho,
        "the starved call hit the cache"
    );
    assert!(
        starved_chirho.is_err(),
        "the cached module still runs out of its own fuel"
    );

    let growing_chirho = growing_wat_chirho(&unique_tag_chirho("memory"));
    run_node_bytes_with_limits_chirho(
        growing_chirho.as_bytes(),
        "entry_chirho",
        b"x",
        1_000_000,
        1024,
        1024 * 1024,
    )
    .unwrap();
    let before_chirho = compiles_chirho();
    let refused_chirho = run_node_bytes_with_limits_chirho(
        growing_chirho.as_bytes(),
        "entry_chirho",
        b"x",
        1_000_000,
        1024,
        64 * 1024,
    );
    assert_eq!(
        compiles_chirho(),
        before_chirho,
        "the refused call hit the cache"
    );
    let refusal_chirho = format!("{:#}", refused_chirho.unwrap_err());
    assert!(
        refusal_chirho.contains("growing memory"),
        "{refusal_chirho}"
    );
}

/// For the record (PFE #25894): the compiled size of the repository's example guests, against their WASM size.
#[test]
fn compiled_sizes_are_recorded_chirho() {
    for (name_chirho, wat_chirho) in [
        (
            "upcase",
            include_str!("../../../../examples-chirho/upcase-chirho.wat"),
        ),
        (
            "reverse",
            include_str!("../../../../examples-chirho/reverse-chirho.wat"),
        ),
    ] {
        let compiled_chirho = compiled_bytes_chirho(&compile_chirho(wat_chirho));
        eprintln!(
            "compiled image of the {name_chirho} example: {compiled_chirho} bytes (source {} bytes of WAT)",
            wat_chirho.len()
        );
        assert!(compiled_chirho > 0);
    }
}
