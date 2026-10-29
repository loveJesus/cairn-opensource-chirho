// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! One compiled module per distinct guest, shared by every call in the process: a bounded, least-recently-used cache
//! of wasmtime `Module`s keyed by the blake3 of the module bytes, all compiled by one shared `Engine`.
//!
//! Why: every call used to build a new Engine and compile its guest with Cranelift. PFE measured that at 56.9% of an
//! owner's CPU on the editor road, about 29.5 B instructions per editor save (#25888, #25892). agy ratified this design
//! (#25895); the byte bound is PFE's (#25894).
//! - The guests are instantiated with NO imports, so a compiled module carries no capability. Fuel, the memory and
//!   table limiter and the inputs all stay per Store, per call, so sharing the compiled code changes no outcome.
//! - Bounded (the bounded-growth rule): at most 128 entries AND 256 MiB of compiled image (`Module::image_range`), the
//!   least recently used evicted first. A module larger than the byte cap runs, but is never cached, so it cannot
//!   thrash the others.
//! - A compile runs OUTSIDE the cache lock, so different guests never wait on each other. Two first calls of one guest
//!   may both compile; the second insert keeps the entry already there.
//! - Cold start: the first call of each guest after a process start compiles it, once.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use wasmtime::{Config, Engine, Module};

/// At most this many compiled modules are kept.
pub const MODULE_CACHE_MAX_ENTRIES_CHIRHO: usize = 128;
/// At most this many bytes of compiled image are kept.
pub const MODULE_CACHE_MAX_BYTES_CHIRHO: usize = 256 * 1024 * 1024;

/// The one engine every call compiles and runs with: fuel metering on, as each call's Store requires.
pub(crate) fn shared_engine_chirho() -> Result<&'static Engine> {
    static ENGINE_CHIRHO: OnceLock<std::result::Result<Engine, String>> = OnceLock::new();
    ENGINE_CHIRHO
        .get_or_init(|| {
            let mut config_chirho = Config::new();
            config_chirho.consume_fuel(true);
            Engine::new(&config_chirho).map_err(|error_chirho| format!("{error_chirho:#}"))
        })
        .as_ref()
        .map_err(|error_chirho| anyhow!("the shared wasmtime engine did not build: {error_chirho}"))
}

/// A module's compiled size: its image in memory, code plus metadata.
pub(crate) fn compiled_bytes_chirho(module_chirho: &Module) -> usize {
    let range_chirho = module_chirho.image_range();
    (range_chirho.end as usize).saturating_sub(range_chirho.start as usize)
}

struct CachedModuleChirho {
    module_chirho: Module,
    compiled_bytes_chirho: usize,
    last_use_chirho: u64,
}

/// A bounded, least-recently-used map from a module's bytes hash to its compiled module.
pub(crate) struct ModuleCacheChirho {
    max_entries_chirho: usize,
    max_bytes_chirho: usize,
    entries_chirho: HashMap<[u8; 32], CachedModuleChirho>,
    total_bytes_chirho: usize,
    tick_chirho: u64,
}

impl ModuleCacheChirho {
    pub(crate) fn new_chirho(max_entries_chirho: usize, max_bytes_chirho: usize) -> Self {
        Self {
            max_entries_chirho,
            max_bytes_chirho,
            entries_chirho: HashMap::new(),
            total_bytes_chirho: 0,
            tick_chirho: 0,
        }
    }

    /// The cached module for `key`, marked as used now.
    pub(crate) fn get_chirho(&mut self, key_chirho: &[u8; 32]) -> Option<Module> {
        self.tick_chirho += 1;
        let tick_chirho = self.tick_chirho;
        self.entries_chirho.get_mut(key_chirho).map(|entry_chirho| {
            entry_chirho.last_use_chirho = tick_chirho;
            entry_chirho.module_chirho.clone()
        })
    }

    /// Keep `module` under `key`, unless it alone is over the byte cap or an entry is already there; then evict the
    /// least recently used until both bounds hold.
    pub(crate) fn insert_chirho(&mut self, key_chirho: [u8; 32], module_chirho: Module) {
        let compiled_bytes_chirho = compiled_bytes_chirho(&module_chirho);
        if compiled_bytes_chirho > self.max_bytes_chirho
            || self.entries_chirho.contains_key(&key_chirho)
        {
            return;
        }
        self.tick_chirho += 1;
        self.entries_chirho.insert(
            key_chirho,
            CachedModuleChirho {
                module_chirho,
                compiled_bytes_chirho,
                last_use_chirho: self.tick_chirho,
            },
        );
        self.total_bytes_chirho += compiled_bytes_chirho;
        while self.entries_chirho.len() > self.max_entries_chirho
            || self.total_bytes_chirho > self.max_bytes_chirho
        {
            let Some(oldest_chirho) = self
                .entries_chirho
                .iter()
                .min_by_key(|(_key_chirho, entry_chirho)| entry_chirho.last_use_chirho)
                .map(|(key_chirho, _entry_chirho)| *key_chirho)
            else {
                break;
            };
            if let Some(evicted_chirho) = self.entries_chirho.remove(&oldest_chirho) {
                self.total_bytes_chirho -= evicted_chirho.compiled_bytes_chirho;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len_chirho(&self) -> usize {
        self.entries_chirho.len()
    }

    #[cfg(test)]
    pub(crate) fn total_bytes_chirho(&self) -> usize {
        self.total_bytes_chirho
    }

    #[cfg(test)]
    pub(crate) fn contains_chirho(&self, key_chirho: &[u8; 32]) -> bool {
        self.entries_chirho.contains_key(key_chirho)
    }
}

fn process_cache_chirho() -> &'static Mutex<ModuleCacheChirho> {
    static CACHE_CHIRHO: OnceLock<Mutex<ModuleCacheChirho>> = OnceLock::new();
    CACHE_CHIRHO.get_or_init(|| {
        Mutex::new(ModuleCacheChirho::new_chirho(
            MODULE_CACHE_MAX_ENTRIES_CHIRHO,
            MODULE_CACHE_MAX_BYTES_CHIRHO,
        ))
    })
}

/// The compiled module for these bytes: from the process cache, or compiled now (outside the lock) and kept.
pub(crate) fn cached_module_chirho(wasm_chirho: &[u8]) -> Result<Module> {
    let engine_chirho = shared_engine_chirho()?;
    let key_chirho = *blake3::hash(wasm_chirho).as_bytes();
    if let Some(module_chirho) = process_cache_chirho()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_chirho(&key_chirho)
    {
        return Ok(module_chirho);
    }
    #[cfg(test)]
    module_compile_metrics_chirho::note_compile_chirho();
    let module_chirho = Module::new(engine_chirho, wasm_chirho)?;
    process_cache_chirho()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert_chirho(key_chirho, module_chirho.clone());
    Ok(module_chirho)
}

/// How many guests this thread compiled, for the arms. Thread-local, so parallel tests never perturb one another.
#[cfg(test)]
pub(crate) mod module_compile_metrics_chirho {
    use std::cell::Cell;

    thread_local! {
        static COMPILES_CHIRHO: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn note_compile_chirho() {
        COMPILES_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }

    pub(crate) fn compiles_chirho() -> u64 {
        COMPILES_CHIRHO.with(std::cell::Cell::get)
    }
}

#[cfg(test)]
#[path = "module_cache_tests_chirho.rs"]
mod module_cache_tests_chirho;
