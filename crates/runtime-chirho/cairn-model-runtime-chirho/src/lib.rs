// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure runtime package model records.
//!
//! This crate owns serializable runtime package DTOs only. It does not compile DAGs, read a cairn
//! root, gather package closures, validate stored modules, or serve artifacts.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

use cairn_core_chirho::model_chirho::{CapabilityChirho, HashChirho, PortChirho};
use serde::{Deserialize, Serialize};

pub const BYTES_ABI_CHIRHO: &str = "bytes-abi-v1-chirho";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeProfileKindChirho {
    BrowserChirho,
    EmbeddedChirho,
    ServerChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuntimePackageItemKindChirho {
    ExecutableWasmChirho,
    BytesAbiChirho,
    PortSchemaHashesChirho,
    ImportManifestChirho,
    ModuleDescriptorChirho,
    DagDescriptorChirho,
    NodeDescriptorsChirho,
    WasmSourceObjectsChirho,
    LedgerDescriptorsChirho,
    ResourceDescriptorsChirho,
    OwnerDescriptorsChirho,
    SchedulerDescriptorsChirho,
    ProvenanceDescriptorsChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePackageChirho {
    pub profile_chirho: RuntimeProfileKindChirho,
    pub module_chirho: HashChirho,
    pub dag_chirho: HashChirho,
    pub executable_chirho: HashChirho,
    pub entry_chirho: String,
    pub abi_chirho: String,
    pub inputs_chirho: Vec<PortChirho>,
    pub outputs_chirho: Vec<PortChirho>,
    pub capabilities_chirho: Vec<CapabilityChirho>,
    pub included_items_chirho: Vec<RuntimePackageItemKindChirho>,
    pub excluded_items_chirho: Vec<RuntimePackageItemKindChirho>,
    pub object_hashes_chirho: Vec<HashChirho>,
}

/// The PURE public-artifact contract (M150): only browser/embedded profiles are public.
/// Extracted from the root `runtime_profile_chirho` (which re-exports it) so capability-free
/// consumers — the read-only replica serve adapter — enforce the identical contract without root
/// authority. Deep module/DAG cross-validation stays a root/deploy-time concern.
pub fn is_public_runtime_profile_chirho(profile_chirho: RuntimeProfileKindChirho) -> bool {
    matches!(
        profile_chirho,
        RuntimeProfileKindChirho::BrowserChirho | RuntimeProfileKindChirho::EmbeddedChirho
    )
}

/// A well-formed content address: exactly 64 lower-case hex digits (a blake3 digest). A hash that
/// arrives inside a MANIFEST is data, not a proven address — an ill-formed one must never reach a
/// store read, where it can panic a sharded-path split or address something that is not an object
/// at all.
fn is_lower_hex64_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
}

/// Every hash a runtime package carries must be a well-formed content address BEFORE any consumer
/// reads a store with it. Manifest-sourced hashes are untrusted input on a replica: an empty or
/// multi-byte-char value panics a naive sharded-path split, and a `..`-bearing value would address
/// a file outside the object tree — verify-on-read (M142) would still refuse the CONTENT, but a
/// store read must not be reachable with a string that is not an address in the first place.
pub fn ensure_runtime_package_hashes_well_formed_chirho(
    package_chirho: &RuntimePackageChirho,
) -> anyhow::Result<()> {
    let mut named_chirho: Vec<(&str, &HashChirho)> = vec![
        ("module", &package_chirho.module_chirho),
        ("dag", &package_chirho.dag_chirho),
        ("executable", &package_chirho.executable_chirho),
    ];
    named_chirho.extend(
        package_chirho
            .object_hashes_chirho
            .iter()
            .map(|hash_chirho| ("object", hash_chirho)),
    );
    for (label_chirho, hash_chirho) in named_chirho {
        if !is_lower_hex64_chirho(&hash_chirho.0) {
            anyhow::bail!(
                "runtime package {label_chirho} hash is not a 64-hex content address (refusing to \
                 read a store with a manifest-supplied non-address)"
            );
        }
    }
    Ok(())
}

/// The pure public-artifact gate: well-formed hashes, public profile, capability-free, and exposing
/// ONLY the executable bytes. Hash well-formedness is checked FIRST, so no consumer of a gated
/// package can reach a store read with a manifest-supplied non-address. Otherwise behavior-identical
/// to the pre-extraction root implementation (the root crate's gate tests keep pinning it through
/// the re-export).
pub fn ensure_public_runtime_package_artifact_chirho(
    package_chirho: &RuntimePackageChirho,
) -> anyhow::Result<()> {
    ensure_runtime_package_hashes_well_formed_chirho(package_chirho)?;
    if !is_public_runtime_profile_chirho(package_chirho.profile_chirho) {
        anyhow::bail!("server runtime packages are not public artifacts");
    }
    if !package_chirho.capabilities_chirho.is_empty() {
        anyhow::bail!("runtime package public artifacts must be capability-free");
    }
    if package_chirho.object_hashes_chirho != vec![package_chirho.executable_chirho.clone()] {
        anyhow::bail!("runtime package public artifacts must expose only executable bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn runtime_profile_kind_serialization_stays_stable_chirho() {
        assert_eq!(
            serde_json::to_string(&RuntimeProfileKindChirho::BrowserChirho).unwrap(),
            "\"BrowserChirho\""
        );
        assert_eq!(
            serde_json::to_string(&RuntimeProfileKindChirho::EmbeddedChirho).unwrap(),
            "\"EmbeddedChirho\""
        );
        assert_eq!(
            serde_json::to_string(&RuntimeProfileKindChirho::ServerChirho).unwrap(),
            "\"ServerChirho\""
        );
    }

    #[test]
    fn runtime_package_item_kind_serialization_stays_stable_chirho() {
        assert_eq!(
            serde_json::to_string(&RuntimePackageItemKindChirho::ExecutableWasmChirho).unwrap(),
            "\"ExecutableWasmChirho\""
        );
        assert_eq!(
            serde_json::to_string(&RuntimePackageItemKindChirho::ProvenanceDescriptorsChirho)
                .unwrap(),
            "\"ProvenanceDescriptorsChirho\""
        );
    }
}
