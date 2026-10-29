// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The I/O adapters that let the pure migration verifiers look at a REAL tenant root.
//!
//! [`super::migration_completeness_chirho`] and [`super::self_containment_chirho`] are deliberately
//! pure — they take an enumerator and a resolver as injected ports so they can be tested without a
//! root and cannot accidentally consult a live filesystem. That purity is worth keeping, so the
//! filesystem reach lives HERE, next to them rather than inside them.
//!
//! **Until this module existed, both ports had zero production implementors.** The rules were built
//! and tested against fixtures, and nothing ever pointed them at a root — so CF8 clause 5's
//! "enumerates every ACTUAL root surface" was not met by code that could only enumerate a `Vec` it
//! was handed. These are the first two implementors that touch real state.

use crate::migration_completeness_chirho::{
    declared_log_surfaces_chirho, RootSurfaceEnumeratorChirho,
};
use crate::self_containment_chirho::{TenantLogReferenceChirho, TenantObjectResolverChirho};
use anyhow::{Context, Result};
use cairn_core_chirho::cas_chirho;
use cairn_core_chirho::model_chirho::{
    effect_signing_message_chirho, EffectChirho, HashChirho, RunKeyChirho,
};
use cairn_core_chirho::object_graph_chirho::scan_hashes_chirho;
use cairn_core_chirho::store_chirho;
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};

/// The top-level surfaces present in one root, read once at construction.
///
/// **Why a snapshot rather than a live read.** [`RootSurfaceEnumeratorChirho`] returns a plain
/// `Vec<String>` with no error channel, and reading a directory can fail. Doing the I/O in the
/// constructor gives that failure somewhere honest to go — an unreadable root becomes a `Result`
/// the caller must handle, instead of an empty list that reads as "this root has no surfaces".
///
/// It also makes the MOMENT explicit. A root is live state; what this holds is what was there when
/// it was opened, and a migration decision taken from it is a decision about that instant.
///
/// **Top-level only, on purpose.** A surface is a root entry — `objects-chirho`, a
/// `*-chirho.jsonl` log, the tenant marker. Recursing would enumerate every content-addressed
/// object in the store, which is not a surface but the CONTENT of one, and would turn a bounded
/// check into a walk of the whole root.
pub struct RootSurfaceSnapshotChirho {
    surfaces_chirho: Vec<String>,
}

impl RootSurfaceSnapshotChirho {
    /// Read the root's top-level entries once.
    ///
    /// A missing or unreadable root is an error, never an empty snapshot. The distinction matters
    /// because the two are opposite findings: an empty snapshot says "nothing to migrate", and an
    /// unreadable root says "I could not look".
    pub fn open_chirho(root_chirho: &Path) -> Result<Self> {
        let entries_chirho = std::fs::read_dir(root_chirho)
            .with_context(|| format!("read root surfaces at {}", root_chirho.display()))?;
        let mut surfaces_chirho = Vec::new();
        for entry_chirho in entries_chirho {
            let entry_chirho = entry_chirho
                .with_context(|| format!("read a root entry at {}", root_chirho.display()))?;
            surfaces_chirho.push(entry_chirho.file_name().to_string_lossy().into_owned());
        }
        // Sorted so a verdict over one root is reproducible run to run; `read_dir` order is not
        // defined, and an unstable observed list makes two identical checks look different.
        surfaces_chirho.sort();
        Ok(Self { surfaces_chirho })
    }

    /// How many surfaces this snapshot saw. A caller that wants to reason about vacuity needs this.
    pub fn observed_count_chirho(&self) -> usize {
        self.surfaces_chirho.len()
    }
}

impl RootSurfaceEnumeratorChirho for RootSurfaceSnapshotChirho {
    fn observed_surfaces_chirho(&self) -> Vec<String> {
        self.surfaces_chirho.clone()
    }
}

/// Resolves hash-named artifacts against exactly ONE tenant root.
///
/// **Tenant scoping is structural here, not a promise.** The resolver holds a single root path and
/// has no other place to look, so it cannot answer the global "does this object exist anywhere"
/// question even by mistake. That distinction is the whole point of the self-containment check: a
/// hash that resolves in a sibling tenant's root is still dangling for THIS tenant, and a resolver
/// with a global view would pass exactly the roots the verifier exists to catch.
///
/// **Why three verified readers and not an existence test.** Declared tenant logs name ordinary CAS
/// objects, run ids stored under `runkeys-chirho`, and effect idempotency keys stored under
/// `effects-chirho`. The CAS reader re-hashes bytes, a run-key reader decodes and re-hashes the
/// structured key, and an effect reader checks both its idempotency-key filename binding and its
/// instance signature. A corrupt or substituted runtime record therefore does not count as
/// resolved merely because a file exists at the expected path.
///
/// **And note which way this one collapses**, because the mirror-image idiom is a live privacy
/// defect elsewhere. Asking `is_ok()` means only a VERIFIED read counts as resolved, so absent,
/// tampered and unreadable all land on `false` — an upper bound on dangling references, refusing to
/// certify. Asking `is_err()` to mean ABSENT is the opposite and is not safe: it treats "I could not
/// read it" as "it is not there", which claims an absence the read never established. That is why
/// this site is sound with the collapsing getter while an absence claim needs
/// [`cas_chirho::read_verified_chirho`].
///
/// The CAS sharding rule is not restated here. Re-deriving `objects-chirho/ab/cdef…` would put a
/// second copy of that layout in the tree, and a second copy can drift without anything noticing.
pub struct TenantScopedArtifactResolverChirho {
    root_chirho: PathBuf,
}

impl TenantScopedArtifactResolverChirho {
    pub fn for_root_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
        }
    }

    fn resolves_run_key_chirho(&self, hash_chirho: &str) -> bool {
        let path_chirho = self.root_chirho.join("runkeys-chirho").join(hash_chirho);
        let Ok(metadata_chirho) = std::fs::symlink_metadata(&path_chirho) else {
            return false;
        };
        if !metadata_chirho.file_type().is_file() {
            return false;
        }
        let Ok(bytes_chirho) = std::fs::read(path_chirho) else {
            return false;
        };
        let Ok(run_key_chirho) = serde_json::from_slice::<RunKeyChirho>(&bytes_chirho) else {
            return false;
        };
        store_chirho::hash_object_chirho(&run_key_chirho)
            .is_ok_and(|address_chirho| address_chirho.0 == hash_chirho)
    }

    fn resolves_effect_chirho(&self, hash_chirho: &str) -> bool {
        let path_chirho = self.root_chirho.join("effects-chirho").join(hash_chirho);
        let Ok(metadata_chirho) = std::fs::symlink_metadata(&path_chirho) else {
            return false;
        };
        if !metadata_chirho.file_type().is_file() {
            return false;
        }
        let Ok(bytes_chirho) = std::fs::read(path_chirho) else {
            return false;
        };
        let Ok(effect_chirho) = serde_json::from_slice::<EffectChirho>(&bytes_chirho) else {
            return false;
        };
        if effect_chirho.idem_key_chirho.0 != hash_chirho {
            return false;
        }
        let Ok(message_chirho) = effect_signing_message_chirho(&effect_chirho) else {
            return false;
        };
        signer_chirho::verify_with_root_pubkey_chirho(
            &self.root_chirho,
            &message_chirho,
            &effect_chirho.sig_chirho,
        )
        .unwrap_or(false)
    }
}

impl TenantObjectResolverChirho for TenantScopedArtifactResolverChirho {
    fn resolves_in_tenant_chirho(&self, hash_chirho: &str) -> bool {
        if hash_chirho.len() != 64
            || !hash_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho)
            })
        {
            return false;
        }
        cas_chirho::get_chirho(&self.root_chirho, &HashChirho(hash_chirho.to_string())).is_ok()
            || self.resolves_run_key_chirho(hash_chirho)
            || self.resolves_effect_chirho(hash_chirho)
    }
}

/// Every hash-shaped token in this root's declared LOG surfaces, with the site that named it.
///
/// **This is CONSERVATIVE, and the direction of its error is the thing to understand.** It reuses
/// [`scan_hashes_chirho`], the same scanner GC marks with: maximal runs of *exactly* 64 hex chars.
/// That length rule is doing real work — a 128-char ed25519 signature is a maximal run of 128, so it
/// is NOT mistaken for two hashes, which is the false positive a naive scan would drown in.
///
/// It still over-approximates, and the over-approximation lands in the FAIL-CLOSED direction: a
/// 64-hex digest that names something other than a supported root artifact — for example a public
/// key or coordinate digest — will still be reported as unresolved. **So an unresolved count is an
/// upper bound on dangling references, not a count of them.** The production resolver does cover
/// the non-CAS runtime records emitted by shipped code: run keys and signed effects.
///
/// The alternative — teaching this the typed schema of all 94 log surfaces so it could tell a
/// content hash from any other digest — would be a large, brittle second copy of every schema, and
/// it would fail silently in the PERMISSIVE direction the day a schema changed. A loud upper bound
/// beats a quiet exact answer that goes stale.
///
/// Only DECLARED log surfaces are scanned, which is the scope the clause names ("every tenant-log
/// content hash"). A root entry that is not a declared log is completeness's business, not this
/// function's.
///
/// `seq_chirho` is the 1-based LINE ORDINAL within the surface, not a ledger sequence number. It
/// exists so an operator can find the site; do not read it as a log's own sequence.
pub fn tenant_log_references_chirho(root_chirho: &Path) -> Result<Vec<TenantLogReferenceChirho>> {
    let mut references_chirho = Vec::new();
    for surface_chirho in declared_log_surfaces_chirho() {
        let path_chirho = root_chirho.join(&surface_chirho);
        if !path_chirho.is_file() {
            continue;
        }
        let bytes_chirho = std::fs::read(&path_chirho)
            .with_context(|| format!("read log surface {}", path_chirho.display()))?;
        let text_chirho = String::from_utf8_lossy(&bytes_chirho);
        for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
            for hash_chirho in scan_hashes_chirho(line_chirho.as_bytes()) {
                references_chirho.push(TenantLogReferenceChirho {
                    log_name_chirho: surface_chirho.clone(),
                    seq_chirho: index_chirho as u64 + 1,
                    hash_chirho: hash_chirho.0,
                });
            }
        }
    }
    Ok(references_chirho)
}

#[cfg(test)]
#[path = "root_surfaces_tests_chirho.rs"]
mod root_surfaces_tests_chirho;
