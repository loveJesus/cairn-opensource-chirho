// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! What was deployed where, bound tightly enough that a wrong-architecture binary cannot pass as right.
//!
//! CF8 clause 12 asks that deploy evidence bind **source commit, target triple, architecture, and
//! binary hash**, including one reviewed aarch64/x86_64 pair. The four together are the claim; any one
//! alone is nearly useless. A binary hash without a triple does not say what it runs on. A triple
//! without a hash does not say which build. A commit without either is a wish.
//!
//! **The hazard this exists to refuse is a mismatch that LOOKS fine.** A heterogeneous fleet builds the
//! same commit twice, and the two artifacts differ in every byte while being equally correct — so
//! "the hashes differ" cannot be the alarm. What must be impossible is an artifact whose declared
//! architecture disagrees with its declared triple, or two deploys claiming the same commit AND the
//! same triple while carrying different bytes. The first is a mislabelled build; the second means one
//! of them is not what it says.
//!
//! Pure: no I/O, no process execution. It judges records someone else gathered, which is deliberate —
//! the gatherer is the part that must run on a host, and this must be testable without one.

use serde::{Deserialize, Serialize};

/// One deployed artifact, bound to what produced it and where it runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployEvidenceChirho {
    /// Full source commit the artifact was built from.
    pub source_commit_chirho: String,
    /// Rust target triple, e.g. `aarch64-unknown-linux-gnu.2.35`.
    pub target_triple_chirho: String,
    /// Architecture as reported by the HOST that ran it, e.g. `aarch64` — deliberately a separate
    /// field from the triple, because the whole point is to catch them disagreeing.
    pub host_architecture_chirho: String,
    /// SHA-256 of the installed bytes.
    pub binary_sha256_chirho: String,
}

/// Why a deploy evidence record, or a set of them, is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeployEvidenceRefusalChirho {
    /// One of the four fields is empty; a partial binding is not a binding.
    MissingFieldChirho { field_chirho: String },
    /// The declared architecture is not the one the target triple names.
    ArchitectureTripleMismatchChirho {
        host_architecture_chirho: String,
        target_triple_chirho: String,
    },
    /// The same commit built for the same triple produced different bytes. One of these is wrong.
    SameBuildDifferentBytesChirho {
        source_commit_chirho: String,
        target_triple_chirho: String,
    },
}

fn require_nonempty_chirho(
    value_chirho: &str,
    field_chirho: &str,
) -> Result<(), DeployEvidenceRefusalChirho> {
    if value_chirho.trim().is_empty() {
        return Err(DeployEvidenceRefusalChirho::MissingFieldChirho {
            field_chirho: field_chirho.to_string(),
        });
    }
    Ok(())
}

impl DeployEvidenceChirho {
    /// Check one record on its own terms.
    pub fn verify_chirho(&self) -> Result<(), DeployEvidenceRefusalChirho> {
        require_nonempty_chirho(&self.source_commit_chirho, "source_commit_chirho")?;
        require_nonempty_chirho(&self.target_triple_chirho, "target_triple_chirho")?;
        require_nonempty_chirho(&self.host_architecture_chirho, "host_architecture_chirho")?;
        require_nonempty_chirho(&self.binary_sha256_chirho, "binary_sha256_chirho")?;
        // The triple names its architecture first, so a disagreement is checkable rather than
        // trusted. `aarch64-unknown-linux-gnu` on an `x86_64` host is a mislabelled build, and it is
        // exactly the mistake a heterogeneous fleet makes.
        if !self
            .target_triple_chirho
            .starts_with(&self.host_architecture_chirho)
        {
            return Err(
                DeployEvidenceRefusalChirho::ArchitectureTripleMismatchChirho {
                    host_architecture_chirho: self.host_architecture_chirho.clone(),
                    target_triple_chirho: self.target_triple_chirho.clone(),
                },
            );
        }
        Ok(())
    }
}

/// Check a set of deploy records together.
///
/// Differing hashes across ARCHITECTURES are expected and correct — the same source builds to
/// different bytes for different targets, which is why a naive "all hashes equal" check would be
/// worse than none. What is refused is the same commit AND the same triple carrying different bytes.
pub fn verify_deploy_set_chirho(
    records_chirho: &[DeployEvidenceChirho],
) -> Result<(), DeployEvidenceRefusalChirho> {
    for record_chirho in records_chirho {
        record_chirho.verify_chirho()?;
    }
    for (index_chirho, left_chirho) in records_chirho.iter().enumerate() {
        for right_chirho in records_chirho.iter().skip(index_chirho + 1) {
            if left_chirho.source_commit_chirho == right_chirho.source_commit_chirho
                && left_chirho.target_triple_chirho == right_chirho.target_triple_chirho
                && left_chirho.binary_sha256_chirho != right_chirho.binary_sha256_chirho
            {
                return Err(DeployEvidenceRefusalChirho::SameBuildDifferentBytesChirho {
                    source_commit_chirho: left_chirho.source_commit_chirho.clone(),
                    target_triple_chirho: left_chirho.target_triple_chirho.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Whether a set spans both architectures CF8 clause 12 names, from ONE source commit.
///
/// The single-commit requirement is the substance: two binaries built from different commits are not
/// a cross-architecture pair, they are two deployments that happen to differ.
pub fn is_reviewed_arch_pair_chirho(records_chirho: &[DeployEvidenceChirho]) -> bool {
    if verify_deploy_set_chirho(records_chirho).is_err() {
        return false;
    }
    let commits_chirho: std::collections::BTreeSet<&str> = records_chirho
        .iter()
        .map(|record_chirho| record_chirho.source_commit_chirho.as_str())
        .collect();
    if commits_chirho.len() != 1 {
        return false;
    }
    let arches_chirho: std::collections::BTreeSet<&str> = records_chirho
        .iter()
        .map(|record_chirho| record_chirho.host_architecture_chirho.as_str())
        .collect();
    arches_chirho.contains("aarch64") && arches_chirho.contains("x86_64")
}

#[cfg(test)]
#[path = "deploy_evidence_tests_chirho.rs"]
mod deploy_evidence_tests_chirho;
