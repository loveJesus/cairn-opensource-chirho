// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

#![allow(clippy::enum_variant_names)]

//! Operator evidence smokes: end-to-end harnesses that drive a checked-in example through the real
//! runtime and emit path-redacted, schema-tagged evidence an operator can review.
//!
//! Three harnesses live here — the contact example, the agent-authored backend, and the credits-demo
//! LocalPhaseB arc. Each proves a shipped example still works against real HTTP or a real store; none
//! of them authorizes hosting, cutover, or deletion.

pub mod agent_authored_backend_smoke_chirho;
pub(crate) mod cas_absence_evidence_chirho;
pub mod contact_example_smoke_chirho;
pub mod credits_demo_smoke_chirho;

pub(crate) fn workspace_root_for_operator_smoke_chirho() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .to_path_buf()
}
