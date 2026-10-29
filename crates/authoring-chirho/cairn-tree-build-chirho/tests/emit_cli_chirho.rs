// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Producer×consumer byte-seam pin (#5950): the real `tree-build-chirho emit <app_root>` CLI stdout
//! MUST equal the in-process `emit_manifest_bytes_chirho` output byte-for-byte, including exactly one
//! terminal newline. A reviewer re-running the CLI on a checked-in app root reproduces the RAW
//! manifest hash the credits-demo LocalPhaseB smoke records; a `println!` double-newline regression
//! in `cmd_emit_chirho` must make THIS test fire (the unit pin alone cannot catch a CLI divergence
//! because it never runs the binary).

use cairn_tree_build_chirho::emit_chirho::{
    emit_manifest_bytes_chirho, load_app_descriptor_chirho,
};
use cairn_tree_build_chirho::tree_chirho::walk_app_tree_chirho;
use std::path::PathBuf;
use std::process::Command;

fn fixture_app_root_chirho() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../examples-chirho/tree-contact-chirho")
}

#[test]
fn cli_emit_stdout_matches_emit_manifest_bytes_helper_chirho() {
    let app_root_chirho = fixture_app_root_chirho();

    let output_chirho = Command::new(env!("CARGO_BIN_EXE_tree-build-chirho"))
        .arg("emit")
        .arg(&app_root_chirho)
        .output()
        .expect("run tree-build-chirho emit");
    assert!(
        output_chirho.status.success(),
        "tree-build-chirho emit failed: stderr={}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );

    let tree_chirho = walk_app_tree_chirho(&app_root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(&app_root_chirho).expect("app descriptor");
    let helper_bytes_chirho =
        emit_manifest_bytes_chirho(&tree_chirho, &descriptor_chirho).expect("emit bytes");

    assert_eq!(
        output_chirho.stdout, helper_bytes_chirho,
        "CLI emit stdout must equal emit_manifest_bytes_chirho byte-for-byte (single-source seam)"
    );
    assert_eq!(
        helper_bytes_chirho.last().copied(),
        Some(b'\n'),
        "emit bytes end with exactly one terminal newline"
    );
    assert_ne!(
        helper_bytes_chirho
            .get(helper_bytes_chirho.len().wrapping_sub(2))
            .copied(),
        Some(b'\n'),
        "no double terminal newline (a println! regression would add one)"
    );
}
