// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Structural boundary for the CF7 operator control.
//!
//! The money path is admitted only by the test-kind winner opener already composed on the shared
//! cluster elector. Its request surface is a root-confined Unix socket, never the geo mesh listener.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const OPERATOR_BIN_CHIRHO: &str =
    env!("CARGO_BIN_EXE_cairn-ledger-geo-node-testkind-operator-chirho");
const OPERATOR_BIN_NAME_CHIRHO: &str = "cairn-ledger-geo-node-testkind-operator-chirho";

fn source_chirho(relative_chirho: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_chirho))
        .expect("read test-kind operator source")
}

fn occurrences_chirho(haystack_chirho: &str, needle_chirho: &str) -> usize {
    haystack_chirho.match_indices(needle_chirho).count()
}

#[test]
fn serve_binaries_select_their_admission_and_share_only_the_testkind_sidecar_chirho() {
    let main_chirho = source_chirho("src/main.rs");
    let placement_main_chirho =
        source_chirho("src/bin/cairn-ledger-geo-node-placement-testkind-chirho.rs");
    let shipping_main_chirho = source_chirho("../cairn-ledger-geo-node-chirho/src/main.rs");
    let sidecar_serve_chirho = "serve_testkind_roster_wide_gd7_voter_geo_node_chirho";
    assert_eq!(
        occurrences_chirho(&main_chirho, sidecar_serve_chirho),
        2,
        "the feature-gated test-kind composition must appear once in the import and once at the call site"
    );
    assert_eq!(
        occurrences_chirho(&main_chirho, "testkind_resident_opener_chirho"),
        2,
        "the call must retain the test-kind shared-elector compensation-provider opener"
    );
    assert_eq!(
        occurrences_chirho(&main_chirho, "start_testkind_cf7_operator_control_chirho"),
        2,
        "the local-owner sidecar factory must start the test-kind CF7 control"
    );
    assert!(
        !main_chirho.contains("serve_resident_gd7_voter_geo_node_with_resident_opener_chirho("),
        "the test-kind binary must not silently select the no-sidecar composition"
    );
    assert_eq!(
        occurrences_chirho(
            &placement_main_chirho,
            "serve_resident_gd7_voter_geo_node_with_resident_opener_and_local_owner_sidecar_chirho"
        ),
        2,
        "the placement test-kind binary must import and call the production-required sidecar wrapper"
    );
    assert_eq!(
        occurrences_chirho(&placement_main_chirho, "testkind_resident_opener_chirho"),
        2,
        "the placement target must retain the same synthetic compensation-provider opener"
    );
    assert_eq!(
        occurrences_chirho(
            &placement_main_chirho,
            "start_testkind_cf7_operator_control_chirho"
        ),
        2,
        "the placement target must retain the same root-confined operator sidecar"
    );
    assert!(
        !placement_main_chirho.contains(sidecar_serve_chirho),
        "the placement target must not select feature-gated roster-wide admission"
    );
    assert_eq!(
        occurrences_chirho(
            &placement_main_chirho,
            "GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho"
        ),
        1,
        "only the explicit placement-testkind mode may select resident-owner recomposition"
    );
    assert!(
        !main_chirho.contains("RecomposeLocalOwnerChirho")
            && !shipping_main_chirho.contains("RecomposeLocalOwnerChirho"),
        "resident-owner transfer startup must remain unreachable from both ordinary serve mains"
    );
}

#[test]
fn operator_transport_has_unix_custody_and_no_mesh_capable_primitive_chirho() {
    let control_chirho = source_chirho("src/operator_control_chirho.rs");
    let client_chirho = source_chirho("src/bin/cairn-ledger-geo-node-testkind-operator-chirho.rs");
    assert_eq!(
        occurrences_chirho(&control_chirho, "UnixListener::bind("),
        1,
        "the control must have exactly one filesystem-custodied listener"
    );
    for forbidden_chirho in ["TcpListener", "TcpStream", "SocketAddr", "tokio::net"] {
        assert!(
            !control_chirho.contains(forbidden_chirho) && !client_chirho.contains(forbidden_chirho),
            "the operator transport must stay off the election/relay mesh: {forbidden_chirho}"
        );
    }
    for authority_door_chirho in [
        "open_resident_effect_journal_handle_chirho",
        "open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho",
        "open_resident_effect_journal_handle_with_shared_elector_chirho",
        "open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho",
    ] {
        assert!(
            !control_chirho.contains(authority_door_chirho)
                && !client_chirho.contains(authority_door_chirho),
            "the transport may reach only the runtime injected by the geo composition; it may not open an authority door: {authority_door_chirho}"
        );
    }
}

#[test]
fn operator_binary_names_itself_and_refuses_oversize_before_connect_chirho() {
    let version_chirho = Command::new(OPERATOR_BIN_CHIRHO)
        .arg("--version")
        .output()
        .expect("run operator version surface");
    assert!(version_chirho.status.success());
    assert!(
        String::from_utf8(version_chirho.stdout)
            .unwrap()
            .starts_with(&format!("{OPERATOR_BIN_NAME_CHIRHO} ")),
        "a staged operator binary must identify itself"
    );

    let root_chirho =
        std::env::temp_dir().join(format!("cairn-r4b-oversize-{}-chirho", std::process::id()));
    let mut child_chirho = Command::new(OPERATOR_BIN_CHIRHO)
        .arg(&root_chirho)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start operator client");
    child_chirho
        .stdin
        .take()
        .unwrap()
        .write_all(&vec![b'x'; 64 * 1024 + 2])
        .expect("write oversized request");
    let output_chirho = child_chirho
        .wait_with_output()
        .expect("join operator client");
    assert!(!output_chirho.status.success());
    assert!(
        String::from_utf8_lossy(&output_chirho.stderr)
            .contains("TestkindCf7OperatorRequestTooLargeChirho"),
        "oversize must refuse before any socket connection"
    );
}
