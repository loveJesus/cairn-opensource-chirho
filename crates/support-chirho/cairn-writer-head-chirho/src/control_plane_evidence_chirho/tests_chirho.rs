// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the control-plane law evidence probes and the law marker's durable publication (C2.1 1a-ii).

use super::*;
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// RFC 8032 test-vector public keys 1 and 2: valid, strong and distinct points.
const PIN_ONE_HEX_CHIRHO: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const PIN_TWO_HEX_CHIRHO: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

thread_local! {
    static REPLAY_BARRIERS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    static FAIL_NEXT_REPLAY_BARRIER_CHIRHO: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn note_replay_barrier_chirho() {
    REPLAY_BARRIERS_CHIRHO.with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
}

/// This thread's equal-replay barriers so far; the root handle's arms read it too.
pub(crate) fn replay_barriers_chirho() -> u64 {
    REPLAY_BARRIERS_CHIRHO.with(Cell::get)
}

/// Make this thread's next equal-replay barrier fail.
pub(crate) fn fail_next_replay_barrier_chirho() {
    FAIL_NEXT_REPLAY_BARRIER_CHIRHO.with(|fail_chirho| fail_chirho.set(true));
}

pub(super) fn take_replay_barrier_failure_chirho() -> bool {
    FAIL_NEXT_REPLAY_BARRIER_CHIRHO.with(|fail_chirho| fail_chirho.replace(false))
}

static NEXT_ROOT_CHIRHO: AtomicU64 = AtomicU64::new(0);

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-control-plane-evidence-{label_chirho}-{}-{}",
        std::process::id(),
        NEXT_ROOT_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn marker_chirho(pin_hex_chirho: &str, instance_chirho: &str) -> ControlPlaneLawMarkerChirho {
    ControlPlaneLawMarkerChirho {
        key_id_hex_chirho: ControlPlanePinChirho::from_hex_chirho(pin_hex_chirho)
            .unwrap()
            .key_id_hex_chirho(),
        lineage_chirho: ControlPlaneLineageChirho::new_chirho(
            "tenant-alpha-chirho",
            instance_chirho,
        )
        .unwrap(),
    }
}

fn marker_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO)
}

fn write_marker_bytes_chirho(root_chirho: &Path, bytes_chirho: &[u8]) {
    std::fs::write(marker_path_chirho(root_chirho), bytes_chirho).unwrap();
}

fn read_error_chirho(root_chirho: &Path) -> String {
    read_control_plane_law_marker_chirho(root_chirho)
        .expect_err("the marker must refuse")
        .to_string()
}

// --- the evidence ---

#[test]
fn an_empty_root_shows_no_geo_evidence_chirho() {
    let root_chirho = temp_root_chirho("empty");
    assert_eq!(
        read_control_plane_evidence_chirho(&root_chirho).unwrap(),
        ControlPlaneEvidenceChirho {
            era_elected_chirho: false,
            genesis_marker_present_chirho: false,
            law_marker_chirho: None,
        }
    );
}

#[test]
fn an_elected_era_is_evidence_e1_chirho() {
    let root_chirho = temp_root_chirho("elected");
    crate::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(&root_chirho, 7).unwrap();
    let evidence_chirho = read_control_plane_evidence_chirho(&root_chirho).unwrap();
    assert!(evidence_chirho.era_elected_chirho);
    assert!(!evidence_chirho.genesis_marker_present_chirho);
}

#[test]
fn any_entry_at_the_genesis_guard_name_is_evidence_e2_chirho() {
    let directory_root_chirho = temp_root_chirho("genesis-dir");
    std::fs::create_dir_all(directory_root_chirho.join(GEO_GENESIS_GUARD_DIR_CHIRHO)).unwrap();
    assert!(
        read_control_plane_evidence_chirho(&directory_root_chirho)
            .unwrap()
            .genesis_marker_present_chirho
    );
    // A file in its place still counts: presence is what refuses, never a well-formed shape.
    let file_root_chirho = temp_root_chirho("genesis-file");
    std::fs::write(file_root_chirho.join(GEO_GENESIS_GUARD_DIR_CHIRHO), b"x").unwrap();
    assert!(
        read_control_plane_evidence_chirho(&file_root_chirho)
            .unwrap()
            .genesis_marker_present_chirho
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_root_refuses_instead_of_reading_as_absent_chirho() {
    use std::os::unix::fs::PermissionsExt;
    let root_chirho = temp_root_chirho("unreadable");
    std::fs::set_permissions(&root_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
    let probe_chirho = std::fs::symlink_metadata(root_chirho.join(GEO_GENESIS_GUARD_DIR_CHIRHO));
    // Each probe is called on its own, so each refusal is pinned by its own identity: the evidence
    // read stops at its FIRST failing probe (the era), which alone would leave the other two unarmed.
    let evidence_chirho = read_control_plane_evidence_chirho(&root_chirho);
    let genesis_chirho = root_entry_present_chirho(&root_chirho.join(GEO_GENESIS_GUARD_DIR_CHIRHO));
    let marker_chirho = read_control_plane_law_marker_chirho(&root_chirho);
    std::fs::set_permissions(&root_chirho, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A process that can search a mode-000 directory anyway (root) cannot exercise this arm.
    if probe_chirho.as_ref().err().map(std::io::Error::kind) != Some(ErrorKind::PermissionDenied) {
        return;
    }
    let evidence_error_chirho = format!(
        "{:#}",
        evidence_chirho.expect_err("an unreadable root's evidence must refuse")
    );
    assert!(
        evidence_error_chirho.contains("ControlPlaneEvidenceEraUnreadableChirho"),
        "E1 must refuse, never read as Local: {evidence_error_chirho}"
    );
    assert_eq!(
        genesis_chirho
            .expect_err("E2 must refuse, never read as absent")
            .to_string(),
        "ControlPlaneEvidenceUnreadableChirho"
    );
    assert_eq!(
        marker_chirho
            .expect_err("E3 must refuse, never read as absent")
            .to_string(),
        "ControlPlaneLawMarkerUnreadableChirho"
    );
}

// --- the law marker, read ---

#[test]
fn a_published_marker_reads_back_equal_chirho() {
    let root_chirho = temp_root_chirho("roundtrip");
    let marker_chirho = marker_chirho(PIN_ONE_HEX_CHIRHO, "genesis-0001-chirho");
    publish_control_plane_law_marker_chirho(&root_chirho, &marker_chirho).unwrap();
    assert_eq!(
        read_control_plane_law_marker_chirho(&root_chirho).unwrap(),
        Some(marker_chirho.clone())
    );
    assert_eq!(
        read_control_plane_evidence_chirho(&root_chirho)
            .unwrap()
            .law_marker_chirho,
        Some(marker_chirho)
    );
}

#[cfg(unix)]
#[test]
fn a_marker_that_is_not_a_regular_file_refuses_chirho() {
    let symlink_root_chirho = temp_root_chirho("marker-symlink");
    let target_chirho = symlink_root_chirho.join("elsewhere-chirho.json");
    std::fs::write(&target_chirho, b"{}").unwrap();
    std::os::unix::fs::symlink(&target_chirho, marker_path_chirho(&symlink_root_chirho)).unwrap();
    assert_eq!(
        read_error_chirho(&symlink_root_chirho),
        "ControlPlaneLawMarkerNotRegularFileChirho"
    );
    let directory_root_chirho = temp_root_chirho("marker-dir");
    std::fs::create_dir_all(marker_path_chirho(&directory_root_chirho)).unwrap();
    assert_eq!(
        read_error_chirho(&directory_root_chirho),
        "ControlPlaneLawMarkerNotRegularFileChirho"
    );
}

#[test]
fn a_marker_over_the_bound_refuses_chirho() {
    let root_chirho = temp_root_chirho("marker-large");
    write_marker_bytes_chirho(&root_chirho, &vec![b' '; 4097]);
    assert_eq!(
        read_error_chirho(&root_chirho),
        "ControlPlaneLawMarkerTooLargeChirho"
    );
}

#[test]
fn a_marker_that_does_not_parse_strictly_refuses_chirho() {
    let record_chirho = |key_chirho: &str, tenant_chirho: &str, extra_chirho: &str| {
        format!(
            "{{\"schema_chirho\":\"{CONTROL_PLANE_LAW_MARKER_SCHEMA_CHIRHO}\",\"key_id_hex_chirho\":\"{key_chirho}\",\"tenant_id_chirho\":\"{tenant_chirho}\",\"genesis_instance_id_chirho\":\"g-chirho\"{extra_chirho}}}"
        )
    };
    let cases_chirho = [
        (
            "not json".to_string(),
            "ControlPlaneLawMarkerMalformedChirho",
        ),
        (
            record_chirho(PIN_ONE_HEX_CHIRHO, "t-chirho", ",\"extra_chirho\":1"),
            "ControlPlaneLawMarkerMalformedChirho",
        ),
        (
            record_chirho(PIN_ONE_HEX_CHIRHO, "t-chirho", "").replace(
                CONTROL_PLANE_LAW_MARKER_SCHEMA_CHIRHO,
                "control-plane-law-marker-v0-chirho",
            ),
            "ControlPlaneLawMarkerSchemaChirho",
        ),
        (
            record_chirho(&PIN_ONE_HEX_CHIRHO.to_uppercase(), "t-chirho", ""),
            "ControlPlaneLawMarkerKeyIdChirho",
        ),
        (
            record_chirho(PIN_ONE_HEX_CHIRHO, "t\\u0000x", ""),
            "ControlPlaneLawMarkerLineageChirho",
        ),
    ];
    for (bytes_chirho, expected_chirho) in cases_chirho {
        let root_chirho = temp_root_chirho("marker-strict");
        write_marker_bytes_chirho(&root_chirho, bytes_chirho.as_bytes());
        assert_eq!(
            read_error_chirho(&root_chirho),
            expected_chirho,
            "{bytes_chirho}"
        );
    }
}

// --- the law marker, published ---

#[test]
fn an_equal_replay_succeeds_and_still_runs_its_directory_barrier_chirho() {
    let root_chirho = temp_root_chirho("replay");
    let marker_chirho = marker_chirho(PIN_ONE_HEX_CHIRHO, "genesis-0001-chirho");
    let before_chirho = replay_barriers_chirho();
    publish_control_plane_law_marker_chirho(&root_chirho, &marker_chirho).unwrap();
    assert_eq!(
        replay_barriers_chirho(),
        before_chirho,
        "a fresh publication syncs inside the primitive, not through the replay barrier"
    );
    publish_control_plane_law_marker_chirho(&root_chirho, &marker_chirho).unwrap();
    assert_eq!(
        replay_barriers_chirho(),
        before_chirho + 1,
        "an equal replay must run its own directory barrier (gpt #29485)"
    );
}

#[test]
fn a_different_marker_never_replaces_the_published_one_chirho() {
    let root_chirho = temp_root_chirho("mismatch");
    publish_control_plane_law_marker_chirho(
        &root_chirho,
        &marker_chirho(PIN_ONE_HEX_CHIRHO, "genesis-0001-chirho"),
    )
    .unwrap();
    let published_chirho = std::fs::read(marker_path_chirho(&root_chirho)).unwrap();
    for other_chirho in [
        marker_chirho(PIN_TWO_HEX_CHIRHO, "genesis-0001-chirho"),
        marker_chirho(PIN_ONE_HEX_CHIRHO, "genesis-0002-chirho"),
    ] {
        let error_chirho = publish_control_plane_law_marker_chirho(&root_chirho, &other_chirho)
            .expect_err("a different marker must refuse");
        assert_eq!(
            error_chirho.to_string(),
            "ControlPlaneLawMarkerMismatchChirho"
        );
        assert_eq!(
            std::fs::read(marker_path_chirho(&root_chirho)).unwrap(),
            published_chirho,
            "the published marker must be byte-for-byte unchanged"
        );
    }
}

#[test]
fn publishing_over_a_non_file_refuses_chirho() {
    let root_chirho = temp_root_chirho("publish-over-dir");
    std::fs::create_dir_all(marker_path_chirho(&root_chirho)).unwrap();
    let error_chirho = publish_control_plane_law_marker_chirho(
        &root_chirho,
        &marker_chirho(PIN_ONE_HEX_CHIRHO, "genesis-0001-chirho"),
    )
    .expect_err("a directory at the marker's name must refuse");
    let rendered_chirho = format!("{error_chirho:#}");
    assert!(
        rendered_chirho.contains("ControlPlaneLawMarker"),
        "the refusal must name the marker: {rendered_chirho}"
    );
    assert!(marker_path_chirho(&root_chirho).is_dir());
}

#[test]
fn reading_the_evidence_writes_nothing_chirho() {
    let root_chirho = temp_root_chirho("write-free");
    let entries_chirho = |root_chirho: &Path| -> Vec<String> {
        let mut names_chirho: Vec<String> = std::fs::read_dir(root_chirho)
            .unwrap()
            .map(|entry_chirho| {
                entry_chirho
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names_chirho.sort();
        names_chirho
    };
    let before_chirho = entries_chirho(&root_chirho);
    read_control_plane_evidence_chirho(&root_chirho).unwrap();
    assert_eq!(entries_chirho(&root_chirho), before_chirho);
}
