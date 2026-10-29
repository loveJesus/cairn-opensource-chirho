// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use crate::public_evidence_chirho::{
    legacy_public_effect_evidence_path_chirho, public_effect_evidence_path_chirho,
    PublicEffectEvidenceKindChirho, PublicEffectEvidenceRefusalChirho,
    RootPublicEffectEvidenceStoreChirho, MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let count_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-public-effect-evidence-{label_chirho}-{nanos_chirho}-{count_chirho}"
    ));
    fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn digest_chirho(nibble_chirho: char) -> String {
    std::iter::repeat_n(nibble_chirho, 64).collect()
}

#[test]
fn sharded_store_reads_exact_lines_and_legacy_fallback_chirho() {
    let root_chirho = temp_root_chirho("sharded-legacy");
    let store_chirho = RootPublicEffectEvidenceStoreChirho::new_chirho(&root_chirho);
    let intent_ref_chirho = digest_chirho('a');
    let terminal_ref_chirho = digest_chirho('b');
    store_chirho
        .store_line_chirho(
            PublicEffectEvidenceKindChirho::IntentChirho,
            &intent_ref_chirho,
            b"intent-line-chirho",
        )
        .unwrap();
    let intent_path_chirho = public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::IntentChirho,
        &intent_ref_chirho,
    )
    .unwrap();
    assert!(intent_path_chirho.ends_with(format!("intents-chirho/aa/aa/{intent_ref_chirho}.json")));
    let warrant_path_chirho = public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &intent_ref_chirho,
    )
    .unwrap();
    assert!(
        warrant_path_chirho.ends_with(format!("warrants-chirho/aa/aa/{intent_ref_chirho}.json"))
    );
    assert_ne!(
        intent_path_chirho, warrant_path_chirho,
        "families must remain distinct in both canonical paths"
    );
    assert_eq!(
        store_chirho
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::IntentChirho,
                &intent_ref_chirho,
                64,
            )
            .unwrap()
            .unwrap(),
        b"intent-line-chirho"
    );
    let intent_legacy_path_chirho = legacy_public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::IntentChirho,
        &intent_ref_chirho,
    )
    .unwrap();
    fs::write(&intent_legacy_path_chirho, b"intent-line-chirho").unwrap();
    assert_eq!(
        store_chirho
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::IntentChirho,
                &intent_ref_chirho,
                64,
            )
            .unwrap()
            .unwrap(),
        b"intent-line-chirho",
        "byte-identical canonical and legacy coordinates are one immutable object"
    );

    let terminal_legacy_path_chirho = legacy_public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::TerminalChirho,
        &terminal_ref_chirho,
    )
    .unwrap();
    fs::create_dir_all(terminal_legacy_path_chirho.parent().unwrap()).unwrap();
    fs::write(&terminal_legacy_path_chirho, b"terminal-line-chirho").unwrap();
    assert_eq!(
        store_chirho
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::TerminalChirho,
                &terminal_ref_chirho,
                64,
            )
            .unwrap()
            .unwrap(),
        b"terminal-line-chirho"
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn duplicate_layout_conflict_and_oversize_fail_closed_chirho() {
    let root_chirho = temp_root_chirho("conflict-oversize");
    let store_chirho = RootPublicEffectEvidenceStoreChirho::new_chirho(&root_chirho);
    let coordinate_chirho = digest_chirho('c');
    store_chirho
        .store_line_chirho(
            PublicEffectEvidenceKindChirho::IntentChirho,
            &coordinate_chirho,
            b"canonical-chirho",
        )
        .unwrap();
    let legacy_path_chirho = legacy_public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::IntentChirho,
        &coordinate_chirho,
    )
    .unwrap();
    fs::write(&legacy_path_chirho, b"different-chirho").unwrap();
    assert_eq!(
        store_chirho
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::IntentChirho,
                &coordinate_chirho,
                64,
            )
            .unwrap_err(),
        PublicEffectEvidenceRefusalChirho::ImmutableCollisionChirho
    );

    let oversized_ref_chirho = digest_chirho('d');
    assert_eq!(
        store_chirho
            .store_line_chirho(
                PublicEffectEvidenceKindChirho::TerminalChirho,
                &oversized_ref_chirho,
                &vec![b'x'; MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO + 1],
            )
            .unwrap_err(),
        PublicEffectEvidenceRefusalChirho::OversizedLineChirho
    );
    assert!(store_chirho
        .load_bounded_chirho(
            PublicEffectEvidenceKindChirho::IntentChirho,
            &digest_chirho('e'),
            64,
        )
        .unwrap()
        .is_none());

    let warrant_coordinate_chirho = digest_chirho('a');
    let warrant_legacy_path_chirho = legacy_public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &warrant_coordinate_chirho,
    )
    .unwrap();
    fs::create_dir_all(warrant_legacy_path_chirho.parent().unwrap()).unwrap();
    fs::write(&warrant_legacy_path_chirho, b"malformed-warrant-chirho").unwrap();
    assert_eq!(
        store_chirho
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::WarrantChirho,
                &warrant_coordinate_chirho,
                64,
            )
            .unwrap()
            .unwrap(),
        b"malformed-warrant-chirho",
        "the storage layer preserves malformed bytes for the verifying reader to reject"
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[cfg(unix)]
#[test]
fn malformed_alias_and_symlink_coordinates_refuse_without_scanning_chirho() {
    use std::os::unix::fs::symlink;

    let root_chirho = temp_root_chirho("unsafe-files");
    let store_chirho = RootPublicEffectEvidenceStoreChirho::new_chirho(&root_chirho);
    assert_eq!(
        store_chirho
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::IntentChirho,
                "../escape-chirho",
                64,
            )
            .unwrap_err(),
        PublicEffectEvidenceRefusalChirho::InvalidCoordinateChirho
    );

    let hard_link_ref_chirho = digest_chirho('f');
    let hard_link_path_chirho = public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::IntentChirho,
        &hard_link_ref_chirho,
    )
    .unwrap();
    fs::create_dir_all(hard_link_path_chirho.parent().unwrap()).unwrap();
    fs::write(&hard_link_path_chirho, b"aliased-chirho").unwrap();
    fs::hard_link(
        &hard_link_path_chirho,
        hard_link_path_chirho.with_extension("alias-chirho"),
    )
    .unwrap();
    assert!(store_chirho
        .load_bounded_chirho(
            PublicEffectEvidenceKindChirho::IntentChirho,
            &hard_link_ref_chirho,
            64,
        )
        .is_err());

    let symlink_ref_chirho = digest_chirho('1');
    let symlink_path_chirho = public_effect_evidence_path_chirho(
        &root_chirho,
        PublicEffectEvidenceKindChirho::TerminalChirho,
        &symlink_ref_chirho,
    )
    .unwrap();
    fs::create_dir_all(symlink_path_chirho.parent().unwrap()).unwrap();
    let target_chirho = root_chirho.join("target-chirho");
    fs::write(&target_chirho, b"symlink-target-chirho").unwrap();
    symlink(&target_chirho, &symlink_path_chirho).unwrap();
    assert!(store_chirho
        .load_bounded_chirho(
            PublicEffectEvidenceKindChirho::TerminalChirho,
            &symlink_ref_chirho,
            64,
        )
        .is_err());
    fs::remove_dir_all(root_chirho).unwrap();
}
