// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for C2.1 brick 1b-0: the writer-fence read treats only a genuine absence as no fence, so an
//! unexaminable fence never reads as the Local era (agy #29613, gpt #29614, agy #29619).

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

fn root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-writer-head-fence-read-{label_chirho}-{}-{}",
        std::process::id(),
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn fence_path_for_chirho(root_chirho: &Path) -> PathBuf {
    let group_chirho = consistency_group_for_root_chirho(root_chirho).unwrap();
    writer_fence_path_chirho(root_chirho, &group_chirho).unwrap()
}

/// A root holding a valid Elected fence, with the token it was issued under.
fn elected_root_chirho(label_chirho: &str) -> (PathBuf, WriterFenceTokenChirho) {
    let root_chirho = root_chirho(label_chirho);
    let token_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 7).unwrap();
    assert_eq!(
        writer_authority_era_chirho(&root_chirho).unwrap(),
        WriterAuthorityEraChirho::ElectedChirho,
        "the fixture's fence must read Elected before any arm changes it"
    );
    (root_chirho, token_chirho)
}

/// The era read must refuse. The old `exists()` gate read every one of these as Local or followed them.
fn assert_era_refuses_chirho(root_chirho: &Path, case_chirho: &str) {
    let result_chirho = writer_authority_era_chirho(root_chirho);
    assert!(
        result_chirho.is_err(),
        "{case_chirho}: the era read must refuse, got {result_chirho:?}"
    );
}

/// The verify read must call an unexaminable fence corrupt, never "no fence issued".
fn assert_verify_says_corrupt_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    case_chirho: &str,
) {
    assert_eq!(
        verify_writer_fence_for_root_chirho(root_chirho, token_chirho),
        Err(WriterFenceVerifyErrorChirho::CorruptFenceFileChirho),
        "{case_chirho}"
    );
}

#[test]
fn a_genuinely_absent_fence_still_reads_local_and_unissued_chirho() {
    let fresh_chirho = root_chirho("absent");
    assert_eq!(
        writer_authority_era_chirho(&fresh_chirho).unwrap(),
        WriterAuthorityEraChirho::LocalChirho
    );
    // An empty fence directory is still a genuine absence of this group's fence.
    std::fs::create_dir_all(fence_path_for_chirho(&fresh_chirho).parent().unwrap()).unwrap();
    assert_eq!(
        writer_authority_era_chirho(&fresh_chirho).unwrap(),
        WriterAuthorityEraChirho::LocalChirho
    );

    let (root_chirho, token_chirho) = elected_root_chirho("absent-verify");
    std::fs::remove_file(fence_path_for_chirho(&root_chirho)).unwrap();
    assert_eq!(
        verify_writer_fence_for_root_chirho(&root_chirho, &token_chirho),
        Err(WriterFenceVerifyErrorChirho::NoFenceIssuedChirho)
    );
}

#[test]
fn a_dangling_link_at_the_fence_path_refuses_chirho() {
    let (root_chirho, token_chirho) = elected_root_chirho("dangling");
    let fence_chirho = fence_path_for_chirho(&root_chirho);
    std::fs::remove_file(&fence_chirho).unwrap();
    symlink(root_chirho.join("nowhere-chirho.json"), &fence_chirho).unwrap();
    assert_era_refuses_chirho(&root_chirho, "a dangling link");
    assert_verify_says_corrupt_chirho(&root_chirho, &token_chirho, "a dangling link");
}

#[test]
fn a_live_link_to_this_roots_own_valid_fence_refuses_chirho() {
    // The link target is this root's own valid fence, moved aside. The old read followed the link and read
    // Elected; a link to another root's fence would fail its group check anyway and prove nothing.
    let (root_chirho, token_chirho) = elected_root_chirho("live-link");
    let fence_chirho = fence_path_for_chirho(&root_chirho);
    let moved_chirho = root_chirho.join("moved-fence-chirho.json");
    std::fs::rename(&fence_chirho, &moved_chirho).unwrap();
    symlink(&moved_chirho, &fence_chirho).unwrap();
    assert_era_refuses_chirho(&root_chirho, "a live link to a valid fence");
    assert_verify_says_corrupt_chirho(&root_chirho, &token_chirho, "a live link to a valid fence");
}

#[test]
fn a_directory_at_the_fence_path_refuses_chirho() {
    let (root_chirho, token_chirho) = elected_root_chirho("directory");
    let fence_chirho = fence_path_for_chirho(&root_chirho);
    std::fs::remove_file(&fence_chirho).unwrap();
    std::fs::create_dir(&fence_chirho).unwrap();
    assert_era_refuses_chirho(&root_chirho, "a directory at the fence path");
    assert_verify_says_corrupt_chirho(&root_chirho, &token_chirho, "a directory at the fence path");
}

#[test]
fn a_regular_file_where_the_fence_directory_belongs_refuses_chirho() {
    // gpt #29614: probing the fence beneath a regular file answers NotADirectory, which is not NotFound.
    let (root_chirho, token_chirho) = elected_root_chirho("not-a-directory");
    let fence_dir_chirho = fence_path_for_chirho(&root_chirho)
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::remove_dir_all(&fence_dir_chirho).unwrap();
    std::fs::write(&fence_dir_chirho, b"not a directory").unwrap();
    assert_era_refuses_chirho(&root_chirho, "a regular file at the fence directory");
    assert_verify_says_corrupt_chirho(
        &root_chirho,
        &token_chirho,
        "a regular file at the fence directory",
    );
}

#[test]
fn an_unreadable_fence_directory_refuses_chirho() {
    let (root_chirho, token_chirho) = elected_root_chirho("unreadable");
    let fence_dir_chirho = fence_path_for_chirho(&root_chirho)
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::set_permissions(&fence_dir_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
    // A privileged run can still look inside, so the denial cannot be staged there.
    let staged_chirho = std::fs::read_dir(&fence_dir_chirho).is_err();
    if staged_chirho {
        assert_era_refuses_chirho(&root_chirho, "an unreadable fence directory");
        assert_verify_says_corrupt_chirho(
            &root_chirho,
            &token_chirho,
            "an unreadable fence directory",
        );
    }
    std::fs::set_permissions(&fence_dir_chirho, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        staged_chirho,
        "the denial could not be staged: this arm must run unprivileged"
    );
}

#[test]
fn issuance_refuses_over_a_dangling_link_and_leaves_the_link_in_place_chirho() {
    // The old read took a dangling link for no fence. Local issuance then composed geo term 0, passed
    // the latch check and wrote a fresh Local fence over the link, rolling an elected root back to Local.
    let (root_chirho, _token_chirho) = elected_root_chirho("issuance");
    let fence_chirho = fence_path_for_chirho(&root_chirho);
    std::fs::rename(&fence_chirho, root_chirho.join("moved-fence-chirho.json")).unwrap();
    let target_chirho = root_chirho.join("nowhere-chirho.json");
    symlink(&target_chirho, &fence_chirho).unwrap();

    for (case_chirho, result_chirho) in [
        (
            "local issuance",
            issue_writer_fence_for_root_chirho(&root_chirho),
        ),
        (
            "elected issuance",
            issue_elected_writer_fence_for_root_chirho(&root_chirho, 8),
        ),
    ] {
        let error_chirho = result_chirho.expect_err(case_chirho);
        assert!(
            format!("{error_chirho:#}").contains("read bounded fence"),
            "{case_chirho} must refuse at the fence read, got {error_chirho:#}"
        );
    }
    assert_eq!(
        std::fs::read_link(&fence_chirho).unwrap(),
        target_chirho,
        "the link must stay in place"
    );
    assert!(
        !target_chirho.exists(),
        "nothing may be written through the link"
    );
}

fn fence_directory_for_chirho(root_chirho: &Path) -> PathBuf {
    fence_path_for_chirho(root_chirho)
        .parent()
        .unwrap()
        .to_path_buf()
}

/// A link at the fence directory, live or dangling, must refuse the era read, the verify read and both
/// issuance roads at the directory check, and must still be the same link afterwards (gpt #29681).
fn assert_fence_directory_link_refuses_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    case_chirho: &str,
) {
    let fence_dir_chirho = fence_directory_for_chirho(root_chirho);
    let link_target_chirho = std::fs::read_link(&fence_dir_chirho).unwrap();
    let era_error_chirho = writer_authority_era_chirho(root_chirho).expect_err(case_chirho);
    assert!(
        format!("{era_error_chirho:#}").contains("writer fence directory is a link"),
        "{case_chirho}: the era read must refuse at the directory, got {era_error_chirho:#}"
    );
    assert_verify_says_corrupt_chirho(root_chirho, token_chirho, case_chirho);
    for (road_chirho, result_chirho) in [
        (
            "local issuance",
            issue_writer_fence_for_root_chirho(root_chirho),
        ),
        (
            "elected issuance",
            issue_elected_writer_fence_for_root_chirho(root_chirho, 8),
        ),
    ] {
        let error_chirho = result_chirho.expect_err(road_chirho);
        assert!(
            format!("{error_chirho:#}").contains("writer fence directory is a link"),
            "{case_chirho}, {road_chirho}: must refuse at the directory, got {error_chirho:#}"
        );
    }
    assert_eq!(
        std::fs::read_link(&fence_dir_chirho).unwrap(),
        link_target_chirho,
        "{case_chirho}: the link must stay in place"
    );
}

#[test]
fn a_dangling_link_at_the_fence_directory_refuses_chirho() {
    // A present link is not an absent directory, even when nothing is behind it.
    let (root_chirho, token_chirho) = elected_root_chirho("dir-dangling");
    let fence_dir_chirho = fence_directory_for_chirho(&root_chirho);
    std::fs::rename(&fence_dir_chirho, root_chirho.join("moved-fences-chirho")).unwrap();
    let nowhere_chirho = root_chirho.join("nowhere-fences-chirho");
    symlink(&nowhere_chirho, &fence_dir_chirho).unwrap();
    assert_fence_directory_link_refuses_chirho(
        &root_chirho,
        &token_chirho,
        "a dangling directory link",
    );
    assert!(
        !nowhere_chirho.exists(),
        "nothing may be created through the link"
    );
}

#[test]
fn a_live_link_to_this_roots_moved_fence_directory_refuses_chirho() {
    // A leaf-only check followed this link and read Elected from the moved directory.
    let (root_chirho, token_chirho) = elected_root_chirho("dir-live-valid");
    let fence_dir_chirho = fence_directory_for_chirho(&root_chirho);
    let moved_chirho = root_chirho.join("moved-fences-chirho");
    std::fs::rename(&fence_dir_chirho, &moved_chirho).unwrap();
    let moved_fence_chirho =
        moved_chirho.join(fence_path_for_chirho(&root_chirho).file_name().unwrap());
    let fence_bytes_chirho = std::fs::read(&moved_fence_chirho).unwrap();
    symlink(&moved_chirho, &fence_dir_chirho).unwrap();
    assert_fence_directory_link_refuses_chirho(
        &root_chirho,
        &token_chirho,
        "a live link to the moved directory",
    );
    assert_eq!(
        std::fs::read(&moved_fence_chirho).unwrap(),
        fence_bytes_chirho,
        "the valid fence behind the link must be unchanged"
    );
}

#[test]
fn a_live_link_to_an_empty_directory_refuses_and_issues_nothing_through_it_chirho() {
    // gpt #29681: a leaf-only check read no fence through this link, so the era was Local and local
    // issuance wrote a Local fence into the empty directory, rolling the elected root back.
    let (root_chirho, token_chirho) = elected_root_chirho("dir-live-empty");
    let fence_dir_chirho = fence_directory_for_chirho(&root_chirho);
    std::fs::rename(&fence_dir_chirho, root_chirho.join("moved-fences-chirho")).unwrap();
    let empty_chirho = root_chirho.join("empty-fences-chirho");
    std::fs::create_dir(&empty_chirho).unwrap();
    symlink(&empty_chirho, &fence_dir_chirho).unwrap();
    assert_fence_directory_link_refuses_chirho(
        &root_chirho,
        &token_chirho,
        "a live link to an empty directory",
    );
    assert_eq!(
        std::fs::read_dir(&empty_chirho).unwrap().count(),
        0,
        "no fence may be written through the link"
    );
}
