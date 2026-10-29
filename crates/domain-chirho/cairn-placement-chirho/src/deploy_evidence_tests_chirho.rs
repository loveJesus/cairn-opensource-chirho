// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A mislabelled build is refused; a genuine cross-architecture pair is not.

use super::*;

/// The REAL pair deployed on 2026-07-25 — cax11 (Hetzner, Germany) and ruth (OVH, France) — both
/// built from the same tree and SHA-verified at install before anything ran. Using the measured
/// values rather than invented ones keeps this test honest about what it is modelling.
fn measured_aarch64_chirho() -> DeployEvidenceChirho {
    DeployEvidenceChirho {
        source_commit_chirho: "a98acca8".to_string(),
        target_triple_chirho: "aarch64-unknown-linux-gnu.2.35".to_string(),
        host_architecture_chirho: "aarch64".to_string(),
        binary_sha256_chirho: "fd6e7b7a2a4a8650806965fe44583d05741486a40566042ddfc9b64fd400975f"
            .to_string(),
    }
}

fn measured_x86_64_chirho() -> DeployEvidenceChirho {
    DeployEvidenceChirho {
        source_commit_chirho: "a98acca8".to_string(),
        target_triple_chirho: "x86_64-unknown-linux-gnu.2.35".to_string(),
        host_architecture_chirho: "x86_64".to_string(),
        binary_sha256_chirho: "8b79e89c5258c428d59ab13745ff11bf2b283f1f25b449705465d5b38ed60c45"
            .to_string(),
    }
}

#[test]
fn the_measured_cross_architecture_pair_verifies_chirho() {
    let pair_chirho = vec![measured_aarch64_chirho(), measured_x86_64_chirho()];
    verify_deploy_set_chirho(&pair_chirho).expect("the measured pair is well formed");
    assert!(
        is_reviewed_arch_pair_chirho(&pair_chirho),
        "one commit built for both architectures is exactly the pair CF8 clause 12 names"
    );
}

#[test]
fn differing_hashes_across_architectures_are_expected_not_an_alarm_chirho() {
    // The naive check -- "all binary hashes must match" -- would be worse than no check at all: the
    // same source builds to entirely different bytes for different targets, so that rule would fire
    // on every correct heterogeneous fleet and teach everyone to ignore it.
    let pair_chirho = vec![measured_aarch64_chirho(), measured_x86_64_chirho()];
    assert_ne!(
        pair_chirho[0].binary_sha256_chirho, pair_chirho[1].binary_sha256_chirho,
        "the fixture must actually differ, or this test proves nothing"
    );
    assert!(verify_deploy_set_chirho(&pair_chirho).is_ok());
}

#[test]
fn the_same_commit_and_triple_with_different_bytes_is_refused_chirho() {
    // THE REAL ALARM. Same source, same target, different artifact -- one of those two deploys is not
    // what it claims, and which one is unknowable from here, which is why it refuses rather than
    // picking a winner.
    let mut impostor_chirho = measured_aarch64_chirho();
    impostor_chirho.binary_sha256_chirho = "0".repeat(64);
    let set_chirho = vec![measured_aarch64_chirho(), impostor_chirho];
    assert_eq!(
        verify_deploy_set_chirho(&set_chirho),
        Err(DeployEvidenceRefusalChirho::SameBuildDifferentBytesChirho {
            source_commit_chirho: "a98acca8".to_string(),
            target_triple_chirho: "aarch64-unknown-linux-gnu.2.35".to_string(),
        })
    );
    assert!(!is_reviewed_arch_pair_chirho(&set_chirho));
}

#[test]
fn a_binary_labelled_for_the_wrong_architecture_is_refused_chirho() {
    // The mislabelled build: an x86_64 host carrying something declared for aarch64. This is the
    // mistake a heterogeneous fleet actually makes, and it is checkable rather than trusted because
    // the triple names its own architecture first.
    let mut mislabelled_chirho = measured_aarch64_chirho();
    mislabelled_chirho.host_architecture_chirho = "x86_64".to_string();
    assert_eq!(
        mislabelled_chirho.verify_chirho(),
        Err(
            DeployEvidenceRefusalChirho::ArchitectureTripleMismatchChirho {
                host_architecture_chirho: "x86_64".to_string(),
                target_triple_chirho: "aarch64-unknown-linux-gnu.2.35".to_string(),
            }
        )
    );
}

#[test]
fn every_one_of_the_four_fields_is_load_bearing_chirho() {
    // A partial binding is not a binding, so each field is removed in turn rather than trusting that
    // "we check them all" -- which is the claim a single happy-path test would leave unproven.
    for (field_chirho, mutate_chirho) in [
        (
            "source_commit_chirho",
            Box::new(|r_chirho: &mut DeployEvidenceChirho| {
                r_chirho.source_commit_chirho = String::new()
            }) as Box<dyn Fn(&mut DeployEvidenceChirho)>,
        ),
        (
            "target_triple_chirho",
            Box::new(|r_chirho: &mut DeployEvidenceChirho| {
                r_chirho.target_triple_chirho = "   ".to_string()
            }),
        ),
        (
            "host_architecture_chirho",
            Box::new(|r_chirho: &mut DeployEvidenceChirho| {
                r_chirho.host_architecture_chirho = String::new()
            }),
        ),
        (
            "binary_sha256_chirho",
            Box::new(|r_chirho: &mut DeployEvidenceChirho| {
                r_chirho.binary_sha256_chirho = String::new()
            }),
        ),
    ] {
        let mut record_chirho = measured_aarch64_chirho();
        mutate_chirho(&mut record_chirho);
        assert_eq!(
            record_chirho.verify_chirho(),
            Err(DeployEvidenceRefusalChirho::MissingFieldChirho {
                field_chirho: field_chirho.to_string(),
            }),
            "removing {field_chirho} must refuse the record"
        );
    }
}

#[test]
fn two_different_commits_are_not_a_cross_architecture_pair_chirho() {
    // Two binaries from DIFFERENT commits are two deployments that happen to differ, not a pair. The
    // single-commit requirement is what makes "reviewed pair" mean anything.
    let mut other_commit_chirho = measured_x86_64_chirho();
    other_commit_chirho.source_commit_chirho = "deadbeef".to_string();
    let set_chirho = vec![measured_aarch64_chirho(), other_commit_chirho];
    assert!(
        verify_deploy_set_chirho(&set_chirho).is_ok(),
        "each is valid"
    );
    assert!(
        !is_reviewed_arch_pair_chirho(&set_chirho),
        "but they are not a pair -- they were built from different sources"
    );
}
