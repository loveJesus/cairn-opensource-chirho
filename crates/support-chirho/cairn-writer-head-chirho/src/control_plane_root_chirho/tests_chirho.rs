// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for C2.1 brick 1b-1a: binding refuses a contradicted law, a bound handle refuses once its root or evidence changes, and a write holds the law lock from its signature to its commit.

use super::*;
use crate::control_plane_evidence_chirho::{
    publish_control_plane_law_marker_chirho, read_control_plane_law_marker_chirho,
};
use crate::writer_head_chirho::WRITER_FENCE_LOCK_CHIRHO;
use cairn_seqlog_chirho::seqlog_chirho::{with_append_log_lock_chirho, with_named_lock_chirho};
use cairn_signer_chirho::control_plane_signer_chirho::{
    select_control_plane_law_chirho, ControlPlaneConfigChirho, ControlPlaneEvidenceChirho,
    ControlPlaneLineageChirho, ControlPlanePinChirho, ControlPlaneSignerChirho,
    ControlPlaneVerifierChirho,
};
use ed25519_dalek::SigningKey;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use zeroize::Zeroizing;

const SEED_A_CHIRHO: [u8; 32] = [7; 32];
const SEED_B_CHIRHO: [u8; 32] = [9; 32];
const FAMILY_CHIRHO: ControlPlaneFamilyChirho = ControlPlaneFamilyChirho::AppRecordsChirho;

fn new_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-control-plane-root-{label_chirho}-{}-{}",
        std::process::id(),
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn verifier_chirho(seed_chirho: [u8; 32]) -> ControlPlaneVerifierChirho {
    let key_chirho = SigningKey::from_bytes(&seed_chirho);
    ControlPlaneVerifierChirho::new_chirho(
        ControlPlanePinChirho::from_hex_chirho(&hex_chirho(key_chirho.verifying_key().as_bytes()))
            .unwrap(),
        ControlPlaneLineageChirho::new_chirho("tenant-alpha-chirho", "genesis-0001-chirho")
            .unwrap(),
    )
}

fn no_evidence_chirho() -> ControlPlaneEvidenceChirho {
    ControlPlaneEvidenceChirho {
        era_elected_chirho: false,
        genesis_marker_present_chirho: false,
        law_marker_chirho: None,
    }
}

/// The lineage law a composition would choose from a reviewed config holding this seed's signer.
fn lineage_law_chirho(seed_chirho: [u8; 32]) -> ControlPlaneLawChirho {
    let signer_chirho = ControlPlaneSignerChirho::from_seed_chirho(
        Zeroizing::new(seed_chirho),
        verifier_chirho(seed_chirho),
    )
    .unwrap();
    let config_chirho =
        ControlPlaneConfigChirho::new_chirho(verifier_chirho(seed_chirho), Some(signer_chirho))
            .unwrap();
    select_control_plane_law_chirho(Some(config_chirho), &no_evidence_chirho()).unwrap()
}

fn node_key_law_chirho() -> ControlPlaneLawChirho {
    select_control_plane_law_chirho(None, &no_evidence_chirho()).unwrap()
}

fn refusal_text_chirho<T: std::fmt::Debug>(result_chirho: Result<T>) -> String {
    format!("{:#}", result_chirho.expect_err("must refuse"))
}

#[test]
fn binding_refuses_a_law_the_evidence_contradicts_chirho() {
    let geo_chirho = new_root_chirho("bind-geo");
    std::fs::create_dir(geo_chirho.join(GEO_GENESIS_GUARD_DIR_CHIRHO)).unwrap();
    assert!(refusal_text_chirho(ControlPlaneRootChirho::bind_chirho(
        &geo_chirho,
        node_key_law_chirho()
    ))
    .contains("ControlPlaneLawPinMissingOnGeoRootChirho"));

    let other_pin_chirho = new_root_chirho("bind-other-pin");
    publish_control_plane_law_marker_chirho(
        &other_pin_chirho,
        &ControlPlaneLawMarkerChirho::for_verifier_chirho(&verifier_chirho(SEED_B_CHIRHO)),
    )
    .unwrap();
    assert!(refusal_text_chirho(ControlPlaneRootChirho::bind_chirho(
        &other_pin_chirho,
        lineage_law_chirho(SEED_A_CHIRHO)
    ))
    .contains("ControlPlaneLawMarkerMismatchChirho"));

    // Controls: each law binds where its evidence agrees.
    ControlPlaneRootChirho::bind_chirho(&new_root_chirho("bind-plain"), node_key_law_chirho())
        .unwrap();
    ControlPlaneRootChirho::bind_chirho(&other_pin_chirho, lineage_law_chirho(SEED_B_CHIRHO))
        .unwrap();
}

#[test]
fn a_node_key_handle_refuses_once_another_handle_publishes_the_marker_chirho() {
    let root_chirho = new_root_chirho("freshness");
    let node_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, node_key_law_chirho()).unwrap();
    let lineage_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, lineage_law_chirho(SEED_A_CHIRHO))
            .unwrap();
    node_chirho.check_fresh_chirho().unwrap();

    lineage_chirho
        .with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"first lineage row")
        })
        .unwrap();

    assert!(refusal_text_chirho(node_chirho.check_fresh_chirho())
        .contains("ControlPlaneLawPinMissingOnGeoRootChirho"));
    assert!(
        refusal_text_chirho(node_chirho.with_verified_read_chirho(|_verifier_chirho| Ok(())))
            .contains("ControlPlaneLawPinMissingOnGeoRootChirho")
    );
    assert!(
        refusal_text_chirho(node_chirho.with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"node row")
        }))
        .contains("ControlPlaneLawPinMissingOnGeoRootChirho")
    );
    lineage_chirho.check_fresh_chirho().unwrap();
}

#[test]
fn a_replaced_root_refuses_and_never_retargets_chirho() {
    // gpt #29610: with no evidence anywhere, only the directory's identity tells the roots apart.
    let parent_chirho = new_root_chirho("replace");
    let path_chirho = parent_chirho.join("root-chirho");
    std::fs::create_dir(&path_chirho).unwrap();
    let handle_chirho =
        ControlPlaneRootChirho::bind_chirho(&path_chirho, node_key_law_chirho()).unwrap();
    handle_chirho.check_fresh_chirho().unwrap();

    std::fs::rename(&path_chirho, parent_chirho.join("moved-root-chirho")).unwrap();
    std::fs::create_dir(&path_chirho).unwrap();

    assert!(refusal_text_chirho(handle_chirho.check_fresh_chirho())
        .contains("ControlPlaneRootReplacedChirho"));
    assert!(refusal_text_chirho(
        handle_chirho.with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"row")
        })
    )
    .contains("ControlPlaneRootReplacedChirho"));
    // Nothing was written to the new directory through the old handle.
    assert_eq!(std::fs::read_dir(&path_chirho).unwrap().count(), 0);
}

#[test]
fn the_first_lineage_signing_publishes_the_marker_before_its_signature_chirho() {
    let root_chirho = new_root_chirho("first-lineage");
    let handle_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, lineage_law_chirho(SEED_A_CHIRHO))
            .unwrap();
    assert!(read_control_plane_law_marker_chirho(&root_chirho)
        .unwrap()
        .is_none());

    let signature_chirho = handle_chirho
        .with_control_plane_write_chirho(|scope_chirho| {
            let signature_chirho =
                scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"row one")?;
            // Still inside the lock: the marker is already published.
            assert!(
                read_control_plane_law_marker_chirho(scope_chirho.operation_path_chirho())?
                    .is_some()
            );
            Ok(signature_chirho)
        })
        .unwrap();

    assert_eq!(
        read_control_plane_law_marker_chirho(&root_chirho).unwrap(),
        Some(ControlPlaneLawMarkerChirho::for_verifier_chirho(
            &verifier_chirho(SEED_A_CHIRHO)
        ))
    );
    handle_chirho
        .with_verified_read_chirho(|verifier_chirho| {
            assert!(verifier_chirho.verify_control_plane_record_chirho(
                FAMILY_CHIRHO,
                b"row one",
                &signature_chirho
            )?);
            assert!(!verifier_chirho.verify_control_plane_record_chirho(
                FAMILY_CHIRHO,
                b"row two",
                &signature_chirho
            )?);
            assert!(!verifier_chirho.verify_control_plane_record_chirho(
                ControlPlaneFamilyChirho::HeadRemovalsChirho,
                b"row one",
                &signature_chirho
            )?);
            Ok(())
        })
        .unwrap();
}

#[test]
fn a_node_key_handle_signs_and_verifies_with_the_root_node_key_chirho() {
    let root_chirho = new_root_chirho("node-key");
    let handle_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, node_key_law_chirho()).unwrap();
    let signature_chirho = handle_chirho
        .with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"node row")
        })
        .unwrap();
    // A lineage signature over the same bytes is not this root's node-key signature.
    let other_chirho = ControlPlaneRootChirho::bind_chirho(
        &new_root_chirho("node-key-other"),
        lineage_law_chirho(SEED_A_CHIRHO),
    )
    .unwrap();
    let lineage_signature_chirho = other_chirho
        .with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"node row")
        })
        .unwrap();
    handle_chirho
        .with_verified_read_chirho(|verifier_chirho| {
            assert!(verifier_chirho.verify_control_plane_record_chirho(
                FAMILY_CHIRHO,
                b"node row",
                &signature_chirho
            )?);
            assert!(!verifier_chirho.verify_control_plane_record_chirho(
                FAMILY_CHIRHO,
                b"node row",
                &lineage_signature_chirho
            )?);
            Ok(())
        })
        .unwrap();
}

#[test]
fn the_law_lock_refuses_inside_the_fence_or_append_lock_by_name_chirho() {
    let root_chirho = new_root_chirho("lock-order");
    let handle_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, node_key_law_chirho()).unwrap();

    let under_fence_chirho = with_named_lock_chirho(&root_chirho, WRITER_FENCE_LOCK_CHIRHO, || {
        handle_chirho.with_control_plane_write_chirho(|_scope_chirho| Ok(()))
    });
    assert!(refusal_text_chirho(under_fence_chirho).contains("NamedLockOrderChirho"));
    let under_append_chirho = with_append_log_lock_chirho(&root_chirho, || {
        handle_chirho.with_control_plane_write_chirho(|_scope_chirho| Ok(()))
    });
    assert!(refusal_text_chirho(under_append_chirho).contains("NamedLockOrderChirho"));

    // Control: the law lock outermost, with the fence lock inside it, is the allowed order.
    handle_chirho
        .with_control_plane_write_chirho(|scope_chirho| {
            with_named_lock_chirho(
                scope_chirho.operation_path_chirho(),
                WRITER_FENCE_LOCK_CHIRHO,
                || Ok(()),
            )
        })
        .unwrap();
}

#[test]
fn a_second_writer_cannot_publish_the_marker_while_a_first_holds_its_scope_chirho() {
    // A node-key writer signs, pauses before its commit, and only then lets go. A lineage writer started
    // meanwhile must wait for the lock, so the marker cannot appear between that signature and its commit.
    let root_chirho = new_root_chirho("hold-release");
    let node_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, node_key_law_chirho()).unwrap();
    let lineage_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, lineage_law_chirho(SEED_A_CHIRHO))
            .unwrap();
    let (signed_tx_chirho, signed_rx_chirho) = mpsc::channel::<()>();
    let (release_tx_chirho, release_rx_chirho) = mpsc::channel::<()>();
    let (lineage_started_tx_chirho, lineage_started_rx_chirho) = mpsc::channel::<()>();

    let node_ref_chirho = &node_chirho;
    let lineage_ref_chirho = &lineage_chirho;
    std::thread::scope(|threads_chirho| {
        let first_chirho = threads_chirho.spawn(move || {
            node_ref_chirho.with_control_plane_write_chirho(|scope_chirho| {
                scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"node row")?;
                signed_tx_chirho.send(()).unwrap();
                release_rx_chirho.recv().unwrap();
                // The commit: the marker must still be absent here, whatever the second writer did.
                let marker_chirho =
                    read_control_plane_law_marker_chirho(scope_chirho.operation_path_chirho())?;
                std::fs::write(
                    scope_chirho.operation_path_chirho().join("node-row-chirho"),
                    b"row",
                )?;
                Ok(marker_chirho)
            })
        });
        signed_rx_chirho.recv().unwrap();
        let second_chirho = threads_chirho.spawn(move || {
            lineage_started_tx_chirho.send(()).unwrap();
            lineage_ref_chirho.with_control_plane_write_chirho(|scope_chirho| {
                scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"lineage row")
            })
        });
        lineage_started_rx_chirho.recv().unwrap();
        // Give the second writer every chance to run if the lock did not hold it.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            read_control_plane_law_marker_chirho(&root_chirho)
                .unwrap()
                .is_none(),
            "the marker was published while the first writer held its scope"
        );
        release_tx_chirho.send(()).unwrap();
        assert_eq!(first_chirho.join().unwrap().unwrap(), None);
        second_chirho.join().unwrap().unwrap();
    });

    assert!(read_control_plane_law_marker_chirho(&root_chirho)
        .unwrap()
        .is_some());
    assert!(refusal_text_chirho(node_chirho.check_fresh_chirho())
        .contains("ControlPlaneLawPinMissingOnGeoRootChirho"));
}

#[cfg(unix)]
#[test]
fn binding_keeps_the_operation_path_as_given_chirho() {
    // The path is the caller's spelling; only the identity is resolved.
    let real_chirho = new_root_chirho("spelling-real");
    let link_chirho = real_chirho.with_file_name(format!(
        "{}-link-chirho",
        real_chirho.file_name().unwrap().to_string_lossy()
    ));
    std::os::unix::fs::symlink(&real_chirho, &link_chirho).unwrap();
    let handle_chirho =
        ControlPlaneRootChirho::bind_chirho(&link_chirho, node_key_law_chirho()).unwrap();
    assert_eq!(handle_chirho.operation_path_chirho(), link_chirho.as_path());
    assert_eq!(&*handle_chirho, link_chirho.as_path());
    handle_chirho.check_fresh_chirho().unwrap();
}

#[test]
fn a_tenant_marker_written_or_corrupted_after_binding_refuses_chirho() {
    // agy #29772: the tenant marker names the consistency group, and so the fence the era is read from.
    let created_chirho = new_root_chirho("tenant-created");
    let handle_chirho =
        ControlPlaneRootChirho::bind_chirho(&created_chirho, node_key_law_chirho()).unwrap();
    std::fs::write(
        created_chirho.join(TENANT_MARKER_CHIRHO),
        br#"{"tenant_id_chirho":"tenant-late-chirho"}"#,
    )
    .unwrap();
    assert!(refusal_text_chirho(handle_chirho.check_fresh_chirho())
        .contains("ControlPlaneRootGroupChangedChirho"));
    assert!(refusal_text_chirho(
        handle_chirho.with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"row")
        })
    )
    .contains("ControlPlaneRootGroupChangedChirho"));

    let corrupted_chirho = new_root_chirho("tenant-corrupted");
    std::fs::write(
        corrupted_chirho.join(TENANT_MARKER_CHIRHO),
        br#"{"tenant_id_chirho":"tenant-bound-chirho"}"#,
    )
    .unwrap();
    let bound_chirho =
        ControlPlaneRootChirho::bind_chirho(&corrupted_chirho, node_key_law_chirho()).unwrap();
    bound_chirho.check_fresh_chirho().unwrap();
    std::fs::write(corrupted_chirho.join(TENANT_MARKER_CHIRHO), b"not a marker").unwrap();
    assert!(
        refusal_text_chirho(bound_chirho.check_fresh_chirho()).contains("tenant marker"),
        "a corrupted tenant marker must refuse the next read"
    );
}

#[test]
fn a_verifier_only_lineage_handle_refuses_to_sign_and_publishes_nothing_chirho() {
    // agy #29772: the signature comes first, so a law that cannot sign never touches the root.
    let root_chirho = new_root_chirho("verifier-only");
    let config_chirho =
        ControlPlaneConfigChirho::new_chirho(verifier_chirho(SEED_A_CHIRHO), None).unwrap();
    let law_chirho =
        select_control_plane_law_chirho(Some(config_chirho), &no_evidence_chirho()).unwrap();
    let handle_chirho = ControlPlaneRootChirho::bind_chirho(&root_chirho, law_chirho).unwrap();

    assert!(refusal_text_chirho(
        handle_chirho.with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"row")
        })
    )
    .contains("ControlPlaneSignerUnavailableChirho"));
    assert!(
        read_control_plane_law_marker_chirho(&root_chirho)
            .unwrap()
            .is_none(),
        "a verifier-only law must publish nothing"
    );
}

#[test]
fn the_first_sign_in_each_scope_runs_the_marker_barrier_even_when_the_marker_is_visible_chirho() {
    // gpt #29775: a visible marker may not be durable, so each scope runs the durable path once.
    use crate::control_plane_evidence_chirho::tests_chirho::replay_barriers_chirho;
    let root_chirho = new_root_chirho("barrier-each-scope");
    let handle_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, lineage_law_chirho(SEED_A_CHIRHO))
            .unwrap();
    handle_chirho
        .with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"publishes the marker")
        })
        .unwrap();
    let before_chirho = replay_barriers_chirho();
    handle_chirho
        .with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"row one")?;
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"row two")
        })
        .unwrap();
    assert_eq!(
        replay_barriers_chirho(),
        before_chirho + 1,
        "a scope over a visible marker runs its barrier exactly once"
    );
}

#[test]
fn a_failed_marker_barrier_refuses_the_sign_chirho() {
    use crate::control_plane_evidence_chirho::tests_chirho::fail_next_replay_barrier_chirho;
    let root_chirho = new_root_chirho("barrier-fails");
    let handle_chirho =
        ControlPlaneRootChirho::bind_chirho(&root_chirho, lineage_law_chirho(SEED_A_CHIRHO))
            .unwrap();
    handle_chirho
        .with_control_plane_write_chirho(|scope_chirho| {
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"publishes the marker")
        })
        .unwrap();
    fail_next_replay_barrier_chirho();
    assert!(refusal_text_chirho(
        handle_chirho.with_control_plane_write_chirho(
            |scope_chirho| scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"row")
        )
    )
    .contains("ControlPlaneLawMarkerPublishFailedChirho"));
}

#[test]
fn a_root_replaced_inside_the_scope_refuses_the_sign_and_writes_nothing_there_chirho() {
    // gpt #29775: replace the root after the scope's checks and before its signature.
    for (case_chirho, law_chirho) in [
        ("node key", node_key_law_chirho()),
        ("lineage", lineage_law_chirho(SEED_A_CHIRHO)),
    ] {
        let parent_chirho = new_root_chirho("replace-inside");
        let path_chirho = parent_chirho.join("root-chirho");
        std::fs::create_dir(&path_chirho).unwrap();
        let handle_chirho = ControlPlaneRootChirho::bind_chirho(&path_chirho, law_chirho).unwrap();
        let result_chirho = handle_chirho.with_control_plane_write_chirho(|scope_chirho| {
            std::fs::rename(&path_chirho, parent_chirho.join("moved-root-chirho"))?;
            std::fs::create_dir(&path_chirho)?;
            scope_chirho.sign_control_plane_record_chirho(FAMILY_CHIRHO, b"row")
        });
        assert!(
            refusal_text_chirho(result_chirho).contains("ControlPlaneRootReplacedChirho"),
            "{case_chirho}"
        );
        assert_eq!(
            std::fs::read_dir(&path_chirho).unwrap().count(),
            0,
            "{case_chirho}: no key and no marker in the replacement"
        );
    }
}
