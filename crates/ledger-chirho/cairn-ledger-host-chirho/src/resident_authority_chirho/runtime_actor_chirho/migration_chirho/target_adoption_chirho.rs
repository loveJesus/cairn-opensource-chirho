// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Can a migration target be OPENED as a writer? Asked BEFORE the source is fenced.
//!
//! It lives HERE rather than beside the identity verifier, and the placement is the honest one: this
//! reads an identity record and compares two integers — it performs no identity VERIFICATION and
//! touches none of that machinery. Putting it next to the verifier would have widened a surface that
//! is deliberately confined to the parties who verify and mint, for a check that does neither. The
//! real verification still happens at open, unchanged.

use cairn_writer_head_chirho::resident_writer_chirho::{
    inspect_resident_writer_identity_chirho, resident_writer_identity_path_chirho,
};
use std::fmt;
use std::path::Path;

/// Identity read used by both the pre-fence authority gate and startup consumption.
///
/// `IdentityAbsentChirho` is a posture rather than an error here because a verified adoption
/// warrant can lawfully consume it. Every present-but-invalid state remains a refusal and can never
/// enter the absent branch.
pub fn inspect_target_adoption_posture_chirho(
    target_root_chirho: &Path,
) -> Result<TargetAdoptionPostureChirho, TargetAdoptionRefusalChirho> {
    // THREE cases, not two, and the third is the one a two-case version silently swallows. ABSENT
    // and PRESENT-BUT-UNREADABLE demand opposite operator actions — stage an identity versus
    // investigate a corrupt one — and this repo has paid for an `Err` that meant both before. The
    // absence is decided by a stat, so a readable-file failure can never be reported as "there was
    // nothing there".
    let identity_path_chirho = resident_writer_identity_path_chirho(target_root_chirho)
        .map_err(|_error_chirho| TargetAdoptionRefusalChirho::TargetRootUnreadableChirho)?;
    match std::fs::symlink_metadata(&identity_path_chirho) {
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TargetAdoptionPostureChirho::IdentityAbsentChirho);
        }
        Err(_error_chirho) => return Err(TargetAdoptionRefusalChirho::IdentityUnreadableChirho),
        Ok(_metadata_chirho) => {}
    }
    let inspection_chirho = inspect_resident_writer_identity_chirho(target_root_chirho)
        .map_err(|_error_chirho| TargetAdoptionRefusalChirho::IdentityMalformedChirho)?;
    let canonical_chirho: serde_json::Value =
        serde_json::from_slice(inspection_chirho.canonical_identity_chirho())
            .map_err(|_error_chirho| TargetAdoptionRefusalChirho::IdentityMalformedChirho)?;
    let state_chirho = canonical_chirho
        .get("state_chirho")
        .and_then(serde_json::Value::as_str)
        .ok_or(TargetAdoptionRefusalChirho::IdentityMalformedChirho)?;
    let coordinate_chirho = canonical_chirho
        .get("coordinate_chirho")
        .ok_or(TargetAdoptionRefusalChirho::IdentityMalformedChirho)?;
    let recorded_device_chirho = coordinate_chirho
        .get("authority_root_device_chirho")
        .and_then(serde_json::Value::as_u64)
        .ok_or(TargetAdoptionRefusalChirho::IdentityMalformedChirho)?;
    let recorded_inode_chirho = coordinate_chirho
        .get("authority_root_inode_chirho")
        .and_then(serde_json::Value::as_u64)
        .ok_or(TargetAdoptionRefusalChirho::IdentityMalformedChirho)?;
    let metadata_chirho = std::fs::metadata(target_root_chirho)
        .map_err(|_error_chirho| TargetAdoptionRefusalChirho::TargetRootUnreadableChirho)?;
    #[cfg(unix)]
    let (actual_device_chirho, actual_inode_chirho) = {
        use std::os::unix::fs::MetadataExt;
        (metadata_chirho.dev(), metadata_chirho.ino())
    };
    #[cfg(not(unix))]
    let (actual_device_chirho, actual_inode_chirho) =
        (recorded_device_chirho, recorded_inode_chirho);
    if recorded_device_chirho != actual_device_chirho
        || recorded_inode_chirho != actual_inode_chirho
    {
        // The COPIED-IDENTITY case, and it is the likely one: staging a target by copying a root
        // brings an identity bound to the root it came from. Its own identity says it is somewhere
        // else, so the resident open path will refuse it — which is right, and must be discovered
        // here rather than after the source has been fenced.
        return Err(TargetAdoptionRefusalChirho::IdentityBoundToAnotherRootChirho);
    }
    match state_chirho {
        "pending_chirho" => Ok(TargetAdoptionPostureChirho::IdentityPendingChirho {
            identity_digest_chirho: inspection_chirho.identity_digest_chirho().to_owned(),
        }),
        "bound_chirho" => Ok(TargetAdoptionPostureChirho::IdentityBoundChirho {
            identity_digest_chirho: inspection_chirho.identity_digest_chirho().to_owned(),
        }),
        _ => Err(TargetAdoptionRefusalChirho::IdentityMalformedChirho),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "the shared Identity prefix makes each externally reported posture explicit"
)]
pub enum TargetAdoptionPostureChirho {
    IdentityAbsentChirho,
    /// A crash after birth reservation but before binding. Only an already-durable matching
    /// consumption record may resume this exact state; a new operator attempt cannot adopt it.
    IdentityPendingChirho {
        identity_digest_chirho: String,
    },
    IdentityBoundChirho {
        identity_digest_chirho: String,
    },
}

/// Why a target cannot be adopted as a resident writer. Distinct identities on purpose: "there is no
/// identity" and "the identity belongs to another root" call for opposite operator actions, and a
/// single refusal covering both is how one of them gets treated as the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum TargetAdoptionRefusalChirho {
    /// Present and unreadable. NEVER folded into absence: "stage one" and "investigate a corrupt
    /// one" are different actions, and a reader told the wrong one acts on the wrong root.
    IdentityUnreadableChirho,
    /// Present, readable, and bound to a different root — the copied-identity case.
    IdentityBoundToAnotherRootChirho,
    IdentityMalformedChirho,
    TargetRootUnreadableChirho,
}

impl fmt::Display for TargetAdoptionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::IdentityUnreadableChirho => {
                "migration target has a resident writer identity that could not be read"
            }
            Self::IdentityBoundToAnotherRootChirho => {
                "migration target's resident writer identity is bound to a different root"
            }
            Self::IdentityMalformedChirho => {
                "migration target has a readable but malformed resident writer identity"
            }
            Self::TargetRootUnreadableChirho => "migration target root could not be read",
        })
    }
}

#[cfg(test)]
mod target_adoption_tests_chirho {
    use super::*;
    use cairn_writer_head_chirho::resident_writer_chirho::{
        reserve_resident_writer_chirho, ResidentWriterBindingChirho,
    };

    fn fixture_root_chirho(label_chirho: &str) -> std::path::PathBuf {
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-target-adoption-{label_chirho}-{}-chirho",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root_chirho);
        std::fs::create_dir_all(&root_chirho).expect("create the fixture root");
        root_chirho
    }

    /// A canonical identity whose recorded root coordinates are `root_chirho`'s real ones.
    fn identity_bound_to_chirho(root_chirho: &std::path::Path) -> Vec<u8> {
        let metadata_chirho = std::fs::metadata(root_chirho).expect("stat the fixture root");
        #[cfg(unix)]
        let (device_chirho, inode_chirho) = {
            use std::os::unix::fs::MetadataExt;
            (metadata_chirho.dev(), metadata_chirho.ino())
        };
        #[cfg(not(unix))]
        let (device_chirho, inode_chirho) = (0u64, 0u64);
        serde_json::to_vec(&serde_json::json!({
            "schema_chirho": "resident-ledger-bound-identity-v4-chirho",
            "state_chirho": "bound_chirho",
            "coordinate_chirho": {
                "authority_root_device_chirho": device_chirho,
                "authority_root_inode_chirho": inode_chirho,
            },
        }))
        .expect("encode the fixture identity")
    }

    /// The posture discriminator must keep absence, valid binding, and foreign binding distinct.
    /// The authority layer decides whether absence is lawful; this reader never promotes it.
    #[test]
    fn target_identity_postures_stay_distinct_before_any_fence_chirho() {
        // (1) STAGED WITHOUT ONE. This is lawful only with a separately verified adoption warrant.
        let bare_chirho = fixture_root_chirho("bare");
        assert_eq!(
            inspect_target_adoption_posture_chirho(&bare_chirho),
            Ok(TargetAdoptionPostureChirho::IdentityAbsentChirho),
            "absence must remain a named posture for the co-signed adoption gate"
        );

        // (2) ADOPTABLE. Reserved through the real machinery, bound to this root's own coordinates.
        let own_chirho = fixture_root_chirho("own");
        let own_identity_chirho = identity_bound_to_chirho(&own_chirho);
        let own_binding_chirho = ResidentWriterBindingChirho {
            root_chirho: &own_chirho,
            identity_kind_chirho: "resident-ledger-bound-identity-v4-chirho",
            canonical_identity_chirho: &own_identity_chirho,
        };
        let (lease_chirho, _outcome_chirho) = reserve_resident_writer_chirho(&own_binding_chirho)
            .expect("reserve the fixture writer");
        drop(lease_chirho);
        assert!(matches!(
            inspect_target_adoption_posture_chirho(&own_chirho),
            Ok(TargetAdoptionPostureChirho::IdentityBoundChirho { .. })
        ));

        // (3) THE COPIED-IDENTITY CASE, staged the way an operator actually produces it: copy a
        // root's writer directory to another root. Its own identity says it lives elsewhere.
        let copied_chirho = fixture_root_chirho("copied");
        let from_chirho = own_chirho.join("resident-writer-chirho");
        let to_chirho = copied_chirho.join("resident-writer-chirho");
        std::fs::create_dir_all(&to_chirho).expect("create the copied writer dir");
        for entry_chirho in std::fs::read_dir(&from_chirho).expect("read the source writer dir") {
            let entry_chirho = entry_chirho.expect("read a writer dir entry");
            std::fs::copy(
                entry_chirho.path(),
                to_chirho.join(entry_chirho.file_name()),
            )
            .expect("copy a writer dir entry");
        }
        let refusal_chirho = inspect_target_adoption_posture_chirho(&copied_chirho);
        assert_eq!(
            refusal_chirho,
            Err(TargetAdoptionRefusalChirho::IdentityBoundToAnotherRootChirho),
            "a copied identity must refuse AS a foreign binding — reporting it as absent would send \
             an operator to stage one, which is the opposite of the right action"
        );
        assert_ne!(
            refusal_chirho,
            Ok(TargetAdoptionPostureChirho::IdentityAbsentChirho)
        );

        // (4) PRESENT AND TAMPERED. The file can be opened, but its authenticated record cannot be
        // decoded. This is not absence and not an I/O failure.
        let tampered_chirho = fixture_root_chirho("tampered");
        let tampered_identity_path_chirho = resident_writer_identity_path_chirho(&tampered_chirho)
            .expect("derive the tampered identity path");
        std::fs::create_dir_all(
            tampered_identity_path_chirho
                .parent()
                .expect("tampered identity has a parent"),
        )
        .expect("create the tampered writer directory");
        std::fs::write(&tampered_identity_path_chirho, b"{tampered-chirho")
            .expect("write a readable malformed identity");
        assert_eq!(
            inspect_target_adoption_posture_chirho(&tampered_chirho),
            Err(TargetAdoptionRefusalChirho::IdentityMalformedChirho)
        );

        // (5) PRESENT BUT UNREADABLE. A non-directory blocks the identity path itself, producing
        // an I/O posture distinct from bytes that were read and rejected.
        let unreadable_chirho = fixture_root_chirho("unreadable");
        std::fs::write(
            unreadable_chirho.join("resident-writer-chirho"),
            b"not-a-directory-chirho",
        )
        .expect("create the unreadable writer-path fixture");
        assert_eq!(
            inspect_target_adoption_posture_chirho(&unreadable_chirho),
            Err(TargetAdoptionRefusalChirho::IdentityUnreadableChirho)
        );

        for root_chirho in [
            bare_chirho,
            own_chirho,
            copied_chirho,
            tampered_chirho,
            unreadable_chirho,
        ] {
            let _ = std::fs::remove_dir_all(root_chirho);
        }
    }
}
