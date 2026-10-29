// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A root bound to the control-plane law the composition chose for it: the one way a family will sign or verify its records, refusing once the root or its evidence changes under it.
//!
//! C2.1 brick 1b-1a, the mechanism alone (design: `spec-chirho/workstream-state-chirho/c2-durability-chirho/
//! brick1-control-plane-signer-design-chirho.md`, "1b-1's design"). No family uses it yet: 1b-1b moves
//! the app-record family and its callers onto it, and 1b-1c binds it in the composers.
//!
//! - **Binding.** [`ControlPlaneRootChirho::bind_chirho`] takes a law the composition chose from the reviewed
//!   config and checks it against the root's evidence, read through 1a-ii's reader. There is no default and
//!   no conversion from a bare path, so no caller can pick the node key by omission.
//! - **Identity.** The root is its directory's `dev` and `ino`, not its spelling. A root renamed away with
//!   another put at the same path refuses, even when neither shows any evidence (gpt #29610). The operation
//!   path is kept exactly as given, so C3's `"."` stays `"."`.
//! - **Freshness.** A verified read compares stats of the root, of every evidence slot and of the tenant
//!   marker that names its consistency group with the last validated ones. On a change it reads the evidence again and re-checks the held law, so a node-key handle
//!   refuses once another process publishes the law marker.
//! - **Writes.** A write runs inside the law lock from before its signature until its commit returns. The
//!   first lineage signature in each write publishes the law marker through its durable path, even when the
//!   marker is already visible, because visible is not durable (gpt #29775).
//! - **Reads.** Law and root freshness is checked at read entry, and the record verifier cannot escape
//!   that read's closure. That is lifetime confinement, not snapshot isolation: evidence may change during
//!   the read and later appends may be observed, so the next read checks freshness again (gpt #29799).
//! - **What is not bound.** The root's identity is checked before the lock, under it, and at every
//!   signature. The record I/O a caller does through the scope's path is check-then-use, not bound to the
//!   checked directory's descriptor: an absolute root path replaced mid-scope is refused at the next
//!   check, not prevented. C3's retained `"."` does not retarget.
//!
//! `Deref<Target = Path>` is filesystem plumbing only, never authority: an entry that needs the law takes the
//! handle itself (gpt #29743).

use crate::control_plane_evidence_chirho::{
    publish_control_plane_law_marker_unlocked_chirho, read_control_plane_evidence_chirho,
    with_law_lock_chirho, LawLockHeldChirho,
};
use crate::writer_head_chirho::{
    consistency_group_for_root_chirho, writer_fence_path_chirho, ConsistencyGroupIdChirho,
};
use anyhow::{anyhow, bail, Result};
use cairn_signer_chirho::control_plane_signer_chirho::{
    ControlPlaneFamilyChirho, ControlPlaneLawChirho, ControlPlaneLawMarkerChirho,
};
use cairn_signer_chirho::signer_chirho;
use cairn_tenant_chirho::tenant_chirho::{
    CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO, GEO_GENESIS_GUARD_DIR_CHIRHO, TENANT_MARKER_CHIRHO,
};
use std::cell::Cell;
use std::io::ErrorKind;
use std::ops::Deref;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// How many times a read re-checks evidence that keeps changing under it before it refuses.
const EVIDENCE_SETTLE_ATTEMPTS_CHIRHO: usize = 3;

/// A root bound to the law the composition chose for it.
#[derive(Debug)]
pub struct ControlPlaneRootChirho {
    operation_path_chirho: PathBuf,
    group_chirho: ConsistencyGroupIdChirho,
    fence_path_chirho: PathBuf,
    root_identity_chirho: RootIdentityChirho,
    law_chirho: ControlPlaneLawChirho,
    validated_chirho: Mutex<EvidenceStampsChirho>,
}

/// A root directory's identity: what a path spelling resolves to, not the spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RootIdentityChirho {
    dev_chirho: u64,
    ino_chirho: u64,
}

/// What a verified read compares: cheap stats, changed by any write to the evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EvidenceStampsChirho {
    root_chirho: RootIdentityChirho,
    tenant_marker_chirho: Option<EntryStampChirho>,
    law_marker_chirho: Option<EntryStampChirho>,
    fence_directory_chirho: Option<EntryStampChirho>,
    fence_chirho: Option<EntryStampChirho>,
    genesis_guard_present_chirho: bool,
}

/// One entry's stat, taken without following a link at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryStampChirho {
    dev_chirho: u64,
    ino_chirho: u64,
    mode_chirho: u32,
    len_chirho: u64,
    mtime_chirho: (i64, i64),
    ctime_chirho: (i64, i64),
}

impl EntryStampChirho {
    fn of_chirho(metadata_chirho: &std::fs::Metadata) -> Self {
        Self {
            dev_chirho: metadata_chirho.dev(),
            ino_chirho: metadata_chirho.ino(),
            mode_chirho: metadata_chirho.mode(),
            len_chirho: metadata_chirho.len(),
            mtime_chirho: (metadata_chirho.mtime(), metadata_chirho.mtime_nsec()),
            ctime_chirho: (metadata_chirho.ctime(), metadata_chirho.ctime_nsec()),
        }
    }
}

/// An entry's stamp. Only "not found" is absent; any other failure refuses.
fn stamp_entry_chirho(path_chirho: &Path) -> Result<Option<EntryStampChirho>> {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) => Ok(Some(EntryStampChirho::of_chirho(&metadata_chirho))),
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => bail!("ControlPlaneRootEvidenceUnreadableChirho"),
    }
}

fn root_identity_chirho(root_chirho: &Path) -> Result<RootIdentityChirho> {
    let metadata_chirho =
        std::fs::metadata(root_chirho).map_err(|_| anyhow!("ControlPlaneRootUnreadableChirho"))?;
    if !metadata_chirho.is_dir() {
        bail!("ControlPlaneRootNotADirectoryChirho");
    }
    Ok(RootIdentityChirho {
        dev_chirho: metadata_chirho.dev(),
        ino_chirho: metadata_chirho.ino(),
    })
}

fn evidence_stamps_chirho(root_chirho: &Path, fence_chirho: &Path) -> Result<EvidenceStampsChirho> {
    Ok(EvidenceStampsChirho {
        root_chirho: root_identity_chirho(root_chirho)?,
        tenant_marker_chirho: stamp_entry_chirho(&root_chirho.join(TENANT_MARKER_CHIRHO))?,
        law_marker_chirho: stamp_entry_chirho(
            &root_chirho.join(CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO),
        )?,
        fence_directory_chirho: match fence_chirho.parent() {
            Some(directory_chirho) => stamp_entry_chirho(directory_chirho)?,
            None => None,
        },
        fence_chirho: stamp_entry_chirho(fence_chirho)?,
        genesis_guard_present_chirho: stamp_entry_chirho(
            &root_chirho.join(GEO_GENESIS_GUARD_DIR_CHIRHO),
        )?
        .is_some(),
    })
}

/// The root's consistency group, recomputed. The tenant marker decides it, and it names the fence the era
/// is read from, so a group that changed under a bound handle refuses (agy #29772).
fn require_same_group_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<()> {
    if consistency_group_for_root_chirho(root_chirho)? != *group_chirho {
        bail!("ControlPlaneRootGroupChangedChirho");
    }
    Ok(())
}

/// Read the evidence and check the law and the group until the stats hold still across the read.
fn settled_check_chirho(
    root_chirho: &Path,
    fence_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    law_chirho: &ControlPlaneLawChirho,
) -> Result<EvidenceStampsChirho> {
    for _attempt_chirho in 0..EVIDENCE_SETTLE_ATTEMPTS_CHIRHO {
        let before_chirho = evidence_stamps_chirho(root_chirho, fence_chirho)?;
        let evidence_chirho = read_control_plane_evidence_chirho(root_chirho)?;
        law_chirho.check_evidence_chirho(&evidence_chirho)?;
        require_same_group_chirho(root_chirho, group_chirho)?;
        let after_chirho = evidence_stamps_chirho(root_chirho, fence_chirho)?;
        if after_chirho == before_chirho {
            return Ok(after_chirho);
        }
    }
    bail!("ControlPlaneRootEvidenceUnsettledChirho")
}

impl ControlPlaneRootChirho {
    /// Bind `root_chirho` to `law_chirho`, which the composition chose from the reviewed config. The law
    /// must stand on the root's evidence as read now.
    pub fn bind_chirho(root_chirho: &Path, law_chirho: ControlPlaneLawChirho) -> Result<Self> {
        let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
        let fence_path_chirho = writer_fence_path_chirho(root_chirho, &group_chirho)?;
        let stamps_chirho =
            settled_check_chirho(root_chirho, &fence_path_chirho, &group_chirho, &law_chirho)?;
        Ok(Self {
            operation_path_chirho: root_chirho.to_path_buf(),
            group_chirho,
            fence_path_chirho,
            root_identity_chirho: stamps_chirho.root_chirho,
            law_chirho,
            validated_chirho: Mutex::new(stamps_chirho),
        })
    }

    /// The path every operation on this root uses, exactly as the composition gave it.
    pub fn operation_path_chirho(&self) -> &Path {
        &self.operation_path_chirho
    }

    pub fn law_chirho(&self) -> &ControlPlaneLawChirho {
        &self.law_chirho
    }

    /// Check, before a verified read, that this is still the bound root and its law still stands.
    /// Unchanged stats cost only the stats; a change costs one evidence read.
    pub fn check_fresh_chirho(&self) -> Result<()> {
        let stamps_chirho =
            evidence_stamps_chirho(&self.operation_path_chirho, &self.fence_path_chirho)?;
        self.require_same_root_chirho(&stamps_chirho)?;
        let mut validated_chirho = self
            .validated_chirho
            .lock()
            .unwrap_or_else(|poisoned_chirho| poisoned_chirho.into_inner());
        if *validated_chirho == stamps_chirho {
            return Ok(());
        }
        let settled_chirho = settled_check_chirho(
            &self.operation_path_chirho,
            &self.fence_path_chirho,
            &self.group_chirho,
            &self.law_chirho,
        )?;
        self.require_same_root_chirho(&settled_chirho)?;
        *validated_chirho = settled_chirho;
        Ok(())
    }

    /// Run one read with a verifier for its records. Law and root freshness is checked at read entry, and
    /// the verifier cannot escape the read's closure, so a later read must enter, and check, again. It does
    /// not freeze the filesystem or snapshot the data at entry (gpt #29775, #29799).
    pub fn with_verified_read_chirho<T>(
        &self,
        read_chirho: impl FnOnce(&ControlPlaneRecordVerifierChirho<'_>) -> Result<T>,
    ) -> Result<T> {
        self.check_fresh_chirho()?;
        let node_pubkey_chirho = match &self.law_chirho {
            ControlPlaneLawChirho::NodeKeyChirho => Some(
                signer_chirho::existing_pubkey_hex_chirho(&self.operation_path_chirho)?,
            ),
            ControlPlaneLawChirho::LineageRoleChirho(_) => None,
        };
        read_chirho(&ControlPlaneRecordVerifierChirho {
            root_chirho: self,
            node_pubkey_chirho,
        })
    }

    /// Run one write inside the law lock. Under it the root and its evidence are checked again; the scope
    /// signs, and the write's commit must return before the lock is released.
    ///
    /// The root's identity is checked once before the lock too, because taking the lock creates its lock
    /// file under the root: a root already replaced refuses without touching the new directory. It is
    /// checked again under the lock, and at every signature. Those are checks, not descriptor custody:
    /// see the module's "What is not bound".
    pub fn with_control_plane_write_chirho<T>(
        &self,
        write_chirho: impl FnOnce(&ControlPlaneWriteScopeChirho<'_>) -> Result<T>,
    ) -> Result<T> {
        self.require_same_root_chirho(&evidence_stamps_chirho(
            &self.operation_path_chirho,
            &self.fence_path_chirho,
        )?)?;
        with_law_lock_chirho(&self.operation_path_chirho, |held_chirho| {
            let stamps_chirho =
                evidence_stamps_chirho(&self.operation_path_chirho, &self.fence_path_chirho)?;
            self.require_same_root_chirho(&stamps_chirho)?;
            let evidence_chirho = read_control_plane_evidence_chirho(&self.operation_path_chirho)?;
            self.law_chirho.check_evidence_chirho(&evidence_chirho)?;
            require_same_group_chirho(&self.operation_path_chirho, &self.group_chirho)?;
            let scope_chirho = ControlPlaneWriteScopeChirho {
                root_chirho: self,
                held_chirho,
                marker_durable_chirho: Cell::new(false),
            };
            write_chirho(&scope_chirho)
        })
    }

    fn require_same_root_chirho(&self, stamps_chirho: &EvidenceStampsChirho) -> Result<()> {
        if stamps_chirho.root_chirho != self.root_identity_chirho {
            bail!("ControlPlaneRootReplacedChirho");
        }
        Ok(())
    }
}

impl Deref for ControlPlaneRootChirho {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.operation_path_chirho
    }
}

/// One write's scope, alive only while the law lock is held.
pub struct ControlPlaneWriteScopeChirho<'root_chirho> {
    root_chirho: &'root_chirho ControlPlaneRootChirho,
    held_chirho: &'root_chirho LawLockHeldChirho,
    /// Whether THIS scope has run the marker's durable publication or equal-replay barrier. Never "the
    /// file was seen": a visible marker may not be durable yet.
    marker_durable_chirho: Cell<bool>,
}

impl ControlPlaneWriteScopeChirho<'_> {
    pub fn operation_path_chirho(&self) -> &Path {
        self.root_chirho.operation_path_chirho()
    }

    /// Sign one record's bytes under the law. The root's identity is checked first, so a root replaced
    /// inside the scope gets no key and no marker (gpt #29775). Under the lineage law the signature is
    /// made before anything touches the root, so a verifier-only law refuses cleanly (agy #29772). The
    /// marker's durable publication, or its equal-replay barrier, then runs once in this scope before the
    /// signature is returned, so the marker is durable before the row it governs.
    pub fn sign_control_plane_record_chirho(
        &self,
        family_chirho: ControlPlaneFamilyChirho,
        inner_chirho: &[u8],
    ) -> Result<String> {
        if root_identity_chirho(&self.root_chirho.operation_path_chirho)?
            != self.root_chirho.root_identity_chirho
        {
            bail!("ControlPlaneRootReplacedChirho");
        }
        match &self.root_chirho.law_chirho {
            ControlPlaneLawChirho::NodeKeyChirho => signer_chirho::sign_message_chirho(
                &self.root_chirho.operation_path_chirho,
                inner_chirho,
            ),
            ControlPlaneLawChirho::LineageRoleChirho(lineage_law_chirho) => {
                let signature_chirho = self
                    .root_chirho
                    .law_chirho
                    .sign_lineage_chirho(family_chirho, inner_chirho)?;
                if !self.marker_durable_chirho.get() {
                    publish_control_plane_law_marker_unlocked_chirho(
                        &self.root_chirho.operation_path_chirho,
                        &ControlPlaneLawMarkerChirho::for_verifier_chirho(
                            &lineage_law_chirho.verifier_chirho,
                        ),
                        self.held_chirho,
                    )?;
                    self.marker_durable_chirho.set(true);
                }
                Ok(signature_chirho)
            }
        }
    }
}

/// Verifies one read's records under the root's law, after one freshness check.
pub struct ControlPlaneRecordVerifierChirho<'root_chirho> {
    root_chirho: &'root_chirho ControlPlaneRootChirho,
    node_pubkey_chirho: Option<String>,
}

impl ControlPlaneRecordVerifierChirho<'_> {
    /// Whether `signature_hex_chirho` is this law's signature over the record's bytes.
    pub fn verify_control_plane_record_chirho(
        &self,
        family_chirho: ControlPlaneFamilyChirho,
        inner_chirho: &[u8],
        signature_hex_chirho: &str,
    ) -> Result<bool> {
        match (&self.root_chirho.law_chirho, &self.node_pubkey_chirho) {
            (ControlPlaneLawChirho::NodeKeyChirho, Some(pubkey_chirho)) => {
                signer_chirho::verify_with_pubkey_chirho(
                    pubkey_chirho,
                    inner_chirho,
                    signature_hex_chirho,
                )
            }
            (ControlPlaneLawChirho::NodeKeyChirho, None) => {
                bail!("ControlPlaneNodeKeyUnavailableChirho")
            }
            (ControlPlaneLawChirho::LineageRoleChirho(lineage_law_chirho), _) => lineage_law_chirho
                .verifier_chirho
                .verify_chirho(family_chirho, inner_chirho, signature_hex_chirho),
        }
    }
}

#[cfg(test)]
#[path = "control_plane_root_chirho/tests_chirho.rs"]
mod tests_chirho;
