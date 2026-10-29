// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Registers an identity under a principal named by a reviewed input instead of drawn at random, so
//! roots born from one reviewed plan can hold the same payer and owner.
//!
//! Its only production caller is the credits-demo setup on the test-kind geo seed's path, and a
//! source-scan guard pins that (C1 A3; claude2 #29250, Agy #29261). A chosen principal must:
//! - have exactly the shape `next_principal_chirho` draws;
//! - be new to the whole identity log, revoked records included, and to the identity key directory;
//! - have no account-attribution rows, because a reused coordinate would inherit an earlier owner's
//!   subject-owner records.
//!
//! `precheck_reviewed_principal_chirho` makes the same checks and claims nothing: it writes no identity,
//! key-file or attribution state, though taking the attribution lock can create that lock's file. So a
//! caller can refuse in a read-only phase and register only once its own checks are done.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/promotion-restart-design-chirho.md`.

use super::{
    credential_meets_floor_chirho, identity_key_path_chirho, load_identities_chirho,
    register_identity_internal_chirho, IdentityRecordChirho, PrincipalKindChirho,
    PrincipalSourceChirho, IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO,
};
use anyhow::{bail, Result};
use cairn_account_attribution_chirho::{
    account_attribution_snapshot_unlocked_chirho, with_account_attribution_lock_chirho,
    AccountCoordinateChirho,
};
use std::path::Path;

/// How many characters a drawn principal's id has: `next_principal_chirho` cuts a hash to this.
const DRAWN_PRINCIPAL_ID_LEN_CHIRHO: usize = 16;

/// Refuse unless `register_identity_with_reviewed_principal_chirho` would accept `principal_chirho`
/// now, claiming nothing: it writes no identity, key-file or attribution state, though taking the
/// attribution lock can create that lock's file (claude2 #29410). It makes the registration's own checks,
/// without the append lock. A caller with
/// a read-only phase prechecks there and registers later. The registration repeats every check under
/// the lock, so nothing that changes in between is trusted.
pub fn precheck_reviewed_principal_chirho(
    root_chirho: &Path,
    kind_chirho: PrincipalKindChirho,
    principal_chirho: &str,
    credential_chirho: Option<&str>,
) -> Result<()> {
    refuse_unless_admissible_chirho(&kind_chirho, principal_chirho, credential_chirho)?;
    refuse_unless_unclaimed_chirho(root_chirho, principal_chirho)
}

/// Register `principal_chirho` exactly, or refuse with a fixed identity. The shape and the credential
/// are checked first. The claim (`claim_reviewed_principal_chirho`) then runs inside the identity log's
/// append lock, so a refusal there appends nothing.
pub fn register_identity_with_reviewed_principal_chirho(
    root_chirho: &Path,
    kind_chirho: PrincipalKindChirho,
    principal_chirho: &str,
    credential_chirho: Option<&str>,
) -> Result<IdentityRecordChirho> {
    refuse_unless_admissible_chirho(&kind_chirho, principal_chirho, credential_chirho)?;
    register_identity_internal_chirho(
        root_chirho,
        kind_chirho,
        credential_chirho,
        PrincipalSourceChirho::ReviewedChirho(principal_chirho),
    )
}

/// Claim a reviewed principal. This runs inside the identity log's append lock, so the checks and the
/// append cannot be split.
pub(super) fn claim_reviewed_principal_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Result<String> {
    refuse_unless_unclaimed_chirho(root_chirho, principal_chirho)?;
    Ok(principal_chirho.to_string())
}

/// The principal has the drawn shape, and a supplied credential meets the floor.
fn refuse_unless_admissible_chirho(
    kind_chirho: &PrincipalKindChirho,
    principal_chirho: &str,
    credential_chirho: Option<&str>,
) -> Result<()> {
    if !has_drawn_principal_shape_chirho(kind_chirho, principal_chirho) {
        bail!("ReviewedPrincipalShapeRefusedChirho");
    }
    if let Some(credential_chirho) = credential_chirho {
        if !credential_meets_floor_chirho(credential_chirho) {
            bail!("{IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO}");
        }
    }
    Ok(())
}

/// The principal must be new to every record, revoked ones included. No entry of any kind may sit at
/// its key-file path, a dangling link included. And its coordinate must carry no attribution rows and no
/// freeze; that check takes the attribution lock. Inside the claim it is taken INSIDE the append lock,
/// which is the root's declared order (`append-log -> account-attribution`, the
/// `FORBIDDEN_LOCK_NESTINGS_CHIRHO` table in `cairn-seqlog-chirho`). What it rules out is a reused
/// coordinate's leftover rows.
fn refuse_unless_unclaimed_chirho(root_chirho: &Path, principal_chirho: &str) -> Result<()> {
    if load_identities_chirho(root_chirho)?
        .iter()
        .any(|record_chirho| record_chirho.principal_chirho == principal_chirho)
    {
        bail!("ReviewedPrincipalAlreadyRegisteredChirho");
    }
    refuse_unless_key_path_absent_chirho(&identity_key_path_chirho(root_chirho, principal_chirho))?;
    let account_chirho = AccountCoordinateChirho::from_principal_chirho(principal_chirho)?;
    with_account_attribution_lock_chirho(root_chirho, || {
        let snapshot_chirho =
            account_attribution_snapshot_unlocked_chirho(root_chirho, &account_chirho)?;
        if snapshot_chirho.freeze_chirho().is_some() || !snapshot_chirho.entries_chirho().is_empty()
        {
            bail!("ReviewedPrincipalHasAttributionChirho");
        }
        Ok(())
    })
}

/// The key-file path must be ABSENT, proven by `NotFound`. An entry of any kind refuses, and so does any
/// other error: a permission or I/O failure is not evidence of absence (claude2 #29330).
pub(super) fn refuse_unless_key_path_absent_chirho(key_path_chirho: &Path) -> Result<()> {
    match std::fs::symlink_metadata(key_path_chirho) {
        Ok(_) => bail!("ReviewedPrincipalKeyFileExistsChirho"),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => bail!("ReviewedPrincipalKeyFileUnreadableChirho"),
    }
}

/// Exactly what `next_principal_chirho` emits: the kind's prefix, a slash, and 16 lowercase hex
/// characters with at least one letter among them.
fn has_drawn_principal_shape_chirho(
    kind_chirho: &PrincipalKindChirho,
    principal_chirho: &str,
) -> bool {
    let Some(id_chirho) = principal_chirho
        .strip_prefix(kind_chirho.prefix_chirho())
        .and_then(|rest_chirho| rest_chirho.strip_prefix('/'))
    else {
        return false;
    };
    id_chirho.len() == DRAWN_PRINCIPAL_ID_LEN_CHIRHO
        && id_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
        && id_chirho
            .bytes()
            .any(|byte_chirho| byte_chirho.is_ascii_alphabetic())
}

#[cfg(test)]
#[path = "reviewed_principal_tests_chirho.rs"]
mod reviewed_principal_tests_chirho;
