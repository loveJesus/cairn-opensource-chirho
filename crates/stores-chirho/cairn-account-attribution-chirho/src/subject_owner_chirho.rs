// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Who owns each privacy subject, one account or no account, recorded at its first key, so erasing one subject can never shred another owner's keys.
//!
//! The canonical shred path, `erase_subject_data_chirho`, erases EVERY key of a subject (gpt #28915). An
//! account's inventory is therefore safe to erase subject by subject only if each of its subjects belongs
//! to that account alone. The key-creation chokepoint admits each key here, under the attribution lock:
//! the first key of a subject claims it for its owner, and a later key for a different owner refuses
//! before it exists. A record names the subject only by a domain-separated digest, is signed by the root,
//! and is verified on read; anything that does not verify refuses. Layout:
//! `<root>/privacy-account-attribution-chirho/subjects-chirho/<h2>/<h>.json`, sharded so no directory
//! holds every subject.
//!
//! A missing owner record is "unclaimed" only if the subject was never claimed. Each claim also leaves a
//! claim witness in a separate tree, `subject-claims-chirho/<h2>/<h>.json`, so a subject whose owner record
//! has gone missing refuses instead of being claimed afresh by another owner, which would let that owner's
//! erasure shred the earlier owner's keys (gpt #29068). Deleting BOTH the record and its witness defeats
//! this check; an account close's per-key reconciliation remains the backstop for that.

use crate::coordinate_chirho::{is_lower_hex_chirho, AccountCoordinateChirho};
use crate::coverage_debt_chirho::{record_coverage_debt_unlocked_chirho, CoverageDebtChirho};
use crate::record_chirho::{
    update_field_chirho, validate_subject_and_key_id_chirho, validate_subject_chirho,
    NO_ACTOR_CHIRHO, ROLE_CONTRIBUTION_CHIRHO, ROLE_OWNED_CHIRHO,
};
use crate::refusal_chirho::{refuse_chirho, AccountAttributionRefusalChirho};
use crate::store_chirho::{
    append_attribution_row_unlocked_chirho, now_ms_chirho, refuse_if_account_frozen_chirho,
    unverified_chirho, verify_root_signature_chirho, AttributionRowChirho,
    ACCOUNT_ATTRIBUTION_DIR_CHIRHO, PRIVATE_FILE_MODE_CHIRHO,
};
use anyhow::Result;
use cairn_durable_chirho::{
    create_complete_file_durable_with_mode_chirho,
    read_identity_stable_bounded_regular_file_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_signer_chirho::signer_chirho::{existing_pubkey_hex_chirho, sign_message_chirho};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

pub const SUBJECT_OWNER_RECORD_SCHEMA_V1_CHIRHO: &str = "subject-owner-record-v1-chirho";
const SUBJECT_OWNERS_DIR_CHIRHO: &str = "subjects-chirho";
const SUBJECT_CLAIMS_DIR_CHIRHO: &str = "subject-claims-chirho";
pub const SUBJECT_CLAIM_WITNESS_SCHEMA_V1_CHIRHO: &str = "subject-claim-witness-v1-chirho";
const SUBJECT_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-subject-owner-digest-v1-chirho";
const SUBJECT_OWNER_MESSAGE_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-subject-owner-record-v1-chirho";
pub(crate) const NO_ACCOUNT_OWNER_LABEL_CHIRHO: &str = "no-account-chirho";
const SUBJECT_OWNER_MAX_BYTES_CHIRHO: u64 = 4 * 1024;

/// The owner a subject's keys all share. One account; the no-account class (genuinely anonymous, system
/// or operator work, whose reason is proven where the store is called, and which no account's close
/// needs); or a coverage debt (data no account's inventory lists but some account's close may need).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectOwnerChirho {
    AccountChirho(AccountCoordinateChirho),
    NoAccountChirho,
    CoverageDebtChirho(CoverageDebtChirho),
}

impl SubjectOwnerChirho {
    pub(crate) fn label_chirho(&self) -> &str {
        match self {
            Self::AccountChirho(account_chirho) => account_chirho.as_hex_chirho(),
            Self::NoAccountChirho => NO_ACCOUNT_OWNER_LABEL_CHIRHO,
            Self::CoverageDebtChirho(debt_chirho) => debt_chirho.owner_label_chirho(),
        }
    }

    /// The one parser of an owner label, for owner records and for rows' containers alike.
    pub(crate) fn from_label_chirho(label_chirho: &str) -> Result<Self> {
        if label_chirho == NO_ACCOUNT_OWNER_LABEL_CHIRHO {
            return Ok(Self::NoAccountChirho);
        }
        if let Some(debt_chirho) = CoverageDebtChirho::from_owner_label_chirho(label_chirho) {
            return Ok(Self::CoverageDebtChirho(debt_chirho));
        }
        Ok(Self::AccountChirho(
            AccountCoordinateChirho::from_hex_chirho(label_chirho)?,
        ))
    }
}

/// One subject's signed owner record. It carries the subject's digest, never the subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectOwnerRecordChirho {
    pub schema_chirho: String,
    pub subject_digest_chirho: String,
    pub owner_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

impl SubjectOwnerRecordChirho {
    fn message_chirho(&self) -> Vec<u8> {
        let mut bytes_chirho = SUBJECT_OWNER_MESSAGE_DOMAIN_V1_CHIRHO.to_vec();
        update_field_chirho(&mut bytes_chirho, b"schema", self.schema_chirho.as_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"subject-digest",
            self.subject_digest_chirho.as_bytes(),
        );
        update_field_chirho(&mut bytes_chirho, b"owner", self.owner_chirho.as_bytes());
        update_field_chirho(
            &mut bytes_chirho,
            b"at-ms",
            &self.at_ms_chirho.to_le_bytes(),
        );
        bytes_chirho
    }
}

fn subject_digest_chirho(subject_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(SUBJECT_DIGEST_DOMAIN_V1_CHIRHO);
    hasher_chirho.update(&(subject_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(subject_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

fn subject_owner_path_chirho(root_chirho: &Path, digest_chirho: &str) -> PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(SUBJECT_OWNERS_DIR_CHIRHO)
        .join(&digest_chirho[..2])
        .join(format!("{digest_chirho}.json"))
}

fn subject_claim_witness_path_chirho(root_chirho: &Path, digest_chirho: &str) -> PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(SUBJECT_CLAIMS_DIR_CHIRHO)
        .join(&digest_chirho[..2])
        .join(format!("{digest_chirho}.json"))
}

/// Whether ANYTHING sits at the subject's claim witness path. Its content is never trusted: any entry,
/// even a malformed one, means the subject was claimed, which only ever refuses a fresh claim.
fn subject_claim_witness_exists_chirho(root_chirho: &Path, digest_chirho: &str) -> Result<bool> {
    match std::fs::symlink_metadata(subject_claim_witness_path_chirho(
        root_chirho,
        digest_chirho,
    )) {
        Ok(_) => Ok(true),
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(unverified_chirho(
            "the subject claim witness cannot be examined",
        )),
    }
}

/// Leave the claim witness, create-once. It names only the subject's digest.
fn write_subject_claim_witness_chirho(root_chirho: &Path, digest_chirho: &str) -> Result<()> {
    if subject_claim_witness_exists_chirho(root_chirho, digest_chirho)? {
        return Ok(());
    }
    let witness_chirho = serde_json::json!({
        "schema_chirho": SUBJECT_CLAIM_WITNESS_SCHEMA_V1_CHIRHO,
        "subject_digest_chirho": digest_chirho,
    });
    create_complete_file_durable_with_mode_chirho(
        &subject_claim_witness_path_chirho(root_chirho, digest_chirho),
        &serde_json::to_vec(&witness_chirho)?,
        PRIVATE_FILE_MODE_CHIRHO,
    )?;
    Ok(())
}

/// The subject's verified owner, or `None` when it was never claimed. A record that is unreadable,
/// malformed, for another subject or not signed by this root refuses, and so does a missing record whose
/// claim witness remains, so neither ever reads as unclaimed.
pub fn subject_owner_unlocked_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
) -> Result<Option<SubjectOwnerChirho>> {
    validate_subject_chirho(subject_chirho)?;
    let digest_chirho = subject_digest_chirho(subject_chirho);
    let path_chirho = subject_owner_path_chirho(root_chirho, &digest_chirho);
    let bytes_chirho = match read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        SUBJECT_OWNER_MAX_BYTES_CHIRHO,
    ) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
            if subject_claim_witness_exists_chirho(root_chirho, &digest_chirho)? {
                return Err(refuse_chirho(
                    AccountAttributionRefusalChirho::SubjectOwnerRecordMissingChirho,
                    "a claimed subject's owner record is missing; it needs a verified migration",
                ));
            }
            return Ok(None);
        }
        Err(_) => {
            return Err(unverified_chirho(
                "the subject owner file is not a bounded single regular file",
            ))
        }
    };
    let record_chirho: SubjectOwnerRecordChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_| unverified_chirho("the subject owner file does not parse"))?;
    if record_chirho.schema_chirho != SUBJECT_OWNER_RECORD_SCHEMA_V1_CHIRHO
        || !is_lower_hex_chirho(&record_chirho.subject_digest_chirho, 64)
    {
        return Err(unverified_chirho(
            "the subject owner record's schema or digest is not in form",
        ));
    }
    if record_chirho.subject_digest_chirho != digest_chirho {
        return Err(unverified_chirho(
            "the subject owner record names another subject",
        ));
    }
    let owner_chirho = SubjectOwnerChirho::from_label_chirho(&record_chirho.owner_chirho)
        .map_err(|_| unverified_chirho("the subject owner record's owner is not in form"))?;
    let pubkey_chirho = existing_pubkey_hex_chirho(root_chirho)
        .map_err(|_| unverified_chirho("the root has no existing signing key"))?;
    verify_root_signature_chirho(
        &pubkey_chirho,
        &record_chirho.message_chirho(),
        &record_chirho.sig_chirho,
    )?;
    Ok(Some(owner_chirho))
}

/// The principal namespaces: `PrincipalKindChirho` has only User and Owner, and every principal is
/// `user/<id>` or `owner/<id>` (gpt #28945).
const PRINCIPAL_NAMESPACES_CHIRHO: [&str; 2] = ["user/", "owner/"];

/// Admit one new private key, before its key file exists. `container_chirho` owns the key's subject;
/// `actor_chirho` is the account that initiated the write, when one did.
/// - Either account being frozen refuses: a retained actor context cannot write into another owner's
///   still-open container after the actor's own close (gpt #28929).
/// - A subject in a principal's namespace may be owned only by that principal's account, so no app can
///   pre-claim a user's canonical subject. This constrains ownership; it never grants it.
/// - A coverage-debt container records its root marker first, so the debt is visible before its key is.
/// - The subject is claimed for the container, or must already be the container's. A subject whose owner
///   record is missing but whose claim witness remains refuses: it needs a verified migration.
/// - The container's log gets an OWNED row naming the actor, and an actor that is not the container gets
///   a CONTRIBUTION row naming the container. Both are signed and durable before this returns, so a crash
///   can leave a row for a key never created, but never a created key missing from either log.
///
/// The caller holds the attribution lock, so no other key of the subject or either account interleaves.
pub fn admit_private_key_unlocked_chirho(
    root_chirho: &Path,
    container_chirho: &SubjectOwnerChirho,
    actor_chirho: Option<&AccountCoordinateChirho>,
    subject_chirho: &str,
    key_id_chirho: &str,
) -> Result<()> {
    validate_subject_and_key_id_chirho(subject_chirho, key_id_chirho)?;
    if let SubjectOwnerChirho::AccountChirho(account_chirho) = container_chirho {
        refuse_if_account_frozen_chirho(root_chirho, account_chirho)?;
    }
    if let Some(actor_chirho) = actor_chirho {
        refuse_if_account_frozen_chirho(root_chirho, actor_chirho)?;
    }
    refuse_unless_namespace_permits_chirho(container_chirho, subject_chirho)?;
    if let SubjectOwnerChirho::CoverageDebtChirho(debt_chirho) = container_chirho {
        record_coverage_debt_unlocked_chirho(root_chirho, *debt_chirho)?;
    }
    claim_subject_owner_unlocked_chirho(root_chirho, container_chirho, subject_chirho)?;
    let actor_label_chirho =
        actor_chirho.map_or(NO_ACTOR_CHIRHO, AccountCoordinateChirho::as_hex_chirho);
    if let SubjectOwnerChirho::AccountChirho(account_chirho) = container_chirho {
        append_attribution_row_unlocked_chirho(
            root_chirho,
            account_chirho,
            AttributionRowChirho {
                role_chirho: ROLE_OWNED_CHIRHO,
                container_chirho: container_chirho.label_chirho(),
                actor_chirho: actor_label_chirho,
                subject_chirho,
                key_id_chirho,
            },
        )?;
    }
    if let Some(actor_chirho) = actor_chirho {
        if container_chirho != &SubjectOwnerChirho::AccountChirho(actor_chirho.clone()) {
            append_attribution_row_unlocked_chirho(
                root_chirho,
                actor_chirho,
                AttributionRowChirho {
                    role_chirho: ROLE_CONTRIBUTION_CHIRHO,
                    container_chirho: container_chirho.label_chirho(),
                    actor_chirho: actor_chirho.as_hex_chirho(),
                    subject_chirho,
                    key_id_chirho,
                },
            )?;
        }
    }
    Ok(())
}

/// A subject inside `user/<id>` or `owner/<id>` (that principal, or a path below it) may be held only by
/// the account whose coordinate derives from that exact principal.
fn refuse_unless_namespace_permits_chirho(
    container_chirho: &SubjectOwnerChirho,
    subject_chirho: &str,
) -> Result<()> {
    let Some(namespace_chirho) = PRINCIPAL_NAMESPACES_CHIRHO
        .iter()
        .find(|namespace_chirho| subject_chirho.starts_with(**namespace_chirho))
    else {
        return Ok(());
    };
    let principal_end_chirho = subject_chirho[namespace_chirho.len()..]
        .find('/')
        .map_or(subject_chirho.len(), |offset_chirho| {
            namespace_chirho.len() + offset_chirho
        });
    let principal_chirho = &subject_chirho[..principal_end_chirho];
    let permitted_chirho = AccountCoordinateChirho::from_principal_chirho(principal_chirho)
        .is_ok_and(|principal_account_chirho| {
            container_chirho == &SubjectOwnerChirho::AccountChirho(principal_account_chirho)
        });
    if !permitted_chirho {
        return Err(refuse_chirho(
            AccountAttributionRefusalChirho::SubjectNamespaceReservedChirho,
            "only the principal named by a principal-namespace subject may own it",
        ));
    }
    Ok(())
}

fn claim_subject_owner_unlocked_chirho(
    root_chirho: &Path,
    owner_chirho: &SubjectOwnerChirho,
    subject_chirho: &str,
) -> Result<()> {
    let digest_chirho = subject_digest_chirho(subject_chirho);
    if let Some(existing_chirho) = subject_owner_unlocked_chirho(root_chirho, subject_chirho)? {
        refuse_unless_same_owner_chirho(&existing_chirho, owner_chirho)?;
        // A crash between a claim's record and its witness heals here, from the verified record.
        return write_subject_claim_witness_chirho(root_chirho, &digest_chirho);
    }
    let mut record_chirho = SubjectOwnerRecordChirho {
        schema_chirho: SUBJECT_OWNER_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        subject_digest_chirho: digest_chirho.clone(),
        owner_chirho: owner_chirho.label_chirho().to_string(),
        at_ms_chirho: now_ms_chirho(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(root_chirho, &record_chirho.message_chirho())?;
    match create_complete_file_durable_with_mode_chirho(
        &subject_owner_path_chirho(root_chirho, &digest_chirho),
        &serde_json::to_vec(&record_chirho)?,
        PRIVATE_FILE_MODE_CHIRHO,
    )? {
        CreateFileDurableOutcomeChirho::CreatedChirho => {}
        CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = subject_owner_unlocked_chirho(root_chirho, subject_chirho)?
                .ok_or_else(|| unverified_chirho("a subject owner appeared and then vanished"))?;
            refuse_unless_same_owner_chirho(&existing_chirho, owner_chirho)?;
        }
    }
    write_subject_claim_witness_chirho(root_chirho, &digest_chirho)
}

fn refuse_unless_same_owner_chirho(
    existing_chirho: &SubjectOwnerChirho,
    owner_chirho: &SubjectOwnerChirho,
) -> Result<()> {
    if existing_chirho != owner_chirho {
        return Err(refuse_chirho(
            AccountAttributionRefusalChirho::SubjectOwnedElsewhereChirho,
            "a key for this owner may not be created under a subject another owner holds",
        ));
    }
    Ok(())
}
