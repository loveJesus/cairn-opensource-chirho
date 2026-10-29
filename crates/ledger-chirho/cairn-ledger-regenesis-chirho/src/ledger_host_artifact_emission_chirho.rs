// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Write the authored host config and regenesis plan into the selected root, overwriting nothing
//! and leaving nothing behind when it refuses.
//!
//! Brick #4 of the generic ledger-host authoring program
//! (`spec-chirho/workstream-state-chirho/ledger-host-config-authoring-design-chirho.md` §5). It is
//! the first brick in this program that touches a FILESYSTEM, so its failure modes are new ones:
//! a partial write, an overwrite of an existing authority artifact, a world-readable
//! secret-adjacent file, and a file whose bytes never reached the disk.
//!
//! **This road AUTHORS as well as emits, and that is a security decision rather than convenience.**
//! The obvious alternative — take an already-derived [`LedgerHostCustodyBoundArtifactsChirho`] and
//! just write it — reopens exactly the hazard the program's seal ruling closes one type over: that
//! struct's fields are `pub`, so a caller outside this crate could assemble artifacts carrying an
//! INVENTED issuer pin, hand them here, and have them written at mode `0600` wearing a custody
//! evidence value that nothing behind it ever proved. So emission accepts only the same untrusted
//! inputs the custody road accepts — a root, a reviewed document, and two secret NAMES — and calls
//! [`bind_custody_and_derive_ledger_host_artifacts_chirho`] itself. Nothing derived crosses this
//! crate's boundary inward, and no signer set crosses it in either direction.
//!
//! **Order is part of the contract, and the cheap refusals come first.** Root, then both output
//! paths, then output distinctness — all before a single secret is read. An operator who aims at an
//! existing artifact gets a named refusal without this process having touched the secret store.
//!
//! **The no-overwrite property is fenced TWICE, deliberately.**
//! 1. `symlink_metadata` must report `NotFound` for each resolved output. This is the NAMED fence:
//!    it produces [`LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho`] carrying which
//!    artifact was in the way, before anything is written or read. It is also the only one of the
//!    two that can SEE a dangling symlink at all — `metadata` follows the link and reports the
//!    output free.
//! 2. `create_new(true)` at the syscall. This is the ATOMIC fence: it closes the window between the
//!    check above and the write, which no amount of checking can close.
//!
//! **What the first fence buys over the second, measured rather than argued.** An earlier draft of
//! this note claimed `create_new` would follow a dangling symlink and create the artifact at its
//! target, outside the root. That is FALSE, and the correction belongs here rather than downstream:
//! `O_CREAT | O_EXCL` refuses a symlink outright with `EEXIST` and creates nothing at the target
//! (measured directly, and mutation-confirmed by swapping this check to `metadata` — the emission
//! still refused, and the link's target was never created). So the symlink hole is closed by the
//! KERNEL. What the first fence actually buys is the MESSAGE and the ordering: without it an
//! occupied output degrades from "this artifact already exists" to a generic write failure, arriving
//! after the secret store has been read and after the other artifact is already on disk.
//!
//! **What `sync_all` buys, stated exactly, because "durable" would overclaim.** Each artifact's
//! bytes and metadata are flushed to the storage device before this function returns, so a crash
//! cannot leave a file that exists with unwritten contents. The containing DIRECTORY entry is not
//! separately synced, so a crash can still lose a just-created file entirely. That residual is
//! deliberately left open: these artifacts are re-derivable from the one reviewed document, so
//! losing an emission costs a re-run and never a money-safety property — and a half-built
//! crash-consistency story on a money path is worse than a named gap.
//!
//! **What this brick deliberately does NOT do, said here rather than discovered downstream.**
//! - It does not author the pre-signed ledger ACTIVATION AUTHORIZATION. The design's brick row
//!   names it, and it is stopped on purpose: it is a signing act producing an authority artifact,
//!   its validity window is fixed at 15 minutes with no override, so an authorization baked at
//!   authoring time is stale by the time a host boots, and the offline activation authoring
//!   function that mints it is already exported from this crate and already loads its own signers.
//!   A composed node therefore cannot boot from these two artifacts alone; that third step remains,
//!   and belongs beside the start it authorizes. (That function is described here rather than
//!   SPELLED: a confinement guard censuses its name across all production text and treats any
//!   occurrence as a reference site, so a doc mention would read to that guard exactly like a new
//!   caller. The custody brick names a crate the same way and for the same reason.)
//! - It does not choose or install the expected config digest.
//!   [`ledger_host_config_digest_chirho`] is computed and returned for independent review; every
//!   composed startup now requires that reviewed value through its external deployment channel and
//!   compares it with the exact config bytes before parsing. Keeping the producer and startup
//!   binder separate prevents this authoring road from certifying its own output.
//! - It creates no directory. Both outputs must land in a parent that already exists inside the
//!   selected root.

use crate::destination_authority_enrollment_chirho::VerifiedDestinationAuthorityEnrollmentChirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::ledger_host_authoring_inputs_chirho::LedgerHostAuthoringInputsV1Chirho;
use crate::ledger_host_authoring_mode_chirho::LedgerHostAuthoringModeChirho;
use crate::ledger_host_custody_binding_chirho::{
    bind_custody_and_derive_ledger_host_artifacts_chirho, LedgerHostCustodyEvidenceChirho,
    LedgerHostCustodyRequestChirho,
};
use cairn_config_chirho::config_chirho::{serialize_config_chirho, ConfigChirho};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Which of the two emitted artifacts a path-shaped refusal is about. Both are written by one road
/// with one set of laws, so a refusal that could not say WHICH file was in the way would send an
/// operator to inspect the wrong one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerHostArtifactKindChirho {
    HostConfigChirho,
    RegenesisPlanChirho,
}

impl LedgerHostArtifactKindChirho {
    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::HostConfigChirho => "ledger host config",
            Self::RegenesisPlanChirho => "ledger regenesis plan",
        }
    }
}

/// One authoring-and-emission request. It carries the custody road's inputs unchanged plus the two
/// output paths and the serve port, and deliberately carries nothing already derived.
pub struct LedgerHostEmissionRequestChirho<'request_chirho> {
    pub selected_root_chirho: &'request_chirho Path,
    pub inputs_chirho: &'request_chirho LedgerHostAuthoringInputsV1Chirho,
    pub destination_authority_enrollment_chirho:
        &'request_chirho VerifiedDestinationAuthorityEnrollmentChirho,
    pub issuer_secret_name_chirho: &'request_chirho str,
    /// Absent emits a config with no activation authority, exactly as the custody road handles it.
    pub activation_secret_name_chirho: Option<&'request_chirho str>,
    /// Relative paths resolve inside the selected root; absolute paths must still land inside it.
    pub config_output_chirho: &'request_chirho Path,
    pub plan_output_chirho: &'request_chirho Path,
    /// The HTTP serve port the emitted runtime config names. Not authority — it is the one
    /// coordinate the reviewed document has no field for, because it is about this host's process
    /// rather than about the money group.
    pub serve_port_chirho: u16,
    /// Production or synthetic test kind, passed straight through to the custody road. Required
    /// with no default so an emission cannot become a production artifact by omission; see
    /// [`crate::ledger_host_authoring_mode_chirho`] for why the mode is legibility rather than the
    /// control.
    pub mode_chirho: LedgerHostAuthoringModeChirho,
}

/// What was written, where, and the custody proof that authorized it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerHostEmittedArtifactsChirho {
    pub config_path_chirho: PathBuf,
    pub plan_path_chirho: PathBuf,
    /// The schema of the FINAL validated config bytes, after any custody-derived test-kind
    /// shared-journal augmentation.
    pub config_schema_chirho: String,
    /// Whether the final config carries the custody-derived journal-only held-verifier pin.
    pub shared_journal_verifier_authored_chirho: bool,
    /// REVIEW-ONLY. Nothing reads this back at boot today; the config's integrity between review
    /// and boot still rests on file mode and owner alone. Ruling (f) owns closing that.
    pub config_digest_chirho: String,
    /// The plan digest a later regenesis start must be given explicitly, and which
    /// `load_verified_plan_chirho` re-derives and compares before it trusts the plan.
    pub plan_digest_chirho: String,
    /// Digest of the exact retained enrollment whose public half was emitted into this config.
    pub destination_authority_enrollment_digest_chirho: String,
    pub custody_evidence_chirho: LedgerHostCustodyEvidenceChirho,
}

/// The review digest of already-serialized config bytes, matching the plan and inputs digest shape.
///
/// It gets its own name rather than borrowing `plan_digest_chirho`: the two are the same blake3
/// over bytes, and a plan-named function computing a config digest is a name asserting the wrong
/// thing, which costs more than the four lines it saves.
pub fn ledger_host_config_digest_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

/// Prove custody, derive the config and plan, and write them into the selected root.
///
/// Refuses, in order: a root that is not an existing non-symlink directory; an output path that
/// cannot be resolved, escapes the root, or already exists; two outputs naming one object; then
/// everything the custody road and the derivation refuse; then a config whose re-parsed root does
/// not bind the selected root; then a write that fails.
///
/// **Nothing survives a refusal.** Every path, custody, and derivation refusal happens before any
/// byte is written. The one refusal that can fire with a file already on disk — the config write
/// failing after the plan wrote — removes the plan before returning, so a caller that sees an error
/// never has to guess whether half an authoring landed.
pub fn author_and_emit_ledger_host_artifacts_chirho(
    request_chirho: LedgerHostEmissionRequestChirho<'_>,
) -> LedgerRegenesisResultChirho<LedgerHostEmittedArtifactsChirho> {
    let canonical_root_chirho =
        canonical_selected_root_chirho(request_chirho.selected_root_chirho)?;
    // Both output paths are resolved and proven fresh BEFORE the secret store is touched, so an
    // operator aiming at an existing artifact is refused without this process reading a key.
    let plan_path_chirho = checked_fresh_output_chirho(
        &canonical_root_chirho,
        request_chirho.plan_output_chirho,
        LedgerHostArtifactKindChirho::RegenesisPlanChirho,
    )?;
    let config_path_chirho = checked_fresh_output_chirho(
        &canonical_root_chirho,
        request_chirho.config_output_chirho,
        LedgerHostArtifactKindChirho::HostConfigChirho,
    )?;
    // Compared AFTER resolution, so `./x` and `x` cannot slip past as two names for one object.
    // Two outputs at one path would let the second write clobber the first through `create_new`'s
    // one legitimate gap: a path that was fresh when checked and is not fresh when written.
    if plan_path_chirho == config_path_chirho {
        return Err(LedgerRegenesisRefusalChirho::AuthoringOutputsAliasChirho);
    }

    let bound_chirho =
        bind_custody_and_derive_ledger_host_artifacts_chirho(LedgerHostCustodyRequestChirho {
            selected_root_chirho: &canonical_root_chirho,
            inputs_chirho: request_chirho.inputs_chirho,
            destination_authority_enrollment_chirho: request_chirho
                .destination_authority_enrollment_chirho,
            issuer_secret_name_chirho: request_chirho.issuer_secret_name_chirho,
            activation_secret_name_chirho: request_chirho.activation_secret_name_chirho,
            mode_chirho: request_chirho.mode_chirho,
        })?;

    let config_bytes_chirho = canonical_runtime_config_bytes_chirho(
        &canonical_root_chirho,
        request_chirho.serve_port_chirho,
        &bound_chirho,
    )?;

    // The plan is written FIRST on purpose. Either order needs the same rollback, but a crash
    // between the two writes leaves at most an inert JSON plan rather than a lone authority config
    // that a later reader could mistake for a reviewed one.
    write_private_create_new_chirho(
        &plan_path_chirho,
        &bound_chirho.artifacts_chirho.canonical_plan_bytes_chirho,
        LedgerHostArtifactKindChirho::RegenesisPlanChirho,
    )?;
    if let Err(refusal_chirho) = write_private_create_new_chirho(
        &config_path_chirho,
        &config_bytes_chirho,
        LedgerHostArtifactKindChirho::HostConfigChirho,
    ) {
        // Best effort by necessity: if this removal also fails there is nothing further this
        // process can do, and the refusal it must report is the WRITE failure that caused the
        // rollback, never a rollback failure that would hide it.
        let _removed_chirho = fs::remove_file(&plan_path_chirho);
        return Err(refusal_chirho);
    }

    Ok(LedgerHostEmittedArtifactsChirho {
        config_path_chirho,
        plan_path_chirho,
        config_schema_chirho: bound_chirho
            .artifacts_chirho
            .config_chirho
            .schema_chirho
            .clone(),
        shared_journal_verifier_authored_chirho: bound_chirho
            .custody_evidence_chirho
            .shared_journal_verifier_authored_chirho,
        config_digest_chirho: ledger_host_config_digest_chirho(&config_bytes_chirho),
        plan_digest_chirho: bound_chirho.artifacts_chirho.plan_digest_chirho.clone(),
        destination_authority_enrollment_digest_chirho: request_chirho
            .destination_authority_enrollment_chirho
            .enrollment_digest_chirho()
            .to_owned(),
        custody_evidence_chirho: bound_chirho.custody_evidence_chirho,
    })
}

/// The selected root must be an existing, non-symlink directory, and everything downstream speaks
/// its canonical form. This is the same three-line precondition `load_verified_plan_chirho` applies
/// at the consuming end, restated rather than shared because it is a precondition of two different
/// acts and neither owns the other.
fn canonical_selected_root_chirho(root_chirho: &Path) -> LedgerRegenesisResultChirho<PathBuf> {
    let metadata_chirho = fs::symlink_metadata(root_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::SelectedRootUnavailableChirho)?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        return Err(LedgerRegenesisRefusalChirho::SelectedRootUnavailableChirho);
    }
    root_chirho
        .canonicalize()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::SelectedRootUnavailableChirho)
}

/// Resolve one requested output to a fresh, in-root path.
///
/// The parent is canonicalized and required to be inside the root BEFORE the file name is rejoined,
/// so a symlinked parent cannot land an artifact outside the root while a textual check reads as
/// clean. `symlink_metadata` rather than `metadata` is what makes a DANGLING symlink count as
/// "already exists" — `metadata` follows it and reports the path free. The kernel would still refuse
/// the write (`O_CREAT | O_EXCL` fails `EEXIST` on a symlink), so this is about the refusal an
/// operator READS, not about a containment hole; see the module header's measured note.
fn checked_fresh_output_chirho(
    canonical_root_chirho: &Path,
    requested_output_chirho: &Path,
    artifact_chirho: LedgerHostArtifactKindChirho,
) -> LedgerRegenesisResultChirho<PathBuf> {
    let joined_chirho = if requested_output_chirho.is_absolute() {
        requested_output_chirho.to_path_buf()
    } else {
        canonical_root_chirho.join(requested_output_chirho)
    };
    let parent_chirho = joined_chirho
        .parent()
        .ok_or(LedgerRegenesisRefusalChirho::AuthoringOutputPathRefusedChirho { artifact_chirho })?
        .canonicalize()
        .map_err(|_error_chirho| {
            LedgerRegenesisRefusalChirho::AuthoringOutputPathRefusedChirho { artifact_chirho }
        })?;
    if !parent_chirho.starts_with(canonical_root_chirho) {
        return Err(
            LedgerRegenesisRefusalChirho::AuthoringOutputOutsideRootChirho { artifact_chirho },
        );
    }
    let file_name_chirho = joined_chirho.file_name().ok_or(
        LedgerRegenesisRefusalChirho::AuthoringOutputPathRefusedChirho { artifact_chirho },
    )?;
    let output_chirho = parent_chirho.join(file_name_chirho);
    match fs::symlink_metadata(&output_chirho) {
        Ok(_metadata_chirho) => {
            Err(LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho { artifact_chirho })
        }
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            Ok(output_chirho)
        }
        // Anything else — a permission failure on the parent, most plausibly — is not proof the
        // path is free, so it refuses rather than proceeding to a write that would decide it.
        Err(_error_chirho) => {
            Err(LedgerRegenesisRefusalChirho::AuthoringOutputPathRefusedChirho { artifact_chirho })
        }
    }
}

/// Compose the derived host-config block into the runtime config the serve path actually parses,
/// serialize it through the one function that validates-serializes-and-reparses its own bytes, and
/// prove the emitted text binds the selected root.
///
/// The root binding is belt and braces on top of `serialize_config_chirho`, and it is the belt that
/// matters: that function proves the bytes are a valid config, never that they are THIS root's
/// config. A config whose `root_chirho` names a different tree would validate, parse, and boot
/// against storage nobody reviewed.
///
/// **That binding check is DELIBERATELY unreachable from any accepted input, and it was measured
/// rather than assumed.** Disabling it changes no test — because this function sets `root_chirho`
/// from the canonical root a few lines above, so the two can only disagree if the config crate's
/// serialize/parse pair mangles the field or the root moves underneath us. A surviving mutation is
/// an unanswered question, so the question was answered from the other side: making the composed
/// root drift (`{root}/..`) fires `AuthoringConfigRootBindingRefusedChirho` immediately. The check
/// is therefore live and is a DRIFT TRIPWIRE on a neighbouring crate, not a dead branch — and it is
/// not something a behavioural arm in this crate can pin without inventing a way to inject a wrong
/// root, which would mean widening this API for a test.
fn canonical_runtime_config_bytes_chirho(
    canonical_root_chirho: &Path,
    serve_port_chirho: u16,
    bound_chirho: &crate::ledger_host_custody_binding_chirho::LedgerHostCustodyBoundArtifactsChirho,
) -> LedgerRegenesisResultChirho<Vec<u8>> {
    let root_text_chirho = canonical_root_chirho
        .to_str()
        .ok_or(LedgerRegenesisRefusalChirho::SelectedRootUnavailableChirho)?;
    let runtime_config_chirho = ConfigChirho {
        root_chirho: root_text_chirho.to_owned(),
        port_chirho: serve_port_chirho,
        ledger_host_chirho: Some(bound_chirho.artifacts_chirho.config_chirho.clone()),
        ..ConfigChirho::default()
    };
    let text_chirho = serialize_config_chirho(&runtime_config_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
    let parsed_chirho = cairn_config_chirho::config_chirho::parse_config_chirho(&text_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
    let reparsed_text_chirho = serialize_config_chirho(&parsed_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
    if reparsed_text_chirho != text_chirho {
        return Err(LedgerRegenesisRefusalChirho::ConfigInvalidChirho);
    }
    let parsed_root_chirho = Path::new(&parsed_chirho.root_chirho)
        .canonicalize()
        .map_err(|_error_chirho| {
            LedgerRegenesisRefusalChirho::AuthoringConfigRootBindingRefusedChirho
        })?;
    if parsed_root_chirho != canonical_root_chirho {
        return Err(LedgerRegenesisRefusalChirho::AuthoringConfigRootBindingRefusedChirho);
    }
    Ok(text_chirho.into_bytes())
}

/// Create one artifact that did not exist, readable and writable by its owner alone, with its bytes
/// on the device before this returns.
///
/// `create_new(true)` is the atomic half of the no-overwrite law; the resolved-path check upstream
/// is the named half. `mode(0o600)` is set at OPEN rather than chmod-ed after, so the file is never
/// momentarily group- or world-readable — these artifacts sit beside a secret store and the config
/// custody check the serve path applies refuses anything with `mode & 0o077` set.
fn write_private_create_new_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
    artifact_chirho: LedgerHostArtifactKindChirho,
) -> LedgerRegenesisResultChirho<()> {
    let mut options_chirho = fs::OpenOptions::new();
    options_chirho.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options_chirho.mode(0o600);
    }
    let mut file_chirho = options_chirho.open(path_chirho).map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::AuthoringOutputWriteRefusedChirho { artifact_chirho }
    })?;
    file_chirho
        .write_all(bytes_chirho)
        .map_err(|_error_chirho| {
            LedgerRegenesisRefusalChirho::AuthoringOutputWriteRefusedChirho { artifact_chirho }
        })?;
    file_chirho.sync_all().map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::AuthoringOutputWriteRefusedChirho { artifact_chirho }
    })
}
