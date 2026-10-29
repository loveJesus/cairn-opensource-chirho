// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Class-A PREPARE evidence and the elected COMMIT for the price-book door.
//!
//! # RECORDED LOAN — this file holds a DUPLICATE of the prepare-state evidence machinery
//!
//! `FileStateChirho`, `MutableFileEvidenceKindChirho`, `capture_mutable_state_chirho`,
//! `capture_file_state_chirho`, `same_file_snapshot_chirho`, `capture_terminal_line_chirho`,
//! `require_stable_prepare_state_chirho` and `require_current_prepare_state_chirho` below are a
//! deliberate copy. The other copies live in:
//!
//! - `src/app_runtime_chirho/app_chirho/app_deploy_evidence_chirho.rs` (S1, the original — gpt)
//! - the S2 route-door evidence module (gpt, landing in parallel)
//!
//! **Why a copy is permitted here:** the original is private to a private module and unreachable
//! from this crate path, and extracting it first would serialize the price door behind a refactor
//! of a file another seat is actively editing — spending the demo to buy structure that loses
//! nothing by waiting days. Ruled by claude2_chirho on 2026-07-28, options (a)/(b)/(c), (c) chosen.
//!
//! **Why it is a LOAN and not a norm — the reason, verbatim from the ruling:** *three
//! independently-drifting copies of a safety mechanism is worse than one copy plus a scheduled
//! extraction.* This machinery is what makes PREPARE provably read-only on a money path; three
//! copies free to drift is the same failure as two instruments sharing a blind spot, expressed in
//! code instead of in measurement.
//!
//! **REPAYMENT:** one shared evidence home (placement decided at extraction — likely beside the
//! writer-head/F4 seam), extracted by gpt as its own brick **immediately after the demo lands (the
//! S4 host run), before any fourth consumer of the pattern exists.** gpt authored the original and
//! owns the extraction; this copy and S2's copy die in it. Until then these copies are the recorded
//! exception, not the pattern to follow — **do not add a fourth.**
//!
//! # What is NOT loaned — the S3-specific obligation
//!
//! Unlike app Deploy, whose DAG pre-exists and is merely validated, **the price book object is
//! created by this operation.** PREPARE must write nothing, so it binds the book's content address
//! with `store_chirho::hash_object_chirho` (pure, no write) and COMMIT performs the
//! `put_object_chirho` **only after F4 promotion**, before the record append. That ordering is the
//! Class-A law applied to an operation-created object and stays S3-local, outside any future
//! extraction.

use super::{
    current_price_book_hash_chirho, now_ms_chirho, price_book_transition_operation_bytes_chirho,
    price_record_message_chirho, price_records_path_chirho, pricebook_ref_chirho,
    verified_price_book_records_chirho, PRICE_BOOK_HEAD_REASON_CHIRHO,
    PRICE_BOOK_RECORDS_LOG_CHIRHO,
};
use crate::economic_model_chirho::{
    PriceBookChirho, PriceBookRecordChirho, PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO,
};
use crate::model_chirho::HashChirho;
use crate::{app_chirho, refs_chirho, seqlog_chirho, store_chirho};
use anyhow::{bail, Context, Result};
use cairn_durable_chirho::cas_lifecycle_chirho::{
    CasLifecycleRootChirho, CasLifecycleSnapshotChirho,
};
use cairn_economic_governance_chirho::pricebook_policy_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionCommitScopeChirho;
use cairn_writer_head_chirho::head_transition_chirho::{
    self, PreparedFenceHeadTransitionIdentityInputChirho, PreparedHeadTransitionChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, observe_prepared_fence_lower_bound_chirho,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Tail cap for the terminal-line witness. Same value as the S1 copy; see the loan note.
const MAX_PRICE_BOOK_TAIL_LINE_BYTES_CHIRHO: usize = 1024 * 1024;

pub(super) enum PreparedElectedPriceBookChirho {
    AlreadyAppliedChirho {
        hash_chirho: HashChirho,
        book_chirho: PriceBookChirho,
        record_chirho: PriceBookRecordChirho,
        mutable_state_chirho: PriceBookMutableStateChirho,
    },
    MutationChirho {
        hash_chirho: HashChirho,
        book_chirho: PriceBookChirho,
        record_chirho: PriceBookRecordChirho,
        prepared_head_chirho: PreparedHeadTransitionChirho,
        expected_key_id_chirho: String,
        mutable_state_chirho: Box<PriceBookMutableStateChirho>,
        lifecycle_root_chirho: CasLifecycleRootChirho,
        lifecycle_snapshot_chirho: CasLifecycleSnapshotChirho,
    },
}

/// Every surface this door's decision depends on — **which is NOT the same as the set it writes.**
///
/// The first version of this struct carried only the price family, refs and reflog, with a comment
/// claiming the door "touches no identity family". That was **false and it was exploitable**: the
/// door does not WRITE identities, but `ensure_app_owner_chirho` READS the verified identity-kind
/// and app-owner maps to authorize the mutation. gpt's S3 review planted a valid identity append
/// between PREPARE and the elected scope and **the price mutation committed on stale authorization
/// evidence.**
///
/// The lesson, stated so the next door does not repeat it: **prepare-state evidence must cover the
/// READ INPUTS TO THE AUTHORIZATION DECISION, not the write outputs of the operation.** I derived
/// this set from my own ZR-2b Z9 write census, and a write census is exactly the instrument that
/// cannot see an authorization read.
///
/// The Class-B contract already required these as separate strict tails
/// (`class-b-commit-chirho.md:162-164`, `:213-221`); the miss was mine, not the contract's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PriceBookMutableStateChirho {
    price_records_chirho: FileStateChirho,
    refs_chirho: FileStateChirho,
    reflog_chirho: FileStateChirho,
    /// AUTHORIZATION INPUT: the app-owner map `ensure_app_owner_chirho` resolves ownership from.
    app_records_chirho: FileStateChirho,
    /// AUTHORIZATION INPUT: the identity-kind map `ensure_app_owner_chirho` resolves principals from.
    identities_chirho: FileStateChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FileStateChirho {
    MissingChirho,
    PresentChirho {
        device_chirho: u64,
        inode_chirho: u64,
        length_chirho: u64,
        modified_seconds_chirho: i64,
        modified_nanoseconds_chirho: i64,
        last_line_length_chirho: Option<u64>,
        last_line_blake3_chirho: Option<String>,
    },
}

#[derive(Clone, Copy)]
enum MutableFileEvidenceKindChirho {
    ReplaceUpdatedChirho,
    TailConfinedLogChirho,
}

/// Class-A PREPARE: gather every piece of evidence the COMMIT will re-check, and **write nothing**.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_elected_price_book_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    price_per_request_chirho: Option<i64>,
    effect_prices_chirho: BTreeMap<String, i64>,
    external_markup_bps_chirho: i64,
) -> Result<PreparedElectedPriceBookChirho> {
    let lifecycle_root_chirho = CasLifecycleRootChirho::open_chirho(root_chirho)
        .map_err(anyhow::Error::new)
        .context("PriceBookCasLifecycleUnavailableChirho")?;
    let lifecycle_snapshot_chirho = lifecycle_root_chirho
        .snapshot_chirho()
        .map_err(anyhow::Error::new)
        .context("PriceBookCasLifecycleSnapshotRefusedChirho")?;
    let before_chirho = capture_mutable_state_chirho(root_chirho)?;

    app_chirho::ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let verified_records_chirho = verified_price_book_records_chirho(root_chirho)?;
    refuse_pending_price_transition_chirho(root_chirho, app_chirho, &verified_records_chirho)?;

    // FAIL-CLOSED READ. This is the same read S4P-A hardened in the continuation inventory: it
    // distinguishes "no price book" (Ok(None)) from "the price history did not verify" (Err), and
    // the error must refuse rather than read as absence — here even more directly than there,
    // because absence is what makes this a first-price mint.
    let previous_chirho = current_price_book_hash_chirho(root_chirho, app_chirho)
        .context("PriceBookPreviousHeadUnreadableChirho")?;

    let book_chirho = pricebook_policy_chirho::propose_price_book_chirho(
        app_chirho,
        owner_principal_chirho,
        price_per_request_chirho,
        effect_prices_chirho,
        external_markup_bps_chirho,
        previous_chirho.clone(),
        now_ms_chirho(),
    )?;
    // The address WITHOUT the write: `put_object_chirho` is deferred to COMMIT, after F4 promotion.
    // Both route through the same canonical encoding, so this address is the one COMMIT will store.
    let hash_chirho = store_chirho::hash_object_chirho(&book_chirho)?;

    if previous_chirho.as_ref() == Some(&hash_chirho) {
        let selected_chirho = verified_records_chirho
            .iter()
            .rev()
            .find(|record_chirho| {
                record_chirho.app_chirho == app_chirho
                    && record_chirho.price_book_chirho == hash_chirho
            })
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("PriceBookAlreadyAppliedRecordMissingFromVerifiedHistoryChirho")
            })?;
        let after_chirho = capture_mutable_state_chirho(root_chirho)?;
        require_stable_prepare_state_chirho(&before_chirho, &after_chirho)?;
        return Ok(PreparedElectedPriceBookChirho::AlreadyAppliedChirho {
            hash_chirho,
            book_chirho,
            record_chirho: selected_chirho,
            mutable_state_chirho: after_chirho,
        });
    }

    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    let prepared_fence_chirho =
        observe_prepared_fence_lower_bound_chirho(root_chirho, &group_chirho)?;
    let seq_chirho = u64::try_from(verified_records_chirho.len())
        .context("price book record sequence does not fit u64")?;
    let mut record_chirho = PriceBookRecordChirho {
        seq_chirho,
        schema_chirho: PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_principal_chirho.to_string(),
        price_book_chirho: hash_chirho.clone(),
        previous_chirho: previous_chirho.clone(),
        at_ms_chirho: now_ms_chirho(),
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: Some(prepared_fence_chirho.epoch_chirho()),
        sig_chirho: String::new(),
    };

    let branch_chirho = pricebook_ref_chirho(app_chirho);
    let operation_bytes_chirho = price_book_transition_operation_bytes_chirho(&record_chirho)?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: PRICE_BOOK_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &record_chirho.price_book_chirho,
        reason_chirho: PRICE_BOOK_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    record_chirho.transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_from_prepared_fence_chirho(
            &identity_chirho,
        )?;
    let message_chirho = price_record_message_chirho(&record_chirho)?;
    let possession_chirho =
        signer_chirho::sign_with_existing_key_possession_chirho(root_chirho, &message_chirho)?;
    let expected_key_id_chirho = possession_chirho.key_id_chirho().to_string();
    record_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();

    let operation_bytes_chirho = price_book_transition_operation_bytes_chirho(&record_chirho)?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: PRICE_BOOK_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &record_chirho.price_book_chirho,
        reason_chirho: PRICE_BOOK_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    let prepared_head_chirho =
        head_transition_chirho::bind_caller_verified_head_transition_from_prepared_fence_chirho(
            &identity_chirho,
            &record_chirho.transition_id_chirho,
            &serde_json::to_vec(&record_chirho)?,
        )?;

    let after_chirho = capture_mutable_state_chirho(root_chirho)?;
    require_stable_prepare_state_chirho(&before_chirho, &after_chirho)?;
    Ok(PreparedElectedPriceBookChirho::MutationChirho {
        hash_chirho,
        book_chirho,
        record_chirho,
        prepared_head_chirho,
        expected_key_id_chirho,
        mutable_state_chirho: Box::new(after_chirho),
        lifecycle_root_chirho,
        lifecycle_snapshot_chirho,
    })
}

/// Elected COMMIT under the affine scope. **F4 promotion precedes the first durable write**, and for
/// this door the first durable write is the CAS put of the operation-created book — not the row.
pub(super) fn commit_elected_price_book_chirho(
    root_chirho: &Path,
    prepared_chirho: PreparedElectedPriceBookChirho,
    scope_chirho: HeadTransitionCommitScopeChirho<'_>,
) -> Result<(HashChirho, PriceBookChirho, PriceBookRecordChirho)> {
    match prepared_chirho {
        PreparedElectedPriceBookChirho::AlreadyAppliedChirho {
            hash_chirho,
            book_chirho,
            record_chirho,
            mutable_state_chirho,
        } => {
            require_current_prepare_state_chirho(root_chirho, &mutable_state_chirho)?;
            Ok((hash_chirho, book_chirho, record_chirho))
        }
        PreparedElectedPriceBookChirho::MutationChirho {
            hash_chirho,
            book_chirho,
            record_chirho,
            prepared_head_chirho,
            expected_key_id_chirho,
            mutable_state_chirho,
            lifecycle_root_chirho,
            lifecycle_snapshot_chirho,
        } => {
            scope_chirho.preflight_head_transition_chirho(root_chirho, &prepared_head_chirho)?;
            require_current_prepare_state_chirho(root_chirho, &mutable_state_chirho)?;
            let current_key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
            if current_key_id_chirho != expected_key_id_chirho {
                bail!("PriceBookPreparedSigningKeyChangedChirho");
            }
            let lifecycle_guard_chirho = lifecycle_root_chirho
                .promote_chirho(lifecycle_snapshot_chirho)
                .map_err(anyhow::Error::new)
                .context("PriceBookCasLifecyclePromotionRefusedChirho")?;

            // FIRST DURABLE WRITE, and it is the book — after promotion, by construction.
            let stored_hash_chirho = store_chirho::put_object_chirho(root_chirho, &book_chirho)?;
            if stored_hash_chirho != hash_chirho {
                bail!("PriceBookStoredAddressDivergedFromPreparedChirho");
            }
            seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
                &price_records_path_chirho(root_chirho),
                record_chirho.seq_chirho,
                &record_chirho,
            )?;
            scope_chirho.complete_head_transition_chirho(root_chirho, &prepared_head_chirho)?;
            drop(lifecycle_guard_chirho);
            Ok((hash_chirho, book_chirho, record_chirho))
        }
    }
}

/// A prior unreceipted positive transition REFUSES rather than being repaired here.
///
/// The S3 twin of `refuse_pending_app_transition_chirho`, and ruled the same way in the S1 review: a
/// repair inside read-only PREPARE runs before the authority check and can therefore only strand a
/// half-state. Recovery is post-demo elected retry-repair work.
fn refuse_pending_price_transition_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    records_chirho: &[PriceBookRecordChirho],
) -> Result<()> {
    for record_chirho in records_chirho.iter().filter(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.schema_chirho == PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO
    }) {
        let prepared_chirho =
            super::prepared_from_verified_price_book_record_chirho(root_chirho, record_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("PriceBookPendingHeadTransitionChirho");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LOANED MACHINERY — see the module header. Copy of the S1 original; dies in gpt's post-demo
// extraction. Behaviour must stay identical to the other copies; if you change one, change all.
// ---------------------------------------------------------------------------

fn capture_mutable_state_chirho(root_chirho: &Path) -> Result<PriceBookMutableStateChirho> {
    Ok(PriceBookMutableStateChirho {
        price_records_chirho: capture_file_state_chirho(
            &price_records_path_chirho(root_chirho),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
        refs_chirho: capture_file_state_chirho(
            &root_chirho.join("refs-chirho.json"),
            MutableFileEvidenceKindChirho::ReplaceUpdatedChirho,
        )?,
        reflog_chirho: capture_file_state_chirho(
            &refs_chirho::reflog_path_chirho(root_chirho),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
        app_records_chirho: capture_file_state_chirho(
            &root_chirho.join("app-records-chirho.jsonl"),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
        identities_chirho: capture_file_state_chirho(
            &root_chirho.join("identities-chirho.jsonl"),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
    })
}

fn capture_file_state_chirho(
    path_chirho: &Path,
    evidence_kind_chirho: MutableFileEvidenceKindChirho,
) -> Result<FileStateChirho> {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(path_metadata_chirho) => {
            if !path_metadata_chirho.file_type().is_file() {
                bail!(
                    "PriceBookMutableInputNotRegularChirho: {}",
                    path_chirho.display()
                );
            }
            let mut file_chirho = File::open(path_chirho)
                .with_context(|| format!("open mutable input {}", path_chirho.display()))?;
            let opened_metadata_chirho = file_chirho
                .metadata()
                .with_context(|| format!("stat mutable input {}", path_chirho.display()))?;
            if !same_file_snapshot_chirho(&path_metadata_chirho, &opened_metadata_chirho) {
                bail!(
                    "PriceBookMutableInputReboundChirho: {}",
                    path_chirho.display()
                );
            }
            let (last_line_length_chirho, last_line_blake3_chirho) = match evidence_kind_chirho {
                MutableFileEvidenceKindChirho::ReplaceUpdatedChirho => (None, None),
                MutableFileEvidenceKindChirho::TailConfinedLogChirho => {
                    let (length_chirho, blake3_chirho) =
                        capture_terminal_line_chirho(&mut file_chirho, path_chirho)?;
                    (Some(length_chirho), Some(blake3_chirho))
                }
            };
            let final_opened_metadata_chirho = file_chirho
                .metadata()
                .with_context(|| format!("restat mutable input {}", path_chirho.display()))?;
            let final_path_metadata_chirho = std::fs::symlink_metadata(path_chirho)
                .with_context(|| format!("restat mutable path {}", path_chirho.display()))?;
            if !final_path_metadata_chirho.file_type().is_file()
                || !same_file_snapshot_chirho(
                    &opened_metadata_chirho,
                    &final_opened_metadata_chirho,
                )
                || !same_file_snapshot_chirho(
                    &final_opened_metadata_chirho,
                    &final_path_metadata_chirho,
                )
            {
                bail!(
                    "PriceBookMutableInputChangedDuringReadChirho: {}",
                    path_chirho.display()
                );
            }
            Ok(FileStateChirho::PresentChirho {
                device_chirho: final_opened_metadata_chirho.dev(),
                inode_chirho: final_opened_metadata_chirho.ino(),
                length_chirho: final_opened_metadata_chirho.len(),
                modified_seconds_chirho: final_opened_metadata_chirho.mtime(),
                modified_nanoseconds_chirho: final_opened_metadata_chirho.mtime_nsec(),
                last_line_length_chirho,
                last_line_blake3_chirho,
            })
        }
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => {
            Ok(FileStateChirho::MissingChirho)
        }
        Err(error_chirho) => Err(error_chirho)
            .with_context(|| format!("inspect mutable input {}", path_chirho.display())),
    }
}

fn same_file_snapshot_chirho(
    left_chirho: &std::fs::Metadata,
    right_chirho: &std::fs::Metadata,
) -> bool {
    left_chirho.file_type().is_file()
        && right_chirho.file_type().is_file()
        && left_chirho.dev() == right_chirho.dev()
        && left_chirho.ino() == right_chirho.ino()
        && left_chirho.len() == right_chirho.len()
        && left_chirho.mtime() == right_chirho.mtime()
        && left_chirho.mtime_nsec() == right_chirho.mtime_nsec()
}

/// Hashes only the final physical line. Tail-confinement makes that bounded suffix the mutation
/// witness for append/truncate logs; replace-updated files use inode identity instead.
fn capture_terminal_line_chirho(
    file_chirho: &mut File,
    path_chirho: &Path,
) -> Result<(u64, String)> {
    let byte_length_chirho = file_chirho
        .metadata()
        .with_context(|| format!("stat mutable log {}", path_chirho.display()))?
        .len();
    if byte_length_chirho == 0 {
        return Ok((0, blake3::hash(b"").to_hex().to_string()));
    }
    let max_tail_plus_boundary_chirho = u64::try_from(MAX_PRICE_BOOK_TAIL_LINE_BYTES_CHIRHO + 1)
        .context("price book tail cap does not fit u64")?;
    let suffix_length_chirho = byte_length_chirho.min(max_tail_plus_boundary_chirho);
    let suffix_start_chirho = byte_length_chirho - suffix_length_chirho;
    file_chirho
        .seek(SeekFrom::Start(suffix_start_chirho))
        .with_context(|| format!("seek mutable log tail {}", path_chirho.display()))?;
    let suffix_capacity_chirho =
        usize::try_from(suffix_length_chirho).context("mutable log tail does not fit usize")?;
    let mut suffix_chirho = vec![0u8; suffix_capacity_chirho];
    file_chirho
        .read_exact(&mut suffix_chirho)
        .with_context(|| format!("read mutable log tail {}", path_chirho.display()))?;

    let search_end_chirho = if suffix_chirho.last() == Some(&b'\n') {
        suffix_chirho.len() - 1
    } else {
        suffix_chirho.len()
    };
    let line_start_chirho = suffix_chirho[..search_end_chirho]
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map_or(0, |newline_chirho| newline_chirho + 1);
    if line_start_chirho == 0 && suffix_start_chirho != 0 {
        bail!(
            "PriceBookMutableInputTailTooLargeChirho: {}",
            path_chirho.display()
        );
    }
    let line_chirho = &suffix_chirho[line_start_chirho..];
    if line_chirho.len() > MAX_PRICE_BOOK_TAIL_LINE_BYTES_CHIRHO {
        bail!(
            "PriceBookMutableInputTailTooLargeChirho: {}",
            path_chirho.display()
        );
    }
    Ok((
        u64::try_from(line_chirho.len()).context("mutable log tail length does not fit u64")?,
        blake3::hash(line_chirho).to_hex().to_string(),
    ))
}

fn require_stable_prepare_state_chirho(
    before_chirho: &PriceBookMutableStateChirho,
    after_chirho: &PriceBookMutableStateChirho,
) -> Result<()> {
    if before_chirho != after_chirho {
        bail!("PriceBookPrepareStateChangedChirho");
    }
    Ok(())
}

/// Recheck every prepared surface before any durable output, with **DISTINCT refusals per family**.
///
/// One collapsed refusal would tell an operator that *something* moved; these tell them WHICH, and
/// the two authorization tails are named separately because they fail for different reasons — a new
/// app-owner row is an ownership change, a new identity row is a principal change, and an operator
/// diagnosing a stale-authorization refusal needs to know which map moved under them.
///
/// The authorization tails are checked FIRST: if authorization is stale, the answer is "you were not
/// authorized on current evidence", which is a stronger and more useful statement than "the price
/// log moved".
fn require_current_prepare_state_chirho(
    root_chirho: &Path,
    expected_chirho: &PriceBookMutableStateChirho,
) -> Result<()> {
    let current_chirho = capture_mutable_state_chirho(root_chirho)?;
    if current_chirho.app_records_chirho != expected_chirho.app_records_chirho {
        bail!("StaleAppOwnerTailChirho");
    }
    if current_chirho.identities_chirho != expected_chirho.identities_chirho {
        bail!("StaleIdentityTailChirho");
    }
    if current_chirho != *expected_chirho {
        bail!("PriceBookPreparedStateChangedChirho");
    }
    Ok(())
}
